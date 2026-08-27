/*
* Contains logic for:
*
* - Opening UDP connections (join snadbox with ip and nickname)
* - Forming direct TCP connections between sender and receiver
* - Storing { nickname : ip } snadbox map
* - Closing TCP connections (can be done by either sender or receiver)
* - Closing UDP connections (remove device from snadbox)
 */

package snadbox

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"snad/components"
)

const (
	PoolAddress    = "224.0.0.250:9999"
	SignalInterval = 2 * time.Second
	staleAfter     = SignalInterval * 3
)

const (
	statusHere = "here"
	statusBye  = "bye"
)

// enableMulticastLoopback re-enables IP_MULTICAST_LOOP on conn, which
// net.ListenMulticastUDP disables by default. Without this, two snad
// instances running on the same machine (as opposed to two separate devices
// on the LAN) can never discover each other: the OS only loops a host's own
// multicast sends back to sockets on that same host when this option is on.
// Real cross-device discovery is unaffected either way, since loopback only
// governs local delivery back to the sending host. Best-effort: if the
// underlying fd can't be reached or the option can't be set, discovery still
// works for genuinely separate devices, so errors are ignored.
func enableMulticastLoopback(conn *net.UDPConn) {
	sc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = sc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1)
	})
}

// multicastInterface picks a live (carrier-present), non-loopback interface
// that supports multicast, so discovery works reliably even on machines
// where the OS's default multicast route doesn't point at a usable NIC, or
// where an administratively-up-but-disconnected NIC would otherwise be
// picked first. Returns nil (letting the kernel choose) if no such
// interface is found.
func multicastInterface() *net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	const want = net.FlagUp | net.FlagRunning | net.FlagMulticast
	for i := range ifaces {
		iface := ifaces[i]
		if iface.Flags&want != want || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		return &iface
	}
	return nil
}

// wireMessage is the JSON payload multicast over UDP for discovery. It is
// self-authenticating: Cert is the sender's DER-encoded certificate (whose
// SHA-256 is the sender's fingerprint) and Signature is an ECDSA signature,
// over hashDiscoveryPayload, proving the sender holds the matching private
// key. Seq is a per-sender monotonic counter used to reject replays.
type wireMessage struct {
	Id        string `json:"id"`
	Status    string `json:"status"`
	Port      int    `json:"port"`
	Seq       uint64 `json:"seq"`
	Cert      []byte `json:"cert"`
	Signature []byte `json:"signature"`
}

// discoveryDomain domain-separates the discovery signing scheme from any
// other use of an identity's key, so a signature can never be replayed
// across contexts.
const discoveryDomain = "snad-discovery-v1"

// hashDiscoveryPayload computes the fixed-size digest signed by the sender
// and re-derived by every receiver for a discovery announcement.
// Variable-length fields are length-prefixed so no combination of field
// values can be reinterpreted as a different set of fields.
func hashDiscoveryPayload(id, status string, port int, seq uint64, fingerprint [32]byte) []byte {
	h := sha256.New()
	h.Write([]byte(discoveryDomain))
	writeLenPrefixed(h, id)
	writeLenPrefixed(h, status)
	_ = binary.Write(h, binary.BigEndian, int64(port))
	_ = binary.Write(h, binary.BigEndian, seq)
	h.Write(fingerprint[:])
	return h.Sum(nil)
}

func writeLenPrefixed(h io.Writer, s string) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	h.Write(lenBuf[:])
	h.Write([]byte(s))
}

// verifyWireMessage checks msg is internally self-consistent and
// authentic: its embedded cert's SHA-256 is the fingerprint it implicitly
// claims, and its signature verifies against that cert's public key over
// the canonical signed payload. It does NOT check anti-replay or
// cross-message fingerprint pinning -- that's memberList's job (see
// admitHere/admitBye), done atomically with the state mutation.
func verifyWireMessage(msg wireMessage) (fingerprint [32]byte, ok bool) {
	if len(msg.Cert) == 0 || len(msg.Signature) == 0 {
		return [32]byte{}, false
	}
	cert, err := x509.ParseCertificate(msg.Cert)
	if err != nil {
		return [32]byte{}, false
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return [32]byte{}, false
	}
	fingerprint = sha256.Sum256(msg.Cert)
	digest := hashDiscoveryPayload(msg.Id, msg.Status, msg.Port, msg.Seq, fingerprint)
	if !ecdsa.VerifyASN1(pub, digest, msg.Signature) {
		return [32]byte{}, false
	}
	return fingerprint, true
}

// Member is a peer discovered in the snadbox, ready to be dialed directly
// over TCP+TLS once its advertised port is known.
type Member struct {
	Name        string
	IP          net.IP
	Port        int
	Fingerprint [32]byte
	LastSeen    time.Time
}

// Addr is the dialable host:port for this member's TCP+TLS listener.
func (m Member) Addr() string {
	return net.JoinHostPort(m.IP.String(), fmt.Sprintf("%d", m.Port))
}

// trustedPeer is the durable (never evicted by bye/sweep) trust anchor for
// a discovery name: the fingerprint first validly proven for that name,
// and the highest sequence number accepted from it. TOFU: the first
// validly-signed message for a name pins it for the life of this Snadbox
// process.
type trustedPeer struct {
	fingerprint [32]byte
	seq         uint64
}

type memberList struct {
	mu      sync.RWMutex
	members map[string]Member
	trust   map[string]trustedPeer
}

func newMemberList() *memberList {
	return &memberList{members: make(map[string]Member), trust: make(map[string]trustedPeer)}
}

// checkTrustLocked reports whether a message from name, claiming
// fingerprint and seq, is consistent with name's previously pinned trust
// state. Must be called with l.mu already held.
func (l *memberList) checkTrustLocked(name string, fingerprint [32]byte, seq uint64) bool {
	prev, seen := l.trust[name]
	if !seen {
		return true // first message ever for this name: TOFU-pin it
	}
	return fingerprint == prev.fingerprint && seq > prev.seq
}

// admitHere validates m's fingerprint/seq against pinned trust and, if
// admitted, updates both the trust anchor and the live members map
// atomically under one lock (no check-then-mutate race).
func (l *memberList) admitHere(m Member, seq uint64) (admitted, isNew bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.checkTrustLocked(m.Name, m.Fingerprint, seq) {
		return false, false
	}
	l.trust[m.Name] = trustedPeer{fingerprint: m.Fingerprint, seq: seq}
	_, existed := l.members[m.Name]
	l.members[m.Name] = m
	return true, !existed
}

// admitBye validates a bye's fingerprint/seq against pinned trust and, if
// admitted, advances the trust anchor and removes the member atomically.
func (l *memberList) admitBye(name string, fingerprint [32]byte, seq uint64) (admitted, existed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.checkTrustLocked(name, fingerprint, seq) {
		return false, false
	}
	l.trust[name] = trustedPeer{fingerprint: fingerprint, seq: seq}
	_, existed = l.members[name]
	delete(l.members, name)
	return true, existed
}

func (l *memberList) get(name string) (Member, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	m, ok := l.members[name]
	return m, ok
}

func (l *memberList) snapshot() []Member {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Member, 0, len(l.members))
	for _, m := range l.members {
		out = append(out, m)
	}
	return out
}

// sweepStale evicts members not seen within maxAge and returns their names.
func (l *memberList) sweepStale(maxAge time.Duration) []string {
	cutoff := time.Now().Add(-maxAge)
	l.mu.Lock()
	defer l.mu.Unlock()
	var evicted []string
	for name, m := range l.members {
		if m.LastSeen.Before(cutoff) {
			delete(l.members, name)
			evicted = append(evicted, name)
		}
	}
	return evicted
}

// Events emitted on a Snadbox's events channel for the TUI to consume.
type MemberJoined struct{ Member Member }
type MemberLeft struct{ Name string }

// Snadbox represents this device's membership in a UDP multicast discovery
// pool: it announces itself with a heartbeat, listens for other members,
// and evicts peers that stop announcing.
type Snadbox struct {
	Identity Identity

	conn    *net.UDPConn
	addr    *net.UDPAddr
	members *memberList
	events  chan<- interface{}

	portMu sync.RWMutex
	port   int

	seqMu sync.Mutex
	seq   uint64

	done chan struct{}
	wg   sync.WaitGroup
}

// Join generates a fresh identity, opens the multicast discovery socket,
// and starts the heartbeat/listen/sweep goroutines. The caller should call
// SetPort once its TCP listener is bound, and Leave when shutting down.
func Join(events chan<- interface{}) (*Snadbox, error) {
	identity, err := NewIdentity(nil)
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}

	addr, err := net.ResolveUDPAddr("udp4", PoolAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve pool address: %w", err)
	}

	conn, err := net.ListenMulticastUDP("udp4", multicastInterface(), addr)
	if err != nil {
		return nil, fmt.Errorf("join multicast pool: %w", err)
	}
	enableMulticastLoopback(conn)

	s := &Snadbox{
		Identity: identity,
		conn:     conn,
		addr:     addr,
		members:  newMemberList(),
		events:   events,
		done:     make(chan struct{}),
	}

	s.wg.Add(3)
	go s.heartbeatLoop()
	go s.listenLoop()
	go s.sweepLoop()

	return s, nil
}

// SetPort records the TCP port this device's receiver is listening on, so
// it can be advertised in subsequent heartbeats.
func (s *Snadbox) SetPort(port int) {
	s.portMu.Lock()
	s.port = port
	s.portMu.Unlock()
}

func (s *Snadbox) getPort() int {
	s.portMu.RLock()
	defer s.portMu.RUnlock()
	return s.port
}

// Members returns a snapshot of currently known peers.
func (s *Snadbox) Members() []Member {
	return s.members.snapshot()
}

// Member looks up a currently known peer by name.
func (s *Snadbox) Member(name string) (Member, bool) {
	return s.members.get(name)
}

// IsKnownFingerprint reports whether fingerprint belongs to any
// currently-discovered (and, thanks to signed discovery, cryptographically
// authenticated) member -- used by the receiver's TLS listener to reject
// connections from devices we haven't discovered as peers.
func (s *Snadbox) IsKnownFingerprint(fingerprint [32]byte) bool {
	for _, m := range s.members.snapshot() {
		if m.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// nextSeq returns the next monotonically increasing sequence number for
// this identity's outgoing announcements (starts at 1).
func (s *Snadbox) nextSeq() uint64 {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.seq++
	return s.seq
}

func (s *Snadbox) announce(status string) error {
	seq := s.nextSeq()
	port := s.getPort()
	digest := hashDiscoveryPayload(s.Identity.Name, status, port, seq, s.Identity.Fingerprint)
	sig, err := s.Identity.sign(digest)
	if err != nil {
		return fmt.Errorf("sign announce: %w", err)
	}
	msg := wireMessage{
		Id:        s.Identity.Name,
		Status:    status,
		Port:      port,
		Seq:       seq,
		Cert:      s.Identity.Cert.Certificate[0],
		Signature: sig,
	}
	enc, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = s.conn.WriteToUDP(enc, s.addr)
	return err
}

func (s *Snadbox) heartbeatLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(SignalInterval)
	defer ticker.Stop()

	_ = s.announce(statusHere)
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			_ = s.announce(statusHere)
		}
	}
}

func (s *Snadbox) listenLoop() {
	defer s.wg.Done()
	buf := make([]byte, 2048)
	for {
		if err := s.conn.SetReadDeadline(time.Now().Add(SignalInterval)); err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		n, src, err := s.conn.ReadFromUDP(buf)

		select {
		case <-s.done:
			return
		default:
		}
		if err != nil {
			continue // deadline timeout or transient error; loop and recheck done
		}

		var msg wireMessage
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			continue
		}
		if msg.Id == s.Identity.Name {
			continue // ignore our own announcements
		}

		fingerprint, ok := verifyWireMessage(msg)
		if !ok {
			continue // unsigned, malformed, or forged: drop silently
		}

		if msg.Status == statusBye {
			admitted, existed := s.members.admitBye(msg.Id, fingerprint, msg.Seq)
			if admitted && existed && s.events != nil {
				s.events <- MemberLeft{Name: msg.Id}
			}
			continue
		}

		member := Member{
			Name:        msg.Id,
			IP:          src.IP,
			Port:        msg.Port,
			Fingerprint: fingerprint,
			LastSeen:    time.Now(),
		}
		admitted, isNew := s.members.admitHere(member, msg.Seq)
		if admitted && isNew && s.events != nil {
			s.events <- MemberJoined{Member: member}
		}
	}
}

func (s *Snadbox) sweepLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(SignalInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			for _, name := range s.members.sweepStale(staleAfter) {
				if s.events != nil {
					s.events <- MemberLeft{Name: name}
				}
			}
		}
	}
}

// Leave announces departure, stops all goroutines, and closes the socket.
func (s *Snadbox) Leave() error {
	_ = s.announce(statusBye)
	close(s.done)
	err := s.conn.Close()
	s.wg.Wait()
	return err
}

// AllNames returns the set of currently known member names, used to avoid
// picking a colliding adjective-toy name.
func (s *Snadbox) AllNames() components.Set[string] {
	return s.members.names()
}

func (l *memberList) names() components.Set[string] {
	l.mu.RLock()
	defer l.mu.RUnlock()
	set := components.CreateSet[string]()
	for name := range l.members {
		set.Add(name)
	}
	return set
}
