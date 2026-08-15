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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
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

// wireMessage is the JSON payload multicast over UDP for discovery.
type wireMessage struct {
	Id          string `json:"id"`
	Status      string `json:"status"`
	Fingerprint string `json:"fingerprint"`
	Port        int    `json:"port"`
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

type memberList struct {
	mu      sync.RWMutex
	members map[string]Member
}

func newMemberList() *memberList {
	return &memberList{members: make(map[string]Member)}
}

func (l *memberList) upsert(m Member) (isNew bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, existed := l.members[m.Name]
	l.members[m.Name] = m
	return !existed
}

func (l *memberList) remove(name string) (existed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, existed = l.members[name]
	delete(l.members, name)
	return existed
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

func (s *Snadbox) announce(status string) error {
	msg := wireMessage{
		Id:          s.Identity.Name,
		Status:      status,
		Fingerprint: hex.EncodeToString(s.Identity.Fingerprint[:]),
		Port:        s.getPort(),
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
		_ = s.conn.SetReadDeadline(time.Now().Add(SignalInterval))
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

		if msg.Status == statusBye {
			if s.members.remove(msg.Id) && s.events != nil {
				s.events <- MemberLeft{Name: msg.Id}
			}
			continue
		}

		fingerprint, err := hex.DecodeString(msg.Fingerprint)
		if err != nil || len(fingerprint) != 32 {
			continue
		}
		var fp [32]byte
		copy(fp[:], fingerprint)

		member := Member{
			Name:        msg.Id,
			IP:          src.IP,
			Port:        msg.Port,
			Fingerprint: fp,
			LastSeen:    time.Now(),
		}
		isNew := s.members.upsert(member)
		if isNew && s.events != nil {
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
