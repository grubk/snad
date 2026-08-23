package snadbox

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// mustResolve resolves addr, failing the test on error.
func mustResolve(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// mustMarshal JSON-encodes msg, failing the test on error.
func mustMarshal(t *testing.T, msg wireMessage) []byte {
	t.Helper()
	enc, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// buildSignedWireMessage constructs and signs a wireMessage exactly as
// announce() would, but lets the caller claim any id (not just sender's
// own name) -- used both to simulate a legitimate peer and to simulate an
// attacker who controls their own keypair but impersonates another name.
func buildSignedWireMessage(t *testing.T, sender Identity, id, status string, seq uint64, port int) wireMessage {
	t.Helper()
	digest := hashDiscoveryPayload(id, status, port, seq, sender.Fingerprint)
	sig, err := sender.sign(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return wireMessage{Id: id, Status: status, Port: port, Seq: seq, Cert: sender.Cert.Certificate[0], Signature: sig}
}

// newDiscoverySocket opens a plain (non-multicast-member) UDP socket for
// sending directly to the discovery pool address. Go's ListenMulticastUDP
// disables IP_MULTICAST_LOOP on its own socket (correct for real
// deployments, where two devices are two different hosts and don't need to
// hear their own announcements), so a Join()'d Snadbox on the *same* host
// in a test/dev sandbox won't hear another Join()'d Snadbox. A plain
// sender socket sidesteps that self-loopback restriction, which is exactly
// the same mechanism a real second host on the LAN relies on.
func newDiscoverySocket(t *testing.T) *net.UDPConn {
	t.Helper()
	sock, err := net.DialUDP("udp4", nil, mustResolve(t, PoolAddress))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { sock.Close() })
	return sock
}

func sendUDP(t *testing.T, sock *net.UDPConn, enc []byte) {
	t.Helper()
	if _, err := sock.Write(enc); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// sendAndSettle sends enc a handful of times with small pauses, giving a
// message that should be rejected every opportunity to (incorrectly)
// affect state, without looping forever the way a should-succeed wait
// would.
func sendAndSettle(t *testing.T, sock *net.UDPConn, enc []byte) {
	t.Helper()
	for i := 0; i < 5; i++ {
		sendUDP(t, sock, enc)
		time.Sleep(100 * time.Millisecond)
	}
}

// pollMember resends enc until check(box.Member(name)) is satisfied or the
// deadline elapses.
func pollMember(t *testing.T, box *Snadbox, sock *net.UDPConn, enc []byte, name string, check func(Member, bool) bool) Member {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		sendUDP(t, sock, enc)
		if m, ok := box.Member(name); check(m, ok) {
			return m
		}
		select {
		case <-time.After(150 * time.Millisecond):
		case <-deadline:
			t.Fatal("timed out waiting for expected member state")
		}
	}
}

// pollMemberGone resends enc until box.Member(name) reports absent.
func pollMemberGone(t *testing.T, box *Snadbox, sock *net.UDPConn, enc []byte, name string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		sendUDP(t, sock, enc)
		if _, ok := box.Member(name); !ok {
			return
		}
		select {
		case <-time.After(150 * time.Millisecond):
		case <-deadline:
			t.Fatal("timed out waiting for member to be evicted")
		}
	}
}

// TestDiscoveryAcceptsValidSignedAnnounce verifies a validly-signed "here"
// is admitted and surfaced as MemberJoined.
func TestDiscoveryAcceptsValidSignedAnnounce(t *testing.T) {
	events := make(chan interface{}, 8)
	box, err := Join(events)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	defer box.Leave()

	sock := newDiscoverySocket(t)
	peer := NewTestIdentity(t)
	enc := mustMarshal(t, buildSignedWireMessage(t, peer, peer.Name, statusHere, 1, 4242))

	deadline := time.After(5 * time.Second)
	for {
		sendUDP(t, sock, enc)
		select {
		case e := <-events:
			joined, ok := e.(MemberJoined)
			if !ok {
				continue
			}
			if joined.Member.Name != peer.Name || joined.Member.Port != 4242 {
				t.Fatalf("unexpected member: %+v", joined.Member)
			}
			if joined.Member.Fingerprint != peer.Fingerprint {
				t.Fatalf("fingerprint mismatch: got %x want %x", joined.Member.Fingerprint, peer.Fingerprint)
			}
			if m, ok := box.Member(peer.Name); !ok || m.Port != 4242 {
				t.Fatalf("member not tracked in Snadbox: %+v ok=%v", m, ok)
			}
			return
		case <-time.After(200 * time.Millisecond):
		case <-deadline:
			t.Fatal("timed out waiting for MemberJoined event")
		}
	}
}

// TestDiscoveryRejectsFingerprintMismatchForKnownName is the core
// anti-spoofing regression test: once a name is pinned to a fingerprint,
// a different keypair claiming that name must be rejected, even though
// its message is validly self-signed.
func TestDiscoveryRejectsFingerprintMismatchForKnownName(t *testing.T) {
	events := make(chan interface{}, 16)
	box, err := Join(events)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	defer box.Leave()

	sock := newDiscoverySocket(t)

	victim := NewTestIdentity(t)
	hello := mustMarshal(t, buildSignedWireMessage(t, victim, victim.Name, statusHere, 1, 1111))
	pollMember(t, box, sock, hello, victim.Name, func(m Member, ok bool) bool { return ok && m.Port == 1111 })

	attacker := NewTestIdentity(t) // independently-keyed, no relation to victim
	forged := mustMarshal(t, buildSignedWireMessage(t, attacker, victim.Name, statusHere, 2, 9999))
	sendAndSettle(t, sock, forged)

	m, ok := box.Member(victim.Name)
	if !ok || m.Port != 1111 || m.Fingerprint != victim.Fingerprint {
		t.Fatalf("member state was corrupted by forged message: %+v ok=%v", m, ok)
	}
}

// TestDiscoveryReplayedByeIgnoredAfterReannounce is the core anti-replay
// regression test: a captured "bye" replayed after the peer re-announces
// must not evict it.
func TestDiscoveryReplayedByeIgnoredAfterReannounce(t *testing.T) {
	events := make(chan interface{}, 16)
	box, err := Join(events)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	defer box.Leave()

	sock := newDiscoverySocket(t)
	peer := NewTestIdentity(t)

	here1 := mustMarshal(t, buildSignedWireMessage(t, peer, peer.Name, statusHere, 1, 100))
	pollMember(t, box, sock, here1, peer.Name, func(m Member, ok bool) bool { return ok && m.Port == 100 })

	bye := mustMarshal(t, buildSignedWireMessage(t, peer, peer.Name, statusBye, 2, 100))
	pollMemberGone(t, box, sock, bye, peer.Name)

	here2 := mustMarshal(t, buildSignedWireMessage(t, peer, peer.Name, statusHere, 3, 200))
	pollMember(t, box, sock, here2, peer.Name, func(m Member, ok bool) bool { return ok && m.Port == 200 })

	// Replay the captured (now-stale) bye: must be a no-op.
	sendAndSettle(t, sock, bye)

	m, ok := box.Member(peer.Name)
	if !ok || m.Port != 200 {
		t.Fatalf("replayed bye affected membership: %+v ok=%v", m, ok)
	}
}

// TestDiscoveryRejectsStaleOrDuplicateSeq verifies sequence numbers must
// strictly increase per name.
func TestDiscoveryRejectsStaleOrDuplicateSeq(t *testing.T) {
	events := make(chan interface{}, 16)
	box, err := Join(events)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	defer box.Leave()

	sock := newDiscoverySocket(t)
	peer := NewTestIdentity(t)

	seq5 := mustMarshal(t, buildSignedWireMessage(t, peer, peer.Name, statusHere, 5, 4444))
	pollMember(t, box, sock, seq5, peer.Name, func(m Member, ok bool) bool { return ok && m.Port == 4444 })

	dup5 := mustMarshal(t, buildSignedWireMessage(t, peer, peer.Name, statusHere, 5, 5555))
	sendAndSettle(t, sock, dup5)
	if m, _ := box.Member(peer.Name); m.Port != 4444 {
		t.Fatalf("duplicate seq changed member state: %+v", m)
	}

	lower3 := mustMarshal(t, buildSignedWireMessage(t, peer, peer.Name, statusHere, 3, 6666))
	sendAndSettle(t, sock, lower3)
	if m, _ := box.Member(peer.Name); m.Port != 4444 {
		t.Fatalf("stale seq changed member state: %+v", m)
	}

	seq6 := mustMarshal(t, buildSignedWireMessage(t, peer, peer.Name, statusHere, 6, 7777))
	pollMember(t, box, sock, seq6, peer.Name, func(m Member, ok bool) bool { return ok && m.Port == 7777 })
}

// TestDiscoveryRejectsTamperedMessage verifies malformed/tampered messages
// never result in an admitted member.
func TestDiscoveryRejectsTamperedMessage(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(msg *wireMessage)
	}{
		{"flipped signature byte", func(msg *wireMessage) {
			if len(msg.Signature) > 0 {
				msg.Signature[0] ^= 0xFF
			}
		}},
		{"garbage cert", func(msg *wireMessage) { msg.Cert = []byte("not a certificate") }},
		{"empty signature", func(msg *wireMessage) { msg.Signature = nil }},
		{"empty cert", func(msg *wireMessage) { msg.Cert = nil }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := make(chan interface{}, 8)
			box, err := Join(events)
			if err != nil {
				t.Fatalf("join: %v", err)
			}
			defer box.Leave()

			sock := newDiscoverySocket(t)
			peer := NewTestIdentity(t)
			msg := buildSignedWireMessage(t, peer, peer.Name, statusHere, 1, 555)
			tc.corrupt(&msg)
			enc := mustMarshal(t, msg)

			sendAndSettle(t, sock, enc)

			if _, ok := box.Member(peer.Name); ok {
				t.Fatalf("tampered message (%s) was incorrectly admitted", tc.name)
			}
		})
	}
}

// TestDiscoverySelfAnnouncementsIgnored verifies the self-name filter
// still works with the signed wire format.
func TestDiscoverySelfAnnouncementsIgnored(t *testing.T) {
	events := make(chan interface{}, 8)
	box, err := Join(events)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	defer box.Leave()

	sock := newDiscoverySocket(t)
	enc := mustMarshal(t, buildSignedWireMessage(t, box.Identity, box.Identity.Name, statusHere, 999, 42))

	sendAndSettle(t, sock, enc)

	if _, ok := box.Member(box.Identity.Name); ok {
		t.Fatalf("self-announcement should be ignored, not tracked as a member")
	}
}
