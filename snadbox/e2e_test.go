package snadbox

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDiscoveryParsesAnnounce verifies that Snadbox correctly parses an
// incoming UDP discovery announce and surfaces it as a MemberJoined event.
// A plain (non-multicast-member) UDP socket is used as the sender: Go's
// ListenMulticastUDP disables IP_MULTICAST_LOOP on its own socket (correct
// for real deployments, where two devices are two different hosts and
// don't need to hear their own announcements), so two Join()'d sockets on
// the *same* host in a test/dev sandbox won't hear each other. A plain
// sender socket sidesteps that self-loopback restriction, which is exactly
// the same mechanism a real second host on the LAN relies on.
func TestDiscoveryParsesAnnounce(t *testing.T) {
	events := make(chan interface{}, 8)
	box, err := Join(events)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	defer box.Leave()

	sender, err := net.DialUDP("udp4", nil, mustResolve(t, PoolAddress))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()

	var fp [32]byte
	fp[0] = 0xAB
	msg := wireMessage{
		Id:          "test-peer",
		Status:      statusHere,
		Fingerprint: hex.EncodeToString(fp[:]),
		Port:        4242,
	}
	enc, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for {
		if _, err := sender.Write(enc); err != nil {
			t.Fatalf("write announce: %v", err)
		}
		select {
		case e := <-events:
			joined, ok := e.(MemberJoined)
			if !ok {
				continue
			}
			if joined.Member.Name != "test-peer" || joined.Member.Port != 4242 {
				t.Fatalf("unexpected member: %+v", joined.Member)
			}
			if joined.Member.Fingerprint != fp {
				t.Fatalf("fingerprint mismatch: got %x want %x", joined.Member.Fingerprint, fp)
			}
			if m, ok := box.Member("test-peer"); !ok || m.Port != 4242 {
				t.Fatalf("member not tracked in Snadbox: %+v ok=%v", m, ok)
			}
			return
		case <-time.After(200 * time.Millisecond):
		case <-deadline:
			t.Fatal("timed out waiting for MemberJoined event")
		}
	}
}

func mustResolve(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestSendReceiveAndDedup exercises the full TCP+TLS transfer pipeline:
// fingerprint-pinned dial, header/ack framing, checksum verification, and
// receiver-side dedup against files already on disk. The peer is pointed
// directly at a loopback listener rather than discovered via UDP, since
// discovery itself is covered by TestDiscoveryParsesAnnounce.
func TestSendReceiveAndDedup(t *testing.T) {
	aDir := t.TempDir()
	bDir := t.TempDir()

	content := []byte("hello snad, this is a test file for end to end transfer verification.")
	srcPath := filepath.Join(aDir, "hello.txt")
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	identityA, err := NewIdentity(nil)
	if err != nil {
		t.Fatalf("identity a: %v", err)
	}
	identityB, err := NewIdentity(nil)
	if err != nil {
		t.Fatalf("identity b: %v", err)
	}

	bEvents := make(chan interface{}, 64)
	bLn, bPort, err := Listen(identityB)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer bLn.Close()
	go Serve(bLn, bDir, bEvents)

	peer := Member{
		Name:        identityB.Name,
		IP:          net.ParseIP("127.0.0.1"),
		Port:        bPort,
		Fingerprint: identityB.Fingerprint,
		LastSeen:    time.Now(),
	}

	aEvents := make(chan interface{}, 64)
	sender, err := NewSender(aDir)
	if err != nil {
		t.Fatal(err)
	}

	sender.Send(identityA, peer, []string{srcPath}, aEvents)

	waitForDone(t, aEvents, "send completion")
	waitForDone(t, bEvents, "receive completion")

	gotPath := filepath.Join(bDir, "hello.txt")
	got, err := os.ReadFile(gotPath)
	if err != nil {
		t.Fatalf("read received file: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: got %q want %q", got, content)
	}

	// A fresh Sender (bypassing sender-side already-sent tracking) still
	// gets skipped by the receiver's own dedup against its directory.
	sender2, err := NewSender(aDir)
	if err != nil {
		t.Fatal(err)
	}
	sender2.Send(identityA, peer, []string{srcPath}, aEvents)

	waitForSkipped(t, aEvents, "send-side dedup skip")
	waitForSkipped(t, bEvents, "receiver-side dedup skip")
}

// waitForDone blocks until a TransferDone event arrives on ch, failing the
// test on a TransferError or on timeout.
func waitForDone(t *testing.T, ch <-chan interface{}, what string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-ch:
			switch ev := e.(type) {
			case TransferDone:
				return
			case TransferError:
				t.Fatalf("transfer error waiting for %s: %v", what, ev.Err)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// waitForSkipped blocks until a TransferSkipped event arrives on ch.
func waitForSkipped(t *testing.T, ch <-chan interface{}, what string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-ch:
			switch ev := e.(type) {
			case TransferSkipped:
				return
			case TransferError:
				t.Fatalf("transfer error waiting for %s: %v", what, ev.Err)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// TestSenderRejectsOutsideBaseDir verifies the sandbox restriction that
// only files under the launch directory can be sent.
func TestSenderRejectsOutsideBaseDir(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()

	sender, err := NewSender(base)
	if err != nil {
		t.Fatal(err)
	}

	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}

	events := make(chan interface{}, 8)
	peer := Member{Name: "nobody", IP: net.ParseIP("127.0.0.1"), Port: 1, Fingerprint: [32]byte{}}
	sender.Send(NewTestIdentity(t), peer, []string{outsideFile}, events)

	select {
	case e := <-events:
		te, ok := e.(TransferError)
		if !ok {
			t.Fatalf("expected TransferError, got %#v", e)
		}
		if te.File != outsideFile {
			t.Fatalf("unexpected file in error: %+v", te)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for rejection error")
	}
}

// NewTestIdentity is a small helper so tests that don't care about the
// certificate/fingerprint don't have to handle NewIdentity's error.
func NewTestIdentity(t *testing.T) Identity {
	t.Helper()
	id, err := NewIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
