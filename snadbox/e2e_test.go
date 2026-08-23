package snadbox

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSendReceiveAndDedup exercises the full TCP+TLS transfer pipeline:
// fingerprint-pinned dial, mutual-TLS peer authentication, header/ack
// framing, checksum verification, and receiver-side dedup against files
// already on disk. The peer is pointed directly at a loopback listener
// rather than discovered via UDP, since discovery itself is covered by
// discovery_test.go.
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

	isKnownPeer := func(fp [32]byte) bool { return fp == identityA.Fingerprint }

	bEvents := make(chan interface{}, 64)
	bLn, bPort, err := Listen(identityB, isKnownPeer)
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

// TestReceiverRejectsUnknownFingerprint verifies the receiver's mutual-TLS
// check: a sender whose certificate fingerprint isKnownPeer doesn't
// recognize must be rejected at the handshake, not merely at the
// application layer.
func TestReceiverRejectsUnknownFingerprint(t *testing.T) {
	dir := t.TempDir()

	receiverIdentity := NewTestIdentity(t)
	knownIdentity := NewTestIdentity(t)
	strangerIdentity := NewTestIdentity(t)

	isKnownPeer := func(fp [32]byte) bool { return fp == knownIdentity.Fingerprint }

	events := make(chan interface{}, 8)
	ln, port, err := Listen(receiverIdentity, isKnownPeer)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go Serve(ln, dir, events)

	peer := Member{
		Name:        receiverIdentity.Name,
		IP:          net.ParseIP("127.0.0.1"),
		Port:        port,
		Fingerprint: receiverIdentity.Fingerprint,
		LastSeen:    time.Now(),
	}

	srcPath := filepath.Join(t.TempDir(), "nope.txt")
	if err := os.WriteFile(srcPath, []byte("should not arrive"), 0o644); err != nil {
		t.Fatal(err)
	}

	sender, err := NewSender(filepath.Dir(srcPath))
	if err != nil {
		t.Fatal(err)
	}

	senderEvents := make(chan interface{}, 8)
	sender.Send(strangerIdentity, peer, []string{srcPath}, senderEvents)

	select {
	case e := <-senderEvents:
		if _, ok := e.(TransferError); !ok {
			t.Fatalf("expected TransferError for unknown-fingerprint sender, got %#v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the handshake to be rejected")
	}

	if _, err := os.Stat(filepath.Join(dir, "nope.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected no file to be written, stat error: %v", err)
	}
}
