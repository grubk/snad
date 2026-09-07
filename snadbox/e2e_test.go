package snadbox

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"snad/components"
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

// waitForNDone blocks until n TransferDone events have arrived on ch,
// tolerating interleaved ordering (the sender's worker pool doesn't
// guarantee an order across multiple files), failing on any TransferError.
func waitForNDone(t *testing.T, ch <-chan interface{}, n int, what string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	seen := 0
	for seen < n {
		select {
		case e := <-ch:
			switch ev := e.(type) {
			case TransferDone:
				seen++
			case TransferError:
				t.Fatalf("transfer error waiting for %s: %v", what, ev.Err)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s (%d/%d done)", what, seen, n)
		}
	}
}

func newLoopbackPeer(t *testing.T, dir string, receiverIdentity Identity, isKnownPeer func([32]byte) bool) (Member, chan interface{}) {
	t.Helper()
	events := make(chan interface{}, 64)
	ln, port, err := Listen(receiverIdentity, isKnownPeer)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go Serve(ln, dir, events)

	return Member{
		Name:        receiverIdentity.Name,
		IP:          net.ParseIP("127.0.0.1"),
		Port:        port,
		Fingerprint: receiverIdentity.Fingerprint,
		LastSeen:    time.Now(),
	}, events
}

// TestSendReceiveDirectoryPreservesStructure verifies that sending a
// directory argument recursively transmits every file inside it and
// reconstructs the same nested structure under the receiver's directory.
func TestSendReceiveDirectoryPreservesStructure(t *testing.T) {
	aDir := t.TempDir()
	bDir := t.TempDir()

	photosDir := filepath.Join(aDir, "photos")
	if err := os.MkdirAll(filepath.Join(photosDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	aContent := []byte("a.jpg content")
	bContent := []byte("sub/b.jpg content")
	if err := os.WriteFile(filepath.Join(photosDir, "a.jpg"), aContent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(photosDir, "sub", "b.jpg"), bContent, 0o644); err != nil {
		t.Fatal(err)
	}

	identityA := NewTestIdentity(t)
	identityB := NewTestIdentity(t)
	isKnownPeer := func(fp [32]byte) bool { return fp == identityA.Fingerprint }
	peer, bEvents := newLoopbackPeer(t, bDir, identityB, isKnownPeer)

	sender, err := NewSender(aDir)
	if err != nil {
		t.Fatal(err)
	}
	aEvents := make(chan interface{}, 64)
	sender.Send(identityA, peer, []string{photosDir}, aEvents)

	waitForNDone(t, aEvents, 2, "send completion")
	waitForNDone(t, bEvents, 2, "receive completion")

	got, err := os.ReadFile(filepath.Join(bDir, "photos", "a.jpg"))
	if err != nil {
		t.Fatalf("read photos/a.jpg: %v", err)
	}
	if string(got) != string(aContent) {
		t.Fatalf("photos/a.jpg content mismatch: got %q want %q", got, aContent)
	}

	got, err = os.ReadFile(filepath.Join(bDir, "photos", "sub", "b.jpg"))
	if err != nil {
		t.Fatalf("read photos/sub/b.jpg: %v", err)
	}
	if string(got) != string(bContent) {
		t.Fatalf("photos/sub/b.jpg content mismatch: got %q want %q", got, bContent)
	}
}

// TestSendReceiveDirectoryPartialDuplicateSkip verifies that when one file
// under a sent folder is already present on the receiver, only that file is
// skipped -- the rest of the folder is still sent.
func TestSendReceiveDirectoryPartialDuplicateSkip(t *testing.T) {
	aDir := t.TempDir()
	bDir := t.TempDir()

	photosDir := filepath.Join(aDir, "photos")
	if err := os.MkdirAll(filepath.Join(photosDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	aContent := []byte("a.jpg content")
	bContent := []byte("sub/b.jpg content")
	if err := os.WriteFile(filepath.Join(photosDir, "a.jpg"), aContent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(photosDir, "sub", "b.jpg"), bContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// Pre-place photos/a.jpg on the receiver so it should be skipped;
	// photos/sub/b.jpg is absent and should be transferred.
	if err := os.MkdirAll(filepath.Join(bDir, "photos"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bDir, "photos", "a.jpg"), aContent, 0o644); err != nil {
		t.Fatal(err)
	}

	identityA := NewTestIdentity(t)
	identityB := NewTestIdentity(t)
	isKnownPeer := func(fp [32]byte) bool { return fp == identityA.Fingerprint }
	peer, bEvents := newLoopbackPeer(t, bDir, identityB, isKnownPeer)

	sender, err := NewSender(aDir)
	if err != nil {
		t.Fatal(err)
	}
	aEvents := make(chan interface{}, 64)
	sender.Send(identityA, peer, []string{photosDir}, aEvents)

	deadline := time.After(5 * time.Second)
	var done, skipped []string
	for len(done)+len(skipped) < 2 {
		select {
		case e := <-bEvents:
			switch ev := e.(type) {
			case TransferDone:
				done = append(done, ev.File)
			case TransferSkipped:
				skipped = append(skipped, ev.File)
			case TransferError:
				t.Fatalf("unexpected transfer error: %v", ev.Err)
			}
		case <-deadline:
			t.Fatalf("timed out: done=%v skipped=%v", done, skipped)
		}
	}

	if len(skipped) != 1 || skipped[0] != "photos/a.jpg" {
		t.Fatalf("expected photos/a.jpg to be skipped, got skipped=%v", skipped)
	}
	if len(done) != 1 || done[0] != "photos/sub/b.jpg" {
		t.Fatalf("expected photos/sub/b.jpg to be sent, got done=%v", done)
	}

	got, err := os.ReadFile(filepath.Join(bDir, "photos", "sub", "b.jpg"))
	if err != nil {
		t.Fatalf("read photos/sub/b.jpg: %v", err)
	}
	if string(got) != string(bContent) {
		t.Fatalf("photos/sub/b.jpg content mismatch: got %q want %q", got, bContent)
	}
}

// TestSendDirectorySkipsSymlinks verifies that a symlink dropped inside a
// sent folder is never enumerated as a job -- it must not be transmitted,
// and no event should ever reference it, since it could otherwise be used
// to exfiltrate a file from outside the folder the sender intended to
// share.
func TestSendDirectorySkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on windows")
	}

	aDir := t.TempDir()
	bDir := t.TempDir()
	outside := t.TempDir()

	photosDir := filepath.Join(aDir, "photos")
	if err := os.MkdirAll(photosDir, 0o755); err != nil {
		t.Fatal(err)
	}
	aContent := []byte("a.jpg content")
	if err := os.WriteFile(filepath.Join(photosDir, "a.jpg"), aContent, 0o644); err != nil {
		t.Fatal(err)
	}

	secretContent := []byte("top secret, must never leave outside/")
	secretPath := filepath.Join(outside, "secret.jpg")
	if err := os.WriteFile(secretPath, secretContent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretPath, filepath.Join(photosDir, "evil")); err != nil {
		t.Fatal(err)
	}

	identityA := NewTestIdentity(t)
	identityB := NewTestIdentity(t)
	isKnownPeer := func(fp [32]byte) bool { return fp == identityA.Fingerprint }
	peer, bEvents := newLoopbackPeer(t, bDir, identityB, isKnownPeer)

	sender, err := NewSender(aDir)
	if err != nil {
		t.Fatal(err)
	}
	aEvents := make(chan interface{}, 64)
	sender.Send(identityA, peer, []string{photosDir}, aEvents)

	waitForNDone(t, aEvents, 1, "send completion")
	waitForNDone(t, bEvents, 1, "receive completion")

	// Give any stray event for the symlink a chance to arrive before
	// asserting it never did.
	select {
	case e := <-bEvents:
		t.Fatalf("unexpected extra event referencing the symlink: %#v", e)
	case <-time.After(200 * time.Millisecond):
	}

	if _, err := os.Stat(filepath.Join(bDir, "photos", "evil")); !os.IsNotExist(err) {
		t.Fatalf("expected photos/evil to not exist, stat error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(bDir, "photos", "a.jpg"))
	if err != nil {
		t.Fatalf("read photos/a.jpg: %v", err)
	}
	if string(got) != string(aContent) {
		t.Fatalf("photos/a.jpg content mismatch: got %q want %q", got, aContent)
	}
}

// TestReceiverRejectsPathTraversalHeader verifies handleConn's safeJoin
// validation: a header claiming a path outside the receive directory must
// be rejected as a protocol violation (connection closed, TransferError
// emitted), never written to disk. A conforming Sender can never produce
// such a header, so this drives handleConn directly over a net.Pipe.
func TestReceiverRejectsPathTraversalHeader(t *testing.T) {
	dir := t.TempDir()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	existing := components.CreateSet[string]()
	var mu sync.Mutex
	events := make(chan interface{}, 8)

	done := make(chan struct{})
	go func() {
		handleConn(serverConn, dir, existing, &mu, events)
		close(done)
	}()

	header := FileHeader{Path: "../../etc/passwd", Size: 0, SHA256: ""}
	if err := writeHeader(clientConn, header); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}

	select {
	case e := <-events:
		te, ok := e.(TransferError)
		if !ok {
			t.Fatalf("expected TransferError, got %#v", e)
		}
		if te.File != header.Path {
			t.Fatalf("unexpected file in error: %+v", te)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TransferError")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleConn to close the connection")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files written to the receive dir, got %v", entries)
	}
}
