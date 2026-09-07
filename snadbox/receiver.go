/*
* After receiver is in the snadbox,
* waits for sender to connect, receives files:
*
* - Store directory contents
* - Wait for sender to connect
* - Receive files, add to stored directory contents (no duplicates)
 */

package snadbox

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"snad/components"
)

// mapDirectory records the slash-separated relative paths of all regular
// files currently under dir (recursively), so incoming transfers can be
// deduplicated against what's already present. Symlinks are excluded,
// matching the sender-side symlink skip in expandDirectory.
func mapDirectory(dir string) (components.Set[string], error) {
	set := components.CreateSet[string]()

	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		set.Add(filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	return set, nil
}

// safeJoin validates that rel -- a slash-separated relative path taken
// verbatim from a peer's FileHeader.Path -- resolves to a location inside
// dir, and returns that location using this OS's native separators. It is
// the receiver-side counterpart to Sender.resolve: the sender enforces its
// sandbox on reads, safeJoin enforces the equivalent sandbox on writes,
// since the wire is not a trusted input.
func safeJoin(dir, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty relative path")
	}
	if strings.Contains(rel, `\`) {
		return "", fmt.Errorf("relative path %q must not contain backslashes", rel)
	}
	if path.IsAbs(rel) {
		return "", fmt.Errorf("relative path %q must not be absolute", rel)
	}

	cleaned := path.Clean(rel)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("relative path %q escapes the receive directory", rel)
	}

	dest := filepath.Join(dir, filepath.FromSlash(cleaned))

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve receive directory: %w", err)
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", fmt.Errorf("resolve destination: %w", err)
	}
	relCheck, err := filepath.Rel(absDir, absDest)
	if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("relative path %q escapes the receive directory", rel)
	}
	return absDest, nil
}

// Listen opens a TLS listener on an OS-assigned port, presenting identity's
// self-signed certificate to connecting senders and rejecting any
// connection whose client certificate fingerprint isKnownPeer doesn't
// recognize. The caller advertises the returned port via Snadbox.SetPort
// and runs Serve in a goroutine.
func Listen(identity Identity, isKnownPeer func(fingerprint [32]byte) bool) (net.Listener, int, error) {
	ln, err := tls.Listen("tcp", ":0", serverTLSConfig(identity, isKnownPeer))
	if err != nil {
		return nil, 0, fmt.Errorf("listen: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	return ln, port, nil
}

// Serve accepts incoming connections and receives files into dir, skipping
// any file whose name is already present there. It blocks until ln is
// closed, at which point it returns the listener's closing error.
func Serve(ln net.Listener, dir string, events chan<- interface{}) error {
	existing, err := mapDirectory(dir)
	if err != nil {
		existing = components.CreateSet[string]()
	}
	var mu sync.Mutex

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn, dir, existing, &mu, events)
	}
}

// handleConn services one sender's connection, which may stream multiple
// files back-to-back before closing.
func handleConn(conn net.Conn, dir string, existing components.Set[string], mu *sync.Mutex, events chan<- interface{}) {
	defer conn.Close()

	peer := conn.RemoteAddr().String()
	reader := bufio.NewReader(conn)

	for {
		header, err := readHeader(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) && events != nil {
				events <- TransferError{Peer: peer, Direction: DirectionRecv, Err: err}
			}
			return
		}

		dest, err := safeJoin(dir, header.Path)
		if err != nil {
			if events != nil {
				events <- TransferError{Peer: peer, File: header.Path, Direction: DirectionRecv, Err: err}
			}
			return
		}

		mu.Lock()
		skip := existing.Contains(header.Path)
		mu.Unlock()

		if err := writeAck(conn, !skip); err != nil {
			return
		}
		if skip {
			if events != nil {
				events <- TransferSkipped{Peer: peer, File: header.Path, Direction: DirectionRecv}
			}
			continue
		}

		if err := receiveFile(conn, reader, dest, header, peer, events); err != nil {
			if events != nil {
				events <- TransferError{Peer: peer, File: header.Path, Direction: DirectionRecv, Err: err}
			}
			return
		}

		mu.Lock()
		existing.Add(header.Path)
		mu.Unlock()
	}
}

// receiveFile streams one file's body from the connection to disk,
// verifying its checksum and emitting progress events along the way. dest
// is the already-validated destination path (see safeJoin).
func receiveFile(conn net.Conn, reader *bufio.Reader, dest string, header FileHeader, peer string, events chan<- interface{}) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("create directories for %s: %w", dest, err)
	}

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	defer out.Close()

	if events != nil {
		events <- TransferStarted{Peer: peer, File: header.Path, Size: header.Size, Direction: DirectionRecv}
	}

	hasher := sha256.New()
	progress := newProgressWriter(header.Size, func(written int64) {
		if events != nil {
			events <- TransferProgress{Peer: peer, File: header.Path, Sent: written, Total: header.Size, Direction: DirectionRecv}
		}
	})

	dst := io.MultiWriter(out, hasher, progress)
	if _, err := io.CopyN(dst, reader, header.Size); err != nil {
		return fmt.Errorf("receive body: %w", err)
	}

	if sum := hex.EncodeToString(hasher.Sum(nil)); sum != header.SHA256 {
		return fmt.Errorf("checksum mismatch for %s", header.Path)
	}

	if events != nil {
		events <- TransferDone{Peer: peer, File: header.Path, Direction: DirectionRecv}
	}
	return nil
}
