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
	"net"
	"os"
	"path/filepath"
	"sync"

	"snad/components"
)

// mapDirectory records the names of all regular files currently in dir, so
// incoming transfers can be deduplicated against what's already present.
func mapDirectory(dir string) (components.Set[string], error) {
	set := components.CreateSet[string]()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			set.Add(entry.Name())
		}
	}

	return set, nil
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

		mu.Lock()
		skip := existing.Contains(header.Name)
		mu.Unlock()

		if err := writeAck(conn, !skip); err != nil {
			return
		}
		if skip {
			if events != nil {
				events <- TransferSkipped{Peer: peer, File: header.Name, Direction: DirectionRecv}
			}
			continue
		}

		if err := receiveFile(conn, reader, dir, header, peer, events); err != nil {
			if events != nil {
				events <- TransferError{Peer: peer, File: header.Name, Direction: DirectionRecv, Err: err}
			}
			return
		}

		mu.Lock()
		existing.Add(header.Name)
		mu.Unlock()
	}
}

// receiveFile streams one file's body from the connection to disk,
// verifying its checksum and emitting progress events along the way.
func receiveFile(conn net.Conn, reader *bufio.Reader, dir string, header FileHeader, peer string, events chan<- interface{}) error {
	dest := filepath.Join(dir, filepath.Base(header.Name))

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	defer out.Close()

	if events != nil {
		events <- TransferStarted{Peer: peer, File: header.Name, Size: header.Size, Direction: DirectionRecv}
	}

	hasher := sha256.New()
	progress := newProgressWriter(header.Size, func(written int64) {
		if events != nil {
			events <- TransferProgress{Peer: peer, File: header.Name, Sent: written, Total: header.Size, Direction: DirectionRecv}
		}
	})

	dst := io.MultiWriter(out, hasher, progress)
	if _, err := io.CopyN(dst, reader, header.Size); err != nil {
		return fmt.Errorf("receive body: %w", err)
	}

	if sum := hex.EncodeToString(hasher.Sum(nil)); sum != header.SHA256 {
		return fmt.Errorf("checksum mismatch for %s", header.Name)
	}

	if events != nil {
		events <- TransferDone{Peer: peer, File: header.Name, Direction: DirectionRecv}
	}
	return nil
}
