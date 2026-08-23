/*
* Shared wire protocol used by sender.go and receiver.go over the direct
* TCP+TLS connection between two peers:
*
* - FileHeader: a newline-delimited JSON header preceding each file's raw
*   bytes on the wire (name, size, checksum)
* - TLS helpers implementing trust-on-first-use certificate pinning: the
*   sender already knows the receiver's certificate fingerprint from the
*   UDP discovery announce, so no CA is needed
 */

package snadbox

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
)

type FileHeader struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func writeHeader(w io.Writer, h FileHeader) error {
	enc, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("encode file header: %w", err)
	}
	enc = append(enc, '\n')
	if _, err := w.Write(enc); err != nil {
		return fmt.Errorf("write file header: %w", err)
	}
	return nil
}

func readHeader(r *bufio.Reader) (FileHeader, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return FileHeader{}, fmt.Errorf("read file header: %w", err)
	}
	var h FileHeader
	if err := json.Unmarshal([]byte(line), &h); err != nil {
		return FileHeader{}, fmt.Errorf("decode file header: %w", err)
	}
	return h, nil
}

const (
	ackSkip   byte = 0
	ackAccept byte = 1
)

// writeAck tells the sender whether to stream the file body (accept) or
// move straight to the next file (skip, e.g. already present on disk).
func writeAck(w io.Writer, accept bool) error {
	b := ackSkip
	if accept {
		b = ackAccept
	}
	_, err := w.Write([]byte{b})
	return err
}

func readAck(r io.Reader) (bool, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return false, fmt.Errorf("read ack: %w", err)
	}
	return b[0] == ackAccept, nil
}

// clientTLSConfig is used by the sender to dial a peer, pinning the
// connection to the fingerprint that peer advertised over UDP discovery
// instead of validating a CA chain.
func clientTLSConfig(local Identity, expectedFingerprint [32]byte) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{local.Cert},
		InsecureSkipVerify: true, // verified manually below via fingerprint pinning
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer presented no certificate")
			}
			if sha256.Sum256(rawCerts[0]) != expectedFingerprint {
				return fmt.Errorf("certificate fingerprint mismatch: peer identity changed since discovery")
			}
			return nil
		},
	}
}

// serverTLSConfig is used by the receiver's listener to present its
// self-signed certificate to connecting senders, and to require and check
// the connecting sender's certificate against isKnownPeer -- so only
// devices we've actually discovered (via authenticated UDP discovery) can
// push files, rather than any device that can reach the listening port.
func serverTLSConfig(local Identity, isKnownPeer func(fingerprint [32]byte) bool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{local.Cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("client presented no certificate")
			}
			if !isKnownPeer(sha256.Sum256(rawCerts[0])) {
				return fmt.Errorf("client certificate fingerprint is not a known peer")
			}
			return nil
		},
	}
}

// progressWriter is a no-op io.Writer that throttles a callback to roughly
// 100 evenly-spaced updates per file, so the TUI's progress bar animates
// smoothly without flooding the events channel on every read.
type progressWriter struct {
	total    int64
	written  int64
	step     int64
	lastEmit int64
	onUpdate func(written int64)
}

func newProgressWriter(total int64, onUpdate func(written int64)) *progressWriter {
	step := total / 100
	if step < 32*1024 {
		step = 32 * 1024
	}
	return &progressWriter{total: total, step: step, onUpdate: onUpdate}
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n := len(b)
	p.written += int64(n)
	if p.onUpdate != nil && (p.written-p.lastEmit >= p.step || p.written == p.total) {
		p.lastEmit = p.written
		p.onUpdate(p.written)
	}
	return n, nil
}
