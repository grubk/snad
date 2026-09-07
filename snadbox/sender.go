/*
* Contains logic for establishing a connection
* and sending data to the receiver using TCP:
*
* - Connect to a receiver's ip over the network
* - Accepts multiple arguments, multiple calls for files to send
* - Only access directory where snad is opened
* - Store directories of sent files so same file cannot be sent twice
* - Distribute threads amongst files
 */

package snadbox

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"snad/components"
)

// Sender tracks files already sent during this process's lifetime, so
// re-selecting the same peer (or the same files again) doesn't resend
// files unnecessarily.
type Sender struct {
	baseDir string
	sentMu  sync.Mutex
	sent    components.Set[string]
}

// sendJob pairs a file's absolute path on local disk with the
// slash-separated path used to identify it on the wire (FileHeader.Path)
// and let the receiver reconstruct directory structure.
type sendJob struct {
	abs string
	rel string
}

// NewSender sandboxes file access to baseDir (the directory snad was
// launched from) -- any file argument outside baseDir is rejected.
func NewSender(baseDir string) (*Sender, error) {
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve base directory: %w", err)
	}
	return &Sender{baseDir: abs, sent: components.CreateSet[string]()}, nil
}

// resolve validates that path lies within the sender's base directory and
// returns its cleaned absolute form.
func (s *Sender) resolve(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	rel, err := filepath.Rel(s.baseDir, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the launch directory", path)
	}
	return abs, nil
}

// expandDirectory recursively walks dirArg -- an already sandbox-validated
// absolute path that Send determined is a directory -- into one sendJob per
// regular file found. Symlinks are skipped entirely: they are never checked
// against the sandbox perimeter enforced by resolve, so following one could
// exfiltrate content from outside the sent folder.
func expandDirectory(dirArg string) ([]sendJob, error) {
	walkRoot := dirArg
	lst, err := os.Lstat(dirArg)
	if err != nil {
		return nil, err
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		walkRoot, err = filepath.EvalSymlinks(dirArg)
		if err != nil {
			return nil, err
		}
	}
	parentDisplay := filepath.Base(dirArg)

	var jobs []sendJob
	err = filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(walkRoot, p)
		if err != nil {
			return err
		}
		jobs = append(jobs, sendJob{abs: p, rel: filepath.ToSlash(filepath.Join(parentDisplay, rel))})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return jobs, nil
}

// Send dials peer over TLS (pinned to its discovered fingerprint) once per
// file, distributing the work across a bounded worker pool so multiple
// files transfer concurrently. A directory argument is expanded recursively
// into one job per regular file inside it, preserving its relative
// structure on the wire.
func (s *Sender) Send(local Identity, peer Member, files []string, events chan<- interface{}) {
	var queue []sendJob
	for _, f := range files {
		abs, err := s.resolve(f)
		if err != nil {
			if events != nil {
				events <- TransferError{Peer: peer.Name, File: f, Direction: DirectionSend, Err: err}
			}
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			if events != nil {
				events <- TransferError{Peer: peer.Name, File: f, Direction: DirectionSend, Err: err}
			}
			continue
		}
		if info.IsDir() {
			jobs, err := expandDirectory(abs)
			if err != nil {
				if events != nil {
					events <- TransferError{Peer: peer.Name, File: f, Direction: DirectionSend, Err: err}
				}
				continue
			}
			queue = append(queue, jobs...)
			continue
		}
		queue = append(queue, sendJob{abs: abs, rel: filepath.ToSlash(filepath.Base(abs))})
	}

	workers := runtime.NumCPU()
	if workers > len(queue) {
		workers = len(queue)
	}
	if workers < 1 {
		return
	}

	jobs := make(chan sendJob)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if s.alreadySent(job.abs) {
					if events != nil {
						events <- TransferSkipped{Peer: peer.Name, File: job.rel, Direction: DirectionSend}
					}
					continue
				}
				if err := s.sendOne(local, peer, job, events); err != nil {
					if events != nil {
						events <- TransferError{Peer: peer.Name, File: job.rel, Direction: DirectionSend, Err: err}
					}
					continue
				}
				s.markSent(job.abs)
			}
		}()
	}

	for _, job := range queue {
		jobs <- job
	}
	close(jobs)
	wg.Wait()
}

func (s *Sender) alreadySent(path string) bool {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	return s.sent.Contains(path)
}

func (s *Sender) markSent(path string) {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	s.sent.Add(path)
}

// sendOne opens its own TLS connection to peer and streams a single file.
func (s *Sender) sendOne(local Identity, peer Member, job sendJob, events chan<- interface{}) error {
	conn, err := tls.Dial("tcp", peer.Addr(), clientTLSConfig(local, peer.Fingerprint))
	if err != nil {
		return fmt.Errorf("dial %s: %w", peer.Name, err)
	}
	defer conn.Close()

	f, err := os.Open(job.abs)
	if err != nil {
		return fmt.Errorf("open %s: %w", job.abs, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", job.abs, err)
	}

	sum, err := fileChecksum(f)
	if err != nil {
		return fmt.Errorf("checksum %s: %w", job.abs, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind %s: %w", job.abs, err)
	}

	header := FileHeader{Path: job.rel, Size: info.Size(), SHA256: sum}
	if err := writeHeader(conn, header); err != nil {
		return err
	}

	accept, err := readAck(conn)
	if err != nil {
		return fmt.Errorf("read ack: %w", err)
	}
	if !accept {
		if events != nil {
			events <- TransferSkipped{Peer: peer.Name, File: job.rel, Direction: DirectionSend}
		}
		return nil
	}

	if events != nil {
		events <- TransferStarted{Peer: peer.Name, File: job.rel, Size: info.Size(), Direction: DirectionSend}
	}

	progress := newProgressWriter(info.Size(), func(written int64) {
		if events != nil {
			events <- TransferProgress{Peer: peer.Name, File: job.rel, Sent: written, Total: info.Size(), Direction: DirectionSend}
		}
	})

	dst := io.MultiWriter(conn, progress)
	if _, err := io.Copy(dst, f); err != nil {
		return fmt.Errorf("send body: %w", err)
	}

	if events != nil {
		events <- TransferDone{Peer: peer.Name, File: job.rel, Direction: DirectionSend}
	}
	return nil
}

func fileChecksum(f *os.File) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
