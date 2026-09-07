package snadbox

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestWriteReadHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := FileHeader{Path: "hello.txt", Size: 1234, SHA256: "abcdef"}

	if err := writeHeader(&buf, want); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}

	got, err := readHeader(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if got != want {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}

func TestWriteReadHeaderRoundTripWithNestedPath(t *testing.T) {
	var buf bytes.Buffer
	want := FileHeader{Path: "photos/sub/b.jpg", Size: 42, SHA256: "deadbeef"}

	if err := writeHeader(&buf, want); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}

	got, err := readHeader(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if got != want {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
	if got.Path != "photos/sub/b.jpg" {
		t.Fatalf("expected slashes to survive round trip, got %q", got.Path)
	}
}

func TestReadHeaderRejectsMalformedLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("not json\n"))
	if _, err := readHeader(r); err == nil {
		t.Fatal("expected an error decoding a malformed header line")
	}
}

func TestReadHeaderRejectsTruncatedInput(t *testing.T) {
	// No trailing newline: ReadString hits EOF before a delimiter.
	r := bufio.NewReader(strings.NewReader(`{"name":"a","size":1,"sha256":"x"}`))
	if _, err := readHeader(r); err == nil {
		t.Fatal("expected an error reading a truncated header")
	}
}

func TestWriteReadAckRoundTrip(t *testing.T) {
	for _, accept := range []bool{true, false} {
		var buf bytes.Buffer
		if err := writeAck(&buf, accept); err != nil {
			t.Fatalf("writeAck(%v): %v", accept, err)
		}
		got, err := readAck(&buf)
		if err != nil {
			t.Fatalf("readAck: %v", err)
		}
		if got != accept {
			t.Fatalf("ack round trip mismatch: got %v want %v", got, accept)
		}
	}
}

func TestReadAckRejectsEmptyInput(t *testing.T) {
	if _, err := readAck(&bytes.Buffer{}); err == nil {
		t.Fatal("expected an error reading an ack from empty input")
	}
}

func TestProgressWriterEmitsThrottledUpdatesAndFinal(t *testing.T) {
	const total = int64(1_000_000)
	var updates []int64
	pw := newProgressWriter(total, func(written int64) {
		updates = append(updates, written)
	})

	chunk := make([]byte, 1024)
	var written int64
	for written < total {
		n := int64(len(chunk))
		if written+n > total {
			n = total - written
		}
		if _, err := pw.Write(chunk[:n]); err != nil {
			t.Fatalf("write: %v", err)
		}
		written += n
	}

	if len(updates) == 0 {
		t.Fatal("expected at least one progress update")
	}
	if last := updates[len(updates)-1]; last != total {
		t.Fatalf("expected final update to equal total (%d), got %d", total, last)
	}
	// Roughly 100 evenly-spaced updates expected; allow generous slack since
	// the last chunk before `total` may not land exactly on a step boundary.
	if len(updates) > 110 {
		t.Fatalf("expected roughly 100 throttled updates, got %d", len(updates))
	}
}

func TestProgressWriterAlwaysEmitsFinalUpdateForSmallFiles(t *testing.T) {
	const total = int64(10) // smaller than the minimum 32KiB step
	var updates []int64
	pw := newProgressWriter(total, func(written int64) {
		updates = append(updates, written)
	})

	if _, err := pw.Write(make([]byte, total)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if len(updates) != 1 || updates[0] != total {
		t.Fatalf("expected exactly one final update of %d, got %v", total, updates)
	}
}
