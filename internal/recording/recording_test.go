package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// bufCloser is an in-memory WriteCloser capturing the cast bytes.
type bufCloser struct{ bytes.Buffer }

func (b *bufCloser) Close() error { return nil }

// fakeClock advances a fixed step per call.
func fakeClock(start time.Time, step time.Duration) func() time.Time {
	t := start
	first := true
	return func() time.Time {
		if first {
			first = false
			return t
		}
		t = t.Add(step)
		return t
	}
}

func TestRecorder_AsciicastAndManifest(t *testing.T) {
	dest := &bufCloser{}
	start := time.Unix(1_700_000_000, 0).UTC()
	rec, err := NewRecorder(dest, "rec/alice/x.cast", 120, 40, fakeClock(start, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	rec.Output([]byte("hello\r\n"))
	rec.Input([]byte("ls\r"))
	rec.Output([]byte("file1\r\n"))

	m, err := rec.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Manifest hash must equal SHA-256 of the exact bytes written.
	sum := sha256.Sum256(dest.Bytes())
	if m.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("manifest hash %s != content hash %s", m.SHA256, hex.EncodeToString(sum[:]))
	}
	if m.Bytes != int64(dest.Len()) {
		t.Fatalf("manifest bytes %d != written %d", m.Bytes, dest.Len())
	}
	if m.Key != "rec/alice/x.cast" || m.Width != 120 || m.Height != 40 {
		t.Fatalf("manifest metadata wrong: %+v", m)
	}

	// First line is a valid asciicast v2 header.
	lines := strings.Split(strings.TrimRight(dest.String(), "\n"), "\n")
	if len(lines) != 4 { // header + 3 events
		t.Fatalf("expected header + 3 events, got %d lines", len(lines))
	}
	var hdr Header
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil || hdr.Version != 2 {
		t.Fatalf("bad header line: %q (%v)", lines[0], err)
	}
	// Event lines are [time, kind, data].
	var ev []interface{}
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil || len(ev) != 3 {
		t.Fatalf("bad event line: %q", lines[1])
	}
	if ev[1] != "o" || ev[2] != "hello\r\n" {
		t.Fatalf("first event wrong: %v", ev)
	}
}

func TestRecorder_TamperChangesHash(t *testing.T) {
	dest := &bufCloser{}
	rec, _ := NewRecorder(dest, "k", 80, 24, fakeClock(time.Unix(1, 0).UTC(), time.Second))
	rec.Output([]byte("secret output"))
	m, _ := rec.Close()

	tampered := bytes.Replace(dest.Bytes(), []byte("secret"), []byte("SECRET"), 1)
	sum := sha256.Sum256(tampered)
	if m.SHA256 == hex.EncodeToString(sum[:]) {
		t.Fatal("tampered cast must not match the manifest hash")
	}
}
