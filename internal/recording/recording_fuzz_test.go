package recording

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// nopWriteCloser adapts a bytes.Buffer to io.WriteCloser for the fuzz test.
type nopWriteCloser struct{ *bytes.Buffer }

func (nopWriteCloser) Close() error { return nil }

// FuzzRecorderRoundTrip feeds arbitrary session I/O (including control bytes,
// invalid UTF-8, and NULs) through the Recorder and asserts the emitted
// asciicast v2 stream is always well formed: a JSON header line followed by
// JSON [time, kind, data] event lines. A recording captures attacker-controlled
// input, so no byte sequence may produce a corrupt (unparseable) cast.
func FuzzRecorderRoundTrip(f *testing.F) {
	f.Add([]byte("ls -la\n"), []byte("total 0\r\n"))
	f.Add([]byte{0x00, 0x1b, 0x5b, 0x41}, []byte{0xff, 0xfe, 0x00})
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("\"quoted\"\\backslash"), []byte("newline\nembedded"))

	f.Fuzz(func(t *testing.T, in, out []byte) {
		buf := &bytes.Buffer{}
		now := func() time.Time { return time.Unix(0, 0).UTC() }
		rec, err := NewRecorder(nopWriteCloser{buf}, "k", 80, 24, now)
		if err != nil {
			t.Fatalf("NewRecorder: %v", err)
		}
		rec.Input(in)
		rec.Output(out)
		if _, err := rec.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		// Every non-empty line must be valid JSON. The first is the header
		// object; the rest are 3-element event arrays.
		sc := bufio.NewScanner(buf)
		sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
		first := true
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if first {
				var hdr Header
				if err := json.Unmarshal([]byte(line), &hdr); err != nil {
					t.Fatalf("header not valid JSON: %q: %v", line, err)
				}
				if hdr.Version != 2 {
					t.Fatalf("header version = %d, want 2", hdr.Version)
				}
				first = false
				continue
			}
			var ev []json.RawMessage
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("event not valid JSON: %q: %v", line, err)
			}
			if len(ev) != 3 {
				t.Fatalf("event has %d elements, want 3: %q", len(ev), line)
			}
		}
		if err := sc.Err(); err != nil {
			t.Fatalf("scan: %v", err)
		}
	})
}
