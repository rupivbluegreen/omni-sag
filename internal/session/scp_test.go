package session

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestParseSCPCommand(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		wantDir scpDirection
		wantPath string
		wantErr string // substring, "" means no error expected
	}{
		{"upload", "scp -t /upload.txt", scpUpload, "/upload.txt", ""},
		{"download", "scp -f /download.txt", scpDownload, "/download.txt", ""},
		{"upload with -p", "scp -p -t /upload.txt", scpUpload, "/upload.txt", ""},
		{"upload with -v -d", "scp -v -d -t /upload.txt", scpUpload, "/upload.txt", ""},
		{"recursive rejected", "scp -r -t /dir", 0, "", "-r"},
		{"missing direction", "scp /path", 0, "", "missing -t or -f"},
		{"conflicting direction", "scp -t -f /path", 0, "", "conflicting"},
		{"not scp", "ls -la", 0, "", "unsupported command"},
		{"unsupported flag", "scp -t -X /path", 0, "", "unsupported flag"},
		{"path with space", "scp -t /path with space", 0, "", "multiple paths"},
		{"path with quote", "scp -t /path'; rm -rf /", 0, "", "unsupported path"},
		{"no path", "scp -t", 0, "", "missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, path, err := parseSCPCommand(c.cmd)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("parseSCPCommand(%q) error = %v, want nil", c.cmd, err)
				}
				if dir != c.wantDir || path != c.wantPath {
					t.Fatalf("parseSCPCommand(%q) = (%v, %q), want (%v, %q)", c.cmd, dir, path, c.wantDir, c.wantPath)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseSCPCommand(%q) = nil error, want containing %q", c.cmd, c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("parseSCPCommand(%q) error = %q, want containing %q", c.cmd, err.Error(), c.wantErr)
			}
		})
	}
}

func TestScpSendOK(t *testing.T) {
	var buf bytes.Buffer
	if err := scpSendOK(&buf); err != nil {
		t.Fatalf("scpSendOK: %v", err)
	}
	if buf.Bytes()[0] != 0 {
		t.Fatalf("scpSendOK wrote %v, want [0]", buf.Bytes())
	}
}

func TestScpSendFatal(t *testing.T) {
	var buf bytes.Buffer
	if err := scpSendFatal(&buf, "boom"); err != nil {
		t.Fatalf("scpSendFatal: %v", err)
	}
	got := buf.Bytes()
	if got[0] != 2 {
		t.Fatalf("scpSendFatal status byte = %d, want 2", got[0])
	}
	if string(got[1:]) != "boom\n" {
		t.Fatalf("scpSendFatal message = %q, want %q", got[1:], "boom\n")
	}
}

func TestScpReadAck(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		r := bufio.NewReader(bytes.NewReader([]byte{0}))
		if err := scpReadAck(r); err != nil {
			t.Fatalf("scpReadAck = %v, want nil", err)
		}
	})
	t.Run("fatal with message", func(t *testing.T) {
		r := bufio.NewReader(bytes.NewReader(append([]byte{2}, []byte("no such file\n")...)))
		err := scpReadAck(r)
		if err == nil || !strings.Contains(err.Error(), "no such file") {
			t.Fatalf("scpReadAck = %v, want error containing %q", err, "no such file")
		}
	})
}

func TestScpReadControlLine(t *testing.T) {
	t.Run("plain C line", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("C0644 5 test.txt\n"))
		var acked bytes.Buffer
		cl, err := scpReadControlLine(r, &acked)
		if err != nil {
			t.Fatalf("scpReadControlLine: %v", err)
		}
		if cl.Perm != "0644" || cl.Size != 5 || cl.Name != "test.txt" {
			t.Fatalf("scpReadControlLine = %+v, want {0644 5 test.txt}", cl)
		}
		if acked.Len() != 0 {
			t.Fatalf("no T line present, expected no ack written, got %v", acked.Bytes())
		}
	})
	t.Run("T line is acked then C line parsed", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("T1000000000 0 1000000000 0\nC0644 5 test.txt\n"))
		var acked bytes.Buffer
		cl, err := scpReadControlLine(r, &acked)
		if err != nil {
			t.Fatalf("scpReadControlLine: %v", err)
		}
		if cl.Name != "test.txt" {
			t.Fatalf("scpReadControlLine = %+v, want Name test.txt", cl)
		}
		if acked.Len() != 1 || acked.Bytes()[0] != 0 {
			t.Fatalf("T line ack = %v, want single [0] byte", acked.Bytes())
		}
	})
	t.Run("directory record rejected", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("D0755 0 subdir\n"))
		var acked bytes.Buffer
		_, err := scpReadControlLine(r, &acked)
		if err == nil || !strings.Contains(err.Error(), "recursive") {
			t.Fatalf("scpReadControlLine = %v, want error containing %q", err, "recursive")
		}
	})
	t.Run("malformed line rejected", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("garbage\n"))
		var acked bytes.Buffer
		_, err := scpReadControlLine(r, &acked)
		if err == nil {
			t.Fatal("scpReadControlLine = nil error, want error on garbage input")
		}
	})
}
