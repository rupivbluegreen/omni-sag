package eventexport

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// withTimeout runs fn in a goroutine and fails the test loudly instead of
// hanging if fn doesn't return within d — mirrors the discipline in
// internal/session/scp_test.go's TestScpCopyBody.
func withTimeout(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("operation timed out — a transport blocked when it must be best-effort")
	}
}

func TestFileTransport(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.jsonl")
	tr, err := newFileTransport(FileConfig{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Write([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{\"a\":1}\n" {
		t.Fatalf("got %q", b)
	}
}

func TestFileTransport_ReopenAppends(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.jsonl")
	tr1, err := newFileTransport(FileConfig{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr1.Write([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := tr1.Close(); err != nil {
		t.Fatal(err)
	}

	tr2, err := newFileTransport(FileConfig{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr2.Write([]byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := tr2.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{\"a\":1}\n{\"a\":2}\n" {
		t.Fatalf("got %q, want both lines appended", b)
	}
}

func TestFileTransport_Perms(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.jsonl")
	tr, err := newFileTransport(FileConfig{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	tr.Close()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("file perm = %o, want 0600", perm)
	}
}

// readOctetCountedFrame reads one RFC 6587 octet-counted frame ("<len> "
// followed by exactly len bytes) from r.
func readOctetCountedFrame(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	lenStr, err := r.ReadString(' ')
	if err != nil {
		t.Fatalf("reading frame length: %v", err)
	}
	lenStr = strings.TrimSuffix(lenStr, " ")
	n, err := strconv.Atoi(lenStr)
	if err != nil {
		t.Fatalf("bad frame length %q: %v", lenStr, err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("reading frame body: %v", err)
	}
	return string(buf)
}

func TestSyslogTransport_FramesAndReconnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tr, err := newSyslogTransport(SyslogConfig{Address: ln.Addr().String(), Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	// First connection: accept, write, assert well-formed RFC 5424 frame.
	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			connCh <- c
		}
	}()

	if err := tr.Write([]byte(`hello world`)); err != nil {
		t.Fatal(err)
	}

	var conn1 net.Conn
	withTimeout(t, 5*time.Second, func() {
		conn1 = <-connCh
	})

	var frame string
	withTimeout(t, 5*time.Second, func() {
		frame = readOctetCountedFrame(t, bufio.NewReader(conn1))
	})

	if !strings.HasPrefix(frame, "<134>1 ") {
		t.Fatalf("frame PRI/version prefix wrong: %q", frame)
	}
	if !strings.Contains(frame, " omni-sag ") {
		t.Fatalf("frame missing app-name omni-sag: %q", frame)
	}
	if !strings.HasSuffix(frame, "hello world") {
		t.Fatalf("frame missing MSG payload: %q", frame)
	}

	// Drop the connection, then accept a fresh one; the next Write must
	// reconnect rather than erroring out forever.
	conn1.Close()

	connCh2 := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			connCh2 <- c
		}
	}()

	// A write to a just-closed peer can locally succeed once before the
	// RST arrives (the kernel buffers it), so a single nil error doesn't
	// prove a reconnect happened. Keep writing in the background and treat
	// the listener actually accepting a fresh connection as the proof.
	writeStop := make(chan struct{})
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for {
			select {
			case <-writeStop:
				return
			default:
			}
			tr.Write([]byte(`second`))
			time.Sleep(20 * time.Millisecond)
		}
	}()

	var conn2 net.Conn
	withTimeout(t, 5*time.Second, func() {
		conn2 = <-connCh2
	})
	close(writeStop)
	<-writeDone
	defer conn2.Close()

	withTimeout(t, 5*time.Second, func() {
		frame = readOctetCountedFrame(t, bufio.NewReader(conn2))
	})
	if !strings.HasSuffix(frame, "second") {
		t.Fatalf("reconnected frame missing payload: %q", frame)
	}
}

func TestSyslogTransport_DeadDestinationDoesNotBlock(t *testing.T) {
	// A destination nobody is listening on: UDP never errors synchronously
	// on Write, TCP would refuse — either way this must return promptly.
	tr, err := newSyslogTransport(SyslogConfig{Address: "127.0.0.1:1", Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	withTimeout(t, 5*time.Second, func() {
		_ = tr.Write([]byte("nobody home"))
	})
}

func TestHTTPTransport_BatchesAndFlushes(t *testing.T) {
	type req struct {
		body        string
		contentType string
	}
	reqs := make(chan req, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reqs <- req{body: string(b), contentType: r.Header.Get("Content-Type")}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, err := newHTTPTransport(HTTPConfig{URL: srv.URL, BatchSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if err := tr.Write([]byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := tr.Write([]byte(`{"n":2}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reqs:
		t.Fatal("POST fired before batch_size reached")
	case <-time.After(100 * time.Millisecond):
	}

	if err := tr.Write([]byte(`{"n":3}`)); err != nil {
		t.Fatal(err)
	}

	var got req
	withTimeout(t, 5*time.Second, func() {
		got = <-reqs
	})
	lines := strings.Split(strings.TrimRight(got.body, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("batch body has %d lines, want 3: %q", len(lines), got.body)
	}
	if lines[0] != `{"n":1}` || lines[1] != `{"n":2}` || lines[2] != `{"n":3}` {
		t.Fatalf("batch body wrong content: %q", got.body)
	}
	if got.contentType == "" {
		t.Fatal("missing Content-Type header")
	}

	// Partial batch: Flush must force it out even though batch_size isn't reached.
	if err := tr.Write([]byte(`{"n":4}`)); err != nil {
		t.Fatal(err)
	}
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	withTimeout(t, 5*time.Second, func() {
		got = <-reqs
	})
	if strings.TrimRight(got.body, "\n") != `{"n":4}` {
		t.Fatalf("flushed partial batch = %q, want single line {\"n\":4}", got.body)
	}
}

func TestHTTPTransport_BestEffortOn500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	tr, err := newHTTPTransport(HTTPConfig{URL: srv.URL, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	withTimeout(t, 5*time.Second, func() {
		// A non-2xx must not panic; it may be returned as an error but must
		// not block or crash the process.
		_ = tr.Write([]byte(`{"n":1}`))
	})
}

func TestHTTPTransport_DeadServerDoesNotBlock(t *testing.T) {
	tr, err := newHTTPTransport(HTTPConfig{URL: "http://127.0.0.1:1/no-such-server", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	withTimeout(t, 5*time.Second, func() {
		_ = tr.Write([]byte(`{"n":1}`))
	})
}
