package session

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// startEchoWithPreamble starts a TCP listener that writes preamble once per
// accepted connection (a server-speaks-first target, e.g. an SSH banner),
// then echoes anything it subsequently receives.
func startEchoWithPreamble(t *testing.T, preamble []byte) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if _, err := c.Write(preamble); err != nil {
					c.Close()
					return
				}
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestTunnelInspect_ObserveEmitsProtocolEvidence(t *testing.T) {
	sink := evidence.NewMemSink()
	preamble := []byte("SSH-2.0-FakeTarget\r\n")
	targetHost, targetPort := startEchoWithPreamble(t, preamble)

	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: targetHost, Ports: []int{targetPort}}},
	}}}
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 3 * time.Second,
	}))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	got := make([]byte, len(preamble))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read preamble through tunnel: %v", err)
	}
	if string(got) != string(preamble) {
		t.Fatalf("tunnel corrupted bytes: got %q, want %q", got, preamble)
	}

	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "ssh"
	})
}

// recordingTarget records every byte it reads from any accepted connection,
// so enforce-mode tests can assert bytes held-and-denied never reached it.
type recordingTarget struct {
	mu       sync.Mutex
	received []byte
}

func (rt *recordingTarget) append(p []byte) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.received = append(rt.received, p...)
}

func (rt *recordingTarget) snapshot() []byte {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return append([]byte(nil), rt.received...)
}

// startRecordingTarget starts a TCP listener that writes preamble (if
// non-empty, a server-speaks-first target) then echoes anything it reads,
// recording every byte it receives. A nil preamble makes it silent until the
// client speaks first (client-first protocols; also exercises the "target
// never receives held bytes" assertion on an enforce mismatch/deny).
func startRecordingTarget(t *testing.T, preamble []byte) (host string, port int, rt *recordingTarget) {
	t.Helper()
	rt = &recordingTarget{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if len(preamble) > 0 {
					if _, err := c.Write(preamble); err != nil {
						c.Close()
						return
					}
				}
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						rt.append(buf[:n])
						if _, werr := c.Write(buf[:n]); werr != nil {
							c.Close()
							return
						}
					}
					if err != nil {
						c.Close()
						return
					}
				}
			}()
		}
	}()
	hostStr, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return hostStr, p, rt
}

// assertClosedSoon reads one byte from conn in a goroutine and fails unless
// it sees an error (the tunnel was torn down) within timeout — guards
// against a hang instead of blocking the test forever, like the scp
// TestScpCopyBody short-read guard.
func assertClosedSoon(t *testing.T, conn net.Conn, timeout time.Duration) {
	t.Helper()
	readErrCh := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readErrCh <- err
	}()
	select {
	case err := <-readErrCh:
		if err == nil {
			t.Fatal("expected tunnel closed, got data instead")
		}
	case <-time.After(timeout):
		t.Fatal("tunnel was not closed in time")
	}
}

func expectProtocolPolicy(host string, port int, expect ...string) policy.Policy {
	return policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: host, Ports: []int{port}, ExpectProtocol: expect}},
	}}}
}

func TestTunnelInspect_EnforceMatchAllowsAndBytesIntact(t *testing.T) {
	sink := evidence.NewMemSink()
	host, port, rt := startRecordingTarget(t, nil)
	p := expectProtocolPolicy(host, port, "postgres")
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 3 * time.Second, Enforce: true,
	}))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	pgStartup := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := conn.Write(pgStartup); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(pgStartup))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo through tunnel: %v", err)
	}
	if !bytes.Equal(got, pgStartup) {
		t.Fatalf("bytes altered: got %x, want %x", got, pgStartup)
	}

	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "postgres" && e.Allow != nil && *e.Allow
	})
	if !bytes.Equal(rt.snapshot(), pgStartup) {
		t.Fatalf("target received %x, want %x", rt.snapshot(), pgStartup)
	}
}

func TestTunnelInspect_EnforceMismatchTerminatesWithoutForwarding(t *testing.T) {
	sink := evidence.NewMemSink()
	host, port, rt := startRecordingTarget(t, nil)
	p := expectProtocolPolicy(host, port, "postgres")
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 2 * time.Second, Enforce: true,
	}))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	jdwp := []byte("JDWP-Handshake")
	if _, err := conn.Write(jdwp); err != nil {
		t.Fatal(err)
	}

	ev := waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "jdwp"
	})
	if ev.Allow == nil || *ev.Allow {
		t.Fatalf("expected Allow=false for mismatch, got %v", ev.Allow)
	}
	if !strings.Contains(ev.Reason, "jdwp") {
		t.Fatalf("reason should name jdwp, got %q", ev.Reason)
	}

	assertClosedSoon(t, conn, 3*time.Second)
	if got := rt.snapshot(); len(got) != 0 {
		t.Fatalf("target received bytes despite mismatch: %q", got)
	}
}

func TestTunnelInspect_EnforceClientFirstDoesNotWaitOnSilentTarget(t *testing.T) {
	sink := evidence.NewMemSink()
	host, port, _ := startRecordingTarget(t, nil) // silent until spoken to
	p := expectProtocolPolicy(host, port, "jdwp")
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		// classify_timeout is intentionally much longer than the outer guard
		// below, so passing quickly proves classification did not wait on
		// the silent target/timeout.
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 10 * time.Second, Enforce: true,
	}))
	client := sshClient(t, addr, "alice")

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			t.Errorf("dial through tunnel: %v", err)
			return
		}
		defer conn.Close()
		jdwp := []byte("JDWP-Handshake")
		if _, err := conn.Write(jdwp); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		got := make([]byte, len(jdwp))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Errorf("read echo: %v", err)
			return
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("enforce hung waiting on the silent target instead of classifying from client bytes alone")
	}

	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "jdwp" && e.Allow != nil && *e.Allow
	})
}

func TestTunnelInspect_EnforceServerFirstMatch(t *testing.T) {
	sink := evidence.NewMemSink()
	preamble := []byte("SSH-2.0-FakeTarget\r\n")
	host, port, _ := startRecordingTarget(t, preamble)
	p := expectProtocolPolicy(host, port, "ssh")
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 3 * time.Second, Enforce: true,
	}))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	got := make([]byte, len(preamble))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read banner through tunnel: %v", err)
	}
	if !bytes.Equal(got, preamble) {
		t.Fatalf("banner altered: got %q, want %q", got, preamble)
	}

	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "ssh" && e.Allow != nil && *e.Allow
	})
}

func TestTunnelInspect_EnforceServerFirstMismatchTerminates(t *testing.T) {
	sink := evidence.NewMemSink()
	preamble := []byte("SSH-2.0-FakeTarget\r\n")
	host, port, _ := startRecordingTarget(t, preamble)
	p := expectProtocolPolicy(host, port, "postgres")
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 2 * time.Second, Enforce: true,
	}))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	ev := waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "ssh"
	})
	if ev.Allow == nil || *ev.Allow {
		t.Fatalf("expected Allow=false, got %v", ev.Allow)
	}

	assertClosedSoon(t, conn, 3*time.Second)
}

func TestTunnelInspect_EnforceUnknownAllow(t *testing.T) {
	sink := evidence.NewMemSink()
	host, port, _ := startRecordingTarget(t, nil)
	p := expectProtocolPolicy(host, port, "postgres")
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 300 * time.Millisecond, Enforce: true, UnknownDeny: false,
	}))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	ev := waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "unknown"
	})
	if ev.Allow == nil || !*ev.Allow {
		t.Fatalf("expected Allow=true for unknown+UnknownDeny=false, got %v", ev.Allow)
	}

	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatalf("write after unknown-allow: %v", err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo after unknown-allow: %v", err)
	}
	if string(got) != "hi" {
		t.Fatalf("echo mismatch: %q", got)
	}
}

func TestTunnelInspect_EnforceUnknownDeny(t *testing.T) {
	sink := evidence.NewMemSink()
	host, port, _ := startRecordingTarget(t, nil)
	p := expectProtocolPolicy(host, port, "postgres")
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 300 * time.Millisecond, Enforce: true, UnknownDeny: true,
	}))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	ev := waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "unknown"
	})
	if ev.Allow == nil || *ev.Allow {
		t.Fatalf("expected Allow=false for unknown+UnknownDeny=true, got %v", ev.Allow)
	}

	assertClosedSoon(t, conn, 2*time.Second)
}

func TestTunnelInspect_DryRunLogsWithoutBlocking(t *testing.T) {
	sink := evidence.NewMemSink()
	host, port, rt := startRecordingTarget(t, nil)
	p := expectProtocolPolicy(host, port, "postgres")
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 3 * time.Second, Enforce: false, // dry-run
	}))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	jdwp := []byte("JDWP-Handshake")
	if _, err := conn.Write(jdwp); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(jdwp))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("dry-run must not block the tunnel: %v", err)
	}
	if !bytes.Equal(got, jdwp) {
		t.Fatalf("bytes altered: got %q, want %q", got, jdwp)
	}

	ev := waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "jdwp"
	})
	if ev.Allow == nil || *ev.Allow {
		t.Fatalf("expected Allow=false (would-block) for dry-run mismatch, got %v", ev.Allow)
	}
	if !strings.Contains(ev.Detail, "dry-run") {
		t.Fatalf("Detail should mention dry-run, got %q", ev.Detail)
	}
	if !bytes.Equal(rt.snapshot(), jdwp) {
		t.Fatalf("target should still receive bytes in dry-run, got %x, want %x", rt.snapshot(), jdwp)
	}
}
