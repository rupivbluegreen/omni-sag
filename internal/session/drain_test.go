package session

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

func drainServer(t *testing.T, p policy.Policy) (*Server, string, context.CancelFunc) {
	t.Helper()
	hostKey, err := NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	sink := evidence.NewMemSink()
	d := dialer.New(p, sink)
	srv := New(hostKey, fakeAuth{users: map[string][]string{"alice": {"dba"}}}, d, sink)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx, ln)
	return srv, ln.Addr().String(), cancel
}

func TestDrain_NoActiveReturnsImmediately(t *testing.T) {
	srv, _, cancel := drainServer(t, policy.Policy{})
	cancel()
	start := time.Now()
	n, err := srv.Drain(2 * time.Second)
	if err != nil || n != 0 {
		t.Fatalf("no active sessions should drain cleanly: n=%d err=%v", n, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("drain with no sessions should return promptly")
	}
}

func TestDrain_WaitsForActiveSessionThenReports(t *testing.T) {
	echoHost, echoPort := startEcho(t)
	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: echoHost, Ports: []int{echoPort}}},
	}}}
	srv, addr, cancel := drainServer(t, p)

	client := sshClient(t, addr, "alice")
	// Open a forward so there is a live, connected session.
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := srv.ActiveSessions(); got != 1 {
		t.Fatalf("expected 1 active session, got %d", got)
	}

	cancel() // begin drain: listener closes, existing session keeps running

	// The existing session must still work during the grace period.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("existing session should survive drain start: %v", err)
	}

	// Drain must not return while the session is still connected.
	n, err := srv.Drain(300 * time.Millisecond)
	if err == nil || n < 1 {
		t.Fatalf("drain should report the still-active session, got n=%d err=%v", n, err)
	}

	// Once the client disconnects, drain completes.
	client.Close()
	if n2, err := srv.Drain(3 * time.Second); err != nil || n2 != 0 {
		t.Fatalf("drain should complete after disconnect: n=%d err=%v", n2, err)
	}
}

func TestServe_RefusesNewConnectionsWhileDraining(t *testing.T) {
	srv, addr, cancel := drainServer(t, policy.Policy{})
	_ = srv
	cancel()
	// Give the drain goroutine a moment to close the listener.
	time.Sleep(100 * time.Millisecond)
	cfg := &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second,
	}
	if c, err := ssh.Dial("tcp", addr, cfg); err == nil {
		c.Close()
		t.Fatal("a draining gateway must refuse new connections")
	}
}
