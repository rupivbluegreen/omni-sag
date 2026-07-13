package session

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

// fakeAuth maps username -> groups, accepting a fixed password.
type fakeAuth struct{ users map[string][]string }

func (f fakeAuth) Authenticate(_ context.Context, username, password string) (authn.Identity, error) {
	if password != "pw" {
		return authn.Identity{}, authn.ErrAuth
	}
	groups, ok := f.users[username]
	if !ok {
		return authn.Identity{}, authn.ErrAuth
	}
	return authn.Identity{User: username, Groups: groups}, nil
}

// startEcho starts a TCP echo server and returns its host and port.
func startEcho(t *testing.T) (string, int) {
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
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// startServer wires policy+dialer+server on a random port and returns its addr.
func startServer(t *testing.T, p policy.Policy, auth authn.Authenticator, sink evidence.Sink) string {
	t.Helper()
	hostKey, err := NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	d := dialer.New(p, sink)
	srv := New(hostKey, auth, d, sink)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return ln.Addr().String()
}

func sshClient(t *testing.T, addr, user string) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("ssh dial as %s: %v", user, err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestWalkingSkeleton_AllowedUserForwards(t *testing.T) {
	echoHost, echoPort := startEcho(t)
	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: echoHost, Ports: []int{echoPort}}},
	}}}
	sink := evidence.NewMemSink()
	auth := fakeAuth{users: map[string][]string{
		"alice": {"dba"}, "bob": {"users"},
	}}
	addr := startServer(t, p, auth, sink)

	// alice is in dba -> the -L forward to the echo target must succeed.
	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err != nil {
		t.Fatalf("alice forward should be allowed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want hello", buf)
	}

	assertDecision(t, sink, "alice", true)
}

func TestWalkingSkeleton_DeniedUserProhibited(t *testing.T) {
	echoHost, echoPort := startEcho(t)
	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: echoHost, Ports: []int{echoPort}}},
	}}}
	sink := evidence.NewMemSink()
	auth := fakeAuth{users: map[string][]string{
		"alice": {"dba"}, "bob": {"users"},
	}}
	addr := startServer(t, p, auth, sink)

	// bob is not in dba -> the same forward must be rejected (prohibited).
	client := sshClient(t, addr, "bob")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err == nil {
		conn.Close()
		t.Fatal("bob forward must be administratively prohibited")
	}

	assertDecision(t, sink, "bob", false)
}

func TestWalkingSkeleton_BadPasswordRejected(t *testing.T) {
	sink := evidence.NewMemSink()
	auth := fakeAuth{users: map[string][]string{"alice": {"dba"}}}
	addr := startServer(t, policy.Policy{}, auth, sink)

	cfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if c, err := ssh.Dial("tcp", addr, cfg); err == nil {
		c.Close()
		t.Fatal("bad password must fail authentication")
	}
}

func TestHandshakeTimeout_ClosesStalledConn(t *testing.T) {
	// A client that connects but never sends the SSH banner must be dropped by
	// the handshake deadline, not parked forever.
	hostKey, err := NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	sink := evidence.NewMemSink()
	d := dialer.New(policy.Policy{}, sink)
	srv := New(hostKey, fakeAuth{}, d, sink)
	srv.handshakeTimeout = 300 * time.Millisecond // shrink for the test

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send no client banner. The server writes its own version line, then must
	// close the connection once the handshake deadline trips. Draining to EOF
	// returns when the server drops us; if it never did, our 3s read deadline
	// makes this take ~3s and the assertion fails.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, _ = io.Copy(io.Discard, conn) // returns when the server closes the conn
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("server took too long (%v) to drop a stalled handshake; deadline not enforced", elapsed)
	}
}

// assertDecision waits briefly for the async tunnel_decision event and checks
// its allow flag for the given user.
func assertDecision(t *testing.T, sink *evidence.MemSink, user string, wantAllow bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range sink.Events() {
			if e.Type == evidence.TypeTunnelDecision && e.User == user {
				if e.Allow == nil || *e.Allow != wantAllow {
					t.Fatalf("decision for %s: allow=%v, want %v (%s)", user, e.Allow, wantAllow, e.Reason)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no tunnel_decision evidence for %s", user)
}
