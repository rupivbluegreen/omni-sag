package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/ratelimit"
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

// fakeAuthenticator always authenticates successfully as the configured
// identity, regardless of the password supplied. Used for unit tests that
// drive passwordCallback directly (not through a real SSH handshake) and
// only care about post-authentication behavior.
type fakeAuthenticator struct{ identity authn.Identity }

func (f fakeAuthenticator) Authenticate(_ context.Context, _, _ string) (authn.Identity, error) {
	return f.identity, nil
}

// fakeConnMeta is a minimal ssh.ConnMetadata for unit-testing auth callbacks
// directly, without a real SSH handshake.
type fakeConnMeta struct{ user string }

func (f fakeConnMeta) User() string          { return f.user }
func (f fakeConnMeta) SessionID() []byte     { return nil }
func (f fakeConnMeta) ClientVersion() []byte { return nil }
func (f fakeConnMeta) ServerVersion() []byte { return nil }
func (f fakeConnMeta) RemoteAddr() net.Addr  { return nil }
func (f fakeConnMeta) LocalAddr() net.Addr   { return nil }

// noopSink discards all evidence events; used where a test doesn't care about
// evidence content, only behavior.
type noopSink struct{}

func (noopSink) Emit(evidence.Event) error { return nil }
func (noopSink) Close() error              { return nil }

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
	// Test harness targets are loopback echo servers; permit loopback so the
	// forward path is exercised. The SSRF guard still blocks metadata/etc.
	d := dialer.New(p, sink, dialer.WithLoopbackTargetsAllowed())
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

func TestTargetSecretStash_RoundTrips(t *testing.T) {
	s := &Server{}
	sec := credential.New([]byte("hunter2"))
	token := s.stashTargetSecret(sec)
	if token == "" {
		t.Fatal("stashTargetSecret returned empty token")
	}
	got := s.takeTargetSecret(token)
	if got != sec {
		t.Fatalf("takeTargetSecret returned a different *Secret")
	}
	// A token is single-use: taking it again must return nil, not the same secret.
	if again := s.takeTargetSecret(token); again != nil {
		t.Fatal("takeTargetSecret must be single-use — second call returned non-nil")
	}
}

func TestTargetSecretStash_UnknownTokenReturnsNil(t *testing.T) {
	s := &Server{}
	if got := s.takeTargetSecret("no-such-token"); got != nil {
		t.Fatal("takeTargetSecret(unknown) must return nil")
	}
}

func TestPasswordCallback_PromptModeChainsKeyboardInteractive(t *testing.T) {
	fakeAuth := fakeAuthenticator{identity: authn.Identity{User: "alice", Groups: []string{"dba"}}}
	s := &Server{
		bfLimiter: ratelimit.New(ratelimit.DefaultConfig()),
		sink:      noopSink{},
		dialerPeek: func(pr policy.Principal, host string) policy.Decision {
			return policy.Decision{Allow: true, CredentialMode: "prompt", MatchedRole: "dba"}
		},
	}
	cb := s.passwordCallback(fakeAuth)
	_, err := cb(fakeConnMeta{user: "alice%db1.lab.local"}, []byte("password123"))

	var partial *ssh.PartialSuccessError
	if !errors.As(err, &partial) {
		t.Fatalf("want *ssh.PartialSuccessError for a prompt-mode target, got %v (%T)", err, err)
	}
	if partial.Next.KeyboardInteractiveCallback == nil {
		t.Fatal("PartialSuccessError.Next.KeyboardInteractiveCallback is nil")
	}

	challenge := func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		if len(questions) != 1 || echos[0] != false {
			t.Fatalf("want one echo-off question, got questions=%v echos=%v", questions, echos)
		}
		return []string{"targetpass"}, nil
	}
	perms, err := partial.Next.KeyboardInteractiveCallback(fakeConnMeta{user: "alice%db1.lab.local"}, challenge)
	if err != nil {
		t.Fatalf("KeyboardInteractiveCallback: %v", err)
	}
	if perms.Extensions["target_host"] != "db1.lab.local" {
		t.Fatalf("target_host = %q, want db1.lab.local", perms.Extensions["target_host"])
	}
	token := perms.Extensions["target_secret_token"]
	if token == "" {
		t.Fatal("target_secret_token not set")
	}
	sec := s.takeTargetSecret(token)
	if sec == nil || string(sec.Bytes()) != "targetpass" {
		t.Fatalf("stashed secret = %v, want \"targetpass\"", sec)
	}
}
