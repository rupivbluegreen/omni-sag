package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func TestSplitTargetUser(t *testing.T) {
	cases := []struct {
		raw           string
		wantUser      string
		wantTarget    string
		wantHasTarget bool
	}{
		{"alice", "alice", "", false},
		{"alice%db1.lab.local", "alice", "db1.lab.local", true},
		{"alice%db1.lab.local%extra", "alice", "db1.lab.local%extra", true}, // only first % splits
		{"%db1.lab.local", "", "db1.lab.local", true},
		{"alice%", "alice", "", true},
	}
	for _, c := range cases {
		u, h, ok := splitTargetUser(c.raw)
		if u != c.wantUser || h != c.wantTarget || ok != c.wantHasTarget {
			t.Errorf("splitTargetUser(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.raw, u, h, ok, c.wantUser, c.wantTarget, c.wantHasTarget)
		}
	}
}

func TestSplitPcodeSelector(t *testing.T) {
	cases := []struct{ raw, wantUser, wantPcode string }{
		{"alice", "alice", ""},
		{"alice+pcodeA", "alice", "pcodeA"},
		{"alice+pcodeA+x", "alice", "pcodeA+x"}, // only the first + splits
		{"+pcodeA", "", "pcodeA"},
		{"alice+", "alice", ""},
	}
	for _, c := range cases {
		u, p := splitPcodeSelector(c.raw)
		if u != c.wantUser || p != c.wantPcode {
			t.Errorf("splitPcodeSelector(%q) = (%q, %q), want (%q, %q)", c.raw, u, p, c.wantUser, c.wantPcode)
		}
	}
}

// startFakeTarget runs a minimal SSH server on an in-memory pipe that accepts
// only the given password, and returns the client-side net.Conn to dial.
// It runs until the test ends (t.Cleanup closes both ends).
func startFakeTarget(t *testing.T, wantPassword string) net.Conn {
	t.Helper()
	signer := testHostKey(t) // see Step 1a
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != wantPassword {
				return nil, errors.New("wrong password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	clientConn, serverConn := fakeTargetPipe(t)
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	go func() {
		sconn, chans, reqs, err := ssh.NewServerConn(serverConn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for range chans {
		}
	}()
	return clientConn
}

// startFakeTargetKbdOnly runs a minimal SSH server that accepts ONLY the
// "keyboard-interactive" auth method (no PasswordCallback, so the SSH
// "password" method is not advertised) and authenticates by challenging the
// client for a single password prompt. This models a BoKS / PAM-MFA target
// like clrv0000332537, whose sshd offers only keyboard-interactive — the case
// a password-only dial config fails with "attempted methods [none]".
func startFakeTargetKbdOnly(t *testing.T, wantPassword string) net.Conn {
	t.Helper()
	signer := testHostKey(t)
	cfg := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != wantPassword {
				return nil, errors.New("wrong password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	clientConn, serverConn := fakeTargetPipe(t)
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	go func() {
		sconn, chans, reqs, err := ssh.NewServerConn(serverConn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for range chans {
		}
	}()
	return clientConn
}

// fakeTargetPipe returns a connected, buffered net.Conn pair over TCP
// loopback. A raw net.Pipe() cannot be used here: it is fully synchronous
// with zero internal buffering, and the SSH transport's version exchange has
// BOTH sides write their identification line before reading the peer's —
// over net.Pipe that deadlocks every single time (both ends block forever in
// Write, since neither has called Read yet). This is a documented, known
// issue: golang.org/x/crypto/ssh's own handshake_test.go has an identical
// "netPipe" helper with the same comment ("net.Pipe deadlocks if both sides
// start with a write"), for the exact same reason.
func fakeTargetPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeTargetPipe: listen: %v", err)
	}
	defer ln.Close()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("fakeTargetPipe: dial: %v", err)
	}
	c2, err := ln.Accept()
	if err != nil {
		c1.Close()
		t.Fatalf("fakeTargetPipe: accept: %v", err)
	}
	return c1, c2
}

// startFakeTargetShell runs a minimal SSH server, like startFakeTarget, that
// additionally serves a toy interactive shell over any "session" channel: it
// echoes every byte written to it straight back out, and closes the channel
// once it reads a line consisting of exactly "exit" (terminated by \r or
// \n) — just enough behavior for a real client to drive runRecordedShell's
// bridge (Task 8) end-to-end in tests, without a real target host. Channel
// types other than "session" are rejected.
//
// If resizeObserved is non-nil, every "window-change" request this fake
// target receives is decoded and sent to it (non-blocking; a full buffer
// drops the sample), letting a test assert that runRecordedShell's
// resize-forwarding goroutine actually reached the target.
func startFakeTargetShell(t *testing.T, wantPassword string, resizeObserved chan<- [2]int) net.Conn {
	t.Helper()
	signer := testHostKey(t)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != wantPassword {
				return nil, errors.New("wrong password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	clientConn, serverConn := fakeTargetPipe(t)
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	go func() {
		sconn, chans, reqs, err := ssh.NewServerConn(serverConn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			ch, requests, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func(requests <-chan *ssh.Request) {
				for req := range requests {
					if req.Type == "window-change" && resizeObserved != nil {
						var wc struct{ Cols, Rows, WidthPx, HeightPx uint32 }
						if ssh.Unmarshal(req.Payload, &wc) == nil {
							select {
							case resizeObserved <- [2]int{int(wc.Rows), int(wc.Cols)}:
							default:
							}
						}
					}
					_ = req.Reply(true, nil)
				}
			}(requests)
			go echoShell(ch)
		}
	}()
	return clientConn
}

// echoShell is a toy "shell" used only by startFakeTargetShell: it echoes
// every byte written to ch straight back out, and closes ch once it reads a
// line consisting of exactly "exit" — just enough for a test client to end
// the session the way it would end a real one.
func echoShell(ch ssh.Channel) {
	defer ch.Close()
	buf := make([]byte, 1)
	var line []byte
	for {
		n, err := ch.Read(buf)
		if n > 0 {
			b := buf[0]
			if _, werr := ch.Write(buf[:1]); werr != nil {
				return
			}
			switch b {
			case '\r', '\n':
				if string(line) == "exit" {
					return
				}
				line = line[:0]
			default:
				line = append(line, b)
			}
		}
		if err != nil {
			return
		}
	}
}

// wireFakeTarget starts a fake target SSH server (startFakeTargetShell) that
// accepts wantPassword over its toy shell, and returns a target host string
// to dial (arbitrary — dialNet is overridden to redirect to the fake target
// regardless of address, restored on test cleanup) plus the Options needed
// to route a real shell session (Task 8) to it in inject-credential mode.
// resizeObserved is forwarded to startFakeTargetShell (see its doc comment);
// pass nil when a test doesn't care about observed window-change requests.
func wireFakeTarget(t *testing.T, wantPassword string, resizeObserved chan<- [2]int) (targetHost string, opts []Option) {
	t.Helper()
	fakeConn := startFakeTargetShell(t, wantPassword, resizeObserved)
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	prov := credential.NewProvider(credential.Config{
		Fetcher: fakeFetcher{secret: []byte(wantPassword)},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})
	return "fake-target.lab.local", []Option{
		WithCredentialProvider(prov),
		WithDialerPeek(func(policy.Principal, string) policy.Decision {
			return policy.Decision{Allow: true, CredentialMode: "inject"}
		}),
		WithInsecureTargetHostKey(),
	}
}

func testHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("wrap host key: %v", err)
	}
	return signer
}

func TestDialTarget_NoHostKeyCallbackFailsClosed(t *testing.T) {
	// s.targetHostKeyCB is unset (the fail-closed default post-security-review:
	// dialTarget must refuse to dial rather than silently fall back to
	// ssh.InsecureIgnoreHostKey()). Build a Server whose inject-mode dial would
	// otherwise succeed (same setup as TestDialTarget_InjectSucceeds) to prove
	// the host-key gate — not a missing credential or a bad mode — is what
	// stops it, and that it stops it BEFORE any dial is attempted.
	dialed := false
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial: host-key check should fail closed first")
	}
	t.Cleanup(func() { dialNet = orig })

	prov := credential.NewProvider(credential.Config{
		Fetcher: fakeFetcher{secret: []byte("injected-secret")},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})
	s := &Server{sink: noopSink{}, cred: prov} // targetHostKeyCB intentionally left nil
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
	if dialed {
		t.Fatal("missing target host-key callback must fail closed before any dial is attempted")
	}
}

func TestDialTarget_Deny(t *testing.T) {
	s := &Server{sink: noopSink{}, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "deny"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestDialTarget_InjectNoProviderFailsClosed(t *testing.T) {
	s := &Server{sink: noopSink{}, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production; s.cred is nil
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
}

func TestDialTarget_PromptNoStashedSecretFailsClosed(t *testing.T) {
	s := &Server{sink: noopSink{}, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "prompt"}, "db1.lab.local", 22, "no-such-token")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
}

func TestDialTarget_PassthroughNoConnFailsClosed(t *testing.T) {
	// sconn is dialTarget's own guard (distinct from forwardedAgentSigners's
	// internal checks, already covered by Task 6's agentfwd_test.go) — it
	// must fail closed, not panic or fall through, when there is no gateway
	// connection to the client to forward an agent from (e.g. sconn is nil
	// in every other dialTarget test in this file).
	s := &Server{sink: noopSink{}, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "passthrough"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
}

func TestDialTarget_InjectSucceeds(t *testing.T) {
	fakeConn := startFakeTarget(t, "injected-secret")
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	prov := credential.NewProvider(credential.Config{
		Fetcher: fakeFetcher{secret: []byte("injected-secret")},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})
	s := &Server{sink: noopSink{}, cred: prov, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	defer client.Close()
}

func TestDialTarget_PromptSucceeds(t *testing.T) {
	fakeConn := startFakeTarget(t, "prompted-secret")
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	s := &Server{sink: noopSink{}, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	token := s.stashTargetSecret(credential.New([]byte("prompted-secret")))
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "prompt"}, "db1.lab.local", 22, token)
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	defer client.Close()
}

// TestDialTarget_PromptSucceedsKeyboardInteractiveOnly is the regression test
// for the keyboard-interactive gap: a target that advertises ONLY
// keyboard-interactive (BoKS / PAM-MFA, e.g. clrv0000332537) must still
// authenticate. Before passwordAuthMethods offered keyboard-interactive
// alongside password, this failed with "unable to authenticate, attempted
// methods [none], no supported methods remain".
func TestDialTarget_PromptSucceedsKeyboardInteractiveOnly(t *testing.T) {
	fakeConn := startFakeTargetKbdOnly(t, "prompted-secret")
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	s := &Server{sink: noopSink{}, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	token := s.stashTargetSecret(credential.New([]byte("prompted-secret")))
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "prompt"}, "db1.lab.local", 22, token)
	if err != nil {
		t.Fatalf("dialTarget against keyboard-interactive-only target: %v", err)
	}
	defer client.Close()
}

// TestDialTarget_InjectSucceedsKeyboardInteractiveOnly proves inject mode also
// authenticates a keyboard-interactive-only target (same gap, inject path).
func TestDialTarget_InjectSucceedsKeyboardInteractiveOnly(t *testing.T) {
	fakeConn := startFakeTargetKbdOnly(t, "injected-secret")
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	prov := credential.NewProvider(credential.Config{
		Fetcher: fakeFetcher{secret: []byte("injected-secret")},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})
	s := &Server{sink: noopSink{}, cred: prov, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if err != nil {
		t.Fatalf("dialTarget against keyboard-interactive-only target: %v", err)
	}
	defer client.Close()
}

// TestRunRecordedShell_DialsDecisionResolvedPort proves DecideHost's resolved
// Port actually reaches the real second-SSH-leg dial address, end to end
// through the session layer — not just that dialTarget's own unit tests pass
// a Decision with Port already filled in by hand. It wires a REAL
// policy.Policy (one rule, one host, one port) through a REAL
// dialer.Dialer.PeekHost (i.e. the real DecideHost, not a canned test
// closure), drives a real client shell session through the full server, and
// asserts the exact addr string dialNet received.
//
// This is the regression test for the bug this plan's port-threading fix
// closed: interactive.go/sftp.go used to hardcode target port 22 regardless
// of policy, which on a host that also runs a real sshd on 22 would silently
// "succeed" against the wrong service.
func TestRunRecordedShell_DialsDecisionResolvedPort(t *testing.T) {
	const wantPort = 2200
	const wantHost = "fake-target.lab.local"
	fakeConn := startFakeTargetShell(t, "targetpw", nil)

	// addrCh (not a plain shared variable) hands the dialed addr back to the
	// test goroutine: a channel send/receive is what gives this a proper
	// happens-before edge under the race detector, since the dial itself
	// happens on a server-side goroutine (handleSession's shell goroutine),
	// not the test goroutine.
	addrCh := make(chan string, 1)
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		addrCh <- addr
		return fakeConn, nil
	}
	t.Cleanup(func() { dialNet = orig })

	prov := credential.NewProvider(credential.Config{
		Fetcher: fakeFetcher{secret: []byte("targetpw")},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})

	pol := policy.Policy{Roles: []policy.Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []policy.Rule{{Host: wantHost, Ports: []int{wantPort}, Credential: "inject"}},
	}}}
	d := dialer.New(pol, evidence.NewMemSink())

	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink,
		WithCredentialProvider(prov),
		WithDialerPeek(d.PeekHost), // the real DecideHost, not a fake
		WithInsecureTargetHostKey(),
	)
	client := sshClient(t, addr, "alice%"+wantHost)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	// See TestRunRecordedShell_ForwardsWindowChangeToTarget's comment on why
	// StdinPipe (not a nil Stdin) is needed to keep the channel open.
	if _, err := sess.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	sess.Stdout = &nopWriter{}
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}

	var capturedAddr string
	select {
	case capturedAddr = <-addrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("dialNet was never called — the target dial never happened")
	}

	want := wantHost + ":" + strconv.Itoa(wantPort)
	if capturedAddr != want {
		t.Fatalf("dialNet addr = %q, want %q (DecideHost's resolved port must reach the actual dial, not a hardcoded fallback)", capturedAddr, want)
	}
}

// fakeFetcher implements credential.Fetcher for TestDialTarget_InjectSucceeds.
type fakeFetcher struct{ secret []byte }

func (f fakeFetcher) Fetch(_ context.Context, _ credential.Query) (*credential.Secret, error) {
	return credential.New(append([]byte(nil), f.secret...)), nil
}

// --- Important finding #1: dialTarget must emit evidence.TypeCredential for
// every second-leg auth attempt (all four modes), never the secret. ---

// singleCredentialEvent asserts sink recorded EXACTLY one
// evidence.TypeCredential event and returns it.
func singleCredentialEvent(t *testing.T, sink *evidence.MemSink) evidence.Event {
	t.Helper()
	var got []evidence.Event
	for _, e := range sink.Events() {
		if e.Type == evidence.TypeCredential {
			got = append(got, e)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 evidence.TypeCredential event, got %d: %+v", len(got), got)
	}
	return got[0]
}

// assertNoSecretLeak fails the test if any string field of e contains any of
// secrets — the credential/password itself must never appear in evidence.
func assertNoSecretLeak(t *testing.T, e evidence.Event, secrets ...string) {
	t.Helper()
	haystack := strings.Join([]string{
		e.User, e.SourceIP, e.Target, e.Reason, e.MatchedRole, e.RecordMode,
		e.ObjectKey, e.SHA256, e.Path, e.Direction, e.Verdict,
		e.CredentialMode, e.Outcome, e.Detail,
	}, "\x00")
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(haystack, secret) {
			t.Fatalf("credential event leaked the secret %q: %+v", secret, e)
		}
	}
}

func TestDialTarget_InjectEmitsCredentialEvidence(t *testing.T) {
	fakeConn := startFakeTarget(t, "injected-secret")
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	prov := credential.NewProvider(credential.Config{
		Fetcher: fakeFetcher{secret: []byte("injected-secret")},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})
	sink := evidence.NewMemSink()
	s := &Server{sink: sink, cred: prov, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	defer client.Close()

	e := singleCredentialEvent(t, sink)
	if e.CredentialMode != "inject" || e.Outcome != string(credential.OutcomeInjected) {
		t.Fatalf("credential event = %+v, want CredentialMode=inject Outcome=%s", e, credential.OutcomeInjected)
	}
	if e.Allow == nil || !*e.Allow {
		t.Fatalf("credential event Allow = %v, want true", e.Allow)
	}
	if e.User != "alice" || e.SourceIP != "10.0.0.1" || e.Target != "db1.lab.local:22" {
		t.Fatalf("credential event user/sourceip/target = %+v, want alice/10.0.0.1/db1.lab.local:22", e)
	}
	assertNoSecretLeak(t, e, "injected-secret")
}

func TestDialTarget_PromptEmitsCredentialEvidence(t *testing.T) {
	fakeConn := startFakeTarget(t, "prompted-secret")
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	sink := evidence.NewMemSink()
	s := &Server{sink: sink, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	token := s.stashTargetSecret(credential.New([]byte("prompted-secret")))
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "prompt"}, "db1.lab.local", 22, token)
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	defer client.Close()

	e := singleCredentialEvent(t, sink)
	if e.CredentialMode != "prompt" || e.Outcome != string(credential.OutcomePrompt) {
		t.Fatalf("credential event = %+v, want CredentialMode=prompt Outcome=%s", e, credential.OutcomePrompt)
	}
	if e.Allow == nil || !*e.Allow {
		t.Fatalf("credential event Allow = %v, want true", e.Allow)
	}
	assertNoSecretLeak(t, e, "prompted-secret")
}

// fakeAgentForwardConn is a minimal ssh.Conn stub whose OpenChannel returns a
// channel wired to a REAL in-memory SSH agent
// (golang.org/x/crypto/ssh/agent), so TestDialTarget_PassthroughEmitsCredentialEvidence
// can exercise dialTarget's passthrough case (and the forwardedAgentSigners
// call inside it) against a genuine agent-protocol conversation end to end —
// unlike agentfwd_test.go's fakeConn, which only covers the fail-closed path
// (see its comment on why a real success case needs a live channel).
type fakeAgentForwardConn struct {
	ssh.Conn
	channel ssh.Channel
}

func (f *fakeAgentForwardConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	if name != agentForwardChannelType {
		return nil, nil, fmt.Errorf("unexpected channel type: %s", name)
	}
	return f.channel, make(chan *ssh.Request), nil
}

// startFakeTargetNoAuth is like startFakeTarget but accepts ANY auth (or
// none), so a test can dial it using whatever ssh.ClientConfig.Auth
// dialTarget's passthrough case actually built (real signers from a forwarded
// agent) without also having to configure the fake target to recognize that
// specific key.
func startFakeTargetNoAuth(t *testing.T) net.Conn {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(testHostKey(t))

	clientConn, serverConn := fakeTargetPipe(t)
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	go func() {
		sconn, chans, reqs, err := ssh.NewServerConn(serverConn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for range chans {
		}
	}()
	return clientConn
}

func TestDialTarget_PassthroughEmitsCredentialEvidence(t *testing.T) {
	// A real in-memory ssh-agent, seeded with one generated key, standing in
	// for the client's local `ssh-agent` that `ssh -A` would forward.
	keyring := agent.NewKeyring()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	agentSide, channelSide := net.Pipe()
	t.Cleanup(func() { agentSide.Close(); channelSide.Close() })
	go agent.ServeAgent(keyring, agentSide)

	fakeConn := startFakeTargetNoAuth(t)
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	sink := evidence.NewMemSink()
	s := &Server{sink: sink, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	sconn := &fakeAgentForwardConn{channel: &fakeChannel{Reader: channelSide, Writer: channelSide}}

	client, err := s.dialTarget(context.Background(), sconn, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "passthrough"}, "db1.lab.local", 22, "")
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	defer client.Close()

	e := singleCredentialEvent(t, sink)
	if e.CredentialMode != "passthrough" || e.Outcome != string(credential.OutcomePassthrough) {
		t.Fatalf("credential event = %+v, want CredentialMode=passthrough Outcome=%s", e, credential.OutcomePassthrough)
	}
	if e.Allow == nil || !*e.Allow {
		t.Fatalf("credential event Allow = %v, want true", e.Allow)
	}
}

func TestDialTarget_DenyEmitsCredentialEvidence(t *testing.T) {
	sink := evidence.NewMemSink()
	s := &Server{sink: sink, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "deny"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}

	e := singleCredentialEvent(t, sink)
	if e.CredentialMode != "deny" || e.Outcome != string(credential.OutcomeDenied) {
		t.Fatalf("credential event = %+v, want CredentialMode=deny Outcome=%s", e, credential.OutcomeDenied)
	}
	if e.Allow == nil || *e.Allow {
		t.Fatalf("credential event Allow = %v, want false", e.Allow)
	}
}

// TestDialTarget_InjectFailClosedEmitsCredentialEvidence proves a fail-closed
// refusal (not just deny) also produces exactly one TypeCredential event,
// with Outcome reflecting the refusal.
func TestDialTarget_InjectFailClosedEmitsCredentialEvidence(t *testing.T) {
	sink := evidence.NewMemSink()
	s := &Server{sink: sink, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production; s.cred is nil
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"}, "10.0.0.1",
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}

	e := singleCredentialEvent(t, sink)
	if e.CredentialMode != "inject" || e.Outcome != "fail_closed" {
		t.Fatalf("credential event = %+v, want CredentialMode=inject Outcome=fail_closed", e)
	}
	if e.Allow == nil || *e.Allow {
		t.Fatalf("credential event Allow = %v, want false", e.Allow)
	}
}
