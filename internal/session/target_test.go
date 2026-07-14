package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/credential"
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
	s := &Server{cred: prov} // targetHostKeyCB intentionally left nil
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
	if dialed {
		t.Fatal("missing target host-key callback must fail closed before any dial is attempted")
	}
}

func TestDialTarget_Deny(t *testing.T) {
	s := &Server{targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "deny"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestDialTarget_InjectNoProviderFailsClosed(t *testing.T) {
	s := &Server{targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production; s.cred is nil
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
}

func TestDialTarget_PromptNoStashedSecretFailsClosed(t *testing.T) {
	s := &Server{targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
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
	s := &Server{targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
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
	s := &Server{cred: prov, targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
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

	s := &Server{targetHostKeyCB: ssh.InsecureIgnoreHostKey()} // test fixture: deliberate, not production
	token := s.stashTargetSecret(credential.New([]byte("prompted-secret")))
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "prompt"}, "db1.lab.local", 22, token)
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	defer client.Close()
}

// fakeFetcher implements credential.Fetcher for TestDialTarget_InjectSucceeds.
type fakeFetcher struct{ secret []byte }

func (f fakeFetcher) Fetch(_ context.Context, _ credential.Query) (*credential.Secret, error) {
	return credential.New(append([]byte(nil), f.secret...)), nil
}
