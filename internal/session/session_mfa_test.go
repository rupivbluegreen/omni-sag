package session

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

// fakeMFA approves only the usernames in allow; everyone else is denied.
type fakeMFA struct{ allow map[string]bool }

func (f fakeMFA) Verify(_ context.Context, req authn.MFARequest) error {
	if f.allow[req.Username] {
		return nil
	}
	return authn.ErrMFA
}

func startServerMFA(t *testing.T, auth authn.Authenticator, mfa authn.MFAProvider, sink evidence.Sink) string {
	t.Helper()
	hostKey, err := NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	d := dialer.New(policy.Policy{}, sink)
	srv := New(hostKey, auth, d, sink, WithMFA(mfa))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return ln.Addr().String()
}

func TestMFA_ApprovedUserLogsIn(t *testing.T) {
	sink := evidence.NewMemSink()
	auth := fakeAuth{users: map[string][]string{"alice": {"dba"}}}
	mfa := fakeMFA{allow: map[string]bool{"alice": true}}
	addr := startServerMFA(t, auth, mfa, sink)

	client := sshClient(t, addr, "alice") // fails the test if login is refused
	_ = client
	assertMFA(t, sink, "alice", true)
}

func TestMFA_DeniedUserRefused(t *testing.T) {
	sink := evidence.NewMemSink()
	auth := fakeAuth{users: map[string][]string{"bob": {"users"}}}
	mfa := fakeMFA{allow: map[string]bool{}} // deny everyone
	addr := startServerMFA(t, auth, mfa, sink)

	cfg := &ssh.ClientConfig{
		User:            "bob",
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if c, err := ssh.Dial("tcp", addr, cfg); err == nil {
		c.Close()
		t.Fatal("MFA denial must refuse the login")
	}
	assertMFA(t, sink, "bob", false)
}

func assertMFA(t *testing.T, sink *evidence.MemSink, user string, wantAllow bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range sink.Events() {
			if e.Type == evidence.TypeMFA && e.User == user {
				if e.Allow == nil || *e.Allow != wantAllow {
					t.Fatalf("mfa evidence for %s: allow=%v want %v", user, e.Allow, wantAllow)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no mfa evidence for %s", user)
}
