package session

import (
	"context"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"golang.org/x/crypto/ssh"
)

// Chaos / fail-closed matrix at the SSH front door.
//
// When the directory (Authenticator) or the second factor (MFAProvider) is
// DOWN, the handshake MUST be refused: no SSH session is granted, and the
// outage is recorded as a not-allowed evidence event — an infrastructure
// failure is never mistaken for a successful login.

// downAuth models a directory that is unreachable: every attempt fails closed.
type downAuth struct{}

func (downAuth) Authenticate(context.Context, string, string) (authn.Identity, error) {
	return authn.Identity{}, authn.ErrAuth
}

// downMFA models a RADIUS/MFA service that is unreachable: every verify fails.
type downMFA struct{}

func (downMFA) Verify(context.Context, authn.MFARequest) error { return authn.ErrMFA }

// dialShouldFail attempts an SSH password login and asserts it is refused.
func dialShouldFail(t *testing.T, addr, user string) {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if c, err := ssh.Dial("tcp", addr, cfg); err == nil {
		c.Close()
		t.Fatal("login must be refused when a dependency is down")
	}
}

// waitNotAllowed asserts an evidence event of the given type for user is present
// and marked not-allowed within a short window.
func waitNotAllowed(t *testing.T, sink *evidence.MemSink, typ evidence.Type, user string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range sink.Events() {
			if e.Type == typ && e.User == user {
				if e.Allow == nil || *e.Allow {
					t.Fatalf("%s evidence for %s must be not-allowed, got allow=%v", typ, user, e.Allow)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s evidence for %s", typ, user)
}

// DIRECTORY DOWN: the authenticator fails closed → login refused, auth evidence
// marked not-allowed. No session is granted.
func TestChaos_AuthenticatorDownRefusesLogin(t *testing.T) {
	sink := evidence.NewMemSink()
	addr := startServerMFA(t, downAuth{}, nil, sink)
	dialShouldFail(t, addr, "alice")
	waitNotAllowed(t, sink, evidence.TypeAuth, "alice")
}

// MFA DOWN: primary auth succeeds but the second factor is unreachable → login
// refused (fail closed), MFA evidence marked not-allowed. Primary success is
// NOT enough.
func TestChaos_MFADownRefusesLogin(t *testing.T) {
	sink := evidence.NewMemSink()
	auth := fakeAuth{users: map[string][]string{"alice": {"dba"}}}
	addr := startServerMFA(t, auth, downMFA{}, sink)
	dialShouldFail(t, addr, "alice")
	waitNotAllowed(t, sink, evidence.TypeMFA, "alice")
}
