package dialer

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func credPolicy(mode string) policy.Policy {
	return policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: "db1.lab.local", Ports: []int{5432}, Credential: mode}},
	}}}
}

// inject with no CyberArk fetcher must fail closed: no socket, ErrCredentialRefused,
// and a credential evidence event marked not-allowed. Never a downgrade.
func TestDialTarget_InjectFailsClosed(t *testing.T) {
	dialCalled := false
	swapDial(t, func(context.Context, string, string) (net.Conn, error) {
		dialCalled = true
		c, _ := net.Pipe()
		return c, nil
	})
	sink := evidence.NewMemSink()
	d := New(credPolicy("inject"), sink) // default provider has no fetcher

	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}
	_, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432}, false)
	if !errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("inject without CyberArk must fail closed, got %v", err)
	}
	if dialCalled {
		t.Fatal("fail-closed must not open a socket")
	}
	if !credEvent(sink, false) {
		t.Fatalf("expected a not-allowed credential event, got %+v", sink.Events())
	}
}

func TestDialTarget_CredentialDeny(t *testing.T) {
	dialCalled := false
	swapDial(t, func(context.Context, string, string) (net.Conn, error) {
		dialCalled = true
		c, _ := net.Pipe()
		return c, nil
	})
	sink := evidence.NewMemSink()
	d := New(credPolicy("deny"), sink)

	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}
	_, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432}, false)
	if !errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("deny must refuse, got %v", err)
	}
	if dialCalled {
		t.Fatal("deny must not open a socket")
	}
}

// A working inject fetcher lets the dial proceed and records an allowed
// credential event.
func TestDialTarget_InjectSucceedsAndDials(t *testing.T) {
	dialed := ""
	swapDial(t, func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		c, _ := net.Pipe()
		return c, nil
	})
	sink := evidence.NewMemSink()
	prov := credential.NewProvider(credential.Config{
		Fetcher: okFetcher{},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})
	d := New(credPolicy("inject"), sink, WithCredentialProvider(prov))

	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}
	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432}, false)
	if err != nil {
		t.Fatalf("inject with a working fetcher must dial: %v", err)
	}
	conn.Close()
	if dialed != "db1.lab.local:5432" {
		t.Fatalf("dialed %q", dialed)
	}
	if !credEvent(sink, true) {
		t.Fatalf("expected an allowed credential event, got %+v", sink.Events())
	}
}

type okFetcher struct{}

func (okFetcher) Fetch(context.Context, credential.Query) (*credential.Secret, error) {
	return credential.New([]byte("target-secret")), nil
}

func credEvent(sink *evidence.MemSink, wantAllow bool) bool {
	for _, e := range sink.Events() {
		if e.Type == evidence.TypeCredential && e.Allow != nil && *e.Allow == wantAllow {
			return true
		}
	}
	return false
}
