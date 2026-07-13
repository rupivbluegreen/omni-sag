package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func demoPolicy() policy.Policy {
	return policy.Policy{Roles: []policy.Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []policy.Rule{{Host: "db1.lab.local", Ports: []int{5432}}},
	}}}
}

// swapDial replaces the target dial for the duration of a test.
func swapDial(t *testing.T, fn func(ctx context.Context, network, addr string) (net.Conn, error)) {
	t.Helper()
	orig := netDial
	netDial = fn
	t.Cleanup(func() { netDial = orig })
}

func TestDialTarget_AllowedDials(t *testing.T) {
	dialed := ""
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = addr
		client, _ := net.Pipe()
		return client, nil
	})

	sink := evidence.NewMemSink()
	d := New(demoPolicy(), sink)
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432})
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	conn.Close()
	if dialed != "db1.lab.local:5432" {
		t.Fatalf("dialed %q, want db1.lab.local:5432", dialed)
	}
	ev := sink.Events()
	if len(ev) != 1 || ev[0].Allow == nil || !*ev[0].Allow {
		t.Fatalf("expected one allow decision event, got %+v", ev)
	}
	if ev[0].SourceIP != "10.0.0.5" || ev[0].MatchedRole != "dba" {
		t.Fatalf("evidence missing source/role: %+v", ev[0])
	}
}

func TestDialTarget_DeniedDoesNotDial(t *testing.T) {
	dialCalled := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCalled = true
		client, _ := net.Pipe()
		return client, nil
	})

	sink := evidence.NewMemSink()
	d := New(demoPolicy(), sink)
	pr := policy.Principal{User: "bob", Groups: []string{"users"}}

	_, err := d.DialTarget(context.Background(), pr, "10.0.0.6", policy.Target{Host: "db1.lab.local", Port: 5432})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
	if dialCalled {
		t.Fatal("deny must not open a socket")
	}
	ev := sink.Events()
	if len(ev) != 1 || ev[0].Allow == nil || *ev[0].Allow {
		t.Fatalf("expected one deny decision event, got %+v", ev)
	}
}

func TestSplice_Bidirectional(t *testing.T) {
	// Wire client(a1)<->a2 and b1<->target(b2), splicing a2<->b1.
	// Bytes written at a1 must arrive at b2, and vice versa.
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	go Splice(a2, b1)

	read := func(c net.Conn, n int) string {
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Errorf("read: %v", err)
			return ""
		}
		return string(buf)
	}

	// client -> target
	go a1.Write([]byte("ping"))
	if got := read(b2, 4); got != "ping" {
		t.Fatalf("target got %q, want ping", got)
	}
	// target -> client
	go b2.Write([]byte("pong"))
	if got := read(a1, 4); got != "pong" {
		t.Fatalf("client got %q, want pong", got)
	}

	a1.Close()
	b2.Close()
}
