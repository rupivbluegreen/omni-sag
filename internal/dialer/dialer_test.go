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
	// Adapt the 3-arg test fake to the seam's control-carrying signature; the
	// fake replaces the whole socket so the guard control is intentionally
	// bypassed (guard behavior is exercised via the real path in guard tests).
	netDial = func(ctx context.Context, network, addr string, _ dialControlFunc) (net.Conn, error) {
		return fn(ctx, network, addr)
	}
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

	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432}, false)
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

// failSink returns an error on every Emit, simulating a degraded evidence sink.
type failSink struct{}

func (failSink) Emit(evidence.Event) error { return errors.New("sink down") }
func (failSink) Close() error              { return nil }

func TestDialTarget_AllowProceedsWhenEvidenceEmitFails(t *testing.T) {
	// An evidence sink outage must not break the allow path (the failure is
	// logged, not swallowed silently, and the decision stands).
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		client, _ := net.Pipe()
		return client, nil
	})
	d := New(demoPolicy(), failSink{})
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}
	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432}, false)
	if err != nil {
		t.Fatalf("allow must still dial despite evidence failure, got %v", err)
	}
	conn.Close()
	if !dialed {
		t.Fatal("target should have been dialed")
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

	_, err := d.DialTarget(context.Background(), pr, "10.0.0.6", policy.Target{Host: "db1.lab.local", Port: 5432}, false)
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

// fullRecPolicy grants db1 with full recording (forwarding must be refused) and
// db2 with metadata-only (forwarding allowed, unrecorded).
func recPolicy() policy.Policy {
	return policy.Policy{Roles: []policy.Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow: []policy.Rule{
			{Host: "db1.lab.local", Ports: []int{5432}, Record: policy.RecordFull},
			{Host: "db2.lab.local", Ports: []int{5432}, Record: policy.RecordMetadataOnly},
		},
	}}}
}

func TestDialTarget_ForwardingRefusedOnFullRecordingTarget(t *testing.T) {
	dialCalled := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCalled = true
		c, _ := net.Pipe()
		return c, nil
	})
	sink := evidence.NewMemSink()
	d := New(recPolicy(), sink)
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	_, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432}, true)
	if !errors.Is(err, ErrForwardingRefused) {
		t.Fatalf("forwarding to a full-recording target must be refused, got %v", err)
	}
	if dialCalled {
		t.Fatal("forwarding refusal must not open a socket")
	}
	ev := sink.Events()
	if len(ev) != 1 || ev[0].Allow == nil || *ev[0].Allow {
		t.Fatalf("expected a single deny (forwarding refused) event, got %+v", ev)
	}
	if ev[0].RecordMode != string(policy.RecordFull) {
		t.Fatalf("evidence should record the full mode, got %q", ev[0].RecordMode)
	}
}

func TestDialTarget_ForwardingAllowedOnMetadataOnly(t *testing.T) {
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	})
	sink := evidence.NewMemSink()
	d := New(recPolicy(), sink)
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db2.lab.local", Port: 5432}, true)
	if err != nil {
		t.Fatalf("forwarding to a metadata-only target must be allowed, got %v", err)
	}
	conn.Close()
	ev := sink.Events()
	if len(ev) != 1 || ev[0].Allow == nil || !*ev[0].Allow {
		t.Fatalf("expected one allow event, got %+v", ev)
	}
	if ev[0].RecordMode != string(policy.RecordMetadataOnly) {
		t.Fatalf("evidence must mark the session metadata-only (unrecorded), got %q", ev[0].RecordMode)
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

func TestPeek_NoEvidenceNoSocket(t *testing.T) {
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial")
	})
	sink := &captureSink{}
	d := New(demoPolicy(), sink)

	dec := d.Peek(policy.Principal{User: "alice", Groups: []string{"dba"}}, policy.Target{Host: "db1.lab.local", Port: 5432})
	if !dec.Allow {
		t.Fatalf("Peek: want Allow=true, got %+v", dec)
	}
	if dialed {
		t.Fatal("Peek must never dial a socket")
	}
	if len(sink.events) != 0 {
		t.Fatalf("Peek must never emit evidence, got %d events", len(sink.events))
	}
}

type captureSink struct{ events []evidence.Event }

func (s *captureSink) Emit(e evidence.Event) error { s.events = append(s.events, e); return nil }
func (s *captureSink) Close() error                { return nil }
