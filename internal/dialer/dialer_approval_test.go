package dialer

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func approvalPolicy() policy.Policy {
	return policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: "crown", Ports: []int{22}, RequireApproval: true}},
	}}}
}

func newStore(t *testing.T) *approval.FileStore {
	t.Helper()
	s, err := approval.NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// decideWhenPending approves or denies the first pending request, from a second
// human ("bob"), simulating an operator acting via the API.
func decideWhenPending(store *approval.FileStore, approve bool) {
	go func() {
		for i := 0; i < 400; i++ {
			for _, r := range store.List() {
				if r.Status == approval.StatusPending {
					if approve {
						_, _ = store.Approve(r.ID, "bob")
					} else {
						_, _ = store.Deny(r.ID, "bob")
					}
					return
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
}

func TestDialTarget_ApprovalApprovedDials(t *testing.T) {
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		c, _ := net.Pipe()
		return c, nil
	})
	store := newStore(t)
	d := New(approvalPolicy(), evidence.NewMemSink(), WithApprovals(store, time.Hour))
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	decideWhenPending(store, true)
	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.1", policy.Target{Host: "crown", Port: 22}, false)
	if err != nil {
		t.Fatalf("an approved session must proceed: %v", err)
	}
	conn.Close()
	if !dialed {
		t.Fatal("approved session should have dialed")
	}
}

func TestDialTarget_ApprovalDeniedFailsClosed(t *testing.T) {
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		c, _ := net.Pipe()
		return c, nil
	})
	store := newStore(t)
	d := New(approvalPolicy(), evidence.NewMemSink(), WithApprovals(store, time.Hour))
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	decideWhenPending(store, false)
	_, err := d.DialTarget(context.Background(), pr, "10.0.0.1", policy.Target{Host: "crown", Port: 22}, false)
	if !errors.Is(err, ErrApprovalRefused) {
		t.Fatalf("a denied session must fail closed with ErrApprovalRefused, got %v", err)
	}
	if dialed {
		t.Fatal("a denied session must NOT dial")
	}
}

func TestDialTarget_ApprovalNoStoreFailsClosed(t *testing.T) {
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		c, _ := net.Pipe()
		return c, nil
	})
	// No WithApprovals: an approval-required target must refuse, not admit.
	d := New(approvalPolicy(), evidence.NewMemSink())
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}
	_, err := d.DialTarget(context.Background(), pr, "10.0.0.1", policy.Target{Host: "crown", Port: 22}, false)
	if !errors.Is(err, ErrApprovalRefused) {
		t.Fatalf("require-approval with no store must fail closed, got %v", err)
	}
	if dialed {
		t.Fatal("must not dial without an approval")
	}
}

func TestDialTarget_ApprovalExpiredFailsClosed(t *testing.T) {
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		c, _ := net.Pipe()
		return c, nil
	})
	store := newStore(t)
	// Short TTL, nobody approves -> Wait expires -> fail closed.
	d := New(approvalPolicy(), evidence.NewMemSink(), WithApprovals(store, 60*time.Millisecond))
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}
	_, err := d.DialTarget(context.Background(), pr, "10.0.0.1", policy.Target{Host: "crown", Port: 22}, false)
	if !errors.Is(err, ErrApprovalRefused) {
		t.Fatalf("an unapproved (expired) session must fail closed, got %v", err)
	}
	if dialed {
		t.Fatal("expired approval must not dial")
	}
}
