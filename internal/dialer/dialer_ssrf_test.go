package dialer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// anyHostPolicy authorizes any host on any port for group "dba". It models the
// SSRF setup: authorization is on the host STRING, so a policy-allowed name
// that resolves to an internal IP is authorized by policy — the resolved-address
// guard is the layer that must still refuse the socket.
func anyHostPolicy() policy.Policy {
	return policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: "*"}},
	}}}
}

// TestDialTarget_SSRFGuardBlocksLoopback drives the REAL dial path (netDial is
// not swapped) against a live loopback listener. Policy allows the host, so the
// tunnel decision is emitted as ALLOW, but the socket to the resolved loopback
// address must be refused by the guard: no usable connection is returned. This
// is the DNS-rebinding / SSRF defense end-to-end — a policy-allowed target that
// resolves to an internal IP cannot be reached.
func TestDialTarget_SSRFGuardBlocksLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := ln.Addr().(*net.TCPAddr).Port

	sink := evidence.NewMemSink()
	d := New(anyHostPolicy(), sink)
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5",
		policy.Target{Host: "127.0.0.1", Port: port}, false)
	if err == nil {
		conn.Close()
		t.Fatalf("guard must refuse a loopback target (port %s)", portStr)
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got %v", err)
	}

	// The listener must NOT have accepted a connection: the guard aborts before
	// connect completes.
	select {
	case <-accepted:
		t.Fatal("guard failed: a socket to the loopback listener was established")
	case <-time.After(150 * time.Millisecond):
	}

	// Policy-level authorization still happened and was evidenced as an allow;
	// the guard is a distinct socket-level defense, not a policy decision.
	ev := sink.Events()
	if len(ev) != 1 || ev[0].Type != evidence.TypeTunnelDecision || ev[0].Allow == nil || !*ev[0].Allow {
		t.Fatalf("expected one ALLOW tunnel_decision (host-level authz), got %+v", ev)
	}
}

// TestDialTarget_SSRFGuardBlocksMetadataIP is the headline case: a target that
// resolves to the cloud metadata IP (169.254.169.254) must be refused. We use
// the IP literal directly (equivalent to a hostname rebound to it) and confirm
// no socket is opened even though policy authorizes the host.
func TestDialTarget_SSRFGuardBlocksMetadataIP(t *testing.T) {
	sink := evidence.NewMemSink()
	d := New(anyHostPolicy(), sink)
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5",
		policy.Target{Host: "169.254.169.254", Port: 80}, false)
	if err == nil {
		conn.Close()
		t.Fatal("guard must refuse the cloud metadata IP 169.254.169.254")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress for metadata IP, got %v", err)
	}
}

// TestDialTarget_SSRFGuardBlocksUnspecified confirms 0.0.0.0 is refused end to
// end through the real dial path.
func TestDialTarget_SSRFGuardBlocksUnspecified(t *testing.T) {
	d := New(anyHostPolicy(), evidence.NewMemSink())
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}
	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5",
		policy.Target{Host: "0.0.0.0", Port: 80}, false)
	if err == nil {
		conn.Close()
		t.Fatal("guard must refuse 0.0.0.0")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress for 0.0.0.0, got %v", err)
	}
}
