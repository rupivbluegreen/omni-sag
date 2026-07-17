package dialer

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func cidrPolicy() policy.Policy {
	return policy.Policy{Roles: []policy.Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []policy.Rule{{Host: "10.0.0.0/8", Ports: []int{5432}}},
	}}}
}

func TestDialTarget_CIDRRuleAllowsLiteralIPWithNoResolverConfigured(t *testing.T) {
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		c, _ := net.Pipe()
		return c, nil
	})
	d := New(cidrPolicy(), evidence.NewMemSink())
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	_, err := d.DialTarget(context.Background(), pr, "1.2.3.4", policy.Target{Host: "10.5.6.7", Port: 5432}, false)
	if err != nil {
		t.Fatalf("literal IP inside the CIDR must dial, got %v", err)
	}
	if !dialed {
		t.Fatal("expected a dial attempt")
	}
}

func TestDialTarget_CIDRRuleUsesConfiguredResolverForHostname(t *testing.T) {
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		c, _ := net.Pipe()
		return c, nil
	})
	resolve := func(host string) ([]net.IP, error) {
		if host != "db.internal.corp" {
			t.Fatalf("unexpected resolve host %q", host)
		}
		return []net.IP{net.ParseIP("10.9.9.9")}, nil
	}
	d := New(cidrPolicy(), evidence.NewMemSink(), WithHostnameResolver(resolve))
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	_, err := d.DialTarget(context.Background(), pr, "1.2.3.4", policy.Target{Host: "db.internal.corp", Port: 5432}, false)
	if err != nil {
		t.Fatalf("hostname resolving inside the CIDR must dial, got %v", err)
	}
	if !dialed {
		t.Fatal("expected a dial attempt")
	}
}

func TestDialTarget_CIDRRuleDeniesHostnameWhenResolutionDisabled(t *testing.T) {
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		c, _ := net.Pipe()
		return c, nil
	})
	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.9.9.9")}, nil
	}
	d := New(cidrPolicy(), evidence.NewMemSink(), WithHostnameResolver(resolve), WithHostnameResolutionDisabled())
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	_, err := d.DialTarget(context.Background(), pr, "1.2.3.4", policy.Target{Host: "db.internal.corp", Port: 5432}, false)
	if err == nil {
		t.Fatal("hostname target against a CIDR rule must be denied when resolution is disabled")
	}
	if dialed {
		t.Fatal("must not dial when denied")
	}
}

func TestPeekHost_CIDR_RuleResolvesHostname(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.9.9.9")}, nil
	}
	p := policy.Policy{Roles: []policy.Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []policy.Rule{{Host: "10.0.0.0/8", Ports: []int{2200}}},
	}}}
	d := New(p, evidence.NewMemSink(), WithHostnameResolver(resolve))
	dec := d.PeekHost(policy.Principal{User: "alice", Groups: []string{"dba"}}, "db.internal.corp")
	if !dec.Allow || dec.Port != 2200 {
		t.Fatalf("PeekHost must resolve the hostname through the configured resolver, got %+v", dec)
	}
}

func TestDialTarget_CIDRRebindDefenseRefusesAddressOutsideMatchedRange(t *testing.T) {
	// Policy decides against db.internal.corp resolving to 10.9.9.9 (inside
	// 10.0.0.0/8, allowed). But the actual connection — netDial, swapped here
	// to simulate what the OS resolver returns at connect time — resolves to
	// 203.0.113.1, outside the matched range. This must be refused even
	// though the policy decision itself was Allow: true.
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		c, _ := net.Pipe()
		return c, nil
	})
	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.9.9.9")}, nil
	}
	d := New(cidrPolicy(), evidence.NewMemSink(), WithHostnameResolver(resolve))
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	dec := d.Peek(pr, policy.Target{Host: "db.internal.corp", Port: 5432})
	if !dec.Allow || dec.MatchedCIDR == nil {
		t.Fatalf("test setup: expected an allowed CIDR match, got %+v", dec)
	}

	// swapDial bypasses the real Control callback entirely (see its doc
	// comment), so this specific test exercises guardWithinCIDR directly
	// instead of end-to-end — the end-to-end path is exactly what
	// TestDialTarget_SSRFGuardBlocksLoopback (dialer_ssrf_test.go) already
	// proves for the existing SSRF guard, using a real listener instead of a
	// swapped dial.
	err := guardWithinCIDR("tcp", "203.0.113.1:5432", dec.MatchedCIDR)
	if err == nil {
		t.Fatal("an address outside the matched CIDR must be refused")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got %v", err)
	}
	_ = dialed
}

func TestDialTarget_CIDRRebindDefenseWrapsControlCallback(t *testing.T) {
	var capturedControl dialControlFunc
	orig := netDial
	netDial = func(ctx context.Context, network, addr string, control dialControlFunc) (net.Conn, error) {
		capturedControl = control
		c, _ := net.Pipe()
		return c, nil
	}
	t.Cleanup(func() { netDial = orig })

	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.9.9.9")}, nil
	}
	d := New(cidrPolicy(), evidence.NewMemSink(), WithHostnameResolver(resolve))
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	_, err := d.DialTarget(context.Background(), pr, "1.2.3.4", policy.Target{Host: "db.internal.corp", Port: 5432}, false)
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if capturedControl == nil {
		t.Fatal("expected a Control callback to be passed to netDial")
	}

	// Simulate the OS resolving db.internal.corp to an address OUTSIDE the
	// matched CIDR at actual connect time (a rebind, moments after the policy
	// decision above used a different resolution) — the captured Control must
	// refuse it even though the policy decision itself was Allow.
	if err := capturedControl("tcp", "203.0.113.1:5432", nil); err == nil {
		t.Fatal("captured Control must refuse an address outside the matched CIDR")
	}
	// And it must still accept the in-range address the policy actually matched
	// (proving the wrapped Control composes with, rather than replaces, the
	// base guard — guardResolvedAddr's syscall.RawConn parameter is unused by
	// both checks, so nil is safe here).
	if err := capturedControl("tcp", "10.9.9.9:5432", nil); err != nil {
		t.Fatalf("captured Control must accept the in-range address, got %v", err)
	}
}
