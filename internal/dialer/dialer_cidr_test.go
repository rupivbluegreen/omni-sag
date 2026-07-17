package dialer

import (
	"context"
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
