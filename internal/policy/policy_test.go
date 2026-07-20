package policy

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// twoPcodePolicy models two pcodes whose subnets overlap on the same host — the
// shared-network case where DecideHost is otherwise ambiguous. Each pcode is a
// distinct role; a member of both reaches the shared host via either, which the
// "+pcode" selector (Principal.SelectedRole) disambiguates. Documentation-range
// IP (RFC 5737) and synthetic names keep this free of any real infrastructure.
func twoPcodePolicy() Policy {
	return Policy{Roles: []Role{
		{Name: "pcodeA", Groups: []string{"grp-a"}, Allow: []Rule{{Host: "192.0.2.10", Ports: []int{22}, Credential: "prompt"}}},
		{Name: "pcodeB", Groups: []string{"grp-b"}, Allow: []Rule{{Host: "192.0.2.10", Ports: []int{22}, Credential: "prompt"}}},
	}}
}

func TestDecideHost_AmbiguousAcrossPcodesNamesThem(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"grp-a", "grp-b"}}
	d := twoPcodePolicy().DecideHost(pr, "192.0.2.10", nil)
	if d.Allow {
		t.Fatal("a host permitted by two pcodes without a selector must be refused as ambiguous")
	}
	if !strings.Contains(d.Reason, "ambiguous") || !strings.Contains(d.Reason, "pcodeA") || !strings.Contains(d.Reason, "pcodeB") {
		t.Fatalf("reason should say ambiguous and name both pcodes, got %q", d.Reason)
	}
}

func TestDecideHost_SelectorResolvesAmbiguity(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"grp-a", "grp-b"}, SelectedRole: "pcodeB"}
	d := twoPcodePolicy().DecideHost(pr, "192.0.2.10", nil)
	if !d.Allow || d.MatchedRole != "pcodeB" || d.Port != 22 {
		t.Fatalf("want allow via pcodeB on port 22, got allow=%v role=%q port=%d reason=%q", d.Allow, d.MatchedRole, d.Port, d.Reason)
	}
}

func TestDecideHost_SelectorCaseInsensitive(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"grp-a", "grp-b"}, SelectedRole: "PCODEB"}
	if d := twoPcodePolicy().DecideHost(pr, "192.0.2.10", nil); !d.Allow || d.MatchedRole != "pcodeB" {
		t.Fatalf("selector should match role name case-insensitively, got allow=%v role=%q", d.Allow, d.MatchedRole)
	}
}

func TestDecide_SelectorNotHeldDeniesGenerically(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"grp-a"}, SelectedRole: "pcodeB"} // holds A, selects B
	if dh := twoPcodePolicy().DecideHost(pr, "192.0.2.10", nil); dh.Allow || dh.Reason != selectorDeniedReason {
		t.Fatalf("DecideHost with unheld selector: want generic deny, got allow=%v reason=%q", dh.Allow, dh.Reason)
	}
	// The -L tunnel path (Decide, with a port) must deny identically.
	if d := twoPcodePolicy().Decide(pr, Target{Host: "192.0.2.10", Port: 22}, nil); d.Allow || d.Reason != selectorDeniedReason {
		t.Fatalf("Decide with unheld selector: want generic deny, got allow=%v reason=%q", d.Allow, d.Reason)
	}
}

func TestDecideHost_ExplicitPortMatchesAnyPortRule(t *testing.T) {
	// A rule with omitted ports (any) is "0 configured ports" for the host-only
	// path, but with an explicit client port ("%host:port") it authorizes
	// host+port and dials the client's port.
	p := Policy{Roles: []Role{{Name: "r", Groups: []string{"g"}, Allow: []Rule{{Host: "192.0.2.10", Credential: "prompt"}}}}}
	pr := Principal{User: "alice", Groups: []string{"g"}, TargetPort: 2222}
	d := p.DecideHost(pr, "192.0.2.10", nil)
	if !d.Allow || d.Port != 2222 || d.CredentialMode != "prompt" {
		t.Fatalf("explicit port vs any-port rule: allow=%v port=%d cred=%q reason=%q", d.Allow, d.Port, d.CredentialMode, d.Reason)
	}
}

func TestDecideHost_ExplicitPortGatedByRulePorts(t *testing.T) {
	p := Policy{Roles: []Role{{Name: "r", Groups: []string{"g"}, Allow: []Rule{{Host: "192.0.2.10", Ports: []int{22}}}}}}
	if d := p.DecideHost(Principal{User: "a", Groups: []string{"g"}, TargetPort: 22}, "192.0.2.10", nil); !d.Allow || d.Port != 22 {
		t.Fatalf("port 22 in [22]: allow=%v port=%d", d.Allow, d.Port)
	}
	if d := p.DecideHost(Principal{User: "a", Groups: []string{"g"}, TargetPort: 2345}, "192.0.2.10", nil); d.Allow {
		t.Fatalf("port 2345 not in [22] must deny, got allow")
	}
}

func TestDecideHost_HostOnlyStillRequiresExactlyOnePort(t *testing.T) {
	// No TargetPort → the existing "matched rule must name exactly one port"
	// requirement is unchanged (a 0-port rule is ambiguous).
	p := Policy{Roles: []Role{{Name: "r", Groups: []string{"g"}, Allow: []Rule{{Host: "192.0.2.10"}}}}}
	if d := p.DecideHost(Principal{User: "a", Groups: []string{"g"}}, "192.0.2.10", nil); d.Allow {
		t.Fatalf("host-only vs 0-port rule must deny as ambiguous, got allow (reason=%q)", d.Reason)
	}
}

func TestDecide_SelectorScopesTunnelDecision(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"grp-a", "grp-b"}, SelectedRole: "pcodeA"}
	if d := twoPcodePolicy().Decide(pr, Target{Host: "192.0.2.10", Port: 22}, nil); !d.Allow || d.MatchedRole != "pcodeA" {
		t.Fatalf("want -L decision scoped to pcodeA, got allow=%v role=%q", d.Allow, d.MatchedRole)
	}
}

// demoPolicy mirrors the Slice 1 demo: a "dba" role granting the DB host, keyed
// off the "dba" AD group.
func demoPolicy() Policy {
	return Policy{Roles: []Role{
		{
			Name:   "dba",
			Groups: []string{"dba"},
			Allow:  []Rule{{Host: "db1.lab.local", Ports: []int{5432}}},
		},
	}}
}

func TestDecide_DBAAllowed(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"dba", "domain users"}}
	d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432}, nil)
	if !d.Allow {
		t.Fatalf("dba should be allowed, got deny: %s", d.Reason)
	}
	if d.MatchedRole != "dba" {
		t.Fatalf("MatchedRole = %q, want dba", d.MatchedRole)
	}
}

func TestDecide_NonDBADenied(t *testing.T) {
	pr := Principal{User: "bob", Groups: []string{"domain users"}}
	d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432}, nil)
	if d.Allow {
		t.Fatal("non-dba must be denied")
	}
}

func TestDecide_DefaultDeny_NoRoles(t *testing.T) {
	pr := Principal{User: "nobody", Groups: nil}
	d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432}, nil)
	if d.Allow {
		t.Fatal("principal with no groups must be denied")
	}
}

func TestDecide_RoleButWrongTarget(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	// right host, wrong port
	if d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 22}, nil); d.Allow {
		t.Fatal("wrong port must be denied")
	}
	// wrong host, right port
	if d := demoPolicy().Decide(pr, Target{Host: "evil.lab.local", Port: 5432}, nil); d.Allow {
		t.Fatal("wrong host must be denied")
	}
}

func TestDecide_GroupMatchCaseInsensitive(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"DBA"}}
	if d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432}, nil); !d.Allow {
		t.Fatalf("group match must be case-insensitive, got: %s", d.Reason)
	}
}

func TestRule_WildcardHostAnyPort(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "admin",
		Groups: []string{"admins"},
		Allow:  []Rule{{Host: "*"}}, // any host, any port
	}}}
	pr := Principal{User: "root", Groups: []string{"admins"}}
	if d := p.Decide(pr, Target{Host: "anything.lab.local", Port: 9999}, nil); !d.Allow {
		t.Fatalf("wildcard host/any-port must allow, got: %s", d.Reason)
	}
}

func TestDecide_RecordModeAndForwarding(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []Rule{
			{Host: "full.lab", Ports: []int{22}, Record: RecordFull},
			{Host: "meta.lab", Ports: []int{22}, Record: RecordMetadataOnly},
			{Host: "plain.lab", Ports: []int{22}}, // no record -> normalizes to none
		},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}

	full := p.Decide(pr, Target{Host: "full.lab", Port: 22}, nil)
	if full.RecordMode != RecordFull || full.ForwardingAllowed() {
		t.Fatalf("full target must forbid forwarding: %+v", full)
	}
	meta := p.Decide(pr, Target{Host: "meta.lab", Port: 22}, nil)
	if meta.RecordMode != RecordMetadataOnly || !meta.ForwardingAllowed() {
		t.Fatalf("metadata-only must allow forwarding: %+v", meta)
	}
	plain := p.Decide(pr, Target{Host: "plain.lab", Port: 22}, nil)
	if plain.RecordMode != RecordNone || !plain.ForwardingAllowed() {
		t.Fatalf("unset record must be none + forwarding allowed: %+v", plain)
	}
}

func TestRecordMode_Normalize(t *testing.T) {
	if RecordMode("").Normalize() != RecordNone {
		t.Fatal("empty must normalize to none")
	}
	if RecordMode("bogus").Normalize() != RecordNone {
		t.Fatal("unknown must normalize to none")
	}
	if RecordFull.Normalize() != RecordFull {
		t.Fatal("full must stay full")
	}
}

func TestDecide_CarriesTargetUser(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "db1.lab.local", TargetUser: "svc_db1"}},
	}}}
	d := p.Decide(Principal{User: "alice", Groups: []string{"dba"}}, Target{Host: "db1.lab.local", Port: 22}, nil)
	if !d.Allow || d.TargetUser != "svc_db1" {
		t.Fatalf("got Allow=%v TargetUser=%q, want Allow=true TargetUser=svc_db1", d.Allow, d.TargetUser)
	}
}

func TestDecide_TargetUserEmptyWhenUnset(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []Rule{{Host: "db1.lab.local"}},
	}}}
	d := p.Decide(Principal{User: "alice", Groups: []string{"dba"}}, Target{Host: "db1.lab.local", Port: 22}, nil)
	if d.TargetUser != "" {
		t.Fatalf("got TargetUser=%q, want empty (caller defaults to login user)", d.TargetUser)
	}
}

func TestDecide_CIDRRuleMatchesLiteralIPInRange(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "10.0.0.0/8", Ports: []int{5432}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.Decide(pr, Target{Host: "10.5.6.7", Port: 5432}, nil)
	if !d.Allow {
		t.Fatalf("literal IP inside the CIDR must be allowed even with a nil resolver, got deny: %s", d.Reason)
	}
	if d.MatchedCIDR == nil || d.MatchedCIDR.String() != "10.0.0.0/8" {
		t.Fatalf("MatchedCIDR = %v, want 10.0.0.0/8", d.MatchedCIDR)
	}
}

func TestDecide_CIDRRuleDeniesLiteralIPOutOfRange(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "10.0.0.0/8", Ports: []int{5432}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.Decide(pr, Target{Host: "192.168.1.1", Port: 5432}, nil)
	if d.Allow {
		t.Fatal("literal IP outside the CIDR must be denied")
	}
}

func TestDecide_CIDRRuleStillEnforcesPort(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "10.0.0.0/8", Ports: []int{5432}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.Decide(pr, Target{Host: "10.5.6.7", Port: 22}, nil)
	if d.Allow {
		t.Fatal("a CIDR rule with an explicit ports list must still enforce the port")
	}
}

func TestDecide_CIDRRuleMatchesResolvedHostname(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.1.2.3")}, nil
	}
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "10.0.0.0/8", Ports: []int{5432}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.Decide(pr, Target{Host: "db.internal.corp", Port: 5432}, resolve)
	if !d.Allow {
		t.Fatalf("hostname resolving inside the CIDR must be allowed, got deny: %s", d.Reason)
	}
	if d.MatchedCIDR == nil || d.MatchedCIDR.String() != "10.0.0.0/8" {
		t.Fatalf("MatchedCIDR = %v, want 10.0.0.0/8", d.MatchedCIDR)
	}
}

func TestDecide_CIDRNotConsultedWhenExactRuleMatches(t *testing.T) {
	called := false
	spy := func(host string) ([]net.IP, error) {
		called = true
		return nil, nil
	}
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow: []Rule{
			{Host: "db1.lab.local", Ports: []int{5432}},
			{Host: "10.0.0.0/8", Ports: []int{5432}},
		},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.Decide(pr, Target{Host: "db1.lab.local", Port: 5432}, spy)
	if !d.Allow {
		t.Fatalf("exact rule should allow, got deny: %s", d.Reason)
	}
	if called {
		t.Fatal("resolver must not be called when an exact/wildcard rule already matched (cheap-first ordering)")
	}
}

func TestDecide_CIDRHostnameDeniedWithNilResolver(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "10.0.0.0/8", Ports: []int{5432}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.Decide(pr, Target{Host: "db.internal.corp", Port: 5432}, nil)
	if d.Allow {
		t.Fatal("a hostname target against a CIDR rule with a nil resolver must be denied, not allowed")
	}
}

func TestDecide_CIDRHostnameDeniedOnResolverError(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) { return nil, fmt.Errorf("dns down") }
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "10.0.0.0/8", Ports: []int{5432}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.Decide(pr, Target{Host: "db.internal.corp", Port: 5432}, resolve)
	if d.Allow {
		t.Fatal("a resolver error must fail closed (deny), not allow")
	}
}
