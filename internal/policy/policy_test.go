package policy

import "testing"

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
