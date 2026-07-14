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
	d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432})
	if !d.Allow {
		t.Fatalf("dba should be allowed, got deny: %s", d.Reason)
	}
	if d.MatchedRole != "dba" {
		t.Fatalf("MatchedRole = %q, want dba", d.MatchedRole)
	}
}

func TestDecide_NonDBADenied(t *testing.T) {
	pr := Principal{User: "bob", Groups: []string{"domain users"}}
	d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432})
	if d.Allow {
		t.Fatal("non-dba must be denied")
	}
}

func TestDecide_DefaultDeny_NoRoles(t *testing.T) {
	pr := Principal{User: "nobody", Groups: nil}
	d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432})
	if d.Allow {
		t.Fatal("principal with no groups must be denied")
	}
}

func TestDecide_RoleButWrongTarget(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	// right host, wrong port
	if d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 22}); d.Allow {
		t.Fatal("wrong port must be denied")
	}
	// wrong host, right port
	if d := demoPolicy().Decide(pr, Target{Host: "evil.lab.local", Port: 5432}); d.Allow {
		t.Fatal("wrong host must be denied")
	}
}

func TestDecide_GroupMatchCaseInsensitive(t *testing.T) {
	pr := Principal{User: "alice", Groups: []string{"DBA"}}
	if d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432}); !d.Allow {
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
	if d := p.Decide(pr, Target{Host: "anything.lab.local", Port: 9999}); !d.Allow {
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

	full := p.Decide(pr, Target{Host: "full.lab", Port: 22})
	if full.RecordMode != RecordFull || full.ForwardingAllowed() {
		t.Fatalf("full target must forbid forwarding: %+v", full)
	}
	meta := p.Decide(pr, Target{Host: "meta.lab", Port: 22})
	if meta.RecordMode != RecordMetadataOnly || !meta.ForwardingAllowed() {
		t.Fatalf("metadata-only must allow forwarding: %+v", meta)
	}
	plain := p.Decide(pr, Target{Host: "plain.lab", Port: 22})
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
