package policy

import "testing"

func demoGroupsPolicy() Policy {
	return Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba", "dba-oncall"}, // a principal need only be in one of these
		Allow:  []Rule{{Host: "db1.lab.local", Ports: []int{22}}},
	}}}
}

func TestDecide_MatchedGroupsIsIntersectionNotFullGroupList(t *testing.T) {
	p := demoGroupsPolicy()
	// alice is in "dba" (matches) AND "engineering" (irrelevant to this role).
	d := p.Decide(Principal{User: "alice", Groups: []string{"dba", "engineering"}}, Target{Host: "db1.lab.local", Port: 22})
	if !d.Allow {
		t.Fatalf("want Allow=true, got Reason=%q", d.Reason)
	}
	if len(d.MatchedGroups) != 1 || d.MatchedGroups[0] != "dba" {
		t.Fatalf("MatchedGroups = %v, want exactly [\"dba\"] (not the full Principal.Groups list)", d.MatchedGroups)
	}
}

func TestDecide_MatchedGroupsCaseInsensitive(t *testing.T) {
	p := demoGroupsPolicy()
	d := p.Decide(Principal{User: "alice", Groups: []string{"DBA"}}, Target{Host: "db1.lab.local", Port: 22})
	if !d.Allow || len(d.MatchedGroups) != 1 || d.MatchedGroups[0] != "DBA" {
		t.Fatalf("want MatchedGroups=[\"DBA\"] (the principal's own casing preserved), got %v", d.MatchedGroups)
	}
}

func TestDecideHost_MatchedGroupsSet(t *testing.T) {
	p := demoGroupsPolicy()
	d := p.DecideHost(Principal{User: "alice", Groups: []string{"dba-oncall"}}, "db1.lab.local")
	if !d.Allow || len(d.MatchedGroups) != 1 || d.MatchedGroups[0] != "dba-oncall" {
		t.Fatalf("want MatchedGroups=[\"dba-oncall\"], got %v (Allow=%v)", d.MatchedGroups, d.Allow)
	}
}

func TestDecide_MatchedGroupsEmptyOnDeny(t *testing.T) {
	p := demoGroupsPolicy()
	d := p.Decide(Principal{User: "mallory", Groups: []string{"engineering"}}, Target{Host: "db1.lab.local", Port: 22})
	if d.Allow || len(d.MatchedGroups) != 0 {
		t.Fatalf("deny decision must have empty MatchedGroups, got %v", d.MatchedGroups)
	}
}
