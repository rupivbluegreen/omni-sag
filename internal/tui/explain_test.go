package tui

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/api"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func samplePolicy() policy.Policy {
	return policy.Policy{Roles: []policy.Role{
		{Name: "dba", Groups: []string{"dba"}, Allow: []policy.Rule{
			{Host: "db1.lab.local", Ports: []int{5432}, Record: policy.RecordFull, Credential: "inject", RequireApproval: true},
			{Host: "db2.lab.local", Ports: []int{5432}, Record: policy.RecordMetadataOnly},
		}},
		{Name: "admin", Groups: []string{"admins"}, Allow: []policy.Rule{{Host: "*"}}},
	}}
}

// The rule-trace must never disagree with policy.Decide: round-trip the policy
// through the API view and confirm every decision is preserved.
func TestPolicyView_RoundTripPreservesDecisions(t *testing.T) {
	p := samplePolicy()
	p2 := PolicyFromView(api.PolicyToView(p))

	principals := []policy.Principal{
		{User: "alice", Groups: []string{"dba"}},
		{User: "root", Groups: []string{"admins"}},
		{User: "bob", Groups: []string{"users"}},
		{User: "n", Groups: nil},
	}
	targets := []policy.Target{
		{Host: "db1.lab.local", Port: 5432}, {Host: "db1.lab.local", Port: 22},
		{Host: "db2.lab.local", Port: 5432}, {Host: "anything", Port: 9999},
	}
	for _, pr := range principals {
		for _, tg := range targets {
			if got, want := p2.Decide(pr, tg, nil), p.Decide(pr, tg, nil); !reflect.DeepEqual(got, want) {
				t.Fatalf("decision drift for %v %v: view=%+v orig=%+v", pr, tg, got, want)
			}
		}
	}
}

func TestExplain_AllowShowsRecordCredentialApprovalForwarding(t *testing.T) {
	pv := api.PolicyToView(samplePolicy())
	ex := Explain(pv, "alice", []string{"dba"}, "db1.lab.local", 5432)
	if !ex.Decision.Allow {
		t.Fatal("alice/dba should be allowed to db1")
	}
	j := strings.Join(ex.Lines, "\n")
	for _, want := range []string{"ALLOW", "role dba", "record:", "credential:", "four-eyes", "REFUSED"} {
		if !strings.Contains(j, want) {
			t.Fatalf("trace missing %q:\n%s", want, j)
		}
	}
}

func TestExplain_Deny(t *testing.T) {
	pv := api.PolicyToView(samplePolicy())
	ex := Explain(pv, "bob", []string{"users"}, "db1.lab.local", 5432)
	if ex.Decision.Allow {
		t.Fatal("bob should be denied")
	}
	if !strings.Contains(strings.Join(ex.Lines, "\n"), "DENY") {
		t.Fatalf("expected DENY: %v", ex.Lines)
	}
}
