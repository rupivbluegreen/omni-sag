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

// cidrPolicy grants "ops" a CIDR-shaped rule only — no exact/wildcard rule
// exists, so a hostname target can only ever match via DNS resolution, which
// Explain never performs (it evaluates offline, resolve=nil).
func cidrPolicy() policy.Policy {
	return policy.Policy{Roles: []policy.Role{
		{Name: "ops", Groups: []string{"ops"}, Allow: []policy.Rule{
			{Host: "10.0.0.0/8", Ports: []int{22}},
		}},
	}}
}

// TestExplain_DenyNotesUnevaluatedCIDR: Explain must not present a CIDR-gated
// deny with the same confidence as a genuine "no rule at all" deny — an
// operator auditing reachability needs to know the answer is incomplete, not
// a confirmed no, since the live gateway (with a real resolver) might allow
// this host if it resolves inside the CIDR.
func TestExplain_DenyNotesUnevaluatedCIDR(t *testing.T) {
	pv := api.PolicyToView(cidrPolicy())
	ex := Explain(pv, "alice", []string{"ops"}, "db.internal.corp", 22)
	if ex.Decision.Allow {
		t.Fatal("hostname target must deny offline (no resolver) even though a CIDR rule could grant it")
	}
	j := strings.Join(ex.Lines, "\n")
	if !strings.Contains(j, "CIDR") {
		t.Fatalf("deny explanation must note an unevaluated CIDR rule exists:\n%s", j)
	}
}

// TestExplain_DenyNoCIDRRuleNoNote: the CIDR note must not appear when no
// CIDR-shaped rule is even held — a plain deny stays a plain deny.
func TestExplain_DenyNoCIDRRuleNoNote(t *testing.T) {
	pv := api.PolicyToView(samplePolicy())
	ex := Explain(pv, "bob", []string{"users"}, "db1.lab.local", 5432)
	if strings.Contains(strings.Join(ex.Lines, "\n"), "CIDR") {
		t.Fatalf("no CIDR rule exists for this policy; explanation must not mention one: %v", ex.Lines)
	}
}

// TestExplain_AllowByLiteralIPInCIDR: a literal-IP target still evaluates
// fully offline (no resolver needed), so it must ALLOW, not just note a CIDR
// possibility.
func TestExplain_AllowByLiteralIPInCIDR(t *testing.T) {
	pv := api.PolicyToView(cidrPolicy())
	ex := Explain(pv, "alice", []string{"ops"}, "10.5.6.7", 22)
	if !ex.Decision.Allow {
		t.Fatalf("literal IP inside the CIDR must be allowed offline: %v", ex.Lines)
	}
}
