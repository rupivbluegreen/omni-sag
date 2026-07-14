package tui

import (
	"strings"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/api"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// A policy Allow with credential mode "deny" is unconditionally refused by the
// gateway, so the trace must report it as NOT reachable — never a bare ALLOW.
func TestExplain_CredentialDenyNotReachable(t *testing.T) {
	p := policy.Policy{Roles: []policy.Role{{
		Name:   "r",
		Groups: []string{"g"},
		Allow:  []policy.Rule{{Host: "db", Ports: []int{5432}, Credential: "deny"}},
	}}}
	ex := Explain(api.PolicyToView(p), "alice", []string{"g"}, "db", 5432)

	if !ex.Decision.Allow {
		t.Fatal("policy.Decide should Allow (host/port match)")
	}
	if ex.Reachable {
		t.Fatal("credential mode deny must be reported NOT reachable")
	}
	if !strings.Contains(strings.Join(ex.Lines, "\n"), "REFUSED") {
		t.Fatalf("trace should show a REFUSED line, got: %v", ex.Lines)
	}
}
