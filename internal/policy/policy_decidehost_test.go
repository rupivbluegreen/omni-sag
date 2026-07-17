package policy

import "testing"

// TestDecideHost_SingleUnambiguousRule: exactly one rule matches the host and
// it names exactly one port — DecideHost succeeds and resolves that port.
func TestDecideHost_SingleUnambiguousRule(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "db1.lab.local", Ports: []int{2200}, Credential: "prompt", TargetUser: "svc_db1"}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}

	d := p.DecideHost(pr, "db1.lab.local", nil)
	if !d.Allow {
		t.Fatalf("unambiguous single-rule/single-port host must be allowed, got deny: %s", d.Reason)
	}
	if d.Port != 2200 {
		t.Fatalf("Port = %d, want 2200", d.Port)
	}
	if d.CredentialMode != "prompt" || d.TargetUser != "svc_db1" {
		t.Fatalf("got CredentialMode=%q TargetUser=%q, want prompt/svc_db1", d.CredentialMode, d.TargetUser)
	}
	if d.MatchedRole != "dba" {
		t.Fatalf("MatchedRole = %q, want dba", d.MatchedRole)
	}
}

// TestDecideHost_NoRoleForHost: no role the principal holds grants the host at
// all — deny, same as Decide's default-deny behavior.
func TestDecideHost_NoRoleForHost(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "db1.lab.local", Ports: []int{22}}},
	}}}
	pr := Principal{User: "bob", Groups: []string{"domain users"}}

	d := p.DecideHost(pr, "db1.lab.local", nil)
	if d.Allow {
		t.Fatal("principal without the granting role must be denied")
	}
	if d.Port != 0 {
		t.Fatalf("Port = %d, want 0 on deny", d.Port)
	}
}

// TestDecideHost_EmptyPortsFailsClosed_NotPort22Fallback: a rule matching the
// host with an EMPTY Ports list (meaning "any port" for -L forwarding, e.g. a
// passthrough/no-approval tunnel rule) must NOT resolve to a guessed port 22
// for the real-target shell/SFTP flow — there is no single port to dial, so
// this must fail closed rather than silently reusing that rule's (possibly
// much weaker) authorization posture at a guessed port.
func TestDecideHost_EmptyPortsFailsClosed_NotPort22Fallback(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "tunnel",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "db1.lab.local", Ports: nil, Credential: "passthrough"}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}

	d := p.DecideHost(pr, "db1.lab.local", nil)
	if d.Allow {
		t.Fatalf("a rule with no configured port must fail closed for the real-target flow, got allow (port=%d): %s", d.Port, d.Reason)
	}
	if d.Port == 22 {
		t.Fatal("must not guess port 22 — this was the bug being fixed")
	}
	if d.Reason == "" {
		t.Fatal("a fail-closed ambiguous decision must explain why")
	}
}

// TestDecideHost_MultiplePortsOnOneRuleFailsClosed: the single matching rule
// names two-or-more ports — again no single port to resolve, must fail closed.
func TestDecideHost_MultiplePortsOnOneRuleFailsClosed(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "db1.lab.local", Ports: []int{22, 2200}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}

	d := p.DecideHost(pr, "db1.lab.local", nil)
	if d.Allow {
		t.Fatalf("a rule with 2+ configured ports must fail closed for the real-target flow, got allow (port=%d)", d.Port)
	}
	if d.Port != 0 {
		t.Fatalf("Port = %d, want 0 on a fail-closed decision", d.Port)
	}
}

// TestDecideHost_TwoRulesSameHostDifferentPortsFailsClosed is the actual
// security-relevant case a reviewer flagged: a normal policy shape where one
// rule permits -L forwarding to a host at one port with a weak posture
// (passthrough, no approval) and a second rule permits real shell access to
// the SAME host at a different port with a strong posture (inject,
// RequireApproval). DecideHost must NOT silently pick whichever rule iterates
// first and apply ITS credential mode / approval requirement to the
// shell/SFTP flow — it must fail closed, because it cannot tell which rule
// the operator means for a flow that carries no port at match time.
func TestDecideHost_TwoRulesSameHostDifferentPortsFailsClosed(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow: []Rule{
			// Weak posture: DB tunnel, no approval.
			{Host: "db1.lab.local", Ports: []int{5432}, Credential: "passthrough", RequireApproval: false},
			// Strong posture: real admin shell, approval-gated.
			{Host: "db1.lab.local", Ports: []int{22}, Credential: "inject", RequireApproval: true, TargetUser: "root"},
		},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}

	d := p.DecideHost(pr, "db1.lab.local", nil)
	if d.Allow {
		t.Fatalf("two rules matching the same host must fail closed, not silently pick one (got CredentialMode=%q RequireApproval=%v Port=%d)",
			d.CredentialMode, d.RequireApproval, d.Port)
	}
	if d.Reason == "" {
		t.Fatal("a fail-closed ambiguous-host decision must explain why")
	}
}

// TestDecideHost_TwoRulesAcrossDifferentRolesFailsClosed: the ambiguity check
// must span every role the principal holds, not just one role's Allow list —
// two different roles each granting a rule for the same host is just as
// ambiguous as two rules in one role.
func TestDecideHost_TwoRulesAcrossDifferentRolesFailsClosed(t *testing.T) {
	p := Policy{Roles: []Role{
		{
			Name:   "tunnel-users",
			Groups: []string{"tunnel"},
			Allow:  []Rule{{Host: "db1.lab.local", Ports: []int{5432}, Credential: "passthrough"}},
		},
		{
			Name:   "shell-admins",
			Groups: []string{"admins"},
			Allow:  []Rule{{Host: "db1.lab.local", Ports: []int{22}, Credential: "inject", RequireApproval: true}},
		},
	}}
	pr := Principal{User: "alice", Groups: []string{"tunnel", "admins"}}

	d := p.DecideHost(pr, "db1.lab.local", nil)
	if d.Allow {
		t.Fatalf("rules from two different held roles matching the same host must still fail closed, got allow: %+v", d)
	}
}

// TestDecideHost_DifferentHostsRemainUnambiguous is the control case matching
// the shipped demo config's shape (two rules, different hosts): each host
// still resolves cleanly on its own.
func TestDecideHost_DifferentHostsRemainUnambiguous(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow: []Rule{
			{Host: "db1.lab.local", Ports: []int{5432}, Credential: "passthrough"},
			{Host: "127.0.0.1", Ports: []int{2200}, Credential: "prompt", TargetUser: "svc_db1"},
		},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}

	d := p.DecideHost(pr, "127.0.0.1", nil)
	if !d.Allow || d.Port != 2200 || d.TargetUser != "svc_db1" {
		t.Fatalf("distinct-host rule must resolve unambiguously, got %+v", d)
	}
}
