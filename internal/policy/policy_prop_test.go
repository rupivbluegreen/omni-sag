package policy

// Property-based tests for the policy evaluator. These assert the core
// authorization invariants of Policy.Decide over randomized policies,
// principals, and targets, using an INDEPENDENT reference implementation of
// the spec (refHeldRoles / refRuleMatches / refFirstMatch below) so a bug in
// policy.go diverges from the spec rather than being tautologically confirmed.
//
// Invariants covered:
//   - default-deny: no matching rule => !Allow
//   - Allow implies some role the principal holds has a rule matching host+port
//   - group matching is case-insensitive (on both principal and role groups)
//   - wildcard host ("*") and empty-ports ("any port") semantics
//   - RecordMode/CredentialMode/RequireApproval come ONLY from the matched rule
//     (and are zero-valued on deny — no leakage)
//   - Decide is deterministic and never panics

import (
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// ---- small value domains, chosen so matches happen frequently ----

var (
	hostPool   = []string{"db1.lab.local", "web.lab.local", "app.lab.local", "cache.lab.local"}
	groupPool  = []string{"dba", "admins", "devs", "auditors", "domain users"}
	portPool   = []int{22, 80, 443, 5432, 6379}
	credPool   = []string{"", "inject", "prompt", "passthrough", "deny"}
	recordPool = []RecordMode{RecordNone, RecordMetadataOnly, RecordFull, "", "bogus"}
	rolePool   = []string{"r0", "r1", "r2", "r3"}
)

// randCase returns g's value with each letter's case randomized, so the tests
// exercise case-insensitive comparison paths without changing logical identity.
func randCase(t *rapid.T, s string, label string) string {
	flags := rapid.SliceOfN(rapid.Bool(), len(s), len(s)).Draw(t, label)
	b := []byte(strings.ToLower(s))
	for i := range b {
		if flags[i] {
			b[i] = []byte(strings.ToUpper(string(b[i])))[0]
		}
	}
	return string(b)
}

func genRule(t *rapid.T) Rule {
	host := rapid.SampledFrom(append([]string{"*"}, hostPool...)).Draw(t, "ruleHost")
	if host != "*" {
		host = randCase(t, host, "ruleHostCase")
	}
	ports := rapid.SliceOfN(rapid.SampledFrom(portPool), 0, 4).Draw(t, "rulePorts")
	return Rule{
		Host:            host,
		Ports:           ports,
		Record:          rapid.SampledFrom(recordPool).Draw(t, "ruleRecord"),
		Credential:      rapid.SampledFrom(credPool).Draw(t, "ruleCred"),
		RequireApproval: rapid.Bool().Draw(t, "ruleApproval"),
	}
}

func genRole(t *rapid.T, name string) Role {
	groups := rapid.SliceOfN(rapid.SampledFrom(groupPool), 0, 3).Draw(t, "roleGroups")
	cased := make([]string, len(groups))
	for i, g := range groups {
		cased[i] = randCase(t, g, "roleGroupCase")
	}
	rules := rapid.SliceOfN(rapid.Custom(genRule), 0, 4).Draw(t, "roleRules")
	return Role{Name: name, Groups: cased, Allow: rules}
}

func genPolicy(t *rapid.T) Policy {
	n := rapid.IntRange(0, len(rolePool)).Draw(t, "numRoles")
	roles := make([]Role, n)
	for i := 0; i < n; i++ {
		roles[i] = genRole(t, rolePool[i])
	}
	return Policy{Roles: roles}
}

func genPrincipal(t *rapid.T) Principal {
	groups := rapid.SliceOfN(rapid.SampledFrom(groupPool), 0, 4).Draw(t, "prGroups")
	cased := make([]string, len(groups))
	for i, g := range groups {
		cased[i] = randCase(t, g, "prGroupCase")
	}
	return Principal{User: rapid.SampledFrom([]string{"alice", "bob", "carol"}).Draw(t, "user"), Groups: cased}
}

func genTarget(t *rapid.T) Target {
	host := rapid.SampledFrom(hostPool).Draw(t, "tgtHost")
	host = randCase(t, host, "tgtHostCase")
	return Target{Host: host, Port: rapid.SampledFrom(portPool).Draw(t, "tgtPort")}
}

// ---- independent reference implementation of the SPEC ----

func refHeldRoles(p Policy, pr Principal) []Role {
	have := map[string]bool{}
	for _, g := range pr.Groups {
		have[strings.ToLower(g)] = true
	}
	var out []Role
	for _, r := range p.Roles {
		for _, g := range r.Groups {
			if have[strings.ToLower(g)] {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func refRuleMatches(r Rule, t Target) bool {
	if r.Host != "*" && !strings.EqualFold(r.Host, t.Host) {
		return false
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p == t.Port {
			return true
		}
	}
	return false
}

// refFirstMatch returns the first (role, rule) that grants t, in role order
// then rule order, matching Decide's precedence. found is false on deny.
func refFirstMatch(p Policy, pr Principal, t Target) (Role, Rule, bool) {
	for _, r := range refHeldRoles(p, pr) {
		for _, rule := range r.Allow {
			if refRuleMatches(rule, t) {
				return r, rule, true
			}
		}
	}
	return Role{}, Rule{}, false
}

// ---- properties ----

func TestProp_DecideMatchesSpec(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := genPolicy(t)
		pr := genPrincipal(t)
		tgt := genTarget(t)

		d := p.Decide(pr, tgt)
		role, rule, want := refFirstMatch(p, pr, tgt)

		// default-deny + allow-implies-match: Allow iff a held role has a
		// matching rule.
		if d.Allow != want {
			t.Fatalf("Allow=%v want %v for target %s\npolicy=%+v\nprincipal=%+v", d.Allow, want, tgt, p, pr)
		}

		if d.Allow {
			// Allow implies the matched role is actually held and its rule
			// actually matches host+port.
			held := false
			for _, hr := range refHeldRoles(p, pr) {
				if hr.Name == d.MatchedRole {
					held = true
					break
				}
			}
			if !held {
				t.Fatalf("MatchedRole %q is not a role the principal holds", d.MatchedRole)
			}
			if d.MatchedRole != role.Name {
				t.Fatalf("MatchedRole=%q want %q", d.MatchedRole, role.Name)
			}
			// Decision fields come ONLY from the matched rule.
			if d.RecordMode != rule.Record.Normalize() {
				t.Fatalf("RecordMode=%q want %q (from matched rule)", d.RecordMode, rule.Record.Normalize())
			}
			if d.CredentialMode != rule.Credential {
				t.Fatalf("CredentialMode=%q want %q (from matched rule)", d.CredentialMode, rule.Credential)
			}
			if d.RequireApproval != rule.RequireApproval {
				t.Fatalf("RequireApproval=%v want %v (from matched rule)", d.RequireApproval, rule.RequireApproval)
			}
			// RecordMode is always a normalized (known) value on allow.
			if d.RecordMode != d.RecordMode.Normalize() {
				t.Fatalf("RecordMode %q is not normalized", d.RecordMode)
			}
		} else {
			// No leakage on deny: outcome fields are zero-valued.
			if d.MatchedRole != "" {
				t.Fatalf("deny leaked MatchedRole=%q", d.MatchedRole)
			}
			if d.RecordMode != RecordNone {
				t.Fatalf("deny RecordMode=%q want RecordNone", d.RecordMode)
			}
			if d.CredentialMode != "" {
				t.Fatalf("deny leaked CredentialMode=%q", d.CredentialMode)
			}
			if d.RequireApproval {
				t.Fatalf("deny leaked RequireApproval=true")
			}
			// A denied session must never be granted forwarding on a
			// full-recording claim: RecordNone permits forwarding, which is
			// fine only because Allow is false.
		}
	})
}

func TestProp_Deterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := genPolicy(t)
		pr := genPrincipal(t)
		tgt := genTarget(t)
		d1 := p.Decide(pr, tgt)
		d2 := p.Decide(pr, tgt)
		if !reflect.DeepEqual(d1, d2) {
			t.Fatalf("Decide not deterministic:\n%+v\n%+v", d1, d2)
		}
	})
}

// TestProp_GroupCaseInsensitive asserts that uppercasing every group name on
// BOTH the principal and the roles leaves the decision unchanged.
func TestProp_GroupCaseInsensitive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := genPolicy(t)
		pr := genPrincipal(t)
		tgt := genTarget(t)

		base := p.Decide(pr, tgt)

		// Flip case of all group strings (principal + roles), preserving host
		// casing and everything else.
		prU := Principal{User: pr.User, Groups: upperAll(pr.Groups)}
		rolesU := make([]Role, len(p.Roles))
		for i, r := range p.Roles {
			rolesU[i] = Role{Name: r.Name, Groups: upperAll(r.Groups), Allow: r.Allow}
		}
		flipped := Policy{Roles: rolesU}.Decide(prU, tgt)

		if base.Allow != flipped.Allow || base.MatchedRole != flipped.MatchedRole {
			t.Fatalf("group casing changed decision: base=%+v flipped=%+v", base, flipped)
		}
	})
}

func upperAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToUpper(s)
	}
	return out
}

// TestProp_WildcardHostAnyPort: a held role whose only rule is {Host:"*"}
// (empty ports) allows EVERY target.
func TestProp_WildcardHostAnyPort(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		grp := rapid.SampledFrom(groupPool).Draw(t, "grp")
		p := Policy{Roles: []Role{{
			Name:   "wild",
			Groups: []string{randCase(t, grp, "wildGroupCase")},
			Allow:  []Rule{{Host: "*"}},
		}}}
		pr := Principal{User: "x", Groups: []string{randCase(t, grp, "prGroupCase")}}
		tgt := genTarget(t)
		d := p.Decide(pr, tgt)
		if !d.Allow {
			t.Fatalf("wildcard host/any-port must allow target %s, got deny: %s", tgt, d.Reason)
		}
	})
}

// TestProp_EmptyPortsMatchesAnyPort: for a host-specific rule with no ports,
// the decision is independent of the target port.
func TestProp_EmptyPortsMatchesAnyPort(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		grp := rapid.SampledFrom(groupPool).Draw(t, "grp")
		host := rapid.SampledFrom(hostPool).Draw(t, "host")
		p := Policy{Roles: []Role{{
			Name:   "hostonly",
			Groups: []string{grp},
			Allow:  []Rule{{Host: host, Ports: nil}},
		}}}
		pr := Principal{User: "x", Groups: []string{grp}}
		p1 := rapid.SampledFrom(portPool).Draw(t, "p1")
		p2 := rapid.SampledFrom(portPool).Draw(t, "p2")
		d1 := p.Decide(pr, Target{Host: host, Port: p1})
		d2 := p.Decide(pr, Target{Host: host, Port: p2})
		if !d1.Allow || !d2.Allow {
			t.Fatalf("empty ports must match any port: p1=%v p2=%v", d1.Allow, d2.Allow)
		}
	})
}

// TestProp_ExplicitPortsMatchExactly: with an explicit non-empty ports list, a
// held host-matching rule allows exactly the listed ports and denies others
// (given no other rule grants the target).
func TestProp_ExplicitPortsMatchExactly(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		grp := rapid.SampledFrom(groupPool).Draw(t, "grp")
		host := rapid.SampledFrom(hostPool).Draw(t, "host")
		ports := rapid.SliceOfNDistinct(rapid.SampledFrom(portPool), 1, len(portPool),
			func(p int) int { return p }).Draw(t, "ports")
		p := Policy{Roles: []Role{{
			Name:   "portlist",
			Groups: []string{grp},
			Allow:  []Rule{{Host: host, Ports: ports}},
		}}}
		pr := Principal{User: "x", Groups: []string{grp}}
		port := rapid.SampledFrom(portPool).Draw(t, "port")
		want := false
		for _, pp := range ports {
			if pp == port {
				want = true
			}
		}
		d := p.Decide(pr, Target{Host: host, Port: port})
		if d.Allow != want {
			t.Fatalf("port %d in %v: Allow=%v want %v", port, ports, d.Allow, want)
		}
	})
}
