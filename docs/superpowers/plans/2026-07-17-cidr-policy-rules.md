# CIDR Policy Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `internal/policy.Rule.Host` be a CIDR range (`"10.0.0.0/8"`) in addition to `"*"` and an exact hostname, so one rule can authorize a whole subnet instead of one host per line.

**Architecture:** `Rule.Host` gains a third shape, detected by parsing (no new YAML field). Matching stays cheap-first: the existing exact/wildcard check runs unmodified; only if nothing matches does a second pass consider CIDR-shaped rules, resolving the target to IP(s) only then (literal IPs need no resolution; hostnames use an injected `ResolverFunc` so `Decide`/`DecideHost` stay parameter-pure and testable without real DNS). A hostname must resolve entirely inside one rule's range to match — fail closed on partial or split matches. Because policy resolves once at decision time and the real connection resolves again independently later, `internal/dialer` re-validates the connect-time address against the same matched range (rebind/TOCTOU defense), reusing the existing post-resolution `net.Dialer.Control` guard mechanism.

**Tech Stack:** Go 1.25, stdlib `net`/`net.IPNet`, `pgregory.net/rapid` for property tests (already a dependency).

**Spec:** `docs/superpowers/specs/2026-07-17-cidr-policy-rules-design.md` — read it for the full rationale; this plan implements it with two deliberate refinements found while drafting real code (documented inline at the relevant task):
1. No new `hostCIDR` field cached on `Rule` — `Rule.cidr()` parses `Host` on every call. `net.ParseCIDR` is a cheap string parse (not I/O); caching would require a constructor and break the many existing tests that build `Rule{Host: ...}` literals directly.
2. The config toggle is `PolicyConfig.DisableCIDRHostnameResolution bool` (yaml `disable_cidr_hostname_resolution`), not the spec's `*bool` — this repo's established convention (`DisableSSH`, `DisableTunnel`, `DisableSFTP` in `internal/config/config.go:39-41`) is a plain `bool` defaulting false-means-enabled; a lone `*bool` field would be the only one of its kind in the file for no real benefit.

## Global Constraints

- Go 1.25 (`go.mod`). Module path `github.com/rupivbluegreen/omni-sag`.
- Build/test: `make ci` (= `build lint check-imports test`). Run `make test` (`go test ./...`) and `make lint` (`gofmt -l .` + `go vet ./...`) before every commit in this plan.
- `scripts/check-imports.sh` enforces: only `internal/dialer` may call `net.Dial`/`net.Dialer` (this plan adds no new dial calls — `net.ParseCIDR`/`net.ParseIP`/`net.DefaultResolver.LookupIPAddr` don't match that rule); `internal/policy` must never import `internal/session`. Run `bash scripts/check-imports.sh` after each task touching `internal/policy` or `internal/dialer`.
- `internal/policy` package doc (`policy.go:1-4`) requires `Decide`/`DecideHost` stay pure functions of their inputs — the new `resolve ResolverFunc` parameter preserves this (same inputs + same resolver behavior ⇒ same output; property tests inject a fake resolver, never real DNS).
- No comments beyond a non-obvious *why*. Match each file's existing terse style exactly (see `policy.go`'s doc comments for the target tone).
- Commit after every green test, using this repo's plain `type: summary` commit style (see `git log --oneline -15` for examples) — no `Co-Authored-By` trailer unless the user's own git workflow adds one; follow whatever the environment's commit tooling does automatically.

---

### Task 1: CIDR rule matching in `internal/policy`

**Files:**
- Modify: `internal/policy/policy.go`
- Modify (mechanical signature updates only): `internal/policy/policy_test.go`, `internal/policy/policy_decidehost_test.go`, `internal/policy/policy_matchedgroups_test.go`, `internal/policy/policy_prop_test.go`
- Test: new cases added to `internal/policy/policy_test.go`, `internal/policy/policy_decidehost_test.go`, and a new `internal/policy/policy_cidr_prop_test.go`

**Interfaces:**
- Produces: `type ResolverFunc func(host string) ([]net.IP, error)`; `Decide(pr Principal, t Target, resolve ResolverFunc) Decision`; `DecideHost(pr Principal, host string, resolve ResolverFunc) Decision`; `Decision.MatchedCIDR *net.IPNet` (nil unless the match came from a CIDR rule).
- Consumes: nothing new from other tasks — this task is self-contained within `internal/policy`.

Every other task in this plan depends on this one (Task 3 calls `Decide`/`DecideHost` with a real resolver; the resolver type is defined here).

- [ ] **Step 1: Add the failing tests for IP-literal CIDR matching**

Append to `internal/policy/policy_test.go`:

```go
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
```

- [ ] **Step 2: Run to verify these fail to compile**

Run: `go test ./internal/policy/... -run TestDecide_CIDR -v`
Expected: compile error — `Decide` called with 3 arguments, current signature takes 2 (`too many arguments in call to p.Decide`).

- [ ] **Step 3: Implement CIDR shape detection and the `ResolverFunc`/`Decision.MatchedCIDR` plumbing**

In `internal/policy/policy.go`, add `"net"` to the import block:

```go
import (
	"fmt"
	"net"
	"strings"
)
```

Add `MatchedCIDR` to the `Decision` struct (after `Port int`):

```go
	Port int
	// MatchedCIDR is the CIDR range of the rule that granted this decision,
	// when the match came from a CIDR-shaped Rule.Host rather than an exact
	// hostname or "*". Nil on deny and on exact/wildcard matches. Threaded
	// into internal/dialer's connect-time guard so the resolved address is
	// re-validated against the same range the decision was based on (DNS
	// rebinding between decision time and connect time is otherwise
	// invisible to policy).
	MatchedCIDR *net.IPNet
```

Replace the existing `Rule.matches` method with a port-only helper plus a matches that uses it (behavior-preserving refactor so the CIDR path can reuse the port check):

```go
func (r Rule) matchesPort(port int) bool {
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}

func (r Rule) matches(t Target) bool {
	if r.Host != "*" && !strings.EqualFold(r.Host, t.Host) {
		return false
	}
	return r.matchesPort(t.Port)
}
```

Add below `matchesHost` (after the existing `func (r Rule) matchesHost(host string) bool { ... }`):

```go
// cidr reports whether r.Host is CIDR notation (e.g. "10.0.0.0/8"), returning
// the parsed range. Only strings containing "/" are considered — hostnames
// never contain one, so this can't misclassify an exact-host rule.
func (r Rule) cidr() (*net.IPNet, bool) {
	if r.Host == "*" || !strings.Contains(r.Host, "/") {
		return nil, false
	}
	_, n, err := net.ParseCIDR(r.Host)
	if err != nil {
		return nil, false
	}
	return n, true
}

// ResolverFunc resolves a hostname to its IP addresses, used to match a CIDR
// rule against a hostname target. A nil ResolverFunc disables hostname
// resolution: CIDR rules still match IP-literal targets directly.
type ResolverFunc func(host string) ([]net.IP, error)

// targetIPs returns the IPs to check a CIDR rule against: host itself,
// parsed, if it is already a literal IP; otherwise resolve(host) when resolve
// is non-nil. Returns nil (never matches any CIDR) for a hostname with no
// resolver, or when resolution errors — fail closed rather than guessing.
func targetIPs(host string, resolve ResolverFunc) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	if resolve == nil {
		return nil
	}
	ips, err := resolve(host)
	if err != nil {
		return nil
	}
	return ips
}

// allIn reports whether every ip in ips falls within n. False on an empty ips
// (unresolved/unresolvable host) or if any ip lands outside n — a hostname
// resolving to several addresses must sit entirely inside one rule's range to
// match it; a partial or split match is a deny, never a guess.
func allIn(ips []net.IP, n *net.IPNet) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		v := ip
		if v4 := ip.To4(); v4 != nil {
			v = v4
		}
		if !n.Contains(v) {
			return false
		}
	}
	return true
}
```

Change `Decide`'s signature and add the CIDR fallback pass after the existing exact/wildcard loop:

```go
func (p Policy) Decide(pr Principal, t Target, resolve ResolverFunc) Decision {
	roles := p.rolesFor(pr)
	if len(roles) == 0 {
		return Decision{Allow: false, RecordMode: RecordNone, Reason: "no role: principal holds no role granting any access"}
	}
	for _, r := range roles {
		for _, rule := range r.Allow {
			if rule.matches(t) {
				return Decision{
					Allow:           true,
					Reason:          "allowed by role " + r.Name,
					MatchedRole:     r.Name,
					RecordMode:      rule.Record.Normalize(),
					CredentialMode:  rule.Credential,
					RequireApproval: rule.RequireApproval,
					TargetUser:      rule.TargetUser,
					MatchedGroups:   intersectGroups(pr.Groups, r.Groups),
				}
			}
		}
	}
	// CIDR rules are consulted only once every exact/wildcard rule has
	// already failed to match — cheap-first, no resolution unless needed.
	var ips []net.IP
	resolved := false
	for _, r := range roles {
		for _, rule := range r.Allow {
			n, ok := rule.cidr()
			if !ok {
				continue
			}
			if !resolved {
				ips = targetIPs(t.Host, resolve)
				resolved = true
			}
			if allIn(ips, n) && rule.matchesPort(t.Port) {
				return Decision{
					Allow:           true,
					Reason:          "allowed by role " + r.Name,
					MatchedRole:     r.Name,
					RecordMode:      rule.Record.Normalize(),
					CredentialMode:  rule.Credential,
					RequireApproval: rule.RequireApproval,
					TargetUser:      rule.TargetUser,
					MatchedGroups:   intersectGroups(pr.Groups, r.Groups),
					MatchedCIDR:     n,
				}
			}
		}
	}
	return Decision{Allow: false, RecordMode: RecordNone, Reason: fmt.Sprintf("no rule in roles %s permits %s", roleNames(roles), t)}
}
```

- [ ] **Step 4: Run to verify the new tests pass**

Run: `go test ./internal/policy/... -run TestDecide_CIDR -v`
Expected: PASS (3 tests) — but the package won't compile yet, because every *other* existing call to `Decide`/`DecideHost` is still 2-arg. Continue to Step 5 before this can go green.

- [ ] **Step 5: Update `DecideHost` the same way**

Replace `DecideHost`'s signature and body in `internal/policy/policy.go`:

```go
func (p Policy) DecideHost(pr Principal, host string, resolve ResolverFunc) Decision {
	roles := p.rolesFor(pr)
	if len(roles) == 0 {
		return Decision{Allow: false, RecordMode: RecordNone, Reason: "no role: principal holds no role granting any access"}
	}
	type hostMatch struct {
		role Role
		rule Rule
		cidr *net.IPNet
	}
	var matches []hostMatch
	for _, r := range roles {
		for _, rule := range r.Allow {
			if rule.matchesHost(host) {
				matches = append(matches, hostMatch{role: r, rule: rule})
			}
		}
	}
	if len(matches) == 0 {
		// No exact/wildcard rule matched host — consult CIDR rules, resolving
		// only now (cheap-first).
		var ips []net.IP
		resolved := false
		for _, r := range roles {
			for _, rule := range r.Allow {
				n, ok := rule.cidr()
				if !ok {
					continue
				}
				if !resolved {
					ips = targetIPs(host, resolve)
					resolved = true
				}
				if allIn(ips, n) {
					matches = append(matches, hostMatch{role: r, rule: rule, cidr: n})
				}
			}
		}
	}
	switch {
	case len(matches) == 0:
		return Decision{Allow: false, RecordMode: RecordNone, Reason: fmt.Sprintf("no rule in roles %s permits host %s", roleNames(roles), host)}
	case len(matches) > 1:
		return Decision{Allow: false, RecordMode: RecordNone, Reason: fmt.Sprintf("ambiguous: %d rules match host %s for the real-target shell/SFTP flow — each host must resolve to exactly one rule with exactly one port", len(matches), host)}
	}
	m := matches[0]
	if len(m.rule.Ports) != 1 {
		return Decision{Allow: false, RecordMode: RecordNone, Reason: fmt.Sprintf("ambiguous: the rule matching host %s has %d configured ports — the real-target shell/SFTP flow requires exactly one", host, len(m.rule.Ports))}
	}
	return Decision{
		Allow:           true,
		Reason:          "allowed by role " + m.role.Name,
		MatchedRole:     m.role.Name,
		RecordMode:      m.rule.Record.Normalize(),
		CredentialMode:  m.rule.Credential,
		RequireApproval: m.rule.RequireApproval,
		TargetUser:      m.rule.TargetUser,
		MatchedGroups:   intersectGroups(pr.Groups, m.role.Groups),
		Port:            m.rule.Ports[0],
		MatchedCIDR:     m.cidr,
	}
}
```

Note what this reuses for free: appending both a matched exact rule candidate and a matched CIDR rule candidate to the same `matches` slice means the existing `len(matches) > 1` branch already produces a correctly-worded "ambiguous: N rules match" deny when a resolved hostname's IPs split across two different CIDR rules — no new branch needed. A *single* CIDR rule that only partially contains a multi-IP hostname's addresses never gets appended at all (`allIn` requires every IP in range), so that case falls through to the plain `len(matches) == 0` "no rule permits" reason — deliberately simpler than the split-rules case, matching `Decide`'s existing precedent of not distinguishing "close but no" from "not tried."

- [ ] **Step 6: Mechanically update every existing call site to pass a resolver argument**

Every existing call to `.Decide(pr, target)` becomes `.Decide(pr, target, nil)`, and every `.DecideHost(pr, host)` becomes `.DecideHost(pr, host, nil)`. `nil` is correct for all of these: none of the existing tests construct CIDR-shaped rules, so a nil resolver changes nothing about their outcomes (literal-IP CIDR matching doesn't need a resolver either, but none of these targets are CIDR rules in the first place).

First, find every call site so none are missed:

```bash
grep -rn '\.Decide(\|\.DecideHost(' internal/policy/*_test.go
```

Expected: around 33 matches across `policy_test.go`, `policy_decidehost_test.go`, `policy_matchedgroups_test.go`, `policy_prop_test.go`.

Edit each one, e.g. in `policy_test.go`:

```go
// before
d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432})
// after
d := demoPolicy().Decide(pr, Target{Host: "db1.lab.local", Port: 5432}, nil)
```

and in `policy_prop_test.go`:

```go
// before
d := p.Decide(pr, tgt)
// after
d := p.Decide(pr, tgt, nil)
```

and in `policy_decidehost_test.go`:

```go
// before
d := p.DecideHost(pr, "db1.lab.local")
// after
d := p.DecideHost(pr, "db1.lab.local", nil)
```

This is fully mechanical — the compiler enforces completeness: `go build` will not succeed while any call site is still 2-arg, so there is no way to miss one silently.

- [ ] **Step 7: Run the full package to verify it compiles and everything passes**

Run: `go build ./... && go test ./internal/policy/... -v`
Expected: builds clean; every existing test still PASSes unchanged (nil resolver preserves all prior behavior); the 3 new CIDR tests from Step 1 PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/policy/policy.go internal/policy/policy_test.go internal/policy/policy_decidehost_test.go internal/policy/policy_matchedgroups_test.go internal/policy/policy_prop_test.go
git commit -m "feat: CIDR rules match literal-IP targets in internal/policy"
```

- [ ] **Step 9: Add the failing tests for hostname resolution against CIDR rules**

Append to `internal/policy/policy_test.go`:

```go
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
```

Add `"fmt"` and `"net"` to `policy_test.go`'s import block (currently just `"testing"`):

```go
import (
	"fmt"
	"net"
	"testing"
)
```

Append to `internal/policy/policy_decidehost_test.go`:

```go
func TestDecideHost_CIDR_MultiIPAllInRangeAllowed(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.1.1.1"), net.ParseIP("10.2.2.2")}, nil
	}
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "10.0.0.0/8", Ports: []int{22}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.DecideHost(pr, "multi.lab.local", resolve)
	if !d.Allow || d.Port != 22 {
		t.Fatalf("a hostname whose IPs are all in range must be allowed with the resolved port, got %+v", d)
	}
}

func TestDecideHost_CIDR_PartialIPMatchDenied(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.1.1.1"), net.ParseIP("192.168.1.1")}, nil
	}
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "10.0.0.0/8", Ports: []int{22}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.DecideHost(pr, "split.lab.local", resolve)
	if d.Allow {
		t.Fatalf("a hostname with only SOME resolved IPs in range must be denied (fail closed), got allow port=%d", d.Port)
	}
}

func TestDecideHost_CIDR_SplitAcrossTwoRulesIsAmbiguous(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.1.1.1"), net.ParseIP("172.16.1.1")}, nil
	}
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow: []Rule{
			{Host: "10.0.0.0/8", Ports: []int{22}},
			{Host: "172.16.0.0/12", Ports: []int{22}},
		},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.DecideHost(pr, "split2.lab.local", resolve)
	if d.Allow {
		t.Fatal("resolved IPs split across two different CIDR rules must be denied (ambiguous)")
	}
	if d.Reason == "" {
		t.Fatal("an ambiguous CIDR split must explain why")
	}
}

func TestDecideHost_CIDR_ResolverErrorFailsClosed(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) { return nil, errors.New("dns down") }
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "10.0.0.0/8", Ports: []int{22}}},
	}}}
	pr := Principal{User: "alice", Groups: []string{"dba"}}
	d := p.DecideHost(pr, "broken.lab.local", resolve)
	if d.Allow {
		t.Fatal("a resolver error must fail closed (deny), not allow")
	}
}
```

Add `"errors"` and `"net"` to `policy_decidehost_test.go`'s import block:

```go
import (
	"errors"
	"net"
	"testing"
)
```

- [ ] **Step 10: Run to verify these fail**

Run: `go test ./internal/policy/... -run 'TestDecide_CIDR|TestDecideHost_CIDR' -v`
Expected: `TestDecide_CIDRRuleMatchesResolvedHostname`, `TestDecideHost_CIDR_MultiIPAllInRangeAllowed` etc. FAIL (the resolver plumbing exists from Step 3/5, so this should actually already pass — if any of the hostname-resolution assertions fail, it means the `targetIPs`/`allIn` logic from Step 3 has a bug; fix it there rather than adding new code, since Steps 3 and 5 already implemented the full resolver path, not just the IP-literal path).

- [ ] **Step 11: Fix any failures, then verify all pass**

Run: `go test ./internal/policy/... -v`
Expected: PASS, all tests (existing + Step 1 + Step 9 additions).

- [ ] **Step 12: Add a CIDR-focused property test**

Create `internal/policy/policy_cidr_prop_test.go`:

```go
package policy

// Property coverage for CIDR rule matching, mirroring policy_prop_test.go's
// independent-reference-implementation approach but scoped to the new
// behavior: a CIDR rule matched via a resolved hostname must always agree
// with the same rule matched via the resolver's raw IP output.

import (
	"net"
	"testing"

	"pgregory.net/rapid"
)

var cidrPool = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

func genCIDRRule(t *rapid.T) Rule {
	cidr := rapid.SampledFrom(cidrPool).Draw(t, "ruleCIDR")
	ports := rapid.SliceOfN(rapid.SampledFrom(portPool), 0, 2).Draw(t, "ruleCIDRPorts")
	return Rule{Host: cidr, Ports: ports}
}

// genIPIn returns a random IP inside n (fixed host bits so the address always
// falls in range regardless of the CIDR's prefix length in cidrPool).
func genIPIn(t *rapid.T, n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	last := rapid.IntRange(1, 254).Draw(t, "lastOctet")
	ip[len(ip)-1] = byte(last)
	return ip
}

// TestProp_CIDRResolvedHostnameMatchesLikeLiteralIP: a CIDR rule granting a
// literal IP must equally grant a hostname that resolves to that same IP —
// the resolution path and the literal-IP path must agree.
func TestProp_CIDRResolvedHostnameMatchesLikeLiteralIP(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rule := genCIDRRule(t)
		n, ok := rule.cidr()
		if !ok {
			t.Fatal("genCIDRRule produced a non-CIDR Host")
		}
		ip := genIPIn(t, n)
		port := rapid.SampledFrom(portPool).Draw(t, "port")

		p := Policy{Roles: []Role{{Name: "r", Groups: []string{"g"}, Allow: []Rule{rule}}}}
		pr := Principal{User: "x", Groups: []string{"g"}}

		literal := p.Decide(pr, Target{Host: ip.String(), Port: port}, nil)
		resolved := p.Decide(pr, Target{Host: "some.host.name", Port: port}, func(string) ([]net.IP, error) {
			return []net.IP{ip}, nil
		})
		if literal.Allow != resolved.Allow {
			t.Fatalf("literal-IP Allow=%v but resolved-hostname Allow=%v for the same IP %s (rule=%+v port=%d)",
				literal.Allow, resolved.Allow, ip, rule, port)
		}
	})
}

// TestProp_CIDRPartialMultiIPNeverAllows: whenever a hostname resolves to 2+
// IPs and at least one falls OUTSIDE every held CIDR rule's range, the
// decision must never be Allow — partial coverage is always a deny.
func TestProp_CIDRPartialMultiIPNeverAllows(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rule := genCIDRRule(t)
		n, ok := rule.cidr()
		if !ok {
			t.Fatal("genCIDRRule produced a non-CIDR Host")
		}
		inRange := genIPIn(t, n)
		outOfRange := net.ParseIP("203.0.113.1") // TEST-NET-3, never in cidrPool's ranges
		port := rapid.SampledFrom(portPool).Draw(t, "port")

		p := Policy{Roles: []Role{{Name: "r", Groups: []string{"g"}, Allow: []Rule{rule}}}}
		pr := Principal{User: "x", Groups: []string{"g"}}

		d := p.Decide(pr, Target{Host: "mixed.host.name", Port: port}, func(string) ([]net.IP, error) {
			return []net.IP{inRange, outOfRange}, nil
		})
		if d.Allow {
			t.Fatalf("a hostname with one IP outside the matched rule's range must never be allowed, got Allow=true (rule=%+v)", rule)
		}
	})
}
```

- [ ] **Step 13: Run the property tests**

Run: `go test ./internal/policy/... -run TestProp_CIDR -v`
Expected: PASS (both properties hold across rapid's generated cases).

- [ ] **Step 14: Full package verification**

Run: `go build ./... && go vet ./internal/policy/... && go test ./internal/policy/... -v && bash scripts/check-imports.sh`
Expected: all green; `check-imports.sh` reports "import rules OK" (adding `"net"` to `internal/policy` does not use `net.Dial`/`net.Dialer`, so the single-dialer rule is unaffected).

- [ ] **Step 15: Commit**

```bash
git add internal/policy/policy.go internal/policy/policy_test.go internal/policy/policy_decidehost_test.go internal/policy/policy_cidr_prop_test.go
git commit -m "feat: CIDR rules match resolved hostnames, fail closed on partial/split matches"
```

---

### Task 2: CIDR syntax validation and the resolution-disable toggle in `internal/config`

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing from Task 1 directly (config doesn't call `Decide`/`DecideHost`) — but the CIDR string format it validates must match what Task 1's `Rule.cidr()` parses (`net.ParseCIDR`), so use the exact same stdlib call.
- Produces: `PolicyConfig.DisableCIDRHostnameResolution bool` — Task 4 (`cmd/omni-sag/main.go`) reads this field to decide whether to wire a real resolver into the dialer.

- [ ] **Step 1: Write the failing tests**

Append to `internal/config/config_test.go`:

```go
func TestValidatePolicyRoles_MalformedCIDRRejected(t *testing.T) {
	roles := []RoleConfig{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []RuleConfig{{Host: "10.0.0.0/abc"}},
	}}
	if err := validatePolicyRoles(roles); err == nil {
		t.Fatal("a Host containing \"/\" that fails net.ParseCIDR must be rejected at config load, not silently treated as a literal hostname")
	}
}

func TestValidatePolicyRoles_ValidCIDRAccepted(t *testing.T) {
	roles := []RoleConfig{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []RuleConfig{{Host: "10.0.0.0/8"}},
	}}
	if err := validatePolicyRoles(roles); err != nil {
		t.Fatalf("a valid CIDR host must be accepted, got %v", err)
	}
}

func TestPolicyConfig_DisableCIDRHostnameResolutionDefaultsFalse(t *testing.T) {
	f, err := Load(writeTemp(t, demoYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if f.Policy.DisableCIDRHostnameResolution {
		t.Fatal("disable_cidr_hostname_resolution must default to false (resolution enabled) when omitted from YAML")
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/config/... -run 'TestValidatePolicyRoles_.*CIDR|TestPolicyConfig_DisableCIDR' -v`
Expected: `TestValidatePolicyRoles_MalformedCIDRRejected` FAILs (current `validatePolicyRoles` has no CIDR check, so a malformed CIDR is accepted as a literal host string); the other two already pass trivially (nothing to break yet) — that's fine, they document the target behavior for Step 3.

- [ ] **Step 3: Implement**

In `internal/config/config.go`, add `"net"` and `"strings"` to the import block:

```go
import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/rupivbluegreen/omni-sag/internal/fips"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"gopkg.in/yaml.v3"
)
```

In `validatePolicyRoles`, add a CIDR check right after the existing empty-host check (a Host containing "/" is unambiguously CIDR-intended — hostnames never contain one — so a parse failure there is a real config error, not something that should silently fall back to being treated as a literal hostname):

```go
		for _, rule := range r.Allow {
			if rule.Host == "" {
				return fmt.Errorf("config: role %q has a rule with empty host", r.Name)
			}
			if strings.Contains(rule.Host, "/") {
				if _, _, err := net.ParseCIDR(rule.Host); err != nil {
					return fmt.Errorf("config: role %q rule has host %q that looks like CIDR notation but does not parse: %w", r.Name, rule.Host, err)
				}
			}
			switch rule.Record {
```

Add the new field to `PolicyConfig` (`internal/config/config.go`, currently just `Roles`):

```go
// PolicyConfig is the YAML shape of the policy document.
type PolicyConfig struct {
	Roles []RoleConfig `yaml:"roles"`
	// DisableCIDRHostnameResolution opts out of resolving hostname targets
	// for CIDR-shaped rules — matching then falls back to IP-literal targets
	// only, same as if no resolver were configured. Default false (resolution
	// enabled); see internal/policy.ResolverFunc.
	DisableCIDRHostnameResolution bool `yaml:"disable_cidr_hostname_resolution"`
}
```

- [ ] **Step 4: Run to verify all three pass**

Run: `go test ./internal/config/... -run 'TestValidatePolicyRoles_.*CIDR|TestPolicyConfig_DisableCIDR' -v`
Expected: PASS.

- [ ] **Step 5: Full package + repo build verification**

Run: `go build ./... && go test ./internal/config/... -v && make lint`
Expected: all green — this task doesn't touch `internal/policy`'s public API, so no other package's tests are affected yet.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: reject malformed CIDR policy hosts at config load, add disable_cidr_hostname_resolution toggle"
```

---

### Task 3: Wire a real resolver into `internal/dialer`

**Files:**
- Modify: `internal/dialer/dialer.go`
- Test: `internal/dialer/dialer_cidr_test.go` (new)

**Interfaces:**
- Consumes: `policy.ResolverFunc`, `Decide(pr, t, resolve)`, `DecideHost(pr, host, resolve)` from Task 1.
- Produces: `dialer.WithHostnameResolver(fn policy.ResolverFunc) Option`, `dialer.WithHostnameResolutionDisabled() Option`. `DialTarget`/`Peek`/`PeekHost` signatures are UNCHANGED (the resolver is internal `Dialer` state, not a caller-supplied argument) — so `dialer_test.go` and `dialer_ssrf_test.go` need no edits.

- [ ] **Step 1: Write the failing tests**

Create `internal/dialer/dialer_cidr_test.go`:

```go
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
	// A resolver is configured, but resolution is also disabled — disabled
	// must win, proving the toggle actually suppresses lookups rather than
	// merely being decorative.
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

func TestPeekHost_CIDRRuleResolvesHostname(t *testing.T) {
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
```

- [ ] **Step 2: Run to verify these fail to compile**

Run: `go test ./internal/dialer/... -run TestDialTarget_CIDR -v`
Expected: compile error — `WithHostnameResolver`/`WithHostnameResolutionDisabled` undefined.

- [ ] **Step 3: Implement**

In `internal/dialer/dialer.go`, add a `resolver` field to `Dialer` (after `dialControl dialControlFunc`):

```go
	// resolver resolves hostname targets for CIDR-shaped policy rules (see
	// policy.ResolverFunc). Defaults to a real, bounded-timeout DNS lookup;
	// nil disables hostname resolution (CIDR rules still match IP-literal
	// targets). See WithHostnameResolver / WithHostnameResolutionDisabled.
	resolver policy.ResolverFunc
```

Add the default resolver and its bounded timeout near the top of `dialer.go`, alongside the other package-level definitions (after `netDial`'s declaration):

```go
// resolverTimeout bounds how long CIDR-rule hostname resolution may block a
// policy decision. PeekHost runs synchronously in the SSH auth path (see
// session.WithDialerPeek), so an unbounded DNS lookup there could stall a
// login; this keeps the worst case small regardless of caller.
const resolverTimeout = 3 * time.Second

// defaultHostnameResolver is a policy.ResolverFunc backed by net.DefaultResolver.
func defaultHostnameResolver(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolverTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	return ips, nil
}
```

Add `"github.com/rupivbluegreen/omni-sag/internal/policy"`'s already-imported — no new import needed for that type; `time` is already imported.

Add the two Options (near the other `With*` functions, e.g. after `WithDebug`):

```go
// WithHostnameResolver overrides the resolver used to match CIDR policy
// rules against hostname targets. Tests use this to inject a fake resolver;
// production can use it to point at a non-default resolver.
func WithHostnameResolver(fn policy.ResolverFunc) Option {
	return func(d *Dialer) { d.resolver = fn }
}

// WithHostnameResolutionDisabled turns off hostname resolution for CIDR
// policy rules — such rules then only ever match IP-literal targets. Wired
// from config.PolicyConfig.DisableCIDRHostnameResolution.
func WithHostnameResolutionDisabled() Option {
	return func(d *Dialer) { d.resolver = nil }
}
```

In `New`, default the resolver (mirroring how `dialControl` defaults to `guardResolvedAddr`):

```go
func New(p policy.Policy, sink evidence.Sink, opts ...Option) *Dialer {
	d := &Dialer{policy: p, sink: sink, timeout: 10 * time.Second, dialControl: guardResolvedAddr, resolver: defaultHostnameResolver}
	for _, opt := range opts {
		opt(d)
	}
	if d.cred == nil {
		d.cred = credential.NewProvider(credential.Config{})
	}
	if d.dialControl == nil {
		d.dialControl = guardResolvedAddr
	}
	return d
}
```

Note `WithHostnameResolutionDisabled` sets `d.resolver = nil` directly — unlike `dialControl`, `nil` is the intentional off-state here (not "unset, use default"), so `New` must NOT re-default a nil resolver back to `defaultHostnameResolver` the way it does for `dialControl`. Do not add a `if d.resolver == nil { d.resolver = defaultHostnameResolver }` guard after the options loop.

Thread the resolver into the three call sites:

```go
func (d *Dialer) DialTarget(ctx context.Context, pr policy.Principal, sourceIP string, target policy.Target, forwarding bool) (net.Conn, error) {
	decision := d.currentPolicy().Decide(pr, target, d.resolver)
```

```go
func (d *Dialer) Peek(pr policy.Principal, target policy.Target) policy.Decision {
	return d.currentPolicy().Decide(pr, target, d.resolver)
}
```

```go
func (d *Dialer) PeekHost(pr policy.Principal, host string) policy.Decision {
	return d.currentPolicy().DecideHost(pr, host, d.resolver)
}
```

- [ ] **Step 4: Run to verify the new tests pass**

Run: `go test ./internal/dialer/... -run 'TestDialTarget_CIDR|TestPeekHost_CIDR' -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Full verification**

Run: `go build ./... && go test ./internal/dialer/... -v && bash scripts/check-imports.sh`
Expected: all green, including every pre-existing `dialer_test.go`/`dialer_ssrf_test.go` test (their call sites didn't change).

- [ ] **Step 6: Commit**

```bash
git add internal/dialer/dialer.go internal/dialer/dialer_cidr_test.go
git commit -m "feat: wire a default DNS resolver into the dialer for CIDR policy rules"
```

---

### Task 4: Rebind defense — re-validate the connect-time address against the matched CIDR

**Files:**
- Modify: `internal/dialer/guard.go`
- Modify: `internal/dialer/dialer.go`
- Test: `internal/dialer/dialer_cidr_test.go`

**Interfaces:**
- Consumes: `Decision.MatchedCIDR` from Task 1; `dialControlFunc` type from `guard.go`.
- Produces: `guardWithinCIDR(network, address string, n *net.IPNet) error` (package-private, used only inside `DialTarget`).

Without this task, CIDR policy enforcement is real at decision time but only theoretical against a DNS-rebinding attacker at connect time — see the spec's "Rebind defense" section for the full rationale.

- [ ] **Step 1: Write the failing test**

Append to `internal/dialer/dialer_cidr_test.go`:

```go
func TestDialTarget_CIDRRebindDefenseRefusesAddressOutsideMatchedRange(t *testing.T) {
	// Policy decides against db.internal.corp resolving to 10.9.9.9 (inside
	// 10.0.0.0/8, allowed). But the actual connection — netDial, swapped here
	// to simulate what the OS resolver returns at connect time — resolves to
	// 203.0.113.1, outside the matched range. This must be refused even
	// though the policy decision itself was Allow: true.
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		c, _ := net.Pipe()
		return c, nil
	})
	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.9.9.9")}, nil
	}
	d := New(cidrPolicy(), evidence.NewMemSink(), WithHostnameResolver(resolve))
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	dec := d.Peek(pr, policy.Target{Host: "db.internal.corp", Port: 5432})
	if !dec.Allow || dec.MatchedCIDR == nil {
		t.Fatalf("test setup: expected an allowed CIDR match, got %+v", dec)
	}

	// swapDial bypasses the real Control callback entirely (see its doc
	// comment), so this specific test exercises guardWithinCIDR directly
	// instead of end-to-end — the end-to-end path is exactly what
	// TestDialTarget_SSRFGuardBlocksLoopback (dialer_ssrf_test.go) already
	// proves for the existing SSRF guard, using a real listener instead of a
	// swapped dial.
	err := guardWithinCIDR("tcp", "203.0.113.1:5432", dec.MatchedCIDR)
	if err == nil {
		t.Fatal("an address outside the matched CIDR must be refused")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got %v", err)
	}
	_ = dialed
}
```

Add `"errors"` to `dialer_cidr_test.go`'s import block.

Also add a wiring test proving `DialTarget` actually installs the CIDR recheck into the `Control` callback it hands `netDial` — this is the part Step 1's direct `guardWithinCIDR` call doesn't cover, since that call bypasses `DialTarget` entirely. `swapDial` (used everywhere else in this package) isn't usable here because it deliberately drops the `control` argument — see its doc comment in `dialer_test.go`: "the fake replaces the whole socket so the guard control is intentionally bypassed." This test captures `control` instead of bypassing it:

```go
func TestDialTarget_CIDRRebindDefenseWrapsControlCallback(t *testing.T) {
	var capturedControl dialControlFunc
	orig := netDial
	netDial = func(ctx context.Context, network, addr string, control dialControlFunc) (net.Conn, error) {
		capturedControl = control
		c, _ := net.Pipe()
		return c, nil
	}
	t.Cleanup(func() { netDial = orig })

	resolve := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.9.9.9")}, nil
	}
	d := New(cidrPolicy(), evidence.NewMemSink(), WithHostnameResolver(resolve))
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	_, err := d.DialTarget(context.Background(), pr, "1.2.3.4", policy.Target{Host: "db.internal.corp", Port: 5432}, false)
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if capturedControl == nil {
		t.Fatal("expected a Control callback to be passed to netDial")
	}

	// Simulate the OS resolving db.internal.corp to an address OUTSIDE the
	// matched CIDR at actual connect time (a rebind, moments after the policy
	// decision above used a different resolution) — the captured Control must
	// refuse it even though the policy decision itself was Allow.
	if err := capturedControl("tcp", "203.0.113.1:5432", nil); err == nil {
		t.Fatal("captured Control must refuse an address outside the matched CIDR")
	}
	// And it must still accept the in-range address the policy actually matched
	// (proving the wrapped Control composes with, rather than replaces, the
	// base guard — guardResolvedAddr's syscall.RawConn parameter is unused by
	// both checks, so nil is safe here).
	if err := capturedControl("tcp", "10.9.9.9:5432", nil); err != nil {
		t.Fatalf("captured Control must accept the in-range address, got %v", err)
	}
}
```

- [ ] **Step 2: Run to verify these fail to compile**

Run: `go test ./internal/dialer/... -run TestDialTarget_CIDRRebindDefense -v`
Expected: compile error — `guardWithinCIDR` undefined.

- [ ] **Step 3: Implement `guardWithinCIDR`**

Append to `internal/dialer/guard.go`:

```go
// guardWithinCIDR re-validates a connect-time address against the CIDR range
// a policy decision matched at decision time. Policy resolves a hostname
// once, when Decide/DecideHost runs; the actual connection resolves the same
// hostname again, independently, moments later inside netDial's Control
// callback. Between those two resolutions a low-TTL DNS record can rebind to
// a different address — this closes that gap by checking the exact address
// about to be dialed, the same way guardResolvedAddr does for the static
// SSRF blocklist. Composed with (not a replacement for) guardResolvedAddr.
func guardWithinCIDR(network, address string, n *net.IPNet) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %s %q resolved to an unparseable address", ErrBlockedAddress, network, address)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if !n.Contains(ip) {
		return fmt.Errorf("%w: %s -> %s (outside matched CIDR %s — possible DNS rebind)", ErrBlockedAddress, address, ip, n)
	}
	return nil
}
```

- [ ] **Step 4: Wire it into `DialTarget`**

In `internal/dialer/dialer.go`, replace the dial call in `DialTarget`:

```go
	dialCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	conn, err := netDial(dialCtx, "tcp", target.String(), d.dialControl)
	if err != nil {
		return nil, fmt.Errorf("dialer: dial %s: %w", target, err)
	}
	return conn, nil
```

with:

```go
	dialCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	control := d.dialControl
	if decision.MatchedCIDR != nil {
		base, n := d.dialControl, decision.MatchedCIDR
		control = func(network, address string, c syscall.RawConn) error {
			if err := base(network, address, c); err != nil {
				return err
			}
			return guardWithinCIDR(network, address, n)
		}
	}
	conn, err := netDial(dialCtx, "tcp", target.String(), control)
	if err != nil {
		return nil, fmt.Errorf("dialer: dial %s: %w", target, err)
	}
	return conn, nil
```

Add `"syscall"` to `dialer.go`'s import block.

- [ ] **Step 5: Run to verify all pass**

Run: `go test ./internal/dialer/... -v`
Expected: PASS, all tests including the pre-existing SSRF and CIDR ones from Task 3.

- [ ] **Step 6: Full verification**

Run: `go build ./... && go vet ./... && bash scripts/check-imports.sh && make test`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add internal/dialer/guard.go internal/dialer/dialer.go internal/dialer/dialer_cidr_test.go
git commit -m "feat: re-validate connect-time address against the matched CIDR (rebind defense)"
```

---

### Task 5: Wire the config toggle in `cmd/omni-sag` and document it

**Files:**
- Modify: `cmd/omni-sag/main.go`
- Modify: `deploy/compose/config.example.yaml`

**Interfaces:**
- Consumes: `cfg.Policy.DisableCIDRHostnameResolution` (Task 2), `dialer.WithHostnameResolutionDisabled()` (Task 3).

This task has no new unit test of its own — it's composition-root wiring, already covered end-to-end by Task 3's `TestDialTarget_CIDRRuleDeniesHostnameWhenResolutionDisabled` (which exercises the `Dialer` option directly). Verification here is a manual config load + `make ci`.

- [ ] **Step 1: Wire the toggle**

In `cmd/omni-sag/main.go`, next to the existing capability-toggle wiring (`dopts = append(dopts, dialer.WithDebug(debug))` and the `DisableSSH`/`DisableTunnel`/`DisableSFTP` block further down), add:

```go
	if cfg.Policy.DisableCIDRHostnameResolution {
		dopts = append(dopts, dialer.WithHostnameResolutionDisabled())
		log.Printf("omni-sag: CIDR policy rules will not resolve hostnames (disable_cidr_hostname_resolution)")
	}
```

Place it right after the existing `dopts = append(dopts, dialer.WithDebug(debug))` block (before the CyberArk block), so all `dopts` capability wiring stays grouped together.

- [ ] **Step 2: Document the field in the compose example**

In `deploy/compose/config.example.yaml`, find the `policy:` section (currently starts `policy:\n  roles:\n    - name: dba...`) and add a comment above it, matching the style of the existing `# disable_ssh: true` block near the top of the file:

```yaml
# CIDR ranges are accepted as Rule.Host anywhere below (e.g. "10.0.0.0/8"),
# alongside exact hostnames and "*". A hostname target is matched against a
# CIDR rule by resolving it first; uncomment to turn that resolution off
# (CIDR rules then only ever match IP-literal targets):
# policy:
#   disable_cidr_hostname_resolution: true
policy:
  roles:
    - name: dba
      groups: ["dba"] # AD group granting this role
```

- [ ] **Step 3: Add a regression test that the shipped example config still loads**

`cmd/omni-sag` has no dry-run/check flag (`flag.String("config", ...)` and `flag.Bool("debug", ...)` are the only two flags — see `cmd/omni-sag/main.go:44-45`), so verify via `internal/config` directly. Append to `internal/config/config_test.go`:

```go
func TestLoad_ComposeExampleConfigParses(t *testing.T) {
	// Regression check: the shipped deploy/compose/config.example.yaml must
	// always be loadable, including the new commented-out
	// disable_cidr_hostname_resolution documentation added alongside it.
	_, err := Load("../../deploy/compose/config.example.yaml")
	if err != nil {
		t.Fatalf("deploy/compose/config.example.yaml failed to load: %v", err)
	}
}
```

Run: `go test ./internal/config/... -run TestLoad_ComposeExampleConfigParses -v`
Expected: PASS — confirms the commented-out `policy.disable_cidr_hostname_resolution` documentation doesn't break YAML parsing (comments never do, but this also catches any other accidental breakage in the example file going forward, not just this task's edit).

- [ ] **Step 4: Full repo verification**

Run: `make ci`
Expected: `build lint check-imports test` all pass — this is the final gate for the whole feature; every task's tests run together here for the first time.

- [ ] **Step 5: Commit**

```bash
git add cmd/omni-sag/main.go deploy/compose/config.example.yaml internal/config/config_test.go
git commit -m "feat: wire disable_cidr_hostname_resolution into the gateway, document CIDR rules in the compose example"
```
