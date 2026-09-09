# Client-selected target user Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the SSH auth-username grammar to `loginuser[+pcode]%[targetuser@]targethost[:port]` so a client can name the account to use on the target host, gated by a default-deny per-rule `allow_target_users` allow-list.

**Architecture:** A fourth pure splitter (`splitTargetAccount`) runs between the existing `%` and `:port` splits and validates rather than tolerates. The requested account rides `ssh.Permissions.Extensions` → `policy.Principal` as a carrier field, exactly like `TargetHost`. One pure helper in `internal/policy` (`ResolveTargetUser`) decides the effective account and is the sole authority; it is called from `dialTarget` (the single choke point for shell, SFTP and SCP) and from the prompt-mode password prompt, so the two can never disagree.

**Tech Stack:** Go, `golang.org/x/crypto/ssh`, existing `internal/{policy,config,session,evidence,sessions,credential,ratelimit}` packages. No new module dependencies.

**Spec:** `docs/superpowers/specs/2026-09-09-client-selected-target-user-design.md`

## Global Constraints

- `internal/policy` must stay pure: stdlib imports only, no `internal/session`, no `internal/credential` (`scripts/check-imports.sh`). `ResolveTargetUser` returns `policy.ErrTargetUserDenied`; `internal/session` wraps it into `credential.ErrDenied`.
- No silent downgrade: a denied or unparseable target account never falls back to another account, and never yields a usable `*ssh.Client` (FR-18, and the same contract `internal/credential` already enforces).
- Default-deny: an absent or empty `allow_target_users` refuses a client-supplied account. Every existing policy file must behave exactly as it does today after this change.
- Under `credential: inject` a client-supplied account that is not identical to the rule's `target_user` is always denied, allow-list or not.
- The secret is never placed in any evidence field, log line, or registry entry.
- `gofmt`/`go vet` clean; `make ci` green after every task.
- Every pre-existing test in `internal/session`, `internal/policy` and `internal/config` must pass untouched.

---

## File Structure

New files:
- `internal/policy/targetuser.go` — `ErrTargetUserDenied`, `ResolveTargetUser`, `allowsTargetUser`. Kept out of `policy.go` because it is resolution, not evaluation, and `policy.go` is already large.
- `internal/policy/targetuser_test.go` — the precedence matrix.

Modified files:
- `internal/policy/policy.go` — `Rule.AllowTargetUsers`, `Decision.AllowTargetUsers`, wired into the three `Decision` literals (`:263`, `:292`, `:482`).
- `internal/config/config.go` — `RuleConfig.AllowTargetUsers` (yaml `allow_target_users`), validation, `CompilePolicy` wiring (`:897`).
- `internal/session/target.go` — `splitTargetAccount`; `dialTarget` calls `ResolveTargetUser`; `emitTargetCredential` gains a `targetUser` parameter; second-leg auth failures feed `bfLimiter`.
- `internal/session/session.go` — `passwordCallback` parse + auth-time resolution + `requested_target_user` extension in both permission branches; `principalFrom`; `sessions.Info` registration.
- `internal/policy/policy.go` — `Principal.RequestedTargetUser`.
- `internal/evidence/evidence.go` — `Event.TargetUser`.
- `internal/sessions/registry.go` — `Info.TargetUser`.
- `README.md`, `deploy/compose/config.example.yaml`, `scripts/lab-test-real-target.sh`.

Not in this repo: the private control-plane chart's policy files. `deploy/helm/omni-sag` carries policy inside `templates/configmap.yaml` and documents no grammar, so it needs no change.

---

### Task 1: Policy — `AllowTargetUsers` and `ResolveTargetUser`

**Files:**
- Create: `internal/policy/targetuser.go`
- Test: `internal/policy/targetuser_test.go`
- Modify: `internal/policy/policy.go`

**Interfaces:**
- Consumes: `policy.Decision` (existing `TargetUser`, `CredentialMode`).
- Produces: `policy.Rule.AllowTargetUsers []string`, `policy.Decision.AllowTargetUsers []string`, `policy.Principal.RequestedTargetUser string`, `policy.ErrTargetUserDenied`, `func policy.ResolveTargetUser(requested string, d Decision, loginUser string) (string, error)`.

- [ ] **Step 1: Write the failing precedence test**

Create `internal/policy/targetuser_test.go`:

```go
package policy

import (
	"errors"
	"testing"
)

func TestResolveTargetUser(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		decision  Decision
		loginUser string
		want      string
		wantDeny  bool
	}{
		{
			name: "rule pins, client asks for a different account -> deny",
			requested: "user01", loginUser: "alice",
			decision: Decision{TargetUser: "svc_db1", CredentialMode: "prompt"},
			wantDeny: true,
		},
		{
			name: "rule pins, client asks for nothing -> rule wins",
			requested: "", loginUser: "alice",
			decision: Decision{TargetUser: "svc_db1", CredentialMode: "prompt"},
			want: "svc_db1",
		},
		{
			name: "rule pins, client asks for the same account -> rule wins",
			requested: "svc_db1", loginUser: "alice",
			decision: Decision{TargetUser: "svc_db1", CredentialMode: "prompt"},
			want: "svc_db1",
		},
		{
			name: "no rule account, client asks, listed -> client wins",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt", AllowTargetUsers: []string{"user01", "user02"}},
			want: "user01",
		},
		{
			name: "no rule account, client asks, wildcard -> client wins",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "passthrough", AllowTargetUsers: []string{"*"}},
			want: "user01",
		},
		{
			name: "no rule account, client asks, not listed -> deny",
			requested: "root", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt", AllowTargetUsers: []string{"user01"}},
			wantDeny: true,
		},
		{
			name: "no rule account, client asks, empty allow-list -> deny (default-deny)",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt"},
			wantDeny: true,
		},
		{
			name: "inject mode, client asks, even when listed -> deny (credential oracle)",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "inject", AllowTargetUsers: []string{"user01"}},
			wantDeny: true,
		},
		{
			name: "deny mode, client asks -> deny",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "deny", AllowTargetUsers: []string{"user01"}},
			wantDeny: true,
		},
		{
			name: "neither -> gateway login user",
			requested: "", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt"},
			want: "alice",
		},
		{
			name: "empty credential mode is passthrough, listed -> client wins",
			requested: "user01", loginUser: "alice",
			decision: Decision{AllowTargetUsers: []string{"user01"}},
			want: "user01",
		},
		{
			name: "allow-list match is exact, not case-folded -> deny",
			requested: "User01", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt", AllowTargetUsers: []string{"user01"}},
			wantDeny: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveTargetUser(c.requested, c.decision, c.loginUser)
			if c.wantDeny {
				if !errors.Is(err, ErrTargetUserDenied) {
					t.Fatalf("got (%q, %v), want an error wrapping ErrTargetUserDenied", got, err)
				}
				if got != "" {
					t.Fatalf("got user %q on denial, want empty (no silent downgrade)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("got err %v, want nil", err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestDecideCarriesAllowTargetUsers(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "db1.lab.local", Credential: "prompt", AllowTargetUsers: []string{"user01"}}},
	}}}
	d := p.Decide(Principal{User: "alice", Groups: []string{"dba"}}, Target{Host: "db1.lab.local", Port: 22}, nil)
	if !d.Allow || len(d.AllowTargetUsers) != 1 || d.AllowTargetUsers[0] != "user01" {
		t.Fatalf("got Allow=%v AllowTargetUsers=%v, want true [user01]", d.Allow, d.AllowTargetUsers)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/policy/... -run 'TestResolveTargetUser|TestDecideCarriesAllowTargetUsers' -v`
Expected: FAIL — compile error, `ResolveTargetUser`/`ErrTargetUserDenied`/`AllowTargetUsers` undefined.

- [ ] **Step 3: Add the carrier and allow-list fields**

In `internal/policy/policy.go`, add to `Rule` (after `TargetUser string`):

```go
	// AllowTargetUsers is the exhaustive set of accounts a CLIENT may name in
	// the "%[targetuser@]host" auth-username grammar for this rule's matches.
	// Empty (the default) denies any client-supplied account, so a policy
	// written before that grammar existed keeps its exact behaviour. "*"
	// permits any syntactically valid account. Only meaningful when TargetUser
	// is unset and Credential is prompt/passthrough; config validation rejects
	// the other combinations rather than silently ignoring the list.
	AllowTargetUsers []string
```

Add to `Decision` (after `TargetUser string`):

```go
	AllowTargetUsers []string // accounts a client may name; empty => none (see Rule.AllowTargetUsers)
```

Add to `Principal` (after the `TargetPort` block):

```go
	// RequestedTargetUser is the account the client asked to use ON THE TARGET
	// via the "%[targetuser@]host" auth-username grammar ("" when it wrote
	// only "%host"). It is a client-REQUESTED, NOT-YET-AUTHORIZED value:
	// nothing may dial or prompt with it until ResolveTargetUser has approved
	// it against the matched Decision. Carrier field, threaded from the auth
	// layer like TargetHost and TargetSecretToken; no Decide logic reads it.
	RequestedTargetUser string
```

Add `AllowTargetUsers: rule.AllowTargetUsers,` to the `Decision` literal in `Decide`'s exact-match branch (`policy.go:263`), `AllowTargetUsers: rule.AllowTargetUsers,` to its CIDR branch (`policy.go:292`), and `AllowTargetUsers: m.rule.AllowTargetUsers,` to `DecideHost`'s literal (`policy.go:482`).

- [ ] **Step 4: Write the resolver**

Create `internal/policy/targetuser.go`:

```go
// Package policy (targetuser.go): resolving which account the gateway
// authenticates as on the target host.
package policy

import (
	"errors"
	"fmt"
)

// ErrTargetUserDenied is returned when the client named a target account it
// may not use. internal/policy cannot import internal/credential (CI-enforced
// import rule), so callers in internal/session wrap this into
// credential.ErrDenied and the fail-closed credential contract is unchanged.
var ErrTargetUserDenied = errors.New("policy: target user denied")

// ResolveTargetUser returns the account the gateway must authenticate as on
// the target: requested is what the client asked for in the
// "%[targetuser@]host" auth-username grammar ("" when it asked for nothing),
// d is the matched decision, loginUser is the gateway login user.
//
// Precedence:
//
//  1. rule pins TargetUser and requested differs      -> ErrTargetUserDenied
//  2. rule pins TargetUser, requested empty or equal  -> the rule's account
//  3. rule pins nothing, requested non-empty          -> requested, but only
//     under credential mode prompt/passthrough and only when
//     d.AllowTargetUsers lists it; otherwise ErrTargetUserDenied
//  4. neither                                         -> loginUser
//
// Case 3's inject exclusion holds even when the allow-list names the account:
// under inject the gateway fetches a secret keyed by the account, so honouring
// a client-named one would make the gateway a credential oracle for every
// vaulted account on an allowed host.
//
// Matching is exact, never case-folded: the account is a local account on the
// target, where case is significant, and a near-miss must fail closed rather
// than authenticate as a different account than the one the client named.
//
// On denial the returned string is always empty — there is no partial result
// a caller could mistake for a usable account.
func ResolveTargetUser(requested string, d Decision, loginUser string) (string, error) {
	if requested == "" {
		if d.TargetUser != "" {
			return d.TargetUser, nil
		}
		return loginUser, nil
	}
	if d.TargetUser != "" {
		if requested == d.TargetUser {
			return d.TargetUser, nil
		}
		return "", fmt.Errorf("%w: rule pins target user %q, client requested %q", ErrTargetUserDenied, d.TargetUser, requested)
	}
	switch d.CredentialMode {
	case "prompt", "passthrough", "": // empty == passthrough, per Rule.Credential
	default:
		return "", fmt.Errorf("%w: credential mode %q never accepts a client-supplied target user", ErrTargetUserDenied, d.CredentialMode)
	}
	if !allowsTargetUser(d.AllowTargetUsers, requested) {
		return "", fmt.Errorf("%w: rule does not list target user %q in allow_target_users", ErrTargetUserDenied, requested)
	}
	return requested, nil
}

func allowsTargetUser(allow []string, requested string) bool {
	for _, a := range allow {
		if a == "*" || a == requested {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run the policy tests, verify pass**

Run: `go test ./internal/policy/... -v`
Expected: PASS — the new tests plus every pre-existing policy test.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/targetuser.go internal/policy/targetuser_test.go internal/policy/policy.go
git commit -m "policy: resolve the target user from rule, allow-list and request"
```

---

### Task 2: Config — `allow_target_users`

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: `policy.Rule.AllowTargetUsers` (Task 1).
- Produces: `config.RuleConfig.AllowTargetUsers []string` (yaml `allow_target_users`), compiled through `CompilePolicy`.

- [ ] **Step 1: Write the failing config tests**

Add to `internal/config/config_test.go`:

```go
func TestCompilePolicy_AllowTargetUsers(t *testing.T) {
	f := &File{Roles: []RoleConfig{{
		Name:  "dba",
		Allow: []RuleConfig{{Host: "db1.lab.local", Credential: "prompt", AllowTargetUsers: []string{"user01"}}},
	}}}
	p := f.CompilePolicy()
	got := p.Roles[0].Allow[0].AllowTargetUsers
	if len(got) != 1 || got[0] != "user01" {
		t.Fatalf("AllowTargetUsers = %v, want [user01]", got)
	}
}

func TestValidate_AllowTargetUsersRejected(t *testing.T) {
	cases := []struct {
		name string
		rule RuleConfig
	}{
		{"with target_user", RuleConfig{Host: "h", Credential: "prompt", TargetUser: "svc_db1", AllowTargetUsers: []string{"user01"}}},
		{"with inject", RuleConfig{Host: "h", Credential: "inject", AllowTargetUsers: []string{"user01"}}},
		{"with deny", RuleConfig{Host: "h", Credential: "deny", AllowTargetUsers: []string{"user01"}}},
		{"empty entry", RuleConfig{Host: "h", Credential: "prompt", AllowTargetUsers: []string{""}}},
		{"entry with @", RuleConfig{Host: "h", Credential: "prompt", AllowTargetUsers: []string{"svc@corp.local"}}},
		{"entry with space", RuleConfig{Host: "h", Credential: "prompt", AllowTargetUsers: []string{"user 01"}}},
		{"wildcard mixed with names", RuleConfig{Host: "h", Credential: "prompt", AllowTargetUsers: []string{"*", "user01"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &File{Listen: ":2222", Roles: []RoleConfig{{Name: "dba", Allow: []RuleConfig{c.rule}}}}
			if err := f.validate(); err == nil {
				t.Fatal("validate() = nil, want an error")
			}
		})
	}
}

func TestValidate_AllowTargetUsersAccepted(t *testing.T) {
	for _, allow := range [][]string{{"user01", "user02"}, {"*"}} {
		f := &File{Listen: ":2222", Roles: []RoleConfig{{
			Name:  "dba",
			Allow: []RuleConfig{{Host: "h", Credential: "prompt", AllowTargetUsers: allow}},
		}}}
		if err := f.validate(); err != nil {
			t.Fatalf("validate() with %v = %v, want nil", allow, err)
		}
	}
}
```

If `File.validate()` requires more fields than `Listen` to pass, copy the minimal valid `File` literal from the nearest existing `validate` test in the same file rather than inventing one.

- [ ] **Step 2: Run them, verify they fail**

Run: `go test ./internal/config/... -run AllowTargetUsers -v`
Expected: FAIL — `RuleConfig` has no field `AllowTargetUsers` (compile error).

- [ ] **Step 3: Add the field, validation and wiring**

In `internal/config/config.go`, add to `RuleConfig` (after `TargetUser`):

```go
	AllowTargetUsers []string `yaml:"allow_target_users,omitempty"` // accounts a client may name via "%targetuser@host"; empty => none, "*" => any
```

In `validate()`, inside the rule loop that already checks `record`/`credential` (around `config.go:830-843`), after the `credential` switch:

```go
			if len(rule.AllowTargetUsers) > 0 {
				if rule.TargetUser != "" {
					return fmt.Errorf("config: role %q rule for %q sets both target_user and allow_target_users — target_user pins the account, so the allow-list would never be consulted", r.Name, rule.Host)
				}
				switch rule.Credential {
				case "inject", "deny":
					return fmt.Errorf("config: role %q rule for %q sets allow_target_users with credential %q — a client-supplied target user is never honoured in that mode", r.Name, rule.Host, rule.Credential)
				}
				wildcard := false
				for _, u := range rule.AllowTargetUsers {
					if u == "*" {
						wildcard = true
						continue
					}
					if u == "" || strings.ContainsAny(u, " \t@%+") {
						return fmt.Errorf("config: role %q rule for %q has invalid allow_target_users entry %q", r.Name, rule.Host, u)
					}
				}
				if wildcard && len(rule.AllowTargetUsers) > 1 {
					return fmt.Errorf("config: role %q rule for %q mixes \"*\" with named entries in allow_target_users — use one or the other", r.Name, rule.Host)
				}
			}
```

In `CompilePolicy` (`config.go:891-899`), add to the `policy.Rule` literal:

```go
				AllowTargetUsers: ru.AllowTargetUsers,
```

- [ ] **Step 4: Run the config tests, verify pass**

Run: `go test ./internal/config/... -v`
Expected: PASS — new tests plus every pre-existing config test.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "config: add allow_target_users and reject the inert combinations"
```

---

### Task 3: Parse `[targetuser@]host` and carry the request through auth

**Files:**
- Modify: `internal/session/target.go`
- Modify: `internal/session/session.go`
- Test: `internal/session/target_test.go`

**Interfaces:**
- Consumes: `policy.Principal.RequestedTargetUser` (Task 1).
- Produces: `func splitTargetAccount(targetSpec string) (targetUser, hostSpec string, ok bool)`; `ssh.Permissions.Extensions["requested_target_user"]`; `principalFrom` populating `RequestedTargetUser`.

- [ ] **Step 1: Write the failing parser test**

Add to `internal/session/target_test.go`:

```go
func TestSplitTargetAccount(t *testing.T) {
	cases := []struct {
		raw          string
		wantUser     string
		wantHostSpec string
		wantOK       bool
	}{
		{"10.0.0.5", "", "10.0.0.5", true},
		{"user01@10.0.0.5", "user01", "10.0.0.5", true},
		{"user01@10.0.0.5:2222", "user01", "10.0.0.5:2222", true},
		{"user01@[2001:db8::1]:22", "user01", "[2001:db8::1]:22", true},
		{"fe80::1%eth0", "", "fe80::1%eth0", true}, // IPv6 zone id untouched
		{"", "", "", true},
		{"@host", "", "", false},          // empty account
		{"user01@", "", "", false},        // empty host
		{"user01@host@x", "", "", false},  // ambiguous: more than one "@"
		{"user 01@host", "", "", false},   // whitespace in the account
	}
	for _, c := range cases {
		u, h, ok := splitTargetAccount(c.raw)
		if u != c.wantUser || h != c.wantHostSpec || ok != c.wantOK {
			t.Errorf("splitTargetAccount(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.raw, u, h, ok, c.wantUser, c.wantHostSpec, c.wantOK)
		}
	}
}

func TestFullGrammarChain(t *testing.T) {
	cases := []struct {
		raw        string
		wantLogin  string
		wantPcode  string
		wantTUser  string
		wantHost   string
		wantPort   int
		wantOK     bool
	}{
		{"u%host", "u", "", "", "host", 0, true},
		{"u%user01@host", "u", "", "user01", "host", 0, true},
		{"u%user01@host:2222", "u", "", "user01", "host", 2222, true},
		{"u+pcodeA%user01@host", "u", "pcodeA", "user01", "host", 0, true},
		{"u%user01@[2001:db8::1]:22", "u", "", "user01", "2001:db8::1", 22, true},
		{"u%@host", "u", "", "", "", 0, false},
		{"u%user01@", "u", "", "", "", 0, false},
		{"u%user01@host@x", "u", "", "", "", 0, false},
	}
	for _, c := range cases {
		login, spec, _ := splitTargetUser(c.raw)
		login, pcode := splitPcodeSelector(login)
		tuser, hostSpec, ok := splitTargetAccount(spec)
		if ok != c.wantOK {
			t.Errorf("%q: ok = %v, want %v", c.raw, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		host, port := splitTargetHostPort(hostSpec)
		if login != c.wantLogin || pcode != c.wantPcode || tuser != c.wantTUser || host != c.wantHost || port != c.wantPort {
			t.Errorf("%q = (login %q, pcode %q, targetuser %q, host %q, port %d), want (%q, %q, %q, %q, %d)",
				c.raw, login, pcode, tuser, host, port, c.wantLogin, c.wantPcode, c.wantTUser, c.wantHost, c.wantPort)
		}
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run 'TestSplitTargetAccount|TestFullGrammarChain' -v`
Expected: FAIL — `splitTargetAccount` undefined.

- [ ] **Step 3: Write the splitter**

In `internal/session/target.go`, immediately after `splitPcodeSelector` (so the file reads in parse order):

```go
// splitTargetAccount splits the target portion of an SSH auth username —
// everything after the "%" — into an optional target account and the host
// spec: "user01@10.0.0.5:22" -> ("user01", "10.0.0.5:22"), "10.0.0.5:22" ->
// ("", "10.0.0.5:22"). "@" is the separator because it cannot appear in an AD
// sAMAccountName and does not collide with "%" (the login/target boundary) or
// "+" (the pcode selector); the SSH client has already consumed its own
// trailing "@gateway" by splitting its [user@]host argument on the LAST "@",
// so only the gateway-side string reaches here. It runs BEFORE
// splitTargetHostPort so that splitter still sees a plain "[host]:port".
//
// Unlike the other splitters this one validates instead of tolerating: an
// empty account, an empty host, whitespace in the account, or more than one
// "@" returns ok=false and the caller fails authentication closed. More than
// one "@" is ambiguous rather than merely odd — AD accounts are often written
// as UPNs ("svc_db1@corp.local"), and CyberArk's PSM for SSH hit the same
// collision and reserved "#" for the domain rather than overloading "@".
// Guessing which "@" splits would pick a target account on the user's behalf.
func splitTargetAccount(targetSpec string) (targetUser, hostSpec string, ok bool) {
	i := strings.IndexByte(targetSpec, '@')
	if i < 0 {
		return "", targetSpec, true
	}
	targetUser, hostSpec = targetSpec[:i], targetSpec[i+1:]
	if targetUser == "" || hostSpec == "" ||
		strings.ContainsAny(targetUser, " \t") || strings.Contains(hostSpec, "@") {
		return "", "", false
	}
	return targetUser, hostSpec, true
}
```

- [ ] **Step 4: Run the parser tests, verify pass**

Run: `go test ./internal/session/... -run 'TestSplitTargetAccount|TestFullGrammarChain' -v`
Expected: PASS

- [ ] **Step 5: Wire it into `passwordCallback`**

In `internal/session/session.go`, replace the three-line split at `:381-383`:

```go
		loginUser, targetHost, hasTarget := splitTargetUser(meta.User())
		loginUser, pcode := splitPcodeSelector(loginUser)
		targetHost, targetPort := splitTargetHostPort(targetHost)
```

with:

```go
		loginUser, targetSpec, hasTarget := splitTargetUser(meta.User())
		loginUser, pcode := splitPcodeSelector(loginUser)
		requestedTargetUser, hostSpec, specOK := splitTargetAccount(targetSpec)
		if !specOK {
			s.bfLimiter.RecordFailure(srcIP)
			s.emit(ctx, evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeAuth,
				User: loginUser, SourceIP: srcIP,
				Allow: evidence.BoolPtr(false), Reason: "malformed target specification",
			})
			return nil, errors.New("authentication failed")
		}
		targetHost, targetPort := splitTargetHostPort(hostSpec)
```

Pack the request into both permission branches. In the prompt-mode
`KeyboardInteractiveCallback`'s returned `ssh.Permissions.Extensions` map
(`session.go:471-478`), add:

```go
							"requested_target_user": requestedTargetUser,
```

and in the normal `perms` construction (`session.go:479-491`), after the
`target_port` block:

```go
		if requestedTargetUser != "" {
			perms.Extensions["requested_target_user"] = requestedTargetUser
		}
```

In `principalFrom` (`session.go:774-791`), add to the returned literal:

```go
		RequestedTargetUser: perms.Extensions["requested_target_user"],
```

- [ ] **Step 6: Run the full session suite, verify pass**

Run: `go test ./internal/session/... ./internal/policy/... ./internal/config/... -v`
Expected: PASS — no pre-existing test changes.

- [ ] **Step 7: Commit**

```bash
git add internal/session/target.go internal/session/target_test.go internal/session/session.go
git commit -m "session: parse an optional target account out of the auth username"
```

---

### Task 4: Evidence — record the target account

**Files:**
- Modify: `internal/evidence/evidence.go`
- Modify: `internal/session/target.go`
- Test: `internal/evidence/evidence_test.go`

**Interfaces:**
- Produces: `evidence.Event.TargetUser string` (json `target_user`); `emitTargetCredential` gains a `targetUser string` parameter after `targetPort int`.

- [ ] **Step 1: Write the failing evidence test**

Add to `internal/evidence/evidence_test.go`:

```go
func TestEventTargetUserJSON(t *testing.T) {
	b, err := json.Marshal(Event{Type: TypeCredential, User: "alice", TargetUser: "user01"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"target_user":"user01"`) {
		t.Fatalf("marshalled event = %s, want a target_user field", b)
	}
	b, err = json.Marshal(Event{Type: TypeCredential, User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "target_user") {
		t.Fatalf("marshalled event = %s, want target_user omitted when empty", b)
	}
}
```

Add `encoding/json` and `strings` to that file's imports if they are not already there.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/evidence/... -run TestEventTargetUserJSON -v`
Expected: FAIL — `Event` has no field `TargetUser`.

- [ ] **Step 3: Add the field and thread it through the credential emitter**

In `internal/evidence/evidence.go`, in the credential block (`:65-67`):

```go
	// Credential fields (credential events). The secret is NEVER recorded.
	CredentialMode string `json:"credential_mode,omitempty"` // inject | prompt | passthrough | deny
	Outcome        string `json:"outcome,omitempty"`         // injected | prompt | passthrough | denied
	// TargetUser is the account the gateway authenticates as on the target's
	// second SSH leg — the effective one, after policy resolution, not what
	// the client asked for. Accountability for "who connected as whom" is the
	// point of this gateway, so it must be a field, not a Detail string.
	TargetUser string `json:"target_user,omitempty"`
```

In `internal/session/target.go`, change `emitTargetCredential`'s signature and body:

```go
func (s *Server) emitTargetCredential(ctx context.Context, pr policy.Principal, srcIP, targetHost string, targetPort int, targetUser string, mode credential.Mode, outcome, reason string, allow bool) {
	s.emit(ctx, evidence.Event{
		Time:           time.Now().UTC(),
		Type:           evidence.TypeCredential,
		User:           pr.User,
		SourceIP:       srcIP,
		Target:         net.JoinHostPort(targetHost, strconv.Itoa(targetPort)),
		TargetUser:     targetUser,
		Allow:          evidence.BoolPtr(allow),
		CredentialMode: string(mode),
		Outcome:        outcome,
		Reason:         reason,
	})
}
```

Update all eleven call sites inside `dialTarget` (`target.go:162,168,175,178,189,192,199,204,211,216`) to pass the local `targetUser` in the new position. They are all in scope of that variable, so the edit is mechanical:
`..., targetPort, mode, ...` becomes `..., targetPort, targetUser, mode, ...`.

- [ ] **Step 4: Run the evidence and session suites, verify pass**

Run: `go test ./internal/evidence/... ./internal/session/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/evidence.go internal/evidence/evidence_test.go internal/session/target.go
git commit -m "evidence: record the target account on credential events"
```

---

### Task 5: Resolve the target account at both call sites

**Files:**
- Modify: `internal/session/target.go`
- Modify: `internal/session/session.go`
- Test: `internal/session/target_test.go`

**Interfaces:**
- Consumes: `policy.ResolveTargetUser`, `policy.ErrTargetUserDenied` (Task 1); `policy.Principal.RequestedTargetUser` (Task 3); `evidence.Event.TargetUser` (Task 4).
- Produces: `dialTarget` denying with an error wrapping `credential.ErrDenied`; the prompt string naming the resolved account.

- [ ] **Step 1: Write the failing tests**

Add to `internal/session/target_test.go`:

```go
func TestDialTargetDeniesUnauthorizedTargetUser(t *testing.T) {
	sink := evidence.NewMemSink()
	s := New(WithEvidence(sink), WithInsecureTargetHostKey())
	pr := policy.Principal{User: "alice", RequestedTargetUser: "root"}
	d := policy.Decision{Allow: true, CredentialMode: "prompt", AllowTargetUsers: []string{"user01"}}

	c, err := s.dialTarget(context.Background(), nil, pr, "10.0.0.1", d, "db1.lab.local", 22, "")
	if c != nil {
		t.Fatal("got a client on a denied target user, want nil (no silent downgrade)")
	}
	if !errors.Is(err, credential.ErrDenied) {
		t.Fatalf("got err %v, want one wrapping credential.ErrDenied", err)
	}
	var found bool
	for _, e := range sink.Events() {
		if e.Type == evidence.TypeCredential && e.Outcome == "denied" {
			found = true
			if !strings.Contains(e.Detail, "requested=root") {
				t.Errorf("denial event Detail = %q, want it to name the requested account", e.Detail)
			}
		}
	}
	if !found {
		t.Fatal("no denied credential event emitted")
	}
}

func TestDialTargetUsesAllowedTargetUser(t *testing.T) {
	pr := policy.Principal{User: "alice", RequestedTargetUser: "user01"}
	d := policy.Decision{Allow: true, CredentialMode: "prompt", AllowTargetUsers: []string{"user01"}}
	got, err := policy.ResolveTargetUser(pr.RequestedTargetUser, d, pr.User)
	if err != nil || got != "user01" {
		t.Fatalf("ResolveTargetUser = (%q, %v), want (user01, nil)", got, err)
	}
}
```

Match the constructor, evidence sink and option names to the ones the
neighbouring tests in `internal/session` already use (`New(...)`, the sink
helper, `WithInsecureTargetHostKey`); copy the exact setup lines from the
nearest existing `dialTarget` test rather than inventing them. Add `errors`
and `strings` to the test file's imports if missing.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestDialTarget -v`
Expected: FAIL — `dialTarget` still returns a client (or a different error); no denial event.

- [ ] **Step 3: Resolve inside `dialTarget`**

In `internal/session/target.go`, replace the opening of `dialTarget`
(`:139-142`):

```go
	targetUser := decision.TargetUser
	if targetUser == "" {
		targetUser = pr.User
	}
```

with:

```go
	// Single authority for the effective target account: rule pin, client
	// request and allow-list resolved in one pure helper, shared with the
	// prompt-mode password prompt in session.go so the account the user is
	// asked to authenticate as is always the account the leg authenticates
	// as. A denial fails closed like every other credential-path failure —
	// internal/policy cannot import internal/credential, so its sentinel is
	// wrapped into credential.ErrDenied here.
	targetUser, tuErr := policy.ResolveTargetUser(pr.RequestedTargetUser, decision, pr.User)
	if tuErr != nil {
		effective := decision.TargetUser
		if effective == "" {
			effective = pr.User
		}
		s.emit(ctx, evidence.Event{
			Time:           time.Now().UTC(),
			Type:           evidence.TypeCredential,
			User:           pr.User,
			SourceIP:       srcIP,
			Target:         net.JoinHostPort(targetHost, strconv.Itoa(targetPort)),
			TargetUser:     effective,
			Allow:          evidence.BoolPtr(false),
			CredentialMode: decision.CredentialMode,
			Outcome:        string(credential.OutcomeDenied),
			Reason:         "target user denied",
			Detail:         fmt.Sprintf("requested=%s effective=%s", pr.RequestedTargetUser, effective),
		})
		return nil, fmt.Errorf("%w: %s", credential.ErrDenied, tuErr)
	}
```

- [ ] **Step 4: Resolve at auth time, before the prompt**

In `internal/session/session.go`, inside the `if hasTarget && s.dialerPeek != nil` block (`:438`), immediately after `decision := s.dialerPeek(...)` — note the peeked principal also carries the request now:

```go
			decision := s.dialerPeek(policy.Principal{User: id.User, Groups: id.Groups, SelectedRole: pcode, TargetPort: targetPort, RequestedTargetUser: requestedTargetUser}, targetHost)
			// Resolve before any prompt is issued. Denying here rather than at
			// channel-open means the gateway never collects a password for an
			// account the client is not allowed to use.
			targetUser, tuErr := policy.ResolveTargetUser(requestedTargetUser, decision, id.User)
			if tuErr != nil {
				s.bfLimiter.RecordFailure(srcIP)
				s.emit(ctx, evidence.Event{
					Time: time.Now().UTC(), Type: evidence.TypeCredential,
					User: id.User, SourceIP: srcIP, Target: targetHost,
					Allow: evidence.BoolPtr(false),
					CredentialMode: decision.CredentialMode,
					Outcome: string(credential.OutcomeDenied),
					Reason:  "target user denied",
					Detail:  fmt.Sprintf("requested=%s", requestedTargetUser),
				})
				return nil, errors.New("authentication failed")
			}
```

Then, in the prompt-mode branch, delete the local default:

```go
						targetUser := decision.TargetUser
						if targetUser == "" {
							targetUser = id.User
						}
```

and use the resolved `targetUser` captured above:

```go
						prompt := fmt.Sprintf("%s@%s password: ", targetUser, targetHost)
```

Update the doc comment above it to say the account is the resolved one — rule
pin, client request or gateway login user — not just "TargetUser defaults to
the gateway login user".

- [ ] **Step 5: Run the full suite, verify pass**

Run: `go test ./internal/session/... ./internal/policy/... ./internal/config/... -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/session/target.go internal/session/session.go internal/session/target_test.go
git commit -m "session: honour an authorized client-supplied target account"
```

---

### Task 6: Count second-leg auth failures toward the brute-force limiter

**Files:**
- Modify: `internal/session/target.go`
- Modify: `internal/session/session.go`
- Test: `internal/session/target_test.go`

**Interfaces:**
- Consumes: the existing `s.bfLimiter` (`ratelimit`), already used at `session.go:364,386,429,436`.
- Produces: `dialTarget` recording a failure for the client's source IP when the target rejects the second-leg authentication.

Rationale: `bfLimiter.RecordSuccess(srcIP)` fires at `session.go:436` as soon
as gateway auth succeeds, and a target-side auth failure is currently counted
nowhere. That is harmless while the account is fixed by policy — there is
nothing to guess. Once a client can name the account, the second leg becomes
an unmetered spray channel behind a valid AD login, with target-side account
lockout as the denial-of-service consequence.

- [ ] **Step 1: Write the failing test**

Add to `internal/session/target_test.go`:

```go
func TestDialTargetRecordsSecondLegFailure(t *testing.T) {
	s := New(WithInsecureTargetHostKey())
	srcIP := "10.9.9.9"
	// Substitute a transport whose handshake always fails, so dialTarget
	// takes its auth-failure path without a real sshd.
	orig := dialNet
	dialNet = func(_ context.Context, _, _ string, _ time.Duration, _ *net.IPNet, _ bool) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	defer func() { dialNet = orig }()

	pr := policy.Principal{User: "alice"}
	d := policy.Decision{Allow: true, CredentialMode: "passthrough"}
	if _, err := s.dialTarget(context.Background(), nil, pr, srcIP, d, "db1.lab.local", 22, ""); err == nil {
		t.Fatal("dialTarget succeeded, want an error")
	}
	if n := s.bfLimiter.Failures(srcIP); n == 0 {
		t.Fatal("second-leg failure was not recorded against the source IP")
	}
}
```

If `ratelimit` exposes no `Failures` accessor, assert instead that
`s.bfLimiter.Allow(srcIP)` eventually returns `false` after repeating the
`dialTarget` call up to the limiter's configured threshold; read the exact
API from `internal/ratelimit` before writing the assertion.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestDialTargetRecordsSecondLegFailure -v`
Expected: FAIL — no failure recorded.

- [ ] **Step 3: Record the failure**

In `internal/session/target.go`, at every `dialTarget` return path that
represents a rejected or failed authentication to the TARGET (the
`ssh.Dial`/`ssh.NewClientConn` error path and the per-mode `fail_closed`
returns), add before the return:

```go
		s.bfLimiter.RecordFailure(srcIP)
```

Do not record on the "no target host-key callback configured" path — that is
an operator misconfiguration, not an attempt, and would let a misconfigured
gateway lock its own users out.

- [ ] **Step 4: Run the suite, verify pass**

Run: `go test ./internal/session/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/session/target.go internal/session/target_test.go
git commit -m "session: count target-side auth failures toward the brute-force limiter"
```

---

### Task 7: Surface the target account on the live-session registry

**Files:**
- Modify: `internal/sessions/registry.go`
- Modify: `internal/session/session.go`
- Test: `internal/sessions/registry_test.go`

**Interfaces:**
- Produces: `sessions.Info.TargetUser string` (json `target_user,omitempty`), populated at `session.go:616`.

- [ ] **Step 1: Write the failing test**

Add to `internal/sessions/registry_test.go`:

```go
func TestRegistryCarriesTargetUser(t *testing.T) {
	r := NewRegistry()
	id, dereg := r.Register(Info{User: "alice", SourceIP: "10.0.0.1", TargetUser: "user01"}, func() error { return nil })
	defer dereg()
	got, ok := r.Get(id)
	if !ok || got.TargetUser != "user01" {
		t.Fatalf("Get(%q) = (%+v, %v), want TargetUser=user01", id, got, ok)
	}
}
```

Use whatever constructor the neighbouring tests in that file use for a
`*Registry`.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/sessions/... -run TestRegistryCarriesTargetUser -v`
Expected: FAIL — `Info` has no field `TargetUser`.

- [ ] **Step 3: Add the field and populate it**

In `internal/sessions/registry.go`, add to `Info`:

```go
	TargetUser string `json:"target_user,omitempty"` // account the session runs as on the target, when it has one
```

In `internal/session/session.go:616`, extend the registration:

```go
		sessID, dereg = s.reg.Register(sessions.Info{User: pr.User, SourceIP: srcIP, TargetUser: pr.RequestedTargetUser}, func() error {
```

If a resolved account is available at that point (the connection has already
dialled a target), prefer it over the requested one; otherwise the requested
value is the only thing known at registration time and is still useful for the
control-plane view. Note in the field's comment which one it holds.

- [ ] **Step 4: Run the suites, verify pass**

Run: `go test ./internal/sessions/... ./internal/session/... ./internal/api/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/sessions/registry.go internal/session/session.go internal/sessions/registry_test.go
git commit -m "sessions: show the target account in the live-session view"
```

---

### Task 8: Documentation and the lab test

**Files:**
- Modify: `README.md:67-77`
- Modify: `deploy/compose/config.example.yaml`
- Modify: `scripts/lab-test-real-target.sh`

**Interfaces:**
- Consumes: everything above. No Go changes.

- [ ] **Step 1: Update the README grammar section**

In `README.md`, replace the "Real shell & SFTP on the target" block's grammar
description and examples with:

````markdown
**🖥️ Real shell & SFTP on the target** — `user%[targetuser@]host` in the SSH username picks a real
target; the gateway opens a genuine second SSH leg and proxies an actual PTY shell or SFTP session
to it. Not a stand-in.
```console
$ ssh 'alice%db1.lab.local'@gateway -p 2222
$ sftp 'alice%db1.lab.local'@gateway -P 2222
```
Add `targetuser@` before the host to name the account to land on:
```console
$ ssh alice%user01@db1.lab.local@gateway -p 2222
```
No quoting is needed there — OpenSSH splits its own `[user@]host` argument on the **last** `@`, so
`gateway` is the host and `alice%user01@db1.lab.local` is sent as the SSH username. The quoted and
`-l` forms work too. A client-supplied account is honoured only when the matching rule lists it in
`allow_target_users` and uses `credential: prompt` or `passthrough`; a rule that pins `target_user`
is not overridable, and `credential: inject` never accepts one. Without `targetuser@` the account is
the rule's `target_user`, or your gateway login name.

The matching policy rule must resolve to exactly one host and one port (ambiguous matches fail
closed, not "pick one"). When a host is reachable through more than one of your roles the match is
ambiguous — add a `+pcode` selector (the policy role name) to choose which role the session runs
under: `ssh 'alice+dba%db1.lab.local'@gateway`.
````

- [ ] **Step 2: Update the example config**

In `deploy/compose/config.example.yaml`, in the comment block above the
real-target demo rule (around `:341-351`), after the `target_user` line add:

```yaml
          # allow_target_users: the exhaustive set of accounts a CLIENT may
          # name via the "user%targetuser@host" auth-username grammar. Absent
          # (the default) refuses any client-supplied account, so a policy
          # written before that grammar keeps its exact behaviour. "*" permits
          # any account. Only valid when target_user is unset and credential is
          # prompt or passthrough — config load fails otherwise rather than
          # silently ignoring the list, because under inject the gateway fetches
          # the secret keyed by the account and a client-named one would turn
          # the gateway into a credential oracle.
          # allow_target_users: ["user01", "user02"]
```

- [ ] **Step 3: Add a lab case for the new form**

In `scripts/lab-test-real-target.sh`, add a test after the existing shell
test that connects with an explicit target account and asserts it is refused
by default, then permitted once the rule allows it. The lab's demo rule pins
`target_user: "svc_db1"`, so the default-deny case needs no config edit:

```bash
# --- Test 5: a client-supplied target account is refused when the rule pins one
echo "== client-supplied target account is refused against a pinned rule =="
if python3 "$WORKDIR/ssh_shell.py" "$GW_PORT" "${GW_USER}%root@${TARGET_HOST}@${TARGET_HOST}" \
    "$GW_PASSWORD" "$TARGET_PASSWORD" >/dev/null 2>"$WORKDIR/ssh_pinned.log"; then
  fail "alice connected as 'root' against a rule pinning svc_db1"
  exit 1
fi
pass "alice%root@... refused: the rule pins target_user svc_db1"

# --- Test 6: the same account the rule pins is accepted when named explicitly
echo "== naming the rule's own account explicitly is accepted =="
if ! python3 "$WORKDIR/ssh_shell.py" "$GW_PORT" "${GW_USER}%${TARGET_USER}@${TARGET_HOST}@${TARGET_HOST}" \
    "$GW_PASSWORD" "$TARGET_PASSWORD" >/dev/null 2>"$WORKDIR/ssh_named.log"; then
  fail "alice could not connect naming the rule's own account (${TARGET_USER})"
  tail -n 40 "$WORKDIR/ssh_named.log" >&2
  exit 1
fi
pass "alice%${TARGET_USER}@... accepted: matches the rule's target_user"
```

Reuse the existing python PTY driver in that script for the shell test rather
than writing a new one — read how the first shell test invokes it and mirror
that call shape, including the `%`-form login string it already builds.

- [ ] **Step 4: Run the lab**

```bash
make lab-up && make lab-seed && make binaries
make lab-test-real-target
make lab-down
```
Expected: every existing PASS line still passes, plus the two new ones.

- [ ] **Step 5: Run the full CI gate**

Run: `make ci`
Expected: build, lint, `scripts/check-imports.sh` (in particular
"internal/policy must not import internal/session") and all tests green.

- [ ] **Step 6: Commit**

```bash
git add README.md deploy/compose/config.example.yaml scripts/lab-test-real-target.sh
git commit -m "docs: document the target-account form of the auth username"
```

---

## Self-Review

**Spec coverage:** grammar and parse order (Task 3), invalid forms (Task 3),
OpenSSH last-`@` behaviour and quoting (Task 8 README), `allow_target_users`
and its validation (Tasks 1-2), the precedence matrix including the inject
denial (Task 1), the error contract and `internal/policy` purity (Task 1,
verified by `make ci` in Task 8), both call sites agreeing (Task 5),
prompt-before-deny ordering (Task 5 Step 4), brute-force accounting (Task 6),
evidence `target_user` and requested-vs-effective on denial (Tasks 4-5),
registry surfacing (Task 7), docs and lab (Task 8). Backward compatibility is
a global constraint and is checked by every task's full-suite run.

**Type consistency:** `ResolveTargetUser(requested string, d Decision, loginUser string) (string, error)` is defined in Task 1 and called with that exact shape in Task 5 (twice). `AllowTargetUsers` is `[]string` on `Rule`, `Decision` and `RuleConfig`. `RequestedTargetUser` is the `Principal` field name in Tasks 1, 3, 5 and 7; `requested_target_user` is the extension key in Task 3. `Event.TargetUser` (Task 4) is used in Task 5. `Info.TargetUser` (Task 7) is distinct from `Event.TargetUser` and both are json `target_user`.

**Follow-up recorded in the spec, not built here:** a per-rule
`target_user`-as-default plus `allow_target_users`-as-alternatives mode, and a
`targetuser#domain` suffix for UPN-style accounts.
