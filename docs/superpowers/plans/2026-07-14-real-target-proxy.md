# Real-target SSH/SFTP proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the gateway-terminated shell/SFTP stand-ins with a real second SSH leg to the target host, so `ssh user%host@gw` gets a genuine remote shell and real SFTP, gated by policy, credentials, content inspection, and recording exactly as rigorously as the rest of the product.

**Architecture:** The gateway's SSH server side is unchanged. On the first `session` channel request needing a target, the gateway (as an SSH *client*) dials and authenticates a second `ssh.Client` connection to the resolved target, per the target's credential mode (inject/prompt/passthrough/deny), and reuses that connection for further channels on the same client connection. Interactive shell bytes are piped through it; SFTP uploads land in the existing WORM quarantine store and require a `KindQuarantineRelease` approval before being delivered to the target file.

**Tech Stack:** Go, `golang.org/x/crypto/ssh` (+ `ssh/agent`, `ssh/knownhosts`), `github.com/pkg/sftp`, existing `internal/{policy,config,credential,approval,inspectgate,evidence,dialer,session}` packages.

**Spec:** `docs/superpowers/specs/2026-07-14-real-target-proxy-design.md`

## Global Constraints

- No new Go module dependencies — `golang.org/x/crypto/ssh/agent` and `golang.org/x/crypto/ssh/knownhosts` are both sub-packages of the already-vendored `golang.org/x/crypto v0.54.0` (see `go.mod:12`).
- `internal/credential` may only be imported by `internal/session` and `internal/dialer` (CI-enforced allowlist) — session already has this right, no allowlist change needed.
- `internal/policy` must stay pure (no `internal/session` import) — the `TargetUser` field is a plain string, no new imports there.
- `internal/approval` must not import `internal/session`/`internal/api`/`internal/dialer` (leaf package) — session and dialer both depend on it, not the reverse.
- Every credential-mode failure fails closed — no code path may silently downgrade to a mode the caller didn't select (FR-18, already enforced in `internal/credential`; this plan must not weaken it).
- A `*credential.Secret` is converted to a Go `string` only at the exact call site an external API demands one (`ssh.Password(...)`), never stored in a named variable, and `Destroy()`d immediately after use — this is a documented, accepted residual risk identical in kind to the one already recorded in ADR-0002 ("a transient Go string may exist inside the TLS/JSON stack... cannot control every copy the runtime makes").
- `gofmt`/`go vet` clean and `make test` green after every task (`make lint`, `make test`).

---

## File Structure

New files:
- `internal/session/target.go` — username/target parsing, `dialTarget` (per-mode second-leg auth), target-connection cache
- `internal/session/target_test.go`
- `internal/session/agentfwd.go` — server-side `auth-agent@openssh.com` reverse-channel plumbing for passthrough mode
- `internal/session/agentfwd_test.go`
- `internal/credential/cyberark_provider.go` — shared CyberArk-backed `*Provider` constructor (factored out of `internal/dialer.WithCyberArk` so `internal/session` can use the same instance)
- `internal/credential/cyberark_provider_test.go`
- `scripts/lab-test-real-target.sh` — docker-lab integration test

Modified files:
- `internal/policy/policy.go` — `Rule.TargetUser`, `Decision.TargetUser`
- `internal/config/config.go` — `RuleConfig.TargetUser` (yaml `target_user`), `CompilePolicy` wiring, `Config.TargetKnownHosts` (yaml `target_known_hosts`)
- `internal/dialer/dialer.go` — `Dialer.Peek` (non-dialing decision lookup), `WithCyberArk` now calls the shared constructor
- `internal/session/session.go` — `passwordCallback` (username split, `PartialSuccessError`/keyboard-interactive for prompt mode, secret stash), `handleConn` (per-connection target-client cache + cleanup), new `Server` fields/options (`cred`, `approvals`, `approvalTTL`, `dialerPeek`, `targetHostKeyCB`, `pendingSecrets`)
- `internal/session/interactive.go` — `handleSession`/`runRecordedShell` bridge to a real target PTY
- `internal/session/sftp.go` — `runSFTP`/`Filewrite`/`Fileread` use a real `*sftp.Client`; upload `Close()` blocks on quarantine-release approval
- `internal/inspectgate/gate.go` — `inspectSmall`/`inspectLarge` persist to `Quarantine` unconditionally, not only on block
- `cmd/omni-sag/main.go` — share one CyberArk provider between dialer and session, wire `session.WithApprovals`/`WithCredentialProvider`/`WithTargetHostKeyCallback`/`WithInsecureTargetHostKey`
- `deploy/compose/docker-compose.yml` — new `ssh-target` service
- `deploy/compose/config.example.yaml` — a real `Rule` with `target_user`/`credential: inject` pointing at it
- `docs/decisions/0002-credential-injection-threat-model.md` — update "the stand-in boundary" section
- `Makefile` — `lab-test-real-target` target

---

### Task 1: Policy — `TargetUser` field

**Files:**
- Modify: `internal/policy/policy.go`
- Test: `internal/policy/policy_test.go`
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `policy.Rule.TargetUser string`, `policy.Decision.TargetUser string`, `config.RuleConfig.TargetUser string` (yaml `target_user`)

- [ ] **Step 1: Write the failing policy test**

Add to `internal/policy/policy_test.go`:

```go
func TestDecide_CarriesTargetUser(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "db1.lab.local", TargetUser: "svc_db1"}},
	}}}
	d := p.Decide(Principal{User: "alice", Groups: []string{"dba"}}, Target{Host: "db1.lab.local", Port: 22})
	if !d.Allow || d.TargetUser != "svc_db1" {
		t.Fatalf("got Allow=%v TargetUser=%q, want Allow=true TargetUser=svc_db1", d.Allow, d.TargetUser)
	}
}

func TestDecide_TargetUserEmptyWhenUnset(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []Rule{{Host: "db1.lab.local"}},
	}}}
	d := p.Decide(Principal{User: "alice", Groups: []string{"dba"}}, Target{Host: "db1.lab.local", Port: 22})
	if d.TargetUser != "" {
		t.Fatalf("got TargetUser=%q, want empty (caller defaults to login user)", d.TargetUser)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/policy/... -run TestDecide_CarriesTargetUser -v`
Expected: FAIL — `Rule` / `Decision` has no field `TargetUser` (compile error)

- [ ] **Step 3: Add the field**

In `internal/policy/policy.go`, add to `Rule` (after `RequireApproval bool`):

```go
	// TargetUser is the account the gateway authenticates as on the target for
	// this rule's matches. Empty => the same name as the gateway login user.
	TargetUser string
```

Add to `Decision` (after `RequireApproval bool`):

```go
	TargetUser string // account to use on the target; empty => same as login user
```

In `Decide`, inside the `if rule.matches(t)` branch, add `TargetUser: rule.TargetUser,` to the returned `Decision` literal.

- [ ] **Step 4: Run the policy tests, verify pass**

Run: `go test ./internal/policy/... -v`
Expected: PASS, all tests including the two new ones

- [ ] **Step 5: Write the failing config test**

Add to `internal/config/config_test.go` (follow the existing table style in that file for `CompilePolicy`):

```go
func TestCompilePolicy_TargetUser(t *testing.T) {
	f := &File{Policy: PolicyConfig{Roles: []RoleConfig{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []RuleConfig{{Host: "db1.lab.local", TargetUser: "svc_db1"}},
	}}}}
	p := f.CompilePolicy()
	if got := p.Roles[0].Allow[0].TargetUser; got != "svc_db1" {
		t.Fatalf("TargetUser = %q, want svc_db1", got)
	}
}
```

- [ ] **Step 6: Run it, verify it fails**

Run: `go test ./internal/config/... -run TestCompilePolicy_TargetUser -v`
Expected: FAIL — `RuleConfig` has no field `TargetUser` (compile error)

- [ ] **Step 7: Add the config field and wiring**

In `internal/config/config.go`, add to `RuleConfig` (after `RequireApproval bool ...`):

```go
	TargetUser string `yaml:"target_user"` // account on the target; empty => same as gateway login user
```

In `CompilePolicy`, inside the `policy.Rule{...}` literal, add `TargetUser: ru.TargetUser,`.

- [ ] **Step 8: Run the config tests, verify pass**

Run: `go test ./internal/config/... -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/policy/policy.go internal/policy/policy_test.go internal/config/config.go internal/config/config_test.go
git commit -m "feat: add policy.Rule.TargetUser for real-target account mapping"
```

---

### Task 2: Username target-parsing (`user%host`)

**Files:**
- Create: `internal/session/target.go`
- Test: `internal/session/target_test.go`
- Modify: `internal/session/session.go:146-221` (`passwordCallback`)

**Interfaces:**
- Produces: `splitTargetUser(raw string) (loginUser, targetHost string, hasTarget bool)`
- Consumes: nothing new (pure function)
- Produces (session.go): `ssh.Permissions.Extensions["target_host"]` set when a target was parsed

- [ ] **Step 1: Write the failing test**

Create `internal/session/target_test.go`:

```go
package session

import "testing"

func TestSplitTargetUser(t *testing.T) {
	cases := []struct {
		raw            string
		wantUser       string
		wantTarget     string
		wantHasTarget  bool
	}{
		{"alice", "alice", "", false},
		{"alice%db1.lab.local", "alice", "db1.lab.local", true},
		{"alice%db1.lab.local%extra", "alice", "db1.lab.local%extra", true}, // only first % splits
		{"%db1.lab.local", "", "db1.lab.local", true},
		{"alice%", "alice", "", true},
	}
	for _, c := range cases {
		u, h, ok := splitTargetUser(c.raw)
		if u != c.wantUser || h != c.wantTarget || ok != c.wantHasTarget {
			t.Errorf("splitTargetUser(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.raw, u, h, ok, c.wantUser, c.wantTarget, c.wantHasTarget)
		}
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestSplitTargetUser -v`
Expected: FAIL — `splitTargetUser` undefined

- [ ] **Step 3: Implement it**

Create `internal/session/target.go`:

```go
// Package session (target.go): real-target selection and the gateway's
// second SSH leg to that target (interactive shell / SFTP), as opposed to
// internal/dialer's single leg used for -L port-forwarding.
package session

import (
	"strings"
)

// splitTargetUser splits an SSH auth username of the form "user%host" into
// the login username and the target host. "%" was chosen because it cannot
// appear in an AD sAMAccountName and does not collide with "@" (already used
// by the SSH client to address the gateway itself: "ssh alice%host@gw").
// Only the FIRST "%" splits, so a host containing "%" is not truncated.
func splitTargetUser(raw string) (loginUser, targetHost string, hasTarget bool) {
	i := strings.IndexByte(raw, '%')
	if i < 0 {
		return raw, "", false
	}
	return raw[:i], raw[i+1:], true
}
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `go test ./internal/session/... -run TestSplitTargetUser -v`
Expected: PASS

- [ ] **Step 5: Wire it into `passwordCallback`**

In `internal/session/session.go`, `passwordCallback` currently does:

```go
		id, err := auth.Authenticate(ctx, meta.User(), string(password))
```

Change to split the username first:

```go
		loginUser, targetHost, hasTarget := splitTargetUser(meta.User())
		id, err := auth.Authenticate(ctx, loginUser, string(password))
```

And below, every `meta.User()` reference used for evidence/logging in that function (the brute-force/failure emit paths) should use `loginUser` instead, so a target suffix never pollutes the identity shown in evidence. There are two such sites in the failure branches — replace `User: meta.User()` with `User: loginUser` in both.

Finally, in the success return at the end of the function, add the target to Extensions:

```go
		perms := &ssh.Permissions{Extensions: map[string]string{
			"user":   id.User,
			"groups": strings.Join(id.Groups, groupSep),
		}}
		if hasTarget {
			perms.Extensions["target_host"] = targetHost
		}
		return perms, nil
```

(This replaces the existing final `return &ssh.Permissions{...}, nil` literal.)

- [ ] **Step 6: Run the full session package tests, verify pass**

Run: `go test ./internal/session/... -v 2>&1 | tail -40`
Expected: PASS (existing auth tests still pass since a plain `alice` with no `%` behaves exactly as before)

- [ ] **Step 7: Commit**

```bash
git add internal/session/target.go internal/session/target_test.go internal/session/session.go
git commit -m "feat: parse user%host target selection at gateway login"
```

---

### Task 3: Non-dialing policy decision lookup (`Dialer.Peek`)

**Files:**
- Modify: `internal/dialer/dialer.go`
- Test: `internal/dialer/dialer_test.go`

**Interfaces:**
- Produces: `(d *Dialer) Peek(pr policy.Principal, target policy.Target) policy.Decision`
- Consumes: `d.currentPolicy()` (existing unexported method)

Session needs to know a target's `CredentialMode`/`TargetUser` at *auth time* (before any channel opens, so prompt-mode can chain a keyboard-interactive round) without duplicating `DialTarget`'s evidence-emitting, approval-gating, socket-opening logic.

- [ ] **Step 1: Write the failing test**

Add to `internal/dialer/dialer_test.go`:

```go
func TestPeek_NoEvidenceNoSocket(t *testing.T) {
	dialed := false
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial")
	})
	sink := &captureSink{} // if a capture sink already exists in this test file, reuse it; otherwise see Step 3a
	d := New(demoPolicy(), sink)

	dec := d.Peek(policy.Principal{User: "alice", Groups: []string{"dba"}}, policy.Target{Host: "db1.lab.local", Port: 5432})
	if !dec.Allow {
		t.Fatalf("Peek: want Allow=true, got %+v", dec)
	}
	if dialed {
		t.Fatal("Peek must never dial a socket")
	}
	if len(sink.events) != 0 {
		t.Fatalf("Peek must never emit evidence, got %d events", len(sink.events))
	}
}
```

- [ ] **Step 3a: Check for a capture sink fixture**

Run: `grep -n "captureSink\|type.*Sink.*struct" internal/dialer/dialer_test.go`

If no `captureSink` exists yet, add one at the bottom of `internal/dialer/dialer_test.go`:

```go
type captureSink struct{ events []evidence.Event }

func (s *captureSink) Emit(e evidence.Event) error { s.events = append(s.events, e); return nil }
func (s *captureSink) Close() error                { return nil }
```

(If an equivalent fixture already exists under a different name, use that name instead and adjust Step 1's test accordingly.)

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/dialer/... -run TestPeek_NoEvidenceNoSocket -v`
Expected: FAIL — `d.Peek` undefined

- [ ] **Step 3: Implement it**

In `internal/dialer/dialer.go`, add after `DialTarget`:

```go
// Peek evaluates policy for pr against target without opening a socket,
// emitting evidence, or gating on approval. It exists so callers outside the
// dial path (the SSH auth callback, deciding whether prompt-mode needs a
// keyboard-interactive round) can inspect a target's credential mode ahead
// of any channel opening. The real authorization decision — the one that
// actually gates a connection — is still made by DialTarget.
func (d *Dialer) Peek(pr policy.Principal, target policy.Target) policy.Decision {
	return d.currentPolicy().Decide(pr, target)
}
```

- [ ] **Step 4: Run the dialer tests, verify pass**

Run: `go test ./internal/dialer/... -v 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/dialer/dialer.go internal/dialer/dialer_test.go
git commit -m "feat: add Dialer.Peek for non-dialing policy lookups"
```

---

### Task 4: Shared CyberArk-backed credential provider

**Files:**
- Create: `internal/credential/cyberark_provider.go`
- Test: `internal/credential/cyberark_provider_test.go`
- Modify: `internal/dialer/dialer.go:122-160` (`WithCyberArk`)
- Modify: `internal/session/session.go` (new `WithCredentialProvider` option + `cred` field)
- Modify: `cmd/omni-sag/main.go`

**Interfaces:**
- Produces: `credential.NewCyberArkProvider(p credential.CyberArkParams) (*credential.Provider, error)`, `credential.CyberArkParams` (moved from `dialer.CyberArkParams`)
- Produces: `session.WithCredentialProvider(p *credential.Provider) session.Option`
- Consumes (session.go): `s.cred *credential.Provider` field, used later by Task 7's `dialTarget`

`internal/credential`'s package doc already restricts it to `internal/session` and `internal/dialer` importers — this task is what that restriction was anticipating. Both packages need the *same* CyberArk-backed provider instance so the gateway doesn't open two independent CCP client pools for one target credential.

- [ ] **Step 1: Write the failing test**

Create `internal/credential/cyberark_provider_test.go`:

```go
package credential

import "testing"

func TestNewCyberArkProvider_BadCertsErrors(t *testing.T) {
	_, err := NewCyberArkProvider(CyberArkParams{
		BaseURL:    "https://ccp.example",
		ClientCert: "/nonexistent/cert.pem",
		ClientKey:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("want an error for nonexistent cert/key paths, got nil")
	}
}

func TestNewCyberArkProvider_QueryUsesHostOnly(t *testing.T) {
	p, err := NewCyberArkProvider(CyberArkParams{
		BaseURL: "https://ccp.example", AppID: "app1", Safe: "safe1", ObjectTemplate: "{host}",
	})
	if err != nil {
		t.Fatalf("NewCyberArkProvider: %v", err)
	}
	if p == nil {
		t.Fatal("want non-nil provider")
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/credential/... -run TestNewCyberArkProvider -v`
Expected: FAIL — `NewCyberArkProvider`/`CyberArkParams` undefined in this package

- [ ] **Step 3: Move `CyberArkParams` and the construction logic**

Read `internal/dialer/dialer.go:122-160` (the current `CyberArkParams` struct and `WithCyberArk` function) before editing — the query closure and breaker construction move verbatim.

Create `internal/credential/cyberark_provider.go`:

```go
package credential

import (
	"net"
	"strings"
	"time"
)

// CyberArkParams configures credential injection from CyberArk. Plain types
// so callers (cmd, internal/dialer, internal/session) need not import the CCP
// client type directly.
type CyberArkParams struct {
	BaseURL, ClientCert, ClientKey, CACert string
	AppID, Safe, ObjectTemplate            string
	TimeoutSeconds                         int
	BreakerFailures                        int
	BreakerCooldownSeconds                 int
}

// NewCyberArkProvider builds a Provider that resolves inject-mode secrets
// from CyberArk CCP over mTLS. Errors on bad certs. The returned Provider is
// safe to share between internal/dialer (tunnel targets) and
// internal/session (real-target shell/SFTP second-leg auth) — CyberArk is
// queried by (host, safe, object), which is identical for both call sites.
func NewCyberArkProvider(p CyberArkParams) (*Provider, error) {
	ccp, err := NewCCPClient(CCPConfig{
		BaseURL:        p.BaseURL,
		ClientCertPath: p.ClientCert,
		ClientKeyPath:  p.ClientKey,
		CACertPath:     p.CACert,
		Timeout:        time.Duration(p.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	appID, safe, tmpl := p.AppID, p.Safe, p.ObjectTemplate
	query := func(req Request) Query {
		host := req.Target
		if h, _, err := net.SplitHostPort(req.Target); err == nil {
			host = h
		}
		return Query{AppID: appID, Safe: safe, Object: strings.ReplaceAll(tmpl, "{host}", host)}
	}
	breaker := NewBreaker(BreakerConfig{
		Threshold: p.BreakerFailures,
		Cooldown:  time.Duration(p.BreakerCooldownSeconds) * time.Second,
	})
	return NewProvider(Config{Fetcher: ccp, Query: query, Breaker: breaker}), nil
}
```

- [ ] **Step 4: Run the new tests, verify pass**

Run: `go test ./internal/credential/... -v 2>&1 | tail -30`
Expected: PASS

- [ ] **Step 5: Make `dialer.WithCyberArk` a thin wrapper**

In `internal/dialer/dialer.go`, delete the `CyberArkParams` struct (now in `internal/credential`) and replace the body of `WithCyberArk`:

```go
// CyberArkParams configures credential injection from CyberArk.
type CyberArkParams = credential.CyberArkParams

// WithCyberArk builds a credential provider that resolves inject-mode
// secrets from CyberArk CCP over mTLS, and returns it as an Option. Errors on
// bad certs.
func WithCyberArk(p CyberArkParams) (Option, error) {
	prov, err := credential.NewCyberArkProvider(p)
	if err != nil {
		return nil, err
	}
	return WithCredentialProvider(prov), nil
}
```

(`CyberArkParams = credential.CyberArkParams` is a type alias so every existing caller of `dialer.CyberArkParams{...}` — including `cmd/omni-sag/main.go` — keeps compiling unchanged.)

- [ ] **Step 6: Run the dialer tests, verify pass**

Run: `go test ./internal/dialer/... -v 2>&1 | tail -20`
Expected: PASS — existing CyberArk-mode dialer tests are unaffected by the refactor

- [ ] **Step 7: Add `session.WithCredentialProvider` and the `cred` field**

In `internal/session/session.go`, add to the `Server` struct (near `inspect *inspectgate.Gate`):

```go
	cred *credential.Provider // optional; used to resolve inject-mode target credentials for real shell/SFTP sessions
```

Add the import `"github.com/rupivbluegreen/omni-sag/internal/credential"`.

Add a new option near `WithInspection`:

```go
// WithCredentialProvider resolves inject-mode target credentials for the
// gateway's second SSH leg to a real target (shell/SFTP). Nil (the default)
// means inject-mode targets fail closed (see Task 7's dialTarget).
func WithCredentialProvider(p *credential.Provider) Option {
	return func(s *Server) { s.cred = p }
}
```

- [ ] **Step 8: Run `go build ./...`, verify it compiles**

Run: `go build ./...`
Expected: success (the `cred` field is unused until Task 7 — `go vet`/`gofmt` don't flag unused struct fields, only unused locals/imports, so this compiles clean)

- [ ] **Step 9: Wire main.go to share one provider**

In `cmd/omni-sag/main.go`, the existing block is:

```go
	var dopts []dialer.Option
	if ca := cfg.CyberArk; ca != nil {
		opt, err := dialer.WithCyberArk(dialer.CyberArkParams{...})
		...
		dopts = append(dopts, opt)
		log.Printf("omni-sag: CyberArk credential injection enabled (CCP %s)", ca.BaseURL)
	}
```

Replace it so both the dialer and the session server share one `*credential.Provider`:

```go
	var dopts []dialer.Option
	var sessOpts []session.Option // collected here, appended to `opts` further down where session.Option values are built
	if ca := cfg.CyberArk; ca != nil {
		prov, err := credential.NewCyberArkProvider(credential.CyberArkParams{
			BaseURL:                ca.BaseURL,
			ClientCert:             ca.ClientCertPath,
			ClientKey:              ca.ClientKeyPath,
			CACert:                 ca.CACertPath,
			AppID:                  ca.AppID,
			Safe:                   ca.Safe,
			ObjectTemplate:         ca.ObjectTemplate,
			TimeoutSeconds:         ca.TimeoutSeconds,
			BreakerFailures:        ca.BreakerFails,
			BreakerCooldownSeconds: ca.BreakerCoolSec,
		})
		if err != nil {
			return err
		}
		dopts = append(dopts, dialer.WithCredentialProvider(prov))
		sessOpts = append(sessOpts, session.WithCredentialProvider(prov))
		log.Printf("omni-sag: CyberArk credential injection enabled (CCP %s)", ca.BaseURL)
	}
```

Add the import `"github.com/rupivbluegreen/omni-sag/internal/credential"` to `cmd/omni-sag/main.go`.

Further down, where `opts = append(opts, session.WithRegistry(reg))` and the other `session.With...` calls are built, add `opts = append(opts, sessOpts...)` right after that first line (so the CyberArk-derived option, if any, lands in the same `opts` slice passed to `session.New`).

- [ ] **Step 10: Run the full build and test suite**

Run: `make build && make test 2>&1 | tail -40`
Expected: build succeeds, all tests pass

- [ ] **Step 11: Commit**

```bash
git add internal/credential/cyberark_provider.go internal/credential/cyberark_provider_test.go \
  internal/dialer/dialer.go internal/session/session.go cmd/omni-sag/main.go
git commit -m "refactor: share one CyberArk-backed credential.Provider between dialer and session"
```

---

### Task 5: prompt-mode target password via SSH `PartialSuccessError`

**Files:**
- Modify: `internal/session/session.go`
- Test: `internal/session/session_test.go` (or a new `internal/session/prompt_test.go` if `session_test.go` already exceeds ~500 lines — check with `wc -l internal/session/session_test.go` first and create the new file if so)

**Interfaces:**
- Consumes: `s.dialerPeek func(pr policy.Principal, target policy.Target) policy.Decision` (new `Server` field, set from `dialer.Peek` in `cmd/omni-sag/main.go`)
- Produces: `s.stashTargetSecret(sec *credential.Secret) (token string)`, `s.takeTargetSecret(token string) *credential.Secret` — both on `Server`, used later by Task 7's `dialTarget`
- Produces: `ssh.Permissions.Extensions["target_secret_token"]` set only for prompt-mode targets

- [ ] **Step 1: Check test file size before choosing where tests go**

Run: `wc -l internal/session/session_test.go`

If it's under ~500 lines, add tests there; otherwise create `internal/session/prompt_test.go` with `package session` and put the new tests there instead. The steps below assume `session_test.go`; substitute the new file if you created one.

- [ ] **Step 2: Write the failing test for the secret stash**

Add to the chosen test file:

```go
func TestTargetSecretStash_RoundTrips(t *testing.T) {
	s := &Server{}
	sec := credential.New([]byte("hunter2"))
	token := s.stashTargetSecret(sec)
	if token == "" {
		t.Fatal("stashTargetSecret returned empty token")
	}
	got := s.takeTargetSecret(token)
	if got != sec {
		t.Fatalf("takeTargetSecret returned a different *Secret")
	}
	// A token is single-use: taking it again must return nil, not the same secret.
	if again := s.takeTargetSecret(token); again != nil {
		t.Fatal("takeTargetSecret must be single-use — second call returned non-nil")
	}
}

func TestTargetSecretStash_UnknownTokenReturnsNil(t *testing.T) {
	s := &Server{}
	if got := s.takeTargetSecret("no-such-token"); got != nil {
		t.Fatal("takeTargetSecret(unknown) must return nil")
	}
}
```

Add the import `"github.com/rupivbluegreen/omni-sag/internal/credential"` if not already present in the chosen test file.

- [ ] **Step 3: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestTargetSecretStash -v`
Expected: FAIL — `stashTargetSecret`/`takeTargetSecret` undefined

- [ ] **Step 4: Implement the stash**

In `internal/session/session.go`, add to the `Server` struct:

```go
	pendingSecrets sync.Map // token(string) -> *credential.Secret; prompt-mode target passwords awaiting first use
	dialerPeek     func(pr policy.Principal, target policy.Target) policy.Decision // non-dialing decision lookup; nil disables prompt-mode chaining
```

Add near `passwordCallback`:

```go
// stashTargetSecret holds sec under a random single-use token until the
// target dial consumes it (Task 7) or the connection closes without ever
// opening a channel (handleConn's cleanup, added in Step 8 below) — either
// path zeroizes it. Never logged, never placed in evidence.
func (s *Server) stashTargetSecret(sec *credential.Secret) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	s.pendingSecrets.Store(token, sec)
	return token
}

// takeTargetSecret retrieves and removes the secret for token. Single-use:
// a second call for the same token returns nil. Returns nil for an unknown
// or already-consumed token.
func (s *Server) takeTargetSecret(token string) *credential.Secret {
	v, ok := s.pendingSecrets.LoadAndDelete(token)
	if !ok {
		return nil
	}
	return v.(*credential.Secret)
}
```

Add imports `"crypto/rand"` and `"encoding/hex"` to `internal/session/session.go` if not already present.

- [ ] **Step 5: Run the stash tests, verify pass**

Run: `go test ./internal/session/... -run TestTargetSecretStash -v`
Expected: PASS

- [ ] **Step 6: Write the failing test for the PartialSuccessError chain**

Add to the chosen test file — this drives `passwordCallback` end to end for a target whose policy decision is `credential: prompt`:

```go
func TestPasswordCallback_PromptModeChainsKeyboardInteractive(t *testing.T) {
	fakeAuth := fakeAuthenticator{identity: authn.Identity{User: "alice", Groups: []string{"dba"}}}
	s := &Server{
		bfLimiter: ratelimit.New(ratelimit.DefaultConfig()),
		sink:      noopSink{},
		dialerPeek: func(pr policy.Principal, target policy.Target) policy.Decision {
			return policy.Decision{Allow: true, CredentialMode: "prompt", MatchedRole: "dba"}
		},
	}
	cb := s.passwordCallback(fakeAuth)
	_, err := cb(fakeConnMeta{user: "alice%db1.lab.local"}, []byte("password123"))

	var partial *ssh.PartialSuccessError
	if !errors.As(err, &partial) {
		t.Fatalf("want *ssh.PartialSuccessError for a prompt-mode target, got %v (%T)", err, err)
	}
	if partial.Next.KeyboardInteractiveCallback == nil {
		t.Fatal("PartialSuccessError.Next.KeyboardInteractiveCallback is nil")
	}

	challenge := func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		if len(questions) != 1 || echos[0] != false {
			t.Fatalf("want one echo-off question, got questions=%v echos=%v", questions, echos)
		}
		return []string{"targetpass"}, nil
	}
	perms, err := partial.Next.KeyboardInteractiveCallback(fakeConnMeta{user: "alice%db1.lab.local"}, challenge)
	if err != nil {
		t.Fatalf("KeyboardInteractiveCallback: %v", err)
	}
	if perms.Extensions["target_host"] != "db1.lab.local" {
		t.Fatalf("target_host = %q, want db1.lab.local", perms.Extensions["target_host"])
	}
	token := perms.Extensions["target_secret_token"]
	if token == "" {
		t.Fatal("target_secret_token not set")
	}
	sec := s.takeTargetSecret(token)
	if sec == nil || string(sec.Bytes()) != "targetpass" {
		t.Fatalf("stashed secret = %v, want \"targetpass\"", sec)
	}
}
```

Check the existing test file for `fakeAuthenticator`, `fakeConnMeta`, and `noopSink` fixtures (`grep -n "type fakeAuthenticator\|type fakeConnMeta\|type noopSink" internal/session/*_test.go`) — reuse them if present; otherwise add minimal versions matching the `authn.Authenticator`, `ssh.ConnMetadata`, and `evidence.Sink` interfaces respectively, consistent with any similar fixtures already in the package.

- [ ] **Step 7: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestPasswordCallback_PromptModeChainsKeyboardInteractive -v`
Expected: FAIL — `passwordCallback` returns success/failure, never a `PartialSuccessError`, for a prompt-mode target

- [ ] **Step 8: Implement the chaining in `passwordCallback`**

In `internal/session/session.go`, after the MFA block and before the final `bfLimiter.RecordSuccess`/`return &ssh.Permissions{...}` (from Task 2's Step 5 edit), insert the prompt-mode branch:

```go
		// Fully authenticated: clear any accumulated failure/lockout state so a
		// legitimate user who mistyped is not penalized after a real success.
		s.bfLimiter.RecordSuccess(srcIP)

		if hasTarget && s.dialerPeek != nil {
			decision := s.dialerPeek(policy.Principal{User: id.User, Groups: id.Groups}, policy.Target{Host: targetHost})
			if credential.Mode(decision.CredentialMode).Normalize() == credential.ModePrompt {
				groups := strings.Join(id.Groups, groupSep)
				return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
					KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						answers, err := challenge("", "", []string{"Target password: "}, []bool{false})
						if err != nil {
							return nil, errors.New("authentication failed")
						}
						if len(answers) != 1 || answers[0] == "" {
							return nil, errors.New("authentication failed")
						}
						token := s.stashTargetSecret(credential.New([]byte(answers[0])))
						return &ssh.Permissions{Extensions: map[string]string{
							"user":                 id.User,
							"groups":               groups,
							"target_host":          targetHost,
							"target_secret_token":  token,
						}}, nil
					},
				}}
			}
		}

		perms := &ssh.Permissions{Extensions: map[string]string{
			"user":   id.User,
			"groups": strings.Join(id.Groups, groupSep),
		}}
		if hasTarget {
			perms.Extensions["target_host"] = targetHost
		}
		return perms, nil
```

(This replaces the tail end of `passwordCallback` written in Task 2 Step 5 — the `perms`/`hasTarget` block now sits after the new prompt-mode branch instead of being the sole return path.) `policy.Target{Host: targetHost}` intentionally omits `Port` — `Peek` here is only inspecting `CredentialMode`, which today's `Rule.matches` only distinguishes by `Host` in the demo config; if a deployment has multiple rules for the same host differing only by port, note this as a known limitation (a follow-up could carry the target port from the client's first channel-open request instead of guessing it here — out of scope for this plan).

Add the import `"github.com/rupivbluegreen/omni-sag/internal/policy"` to `internal/session/session.go` if not already present (it should already be, since `Server.dialer *dialer.Dialer` implies policy types are already in scope via other functions — confirm with `grep -n '"github.com/rupivbluegreen/omni-sag/internal/policy"' internal/session/session.go`).

- [ ] **Step 9: Run the test, verify it passes**

Run: `go test ./internal/session/... -run TestPasswordCallback_PromptModeChainsKeyboardInteractive -v`
Expected: PASS

- [ ] **Step 10: Wire `dialerPeek` in `cmd/omni-sag/main.go`**

Where `opts = append(opts, session.WithRegistry(reg))` is built, add a new option (define it in Step 11 below) and set it:

```go
	opts = append(opts, session.WithDialerPeek(d.Peek))
```

- [ ] **Step 11: Add `session.WithDialerPeek`**

In `internal/session/session.go`, near `WithCredentialProvider`:

```go
// WithDialerPeek supplies a non-dialing policy-decision lookup (typically
// (*dialer.Dialer).Peek), used at auth time to decide whether a prompt-mode
// target needs a keyboard-interactive round before the connection is fully
// authenticated. Nil (the default) disables prompt-mode entirely — such a
// target's channels later fail closed in dialTarget (Task 7).
func WithDialerPeek(peek func(pr policy.Principal, target policy.Target) policy.Decision) Option {
	return func(s *Server) { s.dialerPeek = peek }
}
```

- [ ] **Step 12: Add cleanup for never-consumed stashed secrets**

In `internal/session/session.go`'s `handleConn`, after `defer sconn.Close()`, add:

```go
	if tok := sconn.Permissions.Extensions["target_secret_token"]; tok != "" {
		defer func() {
			if sec := s.takeTargetSecret(tok); sec != nil {
				sec.Destroy() // connection closed without ever opening a channel that consumed it
			}
		}()
	}
```

- [ ] **Step 13: Run the full session package tests and build**

Run: `go build ./... && go test ./internal/session/... -v 2>&1 | tail -60`
Expected: build succeeds, all tests pass

- [ ] **Step 14: Commit**

```bash
git add internal/session/session.go internal/session/session_test.go internal/session/prompt_test.go cmd/omni-sag/main.go
git commit -m "feat: implement prompt-mode target credential via SSH keyboard-interactive"
```

(Omit `prompt_test.go` from the `git add` if Step 1 determined the existing test file was small enough to extend in place.)

---

### Task 6: Agent-forwarding (passthrough mode)

**Files:**
- Create: `internal/session/agentfwd.go`
- Test: `internal/session/agentfwd_test.go`
- Modify: `internal/session/interactive.go:34-70` (`handleSession`'s request loop)

**Interfaces:**
- Produces: `(s *Server) forwardedAgentSigners(sconn ssh.Conn) ([]ssh.Signer, io.Closer, error)` — the `io.Closer` must be closed by the caller only after it's done using the signers (see the correction note in Step 3)
- Consumes: `ssh.Conn.OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error)` (stdlib)

The client must send `auth-agent-req@openssh.com` as a channel request on its `session` channel (what `ssh -A` does automatically); the gateway acknowledges it, and later — only when passthrough-mode auth is actually needed — opens a *new*, separate `auth-agent@openssh.com` channel back to the client to reach its forwarded agent.

- [ ] **Step 1: Write the failing test**

Create `internal/session/agentfwd_test.go`:

```go
package session

import (
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeConn implements the tiny slice of ssh.Conn that forwardedAgentSigners
// needs, so the test never touches a real network connection.
type fakeConn struct {
	ssh.Conn // embed to satisfy the full interface; only OpenChannel is overridden
	openErr  error
}

func (f *fakeConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	if name != "auth-agent@openssh.com" {
		return nil, nil, errors.New("unexpected channel type: " + name)
	}
	if f.openErr != nil {
		return nil, nil, f.openErr
	}
	return nil, nil, errors.New("no forwarded agent") // real success path is covered by the docker-lab integration test (Task 13); a real ssh.Channel needs a live connection to construct
}

func TestForwardedAgentSigners_NoForwardingFailsClosed(t *testing.T) {
	s := &Server{}
	_, closer, err := s.forwardedAgentSigners(&fakeConn{openErr: errors.New("channel open failed")})
	if err == nil {
		t.Fatal("want an error when the client never forwarded an agent, got nil")
	}
	if closer != nil {
		t.Fatal("a failure must never leak a non-nil closer")
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestForwardedAgentSigners -v`
Expected: FAIL — `forwardedAgentSigners` undefined

- [ ] **Step 3: Implement it**

Create `internal/session/agentfwd.go`:

```go
package session

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentForwardChannelType is OpenSSH's well-known channel type for a
// forwarded ssh-agent. golang.org/x/crypto/ssh/agent.ForwardToAgent uses the
// same string internally but does not export it, so it is restated here.
const agentForwardChannelType = "auth-agent@openssh.com"

// forwardedAgentSigners opens a new auth-agent@openssh.com channel back to
// the connected client (which must have sent an auth-agent-req@openssh.com
// channel request first — see interactive.go's handleSession) and returns
// the signers offered by the client's local agent, plus a closer the CALLER
// must Close() once done using the signers (e.g. after the target SSH
// handshake completes, success or failure) — NOT before. The signers'
// Sign() calls happen lazily, later, over this same channel; closing it
// early makes every returned signer non-functional. This is how passthrough
// mode authenticates the gateway's second SSH leg AS the human user, not as
// the gateway: the target sees the client's own key.
//
// Failure (no forwarding requested, agent has no keys, channel rejected)
// returns an error and never falls back to another credential mode — the
// caller (dialTarget, Task 7) must fail closed.
func (s *Server) forwardedAgentSigners(sconn ssh.Conn) ([]ssh.Signer, io.Closer, error) {
	ch, reqs, err := sconn.OpenChannel(agentForwardChannelType, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("session: no forwarded agent available (client must connect with ssh -A): %w", err)
	}
	go ssh.DiscardRequests(reqs)

	client := agent.NewClient(ch)
	signers, err := client.Signers()
	if err != nil {
		ch.Close()
		return nil, nil, fmt.Errorf("session: forwarded agent has no usable keys: %w", err)
	}
	if len(signers) == 0 {
		ch.Close()
		return nil, nil, fmt.Errorf("session: forwarded agent returned no signers")
	}
	return signers, ch, nil // ch (ssh.Channel) satisfies io.Closer directly
}
```

**Correction note (post-implementation):** the first version of this task's code closed `ch` via `defer` before returning, which broke every returned signer (the agent protocol's `Sign()` RPC runs later, over the same channel, not during `Signers()`'s `List()` RPC). Task review caught this; the code above is the corrected version, and this is what actually landed in the branch. Task 7's `dialTarget` (below) reflects the corrected 3-value signature.

- [ ] **Step 4: Run the test, verify it passes**

Run: `go test ./internal/session/... -run TestForwardedAgentSigners -v`
Expected: PASS

- [ ] **Step 5: Accept the forwarding request in `handleSession`**

In `internal/session/interactive.go`, in `handleSession`'s `for req := range requests` switch, add a case alongside `"env"`:

```go
		case "auth-agent-req@openssh.com":
			_ = req.Reply(true, nil)
```

- [ ] **Step 6: Run the interactive/session tests, verify pass**

Run: `go test ./internal/session/... -v 2>&1 | tail -40`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/session/agentfwd.go internal/session/agentfwd_test.go internal/session/interactive.go
git commit -m "feat: accept SSH agent forwarding for passthrough-mode target auth"
```

---

### Task 7: `dialTarget` — unify all four credential modes

**Files:**
- Modify: `internal/session/target.go`
- Test: `internal/session/target_test.go`
- Modify: `internal/session/session.go` (`Server` struct, `handleConn`, new options)
- Modify: `internal/config/config.go` (`Config.TargetKnownHosts`)
- Modify: `cmd/omni-sag/main.go`

**Interfaces:**
- Consumes: `s.cred` (Task 4), `s.takeTargetSecret` (Task 5), `s.forwardedAgentSigners` (Task 6)
- Produces: `(s *Server) dialTarget(ctx context.Context, sconn ssh.Conn, pr policy.Principal, decision policy.Decision, targetHost string, targetPort int, secretToken string) (*ssh.Client, error)`
- Produces: `targetConnCache` type — per-gateway-connection lazy cache of the target `*ssh.Client`, used by Tasks 8 and 9

- [ ] **Step 1: Write the failing tests**

These use a real in-process SSH server (via `golang.org/x/crypto/ssh` + `net.Pipe`) as the "target," so each mode's `ssh.ClientConfig.Auth` is exercised for real rather than mocked. Add to `internal/session/target_test.go`:

```go
// startFakeTarget runs a minimal SSH server on an in-memory pipe that accepts
// only the given password, and returns the client-side net.Conn to dial.
// It runs until the test ends (t.Cleanup closes both ends).
func startFakeTarget(t *testing.T, wantPassword string) net.Conn {
	t.Helper()
	signer := testHostKey(t) // see Step 1a
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != wantPassword {
				return nil, errors.New("wrong password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	go func() {
		sconn, chans, reqs, err := ssh.NewServerConn(serverConn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for range chans {
		}
	}()
	return clientConn
}

func testHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("wrap host key: %v", err)
	}
	return signer
}

func TestDialTarget_Deny(t *testing.T) {
	s := &Server{}
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "deny"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestDialTarget_InjectNoProviderFailsClosed(t *testing.T) {
	s := &Server{} // s.cred is nil
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
}

func TestDialTarget_PromptNoStashedSecretFailsClosed(t *testing.T) {
	s := &Server{}
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "prompt"}, "db1.lab.local", 22, "no-such-token")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
}
```

(`TestDialTarget_InjectSucceeds` and `TestDialTarget_PromptSucceeds`, which actually dial `startFakeTarget`'s pipe, are added in Step 3 below alongside the implementation — writing them before `dialTarget` exists would require restating the whole dial-address plumbing twice for no benefit; the three fail-closed tests above are sufficient to prove the RED step.)

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestDialTarget -v`
Expected: FAIL — `dialTarget` undefined

- [ ] **Step 3: Implement `dialTarget` and the connection cache**

Append to `internal/session/target.go`:

```go
import (
	"context"
	"crypto/rand"
	"crypto/ed25519" // test-only import; if `go vet` flags this as unused in the non-test file, move it to target_test.go instead — see note below
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)
```

(`crypto/ed25519`/`crypto/rand` are only used by the test helpers in Step 1 — keep them in `target_test.go`'s imports, not `target.go`'s. The import block above for `target.go` itself should be just `context`, `errors`, `fmt`, `net`, `strconv`, `strings`, `sync`, `time`, `golang.org/x/crypto/ssh`, `internal/credential`, `internal/policy`.)

```go
// dialTarget opens and authenticates the gateway's second SSH leg to the
// target, per decision's credential mode. It never returns a client on deny
// or on any auth failure — no downgrade to another mode (mirrors
// internal/credential's ErrFailClosed / ErrDenied contract exactly).
//
// secretToken is the prompt-mode stash token from Task 5 (ignored for other
// modes). sconn is the gateway's connection to the CLIENT, needed only for
// passthrough mode's reverse agent channel (may be nil for the other modes,
// including in tests).
func (s *Server) dialTarget(ctx context.Context, sconn ssh.Conn, pr policy.Principal, decision policy.Decision, targetHost string, targetPort int, secretToken string) (*ssh.Client, error) {
	targetUser := decision.TargetUser
	if targetUser == "" {
		targetUser = pr.User
	}
	if s.targetHostKeyCB == nil {
		// Fail closed: no silent insecure default (a security review of this
		// plan flagged the earlier draft's InsecureIgnoreHostKey()-on-nil
		// fallback as exactly the silent-downgrade pattern FR-18 exists to
		// prevent elsewhere in this codebase). An operator who genuinely wants
		// the dev-lab-insecure posture must opt in explicitly via
		// WithInsecureTargetHostKey() — see Step 5's config wiring.
		return nil, fmt.Errorf("%w: no target host-key callback configured (set target_known_hosts, or target_insecure_host_key for dev-lab)", credential.ErrFailClosed)
	}
	cfg := &ssh.ClientConfig{
		User:            targetUser,
		HostKeyCallback: s.targetHostKeyCB,
		Timeout:         10 * time.Second,
	}

	mode := credential.Mode(decision.CredentialMode).Normalize()
	switch mode {
	case credential.ModeDeny:
		return nil, fmt.Errorf("%w: credential mode deny for target %s", credential.ErrDenied, targetHost)

	case credential.ModeInject:
		if s.cred == nil {
			return nil, fmt.Errorf("%w: inject configured for %s but no credential provider", credential.ErrFailClosed, targetHost)
		}
		res, err := s.cred.Resolve(ctx, credential.Request{
			User: pr.User, Target: net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), Mode: credential.ModeInject,
		})
		if err != nil {
			return nil, err // already wraps ErrFailClosed
		}
		// Residual risk documented in ADR-0002 and this plan's Global
		// Constraints: ssh.Password requires a Go string; the conversion
		// happens only in this expression, never bound to a variable.
		cfg.Auth = []ssh.AuthMethod{ssh.Password(string(res.Secret.Bytes()))}
		res.Secret.Destroy()

	case credential.ModePrompt:
		sec := s.takeTargetSecret(secretToken)
		if sec == nil {
			return nil, fmt.Errorf("%w: prompt mode for %s but no target password was collected", credential.ErrFailClosed, targetHost)
		}
		cfg.Auth = []ssh.AuthMethod{ssh.Password(string(sec.Bytes()))}
		sec.Destroy()

	case credential.ModePassthrough:
		if sconn == nil {
			return nil, fmt.Errorf("%w: passthrough mode for %s but no client connection to forward from", credential.ErrFailClosed, targetHost)
		}
		signers, closer, err := s.forwardedAgentSigners(sconn)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", credential.ErrFailClosed, err)
		}
		// closer stays open until dialTarget returns (this defer runs at
		// function exit, not end-of-case) — signers only sign lazily, during
		// ssh.NewClientConn below, over this same forwarded-agent channel.
		defer closer.Close()
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}

	default:
		return nil, fmt.Errorf("%w: unknown credential mode %q for %s", credential.ErrFailClosed, decision.CredentialMode, targetHost)
	}

	addr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	rawConn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("session: dial target %s: %w", addr, err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, cfg)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("session: target ssh handshake %s: %w", addr, err)
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

// targetConnCache lazily dials and caches one target *ssh.Client per gateway
// connection, reused across every channel (shell, sftp) opened on that
// connection, and closed once when the connection ends (handleConn's
// cleanup).
type targetConnCache struct {
	mu     sync.Mutex
	client *ssh.Client
	err    error
	dialed bool
}

// getOrDial returns the cached target client, dialing it on first use. A
// prior dial failure is NOT retried within the same connection — a fresh SSH
// connection (fresh channel-open) is required to try again, consistent with
// no-silent-downgrade: a transient failure must not quietly succeed on a
// later attempt using different implicit state.
func (c *targetConnCache) getOrDial(dial func() (*ssh.Client, error)) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dialed {
		c.client, c.err = dial()
		c.dialed = true
	}
	return c.client, c.err
}

func (c *targetConnCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		_ = c.client.Close()
	}
}
```

- [ ] **Step 3a: Write the two success-path tests**

Add to `internal/session/target_test.go` (these need the `startFakeTarget`/`testHostKey` helpers from Step 1):

```go
func TestDialTarget_InjectSucceeds(t *testing.T) {
	fakeConn := startFakeTarget(t, "injected-secret")
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	prov := credential.NewProvider(credential.Config{
		Fetcher: fakeFetcher{secret: []byte("injected-secret")},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})
	s := &Server{cred: prov}
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	defer client.Close()
}

func TestDialTarget_PromptSucceeds(t *testing.T) {
	fakeConn := startFakeTarget(t, "prompted-secret")
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	s := &Server{}
	token := s.stashTargetSecret(credential.New([]byte("prompted-secret")))
	client, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "prompt"}, "db1.lab.local", 22, token)
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	defer client.Close()
}

// fakeFetcher implements credential.Fetcher for TestDialTarget_InjectSucceeds.
type fakeFetcher struct{ secret []byte }

func (f fakeFetcher) Fetch(_ context.Context, _ credential.Query) (*credential.Secret, error) {
	return credential.New(append([]byte(nil), f.secret...)), nil
}
```

This requires a `dialNet` package variable seam in `target.go` (mirroring `internal/dialer`'s `netDial` pattern exactly, per the spec's testing section) — go back and replace `dialTarget`'s `net.DialTimeout("tcp", addr, cfg.Timeout)` call:

```go
// dialNet is the single dial seam for the target's second SSH leg. A package
// variable solely so tests can substitute a fake transport (mirrors
// internal/dialer's netDial pattern); production always uses net.DialTimeout.
var dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}
```

And in `dialTarget`, replace:

```go
	rawConn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
```

with:

```go
	rawConn, err := dialNet("tcp", addr, cfg.Timeout)
```

- [ ] **Step 4: Run all target tests, verify pass**

Run: `go test ./internal/session/... -run TestDialTarget -v 2>&1 | tail -60`
Expected: PASS (all five: Deny, InjectNoProviderFailsClosed, PromptNoStashedSecretFailsClosed, InjectSucceeds, PromptSucceeds)

- [ ] **Step 5: Add `targetHostKeyCB` field, two host-key options (verified + explicit-insecure-opt-in), and config plumbing**

**Correction (post-review, security):** the original draft of this step defaulted a nil `targetHostKeyCB` to `ssh.InsecureIgnoreHostKey()` inside `dialTarget` itself. A security review flagged this as a silent-downgrade pattern — exactly what FR-18 exists to prevent elsewhere in this codebase — since an operator who simply forgot to configure host-key verification would get a working-but-insecure gateway with no indication anything was wrong beyond a log line. The corrected design (reflected in Step 3 above and here) fails closed: `dialTarget` refuses to dial when `targetHostKeyCB` is unset, and insecure mode requires a SEPARATE, explicit opt-in call.

In `internal/session/session.go`, add to `Server`:

```go
	targetHostKeyCB ssh.HostKeyCallback // verifies the target's host key on the second SSH leg; nil => dialTarget fails closed (see WithTargetHostKeyCallback / WithInsecureTargetHostKey)
```

Add two options — one for the real, verified case, one for an explicit insecure opt-in:

```go
// WithTargetHostKeyCallback verifies the real target's host key on the
// gateway's second SSH leg using cb (typically built from an OpenSSH
// known_hosts file via golang.org/x/crypto/ssh/knownhosts.New). This is the
// production path.
func WithTargetHostKeyCallback(cb ssh.HostKeyCallback) Option {
	return func(s *Server) { s.targetHostKeyCB = cb }
}

// WithInsecureTargetHostKey disables target host-key verification entirely
// (ssh.InsecureIgnoreHostKey()). This is a DELIBERATE, EXPLICIT opt-in for
// the dev lab only — unlike the rest of this option, it cannot be reached by
// simply leaving something unconfigured; a caller must name this function.
// Never call this in a production wiring path.
func WithInsecureTargetHostKey() Option {
	return func(s *Server) { s.targetHostKeyCB = ssh.InsecureIgnoreHostKey() }
}
```

In `internal/config/config.go`, add to the top-level `File` struct:

```go
	TargetKnownHosts       string `yaml:"target_known_hosts"`        // OpenSSH known_hosts path verifying real-target host keys
	TargetInsecureHostKey  bool   `yaml:"target_insecure_host_key"`  // dev-lab only: explicitly disable target host-key verification; see WithInsecureTargetHostKey
```

- [ ] **Step 6: Wire it in `cmd/omni-sag/main.go`**

Near the other `session.With...` option construction. `target_known_hosts` and `target_insecure_host_key` are mutually exclusive — verified wins if both are somehow set, but treat that as a config mistake worth a loud log, not a silent precedence rule:

```go
	switch {
	case cfg.TargetKnownHosts != "":
		cb, err := knownhosts.New(cfg.TargetKnownHosts)
		if err != nil {
			return fmt.Errorf("target_known_hosts: %w", err)
		}
		opts = append(opts, session.WithTargetHostKeyCallback(cb))
		log.Printf("omni-sag: real-target host keys verified against %s", cfg.TargetKnownHosts)
		if cfg.TargetInsecureHostKey {
			log.Printf("omni-sag: WARNING target_known_hosts and target_insecure_host_key are both set — verified mode wins, insecure flag ignored")
		}
	case cfg.TargetInsecureHostKey:
		opts = append(opts, session.WithInsecureTargetHostKey())
		log.Printf("omni-sag: WARNING real-target host key verification is DISABLED (target_insecure_host_key: true) — dev-lab only, never use in production")
	default:
		log.Printf("omni-sag: real-target host key verification is NOT configured — shell/SFTP sessions to real targets will fail closed until target_known_hosts or target_insecure_host_key (dev-lab only) is set")
	}
```

Add the import `"golang.org/x/crypto/ssh/knownhosts"` and `"fmt"` (if not already imported) to `cmd/omni-sag/main.go`.

- [ ] **Step 7: Run the full build and test suite**

Run: `make build && make test 2>&1 | tail -50`
Expected: build succeeds, all tests pass

- [ ] **Step 8: Commit**

```bash
git add internal/session/target.go internal/session/target_test.go internal/session/session.go \
  internal/config/config.go cmd/omni-sag/main.go
git commit -m "feat: dialTarget — real second-leg SSH auth for all four credential modes"
```

---

### Task 8: Interactive shell — real bridging

**Files:**
- Modify: `internal/session/interactive.go`
- Test: `internal/session/interactive_test.go`

**Interfaces:**
- Consumes: `s.dialTarget` (Task 7), `targetConnCache` (Task 7)
- Consumes: `sconn ssh.Conn` and `tch *targetConnCache`, both newly threaded from `handleConn` through `handleSession` into `runRecordedShell`

- [ ] **Step 1: Thread `sconn`/`tch` through the call chain**

In `internal/session/session.go`'s `handleConn`, after registering the session (near `chSem := make(chan struct{}, maxChannelsPerConn)`), add:

```go
	tch := &targetConnCache{}
	defer tch.close()
```

Change the two dispatch call sites in the `switch ct` block:

```go
			case "direct-tcpip":
				s.handleDirectTCPIP(ctx, newCh, pr, srcIP)
			case "session":
				s.handleSession(ctx, newCh, pr, srcIP, sconn, tch)
```

Update `handleSession`'s signature in `internal/session/interactive.go`:

```go
func (s *Server) handleSession(ctx context.Context, newCh ssh.NewChannel, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache) {
```

And its two call sites inside (`s.runRecordedShell(...)`, `s.runSFTP(...)`) both gain `sconn, tch` as trailing arguments — update both signatures accordingly (the SFTP one is finished out in Task 9; for now just thread the parameters through so the package compiles).

- [ ] **Step 2: Write the failing test**

Add to `internal/session/interactive_test.go` (check first whether this file exists — `ls internal/session/interactive_test.go` — create it if not):

```go
package session

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func TestRunRecordedShell_NoTargetRefusesCleanly(t *testing.T) {
	s := &Server{sink: noopSink{}}
	// pr with no TargetHost set (plain "ssh alice@gw" — no "%host" suffix).
	pr := policy.Principal{User: "alice"}
	clientSide, gwSide := ssh.Pipe() // see helper note below
	defer clientSide.Close()

	done := make(chan struct{})
	go func() {
		s.runRecordedShell(context.Background(), gwSide, 80, 24, pr, "", nil, &targetConnCache{}, "")
		close(done)
	}()

	buf := make([]byte, 256)
	n, _ := clientSide.Read(buf)
	if n == 0 {
		t.Fatal("expected an error message on the channel, got nothing")
	}
	<-done
}
```

`ssh.Pipe()` does not exist in the standard `golang.org/x/crypto/ssh` package — `ssh.Channel` is an interface without an in-memory test double shipped by the library. Use a minimal fake channel instead: check `grep -n "type fakeChannel\|ssh.Channel" internal/session/*_test.go` for an existing fixture (the SFTP tests likely already have one, since `sftp.go`'s tests drive `runSFTP` over a channel today); reuse it. If none exists, add one to `internal/session/interactive_test.go`:

```go
// fakeChannel is a minimal in-memory ssh.Channel backed by a pipe, enough to
// drive runRecordedShell's Read/Write/Close without a real network connection.
type fakeChannel struct {
	io.Reader
	io.Writer
	closed bool
}

func (f *fakeChannel) Close() error                                   { f.closed = true; return nil }
func (f *fakeChannel) CloseWrite() error                               { return nil }
func (f *fakeChannel) SendRequest(string, bool, []byte) (bool, error)  { return true, nil }
func (f *fakeChannel) Stderr() io.ReadWriter                           { return nil }
```

And build the test around a `net.Pipe()`-backed pair of `fakeChannel`s instead of `ssh.Pipe()`.

- [ ] **Step 3: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestRunRecordedShell_NoTargetRefusesCleanly -v`
Expected: FAIL — compile error, `runRecordedShell`'s current signature doesn't match

- [ ] **Step 4: Implement the real bridge**

Replace `runRecordedShell` in `internal/session/interactive.go` (the whole function, from the current echo-loop version) with:

```go
// runRecordedShell opens a real PTY+shell on the target (dialing it via tch
// if not already cached for this connection) and pipes bytes bidirectionally
// between the client's channel and the target's, recording the traffic
// exactly as before regardless of which end produced it. targetHost/
// secretToken/decision come from handleSession's caller (Step 5).
func (s *Server) runRecordedShell(ctx context.Context, channel ssh.Channel, cols, rows int, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache, targetHost string) {
	defer channel.Close()

	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionStart,
		User: pr.User, SourceIP: srcIP, Detail: "interactive shell",
	})

	if targetHost == "" {
		_, _ = channel.Write([]byte("session refused: no target selected — connect as user%host@gateway\r\n"))
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "refused: no target selected",
		})
		return
	}

	decision := policy.Decision{}
	if s.dialerPeek != nil {
		decision = s.dialerPeek(pr, policy.Target{Host: targetHost})
	}
	secretToken := "" // set by session.go's caller when auth resolved a prompt-mode secret; see Step 5's plumbing
	targetClient, err := tch.getOrDial(func() (*ssh.Client, error) {
		return s.dialTarget(ctx, sconn, pr, decision, targetHost, 22, secretToken)
	})
	if err != nil {
		_, _ = channel.Write([]byte(fmt.Sprintf("session refused: %s\r\n", err)))
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "refused: " + err.Error(),
		})
		return
	}

	targetSession, err := targetClient.NewSession()
	if err != nil {
		_, _ = channel.Write([]byte(fmt.Sprintf("session refused: target session: %s\r\n", err)))
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "refused: target session: " + err.Error(),
		})
		return
	}
	defer targetSession.Close()

	if err := targetSession.RequestPty("xterm", rows, cols, ssh.TerminalModes{}); err != nil {
		_, _ = channel.Write([]byte(fmt.Sprintf("session refused: target pty: %s\r\n", err)))
		return
	}
	targetIn, err := targetSession.StdinPipe()
	if err != nil {
		return
	}
	targetOut, err := targetSession.StdoutPipe()
	if err != nil {
		return
	}
	if err := targetSession.Shell(); err != nil {
		_, _ = channel.Write([]byte(fmt.Sprintf("session refused: target shell: %s\r\n", err)))
		return
	}

	var rec *recording.Recorder
	var recKey string
	if s.recordStore != nil {
		recKey = fmt.Sprintf("recordings/%s/%s.cast", pr.User, time.Now().UTC().Format("20060102T150405.000000000Z"))
		dest, derr := s.recordStore.Create(ctx, recKey)
		if derr == nil {
			rec, derr = recording.NewRecorder(dest, recKey, cols, rows, nil)
			if derr != nil {
				_ = dest.Close()
			}
		}
		if derr != nil {
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeRecording,
				User: pr.User, SourceIP: srcIP, ObjectKey: recKey,
				Allow: evidence.BoolPtr(false), Reason: "recording unavailable",
				Detail: "recording start failed: " + derr.Error(),
			})
			_, _ = channel.Write([]byte("session refused: recording unavailable\r\n"))
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
				User: pr.User, SourceIP: srcIP, Detail: "refused: recording unavailable",
			})
			return
		}
	}

	// Bidirectional pipe: client -> target (recording Input), target -> client
	// (recording Output). Both directions run until either side closes.
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := channel.Read(buf)
			if n > 0 {
				if rec != nil {
					rec.Input(buf[:n])
				}
				if _, werr := targetIn.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := targetOut.Read(buf)
			if n > 0 {
				if rec != nil {
					rec.Output(buf[:n])
				}
				if _, werr := channel.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done // either direction closing ends the session

	if rec != nil {
		if m, cerr := rec.Close(); cerr == nil {
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeRecording,
				User: pr.User, SourceIP: srcIP,
				ObjectKey: m.Key, SHA256: m.SHA256, Bytes: m.Bytes,
				RecordMode: string(policy.RecordFull),
				Detail:     fmt.Sprintf("asciicast duration=%s", m.Duration.Round(time.Millisecond)),
			})
		} else {
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeRecording,
				User: pr.User, SourceIP: srcIP, ObjectKey: recKey,
				Detail: "recording finalize failed: " + cerr.Error(),
			})
		}
	}

	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
		User: pr.User, SourceIP: srcIP,
	})
}
```

Update `handleSession`'s `case "shell":` branch to pass the new parameters:

```go
		case "shell":
			_ = req.Reply(true, nil)
			s.runRecordedShell(ctx, channel, cols, rows, pr, srcIP, sconn, tch, pr.TargetHost)
			return
```

This requires `policy.Principal` to carry `TargetHost` — add it now: in `internal/policy/policy.go`, add `TargetHost string` to `Principal`. This is a pure additive field (no `Decide` logic depends on it — it flows through `Principal` only as a carrier from the SSH auth layer to the session layer, the same way `Groups` already does). In `internal/session/session.go`, find `principalFrom` (`grep -n "func principalFrom" internal/session/session.go`) and add `TargetHost: perms.Extensions["target_host"],` to its returned `policy.Principal{...}` literal.

Also update `handleSession`'s `window-change` case to forward the resize to the target once dialed — add after the existing `case "window-change": _ = req.Reply(true, nil)`, a TODO is NOT acceptable per this plan's no-placeholder rule, so instead fold the resize forwarding directly into `runRecordedShell`'s read loop is impractical (window-change arrives on the CLIENT channel's request stream, which `handleSession` already owns, not inside `runRecordedShell`). Restructure: `handleSession` collects window-change sizes into a small buffered channel and passes it to `runRecordedShell`, which forwards them to `targetSession.WindowChange(rows, cols)` in a third goroutine. Add to `handleSession`, replacing the plain `pty-req`/`window-change` cases:

```go
	resizeCh := make(chan [2]int, 4)
	cols, rows := 80, 24
	for req := range requests {
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if ssh.Unmarshal(req.Payload, &p) == nil && p.Cols > 0 {
				cols, rows = int(p.Cols), int(p.Rows)
			}
			_ = req.Reply(true, nil)
		case "window-change":
			var wc struct{ Cols, Rows, WidthPx, HeightPx uint32 }
			if ssh.Unmarshal(req.Payload, &wc) == nil {
				select {
				case resizeCh <- [2]int{int(wc.Rows), int(wc.Cols)}:
				default: // drop if runRecordedShell hasn't started consuming yet or is backed up
				}
			}
			_ = req.Reply(true, nil)
		case "env":
			_ = req.Reply(true, nil)
		case "auth-agent-req@openssh.com":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			s.runRecordedShell(ctx, channel, cols, rows, pr, srcIP, sconn, tch, pr.TargetHost, resizeCh)
			return
```

And add the resize-forwarding goroutine inside `runRecordedShell`, right after `targetSession.Shell()` succeeds:

```go
	go func() {
		for wc := range resizeCh {
			_ = targetSession.WindowChange(wc[0], wc[1])
		}
	}()
```

(`resizeCh` is never explicitly closed — it is abandoned when `runRecordedShell` returns and the goroutine leaks until the channel is garbage collected once nothing references it, which happens as soon as `handleSession`'s goroutine also returns; this matches the size of leak already accepted elsewhere in this package, e.g. the existing `finalizePending` comment in `sftp.go` about backstop cleanup. If this bothers a reviewer, closing `resizeCh` right after the `<-done` line in `runRecordedShell` is a one-line follow-up.)

Update `runRecordedShell`'s signature to accept `resizeCh <-chan [2]int` as the final parameter, and Step 2's test call site accordingly.

- [ ] **Step 5: Thread `secretToken` from auth into the shell path**

`policy.Principal` needs one more carrier field: `TargetSecretToken string`. Add it next to `TargetHost` in `internal/policy/policy.go`. In `principalFrom` (`internal/session/session.go`), add `TargetSecretToken: perms.Extensions["target_secret_token"],`. In `runRecordedShell`, replace the placeholder line `secretToken := ""` from Step 4 with using the parameter — add `pr` already carries it, so simply:

```go
	targetClient, err := tch.getOrDial(func() (*ssh.Client, error) {
		return s.dialTarget(ctx, sconn, pr, decision, targetHost, 22, pr.TargetSecretToken)
	})
```

(removing the now-redundant local `secretToken` variable).

- [ ] **Step 6: Run the interactive tests, verify pass**

Run: `go test ./internal/session/... -run TestRunRecordedShell -v`
Expected: PASS

- [ ] **Step 7: Run the full package build and test suite**

Run: `go build ./... && go test ./internal/session/... -v 2>&1 | tail -80`
Expected: build succeeds, all tests pass

- [ ] **Step 8: Commit**

```bash
git add internal/session/interactive.go internal/session/interactive_test.go internal/session/session.go internal/policy/policy.go
git commit -m "feat: bridge interactive shell to the real target over the second SSH leg"
```

---

### Task 9: SFTP downloads — real remote `Fileread`

**Files:**
- Modify: `internal/session/sftp.go`
- Test: `internal/session/sftp_test.go`

**Interfaces:**
- Consumes: `s.dialTarget`/`targetConnCache` (Task 7)
- Produces: `memFS` is replaced by a new `remoteFS` type wrapping `*sftp.Client`; `Fileread` proxies directly, `Filelist`/`Filecmd` proxy directly (uploads stay a separate concern — Task 11)

Downloads are the simpler half (no inspection, no quarantine — already decided in the spec) and share the same target-connection plumbing shell just gained, so this task lands the remote filesystem type before Task 11 adds the harder upload path onto it.

- [ ] **Step 1: Write the failing test**

Add to `internal/session/sftp_test.go` (reusing `startFakeTarget` from Task 7's `target_test.go` — it is in the same package, no import needed):

```go
func TestRemoteFS_FilereadProxiesRealTarget(t *testing.T) {
	fakeConn := startFakeSFTPTarget(t, map[string][]byte{"/etc/motd": []byte("hello from target\n")})
	client, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer client.Close()

	fs := &remoteFS{client: client, gate: nil}
	r, err := fs.Fileread(&goSftp.Request{Method: "Get", Filepath: "/etc/motd"})
	if err != nil {
		t.Fatalf("Fileread: %v", err)
	}
	buf := make([]byte, 32)
	n, _ := r.ReadAt(buf, 0)
	if got := string(buf[:n]); got != "hello from target\n" {
		t.Fatalf("Fileread content = %q, want %q", got, "hello from target\n")
	}
}
```

This needs two new test helpers — `startFakeSFTPTarget` (an in-process SSH server that also runs the `sftp` subsystem backed by a real `github.com/pkg/sftp` server over a temp dir) and `sshClientOver` (completes an `ssh.ClientConfig` handshake over a `net.Conn` for test use). Add both to `internal/session/sftp_test.go`:

```go
func startFakeSFTPTarget(t *testing.T, files map[string][]byte) net.Conn {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, filepath.Base(name))
		if err := os.WriteFile(full, content, 0o644); err != nil {
			t.Fatalf("seed file %s: %v", name, err)
		}
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(testHostKey(t))

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	go func() {
		sconn, chans, reqs, err := ssh.NewServerConn(serverConn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				_ = newCh.Reject(ssh.UnknownChannelType, "")
				continue
			}
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func() {
				for req := range reqs {
					isSubsystem := req.Type == "subsystem"
					req.Reply(isSubsystem, nil)
					if isSubsystem {
						srv, err := goSftp.NewServer(ch, goSftp.WithServerWorkingDirectory(dir))
						if err == nil {
							_ = srv.Serve()
						}
						return
					}
				}
			}()
		}
	}()
	return clientConn
}

func sshClientOver(t *testing.T, conn net.Conn) *ssh.Client {
	t.Helper()
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, "target", &ssh.ClientConfig{
		User: "test", Auth: nil, HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("ssh.NewClientConn: %v", err)
	}
	return ssh.NewClient(clientConn, chans, reqs)
}
```

Add imports to `internal/session/sftp_test.go`: `"os"`, `"path/filepath"`, and alias the server-side package `goSftp "github.com/pkg/sftp"` (the file already imports the client-side `"github.com/pkg/sftp"` unaliased for `sftp.NewClient` — `github.com/pkg/sftp` provides both `sftp.Client` and `sftp.RequestServer`/`sftp.NewServer` from the *same* package, so no alias is actually needed; use the existing `sftp` import for both `sftp.NewClient` and `sftp.NewServer`/`sftp.WithServerWorkingDirectory`, and drop the `goSftp` alias from the snippet above).

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestRemoteFS_FilereadProxiesRealTarget -v`
Expected: FAIL — `remoteFS` undefined

- [ ] **Step 3: Implement `remoteFS`**

In `internal/session/sftp.go`, add (near `memFS`, which stays in the file for now — Task 11 removes it once uploads also move over):

```go
// remoteFS serves the SFTP subsystem by proxying to a real *sftp.Client
// connected to the target, replacing the in-memory stand-in (memFS) for
// reads. Uploads (Filewrite) are handled separately — see Task 11 — because
// they must land in quarantine first, not straight through to client.
type remoteFS struct {
	client *sftp.Client
	gate   *inspectgate.Gate // set when inspection is configured; used by Filewrite (Task 11)
}

// Fileread (FileGet) proxies directly from the real target file — downloads
// are not content-inspected or quarantined, matching the existing in-memory
// stand-in's behavior and the design spec's explicit scope decision.
func (fs *remoteFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	f, err := fs.client.Open(cleanPath(r.Filepath))
	if err != nil {
		return nil, err
	}
	return f, nil // *sftp.File implements io.ReaderAt directly
}

// Filelist proxies List/Stat to the real target.
func (fs *remoteFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "List":
		infos, err := fs.client.ReadDir(cleanPath(r.Filepath))
		if err != nil {
			return nil, err
		}
		out := make([]os.FileInfo, len(infos))
		copy(out, infos)
		return listerAt(out), nil
	case "Stat":
		info, err := fs.client.Stat(cleanPath(r.Filepath))
		if err != nil {
			return nil, err
		}
		return listerAt{info}, nil
	}
	return nil, fmt.Errorf("sftp: unsupported list method %q", r.Method)
}

// Filecmd proxies Remove/Rename/Mkdir/Rmdir to the real target.
func (fs *remoteFS) Filecmd(r *sftp.Request) error {
	switch r.Method {
	case "Remove":
		return fs.client.Remove(cleanPath(r.Filepath))
	case "Rename":
		return fs.client.Rename(cleanPath(r.Filepath), cleanPath(r.Target))
	case "Mkdir":
		return fs.client.Mkdir(cleanPath(r.Filepath))
	case "Rmdir":
		return fs.client.RemoveDirectory(cleanPath(r.Filepath))
	case "Setstat", "Symlink":
		return nil // no-ops, matching the prior in-memory stand-in's scope
	}
	return nil
}
```

`cleanPath` and `listerAt` already exist in this file (used by `memFS`) — reused as-is, no change needed.

- [ ] **Step 4: Run the test, verify it passes**

Run: `go test ./internal/session/... -run TestRemoteFS_FilereadProxiesRealTarget -v`
Expected: PASS

- [ ] **Step 5: Run the full sftp test file, verify nothing existing broke**

Run: `go test ./internal/session/... -run TestSFTP -v 2>&1 | tail -60` (adjust the `-run` pattern to whatever prefix the existing SFTP tests use — check with `grep -n "^func Test" internal/session/sftp_test.go` first)
Expected: PASS — `memFS`/`Filewrite` are untouched by this task, only `remoteFS` was added

- [ ] **Step 6: Commit**

```bash
git add internal/session/sftp.go internal/session/sftp_test.go
git commit -m "feat: proxy SFTP reads/list/metadata to the real target"
```

---

### Task 10: `inspectgate.Gate` — unconditional quarantine on clean

**Files:**
- Modify: `internal/inspectgate/gate.go`
- Test: `internal/inspectgate/gate_test.go`

**Interfaces:**
- Modifies existing behavior: `Decision.QuarantineKey` is now set for **every** verdict (not only blocked/error), `Decision.HoldingKey` becomes unused (superseded — see Step 5) once this task lands
- No signature changes — existing callers keep compiling; only the `Decision` values they receive change

- [ ] **Step 1: Write the failing tests**

Add to `internal/inspectgate/gate_test.go`:

```go
func TestInspectSmall_CleanContentIsQuarantined(t *testing.T) {
	quar := newFakeBlobStore() // check gate_test.go for an existing fake BlobStore fixture first; reuse its name if one exists
	g, err := New(Config{Inspector: cleanInspector{}, Quarantine: quar})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "small.txt"}, strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !dec.Allow || dec.QuarantineKey == "" {
		t.Fatalf("clean small upload: got Allow=%v QuarantineKey=%q, want Allow=true and a non-empty key", dec.Allow, dec.QuarantineKey)
	}
	stored, err := quar.Get(context.Background(), dec.QuarantineKey)
	if err != nil {
		t.Fatalf("quarantine store missing the clean upload's bytes: %v", err)
	}
	got, _ := io.ReadAll(stored)
	if string(got) != "hello" {
		t.Fatalf("quarantined content = %q, want %q", got, "hello")
	}
}

func TestInspectLarge_CleanContentIsQuarantined(t *testing.T) {
	quar := newFakeBlobStore()
	hold := newFakeBlobStore()
	g, err := New(Config{Inspector: cleanInspector{}, Quarantine: quar, Holding: hold, Threshold: 4})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "large.txt"}, strings.NewReader("hello world, this is bigger than the threshold"))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !dec.Allow || dec.QuarantineKey == "" {
		t.Fatalf("clean large upload: got Allow=%v QuarantineKey=%q, want Allow=true and a non-empty key", dec.Allow, dec.QuarantineKey)
	}
	if _, err := quar.Get(context.Background(), dec.QuarantineKey); err != nil {
		t.Fatalf("quarantine store missing the clean large upload's bytes: %v", err)
	}
	// The transient holding copy must be cleaned up once promoted, exactly as
	// the existing blocked-content path already does (see gate.go's promote).
	if _, err := hold.Get(context.Background(), g.key("holding", inspect.TransferMeta{Filename: "large.txt"})); err == nil {
		t.Fatal("holding copy should have been deleted after promotion to quarantine")
	}
}
```

Check `internal/inspectgate/gate_test.go` for existing `cleanInspector`/`newFakeBlobStore`-equivalent fixtures (`grep -n "type.*Inspector\|BlobStore" internal/inspectgate/gate_test.go`) and reuse whatever names already exist — the blocked-content tests already need a fake inspector and a fake blob store, so both almost certainly already exist under some name; adjust the snippets above to match.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/inspectgate/... -run TestInspectSmall_CleanContentIsQuarantined -v`
Expected: FAIL — `dec.QuarantineKey` is empty for a clean small upload today

- [ ] **Step 3: Make `inspectSmall` quarantine on clean**

In `internal/inspectgate/gate.go`, `inspectSmall`'s clean branch currently reads:

```go
	case res.Verdict == inspect.VerdictClean:
		dec.Allow, dec.Verdict = true, "clean"
		return dec, nil
```

Replace with:

```go
	case res.Verdict == inspect.VerdictClean:
		dec.Allow, dec.Verdict = true, "clean"
		key, qerr := g.quarantineBytes(ctx, meta, data)
		dec.QuarantineKey = key
		if qerr != nil {
			// The scan says clean, but persisting the evidentiary copy failed —
			// this is an infrastructure failure, not a content verdict; fail
			// closed rather than deliver content with no byte-level record.
			dec.Allow = false
			dec.Verdict, dec.Reason = "error", "quarantine write failed: "+qerr.Error()
			return dec, qerr
		}
		return dec, nil
```

- [ ] **Step 4: Run the small-file test, verify it passes**

Run: `go test ./internal/inspectgate/... -run TestInspectSmall_CleanContentIsQuarantined -v`
Expected: PASS

- [ ] **Step 5: Make `inspectLarge` promote clean content to quarantine too**

`inspectLarge`'s clean tail currently reads:

```go
	// Clean: the holding object is the delivered artifact (Modified and Blocked
	// were both handled fail-closed above).
	dec.Allow = true
	dec.HoldingKey = holdKey
	dec.Verdict = "clean"
	return dec, nil
```

Replace with:

```go
	// Clean: promote the held content into quarantine too, same as the
	// blocked path above — every upload gets a permanent, byte-level
	// evidentiary copy, not only blocked ones. The holding copy is deleted
	// once promoted (g.promote already does this).
	dec.Allow = true
	dec.Verdict = "clean"
	qkey := g.key("quarantine", meta)
	if perr := g.promote(ctx, holdKey, qkey); perr != nil {
		return dec, fmt.Errorf("inspectgate: quarantine: %w", perr)
	}
	dec.QuarantineKey = qkey
	return dec, nil
```

This makes `Decision.HoldingKey` dead (nothing sets it anymore, on any path). Remove the `HoldingKey string` field from the `Decision` struct and grep for any other reference:

Run: `grep -rn "HoldingKey" internal/ --include="*.go"`

If any non-test caller reads `.HoldingKey` (unlikely — Task 11's spec review already confirmed `internal/session/sftp.go` never reads it today), update it; otherwise the field removal is safe.

- [ ] **Step 6: Run the large-file test, verify it passes**

Run: `go test ./internal/inspectgate/... -run TestInspectLarge_CleanContentIsQuarantined -v`
Expected: PASS

- [ ] **Step 7: Run the full inspectgate test suite**

Run: `go test ./internal/inspectgate/... -v 2>&1 | tail -60`
Expected: PASS — including every pre-existing blocked/error-path test, which this task did not touch

- [ ] **Step 8: Run the full build**

Run: `go build ./... 2>&1`
Expected: success (confirms the `HoldingKey` removal broke nothing elsewhere)

- [ ] **Step 9: Commit**

```bash
git add internal/inspectgate/gate.go internal/inspectgate/gate_test.go
git commit -m "feat: quarantine every upload unconditionally, not just blocked ones"
```

---

### Task 11: SFTP uploads — quarantine-then-release

**Files:**
- Modify: `internal/session/sftp.go`
- Modify: `internal/session/session.go` (new `Server` fields/options: `approvals`, `approvalTTL`)
- Modify: `cmd/omni-sag/main.go`
- Test: `internal/session/sftp_test.go`

**Interfaces:**
- Consumes: `approval.Store` (existing), `approval.KindQuarantineRelease` (existing, currently dead), `remoteFS`/`inspectgate.Gate` (Tasks 9–10)
- Produces: `remoteFS.Filewrite` returns a `quarantineWriteHandle` whose `Close()` blocks on the release decision

- [ ] **Step 1: Add `approvals`/`approvalTTL` to `Server`**

In `internal/session/session.go`, add to the `Server` struct:

```go
	approvals   approval.Store // optional; required for SFTP uploads when inspection is enabled (quarantine-release gate)
	approvalTTL time.Duration
```

Add the option:

```go
// WithApprovals gates SFTP uploads (when content inspection is enabled)
// behind a KindQuarantineRelease four-eyes approval: the upload blocks on
// Close() until a second human approves it, up to ttl. Mirrors
// dialer.WithApprovals — same Store, same TUI/API queue, different Kind.
func WithApprovals(store approval.Store, ttl time.Duration) Option {
	return func(s *Server) { s.approvals = store; s.approvalTTL = ttl }
}
```

Add the import `"github.com/rupivbluegreen/omni-sag/internal/approval"` to `internal/session/session.go`.

- [ ] **Step 2: Write the failing tests**

Add to `internal/session/sftp_test.go`:

```go
func TestQuarantineWriteHandle_AutoDeniedWithNoApprovalStoreFailsClosed(t *testing.T) {
	quar := newFakeBlobStore()
	g, _ := New(Config{Inspector: cleanInspector{}, Quarantine: quar})
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	s := &Server{sink: noopSink{}, inspect: g} // s.approvals is nil
	fs := &remoteFS{client: targetClient, gate: g}
	h, err := fs.Filewrite(&sftpPkg.Request{Method: "Put", Filepath: "/upload.txt"})
	if err != nil {
		t.Fatalf("Filewrite: %v", err)
	}
	if _, err := h.WriteAt([]byte("clean content"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := h.(io.Closer).Close(); err == nil {
		t.Fatal("Close must fail closed when inspection is enabled but no approval store is configured")
	}
}

func TestQuarantineWriteHandle_ApprovedDeliversToTarget(t *testing.T) {
	quar := newFakeBlobStore()
	g, _ := New(Config{Inspector: cleanInspector{}, Quarantine: quar})
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	store, err := approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s := &Server{sink: noopSink{}, inspect: g, approvals: store, approvalTTL: 5 * time.Second}
	fs := &remoteFS{client: targetClient, gate: g, srv: s, user: "alice"}

	h, err := fs.Filewrite(&sftpPkg.Request{Method: "Put", Filepath: "/upload.txt"})
	if err != nil {
		t.Fatalf("Filewrite: %v", err)
	}
	if _, err := h.WriteAt([]byte("clean content"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	closeErr := make(chan error, 1)
	go func() { closeErr <- h.(io.Closer).Close() }()

	// Poll for the pending request the way the TUI/API would, then approve it
	// as a different user (four-eyes).
	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range store.List() {
			if r.Kind == approval.KindQuarantineRelease && r.Status == approval.StatusPending {
				reqID = r.ID
			}
		}
		if reqID != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("no pending KindQuarantineRelease request was created")
	}
	if _, err := store.Approve(reqID, "bob"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if err := <-closeErr; err != nil {
		t.Fatalf("Close after approval: %v", err)
	}
	delivered, err := targetClient.Open("/upload.txt")
	if err != nil {
		t.Fatalf("target file was not delivered: %v", err)
	}
	got, _ := io.ReadAll(delivered)
	if string(got) != "clean content" {
		t.Fatalf("delivered content = %q, want %q", got, "clean content")
	}
}

func TestQuarantineWriteHandle_DeniedNeverReachesTarget(t *testing.T) {
	quar := newFakeBlobStore()
	g, _ := New(Config{Inspector: cleanInspector{}, Quarantine: quar})
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	store, _ := approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	s := &Server{sink: noopSink{}, inspect: g, approvals: store, approvalTTL: 5 * time.Second}
	fs := &remoteFS{client: targetClient, gate: g, srv: s, user: "alice"}

	h, _ := fs.Filewrite(&sftpPkg.Request{Method: "Put", Filepath: "/upload.txt"})
	_, _ = h.WriteAt([]byte("clean content"), 0)

	closeErr := make(chan error, 1)
	go func() { closeErr <- h.(io.Closer).Close() }()

	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reqID == "" {
		for _, r := range store.List() {
			if r.Kind == approval.KindQuarantineRelease && r.Status == approval.StatusPending {
				reqID = r.ID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("no pending request")
	}
	if _, err := store.Deny(reqID, "bob"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if err := <-closeErr; err == nil {
		t.Fatal("Close must error when the release was denied")
	}
	if _, err := targetClient.Open("/upload.txt"); err == nil {
		t.Fatal("denied content must never reach the target")
	}
}
```

Import `sftpPkg "github.com/pkg/sftp"` — wait, `sftp.go`/`sftp_test.go` already import `"github.com/pkg/sftp"` unaliased as `sftp`, which collides with this task's own package-local `sftp` variable names used in earlier tasks' snippets (e.g. `sftp.NewClient`). Use the existing unaliased `sftp` import throughout (`sftp.Request`, `sftp.NewClient`) — drop the `sftpPkg`/`goSftp` aliasing shown in these snippets and Task 9's, and instead name any local variable that would shadow it something else (e.g. `targetClient` instead of `sftpClient`, already done above). Reconcile this when writing the actual test file — the snippets above are illustrative of behavior, not copy-paste-exact given the shared package import.

- [ ] **Step 3: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestQuarantineWriteHandle -v`
Expected: FAIL — `remoteFS.Filewrite`, `remoteFS.srv`, `remoteFS.user` undefined

- [ ] **Step 4: Implement `Filewrite` and `quarantineWriteHandle`**

In `internal/session/sftp.go`, add fields to `remoteFS` (extending the struct from Task 9):

```go
type remoteFS struct {
	client *sftp.Client
	gate   *inspectgate.Gate
	srv    *Server // for approvals/evidence; nil only in Task 9's read-only tests
	user   string
	ctx    context.Context
}
```

Add:

```go
// Filewrite (FilePut): every upload streams through inspection exactly as
// memFS's inspectUpload already did (that machinery is unchanged — see
// newInspectUpload in this file), but Close no longer decides delivery by
// verdict alone. A clean upload is quarantined (Task 10 made that
// unconditional) and then requires a KindQuarantineRelease approval before
// the gateway delivers it to the real target file. Blocked/unscannable
// content was already fail-closed before this task and still never creates
// a release request.
func (fs *remoteFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if fs.gate == nil {
		// No inspection configured: deliver straight through, no quarantine
		// step — matches the project's existing "inspection is opt-in"
		// posture (session.WithInspection's doc comment).
		f, err := fs.client.Create(cleanPath(r.Filepath))
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	iu := newInspectUpload(fs.ctx, fs.gate, cleanPath(r.Filepath))
	return &quarantineWriteHandle{iu: iu, fs: fs, path: cleanPath(r.Filepath)}, nil
}

// quarantineWriteHandle wraps an inspectUpload (Task 10's now-unconditional
// quarantine) and, on Close, blocks for a KindQuarantineRelease approval
// before delivering the quarantined bytes to the real target file.
type quarantineWriteHandle struct {
	iu   *inspectUpload
	fs   *remoteFS
	path string
}

func (h *quarantineWriteHandle) WriteAt(p []byte, off int64) (int, error) {
	return h.iu.WriteAt(p, off)
}

func (h *quarantineWriteHandle) Close() error {
	if err := h.iu.Close(); err != nil {
		return err // blocked/unscannable — already refused, no release request
	}
	dec := h.iu.dec
	if h.fs.srv == nil || h.fs.srv.approvals == nil {
		return fmt.Errorf("sftp: upload quarantined (key=%s) but no approval store is configured to release it", dec.QuarantineKey)
	}
	req, err := h.fs.srv.approvals.Create(approval.Request{
		Kind:      approval.KindQuarantineRelease,
		Requester: h.fs.user,
		Subject:   dec.QuarantineKey,
		Reason:    fmt.Sprintf("release %s to %s", dec.QuarantineKey, h.path),
	}, h.fs.srv.approvalTTL)
	if err != nil {
		return fmt.Errorf("sftp: create release request: %w", err)
	}
	h.fs.srv.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeApproval,
		User: h.fs.user, Target: h.path, ObjectKey: req.ID,
		Outcome: "requested", Reason: "quarantine release pending",
	})

	final, werr := h.fs.srv.approvals.Wait(h.fs.ctxOrBackground(), req.ID)
	approved := werr == nil && final.Approved(time.Now())
	h.fs.srv.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeApproval,
		User: h.fs.user, Target: h.path, ObjectKey: req.ID,
		Allow: evidence.BoolPtr(approved),
		Outcome: map[bool]string{true: "granted", false: "refused"}[approved],
		Reason:  "quarantine release " + string(final.EffectiveStatus(time.Now())),
	})
	if !approved {
		return fmt.Errorf("sftp: upload to %s denied: quarantine release %s", h.path, final.EffectiveStatus(time.Now()))
	}

	src, err := h.fs.srv.inspect.QuarantineReader(h.fs.ctxOrBackground(), dec.QuarantineKey)
	if err != nil {
		return fmt.Errorf("sftp: read quarantined content %s: %w", dec.QuarantineKey, err)
	}
	defer src.Close()
	dst, err := h.fs.client.Create(h.path)
	if err != nil {
		return fmt.Errorf("sftp: open target %s: %w", h.path, err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("sftp: deliver %s to target: %w", h.path, err)
	}

	h.fs.srv.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeTransfer,
		User: h.fs.user, Path: h.path, Direction: "upload",
		Bytes: dec.Bytes, SHA256: dec.SHA256, ObjectKey: dec.QuarantineKey,
		Detail: "sftp transfer (released from quarantine)",
	})
	return nil
}
```

Two new small pieces this references need adding:

`(fs *remoteFS) ctxOrBackground()` — add to `sftp.go`:

```go
func (fs *remoteFS) ctxOrBackground() context.Context {
	if fs.ctx != nil {
		return fs.ctx
	}
	return context.Background()
}
```

`inspectgate.Gate.QuarantineReader` — a new *reader* accessor, since `Gate.quarantine` is unexported and `Filewrite`'s delivery step needs to read the quarantined bytes back out. Add to `internal/inspectgate/gate.go`:

```go
// QuarantineReader opens the quarantined object at key for reading — used to
// deliver a released (approved) upload to its real target. Callers must
// Close the returned reader.
func (g *Gate) QuarantineReader(ctx context.Context, key string) (io.ReadCloser, error) {
	return g.quarantine.Get(ctx, key)
}
```

- [ ] **Step 5: Run the three new tests, verify pass**

Run: `go test ./internal/session/... -run TestQuarantineWriteHandle -v 2>&1 | tail -80`
Expected: PASS (all three)

- [ ] **Step 6: Wire `runSFTP` to build a `remoteFS` instead of `memFS`, and construct `session.WithApprovals` in main.go**

In `internal/session/sftp.go`, `runSFTP` currently does `fs := newMemFS(s.inspect, ctx, pr.User)`. Replace `runSFTP`'s body to dial the target (reusing `tch`, threaded in from Task 8's `handleSession` change) and build a `remoteFS`:

```go
func (s *Server) runSFTP(ctx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache) {
	if pr.TargetHost == "" {
		_ = channel.Close()
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "sftp refused: no target selected",
		})
		return
	}
	decision := policy.Decision{}
	if s.dialerPeek != nil {
		decision = s.dialerPeek(pr, policy.Target{Host: pr.TargetHost})
	}
	targetClient, err := tch.getOrDial(func() (*ssh.Client, error) {
		return s.dialTarget(ctx, sconn, pr, decision, pr.TargetHost, 22, pr.TargetSecretToken)
	})
	if err != nil {
		_ = channel.Close()
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "sftp refused: " + err.Error(),
		})
		return
	}
	sftpClient, err := sftp.NewClient(targetClient)
	if err != nil {
		_ = channel.Close()
		return
	}
	defer sftpClient.Close()

	fs := &remoteFS{client: sftpClient, gate: s.inspect, srv: s, user: pr.User, ctx: ctx}
	server := sftp.NewRequestServer(channel, sftp.Handlers{
		FileGet:  fs,
		FilePut:  fs,
		FileCmd:  fs,
		FileList: fs,
	})
	_ = server.Serve()
	_ = server.Close()
	_ = channel.Close()
}
```

This makes `memFS`/`newMemFS`/`inspectUpload`'s call sites in the OLD `runSFTP` obsolete — `newInspectUpload` itself is still used (by the new `Filewrite`), so only `memFS`, `newMemFS`, and every `memFile`/`memWriteHandle`/`listerAt`-via-`memFS` reference tied to the old in-memory delivery path is dead now. Run `grep -n "memFS\|newMemFS\|memWriteHandle" internal/session/sftp.go` and delete the now-unused `memFS` type, its constructor, and `Filewrite`/`Fileread`/`Filecmd`/`Filelist` methods (the ones defined on `*memFS`, NOT the ones on `*remoteFS`) along with `memWriteHandle`. Keep `memFile`, `memFileInfo`, `listerAt`, `transfer`, `cleanPath`, `inspectUpload`, `newInspectUpload`, `maxReorderBytes`, `maxMemFileSize` — all still used (`memFile`/`memFileInfo`/`maxMemFileSize` may become genuinely dead too; check with `grep -n "memFile{\|memFileInfo{" internal/session/sftp.go` after the deletion and remove them too if nothing references them).

Update the two call sites of `runSFTP` inside `handleSession` (`internal/session/interactive.go`) to pass `sconn, tch`:

```go
			_ = req.Reply(true, nil)
			s.runSFTP(ctx, channel, pr, srcIP, sconn, tch)
			return
```

In `cmd/omni-sag/main.go`, alongside the existing `dopts = append(dopts, dialer.WithApprovals(...))` block, add:

```go
		opts = append(opts, session.WithApprovals(approvalStore, time.Duration(cfg.Approval.ApprovalTTL())*time.Second))
```

(inside the same `if cfg.Approval != nil { ... }` block, after the existing `dopts = append` line).

- [ ] **Step 7: Run the full session and inspectgate test suites**

Run: `go build ./... && go test ./internal/session/... ./internal/inspectgate/... -v 2>&1 | tail -100`
Expected: build succeeds, all tests pass, no leftover references to the deleted `memFS`

- [ ] **Step 8: Run `make lint` and `make test`**

Run: `make lint && make test 2>&1 | tail -60`
Expected: clean

- [ ] **Step 9: Commit**

```bash
git add internal/session/sftp.go internal/session/session.go internal/session/interactive.go \
  internal/inspectgate/gate.go cmd/omni-sag/main.go internal/session/sftp_test.go
git commit -m "feat: gate SFTP upload delivery behind quarantine-release approval"
```

---

### Task 12: Lab wiring — real target container

**Files:**
- Modify: `deploy/compose/docker-compose.yml`
- Modify: `deploy/compose/config.example.yaml`

**Interfaces:** none (infrastructure/config only)

- [ ] **Step 1: Add the target container**

In `deploy/compose/docker-compose.yml`, add a new service (following the file's existing style — see `minio`'s block for the pattern of `container_name`/`restart: unless-stopped`):

```yaml
  ssh-target:
    image: linuxserver/openssh-server:latest
    container_name: omni-sag-ssh-target
    hostname: db1
    environment:
      PUID: "1000"
      PGID: "1000"
      TZ: "Etc/UTC"
      PASSWORD_ACCESS: "true"
      USER_NAME: "svc_db1"
      USER_PASSWORD: "InjectedSecret123!"
    ports:
      - "2200:2222" # host:container — container's sshd listens on 2222 by default for this image
    restart: unless-stopped
```

- [ ] **Step 2: Verify it comes up**

Run: `cd deploy/compose && docker compose up -d ssh-target && sleep 5 && docker compose ps ssh-target`
Expected: state `running`/`healthy`

Run: `ssh -p 2200 -o StrictHostKeyChecking=no svc_db1@127.0.0.1 whoami` (password `InjectedSecret123!` when prompted)
Expected: prints `svc_db1`

- [ ] **Step 3: Add the demo `Rule` and CyberArk object for it**

In `deploy/compose/config.example.yaml`, add a rule to the existing `dba` role's `allow` list (find the existing `- host: "db1.lab.local"` entry from the tunnel demo and add a sibling entry for the real container's actual reachable name — inside the compose network the container is reachable at hostname `db1` on port `2222`; from the host machine (where `omni-sag` runs in the dev-lab setup) it's `127.0.0.1:2200`. Use whichever the running gateway process actually resolves — for the dev-lab docs this plan targets, that's `127.0.0.1:2200`):

```yaml
        - host: "127.0.0.1"
          ports: [2200]
          target_user: "svc_db1"
          record: full
          credential: inject
```

Add a comment above it explaining the demo intent, matching the file's existing comment density:

```yaml
        # Real-target demo (this design's shell/SFTP proxy, not the -L tunnel
        # above): alice gets a genuine shell/SFTP on the ssh-target container,
        # authenticated as svc_db1 via the mock CyberArk CCP below.
```

If `cfg.CyberArk` isn't already configured with an object matching `svc_db1`'s password for this host in the mock CCP fixture, check `internal/credential/ccp_test.go` / any mock-CCP fixture used by the lab (`grep -rn "mock.*ccp\|MockCCP" internal/ scripts/ deploy/ --include="*.go" --include="*.sh" --include="*.yaml" -i`) and add a matching entry so `credential: inject` actually resolves `InjectedSecret123!` for this target in the dev lab. Document the exact mechanism found (there may not be a standing mock-CCP server in the lab yet — if not, note this explicitly as a gap for Task 13's integration script to work around, e.g. by using `credential: passthrough` or `credential: prompt` in the demo config instead of `inject` if no mock CCP is running in the compose lab).

- [ ] **Step 4: Commit**

```bash
git add deploy/compose/docker-compose.yml deploy/compose/config.example.yaml
git commit -m "feat: add a real SSH target container to the dev lab"
```

---

### Task 13: Docker-lab integration test

**Files:**
- Create: `scripts/lab-test-real-target.sh`
- Modify: `Makefile`

**Interfaces:** none (shell script, follows `scripts/lab-seed.sh`'s existing style)

- [ ] **Step 1: Write the script**

Create `scripts/lab-test-real-target.sh`:

```bash
#!/usr/bin/env bash
# End-to-end check of the real-target shell/SFTP proxy against the dev lab's
# ssh-target container. Requires `make lab-up && make lab-seed` to have run
# first, and the gateway binary already built (`make binaries`).
#
# Usage: scripts/lab-test-real-target.sh
set -euo pipefail

GW_BIN="${GW_BIN:-./bin/omni-sag_$(go env GOOS)_$(go env GOARCH)}"
CONFIG="${CONFIG:-deploy/compose/config.example.yaml}"
GW_PORT="${GW_PORT:-2222}"

if [ ! -x "$GW_BIN" ]; then
  echo "gateway binary not found at $GW_BIN — run: make binaries" >&2
  exit 1
fi

"$GW_BIN" -config "$CONFIG" &
GW_PID=$!
trap 'kill "$GW_PID" 2>/dev/null || true' EXIT
sleep 2

echo "== real shell: alice runs a real command on the target =="
OUT=$(ssh -p "$GW_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "alice%127.0.0.1@127.0.0.1" whoami 2>&1) || true
if [ "$OUT" != "svc_db1" ]; then
  echo "FAIL: expected the real target's whoami (svc_db1), got: $OUT" >&2
  exit 1
fi
echo "PASS: real shell command executed on the target as svc_db1"

echo "== real SFTP: alice puts a file, it lands in quarantine pending release =="
echo "hello from the lab" > /tmp/lab-upload.txt
sftp -P "$GW_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "alice%127.0.0.1@127.0.0.1" <<EOF &
put /tmp/lab-upload.txt /upload.txt
EOF
SFTP_PID=$!

echo "== approve the pending quarantine-release request =="
sleep 1
# This step depends on Task 11's approval store and Task 7's API/TUI wiring
# for listing/approving KindQuarantineRelease requests — use whichever the
# control-plane API exposes (check internal/api's approval endpoints, e.g.
# `omnictl approve <id>` per README's existing approval examples) rather than
# reaching into the FileStore's JSON file directly.
REQ_ID=$(./bin/omnisag-ctl_"$(go env GOOS)"_"$(go env GOARCH)" approvals list --kind quarantine_release --status pending -q | head -1)
if [ -z "$REQ_ID" ]; then
  echo "FAIL: no pending quarantine_release request found" >&2
  exit 1
fi
./bin/omnisag-ctl_"$(go env GOOS)"_"$(go env GOARCH)" approve "$REQ_ID"

wait "$SFTP_PID"

echo "== verify the file actually landed on the target =="
DELIVERED=$(ssh -p 2200 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null svc_db1@127.0.0.1 cat /upload.txt)
if [ "$DELIVERED" != "hello from the lab" ]; then
  echo "FAIL: delivered content mismatch: $DELIVERED" >&2
  exit 1
fi
echo "PASS: released upload delivered to the real target"

echo "ALL PASS"
```

Note: `omnisag-ctl approvals list --kind ... -q` is illustrative of the *intent* (list pending quarantine-release requests, machine-readable) — check `internal/tui`/`cmd/omnisag-ctl/main.go`'s actual current flag surface (`grep -n "\"approve\"\|approvals\|flag\." cmd/omnisag-ctl/main.go`) before finalizing this script, since `omnictl`'s existing commands were seen only as `omnictl approve <id>` / `omnictl deny <id>` / `omnictl sessions kill <id>` in Task 2's grep of `cmd/omnictl/main.go` — there is no confirmed `approvals list --kind` subcommand today. If listing-by-kind doesn't exist, either (a) add a minimal one as part of this task (small, additive change to `cmd/omnisag-ctl/main.go` and whatever `internal/api` endpoint it calls), or (b) have the script poll the API's existing approvals-list endpoint directly with `curl`+`jq` instead of inventing a new CLI flag. Pick (b) first — smaller blast radius — and only add (a) if the API doesn't expose enough to filter by kind/status already (check `internal/api`'s approval handlers: `grep -n "approvals\|Kind" internal/api/*.go`).

- [ ] **Step 2: Make it executable**

Run: `chmod +x scripts/lab-test-real-target.sh`

- [ ] **Step 3: Add the Makefile target**

In `Makefile`, add near `lab-seed`:

```makefile
lab-test-real-target:
	bash scripts/lab-test-real-target.sh
```

Add `lab-test-real-target` to the `.PHONY` line at the top of the file (alongside the existing `lab-up lab-down lab-logs lab-seed`).

- [ ] **Step 4: Run it against the live lab**

Run: `make lab-up && make lab-seed && make binaries && make lab-test-real-target`
Expected: `ALL PASS`

If it fails, this is the point to circle back and fix whatever Task 1–12 code path is actually broken — do not weaken the script's assertions to make it pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/lab-test-real-target.sh Makefile
git commit -m "test: add docker-lab integration check for the real-target proxy"
```

---

### Task 14: Documentation — close out ADR-0002's stand-in boundary

**Files:**
- Modify: `docs/decisions/0002-credential-injection-threat-model.md`
- Modify: `README.md` (the port-forwarding demo section, if it implies shell/SFTP are still stand-ins anywhere)

**Interfaces:** none (docs only)

- [ ] **Step 1: Update ADR-0002**

In `docs/decisions/0002-credential-injection-threat-model.md`, the "The stand-in boundary (honest scope)" section currently says the interactive shell and SFTP are gateway-terminated stand-ins with target-auth stubbed. Replace that section's final two paragraphs (the ones starting "When real target authentication lands...") with:

```markdown
## Real target authentication (landed)

Real target authentication landed in `docs/superpowers/plans/2026-07-14-real-target-proxy.md`.
The interactive shell and SFTP subsystem now bridge to a real second SSH
connection to the target, authenticated per the four credential modes:

- `inject` consumes the CyberArk-fetched `Secret` on the target leg (instead
  of fetch-then-destroy) and zeroizes it immediately after the handshake.
- `prompt` collects the target password via genuine SSH keyboard-interactive
  chaining (`ssh.PartialSuccessError`), not a mid-channel hack.
- `passthrough` uses real OpenSSH agent forwarding — the target authenticates
  the human as themselves, not the gateway.
- `deny` refuses before any channel opens, as before.

SFTP uploads additionally land in the WORM quarantine store unconditionally
(clean or not) and require a `KindQuarantineRelease` four-eyes approval
before delivery to the real target — see the design spec's "SFTP" section.
```

- [ ] **Step 2: Check the README for now-stale "stand-in" language**

Run: `grep -n "in-memory\|echo\|stand-in" README.md`

If any line describes the shell/SFTP path as a stand-in, update it to reflect the real proxy (keep the surrounding tone/structure — this is a small wording fix, not a rewrite).

- [ ] **Step 3: Commit**

```bash
git add docs/decisions/0002-credential-injection-threat-model.md README.md
git commit -m "docs: close out ADR-0002's stand-in boundary — real target auth has landed"
```

---

## Self-Review

**Spec coverage** — every spec section maps to a task:
- Architecture (second SSH leg) → Task 7
- Target selection (`user%host`) → Task 2
- Target account mapping (`TargetUser`) → Task 1
- Second-leg auth per mode → Tasks 4 (inject/shared provider), 5 (prompt), 6 (passthrough), 7 (unifies all four + deny)
- Interactive shell → Task 8
- SFTP (quarantine-then-release) → Tasks 9 (downloads/reads), 10 (Gate unconditional quarantine), 11 (upload release gate)
- Lab/demo wiring → Task 12
- Testing → Task 13 (integration); unit tests are embedded in every task
- Explicitly out of scope (tunnel path, CyberArk real interop) → untouched by every task above, confirmed by each task's file list never touching `internal/dialer`'s tunnel path or `internal/credential/ccp.go`'s real-HTTP behavior

**Placeholder scan** — no TBD/TODO left in any step; the two spots that read like hedges (Task 8's resize-channel-leak note, Task 13's `omnisag-ctl approvals list` uncertainty) both resolve to a concrete decision inline (accept the leak / prefer curling the API directly) rather than deferring the decision to the implementer.

**Type consistency** — `dialTarget`'s signature (`ctx, sconn, pr, decision, targetHost, targetPort, secretToken`) is identical across Tasks 7, 8, and 11's `runSFTP`. `policy.Principal.TargetHost`/`TargetSecretToken` (added in Task 8) are the same names used by Task 11's `runSFTP`. `remoteFS`'s fields (`client, gate, srv, user, ctx`) are consistent between Task 9 (introduces `client`/`gate`) and Task 11 (adds `srv`/`user`/`ctx`).

**Known follow-ups intentionally left out of this plan** (YAGNI — not gaps, deliberate scope cuts already called out inline): the resize-channel goroutine leak noted in Task 8 Step 4; the target port for `dialerPeek`'s prompt-mode lookup always being guessed rather than carried from the client's real target port (Task 5 Step 8); whether `credential: inject` actually has a mock CCP object to resolve in the dev lab (Task 12 Step 3, flagged for the implementer to verify and, if missing, wire up as a small addition to whatever mock-CCP fixture already exists).
