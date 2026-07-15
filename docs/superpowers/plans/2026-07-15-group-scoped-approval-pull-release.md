# Group-scoped approval + pull-download release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** SFTP quarantine-release approvals require a peer in the requester's role-granting AD group (not just "any other user"), and an approved upload is retrieved by the uploader themselves via a browsable `/releases` SFTP directory within 6 hours, instead of being auto-pushed to the real target.

**Architecture:** `policy.Decide`/`DecideHost` compute and expose the requester's matched-role AD groups (`Decision.MatchedGroups`) for free at policy-decision time. `internal/approval.FileStore` gains an optional, dependency-injected `GroupLookup` (mirrors `credential.Provider`'s `Fetcher` pattern) that, when configured, additionally requires the approver's live LDAP group membership to overlap the request's snapshotted `RequesterGroups` for `KindQuarantineRelease` approvals only. A new leaf package `internal/release` tracks approved-and-pending-pickup files (quarantine key, requester, expiry) with a JSON-backed store mirroring `approval.FileStore`'s durability pattern but without four-eyes/blocking semantics. `quarantineWriteHandle.Close()`'s approved branch is rewired from "push to target" to "record a release"; `remoteFS.Fileread`/`Filelist` gain a `/releases` virtual path serving straight from the WORM quarantine store with a fresh identity+expiry check on every access.

**Tech Stack:** Go, existing `internal/policy`/`internal/approval`/`internal/authn`/`internal/session`/`internal/inspectgate`/`internal/evidence` packages, `github.com/go-ldap/ldap/v3` (already a dependency).

**Spec:** `docs/superpowers/specs/2026-07-14-group-scoped-approval-and-pull-release-design.md`

## Global Constraints

- No new Go module dependencies.
- `internal/approval` stays a leaf package (must not import `internal/session`/`internal/api`/`internal/dialer`) — the `GroupLookup` it depends on is an interface `internal/approval` itself defines, not a concrete import of `internal/authn`.
- `internal/release` (new) is also a leaf package, same constraint, for the same reason `internal/approval` is one (shared by the SSH data path and, potentially, a future control-plane surface).
- `internal/policy` stays pure (no `internal/session` import) — `MatchedGroups` is computed from data `Decide`/`DecideHost` already have (`pr.Groups`, the matched `Role.Groups`), no new inputs.
- Group-scoped four-eyes is **additive and opt-in**: a `FileStore` with no `GroupLookup` configured, or a request with empty `RequesterGroups`, behaves exactly as today (plain four-eyes only) — this keeps every existing test and deployment that hasn't wired LDAP group lookup working unchanged. It is only a stricter check when explicitly configured, never a silent weakening.
- No fallback when a requester is the sole member of their matched group — the request simply expires via the existing TTL mechanism (`EffectiveStatus`); no new code models this case.
- No presigned URLs, no HTTP delivery channel — retrieval stays entirely inside the SFTP protocol via the existing `Gate.QuarantineReader` (gateway is the only S3 principal, unchanged from Task 11).
- Approval TTL for `KindQuarantineRelease` becomes its own configured value (24h default), independent of session-access approvals' TTL (which keeps its existing 900s/15min default) — both share the same `approval.Store` instance, just different `Create(..., ttl)` call-site values.
- `gofmt`/`go vet` clean and `make ci` green after every task.

---

## File Structure

New files:
- `internal/release/release.go` — `Release` struct, `Store` interface
- `internal/release/filestore.go` — JSON-backed `FileStore` implementation
- `internal/release/filestore_test.go`
- `internal/policy/policy_matchedgroups_test.go`

Modified files:
- `internal/policy/policy.go` — `Decision.MatchedGroups`, computed in `Decide` and `DecideHost`
- `internal/authn/ldap.go` — `LDAPAuthenticator.Groups(ctx, username) ([]string, error)`, refactored out of `Authenticate`
- `internal/authn/ldap_test.go`
- `internal/approval/approval.go` — `Request.RequesterGroups`, `GroupLookup` interface, `ErrNotPeerGroup`
- `internal/approval/filestore.go` — `SetGroupLookup`, group-check branch in `decide()`
- `internal/approval/filestore_test.go`
- `internal/session/session.go` — `Server.releases`/`WithReleases` option
- `internal/session/sftp.go` — `remoteFS` gains `matchedGroups`/`releases`; `quarantineWriteHandle.doClose()`'s approved branch rewired; `/releases` virtual path on `Fileread`/`Filelist`; `Filecmd`/`Filewrite` refuse under `/releases`
- `internal/session/sftp_test.go`
- `internal/api/approvals.go` — `ErrNotPeerGroup` → HTTP 403
- `internal/config/config.go` — `ApprovalConfig.ReleaseTTLSeconds`
- `cmd/omni-sag/main.go` — wire `LDAPAuthenticator.Groups` as the `GroupLookup`, wire `internal/release.NewFileStore`, wire `session.WithReleases`, use `ReleaseTTLSeconds` for the session-side approval TTL
- `scripts/lab-test-real-target.sh` — extend to exercise group-scoped approval + pull-download release end to end

---

### Task 1: `policy.Decision.MatchedGroups`

**Files:**
- Modify: `internal/policy/policy.go`
- Test: `internal/policy/policy_matchedgroups_test.go`

**Interfaces:**
- Produces: `policy.Decision.MatchedGroups []string`

The requester's own AD groups are already on `Principal.Groups`; what's missing is which of THOSE groups are the ones that actually granted the matched role, for a specific decision — that's what `approval.Request.RequesterGroups` needs to snapshot later.

- [ ] **Step 1: Write the failing test**

Add to `internal/policy/policy_matchedgroups_test.go`:

```go
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
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/policy/... -run TestDecide_MatchedGroups -run TestDecideHost_MatchedGroups -v`
Expected: FAIL — `Decision` has no field `MatchedGroups` (compile error)

- [ ] **Step 3: Implement it**

In `internal/policy/policy.go`, add to `Decision` (after `TargetUser`):

```go
	// MatchedGroups is the subset of the principal's own Groups that actually
	// granted the matched role — i.e. intersect(Principal.Groups, the matched
	// Role.Groups), not the principal's full group list (a principal can hold
	// groups irrelevant to this specific decision). Empty on deny. Used to
	// snapshot approval.Request.RequesterGroups for group-scoped four-eyes on
	// quarantine-release approvals — see docs/superpowers/specs/
	// 2026-07-14-group-scoped-approval-and-pull-release-design.md.
	MatchedGroups []string
```

Add a helper near `rolesFor`:

```go
// intersectGroups returns the elements of principalGroups that case-
// insensitively match an entry in roleGroups, preserving the principal's own
// casing (not the role's) since that's what a later live LDAP group-lookup
// comparison will need to match against.
func intersectGroups(principalGroups, roleGroups []string) []string {
	want := make(map[string]bool, len(roleGroups))
	for _, g := range roleGroups {
		want[strings.ToLower(g)] = true
	}
	var out []string
	for _, g := range principalGroups {
		if want[strings.ToLower(g)] {
			out = append(out, g)
		}
	}
	return out
}
```

In `Decide`, inside the `if rule.matches(t)` branch, add `MatchedGroups: intersectGroups(pr.Groups, r.Groups),` to the returned `Decision{...}` literal.

In `DecideHost`, in the final success-path `return Decision{...}`, add `MatchedGroups: intersectGroups(pr.Groups, m.role.Groups),`.

- [ ] **Step 4: Run the tests, verify pass**

Run: `go test ./internal/policy/... -v 2>&1 | tail -40`
Expected: PASS, all tests including the four new ones

- [ ] **Step 5: Commit**

```bash
git add internal/policy/policy.go internal/policy/policy_matchedgroups_test.go
git commit -m "feat: add policy.Decision.MatchedGroups for group-scoped approval"
```

---

### Task 2: `LDAPAuthenticator.Groups` — group lookup without a password

**Files:**
- Modify: `internal/authn/ldap.go`
- Test: `internal/authn/ldap_test.go`

**Interfaces:**
- Produces: `(a *LDAPAuthenticator) Groups(ctx context.Context, username string) ([]string, error)`

Looking up an approver's CURRENT groups at decision time must not require their password — `Authenticate`'s steps 1-2 (service-account bind, search, read `memberOf`) already do exactly what's needed; step 3 (bind-as-user) is password verification only, not needed here. Refactor the shared part out so both methods use it.

- [ ] **Step 1: Read the current `Authenticate` in full**

Read `internal/authn/ldap.go` before editing — confirm its exact current shape (dial, timeout handling, service bind, search, decoy-bind-on-not-found, user bind, `groupCNsFromMemberOf`) matches what's described below; this file has not changed recently but verify before refactoring live auth code.

- [ ] **Step 2: Write the failing test**

Add to `internal/authn/ldap_test.go` (check the file first for existing test-server fixtures — this package's tests likely already stand up a fake LDAP server for `Authenticate`'s tests; reuse that fixture rather than building a new one):

```go
func TestLDAPAuthenticator_Groups_NoPasswordNeeded(t *testing.T) {
	a := newTestLDAPAuthenticator(t) // reuse whatever fixture Authenticate's tests already use
	groups, err := a.Groups(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	if len(groups) == 0 {
		t.Fatal("want at least one group for alice, got none")
	}
}

func TestLDAPAuthenticator_Groups_UnknownUserErrors(t *testing.T) {
	a := newTestLDAPAuthenticator(t)
	_, err := a.Groups(context.Background(), "no-such-user")
	if err == nil {
		t.Fatal("want an error for an unknown user, got nil")
	}
}
```

If no reusable test-server fixture exists (check first — `grep -n "func newTest\|func setupLDAP\|ldap.NewServer\|httptest" internal/authn/ldap_test.go`), match whatever pattern the file's existing `Authenticate` tests use (in-process fake LDAP server, or a documented skip-if-no-lab-available pattern) rather than inventing a new one.

- [ ] **Step 3: Run it, verify it fails**

Run: `go test ./internal/authn/... -run TestLDAPAuthenticator_Groups -v`
Expected: FAIL — `Groups` undefined

- [ ] **Step 4: Refactor and implement**

In `internal/authn/ldap.go`, extract a shared helper that does connection setup + service bind + search (steps 1-2 of `Authenticate`), returning the found entry:

```go
// lookupUser binds as the service account and searches for username,
// returning the found entry (DN + memberOf). Used by both Authenticate
// (which additionally verifies a password) and Groups (which does not).
func (a *LDAPAuthenticator) lookupUser(ctx context.Context, conn *ldap.Conn, username string) (*ldap.Entry, error) {
	timeout := defaultLDAPTimeout
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	conn.SetTimeout(timeout)
	searchSecs := int(timeout.Seconds())
	if searchSecs < 1 {
		searchSecs = 1
	}

	if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("%w: service bind: %v", ErrAuth, err)
	}

	req := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, searchSecs, false,
		fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn", "memberOf", "sAMAccountName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("%w: search: %v", ErrAuth, err)
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("%w: user not uniquely found", ErrAuth)
	}
	return res.Entries[0], nil
}

func (a *LDAPAuthenticator) dial() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(a.cfg.URL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: a.cfg.InsecureTLS, //nolint:gosec // dev-only opt-in; rejected under fips.mode=enforce by config validation
	}))
	if err != nil {
		return nil, fmt.Errorf("%w: connect: %v", ErrAuth, err)
	}
	return conn, nil
}

// Groups resolves username's current AD group membership via the service
// account only — no password required. Used for group-scoped four-eyes at
// quarantine-release approval time (the approver's password is never
// available to the control plane at that point). Callers must not use this
// as an authentication check: it proves nothing about who is asking, only
// what the named account's groups currently are.
func (a *LDAPAuthenticator) Groups(ctx context.Context, username string) ([]string, error) {
	conn, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	entry, err := a.lookupUser(ctx, conn, username)
	if err != nil {
		return nil, err
	}
	return groupCNsFromMemberOf(entry.GetAttributeValues("memberOf")), nil
}
```

Then simplify `Authenticate` to use `a.dial()` and `a.lookupUser(ctx, conn, username)` for its first two steps, keeping its own decoy-bind-on-not-found and user-bind-for-password-verification steps as they are today — read the current `Authenticate` body and replace only the dial/bind/search portion (steps 1-2) with calls to the two new helpers; do not change its decoy-bind timing-equalization behavior or the password-empty-check at the top.

- [ ] **Step 5: Run the auth package tests, verify pass**

Run: `go test ./internal/authn/... -v 2>&1 | tail -40`
Expected: PASS — both new `Groups` tests, and every pre-existing `Authenticate` test unchanged in behavior (this is a refactor of shared internals, not a behavior change to `Authenticate`)

- [ ] **Step 6: Commit**

```bash
git add internal/authn/ldap.go internal/authn/ldap_test.go
git commit -m "feat: add LDAPAuthenticator.Groups for password-free group lookup"
```

---

### Task 3: `approval` — `RequesterGroups`, `GroupLookup`, group-scoped `Approve`

**Files:**
- Modify: `internal/approval/approval.go`
- Modify: `internal/approval/filestore.go`
- Test: `internal/approval/filestore_test.go`

**Interfaces:**
- Produces: `approval.Request.RequesterGroups []string`, `approval.GroupLookup` interface, `approval.ErrNotPeerGroup`, `(*FileStore).SetGroupLookup(gl GroupLookup)`
- Consumes: nothing new — `GroupLookup` is an interface `internal/approval` defines itself (leaf-package rule), satisfied later by `*authn.LDAPAuthenticator` at the composition root

- [ ] **Step 1: Write the failing tests**

Add to `internal/approval/filestore_test.go` (check the file first for existing fixtures like a `fixedNow` helper or table style to match):

```go
type fakeGroupLookup struct {
	groups map[string][]string // username -> groups
	err    error
}

func (f *fakeGroupLookup) Groups(_ context.Context, username string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.groups[username], nil
}

func TestFileStore_ApproveGroupScoped_PeerInGroupSucceeds(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s.SetGroupLookup(&fakeGroupLookup{groups: map[string][]string{"bob": {"dba"}}})

	req, err := s.Create(Request{Kind: KindQuarantineRelease, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "quarantine/key1"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Approve(req.ID, "bob"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
}

func TestFileStore_ApproveGroupScoped_NonPeerRefused(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s.SetGroupLookup(&fakeGroupLookup{groups: map[string][]string{"carol": {"engineering"}}})

	req, err := s.Create(Request{Kind: KindQuarantineRelease, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "quarantine/key1"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// carol is a DIFFERENT user from alice (passes plain four-eyes) but is not
	// in "dba" — must still be refused.
	_, err = s.Approve(req.ID, "carol")
	if !errors.Is(err, ErrNotPeerGroup) {
		t.Fatalf("want ErrNotPeerGroup, got %v", err)
	}
}

func TestFileStore_ApproveGroupScoped_LookupFailureFailsClosed(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s.SetGroupLookup(&fakeGroupLookup{err: errors.New("ldap down")})

	req, err := s.Create(Request{Kind: KindQuarantineRelease, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "quarantine/key1"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Approve(req.ID, "bob"); err == nil {
		t.Fatal("want an error when GroupLookup fails, got nil (must fail closed, not silently allow)")
	}
}

func TestFileStore_ApproveGroupScoped_NoGroupLookupConfiguredKeepsPlainFourEyes(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json")) // no SetGroupLookup call
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	req, err := s.Create(Request{Kind: KindQuarantineRelease, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "quarantine/key1"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// No GroupLookup configured: any distinct user still succeeds — today's
	// behavior, unchanged, proving this feature is opt-in.
	if _, err := s.Approve(req.ID, "carol"); err != nil {
		t.Fatalf("Approve without a configured GroupLookup must behave as plain four-eyes: %v", err)
	}
}

func TestFileStore_ApproveGroupScoped_SessionKindUnaffected(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s.SetGroupLookup(&fakeGroupLookup{groups: map[string][]string{"carol": {"engineering"}}})

	req, err := s.Create(Request{Kind: KindSession, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "db1.lab.local:22"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// KindSession must NOT be group-scoped even with a GroupLookup configured
	// and RequesterGroups set — the design scopes this narrowly to
	// KindQuarantineRelease only.
	if _, err := s.Approve(req.ID, "carol"); err != nil {
		t.Fatalf("KindSession approvals must stay plain four-eyes: %v", err)
	}
}
```

Add the imports `"context"`, `"errors"` (if not already present) to `internal/approval/filestore_test.go`.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/approval/... -run TestFileStore_ApproveGroupScoped -v`
Expected: FAIL — `Request.RequesterGroups`, `SetGroupLookup`, `ErrNotPeerGroup` undefined

- [ ] **Step 3: Add the types and error**

In `internal/approval/approval.go`, add to `Request` (after `Subject`):

```go
	// RequesterGroups is a snapshot, taken at Create time, of the requester's
	// AD groups that actually granted them access for this request's subject
	// (policy.Decision.MatchedGroups — not their full group list). Used for
	// group-scoped four-eyes on KindQuarantineRelease requests: the approver
	// must currently belong to one of these groups. Empty for request kinds
	// that don't use group-scoped approval, or when the deployment hasn't
	// wired a GroupLookup (see FileStore.SetGroupLookup) — in both cases
	// Approve falls back to plain four-eyes (approver != requester).
	RequesterGroups []string `json:"requester_groups,omitempty"`
```

Add a new error next to `ErrFourEyes`:

```go
// ErrNotPeerGroup is returned when group-scoped four-eyes is active for this
// request (a GroupLookup is configured AND the request has RequesterGroups)
// and the approver's current AD groups do not overlap RequesterGroups. This
// is checked in ADDITION to, not instead of, the plain four-eyes check.
var ErrNotPeerGroup = errors.New("approval: approver is not a member of the requester's role-granting group")
```

Add the `GroupLookup` interface after the `Store` interface:

```go
// GroupLookup resolves a user's CURRENT AD group membership, for
// group-scoped four-eyes on quarantine-release approvals. internal/approval
// defines this interface itself (rather than importing internal/authn's
// concrete LDAP client) to stay a leaf package — the composition root
// (cmd/omni-sag/main.go) wires a real implementation in via
// FileStore.SetGroupLookup, the same dependency-injection pattern
// internal/credential uses for its CyberArk Fetcher.
type GroupLookup interface {
	Groups(ctx context.Context, username string) ([]string, error)
}
```

- [ ] **Step 4: Add `SetGroupLookup` and the group-check to `FileStore`**

In `internal/approval/filestore.go`, add a field to `FileStore`:

```go
	groupLookup GroupLookup // optional; nil disables group-scoped four-eyes (plain four-eyes only)
```

Add the setter (kept separate from `NewFileStore`'s signature so the ~10 existing call sites across the codebase that construct a `FileStore` with just a path continue compiling unchanged):

```go
// SetGroupLookup enables group-scoped four-eyes for KindQuarantineRelease
// approvals: Approve additionally requires the approver's current AD groups
// (resolved via gl) to overlap the request's RequesterGroups. Call once,
// before serving traffic; nil (the default, if never called) keeps every
// request kind on plain four-eyes only (approver != requester) — see this
// method's doc and the plan's Global Constraints for why that's the correct
// default, not a silent weakening.
func (s *FileStore) SetGroupLookup(gl GroupLookup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groupLookup = gl
}
```

In `decide`, after the existing four-eyes check and before `r.Status = status`, add the group-scoped check:

```go
	// Four-eyes: the approver must be a distinct actor from the requester.
	// Identifiers are canonicalized (trim + lowercase) so case/whitespace
	// variants cannot smuggle a self-approval. NOTE: this compares the API
	// subject (token subject / mTLS CN) against the SSH principal that made the
	// request — the deployment MUST configure API subjects to equal SSH login
	// names, or four-eyes can be defeated across the two namespaces.
	if approver == "" || canonicalID(approver) == canonicalID(r.Requester) {
		return Request{}, ErrFourEyes
	}
	// Group-scoped four-eyes (additive, opt-in — see SetGroupLookup's doc):
	// only for an APPROVE decision on a KindQuarantineRelease request that
	// actually has a RequesterGroups snapshot, and only when a GroupLookup is
	// configured. A live lookup failure fails closed (refuses), never falls
	// back to plain four-eyes — that would silently weaken a check the
	// deployment explicitly opted into.
	if status == StatusApproved && r.Kind == KindQuarantineRelease && len(r.RequesterGroups) > 0 && s.groupLookup != nil {
		approverGroups, gerr := s.groupLookup.Groups(context.Background(), approver)
		if gerr != nil {
			return Request{}, fmt.Errorf("%w: group lookup failed: %v", ErrNotPeerGroup, gerr)
		}
		if !groupsOverlap(approverGroups, r.RequesterGroups) {
			return Request{}, ErrNotPeerGroup
		}
	}
```

Add the helper (place near `canonicalID`):

```go
// groupsOverlap reports whether a and b share at least one entry,
// case-insensitively.
func groupsOverlap(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, g := range a {
		set[canonicalID(g)] = true
	}
	for _, g := range b {
		if set[canonicalID(g)] {
			return true
		}
	}
	return false
}
```

`decide` currently takes `s.mu` locked for its whole body (confirm this by reading the current function) — the `s.groupLookup.Groups(...)` call is a live network call (LDAP), so holding `s.mu` across it would block every other `Get`/`List`/`Create`/`Wait` on this store for the LDAP round-trip's duration. Read `s.groupLookup` into a local variable while still holding the lock (a single pointer read, cheap), then release the lock before calling `Groups`, then re-acquire before writing the decision — restructure `decide`'s locking to match this shape rather than holding `s.mu` through the network call. Verify the final structure doesn't reintroduce a TOCTOU gap on the request's pending-ness (re-check `r.EffectiveStatus` is still `StatusPending` after re-acquiring the lock, before writing the decision, in case another decision raced in during the unlocked LDAP call).

- [ ] **Step 5: Run the approval package tests, verify pass**

Run: `go test ./internal/approval/... -v -race 2>&1 | tail -60`
Expected: PASS — all five new tests, and every pre-existing test in this package unchanged (confirms the opt-in/additive property)

- [ ] **Step 6: Commit**

```bash
git add internal/approval/approval.go internal/approval/filestore.go internal/approval/filestore_test.go
git commit -m "feat: group-scoped four-eyes for KindQuarantineRelease approvals"
```

---

### Task 4: `internal/release` — the pull-download release store

**Files:**
- Create: `internal/release/release.go`
- Create: `internal/release/filestore.go`
- Create: `internal/release/filestore_test.go`

**Interfaces:**
- Produces: `release.Release` struct, `release.Store` interface, `release.NewFileStore(path string) (*release.FileStore, error)`

A release is much simpler than an approval request: no four-eyes, no blocking `Wait`, just create-list-expire. Modeled closely on `approval.FileStore` for the durability pattern (atomic JSON writes) but with a smaller interface.

- [ ] **Step 1: Write the failing tests**

Create `internal/release/filestore_test.go`:

```go
package release

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileStore_CreateAndListFor(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s, err := newFileStore(filepath.Join(t.TempDir(), "r.json"), func() time.Time { return now })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	rel, err := s.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice", OriginalFilename: "report.csv"}, 6*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rel.ExpiresAt.Sub(rel.ApprovedAt) != 6*time.Hour {
		t.Fatalf("ExpiresAt-ApprovedAt = %v, want 6h", rel.ExpiresAt.Sub(rel.ApprovedAt))
	}

	list := s.ListFor("alice", now)
	if len(list) != 1 || list[0].QuarantineKey != "quarantine/k1" {
		t.Fatalf("ListFor(alice) = %v, want exactly the one release just created", list)
	}
	if got := s.ListFor("bob", now); len(got) != 0 {
		t.Fatalf("ListFor(bob) = %v, want empty — releases are scoped to their own requester", got)
	}
}

func TestFileStore_ListForExcludesExpired(t *testing.T) {
	created := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s, err := newFileStore(filepath.Join(t.TempDir(), "r.json"), func() time.Time { return created })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	if _, err := s.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice"}, time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}
	afterExpiry := created.Add(2 * time.Hour)
	if got := s.ListFor("alice", afterExpiry); len(got) != 0 {
		t.Fatalf("ListFor after expiry = %v, want empty", got)
	}
}

func TestFileStore_GetRespectsRequesterAndExpiry(t *testing.T) {
	created := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s, err := newFileStore(filepath.Join(t.TempDir(), "r.json"), func() time.Time { return created })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	rel, err := s.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice", OriginalFilename: "report.csv"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, ok := s.Get("alice", rel.ID, created); !ok {
		t.Fatal("Get(alice, ..., within window) should find the release")
	}
	if _, ok := s.Get("bob", rel.ID, created); ok {
		t.Fatal("Get(bob, ...) must not find alice's release — identity check")
	}
	if _, ok := s.Get("alice", rel.ID, created.Add(2*time.Hour)); ok {
		t.Fatal("Get(alice, ..., after expiry) must not find it")
	}
}

func TestFileStore_UnlimitedReadsWithinWindow(t *testing.T) {
	created := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s, err := newFileStore(filepath.Join(t.TempDir(), "r.json"), func() time.Time { return created })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	rel, err := s.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, ok := s.Get("alice", rel.ID, created.Add(30*time.Minute)); !ok {
			t.Fatalf("read #%d: expected the release to still be gettable (unlimited reads within window)", i)
		}
	}
}

func TestFileStore_PersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s1, err := newFileStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	if _, err := s1.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice"}, time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}

	s2, err := newFileStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := s2.ListFor("alice", now); len(got) != 1 {
		t.Fatalf("after reopen, ListFor(alice) = %v, want the persisted release", got)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/release/... -v`
Expected: FAIL — package `internal/release` does not exist

- [ ] **Step 3: Implement `release.go`**

Create `internal/release/release.go`:

```go
// Package release tracks approved-and-pending-pickup SFTP uploads: once a
// KindQuarantineRelease approval is granted, the gateway records a Release
// here instead of pushing the file to the real target — the SAME uploader
// retrieves it themselves later via a browsable /releases SFTP directory,
// within a bounded window.
//
// It is a LEAF, same constraint and same reason as internal/approval: it
// must not import internal/session or internal/api, so the SSH data path can
// use it without depending on the control plane.
//
// Unlike internal/approval, a Release has no four-eyes and no blocking Wait
// — it is a simple create/list/get/expire record, not a decision gate. The
// decision (whether to release at all) already happened in
// internal/approval; this package only tracks what happens after "yes."
package release

import "time"

// Release is one approved-and-pending-pickup upload.
type Release struct {
	ID                string    `json:"id"`
	QuarantineKey     string    `json:"quarantine_key"`
	Requester         string    `json:"requester"`          // must match the retrieving session's identity
	OriginalFilename  string    `json:"original_filename"`  // for display in /releases
	ApprovedAt        time.Time `json:"approved_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// Store persists releases. Implementations must be safe for concurrent use.
type Store interface {
	// Create records a new release (assigns ID + ApprovedAt/ExpiresAt from
	// now+ttl) and persists it durably.
	Create(rel Release, ttl time.Duration) (Release, error)
	// ListFor returns requester's own non-expired releases as of now.
	ListFor(requester string, now time.Time) []Release
	// Get returns one release, but ONLY if it belongs to requester and has
	// not expired as of now — both checks are enforced here, not left to the
	// caller, since this is the identity+expiry gate the design requires on
	// every access.
	Get(requester, id string, now time.Time) (Release, bool)
}
```

- [ ] **Step 4: Implement `filestore.go`**

Create `internal/release/filestore.go`, modeled on `approval.FileStore`'s durability pattern (atomic temp+fsync+rename) but without the decided-channel/four-eyes machinery:

```go
package release

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FileStore is a durable release store backed by a single JSON file.
type FileStore struct {
	path string
	now  func() time.Time

	mu       sync.Mutex
	releases map[string]*Release
}

// NewFileStore opens (creating if absent) the store at path and loads any
// existing releases.
func NewFileStore(path string) (*FileStore, error) {
	return newFileStore(path, time.Now)
}

func newFileStore(path string, now func() time.Time) (*FileStore, error) {
	s := &FileStore{path: path, now: now, releases: map[string]*Release{}}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("release: read store: %w", err)
	}
	var rels []Release
	if len(data) > 0 {
		if err := json.Unmarshal(data, &rels); err != nil {
			return nil, fmt.Errorf("release: parse store: %w", err)
		}
	}
	for i := range rels {
		r := rels[i]
		s.releases[r.ID] = &r
	}
	return s, nil
}

// terminalRetention bounds how long an EXPIRED release stays in the durable
// file before being pruned — mirrors approval.FileStore's terminalRetention,
// same reasoning (bounded rewrite cost), but note the underlying quarantine
// bytes are untouched either way (WORM) — this only prunes the release
// POINTER record, never the audit copy.
const terminalRetention = 24 * time.Hour

func (s *FileStore) persist() error {
	s.pruneLocked()
	out := make([]Release, 0, len(s.releases))
	for _, r := range s.releases {
		out = append(out, *r)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeFileDurable(s.path, data, 0o600)
}

func (s *FileStore) pruneLocked() {
	now := s.now()
	for id, r := range s.releases {
		if now.After(r.ExpiresAt.Add(terminalRetention)) {
			delete(s.releases, id)
		}
	}
}

// Create records a new release.
func (s *FileStore) Create(rel Release, ttl time.Duration) (Release, error) {
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	now := s.now().UTC()
	rel.ID = uuid.NewString()
	rel.ApprovedAt = now
	rel.ExpiresAt = now.Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()
	r := rel
	s.releases[rel.ID] = &r
	if err := s.persist(); err != nil {
		delete(s.releases, rel.ID)
		return Release{}, fmt.Errorf("release: create: %w", err)
	}
	return r, nil
}

// ListFor returns requester's own non-expired releases as of now.
func (s *FileStore) ListFor(requester string, now time.Time) []Release {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Release
	for _, r := range s.releases {
		if r.Requester == requester && now.Before(r.ExpiresAt) {
			out = append(out, *r)
		}
	}
	return out
}

// Get returns one release, only if it belongs to requester and is unexpired.
func (s *FileStore) Get(requester, id string, now time.Time) (Release, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.releases[id]
	if !ok || r.Requester != requester || !now.Before(r.ExpiresAt) {
		return Release{}, false
	}
	return *r, true
}

// writeFileDurable writes data to path atomically and durably — identical
// implementation to approval.FileStore's helper of the same name; duplicated
// rather than shared to keep internal/release independent of
// internal/approval (both are leaves, neither should depend on the other).
func writeFileDurable(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".release-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
```

- [ ] **Step 5: Run the release package tests, verify pass**

Run: `go test ./internal/release/... -v -race 2>&1 | tail -60`
Expected: PASS, all five tests

- [ ] **Step 6: Commit**

```bash
git add internal/release/
git commit -m "feat: internal/release — durable store for approved pull-download releases"
```

---

### Task 5: Wire `release.Store` into `Server`, thread `MatchedGroups` into the SFTP path

**Files:**
- Modify: `internal/session/session.go`
- Modify: `internal/session/sftp.go`
- Test: `internal/session/sftp_test.go`

**Interfaces:**
- Produces: `session.WithReleases(store release.Store, ttl time.Duration) Option`
- Consumes: `release.Store` (Task 4), `policy.Decision.MatchedGroups` (Task 1)

This task only wires the new dependencies through to where `runSFTP`/`remoteFS` can reach them — it does NOT yet change delivery behavior (that's Task 6).

- [ ] **Step 1: Write the failing test**

Add to `internal/session/sftp_test.go` (or wherever `WithApprovals`-style option tests live — check the file first):

```go
func TestWithReleases_SetsFieldsOnServer(t *testing.T) {
	store, err := release.NewFileStore(filepath.Join(t.TempDir(), "r.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	s := &Server{}
	WithReleases(store, 6*time.Hour)(s)
	if s.releases != store {
		t.Fatal("WithReleases did not set s.releases")
	}
	if s.releaseTTL != 6*time.Hour {
		t.Fatalf("s.releaseTTL = %v, want 6h", s.releaseTTL)
	}
}
```

Add the import `"github.com/rupivbluegreen/omni-sag/internal/release"` to the test file.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestWithReleases -v`
Expected: FAIL — `WithReleases`, `s.releases`, `s.releaseTTL` undefined

- [ ] **Step 3: Implement it**

In `internal/session/session.go`, add to `Server` (near `approvals`/`approvalTTL`):

```go
	releases   release.Store // optional; required for the /releases pull-download directory
	releaseTTL time.Duration // how long an approved release stays retrievable (design default: 6h)
```

Add the import `"github.com/rupivbluegreen/omni-sag/internal/release"`.

Add the option (near `WithApprovals`):

```go
// WithReleases enables the /releases pull-download SFTP directory: once a
// quarantine-release approval is granted, the uploader retrieves the file
// themselves within ttl instead of it being auto-delivered to the target.
// Nil store (the default) means Filewrite's approved branch has nowhere to
// record a release — see Task 6 for the resulting fail-closed behavior.
func WithReleases(store release.Store, ttl time.Duration) Option {
	return func(s *Server) { s.releases = store; s.releaseTTL = ttl }
}
```

- [ ] **Step 4: Thread `MatchedGroups` and `s.releases`/`s.releaseTTL` into `remoteFS`**

In `internal/session/sftp.go`, add fields to `remoteFS`:

```go
	matchedGroups []string      // decision.MatchedGroups for this session's target — snapshotted onto release requests for group-scoped four-eyes
	releases      release.Store // for recording approved releases and serving /releases; nil disables the pull-download flow
	releaseTTL    time.Duration
```

Add the import `"github.com/rupivbluegreen/omni-sag/internal/release"`.

In `runSFTP`, the `remoteFS{...}` construction currently reads:

```go
	fs := &remoteFS{client: sftpClient, gate: s.inspect, srv: s, user: pr.User, srcIP: srcIP, ctx: connCtx}
```

Change to:

```go
	fs := &remoteFS{
		client: sftpClient, gate: s.inspect, srv: s, user: pr.User, srcIP: srcIP, ctx: connCtx,
		matchedGroups: decision.MatchedGroups, releases: s.releases, releaseTTL: s.releaseTTL,
	}
```

(`decision` is already in scope in `runSFTP` — it's the `policy.Decision` computed earlier in the function via `s.dialerPeek`.)

- [ ] **Step 5: Run the tests, verify pass**

Run: `go test ./internal/session/... -v 2>&1 | tail -60`
Expected: PASS — the new test, and no regressions (this task only threads data through, doesn't change any existing behavior yet)

- [ ] **Step 6: Commit**

```bash
git add internal/session/session.go internal/session/sftp.go internal/session/sftp_test.go
git commit -m "feat: wire release.Store and MatchedGroups into the SFTP path"
```

---

### Task 6: Rewire `Filewrite`'s approved branch — record a release, don't push to target

**Files:**
- Modify: `internal/session/sftp.go`
- Test: `internal/session/sftp_test.go`

**Interfaces:**
- Consumes: `s.releases`, `s.releaseTTL`, `fs.matchedGroups` (Task 5)
- Modifies existing behavior: `quarantineWriteHandle.doClose()`'s approved branch

This is the core delivery-model change. Everything up through "approved" in `doClose` stays exactly as Task 11 built it (inspect → quarantine → create `KindQuarantineRelease` request with the release-specific TTL → block on `Wait`). Only what happens AFTER approval changes.

- [ ] **Step 1: Write the failing tests**

Add to `internal/session/sftp_test.go` (these replace/sit alongside Task 11's existing `TestQuarantineWriteHandle_ApprovedDeliversToTarget` — read that test first, since this task changes what "approved" does; the OLD test asserted delivery to the target and must be updated, not left contradicting the new behavior):

```go
func TestQuarantineWriteHandle_ApprovedRecordsReleaseNotPush(t *testing.T) {
	quar := newFakeBlobStore()
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	approvals, err := approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatalf("approval.NewFileStore: %v", err)
	}
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	s := &Server{sink: noopSink{}, inspect: g, approvals: approvals, approvalTTL: 5 * time.Second, releases: releases, releaseTTL: 6 * time.Hour}
	fs := &remoteFS{client: targetClient, gate: g, srv: s, user: "alice", matchedGroups: []string{"dba"}, releases: releases, releaseTTL: 6 * time.Hour}

	h, _ := fs.Filewrite(&sftpPkg.Request{Method: "Put", Filepath: "/upload.txt"})
	if _, err := h.WriteAt([]byte("clean content"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	closeErr := make(chan error, 1)
	go func() { closeErr <- h.(io.Closer).Close() }()

	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reqID == "" {
		for _, r := range approvals.List() {
			if r.Kind == approval.KindQuarantineRelease && r.Status == approval.StatusPending {
				reqID = r.ID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("no pending release request")
	}
	if _, err := approvals.Approve(reqID, "bob"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := <-closeErr; err != nil {
		t.Fatalf("Close after approval: %v", err)
	}

	// The target must NEVER have received the file — this is the core
	// behavior change: pull, not push.
	if _, err := targetClient.Open("/upload.txt"); err == nil {
		t.Fatal("approved upload must NOT be delivered to the target — pull-download model, not push")
	}
	// A release must exist for alice, listing the original filename.
	list := releases.ListFor("alice", time.Now())
	if len(list) != 1 {
		t.Fatalf("releases.ListFor(alice) = %v, want exactly one release", list)
	}
	if list[0].OriginalFilename != "/upload.txt" {
		t.Fatalf("release.OriginalFilename = %q, want /upload.txt", list[0].OriginalFilename)
	}
}

func TestQuarantineWriteHandle_ApprovedButNoReleaseStoreConfiguredFailsClosed(t *testing.T) {
	quar := newFakeBlobStore()
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	approvals, err := approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatalf("approval.NewFileStore: %v", err)
	}
	// No releases store configured — s.releases is nil.
	s := &Server{sink: noopSink{}, inspect: g, approvals: approvals, approvalTTL: 5 * time.Second}
	fs := &remoteFS{client: targetClient, gate: g, srv: s, user: "alice"}

	h, _ := fs.Filewrite(&sftpPkg.Request{Method: "Put", Filepath: "/upload.txt"})
	_, _ = h.WriteAt([]byte("clean content"), 0)

	closeErr := make(chan error, 1)
	go func() { closeErr <- h.(io.Closer).Close() }()

	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reqID == "" {
		for _, r := range approvals.List() {
			if r.Kind == approval.KindQuarantineRelease && r.Status == approval.StatusPending {
				reqID = r.ID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("no pending release request")
	}
	if _, err := approvals.Approve(reqID, "bob"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := <-closeErr; err == nil {
		t.Fatal("Close must fail closed when approved but no release store is configured to record it")
	}
}
```

Add imports `sftpPkg "github.com/pkg/sftp"` reconciliation note as in earlier tasks — this repo's `sftp.go`/`sftp_test.go` already import `github.com/pkg/sftp` unaliased as `sftp`; use that existing import for `sftp.Request`/`sftp.NewClient` and rename any locally-conflicting variable instead of introducing an alias (as established in Task 11's own file). Add `"github.com/rupivbluegreen/omni-sag/internal/release"` to the test file's imports.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestQuarantineWriteHandle_Approved -v`
Expected: FAIL — the first new test fails because the current code still pushes to the target (the `targetClient.Open` check finds the file); the second fails because there's currently no "no release store" fail-closed path

- [ ] **Step 3: Rewire `doClose`**

In `internal/session/sftp.go`, `quarantineWriteHandle.doClose`'s current approved-path tail reads:

```go
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
		User: h.fs.user, SourceIP: h.fs.srcIP, Path: h.path, Direction: "upload",
		Bytes: dec.Bytes, SHA256: dec.SHA256, ObjectKey: dec.QuarantineKey,
		Detail: "sftp transfer (released from quarantine)",
	})
	return nil
```

Replace it with:

```go
	if h.fs.releases == nil {
		return fmt.Errorf("sftp: upload %s approved for release (key=%s) but no release store is configured", h.path, dec.QuarantineKey)
	}
	rel, err := h.fs.releases.Create(release.Release{
		QuarantineKey:    dec.QuarantineKey,
		Requester:        h.fs.user,
		OriginalFilename: h.path,
	}, h.fs.releaseTTL)
	if err != nil {
		return fmt.Errorf("sftp: record release for %s: %w", h.path, err)
	}

	h.fs.srv.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeTransfer,
		User: h.fs.user, SourceIP: h.fs.srcIP, Path: h.path, Direction: "released",
		Bytes: dec.Bytes, SHA256: dec.SHA256, ObjectKey: dec.QuarantineKey,
		Detail: fmt.Sprintf("released to /releases (id=%s, expires=%s) — pull-download by %s, not pushed to target", rel.ID, rel.ExpiresAt.Format(time.RFC3339), h.fs.user),
	})
	return nil
```

Add the import `"github.com/rupivbluegreen/omni-sag/internal/release"`.

Also update the `approval.Request{...}` literal a few lines earlier in `doClose` (the `Create` call that makes the `KindQuarantineRelease` request) to snapshot `RequesterGroups`:

```go
	req, err := h.fs.srv.approvals.Create(approval.Request{
		Kind:            approval.KindQuarantineRelease,
		Requester:       h.fs.user,
		RequesterGroups: h.fs.matchedGroups,
		Subject:         dec.QuarantineKey,
		Reason:          fmt.Sprintf("release %s to %s", dec.QuarantineKey, h.path),
	}, h.fs.srv.approvalTTL)
```

- [ ] **Step 4: Run the tests, verify pass**

Run: `go test ./internal/session/... -run TestQuarantineWriteHandle -v 2>&1 | tail -80`
Expected: PASS — both new tests. The PRE-EXISTING `TestQuarantineWriteHandle_ApprovedDeliversToTarget` (Task 11) will now FAIL, since it asserts the old push-to-target behavior — this is expected and correct: update that test's assertions to match the new behavior (it becomes redundant with `TestQuarantineWriteHandle_ApprovedRecordsReleaseNotPush` above — either delete the old test and keep the new one, or rename/repurpose the old one; don't leave two tests asserting contradictory things). `TestQuarantineWriteHandle_DeniedNeverReachesTarget` and `TestQuarantineWriteHandle_AutoDeniedWithNoApprovalStoreFailsClosed` (Task 11, both about the denied/no-approval-store paths, untouched by this task's change) must still pass unmodified.

- [ ] **Step 5: Run the full session package suite**

Run: `go build ./... && go test ./internal/session/... -v -race 2>&1 | tail -100`
Expected: build succeeds, all tests pass

- [ ] **Step 6: Commit**

```bash
git add internal/session/sftp.go internal/session/sftp_test.go
git commit -m "feat: approved SFTP uploads record a pull-download release, no longer push to target"
```

---

### Task 7: The `/releases` virtual SFTP directory

**Files:**
- Modify: `internal/session/sftp.go`
- Test: `internal/session/sftp_test.go`

**Interfaces:**
- Consumes: `remoteFS.releases` (Task 5/6)
- Modifies existing behavior: `remoteFS.Fileread`, `remoteFS.Filelist`; adds refusal behavior to `remoteFS.Filecmd`/`Filewrite` for paths under `/releases`

- [ ] **Step 1: Write the failing tests**

Add to `internal/session/sftp_test.go`:

```go
func TestRemoteFS_ReleasesDirectory_ListsOwnReleasesOnly(t *testing.T) {
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	if _, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice", OriginalFilename: "report.csv"}, time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := releases.Create(release.Release{QuarantineKey: "q/k2", Requester: "bob", OriginalFilename: "secret.txt"}, time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}

	fs := &remoteFS{user: "alice", releases: releases}
	listing, err := fs.Filelist(&sftpPkg.Request{Method: "List", Filepath: "/releases"})
	if err != nil {
		t.Fatalf("Filelist: %v", err)
	}
	infos := make([]os.FileInfo, 8)
	n, _ := listing.ListAt(infos, 0)
	if n != 1 {
		t.Fatalf("got %d entries, want exactly 1 (alice's own release, not bob's)", n)
	}
}

func TestRemoteFS_ReleasesDirectory_ReadStreamsFromQuarantine(t *testing.T) {
	quar := newFakeBlobStore()
	if err := quar.Put(context.Background(), "q/k1", "application/octet-stream", strings.NewReader("secret report"), -1); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
	g, err := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	if err != nil {
		t.Fatalf("inspectgate.New: %v", err)
	}
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice", OriginalFilename: "report.csv"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fs := &remoteFS{user: "alice", releases: releases, gate: g, ctx: context.Background()}
	r, err := fs.Fileread(&sftpPkg.Request{Method: "Get", Filepath: "/releases/" + rel.ID})
	if err != nil {
		t.Fatalf("Fileread: %v", err)
	}
	buf := make([]byte, 32)
	n, _ := r.ReadAt(buf, 0)
	if got := string(buf[:n]); got != "secret report" {
		t.Fatalf("got %q, want %q", got, "secret report")
	}
}

func TestRemoteFS_ReleasesDirectory_WrongUserCannotRead(t *testing.T) {
	quar := newFakeBlobStore()
	_ = quar.Put(context.Background(), "q/k1", "application/octet-stream", strings.NewReader("secret"), -1)
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fs := &remoteFS{user: "mallory", releases: releases, gate: g, ctx: context.Background()}
	if _, err := fs.Fileread(&sftpPkg.Request{Method: "Get", Filepath: "/releases/" + rel.ID}); err == nil {
		t.Fatal("a different user must not be able to read alice's release")
	}
}

func TestRemoteFS_ReleasesDirectory_ExpiredCannotBeRead(t *testing.T) {
	quar := newFakeBlobStore()
	_ = quar.Put(context.Background(), "q/k1", "application/octet-stream", strings.NewReader("secret"), -1)
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice"}, time.Millisecond)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	fs := &remoteFS{user: "alice", releases: releases, gate: g, ctx: context.Background()}
	if _, err := fs.Fileread(&sftpPkg.Request{Method: "Get", Filepath: "/releases/" + rel.ID}); err == nil {
		t.Fatal("an expired release must not be readable, even by its own requester")
	}
}

func TestRemoteFS_ReleasesDirectory_UnlimitedReadsWithinWindow(t *testing.T) {
	quar := newFakeBlobStore()
	_ = quar.Put(context.Background(), "q/k1", "application/octet-stream", strings.NewReader("secret"), -1)
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fs := &remoteFS{user: "alice", releases: releases, gate: g, ctx: context.Background()}
	for i := 0; i < 3; i++ {
		if _, err := fs.Fileread(&sftpPkg.Request{Method: "Get", Filepath: "/releases/" + rel.ID}); err != nil {
			t.Fatalf("read #%d: %v", i, err)
		}
	}
}

func TestRemoteFS_ReleasesDirectory_WriteRefused(t *testing.T) {
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	fs := &remoteFS{user: "alice", releases: releases}
	if _, err := fs.Filewrite(&sftpPkg.Request{Method: "Put", Filepath: "/releases/anything"}); err == nil {
		t.Fatal("writing under /releases must be refused — it's a read-only virtual namespace")
	}
}

func TestRemoteFS_ReleasesDirectory_FilecmdRefused(t *testing.T) {
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	fs := &remoteFS{user: "alice", releases: releases}
	if err := fs.Filecmd(&sftpPkg.Request{Method: "Remove", Filepath: "/releases/anything"}); err == nil {
		t.Fatal("Filecmd under /releases must be refused")
	}
}
```

Add imports `"context"`, `"strings"`, `"github.com/rupivbluegreen/omni-sag/internal/release"` to the test file if not already present.

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/session/... -run TestRemoteFS_ReleasesDirectory -v`
Expected: FAIL — `/releases` paths currently fall through to proxying against `fs.client` (nil in these tests), or simply aren't special-cased at all

- [ ] **Step 3: Implement it**

In `internal/session/sftp.go`, add a small helper near `cleanPath`:

```go
// releasesPrefix is the virtual SFTP directory serving approved
// pull-download releases — see remoteFS.Fileread/Filelist.
const releasesPrefix = "/releases"

func isReleasesPath(p string) bool {
	return p == releasesPrefix || strings.HasPrefix(p, releasesPrefix+"/")
}

// releaseIDFrom extracts the release ID from a /releases/<id> path. Returns
// "" for the bare /releases directory itself.
func releaseIDFrom(p string) string {
	if p == releasesPrefix {
		return ""
	}
	return strings.TrimPrefix(p, releasesPrefix+"/")
}
```

Add the import `"strings"` if not already present.

Modify `Fileread` to check `/releases` first:

```go
func (fs *remoteFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	p := cleanPath(r.Filepath)
	if isReleasesPath(p) {
		return fs.readRelease(p)
	}
	f, err := fs.client.Open(p)
	if err != nil {
		return nil, err
	}
	return newDownloadTap(f, p, fs), nil
}

// readRelease serves a /releases/<id> read: the release must belong to fs.user
// and not be expired (both checked fresh on every access, per the design —
// a release may be read any number of times within its window from any
// number of separate SFTP sessions), then streams directly from the WORM
// quarantine store — the same Gate.QuarantineReader Filewrite's delivery
// path already used before this feature existed, just now serving the
// UPLOADER instead of the target.
func (fs *remoteFS) readRelease(p string) (io.ReaderAt, error) {
	if fs.releases == nil {
		return nil, fmt.Errorf("sftp: /releases is not enabled")
	}
	id := releaseIDFrom(p)
	if id == "" {
		return nil, fmt.Errorf("sftp: %s is a directory", p)
	}
	rel, ok := fs.releases.Get(fs.user, id, time.Now())
	if !ok {
		return nil, os.ErrNotExist
	}
	if fs.gate == nil {
		return nil, fmt.Errorf("sftp: /releases is not enabled")
	}
	rc, err := fs.gate.QuarantineReader(fs.ctxOrBackground(), rel.QuarantineKey)
	if err != nil {
		return nil, fmt.Errorf("sftp: read release %s: %w", id, err)
	}
	return &readCloserAtAdapter{rc: rc}, nil
}
```

`Gate.QuarantineReader` returns an `io.ReadCloser`, but `sftp.Handlers.FileGet` needs an `io.ReaderAt` — check `internal/inspectgate/gate.go`'s current `QuarantineReader` signature to confirm this (it should be unchanged from Task 11), and add a small adapter since a `ReadCloser` from an S3 GET is not naturally seekable/`ReaderAt`-capable:

```go
// readCloserAtAdapter adapts a sequential io.ReadCloser (an S3 GET stream —
// not seekable) to io.ReaderAt by buffering it fully into memory on first
// use. This is acceptable here specifically because it mirrors what
// Filewrite's OWN delivery step already did before this feature (Task 11's
// io.Copy read the whole quarantined object once, sequentially) — a release
// download is the same shape of read, just now going to the uploader instead
// of the target, and quarantined content already has a size ceiling enforced
// upstream by inspectgate's small/large split. A production hardening pass
// could instead track an offset-ordered read the way downloadTap does for
// real target reads, if quarantine objects large enough to matter in memory
// are expected in practice — out of scope for this task.
type readCloserAtAdapter struct {
	rc  io.ReadCloser
	buf []byte
	err error
	once sync.Once
}

func (a *readCloserAtAdapter) ReadAt(p []byte, off int64) (int, error) {
	a.once.Do(func() {
		a.buf, a.err = io.ReadAll(a.rc)
		_ = a.rc.Close()
	})
	if a.err != nil {
		return 0, a.err
	}
	if off >= int64(len(a.buf)) {
		return 0, io.EOF
	}
	n := copy(p, a.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
```

Modify `Filelist` to check `/releases` first:

```go
func (fs *remoteFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	p := cleanPath(r.Filepath)
	if isReleasesPath(p) {
		return fs.listReleases(r.Method)
	}
	switch r.Method {
	case "List":
		infos, err := fs.client.ReadDir(p)
		if err != nil {
			return nil, err
		}
		out := make([]os.FileInfo, len(infos))
		copy(out, infos)
		return listerAt(out), nil
	case "Stat":
		info, err := fs.client.Stat(p)
		if err != nil {
			return nil, err
		}
		return listerAt{info}, nil
	}
	return nil, fmt.Errorf("sftp: unsupported list method %q", r.Method)
}

// listReleases serves the /releases directory listing — scoped to fs.user's
// own non-expired releases only.
func (fs *remoteFS) listReleases(method string) (sftp.ListerAt, error) {
	if fs.releases == nil {
		return nil, fmt.Errorf("sftp: /releases is not enabled")
	}
	list := fs.releases.ListFor(fs.user, time.Now())
	infos := make([]os.FileInfo, len(list))
	for i, r := range list {
		infos[i] = releaseFileInfo{rel: r}
	}
	if method == "Stat" {
		// Stat on the bare /releases directory itself.
		return listerAt{releaseDirInfo{}}, nil
	}
	return listerAt(infos), nil
}
```

Add two small `os.FileInfo` implementations near `memFileInfo` (check if `memFileInfo` still exists post-Task-11's `memFS` deletion — if it was removed, follow whatever `os.FileInfo` implementation pattern `remoteFS`'s existing code already uses for `Filelist`'s "Stat on /" case, or add a minimal one matching that shape):

```go
// releaseFileInfo presents one Release as an os.FileInfo entry in /releases.
type releaseFileInfo struct{ rel release.Release }

func (i releaseFileInfo) Name() string       { return i.rel.OriginalFilename }
func (i releaseFileInfo) Size() int64        { return 0 } // unknown without a HEAD on quarantine; acceptable for a listing
func (i releaseFileInfo) Mode() os.FileMode  { return 0o444 }
func (i releaseFileInfo) ModTime() time.Time { return i.rel.ApprovedAt }
func (i releaseFileInfo) IsDir() bool        { return false }
func (i releaseFileInfo) Sys() interface{}   { return nil }

// releaseDirInfo represents the /releases directory itself for Stat.
type releaseDirInfo struct{}

func (releaseDirInfo) Name() string       { return "releases" }
func (releaseDirInfo) Size() int64        { return 0 }
func (releaseDirInfo) Mode() os.FileMode  { return os.ModeDir | 0o555 }
func (releaseDirInfo) ModTime() time.Time { return time.Time{} }
func (releaseDirInfo) IsDir() bool        { return true }
func (releaseDirInfo) Sys() interface{}   { return nil }
```

Note: listing by `OriginalFilename` means a client sees a filename, not the release ID, in the directory listing — but `Fileread`/`readRelease` above key on ID (`releaseIDFrom`), not filename. Reconcile this: either (a) change `releaseFileInfo.Name()` to return `rel.ID` (less friendly but consistent with how `Fileread` addresses entries), or (b) make `readRelease` look up by filename instead of ID when the path segment isn't a valid ID shape. Prefer (a) for this task — simpler, no ambiguity if two releases share a filename — and note in a comment that the design's "shows OriginalFilename... so the user can recognize their own upload" is satisfied by ALSO embedding the filename in a listing detail humans can see via `ls -la`-style long-format SFTP clients showing size/mtime next to the name, even if the name itself is the ID; if this reads as a UX regression once implemented, revisit in a follow-up rather than blocking this task on it.

Finally, refuse `Filewrite`/`Filecmd` under `/releases`:

In `Filewrite`, add a check at the very top:

```go
func (fs *remoteFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if isReleasesPath(cleanPath(r.Filepath)) {
		return nil, fmt.Errorf("sftp: /releases is read-only")
	}
	// ... rest unchanged
```

In `Filecmd`, add the same check at the top:

```go
func (fs *remoteFS) Filecmd(r *sftp.Request) error {
	if isReleasesPath(cleanPath(r.Filepath)) {
		return fmt.Errorf("sftp: /releases is read-only")
	}
	// ... rest unchanged
```

- [ ] **Step 4: Run the tests, verify pass**

Run: `go test ./internal/session/... -run TestRemoteFS_ReleasesDirectory -v 2>&1 | tail -80`
Expected: PASS, all seven tests

- [ ] **Step 5: Run the full session package suite**

Run: `go build ./... && go test ./internal/session/... -v -race 2>&1 | tail -100`
Expected: build succeeds, all tests pass, no regressions to the real-target proxying paths this task didn't touch

- [ ] **Step 6: Commit**

```bash
git add internal/session/sftp.go internal/session/sftp_test.go
git commit -m "feat: browsable /releases SFTP directory for pull-download retrieval"
```

---

### Task 8: Config + API wiring

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`
- Modify: `internal/api/approvals.go`
- Modify: `cmd/omni-sag/main.go`

**Interfaces:**
- Produces: `config.ApprovalConfig.ReleaseTTLSeconds int`, `config.ApprovalConfig.ReleaseTTL() int`

- [ ] **Step 1: Write the failing config test**

Add to `internal/config/config_test.go`:

```go
func TestApprovalConfig_ReleaseTTL_Default(t *testing.T) {
	var a *ApprovalConfig
	if got := a.ReleaseTTL(); got != 86400 {
		t.Fatalf("ReleaseTTL() on nil config = %d, want 86400 (24h)", got)
	}
	a = &ApprovalConfig{}
	if got := a.ReleaseTTL(); got != 86400 {
		t.Fatalf("ReleaseTTL() on zero-value config = %d, want 86400", got)
	}
}

func TestApprovalConfig_ReleaseTTL_Configured(t *testing.T) {
	a := &ApprovalConfig{ReleaseTTLSeconds: 3600}
	if got := a.ReleaseTTL(); got != 3600 {
		t.Fatalf("ReleaseTTL() = %d, want 3600", got)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/config/... -run TestApprovalConfig_ReleaseTTL -v`
Expected: FAIL — `ReleaseTTLSeconds`/`ReleaseTTL` undefined

- [ ] **Step 3: Implement it**

In `internal/config/config.go`, add to `ApprovalConfig`:

```go
	ReleaseTTLSeconds int `yaml:"release_ttl_seconds"` // KindQuarantineRelease pending-request lifetime (default 86400 = 24h) — separate from ttl_seconds, which governs session-access approvals
```

Add the accessor, mirroring `ApprovalTTL`:

```go
// ReleaseTTL returns the configured quarantine-release approval TTL (in
// seconds) or the default (24h). Kept separate from ApprovalTTL, which
// governs session-access (KindSession) approvals — the two are expected to
// differ (a release approval is not time-critical the way logging into a
// live target is).
func (a *ApprovalConfig) ReleaseTTL() int {
	if a == nil || a.ReleaseTTLSeconds <= 0 {
		return 86400
	}
	return a.ReleaseTTLSeconds
}
```

- [ ] **Step 4: Run the config tests, verify pass**

Run: `go test ./internal/config/... -v 2>&1 | tail -30`
Expected: PASS

- [ ] **Step 5: Map `ErrNotPeerGroup` to HTTP 403 in the API**

In `internal/api/approvals.go`, `decideApproval`'s error switch currently has:

```go
	case errors.Is(err, approval.ErrFourEyes):
		writeError(w, http.StatusForbidden, "four-eyes: you may not decide your own request")
```

Add a case right after it:

```go
	case errors.Is(err, approval.ErrNotPeerGroup):
		writeError(w, http.StatusForbidden, "group-scoped four-eyes: you are not a member of the requester's role-granting group")
```

- [ ] **Step 6: Wire everything in `cmd/omni-sag/main.go`**

Read the current approval-store construction block in full before editing (it's the block starting `var approvalStore approval.Store` / `if cfg.Approval != nil { ... }`) — confirm it still matches what Task 11's own plan documented, since this is live composition-root code.

After the existing `fs, err := approval.NewFileStore(cfg.Approval.StorePath)` line (inside the `!cfg.Approval.UseCRD` branch), wire the LDAP-backed `GroupLookup` — but only if LDAPS auth is actually configured for this deployment (it always is today, per `authn.NewLDAP(authn.LDAPConfig{...})` already being unconditionally constructed earlier in `run()` — reuse that SAME `auth` variable rather than constructing a second `LDAPAuthenticator`):

```go
			fs.SetGroupLookup(auth) // auth is the *authn.LDAPAuthenticator already constructed above for SSH login; Groups() needs no extra wiring
			approvalStore = fs
```

(`auth` must satisfy `approval.GroupLookup`'s one-method interface — `Groups(ctx, username) ([]string, error)` — which Task 2 added to `*authn.LDAPAuthenticator`; Go's structural interface satisfaction means no explicit assertion is needed, but verify `auth`'s declared type at this point in `main.go` is `*authn.LDAPAuthenticator`, not a narrower interface type that doesn't expose `Groups` — read the surrounding code to confirm.)

Change the session-side `WithApprovals` call to use the new release-specific TTL instead of the session-access TTL:

```go
		sessOpts = append(sessOpts, session.WithApprovals(approvalStore, time.Duration(cfg.Approval.ReleaseTTL())*time.Second))
```

(the `dialer.WithApprovals(approvalStore, ...)` line right above it keeps using `cfg.Approval.ApprovalTTL()` unchanged — that TTL governs `KindSession` approvals, untouched by this plan.)

Add the release store construction and `session.WithReleases` wiring, near the recording/inspection option blocks:

```go
	if cfg.Approval != nil {
		relStore, err := release.NewFileStore(filepath.Join(filepath.Dir(cfg.Approval.StorePath), "releases.json"))
		if err != nil {
			return err
		}
		opts = append(opts, session.WithReleases(relStore, 6*time.Hour))
		log.Printf("omni-sag: SFTP pull-download releases enabled (window=6h)")
	}
```

Add the imports `"github.com/rupivbluegreen/omni-sag/internal/release"` and `"path/filepath"` (if not already present) to `cmd/omni-sag/main.go`.

- [ ] **Step 7: Run the full build and test suite**

Run: `make build && make test 2>&1 | tail -60`
Expected: build succeeds, all tests pass

- [ ] **Step 8: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go internal/api/approvals.go cmd/omni-sag/main.go
git commit -m "feat: wire group-scoped approval + pull-download release into config and main.go"
```

---

### Task 9: Lab/integration verification

**Files:**
- Modify: `scripts/lab-test-real-target.sh`

**Interfaces:** none (shell script)

Extend the existing real-target integration script (already proven to work against the live dev lab) to exercise this feature end to end: an upload that requires approval from a peer in the SAME group, then a SEPARATE session retrieving it via `/releases`.

- [ ] **Step 1: Read the current script in full**

Read `scripts/lab-test-real-target.sh` before editing — it already has a working upload → quarantine → approve → (formerly: deliver-to-target, now should be: appears in `/releases`) sequence from the prior plan; this task adapts that section rather than writing a new script from scratch.

- [ ] **Step 2: Add a group-scoped-approval demo user**

The existing lab seeds `alice` (in `dba`) and `bob` (not in `dba`) via `scripts/lab-seed.sh`. This feature needs a THIRD user, in the SAME group as `alice`, to demonstrate group-scoped approval succeeding, and confirm `bob` (not in `dba`) is refused even though he's a different user (proving this is stricter than plain four-eyes). Check `scripts/lab-seed.sh` — add a `carol` user to the `dba` group (mirroring how `alice` is added), idempotently, following that script's existing style.

- [ ] **Step 3: Extend the SFTP section of `lab-test-real-target.sh`**

After the existing upload+approve sequence, replace the "verify delivered to target" check (which the plan doc's own Task 6 above already establishes is now WRONG — approved uploads no longer reach the target) with:

```bash
echo "== attempt release-approval as bob (not in dba) — must be refused =="
# ... create a fresh upload the same way as before ...
# attempt: omnisag-ctl approve <id> as bob's identity — expect failure (403 / ErrNotPeerGroup)
# (exact CLI/API invocation: match whatever pattern the script's EXISTING
# approve step already uses for authenticating as a specific identity — reuse
# that mechanism, don't invent a new one)

echo "== approve as carol (in dba, same as alice) — must succeed =="
# ... approve the SAME request as carol ...

echo "== alice retrieves her own release via /releases in a NEW sftp session =="
# open a fresh sftp session as alice, `ls /releases`, get the one entry, diff
# against the original uploaded content

echo "== bob cannot list or read alice's release =="
# open a fresh sftp session as bob, confirm /releases is empty (or the entry
# is absent) for him
```

Fill in each `# ...` with real commands, matching the existing script's exact style for driving interactive SFTP/SSH sessions (it already solved the pty-driven password-prompt problem for `credential: prompt` — reuse that same harness) and for invoking `omnisag-ctl`/the API to approve as a specific identity (check the script's current approve step for the exact pattern, likely `omnisag-ctl -token <token-for-that-identity> approve <id>` or similar — read it before writing this).

- [ ] **Step 4: Run it against the live lab**

Run: `make lab-test-real-target`
Expected: `ALL PASS`, including the new group-scoped and pull-download assertions. If it fails, this is the point to fix whatever Task 1–8 code path is actually broken — do not weaken the script's assertions to make it pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/lab-test-real-target.sh scripts/lab-seed.sh
git commit -m "test: extend docker-lab integration check for group-scoped approval + pull-download release"
```

---

## Self-Review

**Spec coverage** — every spec section maps to a task:
- Group-scoped four-eyes → Tasks 1 (MatchedGroups), 2 (LDAP group lookup), 3 (approval.Store enforcement)
- Per-Kind approval TTL → Task 8 (`ReleaseTTL` config, separate `WithApprovals` TTL argument)
- Delivery: quarantine-then-pull → Tasks 4 (release store), 5 (wiring), 6 (the actual rewire)
- Retrieval: browsable `/releases` → Task 7
- "What this does NOT change" → confirmed by every task's scope: Task 10's unconditional quarantine untouched (no task modifies `internal/inspectgate`), `KindSession`/`KindStagedPolicyChange` explicitly excluded from the group-check (Task 3's test asserts this), tunnel/shell paths untouched (no task modifies `internal/session/interactive.go` or `internal/session/target.go`), no presigned URLs anywhere (confirmed — every read in Task 7 goes through `Gate.QuarantineReader`, the existing gateway-mediated S3 accessor).
- Testing considerations → each bullet in the spec's "Testing considerations" section has a corresponding test in Tasks 3, 6, or 7 (group-scoped approve/refuse/lookup-failure/no-fallback-needed; no second target connection on the approved path — proven by `TestQuarantineWriteHandle_ApprovedRecordsReleaseNotPush`'s explicit `targetClient.Open` failure assertion; retrieval's multi-read/wrong-user/expiry/post-expiry-quarantine-still-fetchable properties — the last one specifically: Task 7's tests confirm expired releases refuse via the RELEASE store, while Task 4's own tests already prove `Gate.QuarantineReader`-equivalent direct access is a separate, unexpired concern at the inspectgate layer, unchanged by this plan).

**Placeholder scan** — no TBD/TODO left un-resolved as an implementer decision point; the two spots that read as open (Task 7's filename-vs-ID listing tradeoff, Task 9's "fill in each `# ...`") both resolve to a concrete instruction (prefer ID-keyed with a documented follow-up note; reuse the script's own already-proven patterns) rather than leaving a genuine gap.

**Type consistency** — `release.Release`'s fields (`QuarantineKey`, `Requester`, `OriginalFilename`, `ApprovedAt`, `ExpiresAt`) are used identically across Tasks 4, 6, and 7. `remoteFS`'s new fields (`matchedGroups`, `releases`, `releaseTTL`) are introduced in Task 5 and consumed unchanged in Tasks 6 and 7. `approval.GroupLookup`'s single method signature (`Groups(ctx, username) ([]string, error)`) matches exactly between its Task 3 definition and Task 2's `*authn.LDAPAuthenticator.Groups` implementation, and Task 8's `main.go` wiring passes `auth` (already the right concrete type) with no adapter needed.

**Known follow-ups intentionally left out of this plan** (YAGNI — deliberate scope cuts, called out inline in their respective tasks): `releaseFileInfo.Size()` returning 0 rather than a real size (would need a `Stat` call against the quarantine object per listing entry — a real but non-blocking UX polish item); `readCloserAtAdapter` buffering the whole release fully into memory rather than an offset-ordered streaming read (acceptable given quarantine's existing size ceiling, flagged for a future hardening pass if large releases become common); the control-plane TUI not showing releases (explicitly out of scope per the design spec itself).
