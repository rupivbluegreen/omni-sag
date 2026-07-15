# Group-scoped four-eyes approval + pull-download release — design

**Status:** Approved (brainstorming), not yet implemented
**Date:** 2026-07-14
**Depends on:** the real-target SSH/SFTP proxy plan
(`docs/superpowers/plans/2026-07-14-real-target-proxy.md`), specifically
Task 10 (unconditional quarantine) and Task 11 (quarantine-then-release via
`approval.KindQuarantineRelease`). This design **replaces** Task 11's
"approved → push to real target" delivery step; it does not touch Task 11's
inspection/quarantine/blocking-`Close()` mechanics, which stay as built.

## Context

Task 11 built: an SFTP upload streams through content inspection, lands in
the WORM `Quarantine` bucket unconditionally (Task 10), and — if the verdict
is clean — blocks the client's `Close()` on a `KindQuarantineRelease`
four-eyes approval before the gateway auto-delivers it to the real target via
a second SFTP connection.

Two changes are wanted on top of that, both driven by wanting a closer match
to how real four-eyes release processes work:

1. **The approver shouldn't just be "any other user"** — they should be a
   peer with the same privileged access: a member of the same AD group that
   granted the uploader's role for this target. Today's four-eyes check
   (`approver != requester`) is real but blind to *who* the approver is
   relative to the requester's actual privilege.
2. **Delivery shouldn't auto-push to the target at all.** Once approved, the
   file should become available for the *same uploader* to retrieve
   themselves, within a bounded window — not silently placed on a machine
   the approver may not have intended to write to.

## Group-scoped four-eyes

The requester's role-granting AD group(s) — the specific `Role.Groups` that
matched to produce `policy.Decision.MatchedRole` for this upload's target —
are snapshotted onto the `approval.Request` at creation time (a new field,
e.g. `RequesterGroups []string`). The requester's own groups are already
known at upload time (from their LDAPS-authenticated session), so this is
free — no extra lookup.

At `Approve()` time, `approval.Store` needs the approver's **current** AD
groups to check for overlap against `RequesterGroups`. This is a live LDAP
query, injected as a dependency — the same pattern `internal/credential`
already uses for CyberArk (`credential.Provider`'s `Fetcher`): a small
interface,

```go
// GroupLookup resolves a user's current AD group membership, for
// group-scoped four-eyes on quarantine-release approvals.
type GroupLookup interface {
    Groups(ctx context.Context, username string) ([]string, error)
}
```

injected into `approval.Store`'s construction (mirrors
`credential.Config.Fetcher`). This keeps `internal/approval` a leaf package —
it depends on an interface it defines, not on `internal/authn`'s concrete
LDAP client; the control-plane composition root (`cmd/omni-sag/main.go`)
wires the real LDAP-backed implementation in, same as it wires
`credential.NewCyberArkProvider` today.

`Approve(id, approver string)` becomes: fetch `approver`'s groups via
`GroupLookup`, intersect with the request's `RequesterGroups`; empty
intersection → refuse (a new error, distinct from `ErrFourEyes`, e.g.
`ErrNotPeerGroup`), same as the four-eyes check refuses today. This is
**only** applied to `KindQuarantineRelease` requests — `KindSession` and
`KindStagedPolicyChange` keep today's plain four-eyes (approver != requester)
unless a future change asks for it there too; scope this change narrowly.

**No fallback when the requester is the only member of their group.** The
request simply sits pending — if no eligible peer approves before it expires,
`EffectiveStatus` already turns it `Expired`, and `Close()` already treats
that as a refusal. No new logic is needed for this case; it's a direct
consequence of the existing TTL mechanism.

## Per-Kind approval TTL

Quarantine-release requests get their own TTL — 24 hours, distinct from
session-access approvals' existing TTL (currently a single
`session.WithApprovals(store, ttl)` value). `Server.approvalTTL` becomes
either two fields (`sessionApprovalTTL`, `releaseApprovalTTL`) or the
`Create` call site passes an explicit per-`Kind` TTL rather than relying on
one `Server`-wide value — an implementation-plan decision, not a design one.

## Delivery: quarantine-then-pull, not quarantine-then-push

`quarantineWriteHandle.Close()` keeps every mechanic Task 11 already built:
stream through inspection, quarantine unconditionally, block on the
`KindQuarantineRelease` decision. **Only the approved branch changes.**

Today (Task 11): approved → `QuarantineReader` → `io.Copy` → a live SFTP
`Create` on the dialed target connection.

This design: approved → record a **release** and return success from
`Close()` — no target connection is touched for this path at all. A release
is a small record:

```go
type release struct {
    QuarantineKey    string
    Requester        string    // must match the later retrieving session's identity
    OriginalFilename string    // for display in /releases
    ApprovedAt       time.Time
    ExpiresAt        time.Time // ApprovedAt + 6h
}
```

Where this lives is an implementation-plan decision (a new small in-memory or
file-backed store, analogous to `approval.FileStore` but simpler — no
four-eyes, no Wait/blocking semantics, just create-and-list-and-expire).

The client's original `put` still blocks on the approval decision exactly as
today (up to the 24h release-approval TTL) — the only change is what happens
after "approved."

## Retrieval: a browsable `/releases` directory

A new virtual SFTP path, `/releases/`, scoped to the connected session's own
username: `Filelist("List", "/releases")` returns only that user's own
non-expired releases, showing `OriginalFilename` and `ApprovedAt` (so the
user can recognize their own upload without needing to remember an opaque
ID). `Fileread` on any listed entry streams directly from the `Quarantine`
bucket via the gateway's own S3 credentials (`Gate.QuarantineReader`, already
built in Task 11) — the same "gateway is the only S3 principal" property
holds; no presigned URLs, no HTTP surface, the retrieving client never
leaves the SFTP protocol.

- **Unlimited downloads** within the 6h window — each `Fileread` is a fresh,
  independent S3 `Get`; no consume-on-first-read semantics.
- **After 6h**, the release is no longer listed/readable — `Filelist`
  excludes expired releases, `Fileread` on an expired one refuses. The
  quarantined bytes themselves are never deleted (WORM/Object-Lock — the
  gateway cannot delete them even if it wanted to); only the *release*
  (the pointer/permission to retrieve) expires.
- **Identity check**: the retrieving session's authenticated username must
  match `release.Requester` — this SFTP session may be a completely
  different connection/time than the original upload, so this is checked
  fresh on every `/releases` access, not inherited from any prior session
  state.

This applies globally to every inspected upload — not a per-rule toggle
(matches Task 10's own unconditional-quarantine precedent: one consistent
model, no policy-surface growth).

## What this does NOT change

- Task 10's unconditional quarantine (every upload, clean or not, gets a WORM
  copy) — unchanged.
- The blocking `Close()` mechanic and its evidence emissions
  (`TypeInspection`, `TypeApproval` requested/granted-refused,
  `TypeTransfer`) — unchanged in shape; the `TypeTransfer` emission's
  `Direction` may need a value distinguishing "released to quarantine
  pending pickup" from a completed delivery, an implementation-plan detail.
- `KindSession`/`KindStagedPolicyChange` approvals — untouched; group-scoped
  four-eyes is scoped to `KindQuarantineRelease` only in this design.
- The tunnel (`-L`) and real-target interactive shell paths — untouched.
- No presigned URLs anywhere in this design (considered and rejected: the
  SFTP client can never consume one directly, and introducing one would mean
  a second, HTTP-based delivery channel outside the SSH data path).

## Testing considerations (for the eventual implementation plan)

- Group-scoped four-eyes: an approver in the requester's role-granting group
  succeeds; an approver NOT in that group is refused even though they are a
  different user (proves this is stricter than plain four-eyes, not just a
  rename of it); a `GroupLookup` failure at `Approve()` time fails closed
  (refuses, does not silently fall back to plain four-eyes).
  A request whose requester is the sole member of their group: never
  approved, expires naturally, `Close()` sees the same refusal path as any
  other expired request.
- Pull delivery: approved upload never opens a second target connection at
  all (a strong assertion: no `dialTarget`/`targetConnCache` call happens on
  the approved path anymore for this flow); a `/releases` entry is created
  with the right requester/expiry.
- Retrieval: same user, within 6h, can `Fileread` the same release multiple
  times; a *different* user cannot list or read another user's release even
  if they know precise filenames; after 6h, both `Filelist` and `Fileread`
  refuse for the original uploader too; the underlying quarantine bytes are
  still fetchable directly via `Gate.QuarantineReader` after expiry (proving
  expiry only revokes the release pointer, not the audit copy).

## Explicitly out of scope for this design

- Standing up a real CyberArk CCP or LDAP server in the dev lab beyond what
  already exists — this is a design for production wiring; dev-lab
  demonstration details are an implementation-plan/lab-wiring concern.
- Any change to `KindSession`/`KindStagedPolicyChange`'s four-eyes semantics.
- A UI/TUI surface for browsing releases outside of the SFTP `/releases`
  directory itself (the control-plane TUI already lists pending approval
  *requests*; whether it should also show *releases* post-approval is a
  follow-on nicety, not required by this design).
