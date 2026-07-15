// Package approval is the durable, four-eyes approval store shared between the
// control-plane API (which creates/approves/denies requests) and the SSH data
// path (which blocks a session until its request is approved).
//
// It is a LEAF: it must not import internal/session, internal/api, or
// internal/dialer, so the data path can gate on approvals without depending on
// the control plane (the control-plane-out-of-band invariant).
//
// The load-bearing properties are FOUR-EYES (the approver must not be the
// requester, enforced here — not just in the UI), TTL (a pending request past
// its expiry is treated as not-approved), and FAIL-CLOSED (an unavailable store
// or an undecided/denied/expired request refuses the session).
package approval

import (
	"context"
	"errors"
	"time"
)

// Kind is the type of thing being approved.
type Kind string

const (
	KindSession            Kind = "session_access"       // a session to an approval-gated target
	KindQuarantineRelease  Kind = "quarantine_release"   // releasing quarantined content
	KindStagedPolicyChange Kind = "staged_policy_change" // promoting a staged policy change
)

// Status is the lifecycle state of a request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
)

// Request is one approval object. It is safe to serialize and to record in
// evidence (it carries no secret).
type Request struct {
	ID        string `json:"id"`
	Kind      Kind   `json:"kind"`
	Requester string `json:"requester"`
	Subject   string `json:"subject"` // target host:port, quarantine key, or change id
	// RequesterGroups is a snapshot, taken at Create time, of the requester's
	// AD groups that actually granted them access for this request's subject
	// (policy.Decision.MatchedGroups — not their full group list). Used for
	// group-scoped four-eyes on KindQuarantineRelease requests: the approver
	// must currently belong to one of these groups. Empty for request kinds
	// that don't use group-scoped approval, or when the deployment hasn't
	// wired a GroupLookup (see FileStore.SetGroupLookup) — in both cases
	// Approve falls back to plain four-eyes (approver != requester).
	RequesterGroups []string  `json:"requester_groups,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	Status          Status    `json:"status"`
	Approver        string    `json:"approver,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	DecidedAt       time.Time `json:"decided_at,omitempty"`
}

// EffectiveStatus applies the TTL: a pending request past ExpiresAt is Expired.
// A decision (approved/denied) is terminal and never expires.
func (r Request) EffectiveStatus(now time.Time) Status {
	if r.Status == StatusPending && now.After(r.ExpiresAt) {
		return StatusExpired
	}
	return r.Status
}

// Approved reports whether the request is approved as of now (never true once
// expired). This is the gate's decision function — fail-closed by construction.
func (r Request) Approved(now time.Time) bool {
	return r.EffectiveStatus(now) == StatusApproved
}

// Errors.
var (
	ErrNotFound         = errors.New("approval: request not found")
	ErrNotPending       = errors.New("approval: request is not pending")
	ErrFourEyes         = errors.New("approval: approver must not be the requester (four-eyes)")
	ErrStoreUnavailable = errors.New("approval: store unavailable")
	ErrRefused          = errors.New("approval: refused")
)

// ErrNotPeerGroup is returned when group-scoped four-eyes is active for this
// request (a GroupLookup is configured AND the request has RequesterGroups)
// and the approver's current AD groups do not overlap RequesterGroups. This
// is checked in ADDITION to, not instead of, the plain four-eyes check.
var ErrNotPeerGroup = errors.New("approval: approver is not a member of the requester's role-granting group")

// Store persists and decides approval requests. Implementations must be safe for
// concurrent use and must enforce four-eyes and TTL server-side.
type Store interface {
	// Create records a new pending request (assigns ID + timestamps) and persists
	// it durably.
	Create(req Request, ttl time.Duration) (Request, error)
	// Get returns one request (with TTL applied to its status).
	Get(id string) (Request, bool)
	// List returns all requests (with TTL applied).
	List() []Request
	// Approve/Deny decide a pending request. Approve enforces four-eyes:
	// approver must differ from the request's requester.
	Approve(id, approver string) (Request, error)
	Deny(id, approver string) (Request, error)
	// Wait blocks until the request is decided (approved/denied) or expires or ctx
	// is done, then returns the final request. Fail-closed: ctx cancellation or
	// expiry yields a non-approved status.
	Wait(ctx context.Context, id string) (Request, error)
}

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
