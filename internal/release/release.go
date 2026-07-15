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
	ID               string    `json:"id"`
	QuarantineKey    string    `json:"quarantine_key"`
	Requester        string    `json:"requester"`         // must match the retrieving session's identity
	OriginalFilename string    `json:"original_filename"` // for display in /releases
	ApprovedAt       time.Time `json:"approved_at"`
	ExpiresAt        time.Time `json:"expires_at"`
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
