// Package evidence provides the event bus, emitter epochs, Merkle chain,
// and S3 writer. Every package may import evidence: emitting is universal
// and non-optional.
//
// Slice 1 is deliberately crude: a typed Event and a Sink interface with a
// file (JSONL) and an S3/MinIO implementation. Slice 3 promotes this into the
// ordered bus, per-emitter epoch+sequence, Merkle chain, and signed
// checkpoints. The Event shape is kept forward-compatible so that promotion
// does not require reshaping already-written records.
package evidence

import (
	"time"
)

// Type enumerates the kinds of events emitted in Slice 1.
type Type string

const (
	TypeAuth           Type = "auth"            // primary authentication attempt
	TypeMFA            Type = "mfa"             // second-factor (MFA) outcome
	TypeTunnelDecision Type = "tunnel_decision" // dialer authorization decision
	TypeSessionStart   Type = "session_start"   // interactive session opened
	TypeSessionEnd     Type = "session_end"     // interactive session closed
	TypeRecording      Type = "recording"       // a session recording was produced (asciicast)
	TypeTransfer       Type = "transfer"        // an SFTP file transfer manifest
	TypeInspection     Type = "inspection"      // a content-inspection (ICAP) verdict
	TypeCredential     Type = "credential"      // a credential-mode resolution outcome
	TypeApproval       Type = "approval"        // a four-eyes approval request/decision
	TypeSupervision    Type = "supervision"     // a supervisor attached to / killed a session
)

// Event is a single evidence record. Fields are additive: new event kinds add
// fields rather than repurposing existing ones, so the JSONL stream stays
// readable across slices.
type Event struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Type     Type      `json:"type"`
	User     string    `json:"user,omitempty"`
	SourceIP string    `json:"source_ip,omitempty"`

	// Target and decision fields (tunnel_decision / session events).
	Target      string `json:"target,omitempty"` // host:port
	Allow       *bool  `json:"allow,omitempty"`
	Reason      string `json:"reason,omitempty"`
	MatchedRole string `json:"matched_role,omitempty"`
	RecordMode  string `json:"record_mode,omitempty"` // none | metadata-only | full

	// Recording / transfer / inspection fields.
	ObjectKey string `json:"object_key,omitempty"` // S3 (or local) key of the artifact (or quarantine key)
	SHA256    string `json:"sha256,omitempty"`     // digest of the artifact/file
	Bytes     int64  `json:"bytes,omitempty"`      // size in bytes
	Path      string `json:"path,omitempty"`       // SFTP path
	Direction string `json:"direction,omitempty"`  // upload | download | released | remove | rename | mkdir | rmdir

	// Content-inspection fields (inspection events).
	Verdict    string `json:"verdict,omitempty"`     // clean | blocked | modified | error
	ICAPStatus int    `json:"icap_status,omitempty"` // raw ICAP status code

	// Credential fields (credential events). The secret is NEVER recorded.
	CredentialMode string `json:"credential_mode,omitempty"` // inject | prompt | passthrough | deny
	Outcome        string `json:"outcome,omitempty"`         // injected | prompt | passthrough | denied

	// Freeform detail for anything not yet promoted to a field.
	Detail string `json:"detail,omitempty"`
}

// Sink is a destination for evidence events. Implementations must be safe for
// concurrent use by multiple goroutines: many sessions emit at once.
type Sink interface {
	Emit(e Event) error
	Close() error
}

// BoolPtr is a helper for the Allow field.
func BoolPtr(b bool) *bool { return &b }
