// Package inspect implements the ICAP (RFC 3507) client used for AV and DLP
// content inspection of file transfers.
//
// This is the decoupled leaf of Slice 5: a self-contained ICAP client behind
// the Inspector interface. Wiring it into the SFTP/transfer path, size-tiered
// handling, and quarantine to Object-Locked storage are Slice 5 proper and
// live in other packages. Nothing here imports session, evidence, dialer, or
// policy — inspect is a leaf.
//
// Fail-closed is the contract: if the ICAP server is unreachable, times out, or
// returns something the client cannot parse, Inspect returns an error. Callers
// MUST treat an error as "block" and never let unscanned content through.
package inspect

import (
	"context"
	"io"
)

// Verdict is the inspection outcome for a payload.
type Verdict int

const (
	// VerdictClean means the inspection service passed the content unchanged
	// (ICAP 204 No Modification, or 200 with no modification indicators).
	VerdictClean Verdict = iota
	// VerdictBlocked means the service flagged the content (e.g. an infection
	// or DLP violation). The transfer must not proceed.
	VerdictBlocked
	// VerdictModified means the service returned a modified payload (available
	// in Result.Modified). The caller decides whether to deliver the
	// modification or treat it as a block.
	VerdictModified
)

func (v Verdict) String() string {
	switch v {
	case VerdictClean:
		return "clean"
	case VerdictBlocked:
		return "blocked"
	case VerdictModified:
		return "modified"
	default:
		return "unknown"
	}
}

// Result is the outcome of an Inspect call.
type Result struct {
	Verdict    Verdict
	Reason     string // human-readable, e.g. the ICAP X-Infection-Found value
	Modified   []byte // non-nil only when Verdict == VerdictModified
	ICAPStatus int    // the raw ICAP status code (204, 200, ...)
}

// Method is the ICAP method used to present the payload.
type Method string

const (
	// RESPMOD presents the payload as an HTTP response body (the common shape
	// for scanning a download/served file).
	RESPMOD Method = "RESPMOD"
	// REQMOD presents the payload as an HTTP request body (the shape for
	// scanning an upload).
	REQMOD Method = "REQMOD"
)

// TransferMeta describes the payload being inspected. All fields are optional;
// they populate the encapsulated HTTP message the ICAP service inspects.
type TransferMeta struct {
	Filename    string
	ContentType string
	// Method selects REQMOD (upload) vs RESPMOD (download). Empty defaults to
	// the client's configured method.
	Method Method
	// URL is the request-target placed in the encapsulated HTTP header line.
	// Empty defaults to a synthetic path derived from Filename.
	URL string
}

// Inspector inspects a payload and returns a verdict. Implementations must
// fail closed: any transport or protocol failure is returned as an error.
type Inspector interface {
	Inspect(ctx context.Context, meta TransferMeta, body io.Reader) (Result, error)
}
