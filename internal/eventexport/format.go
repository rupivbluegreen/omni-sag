// Package eventexport renders evidence.Event records for external
// SIEM/log-management systems. It imports only internal/evidence, stdlib,
// and (for the experimental "otlp" transport) internal/otelexport, so it
// stays free of import cycles with internal/session and internal/dialer.
package eventexport

import (
	"encoding/json"
	"fmt"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// Formatter renders a single evidence.Event as one line of output bytes,
// with no trailing newline — the transport is responsible for framing
// (newline, syslog octet-count, HTTP batching, etc).
type Formatter interface {
	Format(evidence.Event) ([]byte, error)
	ContentType() string
}

// NewFormatter returns the Formatter registered under name.
func NewFormatter(name string) (Formatter, error) {
	switch name {
	case "json":
		return jsonFormatter{}, nil
	case "ecs":
		return ecsFormatter{}, nil
	case "cef":
		return cefFormatter{}, nil
	default:
		return nil, fmt.Errorf("eventexport: unknown formatter %q", name)
	}
}

// jsonFormatter emits the raw evidence.Event using its existing json tags —
// the same shape already written to the JSONL evidence stream.
type jsonFormatter struct{}

func (jsonFormatter) Format(e evidence.Event) ([]byte, error) { return json.Marshal(e) }

func (jsonFormatter) ContentType() string { return "application/json" }

// outcomeString derives the ECS/CEF "success"/"failure" outcome from the
// tri-state Allow field: nil (not a decision event) and true both read as
// success; an explicit false is a denial.
func outcomeString(allow *bool) string {
	if allow == nil || *allow {
		return "success"
	}
	return "failure"
}
