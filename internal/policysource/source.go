// Package policysource abstracts where the access policy comes from. The plan
// moves policy from a YAML file to Kubernetes CRDs watched by an informer; both
// live behind the same Source interface so the gateway wiring is identical.
// A Source Loads an initial policy and Watches for changes, recompiling the
// in-memory policy.Policy atomically on each update.
package policysource

import (
	"context"

	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// Source provides the compiled policy and notifies on changes.
type Source interface {
	// Load returns the current compiled policy.
	Load() (policy.Policy, error)
	// Watch calls onChange with a freshly compiled policy whenever the source
	// changes, until ctx is cancelled. It must not call onChange with a policy
	// that failed to parse — a bad edit keeps the last good policy in force.
	Watch(ctx context.Context, onChange func(policy.Policy))
}
