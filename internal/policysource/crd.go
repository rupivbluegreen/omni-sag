package policysource

import (
	"context"
	"errors"

	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// ErrCRDUnavailable indicates the CRD-backed source is not usable in this build
// or environment.
var ErrCRDUnavailable = errors.New("policysource: CRD source requires a Kubernetes cluster and client-go informer (not implemented in this build)")

// CRDSource watches AccessPolicy CustomResources via a client-go informer and
// compiles them into a policy.Policy. It implements the same Source interface
// as FileSource so the gateway wiring is unchanged.
//
// TODO(slice-7-followup): implement against client-go once a cluster (kind/k3s)
// is available in CI. The informer's Add/Update/Delete handlers recompile the
// full policy and call onChange; deletes fall back to deny-all for the removed
// role. Until then NewCRDSource returns ErrCRDUnavailable so operators fall
// back to the file source explicitly rather than silently getting deny-all.
type CRDSource struct{}

// NewCRDSource is a stub that reports the CRD source is unavailable.
func NewCRDSource(_ string) (Source, error) {
	return nil, ErrCRDUnavailable
}

// Compile-time check that CRDSource is drop-in once implemented.
var _ Source = (*CRDSource)(nil)

// Load / Watch satisfy Source so CRDSource is drop-in once implemented.
func (c *CRDSource) Load() (policy.Policy, error)               { return policy.Policy{}, ErrCRDUnavailable }
func (c *CRDSource) Watch(context.Context, func(policy.Policy)) {}
