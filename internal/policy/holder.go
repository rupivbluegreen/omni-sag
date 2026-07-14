package policy

import "sync/atomic"

// Holder is an atomically-swappable Policy, so a policy source can hot-reload
// the compiled policy while the data path reads it lock-free. The zero Holder
// returns an empty (deny-all) Policy until Store is called.
type Holder struct {
	p atomic.Pointer[Policy]
}

// NewHolder returns a Holder initialized to p.
func NewHolder(p Policy) *Holder {
	h := &Holder{}
	h.Store(p)
	return h
}

// Store atomically replaces the current policy.
func (h *Holder) Store(p Policy) { h.p.Store(&p) }

// Load returns the current policy (an empty, deny-all Policy if never stored).
func (h *Holder) Load() Policy {
	if v := h.p.Load(); v != nil {
		return *v
	}
	return Policy{}
}
