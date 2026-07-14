package approval

import (
	"context"
	"time"
)

// CRDStore is a stub for a Kubernetes-CRD-backed approval store (ApprovalRequest
// custom resources reconciled by an informer). It is wired behind the same Store
// interface as FileStore; a real client-go implementation is a follow-up that
// needs a cluster. Until then it fails closed: every operation reports the store
// unavailable, so an approval-gated session is refused rather than admitted.
type CRDStore struct{}

func (CRDStore) Create(Request, time.Duration) (Request, error) {
	return Request{}, ErrStoreUnavailable
}
func (CRDStore) Get(string) (Request, bool)              { return Request{}, false }
func (CRDStore) List() []Request                         { return nil }
func (CRDStore) Approve(string, string) (Request, error) { return Request{}, ErrStoreUnavailable }
func (CRDStore) Deny(string, string) (Request, error)    { return Request{}, ErrStoreUnavailable }
func (CRDStore) Wait(context.Context, string) (Request, error) {
	return Request{}, ErrStoreUnavailable
}
