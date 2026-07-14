package approval

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Chaos / fail-closed matrix for the four-eyes approval store.
//
// The gate's decision function is Request.Approved(now); it must be false for
// every non-approved lifecycle state. These tests drive each failure of the
// durable store (expiry, four-eyes violation, ctx cancellation, denial) and
// assert the session would be REFUSED — approval never falls open.

func chaosStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pendingReq(requester, subject string) Request {
	return Request{Kind: KindSession, Requester: requester, Subject: subject}
}

// A pending request whose TTL elapses is Expired and NOT approved — the gate
// (Wait) returns a non-approved request, so the session fails closed.
func TestChaos_ApprovalExpiryFailsClosed(t *testing.T) {
	s := chaosStore(t)
	req, err := s.Create(pendingReq("alice", "crown:22"), 15*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	final, werr := s.Wait(context.Background(), req.ID)
	if werr != nil {
		t.Fatalf("Wait on expiry should return the final request, not error: %v", werr)
	}
	if final.Approved(time.Now()) {
		t.Fatal("an expired request must never be approved (fail closed)")
	}
	if final.EffectiveStatus(time.Now()) != StatusExpired {
		t.Fatalf("expected expired, got %s", final.EffectiveStatus(time.Now()))
	}
}

// Four-eyes is enforced server-side: the requester cannot approve their own
// request. The store refuses and the request stays not-approved.
func TestChaos_ApprovalSelfApprovalRefused(t *testing.T) {
	s := chaosStore(t)
	req, err := s.Create(pendingReq("alice", "crown:22"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(req.ID, "alice"); err == nil {
		t.Fatal("self-approval must be refused (four-eyes)")
	}
	got, _ := s.Get(req.ID)
	if got.Approved(time.Now()) {
		t.Fatal("request must not be approved after a refused self-approval")
	}
}

// Context cancellation while waiting (e.g. the SSH client disconnects) must
// surface the ctx error AND leave the request not-approved: fail closed.
func TestChaos_ApprovalCtxCancelFailsClosed(t *testing.T) {
	s := chaosStore(t)
	req, err := s.Create(pendingReq("alice", "crown:22"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	final, werr := s.Wait(ctx, req.ID)
	if werr == nil {
		t.Fatal("Wait must surface ctx cancellation, not swallow it")
	}
	if final.Approved(time.Now()) {
		t.Fatal("a cancelled wait must never be approved")
	}
}

// A denied request is terminal and never approved, even before its TTL.
func TestChaos_ApprovalDeniedIsTerminal(t *testing.T) {
	s := chaosStore(t)
	req, err := s.Create(pendingReq("alice", "crown:22"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deny(req.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	final, werr := s.Wait(context.Background(), req.ID)
	if werr != nil {
		t.Fatalf("Wait on a decided request should not error: %v", werr)
	}
	if final.Approved(time.Now()) {
		t.Fatal("a denied request must never be approved")
	}
}

// Deciding a request that does not exist (store lost it / wrong id) is refused,
// never silently treated as approved.
func TestChaos_ApprovalUnknownIDRefused(t *testing.T) {
	s := chaosStore(t)
	if _, err := s.Approve("does-not-exist", "bob"); err == nil {
		t.Fatal("approving an unknown request must error")
	}
	if _, ok := s.Get("does-not-exist"); ok {
		t.Fatal("unknown request must not be found")
	}
	if _, err := s.Wait(context.Background(), "does-not-exist"); err == nil {
		t.Fatal("waiting on an unknown request must error (fail closed)")
	}
}
