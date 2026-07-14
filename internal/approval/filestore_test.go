package approval

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T, now func() time.Time) *FileStore {
	t.Helper()
	s, err := newFileStore(filepath.Join(t.TempDir(), "approvals.json"), now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFourEyes_ApproverCannotBeRequester(t *testing.T) {
	s := newTestStore(t, time.Now)
	req, err := s.Create(Request{Kind: KindSession, Requester: "alice", Subject: "db1:5432"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The requester approving their own request must be rejected.
	if _, err := s.Approve(req.ID, "alice"); !errors.Is(err, ErrFourEyes) {
		t.Fatalf("self-approval must fail four-eyes, got %v", err)
	}
	// A distinct approver succeeds.
	got, err := s.Approve(req.ID, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || got.Approver != "bob" {
		t.Fatalf("expected approved by bob, got %+v", got)
	}
}

func TestTTL_ExpiredPendingFailsClosed(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newTestStore(t, func() time.Time { return now })
	req, _ := s.Create(Request{Requester: "alice", Subject: "db1:5432"}, 10*time.Second)

	if got, _ := s.Get(req.ID); got.Approved(now) {
		t.Fatal("fresh pending must not be approved")
	}
	// Advance past expiry.
	now = now.Add(11 * time.Second)
	got, _ := s.Get(req.ID)
	if got.EffectiveStatus(now) != StatusExpired {
		t.Fatalf("expected expired, got %s", got.EffectiveStatus(now))
	}
	if got.Approved(now) {
		t.Fatal("expired request must never be approved (fail closed)")
	}
	// An expired request cannot be approved.
	if _, err := s.Approve(req.ID, "bob"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("approving an expired request must fail, got %v", err)
	}
}

func TestDurability_PendingSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")

	s1, err := newFileStore(path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := s1.Create(Request{Requester: "alice", Subject: "crown-jewel:22", Reason: "deploy"}, time.Hour)

	// Simulate a process restart: a fresh store from the same file.
	s2, err := newFileStore(path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get(req.ID)
	if !ok {
		t.Fatal("pending request must survive a restart")
	}
	if got.Status != StatusPending || got.Requester != "alice" || got.Subject != "crown-jewel:22" {
		t.Fatalf("reloaded request wrong: %+v", got)
	}
	// And it can still be approved after the restart.
	if _, err := s2.Approve(req.ID, "bob"); err != nil {
		t.Fatalf("reloaded request must be approvable: %v", err)
	}
}

func TestWait_UnblocksOnApproval(t *testing.T) {
	s := newTestStore(t, time.Now)
	req, _ := s.Create(Request{Requester: "alice", Subject: "db1:5432"}, time.Hour)

	done := make(chan Request, 1)
	go func() {
		got, _ := s.Wait(context.Background(), req.ID)
		done <- got
	}()
	// Approve from "another human".
	time.Sleep(20 * time.Millisecond)
	if _, err := s.Approve(req.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if !got.Approved(time.Now()) {
			t.Fatalf("Wait should return an approved request, got %s", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not unblock on approval")
	}
}

func TestWait_ExpiresFailClosed(t *testing.T) {
	// Real-time short TTL so the Wait timer fires.
	s := newTestStore(t, time.Now)
	req, _ := s.Create(Request{Requester: "alice", Subject: "db1:5432"}, 60*time.Millisecond)
	got, err := s.Wait(context.Background(), req.ID)
	if err != nil {
		t.Fatalf("wait returned error: %v", err)
	}
	if got.Approved(time.Now()) || got.EffectiveStatus(time.Now()) != StatusExpired {
		t.Fatalf("undecided request must expire fail-closed, got %s", got.Status)
	}
}

func TestWait_CtxCancelFailsClosed(t *testing.T) {
	s := newTestStore(t, time.Now)
	req, _ := s.Create(Request{Requester: "alice", Subject: "db1:5432"}, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := s.Wait(ctx, req.ID)
	if err == nil {
		t.Fatal("cancelled ctx must return an error (fail closed)")
	}
	if got.Approved(time.Now()) {
		t.Fatal("must not be approved on ctx cancel")
	}
}
