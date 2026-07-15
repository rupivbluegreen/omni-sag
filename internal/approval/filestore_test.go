package approval

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
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

type fakeGroupLookup struct {
	groups map[string][]string // username -> groups
	err    error
}

func (f *fakeGroupLookup) Groups(_ context.Context, username string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.groups[username], nil
}

func TestFileStore_ApproveGroupScoped_PeerInGroupSucceeds(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s.SetGroupLookup(&fakeGroupLookup{groups: map[string][]string{"bob": {"dba"}}})

	req, err := s.Create(Request{Kind: KindQuarantineRelease, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "quarantine/key1"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Approve(req.ID, "bob"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
}

func TestFileStore_ApproveGroupScoped_NonPeerRefused(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s.SetGroupLookup(&fakeGroupLookup{groups: map[string][]string{"carol": {"engineering"}}})

	req, err := s.Create(Request{Kind: KindQuarantineRelease, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "quarantine/key1"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// carol is a DIFFERENT user from alice (passes plain four-eyes) but is not
	// in "dba" — must still be refused.
	_, err = s.Approve(req.ID, "carol")
	if !errors.Is(err, ErrNotPeerGroup) {
		t.Fatalf("want ErrNotPeerGroup, got %v", err)
	}
}

func TestFileStore_ApproveGroupScoped_LookupFailureFailsClosed(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s.SetGroupLookup(&fakeGroupLookup{err: errors.New("ldap down")})

	req, err := s.Create(Request{Kind: KindQuarantineRelease, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "quarantine/key1"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Approve(req.ID, "bob"); err == nil {
		t.Fatal("want an error when GroupLookup fails, got nil (must fail closed, not silently allow)")
	}
}

func TestFileStore_ApproveGroupScoped_NoGroupLookupConfiguredKeepsPlainFourEyes(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json")) // no SetGroupLookup call
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	req, err := s.Create(Request{Kind: KindQuarantineRelease, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "quarantine/key1"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// No GroupLookup configured: any distinct user still succeeds — today's
	// behavior, unchanged, proving this feature is opt-in.
	if _, err := s.Approve(req.ID, "carol"); err != nil {
		t.Fatalf("Approve without a configured GroupLookup must behave as plain four-eyes: %v", err)
	}
}

func TestFileStore_ApproveGroupScoped_SessionKindUnaffected(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s.SetGroupLookup(&fakeGroupLookup{groups: map[string][]string{"carol": {"engineering"}}})

	req, err := s.Create(Request{Kind: KindSession, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "db1.lab.local:22"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// KindSession must NOT be group-scoped even with a GroupLookup configured
	// and RequesterGroups set — the design scopes this narrowly to
	// KindQuarantineRelease only.
	if _, err := s.Approve(req.ID, "carol"); err != nil {
		t.Fatalf("KindSession approvals must stay plain four-eyes: %v", err)
	}
}

// TestFileStore_ApproveGroupScoped_ConcurrentDecideRace exercises the TOCTOU
// window in decide(): the mutex is released across the live GroupLookup call,
// so two approvers racing on the same pending request must still yield
// exactly one winning decision, never a corrupted/overwritten one.
func TestFileStore_ApproveGroupScoped_ConcurrentDecideRace(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	// A slow GroupLookup widens the unlocked window so the race is real, not
	// theoretical.
	gl := &slowGroupLookup{delay: 20 * time.Millisecond, groups: map[string][]string{
		"bob":   {"dba"},
		"carol": {"dba"},
	}}
	s.SetGroupLookup(gl)

	req, err := s.Create(Request{Kind: KindQuarantineRelease, Requester: "alice", RequesterGroups: []string{"dba"}, Subject: "quarantine/key1"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := s.Approve(req.ID, "bob")
		results <- err
	}()
	go func() {
		defer wg.Done()
		_, err := s.Deny(req.ID, "carol")
		results <- err
	}()
	wg.Wait()
	close(results)

	var oks, notPending int
	for err := range results {
		switch {
		case err == nil:
			oks++
		case errors.Is(err, ErrNotPending):
			notPending++
		default:
			t.Fatalf("unexpected error from concurrent decide: %v", err)
		}
	}
	if oks != 1 || notPending != 1 {
		t.Fatalf("want exactly one winner and one ErrNotPending, got oks=%d notPending=%d", oks, notPending)
	}

	got, ok := s.Get(req.ID)
	if !ok {
		t.Fatal("request must still exist after the race")
	}
	if got.Status != StatusApproved && got.Status != StatusDenied {
		t.Fatalf("request must be decided exactly once, got status=%s", got.Status)
	}
	if got.Approver != "bob" && got.Approver != "carol" {
		t.Fatalf("approver must be whichever goroutine won, got %q", got.Approver)
	}
}

// slowGroupLookup simulates a live LDAP round-trip's latency, so a test can
// exercise the window during which FileStore.decide holds no lock.
type slowGroupLookup struct {
	delay  time.Duration
	groups map[string][]string
}

func (g *slowGroupLookup) Groups(_ context.Context, username string) ([]string, error) {
	time.Sleep(g.delay)
	return g.groups[username], nil
}
