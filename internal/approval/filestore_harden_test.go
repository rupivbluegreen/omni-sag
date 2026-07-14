package approval

import (
	"path/filepath"
	"testing"
	"time"
)

// Four-eyes must not be defeated by case/whitespace variants of the requester.
func TestFourEyes_CaseAndWhitespaceInsensitive(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Create(Request{Requester: "alice", Subject: "db:5432"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(r.ID, "  Alice  "); err != ErrFourEyes {
		t.Fatalf("case/whitespace self-approval must be rejected, got %v", err)
	}
	if _, err := s.Approve(r.ID, "bob"); err != nil {
		t.Fatalf("a distinct approver should approve: %v", err)
	}
}

// Terminal requests older than the retention horizon are pruned so the durable
// file (and the per-Create rewrite) stays bounded.
func TestPrune_TerminalRequestsExpire(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	s, err := newFileStore(filepath.Join(t.TempDir(), "a.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	old, _ := s.Create(Request{Requester: "alice", Subject: "x"}, time.Minute)
	if _, err := s.Approve(old.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	// Advance well past the request's expiry + retention, then trigger a persist.
	now = now.Add(2 * time.Minute).Add(terminalRetention).Add(time.Hour)
	if _, err := s.Create(Request{Requester: "carol", Subject: "y"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(old.ID); ok {
		t.Fatal("an old terminal request should have been pruned")
	}
}
