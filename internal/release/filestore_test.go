package release

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileStore_CreateAndListFor(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s, err := newFileStore(filepath.Join(t.TempDir(), "r.json"), func() time.Time { return now })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	rel, err := s.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice", OriginalFilename: "report.csv"}, 6*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rel.ExpiresAt.Sub(rel.ApprovedAt) != 6*time.Hour {
		t.Fatalf("ExpiresAt-ApprovedAt = %v, want 6h", rel.ExpiresAt.Sub(rel.ApprovedAt))
	}

	list := s.ListFor("alice", now)
	if len(list) != 1 || list[0].QuarantineKey != "quarantine/k1" {
		t.Fatalf("ListFor(alice) = %v, want exactly the one release just created", list)
	}
	if got := s.ListFor("bob", now); len(got) != 0 {
		t.Fatalf("ListFor(bob) = %v, want empty — releases are scoped to their own requester", got)
	}
}

func TestFileStore_ListForExcludesExpired(t *testing.T) {
	created := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s, err := newFileStore(filepath.Join(t.TempDir(), "r.json"), func() time.Time { return created })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	if _, err := s.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice"}, time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}
	afterExpiry := created.Add(2 * time.Hour)
	if got := s.ListFor("alice", afterExpiry); len(got) != 0 {
		t.Fatalf("ListFor after expiry = %v, want empty", got)
	}
}

func TestFileStore_GetRespectsRequesterAndExpiry(t *testing.T) {
	created := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s, err := newFileStore(filepath.Join(t.TempDir(), "r.json"), func() time.Time { return created })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	rel, err := s.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice", OriginalFilename: "report.csv"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, ok := s.Get("alice", rel.ID, created); !ok {
		t.Fatal("Get(alice, ..., within window) should find the release")
	}
	if _, ok := s.Get("bob", rel.ID, created); ok {
		t.Fatal("Get(bob, ...) must not find alice's release — identity check")
	}
	if _, ok := s.Get("alice", rel.ID, created.Add(2*time.Hour)); ok {
		t.Fatal("Get(alice, ..., after expiry) must not find it")
	}
}

func TestFileStore_UnlimitedReadsWithinWindow(t *testing.T) {
	created := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s, err := newFileStore(filepath.Join(t.TempDir(), "r.json"), func() time.Time { return created })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	rel, err := s.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, ok := s.Get("alice", rel.ID, created.Add(30*time.Minute)); !ok {
			t.Fatalf("read #%d: expected the release to still be gettable (unlimited reads within window)", i)
		}
	}
}

func TestFileStore_PersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	s1, err := newFileStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	if _, err := s1.Create(Release{QuarantineKey: "quarantine/k1", Requester: "alice"}, time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}

	s2, err := newFileStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := s2.ListFor("alice", now); len(got) != 1 {
		t.Fatalf("after reopen, ListFor(alice) = %v, want the persisted release", got)
	}
}
