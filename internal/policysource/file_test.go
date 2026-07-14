package policysource

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

const polV1 = `
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "db1.lab.local"
          ports: [5432]
`

const polV2 = `
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "db1.lab.local"
          ports: [5432]
    - name: web
      groups: ["web"]
      allow:
        - host: "web1.lab.local"
          ports: [443]
`

func write(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFileSource_LoadAndHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	write(t, path, polV1, time.Now().Add(-time.Hour))

	s := NewFileSource(path, 20*time.Millisecond)
	p, err := s.Load()
	if err != nil || len(p.Roles) != 1 || p.Roles[0].Name != "dba" {
		t.Fatalf("initial load = %+v err=%v", p, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := make(chan policy.Policy, 4)
	go s.Watch(ctx, func(np policy.Policy) { changed <- np })

	// Rewrite with a newer mtime; the watcher must recompile and notify.
	write(t, path, polV2, time.Now())
	select {
	case np := <-changed:
		if len(np.Roles) != 2 {
			t.Fatalf("reloaded policy should have 2 roles, got %d", len(np.Roles))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("hot-reload did not fire on file change")
	}
}

// A parseable-but-semantically-invalid edit (bad record value) must be rejected
// on hot-reload, not silently normalized to RecordNone — which would unrecord a
// full-recording target and re-enable -L forwarding (FR-10 fail-open).
const polBadRecord = `
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "db1.lab.local"
          ports: [5432]
          record: "Full"
`

func TestFileSource_InvalidRecordRejectedKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	write(t, path, polV1, time.Now().Add(-time.Hour))

	s := NewFileSource(path, 20*time.Millisecond)
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := make(chan policy.Policy, 4)
	go s.Watch(ctx, func(np policy.Policy) { changed <- np })

	write(t, path, polBadRecord, time.Now())
	select {
	case <-changed:
		t.Fatal("an invalid record value must not be applied (would fail-open FR-10)")
	case <-time.After(500 * time.Millisecond):
		// good: rejected, last good policy kept
	}
}

func TestFileSource_BadEditKeepsPreviousPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	write(t, path, polV1, time.Now().Add(-time.Hour))

	s := NewFileSource(path, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := make(chan policy.Policy, 4)
	go s.Watch(ctx, func(np policy.Policy) { changed <- np })

	// A syntactically broken edit must NOT trigger onChange (keep last good).
	write(t, path, "policy:\n  roles: [ this is : not : valid", time.Now())
	select {
	case <-changed:
		t.Fatal("a broken policy edit must not be applied")
	case <-time.After(500 * time.Millisecond):
		// good: no change delivered
	}
}
