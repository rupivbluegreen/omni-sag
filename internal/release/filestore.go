package release

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FileStore is a durable release store backed by a single JSON file.
type FileStore struct {
	path string
	now  func() time.Time

	mu       sync.Mutex
	releases map[string]*Release
}

// NewFileStore opens (creating if absent) the store at path and loads any
// existing releases.
func NewFileStore(path string) (*FileStore, error) {
	return newFileStore(path, time.Now)
}

func newFileStore(path string, now func() time.Time) (*FileStore, error) {
	s := &FileStore{path: path, now: now, releases: map[string]*Release{}}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("release: read store: %w", err)
	}
	var rels []Release
	if len(data) > 0 {
		if err := json.Unmarshal(data, &rels); err != nil {
			return nil, fmt.Errorf("release: parse store: %w", err)
		}
	}
	for i := range rels {
		r := rels[i]
		s.releases[r.ID] = &r
	}
	return s, nil
}

// terminalRetention bounds how long an EXPIRED release stays in the durable
// file before being pruned — mirrors approval.FileStore's terminalRetention,
// same reasoning (bounded rewrite cost), but note the underlying quarantine
// bytes are untouched either way (WORM) — this only prunes the release
// POINTER record, never the audit copy.
const terminalRetention = 24 * time.Hour

func (s *FileStore) persist() error {
	s.pruneLocked()
	out := make([]Release, 0, len(s.releases))
	for _, r := range s.releases {
		out = append(out, *r)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeFileDurable(s.path, data, 0o600)
}

func (s *FileStore) pruneLocked() {
	now := s.now()
	for id, r := range s.releases {
		if now.After(r.ExpiresAt.Add(terminalRetention)) {
			delete(s.releases, id)
		}
	}
}

// Create records a new release.
func (s *FileStore) Create(rel Release, ttl time.Duration) (Release, error) {
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	now := s.now().UTC()
	rel.ID = uuid.NewString()
	rel.ApprovedAt = now
	rel.ExpiresAt = now.Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()
	r := rel
	s.releases[rel.ID] = &r
	if err := s.persist(); err != nil {
		delete(s.releases, rel.ID)
		return Release{}, fmt.Errorf("release: create: %w", err)
	}
	return r, nil
}

// ListFor returns requester's own non-expired releases as of now.
func (s *FileStore) ListFor(requester string, now time.Time) []Release {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Release
	for _, r := range s.releases {
		if r.Requester == requester && now.Before(r.ExpiresAt) {
			out = append(out, *r)
		}
	}
	return out
}

// Get returns one release, only if it belongs to requester and is unexpired.
func (s *FileStore) Get(requester, id string, now time.Time) (Release, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.releases[id]
	if !ok || r.Requester != requester || !now.Before(r.ExpiresAt) {
		return Release{}, false
	}
	return *r, true
}

// writeFileDurable writes data to path atomically and durably — identical
// implementation to approval.FileStore's helper of the same name; duplicated
// rather than shared to keep internal/release independent of
// internal/approval (both are leaves, neither should depend on the other).
func writeFileDurable(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".release-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
