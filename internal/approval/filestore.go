package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FileStore is a durable approval store backed by a single JSON file. Every
// mutation is persisted atomically (temp + fsync + rename), so a pending request
// survives a process restart and can still be approved.
type FileStore struct {
	path string
	now  func() time.Time

	mu       sync.Mutex
	requests map[string]*Request
	decided  map[string]chan struct{} // closed when a request leaves pending (per process)
}

// NewFileStore opens (creating if absent) the store at path and loads any
// existing requests. On load, pending requests keep their persisted ExpiresAt,
// so TTL and four-eyes still apply after a restart.
func NewFileStore(path string) (*FileStore, error) {
	return newFileStore(path, time.Now)
}

func newFileStore(path string, now func() time.Time) (*FileStore, error) {
	s := &FileStore{
		path:     path,
		now:      now,
		requests: map[string]*Request{},
		decided:  map[string]chan struct{}{},
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("approval: read store: %w", err)
	}
	var reqs []Request
	if len(data) > 0 {
		if err := json.Unmarshal(data, &reqs); err != nil {
			return nil, fmt.Errorf("approval: parse store: %w", err)
		}
	}
	for i := range reqs {
		r := reqs[i]
		s.requests[r.ID] = &r
		ch := make(chan struct{})
		if r.Status != StatusPending {
			close(ch) // already decided before the restart
		}
		s.decided[r.ID] = ch
	}
	return s, nil
}

// terminalRetention is how long a decided/expired request is kept before being
// pruned, so the durable file (rewritten on the data path per new request)
// cannot grow without bound.
const terminalRetention = 24 * time.Hour

// persist prunes old terminal requests then writes all requests durably.
// Caller holds s.mu.
func (s *FileStore) persist() error {
	s.pruneLocked()
	out := make([]Request, 0, len(s.requests))
	for _, r := range s.requests {
		out = append(out, *r)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeFileDurable(s.path, data, 0o600)
}

// pruneLocked drops decided/expired requests whose expiry is older than the
// retention horizon, bounding file size and per-Create rewrite cost. Caller
// holds s.mu. A pending request is never pruned.
func (s *FileStore) pruneLocked() {
	now := s.now()
	for id, r := range s.requests {
		if r.EffectiveStatus(now) == StatusPending {
			continue
		}
		if now.After(r.ExpiresAt.Add(terminalRetention)) {
			delete(s.requests, id)
			delete(s.decided, id)
		}
	}
}

// canonicalID normalizes an identity for four-eyes comparison.
func canonicalID(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Create records a new pending request.
func (s *FileStore) Create(req Request, ttl time.Duration) (Request, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := s.now().UTC()
	req.ID = uuid.NewString()
	req.Status = StatusPending
	req.Approver = ""
	req.CreatedAt = now
	req.ExpiresAt = now.Add(ttl)
	req.DecidedAt = time.Time{}
	if req.Kind == "" {
		req.Kind = KindSession
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	r := req
	s.requests[req.ID] = &r
	s.decided[req.ID] = make(chan struct{})
	if err := s.persist(); err != nil {
		delete(s.requests, req.ID)
		delete(s.decided, req.ID)
		return Request{}, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	return r, nil
}

// Get returns one request with TTL applied.
func (s *FileStore) Get(id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[id]
	if !ok {
		return Request{}, false
	}
	out := *r
	out.Status = r.EffectiveStatus(s.now())
	return out, true
}

// List returns all requests with TTL applied.
func (s *FileStore) List() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]Request, 0, len(s.requests))
	for _, r := range s.requests {
		c := *r
		c.Status = r.EffectiveStatus(now)
		out = append(out, c)
	}
	return out
}

// Approve decides a pending request, enforcing four-eyes.
func (s *FileStore) Approve(id, approver string) (Request, error) {
	return s.decide(id, approver, StatusApproved)
}

// Deny decides a pending request.
func (s *FileStore) Deny(id, approver string) (Request, error) {
	return s.decide(id, approver, StatusDenied)
}

func (s *FileStore) decide(id, approver string, status Status) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[id]
	if !ok {
		return Request{}, ErrNotFound
	}
	// A request that has already expired (by TTL) cannot be decided.
	if r.EffectiveStatus(s.now()) != StatusPending {
		return Request{}, ErrNotPending
	}
	// Four-eyes: the approver must be a distinct actor from the requester.
	// Identifiers are canonicalized (trim + lowercase) so case/whitespace
	// variants cannot smuggle a self-approval. NOTE: this compares the API
	// subject (token subject / mTLS CN) against the SSH principal that made the
	// request — the deployment MUST configure API subjects to equal SSH login
	// names, or four-eyes can be defeated across the two namespaces.
	if approver == "" || canonicalID(approver) == canonicalID(r.Requester) {
		return Request{}, ErrFourEyes
	}
	r.Status = status
	r.Approver = approver
	r.DecidedAt = s.now().UTC()
	if err := s.persist(); err != nil {
		// Roll back the in-memory decision so state matches disk.
		r.Status = StatusPending
		r.Approver = ""
		r.DecidedAt = time.Time{}
		return Request{}, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	s.closeDecided(id)
	return *r, nil
}

// closeDecided signals waiters. Caller holds s.mu.
func (s *FileStore) closeDecided(id string) {
	if ch, ok := s.decided[id]; ok {
		select {
		case <-ch: // already closed
		default:
			close(ch)
		}
	}
}

// Wait blocks until the request is decided, expires, or ctx is done.
func (s *FileStore) Wait(ctx context.Context, id string) (Request, error) {
	s.mu.Lock()
	r, ok := s.requests[id]
	if !ok {
		s.mu.Unlock()
		return Request{}, ErrNotFound
	}
	ch := s.decided[id]
	expiry := r.ExpiresAt
	s.mu.Unlock()

	// If already decided, return immediately.
	select {
	case <-ch:
		got, _ := s.Get(id)
		return got, nil
	default:
	}

	timer := time.NewTimer(time.Until(expiry))
	defer timer.Stop()
	select {
	case <-ch:
		got, _ := s.Get(id)
		return got, nil
	case <-timer.C:
		// TTL elapsed with no decision: mark expired durably, fail closed.
		s.mu.Lock()
		if cur, ok := s.requests[id]; ok && cur.Status == StatusPending {
			cur.Status = StatusExpired
			cur.DecidedAt = s.now().UTC()
			_ = s.persist() // best-effort; status is already expired in memory
			s.closeDecided(id)
		}
		s.mu.Unlock()
		got, _ := s.Get(id)
		return got, nil
	case <-ctx.Done():
		got, _ := s.Get(id)
		return got, ctx.Err()
	}
}

// writeFileDurable writes data to path atomically and durably.
func writeFileDurable(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".approval-*")
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
