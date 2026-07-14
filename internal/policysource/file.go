package policysource

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/config"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// FileSource loads the policy from a YAML file and hot-reloads it when the file
// content changes on disk. Change detection is by CONTENT HASH (not mtime), so
// two edits in the same second, mtime-preserving writes, and partial reads
// during an atomic rename are all handled correctly. A parse or validation
// error keeps the last good policy in force rather than dropping to deny-all.
type FileSource struct {
	path     string
	interval time.Duration

	mu       sync.Mutex
	lastHash string // hash of the content last loaded by Load
}

// NewFileSource returns a file-backed policy source. interval<=0 uses 2s.
func NewFileSource(path string, interval time.Duration) *FileSource {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &FileSource{path: path, interval: interval}
}

// Load compiles (and validates) the current policy from the file, recording the
// content hash so Watch's baseline reflects exactly what was loaded (closing the
// window between the initial Load and Watch starting).
func (s *FileSource) Load() (policy.Policy, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("read policy %s: %w", s.path, err)
	}
	p, err := config.CompilePolicyBytes(data)
	if err != nil {
		return policy.Policy{}, err
	}
	s.mu.Lock()
	s.lastHash = hashBytes(data)
	s.mu.Unlock()
	return p, nil
}

// Watch polls the file content and calls onChange with the recompiled policy on
// each successful change until ctx is cancelled. Its baseline is the hash from
// the initial Load, so an edit made before Watch starts is not missed.
func (s *FileSource) Watch(ctx context.Context, onChange func(policy.Policy)) {
	s.mu.Lock()
	baseline := s.lastHash
	s.mu.Unlock()

	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			data, err := os.ReadFile(s.path)
			if err != nil {
				continue // transient (e.g. mid-rename); retry next tick
			}
			h := hashBytes(data)
			if h == baseline {
				continue
			}
			// Advance the baseline regardless of outcome so a persistently bad
			// file is not re-parsed and re-logged every tick; a later good edit
			// has a different hash and is picked up.
			baseline = h
			p, perr := config.CompilePolicyBytes(data)
			if perr != nil {
				log.Printf("omni-sag: policy reload rejected, keeping previous policy: %v", perr)
				continue
			}
			log.Printf("omni-sag: policy reloaded from %s", s.path)
			onChange(p)
		}
	}
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return string(sum[:])
}
