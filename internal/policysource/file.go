package policysource

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/config"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// FileSource loads the policy from a YAML file and hot-reloads it when the file
// changes on disk (polling its modification time). A parse error keeps the last
// good policy in force rather than dropping to deny-all.
type FileSource struct {
	path     string
	interval time.Duration
}

// NewFileSource returns a file-backed policy source. interval<=0 uses 2s.
func NewFileSource(path string, interval time.Duration) *FileSource {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &FileSource{path: path, interval: interval}
}

// Load compiles the current policy from the file.
func (s *FileSource) Load() (policy.Policy, error) {
	return config.LoadPolicyDoc(s.path)
}

// Watch polls the file's mtime and calls onChange with the recompiled policy on
// each successful change until ctx is cancelled.
func (s *FileSource) Watch(ctx context.Context, onChange func(policy.Policy)) {
	last := s.modTime()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			mt := s.modTime()
			if mt.Equal(last) {
				continue
			}
			last = mt
			p, err := s.Load()
			if err != nil {
				log.Printf("omni-sag: policy reload failed, keeping previous policy: %v", err)
				continue
			}
			log.Printf("omni-sag: policy reloaded from %s", s.path)
			onChange(p)
		}
	}
}

func (s *FileSource) modTime() time.Time {
	fi, err := os.Stat(s.path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}
