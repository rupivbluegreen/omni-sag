package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/google/uuid"
)

// FileSink appends events as JSON lines (JSONL) to a file. It is the
// zero-infrastructure sink used in development and tests.
type FileSink struct {
	mu sync.Mutex
	f  *os.File
	w  *json.Encoder
}

// NewFileSink opens (creating if needed, appending if present) the JSONL file
// at path.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("evidence: open %s: %w", path, err)
	}
	return &FileSink{f: f, w: json.NewEncoder(f)}, nil
}

// Emit writes one event as a JSON line. It fills ID and Time if unset.
func (s *FileSink) Emit(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if err := s.w.Encode(e); err != nil {
		return fmt.Errorf("evidence: encode: %w", err)
	}
	return s.f.Sync()
}

// Close closes the underlying file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
