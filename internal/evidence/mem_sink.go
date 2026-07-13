package evidence

import (
	"sync"

	"github.com/google/uuid"
)

// MemSink records events in memory. Useful for tests and for asserting on the
// evidence a code path produced.
type MemSink struct {
	mu     sync.Mutex
	events []Event
}

// NewMemSink returns an empty in-memory sink.
func NewMemSink() *MemSink { return &MemSink{} }

// Emit appends the event, assigning an ID if unset.
func (s *MemSink) Emit(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	s.events = append(s.events, e)
	return nil
}

// Close is a no-op.
func (s *MemSink) Close() error { return nil }

// Events returns a copy of the recorded events.
func (s *MemSink) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}
