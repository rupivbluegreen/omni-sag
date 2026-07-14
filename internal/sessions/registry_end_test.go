package sessions

import (
	"testing"
	"time"
)

// Deregistering a session must publish a session_end event so an attached
// supervisor gets a terminal signal (and its SSE stream can close).
func TestDeregister_PublishesSessionEnd(t *testing.T) {
	r := NewRegistry()
	id, dereg := r.Register(Info{User: "alice"}, nil)
	ch, cancel := r.Subscribe(id)
	defer cancel()

	dereg()

	select {
	case ev := <-ch:
		if ev.Kind != "session_end" {
			t.Fatalf("want session_end, got %q", ev.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("deregister did not publish session_end")
	}
}
