package evidence

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSink_EmitAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Emit(Event{Type: TypeAuth, User: "alice", Detail: "bind ok"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Emit(Event{Type: TypeTunnelDecision, User: "alice",
		Target: "db1.lab.local:5432", Allow: BoolPtr(true), Reason: "allowed by role dba", MatchedRole: "dba"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad JSONL line: %v", err)
		}
		events = append(events, e)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].ID == "" {
		t.Fatal("Emit must assign an ID")
	}
	if events[1].Allow == nil || !*events[1].Allow {
		t.Fatal("second event should be an allow decision")
	}
	if events[1].MatchedRole != "dba" {
		t.Fatalf("MatchedRole = %q", events[1].MatchedRole)
	}
}

func TestFileSink_AppendsAcrossOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	s1, _ := NewFileSink(path)
	_ = s1.Emit(Event{Type: TypeAuth, User: "a"})
	_ = s1.Close()

	s2, _ := NewFileSink(path)
	_ = s2.Emit(Event{Type: TypeAuth, User: "b"})
	_ = s2.Close()

	data, _ := os.ReadFile(path)
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Fatalf("expected 2 appended lines, got %d", lines)
	}
}
