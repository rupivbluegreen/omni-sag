package eventexport

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// TestFanout_SharedAcrossTwoWrappedSinks proves the shared-fan-out shape: ONE
// Fanout (one exporter set, one SIEM connection each) wraps TWO distinct
// durable sinks. Every event emitted through EITHER wrapped sink reaches its
// own inner (authoritative) AND both shared exporters — so a gateway with a
// dialer sink and a session sink never builds two exporter sets.
func TestFanout_SharedAcrossTwoWrappedSinks(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a.jsonl")
	fileB := filepath.Join(dir, "b.cef")

	cfg := Config{Enabled: true, Exporters: []ExporterConfig{
		{Name: "a", Format: "json", Transport: "file", File: &FileConfig{Path: fileA}},
		{Name: "b", Format: "cef", Transport: "file", File: &FileConfig{Path: fileB}},
	}}
	fo, err := NewFanout(cfg, func(string) {})
	if err != nil {
		t.Fatalf("NewFanout: %v", err)
	}
	if got := len(fo.exporters); got != 2 {
		t.Fatalf("exporters = %d, want 2", got)
	}

	innerDialer := evidence.NewMemSink()
	innerSession := evidence.NewMemSink()
	dialerSink := fo.Wrap(innerDialer)
	sessionSink := fo.Wrap(innerSession)

	const nEach = 25
	for i := 0; i < nEach; i++ {
		if err := dialerSink.Emit(evidence.Event{Type: evidence.TypeAuth, User: "d"}); err != nil {
			t.Fatalf("dialerSink.Emit %d: %v", i, err)
		}
	}
	for i := 0; i < nEach; i++ {
		if err := sessionSink.Emit(evidence.Event{Type: evidence.TypeAuth, User: "s"}); err != nil {
			t.Fatalf("sessionSink.Emit %d: %v", i, err)
		}
	}

	withTimeout(t, 10*time.Second, func() {
		if err := fo.Close(); err != nil {
			t.Fatalf("Fanout.Close: %v", err)
		}
	})

	if got := len(innerDialer.Events()); got != nEach {
		t.Fatalf("innerDialer has %d events, want %d", got, nEach)
	}
	if got := len(innerSession.Events()); got != nEach {
		t.Fatalf("innerSession has %d events, want %d", got, nEach)
	}

	// Both shared exporters must have seen ALL events from BOTH wrapped sinks.
	const wantTotal = 2 * nEach
	if got := len(readLines(t, fileA)); got != wantTotal {
		t.Fatalf("fileA (shared exporter a) has %d lines, want %d", got, wantTotal)
	}
	if got := len(readLines(t, fileB)); got != wantTotal {
		t.Fatalf("fileB (shared exporter b) has %d lines, want %d", got, wantTotal)
	}
}

// closeTrackingSink wraps an evidence.Sink and records whether/how-many-times
// Close was called, so tests can assert Close ownership boundaries.
type closeTrackingSink struct {
	evidence.Sink
	closes int
}

func (c *closeTrackingSink) Close() error {
	c.closes++
	return c.Sink.Close()
}

// TestFanout_WrapCloseClosesOnlyInner proves a wrapped sink's Close() closes
// only its own inner — the Fanout (and its shared exporters, and any other
// wrapped sink sharing them) must stay alive until Fanout.Close() runs.
func TestFanout_WrapCloseClosesOnlyInner(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Enabled: true, Exporters: []ExporterConfig{
		{Name: "a", Format: "json", Transport: "file", File: &FileConfig{Path: filepath.Join(dir, "a.jsonl")}},
	}}
	fo, err := NewFanout(cfg, func(string) {})
	if err != nil {
		t.Fatalf("NewFanout: %v", err)
	}

	inner1 := &closeTrackingSink{Sink: evidence.NewMemSink()}
	inner2 := &closeTrackingSink{Sink: evidence.NewMemSink()}
	sink1 := fo.Wrap(inner1)
	sink2 := fo.Wrap(inner2)

	if err := sink1.Close(); err != nil {
		t.Fatalf("sink1.Close: %v", err)
	}
	if inner1.closes != 1 {
		t.Fatalf("sink1.Close should have closed inner1 once, got %d", inner1.closes)
	}
	if inner2.closes != 0 {
		t.Fatal("sink1.Close must not close inner2 (a different wrapped sink)")
	}

	// sink2 must still work — the shared exporters are still alive.
	if err := sink2.Emit(evidence.Event{Type: evidence.TypeAuth, User: "u"}); err != nil {
		t.Fatalf("sink2.Emit after sink1.Close: %v", err)
	}

	withTimeout(t, 10*time.Second, func() {
		if err := fo.Close(); err != nil {
			t.Fatalf("Fanout.Close: %v", err)
		}
	})
	if inner2.closes != 0 {
		t.Fatal("inner2 should not be closed by Fanout.Close (Fanout does not own wrapped inners)")
	}
}

// TestFanout_New_UnknownFormat proves NewFanout shares the same eager
// validation as New — a boot error, not a silent runtime drop.
func TestFanout_New_UnknownFormat(t *testing.T) {
	cfg := Config{Exporters: []ExporterConfig{
		{Name: "a", Format: "bogus", Transport: "file", File: &FileConfig{Path: filepath.Join(t.TempDir(), "e.jsonl")}},
	}}
	if _, err := NewFanout(cfg, func(string) {}); err == nil {
		t.Fatal("NewFanout: want error for unknown format, got nil")
	}
}
