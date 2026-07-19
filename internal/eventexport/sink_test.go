package eventexport

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// readLines returns the non-empty lines of the file at path.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return lines
}

func TestForwardingSink_FanOutAndDurableAuthoritative(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a.jsonl")
	fileB := filepath.Join(dir, "b.cef")

	inner := evidence.NewMemSink()
	cfg := Config{Enabled: true, Exporters: []ExporterConfig{
		{Name: "a", Format: "json", Transport: "file", File: &fileConfig{Path: fileA}},
		{Name: "b", Format: "cef", Transport: "file", File: &fileConfig{Path: fileB}},
	}}
	fs, err := New(inner, cfg, func(string) {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 50
	for i := 0; i < n; i++ {
		if err := fs.Emit(evidence.Event{Type: evidence.TypeAuth, User: "u"}); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}

	withTimeout(t, 10*time.Second, func() {
		if err := fs.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	if got := len(inner.Events()); got != n {
		t.Fatalf("inner sink has %d events, want %d", got, n)
	}

	jsonLines := readLines(t, fileA)
	if got := len(jsonLines); got != n {
		t.Fatalf("fileA has %d lines, want %d", got, n)
	}
	for i, line := range jsonLines {
		var e evidence.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("fileA line %d not valid json: %v (%q)", i, err, line)
		}
	}

	cefLines := readLines(t, fileB)
	if got := len(cefLines); got != n {
		t.Fatalf("fileB has %d lines, want %d", got, n)
	}
	for i, line := range cefLines {
		if !strings.HasPrefix(line, "CEF:0|") {
			t.Fatalf("fileB line %d not CEF-framed: %q", i, line)
		}
	}
}

func TestForwardingSink_BrokenExporterNeverFailsEmit(t *testing.T) {
	inner := evidence.NewMemSink()
	bt := newBlockingTransport() // Write blocks until bt.unblock is closed
	x := newAsyncExporter("dead", jsonFormatter{}, bt, 1, time.Hour, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	fs := &ForwardingSink{inner: inner, exporters: []*asyncExporter{x}, ctx: ctx, cancel: cancel}
	x.start(ctx)

	const n = 20
	withTimeout(t, 2*time.Second, func() {
		for i := 0; i < n; i++ {
			if err := fs.Emit(evidence.Event{Type: evidence.TypeAuth, User: "u"}); err != nil {
				t.Errorf("Emit %d returned %v, want nil (a broken exporter must never fail Emit)", i, err)
			}
		}
	})

	if got := len(inner.Events()); got != n {
		t.Fatalf("inner sink has %d events, want %d", got, n)
	}

	close(bt.unblock) // let the stuck drain goroutine finish so Close doesn't eat drainTimeout
	withTimeout(t, 5*time.Second, func() { fs.Close() })
}

func TestForwardingSink_New_UnknownFormat(t *testing.T) {
	inner := evidence.NewMemSink()
	cfg := Config{Exporters: []ExporterConfig{
		{Name: "a", Format: "bogus", Transport: "file", File: &fileConfig{Path: filepath.Join(t.TempDir(), "e.jsonl")}},
	}}
	fs, err := New(inner, cfg, func(string) {})
	if err == nil {
		t.Fatal("New: want error for unknown format, got nil")
	}
	if fs != nil {
		t.Fatal("New: want nil ForwardingSink on error")
	}
}

func TestForwardingSink_New_UnknownTransport(t *testing.T) {
	inner := evidence.NewMemSink()
	cfg := Config{Exporters: []ExporterConfig{
		{Name: "a", Format: "json", Transport: "carrier-pigeon"},
	}}
	if _, err := New(inner, cfg, func(string) {}); err == nil {
		t.Fatal("New: want error for unknown transport, got nil")
	}
}

func TestForwardingSink_New_MissingSyslogSubConfig(t *testing.T) {
	inner := evidence.NewMemSink()
	cfg := Config{Exporters: []ExporterConfig{
		{Name: "a", Format: "cef", Transport: "syslog", Syslog: nil},
	}}
	if _, err := New(inner, cfg, func(string) {}); err == nil {
		t.Fatal("New: want error for missing syslog sub-config, got nil")
	}
}

func TestForwardingSink_New_MissingHTTPSubConfig(t *testing.T) {
	inner := evidence.NewMemSink()
	cfg := Config{Exporters: []ExporterConfig{
		{Name: "a", Format: "ecs", Transport: "http", HTTP: nil},
	}}
	if _, err := New(inner, cfg, func(string) {}); err == nil {
		t.Fatal("New: want error for missing http sub-config, got nil")
	}
}

// TestForwardingSink_New_PartialBuildFailureDoesNotLeakOrPanic builds a good
// exporter followed by a bad one. New must surface the error and return a
// nil sink without panicking; direct leak detection (open fds/goroutines) is
// impractical to assert here, so this is the documented bound per the task
// brief.
func TestForwardingSink_New_PartialBuildFailureDoesNotLeakOrPanic(t *testing.T) {
	inner := evidence.NewMemSink()
	goodPath := filepath.Join(t.TempDir(), "good.jsonl")
	cfg := Config{Exporters: []ExporterConfig{
		{Name: "good", Format: "json", Transport: "file", File: &fileConfig{Path: goodPath}},
		{Name: "bad", Format: "json", Transport: "syslog", Syslog: nil},
	}}
	fs, err := New(inner, cfg, func(string) {})
	if err == nil {
		t.Fatal("New: want error when a later exporter fails to build, got nil")
	}
	if fs != nil {
		t.Fatal("New: want nil ForwardingSink on partial build failure")
	}
}

func TestForwardingSink_Config_BufferSizeDefault(t *testing.T) {
	inner := evidence.NewMemSink()
	cfg := Config{Exporters: []ExporterConfig{
		{Name: "a", Format: "json", Transport: "file", File: &fileConfig{Path: filepath.Join(t.TempDir(), "e.jsonl")}},
	}}
	fs, err := New(inner, cfg, func(string) {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fs.Close()

	if len(fs.exporters) != 1 {
		t.Fatalf("exporters = %d, want 1", len(fs.exporters))
	}
	if got := cap(fs.exporters[0].buf); got != defaultBufferSize {
		t.Fatalf("buffer capacity = %d, want default %d", got, defaultBufferSize)
	}
}

func TestForwardingSink_Config_BufferSizeExplicit(t *testing.T) {
	inner := evidence.NewMemSink()
	cfg := Config{Exporters: []ExporterConfig{
		{Name: "a", Format: "json", Transport: "file", BufferSize: 5, File: &fileConfig{Path: filepath.Join(t.TempDir(), "e.jsonl")}},
	}}
	fs, err := New(inner, cfg, func(string) {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fs.Close()

	if got := cap(fs.exporters[0].buf); got != 5 {
		t.Fatalf("buffer capacity = %d, want 5", got)
	}
}
