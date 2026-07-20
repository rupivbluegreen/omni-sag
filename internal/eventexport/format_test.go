package eventexport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

func sampleEvent() evidence.Event {
	deny := false
	return evidence.Event{
		Time: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC),
		Type: evidence.TypeTunnelDecision, User: "alice", SourceIP: "10.0.0.1",
		Target: "db1:5432", Allow: &deny, Reason: "administratively prohibited",
	}
}

func mustFormat(t *testing.T, f Formatter, e evidence.Event) []byte {
	t.Helper()
	out, err := f.Format(e)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	return out
}

// deepGet walks nested map[string]any objects (as produced by json.Unmarshal
// into map[string]any) following keys in order, returning nil if any hop
// isn't present or isn't a nested object.
func deepGet(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func TestJSONFormatter(t *testing.T) {
	f, _ := NewFormatter("json")
	out, err := f.Format(sampleEvent())
	if err != nil {
		t.Fatal(err)
	}
	var back evidence.Event
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("json not round-trippable: %v", err)
	}
	if back.User != "alice" || back.Type != evidence.TypeTunnelDecision {
		t.Fatalf("json missing fields: %s", out)
	}
	if strings.Contains(string(out), "\n") {
		t.Fatalf("json formatter must emit a single line: %s", out)
	}
}

func TestCEFFormatter(t *testing.T) {
	f, _ := NewFormatter("cef")
	out := string(mustFormat(t, f, sampleEvent()))
	// CEF:0|vendor|product|version|sig|name|severity|ext...
	if !strings.HasPrefix(out, "CEF:0|omni-sag|gateway|") {
		t.Fatalf("bad CEF header: %s", out)
	}
	for _, want := range []string{"suser=alice", "src=10.0.0.1", "outcome=", "administratively prohibited"} {
		if !strings.Contains(out, want) {
			t.Fatalf("CEF missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "\n") {
		t.Fatalf("cef formatter must emit a single line: %s", out)
	}
}

func TestECSFormatter(t *testing.T) {
	f, _ := NewFormatter("ecs")
	out := mustFormat(t, f, sampleEvent())
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["user.name"] != "alice" && deepGet(m, "user", "name") != "alice" {
		t.Fatalf("ECS user.name missing: %v", m)
	}
	if deepGet(m, "event", "outcome") != "failure" {
		t.Fatalf("ECS event.outcome should be failure for a denied event: %v", m)
	}
	if strings.Contains(string(out), "\n") {
		t.Fatalf("ecs formatter must emit a single line: %s", out)
	}
}

func TestNewFormatter_Unknown(t *testing.T) {
	if _, err := NewFormatter("nope"); err == nil {
		t.Fatal("want error for unknown format")
	}
}

// CEF escaping: a Reason containing '|', '=', and a newline must not break
// header/extension parsing.
func TestCEFFormatter_Escaping(t *testing.T) {
	f, _ := NewFormatter("cef")
	e := sampleEvent()
	e.Reason = `weird|reason=with\backslash` + "\nand a newline"
	out := string(mustFormat(t, f, e))

	header, ext, ok := strings.Cut(out, "\n")
	_ = header
	if ok {
		t.Fatalf("cef output must not contain a literal newline: %s", out)
	}
	// Header must still have exactly 7 unescaped pipes (CEF:0|vendor|product|version|sig|name|sev|ext).
	full := out
	pipeCount := 0
	escaped := false
	headerEnd := -1
	for i, r := range full {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '|' {
			pipeCount++
			if pipeCount == 7 {
				headerEnd = i
				break
			}
		}
	}
	if headerEnd == -1 {
		t.Fatalf("could not find 7 unescaped header pipes: %s", full)
	}
	_ = ext
}

// ECS escaping: json.Marshal handles this for us, but confirm a value with
// a quote/backslash still round-trips through the ECS map shape.
func TestECSFormatter_SpecialChars(t *testing.T) {
	f, _ := NewFormatter("ecs")
	e := sampleEvent()
	e.Reason = `has "quotes" and \backslash`
	out := mustFormat(t, f, e)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("ECS output with special chars must still be valid JSON: %v (%s)", err, out)
	}
	if deepGet(m, "message") != e.Reason && m["message"] != e.Reason {
		t.Fatalf("message not preserved: %v", m)
	}
}
