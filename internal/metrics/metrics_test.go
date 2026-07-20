package metrics

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

type failSink struct{}

func (failSink) Emit(evidence.Event) error { return errors.New("down") }
func (failSink) Close() error              { return nil }

func TestCountingSink_CountsByType(t *testing.T) {
	m := New()
	s := m.CountingSink(evidence.NewMemSink())
	emit := func(typ evidence.Type, allow bool, verdict, outcome string) {
		_ = s.Emit(evidence.Event{Type: typ, Allow: evidence.BoolPtr(allow), Verdict: verdict, Outcome: outcome})
	}
	emit(evidence.TypeAuth, true, "", "")
	emit(evidence.TypeAuth, false, "", "")
	emit(evidence.TypeTunnelDecision, true, "", "")
	emit(evidence.TypeApproval, false, "", "refused") // terminal refusal
	emit(evidence.TypeInspection, false, "blocked", "")
	emit(evidence.TypeInspection, true, "clean", "")

	if m.authSuccess.get() != 1 || m.authFailure.get() != 1 {
		t.Fatalf("auth counters wrong: %d/%d", m.authSuccess.get(), m.authFailure.get())
	}
	if m.tunnelAllow.get() != 1 || m.approvalRefused.get() != 1 {
		t.Fatal("tunnel/approval counters wrong")
	}
	if m.inspectBlocked.get() != 1 || m.inspectClean.get() != 1 {
		t.Fatalf("inspection counters wrong: %d/%d", m.inspectBlocked.get(), m.inspectClean.get())
	}
}

func TestCountingSink_CountsEmitFailures(t *testing.T) {
	m := New()
	s := m.CountingSink(failSink{})
	if err := s.Emit(evidence.Event{Type: evidence.TypeAuth, Allow: evidence.BoolPtr(true)}); err == nil {
		t.Fatal("expected the inner emit error to propagate")
	}
	if m.evidenceEmitFailures.get() != 1 {
		t.Fatal("an emit failure must be counted")
	}
}

func TestIncExportDrop_CountsPerExporterName(t *testing.T) {
	m := New()
	m.IncExportDrop("arcsight")
	m.IncExportDrop("arcsight")
	m.IncExportDrop("elastic-filebeat")

	var b bytes.Buffer
	m.WriteText(&b)
	body := b.String()
	if !strings.Contains(body, `omnisag_eventexport_dropped_total{exporter="arcsight"} 2`) {
		t.Fatalf("missing/wrong arcsight drop count:\n%s", body)
	}
	if !strings.Contains(body, `omnisag_eventexport_dropped_total{exporter="elastic-filebeat"} 1`) {
		t.Fatalf("missing/wrong elastic-filebeat drop count:\n%s", body)
	}
}

func TestHandler_RendersPrometheus(t *testing.T) {
	m := New()
	m.SetActiveFn(func() int64 { return 3 })
	_ = m.CountingSink(evidence.NewMemSink()).Emit(evidence.Event{Type: evidence.TypeAuth, Allow: evidence.BoolPtr(true)})

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "omnisag_active_sessions 3") {
		t.Fatalf("missing active gauge:\n%s", body)
	}
	if !strings.Contains(body, "omnisag_auth_success_total 1") {
		t.Fatalf("missing auth counter:\n%s", body)
	}
	// Prometheus format sanity: every metric has HELP+TYPE.
	var b bytes.Buffer
	m.WriteText(&b)
	if strings.Count(b.String(), "# TYPE") < 13 {
		t.Fatal("expected a TYPE line per metric")
	}
}

func TestSetOTelExportFailuresFn_DefaultsZeroAndWiresThrough(t *testing.T) {
	m := New()
	var b bytes.Buffer
	m.WriteText(&b)
	if !strings.Contains(b.String(), "omnisag_otel_export_failures_total 0") {
		t.Fatalf("expected zero otel export failures by default:\n%s", b.String())
	}

	m.SetOTelExportFailuresFn(func() int64 { return 5 })
	b.Reset()
	m.WriteText(&b)
	if !strings.Contains(b.String(), "omnisag_otel_export_failures_total 5") {
		t.Fatalf("expected wired otel export failures count:\n%s", b.String())
	}
}
