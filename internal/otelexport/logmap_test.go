package otelexport

import (
	"testing"
	"time"

	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

func recordAttrs(t *testing.T, r log.Record) map[string]log.Value {
	t.Helper()
	m := make(map[string]log.Value, r.AttributesLen())
	r.WalkAttributes(func(kv log.KeyValue) bool {
		m[kv.Key] = kv.Value
		return true
	})
	return m
}

var testSpanContext = trace.NewSpanContext(trace.SpanContextConfig{
	TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	SpanID:     trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
	TraceFlags: trace.FlagsSampled,
})

func TestEventToLogRecord_TableDriven(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		e            evidence.Event
		wantSeverity log.Severity
		wantBodyHas  string
	}{
		{
			name:         "auth allow",
			e:            evidence.Event{ID: "e1", Time: now, Type: evidence.TypeAuth, User: "alice", SourceIP: "10.0.0.5", Allow: evidence.BoolPtr(true), Reason: "authenticated"},
			wantSeverity: log.SeverityInfo,
			wantBodyHas:  "authenticated",
		},
		{
			name:         "auth deny",
			e:            evidence.Event{ID: "e2", Time: now, Type: evidence.TypeAuth, User: "mallory", Allow: evidence.BoolPtr(false), Reason: "authentication failed"},
			wantSeverity: log.SeverityWarn,
			wantBodyHas:  "authentication failed",
		},
		{
			name:         "tunnel_decision allow",
			e:            evidence.Event{ID: "e3", Time: now, Type: evidence.TypeTunnelDecision, User: "alice", Target: "db1:5432", Allow: evidence.BoolPtr(true), MatchedRole: "dba"},
			wantSeverity: log.SeverityInfo,
			wantBodyHas:  string(evidence.TypeTunnelDecision),
		},
		{
			name:         "transfer",
			e:            evidence.Event{ID: "e4", Time: now, Type: evidence.TypeTransfer, User: "alice", Path: "/f.txt", Bytes: 100, Direction: "download"},
			wantSeverity: log.SeverityInfo,
			wantBodyHas:  string(evidence.TypeTransfer),
		},
		{
			name:         "inspection blocked",
			e:            evidence.Event{ID: "e5", Time: now, Type: evidence.TypeInspection, User: "alice", Verdict: "blocked", Allow: evidence.BoolPtr(false), Reason: "malware detected"},
			wantSeverity: log.SeverityError,
			wantBodyHas:  "malware detected",
		},
		{
			name:         "approval granted",
			e:            evidence.Event{ID: "e6", Time: now, Type: evidence.TypeApproval, User: "alice", Outcome: "granted", Allow: evidence.BoolPtr(true)},
			wantSeverity: log.SeverityInfo,
			wantBodyHas:  string(evidence.TypeApproval),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := EventToLogRecord(tt.e, trace.SpanContext{})
			if !r.Timestamp().Equal(now) {
				t.Fatalf("Timestamp = %v, want %v", r.Timestamp(), now)
			}
			if r.Severity() != tt.wantSeverity {
				t.Fatalf("Severity = %v, want %v", r.Severity(), tt.wantSeverity)
			}
			body := r.Body().AsString()
			if body == "" {
				t.Fatal("Body must not be empty")
			}
			attrs := recordAttrs(t, r)
			if attrs["user"].AsString() != tt.e.User {
				t.Fatalf("user attr = %q, want %q", attrs["user"].AsString(), tt.e.User)
			}
			if attrs["type"].AsString() != string(tt.e.Type) {
				t.Fatalf("type attr = %q, want %q", attrs["type"].AsString(), tt.e.Type)
			}
			if attrs["evidence_id"].AsString() != tt.e.ID {
				t.Fatalf("evidence_id attr = %q, want %q", attrs["evidence_id"].AsString(), tt.e.ID)
			}
			if tt.e.SourceIP != "" && attrs["source_ip"].AsString() != tt.e.SourceIP {
				t.Fatalf("source_ip attr = %q, want %q", attrs["source_ip"].AsString(), tt.e.SourceIP)
			}
			if tt.e.Target != "" && attrs["target"].AsString() != tt.e.Target {
				t.Fatalf("target attr = %q, want %q", attrs["target"].AsString(), tt.e.Target)
			}
			if tt.e.Verdict != "" && attrs["verdict"].AsString() != tt.e.Verdict {
				t.Fatalf("verdict attr = %q, want %q", attrs["verdict"].AsString(), tt.e.Verdict)
			}
			if _, ok := attrs["trace_id"]; ok {
				t.Fatal("trace_id must not appear for an invalid SpanContext")
			}
		})
	}
}

func TestEventToLogRecord_TraceIDPresentIffSpanContextValid(t *testing.T) {
	e := evidence.Event{ID: "e1", Time: time.Now(), Type: evidence.TypeAuth, User: "alice"}

	withoutSpan := EventToLogRecord(e, trace.SpanContext{})
	attrs := recordAttrs(t, withoutSpan)
	if _, ok := attrs["trace_id"]; ok {
		t.Fatal("trace_id must be absent for an invalid SpanContext")
	}
	if _, ok := attrs["span_id"]; ok {
		t.Fatal("span_id must be absent for an invalid SpanContext")
	}

	withSpan := EventToLogRecord(e, testSpanContext)
	attrs = recordAttrs(t, withSpan)
	if attrs["trace_id"].AsString() != testSpanContext.TraceID().String() {
		t.Fatalf("trace_id = %q, want %q", attrs["trace_id"].AsString(), testSpanContext.TraceID().String())
	}
	if attrs["span_id"].AsString() != testSpanContext.SpanID().String() {
		t.Fatalf("span_id = %q, want %q", attrs["span_id"].AsString(), testSpanContext.SpanID().String())
	}
}
