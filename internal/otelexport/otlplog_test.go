package otelexport

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/log"
	logglobal "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// LogTransport's structural compliance with eventexport.Transport (the #19
// exporter matrix's interface) is enforced at compile time where it
// matters: internal/eventexport/sink.go's buildTransport returns
// NewLogTransport(...) typed as Transport. Asserting it again here would
// require importing eventexport from this package's test build, which
// (eventexport itself importing otelexport for that same reason) is an
// import cycle — internal test files are compiled as part of the package
// under test, unlike an external ...export_test package.

// recordingProcessor is a minimal in-memory sdklog.Processor test double,
// mirroring tracetest.SpanRecorder's role for traces (no equivalent ships
// for logs).
type recordingProcessor struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (p *recordingProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, r.Clone())
	return nil
}
func (p *recordingProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }
func (p *recordingProcessor) Shutdown(context.Context) error                         { return nil }
func (p *recordingProcessor) ForceFlush(context.Context) error                       { return nil }

func (p *recordingProcessor) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = nil
}

func (p *recordingProcessor) snapshot() []sdklog.Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]sdklog.Record, len(p.records))
	copy(out, p.records)
	return out
}

// otel's log/global has the same "first real provider wins" delegation
// gotcha as trace/metric globals (see internal/session/otel_trace_test.go
// and internal/dialer/otel_trace_test.go) — install exactly one recorder
// for the whole test binary and reset it per test.
var (
	sharedLogProcessorOnce sync.Once
	sharedLogProcessor     *recordingProcessor
)

func installLogRecorder(t *testing.T) *recordingProcessor {
	t.Helper()
	sharedLogProcessorOnce.Do(func() {
		sharedLogProcessor = &recordingProcessor{}
		logglobal.SetLoggerProvider(sdklog.NewLoggerProvider(sdklog.WithProcessor(sharedLogProcessor)))
	})
	sharedLogProcessor.reset()
	return sharedLogProcessor
}

func attrOf(r sdklog.Record, key string) (log.Value, bool) {
	var v log.Value
	found := false
	r.WalkAttributes(func(kv log.KeyValue) bool {
		if kv.Key == key {
			v, found = kv.Value, true
			return false
		}
		return true
	})
	return v, found
}

// TestLogTransport_WriteEmitsMappedRecord proves the otlp transport's real
// job: decode a jsonFormatter-shaped payload (exactly what #19 hands every
// Transport when Format: "json" is configured) and emit the mapped record
// through the installed Logger.
func TestLogTransport_WriteEmitsMappedRecord(t *testing.T) {
	rp := installLogRecorder(t)
	tr := NewLogTransport("test-exporter")

	e := evidence.Event{
		ID: "e1", Time: time.Now().UTC(), Type: evidence.TypeAuth,
		User: "alice", SourceIP: "10.0.0.5", Allow: evidence.BoolPtr(true), Reason: "authenticated",
	}
	payload, err := json.Marshal(e) // the exact shape eventexport's jsonFormatter produces
	if err != nil {
		t.Fatal(err)
	}

	if err := tr.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	records := rp.snapshot()
	if len(records) != 1 {
		t.Fatalf("expected 1 emitted record, got %d", len(records))
	}
	got := records[0]
	if got.Body().AsString() == "" {
		t.Fatal("expected a non-empty body")
	}
	if v, ok := attrOf(got, "user"); !ok || v.AsString() != "alice" {
		t.Fatalf("user attr = %v (ok=%v), want alice", v, ok)
	}
	if v, ok := attrOf(got, "evidence_id"); !ok || v.AsString() != "e1" {
		t.Fatalf("evidence_id attr = %v (ok=%v), want e1", v, ok)
	}
}

// TestLogTransport_WriteCorrelatesTraceIDFromEvent proves an event carrying
// TraceID/SpanID (Task 6's additive evidence fields, populated when a span
// was active) round-trips into the mapped record's trace_id/span_id
// attributes.
func TestLogTransport_WriteCorrelatesTraceIDFromEvent(t *testing.T) {
	rp := installLogRecorder(t)
	tr := NewLogTransport("test-exporter")

	e := evidence.Event{
		ID: "e2", Time: time.Now().UTC(), Type: evidence.TypeTransfer,
		User: "alice", TraceID: testSpanContext.TraceID().String(), SpanID: testSpanContext.SpanID().String(),
	}
	payload, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	records := rp.snapshot()
	if len(records) != 1 {
		t.Fatalf("expected 1 emitted record, got %d", len(records))
	}
	if v, ok := attrOf(records[0], "trace_id"); !ok || v.AsString() != testSpanContext.TraceID().String() {
		t.Fatalf("trace_id attr = %v (ok=%v), want %s", v, ok, testSpanContext.TraceID().String())
	}
}

func TestLogTransport_WriteRejectsMalformedPayload(t *testing.T) {
	tr := NewLogTransport("test-exporter")
	if err := tr.Write([]byte("not json")); err == nil {
		t.Fatal("expected an error decoding a malformed payload")
	}
}
