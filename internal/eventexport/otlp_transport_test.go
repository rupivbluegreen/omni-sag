package eventexport

import (
	"context"
	"sync"
	"testing"
	"time"

	logglobal "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// otlpRecordingProcessor is a minimal in-memory sdklog.Processor test
// double, standing in for a real OTLP log exporter.
type otlpRecordingProcessor struct {
	mu    sync.Mutex
	count int
}

func (p *otlpRecordingProcessor) OnEmit(context.Context, *sdklog.Record) error {
	p.mu.Lock()
	p.count++
	p.mu.Unlock()
	return nil
}
func (p *otlpRecordingProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }
func (p *otlpRecordingProcessor) Shutdown(context.Context) error                         { return nil }
func (p *otlpRecordingProcessor) ForceFlush(context.Context) error                       { return nil }

func (p *otlpRecordingProcessor) count_() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

// TestIntegration_OTLPTransportEmitsThroughRealLogPipeline proves the
// experimental `otlp` transport (internal/otelexport.LogTransport), wired
// through New exactly like file/syslog/http, reaches the real OTel logs
// SDK — reusing this package's fan-out/bounded-buffer engine, not a second
// parallel pump (see the design doc's #19 boundary).
func TestIntegration_OTLPTransportEmitsThroughRealLogPipeline(t *testing.T) {
	rp := &otlpRecordingProcessor{}
	logglobal.SetLoggerProvider(sdklog.NewLoggerProvider(sdklog.WithProcessor(rp)))

	inner := evidence.NewMemSink()
	cfg := Config{Enabled: true, Exporters: []ExporterConfig{
		{Name: "otel-logs", Format: "json", Transport: "otlp"},
	}}
	sink, err := New(inner, cfg, func(string) {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Emit(evidence.Event{Type: evidence.TypeAuth, User: "alice", Allow: evidence.BoolPtr(true), Reason: "authenticated"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && rp.count_() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if rp.count_() < 1 {
		t.Fatal("expected at least one log record emitted through the real OTel log pipeline")
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestBuildTransport_OTLPRejectsNonJSONFormat proves the otlp transport
// fails fast at boot (not silently at runtime) when paired with a
// non-json Format.
func TestBuildTransport_OTLPRejectsNonJSONFormat(t *testing.T) {
	_, err := New(evidence.NewMemSink(), Config{Enabled: true, Exporters: []ExporterConfig{
		{Name: "otel-logs", Format: "ecs", Transport: "otlp"},
	}}, func(string) {})
	if err == nil {
		t.Fatal("expected otlp+non-json format to be rejected at boot")
	}
}
