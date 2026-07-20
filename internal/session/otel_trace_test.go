package session

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// installSpanRecorder installs a fresh TracerProvider backed by an
// in-memory SpanRecorder as the global provider, restoring the previous
// global provider on test cleanup so tests never leak state into each
// other.
func installSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})
	otel.SetTracerProvider(tp)
	return sr
}

// findSpan returns the first ended span named name, or nil.
func findSpan(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

func attrString(s sdktrace.ReadOnlySpan, key string) (string, bool) {
	for _, kv := range s.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

// driveAllowedForward starts a server+echo-target pair, dials as alice
// (member of dba, allowed to the echo target), forwards one -L connection
// through it, and waits for the connection to close — enough to complete a
// full omnisag.connection -> omnisag.auth -> omnisag.channel -> omnisag.tunnel
// lifecycle.
func driveAllowedForward(t *testing.T) {
	t.Helper()
	echoHost, echoPort := startEcho(t)
	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: echoHost, Ports: []int{echoPort}}},
	}}}
	sink := evidence.NewMemSink()
	auth := fakeAuth{users: map[string][]string{"alice": {"dba"}}}
	addr := startServer(t, p, auth, sink)

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err != nil {
		t.Fatalf("forward should be allowed: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	conn.Close()
	client.Close()
	// Give handleConn's per-channel goroutine and the connection teardown a
	// moment to run and end their spans.
	time.Sleep(150 * time.Millisecond)
}

func TestTracing_ConnectionAndAuthSpans(t *testing.T) {
	sr := installSpanRecorder(t)
	driveAllowedForward(t)

	ended := sr.Ended()
	root := findSpan(ended, "omnisag.connection")
	if root == nil {
		t.Fatalf("expected an omnisag.connection root span, got: %+v", ended)
	}
	if root.SpanKind() != trace.SpanKindServer {
		t.Fatalf("root span kind = %v, want SpanKindServer", root.SpanKind())
	}
	if u, ok := attrString(root, "omnisag.user"); !ok || u != "alice" {
		t.Fatalf("root span omnisag.user = %q (ok=%v), want alice", u, ok)
	}
	if _, ok := attrString(root, "client.address"); !ok {
		t.Fatal("root span missing client.address attribute")
	}

	auth := findSpan(ended, "omnisag.auth")
	if auth == nil {
		t.Fatalf("expected an omnisag.auth span, got: %+v", ended)
	}
	if auth.Parent().SpanID() != root.SpanContext().SpanID() {
		t.Fatal("omnisag.auth must be a child of the omnisag.connection root span")
	}
}

func TestTracing_DisabledProducesNoSpans(t *testing.T) {
	// No provider installed: the global tracer stays the default no-op, so
	// driving a real session must succeed exactly as without this feature —
	// proving the disabled instrumentation path is inert, not just cheap.
	driveAllowedForward(t)
}

// blackHoleExporter's ExportSpans blocks until its context is cancelled,
// simulating an unreachable/hung OTLP collector.
type blackHoleExporter struct{}

func (blackHoleExporter) ExportSpans(ctx context.Context, _ []sdktrace.ReadOnlySpan) error {
	<-ctx.Done()
	return ctx.Err()
}
func (blackHoleExporter) Shutdown(context.Context) error { return nil }

func TestTracing_ExporterErrorDoesNotBlockSession(t *testing.T) {
	prev := otel.GetTracerProvider()
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(blackHoleExporter{},
		sdktrace.WithExportTimeout(50*time.Millisecond)))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = tp.Shutdown(shutCtx)
		otel.SetTracerProvider(prev)
	})

	start := time.Now()
	driveAllowedForward(t)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("session with a black-hole span exporter took %s, want it unaffected", elapsed)
	}
}
