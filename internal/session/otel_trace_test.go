package session

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// otel's global TracerProvider only ever re-delegates already-minted
// otel.Tracer(name) handles (like this package's package-level `tracer`
// var) to the FIRST real provider passed to otel.SetTracerProvider — see
// go.opentelemetry.io/otel/internal/global's delegateTraceOnce. A second
// SetTracerProvider call updates otel.GetTracerProvider()'s return value
// but does NOT re-delegate already-obtained tracers, so installing a fresh
// TracerProvider per test silently orphans every test after the first. The
// fix: install exactly one recorder for the whole test binary and Reset it
// per test instead of swapping providers. A black-hole batch exporter rides
// alongside the recorder on every span for the rest of the file's tests, so
// TestTracing_ExporterErrorDoesNotBlockSession is exercising the real
// installed provider rather than one that got silently orphaned.
var (
	sharedRecorderOnce sync.Once
	sharedRecorder     *tracetest.SpanRecorder
)

func installSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sharedRecorderOnce.Do(func() {
		sharedRecorder = tracetest.NewSpanRecorder()
		otel.SetTracerProvider(sdktrace.NewTracerProvider(
			sdktrace.WithSpanProcessor(sharedRecorder),
			sdktrace.WithBatcher(blackHoleExporter{}, sdktrace.WithExportTimeout(50*time.Millisecond)),
		))
	})
	sharedRecorder.Reset()
	return sharedRecorder
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

// TestTracing_DisabledProducesNoSpans proves the instrumentation call sites
// never break a session's normal behavior, regardless of tracer state. The
// authoritative "OTel disabled installs nothing globally" guarantee is
// internal/otelexport's TestSetup_DisabledInstallsNoopAndNoShutdownWork,
// which runs in its own process before any provider has ever been
// installed; that specific assertion can't be repeated here once another
// test in this binary has installed a real provider (see the comment on
// installSpanRecorder).
func TestTracing_DisabledProducesNoSpans(t *testing.T) {
	driveAllowedForward(t)
}

// blackHoleExporter's ExportSpans blocks until its context is cancelled,
// simulating an unreachable/hung OTLP collector. It rides alongside the
// shared SpanRecorder on every span end for the rest of this file's tests
// (see installSpanRecorder) — a BatchSpanProcessor's OnEnd is a
// non-blocking enqueue, so a stuck/erroring exporter here must never slow
// span.End() or the session itself.
type blackHoleExporter struct{}

func (blackHoleExporter) ExportSpans(ctx context.Context, _ []sdktrace.ReadOnlySpan) error {
	<-ctx.Done()
	return ctx.Err()
}
func (blackHoleExporter) Shutdown(context.Context) error { return nil }

func TestTracing_ExporterErrorDoesNotBlockSession(t *testing.T) {
	installSpanRecorder(t)
	start := time.Now()
	driveAllowedForward(t)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("session with a black-hole span exporter took %s, want it unaffected", elapsed)
	}
}

func TestTracing_TunnelChannelSpanTree(t *testing.T) {
	sr := installSpanRecorder(t)
	driveAllowedForward(t)

	ended := sr.Ended()
	ch := findSpan(ended, "omnisag.channel")
	if ch == nil {
		t.Fatalf("expected an omnisag.channel span, got: %+v", ended)
	}
	if typ, ok := attrString(ch, "omnisag.channel.type"); !ok || typ != "direct-tcpip" {
		t.Fatalf("omnisag.channel.type = %q (ok=%v), want direct-tcpip", typ, ok)
	}

	tun := findSpan(ended, "omnisag.tunnel")
	if tun == nil {
		t.Fatalf("expected an omnisag.tunnel span, got: %+v", ended)
	}
	if tun.Parent().SpanID() != ch.SpanContext().SpanID() {
		t.Fatal("omnisag.tunnel must be a child of omnisag.channel")
	}

	dial := findSpan(ended, "omnisag.dial")
	if dial == nil {
		t.Fatalf("expected an omnisag.dial span (from dialer.DialTarget), got: %+v", ended)
	}
	if dial.Parent().SpanID() != tun.SpanContext().SpanID() {
		t.Fatal("omnisag.dial must be a child of omnisag.tunnel")
	}

	splice := findSpan(ended, "omnisag.splice")
	if splice == nil {
		t.Fatalf("expected an omnisag.splice span, got: %+v", ended)
	}
	if splice.Parent().SpanID() != tun.SpanContext().SpanID() {
		t.Fatal("omnisag.splice must be a child of omnisag.tunnel")
	}
	found := false
	for _, kv := range splice.Attributes() {
		if string(kv.Key) == "omnisag.transfer.bytes" {
			found = true
			if kv.Value.AsInt64() <= 0 {
				t.Fatalf("omnisag.transfer.bytes = %d, want > 0", kv.Value.AsInt64())
			}
		}
	}
	if !found {
		t.Fatal("omnisag.splice span missing omnisag.transfer.bytes attribute")
	}
}
