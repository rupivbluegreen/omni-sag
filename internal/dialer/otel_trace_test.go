package dialer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

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
// per test instead of swapping providers.
var (
	sharedRecorderOnce sync.Once
	sharedRecorder     *tracetest.SpanRecorder
)

func installSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sharedRecorderOnce.Do(func() {
		sharedRecorder = tracetest.NewSpanRecorder()
		otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sharedRecorder)))
	})
	sharedRecorder.Reset()
	return sharedRecorder
}

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

func TestTracing_AllowedDialProducesDecideAndDialSpans(t *testing.T) {
	sr := installSpanRecorder(t)
	swapDial(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, _ := net.Pipe()
		return client, nil
	})
	sink := evidence.NewMemSink()
	d := New(demoPolicy(), sink)
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432}, false)
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	conn.Close()

	ended := sr.Ended()
	dec := findSpan(ended, "omnisag.policy.decide")
	if dec == nil {
		t.Fatalf("expected omnisag.policy.decide span, got %+v", ended)
	}
	if role, ok := attrString(dec, "omnisag.policy.matched_role"); !ok || role != "dba" {
		t.Fatalf("policy.decide matched_role = %q (ok=%v), want dba", role, ok)
	}
	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("expected one evidence event, got %d", len(events))
	}
	if id, ok := attrString(dec, "omnisag.evidence.id"); !ok || id != events[0].ID || id == "" {
		t.Fatalf("policy.decide omnisag.evidence.id = %q (ok=%v), want %q", id, ok, events[0].ID)
	}

	dial := findSpan(ended, "omnisag.dial")
	if dial == nil {
		t.Fatalf("expected omnisag.dial span, got %+v", ended)
	}
	if addr, ok := attrString(dial, "server.address"); !ok || addr != "db1.lab.local" {
		t.Fatalf("dial server.address = %q (ok=%v)", addr, ok)
	}
}

func TestTracing_ApprovalGatedTargetProducesApprovalSpan(t *testing.T) {
	sr := installSpanRecorder(t)
	swapDial(t, func(context.Context, string, string) (net.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	})
	store := newStore(t)
	d := New(approvalPolicy(), evidence.NewMemSink(), WithApprovals(store, time.Hour))
	decideWhenPending(store, true)

	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}
	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "crown", Port: 22}, false)
	if err != nil {
		t.Fatalf("expected the approval to be granted, got %v", err)
	}
	conn.Close()

	ended := sr.Ended()
	appr := findSpan(ended, "omnisag.approval")
	if appr == nil {
		t.Fatalf("expected an omnisag.approval span, got %+v", ended)
	}
	if outcome, ok := attrString(appr, "omnisag.approval.outcome"); !ok || outcome != "granted" {
		t.Fatalf("approval outcome = %q (ok=%v), want granted", outcome, ok)
	}
}

func TestTracing_CredentialDenyProducesCredentialResolveSpan(t *testing.T) {
	sr := installSpanRecorder(t)
	swapDial(t, func(context.Context, string, string) (net.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	})
	d := New(credPolicy("deny"), evidence.NewMemSink())
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}

	_, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432}, false)
	if err == nil {
		t.Fatal("expected credential deny to refuse")
	}

	ended := sr.Ended()
	cred := findSpan(ended, "omnisag.credential.resolve")
	if cred == nil {
		t.Fatalf("expected an omnisag.credential.resolve span, got %+v", ended)
	}
	if mode, ok := attrString(cred, "omnisag.credential.mode"); !ok || mode != "deny" {
		t.Fatalf("credential.mode = %q (ok=%v), want deny", mode, ok)
	}
}

// TestTracing_DisabledProducesNoSpans proves the instrumentation call sites
// never break DialTarget's normal behavior, regardless of tracer state. The
// authoritative "OTel disabled installs nothing globally" guarantee is
// internal/otelexport's TestSetup_DisabledInstallsNoopAndNoShutdownWork,
// which runs in its own process before any provider has ever been
// installed; that specific assertion can't be repeated here once another
// test in this binary has installed a real provider (see the comment on
// installSpanRecorder).
func TestTracing_DisabledProducesNoSpans(t *testing.T) {
	swapDial(t, func(context.Context, string, string) (net.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	})
	d := New(demoPolicy(), evidence.NewMemSink())
	pr := policy.Principal{User: "alice", Groups: []string{"dba"}}
	conn, err := d.DialTarget(context.Background(), pr, "10.0.0.5", policy.Target{Host: "db1.lab.local", Port: 5432}, false)
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	conn.Close()
}
