package eventexport

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// This file is the reliability ground truth for the feature: a dead or
// permanently-slow SIEM destination must never block or fail the durable
// Emit path, and must never leak per-event. Every test here drives the REAL
// wired path (Fanout.Wrap / New over a real evidence.MemSink) with a REAL
// Transport (syslog/http) built through the exported Config surface — never
// the asyncExporter in isolation, and never a fake Transport spliced in
// directly (see exporter_test.go for that unit-level coverage).

// blackHoleAddr is a TEST-NET-2 address (RFC 5737, reserved for
// documentation — guaranteed non-routable). A TCP dial to it gets no
// SYN-ACK and no RST, so it hangs until the syslog transport's own dial
// deadline (syslogDialTimeout, 3s) fires. That makes it a genuinely
// dead/blocking destination reached entirely through SyslogConfig — no
// production code touched, no fake Transport.
const blackHoleAddr = "198.51.100.1:9"

// countingDrop returns an onDrop callback safe for concurrent use plus an
// accessor for its current count.
func countingDrop() (onDrop func(string), count func() int32) {
	var n int32
	return func(string) { atomic.AddInt32(&n, 1) }, func() int32 { return atomic.LoadInt32(&n) }
}

// TestIntegration_DeadSyslogNeverBlocksEmit proves the single most
// important property of this feature end to end: wrapping a real MemSink
// with a Fanout whose only exporter points at a black-hole syslog
// destination, a burst that overflows the exporter's tiny buffer never
// blocks or fails Emit, every event still lands durably, the overflow is
// counted as a drop (not silently lost), and Close returns within its
// documented bound instead of hanging on the dead destination.
func TestIntegration_DeadSyslogNeverBlocksEmit(t *testing.T) {
	inner := evidence.NewMemSink()
	onDrop, drops := countingDrop()

	cfg := Config{Enabled: true, Exporters: []ExporterConfig{
		{
			Name: "dead-soc", Format: "json", Transport: "syslog", BufferSize: 5,
			Syslog: &SyslogConfig{Address: blackHoleAddr, Protocol: "tcp"},
		},
	}}
	fo, err := NewFanout(cfg, onDrop)
	if err != nil {
		t.Fatalf("NewFanout: %v", err)
	}

	sink := fo.Wrap(inner)

	// The drain goroutine's first Write blocks in redial for up to
	// syslogDialTimeout (3s); the 5-slot buffer is far smaller than the
	// burst, so most of it must overflow to drops while that first attempt
	// is still stuck. A regression that made offer() block instead of drop
	// would serialize this burst behind that 3s stall — 200 events would
	// then take minutes, not the microseconds a correct non-blocking send
	// takes — so 2s is a tight, non-flaky bound for the correct behavior
	// and a guaranteed loud failure for the regression.
	const n = 200
	withTimeout(t, 2*time.Second, func() {
		for i := 0; i < n; i++ {
			if err := sink.Emit(evidence.Event{Type: evidence.TypeAuth, User: "u"}); err != nil {
				t.Errorf("Emit %d returned %v, want nil (a dead SIEM must never fail Emit)", i, err)
			}
		}
	})

	if got := len(inner.Events()); got != n {
		t.Fatalf("inner sink has %d events, want %d (durable path must be unaffected by a dead exporter)", got, n)
	}

	if got := drops(); got <= 0 {
		t.Fatalf("drop count = %d, want > 0 (the overflowed events must be counted as best-effort drops, not silently lost)", got)
	}

	// Close must return within its documented bound (shutdown's
	// drainTimeout+1s per exporter) even though the destination is
	// permanently dead and the drain goroutine may still be stuck
	// redialing in the background — that background stall is an accepted,
	// bounded leak (see asyncExporter.drainAndFlush), not a hang on Close
	// itself.
	withTimeout(t, drainTimeout+7*time.Second, func() {
		if err := fo.Close(); err != nil {
			t.Fatalf("Fanout.Close: %v", err)
		}
	})
}

// TestIntegration_SlowHTTPTransportNeverBlocksEmit proves the
// "slow-but-eventually-draining" half of the contract with a REAL HTTP
// destination (httptest.Server) whose handler sleeps before responding —
// genuine, deterministic network-level latency, not a fake Transport. Emit
// must stay non-blocking regardless, the durable inner copy must always be
// complete, and — unlike the dead-destination case — the transport must
// actually deliver something, proving it drains rather than merely dropping
// everything.
func TestIntegration_SlowHTTPTransportNeverBlocksEmit(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // slow collector — but it does respond
		io.Copy(io.Discard, r.Body)
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	inner := evidence.NewMemSink()
	onDrop, drops := countingDrop()

	cfg := Config{Enabled: true, Exporters: []ExporterConfig{
		{
			Name: "slow-soc", Format: "json", Transport: "http", BufferSize: 3,
			HTTP: &HTTPConfig{URL: srv.URL, BatchSize: 1},
		},
	}}
	fs, err := New(inner, cfg, onDrop)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// With batch_size 1, every Write is a synchronous 50ms POST; the
	// 3-slot buffer is much smaller than the burst, so under a bug where
	// offer() blocks instead of dropping, 60 events would serialize behind
	// that 50ms/write pace (~2.85s) — well past the 2s bound below, while a
	// correct non-blocking burst finishes in microseconds.
	const n = 60
	withTimeout(t, 2*time.Second, func() {
		for i := 0; i < n; i++ {
			if err := fs.Emit(evidence.Event{Type: evidence.TypeAuth, User: "u"}); err != nil {
				t.Errorf("Emit %d returned %v, want nil (a slow SIEM must never fail Emit)", i, err)
			}
		}
	})

	if got := len(inner.Events()); got != n {
		t.Fatalf("inner sink has %d events, want %d (durable path must be unaffected by a slow exporter)", got, n)
	}

	withTimeout(t, drainTimeout+3*time.Second, func() {
		if err := fs.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	// Not dead — assert it actually drained something. Per the task's own
	// contract, exporter-side completeness under load is NOT required (some
	// events may drop); only inner completeness (asserted above) is.
	if atomic.LoadInt32(&received) == 0 {
		t.Fatal("slow transport delivered 0 events — expected it to drain some, unlike a permanently dead destination")
	}
	t.Logf("slow transport: %d/%d events delivered to the collector, %d dropped", received, n, drops())
}

// TestIntegration_ConcurrentEmittersAgainstDeadTransport mirrors a real
// gateway's concurrent dialer+session emission: many goroutines call the
// SAME Fanout-wrapped sink's Emit concurrently while the shared exporter's
// transport is dead. Run with -race: proves offer()/Emit are safe for
// concurrent use, never block, and every event still lands durably despite
// the contention.
func TestIntegration_ConcurrentEmittersAgainstDeadTransport(t *testing.T) {
	inner := evidence.NewMemSink()
	onDrop, drops := countingDrop()

	cfg := Config{Enabled: true, Exporters: []ExporterConfig{
		{
			Name: "dead-soc", Format: "json", Transport: "syslog", BufferSize: 5,
			Syslog: &SyslogConfig{Address: blackHoleAddr, Protocol: "tcp"},
		},
	}}
	fo, err := NewFanout(cfg, onDrop)
	if err != nil {
		t.Fatalf("NewFanout: %v", err)
	}
	sink := fo.Wrap(inner)

	const goroutines = 10
	const perGoroutine = 30
	const total = goroutines * perGoroutine

	var wg sync.WaitGroup
	withTimeout(t, 2*time.Second, func() {
		for g := 0; g < goroutines; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < perGoroutine; i++ {
					if err := sink.Emit(evidence.Event{Type: evidence.TypeAuth, User: fmt.Sprintf("g%d", g)}); err != nil {
						t.Errorf("Emit (goroutine %d, iter %d) returned %v, want nil", g, i, err)
					}
				}
			}(g)
		}
		wg.Wait()
	})

	if got := len(inner.Events()); got != total {
		t.Fatalf("inner sink has %d events, want %d (concurrent Emit against a dead exporter must never lose a durable write)", got, total)
	}

	withTimeout(t, drainTimeout+7*time.Second, func() {
		if err := fo.Close(); err != nil {
			t.Fatalf("Fanout.Close: %v", err)
		}
	})

	t.Logf("concurrent emitters: %d events durable, %d dropped by the dead exporter", total, drops())
}
