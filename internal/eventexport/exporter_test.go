package eventexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// blockingTransport's Write blocks until the test closes unblock — used to
// force the drain goroutine to get stuck so we can prove offer() still
// returns immediately (non-blocking send) instead of waiting on it.
type blockingTransport struct {
	writeStarted chan struct{}
	unblock      chan struct{}
	once         sync.Once
}

func newBlockingTransport() *blockingTransport {
	return &blockingTransport{writeStarted: make(chan struct{}), unblock: make(chan struct{})}
}

func (b *blockingTransport) Write(payload []byte) error {
	b.once.Do(func() { close(b.writeStarted) })
	<-b.unblock
	return nil
}
func (b *blockingTransport) Flush() error { return nil }
func (b *blockingTransport) Close() error { return nil }

// recordingTransport captures every payload it receives (in order) plus
// Flush/Close call counts, guarded by a mutex since it's read from the test
// goroutine while the drain goroutine writes to it.
type recordingTransport struct {
	mu       sync.Mutex
	payloads [][]byte
	flushes  int
	closed   bool
}

func (r *recordingTransport) Write(p []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.payloads = append(r.payloads, append([]byte(nil), p...))
	return nil
}
func (r *recordingTransport) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushes++
	return nil
}
func (r *recordingTransport) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}
func (r *recordingTransport) snapshot() (payloads [][]byte, flushes int, closed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	payloads = make([][]byte, len(r.payloads))
	copy(payloads, r.payloads)
	return payloads, r.flushes, r.closed
}

// errTransport always fails Write — used to prove a Write error doesn't
// crash or stall the drain goroutine.
type errTransport struct {
	mu    sync.Mutex
	calls int
}

func (e *errTransport) Write(p []byte) error {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	return errors.New("write boom")
}
func (e *errTransport) Flush() error { return nil }
func (e *errTransport) Close() error { return nil }
func (e *errTransport) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// errFormatter always fails Format — used to prove a Format error doesn't
// crash the drain goroutine and never reaches the transport.
type errFormatter struct{}

func (errFormatter) Format(evidence.Event) ([]byte, error) { return nil, errors.New("format boom") }
func (errFormatter) ContentType() string                   { return "text/plain" }

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	withTimeout(t, d, func() {
		for !cond() {
			time.Sleep(5 * time.Millisecond)
		}
	})
}

func TestAsyncExporter_OfferNeverBlocks(t *testing.T) {
	tr := newBlockingTransport()
	var drops int32
	a := newAsyncExporter("t", jsonFormatter{}, tr, 1, time.Hour, func() { atomic.AddInt32(&drops, 1) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.start(ctx)

	// event 1 is picked up by the drain goroutine immediately; its Write
	// blocks on tr.unblock, leaving the goroutine stuck.
	a.offer(evidence.Event{User: "one"})
	withTimeout(t, 2*time.Second, func() { <-tr.writeStarted })

	// event 2 fills the size-1 buffer (goroutine is busy in Write, not
	// draining).
	a.offer(evidence.Event{User: "two"})

	// event 3: buffer full AND goroutine stuck — offer must return
	// immediately via the default branch, never block on the stuck
	// goroutine, and must count the drop.
	withTimeout(t, 2*time.Second, func() {
		a.offer(evidence.Event{User: "three"})
	})

	if got := atomic.LoadInt32(&drops); got < 1 {
		t.Fatalf("onDrop count = %d, want >= 1 (event three must have been dropped)", got)
	}

	close(tr.unblock)
	withTimeout(t, 5*time.Second, func() { a.shutdown() })
}

func TestAsyncExporter_DrainsFormatAndWriteInOrder(t *testing.T) {
	tr := &recordingTransport{}
	const n = 20
	// Buffer sized to the whole burst: offer() only drops on a full
	// buffer, so this guarantees every event is retained regardless of how
	// the producer and drain goroutine happen to interleave.
	a := newAsyncExporter("t", jsonFormatter{}, tr, n, time.Hour, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.start(ctx)

	for i := 0; i < n; i++ {
		a.offer(evidence.Event{User: fmt.Sprintf("u%d", i)})
	}

	waitFor(t, 2*time.Second, func() bool {
		payloads, _, _ := tr.snapshot()
		return len(payloads) == n
	})

	payloads, _, _ := tr.snapshot()
	for i, p := range payloads {
		var e evidence.Event
		if err := json.Unmarshal(p, &e); err != nil {
			t.Fatalf("payload %d: unmarshal: %v", i, err)
		}
		if want := fmt.Sprintf("u%d", i); e.User != want {
			t.Fatalf("payload %d user = %q, want %q (out of order)", i, e.User, want)
		}
	}

	withTimeout(t, 5*time.Second, func() { a.shutdown() })
}

func TestAsyncExporter_WriteErrorKeepsDrainingAndCountsDrops(t *testing.T) {
	tr := &errTransport{}
	var drops int32
	a := newAsyncExporter("t", jsonFormatter{}, tr, 10, time.Hour, func() { atomic.AddInt32(&drops, 1) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.start(ctx)

	const n = 5
	for i := 0; i < n; i++ {
		a.offer(evidence.Event{User: fmt.Sprintf("u%d", i)})
	}

	waitFor(t, 2*time.Second, func() bool { return tr.callCount() == n })

	if got := atomic.LoadInt32(&drops); got != n {
		t.Fatalf("drops = %d, want %d (every Write error must be counted, goroutine must keep draining)", got, n)
	}

	withTimeout(t, 5*time.Second, func() { a.shutdown() })
}

func TestAsyncExporter_FormatErrorKeepsDrainingAndNeverReachesTransport(t *testing.T) {
	tr := &recordingTransport{}
	var drops int32
	a := newAsyncExporter("t", errFormatter{}, tr, 10, time.Hour, func() { atomic.AddInt32(&drops, 1) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.start(ctx)

	const n = 3
	for i := 0; i < n; i++ {
		a.offer(evidence.Event{User: fmt.Sprintf("u%d", i)})
	}

	waitFor(t, 2*time.Second, func() bool { return atomic.LoadInt32(&drops) == n })

	payloads, _, _ := tr.snapshot()
	if len(payloads) != 0 {
		t.Fatalf("transport got %d payloads, want 0 (format errors must never reach Write)", len(payloads))
	}

	withTimeout(t, 5*time.Second, func() { a.shutdown() })
}

func TestAsyncExporter_PeriodicFlush(t *testing.T) {
	tr := &recordingTransport{}
	a := newAsyncExporter("t", jsonFormatter{}, tr, 10, 20*time.Millisecond, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.start(ctx)

	waitFor(t, 2*time.Second, func() bool {
		_, flushes, _ := tr.snapshot()
		return flushes >= 1
	})

	withTimeout(t, 5*time.Second, func() { a.shutdown() })
}

func TestAsyncExporter_ShutdownDrainsFlushesClosesBounded(t *testing.T) {
	tr := &recordingTransport{}
	a := newAsyncExporter("t", jsonFormatter{}, tr, 10, time.Hour, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.start(ctx)

	const n = 3
	for i := 0; i < n; i++ {
		a.offer(evidence.Event{User: fmt.Sprintf("u%d", i)})
	}

	withTimeout(t, 5*time.Second, func() { a.shutdown() })

	payloads, flushes, closed := tr.snapshot()
	if len(payloads) != n {
		t.Fatalf("payloads = %d, want %d (shutdown must drain buffered events)", len(payloads), n)
	}
	if flushes < 1 {
		t.Fatal("transport never flushed during shutdown")
	}
	if !closed {
		t.Fatal("transport not closed by shutdown")
	}
}

func TestAsyncExporter_CtxCancelAlsoDrainsAndCloses(t *testing.T) {
	tr := &recordingTransport{}
	a := newAsyncExporter("t", jsonFormatter{}, tr, 10, time.Hour, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	a.start(ctx)

	a.offer(evidence.Event{User: "one"})

	cancel()
	withTimeout(t, 5*time.Second, func() { <-a.done })

	payloads, _, closed := tr.snapshot()
	if len(payloads) != 1 {
		t.Fatalf("payloads = %d, want 1 (ctx cancel must drain buffered events)", len(payloads))
	}
	if !closed {
		t.Fatal("transport not closed on ctx cancel")
	}
}
