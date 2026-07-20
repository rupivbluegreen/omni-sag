package eventexport

import (
	"context"
	"log"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// defaultFlushInterval is used when a caller passes a non-positive
// flushInterval, which would otherwise panic in time.NewTicker.
const defaultFlushInterval = time.Minute

// drainTimeout bounds how long shutdown waits for buffered events to be
// formatted+written and the transport flushed+closed, so a stuck
// Transport.Write/Flush/Close (a dead destination) can't hang shutdown
// forever. It exceeds the largest Transport's own single-op timeout
// (httpRequestTimeout, 3s) so a normal in-flight Write on a HEALTHY
// connection completes during shutdown rather than being abandoned. Note it
// does NOT cover a worst-case syslog redial (3s) + write (3s) = 6s on a
// connection that broke right at shutdown; that case takes the
// abandon-and-count-drops path, which is bounded and correct (buffered
// best-effort events are dropped, the durable record is already written).
const drainTimeout = 5 * time.Second

// asyncExporter ties a Formatter and Transport together behind a bounded,
// non-blocking buffer, formatting and writing in its own goroutine so the
// (bounded-but-synchronous) transport I/O never runs on the session/dialer
// hot path. Delivery is best-effort: a full buffer, a Format error, or a
// Transport error all just count a drop and keep going — the durable
// evidence sink (outside this package) is the system of record.
type asyncExporter struct {
	name          string
	fmtr          Formatter
	tr            Transport
	buf           chan evidence.Event
	onDrop        func()
	flushInterval time.Duration
	done          chan struct{}
	cancel        context.CancelFunc
}

func newAsyncExporter(name string, f Formatter, t Transport, bufSize int, flushInterval time.Duration, onDrop func()) *asyncExporter {
	return &asyncExporter{
		name:          name,
		fmtr:          f,
		tr:            t,
		buf:           make(chan evidence.Event, bufSize),
		onDrop:        onDrop,
		flushInterval: flushInterval,
		done:          make(chan struct{}),
	}
}

// offer enqueues e for async delivery. Non-blocking: if the buffer is full
// (the drain goroutine can't keep up, or is stuck on a slow transport), the
// event is dropped and counted instead of blocking the caller — this is
// called on the session/dialer hot path and must never wait.
func (a *asyncExporter) offer(e evidence.Event) {
	select {
	case a.buf <- e:
	default:
		a.onDrop()
	}
}

// start launches the drain goroutine. ctx cancellation (directly, or via a
// later shutdown() call) stops it: buffered events are drained best-effort,
// the transport is flushed and closed, then the goroutine exits.
func (a *asyncExporter) start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	go a.run(ctx)
}

// shutdown stops the drain goroutine and waits for it to finish draining,
// flushing, and closing the transport — bounded, so a dead transport can't
// hang the caller forever.
func (a *asyncExporter) shutdown() {
	if a.cancel != nil {
		a.cancel()
	}
	select {
	case <-a.done:
	case <-time.After(drainTimeout + time.Second):
	}
}

func (a *asyncExporter) run(ctx context.Context) {
	defer close(a.done)

	interval := a.flushInterval
	if interval <= 0 {
		interval = defaultFlushInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var loggedFormatErr, loggedWriteErr bool
	for {
		select {
		case <-ctx.Done():
			a.drainAndFlush(&loggedFormatErr, &loggedWriteErr)
			return
		case e := <-a.buf:
			a.process(e, &loggedFormatErr, &loggedWriteErr)
		case <-ticker.C:
			_ = a.tr.Flush()
		}
	}
}

// process formats and writes a single event, best-effort: either failure
// counts a drop and logs once (per error kind, for this exporter's
// lifetime) instead of crashing or blocking the drain loop.
func (a *asyncExporter) process(e evidence.Event, loggedFormatErr, loggedWriteErr *bool) {
	b, err := a.fmtr.Format(e)
	if err != nil {
		a.onDrop()
		if !*loggedFormatErr {
			*loggedFormatErr = true
			log.Printf("eventexport: exporter %q: format error, dropping events: %v", a.name, err)
		}
		return
	}
	if err := a.tr.Write(b); err != nil {
		a.onDrop()
		if !*loggedWriteErr {
			*loggedWriteErr = true
			log.Printf("eventexport: exporter %q: write error, dropping events: %v", a.name, err)
		}
	}
}

// drainAndFlush best-effort drains whatever is currently buffered, flushes,
// and closes the transport — all inside one sub-goroutine raced against
// drainTimeout, so a Transport.Write/Flush/Close stuck on a dead
// destination can't hang the caller past the deadline. Running Close in the
// same goroutine, after the drain loop and Flush, also means it never runs
// concurrently with a still-in-flight Write/Flush from this exporter, which
// could otherwise produce a duplicate/out-of-order request to the
// destination.
//
// If the bound is hit, the sub-goroutine may still be stuck (and will run
// to completion, including Close, whenever/if the transport call it's
// blocked on returns — this is an accepted leak for a truly pathological
// transport). Whatever's still sitting in a.buf at that point was never
// handed to it, so it's drained here, non-blockingly, and counted as
// dropped — otherwise the drop metric would silently undercount just
// because the transport got abandoned.
func (a *asyncExporter) drainAndFlush(loggedFormatErr, loggedWriteErr *bool) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		n := len(a.buf)
		for i := 0; i < n; i++ {
			select {
			case e := <-a.buf:
				a.process(e, loggedFormatErr, loggedWriteErr)
			default:
				return
			}
		}
		_ = a.tr.Flush()
		_ = a.tr.Close()
	}()
	select {
	case <-done:
	case <-time.After(drainTimeout):
		for {
			select {
			case <-a.buf:
				a.onDrop()
			default:
				return
			}
		}
	}
}
