package eventexport

import (
	"context"
	"sync"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// Fanout is a shared set of exporters, built and started ONCE, that can wrap
// multiple durable evidence.Sink instances (e.g. a gateway's separate dialer
// and session sinks). Every event offered through ANY wrapped sink reaches
// EVERY exporter in the set — so a deployment with multiple durable sinks
// still gets exactly one SIEM connection per configured exporter, not one
// per sink.
//
// Fanout owns the exporters' lifecycle: individual wrapped sinks' Close()
// closes only their own inner; only Fanout.Close() drains/stops the shared
// exporters.
type Fanout struct {
	exporters []*asyncExporter
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewFanout builds and starts the exporters in cfg once, via the same
// buildExporters helper New uses — so validation and per-exporter
// construction never diverge between the single-sink and shared-fan-out
// paths. An unknown format/transport, or a transport missing its matching
// sub-config, is a boot error. On any build error, exporters already started
// for earlier entries are shut down before returning (no leaked goroutine or
// open transport connection).
func NewFanout(cfg Config, onDrop func(exporterName string)) (*Fanout, error) {
	ctx, cancel := context.WithCancel(context.Background())
	exporters, err := buildExporters(ctx, cfg, onDrop)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Fanout{exporters: exporters, ctx: ctx, cancel: cancel}, nil
}

// Wrap returns an evidence.Sink that fans e out to every exporter in f
// (non-blocking, best-effort) after writing it to inner inline
// (authoritative — Emit's result is entirely inner's). The returned sink's
// Close() closes ONLY inner; f's shared exporters keep running (and keep
// serving any other sink Wrap has produced) until f.Close() is called.
func (f *Fanout) Wrap(inner evidence.Sink) evidence.Sink {
	return &fanoutSink{fanout: f, inner: inner}
}

// Close cancels every exporter's context, then waits for each to drain its
// buffer, flush, and close its transport. The waits run CONCURRENTLY, so the
// total is bounded by a single exporter's drain deadline regardless of how
// many exporters there are — a serial wait would be O(N · drainTimeout) and,
// with several dead SIEM destinations, could exceed a container's stop grace
// (SIGKILL). Every exporter's context is already cancelled by f.cancel()
// before the waits begin, so they drain in parallel. Wrapped sinks' own
// inners are NOT touched here — Fanout does not own them.
func (f *Fanout) Close() error {
	f.cancel()
	var wg sync.WaitGroup
	for _, x := range f.exporters {
		wg.Add(1)
		go func(x *asyncExporter) { defer wg.Done(); x.shutdown() }(x)
	}
	wg.Wait()
	return nil
}

type fanoutSink struct {
	fanout *Fanout
	inner  evidence.Sink
}

func (s *fanoutSink) Emit(e evidence.Event) error {
	err := s.inner.Emit(e)
	for _, x := range s.fanout.exporters {
		x.offer(e)
	}
	return err
}

// Close closes only this sink's own inner. The shared exporters belong to
// the Fanout, not to any one wrapped sink.
func (s *fanoutSink) Close() error {
	return s.inner.Close()
}
