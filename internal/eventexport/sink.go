package eventexport

import (
	"context"
	"fmt"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/fips"
)

// ForwardingSink decorates a durable evidence.Sink with best-effort fan-out
// to zero or more export destinations (SIEM/log-management). The durable
// sink is authoritative: Emit's outcome is entirely determined by
// inner.Emit — a slow or broken exporter can never stall or fail it.
//
// ForwardingSink is the single-sink case: one inner, one exporter set it
// alone owns. When a deployment has multiple durable sinks that must share
// ONE exporter set (e.g. a gateway's separate dialer/session sinks — see
// Fanout), build a Fanout directly and Wrap each sink instead of calling New
// per sink, which would otherwise open the SIEM connections twice.
type ForwardingSink struct {
	inner     evidence.Sink
	exporters []*asyncExporter
	ctx       context.Context
	cancel    context.CancelFunc
}

// New builds a ForwardingSink wrapping inner from cfg. Each exporter's
// Formatter/Transport is constructed and validated eagerly — an unknown
// format/transport, or a transport missing its matching sub-config, is a
// boot error — so a broken export config fails fast at startup instead of
// silently dropping events at runtime. onDrop is invoked with an exporter's
// name whenever that exporter drops an event (full buffer, format error, or
// write error).
//
// On any build error, exporters already built (and started) for earlier
// entries in cfg.Exporters are shut down before returning, so a partial
// failure never leaks a goroutine or an open transport connection.
//
// New and NewFanout share the same build/validate logic (buildExporters);
// New just keeps the resulting exporter set private to a single sink instead
// of exposing it for reuse across sinks.
func New(inner evidence.Sink, cfg Config, onDrop func(exporterName string)) (*ForwardingSink, error) {
	ctx, cancel := context.WithCancel(context.Background())
	exporters, err := buildExporters(ctx, cfg, onDrop)
	if err != nil {
		cancel()
		return nil, err
	}
	return &ForwardingSink{inner: inner, exporters: exporters, ctx: ctx, cancel: cancel}, nil
}

// buildExporters builds and starts (under ctx) one asyncExporter per entry
// in cfg.Exporters, in order. It is the single build/validate path shared by
// New (one sink, private exporter set) and NewFanout (N sinks, one shared
// exporter set) — an unknown format/transport, or a transport missing its
// matching sub-config, is a boot error. On any error, exporters already
// started for earlier entries are shut down before returning, so a partial
// failure never leaks a goroutine or an open transport connection; the
// caller does not need to (and must not) shut them down again.
func buildExporters(ctx context.Context, cfg Config, onDrop func(exporterName string)) ([]*asyncExporter, error) {
	var exporters []*asyncExporter
	for _, ec := range cfg.Exporters {
		x, err := buildExporter(ec, cfg.Mode, onDrop)
		if err != nil {
			for _, built := range exporters {
				built.shutdown()
			}
			return nil, fmt.Errorf("eventexport: exporter %q: %w", ec.Name, err)
		}
		x.start(ctx)
		exporters = append(exporters, x)
	}
	return exporters, nil
}

func buildExporter(ec ExporterConfig, mode fips.Mode, onDrop func(exporterName string)) (*asyncExporter, error) {
	fmtr, err := NewFormatter(ec.Format)
	if err != nil {
		return nil, err
	}
	tr, err := buildTransport(ec, mode)
	if err != nil {
		return nil, err
	}
	name := ec.Name
	return newAsyncExporter(name, fmtr, tr, ec.bufferSize(), ec.flushInterval(), func() { onDrop(name) }), nil
}

func buildTransport(ec ExporterConfig, mode fips.Mode) (Transport, error) {
	switch ec.Transport {
	case "file":
		if ec.File == nil {
			return nil, fmt.Errorf("transport %q: missing file config", ec.Transport)
		}
		return newFileTransport(*ec.File)
	case "syslog":
		if ec.Syslog == nil {
			return nil, fmt.Errorf("transport %q: missing syslog config", ec.Transport)
		}
		return newSyslogTransport(*ec.Syslog, mode)
	case "http":
		if ec.HTTP == nil {
			return nil, fmt.Errorf("transport %q: missing http config", ec.Transport)
		}
		return newHTTPTransport(*ec.HTTP, mode)
	default:
		return nil, fmt.Errorf("unknown transport %q", ec.Transport)
	}
}

// Emit writes e to the durable inner sink inline and returns THAT result —
// the inner sink is authoritative. e is then offered (non-blocking) to
// every exporter; a slow or dead exporter can never stall Emit or change
// its result.
func (s *ForwardingSink) Emit(e evidence.Event) error {
	err := s.inner.Emit(e)
	for _, x := range s.exporters {
		x.offer(e)
	}
	return err
}

// Close cancels every exporter's context and waits (bounded) for each to
// drain its buffer, flush, and close its transport, then closes the inner
// sink.
func (s *ForwardingSink) Close() error {
	s.cancel()
	for _, x := range s.exporters {
		x.shutdown()
	}
	return s.inner.Close()
}
