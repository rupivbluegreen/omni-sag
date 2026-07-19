package eventexport

import (
	"context"
	"fmt"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// ForwardingSink decorates a durable evidence.Sink with best-effort fan-out
// to zero or more export destinations (SIEM/log-management). The durable
// sink is authoritative: Emit's outcome is entirely determined by
// inner.Emit — a slow or broken exporter can never stall or fail it.
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
func New(inner evidence.Sink, cfg Config, onDrop func(exporterName string)) (*ForwardingSink, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &ForwardingSink{inner: inner, ctx: ctx, cancel: cancel}

	for _, ec := range cfg.Exporters {
		x, err := buildExporter(ec, onDrop)
		if err != nil {
			for _, built := range s.exporters {
				built.shutdown()
			}
			cancel()
			return nil, fmt.Errorf("eventexport: exporter %q: %w", ec.Name, err)
		}
		x.start(ctx)
		s.exporters = append(s.exporters, x)
	}
	return s, nil
}

func buildExporter(ec ExporterConfig, onDrop func(exporterName string)) (*asyncExporter, error) {
	fmtr, err := NewFormatter(ec.Format)
	if err != nil {
		return nil, err
	}
	tr, err := buildTransport(ec)
	if err != nil {
		return nil, err
	}
	name := ec.Name
	return newAsyncExporter(name, fmtr, tr, ec.bufferSize(), ec.flushInterval(), func() { onDrop(name) }), nil
}

func buildTransport(ec ExporterConfig) (Transport, error) {
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
		return newSyslogTransport(*ec.Syslog)
	case "http":
		if ec.HTTP == nil {
			return nil, fmt.Errorf("transport %q: missing http config", ec.Transport)
		}
		return newHTTPTransport(*ec.HTTP)
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
