// EXPERIMENTAL: go.opentelemetry.io/otel/log and .../sdk/log are pre-GA
// (v0.x, non-standard versioning — see the design doc). This file and
// logmap.go are the only places those modules are referenced, so a breaking
// 0.x bump touches only these two files. The stable traces/metrics
// deliverable does not depend on any of this.
package otelexport

import (
	"context"
	"encoding/json"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	logglobal "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/credentials"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// buildLoggerProvider builds the OTLP log exporter and a LoggerProvider
// behind a BatchProcessor — the same bounded, async, drop-on-overflow
// posture as the trace/metric providers.
func buildLoggerProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdklog.LoggerProvider, error) {
	exp, err := buildLogExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("otelexport: log exporter: %w", err)
	}
	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
	), nil
}

// buildLogExporter builds the OTLP log exporter for cfg.Protocol. Both
// otlploggrpc.New and otlploghttp.New dial lazily, matching the trace/metric
// exporters' non-blocking-dial posture.
func buildLogExporter(ctx context.Context, cfg Config) (sdklog.Exporter, error) {
	switch cfg.Protocol {
	case "", "grpc":
		opts := []otlploggrpc.Option{otlploggrpc.WithEndpoint(cfg.Endpoint)}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploggrpc.WithHeaders(cfg.Headers))
		}
		if cfg.Insecure {
			opts = append(opts, otlploggrpc.WithInsecure())
		} else {
			tlsCfg, err := buildTLSConfig(cfg.TLS)
			if err != nil {
				return nil, err
			}
			opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
		}
		return otlploggrpc.New(ctx, opts...)
	case "http":
		opts := []otlploghttp.Option{otlploghttp.WithEndpoint(cfg.Endpoint)}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(cfg.Headers))
		}
		if cfg.Insecure {
			opts = append(opts, otlploghttp.WithInsecure())
		} else {
			tlsCfg, err := buildTLSConfig(cfg.TLS)
			if err != nil {
				return nil, err
			}
			opts = append(opts, otlploghttp.WithTLSClientConfig(tlsCfg))
		}
		return otlploghttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("otelexport: unknown protocol %q (want grpc|http)", cfg.Protocol)
	}
}

// LogTransport is the experimental `otlp` transport for #19's eventexport
// exporter matrix (Formatter x Transport). eventexport.Transport is
// byte-oriented (Write([]byte) error; Flush() error; Close() error) — it
// frames an already-formatted payload — while an OTLP LogRecord needs the
// structured evidence.Event (for severity, attributes, and trace
// correlation). Rather than widen eventexport's Transport interface for one
// experimental transport, LogTransport requires pairing with Format: "json"
// (the same shape internal/eventexport's own jsonFormatter produces,
// including the additive trace_id/span_id fields) and round-trips it back
// into an evidence.Event. It delegates all batching/export to the OTel log
// SDK's own BatchProcessor + OTLP exporter (built by buildLoggerProvider) —
// never a second best-effort pump; see the design doc's #19 boundary.
type LogTransport struct {
	logger log.Logger
}

// NewLogTransport returns the `otlp` Transport, using the global OTel
// Logger named name (the eventexport exporter's configured name) — a no-op
// Logger when OTel logs are disabled (Setup never installed a real
// LoggerProvider), so an enabled `otlp` exporter entry costs nothing beyond
// its own JSON formatting when cfg.otel.logs.enabled is false.
func NewLogTransport(name string) *LogTransport {
	return &LogTransport{logger: logglobal.Logger(name)}
}

// Write decodes payload (a jsonFormatter-produced evidence.Event), maps it
// to a log.Record, and emits it. ctx carries the event's own span context
// when present so a real Logger's Emit derives OTLP's wire-level
// trace_id/span_id from it, in addition to the trace_id/span_id attributes
// EventToLogRecord already sets.
func (t *LogTransport) Write(payload []byte) error {
	var e evidence.Event
	if err := json.Unmarshal(payload, &e); err != nil {
		return fmt.Errorf("otelexport: otlp transport: decode event: %w", err)
	}
	sc := spanContextFromEvent(e)
	record := EventToLogRecord(e, sc)
	emitCtx := context.Background()
	if sc.IsValid() {
		emitCtx = trace.ContextWithSpanContext(emitCtx, sc)
	}
	t.logger.Emit(emitCtx, record)
	return nil
}

func (t *LogTransport) Flush() error { return nil }
func (t *LogTransport) Close() error { return nil }

// spanContextFromEvent rebuilds a trace.SpanContext from an evidence.Event's
// additive TraceID/SpanID hex strings (see internal/evidence.Event and
// internal/session's/internal/dialer's emit). Any parse failure — including
// both fields simply being empty, the normal disabled-OTel case — yields a
// zero, invalid SpanContext.
func spanContextFromEvent(e evidence.Event) trace.SpanContext {
	if e.TraceID == "" || e.SpanID == "" {
		return trace.SpanContext{}
	}
	tid, err := trace.TraceIDFromHex(e.TraceID)
	if err != nil {
		return trace.SpanContext{}
	}
	sid, err := trace.SpanIDFromHex(e.SpanID)
	if err != nil {
		return trace.SpanContext{}
	}
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
	})
}
