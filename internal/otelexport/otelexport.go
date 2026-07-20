// Package otelexport owns all OpenTelemetry SDK wiring: resource
// construction, TracerProvider/MeterProvider/LoggerProvider, OTLP exporters,
// samplers, and a single bounded Shutdown. It is a leaf package — nothing
// else in the tree imports the OTel SDK; instrumentation call sites elsewhere
// use only the global API (otel.Tracer(...)), which is a no-op when Setup is
// never called or cfg.Enabled is false, so the disabled path costs nothing.
package otelexport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"google.golang.org/grpc/credentials"
)

// defaultServiceName names the OTel Resource when cfg.Resource sets no
// service.name.
const defaultServiceName = "omni-sag"

// Config mirrors config.OTelConfig as a plain struct built by the caller
// (cmd/omni-sag) — otelexport does NOT import internal/config, keeping this
// package a leaf.
type Config struct {
	Enabled  bool
	Endpoint string
	Protocol string // grpc | http
	Insecure bool
	TLS      TLSConfig
	Headers  map[string]string
	Resource map[string]string
	Traces   TracesConfig
	Metrics  MetricsConfig
	Logs     LogsConfig
}

// TLSConfig names PEM files for a client TLS connection to the collector.
type TLSConfig struct {
	CACert     string
	ClientCert string
	ClientKey  string
}

// TracesConfig configures the traces signal.
type TracesConfig struct {
	Enabled              bool
	Sampler              string
	SampleRatio          float64
	MaxQueueSize         int
	MaxExportBatchSize   int
	ExportTimeoutSeconds int
}

// MetricsConfig configures the optional OTLP metrics signal.
type MetricsConfig struct {
	Enabled         bool
	IntervalSeconds int
}

// LogsConfig configures the experimental OTLP logs signal.
type LogsConfig struct {
	Enabled bool
}

// Providers holds the constructed SDK providers and a single shutdown hook.
// The zero value (as returned by Setup for a disabled Config) installs
// nothing globally and Shutdown is a no-op.
type Providers struct {
	shutdown func(context.Context) error
	failures atomic.Int64
}

// ExportFailures returns the count of failed/dropped OTLP export attempts
// observed so far. Always 0 when OTel is disabled.
func (p *Providers) ExportFailures() int64 { return p.failures.Load() }

// Shutdown flushes and closes every provider Setup installed, bounded by
// ctx. A disabled Providers returns nil immediately.
func (p *Providers) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

// Setup builds providers from cfg and registers them as the global
// TracerProvider (and, later, MeterProvider/LoggerProvider), returning a
// Providers whose Shutdown flushes and closes with a bounded timeout
// supplied by the caller. When cfg.Enabled is false it installs nothing and
// returns a Providers whose Shutdown is a no-op — the global no-op tracer
// means every instrumented call site costs nothing.
func Setup(ctx context.Context, cfg Config) (*Providers, error) {
	p := &Providers{shutdown: func(context.Context) error { return nil }}
	if !cfg.Enabled {
		return p, nil
	}

	res, err := buildResource(ctx, cfg.Resource)
	if err != nil {
		return nil, fmt.Errorf("otelexport: resource: %w", err)
	}

	var shutdowns []func(context.Context) error

	if cfg.Traces.Enabled {
		tp, err := buildTracerProvider(ctx, cfg, res, &p.failures)
		if err != nil {
			return nil, err
		}
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{}))
		shutdowns = append(shutdowns, tp.Shutdown)
	}

	p.shutdown = func(ctx context.Context) error {
		var firstErr error
		for _, sd := range shutdowns {
			if err := sd(ctx); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	return p, nil
}

// buildResource merges cfg.Resource attributes (service.name defaulting to
// "omni-sag") with the SDK's own default resource (process/telemetry.sdk.*
// attributes).
func buildResource(ctx context.Context, attrs map[string]string) (*resource.Resource, error) {
	serviceName := defaultServiceName
	if v, ok := attrs["service.name"]; ok && v != "" {
		serviceName = v
	}
	kvs := []attribute.KeyValue{semconv.ServiceName(serviceName)}
	for k, v := range attrs {
		if k == "service.name" {
			continue
		}
		kvs = append(kvs, attribute.String(k, v))
	}
	return resource.New(ctx,
		resource.WithAttributes(kvs...),
		resource.WithSchemaURL(semconv.SchemaURL),
	)
}

// buildSampler maps the config sampler name to an sdktrace.Sampler,
// defaulting to parentbased_always_on for an empty/unknown name — a
// low-volume, high-value privileged-access gateway records every session.
func buildSampler(name string, ratio float64) sdktrace.Sampler {
	if ratio <= 0 {
		ratio = 1.0
	}
	switch name {
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "traceidratio":
		return sdktrace.TraceIDRatioBased(ratio)
	case "parentbased_traceidratio":
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	default: // "", "parentbased_always_on", or anything unrecognized
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
}

// buildTracerProvider builds the OTLP trace exporter (wrapped to count
// export failures into failures) and a BatchSpanProcessor-backed
// TracerProvider. The exporter's client dial is non-blocking: an
// unreachable collector at boot never delays or fails Setup, and bounded
// export timeouts mean a dead collector never stalls a session.
func buildTracerProvider(ctx context.Context, cfg Config, res *resource.Resource, failures *atomic.Int64) (*sdktrace.TracerProvider, error) {
	exp, err := buildTraceExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("otelexport: trace exporter: %w", err)
	}
	counted := &countingSpanExporter{SpanExporter: exp, failures: failures}

	var batchOpts []sdktrace.BatchSpanProcessorOption
	if n := cfg.Traces.MaxQueueSize; n > 0 {
		batchOpts = append(batchOpts, sdktrace.WithMaxQueueSize(n))
	}
	if n := cfg.Traces.MaxExportBatchSize; n > 0 {
		batchOpts = append(batchOpts, sdktrace.WithMaxExportBatchSize(n))
	}
	if s := cfg.Traces.ExportTimeoutSeconds; s > 0 {
		batchOpts = append(batchOpts, sdktrace.WithExportTimeout(time.Duration(s)*time.Second))
	}

	return sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(buildSampler(cfg.Traces.Sampler, cfg.Traces.SampleRatio)),
		sdktrace.WithBatcher(counted, batchOpts...),
	), nil
}

// buildTraceExporter builds the OTLP trace exporter for cfg.Protocol. Both
// otlptracegrpc.New and otlptracehttp.New dial lazily (no WithBlock/blocking
// connect), so an unreachable endpoint never blocks this call.
func buildTraceExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	timeout := 10 * time.Second
	if s := cfg.Traces.ExportTimeoutSeconds; s > 0 {
		timeout = time.Duration(s) * time.Second
	}
	switch cfg.Protocol {
	case "", "grpc":
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
			otlptracegrpc.WithTimeout(timeout),
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		} else {
			tlsCfg, err := buildTLSConfig(cfg.TLS)
			if err != nil {
				return nil, err
			}
			opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
		}
		return otlptracegrpc.New(ctx, opts...)
	case "http":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(cfg.Endpoint),
			otlptracehttp.WithTimeout(timeout),
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		} else {
			tlsCfg, err := buildTLSConfig(cfg.TLS)
			if err != nil {
				return nil, err
			}
			opts = append(opts, otlptracehttp.WithTLSClientConfig(tlsCfg))
		}
		return otlptracehttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("otelexport: unknown protocol %q (want grpc|http)", cfg.Protocol)
	}
}

// buildTLSConfig loads TLS material for a verified (optionally mutual-TLS)
// connection to the collector. A zero-value TLSConfig yields the platform
// default trust store with no client certificate.
func buildTLSConfig(c TLSConfig) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CACert != "" {
		pem, err := os.ReadFile(c.CACert)
		if err != nil {
			return nil, fmt.Errorf("tls ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls ca_cert: no certificates parsed")
		}
		cfg.RootCAs = pool
	}
	if c.ClientCert != "" || c.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("tls client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// countingSpanExporter wraps a SpanExporter to increment failures on every
// failed ExportSpans call, surfaced by main.go as
// omnisag_otel_export_failures_total on the Prometheus endpoint.
type countingSpanExporter struct {
	sdktrace.SpanExporter
	failures *atomic.Int64
}

func (e *countingSpanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := e.SpanExporter.ExportSpans(ctx, spans)
	if err != nil {
		e.failures.Add(1)
	}
	return err
}
