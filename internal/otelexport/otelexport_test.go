package otelexport

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
)

func TestSetup_DisabledInstallsNoopAndNoShutdownWork(t *testing.T) {
	before := otel.GetTracerProvider()
	p, err := Setup(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("Setup(disabled): %v", err)
	}
	if otel.GetTracerProvider() != before {
		t.Fatal("Setup(disabled) must not install a TracerProvider")
	}
	if p.ExportFailures() != 0 {
		t.Fatal("disabled Providers should report zero export failures")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(disabled) should be a no-op nil, got %v", err)
	}
}

func TestSetup_EnabledBuildsProviderAndShutsDownCleanly(t *testing.T) {
	// Endpoint is unreachable on purpose: Setup must NOT block or fail on a
	// dead collector (non-blocking dial), and Shutdown must return within a
	// bounded time even though nothing is listening.
	p, err := Setup(context.Background(), Config{
		Enabled:  true,
		Endpoint: "127.0.0.1:4317",
		Protocol: "grpc",
		Insecure: true,
		Traces:   TracesConfig{Enabled: true, Sampler: "always_on", MaxQueueSize: 8},
	})
	if err != nil {
		t.Fatalf("Setup(enabled): %v", err)
	}

	tr := otel.Tracer("test")
	_, span := tr.Start(context.Background(), "probe")
	span.End()

	// Shutdown must return within the bound even though nothing is
	// listening on the endpoint — a dead collector may cause the flush to
	// fail (a bounded ctx.Err()), but it must never hang past the deadline.
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		done <- p.Shutdown(ctx)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return promptly against a dead collector")
	}
}

func TestSetup_BadProtocolErrors(t *testing.T) {
	_, err := Setup(context.Background(), Config{
		Enabled:  true,
		Endpoint: "127.0.0.1:4317",
		Protocol: "carrier-pigeon",
		Traces:   TracesConfig{Enabled: true},
	})
	if err == nil {
		t.Fatal("expected an error for an unknown protocol")
	}
}

func TestSetup_LogsEnabledNonBlockingAgainstDeadCollector(t *testing.T) {
	p, err := Setup(context.Background(), Config{
		Enabled:  true,
		Endpoint: "127.0.0.1:4319",
		Protocol: "grpc",
		Insecure: true,
		Logs:     LogsConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("Setup(logs enabled): %v", err)
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		done <- p.Shutdown(ctx)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return promptly against a dead collector")
	}
}
