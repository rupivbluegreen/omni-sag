package otelexport

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestRegisterObservableCounters_ReadsSnapshot exercises the exact
// registration logic Setup uses for cfg.Metrics, against a ManualReader
// instead of a real OTLP exporter — mirroring the trace test's use of an
// unexported seam rather than a live collector for the assertion that
// matters: callback values equal the injected snapshot.
func TestRegisterObservableCounters_ReadsSnapshot(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	snap := map[string]int64{"auth_success_total": 3, "tunnel_deny_total": 1}
	if err := registerObservableCounters(mp.Meter("test"), func() map[string]int64 { return snap }); err != nil {
		t.Fatalf("registerObservableCounters: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
				for _, dp := range sum.DataPoints {
					got[m.Name] = dp.Value
				}
			}
		}
	}
	if got["omnisag_auth_success_total"] != 3 {
		t.Fatalf("omnisag_auth_success_total = %v, want 3 (got %v)", got["omnisag_auth_success_total"], got)
	}
	if got["omnisag_tunnel_deny_total"] != 1 {
		t.Fatalf("omnisag_tunnel_deny_total = %v, want 1 (got %v)", got["omnisag_tunnel_deny_total"], got)
	}

	// Update the live snapshot and collect again: the callback must read it
	// fresh each time, not a value captured at registration.
	snap["auth_success_total"] = 7
	rm = metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "omnisag_auth_success_total" {
				if sum, ok := m.Data.(metricdata.Sum[int64]); ok && len(sum.DataPoints) == 1 && sum.DataPoints[0].Value != 7 {
					t.Fatalf("expected the callback to read the live snapshot (7), got %d", sum.DataPoints[0].Value)
				}
			}
		}
	}
}

func TestSetup_MetricsEnabledNonBlockingAgainstDeadCollector(t *testing.T) {
	p, err := Setup(context.Background(), Config{
		Enabled:  true,
		Endpoint: "127.0.0.1:4318",
		Protocol: "grpc",
		Insecure: true,
		Metrics: MetricsConfig{
			Enabled:         true,
			IntervalSeconds: 60,
			SnapshotFn:      func() map[string]int64 { return map[string]int64{"auth_success_total": 1} },
		},
	})
	if err != nil {
		t.Fatalf("Setup(metrics enabled): %v", err)
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
