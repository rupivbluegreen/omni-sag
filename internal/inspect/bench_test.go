package inspect

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

// BenchmarkInspect measures Inspect latency across payload sizes.
//
// By default it runs against the in-process mock (measures the client's framing
// overhead, not real scanning). To get the number the PRD flags as provisional
// — the DLP/AV latency penalty — point it at a live engine:
//
//	ICAP_ENDPOINT=127.0.0.1:1344 ICAP_SERVICE=avscan \
//	  go test ./internal/inspect -run '^$' -bench BenchmarkInspect -benchmem
//
// A local c-icap+ClamAV listens on 1344 (service "avscan"/"srv_clamav"); a
// commercial DLP exposes its own host/port/service. Compare ns/op against a
// no-op passthrough to derive the penalty; ClamAV is a floor, not a
// substitute for a real DLP engine.
func BenchmarkInspect(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 64 << 10},
		{"1MB", 1 << 20},
		{"8MB", 8 << 20},
	}

	c, cleanup := benchClient(b)
	defer cleanup()

	for _, s := range sizes {
		payload := bytes.Repeat([]byte("A"), s.n)
		b.Run(s.name, func(b *testing.B) {
			b.SetBytes(int64(s.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				res, err := c.Inspect(context.Background(), TransferMeta{Filename: "bench.bin"}, bytes.NewReader(payload))
				if err != nil {
					b.Fatalf("inspect: %v", err)
				}
				_ = res
			}
		})
	}
}

// benchClient returns a client pointed at a live ICAP server if ICAP_ENDPOINT
// is set, otherwise at a fresh in-process mock.
func benchClient(b *testing.B) (*Client, func()) {
	if ep := os.Getenv("ICAP_ENDPOINT"); ep != "" {
		svc := os.Getenv("ICAP_SERVICE")
		if svc == "" {
			svc = "avscan"
		}
		return New(Config{Endpoint: ep, Service: svc, Timeout: 30 * time.Second}), func() {}
	}
	m := newMockICAP(b)
	return New(Config{Endpoint: m.addr, Service: "avscan", Timeout: 30 * time.Second}), m.Close
}
