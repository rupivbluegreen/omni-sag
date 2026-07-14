package inspectgate

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/inspect"
)

// Chaos / fail-closed matrix for the content-inspection gate.
//
// Whenever the ICAP inspector cannot render a trustworthy CLEAN verdict — it is
// down, times out, returns garbage, requests a modification, or returns an
// unrecognized verdict — the gate MUST refuse the transfer (Allow=false) and
// QUARANTINE the content to WORM, never deliver it. These tests drive each
// inspector failure and assert refusal + quarantine + no delivery.

// stallInspector blocks until ctx is cancelled, then reports the ctx error —
// modelling an ICAP server that accepts the body but never returns a verdict.
type stallInspector struct{}

func (stallInspector) Inspect(ctx context.Context, _ inspect.TransferMeta, body io.Reader) (inspect.Result, error) {
	_, _ = io.Copy(io.Discard, body)
	<-ctx.Done()
	return inspect.Result{}, ctx.Err()
}

func assertRefusedAndQuarantined(t *testing.T, dec Decision, err error, q *memStore) {
	t.Helper()
	if err != nil {
		t.Fatalf("a scannable-failure must yield a fail-closed Decision, not an error: %v", err)
	}
	if dec.Allow {
		t.Fatalf("inspector failure must NOT allow the transfer: %+v", dec)
	}
	if dec.HoldingKey != "" {
		t.Fatalf("refused content must not be delivered via a holding key: %+v", dec)
	}
	if dec.QuarantineKey == "" {
		t.Fatal("refused content must be quarantined (QuarantineKey set)")
	}
	if q.count() == 0 {
		t.Fatal("refused content must actually land in the WORM quarantine store")
	}
}

// ICAP down / transport error on a small file → fail closed + quarantine.
func TestChaos_GateInspectorDownSmall(t *testing.T) {
	q := newMemStore()
	g := newGate(t, fakeInspector{err: errors.New("icap connection refused")}, newMemStore(), q, 1<<20)
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "f"}, strings.NewReader("payload"))
	assertRefusedAndQuarantined(t, dec, err, q)
}

// ICAP down / transport error on a large (streamed) file → fail closed +
// quarantine, with nothing delivered from holding.
func TestChaos_GateInspectorDownLarge(t *testing.T) {
	q := newMemStore()
	g := newGate(t, fakeInspector{err: errors.New("icap reset")}, newMemStore(), q, 8)
	big := strings.Repeat("A", 4096) // exceeds the 8-byte threshold -> streaming path
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "big"}, strings.NewReader(big))
	assertRefusedAndQuarantined(t, dec, err, q)
}

// ICAP timeout: the inspector stalls until the caller's deadline fires → fail
// closed + quarantine (small path).
func TestChaos_GateInspectorTimeoutSmall(t *testing.T) {
	q := newMemStore()
	g := newGate(t, stallInspector{}, newMemStore(), q, 1<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	dec, err := g.Inspect(ctx, inspect.TransferMeta{Filename: "f"}, strings.NewReader("payload"))
	assertRefusedAndQuarantined(t, dec, err, q)
}

// ICAP timeout on the large streaming path → fail closed + quarantine.
func TestChaos_GateInspectorTimeoutLarge(t *testing.T) {
	q := newMemStore()
	g := newGate(t, stallInspector{}, newMemStore(), q, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	big := strings.Repeat("B", 4096)
	dec, err := g.Inspect(ctx, inspect.TransferMeta{Filename: "big"}, strings.NewReader(big))
	assertRefusedAndQuarantined(t, dec, err, q)
}

// Modified verdict (DLP wants to alter the payload): we do not deliver
// sanitized bytes, so it fails closed + quarantine on both size tiers.
func TestChaos_GateModifiedFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		threshold int64
		size      int
	}{
		{"small", 1 << 20, 16},
		{"large", 8, 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := newMemStore()
			g := newGate(t, fakeInspector{verdict: inspect.VerdictModified, reason: "PII redacted"}, newMemStore(), q, tc.threshold)
			dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "f"}, strings.NewReader(strings.Repeat("x", tc.size)))
			assertRefusedAndQuarantined(t, dec, err, q)
			if dec.Verdict != "modified" {
				t.Fatalf("verdict = %q, want modified", dec.Verdict)
			}
		})
	}
}

// Defense in depth: an UNRECOGNIZED verdict (out of the known enum range) — a
// buggy/compromised inspector — must fail closed, never fall through to allow.
// This guards the switch-default fail-open branch on both size tiers.
func TestChaos_GateUnknownVerdictFailsClosed(t *testing.T) {
	const bogus = inspect.Verdict(99)
	for _, tc := range []struct {
		name      string
		threshold int64
		size      int
	}{
		{"small", 1 << 20, 16},
		{"large", 8, 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := newMemStore()
			g := newGate(t, fakeInspector{verdict: bogus}, newMemStore(), q, tc.threshold)
			dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "f"}, strings.NewReader(strings.Repeat("z", tc.size)))
			assertRefusedAndQuarantined(t, dec, err, q)
		})
	}
}

// No holding store configured and the file exceeds the inline limit: the gate
// must refuse rather than inspect only a prefix and (falsely) pass it.
func TestChaos_GateOversizedNoHoldingFailsClosed(t *testing.T) {
	g := newGate(t, fakeInspector{verdict: inspect.VerdictClean}, nil, newMemStore(), 8)
	big := strings.Repeat("C", 4096)
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "big"}, strings.NewReader(big))
	if err != nil {
		t.Fatalf("oversized-no-holding must be a fail-closed Decision, not error: %v", err)
	}
	if dec.Allow {
		t.Fatal("oversized content with no holding store must fail closed")
	}
}
