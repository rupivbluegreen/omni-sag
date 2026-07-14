package inspectgate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/inspect"
)

// fixedInspector drains the body and returns a fixed verdict.
type fixedInspector struct {
	verdict inspect.Verdict
	err     error
}

func (f fixedInspector) Inspect(_ context.Context, _ inspect.TransferMeta, body io.Reader) (inspect.Result, error) {
	_, _ = io.Copy(io.Discard, body)
	if f.err != nil {
		return inspect.Result{}, f.err
	}
	return inspect.Result{Verdict: f.verdict, ICAPStatus: 204}, nil
}

// hdStore is an in-memory BlobStore recording puts.
type hdStore struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func newHDStore() *hdStore { return &hdStore{objs: map[string][]byte{}} }
func (s *hdStore) Put(_ context.Context, key, _ string, r io.Reader, _ int64) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.objs[key] = b
	s.mu.Unlock()
	return nil
}
func (s *hdStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objs[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
func (s *hdStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	delete(s.objs, key)
	s.mu.Unlock()
	return nil
}
func (s *hdStore) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.objs) }

// failingHolding reads a little then fails, and cannot Get — simulating a
// holding store that dies mid-stream.
type failingHolding struct{ readLimit int }

func (h failingHolding) Put(_ context.Context, _, _ string, r io.Reader, _ int64) error {
	_, _ = io.ReadFull(r, make([]byte, h.readLimit))
	return errors.New("holding write failed mid-stream")
}
func (h failingHolding) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("holding gone")
}
func (h failingHolding) Delete(context.Context, string) error { return nil }

// #2: a holding-store failure mid-stream must fail closed (return), not deadlock.
func TestGate_HoldingFailureFailsClosedNoDeadlock(t *testing.T) {
	q := newHDStore()
	g, err := New(Config{Inspector: fixedInspector{verdict: inspect.VerdictClean}, Holding: failingHolding{readLimit: 4}, Quarantine: q, Threshold: 4})
	if err != nil {
		t.Fatal(err)
	}
	// > threshold -> large path -> streams to the failing holding store.
	body := bytes.NewReader(bytes.Repeat([]byte("x"), 1024))

	done := make(chan Decision, 1)
	go func() {
		dec, _ := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "f"}, body)
		done <- dec
	}()
	select {
	case dec := <-done:
		if dec.Allow {
			t.Fatal("a holding-store failure must not allow the transfer")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Inspect deadlocked on holding-store failure (did not fail closed)")
	}
}

// #3: a Modified verdict must be refused (fail closed) and quarantined, on both
// the small and large paths — never delivered as the original bytes.
func TestGate_ModifiedIsRefusedAndQuarantined(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		hold BlobStore
	}{
		{"small", 8, nil},
		{"large", 4096, newHDStore()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := newHDStore()
			g, _ := New(Config{Inspector: fixedInspector{verdict: inspect.VerdictModified}, Holding: tc.hold, Quarantine: q, Threshold: 1024})
			dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "f"}, bytes.NewReader(bytes.Repeat([]byte("y"), tc.size)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Allow {
				t.Fatal("Modified must not be allowed (would deliver un-inspected original)")
			}
			if dec.Verdict != "modified" || dec.QuarantineKey == "" || q.count() != 1 {
				t.Fatalf("Modified must be quarantined: %+v (quarantined=%d)", dec, q.count())
			}
		})
	}
}

// #4: with no holding store, a file larger than the buffer must fail closed —
// not be prefix-inspected and recorded clean.
func TestGate_NoHoldingOversizedFailsClosed(t *testing.T) {
	q := newHDStore()
	g, _ := New(Config{Inspector: fixedInspector{verdict: inspect.VerdictClean}, Quarantine: q, Threshold: 16})
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "big"}, strings.NewReader(strings.Repeat("z", 1024)))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Fatal("oversized file with no holding store must fail closed, not be allowed on a prefix")
	}
	if dec.Verdict != "error" {
		t.Fatalf("expected error verdict, got %q", dec.Verdict)
	}
}
