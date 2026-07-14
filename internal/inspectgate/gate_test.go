package inspectgate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/inspect"
)

// fakeInspector returns a fixed verdict/error after consuming the whole body.
type fakeInspector struct {
	verdict inspect.Verdict
	reason  string
	status  int
	err     error
}

func (f fakeInspector) Inspect(_ context.Context, _ inspect.TransferMeta, body io.Reader) (inspect.Result, error) {
	_, _ = io.Copy(io.Discard, body) // drain so the streaming tee never blocks
	if f.err != nil {
		return inspect.Result{}, f.err
	}
	return inspect.Result{Verdict: f.verdict, Reason: f.reason, ICAPStatus: f.status}, nil
}

// errQuarantineDown is injected via memStore.putErr to simulate a WORM
// quarantine store that fails writes; tests assert on it with errors.Is to
// confirm the gate actually wraps and propagates the underlying failure.
var errQuarantineDown = errors.New("quarantine store down")

// memStore is an in-memory BlobStore. putErr, when set, makes every Put fail
// with that error instead of storing anything — used to simulate a WORM
// quarantine store that is down/full/otherwise failing writes.
type memStore struct {
	mu     sync.Mutex
	objs   map[string][]byte
	putErr error
}

func newMemStore() *memStore { return &memStore{objs: map[string][]byte{}} }

func (m *memStore) Put(_ context.Context, key, _ string, r io.Reader, _ int64) error {
	if m.putErr != nil {
		return m.putErr
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.objs[key] = data
	m.mu.Unlock()
	return nil
}
func (m *memStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objs[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(strings.NewReader(string(data))), nil
}
func (m *memStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.objs, key)
	m.mu.Unlock()
	return nil
}
func (m *memStore) len(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.objs[key])
}
func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.objs)
}

// countingStore discards content but records the total bytes written, to prove
// large content is streamed rather than buffered.
type countingStore struct {
	mu    sync.Mutex
	bytes int64
}

func (c *countingStore) Put(_ context.Context, _, _ string, r io.Reader, _ int64) error {
	n, err := io.Copy(io.Discard, r)
	c.mu.Lock()
	c.bytes += n
	c.mu.Unlock()
	return err
}
func (c *countingStore) Get(context.Context, string) (io.ReadCloser, error) {
	c.mu.Lock()
	n := c.bytes
	c.mu.Unlock()
	return io.NopCloser(io.LimitReader(zeroReader{}, n)), nil
}
func (c *countingStore) Delete(context.Context, string) error { return nil }

func newGate(t *testing.T, insp inspect.Inspector, holding BlobStore, q BlobStore, threshold int64) *Gate {
	t.Helper()
	g, err := New(Config{Inspector: insp, Holding: holding, Quarantine: q, Threshold: threshold})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestGate_SmallClean(t *testing.T) {
	q := newMemStore()
	g := newGate(t, fakeInspector{verdict: inspect.VerdictClean, status: 204}, nil, q, 1<<20)
	body := []byte("hello world")
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "a.txt"}, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow || dec.Verdict != "clean" {
		t.Fatalf("want clean/allow, got %+v", dec)
	}
	if dec.SHA256 != sha(body) || dec.Bytes != int64(len(body)) {
		t.Fatalf("digest/size wrong: %+v", dec)
	}
	// Every upload — clean or not — gets a permanent, byte-level evidentiary
	// copy in WORM quarantine; verify the actual bytes are recoverable, not
	// just that a key was assigned.
	if dec.QuarantineKey == "" {
		t.Fatal("clean content must still be quarantined (byte-level evidentiary copy)")
	}
	stored, err := q.Get(context.Background(), dec.QuarantineKey)
	if err != nil {
		t.Fatalf("quarantine store missing the clean upload's bytes: %v", err)
	}
	got, err := io.ReadAll(stored)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("quarantined content = %q, want %q", got, body)
	}
}

// TestGate_SmallCleanQuarantineWriteFailureFailsClosed locks in the
// fail-closed ordering: a clean scan verdict must NOT be allowed through if
// persisting the evidentiary quarantine copy itself fails. Regression guard
// for a bug where Allow could be set true before the quarantine write was
// confirmed to succeed.
func TestGate_SmallCleanQuarantineWriteFailureFailsClosed(t *testing.T) {
	q := newMemStore()
	q.putErr = errQuarantineDown
	g := newGate(t, fakeInspector{verdict: inspect.VerdictClean, status: 204}, nil, q, 1<<20)
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "f"}, strings.NewReader("hello"))
	if err == nil || !errors.Is(err, errQuarantineDown) {
		t.Fatalf("a quarantine write failure on an otherwise-clean scan must return a wrapped error, got %v", err)
	}
	if dec.Allow {
		t.Fatal("a quarantine write failure must fail closed: Allow must be false even though the scan itself was clean")
	}
	if dec.Verdict != "error" {
		t.Fatalf("verdict = %q, want error", dec.Verdict)
	}
}

func TestGate_SmallBlockedQuarantines(t *testing.T) {
	q := newMemStore()
	g := newGate(t, fakeInspector{verdict: inspect.VerdictBlocked, reason: "EICAR", status: 200}, nil, q, 1<<20)
	body := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "virus"}, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow || dec.Verdict != "blocked" {
		t.Fatalf("blocked content must be refused: %+v", dec)
	}
	if dec.QuarantineKey == "" || q.len(dec.QuarantineKey) != len(body) {
		t.Fatalf("blocked content must be quarantined intact: %+v", dec)
	}
}

func TestGate_FailClosedOnInspectorError(t *testing.T) {
	q := newMemStore()
	g := newGate(t, fakeInspector{err: errors.New("icap down")}, nil, q, 1<<20)
	body := []byte("anything")
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "f"}, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Fatal("an unscannable transfer must fail closed (refused)")
	}
	if dec.Verdict != "error" || dec.QuarantineKey == "" || q.len(dec.QuarantineKey) != len(body) {
		t.Fatalf("fail-closed content must be quarantined: %+v", dec)
	}
}

func TestGate_LargeCleanIsQuarantined(t *testing.T) {
	holding := newMemStore()
	q := newMemStore()
	g := newGate(t, fakeInspector{verdict: inspect.VerdictClean, status: 204}, holding, q, 8)
	body := []byte(strings.Repeat("abcd", 100)) // 400 bytes > threshold 8
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "big.bin"}, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow || dec.Verdict != "clean" || dec.QuarantineKey == "" {
		t.Fatalf("large clean file must be delivered and quarantined: %+v", dec)
	}
	if dec.SHA256 != sha(body) || dec.Bytes != int64(len(body)) {
		t.Fatalf("digest/size wrong: %+v", dec)
	}
	// Verify the actual bytes are recoverable from quarantine, not just that a
	// key was assigned — this is the whole point of the evidentiary copy.
	stored, err := q.Get(context.Background(), dec.QuarantineKey)
	if err != nil {
		t.Fatalf("quarantine store missing the clean upload's bytes: %v", err)
	}
	got, err := io.ReadAll(stored)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("quarantined content = %q, want %q", got, body)
	}
	// The transient holding copy is promoted then deleted, exactly as the
	// existing blocked-content path already does.
	if holding.count() != 0 {
		t.Fatal("holding copy should have been deleted after promotion to quarantine")
	}
}

// TestGate_LargeCleanQuarantineWriteFailureFailsClosed is the large-file
// counterpart to TestGate_SmallCleanQuarantineWriteFailureFailsClosed: the
// stream tees successfully into a working holding store, the inspector says
// clean, but promote's final copy into quarantine fails — the gate must fail
// closed rather than deliver the streamed content.
func TestGate_LargeCleanQuarantineWriteFailureFailsClosed(t *testing.T) {
	holding := newMemStore() // succeeds, so the stream/tee completes fine
	q := newMemStore()
	q.putErr = errQuarantineDown // fails only at promote's final quarantine.Put
	g := newGate(t, fakeInspector{verdict: inspect.VerdictClean, status: 204}, holding, q, 8)
	body := strings.Repeat("z", 500) // > threshold 8 -> large/streaming path
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "big"}, strings.NewReader(body))
	if err == nil || !errors.Is(err, errQuarantineDown) {
		t.Fatalf("a quarantine promotion failure on an otherwise-clean large upload must return a wrapped error, got %v", err)
	}
	if dec.Allow {
		t.Fatal("a quarantine promotion failure must fail closed: Allow must be false even though the scan itself was clean")
	}
	if dec.Verdict != "error" {
		t.Fatalf("verdict = %q, want error", dec.Verdict)
	}
}

func TestGate_LargeBlockedPromotedToQuarantine(t *testing.T) {
	holding := newMemStore()
	q := newMemStore()
	g := newGate(t, fakeInspector{verdict: inspect.VerdictBlocked, reason: "sig", status: 200}, holding, q, 8)
	body := []byte(strings.Repeat("z", 500))
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "mal.bin"}, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow || dec.Verdict != "blocked" || dec.QuarantineKey == "" {
		t.Fatalf("large blocked file must be quarantined: %+v", dec)
	}
	if q.len(dec.QuarantineKey) != len(body) {
		t.Fatalf("quarantine must hold the full content, got %d", q.len(dec.QuarantineKey))
	}
	if holding.count() != 0 {
		t.Fatal("holding copy must be dropped after promotion to quarantine")
	}
}

func TestGate_LargeNoOOM(t *testing.T) {
	// Stream 64 MiB through the gate with a small threshold and discarding
	// holding/quarantine stores; if this buffered the whole file at any stage
	// (streaming tee, or promotion into quarantine) it would allocate 64 MiB.
	const size = 64 << 20
	holding := &countingStore{}
	q := &countingStore{}
	g := newGate(t, fakeInspector{verdict: inspect.VerdictClean, status: 204}, holding, q, 4096)
	dec, err := g.Inspect(context.Background(), inspect.TransferMeta{Filename: "huge.bin"}, io.LimitReader(zeroReader{}, size))
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow || dec.Bytes != size {
		t.Fatalf("large clean stream must be delivered with full byte count: %+v", dec)
	}
	if holding.bytes != size {
		t.Fatalf("holding must have received the full stream: got %d want %d", holding.bytes, size)
	}
	if dec.QuarantineKey == "" {
		t.Fatal("clean content must be quarantined")
	}
	if q.bytes != size {
		t.Fatalf("quarantine must hold the full promoted content: got %d want %d", q.bytes, size)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}
