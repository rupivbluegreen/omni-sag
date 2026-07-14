package session

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/inspect"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
)

// recInspector records the reassembled body it receives.
type recInspector struct {
	mu  sync.Mutex
	got []byte
}

func (r *recInspector) Inspect(_ context.Context, _ inspect.TransferMeta, body io.Reader) (inspect.Result, error) {
	b, _ := io.ReadAll(body)
	r.mu.Lock()
	r.got = b
	r.mu.Unlock()
	return inspect.Result{Verdict: inspect.VerdictClean, ICAPStatus: 204}, nil
}

type nopStore struct{}

func (nopStore) Put(context.Context, string, string, io.Reader, int64) error { return nil }
func (nopStore) Get(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (nopStore) Delete(context.Context, string) error { return nil }

func newTestGate(t *testing.T, insp inspect.Inspector) *inspectgate.Gate {
	t.Helper()
	g, err := inspectgate.New(inspectgate.Config{Inspector: insp, Quarantine: nopStore{}, Threshold: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// #1: pkg/sftp delivers writes out of order; the inspected stream must be
// reassembled in offset order before inspection.
func TestInspectUpload_ReassemblesOutOfOrder(t *testing.T) {
	insp := &recInspector{}
	iu := newInspectUpload(context.Background(), newTestGate(t, insp), "/f")
	if _, err := iu.WriteAt([]byte("BBBBB"), 5); err != nil { // buffered ahead
		t.Fatal(err)
	}
	if _, err := iu.WriteAt([]byte("CCCCC"), 10); err != nil { // buffered ahead
		t.Fatal(err)
	}
	if _, err := iu.WriteAt([]byte("AAAAA"), 0); err != nil { // triggers ordered flush
		t.Fatal(err)
	}
	if err := iu.Close(); err != nil {
		t.Fatalf("clean upload should succeed: %v", err)
	}
	if string(insp.got) != "AAAAABBBBBCCCCC" {
		t.Fatalf("reassembled out of order: %q", insp.got)
	}
	if !iu.dec.Allow {
		t.Fatal("clean upload must be allowed")
	}
}

// #1: concurrent writes (the real pkg/sftp behavior) must not race and must
// reassemble correctly. Run with -race.
func TestInspectUpload_ConcurrentWrites(t *testing.T) {
	insp := &recInspector{}
	iu := newInspectUpload(context.Background(), newTestGate(t, insp), "/f")
	const chunks, sz = 8, 1000
	var wg sync.WaitGroup
	for i := 0; i < chunks; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = iu.WriteAt(bytes.Repeat([]byte{byte('A' + i)}, sz), int64(i*sz))
		}(i)
	}
	wg.Wait()
	if err := iu.Close(); err != nil {
		t.Fatalf("upload should succeed: %v", err)
	}
	if len(insp.got) != chunks*sz {
		t.Fatalf("got %d bytes, want %d", len(insp.got), chunks*sz)
	}
	for i := 0; i < chunks; i++ {
		for _, c := range insp.got[i*sz : (i+1)*sz] {
			if c != byte('A'+i) {
				t.Fatalf("bytes out of order in chunk %d", i)
			}
		}
	}
}

// Final audit (HIGH): an upload with a forward offset gap leaves bytes that
// were never presented to the inspector; Close must fail closed, not grade the
// contiguous prefix as clean.
func TestInspectUpload_GappedUploadFailsClosed(t *testing.T) {
	iu := newInspectUpload(context.Background(), newTestGate(t, &recInspector{}), "/f")
	if _, err := iu.WriteAt([]byte("AAAA"), 0); err != nil { // flushed
		t.Fatal(err)
	}
	if _, err := iu.WriteAt([]byte("EVILPAYLOAD"), 1000); err != nil { // gap -> buffered, never inspected
		t.Fatal(err)
	}
	if err := iu.Close(); err == nil {
		t.Fatal("a gapped (never-contiguous) upload must be refused, not accepted")
	}
	if iu.dec.Allow {
		t.Fatal("gapped upload must not be graded Allow")
	}
}
