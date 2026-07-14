package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildMultiEpoch runs `epochs` separate Bus lifetimes over one dir (each is a
// fresh process/epoch), emitting recs records each. It returns the bundle dir,
// the shared signer, and the final global chain head.
func buildMultiEpoch(t *testing.T, epochs, recs int) (string, *Signer, string) {
	t.Helper()
	dir := t.TempDir()
	signer, err := NewEphemeralSigner()
	if err != nil {
		t.Fatal(err)
	}
	tick := int64(0)
	var head string
	for e := 0; e < epochs; e++ {
		bus, err := NewBus(BusConfig{
			DataDir: dir, SegmentSize: 100, Signer: signer,
			Now: func() time.Time { tick++; return time.Unix(1700000000+tick, 0).UTC() },
		})
		if err != nil {
			t.Fatal(err)
		}
		em := bus.Emitter("session")
		for i := 0; i < recs; i++ {
			if err := em.Emit(Event{Type: TypeAuth, User: "alice", Allow: BoolPtr(true)}); err != nil {
				t.Fatal(err)
			}
		}
		if err := bus.Close(); err != nil {
			t.Fatal(err)
		}
		head = bus.Head()
	}
	return dir, signer, head
}

func deleteEpochFiles(t *testing.T, dir string, epoch uint64) {
	t.Helper()
	for _, s := range []struct{ d, pre string }{{"segments", "segment-"}, {"checkpoints", "checkpoint-"}} {
		entries, _ := os.ReadDir(filepath.Join(dir, s.d))
		removed := 0
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), fmt.Sprintf("%s%d-", s.pre, epoch)) {
				if err := os.Remove(filepath.Join(dir, s.d, e.Name())); err != nil {
					t.Fatal(err)
				}
				removed++
			}
		}
		if removed == 0 {
			t.Fatalf("no %s files found for epoch %d", s.d, epoch)
		}
	}
}

func TestVerify_WholeEpochDeletionDetected(t *testing.T) {
	dir, signer, _ := buildMultiEpoch(t, 3, 2)
	// sanity: intact bundle verifies
	if rep, _ := VerifyBundle(dir, signer.PublicKeyHex(), ""); !rep.OK {
		t.Fatalf("intact multi-epoch bundle must verify: %v", rep.Problems)
	}
	// Delete the entire MIDDLE epoch (2). The global checkpoint chain must break.
	deleteEpochFiles(t, dir, 2)
	rep, _ := VerifyBundle(dir, signer.PublicKeyHex(), "")
	if rep.OK {
		t.Fatal("whole-epoch deletion must FAIL verification")
	}
	if !anyContains(rep.Problems, "broken checkpoint chain") {
		t.Fatalf("expected a broken-chain problem, got: %v", rep.Problems)
	}
}

func TestVerify_PrefixDeletionDetected(t *testing.T) {
	dir, signer, _ := buildMultiEpoch(t, 3, 2)
	// Delete the FIRST epoch: the new first checkpoint no longer links to genesis.
	deleteEpochFiles(t, dir, 1)
	rep, _ := VerifyBundle(dir, signer.PublicKeyHex(), "")
	if rep.OK {
		t.Fatal("prefix (first-epoch) deletion must FAIL verification")
	}
	if !anyContains(rep.Problems, "broken checkpoint chain") {
		t.Fatalf("expected a broken-chain problem, got: %v", rep.Problems)
	}
}

func TestVerify_TrailingTruncationDetectedWithHead(t *testing.T) {
	dir, signer, head := buildMultiEpoch(t, 3, 2)
	key := signer.PublicKeyHex()

	// Delete the newest epoch (3). Without a pinned head this is undetectable
	// (documented gap: only the pinned head or WORM catches trailing deletion).
	deleteEpochFiles(t, dir, 3)

	if rep, _ := VerifyBundle(dir, key, ""); !rep.OK {
		t.Fatalf("trailing deletion without a pinned head should still pass internal checks (documented): %v", rep.Problems)
	}
	// With the out-of-band pinned head, the truncation is caught.
	rep, _ := VerifyBundle(dir, key, head)
	if rep.OK {
		t.Fatal("trailing truncation must FAIL when the head is pinned")
	}
	if !anyContains(rep.Problems, "trailing truncation") {
		t.Fatalf("expected a trailing-truncation problem, got: %v", rep.Problems)
	}
}

func TestVerify_UnpinnedIsNotAuthenticated(t *testing.T) {
	dir, signer, _ := buildMultiEpoch(t, 1, 4)

	// Unpinned: internal checks pass but KeyPinned is false — the CLI uses this
	// to refuse to claim authenticity.
	rep, _ := VerifyBundle(dir, "", "")
	if !rep.OK {
		t.Fatalf("internally consistent bundle should pass integrity checks: %v", rep.Problems)
	}
	if rep.KeyPinned {
		t.Fatal("KeyPinned must be false when no key is pinned")
	}

	// A wrong pinned key must be rejected (pinning is the real authenticity gate).
	other, _ := NewEphemeralSigner()
	if rep, _ := VerifyBundle(dir, other.PublicKeyHex(), ""); rep.OK {
		t.Fatal("a bundle signed by a different key must FAIL against a pinned key")
	}
	_ = signer
}

func TestBus_CloseSurfacesSealError(t *testing.T) {
	dir := t.TempDir()
	signer, _ := NewEphemeralSigner()
	bus, err := NewBus(BusConfig{DataDir: dir, SegmentSize: 100, Signer: signer,
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	if err := bus.Emitter("session").Emit(Event{Type: TypeAuth, User: "a"}); err != nil {
		t.Fatal(err)
	}
	// Make the checkpoints dir unwritable so the trailing seal at Close fails.
	ckDir := filepath.Join(dir, "checkpoints")
	if err := os.Chmod(ckDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(ckDir, 0o700)

	err = bus.Close()
	if err == nil {
		t.Skip("checkpoint write succeeded despite 0500 dir (running as root?); cannot exercise seal-error path")
	}
	if !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("Close should surface the seal error, got: %v", err)
	}
}

func TestBus_OpenSegmentFailsClosedOnCollision(t *testing.T) {
	dir := t.TempDir()
	signer, _ := NewEphemeralSigner()
	if err := os.MkdirAll(filepath.Join(dir, "segments"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "checkpoints"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Simulate a leftover segment from a reused epoch: epoch will advance to 1,
	// so pre-create segment-1-0.jsonl. O_EXCL must refuse to overwrite it.
	if err := os.WriteFile(filepath.Join(dir, "segments", "segment-1-0.jsonl"), []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bus, err := NewBus(BusConfig{DataDir: dir, SegmentSize: 100, Signer: signer,
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.Emitter("session").Emit(Event{Type: TypeAuth, User: "a"}); err == nil {
		t.Fatal("emit must fail closed when the segment file already exists (epoch reuse)")
	}
}
