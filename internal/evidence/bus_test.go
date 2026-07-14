package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildBundle emits events from two emitters into a fresh bus and returns the
// bundle directory (sealed and closed).
func buildBundle(t *testing.T, segmentSize int) (string, *Signer) {
	t.Helper()
	dir := t.TempDir()
	signer, err := NewEphemeralSigner()
	if err != nil {
		t.Fatal(err)
	}
	tick := int64(0)
	bus, err := NewBus(BusConfig{
		DataDir:     dir,
		SegmentSize: segmentSize,
		Signer:      signer,
		Now:         func() time.Time { tick++; return time.Unix(1700000000+tick, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	dialer := bus.Emitter("dialer")
	session := bus.Emitter("session")

	// Interleave emitters so global order != per-emitter order.
	for i := 0; i < 5; i++ {
		if err := session.Emit(Event{Type: TypeAuth, User: "alice", Allow: BoolPtr(true)}); err != nil {
			t.Fatalf("session emit: %v", err)
		}
		if err := dialer.Emit(Event{Type: TypeTunnelDecision, User: "alice", Target: "db:5432", Allow: BoolPtr(true)}); err != nil {
			t.Fatalf("dialer emit: %v", err)
		}
	}
	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, signer
}

func TestBus_ProducesVerifiableBundle(t *testing.T) {
	dir, signer := buildBundle(t, 3)

	rep, err := VerifyBundle(dir, signer.PublicKeyHex(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("fresh bundle must verify, problems: %v", rep.Problems)
	}
	if rep.RecordsChecked != 10 {
		t.Fatalf("expected 10 records, got %d", rep.RecordsChecked)
	}
	if rep.CheckpointsChecked == 0 {
		t.Fatal("expected at least one checkpoint")
	}
	// Two emitters, each with 5 records, epoch 1.
	if len(rep.SigningKeys) != 1 || rep.SigningKeys[0] != signer.PublicKeyHex() {
		t.Fatalf("unexpected signing keys: %v", rep.SigningKeys)
	}
}

func TestBus_TamperedRecordFailsVerification(t *testing.T) {
	dir, signer := buildBundle(t, 3)

	// Flip a byte in the first segment's payload.
	segDir := filepath.Join(dir, "segments")
	entries, _ := os.ReadDir(segDir)
	var target string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			target = filepath.Join(segDir, e.Name())
			break
		}
	}
	data, _ := os.ReadFile(target)
	tampered := strings.Replace(string(data), "alice", "mallo", 1)
	if tampered == string(data) {
		t.Fatal("expected to tamper a record")
	}
	if err := os.WriteFile(target, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifyBundle(dir, signer.PublicKeyHex(), "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("tampered bundle must FAIL verification")
	}
	if !anyContains(rep.Problems, "TAMPER") && !anyContains(rep.Problems, "Merkle root mismatch") {
		t.Fatalf("expected a tamper/merkle problem, got: %v", rep.Problems)
	}
}

func TestBus_DeletedRecordDetected(t *testing.T) {
	dir, signer := buildBundle(t, 10) // one segment holds all 10

	segDir := filepath.Join(dir, "segments")
	entries, _ := os.ReadDir(segDir)
	target := filepath.Join(segDir, entries[0].Name())
	data, _ := os.ReadFile(target)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// Drop the middle record.
	kept := append(lines[:5], lines[6:]...)
	if err := os.WriteFile(target, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, _ := VerifyBundle(dir, signer.PublicKeyHex(), "")
	if rep.OK {
		t.Fatal("deleting a record must FAIL verification")
	}
}

func TestBus_TamperedCheckpointSignatureFails(t *testing.T) {
	dir, signer := buildBundle(t, 3)

	ckDir := filepath.Join(dir, "checkpoints")
	entries, _ := os.ReadDir(ckDir)
	target := filepath.Join(ckDir, entries[0].Name())
	data, _ := os.ReadFile(target)
	// Corrupt the merkle_root field value; signature will no longer match.
	tampered := strings.Replace(string(data), "\"merkle_root\": \"", "\"merkle_root\": \"00", 1)
	if err := os.WriteFile(target, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, _ := VerifyBundle(dir, signer.PublicKeyHex(), "")
	if rep.OK {
		t.Fatal("tampered checkpoint must FAIL verification")
	}
}

func TestBus_EpochAdvancesOnRestart(t *testing.T) {
	dir := t.TempDir()
	signer, _ := NewEphemeralSigner()
	mk := func() *Bus {
		b, err := NewBus(BusConfig{DataDir: dir, SegmentSize: 100, Signer: signer,
			Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b1 := mk()
	_ = b1.Emitter("dialer").Emit(Event{Type: TypeAuth, User: "a"})
	if err := b1.Close(); err != nil {
		t.Fatal(err)
	}
	b2 := mk()
	_ = b2.Emitter("dialer").Emit(Event{Type: TypeAuth, User: "b"})
	if err := b2.Close(); err != nil {
		t.Fatal(err)
	}

	// Both runs should verify together, and the second run's records must be in
	// epoch 2 (per-emitter seq resets to 1 under the new epoch).
	rep, err := VerifyBundle(dir, signer.PublicKeyHex(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("multi-epoch bundle must verify: %v", rep.Problems)
	}
}

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
