package evidence

import (
	"testing"
	"time"
)

func sampleRecord() Record {
	return Record{
		EmitterID: "dialer",
		Epoch:     7,
		Seq:       3,
		GlobalSeq: 42,
		Time:      time.Unix(1700000000, 0).UTC(),
		Event:     Event{ID: "e1", Type: TypeTunnelDecision, User: "alice", Allow: BoolPtr(true)},
	}
}

func TestRecord_SealAndVerifyHash(t *testing.T) {
	r := sampleRecord()
	head, err := r.seal(GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	if r.Hash == "" || head != r.Hash {
		t.Fatal("seal must set Hash and return it as the new head")
	}
	// Recomputing the hash from canonical bytes must match (verification path).
	got, err := r.ComputeHash()
	if err != nil {
		t.Fatal(err)
	}
	if got != r.Hash {
		t.Fatalf("recomputed hash %s != stored %s", got, r.Hash)
	}
}

func TestRecord_HashExcludesHashField(t *testing.T) {
	r := sampleRecord()
	_, _ = r.seal(GenesisPrevHash)
	// Mutating the stored Hash must not change the recomputed canonical hash.
	r.Hash = "deadbeef"
	got, _ := r.ComputeHash()
	if got == "deadbeef" {
		t.Fatal("ComputeHash must ignore the stored Hash field")
	}
}

func TestRecord_TamperDetected(t *testing.T) {
	r := sampleRecord()
	_, _ = r.seal(GenesisPrevHash)
	original := r.Hash

	// Flip a payload field; recomputed hash must diverge from the sealed hash.
	r.Event.User = "mallory"
	got, _ := r.ComputeHash()
	if got == original {
		t.Fatal("tampering the event must change the recomputed hash")
	}
}

func TestRecord_ChainLinks(t *testing.T) {
	r1 := sampleRecord()
	h1, _ := r1.seal(GenesisPrevHash)

	r2 := sampleRecord()
	r2.Seq = 4
	r2.GlobalSeq = 43
	h2, _ := r2.seal(h1)

	if r2.PrevHash != h1 {
		t.Fatal("record 2 must link to record 1's hash")
	}
	if h2 == h1 {
		t.Fatal("distinct records must have distinct hashes")
	}
	if r1.PrevHash != GenesisPrevHash {
		t.Fatal("first record must link to genesis")
	}
}
