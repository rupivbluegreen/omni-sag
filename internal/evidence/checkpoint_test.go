package evidence

import (
	"testing"
	"time"
)

func TestCheckpoint_SignAndVerify(t *testing.T) {
	s, err := NewEphemeralSigner()
	if err != nil {
		t.Fatal(err)
	}
	c := Checkpoint{
		Epoch: 1, SegmentIndex: 0, FirstGlobalSeq: 1, LastGlobalSeq: 10,
		RecordCount: 10, MerkleRoot: "abc", ChainHead: "def",
		PrevCheckpointHash: GenesisPrevCheckpoint, Time: time.Unix(1700000000, 0).UTC(),
	}
	if err := c.signWith(s); err != nil {
		t.Fatal(err)
	}
	if c.PublicKey != s.PublicKeyHex() {
		t.Fatal("checkpoint must embed the signer public key")
	}
	if !c.VerifySig() {
		t.Fatal("freshly signed checkpoint must verify")
	}
}

func TestCheckpoint_TamperBreaksSignature(t *testing.T) {
	s, _ := NewEphemeralSigner()
	c := Checkpoint{Epoch: 1, MerkleRoot: "root", LastGlobalSeq: 5, Time: time.Unix(1, 0).UTC()}
	_ = c.signWith(s)

	c.MerkleRoot = "tampered"
	if c.VerifySig() {
		t.Fatal("tampering a signed field must break verification")
	}
}

func TestCheckpoint_WrongKeyFails(t *testing.T) {
	s1, _ := NewEphemeralSigner()
	s2, _ := NewEphemeralSigner()
	c := Checkpoint{Epoch: 1, MerkleRoot: "root", Time: time.Unix(1, 0).UTC()}
	_ = c.signWith(s1)
	// Swap in another key id: verification against the embedded (now wrong) key
	// must fail because the signature was made by s1.
	c.PublicKey = s2.PublicKeyHex()
	if c.VerifySig() {
		t.Fatal("signature must not verify under a different public key")
	}
}

func TestCheckpoint_HashChainDiffers(t *testing.T) {
	s, _ := NewEphemeralSigner()
	c1 := Checkpoint{Epoch: 1, SegmentIndex: 0, MerkleRoot: "r0", Time: time.Unix(1, 0).UTC()}
	_ = c1.signWith(s)
	h1, err := c1.HashHex()
	if err != nil {
		t.Fatal(err)
	}
	c2 := Checkpoint{Epoch: 1, SegmentIndex: 1, MerkleRoot: "r1", PrevCheckpointHash: h1, Time: time.Unix(2, 0).UTC()}
	_ = c2.signWith(s)
	h2, _ := c2.HashHex()
	if h1 == h2 {
		t.Fatal("distinct checkpoints must hash differently")
	}
}
