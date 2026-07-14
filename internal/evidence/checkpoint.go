package evidence

import (
	"encoding/json"
	"time"
)

// CheckpointSchemaVersion versions the checkpoint encoding.
const CheckpointSchemaVersion = 1

// GenesisPrevCheckpoint is the prev_checkpoint_hash of the first checkpoint.
const GenesisPrevCheckpoint = ""

// Checkpoint is a signed attestation over one sealed segment. It commits to the
// segment's Merkle root and the running hash-chain head, chains to the previous
// checkpoint, and is signed with the gateway's Ed25519 key. A verifier with
// only the public key can confirm the segment has not been altered or truncated.
type Checkpoint struct {
	SchemaVersion      int       `json:"schema_version"`
	Epoch              uint64    `json:"epoch"`
	SegmentIndex       uint64    `json:"segment_index"`
	FirstGlobalSeq     uint64    `json:"first_global_seq"`
	LastGlobalSeq      uint64    `json:"last_global_seq"`
	RecordCount        int       `json:"record_count"`
	MerkleRoot         string    `json:"merkle_root"`          // hex
	ChainHead          string    `json:"chain_head"`           // hash of last record in segment
	PrevCheckpointHash string    `json:"prev_checkpoint_hash"` // hex sha256 of previous checkpoint canonical bytes
	Time               time.Time `json:"time"`
	PublicKey          string    `json:"public_key"` // hex ed25519 key id
	Signature          string    `json:"signature"`  // hex ed25519 over canonical (excl. Signature)
}

type checkpointCore struct {
	SchemaVersion      int       `json:"schema_version"`
	Epoch              uint64    `json:"epoch"`
	SegmentIndex       uint64    `json:"segment_index"`
	FirstGlobalSeq     uint64    `json:"first_global_seq"`
	LastGlobalSeq      uint64    `json:"last_global_seq"`
	RecordCount        int       `json:"record_count"`
	MerkleRoot         string    `json:"merkle_root"`
	ChainHead          string    `json:"chain_head"`
	PrevCheckpointHash string    `json:"prev_checkpoint_hash"`
	Time               time.Time `json:"time"`
	PublicKey          string    `json:"public_key"`
}

func (c Checkpoint) core() checkpointCore {
	return checkpointCore{
		SchemaVersion:      c.SchemaVersion,
		Epoch:              c.Epoch,
		SegmentIndex:       c.SegmentIndex,
		FirstGlobalSeq:     c.FirstGlobalSeq,
		LastGlobalSeq:      c.LastGlobalSeq,
		RecordCount:        c.RecordCount,
		MerkleRoot:         c.MerkleRoot,
		ChainHead:          c.ChainHead,
		PrevCheckpointHash: c.PrevCheckpointHash,
		Time:               c.Time,
		PublicKey:          c.PublicKey,
	}
}

// CanonicalBytes returns the deterministic signed message (all fields except
// Signature).
func (c Checkpoint) CanonicalBytes() ([]byte, error) {
	return json.Marshal(c.core())
}

// sign fills PublicKey and Signature.
func (c *Checkpoint) signWith(s *Signer) error {
	c.SchemaVersion = CheckpointSchemaVersion
	c.PublicKey = s.PublicKeyHex()
	msg, err := c.CanonicalBytes()
	if err != nil {
		return err
	}
	c.Signature = s.sign(msg)
	return nil
}

// VerifySig checks the checkpoint's own signature against its embedded public
// key. Callers that pin a trusted key must additionally compare c.PublicKey to
// the expected key id.
func (c Checkpoint) VerifySig() bool {
	msg, err := c.CanonicalBytes()
	if err != nil {
		return false
	}
	return VerifySignature(c.PublicKey, c.Signature, msg)
}

// HashHex returns the hex sha256 of the full signed checkpoint (canonical bytes
// plus signature), used to chain the next checkpoint's PrevCheckpointHash.
func (c Checkpoint) HashHex() (string, error) {
	msg, err := c.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return sha256Hex(append(msg, []byte(c.Signature)...)), nil
}
