package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// RecordSchemaVersion is the on-disk schema version for sealed records. Bump it
// only for a breaking change to the canonical encoding; the verifier keys its
// hashing on this value.
const RecordSchemaVersion = 1

// GenesisPrevHash is the prev_hash of the very first record in a chain.
const GenesisPrevHash = ""

// Record is a sealed, ordered, tamper-evident evidence record. It wraps an
// Event with the metadata that makes the stream verifiable offline:
//   - EmitterID + Epoch + Seq: per-emitter monotonic sequence (gap detection).
//   - GlobalSeq: bus-assigned total order across all emitters.
//   - PrevHash + Hash: a hash chain linking every record to its predecessor.
//
// Hash is SHA-256 over the canonical encoding of every field EXCEPT Hash.
type Record struct {
	SchemaVersion int       `json:"schema_version"`
	EmitterID     string    `json:"emitter_id"`
	Epoch         uint64    `json:"epoch"`
	Seq           uint64    `json:"seq"`
	GlobalSeq     uint64    `json:"global_seq"`
	Time          time.Time `json:"time"`
	Event         Event     `json:"event"`
	PrevHash      string    `json:"prev_hash"`
	Hash          string    `json:"hash"`
}

// recordCore is the canonical, hash-covered projection of a Record: every field
// except Hash, in a fixed field order. Go marshals struct fields in declaration
// order and Event contains no maps, so this encoding is deterministic.
type recordCore struct {
	SchemaVersion int       `json:"schema_version"`
	EmitterID     string    `json:"emitter_id"`
	Epoch         uint64    `json:"epoch"`
	Seq           uint64    `json:"seq"`
	GlobalSeq     uint64    `json:"global_seq"`
	Time          time.Time `json:"time"`
	Event         Event     `json:"event"`
	PrevHash      string    `json:"prev_hash"`
}

func (r Record) core() recordCore {
	return recordCore{
		SchemaVersion: r.SchemaVersion,
		EmitterID:     r.EmitterID,
		Epoch:         r.Epoch,
		Seq:           r.Seq,
		GlobalSeq:     r.GlobalSeq,
		Time:          r.Time,
		Event:         r.Event,
		PrevHash:      r.PrevHash,
	}
}

// CanonicalBytes returns the deterministic byte encoding hashed by ComputeHash.
func (r Record) CanonicalBytes() ([]byte, error) {
	return json.Marshal(r.core())
}

// ComputeHash returns the hex SHA-256 of the record's canonical bytes. It does
// not depend on the stored Hash field, so it can be used to re-derive and thus
// verify Hash.
func (r Record) ComputeHash() (string, error) {
	b, err := r.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// seal fills PrevHash from the chain head and computes Hash. It returns the new
// chain head (this record's Hash).
func (r *Record) seal(prevHash string) (string, error) {
	r.SchemaVersion = RecordSchemaVersion
	r.PrevHash = prevHash
	h, err := r.ComputeHash()
	if err != nil {
		return "", err
	}
	r.Hash = h
	return h, nil
}
