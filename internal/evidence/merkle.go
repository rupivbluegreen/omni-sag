package evidence

import "crypto/sha256"

// Merkle tree with domain-separated leaf and internal nodes (RFC 6962 style) so
// a leaf hash can never be reinterpreted as an internal node (second-preimage
// resistance). Leaf   = SHA-256(0x00 || data). Node = SHA-256(0x01 || l || r).
// An odd node at a level is promoted (not duplicated) to avoid the CVE-2012-2459
// duplicate-leaf ambiguity.

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

func leafHash(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot computes the root over the given leaf payloads. The empty set has
// a fixed root of SHA-256(0x00) (the hash of an empty leaf) so a zero-record
// segment still has a well-defined, verifiable root.
func MerkleRoot(leaves [][]byte) [32]byte {
	if len(leaves) == 0 {
		return leafHash(nil)
	}
	level := make([][32]byte, len(leaves))
	for i, l := range leaves {
		level[i] = leafHash(l)
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // promote odd tail
			} else {
				next = append(next, nodeHash(level[i], level[i+1]))
			}
		}
		level = next
	}
	return level[0]
}
