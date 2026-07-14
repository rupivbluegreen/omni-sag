package evidence

import (
	"bytes"
	"testing"
)

func TestMerkleRoot_Deterministic(t *testing.T) {
	a := MerkleRoot([][]byte{[]byte("a"), []byte("b"), []byte("c")})
	b := MerkleRoot([][]byte{[]byte("a"), []byte("b"), []byte("c")})
	if a != b {
		t.Fatal("root must be deterministic")
	}
}

func TestMerkleRoot_OrderSensitive(t *testing.T) {
	a := MerkleRoot([][]byte{[]byte("a"), []byte("b")})
	b := MerkleRoot([][]byte{[]byte("b"), []byte("a")})
	if a == b {
		t.Fatal("root must depend on leaf order")
	}
}

func TestMerkleRoot_TamperChangesRoot(t *testing.T) {
	base := MerkleRoot([][]byte{[]byte("x"), []byte("y"), []byte("z")})
	tampered := MerkleRoot([][]byte{[]byte("x"), []byte("Y"), []byte("z")})
	if base == tampered {
		t.Fatal("changing a leaf must change the root")
	}
}

func TestMerkleRoot_LeafVsNodeDomainSeparation(t *testing.T) {
	// A single leaf's root is the leaf hash, which must not collide with a
	// two-leaf internal node built from arbitrary children.
	single := MerkleRoot([][]byte{[]byte("data")})
	if single != leafHash([]byte("data")) {
		t.Fatal("single-leaf root should equal its leaf hash")
	}
	lx := leafHash([]byte("x"))
	nx := nodeHash(lx, lx)
	if bytes.Equal(lx[:], nx[:]) {
		t.Fatal("leaf and node hashes must be domain-separated")
	}
}

func TestMerkleRoot_EmptyStable(t *testing.T) {
	if MerkleRoot(nil) != MerkleRoot([][]byte{}) {
		t.Fatal("empty root must be stable")
	}
}
