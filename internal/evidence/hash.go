package evidence

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hexBytes returns the lowercase hex encoding of b (no hashing).
func hexBytes(b []byte) string { return hex.EncodeToString(b) }
