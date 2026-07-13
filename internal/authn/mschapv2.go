package authn

import (
	"crypto/des"  //nolint:gosec // DES is mandated by the MS-CHAPv2 wire format (RFC 2759), not used for confidentiality
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by MS-CHAPv2 ChallengeHash (RFC 2759)
	"encoding/binary"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 is mandated by MS-CHAPv2 NtPasswordHash (RFC 2759)
)

// MS-CHAPv2 response construction per RFC 2759. These primitives are used only
// to satisfy the on-the-wire authentication format; none of MD4/SHA-1/DES here
// provides confidentiality. The reusable password never leaves the process in
// cleartext or via PAP: it is consumed here to derive the NT response.

// ntPasswordHash returns MD4(UTF-16LE(password)) — the 16-byte NT hash.
func ntPasswordHash(password string) []byte {
	enc := utf16.Encode([]rune(password))
	b := make([]byte, len(enc)*2)
	for i, r := range enc {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	h := md4.New()
	_, _ = h.Write(b)
	return h.Sum(nil)
}

// challengeHash returns the first 8 bytes of SHA1(peer||authenticator||user)
// per RFC 2759 §8.2. The username is the bare account name, ASCII.
func challengeHash(peerChallenge, authenticatorChallenge []byte, username string) []byte {
	h := sha1.New() //nolint:gosec // required by RFC 2759
	_, _ = h.Write(peerChallenge)
	_, _ = h.Write(authenticatorChallenge)
	_, _ = h.Write([]byte(username))
	return h.Sum(nil)[:8]
}

// desEncrypt encrypts the 8-byte block with a DES key expanded from 7 bytes.
func desEncrypt(key7, block8 []byte) ([]byte, error) {
	key := expandDESKey(key7)
	c, err := des.NewCipher(key) //nolint:gosec // required by RFC 2759
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	c.Encrypt(out, block8)
	return out, nil
}

// expandDESKey turns 7 key bytes into an 8-byte DES key by inserting a bit
// after every 7 bits (the parity bits are ignored by crypto/des).
func expandDESKey(k []byte) []byte {
	out := make([]byte, 8)
	out[0] = k[0]
	out[1] = (k[0] << 7) | (k[1] >> 1)
	out[2] = (k[1] << 6) | (k[2] >> 2)
	out[3] = (k[2] << 5) | (k[3] >> 3)
	out[4] = (k[3] << 4) | (k[4] >> 4)
	out[5] = (k[4] << 3) | (k[5] >> 5)
	out[6] = (k[5] << 2) | (k[6] >> 6)
	out[7] = k[6] << 1
	return out
}

// challengeResponse computes the 24-byte NT response from an 8-byte challenge
// and the 16-byte NT password hash (RFC 2759 §8.5).
func challengeResponse(challenge8, passwordHash16 []byte) ([]byte, error) {
	zHash := make([]byte, 21)
	copy(zHash, passwordHash16)

	out := make([]byte, 0, 24)
	for _, seg := range [][2]int{{0, 7}, {7, 14}, {14, 21}} {
		block, err := desEncrypt(zHash[seg[0]:seg[1]], challenge8)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
	}
	return out, nil
}

// generateNTResponse computes the 24-byte MS-CHAPv2 NT response (RFC 2759 §8.1).
func generateNTResponse(authenticatorChallenge, peerChallenge []byte, username, password string) ([]byte, error) {
	ch := challengeHash(peerChallenge, authenticatorChallenge, username)
	ph := ntPasswordHash(password)
	return challengeResponse(ch, ph)
}

// msChap2Response assembles the 50-byte MS-CHAP2-Response attribute value:
// Ident(1) Flags(1) PeerChallenge(16) Reserved(8) NTResponse(24).
func msChap2Response(ident byte, peerChallenge, ntResponse []byte) []byte {
	v := make([]byte, 50)
	v[0] = ident
	v[1] = 0 // flags
	copy(v[2:18], peerChallenge)
	// v[18:26] reserved, already zero
	copy(v[26:50], ntResponse)
	return v
}
