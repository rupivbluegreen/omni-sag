package authn

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Test vectors from RFC 2759 §9.2 (MS-CHAPv2 worked example).
//
//	UserName               = "User"
//	Password               = "clientPass"
//	AuthenticatorChallenge = 5B5D7C7D7B3F2F3E3C2C60213226 2628 ...
//	PeerChallenge          = 21402324255E262A28295F2B3A337C7E
func TestMSCHAPv2_RFC2759Vectors(t *testing.T) {
	authChallenge := mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peerChallenge := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	username := "User"
	password := "clientPass"

	wantPwHash := mustHex(t, "44EBBA8D5312B8D611474411F56989AE")
	wantChalHash := mustHex(t, "D02E4386BCE91226")
	wantNTResp := mustHex(t, "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")

	if got := ntPasswordHash(password); !bytes.Equal(got, wantPwHash) {
		t.Errorf("ntPasswordHash = %X, want %X", got, wantPwHash)
	}
	if got := challengeHash(peerChallenge, authChallenge, username); !bytes.Equal(got, wantChalHash) {
		t.Errorf("challengeHash = %X, want %X", got, wantChalHash)
	}
	got, err := generateNTResponse(authChallenge, peerChallenge, username, password)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantNTResp) {
		t.Errorf("generateNTResponse = %X, want %X", got, wantNTResp)
	}
}

func TestMSChap2Response_Layout(t *testing.T) {
	peer := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	nt := bytes.Repeat([]byte{0xAB}, 24)
	v := msChap2Response(0x07, peer, nt)

	if len(v) != 50 {
		t.Fatalf("MS-CHAP2-Response length = %d, want 50", len(v))
	}
	if v[0] != 0x07 {
		t.Errorf("ident = %#x, want 0x07", v[0])
	}
	if v[1] != 0 {
		t.Errorf("flags = %#x, want 0", v[1])
	}
	if !bytes.Equal(v[2:18], peer) {
		t.Error("peer challenge misplaced")
	}
	if !bytes.Equal(v[18:26], make([]byte, 8)) {
		t.Error("reserved must be zero")
	}
	if !bytes.Equal(v[26:50], nt) {
		t.Error("NT response misplaced")
	}
}
