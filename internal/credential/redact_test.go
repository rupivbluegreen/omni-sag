package credential

import (
	"strings"
	"testing"
)

func TestRedact_ScrubsSecretFromStream(t *testing.T) {
	secret := New([]byte("P@ssw0rd"))
	transcript := []byte("login as admin, password P@ssw0rd then enter")
	out := Redact(transcript, secret)
	if strings.Contains(string(out), "P@ssw0rd") {
		t.Fatalf("secret not redacted: %q", out)
	}
	if !strings.Contains(string(out), strings.Repeat("*", 8)) {
		t.Fatalf("expected mask of equal length: %q", out)
	}
	// Original slice is untouched.
	if !strings.Contains(string(transcript), "P@ssw0rd") {
		t.Fatal("Redact must not mutate its input")
	}
}

func TestRedact_DestroyedSecretIsNoOp(t *testing.T) {
	secret := New([]byte("abc"))
	secret.Destroy()
	out := Redact([]byte("xabcx"), secret)
	if string(out) != "xabcx" {
		t.Fatalf("destroyed secret should not redact: %q", out)
	}
}
