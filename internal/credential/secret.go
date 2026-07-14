package credential

import (
	"fmt"
	"io"
	"runtime"
	"strconv"
)

// Secret holds sensitive material in a mutable byte buffer — never a Go string
// (ADR-0001). Go strings are immutable and may be copied by the runtime, so
// their backing bytes cannot be reliably wiped. The buffer is zeroized by
// Destroy and must be used in place, never converted to a string. There is
// deliberately NO String() method (a String() would invite exactly the
// unwipeable-string handling this type exists to prevent); Format and GoString
// redact so a stray %v never leaks the secret.
type Secret struct {
	b    []byte
	dead bool
}

// New takes ownership of b without copying. The caller must not retain or reuse
// b afterward; Destroy will zero it in place.
func New(b []byte) *Secret { return &Secret{b: b} }

// Bytes returns the live secret buffer, or nil after Destroy. Callers must use
// it in place and must NOT convert it to a string.
func (s *Secret) Bytes() []byte {
	if s == nil || s.dead {
		return nil
	}
	return s.b
}

// Len returns the secret length (safe to log).
func (s *Secret) Len() int {
	if s == nil {
		return 0
	}
	return len(s.b)
}

// Destroy zeroizes the buffer. Idempotent. runtime.KeepAlive prevents the
// compiler from eliding the wipe as dead stores.
func (s *Secret) Destroy() {
	if s == nil {
		return
	}
	for i := range s.b {
		s.b[i] = 0
	}
	s.dead = true
	runtime.KeepAlive(s.b)
}

// Format renders the secret redacted for every verb so a stray %v/%s/%q never
// leaks it. This is intentionally NOT a String() method (ADR-0001 / CI lint).
func (s *Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.redacted())
}

// GoString redacts under %#v.
func (s *Secret) GoString() string { return "credential.Secret(REDACTED)" }

func (s *Secret) redacted() string {
	n := 0
	if s != nil {
		n = len(s.b)
	}
	return "credential.Secret(len=" + strconv.Itoa(n) + ", REDACTED)"
}
