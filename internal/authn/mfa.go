package authn

import (
	"context"
	"errors"
)

// ErrMFA is returned for any second-factor failure: denial, timeout, transport
// error, or an unsupported challenge. Like ErrAuth it is deliberately opaque
// and always fails closed — a caller must never treat an error as success.
var ErrMFA = errors.New("multi-factor authentication failed")

// Prompter asks the user an interactive question and returns their reply. It
// backs RADIUS Access-Challenge round-trips (e.g. OTP entry). Push-style
// providers never call it; a nil Prompter means the connection cannot answer
// an interactive challenge, so any challenge fails closed.
type Prompter func(ctx context.Context, prompt string, echoInput bool) (string, error)

// MFARequest carries what a second factor needs. Password is the primary
// credential (reused to build the MS-CHAPv2 response) and is held as []byte per
// the mlock-free posture (ADR-0001): it is never converted to a string for
// storage or logging and is not retained after Verify returns.
type MFARequest struct {
	Username string
	Password []byte
	SourceIP string
	Prompt   Prompter
}

// MFAProvider gates an already-primary-authenticated identity behind a second
// factor. Verify returns nil only on an affirmative second-factor success;
// every other outcome returns an error wrapping ErrMFA.
type MFAProvider interface {
	Verify(ctx context.Context, req MFARequest) error
}
