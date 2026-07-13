// Package authn provides authentication with MFA behind a single provider
// interface. Slice 1 implements only LDAPS (AD) password authentication;
// RADIUS/MFA arrive in Slice 2 behind the same Authenticator interface.
package authn

import (
	"context"
	"errors"
)

// ErrAuth is returned for any authentication failure. It is deliberately
// opaque: callers must not distinguish "no such user" from "bad password".
var ErrAuth = errors.New("authentication failed")

// Identity is the result of a successful authentication.
type Identity struct {
	User   string
	Groups []string
}

// Authenticator verifies a credential and returns the resolved identity.
// Implementations must fail closed: any error returns ErrAuth (optionally
// wrapped) and never a partial Identity.
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (Identity, error)
}
