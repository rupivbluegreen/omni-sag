package api

import (
	"errors"
	"net/http"
	"strings"
)

// Role is an API RBAC role. Higher rank grants strictly more.
type Role string

const (
	RoleViewer   Role = "viewer"   // read: list/inspect sessions, read policy
	RoleOperator Role = "operator" // + terminate sessions
	RoleAdmin    Role = "admin"    // everything
)

func (r Role) rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// atLeast reports whether r satisfies the minimum required role.
func (r Role) atLeast(min Role) bool { return r.rank() >= min.rank() && r.rank() > 0 }

// Identity is the authenticated API caller.
type Identity struct {
	Subject string
	Role    Role
}

// ErrUnauthenticated / ErrForbidden drive 401 / 403 responses.
var (
	ErrUnauthenticated = errors.New("api: unauthenticated")
	ErrForbidden       = errors.New("api: forbidden")
)

// Authorizer authenticates a request and returns the caller's identity. It must
// fail closed: any missing/invalid credential returns ErrUnauthenticated and no
// identity.
type Authorizer interface {
	Authorize(r *http.Request) (Identity, error)
}

// TokenAuthorizer maps static bearer tokens to identities. Suitable for dev and
// tests; in production the same interface is satisfied by an OIDC authorizer
// that validates a JWT (via JWKS) and maps a claim to a Role.
type TokenAuthorizer struct {
	tokens map[string]Identity
}

// NewTokenAuthorizer builds a token authorizer from token->identity pairs.
func NewTokenAuthorizer(tokens map[string]Identity) *TokenAuthorizer {
	m := make(map[string]Identity, len(tokens))
	for k, v := range tokens {
		m[k] = v
	}
	return &TokenAuthorizer{tokens: m}
}

// Authorize reads a "Authorization: Bearer <token>" header.
func (a *TokenAuthorizer) Authorize(r *http.Request) (Identity, error) {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return Identity{}, ErrUnauthenticated
	}
	id, ok := a.tokens[tok]
	if !ok || id.Role.rank() == 0 {
		return Identity{}, ErrUnauthenticated
	}
	return id, nil
}

// MTLSAuthorizer maps a verified client-certificate CommonName to a role. The
// TLS layer must be configured to require and verify client certs; this only
// runs after a cert has been verified.
type MTLSAuthorizer struct {
	cnRoles map[string]Role
}

// NewMTLSAuthorizer builds an mTLS authorizer from CommonName->Role bindings.
func NewMTLSAuthorizer(cnRoles map[string]Role) *MTLSAuthorizer {
	m := make(map[string]Role, len(cnRoles))
	for k, v := range cnRoles {
		m[k] = v
	}
	return &MTLSAuthorizer{cnRoles: m}
}

// Authorize reads the verified peer certificate's CommonName.
func (a *MTLSAuthorizer) Authorize(r *http.Request) (Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return Identity{}, ErrUnauthenticated
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	role, ok := a.cnRoles[cn]
	if !ok || role.rank() == 0 {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{Subject: cn, Role: role}, nil
}
