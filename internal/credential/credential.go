// Package credential provides the credential provider interface
// (cyberark | prompt | passthrough).
//
// Only internal/session and internal/dialer may import this package; that
// allowlist is CI-enforced to minimize the blast radius of secret handling.
package credential
