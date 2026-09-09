// Package policy (targetuser.go): resolving which account the gateway
// authenticates as on the target host.
package policy

import (
	"errors"
	"fmt"
)

// ErrTargetUserDenied is returned when the client named a target account it
// may not use. internal/policy cannot import internal/credential (CI-enforced
// import rule), so callers in internal/session wrap this into
// credential.ErrDenied and the fail-closed credential contract is unchanged.
var ErrTargetUserDenied = errors.New("policy: target user denied")

// ResolveTargetUser returns the account the gateway must authenticate as on
// the target: requested is what the client asked for in the
// "%[targetuser@]host" auth-username grammar ("" when it asked for nothing),
// d is the matched decision, loginUser is the gateway login user.
//
// Precedence:
//
//  1. rule pins TargetUser and requested differs      -> ErrTargetUserDenied
//  2. rule pins TargetUser, requested empty or equal  -> the rule's account
//  3. rule pins nothing, requested non-empty          -> requested, but only
//     under credential mode prompt/passthrough and only when
//     d.AllowTargetUsers lists it; otherwise ErrTargetUserDenied
//  4. neither                                         -> loginUser
//
// Case 3's inject exclusion holds even when the allow-list names the account:
// under inject the gateway fetches a secret keyed by the account, so honouring
// a client-named one would make the gateway a credential oracle for every
// vaulted account on an allowed host.
//
// Matching is exact, never case-folded: the account is a local account on the
// target, where case is significant, and a near-miss must fail closed rather
// than authenticate as an account the client did not name.
//
// On denial the returned string is always empty — there is no partial result a
// caller could mistake for a usable account.
func ResolveTargetUser(requested string, d Decision, loginUser string) (string, error) {
	if requested == "" {
		if d.TargetUser != "" {
			return d.TargetUser, nil
		}
		return loginUser, nil
	}
	if d.TargetUser != "" {
		if requested == d.TargetUser {
			return d.TargetUser, nil
		}
		return "", fmt.Errorf("%w: rule pins target user %q, client requested %q", ErrTargetUserDenied, d.TargetUser, requested)
	}
	switch d.CredentialMode {
	case "prompt", "passthrough", "": // empty == passthrough, per Rule.Credential
	default:
		return "", fmt.Errorf("%w: credential mode %q never accepts a client-supplied target user", ErrTargetUserDenied, d.CredentialMode)
	}
	if !allowsTargetUser(d.AllowTargetUsers, requested) {
		return "", fmt.Errorf("%w: rule does not list target user %q in allow_target_users", ErrTargetUserDenied, requested)
	}
	return requested, nil
}

func allowsTargetUser(allow []string, requested string) bool {
	for _, a := range allow {
		if a == "*" || a == requested {
			return true
		}
	}
	return false
}
