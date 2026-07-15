// Package policy resolves roles and evaluates access decisions.
//
// It must stay pure (inputs -> decision) and must not import
// internal/session, so the evaluator remains property-testable.
package policy

import (
	"fmt"
	"strings"
)

// Target is the destination a session wants to reach.
type Target struct {
	Host string
	Port int
}

func (t Target) String() string { return fmt.Sprintf("%s:%d", t.Host, t.Port) }

// Principal is the authenticated identity requesting access.
type Principal struct {
	User   string
	Groups []string

	// TargetHost and TargetSecretToken are pure carrier fields threaded from
	// the SSH auth layer (session.principalFrom, packed into
	// ssh.Permissions.Extensions during password/keyboard-interactive auth)
	// through to the session layer, which uses them to select and dial the
	// real target on the gateway's second SSH leg. No Decide logic depends on
	// them — they ride along on Principal the same way Groups does.
	TargetHost        string
	TargetSecretToken string
}

// RecordMode is the recording posture required for a target (PRD FR-10).
//
//   - RecordFull: interactive sessions must be recorded; port-forwarding (-L)
//     is refused because forwarded bytes cannot be meaningfully recorded.
//   - RecordMetadataOnly: forwarding is allowed but the session is not
//     recorded; evidence must mark it unrecorded.
//   - RecordNone: no recording constraint.
type RecordMode string

const (
	RecordNone         RecordMode = "none"
	RecordMetadataOnly RecordMode = "metadata-only"
	RecordFull         RecordMode = "full"
)

// Normalize maps an empty or unknown mode to RecordNone so a missing policy
// field is fail-safe (no false claim of recording).
func (m RecordMode) Normalize() RecordMode {
	switch m {
	case RecordFull, RecordMetadataOnly, RecordNone:
		return m
	default:
		return RecordNone
	}
}

// Rule allows a set of ports on a host. Host "*" matches any host.
// An empty Ports slice matches any port. Record sets the recording posture for
// targets this rule grants.
type Rule struct {
	Host   string
	Ports  []int
	Record RecordMode
	// Credential is the credential posture for matching targets:
	// "inject" | "prompt" | "passthrough" | "deny" (empty ⇒ passthrough). Kept
	// as a plain string so policy stays free of the internal/credential import.
	Credential string
	// RequireApproval gates matching targets behind a four-eyes approval: the
	// session blocks until a second human approves it (PRD approvals).
	RequireApproval bool
	// TargetUser is the account the gateway authenticates as on the target for
	// this rule's matches. Empty => the same name as the gateway login user.
	TargetUser string
}

// Role binds AD group membership to a set of allow rules.
type Role struct {
	Name   string
	Groups []string
	Allow  []Rule
}

// Policy is a compiled, immutable set of roles. It is the sole input to
// authorization decisions.
type Policy struct {
	Roles []Role
}

// Decision is the outcome of evaluating a Principal against a Target.
type Decision struct {
	Allow           bool
	Reason          string
	MatchedRole     string     // role that granted access, empty on deny
	RecordMode      RecordMode // recording posture of the matched target (RecordNone on deny)
	CredentialMode  string     // credential posture of the matched target (empty on deny)
	RequireApproval bool       // matched target requires a four-eyes approval
	TargetUser      string     // account to use on the target; empty => same as login user
	// Port is the real second-SSH-leg port to dial for the gateway's
	// shell/SFTP proxy to a real target (see DecideHost's doc comment for why
	// this can only be resolved AFTER matching, unlike the -L forwarding
	// path's Target.Port, which the client always supplies up front). Zero on
	// deny or when Decide (not DecideHost) produced this Decision.
	Port int
}

// ForwardingAllowed reports whether port-forwarding (-L) is permitted for this
// decision. Forwarding is refused on full-recording targets (PRD FR-10).
func (d Decision) ForwardingAllowed() bool {
	return d.RecordMode != RecordFull
}

// Roles returns the names of the roles a principal holds, by group membership.
func (p Policy) rolesFor(pr Principal) []Role {
	have := make(map[string]bool, len(pr.Groups))
	for _, g := range pr.Groups {
		have[strings.ToLower(g)] = true
	}
	var out []Role
	for _, r := range p.Roles {
		for _, g := range r.Groups {
			if have[strings.ToLower(g)] {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func (r Rule) matches(t Target) bool {
	if r.Host != "*" && !strings.EqualFold(r.Host, t.Host) {
		return false
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p == t.Port {
			return true
		}
	}
	return false
}

// Decide is the pure authorization function: given a Principal and a Target,
// it returns Allow only if some role the principal holds permits the target.
// Default is deny.
func (p Policy) Decide(pr Principal, t Target) Decision {
	roles := p.rolesFor(pr)
	if len(roles) == 0 {
		return Decision{Allow: false, RecordMode: RecordNone, Reason: "no role: principal holds no role granting any access"}
	}
	for _, r := range roles {
		for _, rule := range r.Allow {
			if rule.matches(t) {
				return Decision{
					Allow:           true,
					Reason:          "allowed by role " + r.Name,
					MatchedRole:     r.Name,
					RecordMode:      rule.Record.Normalize(),
					CredentialMode:  rule.Credential,
					RequireApproval: rule.RequireApproval,
					TargetUser:      rule.TargetUser,
				}
			}
		}
	}
	return Decision{Allow: false, RecordMode: RecordNone, Reason: fmt.Sprintf("no rule in roles %s permits %s", roleNames(roles), t)}
}

// matchesHost reports whether r's host pattern matches host, ignoring ports
// entirely. Used by DecideHost, never by Decide/matches (the -L forwarding
// path must still enforce ports exactly).
func (r Rule) matchesHost(host string) bool {
	return r.Host == "*" || strings.EqualFold(r.Host, host)
}

// DecideHost is Decide's host-only counterpart for the gateway's real-target
// second SSH leg (interactive shell / SFTP over a "session" channel). Unlike
// -L forwarding — where the client's direct-tcpip request always carries a
// real destination port, so Decide/Target.Port/Rule.matches can enforce it
// exactly — the real-target flow's client auth username encodes only
// "user%host" (splitTargetUser), never a port. There is therefore no port to
// match against until AFTER a rule is chosen, which is exactly what this
// method resolves: it matches by host alone, then reports the matched rule's
// intended real-target port via Decision.Port.
//
// Because there is no port to disambiguate on, DecideHost requires the host
// to resolve UNAMBIGUOUSLY: exactly one rule (across every role the
// principal holds) matches the host, and that rule names exactly one port.
// Any other outcome fails closed (Allow: false, with a Reason explaining
// why) rather than guessing:
//   - zero matching rules: deny, same as Decide.
//   - two or more rules match the same host (e.g. a passthrough/no-approval
//     rule for -L forwarding at one port and an inject/approval-gated rule
//     for real shell access at another port on the same host — a normal way
//     to use this schema): this method cannot tell which posture the
//     operator intends for the shell/SFTP flow, so it refuses rather than
//     silently picking whichever rule iterates first and applying its
//     credential mode / approval requirement to the session.
//   - the single matching rule has zero or 2+ configured ports: same
//     problem — there is no single port to resolve, and guessing (e.g.
//     always trying 22) risks dialing a service the operator never intended
//     this flow to reach under that rule's authorization posture.
//
// A rule meant for this flow should therefore name exactly one host and
// exactly one port.
func (p Policy) DecideHost(pr Principal, host string) Decision {
	roles := p.rolesFor(pr)
	if len(roles) == 0 {
		return Decision{Allow: false, RecordMode: RecordNone, Reason: "no role: principal holds no role granting any access"}
	}
	type hostMatch struct {
		role Role
		rule Rule
	}
	var matches []hostMatch
	for _, r := range roles {
		for _, rule := range r.Allow {
			if rule.matchesHost(host) {
				matches = append(matches, hostMatch{role: r, rule: rule})
			}
		}
	}
	switch {
	case len(matches) == 0:
		return Decision{Allow: false, RecordMode: RecordNone, Reason: fmt.Sprintf("no rule in roles %s permits host %s", roleNames(roles), host)}
	case len(matches) > 1:
		return Decision{Allow: false, RecordMode: RecordNone, Reason: fmt.Sprintf("ambiguous: %d rules match host %s for the real-target shell/SFTP flow — each host must resolve to exactly one rule with exactly one port", len(matches), host)}
	}
	m := matches[0]
	if len(m.rule.Ports) != 1 {
		return Decision{Allow: false, RecordMode: RecordNone, Reason: fmt.Sprintf("ambiguous: the rule matching host %s has %d configured ports — the real-target shell/SFTP flow requires exactly one", host, len(m.rule.Ports))}
	}
	return Decision{
		Allow:           true,
		Reason:          "allowed by role " + m.role.Name,
		MatchedRole:     m.role.Name,
		RecordMode:      m.rule.Record.Normalize(),
		CredentialMode:  m.rule.Credential,
		RequireApproval: m.rule.RequireApproval,
		TargetUser:      m.rule.TargetUser,
		Port:            m.rule.Ports[0],
	}
}

func roleNames(roles []Role) string {
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return strings.Join(names, ",")
}
