// Package tui implements the omnictl Bubble Tea terminal UI over the
// control-plane SDK (internal/api.Client). It never bypasses the API for
// control-plane data; it may evaluate the policy locally (internal/policy) for
// the rule-trace and parse recordings locally (internal/recording) for replay.
package tui

import (
	"fmt"
	"strings"

	"github.com/rupivbluegreen/omni-sag/internal/api"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// PolicyFromView reconstructs a policy.Policy from the API's PolicyView so the
// rule-trace evaluates with exactly the same policy.Decide the gateway uses.
func PolicyFromView(pv api.PolicyView) policy.Policy {
	p := policy.Policy{Roles: make([]policy.Role, 0, len(pv.Roles))}
	for _, rv := range pv.Roles {
		role := policy.Role{Name: rv.Name, Groups: rv.Groups}
		for _, ru := range rv.Allow {
			role.Allow = append(role.Allow, policy.Rule{
				Host:            ru.Host,
				Ports:           ru.Ports,
				Record:          policy.RecordMode(ru.Record),
				Credential:      ru.Credential,
				RequireApproval: ru.RequireApproval,
			})
		}
		p.Roles = append(p.Roles, role)
	}
	return p
}

// Explanation is a human-readable rule trace whose Decision is exactly what
// policy.Decide returns for the reconstructed policy.
type Explanation struct {
	Decision policy.Decision
	// Reachable is the EFFECTIVE outcome: policy may Allow while the gateway
	// still refuses the connection (e.g. credential mode "deny" is refused by
	// the dialer before any socket). Reachable reflects what actually happens.
	Reachable bool
	Lines     []string
}

// Explain answers "why can <user in groups> reach host:port?" against pv.
func Explain(pv api.PolicyView, user string, groups []string, host string, port int) Explanation {
	p := PolicyFromView(pv)
	pr := policy.Principal{User: user, Groups: groups}
	d := p.Decide(pr, policy.Target{Host: host, Port: port})

	// A policy Allow with credential mode "deny" is unconditionally refused by
	// the dialer (credential.Resolve -> ErrDenied) before any socket opens, so
	// the target is NOT reachable despite the policy match.
	credDeny := d.Allow && d.CredentialMode == "deny"
	reachable := d.Allow && !credDeny

	lines := []string{fmt.Sprintf("%s (groups: %s)  →  %s:%d", user, strings.Join(groups, ","), host, port)}
	if d.Allow {
		if credDeny {
			lines = append(lines, "ALLOW by policy — but connection REFUSED (credential mode: deny)")
		} else {
			lines = append(lines, "ALLOW — matched role "+d.MatchedRole)
		}
		lines = append(lines, "  record:     "+orNone(string(d.RecordMode)))
		lines = append(lines, "  credential: "+orNone(d.CredentialMode))
		if d.RequireApproval {
			lines = append(lines, "  four-eyes:  approval required before connect")
		}
		if !d.ForwardingAllowed() {
			lines = append(lines, "  forwarding: -L REFUSED (target requires full recording)")
		}
	} else {
		lines = append(lines, "DENY — "+d.Reason)
		if held := rolesHeld(p, pr); len(held) > 0 {
			lines = append(lines, "  roles held: "+strings.Join(held, ", "))
		} else {
			lines = append(lines, "  roles held: none (no group grants a role)")
		}
	}
	return Explanation{Decision: d, Reachable: reachable, Lines: lines}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// rolesHeld lists the roles a principal holds by group membership (for the
// deny explanation). Mirrors policy's own case-insensitive group match.
func rolesHeld(p policy.Policy, pr policy.Principal) []string {
	have := make(map[string]bool, len(pr.Groups))
	for _, g := range pr.Groups {
		have[strings.ToLower(g)] = true
	}
	var out []string
	for _, r := range p.Roles {
		for _, g := range r.Groups {
			if have[strings.ToLower(g)] {
				out = append(out, r.Name)
				break
			}
		}
	}
	return out
}
