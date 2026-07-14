// Package session (target.go): real-target selection and the gateway's
// second SSH leg to that target (interactive shell / SFTP), as opposed to
// internal/dialer's single leg used for -L port-forwarding.
package session

import (
	"strings"
)

// splitTargetUser splits an SSH auth username of the form "user%host" into
// the login username and the target host. "%" was chosen because it cannot
// appear in an AD sAMAccountName and does not collide with "@" (already used
// by the SSH client to address the gateway itself: "ssh alice%host@gw").
// Only the FIRST "%" splits, so a host containing "%" is not truncated.
func splitTargetUser(raw string) (loginUser, targetHost string, hasTarget bool) {
	i := strings.IndexByte(raw, '%')
	if i < 0 {
		return raw, "", false
	}
	return raw[:i], raw[i+1:], true
}
