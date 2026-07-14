package authn

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// defaultLDAPTimeout bounds each LDAP request (bind/search) when the caller's
// context carries no deadline. go-ldap's per-request timeout is otherwise
// infinite, so a stalled DC would park the auth goroutine forever.
const defaultLDAPTimeout = 10 * time.Second

// LDAPConfig configures an Active Directory LDAPS authenticator.
type LDAPConfig struct {
	URL          string // ldaps://dc1.lab.local:636
	BaseDN       string // DC=lab,DC=local
	BindDN       string // service account DN used for the user lookup
	BindPassword string // service account password
	UserFilter   string // printf with one %s for the username, e.g. (sAMAccountName=%s)
	InsecureTLS  bool   // dev only: skip server certificate verification
}

// LDAPAuthenticator authenticates against Active Directory over LDAPS.
//
// Flow: bind as the service account, search for the user, then re-bind as the
// user's DN with the supplied password to verify the credential. Groups are
// read from the user's memberOf attribute.
type LDAPAuthenticator struct {
	cfg LDAPConfig
}

// NewLDAP returns an LDAP authenticator for cfg.
func NewLDAP(cfg LDAPConfig) *LDAPAuthenticator {
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(sAMAccountName=%s)"
	}
	return &LDAPAuthenticator{cfg: cfg}
}

// Authenticate verifies username/password and resolves group membership.
func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	// Empty password would be an "unauthenticated bind" against AD, which
	// succeeds and would be a severe auth bypass. Reject before dialing.
	if password == "" {
		return Identity{}, fmt.Errorf("%w: empty password", ErrAuth)
	}

	conn, err := ldap.DialURL(a.cfg.URL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: a.cfg.InsecureTLS, //nolint:gosec // dev-only opt-in; rejected under fips.mode=enforce by config validation
	}))
	if err != nil {
		return Identity{}, fmt.Errorf("%w: connect: %v", ErrAuth, err)
	}
	defer conn.Close()

	// Bound every subsequent request so a stalled DC cannot block forever.
	// Honor the caller's deadline if it is tighter than the default.
	timeout := defaultLDAPTimeout
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	conn.SetTimeout(timeout)
	searchSecs := int(timeout.Seconds())
	if searchSecs < 1 {
		searchSecs = 1
	}

	// 1. Bind as the service account to perform the lookup.
	if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return Identity{}, fmt.Errorf("%w: service bind: %v", ErrAuth, err)
	}

	// 2. Find the user; read DN and group membership.
	req := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, searchSecs, false,
		fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn", "memberOf", "sAMAccountName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: search: %v", ErrAuth, err)
	}
	if len(res.Entries) != 1 {
		// Equalize round-trips: a wrong-password attempt for an existing user
		// incurs a user bind below, so a nonexistent user must incur one too,
		// or response latency becomes a username-enumeration oracle. Bind a
		// decoy DN that cannot be a real account (avoids any lockout risk).
		_ = conn.Bind("CN=omni-sag-nonexistent-decoy,"+a.cfg.BaseDN, password)
		return Identity{}, fmt.Errorf("%w: user not uniquely found", ErrAuth)
	}
	entry := res.Entries[0]

	// 3. Verify the password by binding as the user.
	if err := conn.Bind(entry.DN, password); err != nil {
		return Identity{}, fmt.Errorf("%w: user bind: %v", ErrAuth, err)
	}

	groups := groupCNsFromMemberOf(entry.GetAttributeValues("memberOf"))
	return Identity{User: username, Groups: groups}, nil
}

// groupCNsFromMemberOf extracts the CN component from each AD group DN in a
// memberOf attribute. "CN=dba,OU=Groups,DC=lab,DC=local" -> "dba". Entries
// without a leading CN are skipped.
func groupCNsFromMemberOf(memberOf []string) []string {
	var out []string
	for _, dn := range memberOf {
		parsed, err := ldap.ParseDN(dn)
		if err != nil || len(parsed.RDNs) == 0 {
			continue
		}
		rdn := parsed.RDNs[0]
		if len(rdn.Attributes) == 0 {
			continue
		}
		attr := rdn.Attributes[0]
		if strings.EqualFold(attr.Type, "CN") {
			out = append(out, attr.Value)
		}
	}
	return out
}
