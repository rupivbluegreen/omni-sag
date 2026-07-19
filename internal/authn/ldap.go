package authn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// errUserNotFound distinguishes "the search found zero or multiple entries"
// from lookupUser's other failure modes (service bind, search RPC), so
// Authenticate knows precisely when its decoy bind applies.
var errUserNotFound = errors.New("user not uniquely found")

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
	NestedGroups bool   // resolve transitive/nested group membership (see resolveGroups)
}

// ldapMatchingRuleInChain is Active Directory's LDAP_MATCHING_RULE_IN_CHAIN
// OID. Applied to the "member" attribute it walks nested group membership
// transitively, so the gateway resolves the full chain of memberOf groups
// rather than only a user's direct memberOf values. The result is a superset
// of a direct memberOf read; note it still excludes the primaryGroupID-based
// primary group (e.g. Domain Users), which SSSD's `id -nG` does include. Used
// when NestedGroups is set; see resolveGroups.
const ldapMatchingRuleInChain = "1.2.840.113556.1.4.1941"

// maxNestedGroups is the server-side size-limit hint sent with the in-chain
// group search (go-ldap leaves client-side EnforceSizeLimit off, so this is
// not a hard client cap). It is set well above realistic heavy-user membership
// — which runs to the hundreds — so it never denies a real user. Note real AD
// also enforces its own MaxPageSize (default ~1000) on a non-paged search, so
// the effective ceiling is min(this, ~1000); a directory returning more makes
// Search error, failing the login closed rather than under-resolving groups.
const maxNestedGroups = 4096

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

	conn, err := a.dial()
	if err != nil {
		return Identity{}, err
	}
	defer conn.Close()

	// 1-2. Bind as the service account and find the user; read DN and group membership.
	entry, err := a.lookupUser(ctx, conn, username)
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			// Equalize round-trips: a wrong-password attempt for an existing
			// user incurs a user bind below, so a nonexistent user must incur
			// one too, or response latency becomes a username-enumeration
			// oracle. Bind a decoy DN that cannot be a real account (avoids
			// any lockout risk).
			_ = conn.Bind("CN=omni-sag-nonexistent-decoy,"+a.cfg.BaseDN, password)
		}
		return Identity{}, err
	}

	// 3. Verify the password by binding as the user.
	if err := conn.Bind(entry.DN, password); err != nil {
		return Identity{}, fmt.Errorf("%w: user bind: %v", ErrAuth, err)
	}

	groups, err := a.resolveGroups(ctx, conn, entry)
	if err != nil {
		return Identity{}, err
	}
	return Identity{User: username, Groups: groups}, nil
}

// resolveGroups returns the CNs of the groups the user (entry) belongs to.
// Direct memberOf by default; with NestedGroups it instead runs an
// LDAP_MATCHING_RULE_IN_CHAIN search on the user's DN so transitive/AGDLP
// (e.g. domain-local) memberships resolve too. The chain result is a superset
// of memberOf WITHIN BaseDN's domain, so it fully replaces the direct read
// when enabled. Caveat for multi-domain forests: a foreign-security-principal
// group rooted outside BaseDN can appear in a direct memberOf read but is not
// returned by this BaseDN-scoped search; harmless for a single-domain directory.
func (a *LDAPAuthenticator) resolveGroups(ctx context.Context, conn *ldap.Conn, entry *ldap.Entry) ([]string, error) {
	if !a.cfg.NestedGroups {
		return groupCNsFromMemberOf(entry.GetAttributeValues("memberOf")), nil
	}
	// The in-chain search needs directory read rights. In Authenticate the
	// connection is currently bound as the (possibly low-privilege) user from
	// the password check, so re-bind as the service account first; in Groups()
	// it is already service-bound and this is a harmless no-op re-bind.
	if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("%w: service re-bind for nested groups: %v", ErrAuth, err)
	}
	return a.nestedGroupCNs(ctx, conn, entry.DN)
}

// nestedGroupCNs returns the CN of every group that has userDN as a member,
// following nested membership via LDAP_MATCHING_RULE_IN_CHAIN. One extra
// subtree search per login; only reached when NestedGroups is set.
func (a *LDAPAuthenticator) nestedGroupCNs(ctx context.Context, conn *ldap.Conn, userDN string) ([]string, error) {
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

	// Match groups whose (nested) member is this user. The DN is a filter
	// assertion value, so it must be filter-escaped.
	filter := fmt.Sprintf("(member:%s:=%s)", ldapMatchingRuleInChain, ldap.EscapeFilter(userDN))
	req := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, maxNestedGroups, searchSecs, false,
		filter,
		[]string{"cn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("%w: nested group search: %v", ErrAuth, err)
	}
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		// Take the CN from the group's DN (RDN) so the value matches exactly
		// what groupCNsFromMemberOf produces; fall back to the cn attribute.
		if cns := groupCNsFromMemberOf([]string{e.DN}); len(cns) > 0 {
			out = append(out, cns...)
			continue
		}
		if cn := e.GetAttributeValue("cn"); cn != "" {
			out = append(out, cn)
		}
	}
	return out, nil
}

// lookupUser binds as the service account and searches for username,
// returning the found entry (DN + memberOf). Used by both Authenticate
// (which additionally verifies a password) and Groups (which does not).
func (a *LDAPAuthenticator) lookupUser(ctx context.Context, conn *ldap.Conn, username string) (*ldap.Entry, error) {
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

	if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("%w: service bind: %v", ErrAuth, err)
	}

	req := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, searchSecs, false,
		fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn", "memberOf", "sAMAccountName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("%w: search: %v", ErrAuth, err)
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("%w: %w", ErrAuth, errUserNotFound)
	}
	return res.Entries[0], nil
}

func (a *LDAPAuthenticator) dial() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(a.cfg.URL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: a.cfg.InsecureTLS, //nolint:gosec // dev-only opt-in; rejected under fips.mode=enforce by config validation
	}))
	if err != nil {
		return nil, fmt.Errorf("%w: connect: %v", ErrAuth, err)
	}
	return conn, nil
}

// Groups resolves username's current AD group membership via the service
// account only — no password required. Used for group-scoped four-eyes at
// quarantine-release approval time (the approver's password is never
// available to the control plane at that point). Callers must not use this
// as an authentication check: it proves nothing about who is asking, only
// what the named account's groups currently are.
func (a *LDAPAuthenticator) Groups(ctx context.Context, username string) ([]string, error) {
	conn, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	entry, err := a.lookupUser(ctx, conn, username)
	if err != nil {
		return nil, err
	}
	return a.resolveGroups(ctx, conn, entry)
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
