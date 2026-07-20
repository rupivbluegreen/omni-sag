package authn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rupivbluegreen/omni-sag/internal/fips"
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
	URL          string    // ldaps://dc1.lab.local:636
	BaseDN       string    // DC=lab,DC=local
	BindDN       string    // service account DN used for the user lookup
	BindPassword string    // service account password
	UserFilter   string    // printf with one %s for the username, e.g. (sAMAccountName=%s)
	InsecureTLS  bool      // dev only: skip server certificate verification
	NestedGroups bool      // resolve transitive/nested group membership (see resolveGroups)
	Mode         fips.Mode // FIPS TLS posture; warn/enforce harden the LDAPS TLS config
}

// sidResolveBatch bounds how many group SIDs are resolved to CNs per objectSid
// search, so a heavily-grouped user (hundreds of SIDs) never builds one giant
// OR filter. objectSid is indexed, so each batch is a fast lookup; a handful of
// batches covers even the largest realistic membership.
const sidResolveBatch = 200

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
// Direct memberOf by default; with NestedGroups it resolves the full transitive
// (AGDLP-nested, e.g. domain-local) set via AD's constructed tokenGroups
// attribute, which the DC precomputes — no expensive LDAP_MATCHING_RULE_IN_CHAIN
// walk over the whole directory (that is O(groups-in-forest) and times out for
// heavily-grouped users on a large AD). The tokenGroups set is a superset of
// memberOf within the domain; foreign-security-principal groups rooted outside
// BaseDN resolve only if reachable from BaseDN (harmless for single-domain).
func (a *LDAPAuthenticator) resolveGroups(ctx context.Context, conn *ldap.Conn, entry *ldap.Entry) ([]string, error) {
	if !a.cfg.NestedGroups {
		return groupCNsFromMemberOf(entry.GetAttributeValues("memberOf")), nil
	}
	// The tokenGroups read and objectSid resolution need directory read rights.
	// In Authenticate the connection is currently bound as the (possibly
	// low-privilege) user from the password check, so re-bind as the service
	// account first; in Groups() it is already service-bound (no-op re-bind).
	if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("%w: service re-bind for nested groups: %v", ErrAuth, err)
	}
	return a.tokenGroupCNs(ctx, conn, entry.DN)
}

// tokenGroupCNs resolves a user's full transitive group membership: it reads
// the DC-computed tokenGroups (group SIDs) off the user object, then resolves
// those SIDs to CNs with an indexed objectSid search (batched). Both steps are
// cheap on any directory size, unlike the in-chain matching rule. Only reached
// when NestedGroups is set.
func (a *LDAPAuthenticator) tokenGroupCNs(ctx context.Context, conn *ldap.Conn, userDN string) ([]string, error) {
	searchSecs := a.applyTimeout(ctx, conn)

	// 1. Read the transitive group SIDs the DC already computed for this user.
	tgReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, searchSecs, false,
		"(objectClass=*)",
		[]string{"tokenGroups"},
		nil,
	)
	tgRes, err := conn.Search(tgReq)
	if err != nil {
		return nil, fmt.Errorf("%w: tokenGroups read: %v", ErrAuth, err)
	}
	if len(tgRes.Entries) != 1 {
		return nil, fmt.Errorf("%w: tokenGroups read: user object not found", ErrAuth)
	}
	sids := tgRes.Entries[0].GetRawAttributeValues("tokenGroups")
	if len(sids) == 0 {
		return nil, nil
	}

	// 2. Resolve SIDs -> CNs via indexed objectSid, in bounded batches. SIDs
	// that name well-known/builtin or out-of-domain groups simply return no
	// entry and are skipped.
	out := make([]string, 0, len(sids))
	for start := 0; start < len(sids); start += sidResolveBatch {
		end := start + sidResolveBatch
		if end > len(sids) {
			end = len(sids)
		}
		var filter strings.Builder
		filter.WriteString("(|")
		for _, sid := range sids[start:end] {
			filter.WriteString("(objectSid=")
			filter.WriteString(escapeBinaryFilter(sid))
			filter.WriteString(")")
		}
		filter.WriteString(")")

		req := ldap.NewSearchRequest(
			a.cfg.BaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, sidResolveBatch, searchSecs, false,
			filter.String(),
			[]string{"cn"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			return nil, fmt.Errorf("%w: group SID resolution: %v", ErrAuth, err)
		}
		for _, e := range res.Entries {
			// Prefer the CN from the group's DN (RDN) so the value matches what
			// groupCNsFromMemberOf produces; fall back to the cn attribute.
			if cns := groupCNsFromMemberOf([]string{e.DN}); len(cns) > 0 {
				out = append(out, cns...)
				continue
			}
			if cn := e.GetAttributeValue("cn"); cn != "" {
				out = append(out, cn)
			}
		}
	}
	return out, nil
}

// applyTimeout bounds the connection's per-request deadline to the caller's
// remaining context time (capped at defaultLDAPTimeout) and returns the
// matching server-side time limit in whole seconds (>= 1). Shared by the
// nested-group searches.
func (a *LDAPAuthenticator) applyTimeout(ctx context.Context, conn *ldap.Conn) int {
	timeout := defaultLDAPTimeout
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	conn.SetTimeout(timeout)
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	return secs
}

// escapeBinaryFilter renders a raw byte value (e.g. a binary objectSid) as an
// LDAP filter assertion value: every byte becomes a "\XX" hex escape, which is
// always valid and unambiguous (RFC 4515).
func escapeBinaryFilter(b []byte) string {
	const hex = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(len(b) * 3)
	for _, c := range b {
		sb.WriteByte('\\')
		sb.WriteByte(hex[c>>4])
		sb.WriteByte(hex[c&0x0f])
	}
	return sb.String()
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
	tlsCfg := &tls.Config{
		InsecureSkipVerify: a.cfg.InsecureTLS, //nolint:gosec // dev-only opt-in; rejected under fips.mode=enforce by config validation
	}
	if err := fips.Harden(tlsCfg, a.cfg.Mode); err != nil {
		return nil, fmt.Errorf("%w: fips: %v", ErrAuth, err)
	}
	conn, err := ldap.DialURL(a.cfg.URL, ldap.DialWithTLSConfig(tlsCfg))
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
