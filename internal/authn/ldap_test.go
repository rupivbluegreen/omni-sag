package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestGroupCNsFromMemberOf(t *testing.T) {
	in := []string{
		"CN=dba,OU=Groups,DC=lab,DC=local",
		"CN=Domain Users,CN=Users,DC=lab,DC=local",
		"OU=weird,DC=lab,DC=local", // no leading CN -> skipped
		"not a dn",                 // unparseable -> skipped
	}
	got := groupCNsFromMemberOf(in)
	want := []string{"dba", "Domain Users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestGroupCNsFromMemberOf_Empty(t *testing.T) {
	if got := groupCNsFromMemberOf(nil); len(got) != 0 {
		t.Fatalf("expected no groups, got %v", got)
	}
}

func TestAuthenticate_EmptyPasswordRejected(t *testing.T) {
	a := NewLDAP(LDAPConfig{URL: "ldaps://127.0.0.1:636", BaseDN: "DC=lab,DC=local"})
	_, err := a.Authenticate(context.Background(), "alice", "")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("empty password must be rejected with ErrAuth, got %v", err)
	}
}

// --- fake LDAPS server for Groups tests ---
//
// go-ldap/ldap/v3 is client-only (unlike layeh.com/radius, which backs the
// RADIUS fixtures above with a real PacketServer), so there's no off-the-shelf
// in-process directory to bind against. This speaks just enough of the wire
// protocol (RFC 4511 LDAPMessage envelopes, using the same go-asn1-ber
// encoding go-ldap itself builds requests with) to answer a service-account
// bind and a single-equality-filter search, which is all lookupUser sends.

func fakeLDAPCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ldap-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"127.0.0.1", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 keypair: %v", err)
	}
	return cert
}

// fakeLDAPDirectory maps sAMAccountName to the memberOf DNs returned for it;
// a missing key yields zero search results, as a real "user not found" would.
type fakeLDAPDirectory map[string][]string

func startFakeLDAPServer(t *testing.T, dir fakeLDAPDirectory) string {
	addr, _ := startFakeLDAPServerCountingBinds(t, dir)
	return addr
}

// startFakeLDAPServerCountingBinds is startFakeLDAPServer plus a counter of
// BindRequests received, for tests asserting Authenticate's decoy-bind fires
// exactly when expected (see the username-enumeration timing note on it).
func startFakeLDAPServerCountingBinds(t *testing.T, dir fakeLDAPDirectory) (string, *int32) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{fakeLDAPCert(t)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	binds := new(int32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeLDAPConn(conn, dir, binds)
		}
	}()
	return ln.Addr().String(), binds
}

func serveFakeLDAPConn(conn net.Conn, dir fakeLDAPDirectory, binds *int32) {
	defer conn.Close()
	for {
		req, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		if len(req.Children) < 2 {
			return
		}
		msgID := req.Children[0].Value.(int64)
		op := req.Children[1]
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			atomic.AddInt32(binds, 1)
			writeBERPacket(conn, ldapResultEnvelope(msgID, ldap.ApplicationBindResponse))
		case ldap.ApplicationSearchRequest:
			username := searchFilterValue(op)
			if groups, ok := dir[username]; ok {
				writeBERPacket(conn, searchResultEntryEnvelope(msgID, "CN="+username+",DC=lab,DC=local", groups))
			}
			writeBERPacket(conn, ldapResultEnvelope(msgID, ldap.ApplicationSearchResultDone))
		default:
			return
		}
	}
}

func writeBERPacket(conn net.Conn, p *ber.Packet) {
	_, _ = conn.Write(p.Bytes())
}

// searchFilterValue extracts the asserted value of a SearchRequest's
// top-level equality filter (op.Children[6]) — the only filter shape this
// package's UserFilter ever compiles to.
func searchFilterValue(op *ber.Packet) string {
	if len(op.Children) < 7 || len(op.Children[6].Children) < 2 {
		return ""
	}
	v, _ := op.Children[6].Children[1].Value.(string)
	return v
}

// ldapResultEnvelope builds a success (resultCode 0) LDAPResult response
// (used for both BindResponse and SearchResultDone).
func ldapResultEnvelope(msgID int64, appTag ber.Tag) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appTag, nil, "Result")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(0), "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	envelope.AppendChild(op)
	return envelope
}

func searchResultEntryEnvelope(msgID int64, dn string, memberOf []string) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "SearchResultEntry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	memberOfAttr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "memberOf")
	memberOfAttr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "memberOf", "type"))
	vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
	for _, g := range memberOf {
		vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, g, "val"))
	}
	memberOfAttr.AppendChild(vals)
	attrs.AppendChild(memberOfAttr)
	op.AppendChild(attrs)
	envelope.AppendChild(op)
	return envelope
}

func testLDAPConfig(addr string) LDAPConfig {
	return LDAPConfig{
		URL:          "ldaps://" + addr,
		BaseDN:       "DC=lab,DC=local",
		BindDN:       "CN=svc,DC=lab,DC=local",
		BindPassword: "svc-password",
		UserFilter:   "(sAMAccountName=%s)",
		InsecureTLS:  true,
	}
}

// newTestLDAPAuthenticator starts a fake LDAPS server seeded with alice (and
// no one else) and returns an authenticator pointed at it.
func newTestLDAPAuthenticator(t *testing.T) *LDAPAuthenticator {
	t.Helper()
	addr := startFakeLDAPServer(t, fakeLDAPDirectory{
		"alice": {"CN=dba,OU=Groups,DC=lab,DC=local", "CN=Domain Users,CN=Users,DC=lab,DC=local"},
	})
	return NewLDAP(testLDAPConfig(addr))
}

func TestLDAPAuthenticator_Groups_NoPasswordNeeded(t *testing.T) {
	a := newTestLDAPAuthenticator(t)
	groups, err := a.Groups(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	if len(groups) == 0 {
		t.Fatal("want at least one group for alice, got none")
	}
}

func TestLDAPAuthenticator_Groups_UnknownUserErrors(t *testing.T) {
	a := newTestLDAPAuthenticator(t)
	_, err := a.Groups(context.Background(), "no-such-user")
	if err == nil {
		t.Fatal("want an error for an unknown user, got nil")
	}
}

// TestAuthenticate_Success closes a pre-existing gap: no test exercised
// Authenticate's full bind->search->user-bind success path before this
// refactor. It guards that extracting lookupUser/dial did not change it.
func TestAuthenticate_Success(t *testing.T) {
	a := newTestLDAPAuthenticator(t)
	id, err := a.Authenticate(context.Background(), "alice", "any-password")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	want := []string{"dba", "Domain Users"}
	if id.User != "alice" || !reflect.DeepEqual(id.Groups, want) {
		t.Fatalf("got %+v, want User=alice Groups=%v", id, want)
	}
}

// TestAuthenticate_DecoyBindOnUserNotFound guards the username-enumeration
// countermeasure the refactor must not disturb: a nonexistent user must
// still incur a second (decoy) bind, matching the round-trip count of a
// wrong-password attempt against a real user.
func TestAuthenticate_DecoyBindOnUserNotFound(t *testing.T) {
	addr, binds := startFakeLDAPServerCountingBinds(t, fakeLDAPDirectory{})
	a := NewLDAP(testLDAPConfig(addr))
	_, err := a.Authenticate(context.Background(), "ghost", "whatever")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth for unknown user, got %v", err)
	}
	if got := atomic.LoadInt32(binds); got != 2 {
		t.Fatalf("want 2 binds (service + decoy), got %d", got)
	}
}
