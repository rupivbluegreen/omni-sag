package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "omni-sag-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"omni-sag.example.net"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
}

// One Server serving a plain listener and a TLS listener at the same time:
// plain SSH keeps working for in-cluster/port-forward callers while the TLS
// port is what an SNI-routing ingress publishes. Both must reach the same
// server, and both must be accounted for by Drain.
func TestDualListener_PlainAndTLSServeSameServer(t *testing.T) {
	echoHost, echoPort := startEcho(t)
	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: echoHost, Ports: []int{echoPort}}},
	}}}

	hostKey, err := NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	sink := evidence.NewMemSink()
	d := dialer.New(p, sink, dialer.WithLoopbackTargetsAllowed())
	srv := New(hostKey, fakeAuth{users: map[string][]string{"alice": {"dba"}}}, d, sink)

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rawTLSLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(rawTLSLn, testTLSConfig(t))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, plainLn)
	go srv.Serve(ctx, tlsLn)

	// 1. plain SSH still works
	plainClient := sshClient(t, plainLn.Addr().String(), "alice")
	c1, err := plainClient.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err != nil {
		t.Fatalf("forward over plain listener: %v", err)
	}
	defer c1.Close()

	// 2. SSH inside TLS works against the same server
	tlsConn, err := tls.Dial("tcp", tlsLn.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "omni-sag.example.net",
	})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer tlsConn.Close()
	sshConn, chans, reqs, err := ssh.NewClientConn(tlsConn, "omni-sag.example.net", &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("SSH handshake inside TLS: %v", err)
	}
	tlsClient := ssh.NewClient(sshConn, chans, reqs)
	defer tlsClient.Close()
	c2, err := tlsClient.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err != nil {
		t.Fatalf("forward over TLS listener: %v", err)
	}
	defer c2.Close()

	// 3. both sessions belong to the one server, so Drain sees both
	if got := srv.ActiveSessions(); got != 2 {
		t.Fatalf("both listeners should feed one server: want 2 active sessions, got %d", got)
	}
}
