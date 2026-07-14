package credential

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJSONUnquote(t *testing.T) {
	cases := map[string]string{
		`"abc"`:         "abc",
		`"a\"b"`:        `a"b`,
		`"a\\b"`:        `a\b`,
		`"line\nbreak"`: "line\nbreak",
		`"tab\there"`:   "tab\there",
		`"AB"`:          "AB",
	}
	for in, want := range cases {
		got, err := jsonUnquote([]byte(in))
		if err != nil || string(got) != want {
			t.Fatalf("jsonUnquote(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := jsonUnquote([]byte(`notquoted`)); err == nil {
		t.Fatal("expected error for non-string token")
	}
}

func TestCCP_ErrorPaths(t *testing.T) {
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	if _, err := FetchWithClient(srv.URL, srv.Client()).Fetch(ctx, Query{}); err == nil {
		t.Fatal("expected error on HTTP 500")
	}
	srv.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"UserName":"svc"}`))
	}))
	if _, err := FetchWithClient(srv2.URL, srv2.Client()).Fetch(ctx, Query{}); err == nil {
		t.Fatal("expected error when Content is missing")
	}
	srv2.Close()
}

// TestCCP_FetchOverMTLS exercises the full mutual-TLS path: a server that
// requires and verifies a client cert, and a client built from cert/key/CA
// files by NewCCPClient.
func TestCCP_FetchOverMTLS(t *testing.T) {
	caCert, caKey := makeCA(t)
	serverTLS := makeLeaf(t, caCert, caKey, true)
	clientTLS := makeLeaf(t, caCert, caKey, false)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"Content":"p@ss\nw0rd","UserName":"svc"}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLS},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	certPath := writePEM(t, dir, "client.crt", "CERTIFICATE", clientTLS.Certificate[0])
	keyPath := writeKeyPEM(t, dir, "client.key", clientTLS.PrivateKey.(*ecdsa.PrivateKey))
	caPath := writePEM(t, dir, "ca.crt", "CERTIFICATE", caCert.Raw)

	c, err := NewCCPClient(CCPConfig{
		BaseURL: srv.URL, ClientCertPath: certPath, ClientKeyPath: keyPath, CACertPath: caPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	sec, err := c.Fetch(context.Background(), Query{AppID: "app", Safe: "safe", Object: "obj"})
	if err != nil {
		t.Fatalf("fetch over mTLS: %v", err)
	}
	if string(sec.Bytes()) != "p@ss\nw0rd" {
		t.Fatalf("secret = %q", sec.Bytes())
	}
	sec.Destroy()

	// A client with no cert must be rejected by the server (mTLS enforced).
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}}}
	if _, err := FetchWithClient(srv.URL, noCert).Fetch(context.Background(), Query{}); err == nil {
		t.Fatal("server must reject a client without a certificate")
	}
}

func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "omni-sag-test-ca"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func makeLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, server bool) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeKeyPEM(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writePEM(t, dir, name, "PRIVATE KEY", der)
}
