package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/config"
	"github.com/rupivbluegreen/omni-sag/internal/fips"
)

// selfSignedCert writes an ephemeral EC server cert/key pair to t.TempDir()
// and returns the file paths, for apiTLSConfig's tls.LoadX509KeyPair.
func selfSignedCert(t *testing.T) (certPath, keyPath string) {
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
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestAPITLSConfig_OffModeUnchanged(t *testing.T) {
	certPath, keyPath := selfSignedCert(t)
	cfg := &config.APIConfig{TLSCert: certPath, TLSKey: keyPath}
	tc, err := apiTLSConfig(cfg, fips.ModeOff)
	if err != nil {
		t.Fatalf("apiTLSConfig: %v", err)
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("off mode should keep the pre-existing MinVersion TLS1.2, got 0x%04x", tc.MinVersion)
	}
	if tc.CipherSuites != nil {
		t.Fatalf("off mode must not restrict cipher suites, got %v", tc.CipherSuites)
	}
}

func TestAPITLSConfig_EnforceModeHardened(t *testing.T) {
	certPath, keyPath := selfSignedCert(t)
	cfg := &config.APIConfig{TLSCert: certPath, TLSKey: keyPath}
	tc, err := apiTLSConfig(cfg, fips.ModeEnforce)
	if err != nil {
		t.Fatalf("apiTLSConfig: %v", err)
	}
	if err := fips.ValidateTLSConfig(tc); err != nil {
		t.Fatalf("enforce-mode config should be FIPS-acceptable: %v", err)
	}
	if len(tc.CipherSuites) == 0 {
		t.Fatal("expected cipher suites to be restricted under enforce")
	}
}

func TestAPITLSConfig_NoTLSUnaffected(t *testing.T) {
	tc, err := apiTLSConfig(&config.APIConfig{}, fips.ModeEnforce)
	if err != nil {
		t.Fatalf("no tls_cert configured should not error: %v", err)
	}
	if tc != nil {
		t.Fatalf("no tls_cert configured should return a nil config, got %+v", tc)
	}
}

func TestGatewayTLSConfig_NotConfiguredServesPlainSSH(t *testing.T) {
	tc, err := gatewayTLSConfig(nil, fips.ModeEnforce)
	if err != nil {
		t.Fatalf("absent tls block should not error: %v", err)
	}
	if tc != nil {
		t.Fatalf("absent tls block should return a nil config, got %+v", tc)
	}
}

func TestGatewayTLSConfig_EnforceModeHardened(t *testing.T) {
	certPath, keyPath := selfSignedCert(t)
	tc, err := gatewayTLSConfig(&config.GatewayTLSConfig{Cert: certPath, Key: keyPath}, fips.ModeEnforce)
	if err != nil {
		t.Fatalf("gatewayTLSConfig: %v", err)
	}
	if err := fips.ValidateTLSConfig(tc); err != nil {
		t.Fatalf("enforce-mode config should be FIPS-acceptable: %v", err)
	}
}

func TestGatewayTLSConfig_BadClientCARejected(t *testing.T) {
	certPath, keyPath := selfSignedCert(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := gatewayTLSConfig(&config.GatewayTLSConfig{Cert: certPath, Key: keyPath, ClientCA: caPath}, fips.ModeOff)
	if !errors.Is(err, errBadGatewayClientCA) {
		t.Fatalf("want errBadGatewayClientCA, got %v", err)
	}
}

// The point of the whole feature: a TLS-wrapped listener must present a
// handshake an SNI-routing ingress can see, and speak SSH inside it.
func TestGatewayTLSListener_SNIHandshakeThenSSH(t *testing.T) {
	certPath, keyPath := selfSignedCert(t)
	tc, err := gatewayTLSConfig(&config.GatewayTLSConfig{Cert: certPath, Key: keyPath}, fips.ModeOff)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(raw, tc)
	defer ln.Close()

	var sni string
	tc.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = h.ServerName
		return nil, nil
	}

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-Go\r\n"))
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "omni-sag.example.net",
	})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 12)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if got := string(buf); got != "SSH-2.0-Go\r\n" {
		t.Fatalf("want SSH banner inside TLS, got %q", got)
	}
	if sni != "omni-sag.example.net" {
		t.Fatalf("ingress needs SNI to route on; got %q", sni)
	}
}
