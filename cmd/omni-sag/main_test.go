package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
