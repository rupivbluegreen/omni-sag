package credential

import (
	"crypto/ecdsa"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/fips"
)

// ccpClientTLSConfig extracts the TLS config NewCCPClient built into the
// http.Client's transport, so tests can inspect it directly.
func ccpClientTLSConfig(t *testing.T, c *CCPClient) *http.Transport {
	t.Helper()
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", c.client.Transport)
	}
	return tr
}

func newCCPTestCerts(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()
	caCert, caKey := makeCA(t)
	clientTLS := makeLeaf(t, caCert, caKey, false)
	dir := t.TempDir()
	certPath = writePEM(t, dir, "client.crt", "CERTIFICATE", clientTLS.Certificate[0])
	keyPath = writeKeyPEM(t, dir, "client.key", clientTLS.PrivateKey.(*ecdsa.PrivateKey))
	caPath = writePEM(t, dir, "ca.crt", "CERTIFICATE", caCert.Raw)
	return certPath, keyPath, caPath
}

func TestNewCCPClient_OffModeUnchanged(t *testing.T) {
	certPath, keyPath, caPath := newCCPTestCerts(t)
	c, err := NewCCPClient(CCPConfig{BaseURL: "https://ccp.example", ClientCertPath: certPath, ClientKeyPath: keyPath, CACertPath: caPath})
	if err != nil {
		t.Fatalf("NewCCPClient: %v", err)
	}
	tr := ccpClientTLSConfig(t, c)
	if tr.TLSClientConfig.CipherSuites != nil {
		t.Fatalf("off mode must not restrict cipher suites, got %v", tr.TLSClientConfig.CipherSuites)
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("off mode should not change the baseline MinVersion, got 0x%04x", tr.TLSClientConfig.MinVersion)
	}
}

func TestNewCCPClient_EnforceModeHardened(t *testing.T) {
	certPath, keyPath, caPath := newCCPTestCerts(t)
	c, err := NewCCPClient(CCPConfig{
		BaseURL: "https://ccp.example", ClientCertPath: certPath, ClientKeyPath: keyPath, CACertPath: caPath,
		Mode: fips.ModeEnforce,
	})
	if err != nil {
		t.Fatalf("NewCCPClient: %v", err)
	}
	tr := ccpClientTLSConfig(t, c)
	if err := fips.ValidateTLSConfig(tr.TLSClientConfig); err != nil {
		t.Fatalf("enforce-mode CCP TLS config should be FIPS-acceptable: %v", err)
	}
	if len(tr.TLSClientConfig.CipherSuites) == 0 {
		t.Fatal("expected cipher suites to be restricted under enforce")
	}
}
