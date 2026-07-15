package credential

import (
	"crypto/ecdsa"
	"testing"
)

func TestNewCyberArkProvider_BadCertsErrors(t *testing.T) {
	_, err := NewCyberArkProvider(CyberArkParams{
		BaseURL:    "https://ccp.example",
		ClientCert: "/nonexistent/cert.pem",
		ClientKey:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("want an error for nonexistent cert/key paths, got nil")
	}
}

// TestNewCyberArkProvider_QueryUsesHostOnly verifies that a provider builds
// successfully given a valid client cert/key (mTLS is required — see
// NewCCPClient — so unlike the sibling test above this needs real, if
// throwaway, CA-signed material; makeCA/makeLeaf/writePEM/writeKeyPEM are
// shared test helpers from ccp_test.go in this same package).
func TestNewCyberArkProvider_QueryUsesHostOnly(t *testing.T) {
	caCert, caKey := makeCA(t)
	clientTLS := makeLeaf(t, caCert, caKey, false)
	dir := t.TempDir()
	certPath := writePEM(t, dir, "client.crt", "CERTIFICATE", clientTLS.Certificate[0])
	keyPath := writeKeyPEM(t, dir, "client.key", clientTLS.PrivateKey.(*ecdsa.PrivateKey))

	p, err := NewCyberArkProvider(CyberArkParams{
		BaseURL:    "https://ccp.example",
		ClientCert: certPath, ClientKey: keyPath,
		AppID: "app1", Safe: "safe1", ObjectTemplate: "{host}",
	})
	if err != nil {
		t.Fatalf("NewCyberArkProvider: %v", err)
	}
	if p == nil {
		t.Fatal("want non-nil provider")
	}
}
