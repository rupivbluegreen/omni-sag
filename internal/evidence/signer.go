package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// Signer holds the gateway's Ed25519 evidence-signing key. This is the
// gateway's own key, not an injected credential, but it is still secret: it is
// persisted 0600 and never logged.
type Signer struct {
	priv ed25519.PrivateKey
}

// LoadOrCreateSigner loads an Ed25519 signing key from path (PKCS#8 PEM),
// generating and persisting one at mode 0600 if the file does not exist.
func LoadOrCreateSigner(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("evidence signer: no PEM block in %s", path)
		}
		key, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("evidence signer: parse %s: %w", path, perr)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("evidence signer: %s is not an Ed25519 key", path)
		}
		return &Signer{priv: priv}, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("evidence signer: read %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("evidence signer: generate: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("evidence signer: marshal: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("evidence signer: write %s: %w", path, err)
	}
	return &Signer{priv: priv}, nil
}

// NewEphemeralSigner returns an in-memory signer (for tests).
func NewEphemeralSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv}, nil
}

// PublicKeyHex returns the hex-encoded public key, used as the key id and
// written into each checkpoint.
func (s *Signer) PublicKeyHex() string {
	pub := s.priv.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub)
}

func (s *Signer) sign(msg []byte) string {
	return hex.EncodeToString(ed25519.Sign(s.priv, msg))
}

// VerifySignature checks an Ed25519 signature (hex) against a hex public key.
func VerifySignature(pubHex, sigHex string, msg []byte) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
