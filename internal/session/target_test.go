package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func TestSplitTargetUser(t *testing.T) {
	cases := []struct {
		raw           string
		wantUser      string
		wantTarget    string
		wantHasTarget bool
	}{
		{"alice", "alice", "", false},
		{"alice%db1.lab.local", "alice", "db1.lab.local", true},
		{"alice%db1.lab.local%extra", "alice", "db1.lab.local%extra", true}, // only first % splits
		{"%db1.lab.local", "", "db1.lab.local", true},
		{"alice%", "alice", "", true},
	}
	for _, c := range cases {
		u, h, ok := splitTargetUser(c.raw)
		if u != c.wantUser || h != c.wantTarget || ok != c.wantHasTarget {
			t.Errorf("splitTargetUser(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.raw, u, h, ok, c.wantUser, c.wantTarget, c.wantHasTarget)
		}
	}
}

// startFakeTarget runs a minimal SSH server on an in-memory pipe that accepts
// only the given password, and returns the client-side net.Conn to dial.
// It runs until the test ends (t.Cleanup closes both ends).
func startFakeTarget(t *testing.T, wantPassword string) net.Conn {
	t.Helper()
	signer := testHostKey(t) // see Step 1a
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != wantPassword {
				return nil, errors.New("wrong password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	go func() {
		sconn, chans, reqs, err := ssh.NewServerConn(serverConn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for range chans {
		}
	}()
	return clientConn
}

func testHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("wrap host key: %v", err)
	}
	return signer
}

func TestDialTarget_Deny(t *testing.T) {
	s := &Server{}
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "deny"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestDialTarget_InjectNoProviderFailsClosed(t *testing.T) {
	s := &Server{} // s.cred is nil
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "inject"}, "db1.lab.local", 22, "")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
}

func TestDialTarget_PromptNoStashedSecretFailsClosed(t *testing.T) {
	s := &Server{}
	_, err := s.dialTarget(context.Background(), nil, policy.Principal{User: "alice"},
		policy.Decision{CredentialMode: "prompt"}, "db1.lab.local", 22, "no-such-token")
	if !errors.Is(err, credential.ErrFailClosed) {
		t.Fatalf("want ErrFailClosed, got %v", err)
	}
}
