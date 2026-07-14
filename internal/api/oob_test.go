package api_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/api"
	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/session"
	"github.com/rupivbluegreen/omni-sag/internal/sessions"
	"golang.org/x/crypto/ssh"
)

type fakeAuth struct{}

func (fakeAuth) Authenticate(_ context.Context, user, pass string) (authn.Identity, error) {
	if pass != "pw" {
		return authn.Identity{}, authn.ErrAuth
	}
	return authn.Identity{User: user, Groups: []string{"dba"}}, nil
}

func sshDial(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	return c
}

// TestControlPlaneOutOfBand proves that stopping the API server does not drop an
// existing SSH session and does not stop new SSH sessions from connecting.
func TestControlPlaneOutOfBand(t *testing.T) {
	reg := sessions.NewRegistry()
	hostKey, err := session.NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	sink := evidence.NewMemSink()
	d := dialer.New(policy.Policy{}, sink)
	srv := session.New(hostKey, fakeAuth{}, d, sink, session.WithRegistry(reg))

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, sshLn)

	// API server on its OWN listener (separate from SSH).
	apiSrv := api.NewServer(api.Config{
		Registry:   reg,
		Policy:     func() policy.Policy { return policy.Policy{} },
		Authorizer: api.NewTokenAuthorizer(map[string]api.Identity{"v": {Subject: "v", Role: api.RoleViewer}}),
	})
	apiLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiHTTP := &http.Server{Handler: apiSrv.Handler()}
	go apiHTTP.Serve(apiLn)

	// An SSH client connects and stays open.
	client := sshDial(t, sshLn.Addr().String())
	defer client.Close()

	// The API sees the live session.
	c := api.NewClient("http://"+apiLn.Addr().String(), "v", nil)
	deadline := time.Now().Add(2 * time.Second)
	for {
		list, _ := c.ListSessions(context.Background())
		if len(list) == 1 && list[0].User == "alice" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("API never listed the live SSH session")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// STOP the API server.
	if err := apiHTTP.Close(); err != nil {
		t.Fatal(err)
	}
	// Sanity: the API is really down.
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("API should be unreachable after Close")
	}

	// 1) The existing SSH session still works: open a new channel on it.
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("existing SSH session must survive API shutdown: %v", err)
	}
	_ = sess.Close()

	// 2) A brand-new SSH connection still succeeds.
	client2 := sshDial(t, sshLn.Addr().String())
	defer client2.Close()
	if _, err := client2.NewSession(); err != nil {
		t.Fatalf("new SSH session must still connect after API shutdown: %v", err)
	}
}
