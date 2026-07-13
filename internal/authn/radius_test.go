package authn

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/vendors/microsoft"
)

var testSecret = []byte("testing123")

// startMockRADIUS binds a UDP socket, serves handler, and returns its address.
func startMockRADIUS(t *testing.T, handler radius.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := radius.PacketServer{
		Handler:      handler,
		SecretSource: radius.StaticSecretSource(testSecret),
	}
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Shutdown(context.Background()); _ = pc.Close() })
	return pc.LocalAddr().String()
}

func newTestProvider(addr string, interactive bool) *RADIUS {
	return NewRADIUS(RADIUSConfig{
		Server:                    addr,
		Secret:                    testSecret,
		Timeout:                   time.Second,
		Retries:                   1,
		AllowInteractiveChallenge: interactive,
	})
}

func TestRADIUS_AcceptSucceeds_AndSendsMSCHAPv2NotPAP(t *testing.T) {
	var mu sync.Mutex
	var sawMSCHAP2 bool
	var sawUserPassword bool

	addr := startMockRADIUS(t, func(w radius.ResponseWriter, r *radius.Request) {
		mu.Lock()
		sawMSCHAP2 = len(microsoft.MSCHAP2Response_Get(r.Packet)) == 50
		sawUserPassword = len(rfc2865.UserPassword_Get(r.Packet)) > 0
		mu.Unlock()
		_ = w.Write(r.Response(radius.CodeAccessAccept))
	})

	err := newTestProvider(addr, false).Verify(context.Background(), MFARequest{
		Username: "alice", Password: []byte("clientPass"), SourceIP: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !sawMSCHAP2 {
		t.Error("request did not carry a 50-byte MS-CHAP2-Response")
	}
	if sawUserPassword {
		t.Error("request carried User-Password (PAP) — the reusable password must never be sent as PAP")
	}
}

func TestRADIUS_RejectFailsClosed(t *testing.T) {
	addr := startMockRADIUS(t, func(w radius.ResponseWriter, r *radius.Request) {
		_ = w.Write(r.Response(radius.CodeAccessReject))
	})
	err := newTestProvider(addr, false).Verify(context.Background(), MFARequest{
		Username: "bob", Password: []byte("clientPass"),
	})
	if !errors.Is(err, ErrMFA) {
		t.Fatalf("reject must fail closed with ErrMFA, got %v", err)
	}
}

func TestRADIUS_ChallengeThenAccept_Interactive(t *testing.T) {
	var mu sync.Mutex
	step := 0
	var challengeAnswer []byte

	addr := startMockRADIUS(t, func(w radius.ResponseWriter, r *radius.Request) {
		mu.Lock()
		defer mu.Unlock()
		step++
		if step == 1 {
			resp := r.Response(radius.CodeAccessChallenge)
			_ = rfc2865.State_Set(resp, []byte("state-xyz"))
			_ = rfc2865.ReplyMessage_SetString(resp, "Enter code:")
			_ = w.Write(resp)
			return
		}
		// second request: must echo State and carry the one-time reply.
		if string(rfc2865.State_Get(r.Packet)) != "state-xyz" {
			_ = w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		challengeAnswer = rfc2865.UserPassword_Get(r.Packet)
		_ = w.Write(r.Response(radius.CodeAccessAccept))
	})

	prompted := false
	err := newTestProvider(addr, true).Verify(context.Background(), MFARequest{
		Username: "alice", Password: []byte("clientPass"),
		Prompt: func(_ context.Context, _ string, _ bool) (string, error) {
			prompted = true
			return "246810", nil
		},
	})
	if err != nil {
		t.Fatalf("challenge->accept should succeed, got %v", err)
	}
	if !prompted {
		t.Error("prompter was not invoked for the challenge")
	}
	mu.Lock()
	defer mu.Unlock()
	if string(challengeAnswer) != "246810" {
		t.Errorf("challenge reply = %q, want 246810", challengeAnswer)
	}
}

func TestRADIUS_ChallengeFailsClosedWhenNotInteractive(t *testing.T) {
	addr := startMockRADIUS(t, func(w radius.ResponseWriter, r *radius.Request) {
		resp := r.Response(radius.CodeAccessChallenge)
		_ = rfc2865.ReplyMessage_SetString(resp, "Enter code:")
		_ = w.Write(resp)
	})
	err := newTestProvider(addr, false).Verify(context.Background(), MFARequest{
		Username: "alice", Password: []byte("clientPass"),
		Prompt: func(_ context.Context, _ string, _ bool) (string, error) { return "123", nil },
	})
	if !errors.Is(err, ErrMFA) {
		t.Fatalf("challenge with interactive disabled must fail closed, got %v", err)
	}
}

func TestRADIUS_TimeoutFailsClosed(t *testing.T) {
	// Handler never responds -> client times out and must fail closed.
	addr := startMockRADIUS(t, func(w radius.ResponseWriter, r *radius.Request) {})
	p := NewRADIUS(RADIUSConfig{
		Server: addr, Secret: testSecret,
		Timeout: 150 * time.Millisecond, Retries: 1,
	})
	start := time.Now()
	err := p.Verify(context.Background(), MFARequest{Username: "alice", Password: []byte("x")})
	if !errors.Is(err, ErrMFA) {
		t.Fatalf("timeout must fail closed with ErrMFA, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("timeout took too long; retry/timeout bounds not honored")
	}
}
