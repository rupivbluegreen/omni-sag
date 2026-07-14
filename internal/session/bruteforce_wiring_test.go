package session

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/ratelimit"
	"golang.org/x/crypto/ssh"
)

// startServerBF starts a server whose brute-force limiter is the supplied one,
// so the test can drive lockout deterministically with a short backoff.
func startServerBF(t *testing.T, auth authn.Authenticator, sink evidence.Sink, l *ratelimit.Limiter) string {
	t.Helper()
	hostKey, err := NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	d := dialer.New(policy.Policy{}, sink)
	srv := New(hostKey, auth, d, sink, WithBruteForceLimiter(l))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return ln.Addr().String()
}

func dialWith(addr, user, password string) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		c.Close()
	}
	return err
}

func countRateLimited(sink *evidence.MemSink) int {
	n := 0
	for _, e := range sink.Events() {
		if e.Type == evidence.TypeAuth && e.Reason == "rate limited: too many failed attempts" {
			n++
		}
	}
	return n
}

// After the failure threshold, even a correct password is refused (fail closed),
// and the refusal is evidenced. Once the bounded backoff elapses, a correct
// login succeeds again and clears the lockout.
func TestBruteForce_LocksOutThenRecovers(t *testing.T) {
	sink := evidence.NewMemSink()
	auth := fakeAuth{users: map[string][]string{"alice": {"dba"}}}
	l := ratelimit.New(ratelimit.Config{
		MaxFailures: 3,
		Window:      time.Minute,
		BaseBackoff: 800 * time.Millisecond,
		MaxBackoff:  800 * time.Millisecond,
		MaxEntries:  64,
	})
	addr := startServerBF(t, auth, sink, l)

	// Three wrong-password attempts from this source trip the lockout.
	for i := 0; i < 3; i++ {
		if err := dialWith(addr, "alice", "wrong"); err == nil {
			t.Fatalf("attempt %d: wrong password must fail", i)
		}
	}

	// The correct password is now refused: the source is locked out.
	if err := dialWith(addr, "alice", "pw"); err == nil {
		t.Fatal("correct password must be refused while locked out (fail closed)")
	}
	if countRateLimited(sink) < 1 {
		t.Fatal("expected a rate-limited auth evidence event during lockout")
	}

	// After the bounded backoff, the lockout self-clears and login works.
	time.Sleep(1 * time.Second)
	if err := dialWith(addr, "alice", "pw"); err != nil {
		t.Fatalf("login must succeed after lockout expires: %v", err)
	}

	// The success reset the counter: three fresh failures are needed to lock
	// again, so two failures then a good login still works.
	if err := dialWith(addr, "alice", "wrong"); err == nil {
		t.Fatal("wrong password should fail")
	}
	if err := dialWith(addr, "alice", "wrong"); err == nil {
		t.Fatal("wrong password should fail")
	}
	if err := dialWith(addr, "alice", "pw"); err != nil {
		t.Fatalf("login must still succeed after success reset the counter: %v", err)
	}
}
