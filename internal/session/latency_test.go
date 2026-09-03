package session

import (
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// sample is one observation recorded by the test's LatencyObservers.
type sample struct {
	d  time.Duration
	ok bool
}

type recorder struct {
	mu                    sync.Mutex
	auth, setup, lifetime []sample
}

func (r *recorder) observers() LatencyObservers {
	add := func(dst *[]sample) func(time.Duration, bool) {
		return func(d time.Duration, ok bool) {
			r.mu.Lock()
			defer r.mu.Unlock()
			*dst = append(*dst, sample{d, ok})
		}
	}
	authFn, setupFn := add(&r.auth), add(&r.setup)
	return LatencyObservers{
		Auth:            authFn,
		SessionSetup:    setupFn,
		SessionLifetime: func(d time.Duration) { add(&r.lifetime)(d, true) },
	}
}

func (r *recorder) snapshot() (auth, setup, lifetime []sample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sample(nil), r.auth...), append([]sample(nil), r.setup...), append([]sample(nil), r.lifetime...)
}

// waitFor polls until pred holds, so the assertions do not race the
// connection goroutine that records the observation.
func waitFor(t *testing.T, what string, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestLatencyObservers_AuthOutcomeAndLifetime(t *testing.T) {
	var rec recorder
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, WithLatencyObservers(rec.observers()))

	// A rejected handshake still yields one auth observation, marked failed.
	badCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if _, err := ssh.Dial("tcp", addr, badCfg); err == nil {
		t.Fatal("expected the bad-password handshake to fail")
	}
	waitFor(t, "the failed auth observation", func() bool {
		auth, _, _ := rec.snapshot()
		return len(auth) == 1
	})
	if auth, _, _ := rec.snapshot(); auth[0].ok {
		t.Error("a rejected handshake must be observed as ok=false")
	}

	client := sshClient(t, addr, "alice")
	waitFor(t, "the successful auth observation", func() bool {
		auth, _, _ := rec.snapshot()
		return len(auth) == 2
	})
	auth, _, lifetime := rec.snapshot()
	if !auth[1].ok {
		t.Error("an accepted handshake must be observed as ok=true")
	}
	if len(lifetime) != 0 {
		t.Fatal("lifetime must not be observed while the connection is open")
	}

	client.Close()
	waitFor(t, "the lifetime observation", func() bool {
		_, _, l := rec.snapshot()
		return len(l) == 1
	})
	if _, _, l := rec.snapshot(); l[0].d <= 0 {
		t.Errorf("lifetime = %v, want a positive duration", l[0].d)
	}
}

// The observers are optional: a Server built without them must behave
// identically, and must not panic on the nil funcs.
func TestLatencyObservers_UnsetIsSafe(t *testing.T) {
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink)
	sshClient(t, addr, "alice").Close()
}

// getOrDial times only the dial it actually performs; a cache hit must not
// add a second, near-zero sample that would drag a setup-latency SLO down.
var errDialFailed = errors.New("dial failed")

func TestSessionSetupObservedOncePerConnection(t *testing.T) {
	var rec recorder
	obs := rec.observers()
	tch := &targetConnCache{observe: obs.SessionSetup}
	dials := 0
	dial := func() (*ssh.Client, error) {
		dials++
		time.Sleep(5 * time.Millisecond)
		return nil, errDialFailed
	}
	for i := 0; i < 3; i++ {
		if _, err := tch.getOrDial(dial); err != errDialFailed {
			t.Fatalf("getOrDial err = %v, want errDialFailed", err)
		}
	}
	if dials != 1 {
		t.Fatalf("dialed %d times, want 1 (the rest are cache hits)", dials)
	}
	_, setup, _ := rec.snapshot()
	if len(setup) != 1 {
		t.Fatalf("recorded %d setup observations, want exactly 1", len(setup))
	}
	if setup[0].ok {
		t.Error("a failed dial must be observed as ok=false")
	}
	if setup[0].d < 5*time.Millisecond {
		t.Errorf("setup duration = %v, want at least the 5ms the dial took", setup[0].d)
	}
}
