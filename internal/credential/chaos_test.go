package credential

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Chaos / fail-closed matrix for the credential (CyberArk inject) provider.
//
// Every failure mode of the Fetcher and the circuit breaker MUST yield
// ErrFailClosed and NEVER a usable Result — there is no code path from `inject`
// to another mode (PRD FR-18: no silent downgrade). These tests drive each
// failure and assert refusal + surfaced error + no leaked secret.

// stallFetcher blocks until ctx is cancelled, then reports the ctx error —
// modelling a CyberArk CCP that has gone dark and only unblocks on timeout.
type stallFetcher struct{}

func (stallFetcher) Fetch(ctx context.Context, _ Query) (*Secret, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// panicFetcher must never be reached (breaker-open / no-fetcher paths).
type panicFetcher struct{ t *testing.T }

func (f panicFetcher) Fetch(context.Context, Query) (*Secret, error) {
	f.t.Helper()
	f.t.Fatal("fetcher must not be called on a fail-closed path")
	return nil, nil
}

func injectReq() Request {
	return Request{User: "alice", Target: "db1.lab.local:5432", Mode: ModeInject}
}

func mustFailClosed(t *testing.T, r Result, err error) {
	t.Helper()
	if !errors.Is(err, ErrFailClosed) {
		t.Fatalf("inject failure must wrap ErrFailClosed, got %v", err)
	}
	if r.Outcome == OutcomeInjected || r.Outcome == OutcomePassthrough || r.Outcome == OutcomePrompt {
		t.Fatalf("fail-closed must not yield a usable outcome, got %q", r.Outcome)
	}
	if r.Secret != nil {
		t.Fatal("fail-closed must never return a secret")
	}
}

// resolveFC resolves an inject request and asserts it failed closed.
func resolveFC(t *testing.T, p *Provider, ctx context.Context) {
	t.Helper()
	r, err := p.Resolve(ctx, injectReq())
	mustFailClosed(t, r, err)
}

// CyberArk down: the fetcher errors on every call → fail closed, no downgrade.
func TestChaos_InjectFetcherDown(t *testing.T) {
	p := NewProvider(Config{Fetcher: failFetcher{}, Query: func(Request) Query { return Query{} }})
	resolveFC(t, p, context.Background())
}

// CyberArk returns an empty secret (misconfigured object / partial outage):
// treated as failure, fail closed — never an empty injected credential.
func TestChaos_InjectEmptySecret(t *testing.T) {
	p := NewProvider(Config{Fetcher: emptyFetcher{}, Query: func(Request) Query { return Query{} }})
	resolveFC(t, p, context.Background())
}

// CyberArk configured for inject but no fetcher/query wired: fail closed.
func TestChaos_InjectNoProvider(t *testing.T) {
	p := NewProvider(Config{})
	resolveFC(t, p, context.Background())
}

// CyberArk stalls; the caller's context deadline fires → fail closed on timeout.
func TestChaos_InjectTimeout(t *testing.T) {
	p := NewProvider(Config{Fetcher: stallFetcher{}, Query: func(Request) Query { return Query{} }})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	resolveFC(t, p, ctx)
}

// After Threshold consecutive fetch failures the breaker OPENS and subsequent
// inject requests fail closed IMMEDIATELY without ever calling the fetcher, so a
// down CCP is not hammered. Assert the still-open breaker never touches the
// fetcher (panicFetcher would fail the test if reached).
func TestChaos_InjectBreakerOpensAndStaysClosed(t *testing.T) {
	clock := time.Unix(0, 0)
	br := NewBreaker(BreakerConfig{Threshold: 3, Cooldown: time.Minute, Now: func() time.Time { return clock }})
	p := NewProvider(Config{
		Fetcher: failFetcher{},
		Query:   func(Request) Query { return Query{} },
		Breaker: br,
	})
	ctx := context.Background()
	// Drive Threshold failures to open the breaker.
	for i := 0; i < 3; i++ {
		resolveFC(t, p, ctx)
	}
	// Breaker is now open. Swap in a fetcher that must NOT be called.
	p.fetcher = panicFetcher{t: t}
	// Still within cooldown → refused immediately, fetcher untouched.
	r, err := p.Resolve(ctx, injectReq())
	mustFailClosed(t, r, err)
	if err == nil || !strings.Contains(err.Error(), "circuit") {
		t.Fatalf("expected a circuit-open reason, got %v", err)
	}
}

// After cooldown the breaker half-opens for exactly one trial; if CCP is still
// down that trial fails closed and the breaker re-opens — never falls open.
func TestChaos_InjectBreakerHalfOpenTrialFailsClosed(t *testing.T) {
	clock := time.Unix(0, 0)
	now := func() time.Time { return clock }
	br := NewBreaker(BreakerConfig{Threshold: 1, Cooldown: time.Minute, Now: now})
	p := NewProvider(Config{Fetcher: failFetcher{}, Query: func(Request) Query { return Query{} }, Breaker: br})
	ctx := context.Background()

	resolveFC(t, p, ctx)               // opens (threshold 1)
	clock = clock.Add(2 * time.Minute) // cooldown elapsed → half-open trial allowed
	resolveFC(t, p, ctx)               // trial hits down CCP, fails closed, re-opens

	// Immediately after, still open: fetcher must not be hit.
	p.fetcher = panicFetcher{t: t}
	resolveFC(t, p, ctx)
}

// Deny mode always refuses regardless of any fetcher state.
func TestChaos_DenyAlwaysRefuses(t *testing.T) {
	p := NewProvider(Config{Fetcher: okFetcher{pw: "should-never-be-used"}, Query: func(Request) Query { return Query{} }})
	r, err := p.Resolve(context.Background(), Request{Mode: ModeDeny, Target: "db1:5432"})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("deny must return ErrDenied, got %v", err)
	}
	if r.Secret != nil {
		t.Fatal("deny must never carry a secret")
	}
}
