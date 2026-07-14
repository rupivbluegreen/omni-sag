package dialer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// Chaos / fail-closed matrix at the single-dialer choke point.
//
// The dialer is the ONLY path that opens a socket to a target, and every
// dependency it consults (policy, credential/CyberArk, approval store, evidence
// sink) is driven to failure here. The load-bearing assertions:
//   - no unauthorized access — a failure NEVER yields a usable connection;
//   - refusal happens BEFORE any socket — netDial is never reached on refusal;
//   - errors are surfaced, not swallowed — a typed refusal error is returned.

// noDial installs a target dial that FAILS THE TEST if ever called, proving a
// refusal happened before any socket was opened.
func noDial(t *testing.T) {
	t.Helper()
	swapDial(t, func(_ context.Context, _, addr string) (net.Conn, error) {
		t.Fatalf("fail-closed path must not open a socket (dialed %s)", addr)
		return nil, errors.New("unreachable")
	})
}

// downFetcher models a CyberArk CCP that is down: every fetch errors.
type downFetcher struct{}

func (downFetcher) Fetch(context.Context, credential.Query) (*credential.Secret, error) {
	return nil, errors.New("ccp unreachable")
}

func injectProvider() *credential.Provider {
	return credential.NewProvider(credential.Config{
		Fetcher: downFetcher{},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})
}

// unavailableStore models an approval store whose backend is down: every
// operation reports ErrStoreUnavailable. It must cause the gate to fail closed.
type unavailableStore struct{}

func (unavailableStore) Create(approval.Request, time.Duration) (approval.Request, error) {
	return approval.Request{}, approval.ErrStoreUnavailable
}
func (unavailableStore) Get(string) (approval.Request, bool) { return approval.Request{}, false }
func (unavailableStore) List() []approval.Request            { return nil }
func (unavailableStore) Approve(string, string) (approval.Request, error) {
	return approval.Request{}, approval.ErrStoreUnavailable
}
func (unavailableStore) Deny(string, string) (approval.Request, error) {
	return approval.Request{}, approval.ErrStoreUnavailable
}
func (unavailableStore) Wait(context.Context, string) (approval.Request, error) {
	return approval.Request{}, approval.ErrStoreUnavailable
}

var alice = policy.Principal{User: "alice", Groups: []string{"dba"}}
var db1 = policy.Target{Host: "db1.lab.local", Port: 5432}

// POLICY EMPTY: no roles → default deny → no socket, ErrDenied, deny evidence.
func TestChaos_EmptyPolicyDeniesAll(t *testing.T) {
	noDial(t)
	sink := evidence.NewMemSink()
	d := New(policy.Policy{}, sink)
	_, err := d.DialTarget(context.Background(), alice, "10.0.0.5", db1, false)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("empty policy must deny with ErrDenied, got %v", err)
	}
	ev := sink.Events()
	if len(ev) != 1 || ev[0].Allow == nil || *ev[0].Allow {
		t.Fatalf("expected one deny decision event, got %+v", ev)
	}
}

// CYBERARK DOWN: inject-mode target, CCP down → ErrCredentialRefused, no socket,
// no downgrade, and a not-allowed credential evidence event (error surfaced).
func TestChaos_InjectCyberArkDownFailsClosed(t *testing.T) {
	noDial(t)
	sink := evidence.NewMemSink()
	d := New(credPolicy("inject"), sink, WithCredentialProvider(injectProvider()))
	_, err := d.DialTarget(context.Background(), alice, "10.0.0.5", db1, false)
	if !errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("inject with a down CCP must fail closed with ErrCredentialRefused, got %v", err)
	}
	if !credEvent(sink, false) {
		t.Fatalf("expected a not-allowed credential event, got %+v", sink.Events())
	}
}

// CYBERARK BREAKER OPEN: after enough failures the breaker opens and inject
// refuses immediately — still no socket, still ErrCredentialRefused.
func TestChaos_InjectBreakerOpenFailsClosed(t *testing.T) {
	noDial(t)
	br := credential.NewBreaker(credential.BreakerConfig{Threshold: 1, Cooldown: time.Hour})
	prov := credential.NewProvider(credential.Config{
		Fetcher: downFetcher{},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
		Breaker: br,
	})
	d := New(credPolicy("inject"), evidence.NewMemSink(), WithCredentialProvider(prov))
	// First attempt trips the breaker; second finds it open.
	for i := 0; i < 2; i++ {
		if _, err := d.DialTarget(context.Background(), alice, "10.0.0.5", db1, false); !errors.Is(err, ErrCredentialRefused) {
			t.Fatalf("attempt %d must fail closed, got %v", i, err)
		}
	}
}

// APPROVAL STORE UNAVAILABLE: an approval-gated target with a store whose
// backend is down → ErrApprovalRefused, no socket.
func TestChaos_ApprovalStoreUnavailableFailsClosed(t *testing.T) {
	noDial(t)
	d := New(approvalPolicy(), evidence.NewMemSink(), WithApprovals(unavailableStore{}, time.Hour))
	_, err := d.DialTarget(context.Background(), alice, "10.0.0.1", policy.Target{Host: "crown", Port: 22}, false)
	if !errors.Is(err, ErrApprovalRefused) {
		t.Fatalf("an unavailable approval store must fail closed, got %v", err)
	}
}

// APPROVAL REQUIRED BUT NO STORE WIRED: the target demands approval but the
// dialer has no store → refuse, never admit.
func TestChaos_ApprovalRequiredNoStoreFailsClosed(t *testing.T) {
	noDial(t)
	d := New(approvalPolicy(), evidence.NewMemSink()) // no WithApprovals
	_, err := d.DialTarget(context.Background(), alice, "10.0.0.1", policy.Target{Host: "crown", Port: 22}, false)
	if !errors.Is(err, ErrApprovalRefused) {
		t.Fatalf("approval required but no store must fail closed, got %v", err)
	}
}

// APPROVAL WAIT CANCELLED: the client disconnects while waiting → the ctx error
// surfaces as ErrApprovalRefused and no socket is opened.
func TestChaos_ApprovalCtxCancelFailsClosed(t *testing.T) {
	noDial(t)
	store := newStore(t)
	d := New(approvalPolicy(), evidence.NewMemSink(), WithApprovals(store, time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, err := d.DialTarget(ctx, alice, "10.0.0.1", policy.Target{Host: "crown", Port: 22}, false)
	if !errors.Is(err, ErrApprovalRefused) {
		t.Fatalf("a cancelled approval wait must fail closed, got %v", err)
	}
}

// EVIDENCE SINK ERRORING must not turn a DENY into an allow: the error is
// surfaced (logged) but the deny still stands and no socket is opened.
func TestChaos_EvidenceErrorDenyStillDenies(t *testing.T) {
	noDial(t)
	d := New(policy.Policy{}, failSink{}) // empty policy => deny; sink errors on emit
	_, err := d.DialTarget(context.Background(), alice, "10.0.0.5", db1, false)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("a degraded evidence sink must not weaken deny, got %v", err)
	}
}

// EVIDENCE SINK ERRORING on an inject-fail-closed path must still fail closed:
// the credential refusal stands even when the credential event cannot be
// recorded (error surfaced, decision unchanged), and no socket opens.
func TestChaos_EvidenceErrorInjectStillFailsClosed(t *testing.T) {
	noDial(t)
	d := New(credPolicy("inject"), failSink{}, WithCredentialProvider(injectProvider()))
	_, err := d.DialTarget(context.Background(), alice, "10.0.0.5", db1, false)
	if !errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("inject fail-closed must hold even with a degraded sink, got %v", err)
	}
}

// CREDENTIAL DENY mode: explicit deny → ErrCredentialRefused, no socket.
func TestChaos_CredentialDenyFailsClosed(t *testing.T) {
	noDial(t)
	d := New(credPolicy("deny"), evidence.NewMemSink())
	_, err := d.DialTarget(context.Background(), alice, "10.0.0.5", db1, false)
	if !errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("credential deny must fail closed, got %v", err)
	}
}

// A principal holding an UNKNOWN mode string must not be silently downgraded to
// passthrough: it fails closed (credential.Mode.Normalize leaves it unknown and
// Resolve's default returns ErrFailClosed).
func TestChaos_UnknownCredentialModeFailsClosed(t *testing.T) {
	noDial(t)
	d := New(credPolicy("totally-bogus-mode"), evidence.NewMemSink())
	_, err := d.DialTarget(context.Background(), alice, "10.0.0.5", db1, false)
	if !errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("an unknown credential mode must fail closed, not downgrade, got %v", err)
	}
}
