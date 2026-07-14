// Package credential provides the target-credential provider with four modes:
// inject (fetch from CyberArk), prompt, passthrough, and deny.
//
// Only internal/session and internal/dialer may import this package; that
// allowlist is CI-enforced to minimize the blast radius of secret handling.
//
// The load-bearing security property is NO SILENT DOWNGRADE (PRD FR-18): when a
// target is configured for `inject` and the credential cannot be fetched, the
// session FAILS CLOSED. There is no code path from `inject` to another mode.
package credential

import (
	"context"
	"errors"
	"fmt"
)

// Mode is the credential posture for a target.
type Mode string

const (
	ModeInject      Mode = "inject"      // fetch from CyberArk; the user never sees it
	ModePrompt      Mode = "prompt"      // the user supplies the target credential
	ModePassthrough Mode = "passthrough" // reuse the caller's own credential
	ModeDeny        Mode = "deny"        // no credential path; refuse
)

// Normalize maps empty/unknown to ModePassthrough — the safe, backward-compatible
// default (the gateway injects nothing; the caller's own connection is used).
func (m Mode) Normalize() Mode {
	switch m {
	case ModeInject, ModePrompt, ModePassthrough, ModeDeny:
		return m
	default:
		return ModePassthrough
	}
}

// ErrFailClosed wraps every failure of an `inject` resolution. The caller MUST
// refuse the session and MUST NOT retry with another mode (FR-18).
var ErrFailClosed = errors.New("credential: fail closed")

// ErrDenied is returned for ModeDeny.
var ErrDenied = errors.New("credential: denied by policy")

// Outcome is how a credential request was resolved (safe to record in evidence).
type Outcome string

const (
	OutcomeInjected    Outcome = "injected"
	OutcomePrompt      Outcome = "prompt"
	OutcomePassthrough Outcome = "passthrough"
	OutcomeDenied      Outcome = "denied"
)

// Request describes a credential need for a target.
type Request struct {
	User   string
	Target string
	Mode   Mode
}

// Result is the resolved credential. Secret is non-nil only for OutcomeInjected;
// the caller MUST Destroy it after use.
type Result struct {
	Outcome Outcome
	Secret  *Secret
	Reason  string
}

// Fetcher retrieves a secret for a query (implemented by the CyberArk CCP
// client; mockable in tests).
type Fetcher interface {
	Fetch(ctx context.Context, q Query) (*Secret, error)
}

// Provider resolves a credential for a target according to the requested mode.
type Provider struct {
	fetcher Fetcher
	query   func(Request) Query
	breaker *Breaker
}

// Config configures a Provider.
type Config struct {
	Fetcher Fetcher             // nil unless inject is available
	Query   func(Request) Query // maps a request to a CCP query; required if Fetcher set
	Breaker *Breaker            // optional; a default is created if nil and Fetcher set
}

// NewProvider builds a Provider. With no Fetcher, `inject` requests fail closed.
func NewProvider(cfg Config) *Provider {
	p := &Provider{fetcher: cfg.Fetcher, query: cfg.Query, breaker: cfg.Breaker}
	if p.fetcher != nil && p.breaker == nil {
		p.breaker = NewBreaker(BreakerConfig{})
	}
	return p
}

// Resolve returns the credential for req. For ModeInject, ANY failure returns an
// error wrapping ErrFailClosed and never a usable Result — the caller must
// refuse the session and must NEVER fall back to another mode.
func (p *Provider) Resolve(ctx context.Context, req Request) (Result, error) {
	switch req.Mode.Normalize() {
	case ModeDeny:
		return Result{Outcome: OutcomeDenied, Reason: "credential mode: deny"}, ErrDenied
	case ModePassthrough:
		return Result{Outcome: OutcomePassthrough, Reason: "reuse caller credential"}, nil
	case ModePrompt:
		return Result{Outcome: OutcomePrompt, Reason: "prompt user for target credential"}, nil
	case ModeInject:
		return p.inject(ctx, req)
	default:
		return Result{}, fmt.Errorf("%w: unknown credential mode", ErrFailClosed)
	}
}

// inject fetches from CyberArk. Every failure path returns ErrFailClosed and no
// secret; there is intentionally no branch that yields prompt/passthrough here.
func (p *Provider) inject(ctx context.Context, req Request) (Result, error) {
	if p.fetcher == nil || p.query == nil {
		return Result{}, fmt.Errorf("%w: inject configured for %s but no CyberArk provider", ErrFailClosed, req.Target)
	}
	if !p.breaker.Allow() {
		return Result{}, fmt.Errorf("%w: CyberArk circuit open for %s", ErrFailClosed, req.Target)
	}
	sec, err := p.fetcher.Fetch(ctx, p.query(req))
	if err != nil {
		p.breaker.Fail()
		return Result{}, fmt.Errorf("%w: CyberArk fetch failed for %s: %v", ErrFailClosed, req.Target, err)
	}
	if sec == nil || sec.Len() == 0 {
		p.breaker.Fail()
		return Result{}, fmt.Errorf("%w: CyberArk returned an empty secret for %s", ErrFailClosed, req.Target)
	}
	p.breaker.Success()
	return Result{Outcome: OutcomeInjected, Secret: sec, Reason: "injected from CyberArk"}, nil
}
