// Package dialer is the single outbound path to session targets.
//
// No other package may call net.Dial/net.Dialer for targets: this is the
// single-dialer invariant the network-authz model depends on. It must not
// import internal/api, so the data path never depends on the control plane.
//
// Every target connection is authorized against the policy BEFORE a socket is
// opened, and the decision is emitted as evidence regardless of outcome. Deny
// is the default: any error in the authorization step fails closed.
package dialer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// ErrDenied is returned when policy denies a target. Callers (the SSH session)
// translate this into an "administratively prohibited" channel rejection.
var ErrDenied = errors.New("dialer: target administratively prohibited")

// ErrForwardingRefused is returned when a target is authorized but port
// forwarding (-L) is refused because the target requires full session
// recording (PRD FR-10). No socket is opened.
var ErrForwardingRefused = errors.New("dialer: forwarding refused on full-recording target")

// ErrCredentialRefused is returned when the target's credential mode denies the
// session or (for inject) the credential cannot be resolved and the session
// fails closed. No socket is opened; there is no downgrade (PRD FR-18).
var ErrCredentialRefused = errors.New("dialer: credential refused")

// netDial is the ONLY net.Dial call site for targets in the codebase. It is a
// package variable solely so tests can substitute a fake transport; production
// always uses the real dialer.
var netDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Dialer authorizes and opens target connections.
type Dialer struct {
	policy  policy.Policy
	sink    evidence.Sink
	timeout time.Duration
	cred    *credential.Provider // optional; nil ⇒ all targets are passthrough
}

// Option configures a Dialer.
type Option func(*Dialer)

// WithCredentialProvider resolves the target's credential mode (inject | prompt
// | passthrough | deny) as part of establishing the connection.
func WithCredentialProvider(p *credential.Provider) Option {
	return func(d *Dialer) { d.cred = p }
}

// New returns a Dialer bound to a policy and an evidence sink. A credential
// provider is always installed (a fetcher-less default when none is supplied) so
// deny/prompt/passthrough modes are enforced; only inject needs CyberArk.
func New(p policy.Policy, sink evidence.Sink, opts ...Option) *Dialer {
	d := &Dialer{policy: p, sink: sink, timeout: 10 * time.Second}
	for _, opt := range opts {
		opt(d)
	}
	if d.cred == nil {
		d.cred = credential.NewProvider(credential.Config{})
	}
	return d
}

// CyberArkParams configures credential injection from CyberArk. Plain types so
// the composition root (cmd) need not import internal/credential.
type CyberArkParams struct {
	BaseURL, ClientCert, ClientKey, CACert string
	AppID, Safe, ObjectTemplate            string
	TimeoutSeconds                         int
	BreakerFailures                        int
	BreakerCooldownSeconds                 int
}

// WithCyberArk builds a credential provider that resolves inject-mode secrets
// from CyberArk CCP over mTLS, and returns it as an Option. Errors on bad
// certs.
func WithCyberArk(p CyberArkParams) (Option, error) {
	ccp, err := credential.NewCCPClient(credential.CCPConfig{
		BaseURL:        p.BaseURL,
		ClientCertPath: p.ClientCert,
		ClientKeyPath:  p.ClientKey,
		CACertPath:     p.CACert,
		Timeout:        time.Duration(p.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	appID, safe, tmpl := p.AppID, p.Safe, p.ObjectTemplate
	query := func(req credential.Request) credential.Query {
		host := req.Target
		if h, _, err := net.SplitHostPort(req.Target); err == nil {
			host = h
		}
		return credential.Query{AppID: appID, Safe: safe, Object: strings.ReplaceAll(tmpl, "{host}", host)}
	}
	breaker := credential.NewBreaker(credential.BreakerConfig{
		Threshold: p.BreakerFailures,
		Cooldown:  time.Duration(p.BreakerCooldownSeconds) * time.Second,
	})
	prov := credential.NewProvider(credential.Config{Fetcher: ccp, Query: query, Breaker: breaker})
	return WithCredentialProvider(prov), nil
}

// DialTarget authorizes pr against target, emits the decision as evidence, and
// on allow dials the target. On deny it returns ErrDenied and never opens a
// socket. sourceIP is recorded in evidence only.
//
// forwarding indicates the connection is a port-forward (-L / direct-tcpip).
// When true and the target requires full session recording, the forward is
// refused with ErrForwardingRefused and no socket is opened (PRD FR-10).
// Non-forwarding uses (e.g. an SFTP or interactive session layered on the
// target) pass forwarding=false.
func (d *Dialer) DialTarget(ctx context.Context, pr policy.Principal, sourceIP string, target policy.Target, forwarding bool) (net.Conn, error) {
	decision := d.policy.Decide(pr, target)

	forwardRefused := decision.Allow && forwarding && !decision.ForwardingAllowed()
	effectiveAllow := decision.Allow && !forwardRefused
	reason := decision.Reason
	if forwardRefused {
		reason = "forwarding refused: target requires full session recording"
	}

	// Emit the decision as evidence before acting on it. An evidence failure
	// must not silently drop the record: surface it, but the decision stands.
	// Slice 3 will decide whether an un-recordable allow should fail closed;
	// for now the failure is logged so a degraded sink is observable.
	if err := d.sink.Emit(evidence.Event{
		Time:        time.Now().UTC(),
		Type:        evidence.TypeTunnelDecision,
		User:        pr.User,
		SourceIP:    sourceIP,
		Target:      target.String(),
		Allow:       evidence.BoolPtr(effectiveAllow),
		Reason:      reason,
		MatchedRole: decision.MatchedRole,
		RecordMode:  string(decision.RecordMode),
	}); err != nil {
		log.Printf("omni-sag: evidence emit failed (tunnel_decision user=%s target=%s allow=%v): %v",
			pr.User, target, effectiveAllow, err)
	}

	if !decision.Allow {
		return nil, fmt.Errorf("%w: %s", ErrDenied, decision.Reason)
	}
	if forwardRefused {
		return nil, fmt.Errorf("%w: %s", ErrForwardingRefused, target)
	}

	// Resolve the target's credential mode before opening a socket, so a deny or
	// an inject fail-closed never leaves a dangling connection. No downgrade.
	if err := d.resolveCredential(ctx, pr, sourceIP, target, decision); err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	conn, err := netDial(dialCtx, "tcp", target.String())
	if err != nil {
		return nil, fmt.Errorf("dialer: dial %s: %w", target, err)
	}
	return conn, nil
}

// resolveCredential applies the target's credential mode and emits a credential
// evidence event (never the secret). It returns an error — wrapping
// ErrCredentialRefused — when the mode denies the session or an inject fails
// closed; the caller must then refuse and NOT open a socket. The injected
// secret is used just-in-time and zeroized (the real target-auth leg is stubbed
// at the current gateway-terminated boundary — see ADR-0002).
func (d *Dialer) resolveCredential(ctx context.Context, pr policy.Principal, sourceIP string, target policy.Target, decision policy.Decision) error {
	if d.cred == nil {
		return nil
	}
	mode := credential.Mode(decision.CredentialMode).Normalize()
	if mode == credential.ModePassthrough {
		// The default: the gateway injects nothing and the caller's own
		// connection is used. Nothing to resolve or record.
		return nil
	}
	res, cerr := d.cred.Resolve(ctx, credential.Request{
		User:   pr.User,
		Target: target.String(),
		Mode:   mode,
	})

	outcome := string(res.Outcome)
	reason := res.Reason
	if cerr != nil {
		reason = cerr.Error() // safe: credential errors never contain the secret
		if errors.Is(cerr, credential.ErrDenied) {
			outcome = string(credential.OutcomeDenied)
		} else {
			outcome = "fail_closed"
		}
	}
	if err := d.sink.Emit(evidence.Event{
		Time:           time.Now().UTC(),
		Type:           evidence.TypeCredential,
		User:           pr.User,
		SourceIP:       sourceIP,
		Target:         target.String(),
		Allow:          evidence.BoolPtr(cerr == nil),
		CredentialMode: string(mode.Normalize()),
		Outcome:        outcome,
		Reason:         reason,
	}); err != nil {
		log.Printf("omni-sag: evidence emit failed (credential user=%s target=%s): %v", pr.User, target, err)
	}

	if cerr != nil {
		return fmt.Errorf("%w: %v", ErrCredentialRefused, cerr)
	}
	if res.Secret != nil {
		// Just-in-time use then zeroize; never cached, never logged.
		res.Secret.Destroy()
	}
	return nil
}
