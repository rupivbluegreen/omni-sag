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
	"sync"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
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

// ErrApprovalRefused is returned when a target requires a four-eyes approval and
// the request was denied, expired, cancelled, or the approval store is
// unavailable. Fail closed: no socket is opened.
var ErrApprovalRefused = errors.New("dialer: approval refused")

// netDial is the ONLY net.Dial call site for targets in the codebase. It is a
// package variable solely so tests can substitute a fake transport; production
// always uses the real dialer.
var netDial = func(ctx context.Context, network, addr string, control dialControlFunc) (net.Conn, error) {
	// control runs after the resolver produces a concrete IP and before the
	// socket connects, so the resolved-address guard validates the ACTUAL
	// resolved address (closing the DNS-rebinding/TOCTOU gap) and fails closed
	// on any blocked range. See guard.go.
	d := net.Dialer{Control: control}
	return d.DialContext(ctx, network, addr)
}

// Dialer authorizes and opens target connections.
type Dialer struct {
	mu          sync.RWMutex // guards policy for hot-reload
	policy      policy.Policy
	sink        evidence.Sink
	timeout     time.Duration
	cred        *credential.Provider // optional; nil ⇒ all targets are passthrough
	approvals   approval.Store       // optional; required when a target sets RequireApproval
	approvalTTL time.Duration
	// dialControl is the net.Dialer.Control installed at the single dial site;
	// it is the resolved-address (SSRF/DNS-rebinding) guard. Defaults to the
	// strict production guard; an Option may relax it for test/dev harnesses.
	dialControl dialControlFunc
	debug       bool // opt-in: mirrors every emitted evidence event to stdout; see WithDebug
}

// SetPolicy atomically replaces the dialer's policy. A control-plane policy
// source calls this to hot-reload without dropping in-flight sessions.
func (d *Dialer) SetPolicy(p policy.Policy) {
	d.mu.Lock()
	d.policy = p
	d.mu.Unlock()
}

func (d *Dialer) currentPolicy() policy.Policy {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.policy
}

// Option configures a Dialer.
type Option func(*Dialer)

// WithCredentialProvider resolves the target's credential mode (inject | prompt
// | passthrough | deny) as part of establishing the connection.
func WithCredentialProvider(p *credential.Provider) Option {
	return func(d *Dialer) { d.cred = p }
}

// WithApprovals gates targets marked RequireApproval behind a four-eyes
// approval: the session blocks (up to ttl) until a second human approves it via
// the control plane, and fails closed on denial/expiry/cancel. store is a leaf
// shared with the API — the data path never imports the control plane.
func WithApprovals(store approval.Store, ttl time.Duration) Option {
	return func(d *Dialer) { d.approvals = store; d.approvalTTL = ttl }
}

// WithDebug mirrors every evidence event (tunnel decision, approval,
// credential resolution) to stdout as it's emitted, in addition to the sink.
// Dev/troubleshooting only — do not enable in production.
func WithDebug(enabled bool) Option {
	return func(d *Dialer) { d.debug = enabled }
}

// emit sends an evidence event, logging (never swallowing) any sink error,
// and — when debug is enabled — also prints the event itself to stdout so a
// live tail of decisions doesn't require reading evidence.jsonl.
func (d *Dialer) emit(e evidence.Event) {
	if d.debug {
		allow := "?"
		if e.Allow != nil {
			allow = fmt.Sprintf("%v", *e.Allow)
		}
		log.Printf("omni-sag: debug: %s user=%s target=%s allow=%s reason=%q", e.Type, e.User, e.Target, allow, e.Reason)
	}
	if err := d.sink.Emit(e); err != nil {
		log.Printf("omni-sag: evidence emit failed (type=%s user=%s target=%s): %v", e.Type, e.User, e.Target, err)
	}
}

// New returns a Dialer bound to a policy and an evidence sink. A credential
// provider is always installed (a fetcher-less default when none is supplied) so
// deny/prompt/passthrough modes are enforced; only inject needs CyberArk.
func New(p policy.Policy, sink evidence.Sink, opts ...Option) *Dialer {
	d := &Dialer{policy: p, sink: sink, timeout: 10 * time.Second, dialControl: guardResolvedAddr}
	for _, opt := range opts {
		opt(d)
	}
	if d.cred == nil {
		d.cred = credential.NewProvider(credential.Config{})
	}
	if d.dialControl == nil {
		d.dialControl = guardResolvedAddr
	}
	return d
}

// CyberArkParams configures credential injection from CyberArk.
type CyberArkParams = credential.CyberArkParams

// NewCyberArkProvider builds a CyberArk-backed credential provider without
// wrapping it in an Option. It exists so the composition root (cmd) can build
// ONE provider and share it between the dialer (via WithCredentialProvider)
// and internal/session (via session.WithCredentialProvider) without itself
// importing internal/credential — that package's CI-enforced import
// allowlist permits only internal/session and internal/dialer.
func NewCyberArkProvider(p CyberArkParams) (*credential.Provider, error) {
	return credential.NewCyberArkProvider(p)
}

// WithCyberArk builds a credential provider that resolves inject-mode
// secrets from CyberArk CCP over mTLS, and returns it as an Option. Errors on
// bad certs.
func WithCyberArk(p CyberArkParams) (Option, error) {
	prov, err := NewCyberArkProvider(p)
	if err != nil {
		return nil, err
	}
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
	decision := d.currentPolicy().Decide(pr, target)

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
	d.emit(evidence.Event{
		Time:        time.Now().UTC(),
		Type:        evidence.TypeTunnelDecision,
		User:        pr.User,
		SourceIP:    sourceIP,
		Target:      target.String(),
		Allow:       evidence.BoolPtr(effectiveAllow),
		Reason:      reason,
		MatchedRole: decision.MatchedRole,
		RecordMode:  string(decision.RecordMode),
	})

	if !decision.Allow {
		return nil, fmt.Errorf("%w: %s", ErrDenied, decision.Reason)
	}
	if forwardRefused {
		return nil, fmt.Errorf("%w: %s", ErrForwardingRefused, target)
	}

	// A four-eyes approval-gated target blocks here until a second human approves
	// it (or it is denied/expires) — before any credential fetch or socket.
	if decision.RequireApproval {
		if err := d.gateApproval(ctx, pr, sourceIP, target); err != nil {
			return nil, err
		}
	}

	// Resolve the target's credential mode before opening a socket, so a deny or
	// an inject fail-closed never leaves a dangling connection. No downgrade.
	if err := d.resolveCredential(ctx, pr, sourceIP, target, decision); err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	conn, err := netDial(dialCtx, "tcp", target.String(), d.dialControl)
	if err != nil {
		return nil, fmt.Errorf("dialer: dial %s: %w", target, err)
	}
	return conn, nil
}

// Peek evaluates policy for pr against target without opening a socket,
// emitting evidence, or gating on approval. It exists so callers outside the
// dial path (the SSH auth callback, deciding whether prompt-mode needs a
// keyboard-interactive round) can inspect a target's credential mode ahead
// of any channel opening. The real authorization decision — the one that
// actually gates a connection — is still made by DialTarget.
func (d *Dialer) Peek(pr policy.Principal, target policy.Target) policy.Decision {
	return d.currentPolicy().Decide(pr, target)
}

// PeekHost is Peek's host-only counterpart, used by the gateway's real-target
// shell/SFTP flow — see policy.Policy.DecideHost's doc comment for why no
// port is available at these call sites.
func (d *Dialer) PeekHost(pr policy.Principal, host string) policy.Decision {
	return d.currentPolicy().DecideHost(pr, host)
}

// gateApproval blocks the session until a four-eyes approval for this target is
// granted. It fails closed: with no store configured, or on denial, expiry, or
// cancellation, it returns ErrApprovalRefused and no socket is opened. Both the
// request and the outcome are evidenced (never a secret).
func (d *Dialer) gateApproval(ctx context.Context, pr policy.Principal, sourceIP string, target policy.Target) error {
	if d.approvals == nil {
		// Target requires approval but no store is wired: refuse, do not admit.
		return fmt.Errorf("%w: approval required but no approval store configured", ErrApprovalRefused)
	}
	req, err := d.approvals.Create(approval.Request{
		Kind:      approval.KindSession,
		Requester: pr.User,
		Subject:   target.String(),
		Reason:    "session access to an approval-gated target",
	}, d.approvalTTL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrApprovalRefused, err)
	}
	d.emitApproval(pr, sourceIP, target, req.ID, "requested", "pending")

	final, werr := d.approvals.Wait(ctx, req.ID)
	if werr != nil { // ctx cancelled etc.
		d.emitApproval(pr, sourceIP, target, req.ID, "refused", string(final.Status))
		return fmt.Errorf("%w: %v", ErrApprovalRefused, werr)
	}
	if !final.Approved(time.Now()) {
		d.emitApproval(pr, sourceIP, target, req.ID, "refused", string(final.EffectiveStatus(time.Now())))
		return fmt.Errorf("%w: request %s is %s", ErrApprovalRefused, req.ID, final.EffectiveStatus(time.Now()))
	}
	d.emitApproval(pr, sourceIP, target, req.ID, "granted", string(approval.StatusApproved))
	return nil
}

func (d *Dialer) emitApproval(pr policy.Principal, sourceIP string, target policy.Target, reqID, outcome, status string) {
	// Allow is left nil (unset) for "requested": a pending request is neither
	// an allow nor a deny yet, unlike "granted"/"refused" which are a final
	// outcome. Mirrors session.go's quarantine-release approval events,
	// which have always left it unset for the equivalent pending case.
	var allow *bool
	switch outcome {
	case "granted":
		allow = evidence.BoolPtr(true)
	case "refused":
		allow = evidence.BoolPtr(false)
	}
	d.emit(evidence.Event{
		Time:      time.Now().UTC(),
		Type:      evidence.TypeApproval,
		User:      pr.User,
		SourceIP:  sourceIP,
		Target:    target.String(),
		Allow:     allow,
		Outcome:   outcome,
		Reason:    "approval " + status,
		ObjectKey: reqID,
	})
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
	d.emit(evidence.Event{
		Time:           time.Now().UTC(),
		Type:           evidence.TypeCredential,
		User:           pr.User,
		SourceIP:       sourceIP,
		Target:         target.String(),
		Allow:          evidence.BoolPtr(cerr == nil),
		CredentialMode: string(mode.Normalize()),
		Outcome:        outcome,
		Reason:         reason,
	})

	if cerr != nil {
		return fmt.Errorf("%w: %v", ErrCredentialRefused, cerr)
	}
	if res.Secret != nil {
		// Just-in-time use then zeroize; never cached, never logged.
		res.Secret.Destroy()
	}
	return nil
}
