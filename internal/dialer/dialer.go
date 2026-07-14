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
	"time"

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
}

// New returns a Dialer bound to a policy and an evidence sink.
func New(p policy.Policy, sink evidence.Sink) *Dialer {
	return &Dialer{policy: p, sink: sink, timeout: 10 * time.Second}
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

	dialCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	conn, err := netDial(dialCtx, "tcp", target.String())
	if err != nil {
		return nil, fmt.Errorf("dialer: dial %s: %w", target, err)
	}
	return conn, nil
}
