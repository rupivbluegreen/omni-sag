// Package session (target.go): real-target selection and the gateway's
// second SSH leg to that target (interactive shell / SFTP), as opposed to
// internal/dialer's single leg used for -L port-forwarding.
package session

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// splitTargetUser splits an SSH auth username of the form "user%host" into
// the login username and the target host. "%" was chosen because it cannot
// appear in an AD sAMAccountName and does not collide with "@" (already used
// by the SSH client to address the gateway itself: "ssh alice%host@gw").
// Only the FIRST "%" splits, so a host containing "%" is not truncated.
func splitTargetUser(raw string) (loginUser, targetHost string, hasTarget bool) {
	i := strings.IndexByte(raw, '%')
	if i < 0 {
		return raw, "", false
	}
	return raw[:i], raw[i+1:], true
}

// splitPcodeSelector splits the login-user portion of an SSH auth username on
// its first "+" into the actual login user and an optional pcode selector:
// "alice+p1234" -> ("alice", "p1234"). Like "%", "+" cannot appear in an AD
// sAMAccountName, so it is an unambiguous delimiter that never collides with a
// real username. No "+" ⇒ ("alice", ""). Only the FIRST "+" splits. Callers
// pass the part BEFORE the "%" host split (splitTargetUser runs first), so the
// selector applies connection-wide — to both the shell/SFTP target and any -L
// tunnels opened on the connection.
func splitPcodeSelector(loginUser string) (user, pcode string) {
	i := strings.IndexByte(loginUser, '+')
	if i < 0 {
		return loginUser, ""
	}
	return loginUser[:i], loginUser[i+1:]
}

// splitTargetHostPort splits an optional trailing ":port" off the target host
// from the "%host[:port]" grammar: "10.0.0.5:22" -> ("10.0.0.5", 22),
// "10.0.0.5" -> ("10.0.0.5", 0), "[2001:db8::1]:22" -> ("2001:db8::1", 22).
// A bare host — including a bare IPv6 literal without brackets — yields port 0
// (host-only); only a bracketed IPv6 or a host with a valid 1..65535 numeric
// suffix is treated as carrying a port. Port 0 means "no port given", which the
// policy layer resolves from the matched rule instead.
func splitTargetHostPort(hostspec string) (host string, port int) {
	h, p, err := net.SplitHostPort(hostspec)
	if err != nil {
		return hostspec, 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return hostspec, 0
	}
	return h, n
}

// dialNet is the single dial seam for the target's second SSH leg. A package
// variable solely so tests can substitute a fake transport (mirrors
// internal/dialer's netDial pattern); production always uses net.DialTimeout.
var dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

// emitTargetCredential emits one evidence.TypeCredential event for a
// second-leg auth attempt on the gateway's real-target connection —
// mirroring internal/dialer.Dialer.resolveCredential's field shape exactly
// (mode, target, outcome, reason, never the secret) so the same event type
// covers both the -L tunnel path and this real-target shell/SFTP path.
func (s *Server) emitTargetCredential(ctx context.Context, pr policy.Principal, srcIP, targetHost string, targetPort int, mode credential.Mode, outcome, reason string, allow bool) {
	s.emit(ctx, evidence.Event{
		Time:           time.Now().UTC(),
		Type:           evidence.TypeCredential,
		User:           pr.User,
		SourceIP:       srcIP,
		Target:         net.JoinHostPort(targetHost, strconv.Itoa(targetPort)),
		Allow:          evidence.BoolPtr(allow),
		CredentialMode: string(mode),
		Outcome:        outcome,
		Reason:         reason,
	})
}

// passwordAuthMethods returns the auth methods a password-bearing target leg
// offers (inject and prompt modes): the SSH "password" method AND the
// "keyboard-interactive" method, both answered with the same secret. Offering
// both is required because "password" and "keyboard-interactive" are distinct
// SSH auth methods and a target advertises only one of them — some PAM-MFA
// hosts (e.g. bastion.example.net) disable "password" and accept only
// "keyboard-interactive", so a password-only config fails the handshake with
// "attempted methods [none]". The keyboard-interactive callback answers every
// prompt in the challenge with the secret (such a host sends a single
// echo-off password prompt; a zero-prompt info message — e.g. an MFA push
// notice — yields an empty answer set and simply proceeds).
//
// The secret is held as a Go string inside these closures for the lifetime of
// the handshake — the same residual exposure ssh.Password already carries (it
// too retains the string); see ADR-0002. The caller passes the string inline
// and Destroy()s the backing secret immediately after, exactly as before.
func passwordAuthMethods(secret string) []ssh.AuthMethod {
	kbd := ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = secret
		}
		return answers, nil
	})
	return []ssh.AuthMethod{ssh.Password(secret), kbd} // omni-sag:target-auth-string — see ADR-0002 residual risk
}

// dialTarget opens and authenticates the gateway's second SSH leg to the
// target, per decision's credential mode. It never returns a client on deny
// or on any auth failure — no downgrade to another mode (mirrors
// internal/credential's ErrFailClosed / ErrDenied contract exactly). Every
// attempt — success or failure, for every mode including deny — emits an
// evidence.TypeCredential event (see emitTargetCredential); the secret
// itself is never placed in any field.
//
// secretToken is the prompt-mode stash token from Task 5 (ignored for other
// modes). sconn is the gateway's connection to the CLIENT, needed only for
// passthrough mode's reverse agent channel (may be nil for the other modes,
// including in tests). srcIP is recorded in evidence only.
func (s *Server) dialTarget(ctx context.Context, sconn ssh.Conn, pr policy.Principal, srcIP string, decision policy.Decision, targetHost string, targetPort int, secretToken string) (*ssh.Client, error) {
	targetUser := decision.TargetUser
	if targetUser == "" {
		targetUser = pr.User
	}
	if s.targetHostKeyCB == nil {
		// Fail closed: no silent insecure default (a security review of this
		// plan flagged the earlier draft's InsecureIgnoreHostKey()-on-nil
		// fallback as exactly the silent-downgrade pattern FR-18 exists to
		// prevent elsewhere in this codebase). An operator who genuinely wants
		// the dev-lab-insecure posture must opt in explicitly via
		// WithInsecureTargetHostKey() — see Step 5's config wiring.
		return nil, fmt.Errorf("%w: no target host-key callback configured (set target_known_hosts, or target_insecure_host_key for dev-lab)", credential.ErrFailClosed)
	}
	cfg := &ssh.ClientConfig{
		User:            targetUser,
		HostKeyCallback: s.targetHostKeyCB,
		Timeout:         10 * time.Second,
	}

	mode := credential.Mode(decision.CredentialMode).Normalize()
	switch mode {
	case credential.ModeDeny:
		reason := fmt.Sprintf("credential mode deny for target %s", targetHost)
		s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, string(credential.OutcomeDenied), reason, false)
		return nil, fmt.Errorf("%w: %s", credential.ErrDenied, reason)

	case credential.ModeInject:
		if s.cred == nil {
			reason := fmt.Sprintf("inject configured for %s but no credential provider", targetHost)
			s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, "fail_closed", reason, false)
			return nil, fmt.Errorf("%w: %s", credential.ErrFailClosed, reason)
		}
		res, err := s.cred.Resolve(ctx, credential.Request{
			User: pr.User, Target: net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), Mode: credential.ModeInject,
		})
		if err != nil {
			s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, "fail_closed", err.Error(), false)
			return nil, err // already wraps ErrFailClosed
		}
		s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, string(res.Outcome), res.Reason, true)
		// Residual risk documented in ADR-0002 and this plan's Global
		// Constraints: ssh.Password requires a Go string; the conversion
		// happens only in this expression, never bound to a variable.
		cfg.Auth = passwordAuthMethods(string(res.Secret.Bytes())) // omni-sag:target-auth-string — see ADR-0002 residual risk
		res.Secret.Destroy()

	case credential.ModePrompt:
		sec := s.takeTargetSecret(secretToken)
		if sec == nil {
			reason := fmt.Sprintf("prompt mode for %s but no target password was collected", targetHost)
			s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, "fail_closed", reason, false)
			return nil, fmt.Errorf("%w: %s", credential.ErrFailClosed, reason)
		}
		s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, string(credential.OutcomePrompt), "prompt credential collected", true)
		cfg.Auth = passwordAuthMethods(string(sec.Bytes())) // omni-sag:target-auth-string — see ADR-0002 residual risk
		sec.Destroy()

	case credential.ModePassthrough:
		if sconn == nil {
			reason := fmt.Sprintf("passthrough mode for %s but no client connection to forward from", targetHost)
			s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, "fail_closed", reason, false)
			return nil, fmt.Errorf("%w: %s", credential.ErrFailClosed, reason)
		}
		signers, closer, err := s.forwardedAgentSigners(sconn)
		if err != nil {
			s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, "fail_closed", err.Error(), false)
			return nil, fmt.Errorf("%w: %v", credential.ErrFailClosed, err)
		}
		// closer stays open until dialTarget returns (this defer runs at
		// function exit, not end-of-case) — signers only sign lazily, during
		// ssh.NewClientConn below, over this same forwarded-agent channel.
		defer closer.Close()
		s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, string(credential.OutcomePassthrough), "forwarded agent signers obtained", true)
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}

	default:
		reason := fmt.Sprintf("unknown credential mode %q for %s", decision.CredentialMode, targetHost)
		s.emitTargetCredential(ctx, pr, srcIP, targetHost, targetPort, mode, "fail_closed", reason, false)
		return nil, fmt.Errorf("%w: %s", credential.ErrFailClosed, reason)
	}

	addr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	rawConn, err := dialNet("tcp", addr, cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("session: dial target %s: %w", addr, err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, cfg)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("session: target ssh handshake %s: %w", addr, err)
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

// targetConnCache lazily dials and caches one target *ssh.Client per gateway
// connection, reused across every channel (shell, sftp) opened on that
// connection, and closed once when the connection ends (handleConn's
// cleanup).
type targetConnCache struct {
	mu     sync.Mutex
	client *ssh.Client
	err    error
	dialed bool
}

// getOrDial returns the cached target client, dialing it on first use. A
// prior dial failure is NOT retried within the same connection — a fresh SSH
// connection (fresh channel-open) is required to try again, consistent with
// no-silent-downgrade: a transient failure must not quietly succeed on a
// later attempt using different implicit state.
func (c *targetConnCache) getOrDial(dial func() (*ssh.Client, error)) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dialed {
		c.client, c.err = dial()
		c.dialed = true
	}
	return c.client, c.err
}

func (c *targetConnCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		_ = c.client.Close()
	}
}
