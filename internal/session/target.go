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

// dialNet is the single dial seam for the target's second SSH leg. A package
// variable solely so tests can substitute a fake transport (mirrors
// internal/dialer's netDial pattern); production always uses net.DialTimeout.
var dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

// dialTarget opens and authenticates the gateway's second SSH leg to the
// target, per decision's credential mode. It never returns a client on deny
// or on any auth failure — no downgrade to another mode (mirrors
// internal/credential's ErrFailClosed / ErrDenied contract exactly).
//
// secretToken is the prompt-mode stash token from Task 5 (ignored for other
// modes). sconn is the gateway's connection to the CLIENT, needed only for
// passthrough mode's reverse agent channel (may be nil for the other modes,
// including in tests).
func (s *Server) dialTarget(ctx context.Context, sconn ssh.Conn, pr policy.Principal, decision policy.Decision, targetHost string, targetPort int, secretToken string) (*ssh.Client, error) {
	targetUser := decision.TargetUser
	if targetUser == "" {
		targetUser = pr.User
	}
	hostKeyCB := s.targetHostKeyCB
	if hostKeyCB == nil {
		hostKeyCB = ssh.InsecureIgnoreHostKey() // dev-lab default; see WithTargetKnownHosts
	}
	cfg := &ssh.ClientConfig{
		User:            targetUser,
		HostKeyCallback: hostKeyCB,
		Timeout:         10 * time.Second,
	}

	mode := credential.Mode(decision.CredentialMode).Normalize()
	switch mode {
	case credential.ModeDeny:
		return nil, fmt.Errorf("%w: credential mode deny for target %s", credential.ErrDenied, targetHost)

	case credential.ModeInject:
		if s.cred == nil {
			return nil, fmt.Errorf("%w: inject configured for %s but no credential provider", credential.ErrFailClosed, targetHost)
		}
		res, err := s.cred.Resolve(ctx, credential.Request{
			User: pr.User, Target: net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), Mode: credential.ModeInject,
		})
		if err != nil {
			return nil, err // already wraps ErrFailClosed
		}
		// Residual risk documented in ADR-0002 and this plan's Global
		// Constraints: ssh.Password requires a Go string; the conversion
		// happens only in this expression, never bound to a variable.
		cfg.Auth = []ssh.AuthMethod{ssh.Password(string(res.Secret.Bytes()))} // omni-sag:target-auth-string — see ADR-0002 residual risk
		res.Secret.Destroy()

	case credential.ModePrompt:
		sec := s.takeTargetSecret(secretToken)
		if sec == nil {
			return nil, fmt.Errorf("%w: prompt mode for %s but no target password was collected", credential.ErrFailClosed, targetHost)
		}
		cfg.Auth = []ssh.AuthMethod{ssh.Password(string(sec.Bytes()))} // omni-sag:target-auth-string — see ADR-0002 residual risk
		sec.Destroy()

	case credential.ModePassthrough:
		if sconn == nil {
			return nil, fmt.Errorf("%w: passthrough mode for %s but no client connection to forward from", credential.ErrFailClosed, targetHost)
		}
		signers, closer, err := s.forwardedAgentSigners(sconn)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", credential.ErrFailClosed, err)
		}
		// closer stays open until dialTarget returns (this defer runs at
		// function exit, not end-of-case) — signers only sign lazily, during
		// ssh.NewClientConn below, over this same forwarded-agent channel.
		defer closer.Close()
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}

	default:
		return nil, fmt.Errorf("%w: unknown credential mode %q for %s", credential.ErrFailClosed, decision.CredentialMode, targetHost)
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
