// Package session implements the SSH server, channels, and SFTP subsystem.
//
// Slice 1 supports exactly one thing end-to-end: port forwarding (ssh -L),
// which the client realizes as "direct-tcpip" channels. Each such channel is
// authorized through internal/dialer (the single outbound path) before any
// target socket is opened. Interactive shells, SFTP, and recording arrive in
// later slices; here every other channel type is rejected.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/ratelimit"
	"github.com/rupivbluegreen/omni-sag/internal/recording"
	"github.com/rupivbluegreen/omni-sag/internal/release"
	"github.com/rupivbluegreen/omni-sag/internal/sessions"
	"golang.org/x/crypto/ssh"
)

const (
	groupSep = "\x00" // separator for groups packed into ssh.Permissions

	// defaultHandshakeTimeout bounds how long an unauthenticated client may take
	// to complete (or stall) the SSH handshake — including the auth callback.
	// Without it a slowloris client parks a goroutine and FD indefinitely.
	defaultHandshakeTimeout = 30 * time.Second

	// maxInflightHandshakes caps concurrent in-flight handshakes so a flood of
	// stalled connections cannot exhaust goroutines/FDs. Established sessions do
	// not count against it (the slot is released once the handshake completes).
	maxInflightHandshakes = 128

	// authTimeout bounds the authenticator (LDAP + MFA) so a stalled DC or
	// RADIUS server cannot block the handshake goroutine forever. Kept below
	// defaultHandshakeTimeout so auth fails with a clean error first.
	authTimeout = 20 * time.Second

	// maxChannelsPerConn bounds concurrent channels on a single authenticated
	// connection so one client cannot exhaust goroutines/memory by opening an
	// unbounded number of session/direct-tcpip channels. The handshake cap
	// (maxInflightHandshakes) only covers the unauthenticated phase.
	maxChannelsPerConn = 64
)

// Server is the SSH front door.
type Server struct {
	sshCfg           *ssh.ServerConfig
	dialer           *dialer.Dialer
	sink             evidence.Sink
	mfa              authn.MFAProvider    // optional second factor; nil disables MFA
	recordStore      recording.Store      // optional; when set, interactive sessions are recorded
	inspect          *inspectgate.Gate    // optional; when set, SFTP uploads are content-inspected
	cred             *credential.Provider // optional; used to resolve inject-mode target credentials for real shell/SFTP sessions
	reg              *sessions.Registry   // optional; when set, live sessions are registered for the API
	bfLimiter        *ratelimit.Limiter   // per-source-IP brute-force throttle (always set)
	approvals        approval.Store       // optional; required for SFTP uploads when inspection is enabled (quarantine-release gate)
	approvalTTL      time.Duration
	releases         release.Store // optional; required for the /releases pull-download directory
	releaseTTL       time.Duration // how long an approved release stays retrievable (design default: 6h)
	handshakeTimeout time.Duration
	sem              chan struct{} // bounds concurrent in-flight handshakes

	pendingSecrets sync.Map                                               // token(string) -> *credential.Secret; prompt-mode target passwords awaiting first use
	dialerPeek     func(pr policy.Principal, host string) policy.Decision // non-dialing, host-only decision lookup (typically (*dialer.Dialer).PeekHost); nil disables prompt-mode chaining

	targetHostKeyCB ssh.HostKeyCallback // verifies the target's host key on the second SSH leg; nil => dialTarget fails closed (see WithTargetHostKeyCallback / WithInsecureTargetHostKey)

	wg       sync.WaitGroup // tracks active connections for graceful drain
	active   atomic.Int64   // current active connections
	draining atomic.Bool    // set once ctx is cancelled; refuses new connections

	debug bool // opt-in: logs the underlying auth/MFA error to stdout on failure; see WithDebug
}

// WithRegistry registers each authenticated connection in reg so the
// control-plane API can list and terminate it. Nil (the default) disables it.
func WithRegistry(reg *sessions.Registry) Option {
	return func(s *Server) { s.reg = reg }
}

// Option configures a Server.
type Option func(*Server)

// WithDebug logs the underlying auth/MFA error to stdout on every failure,
// in addition to the generic evidence reason. Evidence itself is unchanged
// (still no failure detail, to avoid a user-enumeration/DC-status oracle) —
// this only affects the operator-facing stdout log. Do not enable in
// production: it defeats the anti-enumeration posture for whoever can read
// the gateway's stdout.
func WithDebug(enabled bool) Option {
	return func(s *Server) { s.debug = enabled }
}

// WithMFA gates every successful primary authentication behind a second
// factor. If Verify fails, the login is refused (fail closed).
func WithMFA(p authn.MFAProvider) Option {
	return func(s *Server) { s.mfa = p }
}

// WithRecording records interactive PTY sessions as asciicast to store and
// emits a signed recording manifest for each. Nil (the default) disables
// recording.
func WithRecording(store recording.Store) Option {
	return func(s *Server) { s.recordStore = store }
}

// WithInspection routes SFTP uploads through the content-inspection gate:
// blocked or unscannable content is quarantined and the transfer is refused.
// Nil (the default) disables inspection.
func WithInspection(g *inspectgate.Gate) Option {
	return func(s *Server) { s.inspect = g }
}

// WithApprovals gates SFTP uploads (when content inspection is enabled)
// behind a KindQuarantineRelease four-eyes approval: the upload blocks on
// Close() until a second human approves it, up to ttl. Mirrors
// dialer.WithApprovals — same Store, same TUI/API queue, different Kind.
func WithApprovals(store approval.Store, ttl time.Duration) Option {
	return func(s *Server) { s.approvals = store; s.approvalTTL = ttl }
}

// WithReleases enables the /releases pull-download SFTP directory: once a
// quarantine-release approval is granted, the uploader retrieves the file
// themselves within ttl instead of it being auto-delivered to the target.
// Nil store (the default) means Filewrite's approved branch has nowhere to
// record a release — see Task 6 for the resulting fail-closed behavior.
func WithReleases(store release.Store, ttl time.Duration) Option {
	return func(s *Server) { s.releases = store; s.releaseTTL = ttl }
}

// WithCredentialProvider resolves inject-mode target credentials for the
// gateway's second SSH leg to a real target (shell/SFTP). Nil (the default)
// means inject-mode targets fail closed (see Task 7's dialTarget).
func WithCredentialProvider(p *credential.Provider) Option {
	return func(s *Server) { s.cred = p }
}

// WithDialerPeek supplies a non-dialing, host-only policy-decision lookup
// (typically (*dialer.Dialer).PeekHost), used at auth time to decide whether
// a prompt-mode target needs a keyboard-interactive round before the
// connection is fully authenticated, and later (interactive.go/sftp.go) to
// resolve the real target's port for the gateway's second SSH leg. It is
// host-only, not Target-based, because the client's auth username
// ("user%host") never carries a port — see policy.Policy.DecideHost's doc
// comment. Nil (the default) disables prompt-mode entirely — such a target's
// channels later fail closed in dialTarget (Task 7).
func WithDialerPeek(peek func(pr policy.Principal, host string) policy.Decision) Option {
	return func(s *Server) { s.dialerPeek = peek }
}

// WithTargetHostKeyCallback verifies the real target's host key on the
// gateway's second SSH leg using cb (typically built from an OpenSSH
// known_hosts file via golang.org/x/crypto/ssh/knownhosts.New). This is the
// production path.
func WithTargetHostKeyCallback(cb ssh.HostKeyCallback) Option {
	return func(s *Server) { s.targetHostKeyCB = cb }
}

// WithInsecureTargetHostKey disables target host-key verification entirely
// (ssh.InsecureIgnoreHostKey()). This is a DELIBERATE, EXPLICIT opt-in for
// the dev lab only — unlike the rest of this option, it cannot be reached by
// simply leaving something unconfigured; a caller must name this function.
// Never call this in a production wiring path.
func WithInsecureTargetHostKey() Option {
	return func(s *Server) { s.targetHostKeyCB = ssh.InsecureIgnoreHostKey() }
}

// WithBruteForceLimiter overrides the default per-source-IP brute-force
// throttle. Passing nil is ignored (the defense cannot be disabled); use this
// only to tune the Config.
func WithBruteForceLimiter(l *ratelimit.Limiter) Option {
	return func(s *Server) {
		if l != nil {
			s.bfLimiter = l
		}
	}
}

// New builds an SSH server that authenticates with auth and forwards through d.
func New(hostKey ssh.Signer, auth authn.Authenticator, d *dialer.Dialer, sink evidence.Sink, opts ...Option) *Server {
	s := &Server{
		dialer:           d,
		sink:             sink,
		bfLimiter:        ratelimit.New(ratelimit.DefaultConfig()),
		handshakeTimeout: defaultHandshakeTimeout,
		sem:              make(chan struct{}, maxInflightHandshakes),
	}
	for _, opt := range opts {
		opt(s)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: s.passwordCallback(auth),
	}
	cfg.AddHostKey(hostKey)
	s.sshCfg = cfg
	return s
}

// emit sends an evidence event, logging (never swallowing) any sink error so a
// degraded evidence pipeline is observable. Emitting is non-optional. When
// debug is enabled, the event itself is also mirrored to stdout so a live
// tail of session activity doesn't require reading evidence.jsonl.
func (s *Server) emit(e evidence.Event) {
	if s.debug {
		allow := "?"
		if e.Allow != nil {
			allow = fmt.Sprintf("%v", *e.Allow)
		}
		log.Printf("omni-sag: debug: %s user=%s allow=%s reason=%q detail=%q", e.Type, e.User, allow, e.Reason, e.Detail)
	}
	if err := s.sink.Emit(e); err != nil {
		log.Printf("omni-sag: evidence emit failed (type=%s user=%s): %v", e.Type, e.User, err)
	}
}

// stashTargetSecret holds sec under a random single-use token until the
// target dial consumes it (Task 7) or the connection closes without ever
// opening a channel (handleConn's cleanup) — either path zeroizes it. Never
// logged, never placed in evidence.
func (s *Server) stashTargetSecret(sec *credential.Secret) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	s.pendingSecrets.Store(token, sec)
	return token
}

// takeTargetSecret retrieves and removes the secret for token. Single-use:
// a second call for the same token returns nil. Returns nil for an unknown
// or already-consumed token.
func (s *Server) takeTargetSecret(token string) *credential.Secret {
	v, ok := s.pendingSecrets.LoadAndDelete(token)
	if !ok {
		return nil
	}
	return v.(*credential.Secret)
}

// passwordCallback verifies the password via the authenticator, emits an auth
// evidence event either way, and packs the resolved identity into the
// connection's permissions for later authorization.
func (s *Server) passwordCallback(auth authn.Authenticator) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		srcIP := hostOf(meta.RemoteAddr())

		// Brute-force defense: if this source has already tripped the failure
		// threshold, refuse before touching the authenticator (fail closed and
		// avoid loading the DC with guesses). The lockout is per-source-IP and
		// bounded, so it slows the guessing source without letting anyone lock a
		// victim out permanently.
		if ok, retry := s.bfLimiter.Allow(srcIP); !ok {
			loginUser, _, _ := splitTargetUser(meta.User())
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeAuth,
				User: loginUser, SourceIP: srcIP,
				Allow: evidence.BoolPtr(false), Reason: "rate limited: too many failed attempts",
				Detail: fmt.Sprintf("locked out, retry after %s", retry.Round(time.Second)),
			})
			return nil, errors.New("authentication failed")
		}

		// Bound the authenticator so a stalled DC/RADIUS cannot park this
		// handshake goroutine indefinitely.
		ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
		defer cancel()

		loginUser, targetHost, hasTarget := splitTargetUser(meta.User())
		id, err := auth.Authenticate(ctx, loginUser, string(password))
		if err != nil {
			s.bfLimiter.RecordFailure(srcIP)
			if s.debug {
				log.Printf("omni-sag: debug: auth failed user=%s source=%s err=%v", loginUser, srcIP, err)
			}
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeAuth,
				User: loginUser, SourceIP: srcIP,
				Allow: evidence.BoolPtr(false), Reason: "authentication failed",
			})
			return nil, errors.New("authentication failed")
		}
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeAuth,
			User: id.User, SourceIP: srcIP,
			Allow: evidence.BoolPtr(true), Reason: "authenticated",
		})

		// Second factor: primary success is not enough when MFA is enabled.
		// The password bytes are reused to build the MS-CHAPv2 response and are
		// not retained. The SSH password path cannot prompt interactively, so a
		// provider that issues an interactive challenge fails closed.
		if s.mfa != nil {
			mfaErr := s.mfa.Verify(ctx, authn.MFARequest{
				Username: id.User,
				Password: password,
				SourceIP: srcIP,
			})
			allowed := mfaErr == nil
			reason := "mfa approved"
			if !allowed {
				reason = "mfa denied"
				if s.debug {
					log.Printf("omni-sag: debug: mfa failed user=%s source=%s err=%v", id.User, srcIP, mfaErr)
				}
			}
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeMFA,
				User: id.User, SourceIP: srcIP,
				Allow: evidence.BoolPtr(allowed), Reason: reason,
			})
			if !allowed {
				// A rejected second factor is still a failed login attempt from
				// this source and counts toward the brute-force threshold.
				s.bfLimiter.RecordFailure(srcIP)
				return nil, errors.New("authentication failed")
			}
		}

		// Fully authenticated: clear any accumulated failure/lockout state so a
		// legitimate user who mistyped is not penalized after a real success.
		s.bfLimiter.RecordSuccess(srcIP)

		if hasTarget && s.dialerPeek != nil {
			// Host-only lookup: the client's auth username ("user%host") never
			// carries a port, so this uses DecideHost (via dialerPeek), not
			// Decide — see policy.Policy.DecideHost's doc comment. Only
			// CredentialMode is consulted here; the resolved Decision.Port is
			// used later, by interactive.go/sftp.go, to dial the real target.
			decision := s.dialerPeek(policy.Principal{User: id.User, Groups: id.Groups}, targetHost)
			if credential.Mode(decision.CredentialMode).Normalize() == credential.ModePrompt {
				groups := strings.Join(id.Groups, groupSep)
				return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
					KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						answers, err := challenge("", "", []string{"Target password: "}, []bool{false})
						if err != nil {
							return nil, errors.New("authentication failed")
						}
						if len(answers) != 1 || answers[0] == "" {
							return nil, errors.New("authentication failed")
						}
						token := s.stashTargetSecret(credential.New([]byte(answers[0])))
						return &ssh.Permissions{Extensions: map[string]string{
							"user":                id.User,
							"groups":              groups,
							"target_host":         targetHost,
							"target_secret_token": token,
						}}, nil
					},
				}}
			}
		}

		perms := &ssh.Permissions{Extensions: map[string]string{
			"user":   id.User,
			"groups": strings.Join(id.Groups, groupSep),
		}}
		if hasTarget {
			perms.Extensions["target_host"] = targetHost
		}
		return perms, nil
	}
}

// Serve accepts connections on ln until ctx is cancelled or ln is closed. On
// cancel it stops accepting (and refuses any connection accepted in the race
// window); existing sessions keep running until they finish or Drain's grace
// period elapses.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		s.draining.Store(true)
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if s.draining.Load() {
			_ = conn.Close() // draining: refuse new connections
			continue
		}
		// Acquire a handshake slot before spawning, so a flood of stalled
		// connections cannot grow goroutines/FDs without bound. Block here (not
		// in the goroutine) so back-pressure reaches Accept.
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
		s.wg.Add(1)
		s.active.Add(1)
		go func(c net.Conn) {
			defer func() {
				s.active.Add(-1)
				s.wg.Done()
			}()
			s.handleConn(ctx, c)
		}(conn)
	}
}

// Drain waits for active connections to finish, up to grace. It returns the
// number of sessions still active if the grace period elapses first (the caller
// then exits, forcibly ending them). Call after Serve returns (i.e. after the
// context is cancelled and the listener is closed).
func (s *Server) Drain(grace time.Duration) (int64, error) {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return 0, nil
	case <-time.After(grace):
		n := s.active.Load()
		return n, fmt.Errorf("drain: %d session(s) still active after %s", n, grace)
	}
}

// ActiveSessions returns the current active connection count.
func (s *Server) ActiveSessions() int64 { return s.active.Load() }

func (s *Server) handleConn(ctx context.Context, raw net.Conn) {
	// Bound the handshake with a deadline, then release the slot and clear the
	// deadline once it completes. A stalled handshake trips the deadline instead
	// of parking forever.
	_ = raw.SetDeadline(time.Now().Add(s.handshakeTimeout))
	sconn, chans, reqs, err := ssh.NewServerConn(raw, s.sshCfg)
	_ = raw.SetDeadline(time.Time{})
	<-s.sem // release the handshake slot (success or failure)
	if err != nil {
		_ = raw.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	if tok := sconn.Permissions.Extensions["target_secret_token"]; tok != "" {
		defer func() {
			if sec := s.takeTargetSecret(tok); sec != nil {
				sec.Destroy() // connection closed without ever opening a channel that consumed it
			}
		}()
	}

	pr := principalFrom(sconn.Permissions)
	srcIP := hostOf(sconn.RemoteAddr())

	// Register the live session so the control-plane API can list/terminate it.
	// terminate closes the SSH connection; the data path stays independent of
	// the API (this registry is a leaf package neither imports).
	var sessID string
	if s.reg != nil {
		var dereg func()
		sessID, dereg = s.reg.Register(sessions.Info{User: pr.User, SourceIP: srcIP}, func() error {
			return sconn.Close()
		})
		defer dereg()
	}

	// tch lazily dials and caches one target *ssh.Client per connection,
	// shared across every channel (shell, sftp) opened on it, and closed once
	// here when the connection ends.
	tch := &targetConnCache{}
	defer tch.close()

	// connCtx is cancelled either when the caller's ctx is (gateway
	// shutdown/drain) or when this specific client connection goes away
	// (sconn.Wait returns), whichever comes first. It exists for SFTP's
	// quarantine-release approval wait (runSFTP/quarantineWriteHandle.Close,
	// sftp.go): that wait can otherwise block for the full approval TTL even
	// after the client that requested the upload has vanished. One goroutine
	// here, shared by every channel on this connection (however many SFTP
	// subsystems get opened sequentially on it), rather than one per
	// runSFTP invocation — sconn.Wait() blocks until the whole connection
	// shuts down, so a per-invocation version would accumulate one
	// live-until-teardown goroutine per sequential SFTP open on a
	// long-lived connection.
	connCtx, cancelConnCtx := context.WithCancel(ctx)
	defer cancelConnCtx()
	go func() {
		_ = sconn.Wait()
		cancelConnCtx()
	}()

	// Bound concurrent channels per connection; reject beyond the cap.
	chSem := make(chan struct{}, maxChannelsPerConn)
	for newCh := range chans {
		ct := newCh.ChannelType()
		if ct != "direct-tcpip" && ct != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		select {
		case chSem <- struct{}{}:
		default:
			_ = newCh.Reject(ssh.ResourceShortage, "too many concurrent channels")
			continue
		}
		go func(newCh ssh.NewChannel, ct string) {
			if s.reg != nil {
				s.reg.AddChannels(sessID, 1)
				// Publish a live supervision event so an attached supervisor sees
				// the channel open in real time.
				s.reg.Publish(sessID, sessions.Event{Kind: "channel_open", Detail: ct})
			}
			// A panic in one channel handler must not crash the whole gateway
			// and drop every other live session; contain it to this channel.
			defer func() {
				if s.reg != nil {
					s.reg.AddChannels(sessID, -1)
					s.reg.Publish(sessID, sessions.Event{Kind: "channel_close", Detail: ct})
				}
				<-chSem
				if r := recover(); r != nil {
					log.Printf("omni-sag: recovered panic in %s channel handler (user=%s): %v", ct, pr.User, r)
				}
			}()
			switch ct {
			case "direct-tcpip":
				s.handleDirectTCPIP(ctx, newCh, pr, srcIP)
			case "session":
				s.handleSession(ctx, connCtx, newCh, pr, srcIP, sconn, tch)
			}
		}(newCh, ct)
	}
}

// directTCPIP is the RFC 4254 §7.2 channel-open payload for -L forwarding.
type directTCPIP struct {
	HostToConnect  string
	PortToConnect  uint32
	OriginatorIP   string
	OriginatorPort uint32
}

func (s *Server) handleDirectTCPIP(ctx context.Context, newCh ssh.NewChannel, pr policy.Principal, srcIP string) {
	var d directTCPIP
	if err := ssh.Unmarshal(newCh.ExtraData(), &d); err != nil {
		_ = newCh.Reject(ssh.Prohibited, "malformed forwarding request")
		return
	}
	target := policy.Target{Host: d.HostToConnect, Port: int(d.PortToConnect)}

	// forwarding=true: refused on full-recording targets (PRD FR-10).
	conn, err := s.dialer.DialTarget(ctx, pr, srcIP, target, true)
	if err != nil {
		switch {
		case errors.Is(err, dialer.ErrForwardingRefused):
			_ = newCh.Reject(ssh.Prohibited, "forwarding refused: target requires full session recording")
		case errors.Is(err, dialer.ErrDenied):
			_ = newCh.Reject(ssh.Prohibited, "administratively prohibited")
		case errors.Is(err, dialer.ErrCredentialRefused):
			_ = newCh.Reject(ssh.Prohibited, "credential refused")
		default:
			_ = newCh.Reject(ssh.ConnectionFailed, "connection failed")
		}
		return
	}

	ch, chReqs, err := newCh.Accept()
	if err != nil {
		_ = conn.Close()
		return
	}
	go ssh.DiscardRequests(chReqs)
	dialer.Splice(ch, conn)
}

func principalFrom(perms *ssh.Permissions) policy.Principal {
	if perms == nil {
		return policy.Principal{}
	}
	var groups []string
	if g := perms.Extensions["groups"]; g != "" {
		groups = strings.Split(g, groupSep)
	}
	return policy.Principal{
		User:              perms.Extensions["user"],
		Groups:            groups,
		TargetHost:        perms.Extensions["target_host"],
		TargetSecretToken: perms.Extensions["target_secret_token"],
	}
}

func hostOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr.String()); err == nil {
		return h
	}
	return addr.String()
}
