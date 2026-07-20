// Package session implements the SSH server, channels, and SFTP subsystem.
//
// Two channel types are accepted: "session" (interactive shell, SFTP
// subsystem) and "direct-tcpip" (port forwarding — ssh -L/-D/-J all realize
// as this channel type). Each direct-tcpip channel is authorized through
// internal/dialer (the single outbound path) before any target socket is
// opened. Every other channel type is rejected.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
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

	debug          bool // opt-in: logs the underlying auth/MFA error to stdout on failure; see WithDebug
	sshDisabled    bool // opt-in: rejects "shell" requests on session channels; see WithSSHDisabled
	tunnelDisabled bool // opt-in: rejects "direct-tcpip" channels (-L port forwarding); see WithTunnelDisabled
	sftpDisabled   bool // opt-in: rejects "subsystem"+"sftp" requests on session channels; see WithSFTPDisabled
	scpEnabled     bool // opt-IN (default false = OFF): only when true are "exec" requests matching "scp -t/-f" (legacy protocol) served; see WithSCPEnabled

	tunnelInspect TunnelInspectConfig // opt-IN (default zero value = disabled): protocol identification on -L/-D/-J tunnels; see WithTunnelInspection
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

// WithSSHDisabled rejects every "shell" request on a "session" channel
// (interactive PTY shell to the real target), regardless of policy. SFTP and
// -L port forwarding are unaffected. False (the default) leaves the shell
// available; policy still separately governs which hosts/ports a shell may
// reach.
func WithSSHDisabled(disabled bool) Option {
	return func(s *Server) { s.sshDisabled = disabled }
}

// WithTunnelDisabled rejects every "direct-tcpip" channel (-L port
// forwarding) outright, regardless of policy. Interactive shell and SFTP are
// unaffected. False (the default) leaves forwarding available; policy still
// separately governs which hosts/ports a tunnel may reach.
func WithTunnelDisabled(disabled bool) Option {
	return func(s *Server) { s.tunnelDisabled = disabled }
}

// WithSFTPDisabled rejects every "subsystem"+"sftp" request on a "session"
// channel, regardless of policy. Interactive shell and -L port forwarding
// are unaffected. False (the default) leaves SFTP available; policy still
// separately governs which hosts/ports SFTP may reach.
func WithSFTPDisabled(disabled bool) Option {
	return func(s *Server) { s.sftpDisabled = disabled }
}

// WithSCPEnabled turns ON the legacy exec-based scp protocol ("exec"
// requests matching "scp -t"/"scp -f"). Unlike the three WithXDisabled
// options, this is opt-IN: false (the default) rejects every scp exec
// request outright, since the legacy protocol adds an exec-channel surface
// that stays off unless an operator explicitly enables it. Default-protocol
// scp (modern clients, no -O flag) is unaffected either way — it rides the
// "subsystem"+"sftp" path governed by WithSFTPDisabled. When enabled, policy
// still separately governs which hosts/ports scp may reach.
func WithSCPEnabled(enabled bool) Option {
	return func(s *Server) { s.scpEnabled = enabled }
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
			loginUser, _ = splitPcodeSelector(loginUser)
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
		loginUser, pcode := splitPcodeSelector(loginUser)
		targetHost, targetPort := splitTargetHostPort(targetHost)
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
			decision := s.dialerPeek(policy.Principal{User: id.User, Groups: id.Groups, SelectedRole: pcode, TargetPort: targetPort}, targetHost)
			if credential.Mode(decision.CredentialMode).Normalize() == credential.ModePrompt {
				groups := strings.Join(id.Groups, groupSep)
				return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
					KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						// Name the actual target account@host (the "%host" the client
						// asked for) rather than a generic "Target", so the user knows
						// which credential is being requested. TargetUser defaults to
						// the gateway login user when the rule does not override it.
						targetUser := decision.TargetUser
						if targetUser == "" {
							targetUser = id.User
						}
						prompt := fmt.Sprintf("%s@%s password: ", targetUser, targetHost)
						answers, err := challenge("", "", []string{prompt}, []bool{false})
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
							"target_port":         strconv.Itoa(targetPort),
							"target_secret_token": token,
							"selected_pcode":      pcode,
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
		if targetPort > 0 {
			perms.Extensions["target_port"] = strconv.Itoa(targetPort)
		}
		if pcode != "" {
			perms.Extensions["selected_pcode"] = pcode
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

	// announcer relays "tunnel open" notices from this connection's -L handlers
	// to a tunnel-keeper session, when the client opens one (a plain
	// "ssh -L … user@gw" with no -N and no target). Per-connection, shared
	// across every channel opened on it; announce is non-blocking (see
	// tunnelAnnouncer), so it never stalls the tunnel data path.
	announcer := newTunnelAnnouncer()

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
		if ct == "direct-tcpip" && s.tunnelDisabled {
			_ = newCh.Reject(ssh.Prohibited, "port forwarding disabled: gateway configuration disables -L tunnels")
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
				s.handleDirectTCPIP(ctx, newCh, pr, srcIP, announcer)
			case "session":
				s.handleSession(ctx, connCtx, newCh, pr, srcIP, sconn, tch, announcer)
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

func (s *Server) handleDirectTCPIP(ctx context.Context, newCh ssh.NewChannel, pr policy.Principal, srcIP string, announcer *tunnelAnnouncer) {
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
	// Tunnel is authorized and connected: tell the keeper session (if the
	// client opened one) so the user sees it succeed. announce is non-blocking
	// and drops when no keeper is draining, so it never stalls the splice below.
	if announcer != nil {
		announcer.announce(tunnelOpenNotice(pr.User, d.HostToConnect, int(d.PortToConnect)))
	}
	go ssh.DiscardRequests(chReqs)
	if s.tunnelInspect.Enabled {
		decision := s.dialer.Peek(pr, target)
		if !s.tunnelInspect.Enforce || len(decision.ExpectProtocol) == 0 {
			// Observe, or enforce with nothing to enforce on this target's
			// rule: tee + classify off the hot path, never gate the splice.
			taps := newTunnelTaps(s.tunnelInspect.MaxPrefixBytes)
			ch2 := &tapConn{ReadWriteCloser: ch, taps: taps, fromClient: true}
			conn2 := &tapConn{ReadWriteCloser: conn, taps: taps, fromClient: false}
			go s.classifyAndEmit(taps, pr, srcIP, target.String(), decision.ExpectProtocol)
			dialer.Splice(ch2, conn2)
			return
		}
		s.enforceTunnel(ch, conn, pr, srcIP, target.String(), decision.ExpectProtocol)
		return
	}
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
	targetPort, _ := strconv.Atoi(perms.Extensions["target_port"])
	return policy.Principal{
		User:              perms.Extensions["user"],
		Groups:            groups,
		TargetHost:        perms.Extensions["target_host"],
		TargetPort:        targetPort,
		TargetSecretToken: perms.Extensions["target_secret_token"],
		SelectedRole:      perms.Extensions["selected_pcode"],
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
