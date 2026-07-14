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
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/ratelimit"
	"github.com/rupivbluegreen/omni-sag/internal/recording"
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
	handshakeTimeout time.Duration
	sem              chan struct{} // bounds concurrent in-flight handshakes

	wg       sync.WaitGroup // tracks active connections for graceful drain
	active   atomic.Int64   // current active connections
	draining atomic.Bool    // set once ctx is cancelled; refuses new connections
}

// WithRegistry registers each authenticated connection in reg so the
// control-plane API can list and terminate it. Nil (the default) disables it.
func WithRegistry(reg *sessions.Registry) Option {
	return func(s *Server) { s.reg = reg }
}

// Option configures a Server.
type Option func(*Server)

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

// WithCredentialProvider resolves inject-mode target credentials for the
// gateway's second SSH leg to a real target (shell/SFTP). Nil (the default)
// means inject-mode targets fail closed (see Task 7's dialTarget).
func WithCredentialProvider(p *credential.Provider) Option {
	return func(s *Server) { s.cred = p }
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
// degraded evidence pipeline is observable. Emitting is non-optional.
func (s *Server) emit(e evidence.Event) {
	if err := s.sink.Emit(e); err != nil {
		log.Printf("omni-sag: evidence emit failed (type=%s user=%s): %v", e.Type, e.User, err)
	}
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
				s.handleSession(ctx, newCh, pr, srcIP)
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
	return policy.Principal{User: perms.Extensions["user"], Groups: groups}
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
