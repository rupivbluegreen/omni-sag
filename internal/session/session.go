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
	"log"
	"net"
	"strings"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
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
)

// Server is the SSH front door.
type Server struct {
	sshCfg           *ssh.ServerConfig
	dialer           *dialer.Dialer
	sink             evidence.Sink
	mfa              authn.MFAProvider // optional second factor; nil disables MFA
	handshakeTimeout time.Duration
	sem              chan struct{} // bounds concurrent in-flight handshakes
}

// Option configures a Server.
type Option func(*Server)

// WithMFA gates every successful primary authentication behind a second
// factor. If Verify fails, the login is refused (fail closed).
func WithMFA(p authn.MFAProvider) Option {
	return func(s *Server) { s.mfa = p }
}

// New builds an SSH server that authenticates with auth and forwards through d.
func New(hostKey ssh.Signer, auth authn.Authenticator, d *dialer.Dialer, sink evidence.Sink, opts ...Option) *Server {
	s := &Server{
		dialer:           d,
		sink:             sink,
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
		// Bound the authenticator so a stalled DC/RADIUS cannot park this
		// handshake goroutine indefinitely.
		ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
		defer cancel()

		id, err := auth.Authenticate(ctx, meta.User(), string(password))
		srcIP := hostOf(meta.RemoteAddr())
		if err != nil {
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeAuth,
				User: meta.User(), SourceIP: srcIP,
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
				return nil, errors.New("authentication failed")
			}
		}

		return &ssh.Permissions{Extensions: map[string]string{
			"user":   id.User,
			"groups": strings.Join(id.Groups, groupSep),
		}}, nil
	}
}

// Serve accepts connections on ln until ctx is cancelled or ln is closed.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
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
		// Acquire a handshake slot before spawning, so a flood of stalled
		// connections cannot grow goroutines/FDs without bound. Block here (not
		// in the goroutine) so back-pressure reaches Accept.
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
		go s.handleConn(ctx, conn)
	}
}

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

	for newCh := range chans {
		if newCh.ChannelType() != "direct-tcpip" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only port forwarding (direct-tcpip) is supported")
			continue
		}
		go s.handleDirectTCPIP(ctx, newCh, pr, srcIP)
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

	conn, err := s.dialer.DialTarget(ctx, pr, srcIP, target)
	if err != nil {
		if errors.Is(err, dialer.ErrDenied) {
			_ = newCh.Reject(ssh.Prohibited, "administratively prohibited")
			return
		}
		_ = newCh.Reject(ssh.ConnectionFailed, "connection failed")
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
