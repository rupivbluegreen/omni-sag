package authn

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/vendors/microsoft"
)

// RADIUSConfig configures the RADIUS second-factor provider.
type RADIUSConfig struct {
	Server        string        // host:port of the RADIUS server (NPS/FreeRADIUS)
	Secret        []byte        // shared secret; held as []byte, never logged
	NASIdentifier string        // identifies this gateway to the RADIUS server
	Timeout       time.Duration // per-exchange timeout (default 5s)
	Retries       int           // retransmits per exchange (default 2)
	MaxChallenges int           // max Access-Challenge round-trips (default 3)

	// AllowInteractiveChallenge permits answering Access-Challenge prompts
	// (e.g. OTP) via the request Prompter. When false, any Access-Challenge
	// fails closed. The primary NPS+Entra target is push-based (Accept/Reject)
	// and never needs this. A challenge reply is a one-time token, not the
	// reusable password, and is the only case where User-Password is used.
	AllowInteractiveChallenge bool
}

// RADIUS is an MS-CHAPv2 second-factor provider. It NEVER sends the reusable
// password via PAP (User-Password): the password is consumed locally to build
// an MS-CHAP2-Response. It fails closed on reject, timeout, transport error,
// or an unsupported/unanswerable challenge.
type RADIUS struct {
	cfg  RADIUSConfig
	rand io.Reader // challenge entropy; injectable for tests
}

// NewRADIUS returns a RADIUS provider with sane defaults applied.
func NewRADIUS(cfg RADIUSConfig) *RADIUS {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 2
	}
	if cfg.MaxChallenges <= 0 {
		cfg.MaxChallenges = 3
	}
	if cfg.NASIdentifier == "" {
		cfg.NASIdentifier = "omni-sag"
	}
	return &RADIUS{cfg: cfg, rand: rand.Reader}
}

// Verify runs the MS-CHAPv2 second factor for req.
func (r *RADIUS) Verify(ctx context.Context, req MFARequest) error {
	authChallenge := make([]byte, 16)
	peerChallenge := make([]byte, 16)
	if _, err := io.ReadFull(r.rand, authChallenge); err != nil {
		return fmt.Errorf("%w: entropy: %v", ErrMFA, err)
	}
	if _, err := io.ReadFull(r.rand, peerChallenge); err != nil {
		return fmt.Errorf("%w: entropy: %v", ErrMFA, err)
	}

	ntResp, err := generateNTResponse(authChallenge, peerChallenge, req.Username, string(req.Password))
	if err != nil {
		return fmt.Errorf("%w: ntresponse: %v", ErrMFA, err)
	}

	packet := radius.New(radius.CodeAccessRequest, r.cfg.Secret)
	if err := rfc2865.UserName_SetString(packet, req.Username); err != nil {
		return fmt.Errorf("%w: set username: %v", ErrMFA, err)
	}
	_ = rfc2865.NASIdentifier_SetString(packet, r.cfg.NASIdentifier)
	if req.SourceIP != "" {
		_ = rfc2865.CallingStationID_SetString(packet, req.SourceIP)
	}
	if err := microsoft.MSCHAPChallenge_Set(packet, authChallenge); err != nil {
		return fmt.Errorf("%w: set ms-chap-challenge: %v", ErrMFA, err)
	}
	if err := microsoft.MSCHAP2Response_Set(packet, msChap2Response(0, peerChallenge, ntResp)); err != nil {
		return fmt.Errorf("%w: set ms-chap2-response: %v", ErrMFA, err)
	}

	return r.exchangeLoop(ctx, packet, req)
}

// exchangeLoop performs the initial exchange and follows Access-Challenge
// round-trips up to MaxChallenges. Any non-Accept terminal state fails closed.
func (r *RADIUS) exchangeLoop(ctx context.Context, packet *radius.Packet, req MFARequest) error {
	for i := 0; ; i++ {
		reply, err := r.exchange(ctx, packet)
		if err != nil {
			return fmt.Errorf("%w: exchange: %v", ErrMFA, err)
		}

		switch reply.Code {
		case radius.CodeAccessAccept:
			return nil
		case radius.CodeAccessReject:
			return fmt.Errorf("%w: access-reject", ErrMFA)
		case radius.CodeAccessChallenge:
			if i >= r.cfg.MaxChallenges {
				return fmt.Errorf("%w: too many challenges", ErrMFA)
			}
			next, err := r.answerChallenge(ctx, reply, req)
			if err != nil {
				return err
			}
			packet = next
		default:
			return fmt.Errorf("%w: unexpected code %v", ErrMFA, reply.Code)
		}
	}
}

// answerChallenge builds the follow-up Access-Request for an Access-Challenge.
// It fails closed unless interactive challenge is enabled and a Prompter can
// supply the one-time reply.
func (r *RADIUS) answerChallenge(ctx context.Context, reply *radius.Packet, req MFARequest) (*radius.Packet, error) {
	if !r.cfg.AllowInteractiveChallenge {
		return nil, fmt.Errorf("%w: interactive challenge not permitted", ErrMFA)
	}
	if req.Prompt == nil {
		return nil, fmt.Errorf("%w: challenge issued but connection cannot prompt", ErrMFA)
	}
	msg := rfc2865.ReplyMessage_GetString(reply)
	if msg == "" {
		msg = "Enter your one-time code:"
	}
	answer, err := req.Prompt(ctx, msg, false)
	if err != nil || answer == "" {
		return nil, fmt.Errorf("%w: no challenge answer", ErrMFA)
	}

	next := radius.New(radius.CodeAccessRequest, r.cfg.Secret)
	_ = rfc2865.UserName_SetString(next, req.Username)
	_ = rfc2865.NASIdentifier_SetString(next, r.cfg.NASIdentifier)
	// Echo the server State so it can correlate the challenge.
	if st := rfc2865.State_Get(reply); len(st) > 0 {
		_ = rfc2865.State_Set(next, st)
	}
	// The one-time challenge reply (NOT the reusable password) travels as
	// User-Password. This is the sole PAP-shaped attribute and only for a
	// disposable token, gated by AllowInteractiveChallenge.
	if err := rfc2865.UserPassword_SetString(next, answer); err != nil {
		return nil, fmt.Errorf("%w: set challenge reply: %v", ErrMFA, err)
	}
	return next, nil
}

// exchange sends one packet with retries and per-attempt timeout.
func (r *RADIUS) exchange(ctx context.Context, packet *radius.Packet) (*radius.Packet, error) {
	var lastErr error
	for attempt := 0; attempt <= r.cfg.Retries; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
		reply, err := radius.Exchange(attemptCtx, packet, r.cfg.Server)
		cancel()
		if err == nil {
			return reply, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}
