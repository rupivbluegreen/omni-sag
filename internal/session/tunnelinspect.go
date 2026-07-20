package session

import (
	"io"
	"sync"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/protoident"
)

// TunnelInspectConfig configures tunnel protocol identification for a
// Server. The zero value (Enabled: false) leaves handleDirectTCPIP's splice
// byte-for-byte unchanged — this feature is opt-in.
type TunnelInspectConfig struct {
	Enabled         bool
	MaxPrefixBytes  int
	ClassifyTimeout time.Duration
	Enforce         bool // false = observe/dry-run only, even with expect_protocol rules
	UnknownDeny     bool // enforce mode only: terminate (true) or allow (false, default) on unknown
}

// WithTunnelInspection enables tunnel protocol identification (Phase 1
// observe, and, when cfg.Enforce is true, Phase 2 enforce) on -L/-D/-J
// tunnels.
func WithTunnelInspection(cfg TunnelInspectConfig) Option {
	return func(s *Server) { s.tunnelInspect = cfg }
}

// tunnelTaps buffers up to budget opening bytes per direction, teed off the
// live splice, and signals sig once either side has produced its first
// bytes. It never gates a read — record is called after the real Read
// already returned data.
type tunnelTaps struct {
	mu             sync.Mutex
	client, server []byte
	budget         int
	sig            chan struct{}
	sigOnce        sync.Once
}

func newTunnelTaps(budget int) *tunnelTaps {
	return &tunnelTaps{budget: budget, sig: make(chan struct{})}
}

func (t *tunnelTaps) record(fromClient bool, p []byte) {
	t.mu.Lock()
	buf := &t.server
	if fromClient {
		buf = &t.client
	}
	if n := t.budget - len(*buf); n > 0 {
		if n > len(p) {
			n = len(p)
		}
		*buf = append(*buf, p[:n]...)
	}
	t.mu.Unlock()
	t.sigOnce.Do(func() { close(t.sig) })
}

func (t *tunnelTaps) snapshot() (client, server []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.client...), append([]byte(nil), t.server...)
}

// tapConn wraps an io.ReadWriteCloser, teeing bytes read into taps. Read
// never blocks on or alters what the caller sees — the tee is a copy taken
// after the real Read already returned.
type tapConn struct {
	io.ReadWriteCloser
	taps       *tunnelTaps
	fromClient bool
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	if n > 0 {
		c.taps.record(c.fromClient, p[:n])
	}
	return n, err
}

// CloseWrite forwards the half-close to the inner conn when it supports one
// (e.g. *net.TCPConn), so dialer.Splice's closeWrite still propagates EOF to
// the peer through the tap.
func (c *tapConn) CloseWrite() error {
	if cw, ok := c.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// tunnelSettle is a short grace period after the first tapped bytes arrive,
// letting a message that lands in more than one Read accumulate before
// classification snapshots the buffers. It never gates the splice — only
// classifyAndEmit, which runs off the hot path.
const tunnelSettle = 20 * time.Millisecond

// classifyAndEmit waits for the first opening bytes (or the classify
// timeout), classifies them, and emits exactly one TypeTunnelProtocol
// evidence event. It never blocks or alters the splice — observe mode only.
func (s *Server) classifyAndEmit(taps *tunnelTaps, pr policy.Principal, srcIP, target string) {
	select {
	case <-taps.sig:
		time.Sleep(tunnelSettle)
	case <-time.After(s.tunnelInspect.ClassifyTimeout):
	}
	client, server := taps.snapshot()
	res := protoident.Classify(client, server)
	s.emit(evidence.Event{
		Type:     evidence.TypeTunnelProtocol,
		User:     pr.User,
		SourceIP: srcIP,
		Target:   target,
		Protocol: string(res.Protocol),
		Detail:   res.Detail,
		Allow:    evidence.BoolPtr(true),
	})
}
