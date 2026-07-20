package session

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/dialer"
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
// evidence event. It never blocks or alters the splice.
//
// This is the observe path — also used, with an empty expect, for an
// enforce-mode tunnel whose matched rule sets no expect_protocol (nothing to
// enforce, so it is observe-equivalent). When expect is non-empty this is
// the dry-run path (global enforce: false): decideEnforce may report a
// would-block, logged as Allow=false with "dry-run" in Detail, but the
// splice is never gated — only real enforce (holdAndClassify) can do that.
func (s *Server) classifyAndEmit(taps *tunnelTaps, pr policy.Principal, srcIP, target string, expect []string) {
	select {
	case <-taps.sig:
		time.Sleep(tunnelSettle)
	case <-time.After(s.tunnelInspect.ClassifyTimeout):
	}
	client, server := taps.snapshot()
	res := protoident.Classify(client, server)
	allow, reason := decideEnforce(res, expect, s.tunnelInspect.UnknownDeny)
	detail := res.Detail
	if !allow {
		if detail == "" {
			detail = "dry-run"
		} else {
			detail = "dry-run: " + detail
		}
	}
	s.emit(evidence.Event{
		Type:     evidence.TypeTunnelProtocol,
		User:     pr.User,
		SourceIP: srcIP,
		Target:   target,
		Protocol: string(res.Protocol),
		Detail:   detail,
		Allow:    evidence.BoolPtr(allow),
		Reason:   reason,
	})
}

// decideEnforce reports whether res's classified protocol is permitted under
// expect (a matched rule's expect_protocol list) and unknownDeny, plus a
// human reason (empty when allowed). An empty expect means the matched rule
// enforces nothing — always allowed regardless of the detected protocol.
func decideEnforce(res protoident.Result, expect []string, unknownDeny bool) (allow bool, reason string) {
	if len(expect) == 0 {
		return true, ""
	}
	if res.Protocol == protoident.Unknown {
		if unknownDeny {
			return false, fmt.Sprintf("protocol could not be identified within budget/timeout (expected %v)", expect)
		}
		return true, ""
	}
	for _, want := range expect {
		if want == string(res.Protocol) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("protocol %s not permitted on this tunnel (expected %v)", res.Protocol, expect)
}

// asyncChunk is one Read result handed from an asyncReader's background
// goroutine to its consumer.
type asyncChunk struct {
	b   []byte
	err error
}

// asyncReader runs exactly one background goroutine that continuously reads
// from inner, so a caller that only wants to peek at the first bytes under a
// deadline (holdAndClassify) can later hand the SAME asyncReader to Splice
// for the rest of the tunnel's life without ever having two goroutines
// racing to Read the same underlying conn/channel.
type asyncReader struct {
	ch  chan asyncChunk
	buf []byte // bytes received but not yet returned via Read
	err error  // sticky error once inner.Read errors or returns EOF
}

func newAsyncReader(inner io.Reader) *asyncReader {
	r := &asyncReader{ch: make(chan asyncChunk, 1)}
	go func() {
		for {
			b := make([]byte, 4096)
			n, err := inner.Read(b)
			r.ch <- asyncChunk{b: b[:n], err: err}
			if err != nil {
				return
			}
		}
	}()
	return r
}

func (r *asyncReader) absorb(c asyncChunk) {
	if len(c.b) > 0 {
		r.buf = append(r.buf, c.b...)
	}
	if c.err != nil && r.err == nil {
		r.err = c.err
	}
}

// classifyView returns the bytes seen so far, capped at budget — the
// classification budget bounds how much protoident looks at, not how much of
// the live stream is retained for forwarding (buf itself is never truncated).
func (r *asyncReader) classifyView(budget int) []byte {
	if len(r.buf) > budget {
		return r.buf[:budget]
	}
	return r.buf
}

// Read drains buf first (the held prefix, if any), then blocks on the
// background goroutine like an ordinary synchronous Read.
func (r *asyncReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 && r.err == nil {
		r.absorb(<-r.ch)
	}
	if len(r.buf) == 0 {
		return 0, r.err
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// holdAndClassify peeks at both sides' opening bytes concurrently — via each
// side's already-running asyncReader — until protoident matches a signature,
// both sides reach budget, or timeout elapses. It returns as soon as EITHER
// side alone yields a match, so a client-first protocol classifies without
// ever waiting on a target that stays silent until spoken to (the
// client-first deadlock guard) — and symmetrically for a server-first one.
func holdAndClassify(clientAR, serverAR *asyncReader, budget int, timeout time.Duration) protoident.Result {
	deadline := time.After(timeout)
	for {
		res := protoident.Classify(clientAR.classifyView(budget), serverAR.classifyView(budget))
		if res.Protocol != protoident.Unknown {
			return res
		}
		if len(clientAR.buf) >= budget && len(serverAR.buf) >= budget {
			return res
		}
		select {
		case c := <-clientAR.ch:
			clientAR.absorb(c)
		case c := <-serverAR.ch:
			serverAR.absorb(c)
		case <-deadline:
			return protoident.Classify(clientAR.classifyView(budget), serverAR.classifyView(budget))
		}
	}
}

// holdConn is the enforce-mode splice endpoint: reads continue from an
// asyncReader (replaying whatever holdAndClassify already buffered, then the
// live stream), writes and Close go straight to the real conn/channel.
type holdConn struct {
	reader *asyncReader
	writer io.Writer
	closer io.Closer
}

func (c *holdConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *holdConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *holdConn) Close() error                { return c.closer.Close() }

func (c *holdConn) CloseWrite() error {
	if cw, ok := c.writer.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// enforceTunnel holds the opening bytes of ch/conn until classified, then
// either allows (replaying the held bytes into a normal splice) or, on
// mismatch/unknown-deny, terminates the tunnel without ever forwarding the
// held bytes to either side.
func (s *Server) enforceTunnel(ch io.ReadWriteCloser, conn io.ReadWriteCloser, pr policy.Principal, srcIP, target string, expect []string) {
	budget := s.tunnelInspect.MaxPrefixBytes
	clientAR := newAsyncReader(ch)
	serverAR := newAsyncReader(conn)
	res := holdAndClassify(clientAR, serverAR, budget, s.tunnelInspect.ClassifyTimeout)
	allow, reason := decideEnforce(res, expect, s.tunnelInspect.UnknownDeny)
	s.emit(evidence.Event{
		Type:     evidence.TypeTunnelProtocol,
		User:     pr.User,
		SourceIP: srcIP,
		Target:   target,
		Protocol: string(res.Protocol),
		Detail:   res.Detail,
		Allow:    evidence.BoolPtr(allow),
		Reason:   reason,
	})
	if !allow {
		_ = ch.Close()
		_ = conn.Close()
		return
	}
	a := &holdConn{reader: clientAR, writer: ch, closer: ch}
	b := &holdConn{reader: serverAR, writer: conn, closer: conn}
	dialer.Splice(a, b)
}
