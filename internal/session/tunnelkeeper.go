package session

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

// maxPendingTunnelNotices bounds notices buffered before a keeper attaches, so
// a connection that opens tunnels but never a keeper session (a -N client)
// cannot accumulate notices without limit.
const maxPendingTunnelNotices = 32

// tunnelAnnouncer relays human-readable "tunnel open" notices from a
// connection's direct-tcpip handlers to a tunnel-keeper session — a shell
// session opened with no target host, held open only to carry the client's -L
// forwards (see runTunnelKeeper). It is per-connection: at most one keeper
// attaches, any number of tunnels announce. A -N client opens no session, so
// no keeper attaches and buffered notices are simply discarded on connection
// teardown. All methods are safe for concurrent use.
type tunnelAnnouncer struct {
	mu      sync.Mutex
	w       io.Writer // the attached keeper channel; nil until/unless one attaches
	pending []string  // notices seen before a keeper attached, replayed on attach (bounded)
}

// attach binds the keeper's channel as the notice sink and flushes anything
// that a tunnel announced before the keeper session opened.
func (a *tunnelAnnouncer) attach(w io.Writer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.w = w
	for _, line := range a.pending {
		_, _ = io.WriteString(w, line)
	}
	a.pending = nil
}

// detach unbinds the keeper (its session is ending); later announcements are
// buffered again rather than written to a closing channel.
func (a *tunnelAnnouncer) detach() {
	a.mu.Lock()
	a.w = nil
	a.mu.Unlock()
}

// announce delivers one notice to the attached keeper, or buffers it (bounded)
// if no keeper session has opened yet. Best-effort: it never blocks the tunnel
// data path and never errors.
func (a *tunnelAnnouncer) announce(line string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.w != nil {
		_, _ = io.WriteString(a.w, line)
		return
	}
	if len(a.pending) < maxPendingTunnelNotices {
		a.pending = append(a.pending, line)
	}
}

// tunnelOpenNotice formats the per-tunnel line shown in a keeper window. The
// port is always present (an -L spec always carries a destination port).
func tunnelOpenNotice(user, host string, port int) string {
	return fmt.Sprintf("omni-sag: %s — tunnel open → %s:%d  (keep this window open)\r\n", user, host, port)
}

// runTunnelKeeper holds a targetless "session" channel open so a client's -L
// forwards have a live session to ride on, printing a banner and then a line as
// each tunnel authorizes. It is reached only when a shell is requested with no
// "%host" target selected AND tunneling is enabled — the case a plain
// "ssh -L … user@gw" (no -N, no target) would otherwise hit as a bare "no
// target selected" refusal. It returns when the client closes the session
// (closing the window) or the gateway drains, whichever comes first.
func (s *Server) runTunnelKeeper(ctx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string, announcer *tunnelAnnouncer) {
	defer channel.Close()

	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionStart,
		User: pr.User, SourceIP: srcIP, Detail: "tunnel keeper",
	})

	fmt.Fprint(channel, "omni-sag: no shell target selected — holding this session open for your -L tunnel(s).\r\n")
	fmt.Fprintf(channel, "omni-sag: %s — keep this window open; closing it ends your tunnel(s).\r\n", pr.User)

	announcer.attach(channel)
	defer announcer.detach()

	// A keeper carries no shell I/O of its own: drain the channel so a client
	// closing the window (channel EOF) is noticed, and also unblock on gateway
	// drain (ctx). Either path falls through to the deferred channel.Close().
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, channel)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}

	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
		User: pr.User, SourceIP: srcIP, Detail: "tunnel keeper closed",
	})
}
