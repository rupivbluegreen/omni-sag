package session

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

// maxPendingTunnelNotices bounds notices buffered for a keeper that is not
// draining yet — a tunnel that authorized before the keeper session opened, or
// a -N client that opens no keeper at all. Beyond this, notices are dropped
// rather than exerting any backpressure on the tunnel data path.
const maxPendingTunnelNotices = 32

// tunnelAnnouncer carries best-effort "tunnel open" notices from a
// connection's direct-tcpip handlers to a tunnel-keeper session (a targetless
// shell held open to carry -L forwards; see runTunnelKeeper).
//
// It is a bounded, non-blocking channel by design: announce() NEVER blocks the
// caller — the tunnel data path — and drops notices when no keeper is draining
// or the buffer is full. The actual (possibly blocking) write to the client's
// channel happens only in the keeper's own goroutine, so a client that has
// paused its terminal can never stall a tunnel or another connection. One
// announcer per connection; the design assumes at most one keeper drains it
// (two would merely split notices between them — harmless, never wedged).
type tunnelAnnouncer struct {
	notices chan string
}

func newTunnelAnnouncer() *tunnelAnnouncer {
	return &tunnelAnnouncer{notices: make(chan string, maxPendingTunnelNotices)}
}

// announce queues a notice for the keeper without ever blocking. If no keeper
// is draining, or the buffer is full, the notice is dropped — it is
// best-effort UX, never a backpressure point on the tunnel it describes.
func (a *tunnelAnnouncer) announce(line string) {
	select {
	case a.notices <- line:
	default: // no keeper draining, or buffer full — drop
	}
}

// tunnelOpenNotice formats the per-tunnel line shown in a keeper window. The
// port is always present (an -L spec always carries a destination port).
func tunnelOpenNotice(user, host string, port int) string {
	return fmt.Sprintf("omni-sag: %s — tunnel open → %s:%d  (keep this window open)\r\n", user, host, port)
}

// runTunnelKeeper holds a targetless "session" channel open so a client's -L
// forwards have a live session to ride on, printing a banner and then a line
// as each tunnel authorizes. It is reached only when a shell is requested with
// no "%host" target selected AND tunneling is enabled — the case a plain
// "ssh -L … user@gw" (no -N, no target) would otherwise hit as a bare "no
// target selected" refusal. It dials no target and records nothing. It returns
// when the client closes the session (closing the window) or the gateway
// drains, whichever comes first.
func (s *Server) runTunnelKeeper(ctx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string, announcer *tunnelAnnouncer) {
	defer channel.Close()

	s.emit(ctx, evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionStart,
		User: pr.User, SourceIP: srcIP, Detail: "tunnel keeper",
	})

	fmt.Fprint(channel, "omni-sag: no shell target selected — holding this session open for your -L tunnel(s).\r\n")
	fmt.Fprint(channel, "omni-sag: (for an interactive shell instead, reconnect as user%host@gateway — or user+pcode%host to scope to one role)\r\n")
	fmt.Fprintf(channel, "omni-sag: %s — keep this window open; press Ctrl-C (or close it) to end your tunnel(s).\r\n", pr.User)

	// Close the channel on gateway drain so a keeper blocked writing to a
	// client that paused its terminal unblocks and returns promptly. stop ends
	// this watcher when the keeper exits for any other reason.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = channel.Close()
		case <-stop:
		}
	}()

	// The keeper carries no shell input of its own; draining the channel's
	// reads lets a client closing the window (channel EOF) end the keeper. With
	// a PTY the client forwards Ctrl-C (ETX) and Ctrl-D (EOT) as bytes rather
	// than closing the channel, so treat either as "quit" too — otherwise the
	// user has no in-band way to end the session (plain io.Discard would just
	// swallow them).
	clientGone := make(chan struct{})
	go func() {
		defer close(clientGone)
		buf := make([]byte, 256)
		for {
			n, err := channel.Read(buf)
			for _, b := range buf[:n] {
				if b == 0x03 || b == 0x04 { // Ctrl-C / Ctrl-D
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Drain notices to the client here, in the keeper's own goroutine: the
	// write may block if the client is not reading, but that only ever stalls
	// THIS goroutine — never the tunnel data path (announce is non-blocking).
	for keep := true; keep; {
		select {
		case line := <-announcer.notices:
			if _, err := io.WriteString(channel, line); err != nil {
				keep = false // channel closed/broken
			}
		case <-clientGone:
			keep = false
		}
	}

	s.emit(ctx, evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
		User: pr.User, SourceIP: srcIP, Detail: "tunnel keeper closed",
	})
}
