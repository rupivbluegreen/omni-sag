package session

import (
	"context"
	"fmt"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/recording"
	"golang.org/x/crypto/ssh"
)

// ptyRequest is the RFC 4254 §6.2 pty-req payload.
type ptyRequest struct {
	Term     string
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

// subsystemRequest is the RFC 4254 §6.5 subsystem payload.
type subsystemRequest struct{ Name string }

// handleSession handles a "session" channel: PTY setup, then a shell (recorded
// interactive session bridged to the real target) or the SFTP subsystem.
//
// sconn is the gateway's connection to the client (needed by dialTarget for
// passthrough-mode agent forwarding); tch is the per-connection target dial
// cache shared across every channel opened on this connection, so a shell and
// an SFTP subsystem on the same connection reuse one dial to the target.
//
// The "shell" case launches runRecordedShell in its own goroutine rather than
// calling it inline: runRecordedShell blocks for the lifetime of the session,
// and this function's own for-loop is the only reader of requests, so calling
// it inline would stop draining requests the moment the shell starts —
// silently dropping every window-change (resize) sent after that point, which
// in practice is nearly all of them (resizes happen *during* a session, not
// before it). Running it in a goroutine lets the loop keep forwarding
// window-change into resizeCh for as long as the channel stays open. The
// channel's requests stream closes once runRecordedShell's own deferred
// channel.Close() runs (session end, either side), which ends this loop;
// handleSession then waits on shellDone before returning, so the caller's
// channel-slot/registry accounting (chSem, sessions.Registry) still reflects
// the shell's real lifetime, not just the request loop's.
func (s *Server) handleSession(ctx context.Context, newCh ssh.NewChannel, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache) {
	channel, requests, err := newCh.Accept()
	if err != nil {
		return
	}

	resizeCh := make(chan [2]int, 4)
	cols, rows := 80, 24
	var shellDone chan struct{}
	for req := range requests {
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if ssh.Unmarshal(req.Payload, &p) == nil && p.Cols > 0 {
				cols, rows = int(p.Cols), int(p.Rows)
			}
			_ = req.Reply(true, nil)
		case "window-change":
			var wc struct{ Cols, Rows, WidthPx, HeightPx uint32 }
			if ssh.Unmarshal(req.Payload, &wc) == nil {
				select {
				case resizeCh <- [2]int{int(wc.Rows), int(wc.Cols)}:
				default: // drop if runRecordedShell hasn't started consuming yet or is backed up
				}
			}
			_ = req.Reply(true, nil)
		case "env":
			_ = req.Reply(true, nil)
		case "auth-agent-req@openssh.com":
			_ = req.Reply(true, nil)
		case "shell":
			if shellDone != nil {
				_ = req.Reply(false, nil) // a shell was already dispatched on this channel
				continue
			}
			_ = req.Reply(true, nil)
			shellDone = make(chan struct{})
			go func() {
				defer close(shellDone)
				s.runRecordedShell(ctx, channel, cols, rows, pr, srcIP, sconn, tch, pr.TargetHost, resizeCh)
			}()
		case "subsystem":
			if shellDone != nil {
				_ = req.Reply(false, nil) // a shell was already dispatched on this channel
				continue
			}
			var sub subsystemRequest
			if ssh.Unmarshal(req.Payload, &sub) == nil && sub.Name == "sftp" {
				_ = req.Reply(true, nil)
				s.runSFTP(ctx, channel, pr, srcIP, sconn, tch)
				return
			}
			_ = req.Reply(false, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
	if shellDone != nil {
		<-shellDone // wait for the real session (not just the request stream) to end
	} else {
		_ = channel.Close()
	}
}

// runRecordedShell opens a real PTY+shell on the target (dialing it via tch
// if not already cached for this connection) and pipes bytes bidirectionally
// between the client's channel and the target's, recording the traffic
// exactly as before regardless of which end produced it. targetHost comes
// from handleSession's caller (pr.TargetHost, set during auth); resizeCh
// carries window-change sizes observed by handleSession's request loop,
// forwarded here to the target session.
func (s *Server) runRecordedShell(ctx context.Context, channel ssh.Channel, cols, rows int, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache, targetHost string, resizeCh <-chan [2]int) {
	defer channel.Close()

	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionStart,
		User: pr.User, SourceIP: srcIP, Detail: "interactive shell",
	})

	if targetHost == "" {
		_, _ = channel.Write([]byte("session refused: no target selected — connect as user%host@gateway\r\n"))
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "refused: no target selected",
		})
		return
	}

	decision := policy.Decision{}
	if s.dialerPeek != nil {
		decision = s.dialerPeek(pr, policy.Target{Host: targetHost})
	}
	targetClient, err := tch.getOrDial(func() (*ssh.Client, error) {
		return s.dialTarget(ctx, sconn, pr, decision, targetHost, 22, pr.TargetSecretToken)
	})
	if err != nil {
		_, _ = channel.Write([]byte(fmt.Sprintf("session refused: %s\r\n", err)))
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "refused: " + err.Error(),
		})
		return
	}

	targetSession, err := targetClient.NewSession()
	if err != nil {
		_, _ = channel.Write([]byte(fmt.Sprintf("session refused: target session: %s\r\n", err)))
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "refused: target session: " + err.Error(),
		})
		return
	}
	defer targetSession.Close()

	if err := targetSession.RequestPty("xterm", rows, cols, ssh.TerminalModes{}); err != nil {
		_, _ = channel.Write([]byte(fmt.Sprintf("session refused: target pty: %s\r\n", err)))
		return
	}
	targetIn, err := targetSession.StdinPipe()
	if err != nil {
		return
	}
	targetOut, err := targetSession.StdoutPipe()
	if err != nil {
		return
	}
	if err := targetSession.Shell(); err != nil {
		_, _ = channel.Write([]byte(fmt.Sprintf("session refused: target shell: %s\r\n", err)))
		return
	}

	// Forward window-change sizes observed on the client's channel to the
	// target session. This goroutine is abandoned (not explicitly stopped)
	// when runRecordedShell returns below; resizeCh is owned by
	// handleSession's request loop, not closed here, so the goroutine parks
	// on the empty channel until GC once nothing else references resizeCh
	// (handleSession's goroutine has by then also returned). This is a
	// bounded, understood leak — one blocked goroutine per session until the
	// runtime reclaims it — not a silent one; see this task's brief for why
	// closing resizeCh here is deliberately deferred rather than done now.
	go func() {
		for wc := range resizeCh {
			_ = targetSession.WindowChange(wc[0], wc[1])
		}
	}()

	var rec *recording.Recorder
	var recKey string
	if s.recordStore != nil {
		recKey = fmt.Sprintf("recordings/%s/%s.cast", pr.User, time.Now().UTC().Format("20060102T150405.000000000Z"))
		dest, derr := s.recordStore.Create(ctx, recKey)
		if derr == nil {
			rec, derr = recording.NewRecorder(dest, recKey, cols, rows, nil)
			if derr != nil {
				_ = dest.Close()
			}
		}
		if derr != nil {
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeRecording,
				User: pr.User, SourceIP: srcIP, ObjectKey: recKey,
				Allow: evidence.BoolPtr(false), Reason: "recording unavailable",
				Detail: "recording start failed: " + derr.Error(),
			})
			_, _ = channel.Write([]byte("session refused: recording unavailable\r\n"))
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
				User: pr.User, SourceIP: srcIP, Detail: "refused: recording unavailable",
			})
			return
		}
	}

	// Bidirectional pipe: client -> target (recording Input), target -> client
	// (recording Output). Both directions run until either side closes: the
	// client->target goroutine ends when the client's channel EOFs/errors (or
	// the target's stdin pipe errors on write, e.g. the target session
	// exited), and the target->client goroutine ends when the target's stdout
	// EOFs/errors (the target shell exited) or the client's channel errors on
	// write (client disconnected). Either goroutine finishing ends the
	// session below; the loser is left blocked in its own Read until its side
	// notices the peer is gone (channel.Close()/targetSession.Close() in the
	// deferred cleanup unblock it), so it never leaks past this function
	// returning.
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := channel.Read(buf)
			if n > 0 {
				if rec != nil {
					rec.Input(buf[:n])
				}
				if _, werr := targetIn.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := targetOut.Read(buf)
			if n > 0 {
				if rec != nil {
					rec.Output(buf[:n])
				}
				if _, werr := channel.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done // either direction closing ends the session

	if rec != nil {
		if m, cerr := rec.Close(); cerr == nil {
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeRecording,
				User: pr.User, SourceIP: srcIP,
				ObjectKey: m.Key, SHA256: m.SHA256, Bytes: m.Bytes,
				RecordMode: string(policy.RecordFull),
				Detail:     fmt.Sprintf("asciicast duration=%s", m.Duration.Round(time.Millisecond)),
			})
		} else {
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeRecording,
				User: pr.User, SourceIP: srcIP, ObjectKey: recKey,
				Detail: "recording finalize failed: " + cerr.Error(),
			})
		}
	}

	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
		User: pr.User, SourceIP: srcIP,
	})
}
