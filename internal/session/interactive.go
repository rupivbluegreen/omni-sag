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
// interactive session) or the SFTP subsystem.
//
// The interactive shell in this slice is a minimal gateway-hosted stand-in that
// echoes input; its purpose is to exercise the recording pipeline end-to-end.
// Proxying the recorded PTY to a target host's shell is later work (it needs an
// interactive target-selection mechanism not yet defined).
func (s *Server) handleSession(ctx context.Context, newCh ssh.NewChannel, pr policy.Principal, srcIP string) {
	channel, requests, err := newCh.Accept()
	if err != nil {
		return
	}

	cols, rows := 80, 24
	for req := range requests {
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if ssh.Unmarshal(req.Payload, &p) == nil && p.Cols > 0 {
				cols, rows = int(p.Cols), int(p.Rows)
			}
			_ = req.Reply(true, nil)
		case "window-change":
			_ = req.Reply(true, nil)
		case "env":
			_ = req.Reply(true, nil)
		case "auth-agent-req@openssh.com":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			s.runRecordedShell(ctx, channel, cols, rows, pr, srcIP)
			return
		case "subsystem":
			var sub subsystemRequest
			if ssh.Unmarshal(req.Payload, &sub) == nil && sub.Name == "sftp" {
				_ = req.Reply(true, nil)
				s.runSFTP(ctx, channel, pr, srcIP)
				return
			}
			_ = req.Reply(false, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
	_ = channel.Close()
}

// runRecordedShell serves a minimal interactive shell over channel, recording
// the terminal I/O as asciicast (when a store is configured) and emitting
// session_start / recording / session_end evidence.
func (s *Server) runRecordedShell(ctx context.Context, channel ssh.Channel, cols, rows int, pr policy.Principal, srcIP string) {
	defer channel.Close()

	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionStart,
		User: pr.User, SourceIP: srcIP, Detail: "interactive shell",
	})

	var rec *recording.Recorder
	var key string
	if s.recordStore != nil {
		// Recording is required when a store is configured. If it cannot be
		// started, fail closed (refuse the session) rather than proceed
		// unrecorded, and surface the failure as evidence.
		key = fmt.Sprintf("recordings/%s/%s.cast", pr.User, time.Now().UTC().Format("20060102T150405.000000000Z"))
		dest, err := s.recordStore.Create(ctx, key)
		if err == nil {
			rec, err = recording.NewRecorder(dest, key, cols, rows, nil)
			if err != nil {
				_ = dest.Close() // avoid a leaked upload goroutine on the pipe
			}
		}
		if err != nil {
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeRecording,
				User: pr.User, SourceIP: srcIP, ObjectKey: key,
				Allow: evidence.BoolPtr(false), Reason: "recording unavailable",
				Detail: "recording start failed: " + err.Error(),
			})
			_, _ = channel.Write([]byte("session refused: recording unavailable\r\n"))
			s.emit(evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
				User: pr.User, SourceIP: srcIP, Detail: "refused: recording unavailable",
			})
			return
		}
	}

	out := func(b []byte) {
		_, _ = channel.Write(b)
		if rec != nil {
			rec.Output(b)
		}
	}
	out([]byte("omni-sag recorded session — type 'exit' to quit\r\n$ "))

	buf := make([]byte, 1024)
	var line []byte
loop:
	for {
		n, rerr := channel.Read(buf)
		if n > 0 {
			data := buf[:n]
			if rec != nil {
				rec.Input(data)
			}
			for _, c := range data {
				switch c {
				case '\r', '\n':
					out([]byte("\r\n"))
					cmd := string(line)
					line = line[:0]
					if cmd == "exit" {
						out([]byte("bye\r\n"))
						break loop
					}
					if cmd != "" {
						out([]byte(cmd + "\r\n")) // echo the "command output"
					}
					out([]byte("$ "))
				case 0x7f, 0x08: // DEL / BS
					if len(line) > 0 {
						line = line[:len(line)-1]
						out([]byte("\b \b"))
					}
				default:
					line = append(line, c)
					out([]byte{c}) // local echo
				}
			}
		}
		if rerr != nil {
			break
		}
	}

	if rec != nil {
		if m, err := rec.Close(); err == nil {
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
				User: pr.User, SourceIP: srcIP, ObjectKey: key,
				Detail: "recording finalize failed: " + err.Error(),
			})
		}
	}

	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
		User: pr.User, SourceIP: srcIP,
	})
}
