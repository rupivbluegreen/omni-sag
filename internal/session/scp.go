// Package session (scp.go): the classic, exec-based SCP wire protocol —
// used only when a client forces it (OpenSSH's `scp -O` flag; every
// current OpenSSH client defaults to the SFTP protocol instead, already
// served by runSFTP). See
// docs/superpowers/specs/2026-07-18-scp-legacy-protocol-support-design.md.
package session

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// execRequest is the RFC 4254 §6.5 exec payload — same shape as
// subsystemRequest (interactive.go), a single SSH string.
type execRequest struct{ Command string }

// scpDirection is which way bytes move for one legacy-protocol scp
// invocation.
type scpDirection int

const (
	scpUpload   scpDirection = iota // client -> gateway: "scp -t <path>"
	scpDownload                     // gateway -> client: "scp -f <path>"
)

// parseSCPCommand validates cmd against the exact narrow grammar this
// gateway supports: "scp", zero or more flags from the allowed set, exactly
// one of "-t"/"-f", then a single path containing no spaces or shell
// metacharacters. Real scp single-quotes a path containing spaces before
// sending it; that quoted form (and any unquoted-space form) is refused
// rather than mis-parsed — shell-quote parsing is out of scope for this
// pass (see design doc's Out of scope).
func parseSCPCommand(cmd string) (scpDirection, string, error) {
	fields := strings.Fields(cmd)
	if len(fields) < 2 || fields[0] != "scp" {
		return 0, "", fmt.Errorf("scp: unsupported command")
	}
	var dir scpDirection
	haveDir := false
	var remotePath string
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "-t":
			if haveDir {
				return 0, "", fmt.Errorf("scp: conflicting -t/-f flags")
			}
			dir, haveDir = scpUpload, true
		case f == "-f":
			if haveDir {
				return 0, "", fmt.Errorf("scp: conflicting -t/-f flags")
			}
			dir, haveDir = scpDownload, true
		case f == "-r":
			return 0, "", fmt.Errorf("scp: recursive transfer (-r) is not supported")
		case f == "-p" || f == "-d" || f == "-v" || f == "-q" || f == "--":
			// accepted and ignored: -p's T line is acked per-file (see
			// scpReadControlLine) but not applied; -d/-v/-q affect only
			// client-side behavior/output.
		case strings.HasPrefix(f, "-"):
			return 0, "", fmt.Errorf("scp: unsupported flag %q", f)
		default:
			// Check path for bad characters before allowing multiple paths
			if strings.ContainsAny(f, "'\"$`\\;|&<>*?[]{}~") ||
				strings.IndexFunc(f, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
				return 0, "", fmt.Errorf("scp: unsupported path")
			}
			if remotePath != "" {
				return 0, "", fmt.Errorf("scp: unsupported command (multiple paths)")
			}
			remotePath = f
		}
	}
	if !haveDir {
		return 0, "", fmt.Errorf("scp: missing -t or -f")
	}
	if remotePath == "" {
		return 0, "", fmt.Errorf("scp: missing path")
	}
	return dir, remotePath, nil
}

// Classic SCP protocol status bytes: 0 = ok, 1 = warning (peer may
// continue), 2 = fatal (peer aborts). A non-zero status is followed by a
// '\n'-terminated message.
const (
	scpOK    byte = 0
	scpError byte = 1
	scpFatal byte = 2
)

func scpSendOK(w io.Writer) error {
	_, err := w.Write([]byte{scpOK})
	return err
}

// scpSendFatal writes a fatal-error status + msg, per the classic SCP
// protocol's status-byte + message-line convention, so the receiving scp
// process prints msg and aborts instead of hanging or garbling.
func scpSendFatal(w io.Writer, msg string) error {
	buf := append([]byte{scpFatal}, []byte(msg+"\n")...)
	_, err := w.Write(buf)
	return err
}

// scpReadAck reads one status byte from r. A non-zero status is followed by
// a '\n'-terminated message, folded into the returned error.
func scpReadAck(r *bufio.Reader) error {
	status, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("scp: read ack: %w", err)
	}
	if status == scpOK {
		return nil
	}
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("scp: peer signalled status %d with no message: %w", status, err)
	}
	return fmt.Errorf("scp: peer error: %s", strings.TrimSuffix(line, "\n"))
}

// scpControlLine is a parsed classic-SCP "C" (copy) control line:
// "C<perm> <size> <name>\n".
type scpControlLine struct {
	Perm string
	Size int64
	Name string
}

// scpReadControlLine reads one line from r and parses it as a "C" control
// line, acking (via w) and discarding a leading "T" (preserve-times) line
// first if present. A leading "D"/"E" (directory push/pop) means the peer
// wants a recursive transfer, which this gateway does not support.
func scpReadControlLine(r *bufio.Reader, w io.Writer) (scpControlLine, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return scpControlLine{}, fmt.Errorf("scp: read control line: %w", err)
	}
	line = strings.TrimSuffix(line, "\n")
	if strings.HasPrefix(line, "T") {
		if err := scpSendOK(w); err != nil {
			return scpControlLine{}, fmt.Errorf("scp: ack T line: %w", err)
		}
		line, err = r.ReadString('\n')
		if err != nil {
			return scpControlLine{}, fmt.Errorf("scp: read control line after T: %w", err)
		}
		line = strings.TrimSuffix(line, "\n")
	}
	if strings.HasPrefix(line, "D") || strings.HasPrefix(line, "E") {
		return scpControlLine{}, fmt.Errorf("scp: recursive transfer (-r) is not supported")
	}
	if !strings.HasPrefix(line, "C") {
		return scpControlLine{}, fmt.Errorf("scp: unexpected control line %q", line)
	}
	parts := strings.SplitN(line[1:], " ", 3)
	if len(parts) != 3 {
		return scpControlLine{}, fmt.Errorf("scp: malformed control line %q", line)
	}
	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || size < 0 {
		return scpControlLine{}, fmt.Errorf("scp: malformed size in control line %q", line)
	}
	return scpControlLine{Perm: parts[0], Size: size, Name: parts[2]}, nil
}

// exitStatusMsg is the RFC 4254 §6.10 "exit-status" channel request
// payload. Sent before closing the channel: nothing here is a real exec'd
// process with a real process exit code, so without this a real SSH
// client's Session.Wait() reports "remote command exited without exit
// status" even on success.
type exitStatusMsg struct{ Status uint32 }

// runSCP serves one legacy-protocol scp invocation over channel: a single
// C-line up/download, proxied to the real target via the same
// remoteFS.Filewrite/Fileread machinery runSFTP uses (sftp.go) — see
// scp.go's package doc and the design doc's "Reuse" section. cmd was
// already validated by parseSCPCommand before this is called; no shell is
// ever invoked.
func (s *Server) runSCP(ctx, connCtx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache, dir scpDirection, remotePath string) {
	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionStart,
		User: pr.User, SourceIP: srcIP, Detail: "scp",
	})
	defer channel.Close()

	ok, detail := s.runSCPTransfer(ctx, connCtx, channel, pr, srcIP, sconn, tch, dir, remotePath)

	status := uint32(0)
	if !ok {
		status = 1
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: status}))
	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
		User: pr.User, SourceIP: srcIP, Detail: detail,
	})
}

// runSCPTransfer resolves the target and dispatches to scpUpload/
// scpDownload, mirroring runSFTP's target-resolution shape (sftp.go:52-101)
// exactly — same dialerPeek/Allow re-check, same targetPort fallback, same
// targetConnCache reuse across shell/sftp/scp channels on one connection.
func (s *Server) runSCPTransfer(ctx, connCtx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache, dir scpDirection, remotePath string) (bool, string) {
	if pr.TargetHost == "" {
		_ = scpSendFatal(channel, "scp: no target selected")
		return false, "scp refused: no target selected"
	}
	decision := policy.Decision{}
	if s.dialerPeek != nil {
		decision = s.dialerPeek(pr, pr.TargetHost)
	}
	if !decision.Allow {
		reason := decision.Reason
		if reason == "" {
			reason = "no policy decision available for this target"
		}
		_ = scpSendFatal(channel, "scp: "+reason)
		return false, "scp refused: " + reason
	}
	targetPort := decision.Port
	if targetPort <= 0 {
		targetPort = 22
	}
	targetClient, err := tch.getOrDial(func() (*ssh.Client, error) {
		return s.dialTarget(ctx, sconn, pr, srcIP, decision, pr.TargetHost, targetPort, pr.TargetSecretToken)
	})
	if err != nil {
		_ = scpSendFatal(channel, "scp: "+err.Error())
		return false, "scp refused: " + err.Error()
	}
	sftpClient, err := sftp.NewClient(targetClient)
	if err != nil {
		_ = scpSendFatal(channel, "scp: target sftp client: "+err.Error())
		return false, "scp refused: target sftp client: " + err.Error()
	}
	defer sftpClient.Close()

	fs := &remoteFS{
		client: sftpClient, gate: s.inspect, srv: s, user: pr.User, srcIP: srcIP, ctx: connCtx,
		matchedGroups: decision.MatchedGroups, releases: s.releases, releaseTTL: s.releaseTTL,
	}
	if dir == scpUpload {
		return s.scpUpload(fs, channel, remotePath), ""
	}
	return s.scpDownload(fs, channel, remotePath), ""
}

// scpUpload receives one file from channel (classic SCP sink role) and
// writes it via fs.Filewrite — the SAME method pkg/sftp's FilePut handler
// calls, constructed here with a bare *sftp.Request carrying only
// Filepath (all Filewrite reads; see sftp.go:535-552). Returns false on
// any failure (a fatal status byte has already been sent to channel).
func (s *Server) scpUpload(fs *remoteFS, channel ssh.Channel, remotePath string) bool {
	r := bufio.NewReader(channel)
	// Classic SCP sink handshake: send the initial 0x00 "ready" byte before
	// the source sends anything. The real scp -O client (source) blocks in
	// read() waiting for this; without it both sides deadlock.
	if err := scpSendOK(channel); err != nil {
		return false
	}
	cl, err := scpReadControlLine(r, channel)
	if err != nil {
		_ = scpSendFatal(channel, err.Error())
		return false
	}
	if err := scpSendOK(channel); err != nil {
		return false
	}
	w, err := fs.Filewrite(&sftp.Request{Method: "Put", Filepath: remotePath})
	if err != nil {
		_ = scpSendFatal(channel, "scp: "+err.Error())
		return false
	}
	fail := func(msg string) bool {
		if c, ok := w.(io.Closer); ok {
			_ = c.Close()
		}
		_ = scpSendFatal(channel, msg)
		return false
	}
	var written int64
	buf := make([]byte, 32*1024)
	for written < cl.Size {
		remaining := cl.Size - written
		chunk := int64(len(buf))
		if remaining < chunk {
			chunk = remaining
		}
		n, rerr := r.Read(buf[:chunk])
		if n > 0 {
			if _, werr := w.WriteAt(buf[:n], written); werr != nil {
				return fail("scp: " + werr.Error())
			}
			written += int64(n)
		}
		if rerr != nil {
			return fail("scp: read from client: " + rerr.Error())
		}
	}
	if _, err := r.ReadByte(); err != nil { // trailing terminator the source sends after data
		return fail("scp: read trailer: " + err.Error())
	}
	if c, ok := w.(io.Closer); ok {
		if err := c.Close(); err != nil {
			_ = scpSendFatal(channel, "scp: "+err.Error())
			return false
		}
	}
	if err := scpSendOK(channel); err != nil {
		return false
	}
	return true
}

// scpCopyBody streams exactly size bytes from rd (starting at offset 0) to w
// in bounded chunks. It terminates on io.EOF and returns an error if the
// source yields fewer than size bytes — a target that reports a larger Stat
// size than it will serve (a truncation race or a buggy/hostile target) must
// fail the transfer, never spin. Returns nil only when exactly size bytes
// were written.
func scpCopyBody(w io.Writer, rd io.ReaderAt, size int64) error {
	buf := make([]byte, 32*1024)
	var off int64
	for off < size {
		chunk := int64(len(buf))
		if remaining := size - off; remaining < chunk {
			chunk = remaining
		}
		n, rerr := rd.ReadAt(buf[:chunk], off)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			off += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if off < size {
		return fmt.Errorf("scp: target served %d of %d bytes", off, size)
	}
	return nil
}

// scpDownload sends one file to channel (classic SCP source role), read
// via fs.Fileread — the SAME method pkg/sftp's FileGet handler calls (see
// sftp.go:178-196), so downloads get the identical evidence.TypeTransfer
// manifest sftp get already produces. Returns false on any failure.
func (s *Server) scpDownload(fs *remoteFS, channel ssh.Channel, remotePath string) bool {
	info, err := fs.client.Stat(remotePath)
	if err != nil {
		_ = scpSendFatal(channel, "scp: "+err.Error())
		return false
	}
	rd, err := fs.Fileread(&sftp.Request{Method: "Get", Filepath: remotePath})
	if err != nil {
		_ = scpSendFatal(channel, "scp: "+err.Error())
		return false
	}
	closer, _ := rd.(io.Closer)
	defer func() {
		if closer != nil {
			_ = closer.Close()
		}
	}()
	r := bufio.NewReader(channel)
	// Classic SCP source handshake: the sink (client) sends an initial 0x00
	// "ready" byte first; consume it before sending our C-line. Without this
	// read the ack stream is off by one.
	if err := scpReadAck(r); err != nil {
		return false
	}
	cline := fmt.Sprintf("C0644 %d %s\n", info.Size(), path.Base(remotePath))
	if _, err := channel.Write([]byte(cline)); err != nil {
		return false
	}
	if err := scpReadAck(r); err != nil {
		return false
	}
	if err := scpCopyBody(channel, rd, info.Size()); err != nil {
		_ = scpSendFatal(channel, "scp: "+err.Error())
		return false
	}
	if _, err := channel.Write([]byte{scpOK}); err != nil { // trailing terminator
		return false
	}
	if err := scpReadAck(r); err != nil {
		return false
	}
	return true
}
