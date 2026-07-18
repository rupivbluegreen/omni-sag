// Package session (scp.go): the classic, exec-based SCP wire protocol —
// used only when a client forces it (OpenSSH's `scp -O` flag; every
// current OpenSSH client defaults to the SFTP protocol instead, already
// served by runSFTP). See
// docs/superpowers/specs/2026-07-18-scp-legacy-protocol-support-design.md.
package session

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
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
			if strings.ContainsAny(f, "'\"$`\\;|&<>*?[]{}~") {
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
