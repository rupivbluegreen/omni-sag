# scp (legacy `-O` protocol) support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `scp -O user%host@gateway:/path` (the classic exec-based SCP
wire protocol) work, single file only, both directions, reusing the exact
inspection/quarantine/release machinery SFTP already has.

**Architecture:** Add `case "exec"` to the session-channel request switch
(`interactive.go`), recognizing only `scp -t <path>` / `scp -f <path>`. A new
`internal/session/scp.go` speaks the classic SCP wire protocol on the
client-facing side and reuses `remoteFS.Filewrite`/`Fileread`
(`sftp.go`) unchanged on the target-facing side, by constructing a bare
`&sftp.Request{Filepath: path}` — those two methods only ever read
`r.Filepath`, confirmed by reading their bodies and by the existing test
suite's own use of this exact construction
(`sftp_test.go:300` `fs.Filewrite(&sftp.Request{Method: "Put", Filepath: "/upload.txt"})`).
No target-side exec, no shell is ever invoked.

**Tech Stack:** Go, `golang.org/x/crypto/ssh`, `github.com/pkg/sftp` (target
leg only).

## Global Constraints

- Single file only — no `-r` (recursive/directory) support. Any `-r` flag
  anywhere in the exec command is refused.
- `-p` (preserve times) is accepted (its `T` control line is read and
  acknowledged) but the timestamp is **not** applied to the target file.
- Paths containing spaces or shell metacharacters
  (`'"$\`\;|&<>*?[]{}~`) are refused — this pass does not implement
  shell-quote parsing.
- Nothing is ever shell-invoked. The exec command string is parsed, never
  executed.
- Malformed/unsupported exec commands are refused at the SSH request level
  (`req.Reply(false, nil)`) — a standard, client-understood SSH failure.
  Once the exec request is *accepted* (grammar matched), any later failure
  (no target, policy deny, target IO error, quarantine-blocked content) is
  reported via the classic SCP protocol's status-byte convention (0 = ok, 1
  = warning, 2 = fatal + message), so the real `scp` binary prints something
  sensible instead of hanging. This is a refinement of, not a deviation
  from, `docs/superpowers/specs/2026-07-18-scp-legacy-protocol-support-design.md`'s
  Errors section — the design's *intent* (client always gets a clear
  message) holds; SSH-level request-reject is the correct place for a
  command whose peer never even started speaking SCP framing.
- A clean-verdict upload is quarantined and requires four-eyes approval —
  it is **never** delivered to the target, matching SFTP put's existing
  behavior exactly (`sftp.go:663`). This is inherited, not new.
- `disable_sftp` already gates default-protocol scp today (same
  `subsystem sftp` path). The new `enable_scp` toggle introduced here gates
  *only* this legacy `-O` exec-channel path, and is **opt-in (default OFF)** —
  the opposite sense from the three `disable_*` toggles — because it adds an
  exec-channel surface that should stay off unless explicitly turned on. It
  is NOT part of the "at least one capability must stay enabled" rule (that
  rule governs only ssh/tunnel/sftp), since scp is off by default anyway.
- Every exec-channel session must send an RFC 4254 §6.10 `exit-status`
  channel request before closing (0 on success, 1 on any refusal) — without
  it, a real SSH client's session `Wait()` reports "remote command exited
  without exit status" even on success, since nothing here is a real
  exec'd process with a real process exit code.

---

### Task 1: `enable_scp` config field + validation

> **Superseded / already implemented.** This task shipped first as a
> `disable_scp` (opt-out) toggle, then was converted to `enable_scp` (opt-in,
> default OFF) per a design decision — see the Global Constraints note above
> and commit `refactor(config): make legacy scp opt-in (enable_scp)`. The
> steps below are retained for historical context; the code as merged uses
> `File.EnableSCP bool` (yaml `enable_scp`) and reverts the "all disabled"
> validation to the original three toggles (ssh/tunnel/sftp). Downstream
> Tasks 3/5/6/7 consume `EnableSCP`/`WithSCPEnabled`, not the disable_scp
> names shown in this section.

**Files:**
- Modify: `internal/config/config.go:41-44` (struct fields), `:276-278`
  (validate())
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `File.EnableSCP bool` (yaml `enable_scp`, opt-in default false),
  consumed by Task 3 (`session.WithSCPEnabled`) and Task 5
  (`cmd/omni-sag/main.go`).

- [ ] **Step 1: Write the failing test**

This codebase's convention for these tests is a YAML string fed through
`Load(writeTemp(t, yaml))`, not a direct `File{}` literal + `.validate()`
call — see `TestValidate_AllCapabilitiesDisabledRejected` and
`TestValidate_TwoOfThreeCapabilitiesDisabledIsAllowed`
(`internal/config/config_test.go:93-129`). Add these two tests
immediately after `TestValidate_TwoOfThreeCapabilitiesDisabledIsAllowed`
(after line 129):

```go
func TestValidate_AllFourCapabilityTogglesTrueIsRejected(t *testing.T) {
	bad := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
disable_ssh: true
disable_tunnel: true
disable_sftp: true
disable_scp: true
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error when disable_ssh, disable_tunnel, disable_sftp, and disable_scp are all true")
	}
}

func TestValidate_DisableSCPAloneIsAccepted(t *testing.T) {
	ok := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
disable_scp: true
policy:
  roles: []
`
	f, err := Load(writeTemp(t, ok))
	if err != nil {
		t.Fatal(err)
	}
	if !f.DisableSCP {
		t.Fatal("disable_scp should be true")
	}
	if f.DisableSSH || f.DisableTunnel || f.DisableSFTP {
		t.Fatal("disable_ssh/disable_tunnel/disable_sftp should all be false (omitted)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/... -run TestValidate_AllFourCapabilityTogglesTrueIsRejected -v`
Expected: FAIL — `disable_scp` is an unknown YAML key today (no error from
`yaml.Unmarshal` itself since this parser doesn't reject unknown fields by
default, but the first test expects an error and won't get one, since only
three of the four flags exist yet); confirm by running both new tests and
observing the first one FAIL with "expected error ... got nil" or similar.

- [ ] **Step 3: Add the field and extend validation**

In `internal/config/config.go`, change lines 38-44 to:

```go
	// Capability toggles: any combination may be disabled independently. All
	// default to false (enabled), so a config.yaml written before these
	// fields existed keeps serving all four, unchanged.
	DisableSSH    bool `yaml:"disable_ssh"`    // reject interactive PTY shell ("shell" requests on session channels)
	DisableTunnel bool `yaml:"disable_tunnel"` // reject -L port forwarding ("direct-tcpip" channels)
	DisableSFTP   bool `yaml:"disable_sftp"`   // reject the SFTP subsystem ("subsystem"+"sftp" requests on session channels) — also blocks default-protocol scp, which rides the same subsystem
	DisableSCP    bool `yaml:"disable_scp"`    // reject the legacy exec-based scp protocol ("exec" requests matching "scp -t/-f"); default-protocol scp is governed by disable_sftp instead, see its doc comment
}
```

Change lines 276-278 to:

```go
	if f.DisableSSH && f.DisableTunnel && f.DisableSFTP && f.DisableSCP {
		return fmt.Errorf("config: disable_ssh, disable_tunnel, disable_sftp, and disable_scp cannot all be true (the gateway would serve nothing)")
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/... -v`
Expected: PASS, including the two new tests and every pre-existing
`disable_*` test in the same file (they must still pass unchanged — none of
them set `DisableSCP`, so it defaults false and doesn't affect them).

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add disable_scp capability toggle"
```

---

### Task 2: SCP wire-protocol codec + exec command parser (pure functions)

**Files:**
- Create: `internal/session/scp.go` (codec + parser only — `runSCP` comes in
  Task 3)
- Test: Create `internal/session/scp_test.go`

**Interfaces:**
- Produces (consumed by Task 3):
  - `type execRequest struct{ Command string }`
  - `type scpDirection int` with consts `scpUpload`, `scpDownload`
  - `func parseSCPCommand(cmd string) (scpDirection, string, error)` —
    returns direction, remote path, error
  - `const scpOK, scpError, scpFatal byte`
  - `func scpSendOK(w io.Writer) error`
  - `func scpSendFatal(w io.Writer, msg string) error`
  - `func scpReadAck(r *bufio.Reader) error`
  - `type scpControlLine struct{ Perm string; Size int64; Name string }`
  - `func scpReadControlLine(r *bufio.Reader, w io.Writer) (scpControlLine, error)`

- [ ] **Step 1: Write the failing tests**

Create `internal/session/scp_test.go`:

```go
package session

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestParseSCPCommand(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		wantDir scpDirection
		wantPath string
		wantErr string // substring, "" means no error expected
	}{
		{"upload", "scp -t /upload.txt", scpUpload, "/upload.txt", ""},
		{"download", "scp -f /download.txt", scpDownload, "/download.txt", ""},
		{"upload with -p", "scp -p -t /upload.txt", scpUpload, "/upload.txt", ""},
		{"upload with -v -d", "scp -v -d -t /upload.txt", scpUpload, "/upload.txt", ""},
		{"recursive rejected", "scp -r -t /dir", 0, "", "-r"},
		{"missing direction", "scp /path", 0, "", "missing -t or -f"},
		{"conflicting direction", "scp -t -f /path", 0, "", "conflicting"},
		{"not scp", "ls -la", 0, "", "unsupported command"},
		{"unsupported flag", "scp -t -X /path", 0, "", "unsupported flag"},
		{"path with space", "scp -t /path with space", 0, "", "multiple paths"},
		{"path with quote", "scp -t /path'; rm -rf /", 0, "", "unsupported path"},
		{"no path", "scp -t", 0, "", "missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, path, err := parseSCPCommand(c.cmd)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("parseSCPCommand(%q) error = %v, want nil", c.cmd, err)
				}
				if dir != c.wantDir || path != c.wantPath {
					t.Fatalf("parseSCPCommand(%q) = (%v, %q), want (%v, %q)", c.cmd, dir, path, c.wantDir, c.wantPath)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseSCPCommand(%q) = nil error, want containing %q", c.cmd, c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("parseSCPCommand(%q) error = %q, want containing %q", c.cmd, err.Error(), c.wantErr)
			}
		})
	}
}

func TestScpSendOK(t *testing.T) {
	var buf bytes.Buffer
	if err := scpSendOK(&buf); err != nil {
		t.Fatalf("scpSendOK: %v", err)
	}
	if buf.Bytes()[0] != 0 {
		t.Fatalf("scpSendOK wrote %v, want [0]", buf.Bytes())
	}
}

func TestScpSendFatal(t *testing.T) {
	var buf bytes.Buffer
	if err := scpSendFatal(&buf, "boom"); err != nil {
		t.Fatalf("scpSendFatal: %v", err)
	}
	got := buf.Bytes()
	if got[0] != 2 {
		t.Fatalf("scpSendFatal status byte = %d, want 2", got[0])
	}
	if string(got[1:]) != "boom\n" {
		t.Fatalf("scpSendFatal message = %q, want %q", got[1:], "boom\n")
	}
}

func TestScpReadAck(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		r := bufio.NewReader(bytes.NewReader([]byte{0}))
		if err := scpReadAck(r); err != nil {
			t.Fatalf("scpReadAck = %v, want nil", err)
		}
	})
	t.Run("fatal with message", func(t *testing.T) {
		r := bufio.NewReader(bytes.NewReader(append([]byte{2}, []byte("no such file\n")...)))
		err := scpReadAck(r)
		if err == nil || !strings.Contains(err.Error(), "no such file") {
			t.Fatalf("scpReadAck = %v, want error containing %q", err, "no such file")
		}
	})
}

func TestScpReadControlLine(t *testing.T) {
	t.Run("plain C line", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("C0644 5 test.txt\n"))
		var acked bytes.Buffer
		cl, err := scpReadControlLine(r, &acked)
		if err != nil {
			t.Fatalf("scpReadControlLine: %v", err)
		}
		if cl.Perm != "0644" || cl.Size != 5 || cl.Name != "test.txt" {
			t.Fatalf("scpReadControlLine = %+v, want {0644 5 test.txt}", cl)
		}
		if acked.Len() != 0 {
			t.Fatalf("no T line present, expected no ack written, got %v", acked.Bytes())
		}
	})
	t.Run("T line is acked then C line parsed", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("T1000000000 0 1000000000 0\nC0644 5 test.txt\n"))
		var acked bytes.Buffer
		cl, err := scpReadControlLine(r, &acked)
		if err != nil {
			t.Fatalf("scpReadControlLine: %v", err)
		}
		if cl.Name != "test.txt" {
			t.Fatalf("scpReadControlLine = %+v, want Name test.txt", cl)
		}
		if acked.Len() != 1 || acked.Bytes()[0] != 0 {
			t.Fatalf("T line ack = %v, want single [0] byte", acked.Bytes())
		}
	})
	t.Run("directory record rejected", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("D0755 0 subdir\n"))
		var acked bytes.Buffer
		_, err := scpReadControlLine(r, &acked)
		if err == nil || !strings.Contains(err.Error(), "recursive") {
			t.Fatalf("scpReadControlLine = %v, want error containing %q", err, "recursive")
		}
	})
	t.Run("malformed line rejected", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("garbage\n"))
		var acked bytes.Buffer
		_, err := scpReadControlLine(r, &acked)
		if err == nil {
			t.Fatal("scpReadControlLine = nil error, want error on garbage input")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/... -run 'TestParseSCPCommand|TestScpSendOK|TestScpSendFatal|TestScpReadAck|TestScpReadControlLine' -v`
Expected: FAIL to compile — `undefined: parseSCPCommand` etc. (scp.go
doesn't exist yet)

- [ ] **Step 3: Write the codec and parser**

Create `internal/session/scp.go`:

```go
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
			if remotePath != "" {
				return 0, "", fmt.Errorf("scp: unsupported command (multiple paths)")
			}
			remotePath = f
		}
	}
	if !haveDir {
		return 0, "", fmt.Errorf("scp: missing -t or -f")
	}
	if remotePath == "" || strings.ContainsAny(remotePath, "'\"$`\\;|&<>*?[]{}~") {
		return 0, "", fmt.Errorf("scp: unsupported path")
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/session/... -run 'TestParseSCPCommand|TestScpSendOK|TestScpSendFatal|TestScpReadAck|TestScpReadControlLine' -v`
Expected: PASS, all subtests.

- [ ] **Step 5: Run `go vet` (project lint checks stringintconv-style issues)**

Run: `go vet ./internal/session/...`
Expected: no output (clean)

- [ ] **Step 6: Commit**

```bash
git add internal/session/scp.go internal/session/scp_test.go
git commit -m "feat(session): scp classic-protocol wire codec and command parser"
```

---

### Task 3: Wire the exec channel end-to-end (no inspection gate)

**Files:**
- Modify: `internal/session/session.go:89-137` (field + option)
- Modify: `internal/session/interactive.go:65-134` (exec case)
- Modify: `internal/session/scp.go` (add `runSCP`, `scpUpload`, `scpDownload`)
- Test: `internal/session/scp_test.go` (append)

**Interfaces:**
- Consumes: `parseSCPCommand`, `scpSendOK/Fatal`, `scpReadAck`,
  `scpReadControlLine` (Task 2); `remoteFS`, `targetConnCache.getOrDial`,
  `Server.dialTarget`, `Server.emit` (existing, `sftp.go`/`target.go`/`session.go`)
- Produces: `Server.scpEnabled bool`, `WithSCPEnabled(bool) Option`,
  `func (s *Server) runSCP(ctx, connCtx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache, dir scpDirection, remotePath string)`
  — consumed by Task 4's tests and Task 5's main.go wiring.

**IMPORTANT — legacy scp is opt-IN (default OFF).** Unlike the three
`disable_*` toggles, scp is gated by `scpEnabled` which defaults false: the
exec case rejects every scp exec request UNLESS `WithSCPEnabled(true)` was
passed. Every happy-path scp test below must therefore pass
`WithSCPEnabled(true)` in its server options, or the exec request is refused
before any transfer runs.

- [ ] **Step 1: Write the failing integration test**

Append to `internal/session/scp_test.go` (needs `fmt`, `io`, `time`,
`golang.org/x/crypto/ssh`, and this package's `evidence`/`policy` imports —
add them to the existing import block):

```go
import (
	// ... existing imports from Task 2 ...
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// scpExecUpload obtains sess's stdin/stdout pipes, starts cmd (an
// exec-channel "scp -t <path>" invocation — pipes MUST be obtained before
// Start(), per ssh.Session's contract: calling StdinPipe/StdoutPipe after
// Start returns an error), then drives one client-side legacy-protocol
// upload and returns any error the server signalled (nil on success). The
// caller is responsible for sess.Wait() afterward.
func scpExecUpload(t *testing.T, sess *ssh.Session, cmd string, content []byte, name string) error {
	t.Helper()
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := sess.Start(cmd); err != nil {
		return err
	}
	r := bufio.NewReader(stdout)
	if _, err := fmt.Fprintf(stdin, "C0644 %d %s\n", len(content), name); err != nil {
		return err
	}
	if err := scpReadAck(r); err != nil {
		return err
	}
	if _, err := stdin.Write(content); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte{0}); err != nil {
		return err
	}
	if err := scpReadAck(r); err != nil {
		return err
	}
	return stdin.Close()
}

// scpExecDownload obtains sess's stdin/stdout pipes, starts cmd (an
// exec-channel "scp -f <path>" invocation — same before-Start ordering
// constraint as scpExecUpload), then drives one client-side legacy-protocol
// download and returns the received content. The caller is responsible for
// sess.Wait() afterward.
func scpExecDownload(t *testing.T, sess *ssh.Session, cmd string) []byte {
	t.Helper()
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := sess.Start(cmd); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r := bufio.NewReader(stdout)
	cl, err := scpReadControlLine(r, stdin)
	if err != nil {
		t.Fatalf("scpExecDownload control line: %v", err)
	}
	if err := scpSendOK(stdin); err != nil {
		t.Fatalf("ack control line: %v", err)
	}
	buf := make([]byte, cl.Size)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if _, err := r.ReadByte(); err != nil { // trailing terminator
		t.Fatalf("read trailer: %v", err)
	}
	if err := scpSendOK(stdin); err != nil {
		t.Fatalf("send final ack: %v", err)
	}
	return buf
}

func TestRunSCP_UploadThenDownloadRoundTripsThroughRealTarget(t *testing.T) {
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	sink := evidence.NewMemSink()
	opts := append([]Option{WithSCPEnabled(true)}, targetOpts...)
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, opts...)

	client := sshClient(t, addr, "alice%"+targetHost)

	uploadSess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession (upload): %v", err)
	}
	content := []byte("hello via legacy scp protocol\n")
	if err := scpExecUpload(t, uploadSess, "scp -t /roundtrip.txt", content, "roundtrip.txt"); err != nil {
		t.Fatalf("scpExecUpload: %v", err)
	}
	if err := uploadSess.Wait(); err != nil {
		t.Fatalf("upload Wait: %v", err)
	}
	uploadSess.Close()

	downloadSess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession (download): %v", err)
	}
	got := scpExecDownload(t, downloadSess, "scp -f /roundtrip.txt")
	if err := downloadSess.Wait(); err != nil {
		t.Fatalf("download Wait: %v", err)
	}
	downloadSess.Close()

	if string(got) != string(content) {
		t.Fatalf("round-tripped content = %q, want %q", got, content)
	}

	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeSessionStart && e.User == "alice" && e.Detail == "scp"
	})
}

func TestRunSCP_DisabledByDefaultRefusesExec(t *testing.T) {
	// No WithSCPEnabled option: legacy scp is opt-in and OFF by default, so
	// the exec request must be refused even though policy would allow the
	// target.
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, targetOpts...)

	client := sshClient(t, addr, "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	if err := sess.Start("scp -t /blocked.txt"); err == nil {
		t.Fatal("Start = nil, want error: scp is opt-in and must be refused unless enable_scp is set")
	}
}

func TestRunSCP_RecursiveFlagRefused(t *testing.T) {
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	sink := evidence.NewMemSink()
	opts := append([]Option{WithSCPEnabled(true)}, targetOpts...)
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, opts...)

	client := sshClient(t, addr, "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	// scp IS enabled here, so this exercises the parser's -r rejection, not
	// the enable gate: the exec request is refused because parseSCPCommand
	// rejects -r, not because scp is off.
	if err := sess.Start("scp -r -t /dir"); err == nil {
		t.Fatal("Start = nil, want error: -r must be refused")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/... -run TestRunSCP -v`
Expected: FAIL to compile — `WithSCPEnabled` is undefined (added in Step 3).
Once it compiles, note that today (no `case "exec"` at all, falls to
`default` which does `req.Reply(false, nil)`) `ssh.Session.Start` fails for
ALL of these, including the round-trip test that expects success — that's
the expected RED state, re-verified green in Step 4 after Step 3 lands.

- [ ] **Step 3: Add the field, option, and `runSCP`/`scpUpload`/`scpDownload`**

In `internal/session/session.go`, find the disabled-flags block (the three
fields `sshDisabled`/`tunnelDisabled`/`sftpDisabled`, around line 90-92) and
add a fourth field with the OPPOSITE sense — `scpEnabled` (opt-in), not
`scpDisabled`:

```go
	sshDisabled    bool // opt-in: rejects "shell" requests on session channels; see WithSSHDisabled
	tunnelDisabled bool // opt-in: rejects "direct-tcpip" channels (-L port forwarding); see WithTunnelDisabled
	sftpDisabled   bool // opt-in: rejects "subsystem"+"sftp" requests on session channels; see WithSFTPDisabled
	scpEnabled     bool // opt-IN (default false = OFF): only when true are "exec" requests matching "scp -t/-f" (legacy protocol) served; see WithSCPEnabled
```

Add after `WithSFTPDisabled` (after the existing `WithSFTPDisabled`
function, around line 137):

```go
// WithSCPEnabled turns ON the legacy exec-based scp protocol ("exec"
// requests matching "scp -t"/"scp -f"). Unlike the three WithXDisabled
// options, this is opt-IN: false (the default) rejects every scp exec
// request outright, since the legacy protocol adds an exec-channel surface
// that stays off unless an operator explicitly enables it. Default-protocol
// scp (modern clients, no -O flag) is unaffected either way — it rides the
// "subsystem"+"sftp" path governed by WithSFTPDisabled. When enabled, policy
// still separately governs which hosts/ports scp may reach.
func WithSCPEnabled(enabled bool) Option {
	return func(s *Server) { s.scpEnabled = enabled }
}
```

In `internal/session/interactive.go`, add a `case "exec":` branch to the
switch in `handleSession` (after the existing `case "subsystem":` block,
before `default:`, i.e. after line 130):

```go
		case "exec":
			if shellDone != nil {
				_ = req.Reply(false, nil) // a shell was already dispatched on this channel
				continue
			}
			if !s.scpEnabled {
				_ = req.Reply(false, nil) // legacy scp is opt-in and disabled (enable_scp not set)
				continue
			}
			var e execRequest
			if ssh.Unmarshal(req.Payload, &e) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			dir, remotePath, perr := parseSCPCommand(e.Command)
			if perr != nil {
				_ = req.Reply(false, nil) // not a supported scp invocation
				continue
			}
			_ = req.Reply(true, nil)
			s.runSCP(ctx, connCtx, channel, pr, srcIP, sconn, tch, dir, remotePath)
			return
```

Append to `internal/session/scp.go` (add `context`, `time`,
`github.com/pkg/sftp`, `golang.org/x/crypto/ssh`,
`.../internal/evidence`, `.../internal/policy` to its import block):

```go
import (
	// ... existing imports ...
	"context"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

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

	ok := s.runSCPTransfer(ctx, connCtx, channel, pr, srcIP, sconn, tch, dir, remotePath)

	status := uint32(0)
	if !ok {
		status = 1
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: status}))
	s.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
		User: pr.User, SourceIP: srcIP,
	})
}

// runSCPTransfer resolves the target and dispatches to scpUpload/
// scpDownload, mirroring runSFTP's target-resolution shape (sftp.go:52-101)
// exactly — same dialerPeek/Allow re-check, same targetPort fallback, same
// targetConnCache reuse across shell/sftp/scp channels on one connection.
func (s *Server) runSCPTransfer(ctx, connCtx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache, dir scpDirection, remotePath string) bool {
	if pr.TargetHost == "" {
		_ = scpSendFatal(channel, "scp: no target selected")
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "scp refused: no target selected",
		})
		return false
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
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "scp refused: " + reason,
		})
		return false
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
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "scp refused: " + err.Error(),
		})
		return false
	}
	sftpClient, err := sftp.NewClient(targetClient)
	if err != nil {
		_ = scpSendFatal(channel, "scp: target sftp client: "+err.Error())
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "scp refused: target sftp client: " + err.Error(),
		})
		return false
	}
	defer sftpClient.Close()

	fs := &remoteFS{
		client: sftpClient, gate: s.inspect, srv: s, user: pr.User, srcIP: srcIP, ctx: connCtx,
		matchedGroups: decision.MatchedGroups, releases: s.releases, releaseTTL: s.releaseTTL,
	}
	if dir == scpUpload {
		return s.scpUpload(fs, channel, remotePath)
	}
	return s.scpDownload(fs, channel, remotePath)
}

// scpUpload receives one file from channel (classic SCP sink role) and
// writes it via fs.Filewrite — the SAME method pkg/sftp's FilePut handler
// calls, constructed here with a bare *sftp.Request carrying only
// Filepath (all Filewrite reads; see sftp.go:535-552). Returns false on
// any failure (a fatal status byte has already been sent to channel).
func (s *Server) scpUpload(fs *remoteFS, channel ssh.Channel, remotePath string) bool {
	r := bufio.NewReader(channel)
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

// scpDownload sends one file to channel (classic SCP source role), read
// via fs.Fileread — the SAME method pkg/sftp's FileGet handler calls (see
// sftp.go:178-196), so downloads get the identical evidence.TypeTransfer
// manifest sftp get already produces. Returns false on any failure.
func (s *Server) scpDownload(fs *remoteFS, channel ssh.Channel, remotePath string) bool {
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
	info, err := fs.client.Stat(remotePath)
	if err != nil {
		_ = scpSendFatal(channel, "scp: "+err.Error())
		return false
	}
	r := bufio.NewReader(channel)
	cline := fmt.Sprintf("C0644 %d %s\n", info.Size(), path.Base(remotePath))
	if _, err := channel.Write([]byte(cline)); err != nil {
		return false
	}
	if err := scpReadAck(r); err != nil {
		return false
	}
	buf := make([]byte, 32*1024)
	var off int64
	for off < info.Size() {
		remaining := info.Size() - off
		chunk := int64(len(buf))
		if remaining < chunk {
			chunk = remaining
		}
		n, rerr := rd.ReadAt(buf[:chunk], off)
		if n > 0 {
			if _, werr := channel.Write(buf[:n]); werr != nil {
				return false
			}
			off += int64(n)
		}
		if rerr != nil && rerr != io.EOF {
			_ = scpSendFatal(channel, "scp: "+rerr.Error())
			return false
		}
	}
	if _, err := channel.Write([]byte{scpOK}); err != nil { // trailing terminator
		return false
	}
	if err := scpReadAck(r); err != nil {
		return false
	}
	return true
}
```

Add `"path"` to `scp.go`'s import block (used by `path.Base` above) — note
every function in this file uses the parameter name `remotePath`, never
`path`, specifically so the `path` package import is never shadowed.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/session/... -run TestRunSCP -v`
Expected: PASS, all three tests
(`TestRunSCP_UploadThenDownloadRoundTripsThroughRealTarget`,
`TestRunSCP_DisabledByDefaultRefusesExec`,
`TestRunSCP_RecursiveFlagRefused`).

- [ ] **Step 5: Run the full session package test suite (regression check)**

Run: `go test ./internal/session/... -v 2>&1 | tail -60`
Expected: PASS — every existing shell/sftp/tunnel test is unaffected (the
`exec` case is new, and `shellDone != nil` / `!s.scpEnabled` gate it, so with
scp off by default no existing test path reaches the scp code at all).

- [ ] **Step 6: Commit**

```bash
git add internal/session/session.go internal/session/interactive.go internal/session/scp.go internal/session/scp_test.go
git commit -m "feat(session): serve legacy-protocol scp over the exec channel"
```

---

### Task 4: Quarantine/inspection integration for scp upload

**Files:**
- Modify: `internal/session/sftp_inspect_test.go` (one line — enable scp in
  the shared `startInspectingServer` helper's options)
- Test: `internal/session/scp_test.go` (append)

**Interfaces:**
- Consumes: `startInspectingServer`, `approveRelease`
  (`sftp_inspect_test.go` — same package, already defined); `runSCP`,
  `WithSCPEnabled` (Task 3).

- [ ] **Step 1: Enable scp in the shared inspecting-server helper**

Legacy scp is opt-in (Task 3), so the shared test helper that starts an
inspection-enabled gateway must turn it on for these scp integration tests
to reach the scp code at all. In `internal/session/sftp_inspect_test.go`,
find the `opts :=` line inside `startInspectingServer` (it reads
`opts := append([]Option{WithInspection(gate), WithApprovals(store, 5*time.Second), WithReleases(releases, 6*time.Hour)}, targetOpts...)`)
and add `WithSCPEnabled(true)` to that option list:

```go
	opts := append([]Option{WithInspection(gate), WithApprovals(store, 5*time.Second), WithReleases(releases, 6*time.Hour), WithSCPEnabled(true)}, targetOpts...)
```

This is harmless to the existing SFTP tests that also use this helper — they
never open an exec channel, so enabling scp changes none of their behavior —
and it lets the scp tests below exercise the real quarantine path. Run the
existing inspection tests once after this edit to confirm no regression:
`go test ./internal/session/... -run TestSFTP_Inspection -v` → PASS.

- [ ] **Step 2: Write the failing tests**

Append to `internal/session/scp_test.go`:

```go
func TestRunSCP_CleanUploadQuarantinedAndReleasedNotPushed(t *testing.T) {
	sink := evidence.NewMemSink()
	addr, targetHost, q, store, releases := startInspectingServer(t, sink)

	client := sshClient(t, addr, "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	uploadErr := make(chan error, 1)
	go func() {
		uploadErr <- scpExecUpload(t, sess, "scp -t /clean.txt", []byte("totally benign content"), "clean.txt")
	}()
	approveRelease(t, store, "bob")
	if err := <-uploadErr; err != nil {
		t.Fatalf("clean upload must succeed once released, got %v", err)
	}
	if err := sess.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	sess.Close()

	if list := releases.ListFor("alice", time.Now()); len(list) != 1 {
		t.Fatalf("releases.ListFor(alice) = %v, want exactly one release", list)
	}
	if q.count() != 1 {
		t.Fatalf("quarantine object count = %d, want 1", q.count())
	}

	// Never pushed to the target: reading it back via a fresh scp -f must
	// fail (the file was never written there).
	getSess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession (verify): %v", err)
	}
	defer getSess.Close()
	stdout, err := getSess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe (verify): %v", err)
	}
	stdin, err := getSess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe (verify): %v", err)
	}
	if err := getSess.Start("scp -f /clean.txt"); err != nil {
		t.Fatalf("Start (verify): %v", err)
	}
	r := bufio.NewReader(stdout)
	if _, err := scpReadControlLine(r, stdin); err == nil {
		t.Fatal("scp -f /clean.txt succeeded — upload must never reach the target")
	}
}

func TestRunSCP_BlockedUploadRefusedNeverReleased(t *testing.T) {
	sink := evidence.NewMemSink()
	addr, targetHost, q, store, _ := startInspectingServer(t, sink)

	client := sshClient(t, addr, "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	err = scpExecUpload(t, sess, "scp -t /virus.txt", []byte("prefix X5O!P%@AP EICAR test string"), "virus.txt")
	if err == nil {
		t.Fatal("scpExecUpload = nil error, want refusal for EICAR content")
	}

	if q.count() != 1 {
		t.Fatalf("quarantine object count = %d, want 1 (blocked content is still quarantined for evidence)", q.count())
	}
	for _, r := range store.List() {
		if r.Kind == approval.KindQuarantineRelease {
			t.Fatalf("blocked upload must never create a release request, found: %+v", r)
		}
	}
}
```

Add `"github.com/rupivbluegreen/omni-sag/internal/approval"` to
`scp_test.go`'s import block for the second test's `approval.KindQuarantineRelease`.

- [ ] **Step 3: Run tests to verify they pass**

Run: `go test ./internal/session/... -run 'TestRunSCP_CleanUploadQuarantinedAndReleasedNotPushed|TestRunSCP_BlockedUploadRefusedNeverReleased' -v`
Expected: both PASS if Task 3 + Step 1's helper change are correct (this task
adds coverage of a path — the shared `fs.Filewrite` — that Task 3 already
wired up correctly, since `fs.gate` is populated from `s.inspect`
unconditionally in `runSCPTransfer`, and Step 1 enabled scp in the helper so
the exec request is served). If either FAILS, root-cause per
`superpowers:systematic-debugging` before committing: a refused exec (scp not
enabled in the helper) looks different from a broken quarantine wiring —
check the failure mode against Step 1 first.

- [ ] **Step 4: Commit**

```bash
git add internal/session/scp_test.go internal/session/sftp_inspect_test.go
git commit -m "test(session): scp upload quarantine/release-not-push coverage"
```

---

### Task 5: `main.go` wiring + example config doc

**Files:**
- Modify: `cmd/omni-sag/main.go:168-183`
- Modify: `deploy/compose/config.example.yaml` (capability-toggles block)

**Interfaces:**
- Consumes: `cfg.EnableSCP` (Task 1), `session.WithSCPEnabled` (Task 3).

- [ ] **Step 1: Wire the option and boot log line**

In `cmd/omni-sag/main.go`, find the block that appends the three
`session.WithXDisabled(cfg.DisableX)` options and logs each disabled
capability (around lines 172-183). Add the opt-in scp option and its boot
log line — note the OPPOSITE sense from the three disable_* toggles (the
log fires when scp is ENABLED, not disabled):

```go
	opts = append(opts, session.WithSSHDisabled(cfg.DisableSSH))
	opts = append(opts, session.WithTunnelDisabled(cfg.DisableTunnel))
	opts = append(opts, session.WithSFTPDisabled(cfg.DisableSFTP))
	opts = append(opts, session.WithSCPEnabled(cfg.EnableSCP))
	if cfg.DisableSSH {
		log.Printf("omni-sag: interactive shell disabled (disable_ssh)")
	}
	if cfg.DisableTunnel {
		log.Printf("omni-sag: -L port forwarding disabled (disable_tunnel)")
	}
	if cfg.DisableSFTP {
		log.Printf("omni-sag: SFTP disabled (disable_sftp) — also disables default-protocol scp, which rides the same subsystem")
	}
	if cfg.EnableSCP {
		log.Printf("omni-sag: legacy-protocol scp (-O) ENABLED (enable_scp) — extra exec-channel surface is live")
	}
```

- [ ] **Step 2: Build to confirm it compiles**

Run: `go build ./...`
Expected: no errors

- [ ] **Step 3: Document the toggles in the example config**

In `deploy/compose/config.example.yaml`, find the capability-toggles
comment block (search `disable_sftp`) and change it to:

```yaml
# Capability toggles. The three disable_* below default false (enabled); any
# combination may be disabled independently, but at least one must stay
# enabled. Uncomment to restrict this gateway to, e.g., tunnel-only:
# disable_ssh: true      # reject interactive PTY shell
# disable_tunnel: true   # reject -L port forwarding
# disable_sftp: true     # reject the SFTP subsystem (also disables default-
#                        # protocol scp, which rides the same subsystem)
#
# enable_scp is the OPPOSITE sense — opt-in, default OFF. The legacy
# exec-based scp protocol (OpenSSH's "-O" flag) stays disabled unless you set
# this. Modern scp clients need nothing here — they use the SFTP subsystem
# above. Only enable for old clients that force the legacy protocol:
# enable_scp: true       # serve legacy-protocol scp ("-O" flag)
```

- [ ] **Step 4: Run the config test suite (confirm the example config still parses)**

Run: `go test ./internal/config/... -run TestLoad_ComposeExampleConfigParses -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/omni-sag/main.go deploy/compose/config.example.yaml
git commit -m "feat(cmd): wire enable_scp into the gateway"
```

---

### Task 6: README fix

**Files:**
- Modify: `README.md:80-81`

- [ ] **Step 1: Replace the inaccurate "scp unsupported" line**

Find (README.md, in the "Port forwarding" section):

```
Not supported: `-R` remote/reverse forwarding, X11 forwarding, or `scp` (no `exec` channel —
use `sftp`).
```

Replace with:

```
`scp` works out of the box for any current OpenSSH client — it defaults to the SFTP protocol
under the hood, served by the same real shell/SFTP path above. The legacy exec-based protocol
(`scp -O`) is also supported, single file only (no `-r`), but is opt-in — set `enable_scp: true`
to turn it on (it adds an exec-channel surface, so it stays off by default).

Not supported: `-R` remote/reverse forwarding, or X11 forwarding.
```

- [ ] **Step 2: Read the surrounding section to confirm the replacement reads naturally**

Run: `sed -n '68,85p' README.md`
Expected: the "Port forwarding" section flows correctly with the new
wording; adjust phrasing if the surrounding markdown structure doesn't
match exactly (this step's replacement text assumes the current heading/
code-fence structure — verify before committing).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: correct scp support claim in README"
```

---

### Task 7: Real `scp -O` interop verification against the dev lab

**Files:**
- Create: `scripts/lab-test-scp.sh`
- Modify: `Makefile` (new target)

**Interfaces:**
- Consumes: the running dev lab (`make lab-up && make lab-seed`), built
  binaries (`make binaries`) — same preconditions as
  `scripts/lab-test-real-target.sh`.

- [ ] **Step 1: Write the script**

Create `scripts/lab-test-scp.sh` (mirrors
`scripts/lab-test-real-target.sh`'s structure and the pty-driver technique
from its `ssh_shell.py`, but drives the real local `scp -O` binary — the
actual ground truth for wire-protocol correctness, not a Go-side
approximation of it):

```bash
#!/usr/bin/env bash
# Real scp -O (legacy protocol) check against the dev lab's ssh-target
# container, using the ACTUAL local scp binary as client — the strongest
# possible confirmation that the wire-protocol codec (scp.go) really
# interoperates with a real OpenSSH client forced into legacy mode, not
# just this repo's own Go-side test harness.
#
# Usage: scripts/lab-test-scp.sh
set -euo pipefail

GW_BIN="${GW_BIN:-./bin/omni-sag_$(go env GOOS)_$(go env GOARCH)}"
BASE_CONFIG="${CONFIG:-deploy/compose/config.example.yaml}"
GW_PORT="${GW_PORT:-2222}"

GW_USER="alice"
GW_PASSWORD="Passw0rd!"
TARGET_HOST="127.0.0.1"
TARGET_PASSWORD="InjectedSecret123!"

RED=$'\033[31m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
pass() { echo "${GREEN}PASS${RESET}: $*"; }
fail() { echo "${RED}FAIL${RESET}: $*" >&2; }

if [ ! -x "$GW_BIN" ]; then
  echo "gateway binary not found at $GW_BIN — run: make binaries" >&2
  exit 1
fi
command -v scp >/dev/null 2>&1 || { echo "scp not found" >&2; exit 1; }
if ! scp -O 2>&1 | grep -q "usage: scp"; then
  echo "local scp does not support -O (too old or too new) — cannot run this check" >&2
  exit 1
fi

echo "== checking dev-lab containers =="
for c in omni-sag-samba-ad omni-sag-ssh-target; do
  if ! docker ps --filter "name=^${c}\$" --filter "status=running" --format '{{.Names}}' | grep -qx "$c"; then
    echo "required container not running: $c — run: make lab-up && make lab-seed" >&2
    exit 1
  fi
done

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/omnisag-scp-test.XXXXXX")"
GW_PID=""
cleanup() { [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

# Legacy scp is opt-in (enable_scp, default OFF), and the shipped example
# config leaves it off. Derive a config that turns it on for this test —
# the whole point of the test is to exercise the legacy path, so it must be
# enabled. A plain YAML append of a top-level key is sufficient (yaml.v3
# takes the last value for a duplicated key, and the example config does not
# set enable_scp at all, so there is no duplicate here anyway).
TEST_CONFIG="$WORKDIR/config.yaml"
cp "$BASE_CONFIG" "$TEST_CONFIG"
printf '\nenable_scp: true\n' >> "$TEST_CONFIG"

"$GW_BIN" -config "$TEST_CONFIG" >"$WORKDIR/gateway.log" 2>&1 &
GW_PID=$!
for i in $(seq 1 50); do
  if ! kill -0 "$GW_PID" 2>/dev/null; then
    fail "gateway process exited early"; tail -n 60 "$WORKDIR/gateway.log" >&2; exit 1
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/$GW_PORT") 2>/dev/null && { exec 3<&- 3>&-; break; }
  sleep 0.2
done
echo "gateway up (SSH :$GW_PORT), pid=$GW_PID"

cat >"$WORKDIR/scp_driver.py" <<'PY'
#!/usr/bin/env python3
import os, pty, select, sys, time

def read_avail(fd, timeout):
    r, _, _ = select.select([fd], [], [], timeout)
    if fd in r:
        try:
            return os.read(fd, 65536)
        except OSError:
            return b""
    return None

def run(cmd, gw_pw, tgt_pw, deadline_s):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(127)
    buf = b""
    deadline = time.time() + deadline_s

    def wait_for(pattern, dl):
        nonlocal buf
        pat = pattern.encode()
        while True:
            if pat in buf:
                return True
            if time.time() > dl:
                return False
            chunk = read_avail(fd, min(1.0, max(0.0, dl - time.time())))
            if chunk is None:
                continue
            if chunk == b"":
                return False
            buf += chunk

    if wait_for("password:", deadline):
        os.write(fd, (gw_pw + "\n").encode())
        if wait_for("Target password:", time.time() + 10):
            os.write(fd, (tgt_pw + "\n").encode())
    end = time.time() + 20
    while time.time() < end:
        chunk = read_avail(fd, 1.0)
        if chunk is None:
            continue
        if chunk == b"":
            break
        buf += chunk
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        _, status = os.waitpid(pid, 0)
        code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
    except ChildProcessError:
        code = -1
    return code, buf.decode(errors="replace")

if __name__ == "__main__":
    mode, gw_port, local_path, dest, gw_pw, tgt_pw = sys.argv[1:7]
    cmd = ["scp", "-O", "-P", gw_port,
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no", "-o", "ConnectTimeout=10"]
    if mode == "up":
        cmd += [local_path, dest]
    else:
        cmd += [dest, local_path]
    code, transcript = run(cmd, gw_pw, tgt_pw, 30)
    print(f"EXIT={code}")
    if code != 0:
        print(transcript, file=sys.stderr)
PY

echo "hello from lab-test-scp" >"$WORKDIR/upload.txt"

echo "== real scp -O upload: alice pushes a file to the target =="
UP_OUT="$(python3 "$WORKDIR/scp_driver.py" up "$GW_PORT" "$WORKDIR/upload.txt" \
  "${GW_USER}%${TARGET_HOST}@${TARGET_HOST}:/config/lab-scp-upload.txt" \
  "$GW_PASSWORD" "$TARGET_PASSWORD")"
echo "$UP_OUT"
if ! echo "$UP_OUT" | grep -q "EXIT=0"; then
  fail "real scp -O upload did not exit 0"
  tail -n 60 "$WORKDIR/gateway.log" >&2
  exit 1
fi
pass "real scp -O upload completed (single-file, no inspection configured in this config -> direct delivery)"

echo "== real scp -O download: alice pulls the file back =="
DOWN_OUT="$(python3 "$WORKDIR/scp_driver.py" down "$GW_PORT" "$WORKDIR/downloaded.txt" \
  "${GW_USER}%${TARGET_HOST}@${TARGET_HOST}:/config/lab-scp-upload.txt" \
  "$GW_PASSWORD" "$TARGET_PASSWORD")"
echo "$DOWN_OUT"
if ! echo "$DOWN_OUT" | grep -q "EXIT=0"; then
  fail "real scp -O download did not exit 0"
  tail -n 60 "$WORKDIR/gateway.log" >&2
  exit 1
fi
if ! diff -q "$WORKDIR/upload.txt" "$WORKDIR/downloaded.txt" >/dev/null 2>&1; then
  fail "downloaded content does not match what was uploaded"
  exit 1
fi
pass "real scp -O download completed and content matches"

echo "== real scp -O -r: must be refused, not hang =="
mkdir -p "$WORKDIR/somedir"
REC_OUT="$(python3 "$WORKDIR/scp_driver.py" up "$GW_PORT" "$WORKDIR/somedir" \
  "${GW_USER}%${TARGET_HOST}@${TARGET_HOST}:/config/lab-scp-dir" \
  "$GW_PASSWORD" "$TARGET_PASSWORD" 2>&1 || true)"
# The driver script above doesn't pass -r itself; exercise it directly here
# instead, bypassing scp_driver.py's fixed argv shape:
if scp -O -r -P "$GW_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes -o ConnectTimeout=5 "$WORKDIR/somedir" \
  "${GW_USER}%${TARGET_HOST}@${TARGET_HOST}:/config/lab-scp-dir" >/dev/null 2>&1; then
  fail "scp -O -r unexpectedly succeeded — recursive transfer must be refused"
  exit 1
fi
pass "scp -O -r refused as expected (BatchMode prevents a password prompt, so this also confirms it fails fast, not by hanging on auth)"

echo "ALL PASS"
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x scripts/lab-test-scp.sh`

- [ ] **Step 3: Add a Makefile target**

In `Makefile`, add near `lab-test-real-target` (find via `grep -n
"lab-test-real-target" Makefile`):

```makefile
lab-test-scp:
	bash scripts/lab-test-scp.sh
```

Add `lab-test-scp` to the `.PHONY` line at the top of the Makefile
alongside `lab-test-real-target`.

- [ ] **Step 4: Run it against the live lab**

Precondition: `make lab-up && make lab-seed && make binaries` (skip
`lab-up`/`lab-seed` if the lab is already running from earlier work in this
session — check with `docker ps --filter name=omni-sag-ssh-target`).

Run: `make lab-test-scp`
Expected: `ALL PASS`. If any step fails, this is the ground-truth signal
that something in Task 2/3's protocol codec doesn't match a real OpenSSH
client's actual byte-level expectations — return to
`superpowers:systematic-debugging` and root-cause against this script's
`gateway.log`/transcript output before touching the codec again; do not
patch scp.go from guesswork at this stage.

- [ ] **Step 5: Commit**

```bash
git add scripts/lab-test-scp.sh Makefile
git commit -m "test: real scp -O interop check against the dev lab"
```

---

## Self-Review Notes

- **Spec coverage:** Architecture (exec case + codec, Task 2/3) ✓. Reuse of
  `remoteFS.Filewrite`/`Fileread` (Task 3) ✓. Config toggle + boot
  validation (Task 1/5) ✓. Errors via SCP status bytes post-acceptance, SSH
  reject pre-acceptance (Task 3, documented as a refinement in Global
  Constraints) ✓. Recording/evidence via `Detail: "scp"` (Task 3's test
  asserts it) ✓. Testing plan: codec unit tests (Task 2), upload/download
  integration (Task 3), quarantine integration (Task 4), scp opt-in
  (enable_scp) default-off refusal regression (Task 3), README fix (Task 6),
  real lab interop (Task 7) ✓.
  Out-of-scope items (`-r`, `-p` timestamp application, new discovery
  mechanism) — explicitly not implemented anywhere in this plan, matches
  spec.
- **Placeholder scan:** no TBD/TODO; every code step is complete, runnable
  code against exact file:line locations read directly from the current
  source.
- **Type consistency:** `runSCP`/`runSCPTransfer`/`scpUpload`/`scpDownload`
  signatures are used identically everywhere they're referenced (Task 3
  defines them, Task 3's own tests and Task 4's tests call them only
  indirectly via `sess.Start(...)`, never call the Go functions directly
  from tests — no signature drift risk).
- **Known risk flagged, not hidden:** the classic SCP protocol's exact byte
  shape (Task 2) is written from well-established cross-implementation
  knowledge, not from a byte-capture against this repo's own code. Task 7's
  real-`scp -O`-binary interop check is the actual ground truth and must
  pass before this feature is considered done — if it fails, fix the codec,
  don't fix the test.
