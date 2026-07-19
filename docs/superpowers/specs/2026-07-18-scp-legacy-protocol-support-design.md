# scp (legacy `-O` protocol) support — design

**Status:** Approved (brainstorming), not yet implemented
**Date:** 2026-07-18

## Context

`README.md` currently states scp is unsupported ("no `exec` channel — use
`sftp`"). That claim is only half true. Verified directly against a running
gateway (`deploy/compose/config.example.yaml`, real LDAP, real ssh-target
container):

- Plain `scp file alice%host@gw:/path` (no flags) — **already works today,
  both directions**, full content roundtrip confirmed. OpenSSH 8.x+ (this
  box: 9.6p1, the default on any current distro) no longer uses the classic
  exec-based scp wire protocol by default; it transparently uses the SFTP
  protocol instead, over the same `subsystem sftp` request `runSFTP`
  (`internal/session/sftp.go:52`) already serves. Evidence confirms it:
  `session_start ... Detail: sftp`.
- `scp -O file alice%host@gw:/path` (explicit legacy-protocol flag) —
  **fails**: `exec request failed on channel 0`. `-O` forces the classic
  protocol, which rides an `"exec"` channel request
  (`scp -t <path>` / `scp -f <path>`). `internal/session/interactive.go`'s
  session-channel request switch (`interactive.go:65-134`) has no `case
  "exec"` at all — it falls to `default` (`interactive.go:131`) and gets
  `req.Reply(false, nil)`.

So this design covers the legacy `-O` gap only. Default scp needs no new
code and should be documented as supported once this ships (README's "not
supported" line is already inaccurate for the common case and gets fixed
alongside this work).

**Two independent toggles will govern scp after this ships**, and that
split is worth stating plainly to avoid confusion later: `disable_sftp`
already gates default-protocol scp today (same `subsystem sftp` path as
interactive SFTP — no change needed). The new `disable_scp` toggle
introduced here gates *only* the new legacy `-O` exec-channel path.

## Architecture

**Client-facing side** (new): add `case "exec"` to the session-channel
request switch (`interactive.go:65-134`), narrow grammar only — exactly
`scp -t <path>` (upload) or `scp -f <path>` (download), optionally preceded
by client flags OpenSSH's legacy scp emits (`-p` preserve-times is accepted
and its `T<mtime> 0 <atime> 0` control line is parsed and acknowledged, but
not applied to the target file — out of scope to plumb through `*sftp.Client`
in this pass). Any `-r`, any unrecognized flag, or any command that isn't
exactly this shape is refused with a real SCP-protocol error (see Errors
below), not a silent channel reject — a legacy client should print a
sensible message, not hang.

New file `internal/session/scp.go`: a codec for the classic SCP wire
protocol — control line (`C<mode> <size> <name>\n`), single-byte acks
(`\0` success, `\1`/`\2` + message on warning/fatal), body bytes. Nothing
is ever shell-invoked; the command string is parsed, never executed.

**Target-facing side**: no new work. Both directions reuse the target's
existing `*sftp.Client` (`dialTarget/targetConnCache`, the same dial used by
`runSFTP`) — the target only ever sees SFTP, never a second exec-based scp
process. This mirrors `runSFTP`'s own framing (`sftp.go:27-36`): terminate
the client-visible protocol at the gateway, keep the target leg uniform.

## Reuse

`remoteFS.Filewrite`/`Fileread` (`sftp.go:535-552`, `186-196`) hold all the
inspection/quarantine/release/evidence logic already. This design extracts
their core into two shared functions — an upload core (bytes in → inspect →
quarantine → approval wait → release, exactly `quarantineWriteHandle`'s
`doClose` today) and a download core (target file → tap → evidence) — that
both `pkg/sftp`'s `Handlers` glue and the new scp codec call. No behavior
duplication, no drift between the two protocols' upload/download semantics.

**Consequence to flag explicitly, same as SFTP put today**: a clean-verdict
`scp -O file.txt alice%host@gw:/etc/x` does **not** put the file at
`/etc/x` on the target. It lands in quarantine, needs a four-eyes approval,
and is retrievable only via `/releases` pull-download by the uploader —
identical to `sftp put`'s existing behavior (`sftp.go:663`,
`"released to /releases ... not pushed to target"`). Classic SCP's ack byte
gives no room for a friendly message on success (real scp prints nothing but
a progress meter), so this is undiscoverable from the scp command itself —
the uploader learns it the same way sftp users already do today: `sftp` into
the same target and `ls /releases`, or check evidence/TUI. No new discovery
mechanism proposed here; this is an existing, accepted limitation being
inherited, not introduced.

When inspection is not configured (`fs.gate == nil`), uploads deliver
straight to target exactly like sftp put today — no quarantine detour.

## Data flow

**Upload** (`scp -O file alice%host@gw:/path`): exec request → grammar
check → policy decision (same `dialerPeek`/`pr.TargetHost` check as
`runSFTP`/`runRecordedShell` — scp, like sftp/shell, is only reachable via
the `user%host` real-target syntax, never via a bare `-L` tunnel login) →
`dialTarget` (cached, shared with any concurrent shell/sftp channel on the
same connection) → read control line, ack, stream body through the shared
upload core → quarantine/approval/release → final ack or SCP-protocol error
byte back to the client.

**Download** (`scp -O alice%host@gw:/path file`): exec request → grammar
check → policy decision → `dialTarget` → `Stat`+`Open` on the target via
`*sftp.Client` → write control line, stream bytes through the shared
download core (tap for evidence), wait for client ack, done.

## Config toggle

```go
DisableSCP bool `yaml:"disable_scp"` // internal/config/config.go
```

`WithSCPDisabled` functional option (session.go, alongside
`WithSSHDisabled`/`WithTunnelDisabled`/`WithSFTPDisabled`), wired in
`cmd/omni-sag/main.go`. Checked at request level inside the new `case
"exec"`, same granularity as `case "shell"` (`interactive.go:87`) and
`case "subsystem"` (`interactive.go:122`) — not at the channel-type level,
since `exec` lives inside the same `"session"` channel type as shell/sftp.

The boot-time "not all capability toggles can be true" validation
(`config.go:276-278`) extends from three flags to four.

## Errors

Classic SCP protocol convention: a byte-prefixed status (`\0` ok, `\1`
warning + message line, `\2` fatal + message line) is how the real `scp`
binary learns something went wrong and prints it cleanly, instead of hanging
or garbling. Every refusal path in this design (malformed/unsupported exec
command, `-r` requested, no target selected, policy deny, quarantine-blocked
content, `disable_scp` set) sends a `\2` fatal + message, not a bare channel
close.

## Recording / evidence

No asciicast recording — same as SFTP (`sftp.go` never calls the recorder).
`TypeSessionStart`/`TypeSessionEnd` with `Detail: "scp"` (vs. `"sftp"`) so
evidence readers can tell the two protocols apart; `TypeInspection`,
`TypeApproval`, `TypeTransfer` events reuse the same shapes as SFTP's,
distinguished the same way via `Detail` (e.g. `"scp content inspection"`).
No `evidence.Event` schema change needed — `Detail` is already the
documented "freeform, anything not yet promoted to a field" escape hatch.

## Testing plan

- `internal/session/scp.go` codec unit tests: control-line parse/generate,
  ack byte handling, zero-byte file, oversized declared size, malformed
  control line, `-r` rejection, any exec command outside the exact grammar.
- Upload integration test: reuses the sftp quarantine-flow test pattern —
  clean verdict quarantines + requires approval + never reaches target;
  blocked/unscannable verdict refuses outright with a `\2` error the client
  can read.
- Download integration test: content identity against a real target file,
  evidence manifest correctness, nonexistent path reported as `\2` fatal.
- `disable_scp` regression: exec refused regardless of policy when set;
  boot-time validation extended to four flags, still refuses all-four-true.
- Regression: confirm default-protocol scp (no `-O`) is unaffected — it
  never touches the new `exec` case at all, only `subsystem sftp`.
- Extend `scripts/lab-test-real-target.sh` (or a sibling script) with a real
  `scp -O` client run via the existing pty-driver pattern
  (`ssh_shell.py`/`sftp_put.py`'s technique), against the running lab.
- README fix: replace the "scp: no `exec` channel — use `sftp`" line with
  accurate wording (default scp already works via SFTP; `-O` legacy mode
  needs this feature).

## Out of scope

- Recursive `-r` (directory trees) — classic protocol's nested `C`/`D`/`E`
  control records add real parser complexity; single-file only for this
  pass, `-r` becomes a fast-follow once this path is proven.
- `-p` preserve-times: control line is parsed/acknowledged so the client
  doesn't error out, but the timestamp is not applied to the target file via
  `*sftp.Client` (no immediate use case forcing this; `SetStat`-equivalent
  wiring is a small follow-up if needed).
- Any new discovery mechanism for "your upload is sitting in /releases,
  approved" beyond what SFTP users already have (evidence/TUI/`sftp
  ls /releases`) — explicitly inherited limitation, not solved here.
