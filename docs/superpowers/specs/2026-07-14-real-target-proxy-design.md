# Real-target SSH/SFTP proxy — design

**Status:** Approved (brainstorming), not yet implemented
**Date:** 2026-07-14

## Context

Omni-SAG's port-forwarding path (`ssh -L`) already dials real targets end to
end: `internal/dialer.DialTarget` authorizes against policy, opens a real
`net.Conn`, and the demo (`docs/assets/demo.cast`) proves it live. The
interactive shell and SFTP subsystem do not: per ADR-0002 ("The stand-in
boundary"), both are gateway-terminated stand-ins. The interactive shell
(`internal/session/interactive.go`) echoes typed input back to the user
without touching a target. SFTP (`internal/session/sftp.go`) serves an
in-memory filesystem (`memFS`) that never persists past the session and never
reaches a real host.

This means two of the product's three session types (shell, SFTP; tunnel is
the third) have no real-world use today — only the tunnel path is production
capable. This design closes that gap: it gives the gateway a second SSH leg to
a real target and bridges the shell/SFTP channels to it, while preserving
every existing security property (fail-closed credential handling, no-silent-
downgrade, content inspection on upload, full session recording, tamper-
evident audit).

## Architecture

The gateway becomes an SSH *client* to the target, not just a server. The
client's SSH connection terminates at the gateway exactly as it does today
(LDAPS + MFA auth, `handleSession` channel dispatch). On the first `shell` or
`sftp` request within an authenticated connection, the gateway lazily dials a
second, independent `ssh.Client` connection to the resolved target and
authenticates to it per the target's configured credential mode. That
`ssh.Client` is reused for any further channels opened on the same gateway
connection and closed when the client disconnects.

Raw byte-splicing (the mechanism `-L` port-forwarding already uses) does not
work here: the client's SSH transport terminates at the gateway, so the
"shell"/"sftp" channel bytes are plaintext application data, not an SSH
wire stream the target would understand. Reaching a real target's shell or
SFTP server requires the gateway to speak a genuine second SSH conversation as
a client — there is no simpler alternative that preserves inspection and
recording.

## Target selection

A plain `ssh alice@gw` carries no target information — unlike `-L`, where the
SSH protocol's `direct-tcpip` request carries host:port directly. The target
is instead encoded in the auth username: `ssh alice%db1.lab.local@gw`.

`internal/session/session.go`'s `passwordCallback` splits `meta.User()` on
`%` into `(loginUser, targetHost)` *before* calling `auth.Authenticate`, so
LDAPS only ever sees `alice`. The parsed target host is stored in
`ssh.Permissions.Extensions["target_host"]`, alongside the existing
`user`/`groups` keys, for later channel handlers to read. Target port comes
from the policy rule that matches (or a configured default, e.g. 22, when the
rule allows any port).

## Target account mapping

`policy.Rule` gains a new field:

```go
type Rule struct {
    Host            string
    Ports           []int
    Record          RecordMode
    Credential      string
    RequireApproval bool
    TargetUser      string // NEW: account to authenticate as on the target.
                            // Empty => same as the gateway login name.
}
```

`internal/config.RuleConfig` gains the matching `target_user` YAML field, and
`policy.Decision` carries `TargetUser` through `Decide`.

## Second-leg authentication, per credential mode

The existing four-mode model (`internal/credential`: inject / prompt /
passthrough / deny) already gates *whether* a target credential is available;
this feature is what actually *uses* it to authenticate the gateway's second
SSH leg, replacing today's fetch-then-destroy stand-in
(`internal/dialer.resolveCredential`, see ADR-0002 "when real target
authentication lands").

- **inject** — `credential.Provider.Resolve` already fetches a `*Secret` from
  CyberArk. Instead of destroying it immediately, it is used to build the
  target `ssh.ClientConfig.Auth` (`ssh.Password` or a parsed signer,
  depending on what CyberArk returns), then `Destroy()`d immediately after the
  target handshake completes (success or failure) — never cached, never
  logged, same JIT-then-zeroize discipline as ADR-0001.

- **prompt** — currently a no-op stub
  (`Result{Outcome: OutcomePrompt}, nil` with no actual prompting). This
  design implements it for real via `golang.org/x/crypto/ssh`'s
  `ssh.PartialSuccessError`: after LDAPS + MFA succeed in `passwordCallback`,
  and once the parsed target's policy decision is known (requires a new
  non-dialing `Policy.Decide` peek reachable from `session.Server`, without
  duplicating `dialer`'s evidence-emitting `DialTarget` path), if the
  decision's `CredentialMode` is `prompt`, `passwordCallback` returns a
  `PartialSuccessError` pointing at a new `KeyboardInteractiveCallback`. That
  callback prompts `"Target password:"` with echo disabled — genuine
  SSH-protocol-native echo suppression, not a mid-channel hack. The collected
  password lives only for the connection's lifetime and is zeroized right
  after the target dial.

- **passthrough** — real OpenSSH agent forwarding. The client must request it
  (`ssh -A`); the gateway accepts the forwarded `auth-agent@openssh.com`
  channel, wraps it with `golang.org/x/crypto/ssh/agent`, and uses its
  `Signers()` for the target `ssh.ClientConfig.Auth` — the target
  authenticates the human as themselves, not the gateway. No forwarded agent,
  or no usable signer for the target, fails closed (no downgrade to another
  mode — same FR-18 posture `inject` already has).

- **deny** — refused before any channel opens, exactly as today.

Every second-leg auth attempt emits the existing `evidence.TypeCredential`
event (mode, target, outcome, reason) — never the secret — same as today.

## Interactive shell

`runRecordedShell` (`internal/session/interactive.go`) stops echoing input
locally. Instead it opens a `session` channel on the target `ssh.Client`,
requests a PTY sized to match the client's `pty-req`, requests `shell`, and
forwards subsequent `window-change` resizes to the target channel. Bytes are
piped bidirectionally between the client's channel and the target's channel.
The existing `recording.Recorder` wraps the same `Input`/`Output` calls
regardless of which end produced the bytes — the recording/evidence code
requires no change.

## SFTP

`runSFTP` (`internal/session/sftp.go`) replaces `memFS` with a real
`pkg/sftp` client (`sftp.NewClient`) over the target `ssh.Client`.

**Uploads (quarantine-then-release).** Two alternatives were rejected: a
local-disk temp-file spool (conflicts with the gateway's
read-only-root-filesystem posture) and a stream-with-rollback delivery
(leaves a window where blocked content briefly exists on the real target).
Instead this reuses infrastructure that already exists but is
under-utilized or entirely dead code:

- `internal/inspectgate.Gate` already has a `Holding` BlobStore (transient,
  S3/MinIO-backed, used today only for large-file streaming) and a
  `Quarantine` BlobStore (WORM/Object-Locked, used today only for
  blocked/fail-closed content). This design extends `Gate` so **every**
  upload's bytes persist to `Quarantine`, not just blocked ones — today a
  clean small upload is discarded after hashing and a clean large upload's
  holding copy is never promoted anywhere, so there is currently no
  byte-for-byte record of what was actually uploaded. Unconditional
  quarantine fixes that gap as a side effect.
- `internal/approval.KindQuarantineRelease` is already declared
  (`internal/approval/approval.go`) and completely unused anywhere in the
  codebase. This design wires it up: a clean-verdict upload does not deliver
  to the target in the same SFTP call. It creates an `approval.Request{Kind:
  KindQuarantineRelease, ...}` referencing the quarantine key and target
  path, through the same `Store`/`Create`/`Wait` machinery — and the same
  TUI/API approval queue — that session-access approvals already use
  (Slices 8–9), just a different `Kind`.
- The SFTP write handle's `Close()` blocks on the release decision, mirroring
  `dialer.gateApproval`'s session-blocking pattern, up to the approval TTL.
  On approval, the gateway opens the target SFTP connection **at that
  point** (not held open for the duration of the wait), streams
  quarantine→target, and `Close()` returns success. On denial/expiry,
  `Close()` errors and the client's transfer fails — the bytes remain in
  quarantine permanently as evidence; they are never deleted and never
  reach the target.
- This is **always** required when a rule has inspection enabled — not a
  separate opt-in policy flag. One consistent rule: inspected upload ⇒
  quarantined ⇒ needs a human release. Blocked/unscannable content was
  already fail-closed before this design; now clean content is fail-closed
  too, pending a second human.
- This approval is independent of and stacks with the dialer's existing
  session-level `RequireApproval` (which gates whether a session can reach
  a target at all). A target can require approval to log into, and
  separately require approval for every file pushed to it.

**Downloads.** `Fileread` proxies directly from the remote file, unchanged
from today's behavior (downloads are not content-inspected, not quarantined).

Transfer and approval evidence continue to be emitted through the existing
event types (`evidence.TypeTransfer`, `evidence.TypeApproval`,
`evidence.TypeInspection`), extended to carry the quarantine key and release
outcome.

## Lab / demo wiring

`deploy/compose/docker-compose.yml` gains a lightweight OpenSSH container
(e.g. `linuxserver/openssh-server`) with one or two demo accounts.
`deploy/compose/config.example.yaml` gains a real `Rule` pointing at it, with
`target_user` set and `credential: inject` as the headline mode (the mock
CyberArk CCP plumbing already exists end to end).

## Testing

- Unit tests for username parsing (`alice%host` splitting) and target-user
  resolution — pure, table-driven, alongside existing `policy` tests.
- Unit tests for the quarantine-then-release flow: clean upload blocks on
  `Close()` until a `KindQuarantineRelease` request resolves; approved
  delivers to a fake target and the quarantine copy persists; denied/expired
  errors `Close()` and the quarantine copy still persists; blocked-verdict
  content never creates a release request at all.
- Auth-mode fork tests using a fake `ssh.Client`/agent substitution, mirroring
  the existing `netDial` package-variable substitution pattern in
  `internal/dialer`'s tests.
- A docker-lab integration test that runs a real shell command and a real
  SFTP put/get against the new target container end to end.

## Explicitly out of scope for this design

- Any change to the tunnel (`-L`) path — it already works.
- Any change to policy evaluation semantics beyond adding `TargetUser`.
- CyberArk real interop (still the existing mock CCP).
