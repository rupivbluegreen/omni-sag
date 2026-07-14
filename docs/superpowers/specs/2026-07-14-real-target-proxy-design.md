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

**Uploads (spool-then-commit).** The existing offset-reassembly and
inspection-gate machinery (`inspectUpload`) is unchanged; it now streams into
a temp-file spool (replacing the 64 MiB in-memory buffer with a disk-backed
one, same size philosophy) instead of directly into the target. Only after
the inspector returns Allow does the gateway open the real remote file and
push the spooled bytes. Blocked or unscannable content never reaches the
target — this preserves the fail-closed guarantee more strongly than a
stream-with-rollback approach (considered and rejected: it would let blocked
bytes briefly exist on the real target and adds a rollback-can-fail residual
risk).

**Downloads.** `Fileread` proxies directly from the remote file, unchanged
from today's behavior (downloads are not content-inspected).

Transfer manifests and inspection evidence continue to be emitted exactly as
today.

## Lab / demo wiring

`deploy/compose/docker-compose.yml` gains a lightweight OpenSSH container
(e.g. `linuxserver/openssh-server`) with one or two demo accounts.
`deploy/compose/config.example.yaml` gains a real `Rule` pointing at it, with
`target_user` set and `credential: inject` as the headline mode (the mock
CyberArk CCP plumbing already exists end to end).

## Testing

- Unit tests for username parsing (`alice%host` splitting) and target-user
  resolution — pure, table-driven, alongside existing `policy` tests.
- Auth-mode fork tests using a fake `ssh.Client`/agent substitution, mirroring
  the existing `netDial` package-variable substitution pattern in
  `internal/dialer`'s tests.
- A docker-lab integration test that runs a real shell command and a real
  SFTP put/get against the new target container end to end.

## Explicitly out of scope for this design

- Any change to the tunnel (`-L`) path — it already works.
- Any change to policy evaluation semantics beyond adding `TargetUser`.
- CyberArk real interop (still the existing mock CCP).
