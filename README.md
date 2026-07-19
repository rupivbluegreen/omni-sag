<div align="center">

<img src="docs/assets/logo.svg" alt="Omni-SAG" width="440" />

### the SSH bastion that keeps the receipts

*Your servers' bouncer. Every login checked, every shell/tunnel/transfer authorized, every byte
accounted for — with a tamper-evident paper trail you can verify offline, even with the gateway
switched off.*

[![CI](https://github.com/rupivbluegreen/omni-sag/actions/workflows/ci.yml/badge.svg)](https://github.com/rupivbluegreen/omni-sag/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-ffb000.svg)](LICENSE)
[![Go 1.25](https://img.shields.io/badge/go-1.25-00ADD8.svg)](go.mod)
[![fails](https://img.shields.io/badge/fails-closed%20on%20purpose-ff6b6b.svg)](docs/audit/fail-closed-matrix.md)
[![reviewed](https://img.shields.io/badge/reviewed-adversarially-57d98a.svg)](#-how-it-was-built)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ffb000.svg)](CONTRIBUTING.md)

**[🌐 Website](https://rupivbluegreen.github.io/omni-sag/) · [🚀 Quickstart](#-60-seconds-to-whoa) · [🧾 Audit pack](docs/audit/) · [🗺️ Roadmap](#️-roadmap)**

</div>

---

## 👋 What even is this?

Point your team at **Omni-SAG** instead of straight at your boxes. It authenticates them against
Active Directory (with MFA), decides exactly what they're allowed to reach — a real shell, SFTP,
or just a forwarded port — and writes down *everything* in a way nobody can quietly edit later.
The default answer is always **no**; access is something you earn, per connection.

It's **open source**, built in the open for anyone who thinks privileged access should come with
receipts. No enterprise sales call required. 🙂

```console
$ ssh -L 5432:db1.lab.local:5432 alice@gateway     # alice ∈ dba
✔ ALLOWED · role=dba · tunnel open · evidence: tunnel_decision allow=true

$ ssh -L 5432:db1.lab.local:5432 bob@gateway       # bob ∉ dba
✘ administratively prohibited · evidence: tunnel_decision allow=false

$ omni-verify -bundle ./evidence -pubkey $KEY
PASS — evidence bundle is intact and authentic.
# flip one byte…
FAIL — TAMPER: record hash mismatch. loudly.
```

That's not a mockup — it's a real recorded run: **[▶ watch it live](https://rupivbluegreen.github.io/omni-sag/#start)**
(same lab, same two users, same tamper — the raw [asciicast](docs/assets/demo.cast) is in the repo too).

## ✨ Features

Exact features, minimal fluff — every line below is backed by code, not a roadmap slide.

**🔐 AD + MFA** — LDAPS bind against Active Directory, then RADIUS MS-CHAPv2 as a second factor
(never PAP; interactive OTP fails closed over the SSH password path since it can't prompt). Roles
bind to AD groups; set `ldap.nested_groups` to resolve transitive (AGDLP-nested) membership via
`LDAP_MATCHING_RULE_IN_CHAIN` — matching what `id -nG` sees rather than only a direct `memberOf`
read (default off).
```yaml
mfa:
  enabled: true
  radius: { server: "radius.corp.local:1812", secret: "...", nas_identifier: "omni-sag" }
ldap:
  nested_groups: true    # resolve transitive/AGDLP group membership (default off)
```

**🖥️ Real shell & SFTP on the target** — `user%host` in the SSH username picks a real target; the
gateway opens a genuine second SSH leg and proxies an actual PTY shell or SFTP session to it. Not
a stand-in.
```console
$ ssh 'alice%db1.lab.local'@gateway -p 2222
$ sftp 'alice%db1.lab.local'@gateway -P 2222
```
The matching policy rule must resolve to exactly one host and one port (ambiguous matches fail
closed, not "pick one"). When a host is reachable through more than one of your roles the match is
ambiguous — add a `+pcode` selector (the policy role name) to choose which role the session runs
under: `ssh 'alice+dba%db1.lab.local'@gateway`.

**🚇 Port forwarding** — `-L` tunnels are policy-gated per host:port; `-D` dynamic SOCKS forwarding
rides the same `direct-tcpip` channel, and `-J` ProxyJump works too (a jump is just another
`direct-tcpip` open).
```console
$ ssh -L 5432:db1.lab.local:5432 alice@gateway
$ ssh -D 1080 alice@gateway
$ ssh -J alice@gateway alice@db1.lab.local
```
Running `-L` without `-N` keeps the session open as a keeper window that announces each forward as
it comes up (`tunnel open → host:port`) and reminds you to leave it open — close it to tear the
tunnels down. The `+pcode` selector applies to tunnels too: `ssh -L … alice+dba@gateway`.

`scp` works out of the box for any current OpenSSH client — it defaults to the SFTP protocol
under the hood, served by the same real shell/SFTP path above. The legacy exec-based protocol
(`scp -O`) is also supported, single file only (no `-r`), but is opt-in — set `enable_scp: true`
to turn it on (it adds an exec-channel surface, so it stays off by default).

Not supported: `-R` remote/reverse forwarding, or X11 forwarding.

**🎛️ Capability kill switches** — disable whole classes of access at the gateway, independent of
policy (at least one of the three must stay on). `enable_scp` is the opposite sense — opt-in,
off by default.
```yaml
disable_ssh: true      # no interactive shells
disable_tunnel: true   # no -L/-D forwarding
disable_sftp: true     # no SFTP subsystem (also blocks default-protocol scp)
enable_scp: true       # opt-in: serve legacy scp -O (off by default)
```

**🧭 Policy** — AD-group-bound roles; each rule sets the allowed host+ports plus a recording
posture and a credential posture. `host` can also be a CIDR range (e.g. `10.0.0.0/8`) instead of
one hostname per line — matches literal IPs directly, or a resolved hostname if every address it
resolves to lands inside the range (partial/split matches fail closed).
```yaml
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "db1.lab.local"
          ports: [5432]
          record: none            # none | metadata-only | full (full refuses -L)
          credential: passthrough # passthrough | prompt | inject | deny
          require_approval: false # four-eyes-gate this -L tunnel
        - host: "10.0.0.0/8"      # whole subnet, one rule
          ports: [22]
```

**🎯 Single dialer + SSRF guard** — every `-L`/`-D` target socket is authorized, then opened
through one code path; the *resolved* IP (not just the hostname) is checked against loopback,
link-local (including the `169.254.169.254` cloud metadata IP), unspecified, and multicast/
broadcast — closing the DNS-rebinding TOCTOU gap. RFC1918/CGNAT are allowed on purpose; reaching
internal hosts is the whole point of a bastion.

**🔑 CyberArk injection** — `credential: inject` fetches the target secret from CyberArk CCP over
mTLS, just-in-time; the user never sees it. CCP unreachable = refused, never silently downgraded
to prompt/passthrough.
```yaml
cyberark:
  base_url: "https://ccp.lab.local/AIMWebService"
  client_cert: "cyberark-client.crt"
  client_key: "cyberark-client.key"
  ca_cert: "cyberark-ca.crt"
  app_id: "omni-sag"
  safe: "targets"
```

**🦠 SFTP content inspection** — uploads stream through ICAP (AV/DLP). *Every* upload — clean or
not — gets a permanent copy in an Object-Locked quarantine bucket; blocked, unscannable, or
"modified" verdicts are refused outright.
```yaml
inspection:
  enabled: true
  icap: { endpoint: "icap.lab.local:1344", service: "avscan" }
```

**👀 Four-eyes approvals** — `require_approval` blocks a `-L` tunnel until a second human approves
it; separately, every inspected SFTP upload blocks at close until a second human releases it from
quarantine — group-scoped, so the releaser must share an AD group with the uploader. Never
yourself, either way.
```console
$ omnisag-ctl approvals
$ omnisag-ctl approve <id>
```

**📥 Pull-release** — an approved SFTP upload is never auto-pushed to the target; the same
uploader retrieves it themselves from the gateway's `/releases` directory within the approval
window (default 6h).

**🎥 Session recording** — asciicast v2, streamed to storage so a long session never sits whole in
memory.
```yaml
recording:
  local_dir: "recordings"
```
`record: full` targets get their shell recorded; `-L` forwarding to them is refused (forwarded
bytes can't be meaningfully recorded).

**🧾 Tamper-evident evidence** — every decision (auth, MFA, tunnel, credential, approval,
inspection, recording) is hash-chained, Merkle-checkpointed, and Ed25519-signed.
```console
$ omni-verify -bundle ./evidence -pubkey $KEY -head $HEAD
PASS — evidence bundle is intact and authentic.
```

**🛰️ Control plane** — an HTTP API on its own listener (mTLS or bearer tokens), a CLI, and a
Bubble Tea TUI. Kill the API and SSH keeps serving — it's genuinely out-of-band.
```console
$ omnisag-ctl sessions
$ omnisag-ctl sessions kill <id>
$ omnisag-ctl trace alice dba db1.lab.local 5432
$ omnisag-ctl tui
```

**🪵 `-debug`** — mirrors auth/MFA failures and every evidence decision to stdout. Dev only; it
weakens the anti-enumeration posture.
```console
$ omni-sag -config config.yaml -debug
```

**📦 Packaging** — UBI9 non-root image, a Helm chart (restricted-v2 pod security), Prometheus
metrics on their own listener, graceful drain on SIGTERM, and a FIPS-readiness mode
(`off` | `warn` | `enforce`).

## 🚀 60 seconds to "whoa"

Spins up a throwaway lab (Samba AD, MinIO, FreeRADIUS), then two SSH users where only the DBA gets
the tunnel — with both attempts in the evidence log.

```bash
git clone https://github.com/rupivbluegreen/omni-sag
cd omni-sag

make lab-up        # samba-AD + MinIO + FreeRADIUS
make lab-seed      # create alice (dba) and bob (not)
make binaries      # build omni-sag, omnisag-ctl, omni-verify

./bin/omni-sag_linux_amd64 -config deploy/compose/config.example.yaml
# ssh -L 5432:db1.lab.local:5432 alice@gw  → allowed
# ssh -L 5432:db1.lab.local:5432 bob@gw    → administratively prohibited
# ./bin/omni-verify_linux_amd64 -bundle ./evidence   → PASS (tamper a byte → FAIL)
```

Requirements: **Go 1.25+**, **Docker** (for the lab), and an SSH client. `make lab-down` to clean up.

## 🧠 How it works

A **modular monolith** with CI-enforced package boundaries — comprehensible, without the
distributed-systems tax.

```
client ──ssh──▶ [ session ] ──▶ authn + ratelimit ──▶ policy ──┬──▶ [ dialer ] ──▶ target (-L/-D)
                     │                                          └──▶ 2nd SSH leg ──▶ target (shell/SFTP)
                     ▼
                [ evidence ] ── hash-chain · Merkle · Ed25519 · WORM ──▶ omni-verify (offline)

─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  out-of-band control plane  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
operator ──mTLS──▶ [ api ] ──▶ sessions · policy · approvals · supervision
                     ▲                       (the data path never imports this)
                omnisag-ctl / TUI
```

**Load-bearing invariants** (each CI- or test-enforced):

1. **Fail closed** — any dependency failure denies. Proven by a [29-row fail-closed matrix](docs/audit/fail-closed-matrix.md).
2. **No silent credential downgrade** — `inject` failure refuses; never falls back to prompt/passthrough.
3. **Evidence is non-optional & tamper-evident** — and emit errors are surfaced, never swallowed.
4. **Secrets never become Go strings** — `[]byte` only, zeroized ([ADR-0001](docs/decisions/0001-mlock-free-credential-handling.md)).
5. **Four-eyes** — approver ≠ requester, server-side, durable across restarts.
6. **Control plane out-of-band** — kill the API, SSH keeps serving. (It's a test, not a slogan.)

## 🏗️ How it was built

Thin slices, GA and beyond, each demoable on its own — no five-half-finished-branches energy.
Every slice went through an **adversarial review gate** before the next one started, and a few of
those reviews caught real bugs. That's the point.

- **6** real bugs caught by review/hardening (an ICAP OOM, a policy-eval contract slip, an
  inspection fail-open, an SFTP inspection-gap bypass, …) — all fixed, all regression-locked.
- A **12-auditor sweep** (adversarially verified) before calling it v1; the real-target proxy and
  group-scoped approval + pull-release landed as reviewed slices afterward.
- Full story + slice map on the [website](https://rupivbluegreen.github.io/omni-sag/) and in
  [`docs/audit/`](docs/audit/).

## 🗺️ Roadmap

- **v1 (here):** SSH + SFTP, real shell/SFTP target proxy, AD+MFA, dialer authz, evidence chain,
  recording, content inspection + quarantine, CyberArk injection, four-eyes (session tunnels +
  group-scoped quarantine-release) with pull-download, per-capability toggles, API + CLI + TUI +
  packaging. ✅
- **v1.x:** SSH certificate authority, Kerberos/GSSAPI, a real OIDC (JWKS) validator for the API
  (today a static-token stand-in), CRD-backed policy/approval sources (needs a live cluster), FIPS
  TLS-config routing through every listener.
- **v2:** RDP (native mstsc, then browser RDP with recording).
- **Never:** shared-process multi-tenancy, monetization machinery in the OSS, semantic command
  reconstruction from pixels.

## 🤝 Contributing

Issues, ideas, and PRs all welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)** and the
[Code of Conduct](CODE_OF_CONDUCT.md). Found a security issue? Please read
**[SECURITY.md](SECURITY.md)** first (don't file it as a public issue). New here? Look for
[`good first issue`](https://github.com/rupivbluegreen/omni-sag/labels/good%20first%20issue).

## 📜 License

[MIT](LICENSE) — do fun things with it.

<div align="center">

*Made with too much coffee and a healthy distrust of default-allow.* ☕

</div>
