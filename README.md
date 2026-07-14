<div align="center">

<img src="docs/assets/logo.svg" alt="Omni-SAG" width="440" />

### the SSH bastion that keeps the receipts

*Your servers' bouncer. Every login checked, every tunnel authorized, every byte accounted for —
with a tamper-evident paper trail you can verify offline, even with the gateway switched off.*

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
Active Directory (with MFA), decides what they're allowed to reach, and writes down *everything* in
a way nobody can quietly edit later. The default answer is always **no** — access is something you
earn, per connection.

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

| | |
|---|---|
| 🔐 **AD + MFA** | LDAPS against Active Directory, then RADIUS MS-CHAPv2 (never PAP). |
| 🎯 **One dialer, one rule** | A single authorized path to targets, with an **SSRF guard** (blocks the metadata IP, loopback, DNS rebinding). |
| 🧾 **Tamper-evident evidence** | Per-emitter epoch+sequence, Merkle chain, Ed25519 signed checkpoints, WORM archive — verify offline with `omni-verify`. |
| 🎥 **Session recording** | Asciicast recording (replay in the TUI). Forwarding is **refused** on must-record targets. |
| 🦠 **Content inspection** | SFTP uploads streamed through ICAP (AV/DLP). Blocked or unscannable → quarantined, transfer refused. |
| 🔑 **CyberArk injection** | Just-in-time secret fetch; the user never sees it. Vault down = refused. **No silent downgrade.** |
| 👀 **Four-eyes approvals** | Crown-jewel targets block until a *second* human approves (never yourself). Live supervision + kill switch. |
| 🛰️ **API + TUI** | OpenAPI control plane + a Bubble Tea terminal UI. Kill the API? SSH keeps running — it's genuinely out-of-band. |
| 📦 **Ships nicely** | UBI9 non-root image, Helm chart (restricted-v2), graceful drain, Prometheus metrics, SBOM + cosign, FIPS mode. |

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
client ──ssh──▶ [ session ] ──▶ authn + ratelimit ──▶ policy ──▶ [ dialer ] ──▶ target
                     │                                    │  (the ONLY socket to a target,
                     ▼                                    ▼   authorized + SSRF-guarded first)
                [ evidence ] ── hash-chain · Merkle · Ed25519 · WORM ──▶ omni-verify (offline)

─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  out-of-band control plane  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
operator ──mTLS──▶ [ api ] ──▶ sessions · policy · approvals · supervision
                     ▲                       (the data path never imports this)
                omnisag-ctl / TUI
```

**Load-bearing invariants** (each CI- or test-enforced):

1. **Single dialer** — only `internal/dialer` opens sockets to targets, authorized *before* the socket.
2. **Fail closed** — any dependency failure denies. Proven by a [29-row fail-closed matrix](docs/audit/fail-closed-matrix.md).
3. **No silent credential downgrade** — `inject` failure refuses; never falls back to prompt/passthrough.
4. **Evidence is non-optional & tamper-evident** — and emit errors are surfaced, never swallowed.
5. **Secrets never become Go strings** — `[]byte` only, zeroized ([ADR-0001](docs/decisions/0001-mlock-free-credential-handling.md)).
6. **Four-eyes** — approver ≠ requester, server-side, durable across restarts.
7. **Control plane out-of-band** — kill the API, SSH keeps serving. (It's a test, not a slogan.)

## 🏗️ How it was built

13 thin slices, **0 → GA**, each one demoable on its own — no five-half-finished-branches energy.
Every slice went through an **adversarial review gate** before the next one started, and a few of
those reviews caught real bugs. That's the point.

- **6** real bugs caught by review/hardening (an ICAP OOM, a policy-eval contract slip, an
  inspection fail-open, an SFTP inspection-gap bypass, …) — all fixed, all regression-locked.
- A final **12-auditor sweep** (adversarially verified) before calling it v1.
- Full story + slice map on the [website](https://rupivbluegreen.github.io/omni-sag/) and in
  [`docs/audit/`](docs/audit/).

## 🗺️ Roadmap

- **v1 (here):** SSH + SFTP, AD+MFA, dialer authz, evidence chain, recording, inspection,
  CyberArk, approvals, API + TUI + packaging. ✅
- **v1.x:** real SFTP backend & target-shell proxy, SSH certificate authority, Kerberos/GSSAPI,
  OIDC-primary MFA, CRD informers, TLS-config FIPS routing.
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
