# Tunnel protocol identification — design

**Status:** Approved (brainstorming), not yet implemented
**Date:** 2026-07-19

> Note: this spec is for a NEW feature, unrelated to the scp branch it may
> currently sit in. Move it to its own branch (fresh from master) before
> implementation.

## Context

The `-L`/`-D` tunnel data path is a blind byte splice. `handleDirectTCPIP`
(`internal/session/session.go:604-635`) authorizes the declared
`direct-tcpip` destination (`host:port`) against policy, then hands the
channel to `dialer.Splice(ch, conn)` (`internal/dialer/splice.go`), which is
pure bidirectional `io.Copy`. The gateway therefore knows the *declared*
destination and the *byte counts*, but **nothing about the payload**. A rule
that allows `-L 5432:db:5432` trusts that PostgreSQL is what flows — but an
operator could push JDWP (a remote-code-execution channel), tunnel SSH through
the allowed port to pivot, or run any other protocol, and the gateway is
blind to it.

This feature makes the gateway **identify the protocol actually flowing
through each tunnel** by fingerprinting the opening bytes, record it as
tamper-evident evidence (Phase 1), and optionally enforce an expected
protocol per policy rule (Phase 2).

**Regulatory driver (grounded, cited).** A blind privileged tunnel is, by
definition, *unmonitored privileged activity* — a concrete deficiency against
a **mandatory** obligation, not a best-practice gap. This feature maps to
three *named* obligations simultaneously:
- **DORA (Reg. (EU) 2022/2554, in force 17 Jan 2025) Art. 10 — Detection
  (mandatory):** requires mechanisms to "promptly detect anomalous
  activities" and to "monitor user activity [and] the occurrence of ICT
  anomalies, in particular cyber-attacks." Classifying the actual protocol in
  a tunnel (e.g. JDWP — a remote-code-execution channel — or a nested SSH
  pivot on a DB port) is exactly this. omni-sag is otherwise **Art. 9
  (access-control) strong** but has a systematic **Art. 10 detection gap**;
  this feature is the first increment that closes it.
- **DORA RTS 2024/1774 Art. 12 — Logging:** the emitted, hash-chained,
  WORM-archived `TypeTunnelProtocol` event is the tamper-evident log record.
- **DORA Art. 9 — Protection & prevention (Phase 2 enforce):** per-rule
  `expect_protocol` is least-function enforcement at the protocol layer.
- **PCI-DSS 4.0:** a `-D`/SOCKS tunnel into a CDE is a classic
  segmentation-bypass / covert-exfiltration path — supports Req 1 (constrain
  what crosses the boundary), 10.2 (log access), 11.5 (detect covert
  channels). **NIS2 Art. 21(2)** and **SWIFT CSCF 6.5A** (intrusion
  detection) carry the same mapping.

This triple mapping is the reason the tunnel feature goes live first: it is
the anchor of omni-sag's Art. 10 detection story.

## Non-goals / honest limits (stated up front)

- **Heuristic, spoofable.** Fingerprinting the opening bytes catches JDWP on a
  DB port, casual SSH-tunneling, and port/protocol mismatch. A determined
  insider who wraps their payload to mimic the allowed protocol's opening
  bytes defeats it. This is detection + defense-in-depth, not a cryptographic
  guarantee.
- **TLS is opaque past the handshake.** We can see a TLS ClientHello (and
  extract SNI) but not the inner protocol — no MITM is performed on tunnels.
  "DB-over-TLS" and "SSH-over-TLS" both classify as `tls`.
- **First-packet fingerprinting, not full-stream DPI.** We classify from a
  bounded prefix, then stop looking. No per-packet inspection for the life of
  the tunnel.

## Architecture

New leaf package `internal/protoident` — pure classification, no imports of
`session`/`dialer`/`policy`, so it is unit-testable in isolation and cannot
create import cycles (mirrors the codebase's leaf-package discipline, e.g.
`internal/approval`). It exposes:

```go
package protoident

type Protocol string // "ssh", "postgres", "mysql", "jdwp", "tls", "http",
                     // "http2", "oracle-tns", "rdp", "redis", "telnet",
                     // "smtp", "ftp", "pop3", "imap", "vnc", "unknown"

type Side int
const (
    ClientFirst Side = iota // opener speaks first (bytes from the SSH channel)
    ServerFirst             // target speaks first (bytes from the target conn)
)

type Result struct {
    Protocol   Protocol
    Side       Side   // which side's opening bytes matched
    Detail     string // e.g. SNI for TLS, HTTP method, banner snippet
    BytesSeen  int
    Signature  string // the signature name that matched (audit)
}

// Classify inspects up to len(clientPrefix)+len(serverPrefix) opening bytes
// and returns the best match, or {Protocol: "unknown"} if none. Pure, no I/O.
func Classify(clientPrefix, serverPrefix []byte) Result
```

Hook point: `handleDirectTCPIP` in `session.go`, around the `Splice` call.
Both `-L` and `-D` ride the same `direct-tcpip` channel, so dynamic SOCKS is
covered for free.

## Detection engine

A **data-driven signature table** keyed by side. Each signature = a matcher
over the opening bytes. Adding a protocol = one table entry.

**Client-speaks-first** (first bytes from the SSH-channel/app side):
| Protocol | Signature |
|---|---|
| JDWP | ASCII `JDWP-Handshake` (14 bytes) |
| HTTP/1 | method token + space: `GET `,`POST `,`PUT `,`HEAD `,`DELETE `,`OPTIONS `,`CONNECT `,`PATCH `,`TRACE ` |
| HTTP/2 | preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` |
| TLS | `0x16 0x03 0x0{0..4}` (handshake record + version); extract SNI from ClientHello if present |
| PostgreSQL | SSLRequest `00 00 00 08 04 d2 16 2f`, GSSENCRequest `…04 d2 16 30`, or StartupMessage proto `00 03 00 00` at offset 4 |
| Oracle TNS | packet-type `0x01` (CONNECT) at offset 4 **and** `(DESCRIPTION=` / `(CONNECT_DATA=` ASCII in payload |
| RDP | TPKT `03 00` + X.224 Connection-Request `0xE0` |
| Redis (RESP) | leading `*` (array) or inline uppercase verb (`PING`,`AUTH`,…) |
| Telnet | `0xFF` (IAC) option negotiation |

**Server-speaks-first** (first bytes from the target side):
| Protocol | Signature |
|---|---|
| SSH | `SSH-2.0-` / `SSH-1.99-` |
| MySQL/MariaDB | greeting packet: protocol-version `0x0a` at offset 4 (after 3-byte len + seq) |
| SMTP | `220 ` banner | FTP | `220 ` banner | POP3 | `+OK` | IMAP | `* OK` |
| VNC/RFB | `RFB 003.` |

Ambiguity handling: some ASN.1/text protocols share a leading byte; each
signature specifies enough bytes to disambiguate, and the table is ordered so
the most specific matches win. No match within the byte budget → `unknown`.

## Phase 1 — observe (non-blocking, zero added latency)

Observe mode must **not** gate the splice — a privileged session must not slow
down or deadlock because classification is pending. Design:

- Wrap each direction with a **tee** into a small bounded ring buffer
  (`maxPrefixBytes`, default **512 bytes/direction**). The splice runs at full
  speed; teed bytes are a copy, never consumed from the stream.
- A classifier goroutine watches whichever side produces bytes first (handles
  both client-first and server-first without knowing in advance). It calls
  `protoident.Classify` once it has enough bytes **or** a bound is hit:
  `maxPrefixBytes` reached, or `classifyTimeout` (default **5s**) elapsed, or
  the tunnel closes early.
- It emits exactly one `TypeTunnelProtocol` evidence event with the result
  (including `unknown`). One event per tunnel; never blocks or alters bytes.

Failure modes are all benign: a tunnel that closes before enough bytes → emit
`unknown` with `BytesSeen`; a slow protocol that sends nothing for 5s → emit
`unknown` (timeout). The data stream is never affected.

## Phase 2 — enforce (`expect_protocol` per rule)

Policy schema addition — a new optional field on `RuleConfig` /`policy.Rule`
(`internal/config/config.go` RuleConfig, `internal/policy` Rule):

```yaml
allow:
  - host: db1.lab.local
    ports: [5432]
    expect_protocol: [postgres]   # NEW: allow-list of permitted protocols
```

Enforcement changes the peek from "tee (observe)" to a **head-of-line hold**:
buffer the opening bytes (up to `maxPrefixBytes` / a short `enforceTimeout`)
**before** the first bytes are forwarded, classify, then:
- **match** (detected ∈ `expect_protocol`) → release the buffered bytes into
  the splice and proceed normally.
- **mismatch** (detected ∉ `expect_protocol`) → **terminate** the tunnel
  (close both ends), emit a fail-closed `TypeTunnelProtocol` event with
  `allow=false`, and reject reason `"protocol X not permitted on this tunnel
  (expected [postgres])"`.
- **unknown** (couldn't classify) → **the key open decision below.**

Only rules that set `expect_protocol` are enforced; absent field = observe
only (Phase 1 behavior), fully backward compatible.

### Key open decision — `unknown` under enforcement
Because detection is heuristic, hard-blocking every unclassifiable stream will
break legitimate but unrecognized protocols. Two postures, made configurable:
- **`unknown_action: allow`** (default) — permit + emit an `unknown` event
  flagged for review. Avoids false-positive outages; still creates the audit
  trail. Recommended default.
- **`unknown_action: deny`** — fail-closed; only recognized, expected
  protocols pass. For high-assurance tunnels where an unidentifiable stream is
  itself the anomaly.

The same `classify_timeout_seconds` (default 5s, see config below) bounds the
head-of-line hold in enforce mode; hitting it is treated as `unknown` and
routed through `unknown_action`.

## Config schema

New top-level block (opt-in, **default off**):

```yaml
tunnel_inspection:
  enabled: false           # master switch (default off — consistent with the
                           # project's opt-in posture for new surfaces)
  max_prefix_bytes: 512    # per-direction classification budget
  classify_timeout_seconds: 5
  enforce: false           # false = observe-only even for rules with
                           # expect_protocol (log would-block, don't block);
                           # true = actually terminate on mismatch
  unknown_action: allow    # allow | deny  (only relevant when enforce: true)
```

`enforce: false` with `expect_protocol` rules present gives a **dry-run /
monitor mode**: the gateway logs what it *would* block (evidence
`allow=false, detail="dry-run"`) without terminating — essential for rolling
enforcement out safely at scale. Documented in `config.example.yaml`.

## Evidence schema

New `evidence.Type`: `TypeTunnelProtocol = "tunnel_protocol"`. Fields (reusing
existing `evidence.Event` fields; no struct change if `Detail`/`ObjectKey`
suffice, otherwise add typed fields):
- `User`, `SourceIP`, `Target` (`host:port`) — correlates with the existing
  `TypeTunnelDecision` event on the same tunnel.
- `Detail` — detected protocol + method (which side spoke first, which
  signature matched, SNI/banner snippet, bytes observed).
- `Allow` — true (observe / permitted), false (enforced block or dry-run
  would-block).
- `Reason` — e.g. `"protocol jdwp not permitted (expected [postgres])"`.

Emitted through the existing dialer/session evidence sink so it lands in the
same hash-chained, WORM-archived pipeline — i.e. the protocol-anomaly record
is itself tamper-evident (the compliance point).

## Coverage & performance
- `-L` local, `-D` dynamic SOCKS, and `-J` ProxyJump legs all open
  `direct-tcpip` channels → all covered by the one hook.
- Cost: one small bounded buffer per tunnel (~1 KB) + a single classification
  pass over a few hundred bytes. Negligible vs the connection/LDAP cost.
  Observe mode adds zero latency (tee, not gate); enforce mode adds at most
  the head-of-line hold until the first classifiable bytes arrive.

## Testing plan
- `internal/protoident`: table-driven `Classify` unit tests with **real
  captured opening bytes** for every signature, both client-first and
  server-first, plus ambiguous/short/empty inputs → `unknown`. Include a
  spoof case (JDWP bytes on a "postgres" expectation) to document the
  heuristic limit.
- Observe integration: drive a real `direct-tcpip` channel (reuse the
  `internal/session` test harness + `dialer` test doubles) feeding known
  preambles; assert exactly one `TypeTunnelProtocol` event with the right
  protocol, and assert **the spliced bytes pass through byte-for-byte
  unchanged** and no measurable latency is added.
- Enforce integration: `expect_protocol` match → tunnel proceeds; mismatch →
  tunnel terminated + fail-closed evidence; `unknown` under both
  `unknown_action` settings; `enforce: false` dry-run logs-but-does-not-block.
- Config: `tunnel_inspection` parse + defaults; `expect_protocol` on a rule
  compiles; example config still parses.

## Rollout (why tunnel-first is safe)
1. Ship Phase 1 (observe) opt-in → operators enable, watch
   `TypeTunnelProtocol` evidence, learn what actually flows.
2. Add `expect_protocol` rules with `enforce: false` (dry-run) → see what
   *would* be blocked without impact.
3. Flip `enforce: true` once dry-run is clean.

## Out of scope
- Full-stream DPI / per-packet inspection after the opening classification.
- TLS interception/MITM to see inner protocols.
- Automatic protocol-learning (baseline what a tunnel "normally" carries) —
  possible future, not this pass.
