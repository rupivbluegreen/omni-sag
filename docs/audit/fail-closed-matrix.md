# Fail-Closed Matrix

Every external dependency and internal error path, the failure injected, and the
system's **fail-closed** behavior. "Fail closed" means: access is denied /
content is refused / required evidence is preserved or the operation is
surfaced — never silently granted, delivered, or lost.

Each row is regression-locked by a test (the chaos suite `*_chaos_test.go` plus
the per-slice hardening tests). Column *Proven by* names the test package.

| # | Dependency / path | Failure injected | Behavior (fail-closed) | Proven by |
|---|-------------------|------------------|------------------------|-----------|
| 1 | AD / LDAPS | DC down / refused / timeout | login refused; bounded request timeout so no goroutine parks | `authn`, `session` |
| 2 | LDAPS | empty password (unauth-bind) | rejected before dial | `authn` |
| 3 | MFA / RADIUS | server down / Access-Reject / timeout | login refused (MFA denies) | `authn`, `session` |
| 4 | Brute force | repeated failed auth from a source | per-source lockout (bounded backoff, capped, evidenced); success resets | `ratelimit`, `session` |
| 5 | Policy | empty / no matching rule | default-deny | `policy` (property tests) |
| 6 | Policy hot-reload | invalid/parse-broken edit | keep last good policy; invalid `record`/`credential` rejected | `policysource` |
| 7 | Dialer | policy denies | `ErrDenied`, no socket opened | `dialer` |
| 8 | Dialer / SSRF | hostname resolves to loopback/link-local/metadata/unspecified | resolved-address guard blocks at socket layer (pre-connect) | `dialer` (guard + fuzz) |
| 9 | Forwarding (FR-10) | `-L` to a full-recording target | `ErrForwardingRefused`, no socket | `dialer`, `session` |
| 10 | CyberArk (inject) | CCP down / breaker open / empty secret | `ErrCredentialRefused` before socket; **never** downgrades to prompt/passthrough | `credential`, `dialer` |
| 11 | CyberArk mTLS | bad/empty CA | TLS fails closed (no InsecureSkipVerify) | `credential` |
| 12 | ICAP inspection | server down / timeout / garbage / unknown verdict / modified | quarantine to WORM + refuse the transfer | `inspect`, `inspectgate` (chaos) |
| 13 | ICAP chunked body | oversized chunk-size (OOM attempt) | 64 MiB cap, error → treated as block | `inspect` (fuzz corpus) |
| 14 | SFTP upload | non-contiguous / gapped write stream | refused (content not fully inspected) — no clean grade on a prefix | `session` |
| 15 | Holding store | mid-stream write failure | transfer fails closed + quarantines (no deadlock) | `inspectgate` |
| 16 | Evidence sink | emit error (disk full / S3 down) | error surfaced (logged/metric); the access decision is unchanged and correct | `dialer`, `session`, `metrics` |
| 17 | Evidence bundle | any record/segment/checkpoint tamper or deletion | `omni-verify` FAILS loudly; trailing/whole-epoch deletion caught by global checkpoint chain + pinned head | `evidence`, `omni-verify` |
| 18 | Evidence key trust | unpinned verification | reports UNVERIFIED (exit 3), never "authentic"; only a pinned key rejects a re-signed forgery | `omni-verify` |
| 19 | Approval store | store unavailable / down | approval-gated session refused (`ErrApprovalRefused`), no socket | `approval`, `dialer` |
| 20 | Approval | expired (TTL) / denied / no approval | refused; four-eyes (approver ≠ requester) enforced server-side | `approval` |
| 21 | Approval durability | process restart mid-approval | pending request survives (atomic fsync store) and is still approvable | `approval` |
| 22 | Control-plane API | API crash / bad TLS / port in use | SSH data path unaffected; API best-effort; existing + new SSH sessions unaffected | `api` (out-of-band test) |
| 23 | API authz | viewer attempts terminate/approve | 403 (RBAC fail-closed, viewer < operator < admin) | `api` |
| 24 | SSH handshake | slowloris / stalled handshake | per-conn deadline + in-flight cap; connection dropped | `session` |
| 25 | Post-auth channels | channel flood on one connection | per-connection channel cap (`ResourceShortage`) | `session` |
| 26 | Channel handler | panic in a channel goroutine | recovered; only that channel dies, not the gateway | `session` |
| 27 | SFTP write offset | huge/negative client-controlled offset | bounded (no unbounded `make`, no panic/OOM) | `session` (fuzz) |
| 28 | FIPS | `mode=enforce` but runtime not FIPS, or `insecure_tls` set | refuses to boot (enforce); config rejects `insecure_tls` under enforce | `fips`, `config` |
| 29 | Recording | recording store unavailable at start | interactive session refused (fail-closed) + failure evidenced | `session` |

## Notes

- Row 16 is the one deliberate *fail-open-on-evidence* choice: an evidence emit
  failure is **surfaced** (never swallowed) but the correct allow/deny decision
  still stands, so a degraded sink cannot deny service to legitimate access.
  Whether an un-recordable allow should hard-fail is a documented future policy
  decision; the WORM chain + surfacing make a silent audit gap detectable.
- Row 17/18: offline `omni-verify` cannot detect trailing/whole-bundle deletion
  without an out-of-band anchor — the pinned `-head` (logged by the gateway at
  shutdown) and WORM Object-Lock are the two defenses; unpinned verification is
  explicitly reported as unauthenticated.
