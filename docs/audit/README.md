# Omni-SAG — Audit Pack (v1 GA readiness)

This directory is the internal audit pack that accompanies the **external
third-party penetration test and code audit** gating v1 GA (Slice 12). It
records the system's security architecture, the control inventory, the
fail-closed matrix, the threat model, and the data-protection / regulatory
artifacts a reviewer or works council needs.

> The external audit itself is out of scope for this repository — it is the one
> gate that cannot be self-served. This pack is the evidence that the system is
> *ready* for it, and the map an auditor uses to navigate the code.

## Contents

| Document | Purpose |
|----------|---------|
| [security-architecture](#security-architecture) (below) | system, trust boundaries, load-bearing invariants, control inventory |
| [fail-closed-matrix.md](fail-closed-matrix.md) | every dependency-failure mode and the proven fail-closed behavior |
| [threat-model.md](threat-model.md) | adversaries, attack surfaces, mitigations (STRIDE-oriented) |
| [compliance-pack.md](compliance-pack.md) | DPIA (GDPR), DORA Art. 30 register, works-council recording profiles |
| [../decisions/](../decisions/) | ADR-0001 mlock-free credentials, ADR-0002 credential-injection threat model, ADR-0003 FIPS posture |

## Security architecture

Omni-SAG is an auditable Linux privileged-access gateway (SSH + SFTP). It is a
**modular monolith** in Go: package boundaries are enforced in CI
(`scripts/check-imports.sh`) so the codebase stays comprehensible without the
distributed-systems tax.

### Data plane vs control plane

- **Data plane** (the SSH path): `session` → `authn`/`ratelimit` → `policy` →
  `dialer` → target. Self-contained and fail-closed. It does **not** import the
  control plane (`internal/api`); CI enforces this. Killing the API never drops
  or blocks SSH.
- **Control plane** (`internal/api` + `omnictl`/`tui`): sessions
  list/inspect/terminate, policy read + rule-trace, approvals, live supervision,
  health, metrics. Runs on its own listener; best-effort startup.

### Load-bearing invariants (each is CI- or test-enforced)

1. **Single dialer.** Only `internal/dialer` opens sockets to session targets;
   every target connection is policy-authorized *before* the socket, and a
   resolved-address SSRF guard blocks loopback/link-local/metadata/unspecified
   (incl. IPv4-mapped IPv6) — closing DNS-rebinding. Enforced by a `net.Dial`
   grep in CI + `internal/dialer/guard.go`.
2. **Fail-closed everywhere.** Any dependency failure (LDAP, RADIUS/MFA, ICAP,
   CyberArk, evidence sink, approval store, policy) denies — never falls open.
   Proven by the chaos matrix (`*_chaos_test.go`). See `fail-closed-matrix.md`.
3. **No silent credential downgrade** (FR-18). A target set to `inject` whose
   CyberArk fetch fails refuses the session; it never falls back to
   prompt/passthrough. `internal/credential` has exactly one success path.
4. **Evidence is non-optional and tamper-evident.** Per-emitter epoch+sequence,
   hash chain, RFC-6962-style Merkle, Ed25519 signed + globally-chained
   checkpoints, WORM (Object-Lock) archive, offline `omni-verify`. Emit errors
   are surfaced, never swallowed.
5. **Secrets never become Go strings** (ADR-0001). Injected credential material
   lives in a mutable `[]byte` `Secret` (zeroized, no `String()`); mlock-free by
   design (swap-off + core-dumps-off + ptrace-denied at the node). A CI lint
   rejects string-typed secret carriers in `internal/credential`.
6. **Four-eyes approvals** are server-side (approver ≠ requester), durable
   (atomic fsync store, survives restart), and TTL-bounded.
7. **Control-plane out-of-band.** Data path independent of the API; RBAC
   fail-closed (viewer < operator < admin); mTLS/bearer authn.

### Control inventory

| Control | Package | Verification |
|---------|---------|--------------|
| AD authentication (LDAPS) | `authn` | unauthenticated-bind guard, request timeouts |
| MFA (RADIUS MS-CHAPv2, no PAP) | `authn` | RFC 2759 vectors, live FreeRADIUS |
| Brute-force throttle (per-source, bounded) | `ratelimit` | unit + live SSH lockout |
| Authorization (default-deny) | `policy` | property tests (`rapid`), 20k iters |
| Single-dialer + SSRF guard | `dialer` | adversarial + fuzz tests |
| Recording-vs-forwarding (FR-10) | `policy`/`dialer`/`session` | integration tests |
| Content inspection (ICAP, fail-closed) | `inspect`/`inspectgate` | chaos + fuzz (OOM cap) |
| Credential injection (CyberArk mTLS) | `credential` | mock CCP, no-downgrade property |
| Evidence chain + WORM | `evidence` | tamper/deletion tests, MinIO Object-Lock conformance |
| Four-eyes approvals + supervision | `approval`/`api`/`sessions` | four-eyes/durability/RBAC tests |
| FIPS-140 posture | `fips` | self-test + enforce-mode boot check |
| Container/pod hardening | `deploy/` | restricted-v2 SecurityContext, helm lint |

### Review provenance

Every feature slice passed an adversarial review gate; Slice 11 fan-out found +
fixed 3 real bugs; the Slice 12 final audit (12 auditors, adversarially
verified) confirmed and fixed 3 more. See `git log` for the fix commits.

### Known deployment requirements (operator-guaranteed, not code)

- **Swap disabled** and **core dumps disabled** on the node (replaces mlock for
  injected-credential confidentiality — ADR-0001).
- **Shared SSH host key** across replicas for HA (`replicaCount > 1`).
- **API subjects must equal SSH principal names** for four-eyes to bind across
  the two authenticators (documented at `approval/filestore.go`).
- **WORM bucket** provisioned with Object-Lock at creation for evidence/quarantine.
