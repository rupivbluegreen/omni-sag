# ADR-0003 — FIPS-readiness posture

**Status:** Accepted
**Date:** 2026-07-14
**Context slice:** Slice 11 (hardening); adds `internal/fips` (a leaf) and a
boot-time posture check.

## Context

Prospective operators in regulated environments (US federal, FedRAMP, PCI in
some interpretations) require that a bastion use FIPS-validated cryptography.
Omni-SAG implements no crypto of its own — everything comes from the Go standard
library — so "FIPS support" reduces to two questions:

1. Is the process actually running against a FIPS-approved crypto module?
2. Are the specific algorithms this codebase relies on FIPS-acceptable?

Go 1.24 shipped a native FIPS 140-3 module toggled by `GODEBUG=fips140=on`
(`crypto/fips140.Enabled()` reports it), and the older boringcrypto toolchain
remains an option. We need a way to *declare intent* ("this deployment must be
FIPS") and *fail loudly* when the binary/runtime does not satisfy it — otherwise
an operator can believe they are compliant while running default crypto.

## Decision

Add a small leaf package `internal/fips` with:

- a three-value posture (`off` / `warn` / `enforce`), configured via
  `fips.mode` in the gateway config, defaulting to `off`;
- `Check(mode)` run at the very top of boot: in `enforce` it refuses to start
  unless `crypto/fips140.Enabled()` is true and the algorithm self-test passes;
- a `SelfTest` covering the primitives actually used (Ed25519 signing, SHA-256),
  including a negative case;
- TLS-parameter helpers (approved versions ≥ TLS 1.2, AES-GCM cipher suites;
  ChaCha20-Poly1305/CBC/3DES/RC4 excluded) for LDAPS, CCP, and the API.

`internal/fips` imports only the standard library, keeping it a leaf so config,
boot wiring, and tests can all use it without new import edges.

## Consequences

- **Non-FIPS default builds are unchanged.** With no config the posture is
  `off`, `Check` never errors, and the runtime probe simply reports `false`.
- **Enforce is a hard gate.** A deployment that sets `fips.mode: enforce` on a
  binary/runtime without FIPS crypto fails fast at boot with an actionable
  message pointing at `docs/fips.md`, rather than silently running non-approved
  crypto.
- Formal validation still depends on the deployed module's certificate and the
  operational environment; this ADR delivers *readiness/posture*, not a
  certificate. The self-test is a functional/known-answer check, not a CAVP
  validation.
- Algorithm choices already in the codebase (Ed25519, SHA-256, TLS 1.2+ AES-GCM)
  were confirmed FIPS-acceptable; no crypto had to change.
