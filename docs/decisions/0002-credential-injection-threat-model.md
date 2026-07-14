# ADR-0002 — Credential injection threat model (Slice 6)

**Status:** Accepted
**Date:** 2026-07-14
**Slice:** 6 (CyberArk & credential modes)
**Builds on:** [ADR-0001 — mlock-free credential handling](0001-mlock-free-credential-handling.md)

Credential injection is the highest-consequence surface in the product: the
gateway briefly holds plaintext target credentials. This document enumerates the
assets, boundaries, adversaries, and mitigations that the Slice 6 code is built
against. It is written **before** the implementation, per the build plan.

## Assets

| Asset | Sensitivity |
|-------|-------------|
| Injected target credential (CyberArk-sourced password/key) | Critical — plaintext, briefly in gateway memory |
| CyberArk CCP client certificate + private key (gateway identity to CCP) | Critical — grants the gateway's fetch rights |
| The user's own login credential (passthrough mode) | High |
| Evidence of credential use (which mode, which target, outcome) | High — must be complete and tamper-evident, must NOT contain the secret |

## Trust boundaries

1. **User ⟷ gateway** (SSH). The user is authenticated (LDAPS + MFA) but is an
   adversary for the purpose of the injected secret: in `inject` mode the user
   must *never* observe the credential.
2. **Gateway ⟷ CyberArk CCP** (HTTPS + mTLS). The network between them is
   untrusted; the CCP endpoint must be authenticated (server cert pinned to a CA)
   and the gateway authenticates with a client cert.
3. **Gateway ⟷ target** (future: the gateway authenticates to the target with
   the injected secret). In this slice the target-auth step is a stand-in
   (see "Boundary" below).
4. **Gateway ⟷ evidence store** (covered by ADR/Slice 3: tamper-evident, WORM).

## Adversaries and attacks → mitigations

| Adversary / attack | Mitigation |
|--------------------|------------|
| **Malicious user** tries to read the injected credential (echo, transcript, recording) | User never receives it (`inject` fetches server-side and uses it on the target leg); **keystroke suppression** scrubs the secret bytes from any recorded I/O; the secret is never written to the channel back to the user. |
| **Malicious user** forces a downgrade to a mode they control (`prompt`/`passthrough`) by making CyberArk fail | **No silent downgrade (FR-18):** `inject` + any CyberArk failure ⇒ **fail closed** (session refused). The provider returns an error; there is no code path from `inject` to another mode. Property-tested. |
| **Compromised gateway memory** (core dump, swap, ptrace, another process) reads the secret | ADR-0001: secret lives in a **mutable `[]byte`, never a Go `string`**; **zeroized** immediately after use (`Destroy()` + `runtime.KeepAlive`); **JIT fetch, never cached**; deployment guarantees swap-off, core-dumps-off, ptrace-denied. CI lint forbids a `String()` on `Secret` and string-typed secret fields. |
| **Accidental leak** via logging (`%v`, error strings) | `Secret` implements `fmt.Formatter`/`GoString` to render `REDACTED`; the secret is never placed in an `error` or evidence field; the HTTP response buffer is zeroized after extraction. |
| **Network MITM** to CyberArk (steal cert-auth'd response, or impersonate CCP) | **mTLS**: server cert verified against a configured CA (no `InsecureSkipVerify` in production); client cert authenticates the gateway. A MITM without the CA-signed server cert is rejected. |
| **CyberArk outage / flakiness** used to exhaust or confuse the gateway | **Circuit breaker**: consecutive failures open the breaker; while open, `inject` fails closed immediately (no fetch storm), auto half-opens after a cooldown. |
| **Evidence tamperer** hides that a credential was used | Credential events flow through the Slice-3 tamper-evident chain; emit failures are surfaced, not swallowed. The event records mode/target/outcome — **never** the secret. |
| **Stolen CCP client key** | Out of scope for code (key management is operational): stored 0600, never logged; rotation is an operator concern. Documented as residual. |

## The stand-in boundary (honest scope)

The interactive shell and SFTP subsystem are currently **gateway-terminated
stand-ins** (Slices 4–5): there is no real target-shell authentication yet.
Therefore the *final* step — "use the injected secret to authenticate to the
target" — is stubbed. What Slice 6 fully implements and tests:

- the `Secret` type (mlock-free, zeroizing, no-string) per ADR-0001;
- the four-mode provider (`inject | prompt | passthrough | deny`);
- the CyberArk CCP mTLS client (against a mock CCP);
- the circuit breaker;
- **mode selection and the no-silent-downgrade / fail-closed decision**, wired
  into the dialer (the single outbound path, where the policy decision and
  target live);
- credential evidence emission;
- keystroke-suppression (redaction) mechanism.

When real target authentication lands, the injected `Secret` is consumed on the
target leg (and suppressed from recording) instead of being fetched-and-destroyed
at the stand-in boundary. This ADR governs that future step too.

## Residual risks (documented, not yet mitigated in code)

- CCP client private-key management/rotation is operational.
- A transient Go `string` may exist inside the JSON/TLS stack while parsing the
  CCP response; we extract the secret into a `[]byte` without an intermediate
  password string and zeroize the response buffer, but cannot control every
  copy the runtime makes — swap-off (ADR-0001) is the backstop.
- Real target-auth injection is stubbed (see Boundary).
