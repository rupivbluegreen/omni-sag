# FIPS 140-3 readiness

Omni-SAG can run under a FIPS-validated cryptographic module and enforce a
FIPS-readiness posture at boot. This document explains what "FIPS mode" means
here, how to build and run for it, and what the gateway checks.

## What FIPS mode is (and is not)

The gateway does **not** implement its own cryptography. All crypto comes from
the Go standard library. "FIPS mode" therefore means: *the process is linked
against, and actively using, a FIPS-approved crypto module, restricted to
approved algorithms.* Two supported ways to get there:

1. **Go 1.24+ native FIPS 140-3 module (recommended).** Go 1.24 ships an
   in-tree crypto module that has been submitted for FIPS 140-3 validation.
   Enable it at run time with the `GODEBUG` setting `fips140`:

   - `GODEBUG=fips140=on` — use the FIPS module for approved algorithms.
   - `GODEBUG=fips140=only` — additionally make **non**-approved algorithms
     return errors or panic. This is the strictest setting and surfaces any
     accidental use of a non-approved primitive immediately.

   You can also bake the default into the binary at build time with
   `GOFIPS140=v1.0.0` (or the module version you validated against).

2. **BoringCrypto toolchain.** Building with `GOEXPERIMENT=boringcrypto` links
   Go's BoringCrypto bindings (based on a FIPS-validated BoringSSL module).

`crypto/fips140.Enabled()` reports `true` under either path; `internal/fips`
uses it as the runtime probe.

## Posture: off / warn / enforce

Set the posture in the gateway config:

```yaml
fips:
  mode: enforce   # off (default) | warn | enforce
```

| Mode      | Behaviour                                                                       |
|-----------|---------------------------------------------------------------------------------|
| `off`     | Default. No FIPS requirement. The algorithm self-test still runs for logging.   |
| `warn`    | Never blocks boot. Logs a warning if the runtime is **not** in FIPS mode.       |
| `enforce` | **Refuses to start** unless the runtime is in FIPS mode and the self-test passes. |

The posture is checked at the very top of boot (`fips.Check`), before anything
touches crypto, so an operator who asked for `enforce` on a non-FIPS binary gets
a clear, actionable failure instead of silently-non-compliant crypto.

## Build & run recipes

Default (non-FIPS) build — unchanged, always works:

```sh
go build ./cmd/omni-sag
./omni-sag -config config.yaml
```

Native FIPS 140-3 at run time (no rebuild needed):

```sh
GODEBUG=fips140=on ./omni-sag -config config.yaml     # config: fips.mode: enforce
```

Native FIPS baked into the binary, strictest setting:

```sh
GOFIPS140=v1.0.0 go build ./cmd/omni-sag
GODEBUG=fips140=only ./omni-sag -config config.yaml
```

BoringCrypto build:

```sh
GOEXPERIMENT=boringcrypto CGO_ENABLED=1 go build ./cmd/omni-sag
./omni-sag -config config.yaml     # config: fips.mode: enforce
```

To confirm the module is linked (boringcrypto builds):

```sh
go tool nm ./omni-sag | grep -i boringcrypto
```

## What the self-check verifies

`fips.Check` (in `internal/fips`, a leaf package that imports only the standard
library) does three things:

1. **Runtime probe** — `crypto/fips140.Enabled()`.
2. **Algorithm self-test** (`fips.SelfTest`) — a SHA-256 known-answer test and
   an Ed25519 sign/verify (including a negative "tampered message must fail"
   check). These are the primitives the codebase actually depends on: Ed25519
   for evidence-checkpoint signing, SHA-256 for the evidence hash chain, session
   recording ids, and ICAP digests. Under `fips140=only` any non-approved
   primitive would fault here at boot rather than mid-session.
3. **TLS parameter helpers** — `internal/fips` exposes `ValidateTLSConfig`,
   `ApprovedTLSConfig`, `TLSVersionApproved`, `CipherSuiteApproved`, and
   `ApprovedTLS13Suite` so the TLS used for LDAPS, the CyberArk CCP client, and
   the control-plane API can be pinned to FIPS-acceptable versions (TLS 1.2+)
   and AES-GCM cipher suites (ChaCha20-Poly1305, CBC, 3DES, RC4 excluded).

## Algorithm inventory (FIPS acceptability)

| Use                                   | Algorithm            | FIPS 140-3 status |
|---------------------------------------|----------------------|-------------------|
| Evidence checkpoint signing           | Ed25519 (EdDSA)      | Approved (FIPS 186-5) |
| Evidence hash chain / recording ids   | SHA-256              | Approved (FIPS 180-4 / SHS) |
| LDAPS / CCP / API transport           | TLS 1.2+ AES-GCM     | Approved |
| TLS ChaCha20-Poly1305                 | ChaCha20-Poly1305    | **Not** approved — excluded by the helpers |

## Notes and caveats

- FIPS-readiness is a *posture*, not a validation certificate. Formal FIPS 140-3
  compliance also depends on the deployed module's validation status and the
  operational environment (key management, entropy source, etc.).
- SSH host-key and transport algorithms are governed by `golang.org/x/crypto/ssh`
  and the peer's negotiation; running under `fips140=only` constrains the
  primitives that library may use.
