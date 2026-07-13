# ADR-0001 — mlock-free credential handling

**Status:** Accepted
**Date:** 2026-07-13
**Context slice:** affects Slice 6 (CyberArk & credential modes); constrains the
`internal/credential` package from day one.

## Context

Injected credentials (CyberArk `inject` mode, and any `prompt`/`passthrough`
secret material) must not leak to disk. The conventional mitigation is
`mlock(2)` to pin secret pages so they cannot be swapped out. On the target
OpenShift, `mlock` requires either the `IPC_LOCK` capability or a raised
`RLIMIT_MEMLOCK`, neither of which the stock `restricted-v2` SCC grants.

Open question #1 to the design partner — *"are custom SCCs permitted?"* — is
unanswered and may come back "no". Designing around `mlock` and then losing it
is expensive to unwind. Designing mlock-free is safe under both answers.

## Decision

**Do not depend on `mlock` for credential confidentiality.** The credential
subsystem must be correct under the stock `restricted-v2` SCC with no
`IPC_LOCK` and no raised memlock limit.

## Consequences — the mitigations that replace mlock

Confidentiality now rests on a layered set of guarantees, split between what the
**operator/deployment** guarantees and what the **application** guarantees.

### Operator / deployment guarantees (documented as install requirements)
1. **Swap disabled on the node.** No swap => no swapping of secret pages to
   disk. This is the primary replacement for `mlock`. It is the historical
   Kubernetes default (kubelet required swap off) and must be an explicit,
   documented install requirement, not an assumption.
2. **Core dumps disabled.** `RLIMIT_CORE = 0`, and no writable core path, so a
   crash cannot spill secret memory to disk.
3. **ptrace / debugger attach denied.** Ensured by SCC (no `SYS_PTRACE`) and a
   non-shared process namespace, so another process cannot read this process's
   memory.

### Application guarantees (enforced in `internal/credential`)
4. **Just-in-time fetch, minimal residency.** Fetch the secret at the moment of
   use, use it, wipe it. Never cache. The window in which plaintext exists is
   as short as mechanically possible.
5. **Explicit zeroization.** Overwrite secret bytes immediately after use. Do
   not wait for GC.
6. **Mutable byte buffers only — never `string`.** Go `string` is immutable and
   may be copied by the runtime; its backing bytes cannot be reliably wiped.
   Secret material lives in `[]byte` allocated once, wiped in place, and is
   never converted to `string`. Provide a `Secret` type wrapping a fixed
   `[]byte` with `Bytes()` / `Destroy()` and no `String()` method.
7. **Avoid runtime copies of the buffer.** No `append` growth (pre-size), no
   passing the secret slice by value into APIs that retain it, no logging.
8. **`runtime.KeepAlive` / avoid premature reclaim** so the wipe is not
   optimized away, and the buffer is not GC'd before `Destroy()`.

## What this explicitly rules out

- No code path may call `mlock`/`munlock` or require `IPC_LOCK`.
- No credential value may be stored in a `string`, a struct field of type
  `string`, a map key/value as `string`, or an error message.

## Follow-ups

- Add a CI/lint check (Slice 6) that flags `string`-typed fields or params in
  `internal/credential` carrying secret material.
- Re-open if the design partner permits custom SCCs *and* an operational reason
  to prefer `mlock` appears — but mlock-free remains the default.
