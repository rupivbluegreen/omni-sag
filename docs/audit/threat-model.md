# Threat Model

Scope: the Omni-SAG v1 gateway (SSH + SFTP privileged access). Oriented around
adversaries, trust boundaries, and STRIDE, cross-referenced to the controls that
mitigate each. Per-surface deep-dives live in ADR-0002 (credential injection)
and ADR-0003 (FIPS).

## Assets

- **Target-system access** (the privilege the gateway brokers).
- **Injected credentials** (CyberArk-vaulted target secrets) — highest value.
- **The audit trail** (evidence chain) — itself a primary security control.
- **Session recordings** (may contain sensitive content / personal data).
- **Signing/host keys** (Ed25519 evidence key, SSH host key, CCP client cert).

## Trust boundaries

1. **User ⟷ gateway** (SSH transport). Untrusted client; authenticated by
   AD + MFA.
2. **Gateway ⟷ AD/RADIUS** (LDAPS / RADIUS). MITM-relevant if `insecure_tls`.
3. **Gateway ⟷ CyberArk CCP** (mutual TLS). Vault of target secrets.
4. **Gateway ⟷ ICAP** (content inspection). Integration client, fail-closed.
5. **Gateway ⟷ target** (the single dialer). SSRF boundary.
6. **Gateway ⟷ object storage** (evidence/recording/quarantine WORM).
7. **Operator ⟷ control-plane API** (mTLS/OIDC + RBAC). Separate from the data path.
8. **Node/OS ⟷ process** (memory confidentiality: swap/coredump/ptrace — ADR-0001).

## Adversaries

| Adversary | Capability | Primary mitigations |
|-----------|-----------|---------------------|
| Malicious authenticated user | valid SSH login; crafts SSH/SFTP packets, offsets, forwards | policy default-deny, single-dialer + SSRF guard, SFTP offset/gap bounds, content inspection, recording, four-eyes |
| Credential thief | wants to read an injected secret | `Secret` []byte-only + zeroize, keystroke suppression, no logging/evidencing, mlock-free node posture |
| On-path attacker (network) | MITM gateway↔AD/CCP/ICAP | LDAPS/mTLS cert verification (insecure_tls rejected under FIPS enforce), CCP verified CA |
| Evidence tamperer | write access to the evidence store | hash chain + Merkle + Ed25519 signed global checkpoint chain + WORM Object-Lock; `omni-verify` detects any interior/whole-epoch deletion; pinned head + WORM for trailing |
| Downgrade-forcer | makes a control unavailable to weaken it | fail-closed matrix — every dependency failure denies; no silent credential downgrade |
| Insider abusing approvals | approves own privileged access | four-eyes (approver ≠ requester, server-side), TTL, durable, RBAC operator+ |
| Brute-forcer | guesses passwords | per-source lockout, bounded so it cannot DoS a victim |
| Compromised dependency | buggy/hostile ICAP or DC returns garbage | fail-closed on unknown verdict / parse error / OOM attempt |

## STRIDE summary

- **Spoofing** — AD+MFA authn; mTLS for CCP/API; SSH host key; four-eyes binds
  approver to a verified subject.
- **Tampering** — tamper-evident evidence chain; policy hot-reload validated;
  config validation; WORM.
- **Repudiation** — every auth/tunnel/transfer/recording/approval/inspection is
  evidenced with source IP, user, and a signed chain; offline verifiable.
- **Information disclosure** — secret `[]byte` hygiene; keystroke suppression;
  no secrets in logs/errors/evidence; recording access is control-plane-gated.
- **Denial of service** — handshake deadline + in-flight cap; per-conn channel
  cap; panic recovery; bounded SFTP allocations; brute-force lockout; bounded
  reorder/chunk buffers; drain on SIGTERM.
- **Elevation of privilege** — default-deny policy; single-dialer authz before
  socket; SSRF guard; credential no-downgrade; approval gate; RBAC on the API.

## Residual risks / accepted limitations (for the external auditor)

1. **Evidence emit is fail-open-but-surfaced** (see fail-closed matrix row 16).
2. **Trailing/whole-bundle deletion** is detectable only with a pinned `-head`
   or WORM (inherent to offline verification).
3. **SFTP backend and interactive shell are stand-ins** in v1 (in-memory FS /
   echo shell); the *controls* (inspect-before-accept, recording, evidence) are
   real, but proxying to a real target shell/backend is v1.x work.
4. **CRD policy/approval sources are stubs**; file-backed durable stores are the
   v1 implementation. Kubernetes informer reconcilers require a cluster.
5. **OIDC is a static-token stand-in** behind an `Authorizer` interface; a real
   JWKS validator is the v1.x wiring.
6. **Cross-namespace four-eyes** requires operator config (API subjects = SSH
   names); enforced by canonicalization + documented, not by a directory join.
7. **FIPS TLS-parameter enforcement** provides helpers + an enforce-mode boot
   check + insecure_tls rejection, but does not yet route every TLS config
   through `ValidateTLSConfig`.
