# Compliance Pack — DPIA, DORA Art. 30, Works-Council Profiles

Regulatory artifacts for deploying Omni-SAG in an EU financial-institution
context. These are **drafts for the deploying organization to complete and
ratify** — they encode what the system does; the legal basis, retention
periods, and DPO/works-council sign-off are the operator's to fill.

---

## 1. Data Protection Impact Assessment (GDPR Art. 35)

A DPIA is required: the system performs systematic monitoring (session
recording) of workers' privileged activity.

### Personal data processed

| Category | Where | Purpose | Notes |
|----------|-------|---------|-------|
| AD username, group membership | evidence (auth events), policy | authn/authz | pseudonymous identifier |
| Source IP | evidence (all events) | attribution, brute-force defense | may be personal data |
| Session recordings (asciicast) | recording store (S3/local) | audit of privileged sessions | may contain incidental personal data typed/displayed |
| File-transfer manifests (path, size, SHA-256) | evidence | exfiltration/ingress audit | content hashed, not stored (v1) |
| Approval requests (requester, approver, target, reason) | approval store, evidence | four-eyes accountability | identifies workers |

### Data minimization built in

- **Recording is policy-scoped**: `none` / `metadata-only` / `full` per target.
  Only `full` targets record session content; `metadata-only` is explicitly
  marked unrecorded in evidence; forwarding is refused on `full` targets so
  content cannot bypass recording.
- **Secrets are never persisted or recorded** (keystroke suppression; `[]byte`
  hygiene). Injected credentials never appear in recordings or evidence.
- **Content is not stored** for SFTP in v1 — only a hash + size manifest.

### Rights & retention (operator to set)

- **Retention**: evidence + recordings retention is operator-configured (WORM
  Object-Lock retention days). Set to the minimum legally required.
- **Access**: recordings/evidence are reachable only via the RBAC-gated control
  plane (viewer+); no ambient access.
- **Integrity/erasure tension**: WORM immutability serves legal-hold/audit needs
  but constrains erasure — document the legal basis (legitimate interest /
  legal obligation) and the retention horizon accordingly.

### DPIA risk assessment (indicative)

| Risk | Likelihood | Impact | Residual control |
|------|-----------|--------|------------------|
| Over-collection via `full` recording | med | high | per-target scoping, works-council profile below |
| Recording exposure | low | high | RBAC control plane, WORM, TLS |
| Secret leakage into evidence | low | high | []byte hygiene + CI lint + audit-verified |
| Mis-attribution | low | med | signed evidence chain, four-eyes |

---

## 2. DORA Article 30 — ICT Third-Party Contractual Register

DORA Art. 30 requires key contractual provisions for ICT services supporting
critical/important functions. Omni-SAG's own **ICT third-party dependencies**:

| Dependency | Function | Criticality | Art. 30 provisions to secure in contract |
|------------|----------|-------------|------------------------------------------|
| Active Directory / LDAPS | authentication | critical | availability SLA, secure config (no anonymous bind), incident notification, audit rights |
| RADIUS/NPS + Entra MFA | second factor | critical | availability, MFA method assurance, sub-processor transparency |
| CyberArk (CCP) | credential vault | critical | key management, availability, mTLS, exit/portability of vaulted secrets |
| ICAP AV/DLP engine | content inspection | important | signature currency, latency SLA (see note), availability |
| Object storage (MinIO / Dell ECS) | evidence/recording WORM | critical | Object-Lock durability, retention immutability, data location, exit |
| Container registry / signing (cosign) | supply chain | important | image provenance, SBOM, vulnerability management |

Omni-SAG **as a service** provided to internal functions — Art. 30 provisions
the deploying org offers its own consumers: RTO/RPO (drain-on-upgrade,
out-of-band control plane), audit access (evidence + `omni-verify`), exit
(evidence bundles are self-describing and offline-verifiable), sub-outsourcing
transparency (the dependency table above).

**Note**: the ICAP DLP latency SLA ("≤15% transfer penalty") is provisional
until benchmarked against the deploying org's commercial DLP engine — the
`BenchmarkInspect` harness (`internal/inspect`) is the measurement vehicle.

---

## 3. Works-Council Session-Recording Profiles

Session recording of workers requires works-council (Betriebsrat / CSE)
agreement in many jurisdictions. Omni-SAG supports **graduated profiles** so the
council can agree the least-intrusive posture per system class:

| Profile | Policy `record:` | What is captured | Typical use |
|---------|------------------|------------------|-------------|
| **None** | `none` | auth + tunnel-decision evidence only (who connected where, when) | low-sensitivity targets; default |
| **Metadata-only** | `metadata-only` | + SFTP transfer manifests (path/size/hash), evidence marks the session unrecorded; `-L` forwarding allowed | most targets; accountability without content surveillance |
| **Full** | `full` | + full interactive session recording (asciicast); `-L` forwarding **refused** so nothing bypasses recording | crown-jewel targets only, with council agreement |

Council-relevant guarantees:

- Recording scope is **declared per target in policy**, reviewable via
  `omnictl` policy rule-trace ("why can Alice reach X, and is it recorded?").
- **Keystroke suppression** ensures injected credentials are never recorded.
- Recording **cannot be silently disabled**: if a `full` target's recording
  store is unavailable, the session is **refused** and the failure is evidenced
  (no unrecorded access to a recorded target).
- **Four-eyes + live supervision**: sensitive sessions can require a second
  approver and be watched live (with a kill switch) rather than recorded — a
  proportionality option for the council.
- Recordings are **immutable and access-controlled** (WORM + RBAC), protecting
  workers from tampering as well as the employer from repudiation.

Recommended council agreement: default `metadata-only`; `full` only for an
explicit, listed set of crown-jewel systems; retention set to the legal minimum;
access to recordings restricted to named roles and itself audited.
