# Omni-SAG Operator (scaffold)

Watches the Omni-SAG CustomResources and reconciles them into the running
gateway's policy and approval state. **Requires a Kubernetes cluster.** The CRDs
and the in-process interfaces they target already exist; wiring a
controller-runtime manager is the remaining work.

## CRDs (`crds/crds.yaml`)
| CRD | Reconciles into |
|-----|-----------------|
| `Policy` | `internal/policysource` CRDSource → `policy.Holder` / `dialer.SetPolicy` (hot-swap, already implemented) |
| `ApprovalRequest` | `internal/approval` CRDStore → the four-eyes store the dialer gate consults |
| `QuarantineRelease` | releases a WORM-quarantined object after four-eyes |
| `StagedPolicyChange` | a proposed `Policy` pending four-eyes before it applies |

## Boundary
`cmd/omni-operator` builds and documents the reconciler mapping but does not
import controller-runtime (so `make ci` stays green without a cluster). To make
it live: add controller-runtime, implement a Reconcile loop per CRD, and swap the
stubbed `policysource.CRDSource` / `approval.CRDStore` for informer-backed
implementations. Everything downstream of those interfaces is done and tested.

## Security
The operator's RBAC should be least-privilege (watch/update the four CRDs in its
namespace only). The gateway pods run under the restricted-v2-compatible
SecurityContext in the Helm chart (`deploy/helm`) — non-root, no capabilities,
read-only rootfs, no `IPC_LOCK` (ADR-0001). Nodes must run with swap disabled.
