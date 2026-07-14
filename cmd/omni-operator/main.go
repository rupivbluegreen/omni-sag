// Command omni-operator is the Kubernetes operator that reconciles Omni-SAG
// CustomResources (Policy, ApprovalRequest, QuarantineRelease,
// StagedPolicyChange — see deploy/operator/crds) into the running gateway's
// policy and approval state.
//
// SCAFFOLD BOUNDARY: a functioning operator requires a Kubernetes cluster and a
// controller-runtime manager (watch + reconcile loops), which is not wired here
// so the module builds and `make ci` stays green without a cluster or the
// controller-runtime dependency tree. The reconcilers map 1:1 onto the existing
// in-process abstractions:
//
//   - Policy            -> internal/policysource CRDSource (currently stubbed) ->
//     policy.Holder / dialer.SetPolicy (already implemented)
//   - ApprovalRequest   -> internal/approval CRDStore (stubbed) -> the four-eyes
//     store the dialer gate already consults
//   - QuarantineRelease -> release a WORM-quarantined object (four-eyes)
//   - StagedPolicyChange-> a proposed Policy pending four-eyes before it applies
//
// Wiring controller-runtime is the documented follow-up; the CRDs, RBAC, and the
// interfaces they target already exist.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	kubeconfig := flag.String("kubeconfig", "", "path to a kubeconfig (in-cluster if empty)")
	flag.Parse()

	fmt.Fprintln(os.Stderr, "omni-operator: scaffold — requires a Kubernetes cluster and controller-runtime wiring.")
	fmt.Fprintln(os.Stderr, "Apply deploy/operator/crds/crds.yaml, then run the reconcilers documented in deploy/operator/README.md.")
	if *kubeconfig != "" {
		fmt.Fprintf(os.Stderr, "kubeconfig=%s (not yet used)\n", *kubeconfig)
	}
	os.Exit(0)
}
