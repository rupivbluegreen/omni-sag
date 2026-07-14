#!/usr/bin/env bash
# Build an air-gap bundle: the container image, the Helm chart, the CRDs, and the
# offline evidence verifier, in a single tarball for transfer into a disconnected
# environment.
set -euo pipefail

IMAGE="${IMAGE:-omni-sag:latest}"
OUT="${OUT:-omni-sag-airgap.tar}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "saving image $IMAGE"
docker save "$IMAGE" -o "$STAGE/image.tar"

echo "packaging chart, crds, verifier"
cp -r deploy/helm "$STAGE/helm"
cp -r deploy/operator/crds "$STAGE/crds"
# The offline verifier lets auditors check evidence bundles with no gateway.
go build -trimpath -ldflags="-s -w" -o "$STAGE/omni-verify" ./cmd/omni-verify

cat > "$STAGE/LOAD.md" <<'EOF'
# Air-gap load
1. docker load -i image.tar
2. helm install omni-sag ./helm/omni-sag -f values.yaml
3. kubectl apply -f crds/            # if using the operator
4. ./omni-verify -bundle <evidence-dir> -pubkey <key> -head <hash>   # audit evidence
EOF

tar -C "$STAGE" -cf "$OUT" .
echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
