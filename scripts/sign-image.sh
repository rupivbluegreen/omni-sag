#!/usr/bin/env bash
# Cosign-sign the omni-sag image and attach the SBOM as an attestation.
# Requires cosign, a signing key (COSIGN_KEY or keyless/OIDC), and push access
# to the registry at run time — none of which exist in CI, so this is the
# operator's release step, wired here.
set -euo pipefail

IMAGE="${1:?usage: sign-image.sh <image-ref-with-digest>}"

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign not installed; install from https://docs.sigstore.dev/ and re-run" >&2
  exit 1
fi

# Prefer keyless (Fulcio/OIDC) if no key is set.
if [ -n "${COSIGN_KEY:-}" ]; then
  cosign sign --key "$COSIGN_KEY" "$IMAGE"
else
  cosign sign "$IMAGE"   # keyless: requires an OIDC identity
fi

# Attach the SBOM as an attestation if one was generated.
if [ -f "sbom.cdx.json" ]; then
  cosign attest --predicate sbom.cdx.json --type cyclonedx "$IMAGE"
fi
echo "signed $IMAGE"
