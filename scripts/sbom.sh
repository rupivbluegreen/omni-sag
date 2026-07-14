#!/usr/bin/env bash
# Generate an SBOM for the omni-sag image (or the source module graph).
# Uses syft if available (CycloneDX JSON); otherwise falls back to a native Go
# module list so the target always produces an artifact.
set -euo pipefail

IMAGE="${1:-omni-sag:latest}"
OUT="${OUT:-sbom}"

if command -v syft >/dev/null 2>&1; then
  syft "$IMAGE" -o cyclonedx-json="${OUT}.cdx.json"
  echo "wrote ${OUT}.cdx.json (syft/CycloneDX)"
else
  echo "syft not found; emitting go module SBOM (json)"
  go version -m "$(command -v go >/dev/null && echo omni-sag || true)" >/dev/null 2>&1 || true
  go list -deps -json ./... > "${OUT}.gomod.json"
  echo "wrote ${OUT}.gomod.json (go list -deps). Install syft for a full image SBOM."
fi
