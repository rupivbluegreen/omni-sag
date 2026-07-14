#!/usr/bin/env bash
set -euo pipefail

module="github.com/rupivbluegreen/omni-sag"
fail=0

echo "== net.Dial restricted to internal/dialer (+ marked integration clients) =="
# Only internal/dialer may dial session TARGETS. Integration clients (LDAP,
# RADIUS, S3) dial their operator-configured endpoint inside vendored deps and
# so never appear here. The ICAP client (internal/inspect) hand-rolls TCP, so
# its single dial site is explicitly annotated with the marker below; that one
# line is exempt. The marker names an operator-configured integration endpoint,
# NOT a session target, so the single-target-dialer invariant is preserved.
matches=$(grep -rnE '\bnet\.Dial(er)?\b' --include='*.go' \
  --exclude-dir='.git' --exclude-dir='.claude' --exclude-dir='vendor' . \
  | grep -v '_test\.go:' \
  | grep -v '^\./internal/dialer/' \
  | grep -v 'omni-sag:integration-dial' || true)
if [ -n "$matches" ]; then
  echo "net.Dial/net.Dialer used outside internal/dialer:"
  echo "$matches"
  fail=1
fi

echo "== internal/dialer must not import internal/api =="
if go list -f '{{join .Imports "\n"}}' ./internal/dialer/... 2>/dev/null | grep -q "${module}/internal/api"; then
  echo "internal/dialer imports internal/api"
  fail=1
fi

echo "== internal/policy must not import internal/session =="
if go list -f '{{join .Imports "\n"}}' ./internal/policy/... 2>/dev/null | grep -q "${module}/internal/session"; then
  echo "internal/policy imports internal/session"
  fail=1
fi

echo "== internal/credential import allowlist (session, dialer only) =="
while IFS=$'\t' read -r pkg imports; do
  case ",${imports}," in
    *",${module}/internal/credential,"*)
      case "$pkg" in
        "${module}/internal/session"|"${module}/internal/dialer"|"${module}/internal/credential") ;;
        *)
          echo "package $pkg imports internal/credential (not allowed)"
          fail=1
          ;;
      esac
      ;;
  esac
done < <(go list -f '{{.ImportPath}}{{"\t"}}{{join .Imports ","}}' ./...)

echo "== internal/credential: no string-typed secrets / String() on Secret (ADR-0001) =="
# Secret material must live in []byte, never a Go string (unwipeable). Flag a
# String() method on the Secret type, and any struct field that carries a secret
# VALUE as a string (paths/ids like ClientCertPath/AppID are fine).
if grep -rnE 'func \([a-zA-Z0-9_ ]*\*?Secret\) String\(\)' internal/credential/ 2>/dev/null; then
  echo "internal/credential: Secret must not implement String() (ADR-0001)"
  fail=1
fi
if grep -rnE '\b(Password|Passphrase|Passwd|SecretValue|PlainSecret)\b[[:space:]]+string' \
    --include='*.go' internal/credential/ 2>/dev/null | grep -v '_test\.go:'; then
  echo "internal/credential: secret value carried in a string field (use credential.Secret / []byte)"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "import rule violations found"
  exit 1
fi
echo "import rules OK"
