#!/usr/bin/env bash
set -euo pipefail

module="github.com/rupivbluegreen/omni-sag"
fail=0

echo "== net.Dial restricted to internal/dialer =="
matches=$(grep -rnE '\bnet\.Dial(er)?\b' --include='*.go' . \
  | grep -v '_test\.go:' \
  | grep -v '^\./internal/dialer/' || true)
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

if [ "$fail" -ne 0 ]; then
  echo "import rule violations found"
  exit 1
fi
echo "import rules OK"
