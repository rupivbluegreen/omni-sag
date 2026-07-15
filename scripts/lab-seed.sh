#!/usr/bin/env bash
# Seed the dev-lab AD with the Slice 1 demo identities, idempotently.
#   dba   : role-granting group
#   alice : member of dba   (tunnel allowed)
#   bob   : not in dba      (tunnel prohibited)
#   carol : member of dba   (peer approver for alice's group-scoped four-eyes)
#
# Usage: scripts/lab-seed.sh   (after `make lab-up` and provisioning settles)
set -euo pipefail

CONTAINER="${SAMBA_CONTAINER:-omni-sag-samba-ad}"
USER_PW="${LAB_USER_PW:-Passw0rd!}"

st() { docker exec "$CONTAINER" samba-tool "$@"; }

echo "waiting for samba to serve..."
for i in $(seq 1 60); do
  if docker exec "$CONTAINER" samba-tool user list >/dev/null 2>&1; then break; fi
  sleep 4
  [ "$i" = 60 ] && { echo "samba did not come up"; exit 1; }
done

ensure_group() {
  st group list | grep -qx "$1" || st group add "$1"
}
ensure_user() {
  st user list | grep -qx "$1" || st user create "$1" "$USER_PW" >/dev/null
}

ensure_group dba
ensure_user alice
ensure_user bob
ensure_user carol
# addmembers is idempotent enough: it errors if already a member, so guard it.
st group listmembers dba 2>/dev/null | grep -qx alice || st group addmembers dba alice
st group listmembers dba 2>/dev/null | grep -qx carol || st group addmembers dba carol

echo "seeded. dba members:"
st group listmembers dba
