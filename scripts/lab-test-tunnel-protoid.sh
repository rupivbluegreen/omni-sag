#!/usr/bin/env bash
# Real -L tunnel protocol-identification check against the dev lab: opens a
# genuine -L tunnel through the gateway (using the ACTUAL local ssh binary as
# client) to the lab's ssh-target container, and a second -L tunnel to MinIO's
# HTTP endpoint, then asserts the gateway's own evidence stream recorded the
# correct detected protocol for each — ground truth that protoident's
# signature table classifies real protocol streams, not just crafted test
# bytes (mirrors scripts/lab-test-scp.sh's real-client discipline).
#
# Targets are dialed by each container's own bridge-network IP (docker
# inspect), not by the host-published 127.0.0.1 ports: the gateway's outbound
# dialer runs its SSRF/rebind guard on every real target, which blocks
# loopback addresses unconditionally (internal/dialer/guard.go) — only
# dialer_test.go's harness relaxes that via WithLoopbackTargetsAllowed, which
# cmd/omni-sag never wires in. A real deployment reaches targets by their
# actual network address, so this check does the same.
#
# Usage: scripts/lab-test-tunnel-protoid.sh
set -euo pipefail

GW_BIN="${GW_BIN:-./bin/omni-sag_$(go env GOOS)_$(go env GOARCH)}"
BASE_CONFIG="${CONFIG:-deploy/compose/config.example.yaml}"
GW_PORT="${GW_PORT:-2222}"

GW_USER="alice"
GW_PASSWORD="Passw0rd!"

RED=$'\033[31m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
pass() { echo "${GREEN}PASS${RESET}: $*"; }
fail() { echo "${RED}FAIL${RESET}: $*" >&2; }

if [ ! -x "$GW_BIN" ]; then
  echo "gateway binary not found at $GW_BIN — run: make binaries" >&2
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 1; }

echo "== checking dev-lab containers =="
for c in omni-sag-samba-ad omni-sag-ssh-target omni-sag-minio; do
  if ! docker ps --filter "name=^${c}\$" --filter "status=running" --format '{{.Names}}' | grep -qx "$c"; then
    echo "required container not running: $c — run: make lab-up && make lab-seed" >&2
    exit 1
  fi
done

SSH_TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' omni-sag-ssh-target)"
MINIO_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' omni-sag-minio)"
if [ -z "$SSH_TARGET_IP" ] || [ -z "$MINIO_IP" ]; then
  echo "could not determine container bridge IPs (ssh-target=$SSH_TARGET_IP minio=$MINIO_IP)" >&2
  exit 1
fi
echo "ssh-target bridge IP: $SSH_TARGET_IP:2222, minio bridge IP: $MINIO_IP:9000"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/omnisag-tunnelprotoid-test.XXXXXX")"
GW_PID=""
TUN1_PID=""
TUN2_PID=""
cleanup() {
  [ -n "$TUN1_PID" ] && kill "$TUN1_PID" 2>/dev/null || true
  [ -n "$TUN2_PID" ] && kill "$TUN2_PID" 2>/dev/null || true
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

# tunnel_inspection is opt-in (default off), and the shipped example config
# leaves it off. Derive a config that enables it (observe mode — this check
# is about ground-truth classification, not enforcement) and adds allow rules
# for the two container targets above. host_key/evidence.file are redirected
# into WORKDIR so this run's evidence never mixes with another's.
TEST_CONFIG="$WORKDIR/config.yaml"
python3 - "$BASE_CONFIG" "$TEST_CONFIG" "$WORKDIR" "$SSH_TARGET_IP" "$MINIO_IP" <<'PY'
import sys, yaml

path_in, path_out, workdir, ssh_target_ip, minio_ip = sys.argv[1:6]
with open(path_in) as f:
    cfg = yaml.safe_load(f)

cfg["host_key"] = workdir + "/hostkey.pem"
cfg.setdefault("evidence", {})["file"] = workdir + "/evidence.jsonl"
cfg["tunnel_inspection"] = {
    "enabled": True,
    "enforce": False,
    "max_prefix_bytes": 512,
    "classify_timeout_seconds": 5,
}
for role in cfg.get("policy", {}).get("roles", []):
    if role.get("name") == "dba":
        role.setdefault("allow", []).extend([
            {"host": ssh_target_ip, "ports": [2222]},
            {"host": minio_ip, "ports": [9000]},
        ])

with open(path_out, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False)
PY

"$GW_BIN" -config "$TEST_CONFIG" >"$WORKDIR/gateway.log" 2>&1 &
GW_PID=$!
for i in $(seq 1 50); do
  if ! kill -0 "$GW_PID" 2>/dev/null; then
    fail "gateway process exited early"; tail -n 60 "$WORKDIR/gateway.log" >&2; exit 1
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/$GW_PORT") 2>/dev/null && { exec 3<&- 3>&-; break; }
  sleep 0.2
done
echo "gateway up (SSH :$GW_PORT), pid=$GW_PID"

cat >"$WORKDIR/tunnel_up.py" <<'PY'
#!/usr/bin/env python3
# Opens a real -N -L tunnel via the local ssh binary and keeps it alive until
# killed. Prints TUNNEL-READY once past the password prompt with no immediate
# forwarding failure, so the caller knows it's safe to dial the local port.
import os, pty, select, sys, time

def read_avail(fd, timeout):
    r, _, _ = select.select([fd], [], [], timeout)
    if fd in r:
        try:
            return os.read(fd, 65536)
        except OSError:
            return b""
    return None

def main():
    gw_port, local_port, remote_host, remote_port, gw_user, gw_pw = sys.argv[1:7]
    cmd = ["ssh", "-N", "-L", f"{local_port}:{remote_host}:{remote_port}",
        "-p", gw_port, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no", "-o", "ExitOnForwardFailure=yes",
        "-o", "ConnectTimeout=10", f"{gw_user}@127.0.0.1"]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(127)

    buf = b""
    deadline = time.time() + 15
    sent = False
    while time.time() < deadline:
        chunk = read_avail(fd, 0.5)
        if chunk is None:
            continue
        if chunk == b"":
            print("ssh exited before authenticating", file=sys.stderr)
            sys.exit(1)
        buf += chunk
        if not sent and b"password:" in buf.lower():
            os.write(fd, (gw_pw + "\n").encode())
            sent = True
            deadline = time.time() + 5  # short failure-detection window post-auth
        low = buf.lower()
        for bad in (b"permission denied", b"forwarding failed", b"could not request", b"bind:"):
            if bad in low:
                print(buf.decode(errors="replace"), file=sys.stderr)
                sys.exit(1)
        if sent and time.time() > deadline - 0.1:
            break

    print("TUNNEL-READY", flush=True)
    while True:
        chunk = read_avail(fd, 5.0)
        if chunk == b"":
            return

if __name__ == "__main__":
    main()
PY

wait_ready() {
  local log="$1" what="$2"
  for i in $(seq 1 40); do
    grep -q "TUNNEL-READY" "$log" 2>/dev/null && return 0
    sleep 0.25
  done
  fail "$what tunnel never became ready"; cat "$log" >&2; exit 1
}

wait_local_port() {
  local port="$1" what="$2"
  for i in $(seq 1 40); do
    (exec 9<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 9<&- 9>&-; return 0; }
    sleep 0.2
  done
  fail "$what local forwarded port never accepted a connection"; exit 1
}

wait_evidence() {
  local file="$1" want_protocol="$2"
  for i in $(seq 1 40); do
    if grep -q "\"type\":\"tunnel_protocol\".*\"protocol\":\"${want_protocol}\"" "$file" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

echo "== real -L tunnel to the ssh-target container: must classify as ssh (server-speaks-first) =="
LOCAL_PORT1=18022
python3 "$WORKDIR/tunnel_up.py" "$GW_PORT" "$LOCAL_PORT1" "$SSH_TARGET_IP" 2222 "$GW_USER" "$GW_PASSWORD" \
  >"$WORKDIR/tunnel1.log" 2>&1 &
TUN1_PID=$!
wait_ready "$WORKDIR/tunnel1.log" "ssh-target"
wait_local_port "$LOCAL_PORT1" "ssh-target"
# Pull the target's SSH banner through the tunnel so the gateway's tap sees
# it — a bare connect is not enough, since the classifier needs bytes.
(exec 8<>"/dev/tcp/127.0.0.1/$LOCAL_PORT1"; timeout 5 head -c 8 <&8 >/dev/null; exec 8<&- 8>&-) || true

if wait_evidence "$WORKDIR/evidence.jsonl" "ssh"; then
  pass "real -L tunnel to ssh-target classified as protocol=ssh"
else
  fail "no tunnel_protocol evidence event with protocol=ssh"
  tail -n 60 "$WORKDIR/gateway.log" >&2
  exit 1
fi
kill "$TUN1_PID" 2>/dev/null || true
wait "$TUN1_PID" 2>/dev/null || true
TUN1_PID=""

echo "== real -L tunnel to MinIO's HTTP endpoint: must classify as http (client-speaks-first) =="
LOCAL_PORT2=19000
python3 "$WORKDIR/tunnel_up.py" "$GW_PORT" "$LOCAL_PORT2" "$MINIO_IP" 9000 "$GW_USER" "$GW_PASSWORD" \
  >"$WORKDIR/tunnel2.log" 2>&1 &
TUN2_PID=$!
wait_ready "$WORKDIR/tunnel2.log" "minio"
wait_local_port "$LOCAL_PORT2" "minio"
# The client must speak first for an HTTP classification — send a real GET.
(exec 7<>"/dev/tcp/127.0.0.1/$LOCAL_PORT2"
 printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' >&7
 timeout 5 head -c 12 <&7 >/dev/null
 exec 7<&- 7>&-) || true

if wait_evidence "$WORKDIR/evidence.jsonl" "http"; then
  pass "real -L tunnel to MinIO classified as protocol=http"
else
  fail "no tunnel_protocol evidence event with protocol=http"
  tail -n 60 "$WORKDIR/gateway.log" >&2
  exit 1
fi
kill "$TUN2_PID" 2>/dev/null || true
wait "$TUN2_PID" 2>/dev/null || true
TUN2_PID=""

echo "ALL PASS"
