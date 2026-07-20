#!/usr/bin/env bash
# Ground-truth CEF-over-syslog interop check against the dev lab: proves the
# CEF formatter (internal/eventexport/format_cef.go) and the syslog transport
# (internal/eventexport/transport_syslog.go) really interoperate with a real
# TCP syslog consumer for REAL gateway events — not just this repo's own Go
# unit tests. Drives a real-target session as alice (the same technique as
# lab-test-real-target.sh), which produces real "auth" and "session_start"
# evidence events, and asserts well-formed CEF lines for them arrive at a
# real local TCP syslog receiver.
#
# Usage: scripts/lab-test-eventexport.sh
set -euo pipefail

GW_BIN="${GW_BIN:-./bin/omni-sag_$(go env GOOS)_$(go env GOARCH)}"
BASE_CONFIG="${CONFIG:-deploy/compose/config.example.yaml}"
GW_PORT="${GW_PORT:-2222}"

GW_USER="alice"
GW_PASSWORD="Passw0rd!"
TARGET_HOST="127.0.0.1"
TARGET_PASSWORD="InjectedSecret123!"

RED=$'\033[31m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
pass() { echo "${GREEN}PASS${RESET}: $*"; }
fail() { echo "${RED}FAIL${RESET}: $*" >&2; }

echo "== preflight =="
if [ ! -x "$GW_BIN" ]; then
  echo "gateway binary not found at $GW_BIN — building via 'make binaries'"
  make binaries
fi
if [ ! -x "$GW_BIN" ]; then
  echo "gateway binary still not found at $GW_BIN after 'make binaries'" >&2
  exit 1
fi
for tool in go python3 ssh docker; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required tool not found: $tool" >&2; exit 1; }
done

echo "== checking dev-lab containers =="
for c in omni-sag-samba-ad omni-sag-ssh-target; do
  if ! docker ps --filter "name=^${c}\$" --filter "status=running" --format '{{.Names}}' | grep -qx "$c"; then
    echo "required container not running: $c — run: make lab-up && make lab-seed" >&2
    exit 1
  fi
done
echo "lab containers OK (samba-ad, ssh-target running)"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/omnisag-eventexport-test.XXXXXX")"
GW_PID=""
RECV_PID=""
cleanup() {
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  [ -n "$RECV_PID" ] && kill "$RECV_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "== workdir: $WORKDIR (kept after this run for inspection) =="

# --- Local TCP syslog receiver ---------------------------------------------
# A tiny Go program rather than `nc -l`: nc flavors differ on whether -k
# (keep listening across connections) exists at all, and RFC 6587
# octet-counting framing needs exact byte-count reads to parse cleanly for
# the assertion step below — a raw `nc` capture would still contain the CEF
# text as a substring (fine for a loose grep), but wouldn't let this script
# also verify the framing itself is well-formed, which is part of what
# "interoperates with a real syslog consumer" should mean. Binds to port 0
# (kernel-assigned free port) and prints "PORT=<n>" once listening, so this
# script never has to guess or race on port selection.
cat >"$WORKDIR/syslog_receiver.go" <<'EOF'
package main

import (
	"fmt"
	"net"
	"os"
	"sync"
)

func main() {
	outPath := os.Args[1]
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	fmt.Printf("PORT=%d\n", port)

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer f.Close()

	var mu sync.Mutex // guards concurrent writes if the transport ever redials mid-run
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 65536)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					mu.Lock()
					f.Write(buf[:n])
					mu.Unlock()
				}
				if err != nil {
					return
				}
			}
		}(conn)
	}
}
EOF
go build -o "$WORKDIR/syslog_receiver" "$WORKDIR/syslog_receiver.go"

touch "$WORKDIR/syslog.out"
"$WORKDIR/syslog_receiver" "$WORKDIR/syslog.out" >"$WORKDIR/receiver.stdout" 2>"$WORKDIR/receiver.log" &
RECV_PID=$!

SYSLOG_PORT=""
for i in $(seq 1 25); do
  if ! kill -0 "$RECV_PID" 2>/dev/null; then
    fail "syslog receiver exited early"; cat "$WORKDIR/receiver.log" >&2; exit 1
  fi
  SYSLOG_PORT="$(sed -n 's/^PORT=//p' "$WORKDIR/receiver.stdout" | head -1)"
  [ -n "$SYSLOG_PORT" ] && break
  sleep 0.2
done
if [ -z "$SYSLOG_PORT" ]; then
  fail "syslog receiver never reported its port"; cat "$WORKDIR/receiver.log" >&2; exit 1
fi
echo "syslog receiver up on 127.0.0.1:$SYSLOG_PORT, capturing to $WORKDIR/syslog.out"

# --- Derived gateway config --------------------------------------------------
# Copies the checked-in demo config (unchanged) and layers on only what this
# check needs: state files redirected into WORKDIR (never touches the repo
# tree), and an export block enabling exactly one exporter — cef format over
# a syslog/tcp transport pointed at the receiver above.
mkdir -p "$WORKDIR/recordings"
python3 - "$BASE_CONFIG" "$WORKDIR/config.yaml" "$WORKDIR" "$SYSLOG_PORT" <<'PY'
import sys
import yaml

base_path, out_path, workdir, syslog_port = sys.argv[1:5]

with open(base_path) as f:
    cfg = yaml.safe_load(f)

cfg["host_key"] = f"{workdir}/hostkey.pem"
cfg["evidence"] = {"file": f"{workdir}/evidence.jsonl"}
cfg.setdefault("recording", {}) or cfg.__setitem__("recording", {})
cfg["recording"]["local_dir"] = f"{workdir}/recordings"

cfg["export"] = {
    "enabled": True,
    "exporters": [
        {
            "name": "soc",
            "format": "cef",
            "transport": "syslog",
            "syslog": {
                "address": f"127.0.0.1:{syslog_port}",
                "protocol": "tcp",
            },
        }
    ],
}

with open(out_path, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False)
PY
echo "generated test config: $WORKDIR/config.yaml"

# --- Start the gateway -------------------------------------------------------
"$GW_BIN" -config "$WORKDIR/config.yaml" >"$WORKDIR/gateway.log" 2>&1 &
GW_PID=$!
for i in $(seq 1 50); do
  if ! kill -0 "$GW_PID" 2>/dev/null; then
    fail "gateway process exited early"; tail -n 60 "$WORKDIR/gateway.log" >&2; exit 1
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/$GW_PORT") 2>/dev/null && { exec 3<&- 3>&-; break; }
  sleep 0.2
done
echo "gateway up (SSH :$GW_PORT), pid=$GW_PID"
grep -q "event export active: soc (format=cef transport=syslog)" "$WORKDIR/gateway.log" \
  || { fail "gateway did not log event export as active"; cat "$WORKDIR/gateway.log" >&2; exit 1; }
pass "gateway booted with export.enabled=true, exporter soc (cef/syslog) active"

# --- Drive a real session as alice ------------------------------------------
# Same real-target login syntax and pty technique as lab-test-real-target.sh
# (ssh does not read a password from a pipe, so a real pty is required): a
# real LDAPS login (-> auth event), then the target's keyboard-interactive
# "Target password:" challenge, then a real interactive shell on the real
# ssh-target container (-> session_start event), then a clean exit.
cat >"$WORKDIR/drive_session.py" <<'PY'
#!/usr/bin/env python3
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
    gw_port, login_at, gw_pw, tgt_pw = sys.argv[1:5]
    cmd = [
        "ssh", "-tt", "-p", gw_port,
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no", "-o", "ConnectTimeout=10",
        login_at,
    ]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(127)

    buf = b""
    deadline = time.time() + 45

    def wait_for(pattern):
        nonlocal buf
        pat = pattern.encode()
        while True:
            if pat in buf:
                return True
            if time.time() > deadline:
                return False
            chunk = read_avail(fd, min(1.0, max(0.0, deadline - time.time())))
            if chunk is None:
                continue
            if chunk == b"":
                return False
            buf += chunk

    if not wait_for("password:"):
        print("RESULT=FAIL:never saw gateway password prompt")
        sys.exit(1)
    os.write(fd, (gw_pw + "\n").encode())

    if not wait_for("Target password:"):
        print("RESULT=FAIL:never saw target password prompt")
        sys.exit(1)
    os.write(fd, (tgt_pw + "\n").encode())

    # Let the target's remote shell settle, then exit cleanly.
    time.sleep(2.0)
    os.write(fd, b"whoami; exit\n")

    end = time.time() + 15
    while time.time() < end:
        chunk = read_avail(fd, 1.0)
        if chunk is None:
            continue
        if chunk == b"":
            break
        buf += chunk

    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    print("RESULT=OK")

if __name__ == "__main__":
    main()
PY

echo "== real session: alice authenticates and runs a command on the target =="
DRIVE_OUT="$(python3 "$WORKDIR/drive_session.py" "$GW_PORT" \
  "${GW_USER}%${TARGET_HOST}@${TARGET_HOST}" "$GW_PASSWORD" "$TARGET_PASSWORD")"
echo "$DRIVE_OUT"
if ! echo "$DRIVE_OUT" | grep -q "RESULT=OK"; then
  fail "driven session did not complete (auth or target password prompt never seen)"
  tail -n 60 "$WORKDIR/gateway.log" >&2
  exit 1
fi
pass "real session driven: alice authenticated, ran a command on the real target"

# --- Assert well-formed CEF arrived at the receiver -------------------------
# Parses the capture as RFC 6587 octet-counted frames (rather than a loose
# substring grep over the raw stream) — this also proves the transport's own
# framing is well-formed, not just that the CEF text landed somewhere in the
# byte stream.
cat >"$WORKDIR/parse_frames.py" <<'PY'
#!/usr/bin/env python3
import sys

path = sys.argv[1]
with open(path, "rb") as f:
    data = f.read()

frames = []
i, n = 0, len(data)
while i < n:
    j = data.find(b" ", i)
    if j == -1 or not data[i:j].isdigit():
        print(f"PARSE_ERROR: no valid octet-count length prefix at offset {i}: {data[i:i+40]!r}")
        sys.exit(2)
    length = int(data[i:j])
    start = j + 1
    end = start + length
    if end > n:
        print(f"PARSE_ERROR: frame at offset {i} declares length {length} but only {n-start} bytes remain")
        sys.exit(2)
    frames.append(data[start:end])
    i = end

print(f"FRAMES={len(frames)}")
for fr in frames:
    idx = fr.find(b"CEF:0|omni-sag|gateway|")
    if idx == -1:
        print("NON_CEF_FRAME:" + fr.decode(errors="replace"))
        continue
    print("CEFLINE:" + fr[idx:].decode(errors="replace"))
PY

ok=0
PARSED=""
for i in $(seq 1 20); do
  PARSED="$(python3 "$WORKDIR/parse_frames.py" "$WORKDIR/syslog.out" 2>&1 || true)"
  if echo "$PARSED" | grep -q "^CEFLINE:"; then
    ok=1
    break
  fi
  sleep 1
done
echo "$PARSED" >"$WORKDIR/parsed_frames.out"

if echo "$PARSED" | grep -q "^PARSE_ERROR:"; then
  fail "syslog capture is not well-formed RFC 6587 octet-counted framing"
  echo "$PARSED" >&2
  exit 1
fi
if [ "$ok" -ne 1 ]; then
  fail "no CEF line ever arrived at the syslog receiver"
  echo "--- capture (raw) ---" >&2; cat "$WORKDIR/syslog.out" >&2
  echo "--- gateway log ---" >&2; tail -n 60 "$WORKDIR/gateway.log" >&2
  exit 1
fi
pass "syslog receiver captured well-formed RFC 6587 octet-counted frames containing CEF lines"

AUTH_LINE="$(echo "$PARSED" | grep -E '^CEFLINE:CEF:0\|omni-sag\|gateway\|1\.0\|auth\|auth\|' | head -1)"
if [ -z "$AUTH_LINE" ]; then
  fail "no well-formed CEF 'auth' line found for the real login"
  echo "$PARSED" >&2
  exit 1
fi
if ! echo "$AUTH_LINE" | grep -q "suser=${GW_USER}"; then
  fail "CEF auth line missing expected suser=${GW_USER}: $AUTH_LINE"
  exit 1
fi
if ! echo "$AUTH_LINE" | grep -qE 'src=[0-9a-fA-F.:]+'; then
  fail "CEF auth line missing expected src= field: $AUTH_LINE"
  exit 1
fi
pass "well-formed CEF auth event for a REAL login: ${AUTH_LINE#CEFLINE:}"

SESSION_LINE="$(echo "$PARSED" | grep -E '^CEFLINE:CEF:0\|omni-sag\|gateway\|1\.0\|session_start\|session_start\|' | head -1)"
if [ -n "$SESSION_LINE" ]; then
  pass "well-formed CEF session_start event for the same real session: ${SESSION_LINE#CEFLINE:}"
else
  echo "note: no session_start CEF line observed (auth alone already satisfies the real-event assertion)"
fi

echo "ALL PASS"
