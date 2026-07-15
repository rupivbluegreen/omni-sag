#!/usr/bin/env bash
# End-to-end check of the real-target shell/SFTP proxy against the dev lab's
# ssh-target container. Requires `make lab-up && make lab-seed` to have run
# first, and the gateway + CLI binaries already built (`make binaries`).
#
# What this proves, against the REAL running lab (no mocks for LDAP/MinIO/the
# target's sshd — only a local, ephemeral fake ICAP responder, since no ICAP
# service exists anywhere in this compose lab; see the "fake ICAP" section
# below for why that one substitution is necessary and honest about it):
#   1. alice authenticates to the gateway (LDAPS), answers the target's
#      keyboard-interactive "Target password:" prompt (credential: prompt
#      mode), and runs a real command in a real interactive shell bridged to
#      the real ssh-target container, authenticated as svc_db1.
#   2. alice uploads a file over real SFTP; it is content-inspected,
#      unconditionally quarantined, and held pending a KindQuarantineRelease
#      approval. bob (not in alice's dba group) attempts to approve it and is
#      refused by group-scoped four-eyes; carol (a peer in dba) approves it.
#      The approved upload is never pushed to the target — alice retrieves it
#      herself via a fresh SFTP session's /releases directory, and bob (no
#      route to that target at all) cannot reach it.
#
# Usage: scripts/lab-test-real-target.sh
set -euo pipefail

GW_BIN="${GW_BIN:-./bin/omni-sag_$(go env GOOS)_$(go env GOARCH)}"
CTL_BIN="${CTL_BIN:-./bin/omnisag-ctl_$(go env GOOS)_$(go env GOARCH)}"
BASE_CONFIG="${CONFIG:-deploy/compose/config.example.yaml}"
GW_PORT="${GW_PORT:-2222}"
API_PORT="${API_PORT:-8443}"
ICAP_PORT="${ICAP_PORT:-1344}"

GW_USER="alice"
BOB_USER="bob"                   # not in dba: refused both on approval and on target access
GW_PASSWORD="Passw0rd!"          # lab-seed.sh's LAB_USER_PW default, shared by all seeded users
TARGET_HOST="127.0.0.1"          # must match the demo Rule's `host:` exactly
TARGET_USER="svc_db1"
TARGET_PASSWORD="InjectedSecret123!" # docker-compose.yml's ssh-target USER_PASSWORD
API_TOKEN="lab-test-token-$$"          # lab-tester: listing only, not tied to any AD identity
API_TOKEN_BOB="lab-test-token-bob-$$"      # subject "bob", for the refused approval attempt
API_TOKEN_CAROL="lab-test-token-carol-$$"  # subject "carol", for the peer approval
# A quarantined upload is never written to the real target (Task 6), so this
# is just a logical destination string recorded on the release — it does not
# need to be writable by svc_db1.
REMOTE_UPLOAD_PATH="/config/upload.txt"

RED=$'\033[31m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
pass() { echo "${GREEN}PASS${RESET}: $*"; }
fail() { echo "${RED}FAIL${RESET}: $*" >&2; }

if [ ! -x "$GW_BIN" ]; then
  echo "gateway binary not found at $GW_BIN — run: make binaries" >&2
  exit 1
fi
if [ ! -x "$CTL_BIN" ]; then
  echo "omnisag-ctl binary not found at $CTL_BIN — run: make binaries" >&2
  exit 1
fi
for tool in python3 jq ssh sftp docker; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required tool not found: $tool" >&2; exit 1; }
done

echo "== checking dev-lab containers =="
COMPOSE="docker compose -f deploy/compose/docker-compose.yml"
for c in omni-sag-samba-ad omni-sag-minio omni-sag-ssh-target; do
  if ! docker ps --filter "name=^${c}\$" --filter "status=running" --format '{{.Names}}' | grep -qx "$c"; then
    echo "required container not running: $c — run: make lab-up && make lab-seed" >&2
    exit 1
  fi
done
echo "lab containers OK (samba-ad, minio, ssh-target running)"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/omnisag-lab-test.XXXXXX")"
GW_PID=""
ICAP_PID=""
cleanup() {
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  [ -n "$ICAP_PID" ] && kill "$ICAP_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "== workdir: $WORKDIR (kept after this run for inspection) =="

# --- Fake ICAP responder --------------------------------------------------
# No ICAP (content-inspection) service exists anywhere in this compose lab
# (confirmed: no cyberark/icap entry in docker-compose.yml; internal/inspect's
# only ICAP server is a _test.go-only mock used solely by that package's own
# unit tests). Exercising the real inspection -> quarantine -> approval path
# genuinely end-to-end therefore requires SOME ICAP responder to exist for
# the gateway to talk to. This is a minimal, protocol-correct ICAP server
# (RFC 3507 REQMOD, preview + chunked bodies) that always returns a clean
# (204) verdict — i.e. it plays the role of "the AV/DLP scanner said clean"
# so the rest of the REAL machinery (quarantine write, four-eyes approval,
# release-and-deliver) runs unmocked against the real gateway and real MinIO.
cat >"$WORKDIR/fake_icap.py" <<'PY'
#!/usr/bin/env python3
"""Minimal ICAP (RFC 3507) responder: always verdicts 204 (clean)."""
import socket
import sys


def read_headers(rfile):
    lines = []
    while True:
        line = rfile.readline()
        if not line or line in (b"\r\n", b"\n"):
            break
        lines.append(line)
    return lines


def parse_encapsulated(headers):
    for line in headers:
        if line.lower().startswith(b"encapsulated:"):
            val = line.split(b":", 1)[1].decode().strip()
            offsets = {}
            for part in val.split(","):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    try:
                        offsets[k.strip()] = int(v.strip())
                    except ValueError:
                        pass
            return offsets
    return {}


def read_chunked(rfile):
    data = b""
    while True:
        sizeline = rfile.readline()
        if not sizeline:
            break
        field = sizeline.strip()
        if b";" in field:
            field = field.split(b";", 1)[0].strip()
        try:
            n = int(field, 16)
        except ValueError:
            break
        if n == 0:
            rfile.readline()  # trailing CRLF after the terminating chunk
            break
        chunk = rfile.read(n)
        rfile.read(2)  # CRLF after chunk data
        data += chunk
    return data


def handle(conn):
    rfile = conn.makefile("rb")
    reqline = rfile.readline()
    if not reqline:
        return
    headers = read_headers(rfile)
    offsets = parse_encapsulated(headers)
    hdr_len = None
    for key in ("req-body", "res-body", "opt-body"):
        if key in offsets:
            hdr_len = offsets[key]
            break
    if hdr_len:
        rfile.read(hdr_len)  # discard the embedded HTTP header bytes
    has_body = any(k in offsets for k in ("req-body", "res-body", "opt-body"))
    if has_body:
        read_chunked(rfile)
    resp = b'ICAP/1.0 204 No Modification\r\nISTag: "omnisag-fake-icap"\r\n\r\n'
    conn.sendall(resp)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1344
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print(f"fake-icap listening on 127.0.0.1:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            handle(conn)
        except Exception as e:  # noqa: BLE001 - best-effort test double
            print(f"fake-icap: connection error: {e}", file=sys.stderr, flush=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
PY

python3 "$WORKDIR/fake_icap.py" "$ICAP_PORT" >"$WORKDIR/icap.log" 2>&1 &
ICAP_PID=$!
for i in $(seq 1 25); do
  (exec 3<>"/dev/tcp/127.0.0.1/$ICAP_PORT") 2>/dev/null && { exec 3<&- 3>&-; break; }
  sleep 0.2
  [ "$i" = 25 ] && { fail "fake ICAP responder never came up"; cat "$WORKDIR/icap.log" >&2; exit 1; }
done
echo "fake ICAP responder up on 127.0.0.1:$ICAP_PORT"

# --- Derived gateway config ------------------------------------------------
# Layers onto the checked-in demo config (unchanged) exactly what this
# integration check needs and the shipped example intentionally leaves
# commented out as optional / lab-specific: the control-plane API (so
# omnisag-ctl has something to talk to), the four-eyes approval store, and
# content inspection wired at the fake ICAP responder above. State files
# (host key, evidence, recordings, approvals) are redirected into WORKDIR so
# this script never touches the repo tree.
python3 - "$BASE_CONFIG" "$WORKDIR/config.yaml" "$WORKDIR" "$ICAP_PORT" "$API_PORT" "$API_TOKEN" "$API_TOKEN_BOB" "$API_TOKEN_CAROL" <<'PY'
import sys
import yaml

base_path, out_path, workdir, icap_port, api_port, api_token, api_token_bob, api_token_carol = sys.argv[1:9]

with open(base_path) as f:
    cfg = yaml.safe_load(f)

cfg["host_key"] = f"{workdir}/hostkey.pem"
cfg["evidence"] = {"file": f"{workdir}/evidence.jsonl"}
cfg.setdefault("recording", {}) or cfg.__setitem__("recording", {})
cfg["recording"]["local_dir"] = f"{workdir}/recordings"

cfg["api"] = {
    "listen": f":{api_port}",
    # bob/carol's subjects must equal their AD usernames exactly: Approve's
    # group-scoped four-eyes resolves the approver's CURRENT groups via LDAP
    # by this subject (approval.FileStore.decide -> GroupLookup.Groups).
    "tokens": [
        {"token": api_token, "subject": "lab-tester", "role": "operator"},
        {"token": api_token_bob, "subject": "bob", "role": "operator"},
        {"token": api_token_carol, "subject": "carol", "role": "operator"},
    ],
}
cfg["approval"] = {
    "store_path": f"{workdir}/approvals.json",
    "ttl_seconds": 300,
}
cfg["inspection"] = {
    "enabled": True,
    "icap": {
        "endpoint": f"127.0.0.1:{icap_port}",
        "service": "avscan",
        "preview_bytes": 4096,
        "timeout_seconds": 10,
    },
    "threshold_bytes": 1048576,
    "holding": {
        "endpoint": "127.0.0.1:9000",
        "access_key": "omnisag",
        "secret_key": "omnisag-dev-secret",
        "bucket": "omni-sag-holding",
        "use_ssl": False,
    },
    "quarantine": {
        "endpoint": "127.0.0.1:9000",
        "access_key": "omnisag",
        "secret_key": "omnisag-dev-secret",
        "bucket": "omni-sag-quarantine",
        "use_ssl": False,
        "mode": "COMPLIANCE",
        "retention_days": 1,
    },
}

with open(out_path, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False)
PY
echo "generated test config: $WORKDIR/config.yaml"

# --- Start the gateway ------------------------------------------------------
"$GW_BIN" -config "$WORKDIR/config.yaml" >"$WORKDIR/gateway.log" 2>&1 &
GW_PID=$!

wait_for_port() {
  local port="$1" name="$2"
  for i in $(seq 1 50); do
    if ! kill -0 "$GW_PID" 2>/dev/null; then
      fail "gateway process exited early"; tail -n 60 "$WORKDIR/gateway.log" >&2; exit 1
    fi
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
    sleep 0.2
  done
  fail "$name never came up on 127.0.0.1:$port"; tail -n 60 "$WORKDIR/gateway.log" >&2; exit 1
}
wait_for_port "$GW_PORT" "gateway SSH"
wait_for_port "$API_PORT" "gateway API"
echo "gateway up (SSH :$GW_PORT, API :$API_PORT), pid=$GW_PID"

# --- pty drivers -------------------------------------------------------------
# Both `ssh`/`sftp` clients here go through the gateway's demo rule, which is
# credential:prompt: the client answers TWO password rounds — its own LDAPS
# login (password auth), then the target's password via the keyboard-
# interactive "Target password:" challenge (Task 5's PartialSuccessError
# chaining). Neither `ssh` nor `sftp` will read a password from a pipe (they
# read /dev/tty), so both need a real pty — the same technique used to
# directly test ssh-target's own sshd earlier in this plan (see the Task 12
# report's pty.fork()-based Python harness).
cat >"$WORKDIR/ssh_shell.py" <<'PY'
#!/usr/bin/env python3
import os
import pty
import select
import signal
import sys
import time


def read_avail(fd, timeout):
    r, _, _ = select.select([fd], [], [], timeout)
    if fd in r:
        try:
            return os.read(fd, 65536)
        except OSError:
            return b""
    return None


def finish(fd, pid, code):
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    sys.exit(code)


def main():
    gw_port, login_at, gw_pw, tgt_pw, begin_m, end_m = sys.argv[1:7]
    cmd = [
        "ssh", "-tt", "-p", gw_port,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        "-o", "ConnectTimeout=10",
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
            sys.stderr.buffer.write(chunk)
            sys.stderr.flush()

    if not wait_for("password:"):
        print("DRIVER_ERROR=never saw gateway password prompt")
        finish(fd, pid, 1)
    os.write(fd, (gw_pw + "\n").encode())

    if not wait_for("Target password:"):
        print("DRIVER_ERROR=never saw target password prompt")
        finish(fd, pid, 1)
    os.write(fd, (tgt_pw + "\n").encode())

    # Let the target's remote shell settle before typing into it.
    time.sleep(2.0)
    os.write(fd, f"echo {begin_m}; whoami; echo {end_m}\n".encode())

    if not wait_for(end_m):
        print("DRIVER_ERROR=never saw end marker (command did not complete)")
        finish(fd, pid, 1)

    # A small settle so the final marker's own output line is fully flushed.
    time.sleep(0.3)
    while True:
        chunk = read_avail(fd, 0.3)
        if not chunk:
            break
        buf += chunk

    text = buf.decode(errors="replace")
    last_begin = text.rfind(begin_m)
    last_end = text.rfind(end_m)
    middle = text[last_begin + len(begin_m):last_end] if last_begin != -1 and last_end != -1 else ""
    lines = [l.strip() for l in middle.splitlines() if l.strip()]
    result = lines[-1] if lines else ""
    print("WHOAMI_RESULT=" + result)

    os.write(fd, b"exit\n")
    end_time = time.time() + 8
    while time.time() < end_time:
        chunk = read_avail(fd, 1.0)
        if chunk is None:
            continue
        if chunk == b"":
            break

    finish(fd, pid, 0)


if __name__ == "__main__":
    main()
PY

cat >"$WORKDIR/sftp_put.py" <<'PY'
#!/usr/bin/env python3
import os
import pty
import select
import signal
import sys
import time


def read_avail(fd, timeout):
    r, _, _ = select.select([fd], [], [], timeout)
    if fd in r:
        try:
            return os.read(fd, 65536)
        except OSError:
            return b""
    return None


def finish(fd, pid, code, result):
    print("PUT_RESULT=" + result)
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    sys.exit(code)


def main():
    gw_port, login_at, gw_pw, tgt_pw, local_path, remote_path, approval_wait_s = sys.argv[1:8]
    cmd = [
        "sftp", "-P", gw_port,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        "-o", "ConnectTimeout=10",
        login_at,
    ]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(127)

    buf = b""
    auth_deadline = time.time() + 45

    def wait_for(pattern, deadline):
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
            sys.stderr.buffer.write(chunk)
            sys.stderr.flush()

    if not wait_for("password:", auth_deadline):
        finish(fd, pid, 1, "FAIL:never saw gateway password prompt")
    os.write(fd, (gw_pw + "\n").encode())

    if not wait_for("Target password:", auth_deadline):
        finish(fd, pid, 1, "FAIL:never saw target password prompt")
    os.write(fd, (tgt_pw + "\n").encode())

    if not wait_for("sftp>", auth_deadline):
        finish(fd, pid, 1, "FAIL:never saw sftp prompt after auth")

    put_mark_pos = len(buf)
    os.write(fd, f"put {local_path} {remote_path}\n".encode())

    # The upload's Close() blocks server-side until this script's caller
    # approves the quarantine-release request, up to approval_wait_s.
    put_deadline = time.time() + float(approval_wait_s)
    if not wait_for("sftp>", put_deadline) or buf.rfind(b"sftp>") <= put_mark_pos:
        # Wait once more explicitly for a SECOND prompt occurrence after the
        # put command was sent (the first "sftp>" in buf is the pre-put one).
        while buf.count(b"sftp>", put_mark_pos) < 1 and time.time() < put_deadline:
            chunk = read_avail(fd, 1.0)
            if chunk is None:
                continue
            if chunk == b"":
                break
            buf += chunk
            sys.stderr.buffer.write(chunk)
            sys.stderr.flush()

    os.write(fd, b"quit\n")
    drain_deadline = time.time() + 8
    while time.time() < drain_deadline:
        chunk = read_avail(fd, 1.0)
        if chunk is None:
            continue
        if chunk == b"":
            break
        buf += chunk

    text = buf[put_mark_pos:].decode(errors="replace")
    lowered = text.lower()
    if "couldn't" in lowered or "not uploaded" in lowered or "failure" in lowered or "permission denied" in lowered:
        finish(fd, pid, 1, "FAIL:sftp reported an error - see transcript")
    if "uploading" not in lowered:
        finish(fd, pid, 1, "FAIL:no upload appears to have started")
    finish(fd, pid, 0, "OK")


if __name__ == "__main__":
    main()
PY

# --- Test 1: real interactive shell -----------------------------------------
echo "== real shell: alice runs a real command on the target =="
MARKER="OMNISAG_$$_$(date +%s)"
SHELL_OUT="$(python3 "$WORKDIR/ssh_shell.py" "$GW_PORT" "${GW_USER}%${TARGET_HOST}@${TARGET_HOST}" \
  "$GW_PASSWORD" "$TARGET_PASSWORD" "BEGIN_${MARKER}" "END_${MARKER}" 2>"$WORKDIR/ssh_shell.log")"
WHOAMI_RESULT="$(printf '%s\n' "$SHELL_OUT" | sed -n 's/^WHOAMI_RESULT=//p')"
if [ "$WHOAMI_RESULT" != "$TARGET_USER" ]; then
  fail "expected the real target's whoami ($TARGET_USER), got: '$WHOAMI_RESULT'"
  echo "--- driver transcript ---" >&2; tail -n 80 "$WORKDIR/ssh_shell.log" >&2
  echo "--- gateway log ---" >&2; tail -n 40 "$WORKDIR/gateway.log" >&2
  exit 1
fi
pass "real shell command executed on the target as $TARGET_USER"

# --- Test 2: real SFTP through inspection -> quarantine -> approval --------
echo "== real SFTP: alice puts a file, it is inspected+quarantined pending release =="
echo "hello from the lab" >"$WORKDIR/lab-upload.txt"

python3 "$WORKDIR/sftp_put.py" "$GW_PORT" "${GW_USER}%${TARGET_HOST}@${TARGET_HOST}" \
  "$GW_PASSWORD" "$TARGET_PASSWORD" "$WORKDIR/lab-upload.txt" "$REMOTE_UPLOAD_PATH" 240 \
  >"$WORKDIR/sftp_put.out" 2>"$WORKDIR/sftp_put.log" &
SFTP_PID=$!

echo "== waiting for the quarantine-release approval request to appear =="
REQ_ID=""
for i in $(seq 1 60); do
  REQ_ID="$("$CTL_BIN" -api "http://127.0.0.1:$API_PORT" -token "$API_TOKEN" approvals 2>/dev/null \
    | jq -r '.[]? | select(.kind=="quarantine_release" and .status=="pending") | .id' | head -1)"
  [ -n "$REQ_ID" ] && break
  sleep 1
done
if [ -z "$REQ_ID" ]; then
  fail "no pending quarantine_release request appeared"
  kill "$SFTP_PID" 2>/dev/null || true
  echo "--- sftp driver transcript ---" >&2; tail -n 80 "$WORKDIR/sftp_put.log" >&2
  echo "--- gateway log ---" >&2; tail -n 40 "$WORKDIR/gateway.log" >&2
  exit 1
fi
echo "found pending request: $REQ_ID"

echo "== attempt release-approval as bob (not in dba) — must be refused =="
if BOB_APPROVE_OUT="$("$CTL_BIN" -api "http://127.0.0.1:$API_PORT" -token "$API_TOKEN_BOB" approve "$REQ_ID" 2>&1)"; then
  fail "bob's approval unexpectedly succeeded: $BOB_APPROVE_OUT"
  kill "$SFTP_PID" 2>/dev/null || true
  exit 1
fi
if ! printf '%s' "$BOB_APPROVE_OUT" | grep -q "group-scoped four-eyes"; then
  fail "bob's approval was refused, but not for the expected reason: $BOB_APPROVE_OUT"
  kill "$SFTP_PID" 2>/dev/null || true
  exit 1
fi
STILL_PENDING="$("$CTL_BIN" -api "http://127.0.0.1:$API_PORT" -token "$API_TOKEN" approvals \
  | jq -r --arg id "$REQ_ID" '.[] | select(.id==$id) | .status')"
if [ "$STILL_PENDING" != "pending" ]; then
  fail "request status after bob's refused attempt: expected pending, got '$STILL_PENDING'"
  kill "$SFTP_PID" 2>/dev/null || true
  exit 1
fi
pass "bob (not in dba) refused: group-scoped four-eyes rejected the approval; request still pending"

echo "== approve as carol (in dba, same group as alice, different identity) — must succeed =="
APPROVE_OUT="$("$CTL_BIN" -api "http://127.0.0.1:$API_PORT" -token "$API_TOKEN_CAROL" approve "$REQ_ID")"
if ! printf '%s' "$APPROVE_OUT" | jq -e '.status == "approved"' >/dev/null 2>&1; then
  fail "carol's approval did not return status=approved: $APPROVE_OUT"
  kill "$SFTP_PID" 2>/dev/null || true
  exit 1
fi
pass "quarantine-release request approved by carol, a peer in the uploader's group"

if ! wait "$SFTP_PID"; then
  fail "sftp put did not complete successfully"
  echo "--- sftp driver transcript ---" >&2; tail -n 80 "$WORKDIR/sftp_put.log" >&2
  echo "--- sftp driver stdout ---" >&2; cat "$WORKDIR/sftp_put.out" >&2
  exit 1
fi
PUT_RESULT="$(sed -n 's/^PUT_RESULT=//p' "$WORKDIR/sftp_put.out")"
if [ "$PUT_RESULT" != "OK" ]; then
  fail "sftp put reported: $PUT_RESULT"
  echo "--- sftp driver transcript ---" >&2; tail -n 80 "$WORKDIR/sftp_put.log" >&2
  exit 1
fi
pass "upload released from quarantine and recorded for pull-download"

# --- Test 3: alice retrieves her own release via /releases -----------------
echo "== alice retrieves her own release via /releases in a NEW sftp session =="
cat >"$WORKDIR/sftp_get_release.py" <<'PY'
#!/usr/bin/env python3
import os
import pty
import re
import select
import signal
import sys
import time


def read_avail(fd, timeout):
    r, _, _ = select.select([fd], [], [], timeout)
    if fd in r:
        try:
            return os.read(fd, 65536)
        except OSError:
            return b""
    return None


def finish(fd, pid, code, lines):
    for l in lines:
        print(l)
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    sys.exit(code)


def main():
    gw_port, login_at, gw_pw, tgt_pw, local_get_path = sys.argv[1:6]
    cmd = [
        "sftp", "-P", gw_port,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        "-o", "ConnectTimeout=10",
        login_at,
    ]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(127)

    buf = b""
    auth_deadline = time.time() + 45

    def wait_for(pattern, dl):
        nonlocal buf
        pat = pattern.encode()
        while True:
            if pat in buf:
                return True
            if time.time() > dl:
                return False
            chunk = read_avail(fd, min(1.0, max(0.0, dl - time.time())))
            if chunk is None:
                continue
            if chunk == b"":
                return False
            buf += chunk
            sys.stderr.buffer.write(chunk)
            sys.stderr.flush()

    if not wait_for("password:", auth_deadline):
        finish(fd, pid, 1, ["GET_RESULT=FAIL:never saw gateway password prompt"])
    os.write(fd, (gw_pw + "\n").encode())

    if not wait_for("Target password:", auth_deadline):
        finish(fd, pid, 1, ["GET_RESULT=FAIL:never saw target password prompt"])
    os.write(fd, (tgt_pw + "\n").encode())

    if not wait_for("sftp>", auth_deadline):
        finish(fd, pid, 1, ["GET_RESULT=FAIL:never saw sftp prompt after auth"])

    # Same "wait for a NEW prompt after this mark" idiom as sftp_put.py: the
    # first wait_for above can return instantly on the ALREADY-present prompt,
    # so every subsequent command result is bounded by counting occurrences
    # after the position where the command was sent, not just pattern-in-buf.
    mark = len(buf)
    os.write(fd, b"ls -1 /releases\n")
    ls_deadline = time.time() + 20
    if not wait_for("sftp>", ls_deadline) or buf.rfind(b"sftp>") <= mark:
        while buf.count(b"sftp>", mark) < 1 and time.time() < ls_deadline:
            chunk = read_avail(fd, 1.0)
            if chunk is None:
                continue
            if chunk == b"":
                break
            buf += chunk
            sys.stderr.buffer.write(chunk)
            sys.stderr.flush()
    listing = buf[mark:].decode(errors="replace")
    m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", listing)
    if not m:
        finish(fd, pid, 1, ["GET_RESULT=FAIL:no release id in listing: " + listing.strip().replace("\n", "|")])
    release_id = m.group(0)

    mark = len(buf)
    os.write(fd, f"get /releases/{release_id} {local_get_path}\n".encode())
    get_deadline = time.time() + 30
    if not wait_for("sftp>", get_deadline) or buf.rfind(b"sftp>") <= mark:
        while buf.count(b"sftp>", mark) < 1 and time.time() < get_deadline:
            chunk = read_avail(fd, 1.0)
            if chunk is None:
                continue
            if chunk == b"":
                break
            buf += chunk
            sys.stderr.buffer.write(chunk)
            sys.stderr.flush()
    get_text = buf[mark:].decode(errors="replace").lower()

    os.write(fd, b"quit\n")
    drain_deadline = time.time() + 8
    while time.time() < drain_deadline:
        chunk = read_avail(fd, 1.0)
        if chunk is None:
            continue
        if chunk == b"":
            break

    if "couldn't" in get_text or "no such file" in get_text or "permission denied" in get_text:
        finish(fd, pid, 1, ["RELEASE_ID=" + release_id, "GET_RESULT=FAIL:get reported an error"])
    finish(fd, pid, 0, ["RELEASE_ID=" + release_id, "GET_RESULT=OK"])


if __name__ == "__main__":
    main()
PY

GET_OUT="$(python3 "$WORKDIR/sftp_get_release.py" "$GW_PORT" "${GW_USER}%${TARGET_HOST}@${TARGET_HOST}" \
  "$GW_PASSWORD" "$TARGET_PASSWORD" "$WORKDIR/alice-release.txt" 2>"$WORKDIR/sftp_get_release.log")"
RELEASE_ID="$(printf '%s\n' "$GET_OUT" | sed -n 's/^RELEASE_ID=//p')"
GET_RESULT="$(printf '%s\n' "$GET_OUT" | sed -n 's/^GET_RESULT=//p')"
if [ -z "$RELEASE_ID" ] || [ "$GET_RESULT" != "OK" ]; then
  fail "alice could not retrieve her release: id='$RELEASE_ID' result='$GET_RESULT'"
  echo "--- driver transcript ---" >&2; tail -n 80 "$WORKDIR/sftp_get_release.log" >&2
  exit 1
fi
if ! diff -q "$WORKDIR/lab-upload.txt" "$WORKDIR/alice-release.txt" >/dev/null 2>&1; then
  fail "retrieved release content does not match the original upload"
  exit 1
fi
pass "alice retrieved release $RELEASE_ID via /releases in a fresh session; content matches the upload"

# --- Test 4: bob cannot reach alice's release -------------------------------
echo "== bob cannot see or read alice's release =="
cat >"$WORKDIR/sftp_refused.py" <<'PY'
#!/usr/bin/env python3
import os
import pty
import select
import signal
import sys
import time


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
        "sftp", "-P", gw_port,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        "-o", "ConnectTimeout=10",
        login_at,
    ]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(127)

    buf = b""

    def wait_for(pattern, dl):
        nonlocal buf
        pat = pattern.encode()
        while True:
            if pat in buf:
                return True
            if time.time() > dl:
                return False
            chunk = read_avail(fd, min(1.0, max(0.0, dl - time.time())))
            if chunk is None:
                continue
            if chunk == b"":
                return False
            buf += chunk
            sys.stderr.buffer.write(chunk)
            sys.stderr.flush()

    if not wait_for("password:", time.time() + 30):
        print("RESULT=FAIL:never saw gateway password prompt")
        sys.exit(1)
    os.write(fd, (gw_pw + "\n").encode())

    # bob holds no role granting host 127.0.0.1, so the gateway's own auth
    # decision never issues a "Target password:" challenge for him (see
    # session.go: the credential-mode peek only prompts when a rule
    # matched). Answer it anyway if it somehow appears, so this assertion is
    # about the sftp subsystem being refused, not about which prompt bob sees.
    if wait_for("Target password:", time.time() + 8):
        os.write(fd, (tgt_pw + "\n").encode())

    got_sftp_prompt = wait_for("sftp>", time.time() + 15)

    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass

    print("RESULT=" + ("UNEXPECTED_SFTP_PROMPT" if got_sftp_prompt else "REFUSED"))


if __name__ == "__main__":
    main()
PY

BOB_SFTP_OUT="$(python3 "$WORKDIR/sftp_refused.py" "$GW_PORT" "${BOB_USER}%${TARGET_HOST}@${TARGET_HOST}" \
  "$GW_PASSWORD" "$TARGET_PASSWORD" 2>"$WORKDIR/sftp_refused.log")"
BOB_SFTP_RESULT="$(printf '%s\n' "$BOB_SFTP_OUT" | sed -n 's/^RESULT=//p')"
if [ "$BOB_SFTP_RESULT" != "REFUSED" ]; then
  fail "bob's sftp session to the release-bearing target was not refused: $BOB_SFTP_RESULT"
  echo "--- driver transcript ---" >&2; tail -n 80 "$WORKDIR/sftp_refused.log" >&2
  exit 1
fi
pass "bob (not in dba) has no route to the target: his sftp session is refused before /releases is reachable"

echo "ALL PASS"
