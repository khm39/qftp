#!/usr/bin/env bash
#
# OS user-isolation end-to-end test (ADR 0002 / issue #62).
#
# Verifies that with `--user-isolation` the per-connection worker
# setuid's to the mapped OS account -- so uploaded files are owned by
# that user -- and that killing one worker leaves the dispatcher and
# any sibling worker untouched (crash isolation).
#
# Needs root (to setuid) and a `daemon` account, both present on a
# standard Linux box. When not run as root the script exits 0 with a
# notice, so `bash scripts/isolation-test.sh` on a dev machine is a
# harmless no-op. Set QFTP_ISO_SKIP_BUILD=1 to reuse already-built
# debug binaries (the CI job builds them as the unprivileged user).
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$(id -u)" -ne 0 ]; then
    echo "isolation-test: not running as root; skipping (setuid needs root)."
    exit 0
fi

PORT="${QFTP_ISO_PORT:-4480}"
SERVER="target/debug/qftp-server"
CLIENT="target/debug/qftp-client"
WORK="$(mktemp -d)"
SRV_PID=""

cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
    pkill -f 'qftp-server --user-isolation' 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    [ -f "$WORK/server.log" ] && { echo "--- server log ---"; cat "$WORK/server.log"; }
    exit 1
}

if [ -z "${QFTP_ISO_SKIP_BUILD:-}" ]; then
    echo "== building qftp-server / qftp-client =="
    cargo build -p qftp-server -p qftp-client >/dev/null 2>&1
fi

# A worker that has setuid'd to `daemon` must be able to traverse down
# to the anonymous user's home and create files in it. `mktemp -d`
# makes the work dir 0700, so widen the traversal path and the home.
mkdir -p "$WORK/root/anon"
chmod 0711 "$WORK"
chmod 0755 "$WORK/root"
chmod 0777 "$WORK/root/anon"
cat > "$WORK/users.toml" <<'EOF'
[anonymous]
name = "anon"
uid = 1
gid = 1
permissions = { read = true, write = true }
EOF

echo "== --check-isolation preflight =="
"$SERVER" --check-isolation --users "$WORK/users.toml" \
    || fail "preflight reported a problem"

echo "== starting dispatcher on 127.0.0.1:$PORT =="
RUST_LOG=warn "$SERVER" --user-isolation --self-signed \
    --users "$WORK/users.toml" --root "$WORK/root" \
    --bind "127.0.0.1:$PORT" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
sleep 2
kill -0 "$SRV_PID" 2>/dev/null || fail "server died on startup"

echo "== test 1: upload lands owned by the mapped uid =="
head -c 4096 /dev/urandom > "$WORK/payload"
"$CLIENT" --insecure -e "put $WORK/payload up.bin" "qftp://127.0.0.1:$PORT" >/dev/null 2>&1 \
    || fail "put failed"
[ -f "$WORK/root/anon/up.bin" ] || fail "uploaded file missing"
owner="$(stat -c '%u:%g' "$WORK/root/anon/up.bin")"
[ "$owner" = "1:1" ] || fail "uploaded file owned by $owner, expected 1:1 (daemon)"
cmp -s "$WORK/payload" "$WORK/root/anon/up.bin" || fail "uploaded bytes differ"
echo "   ok: up.bin owned by uid:gid 1:1, bytes match"

echo "== test 2: download round-trips through a worker =="
"$CLIENT" --insecure -e "get up.bin $WORK/down.bin" "qftp://127.0.0.1:$PORT" >/dev/null 2>&1 \
    || fail "get failed"
cmp -s "$WORK/payload" "$WORK/down.bin" || fail "downloaded bytes differ"
echo "   ok: get round-trip verified"

echo "== test 3: crash isolation -- killing one worker spares the rest =="
# Two throttled uploads keep two workers alive long enough to kill one
# of them mid-transfer.
head -c 16777216 /dev/urandom > "$WORK/big"
"$CLIENT" --insecure --bwlimit 2M -e "put $WORK/big slowA.bin" \
    "qftp://127.0.0.1:$PORT" >/dev/null 2>&1 &
CA=$!
"$CLIENT" --insecure --bwlimit 2M -e "put $WORK/big slowB.bin" \
    "qftp://127.0.0.1:$PORT" >/dev/null 2>&1 &
CB=$!
sleep 3
workers="$(pgrep -P "$SRV_PID" || true)"
[ -n "$workers" ] || fail "no worker processes found under the dispatcher"
victim="$(echo "$workers" | head -n1)"
echo "   workers under dispatcher: $(echo "$workers" | tr '\n' ' ')-- killing $victim"
kill -9 "$victim" 2>/dev/null || fail "could not signal worker $victim"

# The dispatcher must still be alive.
kill -0 "$SRV_PID" 2>/dev/null || fail "dispatcher died when a worker was killed"

# Give the surviving upload time to finish, then stop whatever is left.
sleep 10
kill "$CA" "$CB" 2>/dev/null || true
wait "$CA" 2>/dev/null || true
wait "$CB" 2>/dev/null || true

survived=0
for f in slowA.bin slowB.bin; do
    if [ -f "$WORK/root/anon/$f" ]; then
        cmp -s "$WORK/big" "$WORK/root/anon/$f" || fail "$f completed but is corrupt"
        survived=$((survived + 1))
    fi
done
[ "$survived" -ge 1 ] || fail "no sibling upload survived -- a worker kill cascaded"
echo "   ok: dispatcher alive, $survived sibling upload(s) completed intact"

echo "== test 4: new connections are still served after the kill =="
"$CLIENT" --insecure -e "put $WORK/payload after.bin" "qftp://127.0.0.1:$PORT" >/dev/null 2>&1 \
    || fail "dispatcher stopped serving after a worker was killed"
[ "$(stat -c '%u' "$WORK/root/anon/after.bin")" = "1" ] || fail "post-kill upload not isolated"
echo "   ok: fresh connection served, still isolated to uid 1"

echo
echo "isolation-test: PASS"
