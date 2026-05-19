#!/usr/bin/env bash
# Run the SFTP throughput counterpart of `scripts/bench.sh`, against a
# private sshd spawned on loopback. Mirrors qftp-bench: same size sweep,
# same per-iteration "fresh client invocation" model, so the numbers
# line up with `cargo bench -p qftp-bench`.
#
# Usage:
#   scripts/bench-sftp.sh                          # 1M,16M,64M, 10 iters
#   QFTP_BENCH_SIZES=64K,1M,16M scripts/bench-sftp.sh
#   QFTP_BENCH_ITERS=5 scripts/bench-sftp.sh
#
# Requires: openssh-server, openssh-client, sudo (for sshd privsep).

set -euo pipefail

SIZES="${QFTP_BENCH_SIZES:-1M,16M,64M,256M,1G}"
ITERS="${QFTP_BENCH_ITERS:-10}"

if ! command -v sshd >/dev/null || ! command -v sftp >/dev/null; then
    echo "error: sshd and sftp must be installed" >&2
    exit 1
fi

TMP=$(mktemp -d)
cleanup() {
    if [[ -f "$TMP/sshd.pid" ]]; then
        sudo -n kill "$(cat "$TMP/sshd.pid")" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

# sshd needs /run/sshd for privilege separation; create on first run.
if [[ ! -d /run/sshd ]]; then
    sudo -n mkdir -p /run/sshd
    sudo -n chmod 755 /run/sshd
fi

ssh-keygen -q -t ed25519 -N "" -f "$TMP/host_key"
ssh-keygen -q -t ed25519 -N "" -f "$TMP/id"
chmod 600 "$TMP/id" "$TMP/host_key"

USER_NAME=$(id -un)
PORT=$(( 20000 + RANDOM % 10000 ))

cat > "$TMP/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $TMP/host_key
PidFile $TMP/sshd.pid
AuthorizedKeysFile $TMP/authorized_keys
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
AllowUsers $USER_NAME
Subsystem sftp internal-sftp
StrictModes no
LogLevel ERROR
PrintMotd no
EOF

cp "$TMP/id.pub" "$TMP/authorized_keys"
chmod 600 "$TMP/authorized_keys"
chmod 700 "$TMP"

# sshd needs root for privsep; ports >1024 don't need root themselves.
sudo -n /usr/sbin/sshd -f "$TMP/sshd_config" -E "$TMP/sshd.log"

# Wait for the daemon to start listening.
for _ in $(seq 1 50); do
    if ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then break; fi
    sleep 0.05
done

PAYLOADS="$TMP/payloads"
DEST="$TMP/dest"
mkdir -p "$PAYLOADS" "$DEST"

bytes_for() {
    local s=$1
    case $s in
        *K|*k) echo $(( ${s%[Kk]} * 1024 )) ;;
        *M|*m) echo $(( ${s%[Mm]} * 1024 * 1024 )) ;;
        *G|*g) echo $(( ${s%[Gg]} * 1024 * 1024 * 1024 )) ;;
        *) echo "$s" ;;
    esac
}

sftp_opts=(
    -i "$TMP/id"
    -P "$PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o IdentitiesOnly=yes
    -b /dev/stdin
)

run_dir() {
    local dir=$1 size=$2 bytes
    bytes=$(bytes_for "$size")

    local src dst
    if [[ $dir == put ]]; then
        src="$PAYLOADS/up-$size.bin"
        head -c "$bytes" /dev/urandom > "$src"
    else
        src="$PAYLOADS/down-$size.bin"
        head -c "$bytes" /dev/urandom > "$src"
    fi

    local total_ns=0
    for i in $(seq 1 "$ITERS"); do
        if [[ $dir == put ]]; then
            dst="$DEST/u-$size-$i.bin"
            script="put $src $dst"
        else
            dst="$DEST/d-$size-$i.bin"
            script="get $src $dst"
        fi
        local t0 t1
        t0=$(date +%s%N)
        printf '%s\n' "$script" | sftp "${sftp_opts[@]}" "$USER_NAME@127.0.0.1" >/dev/null
        t1=$(date +%s%N)
        total_ns=$(( total_ns + t1 - t0 ))
        rm -f "$dst"
    done

    local mean_ns=$(( total_ns / ITERS ))
    awk -v b="$bytes" -v ns="$mean_ns" -v label="$dir/$size" 'BEGIN {
        mibs = (b / (ns / 1e9)) / (1024*1024)
        printf "%-18s %8.2f MiB/s   (mean %.2f ms)\n", label, mibs, ns/1e6
    }'
}

echo "sftp-bench: sizes = $SIZES, iters = $ITERS, sshd port = $PORT"
echo

IFS=, read -ra SZARR <<< "$SIZES"
for s in "${SZARR[@]}"; do
    run_dir put "$s"
done
for s in "${SZARR[@]}"; do
    run_dir get "$s"
done
