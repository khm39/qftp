#!/usr/bin/env bash
# Run the qftp end-to-end throughput bench. Builds qftp-server and
# qftp-client in release mode, spins one server up on loopback, and
# drives put/get through criterion.
#
# Usage:
#   scripts/bench.sh                      # default size sweep
#   QFTP_BENCH_SIZES=1M,16M,64M scripts/bench.sh
#   scripts/bench.sh -- --save-baseline before
#
# Anything after `--` is forwarded to `cargo bench`.
set -euo pipefail

# Forward extra args to cargo (everything after `--`).
extra=()
seen_sep=0
for a in "$@"; do
  if [[ "$seen_sep" -eq 1 ]]; then
    extra+=("$a")
  elif [[ "$a" == "--" ]]; then
    seen_sep=1
  fi
done

# Pre-build the binaries so the bench's startup doesn't have to.
cargo build --release --bin qftp-server --bin qftp-client

cargo bench -p qftp-bench --bench throughput "${extra[@]}"
