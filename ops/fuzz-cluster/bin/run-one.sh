#!/usr/bin/env bash
# ops/fuzz-cluster/bin/run-one.sh
#
# systemd ExecStart wrapper for plx-fuzz@<target>.service. Runs as user
# 'plxfuzz' with WorkingDirectory=/var/lib/plxfuzz/src.
#
# Runs exactly ONE in-process libFuzzer for <target> (NO -jobs/-workers/-fork:
# those use libFuzzer's experimental fork mode, which can exit 0 even when a
# worker crashed AND drops flags after `--` when combined with -j. One process
# per systemd unit makes the unit's exit code the authoritative crash signal;
# box-level parallelism comes from running several such units).
#
# It looks up the target's row in the AUTHORITATIVE shard table for THIS box's
# node-id, then execs:
#
#   [RUSTFLAGS=<shard_rustflags>] \
#   cargo +nightly-2026-06-10 fuzz run --sanitizer <shard_sanitizer> <target> \
#       fuzz/corpus/<target> [fuzz/seeds/<target>] \
#       -- [-dict=fuzz/<target>.dict] <extra_flags> \
#          -rss_limit_mb=<rss> -malloc_limit_mb=<rss> \
#          -timeout=<timeout> -max_len=<max_len> -print_final_stats=1
#
# Usage: run-one.sh <target>
set -uo pipefail

export CARGO_HOME="${CARGO_HOME:-/var/lib/plxfuzz/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/var/lib/plxfuzz/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

NIGHTLY="nightly-2026-06-10"

die() { echo "run-one: $*" >&2; exit 1; }

TARGET="${1:-}"
[ -n "$TARGET" ] || die "usage: run-one.sh <target>"

# --- box state (written by bootstrap, root) ---------------------------------
ETC=/etc/plxfuzz
SRC=/var/lib/plxfuzz/src

NODE_ID="$(tr -d ' \t\r\n' < "$ETC/node-id" 2>/dev/null || true)"
[ -n "$NODE_ID" ] || die "missing $ETC/node-id"

# Always operate from the source tree so fuzz/corpus, fuzz/seeds and the dicts
# resolve exactly like fuzz/run.sh expects (systemd sets WorkingDirectory too).
cd "$SRC" 2>/dev/null || die "source tree $SRC not found"

# --- locate + source the authoritative shard table --------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARD_TABLE=""
for cand in \
  "$SCRIPT_DIR/../lib/shard-table.sh" \
  "$SCRIPT_DIR/lib/shard-table.sh" \
  "/var/lib/plxfuzz/bin/lib/shard-table.sh" \
  "/var/lib/plxfuzz/bin/shard-table.sh" \
  "$SRC/ops/fuzz-cluster/lib/shard-table.sh"; do
  if [ -f "$cand" ]; then SHARD_TABLE="$cand"; break; fi
done
[ -n "$SHARD_TABLE" ] || die "shard-table.sh not found"
# shellcheck source=/dev/null
. "$SHARD_TABLE"

# --- look up this target's row for THIS box ---------------------------------
# Row format: '<target> <rss_mb> <max_len> <timeout> <extra_flags...>'
read -r _t RSS MAX_LEN TIMEOUT EXTRA <<EOF
$(shard_targets "$NODE_ID" | awk -v t="$TARGET" '$1==t{print; exit}')
EOF

[ -n "${RSS:-}" ] && [ -n "${MAX_LEN:-}" ] && [ -n "${TIMEOUT:-}" ] \
  || die "target '$TARGET' is not in the shard plan for node '$NODE_ID'"

SAN="$(shard_sanitizer "$NODE_ID")"
SAN="${SAN:-address}"

# box-c (sanitizer=none) restores overflow detection via overflow-checks.
# Append to any RUSTFLAGS already in the environment (cargo-fuzz merges these
# with the sanitizer flags it injects for address/thread builds).
RF="$(shard_rustflags "$NODE_ID")"
if [ -n "$RF" ]; then
  export RUSTFLAGS="${RUSTFLAGS:-} ${RF}"
fi

# --- assemble corpus + seed dirs (seeds are read-only curated inputs) --------
mkdir -p "fuzz/corpus/$TARGET" 2>/dev/null || true
CORPUS_DIRS=( "fuzz/corpus/$TARGET" )
[ -d "fuzz/seeds/$TARGET" ] && CORPUS_DIRS+=( "fuzz/seeds/$TARGET" )

# --- libFuzzer flags (after `--`) -------------------------------------------
LF_ARGS=()
DICT="fuzz/$TARGET.dict"
[ -f "$DICT" ] && LF_ARGS+=( "-dict=$DICT" )
# shellcheck disable=SC2206  # EXTRA is a controlled, space-separated flag list
[ -n "${EXTRA:-}" ] && LF_ARGS+=( $EXTRA )
LF_ARGS+=(
  "-rss_limit_mb=$RSS"
  "-malloc_limit_mb=$RSS"
  "-timeout=$TIMEOUT"
  "-max_len=$MAX_LEN"
  "-print_final_stats=1"
)

echo "run-one: node=$NODE_ID target=$TARGET san=$SAN rss=$RSS max_len=$MAX_LEN timeout=$TIMEOUT extra=[${EXTRA:-}] rustflags=[${RF:-}]"

# Single in-process fuzzer. exec so systemd tracks the libFuzzer PID directly
# and its non-zero exit (crash/OOM) is the unit's exit -> OnFailure fires.
exec cargo "+$NIGHTLY" fuzz run --sanitizer "$SAN" "$TARGET" \
  "${CORPUS_DIRS[@]}" \
  -- "${LF_ARGS[@]}"
