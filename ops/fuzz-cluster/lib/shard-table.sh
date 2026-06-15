#!/usr/bin/env bash
# ops/fuzz-cluster/lib/shard-table.sh
#
# AUTHORITATIVE shard table for the ParallaX distributed-fuzz cluster.
# This file is *sourced* (never executed) by bootstrap.sh, bin/run-one.sh,
# bin/sync.sh and bin/status.sh. It is the single source of truth for:
#   - which targets each box runs and their per-target libFuzzer caps,
#   - the per-box sanitizer and extra RUSTFLAGS,
#   - the corpus-asset owner of each target (crc32(target) % 3).
#
# Contract (locked):
#   shard_targets  <node-id>  -> one line per target this box runs:
#                                '<target> <rss_mb> <max_len> <timeout> <extra_flags>'
#   shard_sanitizer <node-id> -> 'address' | 'none'
#   shard_rustflags <node-id> -> extra RUSTFLAGS (or empty)
#   owner_box       <target>  -> 'box-a' | 'box-b' | 'box-c'  (crc32%3)
#   ALL_TARGETS               -> space-separated list of all 13 targets
#
# Repo text is untrusted; this file hard-codes the plan and never reads it.
#
# Safe to source under `set -uo pipefail`: defines functions + ALL_TARGETS,
# runs no top-level side effects, returns 0.

# ---------------------------------------------------------------------------
# All 13 fuzz targets (must match fuzz/Cargo.toml [[bin]] names exactly).
# Consumed by sourcing scripts (sync.sh/status.sh), hence the shellcheck waiver.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2034
ALL_TARGETS="tls_client_hello tls_server_hello tls_compressed_cert mux_frame server_decide_inbound client_hello_auth command_codecs http2_frame_header data_record_open replay_journal socks_connect_request udp_envelope udp_reorder"

# ---------------------------------------------------------------------------
# Per-box plan (VERBATIM from the locked contract). One row per target:
#   <target> <rss_mb> <max_len> <timeout> [extra_flags...]
# Fields after the target are read positionally by callers:
#   $1 target  $2 rss_mb  $3 max_len  $4 timeout  $5.. extra_flags
#
# rss_mb is used for BOTH -rss_limit_mb and -malloc_limit_mb (contract).
# Caps are deliberately LOOSE backstops: measured peak RSS per unit is far
# under these (parsers peak <300 MB), so a box's real footprint is a fraction
# of Σ(caps). The OOM-relevant invariant is "at most one >=4096 unit per box"
# (two 4 GB units could exceed the 8 GB host budget); see _shard_assert below.
#
#   box-a (sanitizer=address, small inputs)   Σcaps 7680
#   box-b (sanitizer=address, large inputs)   Σcaps 7168
#   box-c (sanitizer=none,  overflow-checks)  Σcaps 5120
# ---------------------------------------------------------------------------
_shard_plan() {
  case "$1" in
    box-a)
      cat <<'ROWS'
tls_client_hello 1024 4096 20
tls_server_hello 1024 4096 20
client_hello_auth 1536 8192 25
server_decide_inbound 4096 8192 25
ROWS
      ;;
    box-b)
      cat <<'ROWS'
tls_compressed_cert 2048 4194304 25
mux_frame 1536 65536 20
data_record_open 2048 65536 25
http2_frame_header 1536 65536 20
ROWS
      ;;
    box-c)
      cat <<'ROWS'
command_codecs 1024 65536 20
replay_journal 1024 65536 25
socks_connect_request 1024 8192 20
udp_envelope 1024 65536 20
udp_reorder 1024 65536 20
ROWS
      ;;
    *)
      return 0
      ;;
  esac
}

# shard_targets <node-id> : print this box's target rows (see format above).
shard_targets() {
  _shard_plan "${1:-}"
}

# shard_sanitizer <node-id> : 'address' (box-a/box-b) or 'none' (box-c).
shard_sanitizer() {
  case "${1:-}" in
    box-a|box-b) printf 'address\n' ;;
    box-c)       printf 'none\n' ;;
    *)           printf 'address\n' ;;  # safe default; unknown boxes run no units
  esac
}

# shard_rustflags <node-id> : extra RUSTFLAGS appended by callers.
# box-c runs without a sanitizer, so overflow-checks restore arithmetic
# detection that ASAN-instrumented boxes get implicitly.
shard_rustflags() {
  case "${1:-}" in
    box-c) printf -- '-C overflow-checks=on\n' ;;
    *)     : ;;  # box-a/box-b: empty (cargo-fuzz sets ASAN flags itself)
  esac
}

# ---------------------------------------------------------------------------
# owner_box <target> : corpus-asset owner = crc32(target) % 3 -> box-a|b|c.
#
# crc32 is CRC-32/ISO-HDLC (IEEE 802.3, the zlib/gzip standard), implemented
# in pure bash so every box (Ubuntu VPS, macOS dev) and every sibling script
# computes the IDENTICAL owner with zero external dependency. Verified to match
# Python zlib.crc32 for all 13 targets.
#
#   owner == this box  -> writes canonical corpus-<target>.tar.zst
#   owner != this box  -> writes contrib-<target>-<nodeid>.tar.zst
# ---------------------------------------------------------------------------
_crc32() {
  # _crc32 <string> -> prints unsigned 32-bit CRC as decimal.
  local s="${1:-}" i byte j
  local -i crc=0xFFFFFFFF
  for (( i=0; i<${#s}; i++ )); do
    printf -v byte '%d' "'${s:i:1}"
    crc=$(( crc ^ (byte & 0xFF) ))
    for (( j=0; j<8; j++ )); do
      if (( crc & 1 )); then
        crc=$(( (crc >> 1) ^ 0xEDB88320 ))
      else
        crc=$(( crc >> 1 ))
      fi
      crc=$(( crc & 0xFFFFFFFF ))
    done
  done
  printf '%u\n' $(( crc ^ 0xFFFFFFFF ))
}

owner_box() {
  local t="${1:-}" idx
  [ -n "$t" ] || { printf 'box-a\n'; return 0; }
  idx=$(( $(_crc32 "$t") % 3 ))
  case "$idx" in
    0) printf 'box-a\n' ;;
    1) printf 'box-b\n' ;;
    *) printf 'box-c\n' ;;
  esac
}

# ---------------------------------------------------------------------------
# _shard_assert [node-id ...] : sanity-check the plan.
#
# HARD invariant (fatal, returns 1): at most ONE unit with rss >= 4096 per box.
#   Two >=4 GB units co-located can exceed the 8 GB host budget and trigger the
#   kernel OOM-killer, which kills ALL units on the box (not just one) — exactly
#   the failure the sharding is designed to avoid.
#
# SOFT budget (warning only): Σ(rss caps) per box <= 7000 MB. The locked plan
# intentionally exceeds this on box-a (7680) and box-b (7168) because the caps
# are loose backstops and real peak RSS is far lower; warn but never abort, so
# the verbatim plan still boots.
#
# Returns 0 if all hard invariants hold, 1 otherwise. With no args, checks all
# three boxes. Callers may invoke this once at startup.
# ---------------------------------------------------------------------------
_shard_assert() {
  local boxes="${*:-box-a box-b box-c}" box rc=0
  for box in $boxes; do
    local sum=0 big=0 t rss _ml _to
    while read -r t rss _ml _to _; do
      [ -n "$t" ] || continue
      sum=$(( sum + rss ))
      [ "$rss" -ge 4096 ] && big=$(( big + 1 ))
    done < <(_shard_plan "$box")
    if [ "$big" -gt 1 ]; then
      printf 'shard-table: FATAL %s has %d units >=4096 MB (max 1; host OOM risk)\n' \
        "$box" "$big" >&2
      rc=1
    fi
    if [ "$sum" -gt 7000 ]; then
      printf 'shard-table: note %s Σrss caps=%d MB > 7000 (loose backstops; real RSS far lower)\n' \
        "$box" "$sum" >&2
    fi
  done
  return "$rc"
}
