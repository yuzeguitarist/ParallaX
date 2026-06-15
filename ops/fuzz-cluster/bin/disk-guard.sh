#!/usr/bin/env bash
# ops/fuzz-cluster/bin/disk-guard.sh
# GROUP 3 — maintenance. Runs as 'plxfuzz' from the plx-diskguard timer
# (hourly). Two tripwires:
#
#   1. Per-target corpus tripwire: if a local corpus dir crosses
#      du -sm > 512 MB OR file count > 100000, trigger an EARLY cmin of that
#      target (cmin.sh <target> in forced mode) to fold + minimize it back down.
#
#   2. Root-FS tripwire: if / is > 85% used, reclaim space by cleaning the
#      non-fuzz cargo build artifacts (cargo clean -p parallax — does NOT touch
#      fuzz/target, so the running fuzzers are unaffected), dropping the oldest
#      rotated logs, and vacuuming journald.
#
# Corpus today is tiny (single-MB) and growth is sublinear, so these tripwires
# almost never fire; they are backstops for the 15-day unattended lifetime.
# Every action is wrapped so a transient failure never kills the box. Idempotent.
set -uo pipefail

export CARGO_HOME="${CARGO_HOME:-/var/lib/plxfuzz/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/var/lib/plxfuzz/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

SRC=/var/lib/plxfuzz/src
CORPUS_MB_MAX=512
CORPUS_FILES_MAX=100000
ROOT_PCT_MAX=85
LOGDIR=/var/log/plxfuzz       # where logrotate (sibling config) parks rotated logs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve cmin.sh next to this script (copied to /var/lib/plxfuzz/bin), else src.
CMIN=""
for cand in \
  "$SCRIPT_DIR/cmin.sh" \
  "$SRC/ops/fuzz-cluster/bin/cmin.sh"; do
  if [ -x "$cand" ] || [ -r "$cand" ]; then CMIN="$cand"; break; fi
done

cd "$SRC" 2>/dev/null || cd / || true

root_pct() { df -P / 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5+0}'; }

# --- tripwire 1: per-target corpus size / count -> early cmin ---------------
corpus_tripwire() {
  [ -d fuzz/corpus ] || return 0
  local d t mb n
  for d in fuzz/corpus/*/; do
    [ -d "$d" ] || continue
    t="$(basename "$d")"
    case "$t" in *.bak-*) continue ;; esac     # skip run.sh's cmin backups
    mb="$(du -sm "$d" 2>/dev/null | awk '{print $1+0}')"
    n="$(find "$d" -type f 2>/dev/null | wc -l | tr -d ' ')"
    [ -n "$mb" ] || mb=0; [ -n "$n" ] || n=0
    if [ "$mb" -gt "$CORPUS_MB_MAX" ] || [ "$n" -gt "$CORPUS_FILES_MAX" ]; then
      echo "disk-guard: corpus[$t] over tripwire (mb=$mb files=$n) -> early cmin"
      if [ -n "$CMIN" ]; then
        bash "$CMIN" "$t" || true
      fi
    fi
  done
}

# --- tripwire 2: root FS > 85% -> reclaim ----------------------------------
drop_oldest_logs() {
  # remove the single oldest compressed rotated log per pass (gentle)
  local oldest
  if [ -d "$LOGDIR" ]; then
    oldest="$(find "$LOGDIR" -type f \( -name '*.gz' -o -name '*.xz' -o -name '*.zst' -o -name '*.[0-9]' \) \
                -printf '%T@ %p\n' 2>/dev/null | sort -n | awk 'NR==1{ $1=""; sub(/^ /,""); print }')"
    if [ -n "$oldest" ] && [ -f "$oldest" ]; then
      echo "disk-guard: dropping oldest rotated log $oldest"
      rm -f "$oldest" 2>/dev/null || true
    fi
  fi
  # journald is the primary sink; cap it hard as a guaranteed lever.
  journalctl --vacuum-size=1G >/dev/null 2>&1 || true
}

root_tripwire() {
  local p; p="$(root_pct)"; [ -n "$p" ] || return 0
  [ "$p" -le "$ROOT_PCT_MAX" ] && return 0
  echo "disk-guard: root FS at ${p}% (> ${ROOT_PCT_MAX}%) -> reclaiming"

  # 1. non-fuzz cargo artifacts (root target/, NOT fuzz/target/). Safe: the
  #    instrumented fuzz binaries live under fuzz/target and are untouched.
  if command -v cargo >/dev/null 2>&1; then
    ( cd "$SRC" 2>/dev/null && cargo clean -p parallax >/dev/null 2>&1 ) || true
  fi

  # 2. oldest rotated logs + journald vacuum, repeat while still over budget
  local guard=0
  while :; do
    drop_oldest_logs
    p="$(root_pct)"; [ -n "$p" ] || break
    [ "$p" -le "$ROOT_PCT_MAX" ] && break
    guard=$(( guard + 1 )); [ "$guard" -ge 10 ] && break    # don't loop forever
  done
  echo "disk-guard: root FS now at $(root_pct)%"
}

corpus_tripwire || true
root_tripwire   || true
exit 0
