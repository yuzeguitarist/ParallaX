#!/usr/bin/env bash
# ops/fuzz-cluster/bin/cmin.sh
# GROUP 3 — maintenance. Daily corpus pruner. Runs as 'plxfuzz' from the
# plx-cmin timer (once/day at a fixed UTC minute).
#
# Pruner-of-the-day: each box only prunes the targets it is "assigned" today,
# where assigned == sha256(UTC-date + target) % 3 == this box's index
# (box-a=0, box-b=1, box-c=2). Across 3 boxes every target is covered ~daily
# with no two boxes pruning the same target the same day -> no --clobber race
# on the canonical asset.
#
# Per assigned target:
#   1. download canonical corpus-<t>.tar.zst + all contrib-<t>-*.tar.zst (union)
#   2. re-inject the minimized crash repros from the fuzz-crashes branch FIRST
#      (so cmin can never drop a known-crashing input)
#   3. measure pre-prune coverage features (cargo fuzz run -runs=0 -> ft:)
#   4. cargo +nightly-2026-06-10 fuzz cmin <t>
#   5. measure post-prune features; GATE: publish only if post >= ~99% of pre
#   6. keep a one-generation corpus-<t>.prev.tar.zst backup, then upload the
#      pruned canonical with --clobber
#
# Usage:
#   cmin.sh                 # pruner-of-the-day (today's assigned targets)
#   cmin.sh <target>...     # force-prune exactly these (used by disk-guard.sh)
#
# Every gh/git network op is wrapped (|| true) so a transient failure never
# kills the box; the next daily tick retries. Idempotent.
set -uo pipefail

export CARGO_HOME="${CARGO_HOME:-/var/lib/plxfuzz/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/var/lib/plxfuzz/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

ETC=/etc/plxfuzz
STATE=/var/lib/plxfuzz/state
SRC=/var/lib/plxfuzz/src
WORK="$STATE/cmin"            # scratch; never the live corpus dir
RETAIN_PCT=99                 # gate: keep >= 99% of pre-prune features

read_cfg() { [ -r "$ETC/$1" ] && tr -d ' \t\r\n' < "$ETC/$1" || true; }

NODE_ID="$(read_cfg node-id)"
REPO="$(read_cfg repo)";        REPO="${REPO:-yuzeguitarist/ParallaX}"
TAG="$(read_cfg campaign-tag)"; TAG="${TAG:-fuzz-corpus-f3c9c32f}"
export GH_REPO="$REPO"
export GH_TOKEN="${GH_TOKEN:-$(read_cfg pat)}"   # env, never argv (matches sync.sh)

FUZZ="cargo +nightly-2026-06-10 fuzz"
CRASH_BRANCH=fuzz-crashes

# --- shard table (authoritative) -------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for cand in \
  "$SCRIPT_DIR/lib/shard-table.sh" \
  "$SCRIPT_DIR/../lib/shard-table.sh" \
  "$SRC/ops/fuzz-cluster/lib/shard-table.sh"; do
  # shellcheck source=/dev/null
  if [ -r "$cand" ]; then . "$cand"; break; fi
done
if ! declare -p ALL_TARGETS >/dev/null 2>&1; then
  ALL_TARGETS="tls_client_hello tls_server_hello tls_compressed_cert mux_frame server_decide_inbound client_hello_auth command_codecs http2_frame_header data_record_open replay_journal socks_connect_request udp_envelope udp_reorder replay_dedup"
fi
type shard_sanitizer >/dev/null 2>&1 || shard_sanitizer() { echo address; }
type shard_rustflags >/dev/null 2>&1 || shard_rustflags() { :; }
type shard_targets   >/dev/null 2>&1 || shard_targets()   { :; }

# Box index from node-id (box-a=0, box-b=1, box-c=2). Matches owner_box's
# crc32%3 codomain mapping a->0,b->1,c->2.
box_index() {
  case "$NODE_ID" in
    box-a) echo 0 ;; box-b) echo 1 ;; box-c) echo 2 ;;
    *) echo 0 ;;
  esac
}
MY_IDX="$(box_index)"

# sha256(UTC-date + target) % 3  -> which box prunes <target> today.
assigned_today() {
  local t="$1" today h
  today="$(date -u +%Y-%m-%d)"
  h="$(printf '%s%s' "$today" "$t" | sha256sum | awk '{print $1}')"
  # take low 8 hex digits -> integer -> %3 (bash can't hold full 64 hex)
  local n=$(( 0x${h: -8} % 3 ))
  [ "$n" -eq "$MY_IDX" ]
}

# --- sanitizer / rustflags for THIS box's cargo-fuzz invocations ------------
SAN="$(shard_sanitizer "$NODE_ID" 2>/dev/null)"; SAN="${SAN:-address}"
RF="$(shard_rustflags "$NODE_ID" 2>/dev/null)"
export RUSTFLAGS="${RUSTFLAGS:-} ${RF}"
SAN_ARG=(--sanitizer "$SAN")

# rss cap for a target (from this box's shard line, else a safe 2048 backstop).
rss_for() {
  local t="$1" rss
  rss="$(shard_targets "$NODE_ID" 2>/dev/null | awk -v T="$t" '$1==T {print $2; exit}')"
  [ -n "$rss" ] || rss=2048
  printf '%s' "$rss"
}

# --- auth'd remote for the dedicated crash clone (PAT only in URL) ----------
auth_remote() {
  local tok=""
  [ -r "$ETC/pat" ] && tok="$(tr -d ' \t\r\n' < "$ETC/pat" 2>/dev/null || true)"
  if [ -n "$tok" ]; then printf 'https://x-access-token:%s@github.com/%s' "$tok" "$REPO"
  else printf 'https://github.com/%s' "$REPO"; fi
}

# Best-effort: get the minimized crash repros for <target> into $1 (a dir).
fetch_crash_repros() {
  local t="$1" dest="$2" cw="$STATE/branch-fuzz-crashes"
  mkdir -p "$dest" 2>/dev/null || true
  if [ ! -d "$cw/.git" ]; then
    rm -rf "$cw" 2>/dev/null || true
    git clone --depth 1 --branch "$CRASH_BRANCH" --single-branch "$(auth_remote)" "$cw" -q 2>/dev/null || true
  else
    git -C "$cw" remote set-url origin "$(auth_remote)" 2>/dev/null || true
    git -C "$cw" fetch origin "$CRASH_BRANCH" -q 2>/dev/null || true
    git -C "$cw" reset --hard "origin/$CRASH_BRANCH" -q 2>/dev/null || true
  fi
  if [ -d "$cw/crashes/$t" ]; then
    find "$cw/crashes/$t" -type f -exec cp -f {} "$dest"/ \; 2>/dev/null || true
  fi
}

# Count libFuzzer coverage features for a corpus dir: run -runs=0 and read ft:.
# Returns 0 if it can't be measured (treated as "no signal" by the gate).
count_features() {
  local t="$1" dir="$2" rss; rss="$(rss_for "$t")"
  local ft
  # shellcheck disable=SC2086
  ft="$($FUZZ run "$t" "$dir" "${SAN_ARG[@]}" -- \
          -runs=0 -rss_limit_mb="$rss" -malloc_limit_mb="$rss" -timeout=25 2>&1 \
          | grep -Eo 'ft:[[:space:]]*[0-9]+' | tail -n 1 | grep -Eo '[0-9]+' || true)"
  printf '%s' "${ft:-0}"
}

dl()  { gh release download "$TAG" --pattern "$1" --dir "$2" --clobber 2>/dev/null || true; }
untar(){ tar --use-compress-program=unzstd -xf "$1" -C "$2" 2>/dev/null || true; }
mktar(){ tar --use-compress-program='zstd -19 -T0' -cf "$1" -C "$2" . 2>/dev/null || true; }

prune_one() {
  local t="$1"
  local d="$WORK/$t"
  rm -rf "$d" 2>/dev/null || true
  mkdir -p "$d/merged" "$d/dl" 2>/dev/null || true

  # 1. canonical + contribs -> union in merged/ (SHA1 names dedup naturally)
  dl "corpus-$t.tar.zst" "$d/dl"
  [ -f "$d/dl/corpus-$t.tar.zst" ] && untar "$d/dl/corpus-$t.tar.zst" "$d/merged"
  dl "contrib-$t-*.tar.zst" "$d/dl"
  for c in "$d"/dl/contrib-"$t"-*.tar.zst; do
    [ -f "$c" ] && untar "$c" "$d/merged"
  done

  # L-4: do NOT inject crash repros into the corpus. libFuzzer corpus inputs must
  # not crash on load — a re-injected repro would crash-loop any fuzzer that later
  # pulls this canonical (the M-5 trigger), and -merge=1 is coverage-greedy so it
  # drops coverage-redundant repros anyway (the old "cmin can't drop a known crash"
  # guarantee was false). Crash repros live durably on the fuzz-crashes branch + as
  # Issues — that is the system of record, not the corpus.

  # If we have nothing, there is nothing to prune.
  if [ -z "$(find "$d/merged" -type f -print -quit 2>/dev/null)" ]; then
    echo "cmin[$t]: empty corpus, skip"
    rm -rf "$d" 2>/dev/null || true
    return 0
  fi

  # 3. pre-prune features
  local pre; pre="$(count_features "$t" "$d/merged")"

  # snapshot the pre-prune union as the one-gen rollback BEFORE cmin mutates it
  mktar "$d/prev.tar.zst" "$d/merged"

  # 4. minimize in place (cmin rewrites the first corpus dir)
  local rss; rss="$(rss_for "$t")"
  # shellcheck disable=SC2086
  $FUZZ cmin "$t" "$d/merged" "${SAN_ARG[@]}" -- \
      -rss_limit_mb="$rss" -malloc_limit_mb="$rss" -timeout=25 2>/dev/null || {
        echo "cmin[$t]: cmin failed, skip publish"
        rm -rf "$d" 2>/dev/null || true
        return 0
      }

  # 5. post-prune features + GATE
  local post; post="$(count_features "$t" "$d/merged")"
  echo "cmin[$t]: features pre=$pre post=$post (gate >= ${RETAIN_PCT}%)"
  # Guard against a 0/unknown pre (no signal) -> do not publish a maybe-worse set.
  if [ "${pre:-0}" -le 0 ]; then
    echo "cmin[$t]: no pre-prune signal, skip publish"
    rm -rf "$d" 2>/dev/null || true
    return 0
  fi
  # publish iff post*100 >= pre*RETAIN_PCT
  if [ $(( post * 100 )) -lt $(( pre * RETAIN_PCT )) ]; then
    echo "cmin[$t]: coverage dropped below gate, skip publish (canonical unchanged)"
    rm -rf "$d" 2>/dev/null || true
    return 0
  fi

  # 6. one-gen backup, then publish pruned canonical
  if [ -f "$d/prev.tar.zst" ]; then
    cp -f "$d/prev.tar.zst" "$d/corpus-$t.prev.tar.zst" 2>/dev/null || true
    gh release upload "$TAG" "$d/corpus-$t.prev.tar.zst" --clobber 2>/dev/null || true
  fi
  mktar "$d/corpus-$t.tar.zst" "$d/merged"
  if [ -f "$d/corpus-$t.tar.zst" ]; then
    # L-5: serialize with the owner's sync_owned upload via a per-target flock so
    # the two never clobber each other mid-upload (same lock path as sync.sh).
    mkdir -p "$STATE" 2>/dev/null || true
    if flock "$STATE/corpus-$t.lock" gh release upload "$TAG" "$d/corpus-$t.tar.zst" --clobber 2>/dev/null; then
      echo "cmin[$t]: published pruned canonical"
    else
      echo "cmin[$t]: upload failed (will retry next tick)"
    fi
  fi
  rm -rf "$d" 2>/dev/null || true
}

main() {
  mkdir -p "$WORK" 2>/dev/null || true
  local targets=()
  if [ "$#" -gt 0 ]; then
    targets=("$@")                       # forced (disk-guard) — prune exactly these
  else
    # M-1: prune only the targets THIS box OWNS, so the owner is the SINGLE writer
    # of each canonical corpus-<t>.tar.zst (matches sync_owned's writer and the
    # README one-writer-per-asset contract). The old assigned_today rotation let a
    # NON-owner box clobber the canonical and race the owner's sync.
    for t in $ALL_TARGETS; do
      [ "$(owner_box "$t" 2>/dev/null)" = "$NODE_ID" ] && targets+=("$t")
    done
  fi
  [ "${#targets[@]}" -gt 0 ] || { echo "cmin: nothing owned to prune"; return 0; }
  echo "cmin: node=$NODE_ID idx=$MY_IDX san=$SAN targets=${targets[*]}"
  for t in "${targets[@]}"; do
    prune_one "$t" || true
  done
}

main "$@"
exit 0
