#!/usr/bin/env bash
# ops/fuzz-cluster/bin/status.sh
# GROUP 3 — observability. Runs as user 'plxfuzz' from the plx-status timer
# (~every 1 min). Builds status-<nodeid>.json and commits it to the dedicated
# 'fuzz-status' branch (last-writer-wins: pull --rebase; on a push race reset to
# remote + retry). Every gh/git network op is wrapped so a transient failure can
# never kill the box; the next tick just retries. Idempotent.
#
# IMPORTANT: the branch commit happens in a DEDICATED clone under
# /var/lib/plxfuzz/state/branch-fuzz-status — never in /var/lib/plxfuzz/src,
# which is the pinned source tree the fuzzers are actively running from.
set -uo pipefail

ETC=/etc/plxfuzz
STATE=/var/lib/plxfuzz/state
SRC=/var/lib/plxfuzz/src

read_cfg() { [ -r "$ETC/$1" ] && tr -d ' \t\r\n' < "$ETC/$1" || true; }

NODE_ID="$(read_cfg node-id)"
PINNED="$(read_cfg pinned-commit)"
REPO="$(read_cfg repo)";        REPO="${REPO:-yuzeguitarist/ParallaX}"
TAG="$(read_cfg campaign-tag)"; TAG="${TAG:-fuzz-corpus-84c78add}"
export GH_REPO="$REPO"   # gh reads this; PAT is an env var (NEVER argv).
# Token via env (matches sync.sh) so gh works under systemd even if the
# bootstrap `gh auth login` creds aren't on this unit's HOME. Never argv.
export GH_TOKEN="${GH_TOKEN:-$(read_cfg pat)}"

# Authoritative shard table (sourced, never written here).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for cand in \
  "$SCRIPT_DIR/lib/shard-table.sh" \
  "$SCRIPT_DIR/../lib/shard-table.sh" \
  "$SRC/ops/fuzz-cluster/lib/shard-table.sh"; do
  # shellcheck source=/dev/null
  if [ -r "$cand" ]; then . "$cand"; break; fi
done
if ! declare -p ALL_TARGETS >/dev/null 2>&1; then
  ALL_TARGETS="tls_client_hello tls_server_hello tls_compressed_cert mux_frame server_decide_inbound client_hello_auth command_codecs http2_frame_header data_record_open replay_journal socks_connect_request udp_envelope udp_reorder"
fi
type owner_box     >/dev/null 2>&1 || owner_box()     { :; }
type shard_targets >/dev/null 2>&1 || shard_targets() { :; }

now_iso() { date -u +%FT%TZ; }
TS="$(now_iso)"

# All metrics are read from the live source tree.
cd "$SRC" 2>/dev/null || cd / || true

# --- targets this box runs + targets this box owns --------------------------
MY_TARGETS="$(shard_targets "$NODE_ID" 2>/dev/null | awk 'NF{print $1}' | tr '\n' ' ')"

OWNS=()
for t in $ALL_TARGETS; do
  [ "$(owner_box "$t" 2>/dev/null)" = "$NODE_ID" ] && OWNS+=("$t")
done

# --- per-target exec/s from each unit's journal (-print_final_stats) --------
# libFuzzer prints "exec/s: N" (final stats) and "exec/s N" (pulse). Take the
# most recent numeric value in this unit's journal.
unit_execs() {
  local t="$1" v
  v="$(journalctl -u "plx-fuzz@${t}.service" -o cat --no-pager -n 5000 2>/dev/null \
        | grep -Eo 'exec/s[: ]+[0-9]+' | tail -n 1 || true)"
  printf '%s' "${v//[^0-9]/}"
}

# crash / oom / timeout class counts across this box's units (whole boot).
count_journal() {
  local re="$1" n=0 t c
  for t in $MY_TARGETS; do
    c="$(journalctl -u "plx-fuzz@${t}.service" -o cat --no-pager 2>/dev/null | grep -Ec "$re" || true)"
    n=$(( n + ${c:-0} ))
  done
  printf '%s' "$n"
}

# Max RSS (MB) across this box's units via cgroup MemoryPeak.
max_rss_mb() {
  local best=0 t v
  for t in $MY_TARGETS; do
    v="$(systemctl show "plx-fuzz@${t}.service" -p MemoryPeak --value 2>/dev/null || true)"
    case "$v" in ''|'[not set]'|18446744073709551615) v=0 ;; esac
    v="${v//[^0-9]/}"; [ -n "$v" ] || v=0
    v=$(( v / 1048576 ))
    [ "$v" -gt "$best" ] && best="$v"
  done
  printf '%s' "$best"
}

# --- corpus size (file count + bytes) --------------------------------------
CORPUS_FILES=0; CORPUS_BYTES=0
if [ -d fuzz/corpus ]; then
  CORPUS_FILES="$(find fuzz/corpus -type f 2>/dev/null | wc -l | tr -d ' ')"
  CORPUS_BYTES="$(find fuzz/corpus -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}')"
fi
[ -n "${CORPUS_FILES:-}" ] || CORPUS_FILES=0
[ -n "${CORPUS_BYTES:-}" ] || CORPUS_BYTES=0

# --- crash count (local view: committed repros + un-pushed artifacts) -------
CRASH_COUNT=0
[ -d crashes ]        && CRASH_COUNT=$(( CRASH_COUNT + $(find crashes -type f 2>/dev/null | wc -l | tr -d ' ') ))
[ -d fuzz/artifacts ] && CRASH_COUNT=$(( CRASH_COUNT + $(find fuzz/artifacts -type f -name 'crash-*' 2>/dev/null | wc -l | tr -d ' ') ))

# NOTE: the OOM pattern must NOT include 'rss_limit' — that substring also occurs
# in libFuzzer's own launch-command echo ("Running `... -rss_limit_mb=N ...`"),
# which made every healthy boot count as N OOMs. Match only the real OOM error.
OOM_TIMEOUT=$(( $(count_journal 'ERROR: libFuzzer: out-of-memory') + $(count_journal 'libFuzzer: timeout|timeout after') ))
MAX_RSS="$(max_rss_mb)"

# --- host metrics -----------------------------------------------------------
UPTIME_S="$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null || echo 0)"
DISK_FREE_PCT="$(df -P / 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print 100-$5}')"
[ -n "${DISK_FREE_PCT:-}" ] || DISK_FREE_PCT=0

# last_sync_ts: the most recent updatedAt among the corpus Release assets THIS
# box writes (canonical corpus-<owned> + contrib-*-<nodeid>) == the last time
# our corpus actually landed off-box. Network call, best-effort. Falls back to a
# $STATE/last-sync-ts stamp (if a future sync.sh writes one), else null.
LAST_SYNC="null"
if command -v gh >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  v="$(gh release view "$TAG" --json assets \
        --jq "[.assets[] | select(.name|test(\"^corpus-.*\\\\.tar\\\\.zst$\") or test(\"-${NODE_ID}\\\\.tar\\\\.zst$\")) | .updatedAt] | max // empty" \
        2>/dev/null || true)"
  [ -n "$v" ] && LAST_SYNC="$v"
fi
if [ "$LAST_SYNC" = "null" ] && [ -r "$STATE/last-sync-ts" ]; then
  v="$(tr -d ' \t\r\n' < "$STATE/last-sync-ts" 2>/dev/null || true)"
  [ -n "$v" ] && LAST_SYNC="$v"
fi

# --- per-target exec/s map + total -----------------------------------------
declare -a EPS_KV=(); TOTAL_EPS=0
for t in $MY_TARGETS; do
  e="$(unit_execs "$t")"; [ -n "$e" ] || e=0
  EPS_KV+=("$t" "$e"); TOTAL_EPS=$(( TOTAL_EPS + e ))
done

# --- assemble JSON with jq (safe escaping) ---------------------------------
owns_json="$(printf '%s\n' "${OWNS[@]:-}" | jq -R . 2>/dev/null | jq -s 'map(select(length>0))' 2>/dev/null)"
[ -n "$owns_json" ] || owns_json='[]'

eps_json='{}'
if [ "${#EPS_KV[@]}" -gt 0 ]; then
  eps_json="$(
    { for ((i=0; i<${#EPS_KV[@]}; i+=2)); do printf '%s\t%s\n' "${EPS_KV[i]}" "${EPS_KV[i+1]}"; done; } \
      | jq -R 'split("\t") | {(.[0]): (.[1]|tonumber? // 0)}' 2>/dev/null \
      | jq -s 'add // {}' 2>/dev/null
  )"
  [ -n "$eps_json" ] || eps_json='{}'
fi

# Stage the JSON into the dedicated status worktree (created below), not src.
WT="$STATE/branch-fuzz-status"
BRANCH=fuzz-status
REL="fuzz/dashboard/status-${NODE_ID}.json"

build_json() {  # $1 = absolute output path
  local out="$1"
  mkdir -p "$(dirname "$out")" 2>/dev/null || true
  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg node "$NODE_ID" --arg commit "$PINNED" --arg ts "$TS" \
      --argjson owns "$owns_json" --argjson execs_per_sec "$eps_json" \
      --argjson total_execs_per_sec "${TOTAL_EPS:-0}" \
      --argjson corpus_files "${CORPUS_FILES:-0}" --argjson corpus_bytes "${CORPUS_BYTES:-0}" \
      --argjson crash_count "${CRASH_COUNT:-0}" --argjson oom_timeout_count "${OOM_TIMEOUT:-0}" \
      --argjson max_rss_mb "${MAX_RSS:-0}" --argjson uptime_s "${UPTIME_S:-0}" \
      --argjson disk_free_pct "${DISK_FREE_PCT:-0}" --arg last_sync_ts "$LAST_SYNC" \
      '{node:$node, commit:$commit, ts:$ts, owns:$owns,
        execs_per_sec:$execs_per_sec, total_execs_per_sec:$total_execs_per_sec,
        corpus_files:$corpus_files, corpus_bytes:$corpus_bytes,
        crash_count:$crash_count, oom_timeout_count:$oom_timeout_count,
        max_rss_mb:$max_rss_mb, uptime_s:$uptime_s, disk_free_pct:$disk_free_pct,
        last_sync_ts: (if $last_sync_ts=="null" then null else $last_sync_ts end)}' \
      > "$out" 2>/dev/null || true
  fi
  if [ ! -s "$out" ]; then
    printf '{"node":"%s","commit":"%s","ts":"%s","corpus_files":%s,"crash_count":%s}\n' \
      "$NODE_ID" "$PINNED" "$TS" "${CORPUS_FILES:-0}" "${CRASH_COUNT:-0}" > "$out" || true
  fi
}

# --- dedicated status clone: never touch the source tree's branch -----------
# Authenticated remote uses the PAT from /etc/plxfuzz/pat ONLY inside the URL of
# this throwaway clone; the token is never passed as a command-line argument.
auth_remote() {
  local tok=""
  [ -r "$ETC/pat" ] && tok="$(tr -d ' \t\r\n' < "$ETC/pat" 2>/dev/null || true)"
  if [ -n "$tok" ]; then
    printf 'https://x-access-token:%s@github.com/%s' "$tok" "$REPO"
  else
    printf 'https://github.com/%s' "$REPO"
  fi
}

ensure_status_clone() {
  if [ -d "$WT/.git" ]; then
    git -C "$WT" remote set-url origin "$(auth_remote)" 2>/dev/null || true
    return 0
  fi
  mkdir -p "$STATE" 2>/dev/null || true
  rm -rf "$WT" 2>/dev/null || true
  if git clone --depth 1 --branch "$BRANCH" --single-branch "$(auth_remote)" "$WT" -q 2>/dev/null; then
    return 0
  fi
  # Branch does not exist yet — create it as an orphan in a fresh clone.
  if git clone --depth 1 "$(auth_remote)" "$WT" -q 2>/dev/null; then
    git -C "$WT" checkout --orphan "$BRANCH" -q 2>/dev/null || true
    git -C "$WT" rm -rf --cached . -q 2>/dev/null || true
    git -C "$WT" clean -fdq 2>/dev/null || true
    return 0
  fi
  return 1
}

git_commit_status() {
  git -C "$WT" -c user.name=plxfuzz -c user.email=plxfuzz@localhost \
    commit -q -m "status ${NODE_ID} ${TS}" 2>/dev/null || true
}

push_status() {
  ensure_status_clone || return 0
  git -C "$WT" remote set-url origin "$(auth_remote)" 2>/dev/null || true

  local i
  for i in 1 2 3; do
    git -C "$WT" fetch origin "$BRANCH" -q 2>/dev/null || true
    if git -C "$WT" show-ref --verify --quiet "refs/remotes/origin/$BRANCH" 2>/dev/null; then
      git -C "$WT" checkout -B "$BRANCH" "origin/$BRANCH" -q 2>/dev/null || true
    fi
    build_json "$WT/$REL"
    git -C "$WT" add "$REL" 2>/dev/null || true
    git -C "$WT" diff --cached --quiet 2>/dev/null && return 0   # nothing to do
    git_commit_status
    if git -C "$WT" push origin "HEAD:$BRANCH" -q 2>/dev/null; then
      printf '%s\n' "$TS" > "$STATE/last-status-ts" 2>/dev/null || true
      return 0
    fi
    # lost the race -> reset to remote tip and retry (last-writer-wins).
    git -C "$WT" fetch origin "$BRANCH" -q 2>/dev/null || true
    git -C "$WT" reset --hard "origin/$BRANCH" -q 2>/dev/null || true
  done
  return 0
}

push_status || true
exit 0
