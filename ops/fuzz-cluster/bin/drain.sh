#!/usr/bin/env bash
# ops/fuzz-cluster/bin/drain.sh
# GROUP 3 — graceful pre-destroy. This is the MANUAL pre-destroy drain step:
# the operator runs it by hand before destroying the box (`doctl droplet
# delete`). It is NOT wired as ExecStop on the fuzz units. Goal: an orderly
# 15-day box swap loses ~0 durable state.
#
# Steps:
#   1. systemctl stop 'plx-fuzz@*'   -> let every in-process fuzzer finish its
#      current run cleanly (no SIGKILL mid-write).
#   2. one final forced sync.sh      -> push all local corpus deltas to the
#      Release + final status/crash commits.
#   3. VERIFY the corpus Release upload AND the fuzz-status git push actually
#      landed before returning success. Bounded retries; never hangs forever.
#
# Every network op is wrapped so a transient blip is retried rather than fatal.
# Exit 0 only when both the Release and the status push are confirmed; non-zero
# (after the retry budget) tells the operator the drain could not be confirmed.
set -uo pipefail

ETC=/etc/plxfuzz
STATE=/var/lib/plxfuzz/state
SRC=/var/lib/plxfuzz/src
VERIFY_TRIES=10
VERIFY_SLEEP=12

read_cfg() { [ -r "$ETC/$1" ] && tr -d ' \t\r\n' < "$ETC/$1" || true; }

NODE_ID="$(read_cfg node-id)"
REPO="$(read_cfg repo)";        REPO="${REPO:-yuzeguitarist/ParallaX}"
TAG="$(read_cfg campaign-tag)"; TAG="${TAG:-fuzz-corpus-84c78add}"
export GH_REPO="$REPO"
export GH_TOKEN="${GH_TOKEN:-$(read_cfg pat)}"   # env, never argv (matches sync.sh)

# --- shard table: which targets this box OWNS (canonical asset writer) ------
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
type owner_box >/dev/null 2>&1 || owner_box() { :; }

# Resolve sibling scripts (copied to /var/lib/plxfuzz/bin, else src tree).
resolve() {
  local name="$1" c
  for c in "$SCRIPT_DIR/$name" "$SRC/ops/fuzz-cluster/bin/$name"; do
    if [ -r "$c" ]; then printf '%s' "$c"; return 0; fi
  done
  return 1
}
SYNC="$(resolve sync.sh   || true)"
STATUS="$(resolve status.sh || true)"

# --- 1. stop the fuzzers cleanly -------------------------------------------
echo "drain[$NODE_ID]: stopping plx-fuzz@* (clean finish)"
systemctl stop 'plx-fuzz@*' 2>/dev/null || true

# --- 2. final forced sync + status -----------------------------------------
if [ -n "$SYNC" ]; then
  echo "drain[$NODE_ID]: final sync.sh"
  bash "$SYNC" 2>/dev/null || true
else
  echo "drain[$NODE_ID]: sync.sh not found; relying on verify + final status"
fi
if [ -n "$STATUS" ]; then
  echo "drain[$NODE_ID]: final status.sh"
  bash "$STATUS" 2>/dev/null || true
fi

# --- 3. verification --------------------------------------------------------
# (a) Release is reachable and the canonical assets THIS box owns are present.
owned_assets_present() {
  local out t want
  out="$(gh release view "$TAG" --json assets --jq '.assets[].name' 2>/dev/null || true)"
  [ -n "$out" ] || return 1
  for t in $ALL_TARGETS; do
    [ "$(owner_box "$t" 2>/dev/null)" = "$NODE_ID" ] || continue
    want="corpus-$t.tar.zst"
    printf '%s\n' "$out" | grep -qx "$want" || return 1
  done
  return 0
}

# (b) the fuzz-status push landed in THIS drain run. status.sh stamps
#     last-status-ts on a successful push; require it to be fresh (this run).
status_pushed_recently() {
  local f="$STATE/last-status-ts"
  [ -r "$f" ] || return 1
  local ts age now
  ts="$(stat -c %Y "$f" 2>/dev/null || echo 0)"
  now="$(date +%s)"
  age=$(( now - ts ))
  [ "$age" -ge 0 ] && [ "$age" -le 300 ]   # written within the last 5 min
}

ok_release=1
ok_status=1
i=0
while [ "$i" -lt "$VERIFY_TRIES" ]; do
  i=$(( i + 1 ))
  owned_assets_present && ok_release=0 || ok_release=1
  status_pushed_recently && ok_status=0 || ok_status=1
  if [ "$ok_release" -eq 0 ] && [ "$ok_status" -eq 0 ]; then
    break
  fi
  echo "drain[$NODE_ID]: verify attempt $i (release_ok=$([ $ok_release -eq 0 ] && echo y || echo n) status_ok=$([ $ok_status -eq 0 ] && echo y || echo n)); retrying"
  # nudge another push attempt before the next check
  [ "$ok_status" -ne 0 ] && [ -n "$STATUS" ] && { bash "$STATUS" 2>/dev/null || true; }
  [ "$ok_release" -ne 0 ] && [ -n "$SYNC" ]  && { bash "$SYNC"   2>/dev/null || true; }
  sleep "$VERIFY_SLEEP" 2>/dev/null || true
done

if [ "$ok_release" -eq 0 ] && [ "$ok_status" -eq 0 ]; then
  echo "drain[$NODE_ID]: VERIFIED corpus Release + fuzz-status push — safe to destroy box"
  exit 0
fi
echo "drain[$NODE_ID]: UNCONFIRMED after $VERIFY_TRIES tries (release_ok=$ok_release status_ok=$ok_status) — do NOT destroy until checked"
exit 1
