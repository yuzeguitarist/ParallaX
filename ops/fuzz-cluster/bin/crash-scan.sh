#!/usr/bin/env bash
# ops/fuzz-cluster/bin/crash-scan.sh
# GROUP 3 — reliable crash reporting. Runs every few minutes from the
# plx-crashscan timer (as plxfuzz).
#
# WHY this exists: systemd OnFailure= is NOT a reliable crash trigger under
# Restart=always. A crashing fuzz unit goes failed -> auto-restart WITHOUT
# firing OnFailure; once it hits StartLimitBurst the unit enters a terminal
# failed state ("start request repeated too quickly") which ALSO does not fire
# OnFailure. So crashes can pile up in fuzz/artifacts/<t>/ and never get filed.
# This scanner decouples reporting from OnFailure: it periodically sweeps every
# target's artifact dir and runs crash-push.sh for any with UNFILED artifacts.
# crash-push is idempotent (it renames handled artifacts *.handled and dedups by
# bugkey), so the OnFailure fast-path and this sweep never double-file.
set -uo pipefail

export CARGO_HOME="${CARGO_HOME:-/var/lib/plxfuzz/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/var/lib/plxfuzz/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

SRC="${PLXFUZZ_SRC:-/var/lib/plxfuzz/src}"
BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Authoritative ALL_TARGETS from the shard table (fallback hard-codes the 14).
for cand in \
  "$BIN/lib/shard-table.sh" \
  "$BIN/../lib/shard-table.sh" \
  "$SRC/ops/fuzz-cluster/lib/shard-table.sh"; do
  # shellcheck source=/dev/null
  if [ -r "$cand" ]; then . "$cand"; break; fi
done
if ! declare -p ALL_TARGETS >/dev/null 2>&1; then
  ALL_TARGETS="tls_client_hello tls_server_hello tls_compressed_cert mux_frame server_decide_inbound client_hello_auth command_codecs http2_frame_header data_record_open replay_journal socks_connect_request udp_envelope udp_reorder replay_dedup"
fi

[ -d "$SRC" ] || { echo "crash-scan: source tree $SRC missing"; exit 0; }

filed=0
for t in $ALL_TARGETS; do
  d="$SRC/fuzz/artifacts/$t"
  [ -d "$d" ] || continue
  # Any UNFILED crash/oom/timeout artifact? (handled ones are renamed *.handled)
  if find "$d" -maxdepth 1 -type f \
       \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' \) \
       ! -name '*.handled' -print -quit 2>/dev/null | grep -q .; then
    echo "crash-scan: $t has unfiled artifacts -> crash-push"
    "$BIN/crash-push.sh" "$t" || true
    filed=$((filed + 1))
  fi
done
[ "$filed" -gt 0 ] || echo "crash-scan: no unfiled artifacts"
exit 0
