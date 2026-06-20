#!/usr/bin/env bash
# ParallaX local fuzz runner (Track B). LOCAL ONLY — no CI.
# Usage:
#   fuzz/run.sh smoke [target...]            # 45s each, all targets if none named
#   fuzz/run.sh long  [target...]            # night run, per-target time below
#   fuzz/run.sh cmin  [target...]            # minimize corpus (backs up first)
#   fuzz/run.sh repro <target> <artifact>    # reproduce one crash file
set -u

# Resolve repo root = parent of this script's dir (script lives in fuzz/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

FUZZ="cargo +nightly fuzz"
ALL_TARGETS="tls_client_hello tls_server_hello tls_compressed_cert mux_frame server_decide_inbound client_hello_auth command_codecs http2_frame_header data_record_open replay_journal socks_connect_request udp_envelope udp_reorder replay_dedup mldsa_verify h3_frame_decode h3_settings_parse h3_qpack_field_section"

# Per-target tuning. Fields: RSS_MB TIMEOUT_S LONG_TIME_S WORKERS
# (WORKERS feeds libFuzzer -workers/-jobs; keep total <= phys cores / RAM budget.)
tune() {
  case "$1" in
    tls_compressed_cert)   echo "2048 25 7200 2" ;;   # high RSS for the zlib bomb (H1)
    server_decide_inbound) echo "4096 25 7200 2" ;;   # crypto-heavy; workers=2 to bound RAM
    client_hello_auth)     echo "4096 25 7200 2" ;;   # HMAC path; workers=2 to bound RAM
    data_record_open)      echo "2048 25 3600 2" ;;   # AEAD open + seal/open roundtrip
    tls_client_hello)      echo "2048 20 3600 2" ;;
    tls_server_hello)      echo "2048 20 3600 2" ;;
    mux_frame)             echo "2048 20 3600 2" ;;
    *)                     echo "2048 25 3600 2" ;;
  esac
}

# Extra per-target libFuzzer flags. The H1 bomb seed is ~3 MB, far over the
# default -max_len=4096, so libFuzzer would silently drop it without this.
extra_args() {
  case "$1" in
    tls_compressed_cert) printf -- '-max_len=4194304' ;;
    *) : ;;
  esac
}

dict_arg() {  # echo -dict=... if the file exists
  local d="fuzz/$1.dict"
  [ -f "$d" ] && printf -- '-dict=%s' "$d"
}

corpus_args() {  # main corpus dir + curated seeds dir (if present)
  local t="$1"
  printf 'fuzz/corpus/%s' "$t"
  [ -d "fuzz/seeds/$t" ] && printf ' fuzz/seeds/%s' "$t"
}

MODE="${1:-smoke}"; shift || true
TARGETS="${*:-$ALL_TARGETS}"

FAILED=""
SUMMARY=""

run_one() {
  local t="$1" maxtime="$2"
  read -r RSS TMO LONG WK <<EOF
$(tune "$t")
EOF
  local d; d="$(dict_arg "$t")"
  local x; x="$(extra_args "$t")"
  local cargs; cargs="$(corpus_args "$t")"
  echo "=================================================================="
  echo ">> [$t] max_total_time=${maxtime}s rss=${RSS}MB timeout=${TMO}s ${x} (single in-process)"
  echo "=================================================================="
  # Run ONE in-process fuzzer (no -jobs/-workers) so libFuzzer's parent exit code
  # and -print_final_stats authoritatively reflect a crash. Under -jobs the
  # launcher can exit 0 even when a worker process crashed, hiding the crash.
  # shellcheck disable=SC2086
  $FUZZ run "$t" $cargs -- \
      ${d} ${x} \
      -rss_limit_mb="$RSS" \
      -timeout="$TMO" \
      -max_total_time="$maxtime" \
      -print_final_stats=1
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    FAILED="$FAILED $t"
    local art; art="$(ls -t fuzz/artifacts/$t/ 2>/dev/null | head -1)"
    SUMMARY="$SUMMARY\n  [$t] EXIT=$rc  newest_artifact=fuzz/artifacts/$t/${art:-<none>}"
  else
    SUMMARY="$SUMMARY\n  [$t] clean (exit 0)"
  fi
}

case "$MODE" in
  smoke)
    for t in $TARGETS; do run_one "$t" 45; done ;;
  long)
    for t in $TARGETS; do
      read -r _ _ LONG _ <<EOF
$(tune "$t")
EOF
      run_one "$t" "$LONG"
    done ;;
  cmin)
    for t in $TARGETS; do
      read -r RSS _ _ _ <<EOF
$(tune "$t")
EOF
      ts="$(date +%Y%m%d-%H%M%S)"
      if [ -d "fuzz/corpus/$t" ]; then
        cp -R "fuzz/corpus/$t" "fuzz/corpus/$t.bak-$ts"
        echo ">> backed up fuzz/corpus/$t -> fuzz/corpus/$t.bak-$ts"
      fi
      # shellcheck disable=SC2086
      $FUZZ cmin "$t" -- -rss_limit_mb="$RSS" || FAILED="$FAILED $t(cmin)"
    done ;;
  repro)
    T="${1:?repro needs <target>}"; A="${2:?repro needs <artifact>}"
    read -r RSS TMO _ _ <<EOF
$(tune "$T")
EOF
    x="$(extra_args "$T")"
    # shellcheck disable=SC2086
    exec $FUZZ run "$T" "$A" -- ${x} -rss_limit_mb="$RSS" -timeout="$TMO" -runs=1 ;;
  *)
    echo "unknown mode: $MODE (use smoke|long|cmin|repro)"; exit 2 ;;
esac

echo
echo "================== FUZZ SUMMARY ($MODE) =================="
printf '%b\n' "$SUMMARY"
if [ -n "$FAILED" ]; then
  echo "CRASHES/FAILURES in:$FAILED"
  echo "Reproduce: fuzz/run.sh repro <target> fuzz/artifacts/<target>/<file>"
  exit 1
fi
echo "all clean"
