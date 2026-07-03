#!/usr/bin/env bash
# ParallaX end-to-end GFW lab orchestrator.
#
# Topology (single host, loopback):
#
#   trafficgen --SOCKS5--> plx client --TCP/UDP--> [ gfw-box ] --> plx server --> origin (HTTP)
#                                                   (MITM censor)
#                                                   link impairment
#                                                   + traffic analysis
#
# The gfw-box transparently relays the wire traffic while (a) applying a
# link-quality profile in userspace and (b) passively fingerprinting every flow
# the way a national middle-box would. A separate active differential probe
# compares the ParallaX server's response to unauthenticated probes against the
# genuine reference origin it camouflages as.
#
# The camouflage handshake splices to the real fallback origin, so the run needs
# outbound internet to $FALLBACK_HOST (GitHub-hosted runners have it).
#
# Exit code 0 = PASS (all scenarios succeeded, zero flows flagged as a proxy,
# no active-probe distinguisher). Non-zero = FAIL or setup error.

set -uo pipefail

# --------------------------------------------------------------------------
# Configuration (override via environment)
# --------------------------------------------------------------------------
PLX="${PLX:?set PLX to the plx binary path}"
LAB_BIN_DIR="${LAB_BIN_DIR:?set LAB_BIN_DIR to the gfw-lab target dir}"
TRANSPORT="${TRANSPORT:-tcp}"            # tcp | quic
PROFILES="${PROFILES:-perfect broadband mobile_4g transpacific}"
# Default scenario set is transport-aware. The QUIC fast plane is a
# "single-Connect relay" (see the client's startup log), so it does not carry
# multiple *concurrent* proxied connections; the concurrency-based scenarios
# (parallel, web) are therefore TCP-only. All other shapes run on both.
if [ "${TRANSPORT}" = "quic" ]; then
  SCENARIOS="${SCENARIOS:-download upload bidirectional serial single-stream video call}"
else
  SCENARIOS="${SCENARIOS:-download upload bidirectional serial parallel single-stream video call web}"
fi
FALLBACK_HOST="${FALLBACK_HOST:-www.cloudflare.com}"
FALLBACK_PORT="${FALLBACK_PORT:-443}"
WORKDIR="${WORKDIR:-$(mktemp -d /tmp/plx-lab.XXXXXX)}"
READY_TIMEOUT="${READY_TIMEOUT:-30}"

GFW_BOX="$LAB_BIN_DIR/gfw-box"
ORIGIN="$LAB_BIN_DIR/origin"
TRAFFICGEN="$LAB_BIN_DIR/trafficgen"
LABREPORT="$LAB_BIN_DIR/labreport"

# Addresses. In QUIC mode the server lives on 127.0.0.2 so the box can own the
# advertised UDP port on 127.0.0.1 without colliding with the server.
ORIGIN_ADDR="127.0.0.1:18080"
if [ "$TRANSPORT" = "quic" ]; then
  SERVER_LISTEN="127.0.0.2:8443"
  SERVER_HOST="127.0.0.2"
else
  SERVER_LISTEN="127.0.0.1:8443"
  SERVER_HOST="127.0.0.1"
fi
SERVER_PORT="8443"
BOX_TCP="127.0.0.1:9443"          # client dials this (the censor's ingress)
BOX_UDP="127.0.0.1:${SERVER_PORT}" # QUIC fast plane ingress (advertised port)
CLIENT_SOCKS="127.0.0.1:1080"

mkdir -p "$WORKDIR"
echo "== ParallaX GFW lab =="
echo "   transport   : $TRANSPORT"
echo "   profiles    : $PROFILES"
echo "   scenarios   : $SCENARIOS"
echo "   fallback    : $FALLBACK_HOST:$FALLBACK_PORT"
echo "   workdir     : $WORKDIR"

PIDS=()
cleanup() {
  echo "== cleanup =="
  for pid in "${PIDS[@]:-}"; do
    [ -n "${pid:-}" ] && kill -TERM "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in "${PIDS[@]:-}"; do
    [ -n "${pid:-}" ] && kill -KILL "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

wait_for_log() { # <file> <pattern> <timeout>
  local file="$1" pat="$2" to="$3" i=0
  while [ "$i" -lt "$to" ]; do
    [ -f "$file" ] && grep -q "$pat" "$file" 2>/dev/null && return 0
    sleep 1; i=$((i+1))
  done
  echo "!! timed out waiting for '$pat' in $file"; tail -n 20 "$file" 2>/dev/null || true
  return 1
}

# --------------------------------------------------------------------------
# 1. Preflight: fallback origin reachable over IPv4? (retry a few times so a
#    transient egress blip does not turn CI red — exit 3 = environment error.)
# --------------------------------------------------------------------------
reachable=0
for attempt in 1 2 3 4; do
  if curl -4 -sS -o /dev/null --max-time 15 "https://$FALLBACK_HOST:$FALLBACK_PORT/" 2>/dev/null; then
    reachable=1; break
  fi
  echo "-- fallback preflight attempt $attempt failed; retrying"
  sleep $((attempt * 3))
done
if [ "$reachable" -ne 1 ]; then
  echo "!! fallback origin https://$FALLBACK_HOST:$FALLBACK_PORT unreachable over IPv4."
  echo "   The authenticated handshake requires it; aborting as an environment error (exit 3)."
  exit 3
fi
echo "-- fallback origin reachable"

# --------------------------------------------------------------------------
# 2. Generate paired configs (client dials the BOX, not the server directly)
# --------------------------------------------------------------------------
rm -f "$WORKDIR"/parallax.*.toml
"$PLX" init "$FALLBACK_HOST:$FALLBACK_PORT" \
  --server-addr "$BOX_TCP" \
  --server-listen "$SERVER_LISTEN" \
  --client-listen "$CLIENT_SOCKS" \
  --inline-secrets -o "$WORKDIR" >/dev/null || { echo "!! plx init failed"; exit 3; }

SERVER_CFG="$WORKDIR/parallax.server.toml"
CLIENT_CFG="$WORKDIR/parallax.client.toml"

# Rewrite the generated server config for a hermetic, writable, controlled run:
#   * replay cache in the workdir (default /var/lib is not writable),
#   * data_target pinned to the local origin (operator-fixed target bypasses the
#     SSRF screen so all proxied bytes land on our HTTP origin),
#   * enable the UDP fast plane in QUIC mode.
if ! python3 - "$SERVER_CFG" "$WORKDIR/replay.cache" "$ORIGIN_ADDR" "$TRANSPORT" <<'PY'
import sys
cfg, replay, origin, transport = sys.argv[1:5]
lines = open(cfg).read().splitlines()
out = []
for ln in lines:
    if ln.startswith("replay_cache_path"):
        ln = f'replay_cache_path = "{replay}"'
    out.append(ln)
text = "\n".join(out)
# Pin the relay target to the local origin (operator-fixed target bypasses the
# SSRF screen so all proxied bytes land on our controlled HTTP endpoint).
if "[server]\n" not in text:
    print("no [server] section to inject data_target into", file=sys.stderr)
    sys.exit(1)
text = text.replace("[server]\n", f'[server]\ndata_target = "{origin}"\n', 1)
if transport == "quic":
    text += "\n\n[udp]\nenabled = true\n"
open(cfg, "w").write(text + "\n")
PY
then
  echo "!! server config rewrite failed"; exit 3
fi

# Assert the critical rewrite actually took effect (guards against a silent
# no-op, since the script runs without `set -e`).
grep -q '^data_target' "$SERVER_CFG" || { echo "!! data_target not injected into server config"; exit 3; }

if [ "$TRANSPORT" = "quic" ]; then
  printf '\n[udp]\nenabled = true\n' >> "$CLIENT_CFG"
fi
chmod 600 "$SERVER_CFG" "$CLIENT_CFG"

"$PLX" check -c "$SERVER_CFG" >/dev/null 2>&1 || { echo "!! server config invalid"; "$PLX" check -c "$SERVER_CFG"; exit 3; }
"$PLX" check -c "$CLIENT_CFG" >/dev/null 2>&1 || { echo "!! client config invalid"; "$PLX" check -c "$CLIENT_CFG"; exit 3; }
echo "-- configs generated and validated"

# --------------------------------------------------------------------------
# 3. Start origin + server
# --------------------------------------------------------------------------
"$ORIGIN" --listen "$ORIGIN_ADDR" >"$WORKDIR/origin.log" 2>&1 &
PIDS+=("$!")
wait_for_log "$WORKDIR/origin.log" "origin listening" 10 || exit 3

RUST_LOG=parallax=info "$PLX" serve -c "$SERVER_CFG" >"$WORKDIR/server.log" 2>&1 &
PIDS+=("$!")
wait_for_log "$WORKDIR/server.log" "server listening on" "$READY_TIMEOUT" || exit 3
echo "-- origin + server up"

FAIL=0
SCEN_ARGS=()

# --------------------------------------------------------------------------
# 4. For each link profile: (re)start the box, run scenarios + speed
# --------------------------------------------------------------------------
for PROFILE in $PROFILES; do
  echo "== link profile: $PROFILE =="
  BOX_REPORT="$WORKDIR/box-$PROFILE.json"
  BOX_LOG="$WORKDIR/box-$PROFILE.log"

  UDP_ARGS=()
  if [ "$TRANSPORT" = "quic" ]; then
    UDP_ARGS=(--udp-listen "$BOX_UDP" --udp-upstream "$SERVER_HOST:$SERVER_PORT")
  fi
  "$GFW_BOX" relay --listen "$BOX_TCP" --upstream "$SERVER_HOST:$SERVER_PORT" \
    "${UDP_ARGS[@]}" --profile "$PROFILE" --report "$BOX_REPORT" >"$BOX_LOG" 2>&1 &
  BOX_PID="$!"
  PIDS+=("$BOX_PID")
  # Wait for the post-bind readiness line (printed only once the ingress socket
  # is actually listening).
  wait_for_log "$BOX_LOG" "gfw-box relay listening" 10 || { FAIL=1; }
  if [ "$TRANSPORT" = "quic" ]; then
    wait_for_log "$BOX_LOG" "gfw-box udp relay listening" 10 || { FAIL=1; }
  fi

  # Start the client (dials the box).
  CLIENT_LOG="$WORKDIR/client-$PROFILE.log"
  RUST_LOG=parallax=info "$PLX" client -c "$CLIENT_CFG" >"$CLIENT_LOG" 2>&1 &
  CLIENT_PID="$!"
  PIDS+=("$CLIENT_PID")
  wait_for_log "$CLIENT_LOG" "client SOCKS5 listening on" "$READY_TIMEOUT" || { FAIL=1; }

  # Hostile links (high loss/latency) legitimately need a bigger budget for the
  # large bulk transfers than a fast link does.
  case "$PROFILE" in
    lossy|satellite|mobile_3g) SCEN_TIMEOUT=300 ;;
    *) SCEN_TIMEOUT=120 ;;
  esac

  # Run each traffic scenario through the SOCKS port.
  for S in $SCENARIOS; do
    OUT="$WORKDIR/scenario-$PROFILE-$S.json"
    if "$TRAFFICGEN" --socks "$CLIENT_SOCKS" --connect-host origin.internal --connect-port 80 \
        --scenario "$S" --link-name "$PROFILE" --timeout-secs "$SCEN_TIMEOUT" \
        --report "$OUT" >>"$WORKDIR/trafficgen.log" 2>&1; then
      echo "   [ok]   $S"
    else
      echo "   [FAIL] $S"
      FAIL=1
    fi
    [ -f "$OUT" ] && SCEN_ARGS+=(--scenario "$OUT")
  done

  # Stop the client so `plx speed` (RuntimeGuard) can run over the same box.
  kill -TERM "$CLIENT_PID" 2>/dev/null || true
  sleep 2

  # Throughput evidence over the impaired link (also analysed by the box).
  SPEED_OUT="$WORKDIR/speed-$PROFILE.json"
  if timeout 120 "$PLX" speed -c "$CLIENT_CFG" --json >"$SPEED_OUT" 2>"$WORKDIR/speed-$PROFILE.err"; then
    echo "   [ok]   plx speed"
  else
    echo "   [warn] plx speed did not complete (see speed-$PROFILE.err)"
  fi

  # Stop the box so it flushes its passive analysis report. Block on the
  # process (it exits only after writing the report) instead of a fixed sleep,
  # so a slow flush on a loaded runner cannot cause a false "no report" FAIL.
  kill -TERM "$BOX_PID" 2>/dev/null || true
  wait "$BOX_PID" 2>/dev/null || true
  if [ -f "$BOX_REPORT" ]; then
    FLAGGED=$(python3 -c "import json;print(json.load(open('$BOX_REPORT'))['flagged_flows'])" 2>/dev/null || echo "?")
    TOTAL=$(python3 -c "import json;print(json.load(open('$BOX_REPORT'))['total_flows'])" 2>/dev/null || echo "?")
    echo "   passive: $TOTAL flows, $FLAGGED flagged as proxy"
    [ "$FLAGGED" != "0" ] && FAIL=1
  else
    echo "   !! no box report produced"; FAIL=1
  fi
done

# --------------------------------------------------------------------------
# 5. Active differential probe (direct to server, A/B vs reference origin)
# --------------------------------------------------------------------------
PROBE_REPORT="$WORKDIR/probe.json"
"$GFW_BOX" probe --server "$SERVER_HOST:$SERVER_PORT" \
  --reference "$FALLBACK_HOST:$FALLBACK_PORT" --sni "$FALLBACK_HOST" \
  --report "$PROBE_REPORT" >"$WORKDIR/probe.log" 2>&1 || true

# --------------------------------------------------------------------------
# 6. Assemble the verdict
# --------------------------------------------------------------------------
# Pass EVERY per-profile box report so the verdict aggregates all profiles.
BOX_ARG=()
for BR in "$WORKDIR"/box-*.json; do
  [ -f "$BR" ] && BOX_ARG+=(--box-report "$BR")
done
PROBE_ARG=()
[ -f "$PROBE_REPORT" ] && PROBE_ARG=(--probe "$PROBE_REPORT")

echo "== verdict =="
if "$LABREPORT" --transport "$TRANSPORT" "${SCEN_ARGS[@]}" \
    "${PROBE_ARG[@]}" "${BOX_ARG[@]}" --out "$WORKDIR/lab-report.json"; then
  LAB_PASS=0
else
  LAB_PASS=1
fi

echo "== artifacts in $WORKDIR =="
ls -1 "$WORKDIR"/*.json 2>/dev/null | sed 's/^/   /'

if [ "$FAIL" -ne 0 ] || [ "$LAB_PASS" -ne 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
exit 0
