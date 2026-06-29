#!/usr/bin/env bash
# netem-bdp-bench.sh — Linux netns + tc/netem single-connection throughput
# bench for the ParallaX TCP data plane over a high-BDP, send-throttled link.
#
# WHY THIS EXISTS
# ---------------
# `plx netmatrix` uses a userspace TCP-stream shaper. That shaper buffers up to
# tens of MiB inside its own delay-line channel, so it can NOT exert real
# cwnd/sndbuf backpressure on the sender — it measures latency and bandwidth but
# structurally cannot reproduce the "sndbuf < BDP starves the pipe" regime where
# an application-layer single-write-in-flight relay loop would cap throughput at
# one batch per RTT. This bench builds a real kernel path (veth + netem delay +
# a bounded bottleneck queue) so the sender is genuinely backpressured, which is
# the only environment in which the multi-batch in-flight pipeline change can be
# observed to help (or proven a no-op).
#
# WHAT IT DOES
# ------------
# 1. Creates two network namespaces joined by a veth pair.
# 2. Adds a one-way netem delay on each veth end => a configurable RTT, plus a
#    token-bucket rate (tbf) and a bounded queue so the bandwidth-delay product
#    is finite and the sender is backpressured rather than absorbing the whole
#    BDP into a large local socket buffer.
# 3. Runs `plx serve` in the server ns and `plx speed --json` in the client ns,
#    pointed across the shaped link, and prints the JSON throughput report.
#
# Requires root (ip netns / tc). Designed to run on a GitHub Actions
# ubuntu-latest runner (which grants passwordless sudo) and is equally runnable
# on any Linux box / VPS for a real-link sanity check.
#
# Usage:
#   sudo PLX_BIN=./target/release/plx RTT_MS=150 RATE_MBIT=100 \
#        scripts/netem-bdp-bench.sh
#
# Env knobs (all optional, with defaults):
#   PLX_BIN     path to the plx binary           (default: ./target/release/plx)
#   RTT_MS      round-trip delay in milliseconds (default: 150)
#   RATE_MBIT   per-direction rate cap in Mbit/s (default: 100)
#   QUEUE_KB    bottleneck queue depth in KiB    (default: derived ~0.5*BDP)
#   WORKDIR     scratch dir for configs/logs     (default: mktemp -d)
#   OUT_JSON    where to write the speed JSON     (default: $WORKDIR/speed.json)
set -euo pipefail

PLX_BIN="${PLX_BIN:-./target/release/plx}"
RTT_MS="${RTT_MS:-150}"
RATE_MBIT="${RATE_MBIT:-100}"
WORKDIR="${WORKDIR:-$(mktemp -d)}"
OUT_JSON="${OUT_JSON:-$WORKDIR/speed.json}"

# One-way delay is half the RTT.
HALF_RTT_MS=$(( RTT_MS / 2 ))

# Bandwidth-delay product (bytes) = rate(bytes/s) * RTT(s).
#   rate_bytes_per_s = RATE_MBIT * 125000
#   bdp_bytes        = rate_bytes_per_s * RTT_MS / 1000
BDP_BYTES=$(( RATE_MBIT * 125000 * RTT_MS / 1000 ))
# Bottleneck queue: ~0.5x BDP so the link is genuinely backpressured (a queue
# >= BDP would hide the single-in-flight cost the way netmatrix does). Floor at
# 64 KiB so tiny configs still pass a couple of segments.
QUEUE_KB="${QUEUE_KB:-$(( (BDP_BYTES / 2 / 1024) > 64 ? (BDP_BYTES / 2 / 1024) : 64 ))}"

SNS_S="plxbenchS"
SNS_C="plxbenchC"
VETH_S="vethS"
VETH_C="vethC"
IP_S="10.123.0.1"
IP_C="10.123.0.2"
PORT="8443"

abs_plx="$(cd "$(dirname "$PLX_BIN")" && pwd)/$(basename "$PLX_BIN")"

log() { printf '[netem-bench] %s\n' "$*" >&2; }

cleanup() {
  set +e
  if [[ -n "${SRV_PID:-}" ]]; then kill "$SRV_PID" 2>/dev/null; fi
  ip netns del "$SNS_S" 2>/dev/null
  ip netns del "$SNS_C" 2>/dev/null
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  log "must run as root (ip netns / tc)"; exit 2
fi
if [[ ! -x "$abs_plx" ]]; then
  log "plx binary not found/executable at: $abs_plx"; exit 2
fi

log "RTT=${RTT_MS}ms half=${HALF_RTT_MS}ms rate=${RATE_MBIT}Mbit BDP=${BDP_BYTES}B queue=${QUEUE_KB}KiB"

# --- build the shaped netns topology -------------------------------------------------
ip netns add "$SNS_S"
ip netns add "$SNS_C"
ip link add "$VETH_S" netns "$SNS_S" type veth peer name "$VETH_C" netns "$SNS_C"

ip -n "$SNS_S" addr add "${IP_S}/24" dev "$VETH_S"
ip -n "$SNS_C" addr add "${IP_C}/24" dev "$VETH_C"
ip -n "$SNS_S" link set "$VETH_S" up
ip -n "$SNS_C" link set "$VETH_C" up
ip -n "$SNS_S" link set lo up
ip -n "$SNS_C" link set lo up

# Egress shaping on BOTH ends: tbf (rate cap + bounded queue) with netem (delay)
# as a child. tbf's `limit` is the bottleneck queue that backpressures the
# sender; netem adds the one-way latency. Together: a finite-BDP, throttled,
# latency link with a small queue — the regime netmatrix cannot model.
shape() {
  local ns="$1" dev="$2"
  ip netns exec "$ns" tc qdisc add dev "$dev" root handle 1: tbf \
    rate "${RATE_MBIT}mbit" burst 32kb limit "${QUEUE_KB}kb"
  ip netns exec "$ns" tc qdisc add dev "$dev" parent 1: handle 10: netem \
    delay "${HALF_RTT_MS}ms"
}
shape "$SNS_S" "$VETH_S"
shape "$SNS_C" "$VETH_C"

# --- generate paired configs ---------------------------------------------------------
"$abs_plx" init cloudflare.com \
  --server-addr "${IP_S}:${PORT}" \
  --server-listen "${IP_S}:${PORT}" \
  --client-listen "127.0.0.1:1080" \
  -o "$WORKDIR" >/dev/null 2>&1

# Make the replay cache writable and tighten perms (init writes 0600 already).
sed -i "s|/var/lib/parallax/parallax-replay.cache|$WORKDIR/replay.cache|" \
  "$WORKDIR/parallax.server.toml"
chmod 600 "$WORKDIR/parallax.server.toml"

# --- run server in server-ns, speed client in client-ns ------------------------------
ip netns exec "$SNS_S" "$abs_plx" serve -c "$WORKDIR/parallax.server.toml" \
  >"$WORKDIR/server.log" 2>&1 &
SRV_PID=$!
sleep 2
if ! kill -0 "$SRV_PID" 2>/dev/null; then
  log "server failed to start"; cat "$WORKDIR/server.log" >&2; exit 1
fi

log "running plx speed across shaped link..."
ip netns exec "$SNS_C" "$abs_plx" speed -c "$WORKDIR/parallax.client.toml" --json \
  >"$OUT_JSON" 2>"$WORKDIR/speed.err" || {
    log "speed run failed"; cat "$WORKDIR/speed.err" >&2; exit 1;
  }

cat "$OUT_JSON"
log "JSON written to $OUT_JSON"
