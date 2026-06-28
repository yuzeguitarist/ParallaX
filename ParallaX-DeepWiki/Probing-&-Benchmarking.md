# Probing & Benchmarking

> Navigation: [Index](README.md) | [Camouflage Probe](Camouflage-Target-Probe.md) | [Protocol Benchmarks](Protocol-Benchmarks.md)

ParallaX has four different evidence tools. They answer different questions.

| Tool | Command | Question answered |
|---|---|---|
| Camouflage probe | `plx probe` | Is this fallback origin a good TLS camouflage candidate? |
| CPU benchmark | `plx bench` | How fast are fixed local protocol primitives and record pipelines? |
| Network speed evidence | `plx speed` | What throughput does this configured client/server path produce now? |
| Network regression matrix | `plx netmatrix` | How does throughput hold up across a fixed RTT × bandwidth sweep, reproducibly, on one machine? |

## `plx probe`

`probe` tests an ordinary TLS target. It does not require a ParallaX server.
See [Camouflage Target Probe](Camouflage-Target-Probe.md).

## `plx bench`

`bench` is local and CPU-only. It has fixed case counts and payload sizes so
results can be compared across releases. See
[Protocol Benchmarks](Protocol-Benchmarks.md).

## `plx speed`

`speed` performs a real ParallaX handshake and data transfer against the
configured server. It emits text or JSON evidence with:

- schema `parallax.speed.evidence.v1`
- config fingerprint
- server address and SNI
- traffic profile
- handshake and warmup timings
- three measured download samples
- three measured upload samples
- median/mean/min/max/stddev throughput summaries

Do not run `plx client` and `plx speed` for the same config at the same time;
the runtime guard is designed to fail fast in that case.

## `plx netmatrix`

`netmatrix` (`src/netmatrix.rs`) reuses the `plx speed` data path but interposes
an **emulated loopback shaper** between the client and the configured server, so it
is reproducible on one machine instead of depending on live-network conditions. It
sweeps a fixed 8-cell matrix of network impairments, each applied symmetrically to
both directions:

- a clean-link RTT ladder (`clean-0ms`, `rtt-20ms`, `rtt-80ms`, `rtt-160ms`),
- two bandwidth-constrained high-RTT rows (`rtt-160ms-bw-50`, `rtt-160ms-bw-20`,
  `rtt-320ms-bw-20`),
- one named `real-180ms-bw-60` profile shaped after a China↔Germany path.

The shaper applies one-way latency via a delay line plus an optional token-bucket
bandwidth cap. It covers **latency and bandwidth only** — TCP-based emulation cannot
inject packet loss or reordering, which need a Linux `netns` + `tc qdisc netem`
setup. Requires client mode with `client.server_addr` set. Text output is a table;
`--json` emits schema `parallax.netmatrix.v1` with per-cell `profile`, `rtt_ms`,
`bandwidth_mbit`, `handshake_ms`, `download_median_mbps`, and `upload_median_mbps`.

The upload figure is a loose upper bound (client write-completion time, not
server-receive time); the download figure is accurate.

## Recommended use

1. Use `plx probe` before choosing a fallback.
2. Use `plx bench --quick` for local smoke checks.
3. Use full `plx bench` for release/performance baselines.
4. Use `plx speed --json` when archiving real network evidence.
5. Use `plx netmatrix --json` for reproducible RTT/bandwidth regression sweeps.
6. Use `cargo test --test gfw_simulator` for adversary-model regressions.
