# Probing & Benchmarking

> Navigation: [Index](README.md) | [Camouflage Probe](Camouflage-Target-Probe.md) | [Protocol Benchmarks](Protocol-Benchmarks.md)

ParallaX has three different evidence tools. They answer different questions.

| Tool | Command | Question answered |
|---|---|---|
| Camouflage probe | `plx probe` | Is this fallback origin a good TLS camouflage candidate? |
| CPU benchmark | `plx bench` | How fast are fixed local protocol primitives and record pipelines? |
| Network speed evidence | `plx speed` | What throughput does this configured client/server path produce now? |

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

## Recommended use

1. Use `plx probe` before choosing a fallback.
2. Use `plx bench --quick` for local smoke checks.
3. Use full `plx bench` for release/performance baselines.
4. Use `plx speed --json` when archiving real network evidence.
5. Use `cargo test --test gfw_simulator` for adversary-model regressions.
