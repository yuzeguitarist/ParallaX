# Protocol Benchmarks

> Navigation: [Index](README.md) | [Probing & Benchmarking](<Probing-&-Benchmarking.md>) | [Protocol](Protocol-Commands-&-Data-Records.md)

## Purpose

`plx bench` runs a fixed-parameter CPU benchmark suite. It is not a tuning
framework. Case counts, iteration tiers, and payload sizes are baked into
`src/bench.rs` to keep results comparable across releases.

## Commands

```bash
plx bench
plx bench --quick
plx bench --json
plx bench --quick --json
```

`--quick` scales iteration counts down for smoke testing. It does not change
which cases exist.

## Current suite

Current `main` runs 58 cases across six groups:

| Group | Examples |
|---|---|
| `handshake.crypto` | X25519 keygen/DH, ML-KEM keygen/encap/decap, ML-DSA sign/verify, HKDF rekeys. |
| `handshake.protocol` | Safari ClientHello start, ClientHello parse/auth verify, server inbound decision, PQ rekey records, borrowed/owned command decode, identity chunk encode/decode/verify. |
| `record.aead` | Raw AEAD seal/open at fixed payload sizes. |
| `record.pipeline` | Full TLS ApplicationData record pipeline, chunking, in-place open, 1 MiB bulk paths, TLS record reader. |
| `traffic` | Padding apply/remove with default and configured profiles. |
| `state` | Replay-cache insertion. |

## Text output

The text table reports:

- group
- case
- iterations
- nanoseconds per operation
- operations per second
- MiB/sec for payload-processing cases
- total elapsed time

## JSON output

JSON output contains:

- `version`
- `quick`
- `total_elapsed_ns`
- `cases[]`
  - `group`
  - `name`
  - `iterations`
  - `warmup`
  - `elapsed_ns`
  - `ns_per_op`
  - `ops_per_second`
  - `processed_bytes`
  - `mib_per_second`

## Maintenance rule

Adding, removing, or renaming a benchmark changes the baseline schema and should
be treated as a deliberate release-visible action.
