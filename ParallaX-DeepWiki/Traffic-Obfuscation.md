# Traffic Obfuscation

> Navigation: [Index](README.md) | [Padding & Timing](<Padding-&-Timing-Profiles.md>) | [Cover Traffic](Cover-Traffic.md)

## Scope

Traffic obfuscation is implemented in `src/traffic.rs` and integrated by the
client/server data relay paths. It has three knobs:

- padding
- timing jitter
- cover traffic

Generated configs disable all three for speed-first operation.

## Configuration knobs

```toml
[traffic]
min_padding = 0
max_padding = 0
min_delay_ms = 0
max_delay_ms = 0
cover_min_interval_ms = 0
cover_max_interval_ms = 0
max_concurrent_streams = 1
```

`max_concurrent_streams` is intentionally constrained to `1` until a
fingerprint-safe multiplexing scheduler exists.

## Integration points

| Feature | Used by | Effect |
|---|---|---|
| Padding profile | `DataRecordCodec` | Adds random-length padding and a 2-byte padding-length trailer before AEAD sealing. |
| Timing profile | server identity chunk writer and relay paths | Adds bounded delay only when enabled. |
| Cover traffic profile | client/server relay loops | Schedules dummy traffic only when interval max is non-zero. |

## Important caveat

Traffic shaping can help avoid some simplistic size/timing signatures, but it
can also harm throughput or introduce new signatures if configured without
measurement. Keep the generated zeroed defaults unless you have a concrete
validation plan.

Related pages: [Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md),
[Protocol Benchmarks](Protocol-Benchmarks.md), and
[GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>).
