# Cover Traffic

> Navigation: [Index](README.md) | [Traffic Obfuscation](Traffic-Obfuscation.md) | [Padding & Timing](<Padding-&-Timing-Profiles.md>)

## Purpose

Cover traffic sends dummy encrypted records at configured intervals so an idle
connection does not necessarily look idle. It is disabled by generated configs.

## Configuration

```toml
cover_min_interval_ms = 0
cover_max_interval_ms = 0
```

Behavior:

- `cover_max_interval_ms = 0` disables cover traffic.
- If enabled and `min >= max`, sampling collapses to the minimum.
- Otherwise the interval is sampled within the configured range.

## Runtime integration

The client and server relay loops construct `CoverTrafficProfile` from the
loaded `TrafficConfig`. Dummy traffic is sealed with the same data-record codec
as normal payloads, so it retains TLS ApplicationData shape and AEAD integrity.

## Tradeoffs

Cover traffic can make idle periods less distinct, but it also:

- consumes bandwidth
- can create its own periodic signature
- complicates throughput measurements
- should be validated against the GFW simulator or external captures before
  being treated as an improvement

For most operations, keep cover traffic disabled and use `plx speed` plus real
packet captures when changing it.
