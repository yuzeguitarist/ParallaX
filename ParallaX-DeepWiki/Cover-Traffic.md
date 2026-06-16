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

- `cover_max_interval_ms = 0` disables cover traffic (the generated default).
- When enabled, `cover_min_interval_ms == cover_max_interval_ms` uses a fixed
  interval; `min < max` samples within the range (`max < min` is rejected).

## Validation when enabled

Enabling cover traffic (`cover_max_interval_ms > 0`) adds two startup checks that
fail closed:

- `cover_min_interval_ms` must be at least `50` ms (`CoverIntervalTooSmall`), so
  the cover loop cannot spin into a high-rate, trivially fingerprintable beacon.
- Padding must be variable — `max_padding > min_padding` — or startup fails with
  `CoverRequiresVariablePadding`. With degenerate padding every cover record is
  identical-length and quasi-periodic, a constant-size beacon that is worse than
  sending no cover at all.

So a config that sets, say, `cover_min_interval_ms = 10` and
`cover_max_interval_ms = 20` without also widening padding is rejected by
`plx check` and at startup.

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
