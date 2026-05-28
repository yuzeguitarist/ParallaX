# Padding & Timing Profiles

> Navigation: [Index](README.md) | [Traffic Obfuscation](Traffic-Obfuscation.md) | [Session AEAD](Session-Key-Derivation-&-AEAD-Transport.md)

## Padding profile

`PaddingProfile` appends:

```text
payload || padding bytes || u16 padding_length
```

The padded buffer is then AEAD-sealed by `DataRecordCodec`.

### Validation

- `max_padding >= min_padding`
- configured maximum padding must still leave room for encrypted payload inside
  the TLS record payload limit
- padding removal rejects buffers shorter than the 2-byte length trailer
- padding removal rejects length trailers larger than the buffer

### Sampling behavior

When `min_padding == max_padding`, padding length is fixed. Otherwise the
profile samples within the configured range and may bias toward observed packet
size buckets where appropriate.

## Timing profile

`TimingProfile` is enabled when `max_delay_ms` is non-zero.

| Config | Behavior |
|---|---|
| `max_delay_ms = 0` | disabled; returns zero delay |
| `min_delay_ms == max_delay_ms` | fixed delay |
| `min_delay_ms < max_delay_ms` | samples within the bounded range |

Timing is deliberately opt-in because delay is visible and directly affects
user experience.

## Capacity impact

Higher `max_padding` lowers maximum plaintext per record. If padding is too
large, the config validator rejects it before runtime.

## Related checks

```bash
cargo test traffic
cargo test protocol::data
cargo test --locked --no-fail-fast
```

Related pages: [Traffic Obfuscation](Traffic-Obfuscation.md),
[Cover Traffic](Cover-Traffic.md), and
[Protocol Benchmarks](Protocol-Benchmarks.md).
