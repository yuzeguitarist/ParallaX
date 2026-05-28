# GFW Simulator & QUIC Research

> Navigation: [Index](README.md) | [Transport Layer](Transport-Layer.md) | [Probing & Benchmarking](<Probing-&-Benchmarking.md>)

## Status

ParallaX does not currently ship a QUIC/UDP product transport. Older QUIC
transport documentation was removed because it no longer describes current
`main`.

QUIC remains in the repository as research and adversary-model context:

- research notes under `docs/`
- QUIC Initial detection logic in `tests/gfw_sim/detection/quic_initial.rs`
- scenario-level validation in `tests/gfw_simulator.rs`

## Simulator purpose

The simulator is a source-level model of censorship/DPI behaviors. It is not a
claim that ParallaX always bypasses every deployment. Its job is to make
assumptions explicit and testable.

## Scenario coverage

Current top-level scenarios cover:

- Chrome-to-Cloudflare baseline
- random fully encrypted TCP flagged by USENIX-style heuristics
- ParallaX TCP with blocked SNI and multi-box reset behavior
- fragmented ParallaX identity bursts
- active-probe behavior against Shadowsocks-like endpoints
- active-probe fallback behavior for ParallaX
- DNS keyword injection
- residual blocking and retry behavior
- permissive policy mode

Run:

```bash
cargo test --test gfw_simulator
```

## Detector families

| Detector | Code |
|---|---|
| SNI / TLS parsing | `tests/gfw_sim/detection/sni_filter.rs` |
| JA3/JA4-style TLS fingerprinting | `tests/gfw_sim/detection/tls_fingerprint.rs` |
| Fully encrypted TCP heuristics | `tests/gfw_sim/detection/fully_encrypted.rs` |
| Dual middlebox TCP state | `tests/gfw_sim/detection/tcp_dual_mb.rs` |
| Burst statistics | `tests/gfw_sim/detection/burst_statistics.rs` |
| Active probing | `tests/gfw_sim/detection/active_prober.rs` |
| DNS injection | `tests/gfw_sim/detection/dns_inject.rs` |
| QUIC Initial parsing/decryption model | `tests/gfw_sim/detection/quic_initial.rs` |

## Documentation rule

Do not describe QUIC as an operator mode unless the CLI and runtime grow a
current, tested QUIC product path again. Link to this page for research-only
QUIC material.
