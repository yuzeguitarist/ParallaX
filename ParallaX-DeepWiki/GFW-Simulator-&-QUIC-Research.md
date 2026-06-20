# GFW Simulator & QUIC Research

> Navigation: [Index](README.md) | [Transport Layer](Transport-Layer.md) | [Probing & Benchmarking](<Probing-&-Benchmarking.md>)

## Status

ParallaX ships TCP/TLS as its default, fingerprint-hardened transport and has no
`--quic` CLI flag. It does, however, carry an **experimental, off-by-default
UDP/QUIC fast plane** wired into the client and server runtimes (enabled with
`[udp].enabled = true` on both ends; see [Transport Layer](Transport-Layer.md)
and [Configuration Reference](Configuration-Reference.md)). Its QUIC client
already emits a Safari-26 H3-shaped ClientHello by default (matching Safari's
cipher suites, GREASE, and transport-parameter encoding); the plane is for
throughput experimentation and remains off by default and not yet a
production-ready operator mode.

QUIC also appears in this repository as research and adversary-model context:

- QUIC Initial detection logic in `tests/gfw_sim/detection/quic_initial.rs`
- scenario-level validation in `tests/gfw_simulator.rs`, including UDP-leg QUIC
  Initial tests that drive the real ParallaX QUIC client

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
- standard-decryptable QUIC v1 Initial from the real ParallaX UDP leg
- partial-ClientHello first datagram from the ParallaX UDP leg

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

Describe the UDP/QUIC fast plane as **experimental and off by default**, not as
removed or nonexistent. There is still no `--quic` CLI flag, so do not present
QUIC as a default operator mode; when it grows a Safari-shaped, production-ready
path, promote it here and in [Transport Layer](Transport-Layer.md). Link to this
page for the research and detector context.
