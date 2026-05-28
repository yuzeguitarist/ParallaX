# Transport Layer

> Navigation: [Index](README.md) | [TCP Transport](TCP-Camouflage-Transport.md) | [GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>)

## Current product transport

ParallaX currently ships one product transport:

```text
TCP socket → TLS records → ParallaX encrypted data records
```

There is no active `--quic` or UDP runtime in the operator CLI.

## Responsibilities

| Layer | Code | Responsibility |
|---|---|---|
| TCP socket helpers | `src/transport/tcp.rs` | `TCP_NODELAY`, Linux keepalive tuning, fd-limit derived relay caps. |
| TLS record layer | `src/tls/record.rs` | Read/write exact TLS records and parse headers. |
| Data record layer | `src/protocol/data.rs` | AEAD-sealed payloads inside TLS ApplicationData. |
| Client/server relay | `src/client/runtime.rs`, `src/handshake/server.rs` | Bidirectional application relay. |

## Why TCP-only

The current product line favors one carefully shaped path over multiple
half-maintained transports. QUIC research remains important for the adversary
model, but the production runtime is TCP/TLS.

## Validation

- TCP relay behavior: regular and ignored Rust tests
- TLS record behavior: unit tests in `src/tls/record.rs`
- data record behavior: unit tests and benchmarks in `src/protocol/data.rs`
- adversary behavior: [GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>)

Related page: [TCP Camouflage Transport](TCP-Camouflage-Transport.md).
