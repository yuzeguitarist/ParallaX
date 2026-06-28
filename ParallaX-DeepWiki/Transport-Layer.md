# Transport Layer

> Navigation: [Index](README.md) | [TCP Transport](TCP-Camouflage-Transport.md) | [QUIC Fast Plane](QUIC-Fast-Plane.md) | [GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>)

## Transport plane

ParallaX's default, fingerprint-hardened transport is TCP:

```text
TCP socket → TLS records → ParallaX encrypted data records
```

There is no `--quic` CLI flag. An **experimental** UDP/QUIC fast plane is also
wired into the client and server runtimes, but it is **off by default**: setting
`[udp].enabled = true` on both ends (with matched binaries) activates a QUIC
reliable-stream carrier for the single-Connect data relay. While disabled, every
path stays byte-identical on TCP. When enabled, its QUIC client already emits a
Safari-26 H3-shaped ClientHello by default, but it stays off by default and is
not yet a production-ready operator mode, so it is for experimentation only. See
the `[udp]`
knobs in [Configuration Reference](Configuration-Reference.md) and the detector
context in [GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>).

## Responsibilities

| Layer | Code | Responsibility |
|---|---|---|
| TCP socket helpers | `src/transport/tcp.rs` | `TCP_NODELAY`, cross-platform TCP keepalive (SO_KEEPALIVE), fd-limit derived relay caps, optional post-connect `SO_SNDBUF`/`SO_RCVBUF` overrides (`[transport]` config). |
| TLS record layer | `src/tls/record.rs` | Read/write exact TLS records and parse headers. |
| Data record layer | `src/protocol/data.rs` | AEAD-sealed payloads inside TLS ApplicationData. |
| Client/server relay | `src/client/runtime.rs`, `src/handshake/server.rs` | Bidirectional application relay. |
| Transport leg abstraction | `src/transport/leg.rs` | Uniform reader/writer over either a TCP or a QUIC stream leg. |
| UDP/QUIC fast plane (experimental, off by default) | `src/transport/udp/`, `src/tls/quic/` | Clean-room QUIC endpoint (`quic/` submodule), Happy-Eyeballs probe, 0-RTT resumption, BBR congestion control, mux-over-QUIC, origin splice, and exporter-bound auth. See [QUIC Fast Plane](QUIC-Fast-Plane.md). |

## Why TCP is the default

The product line favors one carefully shaped path over multiple half-maintained
transports, so TCP/TLS is the default and the only fingerprint-hardened
transport. The experimental UDP/QUIC fast plane exists for throughput
experimentation; its QUIC client already emits a Safari-26 H3-shaped ClientHello
by default, but it stays off by default and is not yet a production-ready
operator mode. QUIC also remains important for the adversary model.

## Validation

- TCP relay behavior: regular and ignored Rust tests
- TLS record behavior: unit tests in `src/tls/record.rs`
- data record behavior: unit tests in `src/protocol/data.rs`
- adversary behavior: [GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>)

Related page: [TCP Camouflage Transport](TCP-Camouflage-Transport.md).
