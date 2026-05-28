# Core Architecture

> Navigation: [Index](README.md) | [Overview](ParallaX-Overview.md) | [Protocol](Protocol-Commands-&-Data-Records.md)

## System topology

```text
┌─────────────┐   SOCKS5 CONNECT   ┌────────────┐
│ application │ ─────────────────► │ plx client │
└─────────────┘                    └─────┬──────┘
                                         │ TLS 1.3 camouflage
                                         │ authenticated ClientHello
                                         │ ML-KEM/X25519/PSK rekey
                                         ▼
                                   ┌────────────┐
                                   │ plx serve  │
                                   └─────┬──────┘
                      authenticated      │      unauthenticated/probe
                      data records       │
                                         ▼
                              ┌────────────────────┐
                              │ target or fallback │
                              └────────────────────┘
```

The product transport is TCP. TLS records are the outer wire shape; ParallaX
data records are encrypted payloads carried as TLS `ApplicationData`.

## Startup flow

1. `src/main.rs` or `src/bin/plx.rs` enters `src/cli.rs`.
2. Long-lived commands call `process_hardening::harden_current_process()`.
3. Config is loaded and validated by `src/config.rs`.
4. `serve` enters `handshake::server::run`.
5. `client` enters `client::runtime::run`.
6. `speed` enters `speed::run` after acquiring the speed runtime guard.

## Client connection flow

1. The SOCKS5 parser accepts only CONNECT requests.
2. The client opens a TCP connection to `client.server_addr`.
3. `Safari26TlsCamouflage::start` builds a real TLS ClientHello and embeds
   ParallaX authentication material.
4. The server key-exchange record is applied after skipping bounded residual
   fallback camouflage records.
5. The client verifies ML-DSA identity proof chunks.
6. Data is relayed through `DataRecordCodec` in both directions.

Details: [Client Runtime & SOCKS5 Proxy](Client-Runtime-&-SOCKS5-Proxy.md).

## Server connection flow

1. The server reads the first TLS record or partial probe prefix.
2. `decide_connection_inbound` parses ClientHello and verifies SNI/auth/replay.
3. Failure paths forward to `server.fallback_addr`.
4. Success paths temporarily continue the fallback TLS flow as camouflage until
   the ParallaX PQ rekey arrives.
5. The server sends key-exchange and identity records.
6. The server resolves the fixed or client-requested target and relays data.

Details: [Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md).

## Layer boundaries

| Layer | Responsibility | Does not own |
|---|---|---|
| CLI/config | Command parsing, generated templates, validation. | Wire protocol semantics. |
| TLS camouflage | Browser-shaped TLS handshake and fallback-origin interaction. | ParallaX data-plane encryption. |
| Handshake | Authentication, transcript binding, rekey, identity proof. | Local SOCKS parsing. |
| Protocol | Binary control messages and AEAD record format. | Target selection policy. |
| Transport | TCP socket tuning and relay limits. | QUIC/UDP runtime. |
| Operations | Deployment and service hardening. | Protocol negotiation. |

## Key invariants

- The client SOCKS listener must remain loopback-only.
- Server SNI allowlist must not be empty.
- A malformed or unauthorized first record must not produce a distinct proxy
  failure on the wire.
- `max_concurrent_streams` remains `1` until scheduling has a fingerprint-safe
  design.
- Generated secret configs must not be group/world-readable.
- Benchmarks are fixed-parameter; adding/removing cases changes the baseline.

## Subsystem index

- [TLS Camouflage Layer](TLS-Camouflage-Layer.md)
- [Cryptographic Subsystems](Cryptographic-Subsystems.md)
- [Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md)
- [Traffic Obfuscation](Traffic-Obfuscation.md)
- [Transport Layer](Transport-Layer.md)
- [Probing & Benchmarking](<Probing-&-Benchmarking.md>)
