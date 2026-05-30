# HTTP/2 Fingerprinting

> Navigation: [Index](README.md) | [TLS Camouflage](TLS-Camouflage-Layer.md) | [Stateful Safari Backend](Stateful-Safari-TLS-Camouflage-Backend.md)

## Purpose

When the fallback origin negotiates ALPN `h2`, the TLS camouflage layer should
not stop after TLS handshake bytes. `src/fingerprint/http2.rs` provides a
Safari-shaped HTTP/2 connection preface so the post-handshake behavior remains
browser-like.

## Implemented pieces

| Piece | Purpose |
|---|---|
| HTTP/2 connection preface | Emits `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`. |
| SETTINGS frame | Uses the captured Safari 26.4 settings order and values. |
| WINDOW_UPDATE | Emits the captured connection-level update. |
| SETTINGS ACK parser | Lets the camouflage backend drain expected fallback responses. |
| HEADERS helper | Builds a minimal Safari-like request header block for tests/profile checks. |

## Ground-truth fixture

The reference capture is:

```text
tests/fixtures/safari26_h2_preface_localhost.bin
```

The parity test is:

```bash
cargo test --test safari_h2_parity_baseline
```

## Operational meaning

HTTP/2 fingerprinting is not the ParallaX data plane. It is part of the
fallback-origin camouflage path. Once the ParallaX data session is established,
application data is carried in AEAD-sealed TLS ApplicationData records described
in [Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md).

## Drift risks

Safari HTTP/2 settings and header metadata can change with OS/browser updates.
When capture fixtures are refreshed, update this page and the parity tests
together.
