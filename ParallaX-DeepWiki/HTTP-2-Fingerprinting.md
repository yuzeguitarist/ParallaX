# HTTP/2 Fingerprinting

> Navigation: [Index](README.md) | [TLS Camouflage](TLS-Camouflage-Layer.md) | [Stateful Safari Backend](Stateful-Safari-TLS-Camouflage-Backend.md)

## Purpose

When the fallback origin negotiates ALPN `h2`, the TLS camouflage layer should
not stop after TLS handshake bytes. `src/fingerprint/http2.rs` provides
Safari-shaped HTTP/2 opening-flight frames (a connection preface plus an opening
request) so the post-handshake behavior remains browser-like.

## Implemented pieces

| Piece | Purpose |
|---|---|
| HTTP/2 connection preface | Emits `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`. |
| SETTINGS frame | Uses the captured Safari 26.4 settings order and values. |
| WINDOW_UPDATE | Emits the captured connection-level update. |
| SETTINGS ACK parser | Lets the camouflage backend drain and ACK the server's SETTINGS after sending its own opening flight. |
| HEADERS frame | Builds the Safari-like opening `GET` request header block, sent on the wire right after the preface (and reused by parity tests). `accept-language` defaults to Safari-like `en-US,en;q=0.9` but can be overridden with `client.accept_language`; the rest of the header order/values stay fixed. |

## Opening flight

When ALPN selects `h2`, the camouflage backend sends a browser-shaped opening
flight and does **not** wait for the server's SETTINGS before sending its request
(`open_http2_connection` in `src/tls/safari26.rs`):

1. the connection preface — the `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` magic followed
   by the SETTINGS frame and the connection-level WINDOW_UPDATE, all built by
   `connection_preface()` — written as one record;
2. the opening `GET` HEADERS frame, written back-to-back as a second record;
3. only then does it drain and ACK the server's SETTINGS.

Sending preface and HEADERS as two back-to-back records (not coalesced into one
TLS record, and without a request-after-server-SETTINGS wait) matches a real
browser's first flight.

## Ground-truth fixture

The reference capture is:

```text
tests/fixtures/safari26_h2_preface_localhost.bin
```

The parity test is:

```bash
cargo test --locked --test safari_h2_parity_baseline
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
