# TLS Camouflage Layer

> Navigation: [Index](README.md) | [ClientHello Builder](ClientHello-Builder-&-Browser-Profiles.md) | [Stateful Rustls Backend](Stateful-Rustls-Camouflage-Backend.md)

## Purpose

The TLS camouflage layer makes the client-to-server connection look like a real
browser TLS 1.3 flow while still carrying ParallaX authentication and key
agreement. It is the visible outer shape of the product transport.

## Current implementation

| Piece | Code | Responsibility |
|---|---|---|
| ClientHello parser | `src/tls/client_hello.rs` | Extract SNI, random, SessionID, TLS 1.3 support, X25519 key share. |
| ServerHello parser | `src/tls/server_hello.rs` | Verify fallback-origin ServerHello and TLS 1.3 selection. |
| TLS record helpers | `src/tls/record.rs` | Parse/write TLS record headers and read exact records. |
| Safari profile backend | `src/tls/safari26.rs` | Drive `rustls`, shape ClientHello, patch entropy, send HTTP/2 preface. |
| HTTP/2 fingerprint | `src/fingerprint/http2.rs` | Build Safari 26.4-style HTTP/2 preface, SETTINGS, WINDOW_UPDATE, and HEADERS. |

## Handshake shape

```text
client
  ├─ build rustls ClientConnection
  ├─ shape provider cipher suite / key-exchange ordering
  ├─ intercept generated entropy fields
  ├─ embed ParallaX auth in ClientHello.random and SessionID
  └─ write real TLS ClientHello record

server
  ├─ parse first TLS record
  ├─ verify SNI/auth/replay
  ├─ connect to fallback origin
  ├─ forward ClientHello to fallback origin
  └─ continue authenticated ParallaX state behind camouflage records
```

## Why real `rustls`

ParallaX does not attempt to hand-roll a complete fake TLS transcript. Using
`rustls` keeps the handshake state machine, certificate verification path, and
post-handshake behavior grounded in real TLS behavior. The project-specific
part is narrow: shape the visible profile and replace authenticated entropy
slots.

## Safari profile constraints

The Safari profile is maintained through tests and fixtures:

- `tests/fixtures/safari26_apple_com_clienthello.bin`
- `tests/fixtures/safari26_cloudflare_com_clienthello.bin`
- `tests/fixtures/safari26_h2_preface_localhost.bin`
- `tests/safari_parity_baseline.rs`
- `tests/safari_h2_parity_baseline.rs`

When upgrading `rustls`, re-run those tests before claiming parity still holds.
The crate pins `rustls = "=0.23.40"` until the profile is verified against a
new version.

Related pages: [ClientHello Authentication](<ClientHello-Authentication-(PSK-+-X25519).md>),
[HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md), and
[Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md).
