# TLS Camouflage Layer

> Navigation: [Index](README.md) | [ClientHello Builder](ClientHello-Builder-&-Browser-Profiles.md) | [Stateful Safari Backend](Stateful-Safari-TLS-Camouflage-Backend.md)

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
| Safari profile backend | `src/tls/safari26.rs` | Serialize Safari ClientHello, run the narrow TLS 1.3 state machine, verify certificates, patch auth entropy, send the HTTP/2 opening flight (preface + HEADERS). |
| HTTP/2 fingerprint | `src/fingerprint/http2.rs` | Build Safari 26.4-style HTTP/2 preface, SETTINGS, WINDOW_UPDATE, and HEADERS. |

## Handshake shape

```text
client
  ├─ serialize Safari cipher/group/extension ordering
  ├─ generate X25519MLKEM768 + X25519 key shares
  ├─ embed ParallaX auth in ClientHello.random and SessionID
  ├─ complete TLS 1.3 against the fallback origin
  └─ write Safari-shaped HTTP/2 camouflage when ALPN selects h2

server
  ├─ parse first TLS record
  ├─ verify SNI/auth/replay
  ├─ connect to fallback origin
  ├─ forward ClientHello to fallback origin
  └─ continue authenticated ParallaX state behind camouflage records
```

## Why a single handwritten Safari path

ParallaX now keeps one TLS camouflage implementation: a Safari 26 / TLS 1.3
client path in `src/tls/safari26.rs`. It is not a general-purpose TLS library;
it implements the profile ParallaX actually ships, including key schedule,
record protection, certificate verification, and the HTTP/2 preface needed for
the fallback-origin camouflage.

## Safari profile constraints

The Safari profile is maintained through tests and fixtures:

- `tests/fixtures/safari26_apple_com_clienthello.bin`
- `tests/fixtures/safari26_cloudflare_com_clienthello.bin`
- `tests/fixtures/safari26_h2_preface_localhost.bin`
- `tests/safari_parity_baseline.rs`
- `tests/safari_h2_parity_baseline.rs`

When the Safari profile changes, refresh captures and re-run those tests before
claiming parity still holds.

Related pages: [ClientHello Authentication](<ClientHello-Authentication-(PSK-+-X25519).md>),
[HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md), and
[Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md).
