# Stateful Safari TLS Camouflage Backend

> Navigation: [Index](README.md) | [TLS Camouflage](TLS-Camouflage-Layer.md) | [HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md)

## Design

`Safari26TlsCamouflage` owns the single Safari 26 TLS 1.3 camouflage path. It
serializes the ClientHello directly, validates the authenticated ClientHello
fields, completes the narrow TLS 1.3 handshake against the fallback origin, and
then exposes the result to the client runtime.

The backend is stateful because it must continue driving the same TLS session
after the first record. The fallback origin receives the ClientHello and sends
real TLS responses, while ParallaX overlays its authenticated data-session
transition behind that traffic.

## Main entities

| Entity | Role |
|---|---|
| `Safari26TlsCamouflage` | Starts the profile-shaped TLS session. |
| `Safari26TlsSession` | Holds ClientHello bytes, TLS key-share material, ParallaX X25519 material, and record tap state. |
| `CompletedSafari26Handshake` | Returns ParallaX X25519 material, ServerHello bytes, negotiated ALPN, and post-handshake record counts after handshake completion. |
| `VecRecordTap` / `RecordEvent` | Test/diagnostic hooks for emitted and received TLS records. |
| Certificate verifier | Uses native roots plus `webpki` to verify fallback-origin certificates and TLS 1.3 CertificateVerify. |

## Handshake driving

```text
start()
  ├─ generate ParallaX auth X25519 and TLS X25519MLKEM768 material
  ├─ serialize Safari-shaped ClientHello record
  ├─ verify embedded ClientHello auth material
  └─ return Safari26TlsSession

complete_handshake()
  ├─ write ClientHello to fallback-origin stream
  ├─ read fallback TLS records
  ├─ require a TLS 1.3 ServerHello
  ├─ derive TLS 1.3 handshake/application secrets
  ├─ verify Certificate, CertificateVerify, and Finished
  └─ emit the HTTP/2 camouflage opening flight (preface + opening HEADERS) when h2 is negotiated
```

## HTTP/2 post-handshake behavior

When HTTP/2 is negotiated, the backend sends a Safari-shaped opening flight —
the connection preface (magic + SETTINGS + WINDOW_UPDATE) followed back-to-back
by the opening `GET` HEADERS frame — without waiting for the server's SETTINGS,
then drains and ACKs the server's SETTINGS with a bounded record limit and
timeout. This avoids leaving the fallback TLS connection in a visibly unfinished
state and matches a real browser's first flight.

## Drift risks

This backend relies on Safari capture fixtures and narrow TLS 1.3 assumptions.
Any Safari profile or handshake change should be treated as profile-sensitive
and verified with:

```bash
cargo test --test safari_parity_baseline
cargo test --test safari_h2_parity_baseline
cargo test --locked --no-fail-fast
```

Related pages: [ClientHello Builder & Browser Profiles](ClientHello-Builder-&-Browser-Profiles.md)
and [ClientHello Authentication](<ClientHello-Authentication-(PSK-+-X25519).md>).
