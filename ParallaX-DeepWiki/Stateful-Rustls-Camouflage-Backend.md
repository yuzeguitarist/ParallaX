# Stateful Rustls Camouflage Backend

> Navigation: [Index](README.md) | [TLS Camouflage](TLS-Camouflage-Layer.md) | [HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md)

## Design

`Safari26TlsCamouflage` starts a real `rustls::ClientConnection` and captures
the ClientHello record that `rustls` emits. ParallaX then validates that the
record contains authenticated ClientHello fields before exposing it to the
client runtime.

The backend is stateful because it must continue driving the same TLS session
after the first record. The fallback origin receives the ClientHello and sends
real TLS responses, while ParallaX overlays its authenticated data-session
transition behind that traffic.

## Main entities

| Entity | Role |
|---|---|
| `Safari26TlsCamouflage` | Starts the profile-shaped TLS session. |
| `Safari26TlsSession` | Holds `rustls::ClientConnection`, ClientHello bytes, X25519 key pair, and record tap state. |
| `CompletedSafari26Handshake` | Returns transcript hash, server X25519 material, and ServerHello bytes after handshake completion. |
| `VecRecordTap` / `RecordEvent` | Test/diagnostic hooks for emitted and received TLS records. |
| `CamouflageVerifier` | Uses native roots for fallback-origin certificate verification while preserving Safari-shaped signature-scheme ordering. |

## Handshake driving

```text
start()
  ├─ build rustls config with Safari-shaped provider order
  ├─ create ClientConnection for SNI
  ├─ capture emitted ClientHello record
  └─ return Safari26TlsSession

complete_handshake()
  ├─ write queued TLS records to fallback-origin stream
  ├─ read fallback TLS records
  ├─ feed records into rustls
  ├─ require a TLS 1.3 ServerHello
  └─ emit HTTP/2 camouflage preface when negotiated
```

## HTTP/2 post-handshake behavior

When HTTP/2 is negotiated, the backend can emit a Safari-shaped HTTP/2
connection preface and drain SETTINGS ACK behavior with a bounded record limit
and timeout. This avoids leaving the fallback TLS connection in a visibly
unfinished state.

## Upgrade risks

This backend relies on specific `rustls` construction behavior. Any `rustls`
upgrade should be treated as profile-sensitive and verified with:

```bash
cargo test --test safari_parity_baseline
cargo test --test safari_h2_parity_baseline
cargo test --locked --no-fail-fast
```

Related pages: [ClientHello Builder & Browser Profiles](ClientHello-Builder-&-Browser-Profiles.md)
and [ClientHello Authentication](<ClientHello-Authentication-(PSK-+-X25519).md>).
