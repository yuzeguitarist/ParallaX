# ClientHello Builder & Browser Profiles

> Navigation: [Index](README.md) | [TLS Camouflage](TLS-Camouflage-Layer.md) | [ClientHello Auth](<ClientHello-Authentication-(PSK-+-X25519).md>)

## Scope

This page describes how ParallaX builds the visible ClientHello. The active
profile is Safari 26 / macOS Tahoe, implemented by `src/tls/safari26.rs`.

## Profile-owned fields

The Safari backend shapes or verifies:

- TLS 1.3 cipher suite ordering
- supported key-exchange group ordering
- GREASE positions and values
- ALPN behavior
- SNI
- X25519 key share extraction
- compatibility SessionID handling
- post-handshake HTTP/2 behavior

The Safari backend owns the TLS 1.3 state machine for this profile. ParallaX
serializes the visible ClientHello directly, including Safari extension order
and the authenticated entropy fields.

## Auth-owned fields

Two ClientHello fields carry ParallaX authentication material:

| Field | Why it is available | Auth use |
|---|---|---|
| `ClientHello.random` | Browser handshakes already use random bytes. | Carries masked/authenticated material. |
| Compatibility `SessionID` | TLS 1.3 clients still emit this compatibility field. | Carries additional authenticated bytes. |

The server parser treats these as authenticated state, not as arbitrary random
noise.

## Build flow

```text
profile config
  ├─ select Safari cipher/group/extension order
  ├─ generate TLS X25519MLKEM768 and X25519 key shares
  ├─ patch ClientHello.random and SessionID with auth context
  ├─ expose ClientHello bytes for first-record send
  └─ continue the handwritten TLS 1.3 state machine against the fallback origin
```

## Drift management

Browser TLS profiles drift over time. ParallaX keeps drift visible by:

- storing capture fixtures under `tests/fixtures/`
- running Safari parity tests
- keeping the single Safari TLS path covered by ClientHello and H2 parity tests
- documenting current behavior here instead of preserving stale line-number
  links to old commits

Related pages: [Stateful Safari TLS Camouflage Backend](Stateful-Safari-TLS-Camouflage-Backend.md),
[HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md), and
[Camouflage Target Probe](Camouflage-Target-Probe.md).
