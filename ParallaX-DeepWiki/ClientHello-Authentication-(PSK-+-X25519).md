# ClientHello Authentication (PSK + X25519)

> Navigation: [Index](README.md) | [TLS Camouflage](TLS-Camouflage-Layer.md) | [Cryptographic Subsystems](Cryptographic-Subsystems.md)

## Purpose

ParallaX authenticates clients without adding a proxy-specific TLS extension or
extra round trip. The client starts a real TLS 1.3 ClientHello, then embeds
authentication material into fields that are already entropy-bearing in a
browser handshake.

## Inputs

| Input | Source |
|---|---|
| PSK | `[crypto].psk` in both configs |
| Client X25519 key pair | Generated per connection |
| Server X25519 public key | `[client].server_public_key` |
| SNI | `[client].sni` |
| ClientHello bytes | Built by the Safari camouflage backend |

## Authenticated fields

ParallaX uses:

- `ClientHello.random`
- TLS 1.2 compatibility `SessionID`

The parser in `src/tls/client_hello.rs` exposes the relevant ranges. The auth
logic in `src/crypto/auth.rs` verifies that the masked fields are consistent
with the PSK, X25519 exchange, SNI, and ClientHello transcript.

## Server verification flow

```text
first TLS record
  │
  ├─ parse ClientHello
  ├─ require TLS 1.3 support
  ├─ extract SNI and X25519 key share
  ├─ require SNI in authorized_sni
  ├─ verify PSK/X25519 auth fields
  ├─ check replay cache
  └─ authenticate or fallback
```

Failure does not send a ParallaX error. The server routes the connection to the
fallback origin so active probes see a normal website path.

## Session binding

Successful verification produces the shared material needed by
`src/crypto/session.rs` to derive initial directional AEAD keys. Later, the PQ
rekey updates those keys again; see
[Post-Quantum Cryptography](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>).

## Security properties

- The PSK is never transmitted directly.
- A captured authenticated ClientHello is single-use when the replay cache is
  available.
- The authenticated SNI must be explicitly authorized by the server config.
- The wire format does not introduce a custom extension that can be matched by
  a middlebox.

## Operational notes

- `plx init` creates matching PSKs and key material for both config files.
- `plx check` validates key lengths before a long-lived process starts.
- Rotating the PSK requires replacing both client and server configs.
