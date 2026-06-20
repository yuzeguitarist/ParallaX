# Post-Quantum Cryptography (ML-KEM & ML-DSA)

> Navigation: [Index](README.md) | [Cryptographic Subsystems](Cryptographic-Subsystems.md) | [Session AEAD](Session-Key-Derivation-&-AEAD-Transport.md)

## Components

| Component | Algorithm | Code | Role |
|---|---|---|---|
| PQ KEM | ML-KEM-1024 | `src/crypto/pq.rs` | Shared secret for data-plane rekey. |
| Server identity | ML-DSA-87 | `src/crypto/identity.rs` | Pinned server identity proof. |
| Classical ECDH | X25519 | `src/crypto/session.rs` | Hybrid rekey input. |
| Symmetric input | PSK | `src/config.rs` | Sandwich rekey binding. |

## PQ rekey flow

```text
client
  ├─ generate fresh X25519 key pair
  ├─ generate ML-KEM-1024 key pair
  └─ send PqRekeyRequest

server
  ├─ encapsulate to client ML-KEM public key
  ├─ compute X25519 shared secret
  ├─ derive hybrid sandwich chain secret
  └─ send ServerKeyExchange

client
  ├─ decapsulate ML-KEM ciphertext
  ├─ compute X25519 shared secret
  └─ derive the same chain secret
```

The sandwich KDF input binds:

- old chain secret
- fresh X25519 shared secret
- ML-KEM shared secret
- PSK/symmetric material

## Server identity proof

The server signs an identity message that includes:

- protocol identity label
- epoch
- transcript hash
- server X25519 public key
- PQ rekey binding hash

The PQ rekey binding hashes both the client PQ rekey request and the server key
exchange payload. This prevents replaying a valid identity proof across a
different rekey exchange.

## Config material

Generated server config includes:

- `server.identity_secret_key`

Generated client config includes:

- `client.server_identity_public_key`

## Operational implications

- Rotating server identity requires distributing the new
  `server_identity_public_key` to clients.
- Identity proof verification failure is a hard client-side failure.

Related pages: [Client Runtime & SOCKS5 Proxy](Client-Runtime-&-SOCKS5-Proxy.md),
[Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md), and
[Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md).
