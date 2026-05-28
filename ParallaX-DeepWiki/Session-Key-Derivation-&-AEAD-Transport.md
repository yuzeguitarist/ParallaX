# Session Key Derivation & AEAD Transport

> Navigation: [Index](README.md) | [Protocol](Protocol-Commands-&-Data-Records.md) | [PQ & Identity](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>)

## Initial session keys

`src/crypto/session.rs` derives directional keys after the authenticated TLS
camouflage handshake. Inputs include:

- client/server X25519 shared secret
- transcript hash
- protocol labels

The output contains separate client-to-server and server-to-client key/nonce
material plus a chain secret that can be ratcheted by rekey events.

## AEAD codec

ParallaX uses an AEAD codec with:

- fixed key length
- fixed nonce base length
- monotonically advancing per-record nonce state
- direction-specific additional authenticated data

`DataRecordCodec` wraps this codec with padding and TLS ApplicationData framing.

## Rekey model

The data session tracks an epoch. Rekeying:

1. computes a new chain secret from old chain secret + X25519 + ML-KEM + PSK
2. expands new directional AEAD keys/nonces
3. increments the epoch
4. updates both send and receive codecs

The server identity proof is bound to the same PQ rekey exchange so a signature
from one rekey cannot be replayed onto another.

## Record lifecycle

```text
plaintext
  ├─ append padding and 2-byte padding length
  ├─ seal in place with AEAD
  ├─ append tag
  └─ wrap as TLS ApplicationData
```

Open path:

```text
TLS ApplicationData record
  ├─ validate header and length
  ├─ split ciphertext/tag
  ├─ AEAD open in place
  ├─ remove padding trailer
  └─ return plaintext
```

## Chunking and limits

Large relay payloads are split so each encrypted TLS record stays within the
outer TLS payload limit. The maximum plaintext chunk size depends on the
configured maximum padding length.

## Error classes

- malformed TLS record
- non-ApplicationData content type
- truncated record
- AEAD failure
- invalid padding trailer
- payload too large for the configured padding profile

Related pages: [Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md),
[Padding & Timing Profiles](<Padding-&-Timing-Profiles.md>), and
[Protocol Benchmarks](Protocol-Benchmarks.md).
