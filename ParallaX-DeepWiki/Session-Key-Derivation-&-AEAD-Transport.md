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

## Multi-core AEAD fan-out

A single connection's seal/open work used to be pinned to one task and
therefore one core, which capped per-tunnel throughput at one core's
ChaCha20-Poly1305 rate. `src/crypto/parallel.rs` provides a process-wide
`CryptoPool` (sized to available parallelism and shared by every connection so
tunnels do not oversubscribe the machine) that the data path uses for bulk
batches:

- The serial caller assigns sequence numbers and record boundaries; workers
  receive explicit sequences and a shared cipher handle, and never touch the
  per-direction counter.
- Worker results are reassembled in record order, so the wire bytes are
  identical to the serial path for the same padding stream.
- `should_parallelize_aead` gates the fan-out: small batches (interactive
  traffic, control frames) seal and open inline to avoid cross-thread dispatch
  latency; only bulk batches pay for the pool.
- Any AEAD failure inside a batch fails the whole session closed, matching the
  serial open path.
- Rekeying stays serial: a batch fully completes before the codec can be
  rekeyed, so in-flight jobs never cross an epoch change.

The mux relay writers batch frames into frame-aligned records and seal the
batch through this pool; the mux readers opportunistically collect
already-buffered records and open them the same way.

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
