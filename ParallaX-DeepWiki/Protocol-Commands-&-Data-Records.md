# Protocol Commands & Data Records

> Navigation: [Index](README.md) | [Core Architecture](Core-Architecture.md) | [Session AEAD](Session-Key-Derivation-&-AEAD-Transport.md)

## Two wire layers

ParallaX uses two distinct layers:

1. **Outer TLS record shape.** The network sees TLS records, and the data plane
   is carried as TLS `ApplicationData`.
2. **Inner ParallaX commands/data.** Authenticated peers exchange binary control
   commands and encrypted payloads inside those records.

The command structs live in `src/protocol/command.rs`. The encrypted record
codec lives in `src/protocol/data.rs`.

## Command magic values

| Magic | Command | Direction | Purpose |
|---|---|---|---|
| `PX1C` | `ConnectRequest` | client to server | Target host/port plus optional initial payload. |
| `PX1Q` | `PqRekeyRequest` | client to server | Client X25519 public key plus ML-KEM public key. |
| `PX1K` | `ServerKeyExchange` | server to client | Server X25519 public key plus ML-KEM ciphertext. |
| `PX1S` | `ServerIdentityProof` | server to client | ML-DSA-87 signature payload. |
| `PX1I` | `ServerIdentityChunk` | server to client | Chunked identity-proof transport. |
| `PX1T` | `SpeedTestRequest` | client to server | Fixed warmup/sample byte counts for `plx speed`. |
| `PX1W` | speed ack | server to client | Warmup download done. |
| `PX1V` | speed ack | client to server | Warmup upload done. |
| `PX1D` | speed ack | client/server | Download sample done. |
| `PX1U` | speed ack | client/server | Upload sample done. |

All decoders fail on truncation, bad magic, malformed lengths, empty required
fields, and port `0` where a target port is present.

## Data record format

`DataRecordCodec` builds one or more TLS `ApplicationData` records:

```text
TLS record header
  content_type = 0x17
  legacy_version = 0x0303
  length = ciphertext + tag length

AEAD ciphertext over:
  plaintext payload
  padding bytes
  2-byte padding length trailer

AEAD tag
```

The AEAD additional authenticated data is direction-specific and comes from
session key derivation. The codec rejects non-ApplicationData records, truncated
records, oversized records, AEAD failures, and malformed padding.

## Chunking

`OUTER_TLS_RECORD_LIMIT` follows the TLS record payload limit. Large application
payloads are split into chunks no larger than `max_plaintext_len(max_padding)`.
The relay path uses chunking helpers that can:

- return tracked output ranges for tests/metrics
- reuse output buffers
- avoid tracking ranges for hot relay writes

Batch helpers additionally accept an explicit per-record length list
(`record_lens`) so the mux writers can keep records frame-aligned, with a
serial path and a crypto-pool parallel path that produce identical record
boundaries and sequence numbers. A matching pair of concat-open helpers opens
a run of consecutive records (serially or across the pool) and returns the
concatenated plaintext in record order. See
[Session Key Derivation & AEAD Transport](Session-Key-Derivation-&-AEAD-Transport.md)
for the fan-out rules.

## Speed-test protocol

`plx speed` is built on protocol commands rather than ad hoc text. The request
contains:

- warmup bytes
- download bytes per sample
- upload bytes per sample
- sample count

The current default plan is 1 MiB warmup, 4 MiB per measured sample, and three
samples per direction. Validation rejects zero byte counts and zero sample
counts.

Related pages: [Session Key Derivation & AEAD Transport](Session-Key-Derivation-&-AEAD-Transport.md),
[Protocol Benchmarks](Protocol-Benchmarks.md), and [Client Runtime](Client-Runtime-&-SOCKS5-Proxy.md).
