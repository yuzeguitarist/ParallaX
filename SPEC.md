# ParallaX Protocol Specification

**Version:** 1 (wire protocol `PX1`)
**Status:** Descriptive specification of the reference implementation (Rust).
**Audience:** Implementers building an interoperable client or server in another language.

---

## 0. About This Document

This document specifies the ParallaX censorship-resistant proxy protocol at the
level of detail required to produce an **independent, interoperable
reimplementation** without reading the reference source. Every constant, label,
size, and byte layout below is taken from the reference implementation; where a
value is security-critical for interoperability it is cited inline with its
source file.

ParallaX is a **circumvention transport**: a client forwards application traffic
(typically SOCKS5) to a server, which relays it to arbitrary destinations. Its
design goal is that, to a passive or active network observer, a ParallaX flow is
**byte-for-byte indistinguishable from a Safari 26 connection to a real TLS or
QUIC origin**, while authenticated peers run a fully independent
post-quantum-secure tunnel inside that carrier.

Two transport planes exist and are interoperable peers of the same handshake
secrets:

- **TCP plane** — disguised as Safari 26 **TLS 1.3 over TCP + HTTP/2**.
- **QUIC plane** — disguised as Safari 26 **QUIC v1 + HTTP/3**.

A conforming implementation MAY implement only one plane. The TCP plane is the
normative baseline; the QUIC plane is an optional accelerated path that reuses
the same identities and command/data framing.

### 0.1 Requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY are to be
interpreted as in RFC 2119.

### 0.2 Conventions

- All multi-byte integers on the ParallaX wire are **big-endian (network byte
  order)** unless explicitly stated otherwise.
- `u8`, `u16`, `u32`, `u64` denote unsigned integers of 8/16/32/64 bits.
- `||` denotes byte concatenation.
- `X[a..b]` denotes bytes `a` (inclusive) through `b` (exclusive) of `X`,
  zero-indexed.
- Byte-string literals are written `b"..."` (ASCII) or as hex `0xNN`.
- "Carrier" = the cover protocol (TLS/QUIC record stream) that transports
  ParallaX messages.
- "Inner" = the ParallaX protocol running inside the carrier's encrypted records.

---

## 1. Protocol Overview

```
   Application (browser, curl, ...)
        │  SOCKS5  (CONNECT)
        ▼
   ┌──────────────┐        Carrier: Safari-26 TLS1.3/H2  (TCP)
   │ ParallaX     │  ════  or Safari-26 QUIC v1/H3       (UDP)  ════►  ┌──────────────┐
   │ Client       │        camouflaged, authenticated                  │ ParallaX     │
   └──────────────┘                                                    │ Server       │
                                                                       └──────┬───────┘
                                                                              │ TCP/UDP
                                                                              ▼
                                                                    Destination (the CONNECT
                                                                    target — not the fallback
                                                                    origin of §13)
```

A ParallaX session proceeds in four phases:

1. **Carrier handshake / authentication (Phase A).** The client opens what
   looks like an ordinary Safari TLS (or QUIC) connection to the server's
   public address. The client's identity and freshness proof are **steganographically
   embedded** in fields a real Safari client randomizes — the TLS
   `ClientHello.random` and `session_id` (TCP plane), or the QUIC
   `Initial`'s `ClientHello.random` (QUIC plane). The server **always** bridges
   the connection to a real fallback origin and relays that origin's genuine
   TLS/QUIC handshake to the client (origin-splice; §7.1, §13); an unauthenticated
   or replayed peer is relayed to the origin indefinitely, so probing reveals
   nothing.

2. **Inner cryptographic handshake (Phase B).** Once the carrier is established
   and the client authenticated, the peers run a post-quantum-hybrid key
   exchange: the server proves possession of a long-term **ML-DSA-87** identity,
   contributes an ephemeral **X25519 + ML-KEM-1024** key share, and both sides
   derive AEAD traffic keys bound to the full transcript and a shared PSK.

3. **Command (Phase C).** The client sends a `CONNECT` message naming the
   destination host/port (optionally with 0-RTT initial payload).

4. **Data relay / multiplexing (Phase D).** Bidirectional data flows as a
   stream of AEAD-sealed application-data records. A `MUX` framing layer allows
   many logical streams over one carrier connection, plus cover traffic.

All Phase B–D bytes travel **inside** the carrier's encrypted records, so the
ParallaX magic numbers (`PX1...`) are never visible on the wire — they are only
seen by a peer who already holds the session keys.

### 1.1 Design invariants (normative for camouflage)

A conforming implementation MUST preserve these properties; violating any of
them defeats the protocol's purpose:

- **I1 — Indistinguishable bytes.** Every byte a passive observer sees on the
  carrier MUST be a value a real Safari 26 client/server could emit, in the same
  order and with the same record/packet sizing distribution (§11, §12).
- **I2 — No tells on failure.** Authentication failure, replay, malformed input,
  and policy rejection MUST all funnel into the same observable behavior as a
  real origin serving a non-ParallaX client. There MUST be no
  ParallaX-specific error response, RST timing, or close code observable on the
  wire.
- **I3 — Fail-closed crypto.** Any AEAD open failure, nonce exhaustion, or
  transcript mismatch MUST terminate the session; partial or ambiguous state MUST
  NOT be exposed.
- **I4 — Forward-secret, PQ-bound keys.** Traffic keys MUST be bound to the
  ephemeral X25519 + ML-KEM-1024 shares, the PSK, and the exact carrier
  transcript (§5.3–§5.7). The server's ML-DSA-87 identity is verified separately
  (§5.6) and the signed proof binds the same transcript, epoch, and ephemerals —
  so a client that completes the handshake has both fresh PQ-bound keys and a
  proof it talked to the genuine server.

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Carrier** | The cover protocol stream (Safari TLS 1.3 record layer over TCP, or QUIC v1/H3 over UDP) that transports ParallaX messages inside its encrypted records. |
| **Inner protocol** | The ParallaX command/data protocol that runs inside the carrier's encrypted records, invisible to observers. |
| **PSK** | Pre-shared symmetric secret, identical on both peers, mandatory. Mixed into every key derivation. An empty PSK is rejected. |
| **Server static identity (X25519)** | Long-term X25519 keypair. The client knows the server's static public key; used to derive the ClientHello carrier mask and to authenticate the embedded auth tag. |
| **Server signing identity (ML-DSA-87)** | Long-term post-quantum signature keypair proving server authenticity in Phase B. |
| **Carrier auth** | The steganographic embedding of `{parallax_x25519_public, timestamp, nonce, tag}` in the ClientHello's `random`+`session_id` (TCP) or `random` (QUIC). |
| **Transcript hash** | `SHA-256` over a domain-separated concatenation of the carrier ClientHello and ServerHello records; binds all later keys to the exact handshake bytes. |
| **Chain secret** | The 32-byte master secret derived after Phase B; root of the traffic-key schedule, ratcheted forward on PQ rekey. |
| **Epoch** | A `u64` counter, starting at 0, incremented on each rekey. Bound into every derived key. |
| **Record** | One AEAD-sealed unit on the carrier (a TLS 1.3 application-data record on the TCP plane). |
| **Sequence** | Per-direction `u64` record counter (starts at 0, resets to 0 on rekey) that perturbs the AEAD nonce. |
| **MUX frame** | The inner stream-multiplexing unit (`PX1M`) carrying a stream id, a kind, and a payload. |
| **Origin-splice** | The server's default behavior of transparently bridging the carrier to a real fallback origin so the connection is a genuine TLS/QUIC session to that origin. The server **always** bridges to the origin on every accepted connection; it diverges from this only when an authenticated client sends `PX1Q` (then it takes the connection over). An unauthenticated or replayed peer is therefore relayed to the origin indefinitely. |
| **0-RTT initial payload** | Application bytes the client speculatively attaches to the `CONNECT` so the first request reaches the destination target (not the fallback origin) without an extra round trip. |

---

## 3. IANA-style Registry / Constants

This section is the authoritative registry of all on-wire constants. Other
sections reference these by name.

### 3.1 Inner message magics (4-byte ASCII)

All inner messages begin with a 4-byte ASCII magic. These appear only inside
encrypted records.

| Magic (ASCII) | Hex | Message | Direction | §  |
|---------------|-----|---------|-----------|----|
| `PX1C` | `50 58 31 43` | CONNECT | C→S | 6.1 |
| `PX1Q` | `50 58 31 51` | PQ_REKEY request | C→S | 5.6 |
| `PX1K` | `50 58 31 4B` | SERVER_KEY_EXCHANGE | S→C | 5.6 |
| `PX1S` | `50 58 31 53` | SERVER_IDENTITY (proof, whole) | S→C | 5.5 |
| `PX1I` | `50 58 31 49` | SERVER_IDENTITY_CHUNK | S→C | 5.5 |
| `PX1F` | `50 58 31 46` | FRAMED_CHUNK (generic chunk reassembly) | both | 5.7 |
| `PX1M` | `50 58 31 4D` | MUX_FRAME | both | 7 |
| `PX1G` | `50 58 31 47` | UDP_REQUEST (negotiate QUIC plane) | C→S | 9.1 |
| `PX1O` | `50 58 31 4F` | UDP_OFFER | S→C | 9.1 |
| `PX1P` | `50 58 31 50` | UDP_PROBE_ACK | C→S | 9.1 |
| `PX1N` | `50 58 31 4E` | UDP_DECLINE | S→C | 9.1 |
| `PX1T` | `50 58 31 54` | SPEED_TEST request | C→S | (diagnostic) |
| `PX1W` | `50 58 31 57` | SPEED warmup-download-done | S↔C | (diagnostic) |
| `PX1V` | `50 58 31 56` | SPEED warmup-upload-done | S↔C | (diagnostic) |
| `PX1D` | `50 58 31 44` | SPEED download-done | S↔C | (diagnostic) |
| `PX1U` | `50 58 31 55` | SPEED upload-done | S↔C | (diagnostic) |

`SPEED_*` messages are an optional, non-essential bandwidth self-test and may be
omitted by a minimal implementation.

**Teardown markers (fixed plaintext, not magic-prefixed messages).** Two
fixed-byte markers are sealed as ordinary records to coordinate clean teardown
between the TCP and QUIC planes (used only when both planes are active):

| Marker bytes (ASCII) | Meaning |
|----------------------|---------|
| `b"PX1Z-quic-relay-done"` (20 B) | the QUIC-plane relay finished; signals the TCP side to tear down |
| `b"PX1Z-speed-quic-done"` (21 B) | the QUIC-plane speed test finished |

A TCP-only implementation never emits or sees these. Separately, when a QUIC
relay drains cleanly the connection is closed with QUIC **application close code
`RELAY_IDLE_CLOSE_CODE = 1`** (not 0), distinguishing a normal idle teardown
from an error.

### 3.2 MUX frame kinds (1 byte)

| Value | Kind | Meaning | stream_id rule |
|-------|------|---------|----------------|
| `1` | OPEN | Open a new logical stream; payload is a `CONNECT` message. | non-zero |
| `2` | DATA | Stream payload bytes. | non-zero |
| `3` | FIN | Graceful half-close (no more data this direction). | non-zero |
| `4` | RESET | Abort the stream. | non-zero |
| `5` | COVER | Cover/padding traffic, discarded by receiver. | MUST be 0 |

### 3.3 Cipher-suite negotiation tag (1 byte)

Carried as the trailing byte of `SERVER_KEY_EXCHANGE` (§5.6).

| Value | AEAD |
|-------|------|
| `0x00` | ChaCha20-Poly1305 |
| `0x01` | AES-256-GCM |

### 3.4 TLS carrier record constants

| Name | Value | Meaning |
|------|-------|---------|
| `TLS_HEADER_LEN` | `5` | record header bytes |
| `TLS_LEGACY_VERSION` | `0x03 0x03` | record `legacy_version` field |
| `TLS_CONTENT_HANDSHAKE` | `0x16` | content type: handshake |
| `TLS_CONTENT_APPLICATION_DATA` | `0x17` | content type: application data |
| `TLS_CONTENT_ALERT` | `0x15` | content type: alert |
| `MAX_TLS_RECORD_PAYLOAD` | `16384` | max cleartext record payload (16 KiB) |
| `OUTER_TLS_RECORD_LIMIT` | `16401` | `MAX_TLS_RECORD_PAYLOAD + 17`; max sealed inner record payload (Safari-26-matched) |
| ChangeCipherSpec record | `14 03 03 00 01 01` | emitted for TLS-1.3 middlebox compat |

### 3.5 Cryptographic sizes

| Name | Value (bytes) |
|------|---------------|
| X25519 private / public / shared | 32 / 32 / 32 |
| ML-KEM-1024 public key | 1568 |
| ML-KEM-1024 secret (decapsulation) key | 3168 |
| ML-KEM-1024 ciphertext | 1568 |
| ML-KEM-1024 shared secret | 32 |
| ML-DSA-87 public key | 2592 |
| ML-DSA-87 secret key | 4896 |
| ML-DSA-87 signature | 4627 |
| AEAD key (`KEY_LEN`) | 32 |
| AEAD nonce (`NONCE_LEN`) | 12 |
| AEAD tag (`AEAD_TAG_LEN`) | 16 |
| HKDF/HMAC hash | SHA-256 (32-byte output) |
| `SESSION_ID_LEN` | 32 |
| `AUTH_TAG_LEN` | 16 |
| `STATEFUL_AUTH_TAIL_LEN` | 16 (= `SESSION_ID_LEN − AUTH_TAG_LEN`) |
| `AUTH_TIMESTAMP_LEN` | 8 |
| `AUTH_NONCE_LEN` | 8 (= tail − timestamp) |

### 3.6 Framing length constants

| Name | Value | Meaning |
|------|-------|---------|
| `MAX_HOST_LEN` | 255 | max CONNECT host length |
| `CONNECT_FIXED_LEN` | 12 | `4(magic)+2(hostlen)+2(port)+4(payloadlen)` |
| `MUX_FRAME_FIXED_LEN` | 13 | `4(magic)+4(stream_id)+1(kind)+4(payload_len)` |
| `DATA_RECORD_WIRE_OVERHEAD` | 18 | `2(pad-len field)+16(AEAD tag)` |
| `PADDING_LEN_FIELD` | 2 | self-describing pad-length trailer size |
| `MAX_PQ_HANDSHAKE_FRAME` | 4096 | max reassembled handshake chunk |
| `PQ_HANDSHAKE_CHUNK_MIN_PLAINTEXT` | 256 | min per-chunk plaintext |
| `PQ_HANDSHAKE_CHUNK_MAX_PLAINTEXT` | 1024 | max per-chunk plaintext |
| `PQ_CHUNK_FRAME_HEADER_LEN` | 16 | chunk reassembly header length |
| `MAX_INITIAL_PAYLOAD_CAPTURE` | 4096 | max 0-RTT initial-payload bytes captured at the SOCKS front-end (§15.1) |
| `INITIAL_PAYLOAD_CAPTURE_TIMEOUT` | 2 ms | fixed capture window for the 0-RTT payload (no jitter) |
| `POST_HANDSHAKE_DRAIN_LIMIT` | 4 | max origin post-handshake records the client drains before Phase B (§7.3) |
| `POST_HANDSHAKE_DRAIN_TIMEOUT` | 180 ms | per-record timeout while draining; tolerated only at a record boundary (§7.3) |

### 3.7 Record-size shaping bands (plaintext byte targets)

| Name | Values |
|------|--------|
| `CONNECT_RECORD_SIZE_BANDS` | `[286, 469, 569, 735, 911, 1180, 1353, 1600]` |
| `PQ_FLIGHT_RECORD_TARGETS` | `[144, 191, 286, 339, 469, 519, 569, 713, 735, 911, 1180, 1353]` |
| `PQ_FLIGHT_RECORD_MIN` | `144` |
| `PQ_FLIGHT_AGGREGATE_PAD_MIN` / `_MAX` | `64` / `512` |

### 3.8 UDP-negotiation constants

| Name | Value |
|------|-------|
| `UDP_NEGOTIATION_VERSION` | 1 |
| `UDP_OFFER_ID_LEN` | 16 |
| `UDP_DECLINE_DISABLED` / `_UNSUPPORTED` | 0 / 1 |
| `UDP_CC_BBR` / `UDP_CC_BRUTAL` | 0 / 1 |
| `UDP_FEC_OFF` / `_ADAPTIVE` / `_RS` | 0 / 1 / 2 |

### 3.9 Domain-separation labels (exact ASCII)

These labels are security-critical: an implementation MUST use the exact byte
strings below or it will not interoperate.

**Handshake / transcript / auth:**
- `b"ParallaX v1 handshake transcript"`
- `b"ParallaX v1 ClientHello authentication"`
- `b"ParallaX v4 ClientHello carrier mask key"`
- `b"ParallaX v4 ClientHello.random mask"`
- `b"ParallaX v4 ClientHello session_id tail mask"`
- `b"ParallaX v3 masked stateful rustls ClientHello auth"`

**Traffic-key schedule:**
- `b"ParallaX v2 initial psk+x25519 chain secret"`
- `b"client appdata key"`, `b"server appdata key"`
- `b"client appdata nonce"`, `b"server appdata nonce"`
- `b"ParallaX v1 client appdata"` (AAD, C→S)
- `b"ParallaX v1 server appdata"` (AAD, S→C)

**Substream (mux) keys:**
- `b"ParallaX v1 mux substream client key"`
- `b"ParallaX v1 mux substream server key"`
- `b"ParallaX v1 mux substream client nonce"`
- `b"ParallaX v1 mux substream server nonce"`

**Server identity / PQ rekey:**
- `b"ParallaX v2 ML-DSA-87 server identity"` (ML-DSA signing context)
- `b"ParallaX v2 server identity proof"` (signed message label)
- `b"ParallaX v1 PQ rekey identity binding"`
- Hybrid-rekey IKM markers: `b"x25519:"`, `b"|mlkem1024:"`, `b"|psk:"`

**Replay cache:**
- `b"ParallaX v1 replay cache MAC key"`
- `b"ParallaX v1 replay cache journal header MAC"`
- `b"ParallaX v1 replay cache journal entry MAC"`
- `b"parallax-replay-cache-v3"` (on-disk journal version line)

**QUIC origin-splice marker:**
- `b"ParallaX v1 QUIC marker keystream"`
- `b"ParallaX v1 QUIC marker auth key"`
- `b"ParallaX v1 QUIC marker tag"`

**QUIC-plane exporter-bound auth token (§14.1):**
- `b"ParallaX v1 TUDP auth exporter binding"` (RFC 5705 exporter label)
- `b"ParallaX v1 TUDP auth key"` (HKDF-Expand info)
- `b"ParallaX v1 TUDP auth context"` (exporter-context hash label)

---

## 4. Wire Format

### 4.1 Layering

```
┌─────────────────────────────────────────────────────────────┐
│ Inner message  (PX1C / PX1M / PX1K / ...)                   │  ParallaX
├─────────────────────────────────────────────────────────────┤
│ Padded plaintext = message || padding || pad_len(2 BE)      │  data-record framing (§11)
├─────────────────────────────────────────────────────────────┤
│ AEAD seal (key, nonce=base XOR seq)                         │  crypto (§5)
├─────────────────────────────────────────────────────────────┤
│ TLS-1.3 application-data record (0x17 0x03 0x03 len ...)    │  carrier (§4.2)
├─────────────────────────────────────────────────────────────┤
│ TCP                                                         │
└─────────────────────────────────────────────────────────────┘
```

On the QUIC plane the bottom three layers are replaced by QUIC 1-RTT
stream bytes (§9); the inner-message and data-record-framing layers are
identical.

### 4.2 Carrier TLS record (TCP plane)

A carrier record is exactly a TLS 1.3 record:

```
offset  size  field
0       1     content_type   (0x16 handshake | 0x17 application_data | 0x15 alert)
1       2     legacy_version = 0x03 0x03
3       2     length         (u16 BE, length of the following payload)
5       len   payload
```

- The handshake (`0x16`) records carry the camouflaged ClientHello/ServerHello.
  The client emits a ChangeCipherSpec record — the exact 6 bytes
  `14 03 03 00 01 01` (content type `0x14` = change_cipher_spec, version
  `0x0303`, length 1, body `0x01`) — as the **second record of its first flight,
  immediately after the ClientHello and before reading the ServerHello**. This is REQUIRED for
  middlebox-compat parity: a 32-byte-`session_id` ClientHello that never sends
  the compat CCS matches no BoringSSL/Safari handshake and is a passive
  distinguisher. The CCS is a non-handshake record and is **NOT folded into the
  transcript hash** (the transcript stays `client_hello_record ||
  server_hello_record`, §5.3); the server forwards it verbatim.
- After the handshake completes, all ParallaX inner traffic travels in
  application-data records (`0x17`). The `length` field MUST be ≤
  `MAX_TLS_RECORD_PAYLOAD + 256` on parse; a conforming sealer never produces a
  sealed inner payload larger than `OUTER_TLS_RECORD_LIMIT` (16401).

### 4.3 Sealed inner record payload

The payload of a `0x17` record (after the 5-byte TLS header) is a single
AEAD-sealed unit:

```
ciphertext = AEAD_Seal(key, nonce, plaintext, AAD)   // tag appended
plaintext  = inner_message || padding[pad_len] || pad_len(u16 BE)
```

- `pad_len` is a 2-byte big-endian, **self-describing** trailer placed at the
  END of the plaintext: the last two bytes of the decrypted plaintext give the
  number of padding bytes that immediately precede them.
- The receiver decrypts, reads the trailing `pad_len`, strips `pad_len + 2`
  bytes, and is left with `inner_message`.
- `AAD` is the fixed per-direction label (§5.4): `b"ParallaX v1 client appdata"`
  for client→server records, `b"ParallaX v1 server appdata"` for
  server→client records.
- The on-wire overhead of one record is `DATA_RECORD_WIRE_OVERHEAD = 18` bytes
  (`2` pad-length field + `16` AEAD tag), plus the 5-byte TLS header.

### 4.4 Cursor / length-framing conventions

Inner messages use a simple cursor model. Helpers referenced below:

- `u16()` / `u32()` / `u64()` read a big-endian integer and advance.
- `bytes(n)` reads exactly `n` bytes.
- A length-prefixed blob is `len(u16 or u32 BE) || bytes`.
- Variable trailing fields (e.g. an ML-KEM ciphertext) are framed by a `u32 BE`
  length, and the message MUST consume exactly its declared length (no trailing
  bytes) — otherwise it is rejected (`InvalidPayloadLength`).

---

## 5. Cryptographic Specification

### 5.1 Primitives

| Role | Algorithm | Standard |
|------|-----------|----------|
| Hash | SHA-256 | FIPS 180-4 |
| MAC | HMAC-SHA-256 | RFC 2104 |
| KDF | HKDF-SHA-256 (Extract + Expand) | RFC 5869 |
| Classical KEX | X25519 | RFC 7748 |
| PQ KEM | ML-KEM-1024 | FIPS 203 |
| PQ Signature | ML-DSA-87 | FIPS 204 |
| AEAD (suite 0) | ChaCha20-Poly1305 | RFC 8439 |
| AEAD (suite 1) | AES-256-GCM | NIST SP 800-38D |

All AEADs use a 32-byte key, 12-byte nonce, 16-byte tag.

**Serialization (no ParallaX-specific wrapping).** All asymmetric values appear
on the wire in their standard serialized form — there is no ParallaX envelope,
length tag, or compression around them beyond the message framing of §6:

- **X25519** keys and shared secrets are the raw 32-byte little-endian
  encodings of RFC 7748 (standard clamping applies inside the X25519 function;
  an implementer should use a conformant X25519 and not reimplement clamping).
- **ML-KEM-1024** keys, ciphertexts, and shared secrets are the FIPS 203
  serialized byte strings: encapsulation key 1568 B, decapsulation key 3168 B,
  ciphertext 1568 B, shared secret 32 B. ParallaX transmits exactly these bytes
  (e.g. in `PX1Q`/`PX1K`, §6.2/§6.3).
- **ML-DSA-87** public keys and signatures are the FIPS 204 serialized byte
  strings: public key 2592 B, signature 4627 B (detached). ParallaX transmits
  exactly these bytes (e.g. in `PX1S`, §6.4).

A reimplementation can therefore use any FIPS 203 / FIPS 204 / RFC 7748
conformant library; only the higher-level ParallaX derivations (§5.3–§5.8)
need bespoke code.

### 5.2 X25519 hygiene (MUST)

Every X25519 shared secret MUST be checked, in constant time, against the
all-zero value before use. A zero shared secret (small-order / non-contributory
point) MUST abort the operation (`DegenerateSharedSecret`). This applies to the
initial KEX and to every PQ rekey. The check (and likewise the ClientHello auth
tag comparison, §7.2, and the QUIC marker tag comparison, §12.7) MUST use a
**constant-time** comparison — never `==`/`memcmp` on secret-derived bytes — to
avoid timing oracles (the reference uses `subtle::ConstantTimeEq`).

### 5.3 Initial key schedule

The keys below are **ParallaX-internal** and share nothing with the carrier TLS
1.3 secrets; the carrier ServerHello is the **fallback origin's** real ServerHello
(relayed verbatim, §7.1), and ParallaX binds to its raw record bytes only as
transcript material. After the carrier ClientHello/origin-ServerHello are
exchanged and the client is authenticated (§7.2), both peers hold:

- `psk` — the pre-shared secret (MUST be non-empty),
- `x25519_shared` — the **initial** X25519 shared secret. This is **NOT** the
  TLS `key_share` ECDH and **NOT** the carrier mask ECDH; it is computed from the
  client's *ParallaX ephemeral* key (the one carried, masked, inside
  `ClientHello.random`, §7.2) and the server's *long-term static* X25519 key:
  - client side: `x25519_shared = X25519(parallax_ephemeral_priv, server_static_pub)`
  - server side: `x25519_shared = X25519(server_static_priv, recovered_parallax_ephemeral_pub)`
  This is the **same** shared secret used to derive the ClientHello `auth_key`
  (§7.2), so an implementation computes it exactly once. (Distinguish three
  X25519 ECDHs in Phase A/B, all sharing the server static key on one side:
  (1) the visible TLS `key_share` ECDH — cosmetic, unused by ParallaX;
  (2) `mask_ecdh = X25519(tls_keyshare_ephemeral, server_static)` — unmasks the
  carrier (§7.2); (3) `x25519_shared = X25519(parallax_ephemeral, server_static)`
  — feeds `auth_key` and this chain secret.)
- `transcript_hash` — `SHA-256(b"ParallaX v1 handshake transcript" || client_hello_record || server_hello_record)` (32 bytes), where
  `server_hello_record` is the **fallback origin's** ServerHello record (§7.1).
  The label has **no** length prefix; the two records are concatenated raw, full
  TLS record bytes (5-byte header included), client hello first.

The **initial chain secret** is derived with a standard HKDF
Extract-then-Expand:

```
PRK_init      = HKDF-Extract(salt = psk, IKM = x25519_shared)     // RFC 5869
chain_secret  = HKDF-Expand(PRK_init, info_init, 32)

info_init = u16_be(len(L0)) || L0
          || u64_be(epoch = 0)
          || u16_be(32) || transcript_hash
  where L0 = b"ParallaX v2 initial psk+x25519 chain secret"
```

`chain_secret` is 32 bytes and is the root of the traffic-key schedule.

### 5.4 Per-epoch traffic keys

For a given `epoch` (`u64`, starts at 0) and the current `chain_secret`, derive
four values. **`chain_secret` is used directly as the HKDF pseudo-random key
(PRK); there is NO second HKDF-Extract step.** In RFC 5869 terms the
implementation calls `HKDF-Expand` with `PRK = chain_secret` (the reference uses
`Hkdf::<Sha256>::from_prk(chain_secret)`). Do **not** run
`HKDF-Extract(salt=0, IKM=chain_secret)` first — that produces a different key
and breaks interop.

Each key is then expanded with its label `L`:

```
value = HKDF-Expand(PRK = chain_secret, info, out_len)
info  = u16_be(len(L)) || L
      || u64_be(epoch)
      || u16_be(32) || transcript_hash
```

| Output | Label `L` | `out_len` |
|--------|-----------|-----------|
| client traffic key | `b"client appdata key"` | 32 |
| server traffic key | `b"server appdata key"` | 32 |
| client nonce base | `b"client appdata nonce"` | 12 |
| server nonce base | `b"server appdata nonce"` | 12 |

The client→server direction uses the *client* key+nonce and AAD
`b"ParallaX v1 client appdata"`; the server→client direction uses the *server*
key+nonce and AAD `b"ParallaX v1 server appdata"`. The HKDF-Expand output-length
counter (RFC 5869) is standard: with SHA-256 a 32-byte key is one block `T(1)`,
a 12-byte nonce is the first 12 bytes of `T(1)`.

### 5.4.1 Per-substream keys (MUX / QUIC)

When a session multiplexes streams (§9), each stream derives its **own** four
key/nonce values so no two streams share an AEAD nonce. The derivation is
identical to §5.4 (PRK = `chain_secret`, no extra Extract) except the `info`
adds a `u64_be(stream_id)` field **between** `epoch` and the transcript hash, and
uses distinct labels:

```
value = HKDF-Expand(PRK = chain_secret, info, out_len)
info  = u16_be(len(L)) || L
      || u64_be(epoch)
      || u64_be(stream_id)
      || u16_be(32) || transcript_hash
```

| Output | Label `L` | `out_len` |
|--------|-----------|-----------|
| client substream key | `b"ParallaX v1 mux substream client key"` | 32 |
| server substream key | `b"ParallaX v1 mux substream server key"` | 32 |
| client substream nonce | `b"ParallaX v1 mux substream client nonce"` | 12 |
| server substream nonce | `b"ParallaX v1 mux substream server nonce"` | 12 |

On the QUIC plane `stream_id` is the QUIC wire stream id of the bidi (so both
ends derive the same codec from the id they observe). For TCP-plane `PX1M`
muxing the per-stream id is used identically. The length-prefixed,
fixed-width-integer `info` is injective in `(label, epoch, stream_id,
transcript_hash)`, so distinct streams never collide on a nonce base.

### 5.5 AEAD record sealing and nonce

Each direction maintains an independent `sequence` counter (`u64`, starts at 0).
For the record at sequence `seq`:

```
nonce      = nonce_base XOR ( 0x00000000 || u64_be(seq) )     // 12 bytes
ciphertext = AEAD_Seal(key, nonce, padded_plaintext, AAD)
seq        = seq + 1
```

i.e. the low 8 bytes of the 12-byte `nonce_base` are XORed with the big-endian
sequence number; the high 4 bytes are unchanged. This map is injective in
`seq`, guaranteeing nonce uniqueness per (key, direction). If `seq` would exceed
`u64::MAX` the session MUST abort (`NonceExhausted`); rekeying resets `seq` to 0.

The negotiated AEAD (ChaCha20-Poly1305 or AES-256-GCM) is selected by the server
and signaled in `SERVER_KEY_EXCHANGE` (§3.3); both peers then use it for all
records.

### 5.6 Server identity proof (Phase B authentication)

The server proves it holds the long-term ML-DSA-87 identity the client expects.
It signs, with **ML-DSA-87** under signing context
`b"ParallaX v2 ML-DSA-87 server identity"` (FIPS 204 `ctx`), the message:

```
signed_message = L_id
              || u64_be(epoch)
              || transcript_hash[32]
              || server_ephemeral_x25519_public[32]   // = server_x25519_public from PX1K (§6.3)
              || pq_rekey_binding[32]

  L_id = b"ParallaX v2 server identity proof"

pq_rekey_binding = SHA-256(
        b"ParallaX v1 PQ rekey identity binding"
     || u32_be(len(client_pq_rekey_request)) || client_pq_rekey_request
     || u32_be(len(server_key_exchange))     || server_key_exchange )
```

`client_pq_rekey_request` is the encoded `PX1Q` message bytes; `server_key_exchange`
is the encoded `PX1K` message bytes (see §6). The client verifies the signature
against the server's known ML-DSA-87 public key (config field
`server_identity_public_key`); failure aborts indistinguishably. The `epoch` is
part of the signed message (`u64_be`, immediately after `L_id`), binding the
proof to the current epoch — a proof minted for one epoch does not verify at
another. Concretely: both server (signing) and client (verifying) use the
**post-rekey epoch** — after the first PQ rekey that is `epoch = 1` — and the
**initial-handshake `transcript_hash`** (the `CH || origin-SH` value of §5.3,
which a rekey does NOT change). The client signs/verifies *after* applying the
rekey (§5.7), so `self.keys.epoch` is already 1 when it verifies. The
`server_ephemeral_x25519_public` is the `server_x25519_public` from the `PX1K`
(§6.3) that drove this rekey.

The proof is transported as a `PX1S` message, or fragmented into `PX1I` chunks
(§6.4) when it exceeds a single shaped record (the ML-DSA-87 signature alone is
4627 bytes).

> **`pq_rekey_binding` precise input order (§5.6).** The SHA-256 covers, in
> order: the label, then a `u32_be` length followed by the **encoded `PX1Q`
> request bytes** (`client_pq_rekey_request`, magic included), then a `u32_be`
> length followed by the **encoded `PX1K` exchange bytes** (`server_key_exchange`,
> magic + cipher tag included, i.e. the exact wire bytes the server emitted).
> Both peers MUST hash the on-wire encodings, not the decoded structs.

### 5.7 Post-quantum rekey (hybrid ratchet)

ParallaX upgrades the initial X25519-only secret to a PQ-hybrid secret via a
ratchet that binds X25519 + ML-KEM-1024 + PSK. The client sends `PX1Q`
(`PqRekeyRequest`: ephemeral X25519 public + ML-KEM-1024 public key). The server
encapsulates to the ML-KEM public key, replies with `PX1K`
(`ServerKeyExchange`: its ephemeral X25519 public + ML-KEM ciphertext + cipher
tag), and both compute:

```
x25519_shared = X25519(own_eph_priv, peer_eph_pub)         // 32 bytes, zero-checked
mlkem_shared  = ML-KEM-1024 shared secret                  // 32 bytes

IKM = b"x25519:"      || x25519_shared[32]
   || b"|mlkem1024:" || mlkem_shared[32]
   || b"|psk:"       || u32_be(len(psk)) || psk

new_chain_secret = HKDF-Extract(salt = old_chain_secret, IKM = IKM)   // 32-byte PRK used directly
```

The fixed IKM prefix is 91 bytes (`7 + 32 + 11 + 32 + 5 + 4`). Using the old
chain secret as **salt** (not IKM) means a leaked old secret alone cannot derive
the new one without the fresh ephemeral shares. After rekey, `epoch` increments,
`sequence` resets to 0, and new traffic keys are derived per §5.4.

### 5.8 Chunked handshake reassembly (`PX1F` / `PX1I`)

Large handshake artifacts — chiefly the `PX1Q` PQ-rekey request body — are split
into size-shaped chunks so each sealed record matches a plausible browser record
size (§11). The generic carrier is `PX1F` (`FramedChunk`):

```
offset  size       field
0       4          magic = "PX1F"
4       4          total_len  (u32 BE, full reassembled payload length)
8       4          offset     (u32 BE, this chunk's byte offset)
12      4          chunk_len  (u32 BE, non-zero)
16      chunk_len  bytes
```

The 16-byte header is `PQ_CHUNK_FRAME_HEADER_LEN = 16` (= `4+4+4+4`). The
receiver reassembles strictly in increasing-offset order (out-of-order →
`OutOfOrder`); a differing `total_len` across chunks → `InconsistentTotal`;
`offset + chunk_len > total_len` → `InvalidOffset`. The reassembled artifact MUST
NOT exceed `MAX_PQ_HANDSHAKE_FRAME = 4096` bytes for `PX1F`. Per-chunk plaintext
is drawn from `[PQ_HANDSHAKE_CHUNK_MIN_PLAINTEXT, PQ_HANDSHAKE_CHUNK_MAX_PLAINTEXT]
= [256, 1024]` bytes (the sender picks a per-session chunk size in that range, so
record sizes vary across connections). `PX1I` (§6.4) is the identical layout for
the server identity proof.

---

## 6. Message Types

All inner messages below are carried in the AEAD-sealed record payload (§4.3),
one or more messages per record after de-padding. Every message starts with its
4-byte magic.

### 6.1 CONNECT (`PX1C`) — client → server

Names the destination the server must dial, with optional 0-RTT payload.

```
offset  size      field
0       4         magic = "PX1C"
4       2         host_len   (u16 BE, 1..=255)
6       host_len  host       (UTF-8; IP literal or domain name)
6+H     2         port       (u16 BE, non-zero)
8+H     4         payload_len (u32 BE)
12+H    payload_len  initial_payload  (0-RTT application bytes, may be empty)
```

Validation (each maps to a `ConnectRequestError`, §16): empty host → `EmptyHost`; host > 255
→ `HostTooLong`; non-UTF-8 host → `InvalidHost`; port == 0 → `ZeroPort`;
trailing bytes ≠ declared `payload_len` → `InvalidPayloadLength`; < 4 bytes →
`Truncated`; wrong magic → `BadMagic`.

`host` is a textual host (e.g. `"example.com"`, `"93.184.216.34"`,
`"2606:2800:220:1:248:1893:25c8:1946"`), not a typed address — the server
performs name resolution. The `CONNECT` record is size-shaped to one of
`CONNECT_RECORD_SIZE_BANDS` (§11).

**Server target selection.** By default the server dials the `host:port` from the
`CONNECT`. If the server is configured with a fixed `data_target` (§22.1,
reverse-proxy mode), it **ignores** the client's `host:port` and dials
`data_target` instead — the message is still parsed and validated identically,
only the dialed destination differs. The `initial_payload` (if any) is forwarded
to whichever target is dialed, before the target's first response.

### 6.2 PQ_REKEY (`PX1Q`) — client → server

Client's ephemeral PQ-hybrid offer.

```
offset  size   field
0       4      magic = "PX1Q"
4       32     client_x25519_public
36      4      mlkem_pubkey_len  (u32 BE, non-zero; = 1568 for ML-KEM-1024)
40      L      client_mlkem_public_key  (L bytes)
```

The total length MUST equal `40 + mlkem_pubkey_len` exactly. Empty ML-KEM key →
`EmptyPublicKey`.

### 6.3 SERVER_KEY_EXCHANGE (`PX1K`) — server → client

```
offset  size   field
0       4      magic = "PX1K"
4       32     server_x25519_public
36      4      mlkem_ct_len  (u32 BE, non-zero; = 1568 for ML-KEM-1024)
40      C      mlkem_ciphertext  (C bytes)
40+C    1      cipher_suite_tag   (0x00 ChaCha20-Poly1305 | 0x01 AES-256-GCM)  [with-suite form]
```

The encoder supports two forms: a base form ending after the ciphertext, and the
**with-suite** form that appends the 1-byte negotiated cipher tag. **On the wire,
ParallaX always sends the with-suite form**, and the client always reads the
trailing tag and adopts that AEAD for all subsequent records. (The base form
exists only as an internal encoder variant; a conforming implementation emits and
expects the with-suite form.) `cipher_suite_tag` is a ParallaX AEAD selector
(1 byte, §3.3), **not** a 2-byte TLS cipher-suite id.

### 6.4 SERVER_IDENTITY (`PX1S`) and chunk (`PX1I`) — server → client

Carries the ML-DSA-87 server-identity proof (§5.6). When the proof fits a single
shaped record it is sent whole as `PX1S`; otherwise it is fragmented into `PX1I`
chunks reassembled in offset order.

**`PX1S` (ServerIdentityProof), 8-byte header:**

```
offset  size      field
0       4         magic = "PX1S"
4       4         sig_len    (u32 BE, non-zero; = 4627 for ML-DSA-87)
8       sig_len   signature  (the ML-DSA-87 detached signature)
```

Total length MUST equal `8 + sig_len`. The `signature` is the raw FIPS 204
signature; the verifier checks it against the signed message of §5.6.

**`PX1I` (ServerIdentityChunk), 16-byte header — used when fragmenting:**

```
offset  size       field
0       4          magic = "PX1I"
4       4          total_len  (u32 BE, full reassembled proof byte length)
8       4          offset     (u32 BE, this chunk's byte offset into the proof)
12      4          chunk_len  (u32 BE, non-zero, bytes in this chunk)
16      chunk_len  bytes
```

Total record length MUST equal `16 + chunk_len`. Validation: empty chunk →
`EmptyChunk`; `offset + chunk_len > total_len` or `total_len == 0` →
`InvalidOffset`; a chunk arriving with `offset ≠ next_expected` → `OutOfOrder`; a
`total_len` differing between chunks → `InconsistentTotal`. The receiver
concatenates chunk `bytes` strictly in increasing-offset order to recover the
`PX1S` proof body (the reassembled bytes are the signature itself, then verified
per §5.6).

> **Note on chunk reassembly vs. `PX1F`.** `PX1I` and the generic `PX1F`
> (`FramedChunk`, §5.8) share the identical 16-byte
> `magic||total_len||offset||chunk_len` header layout and in-order semantics;
> they differ only in magic and in what the reassembled payload is (`PX1I` →
> ML-DSA proof; `PX1F` → the `PX1Q` PQ-rekey request body).

### 6.5 MUX_FRAME (`PX1M`) — bidirectional

The stream-multiplexing unit (full semantics in §9).

```
offset  size         field
0       4            magic = "PX1M"
4       4            stream_id   (u32 BE)
8       1            kind        (1 OPEN | 2 DATA | 3 FIN | 4 RESET | 5 COVER)
9       4            payload_len (u32 BE)
13      payload_len  payload
```

`MUX_FRAME_FIXED_LEN = 13`. Stream-id rules: `kind ∈ {OPEN,DATA,FIN,RESET}`
requires `stream_id != 0`; `kind == COVER` requires `stream_id == 0`. A
violation is `InvalidStreamId`. `kind` outside 1..=5 is `InvalidKind`. For an
`OPEN` frame, the `payload` is a complete `CONNECT` (`PX1C`) message.

### 6.6 UDP negotiation messages (optional, QUIC plane)

Used over the established TCP session to bootstrap the QUIC plane (§9.1). All
lengths are fixed.

**UDP_REQUEST (`PX1G`, C→S, 5 bytes):** `magic || version(u8 = 1)`.

**UDP_OFFER (`PX1O`, S→C, `4 + 16 + 2 + 8 + 1 + 1 + 1 = 33` bytes):**

```
offset  size  field
0       4     magic = "PX1O"
4       16    offer_id            (ties a later PROBE_ACK to this offer)
20      2     udp_port    (u16 BE, non-zero)
22      8     port_hop_seed (u64 BE; seeds optional UDP port hopping)
30      1     cc          (congestion control: 0 BBR, 1 Brutal)
31      1     fec_profile (0 off, 1 adaptive, 2 Reed-Solomon)
32      1     ignore_client_bandwidth (0 or 1; if 1 the server ignores the
                client's advertised bandwidth when pacing)
```

**UDP_PROBE_ACK (`PX1P`, C→S, `4 + 16 + 1 + 4 = 25` bytes):**

```
offset  size  field
0       4     magic = "PX1P"
4       16    offer_id     (echoes the UDP_OFFER it responds to)
20      1     status       (0 Verified, 1 Unreachable, 2 Failed)
21      4     rtt_micros   (u32 BE, measured round-trip time in microseconds)
```

`status` values: `0` = a verified application round-trip succeeded over the UDP
leg; `1` = the UDP leg was unreachable / black-holed; `2` = the probe failed for
another reason. A status byte outside 0..=2 is rejected (`InvalidStatus`).

**UDP_DECLINE (`PX1N`, S→C, 5 bytes):** `magic || reason(u8)`, with
`reason ∈ {0 disabled, 1 unsupported}`.

A minimal TCP-only implementation MAY ignore all `PX1G/O/P/N` messages.

---

## 7. Handshake Specification

This section gives the full ordered exchange for the TCP plane. (QUIC differs
only in the carrier; §9.)

> **The carrier is a real, complete TLS 1.3 handshake completed by the fallback
> origin — the ParallaX server holds no TLS certificate.** This is the single
> most important architectural fact for a reimplementer. Phase A is a genuine
> RFC 8446 TLS 1.3 handshake, but the server side of it is played by the **real
> fallback origin**, not by the ParallaX server:
>
> 1. The client sends its (auth-bearing) ClientHello to the ParallaX server.
> 2. The server checks the embedded auth (§7.2). **Whether auth succeeds or
>    fails, the server opens a TCP connection to `fallback_addr` and forwards the
>    client's ClientHello to that real origin.**
> 3. The server reads the **origin's real ServerHello** and forwards it verbatim
>    to the client. The transcript hash (§5.3) is computed over
>    `client_hello_record || origin_ServerHello_record` — i.e. the ServerHello is
>    the origin's, not synthesized by ParallaX.
> 4. The origin's remaining TLS 1.3 flight — `EncryptedExtensions` (0x08),
>    `Certificate`/`CompressedCertificate` (0x0b/0x19), `CertificateVerify`
>    (0x0f), `Finished` (0x14) — is **transparently relayed** between client and
>    origin (in both directions). The client **verifies the origin's genuine
>    certificate chain against `sni`** and completes the handshake as a browser
>    would.
> 5. **Divergence point.** If auth *failed*, the server simply keeps relaying
>    client↔origin forever (origin-splice, §13) — the connection is an ordinary
>    TLS session to the origin. If auth *succeeded*, the server keeps relaying
>    until the client sends its first ParallaX inner record (`PX1Q`, §7.3) inside
>    the established TLS application-data stream; that record is the client's
>    signal "switch to ParallaX from here." On seeing `PX1Q`, the server stops
>    relaying to the origin and runs the inner protocol itself, using the keys
>    derived in step 3.
>
> Consequences for a reimplementation:
> - The ParallaX **server needs no TLS certificate or key** — it borrows the
>   fallback origin's real handshake. It MUST be able to reach `fallback_addr`.
> - The **client** needs a conformant TLS 1.3 client with real certificate
>   verification against `sni`.
> - ParallaX's own auth (masked `random`/`session_id`, §7.2) and inner key
>   schedule (§5.3) ride **alongside** this real TLS and share nothing with the
>   TLS 1.3 secrets; the TLS key_share ECDH is cosmetic to ParallaX (§5.3).
> - Before `PX1Q`, the server caps how much origin→client traffic it relays
>   (`MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS` = 64 records / ~1 MiB) and bounds
>   the whole pre-`PX1Q` phase by the fallback idle timeout; a client that
>   authenticates MUST send `PX1Q` promptly (within ms).

### 7.1 Sequence

In Phase A the ParallaX SERVER bridges the client to the real FALLBACK ORIGIN,
which plays the TLS 1.3 server role; the ParallaX server only relays until it
sees `PX1Q`.

In the diagram, `===>` is a relay: the ParallaX server forwards the bytes between
client and origin unchanged. Phase A is a real TLS 1.3 handshake whose server
side is the origin.

```
CLIENT                          PARALLAX SERVER                      FALLBACK ORIGIN
  │                                   │                                   │
  │ Phase A — real TLS 1.3, origin plays the TLS server                   │
  │── ClientHello (auth in ──────────►│ recover+verify auth & replay      │
  │   random+session_id)              │ (in parallel, UNCONDITIONALLY):   │
  │                                   │ connect origin, forward CH ======>│
  │                                   │◄═══════════ ServerHello ══════════│ origin's real SH
  │◄═══════════ ServerHello ══════════│transcript = CH || origin SH (§5.3)│
  │══ ChangeCipherSpec ══════════════════════ (client's flight) ═════════►│
  │◄═══ EncryptedExtensions, Certificate, CertificateVerify, Finished ════│ origin's real
  │       (client verifies ORIGIN cert vs sni)                            │  cert + flight
  │── Finished ══════════════════════════════════════════════════════════►│
  │                                   │                                   │
  │== both derive chain_secret + epoch-0 keys from the ParallaX auth ECDH │
  │   (§5.3/§5.4; independent of the TLS secrets; ServerHello is origin's)│
  │                                   │                                   │
  │ Phase B — PQ hybrid + identity (sealed, inside the established TLS)   │
  │─ PX1Q PqRekeyRequest(PX1F chunks)►│ first valid PX1Q ──► server STOPS │
  │                                   │  relaying, drops origin ────────╳ │ (origin closed)
  │                                   │  and answers as ParallaX itself:  │
  │◄── PX1K ServerKeyExchange (+tag) ─│                                    
  │◄── PX1S/PX1I ServerIdentityProof ─│ (ML-DSA-87 signature)             
  │== rekey: epoch=1, seq=0, new keys │  (§5.7)                           
  │   (client verifies ML-DSA sig; FAIL ─► abort)                          
  │                                   │                                    
  │ Phase C — command (sealed)        │                                    
  │── PX1C CONNECT host:port(+0-RTT) ►│ server dials the real target      
  │                                   │                                    
  │ Phase D — data relay (sealed, optionally muxed)                       
  │◄───────── PX1M / record stream ──►│                                   
```

If auth had FAILED at the top, the server would simply keep relaying
client↔origin (`===>`) indefinitely (origin-splice, §13) and never reach
Phase B — byte-identical to the success path up to the point where a valid
`PX1Q` would arrive.

### 7.2 Phase A details (carrier authentication)

The client builds a Safari-26 ClientHello (§12.2) and overwrites two fields with
authenticated, masked ParallaX material. Let:

- `parallax_x25519` = the client's ephemeral ParallaX X25519 keypair used for the
  inner KEX (distinct from the TLS key_share ephemeral),
- `tls_ephemeral` = the X25519 keypair whose public half the client places in the
  ClientHello's **plain X25519 `key_share` entry (group `0x001d`)** — NOT the
  X25519MLKEM768 (`0x11ec`) hybrid entry, which carries an independent throwaway
  key. The server reads `tls_ephemeral_pub` from exactly that `0x001d` key_share.
  (A real Safari ClientHello carries both shares; ParallaX binds the mask to the
  `0x001d` one.)
- `mask_ecdh = X25519(tls_ephemeral_priv, server_static_pub)` — equivalently
  `X25519(server_static_priv, tls_ephemeral_pub)` on the server side,
- `tail = u64_be(unix_seconds) || nonce[8]` (16 bytes; §3.5),
- `auth_key = HKDF(salt=psk, IKM=X25519(parallax_x25519_priv, server_static_pub))`
  expanded with `b"ParallaX v1 ClientHello authentication"` → 32 bytes,
- `mask_key = HKDF(salt=psk, IKM=mask_ecdh)` expanded with
  `b"ParallaX v4 ClientHello carrier mask key"` → 32 bytes.

Then:

```
random_mask  = HMAC-SHA256(mask_key,
                 b"ParallaX v4 ClientHello.random mask"
              || u16_be(len(sni)) || sni
              || u16_be(16) || tail
              || u16_be(0) )[0..32]

encoded_random = parallax_x25519_pub XOR random_mask          // → ClientHello.random (32B)

tail_mask    = HMAC-SHA256(mask_key,
                 b"ParallaX v4 ClientHello session_id tail mask"
              || u16_be(len(sni)) || sni
              || u16_be(32) || encoded_random
              || u16_be(0) )[0..16]

encoded_tail = tail XOR tail_mask                              // 16B

tag = HMAC-SHA256(auth_key,
        b"ParallaX v3 masked stateful rustls ClientHello auth"
     || u16_be(len(sni)) || sni
     || parallax_x25519_pub[32]
     || tail[16]
     || encoded_random[32]
     || encoded_tail[16] )[0..16]

session_id   = tag[16] || encoded_tail[16]                     // → ClientHello.session_id (32B)
```

> **Note on the two masks vs. the tag.** `random_mask` and `tail_mask` are
> produced by the **same** generic masking helper, which always frames its two
> variable inputs as `u16_be(len) || bytes` and **always appends a trailing
> `u16_be(0)`** for an (unused) empty second field. So BOTH mask HMACs carry the
> `|| u16_be(0)` shown above — it is not specific to `random_mask`. The auth
> `tag`, by contrast, is produced by a **different** helper that does NOT append
> that trailer and does NOT length-prefix the fixed-width fields after `sni`
> (the public key, tail, encoded_random, encoded_tail are concatenated raw, as
> shown). Reproduce the two helpers exactly as written or the tag will not
> verify.

**Server side.** The server reads the ClientHello, requires `session_id` to be
exactly 32 bytes and an SNI to be present, recomputes `mask_key` from
`X25519(server_static_priv, tls_ephemeral_pub)`, decodes `encoded_tail` →
`tail`, decodes `encoded_random` → `parallax_x25519_pub`, recomputes `auth_key`
from `X25519(server_static_priv, parallax_x25519_pub)`, recomputes `tag`, and
compares it to `session_id[0..16]` **in constant time**. If it matches and the
replay/freshness check (§7.4) passes, the client is authenticated. Otherwise the
server origin-splices (§13) — no distinguishable failure.

### 7.3 Phase B details

**Client post-handshake drain (REQUIRED).** After the origin-played TLS handshake
completes, the real origin typically emits post-handshake records — chiefly one
or more TLS 1.3 `NewSessionTicket` messages — which the ParallaX server relays to
the client. The client MUST **drain these records to a clean TLS record boundary
before** starting the ParallaX inner protocol; otherwise it would mistake the
origin's TLS app-data (which it cannot decrypt under ParallaX keys) for ParallaX
records and desync. The reference drains up to `POST_HANDSHAKE_DRAIN_LIMIT = 4`
records with a `POST_HANDSHAKE_DRAIN_TIMEOUT = 180 ms` per-record timeout, and may
stop early on a clean close; a timeout is tolerated only **at a record boundary**
(a mid-record stall is a hard error, to avoid handing a desynced stream to the
data phase). A reimplemented client needs equivalent draining; the ParallaX
server, having dropped the origin on `PX1Q`, never sends these.

Once that drain reaches a record boundary, the client sends `PX1Q` (its ephemeral
X25519 + ML-KEM-1024 public key), chunked into browser-shaped `PX1F` frames,
sealed under the epoch-0 keys (§5.3) inside the TLS application-data stream. The
**first ParallaX application-data record an authenticated client sends MUST be
the first `PX1Q` chunk** — not an HTTP/2 preface or any other payload: an
authenticated server feeds every post-handshake client record straight into the
epoch-0 decryptor and PX1Q reassembler, so a non-`PX1Q` first record fails to
decode and tears the session down. **`PX1Q` is the trigger that ends Phase A
relaying:** up to this point the ParallaX server has been transparently bridging
the client to the fallback origin (§7.1); on decrypting a valid `PX1Q` it drops
the origin connection and answers as the ParallaX server itself. (A client that
authenticated MUST send `PX1Q` promptly — within ms — or the server tears down at
the pre-`PX1Q` deadline.) The server replies with `PX1K` (its ephemeral X25519 +
ML-KEM ciphertext + 1-byte cipher tag), then the `PX1S`/`PX1I` ML-DSA-87 identity
proof. Both perform the hybrid ratchet (§5.7):
`epoch → 1`, `sequence → 0`, fresh traffic keys. The client MUST verify the
ML-DSA-87 signature before sending any `CONNECT`; verification failure aborts the
session (no `CONNECT`, connection closed like a normal origin would).

### 7.4 Replay / freshness check

Once the auth tag verifies (§7.2), the server runs this freshness/replay check
before treating the client as authenticated (a failure here is treated exactly
like an auth failure → indefinite origin relay). The server extracts
`(timestamp, nonce)` from the recovered `tail` plus a transcript fingerprint of
the ClientHello, and consults the replay cache (capacity/semantics §13.1,
on-disk journal §18):

- `timestamp` MUST satisfy `now − window ≤ timestamp ≤ now + 5s` (`window`
  default 120 s; `+5 s` future skew clamp). Outside → `Stale`, splice.
- The `(nonce, transcript_fingerprint)` MUST be unseen within the window.
  Seen → `Replayed`, splice.
- On acceptance the entry is inserted (single-use).

### 7.5 Handshake timeout

The whole authenticated handshake (Phases A–C) is bounded by a server-side
timeout (default 8 s). Exceeding it closes the connection like an idle origin.

---

## 8. State Machine

### 8.1 Client states

```
   INIT
    │ build ClientHello (carrier auth)               (§7.2)
    ▼
   CARRIER_HANDSHAKE ── recv ServerHello ──► KEYS_DERIVED
    │ (TLS handshake completes)                       (§5.3)
    ▼
   PQ_REKEY_SENT ── send PX1Q ──────────────► await PX1K
    │
    ▼
   IDENTITY_WAIT ── recv PX1K + verify ML-DSA-87 ──► REKEYED   (§5.6,§5.7)
    │ (signature OK)                                  │ (signature BAD)
    ▼                                                 ▼
   CONNECT_SENT ── send PX1C ──► ESTABLISHED        ABORT (close)
                                    │
                                    ▼
                                 RELAY (data / mux)  ── FIN/RESET/close ──► CLOSED
```

### 8.2 Server states

In all cases the server connects to the fallback origin and relays its real TLS
handshake to the client; the only difference is whether it later takes the
connection over.

```
   ACCEPT ── read ClientHello ──► AUTH_DECIDE
                                    │ connect fallback origin, forward CH,
                                    │ relay origin ServerHello+flight to client
                                    │ (transcript = CH || origin SH; derive keys)
              ┌─────────────────────┴────────────────────────┐
        authenticated & fresh                       not-auth / replay / malformed
              │                                              │
              ▼                                              ▼
        BRIDGE_UNTIL_PX1Q                             ORIGIN_SPLICE  (§13)
         (keep relaying client↔origin;               (relay client↔origin forever;
          await client's first PX1Q)                  indistinguishable from a real origin)
              │ recv valid PX1Q → drop origin
              ▼
        SEND_KEX+IDENTITY (PX1K, PX1S/PX1I) ──► REKEYED
              │
              ▼
        AWAIT_FIRST_RECORD ── dispatch on magic (§9 mode selection) ──┐
              │ PX1C → single CONNECT   PX1M → MUX   PX1G → QUIC nego │
              ▼                                                       │
        DIAL_TARGET ──► RELAY ──► CLOSED ◄────────────────────────────┘
```

Note `BRIDGE_UNTIL_PX1Q` and `ORIGIN_SPLICE` are byte-identical to an observer
until a valid `PX1Q` arrives — only an authenticated client can produce one.

**Fail-closed rule (I3).** In any state ≥ KEYS_DERIVED, an AEAD open failure,
nonce exhaustion, transcript mismatch, malformed inner message, or policy
rejection MUST move the session to CLOSED/ABORT and tear down the carrier
exactly as a normal origin would on connection error. No distinct signal.

---

## 9. Stream Multiplexing

ParallaX supports two relay modes over an authenticated session:

1. **Single-CONNECT mode.** The session carries exactly one tunnel: after Phase
   C the record stream is the raw, bidirectional proxied bytes for that one
   target. Simplest; sufficient for a basic implementation.

2. **MUX mode.** Many logical streams share one carrier, framed by `PX1M`
   (§6.5). This is the default for the client's SOCKS front-end so multiple
   browser connections reuse one camouflaged tunnel.

**Mode selection.** The mode is chosen by the **magic of the first sealed inner
record after the PQ rekey** (§7.3), which the server dispatches on:
- `PX1M` (MuxFrame) → MUX mode for the whole session;
- `PX1C` (ConnectRequest) → single-CONNECT mode;
- `PX1G` (UdpRequest, §6.6) → enter QUIC-plane negotiation;
- `PX1T` (SpeedTest) → the optional bandwidth self-test.

There is no separate mode-select message; a conforming server branches on this
first record's 4-byte magic.

### 9.1 MUX framing and stream lifecycle

Each logical stream is identified by a `u32` `stream_id`.

- **Allocation.** The client allocates stream ids as **odd** values starting at
  1, incrementing by 2 (`next = fetch_add(2) | 1`). `stream_id = 0` is reserved
  for `COVER` frames. (A server-initiated stream scheme is not used in the TCP
  plane; the client always initiates.)
- **OPEN (kind 1).** Carries a complete `CONNECT` (`PX1C`) as its payload,
  telling the server the target for this stream. After OPEN the server dials and
  the stream is established.
- **DATA (kind 2).** Carries stream payload bytes. Multiple DATA frames per
  stream, interleaved with other streams' frames.
- **FIN (kind 3).** Graceful half-close: the sender will send no more DATA on
  this `stream_id`. The reverse direction may keep flowing until its own FIN.
- **RESET (kind 4).** Abortive close of the stream (e.g. target connect failed,
  peer reset). The id is then retired.
- **COVER (kind 5).** Padding/keepalive on `stream_id = 0`; the receiver
  discards the payload. Used for traffic shaping and to keep a warm tunnel
  alive.

A `MuxFrame` is self-delimiting via its `payload_len`; a record may contain one
or more concatenated frames (decode-prefix then continue). Frames from different
streams may be freely interleaved across records.

### 9.2 QUIC-plane multiplexing

On the QUIC plane, each logical stream maps to its **own QUIC bidirectional
stream** (native multiplexing) rather than `PX1M` framing. The per-substream
AEAD record codec is keyed by the QUIC wire stream id (so both ends derive the
matching substream keys; §5 substream labels). The first record on a substream
is the sealed `CONNECT`. Teardown is per-QUIC-stream (clean FIN on success,
`RESET_STREAM` on error). Business streams are opened as HTTP/3 request streams
carrying a `GET` HEADERS frame, with ParallaX records riding inside H3 `DATA`
frames (§12).

---

## 10. Flow Control

ParallaX does **not** define an application-layer credit/window protocol in the
TCP plane. Flow control is delegated:

- **TCP plane.** Backpressure is the underlying TCP socket plus bounded internal
  channels: a reader stops pulling from the carrier when the per-stream writer
  channel is full, which stalls the sealer, which stalls TCP reads, propagating
  the destination's or client's pace end-to-end. There are no `WINDOW_UPDATE`
  frames in the ParallaX inner protocol (the only `WINDOW_UPDATE` on the wire is
  the **camouflage** HTTP/2 one, §12, which is a fixed cosmetic value, not real
  flow control).
- **QUIC plane.** Native QUIC connection- and stream-level flow control governs
  pacing, using the Safari-26 transport-parameter values (§12): connection
  `initial_max_data` 16 MiB, per-stream `initial_max_stream_data_*` 2 MiB,
  `initial_max_streams_uni` 8, `active_connection_id_limit` 64.

Consequently, an interoperable peer needs only to honor carrier-level
backpressure and the QUIC transport parameters; it does not implement a bespoke
windowing scheme.

### 10.1 Record batching and parallel sealing

For throughput, a sender MAY seal multiple records as a batch. Records in a
batch map to consecutive sequence numbers `base..base+n` in order, so the
receiver opens them with the same consecutive sequence numbers. This is purely a
performance optimization and is wire-transparent — each record is an independent
AEAD unit with its own sequence-derived nonce (§5.5).

---

## 11. Data Record Framing & Record-Size Shaping

This section describes the **TCP plane**. The padded-plaintext + AEAD sealing of
§11.1 applies on both planes (the inner ParallaX record is AEAD-sealed the same
way on QUIC, §9.2), but the TLS record header and the record-size shaping of
§11.2 are TCP/TLS-specific: on the QUIC plane the sealed record rides inside an
H3 `DATA` frame with **no** TLS record header, and packet sizing/camouflage is
handled by the QUIC/H3 layer (§12.5–12.6), not by the §11.2 bands.

### 11.1 Plaintext layout (recap)

```
padded_plaintext = inner_message || padding[pad_len] || u16_be(pad_len)
sealed_record    = TLS_header(0x17,0x0303,len) || AEAD_Seal(key,nonce,padded_plaintext,AAD)
```

Sealing MUST reject any record whose `padded_plaintext + 16` (tag) would exceed
`OUTER_TLS_RECORD_LIMIT = 16401` (`PayloadTooLarge`); records are never silently
truncated.

### 11.2 Size shaping (camouflage, normative for I1)

To make ParallaX record sizes match Safari's, specific records are padded up to
target sizes drawn from fixed bands:

- **CONNECT record.** The sender computes `raw_wire = encoded_len +
  DATA_RECORD_WIRE_OVERHEAD(18)`, collects every band in
  `CONNECT_RECORD_SIZE_BANDS = [286, 469, 569, 735, 911, 1180, 1353, 1600]` with
  `band ≥ raw_wire` and `band − raw_wire ≤ max_extra_pad` (where `max_extra_pad`
  is how much pad this record can still take without pushing the sealed record
  past `OUTER_TLS_RECORD_LIMIT`), then **picks one of the fitting bands uniformly
  at random** (NOT the smallest — random choice decorrelates the on-wire length
  from the host length and 0-RTT payload size).
  The pad rides the self-describing 2-byte trailer (§11.1), so decoding is
  unchanged. If no band fits (large 0-RTT payload) shaping is skipped for that
  record and its size is dominated by the payload.
- **PQ handshake flight (`PX1Q`, `PX1K`, identity).** Chunked and shaped to
  `PQ_FLIGHT_RECORD_TARGETS = [144, 191, 286, 339, 469, 519, 569, 713, 735, 911,
  1180, 1353]`, with a minimum record size of `PQ_FLIGHT_RECORD_MIN = 144`
  (no tiny records), and a per-session aggregate pad in
  `[PQ_FLIGHT_AGGREGATE_PAD_MIN, PQ_FLIGHT_AGGREGATE_PAD_MAX] = [64, 512]`
  applied to the last record of the flight to decorrelate the total flight size.
- **Control frames.** The fixed-length in-band control frames — UDP negotiation
  (`PX1G`/`PX1O`/`PX1P`/`PX1N`) and the `SPEED_*` diagnostics — are **also** padded
  up to a `CONNECT_RECORD_SIZE_BANDS` target, so a tiny fixed-size control record
  does not stand out as a non-browser tell. Same random-band selection as CONNECT.
- **Steady-state data.** Records are filled toward `MAX_TLS_RECORD_PAYLOAD`
  (16384 plaintext) to mirror Safari's bulk-transfer record packing (one app
  write → one record → one TCP segment in steady state; no `1/n−1` split, no
  coalescing across records).

These targets are *plaintext* byte counts; the on-wire record adds the 18-byte
data-record overhead and the 5-byte TLS header.

### 11.3 Optional traffic-shaping profiles

Beyond the mandatory record-size shaping of §11.2, ParallaX has three optional,
config-driven shaping profiles (all default to **off**, biasing toward
throughput). They affect only padding and timing — never the wire format or
decoding — so two peers interoperate regardless of each side's settings.

- **PaddingProfile (`min_padding`, `max_padding`; default 0/0).** Adds a random
  number of pad bytes (sampled in `[min, max]`) to each data record, on top of
  the self-describing 2-byte trailer (§11.1). With the default 0/0 a record gets
  no extra profile padding. Padding rides the same trailer, so the receiver
  strips it transparently.
- **TimingProfile (`min_delay_ms`, `max_delay_ms`; default 0/0).** When enabled
  (`max > min`), delays each flush by a sampled duration: with 60% probability it
  draws from an observed browser inter-write delay distribution (clamped to
  `[min, max]`), otherwise it draws uniformly from `[min, max]`. Default 0/0
  disables delay.
- **CoverTrafficProfile (`cover_min_interval_ms`, `cover_max_interval_ms`;
  default 0/0).** When enabled (`cover_max_interval_ms > 0`), emits `COVER`
  frames (MUX kind 5 on `stream_id = 0`, §6.5) at random intervals sampled in
  `[min, max]` during idle periods, so an idle tunnel still resembles a live
  browser connection. The receiver discards COVER payloads.

Because these are local policy, a reimplementation MAY omit all three and remain
interoperable; enabling them only changes this peer's own emitted padding/timing.

This section is normative for invariant I1. The values below are the exact
Safari 26 fingerprint the reference implementation reproduces; deviating from
them in field order or value is a distinguishing tell.

### 12.1 GREASE

A 16-value GREASE table is used:

```
BROWSER_GREASE_VALUES = [
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa ]
```

Per ClientHello, a 6-byte seed selects: cipher GREASE = `values[seed[0] % 16]`,
first-extension GREASE = `values[seed[1] % 16]`, group GREASE, version GREASE,
and a final-extension GREASE chosen **independently** and forced distinct from
the first via a stride so the first→last delta is uncorrelated with the cipher
GREASE.

### 12.2 TLS 1.3 ClientHello (TCP plane)

**Cipher suites (21, GREASE-led), in order:**

```
[GREASE], 0x1302, 0x1303, 0x1301,            // TLS1.3 AEADs (256-GCM, ChaCha, 128-GCM)
0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
0xc00a, 0xc009, 0xc014, 0xc013,
0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a
```

**Extension order (exact):**

```
1.  [GREASE]                    (empty)
2.  server_name        0x0000   (SNI)
3.  extended_master_secret 0x0017 (empty)
4.  renegotiation_info 0xff01   ([0x00])
5.  supported_groups   0x000a
6.  ec_point_formats   0x000b   ([0x01,0x00])
7.  application_layer_protocol_negotiation 0x0010 (ALPN)
8.  status_request     0x0005   ([0x01,0,0,0,0])
9.  signature_algorithms 0x000d
10. signed_certificate_timestamp 0x0012 (empty)
11. key_share          0x0033
12. psk_key_exchange_modes 0x002d ([0x01,0x01])
13. supported_versions 0x002b
14. compress_certificate 0x001b ([0x02,0x00,0x01])  (zlib)
15. [GREASE final]              ([0x00])
```

**signature_algorithms list (exact, includes Apple's intentional duplicate
`0x0805`):**

```
0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201
```

**key_share groups:** `[GREASE]`, then **X25519MLKEM768** (`0x11ec`, a
1216-byte client share = 1184-byte ML-KEM-768 encapsulation key + 32-byte
X25519), then **X25519** (`0x001d`, 32 bytes). Note: this PQ group is the
*camouflage* key share (ML-KEM-768); it is independent of the inner KEX which
uses ML-KEM-1024 (§5).

**supported_versions:** contains TLS 1.3 (`0x0304`) plus a version GREASE.
**ALPN:** `h2` and `http/1.1` (TCP plane).

The ParallaX auth material overwrites `ClientHello.random` (32 B) and
`ClientHello.session_id` (32 B) per §7.2. A real Safari client randomizes both,
so the substitution is invisible.

### 12.3 ServerHello (TCP plane)

The ServerHello is the **real fallback origin's** ServerHello, relayed verbatim
by the ParallaX server (§7.1) — ParallaX does not synthesize it. It is a standard
TLS 1.3 ServerHello: `legacy_version = 0x0303`, `cipher_suite ∈ {0x1301, 0x1302,
0x1303}`, `supported_versions` containing `0x0304`, and a `key_share` of either
X25519 (`0x001d`, 32 B) or X25519MLKEM768 (`0x11ec`, 1088-byte ML-KEM-768
ciphertext + 32-byte X25519). (Consequently the fallback origin must itself be a
TLS-1.3 host that mirrors a 32-byte `session_id`; mainstream CDNs/origins like
`cloudflare.com:443` do.)

The ServerHello `session_id` **MUST be exactly 32 bytes and MUST be the verbatim
echo** of the ClientHello `session_id` (a TLS 1.3 middlebox-compat behavior real
origins exhibit). A ServerHello whose echoed `session_id` is not 32 bytes causes
the client to **abort the session** (it closes like any failed TLS handshake — no
distinguishable signal). The echo lets the client recover its own auth material
if needed.

### 12.4 HTTP/2 fingerprint (TCP plane)

After the TLS handshake, the connection looks like Safari's HTTP/2:

- **SETTINGS** (4 settings): `ENABLE_PUSH = 0`, `MAX_CONCURRENT_STREAMS = 100`,
  `INITIAL_WINDOW_SIZE = 2_097_152` (2 MiB), `NO_RFC7540_PRIORITIES (0x09) = 1`.
- **WINDOW_UPDATE**: connection-level increment `+10_420_225` (raising the
  connection window to ~10 MiB). This is cosmetic camouflage, not ParallaX flow
  control (§10).
- The opening client write coalesces the H2 preface + SETTINGS + WINDOW_UPDATE +
  first HEADERS into one record, matching Safari.
- **Request pseudo-header order:** `:method`, `:scheme`, `:authority`, `:path`
  (m, s, a, p).

ParallaX inner records ride as HTTP/2 `DATA` frame payloads on a long-lived
stream; a DATA frame body is sized at 16374 to sit just under the 16384 record
boundary, matching Safari's bulk-transfer behavior.

### 12.5 QUIC ClientHello (QUIC plane)

> **QUIC-plane architecture differs fundamentally from the TCP plane.** On the
> TCP plane the ParallaX server holds no TLS key and *borrows* the fallback
> origin's real TLS handshake (§7.1). On the QUIC plane the ParallaX server **is
> itself the QUIC/TLS endpoint** (it terminates QUIC with its own, e.g.
> self-signed, certificate) and the client **does not verify that certificate**
> (it accepts any server cert — authentication is the covert marker, not PKI).
> The single process-wide endpoint bound on `:443/UDP`:
> - **marker-terminates** a client whose first Initial carries a valid + fresh +
>   non-replayed covert marker (§12.7) — these are the only connections the
>   server accepts as ParallaX;
> - **splices every other v1 Initial verbatim to the real origin** (no / forged /
>   replayed marker, junk, or non-v1) inside the endpoint, so a prober reaches the
>   true origin and ParallaX emits nothing of its own (the QUIC analogue of TCP
>   origin-splice).
>
> The client sets the QUIC **Destination Connection ID to the session's 16-byte
> `offer_id`** (from `PX1O`, §6.6); the server uses that DCID to correlate the
> incoming QUIC connection back to the TCP session that offered the fast plane
> (it cannot predict the client's UDP source port). The QUIC plane reuses the
> PSK + server-static-X25519 trust, not the TCP session's traffic keys; it runs
> its own QUIC handshake and (after it) the exporter-bound auth token of §14.1.

- **QUIC version:** v1 (`0x00000001`) only.
- **Cipher suites (4):** `[GREASE], 0x1302, 0x1303, 0x1301` — pruned to TLS 1.3
  AEADs only (UNLIKE the 21-suite TCP list).
- **Connection IDs:** the client SCID is **zero-length**
  (`initial_source_connection_id` empty), matching Safari.
- **key_share:** includes the PQ group X25519MLKEM768 plus X25519, like the TCP
  hello, GREASE-led.
- **ParallaX auth marker:** the 32-byte `ClientHello.random` of the QUIC Initial
  carries `tag(12) || nonce(12) || timestamp(8)`, each XORed with a keystream
  derived from `X25519(client_ephemeral, server_static)` and the PSK (§12.7).

**QUIC transport parameters (client), emitted in strict ascending id order, then
Apple's vendor codepoint last:**

| id | parameter | value |
|----|-----------|-------|
| `0x04` | `initial_max_data` | 16 MiB (16777216) |
| `0x05` | `initial_max_stream_data_bidi_local` | 2 MiB (2097152) |
| `0x06` | `initial_max_stream_data_bidi_remote` | 2 MiB |
| `0x07` | `initial_max_stream_data_uni` | 2 MiB |
| `0x09` | `initial_max_streams_uni` | 8 |
| `0x0e` | `active_connection_id_limit` | 64 |
| `0x0f` | `initial_source_connection_id` | zero-length |
| `0x17f7586d2cb571` | Apple vendor/GREASE | 0 (value), placed last |

`initial_max_streams_bidi` (id `0x08`) is intentionally **omitted** from the
client parameters (matching Safari, which relies on the peer's grant). Emitting
any id Safari does not send is a distinguishing tell, so the omission is
non-negotiable for camouflage.

**QUIC transport parameters (server).** The server uses the same flow-control
values as the client, **but additionally sends `initial_max_streams_bidi` (id
`0x08`) = 1**, granting the client exactly one bidirectional stream for the relay
tunnel. (The server is the real origin's role here, so it is not bound to Safari
*client* fingerprinting; it must, however, grant at least one bidi for the tunnel
to open.) All other server parameters match the client set above (16 MiB conn
data, 2 MiB per stream, uni-streams 8, active CID limit 64).

### 12.6 HTTP/3 fingerprint (QUIC plane)

- **Stream open order (fingerprint).** Safari opens streams in the order:
  **control stream (uni, type 0x00) → request bidi → QPACK encoder stream (uni,
  type 0x02)**, interleaving the request bidi between the two uni opens. Both
  control and encoder uni-streams stay open for the connection's life (RFC 9114
  §6.2.1). Deviating from this open order is detectable.
- **Control stream (uni, type 0x00):** a SETTINGS frame with exactly three
  settings, in this on-wire order: `QPACK_MAX_TABLE_CAPACITY = 16383`,
  `QPACK_BLOCKED_STREAMS = 100`, then one per-connection GREASE setting. Safari
  (and therefore ParallaX) does **NOT** send `MAX_FIELD_SECTION_SIZE` (0x06);
  emitting it is a tell. A receiver validates the shape as `[cap(16383),
  blocked(100), grease]` and nothing else.
- **GREASE setting derivation.** The GREASE setting's id is a reserved value of
  the form `0x1f * N + 0x21` (RFC 9114 §7.2.4.1), with `N = u32_be(seed[0..4])`;
  the value is `u32_be(seed[4..8])`. Both id and value vary per connection (a
  fixed GREASE id/value is itself a tell); receivers validate only the *form*
  (`(id − 0x21) mod 0x1f == 0`), not the exact value.
- **QPACK encoder/decoder uni-streams** are opened (encoder type 0x02, decoder
  type 0x03). Although a non-zero table capacity is advertised, ParallaX uses the
  RFC 9204 **static table only** (no dynamic-table inserts; required-insert-count
  0); do not depend on dynamic-table insertions for interop.
- **Business (tunnel) bidi streams.** Each carries a full, browser-plausible H3
  request/response lifecycle:
  - **Client → server:** opens the bidi with a `GET` request HEADERS frame. The
    field order (confirmed against real Safari 26 H3 wire) is the **same** field
    sequence as the H2 main-document request: pseudo-headers `:method`,
    `:scheme`, `:authority`, `:path`, then regular headers `sec-fetch-dest`,
    `user-agent`, `accept`, `sec-fetch-site`, `sec-fetch-mode`,
    `accept-language`, `priority`, `accept-encoding`. (`:method = GET`,
    `:scheme = https`, `:authority` = the camouflage authority, `:path = /`.) The
    server validates the first frame is HEADERS (rejecting any non-HEADERS first
    frame, over-cap, or truncation; HEADERS frame capped at 4096 bytes).
  - **Server → client:** responds with a `:status 200` response HEADERS frame as
    the **first** frame it sends on that bidi.
  - **Both directions:** after their respective HEADERS, ParallaX records ride
    inside H3 `DATA` frames. The first client record on the stream is the sealed
    `CONNECT` (§9.2). H3 frames use QUIC varints for `frame_type` and `length`
    (RFC 9000 §16 / RFC 9114).

### 12.7 QUIC origin-splice marker derivation

```
ecdh    = X25519(server_static_priv, client_ephemeral_pub)   // = X25519(client_eph_priv, server_static_pub)
ks      = HKDF(salt=psk, IKM=ecdh) expand b"ParallaX v1 QUIC marker keystream" → 32
ak      = HKDF(salt=psk, IKM=ecdh) expand b"ParallaX v1 QUIC marker auth key"  → 32
tag     = HMAC-SHA256(ak,
            b"ParallaX v1 QUIC marker tag"
         || u16_be(len(sni)) || sni
         || u16_be(len(dcid)) || dcid       // dcid = the session offer_id (16 B), §6.6
         || nonce[12] || u64_be(timestamp) )[0..12]

// carrier plaintext = tag[12] || nonce[12] || u64_be(timestamp)[8]  (32 B),
// then XORed byte-for-byte with the 32-byte keystream `ks`:
random  = (tag XOR ks[0..12]) || (nonce XOR ks[12..24]) || (u64_be(ts) XOR ks[24..32])   // 32B
```

The `dcid` bound into the tag is the QUIC Destination Connection ID, which the
client sets to the session's 16-byte `offer_id` (§12.5); both peers therefore
compute the same tag. The server recomputes `tag` (constant-time compare) and
applies the same freshness window as the TCP replay check (§7.4). A
non-matching/replayed marker triggers QUIC origin-splice (§13).

### 12.8 QUIC 0-RTT resumption (optional)

The QUIC plane optionally supports TLS 1.3 / RFC 9001 session resumption with
0-RTT early data. This is an optional acceleration; a conforming implementation
MAY omit it (always do a full 1-RTT handshake).

- **NewSessionTicket.** After a QUIC handshake the server MAY issue a standard
  `NewSessionTicket` (handshake type `0x04`) whose `early_data` extension body is
  `max_early_data_size = 0xFFFFFFFF` (RFC 9001 §4.6.1 requires this exact value
  for QUIC).
- **Opaque ticket.** The ticket's `ticket` field is **opaque to the client** — it
  is an AEAD-sealed server-side state (a Server Ticket Encryption Key, derived
  per-server, seals: negotiated suite, ALPN, the resumption PSK, issue time, and
  lifetime). The client simply stores and replays it as the
  `pre_shared_key` identity. The sealed ticket is padded to a **fixed 160 bytes**
  on the wire (inside Safari 26.4's observed 157–160 B resumption-ticket range)
  so the `pre_shared_key` identity length is not a ParallaX tell. Ticket
  `lifetime_secs` is capped at 604800 (7 days) per RFC 8446.
- **Anti-replay.** 0-RTT early data is **single-use**: the server keeps a
  resumption-ticket replay cache (optionally file-backed across restarts) and
  rejects a re-presented ticket, falling back to 1-RTT. (Reference internal
  labels: ticket AAD `b"ParallaX v1 QUIC 0-RTT ticket"`, STEK HKDF info
  `b"parallax-quic-0rtt-stek-v1"`, ticket version 1 — these are server-internal
  and not required for client interop, since the ticket is opaque.)
- **Early data.** When resuming, the client MAY attach early application bytes
  (the same 0-RTT idea as the `CONNECT` initial payload, §15.1) in QUIC 0-RTT
  packets; they share the 0-RTT/1-RTT packet-number space per RFC 9001.

---

## 13. Origin-Splice (Active-Probing Resistance)

ParallaX's defense against active probing is **origin-splice**: the server always
bridges the connection to a real fallback origin and only "takes it over" if and
when an authenticated client signals so. A prober — or any non-authenticating
peer — therefore sees nothing but an ordinary TLS/QUIC session to that origin.

**TCP plane.** On accept, the server reads the ClientHello and attempts carrier
auth (§7.2) + freshness (§7.4). **In both outcomes it connects to
`fallback_addr` (e.g. `cloudflare.com:443`), forwards the ClientHello, and
relays the origin's handshake back to the client** (§7.1), so the client always
completes a real TLS 1.3 handshake against the origin's genuine certificate for
`sni`.
- **Auth fails** (bad tag, missing SNI, wrong session_id length, stale/replayed):
  the server keeps relaying client↔origin indefinitely. The connection is a
  genuine TLS session to the origin; no ParallaX bytes, timing, or error are
  ever emitted.
- **Auth succeeds:** the server keeps relaying until the client sends `PX1Q`
  (§7.3) inside the established TLS stream, then drops the origin and runs
  ParallaX. A prober never sends a valid `PX1Q` (it lacks the keys), so it can
  never distinguish itself from the auth-failed path before the relay — the two
  paths are byte-identical up to `PX1Q`.

**QUIC plane.** The model is **not** the same as TCP — here the ParallaX server
is the real QUIC/TLS endpoint and the covert **marker IS the authentication**
(there is no `PX1Q` equivalent; §12.5). Decision is made on the **first UDP
datagram**: the server parses the Initial and recovers the marker (§12.7). A
valid + fresh + non-replayed marker → the endpoint **terminates** the connection
as ParallaX. Any other v1 Initial (no / forged / replayed marker), junk, or a
non-v1 datagram → the endpoint **splices it verbatim to the real origin** inside
the endpoint, so a prober reaches the true origin. To avoid a tell from holding
an ambiguous first packet forever, there is a bounded decide delay (≈50 ms): a
stalled/incomplete first flight times out and is spliced, rather than silently
held.

**Normative requirements:**

- The auth path and the splice path MUST be indistinguishable to the peer in
  bytes and timing to the extent achievable; the reference implementation funnels
  every failure mode (auth, replay, malformed, policy) into the same splice
  behavior (I2).
- The fallback origin's certificate MUST validly chain for `sni`, which is why a
  live deployment requires the fallback host to be reachable.
- A residual, bounded (~50 ms) timing characteristic on the QUIC decide path is
  an accepted design limit and MUST NOT be "fixed" by introducing a new
  observable branch.

### 13.1 Server timing parameters (normative for I2)

These server-side timeouts shape what an observer sees and MUST be honored (with
randomization) by an interoperable server; the values are the reference
defaults:

| Parameter | Default | Semantics |
|-----------|---------|-----------|
| `first_record_wait_floor_ms` | 8000 | After a client authenticates, the server waits up to `floor + rand[0, jitter]` for the first inner record before giving up. A give-up closes like an idle origin. (Floor must be ≤ 300000; a hard minimum applies.) |
| `first_record_wait_jitter_ms` | 7000 | Upward jitter on the above, so the effective first-record deadline is uniform in `[8s, 15s]` per connection. |
| `fallback_idle_floor_ms` | 600000 (10 min) | Idle backstop for a **spliced** (origin) relay. **Resets on every byte**, so it only fires on a genuinely silent connection. Must be ≥ 5000. |
| `fallback_idle_jitter_ms` | 60000 (60 s) | The all-silent close time is spread uniformly into `[floor, floor+jitter]` per connection. This is REQUIRED: a fixed ~600 s close is a synthetic signature no real origin produces — do not emit a round, fixed idle close. |
| `max_concurrent_streams` | 4 | Max concurrent logical (mux) streams per authenticated session. |
| `replay_cache_capacity` | 49152 | Replay-cache entry capacity. Entries are retained for the freshness window (≈ pre-PQ deadline + skew). When full the server **fail-CLOSES new handshakes** (`CacheFull`) rather than admitting a possible replay — it never opens a replay hole. Capacity scales with the window; a busy bridge raises it proportionally. |
| `strict_tls13` | true | Require TLS 1.3 on the carrier. |
| handshake timeout | 8 s | Whole authenticated handshake (Phases A–C) backstop; exceeding it closes like an idle origin. |
| replay-close delay | `[0, 60 s]` | When a **replay** is detected post-PQ, the server delays the graceful close by a jittered `[0, 60 s]` (floor 0, jitter 60 s) so a flagged replay's close timing is not a distinct signature. |

The replay freshness window (§7.4) is derived from these (default ≈ 720 s with
the 10-minute idle floor); the `[now−window, now+5s]` timestamp bound and the
single-use `(nonce, transcript_fingerprint)` rule are as in §7.4.

### 13.2 Source admission (server-side, not wire-visible)

To stop one source monopolizing capacity, the reference server applies a local
admission limiter before the handshake. It does **not** affect the wire format —
a rejected source is simply spliced/closed like any other unauthenticated peer —
so a client reimplementation needs nothing here; a server reimplementation
SHOULD apply an equivalent policy:

- A per-source concurrency cap (`max_concurrent_per_source`, default **256**),
  keyed by IPv4 `/32` or IPv6 masked to `source_ipv6_prefix_len` (default
  **/64**), with a coarser `/48` aggregate rollup ceiling so one routed prefix
  cannot rotate `/64`s to evade the cap.
- A global connection limit as the real backstop.

---

## 14. UDP Relay Specification

Beyond the QUIC *carrier*, ParallaX can proxy the application's UDP-style
traffic in two ways:

1. **QUIC transport plane (carrier acceleration).** The QUIC plane (§9.2, §12.5)
   is an alternative carrier for the same `CONNECT`/record protocol; it is
   negotiated over an established TCP session via the `PX1G/O/P/N` messages
   (§6.6), then a real QUIC/H3 connection is brought up and business streams
   carry the tunnel. This is an optimization, not a separate proxy semantics.

2. **Negotiation handshake (over TCP):**

```
CLIENT                                  SERVER
  │── PX1G  UDP_REQUEST (version=1) ───►│
  │                                     │ (UDP enabled?)
  │◄── PX1O UDP_OFFER (port, cc, fec) ──│   or  ◄── PX1N UDP_DECLINE (reason)
  │── PX1P UDP_PROBE_ACK ──────────────►│   (path probe result)
  │   ... bring up QUIC plane ...       │
```

The offer advertises a UDP `port`, a congestion-control choice (`cc`: BBR or
Brutal), and a FEC mode (`fec`: off / adaptive / Reed-Solomon). A 16-byte
`offer_id` ties the probe ack to the offer. `UDP_DECLINE` reasons: `0` disabled,
`1` unsupported.

A minimal implementation MAY skip the QUIC plane entirely and serve all traffic
(including the application's UDP, tunneled as needed by the SOCKS layer) over the
TCP carrier.

### 14.1 QUIC-plane auth token (RFC 5705 exporter binding)

The QUIC plane uses **two distinct** authentication mechanisms — do not confuse
them:

1. **Origin-splice marker (§12.7).** Embedded in the QUIC Initial's
   `ClientHello.random`. Decided on the **first datagram**, before the TLS
   handshake completes, to choose authenticate-vs-splice. Replay window 3600 s
   (`MARKER_WINDOW_SECS`), single-use via a marker replay cache.
2. **Exporter-bound auth token (this section).** Computed **after** the QUIC TLS
   handshake completes, binding ParallaX authentication to that specific TLS
   session so a token captured on one session is useless on another.

The auth token is derived as follows. The `context` input is the **16-byte
`offer_id`** from the `UDP_OFFER` (`PX1O`, §6.6) that set up this QUIC plane —
both peers already hold it, so both derive the same token. First fold `context`
into a fixed-size exporter context, then export RFC 5705 keying material from the
live QUIC TLS connection:

```
context         = offer_id[16]                                          // from PX1O
ctx             = SHA-256( b"ParallaX v1 TUDP auth context"
                        || u64_be(len(context)) || context )           // 32 B
exporter_secret = TLS-Exporter( label  = b"ParallaX v1 TUDP auth exporter binding",
                                context = ctx,
                                length = 32 )                          // RFC 5705 / RFC 9001 §4.4
```

Then fold in the PSK (PSK as HKDF salt, exporter as IKM — the "need both"
posture):

```
auth_token = HKDF-Expand( HKDF-Extract(salt = psk, IKM = exporter_secret),
                          info = b"ParallaX v1 TUDP auth key",
                          32 )
```

Both peers compute the same 32-byte `auth_token` over the same connection, PSK,
and `context`; a mismatch fails the QUIC-plane admission (and the connection is
handled like any other unauthenticated peer — no distinguishable signal). Sizes:
`UDP_AUTH_EXPORTER_LEN = UDP_AUTH_TOKEN_LEN = 32`.

---

## 15. Address Format

ParallaX uses **textual** destination addressing in `CONNECT` (§6.1), not the
typed SOCKS5 ATYP scheme. The `host` field is a UTF-8 string that is one of:

- a domain name (e.g. `example.com`), 1–255 bytes;
- an IPv4 literal (e.g. `93.184.216.34`);
- an IPv6 literal (e.g. `2606:2800:220:1:248:1893:25c8:1946`).

The server is responsible for parsing/resolving `host`. `port` is a `u16`
big-endian, non-zero. There is no separate address-type tag on the ParallaX
wire; the textual form is self-describing.

### 15.1 SOCKS5 front-end (client-facing)

The client exposes a SOCKS5 listener (RFC 1928) to local applications:

- **Version:** `0x05`. Greeting offers/accepts only method `0x00` (no auth).
- **Command:** only `CONNECT` (`0x01`) is supported; `BIND`/`UDP ASSOCIATE` are
  not.
- **ATYP mapping → ParallaX `host`:**
  - `0x01` IPv4 (4 bytes) → dotted-quad string,
  - `0x03` domain (1-byte len + name, validated) → name string,
  - `0x04` IPv6 (16 bytes) → bracketless IPv6 string.
- **Port:** 2 bytes big-endian, must be non-zero.

The SOCKS request is translated into a `CONNECT` (`PX1C`); the client may also
capture a brief slice of the application's first bytes (a fixed **2 ms** window,
`INITIAL_PAYLOAD_CAPTURE_TIMEOUT = Duration::from_millis(2)`, no jitter) to
attach as the `initial_payload` 0-RTT data so the first request reaches the
origin without an extra round trip. If no bytes arrive within the window the
`CONNECT` is sent with an empty payload.

---

## 16. Error Codes

ParallaX has **no on-wire error codes** for peers — by invariant I2 all failures
present as ordinary connection behavior or origin-splice. The enumerations below
are the implementation's internal result types; they are specified so a
reimplementation handles the same conditions and maps them to the same
fail-closed / splice behavior. None of these names appear on the wire.

### 16.1 Inner-framing errors

`ConnectRequestError`: `Truncated`, `BadMagic`, `EmptyHost`, `HostTooLong`,
`InvalidHost` (non-UTF-8), `ZeroPort`, `InvalidPayloadLength`.

`MuxFrameError`: `Truncated`, `BadMagic`, `InvalidKind` (kind ∉ 1..=5),
`InvalidStreamId` (parity rule violated), `PayloadTooLong`,
`InvalidPayloadLength`.

`PqRekeyError` / `ServerKeyExchangeError`: `Truncated`, `BadMagic`,
`EmptyPublicKey` / `EmptyCiphertext`, `InvalidPublicKeyLength` /
`InvalidCiphertextLength`.

`FramedChunkError` / `ServerIdentityChunkError` (the `PX1F`/`PX1I` reassembly,
§5.8/§6.4): `Truncated`, `BadMagic`, `EmptyChunk`, `InvalidChunkLength`,
`InvalidOffset`, `TooLarge`, `InconsistentTotal` (total_len differs across
chunks), `OutOfOrder` (offset ≠ next expected). `ServerIdentityProofError`:
`Truncated`, `BadMagic`, `EmptySignature`, `InvalidSignatureLength`.

`UdpOfferError` / `UdpProbeAckError` / `UdpRequestError` / `UdpDeclineError`
(the `PX1O`/`PX1P`/`PX1G`/`PX1N` messages, §6.6): `Truncated`, `BadMagic`,
`InvalidLength`, and for the offer `ZeroPort`, for the probe ack
`InvalidStatus` (status byte ∉ 0..=2).

### 16.2 Crypto errors

`SessionError`: `Hkdf`, `Aead` (open/seal failure → fail-closed),
`NonceExhausted` (sequence would overflow `u64`), `DegenerateSharedSecret`
(all-zero X25519), `EmptyPsk`.

`AuthError`: `EmptyPsk`, `ClientHello` (parse failure), `InvalidSessionIdLen`
(≠ 32), `Hkdf`, `Clock` (system time before epoch).

`ReplayCacheError`: `Io`, `MalformedLine`, `MalformedHex`, `MacMismatch`
(journal tamper), `Clock`.

`PqError` (ML-KEM, §5.7): `InvalidPublicKey`, `InvalidSecretKey`,
`InvalidCiphertext`, `DegenerateSharedSecret` (all-zero X25519 in the rekey).
`UdpAuthError` (QUIC auth token, §14.1): `EmptyPsk`, `Exporter` (keying-material
export failed), `Derive`.

### 16.3 Server handshake errors

`HandshakeServerError` covers: `Config`, `MissingServer`, `WrongMode`, `Io`,
`Auth`, `ServerHello`, `Timeout` (handshake), `OutboundConnectTimeout`,
`Tls13Required`, `Session`, `DataRecord`, `Traffic`, `ConnectRequest`,
`SpeedTestRequest`, `MuxFrame`, `PqRekey`, `FramedChunk`, `ServerKeyExchange`,
`Pq`, `ServerIdentityProof`, `ServerIdentityChunk`, `Identity`, `ReplayCache`,
`MissingConnectTarget`, `OutboundTargetDenied`, `BlockingTask`. Every one of
these terminates or splices indistinguishably.

---

## 17. ML-DSA-87 Parameters (for an independent signature implementation)

The reference implements ML-DSA-87 (FIPS 204) directly. An interoperable peer
only needs to **verify** the server's signature, but the parameters are pinned
here for completeness:

| Parameter | Value |
|-----------|-------|
| Ring degree `N` | 256 |
| Modulus `Q` | 8 380 417 (`2²³ − 2¹³ + 1`) |
| Dropped bits `D` | 13 |
| `(K, L)` (matrix dims) | (8, 7) |
| `ETA` | 2 |
| `TAU` (challenge weight) | 60 |
| `BETA` (= TAU·ETA) | 120 |
| `GAMMA1` | 2¹⁹ = 524 288 |
| `GAMMA2` | (Q−1)/32 = 261 888 |
| `OMEGA` (hint bound) | 75 |
| `CTILDEBYTES` (challenge hash) | 64 |
| Public key bytes | 2592 (= 32 + 8·320) |
| Secret key bytes | 4896 |
| Signature bytes | 4627 (= 64 + 7·640 + (75+8)) |
| Hash/XOF | SHAKE-128/256 (FIPS 202) per FIPS 204 |

Signing context for ParallaX identity: `b"ParallaX v2 ML-DSA-87 server
identity"`; the signed message is per §5.6. Verification is FIPS 204
`ML-DSA.Verify(pk, M, sig, ctx)`.

---

## 18. Security Considerations

- **Two-secret binding.** Both the carrier masks and the auth tag require *both*
  the PSK and an X25519 shared secret. A leaked server static private key alone
  does not let an attacker forge carrier auth or recover the masks, and a leaked
  PSK alone does not either. Do not swap the HKDF salt/IKM roles (PSK is always
  the salt for these derivations).
- **PSK is mandatory.** An empty PSK MUST be rejected at config load and at
  runtime. With a zero/all-zero HKDF salt the PSK binding silently vanishes.
- **Forward secrecy + PQ.** Traffic keys derive from ephemeral X25519 and (after
  rekey) ML-KEM-1024; a "harvest-now-decrypt-later" adversary cannot recover
  session keys even with a future quantum computer, because the chain secret is
  bound to the ML-KEM shared secret.
- **Replay.** The carrier auth carries a timestamp + nonce; the server enforces
  a freshness window (default 120 s, +5 s skew) and single-use nonce/transcript
  caching. The on-disk replay journal is HMAC-chained
  (`parallax-replay-cache-v3`: a version header line whose MAC chains the last
  entry's MAC, then one HMAC-chained line per entry of `timestamp || nonce ||
  transcript_fingerprint`) so any tampering or truncation is detected
  (`MacMismatch`) and the journal rejected. **This on-disk format is
  implementation-private**: two independent ParallaX implementations interoperate
  without sharing a replay file — each maintains its own cache. A reimplementation
  only needs the *semantics* (single-use within the freshness window, tamper-evident
  persistence), not byte-compatibility with this journal layout.
- **Nonce reuse.** Per-direction sequence counters make AEAD nonces unique;
  exhaustion aborts. Substreams derive independent keys (distinct HKDF info
  containing the stream id), so two streams never share a nonce base.
- **Active probing.** Origin-splice (§13) makes an unauthenticated/replayed probe
  indistinguishable from a real connection to the fallback origin. The auth and
  failure paths MUST converge (I2).
- **Traffic analysis.** Record-size shaping (§11.2), the Safari fingerprint
  (§12), and cover frames (§9.1) defend against passive size/timing
  classification. An implementer MUST NOT introduce records, settings, or timing
  that a real Safari client would not produce.
- **Memory hygiene.** The reference zeroizes derived keys and excludes plaintext
  buffers from core dumps; a port SHOULD apply equivalent secret-handling
  discipline.
- **Constant time.** Auth-tag and marker comparisons, and the X25519 zero-check,
  MUST be constant-time.

---

## 19. Performance Considerations

- **0-RTT initial payload.** Attaching the application's first bytes to
  `CONNECT` removes one client→server→origin round trip for the first request.
- **Record packing.** In steady-state bulk transfer, fill records toward 16384
  plaintext (one app write → one record → one segment) to match Safari and
  minimize per-record overhead.
- **Parallel/batch AEAD.** Sealing/opening consecutive records as a batch
  (mapping to consecutive sequence numbers) amortizes setup; the reference
  fans out only above thresholds (≈3 records / ≈48 KiB) — below that, inline
  sealing is faster.
- **Transport racing.** A client MAY race TCP and QUIC and use the faster plane;
  both share the same identities and secrets.
- **Socket tuning.** Send/receive buffer sizes are tunable (`[transport]`
  `SO_SNDBUF`/`SO_RCVBUF`); on constrained uplinks the dominant limiter is
  usually the operator path, not the proxy.
- **Warm tunnel.** During active-use windows the client keeps a warm muxed
  tunnel alive (cover frames) so a new SOCKS connection reuses an established
  carrier instead of paying a fresh handshake.

---

## 20. Test Vectors

The reference ships executable conformance tests rather than static vectors in
this document; an implementer should reproduce these checks:

- **AEAD KAT (cross-library).** For a fixed `(key, nonce, plaintext, aad)`,
  AES-256-GCM and ChaCha20-Poly1305 outputs MUST match an independent
  implementation byte-for-byte. (`crypto-self-test` CLI performs a round-trip
  seal/open with AAD `b"self-test"` on plaintext `b"parallax"`.)
- **ML-DSA-87 ACVP.** The signing/verification path is validated against NIST
  ACVP vectors (`tests/mldsa_acvp.rs`) and differential-tested against a
  reference ML-DSA implementation (`tests/mldsa_differential.rs`). A port's
  verifier MUST accept all ACVP `VALID` signatures and reject `INVALID` ones.
- **Nonce injectivity.** For all `seq₁ ≠ seq₂`, `nonce(base, seq₁) ≠
  nonce(base, seq₂)` (formally verified in the reference; reproduce as a
  property test).
- **Auth round-trip.** `build_masked_stateful_*` then
  `recover_stateful_auth_material` + `verify_*` MUST recover the exact
  `parallax_x25519_public`, `timestamp`, `nonce`, and validate the tag; with any
  wrong `mask_ecdh` the recovered timestamp MUST NOT equal the real one (no
  offline PSK-guessing oracle).
- **Frame round-trip.** Every `CONNECT`, `MuxFrame` (all 5 kinds), `PqRekey`,
  `ServerKeyExchange` encode/decode MUST be a perfect round-trip; the `kind`
  byte 0 and 6 MUST be rejected (`InvalidKind`).
- **Safari fingerprint baselines.** The TCP ClientHello, H2 settings, and the H3
  ClientHello/SETTINGS are pinned against captured Safari 26 wire bytes
  (`tests/safari_*_baseline.rs`); a port SHOULD diff its emitted bytes against
  the same captures.

### 20.1 Worked size constants (sanity checks)

- `OUTER_TLS_RECORD_LIMIT = 16384 + 17 = 16401`.
- One CONNECT for `host="example.com"` (11 bytes), no 0-RTT:
  `encoded_len = 12 + 11 + 0 = 23`, so `raw_wire = 23 + 18 = 41`; every band
  ≥ 41 fits (all of them here), and the sender picks one uniformly at random
  (e.g. 286, 469, …, 1600) and pads to it (§11.2).
- `PqRekeyRequest` with ML-KEM-1024 public key: `40 + 1568 = 1608` bytes
  (then chunked/shaped across `PQ_FLIGHT_RECORD_TARGETS`).
- `ServerKeyExchange` (with suite): `40 + 1568 + 1 = 1609` bytes.

---

## 21. Interoperability Tests

A second implementation claiming interoperability with the reference SHOULD pass:

1. **Carrier auth interop.** Reference server accepts the new client's
   ClientHello (auth tag verifies, freshness passes) and vice-versa.
2. **Fingerprint parity.** The new client's TLS ClientHello, H2 SETTINGS +
   WINDOW_UPDATE, and (if QUIC) the QUIC ClientHello + transport parameters are
   byte-identical to the reference's for the same SNI/seed inputs (modulo the
   randomized GREASE/key-share/random fields).
3. **Full tunnel.** New client ↔ reference server: complete Phase A–D, fetch a
   known resource through the tunnel, compare bytes.
4. **PQ rekey.** Epoch advances to 1, both sides derive identical traffic keys;
   a tampered ML-DSA signature is rejected.
5. **MUX.** Open ≥2 concurrent streams over one carrier; interleaved DATA/FIN
   reassembles correctly; a COVER frame on a non-zero stream id is rejected.
6. **Origin-splice.** A connection with a wrong PSK is transparently relayed to
   the fallback origin and completes a valid TLS session to it; the prober
   observes nothing ParallaX-specific.
7. **Replay rejection.** Re-sending a captured authenticated ClientHello within
   the window is spliced (rejected), not authenticated.
8. **Post-handshake drain.** Against a fallback origin that emits a
   `NewSessionTicket` after the TLS handshake, the new client drains it to a
   record boundary and still sends a well-formed first `PX1Q` (§7.3) — it does
   not mistake the ticket for a ParallaX record.
9. **Origin-bridged handshake.** The new client completes Phase A against the
   real origin's certificate (verifying it for `sni`) before any `PX1Q`, and the
   reference server holds no TLS cert of its own (§7.1).

---

## 22. Reference Implementation Notes

- **Language/architecture.** The reference is a single Rust binary (`parallax`,
  alias `plx`) with no external services. Both TLS and QUIC engines are
  hand-written (no rustls/quinn at runtime) so every wire byte is controlled.
- **AEAD/KEM backends.** AES-GCM/ChaCha and ML-KEM use vetted libraries
  (`aws-lc-rs`, RustCrypto); ML-DSA-87 is implemented in-tree and validated
  against ACVP + a reference oracle.
- **Endianness.** Every ParallaX integer on the wire is big-endian (the AEAD
  nonce XOR uses big-endian sequence bytes in the low 8 bytes). The sole
  exception is X25519 key/scalar material, which is the little-endian encoding of
  RFC 7748 (§5.1); ML-KEM/ML-DSA byte strings are FIPS-defined and used verbatim.
- **Determinism caveats.** The GREASE/key-share/`random`/`nonce`/`timestamp`
  fields are randomized per connection; everything else in the fingerprint is
  fixed. A port MUST randomize exactly those fields and fix the rest.
- **Config secrets.** Keys are base64 (STANDARD alphabet). Config files MUST be
  mode `0600` (enforced by `plx check`). Secrets may be supplied inline,
  via file, via env, or sealed.
- **Failure discipline.** Treat every parse/crypto error as fatal to the session
  and route to the same teardown/splice path; never emit a distinguishing
  response.

### 22.1 Config schema (essentials)

```toml
mode = "client" | "server"

[crypto]
psk = "<base64>"              # mandatory, non-empty; mixed into all KDFs

# Client:
[client]
listen = "127.0.0.1:1080"            # local SOCKS5 listener
server_addr = "host:443"             # ParallaX server public address
sni = "cloudflare.com"               # camouflage SNI (must match fallback origin)
server_public_key = "<base64>"        # server static X25519 public
server_identity_public_key = "<base64>"  # server ML-DSA-87 public

# Server:
[server]
listen = "0.0.0.0:443"
fallback_addr = "cloudflare.com:443"  # origin-splice target; MUST be reachable & serve a cert valid for `sni`
data_target = "host:port"             # OPTIONAL. If set, every authenticated tunnel is relayed to THIS
                                      #   fixed target and the client's CONNECT target is ignored (reverse-
                                      #   proxy mode). If unset, the server dials the client's CONNECT target.
private_key = "<base64>"              # ParallaX server static X25519 secret — used for auth unmask + ParallaX KEX,
                                      #   NOT a TLS key (pairs with client.server_public_key)
identity_secret_key = "<base64>"      # ParallaX server ML-DSA-87 secret — signs the Phase B identity proof (PX1S),
                                      #   NOT a TLS cert key (pairs with client.server_identity_public_key)
replay_cache_path = "/var/lib/parallax/parallax-replay.cache"   # default
replay_cache_capacity = 49152         # default
authorized_sni = ["..."]              # OPTIONAL allowlist of SNIs that may authenticate; empty = no SNI filter
strict_tls13 = true                   # default; require TLS 1.3 on the carrier
first_record_wait_floor_ms = 8000     # default (see §13.1)
first_record_wait_jitter_ms = 7000    # default
fallback_idle_floor_ms = 600000       # default 10 min, resets per byte (see §13.1)
fallback_idle_jitter_ms = 60000       # default 60 s
max_concurrent_streams = 4            # default; mux streams per session
max_concurrent_per_source = 256       # default; per-IP(/32 or /64) concurrency cap (§13.2)
source_ipv6_prefix_len = 64           # default IPv6 source aggregation prefix
tcp_congestion = "bbr"                # optional

[traffic]   # all default toward speed (0 / off)
min_padding / max_padding / min_delay_ms / max_delay_ms / cover_min_interval_ms

[transport]
# SO_SNDBUF / SO_RCVBUF socket tuning

[udp]       # optional QUIC plane (experimental knobs; several RESERVED)
```

### 22.2 CLI (reference)

`plx init <domain>` generates a paired client+server config with matching keys
(0600). `plx check <config>` validates a config (and enforces 0600). Other
subcommands: `serve`, `client`, `keygen`, `crypto-self-test`, `speed`,
`netmatrix`, `bench`, `config-template`, `probe`, `seal`.

---

## 23. Examples

### 23.1 End-to-end (TCP plane), `curl` through the client

```
# server                         # client
plx init example.com \           # generates paired configs (0600), matching keys
  --server-addr 1.2.3.4:8443
plx serve server.toml            plx client client.toml   # SOCKS5 at 127.0.0.1:1080

curl --socks5-hostname 127.0.0.1:1080 https://example.org/
```

On the wire, the client→server connection is a Safari-26 TLS 1.3 + HTTP/2
session to `example.com` (the SNI). Inside it: ClientHello carrier auth →
ServerHello → `PX1Q`/`PX1K`/`PX1S` PQ handshake → `PX1C` CONNECT(`example.org`,
443) → relayed HTTPS bytes.

### 23.2 CONNECT message bytes (illustrative)

`CONNECT host="ab", port=443, no payload`:

```
50 58 31 43   "PX1C"
00 02         host_len = 2
61 62         "ab"
01 BB         port = 443
00 00 00 00   payload_len = 0
```

(12 + 2 = 14 bytes pre-shaping; `raw_wire = 14 + 18 = 32`, so inside the sealed
record it is padded up to one randomly chosen `CONNECT_RECORD_SIZE_BANDS` value
≥ 32 — e.g. 286 — per §11.2, not deterministically the smallest.)

### 23.3 MUX OPEN frame (illustrative)

`MUX OPEN stream_id=1, payload = the CONNECT above (14 bytes)`:

```
50 58 31 4D   "PX1M"
00 00 00 01   stream_id = 1
01            kind = OPEN
00 00 00 0E   payload_len = 14
50 58 31 43 00 02 61 62 01 BB 00 00 00 00   <CONNECT "ab":443>
```

### 23.4 Negotiating the QUIC plane (illustrative)

```
client → server :  50 58 31 47 01                 "PX1G" version=1
server → client :  50 58 31 4F <id[16]> <port> .. "PX1O" offer (cc, fec)
client → server :  50 58 31 50 <id[16]> <st> ..   "PX1P" probe ack
   ... client brings up Safari-26 QUIC v1 / H3 with the marker in the Initial ...
```

---

## 24. Conformance Summary

A minimal interoperable implementation MUST implement: §4 (carrier records), §5
(crypto schedule, AEAD, server identity verify, PQ rekey), §6.1–6.5 (CONNECT,
PQ_REKEY, SERVER_KEY_EXCHANGE, SERVER_IDENTITY, MUX), §7 (handshake, including the
origin-bridged Phase A model of §7.1), §11 (record framing + shaping), §12.1–12.4
(TLS/H2 fingerprint), §15 (addressing + SOCKS5). It MAY additionally implement
§9.2/§12.5–12.7/§14 (QUIC plane) and §6.6 (UDP negotiation). It MUST preserve
invariants I1–I4 throughout.

Role-specific obligations:
- A conforming **client** MUST be a real TLS 1.3 client that verifies the
  origin's certificate against `sni` (§7.1), embeds the carrier auth (§7.2), and
  sends `PX1Q` promptly after the handshake to claim the session.
- A conforming **server** MUST implement origin-splice (§13): connect to
  `fallback_addr`, relay the origin's real TLS handshake to the client, and take
  the connection over only on a valid `PX1Q`. It needs **no** TLS certificate of
  its own, but DOES hold the ParallaX X25519 static key and ML-DSA-87 identity
  key (§22.1). `fallback_addr` MUST be reachable and serve a valid cert for `sni`.

