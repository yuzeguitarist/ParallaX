# QUIC Transport (quic_runtime & Salamander)
Relevant source files

- [src/transport/mod.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/mod.rs)
- [src/transport/quic.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs)
- [src/transport/quic_runtime.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs)

The QUIC transport mode in ParallaX provides a high-performance, UDP-based alternative to the standard TCP camouflage transport. It leverages the `quinn` implementation of QUIC to provide 0-RTT resumption, BBR congestion control, and stream-multiplexing, while adding a custom authentication layer and the `Salamander` packet obfuscator to resist traffic analysis and active probing.

## QUIC Runtime Architecture

The `quic_runtime` manages the lifecycle of QUIC connections for both clients and servers. Unlike the TCP transport which uses a single TLS handshake for the entire connection, the QUIC transport performs authentication at the stream level within an established QUIC connection.

### Server Runtime

The server entry point `run_server` initializes a QUIC `Endpoint` with a self-signed certificate and listens for incoming UDP packets [src/transport/quic_runtime.rs#106-114](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L106-L114) Each connection is handled in a dedicated task that continuously accepts bidirectional streams [src/transport/quic_runtime.rs#116-131](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L116-L131)

### Client Runtime

The client entry point `run_client` starts a SOCKS5 proxy server [src/transport/quic_runtime.rs#145-150](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L145-L150) For every SOCKS5 request, it attempts to open a new bidirectional stream over a shared QUIC connection to the ParallaX server [src/transport/quic_runtime.rs#152-164](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L152-L164)

### QUIC Transport Entity Mapping

The following diagram maps the high-level QUIC transport components to their corresponding code entities.

QUIC Transport System Map

[Flowchart Diagram]

Sources: [src/transport/quic_runtime.rs#106-165](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L106-L165)[src/transport/quic_runtime.rs#32-44](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L32-L44)

## Per-Stream Authentication

ParallaX implements a custom authentication mechanism for every QUIC stream to prevent unauthorized use of the server and to protect against replay attacks. This occurs immediately after a stream is opened.

### The Auth Frame

Before any application data or `ConnectRequest` is sent, the client must transmit an authentication frame. The frame consists of:

1. Magic Bytes: `PX1U` (4 bytes) [src/transport/quic_runtime.rs#33](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L33-L33)
2. SNI Length: 1 byte.
3. SNI: The target Server Name Indication.
4. Timestamp: 8-byte big-endian Unix timestamp [src/transport/quic_runtime.rs#250-255](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L250-L255)
5. Nonce: 16 random bytes [src/transport/quic_runtime.rs#35](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L35-L35)
6. HMAC-SHA256 Tag: 32-byte tag calculated over the entire frame (excluding the tag itself) using a key derived from the PSK [src/transport/quic_runtime.rs#36](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L36-L36)

### Verification Process

The server validates the auth frame in `handle_stream`[src/transport/quic_runtime.rs#191-230](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L191-L230):

- Magic & SNI: Checks for `PX1U` and verifies the SNI is in the `authorized_sni` list [src/transport/quic_runtime.rs#260-280](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L260-L280)
- Timestamp: Ensures the request is within the `QUIC_AUTH_WINDOW_SECS` (default 90s) to prevent long-term replays [src/transport/quic_runtime.rs#37](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L37-L37)[src/transport/quic_runtime.rs#294-301](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L294-L301)
- Replay Cache: Checks the `ReplayCache` to ensure the specific nonce/timestamp combination has not been used [src/transport/quic_runtime.rs#303-306](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L303-L306)
- HMAC: Verifies the signature using `HmacSha256`[src/transport/quic_runtime.rs#282-292](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L282-L292)

Sources: [src/transport/quic_runtime.rs#32-44](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L32-L44)[src/transport/quic_runtime.rs#241-310](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L241-L310)

## Salamander: QUIC Packet Obfuscator

`Salamander` is a lightweight obfuscation layer designed to hide the recognizable header patterns of QUIC packets (e.g., the Long Header/Short Header bits) which are often targets for DPI (Deep Packet Inspection).

### Implementation Details

The `Salamander` struct uses a shared key to generate a bitmask for XORing packet data [src/transport/quic.rs#22-31](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs#L22-L31)

| Feature | Specification | Code Reference |
| --- | --- | --- |
| Algorithm | BLAKE2b-based Stream Cipher | [src/transport/quic.rs#65-74](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs#L65-L74) |
| Salt Length | 8 Bytes | [src/transport/quic.rs#8](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs#L8-L8) |
| Hash Length | 32 Bytes | [src/transport/quic.rs#9](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs#L9-L9) |
| Mask Generation | `BLAKE2b(Key \|\| Salt)` | [src/transport/quic.rs#67-68](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs#L67-L68) |

### Obfuscation Flow

1. Obfuscate: Generate a random 8-byte salt, derive a mask via BLAKE2b, and XOR the QUIC packet with the mask. The salt is prepended to the ciphertext [src/transport/quic.rs#33-50](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs#L33-L50)
2. Deobfuscate: Extract the salt from the first 8 bytes, derive the same mask, and XOR the remaining payload to recover the original QUIC packet [src/transport/quic.rs#52-63](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs#L52-L63)

Salamander Data Transformation

[Flowchart Diagram]

Sources: [src/transport/quic.rs#33-75](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs#L33-L75)

## Performance & Congestion Control

The QUIC transport is tuned for high-throughput and low-latency environments:

- BBR Congestion Control: The server and client use the BBR algorithm instead of New Reno for better performance on lossy or high-BDP (Bandwidth-Delay Product) links [src/transport/quic_runtime.rs#336](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L336-L336)
- Initial Window: The initial congestion window is increased to `QUIC_BRUTAL_LIKE_INITIAL_WINDOW_PACKETS` (96 packets) to accelerate the start of data transfer [src/transport/quic_runtime.rs#41](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L41-L41)[src/transport/quic_runtime.rs#337](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L337-L337)
- Flow Control: Connection and stream receive windows are set to 16MB (`QUIC_FLOW_WINDOW`) to prevent buffer-induced bottlenecks [src/transport/quic_runtime.rs#40](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L40-L40)[src/transport/quic_runtime.rs#332-333](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L332-L333)
- 0-RTT Resumption: Enabled via the standard QUIC/TLS mechanism, allowing clients to send data (including the auth frame) in the first flight [src/transport/quic_runtime.rs#328](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L328-L328)

Sources: [src/transport/quic_runtime.rs#32-43](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L32-L43)[src/transport/quic_runtime.rs#320-350](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic_runtime.rs#L320-L350)