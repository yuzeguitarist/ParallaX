# Core Architecture
Relevant source files

- [README.md](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1)
- [src/client/runtime.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/client/runtime.rs)
- [src/handshake/server.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/handshake/server.rs)
- [src/lib.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs)

ParallaX is designed as a censorship-resistant transport protocol that achieves unobservability by mimicking legitimate HTTPS traffic. It employs a client-server topology where the "stealth" server acts as a transparent proxy for authorized clients while masquerading as a standard web server (the "fallback") to unauthorized probers.

## System Topology

The architecture consists of three primary entities: the ParallaX Client, the ParallaX Server, and a Camouflage Target (a legitimate web server).

### Communication Flow

1. SOCKS5 Inbound: The client receives local application traffic via a SOCKS5 interface.
2. Camouflage Handshake: The client initiates a TCP connection to the ParallaX server, sending a TLS 1.3 `ClientHello` that contains embedded authentication tags.
3. Inbound Decision: The server inspects the `ClientHello`.

- Authorized: The server completes a hybrid cryptographic handshake and transitions to data relay mode.
- Unauthorized: The server transparently pipes the connection to the configured `fallback_addr`, appearing as a standard TLS endpoint.
4. Data Relay: Once authenticated, traffic is encapsulated in `ApplicationData` records with randomized padding and timing to defeat traffic analysis.

### Code-to-Entity Mapping

The following diagram maps the high-level architecture to the primary modules and functions in the codebase.

Diagram: Architectural Component Mapping

## Camouflage TLS Model

ParallaX does not merely wrap traffic in TLS; it hijacks the TLS handshake fields to perform out-of-band authentication and key exchange.

- ClientHello Hijacking: The client's ephemeral X25519 public key is placed in the `random` field of the `ClientHello`, and an authentication tag (derived from a Pre-Shared Key) is embedded in the `session_id` field. [src/tls/stateful.rs#185-188](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/stateful.rs#L185-L188)
- Stateful Backend: The `StatefulRustlsCamouflageBackend` manages a real `rustls` instance to ensure the handshake follows the state machine of a legitimate browser (e.g., Chrome or Safari). [src/tls/stateful.rs#30-31](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/stateful.rs#L30-L31)
- Probing Resistance: If the server detects a replay or an invalid signature in the `session_id`, it yields control to `relay_fallback`, which establishes a connection to a legitimate site and copies bytes bidirectionally. [src/handshake/server.rs#203-207](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/handshake/server.rs#L203-L207)

For details, see [Server Runtime & Probing Resistance](#2.2).

## Layered Cryptographic Handshake

The protocol uses a "sandwich" approach to security, layering standard TLS, symmetric PSK authentication, and Post-Quantum (PQ) primitives.

| Layer | Primitive | Purpose |
| --- | --- | --- |
| Authentication | HKDF-SHA256 + PSK | Authenticates the `ClientHello` before the server allocates resources. |
| Key Exchange | X25519 | Establishes the initial transport keys via `ClientHello.random`. |
| PQ Security | ML-KEM-1024 | Hybrid rekeying immediately after the TLS handshake to ensure quantum resistance. |
| Identity Proof | ML-DSA-87 | The server proves its identity to the client using a PQ-secure signature. |

Diagram: Handshake Sequence & Code Entities

## Data Relay Model

Once the handshake is complete, the connection enters a data relay phase. ParallaX treats the underlying TCP stream as a sequence of TLS `ApplicationData` records.

- Encapsulation: Every packet is wrapped in a `DataRecordCodec` which handles AEAD (XChaCha20-Poly1305) encryption and padding. [src/protocol/data.rs#38-42](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/protocol/data.rs#L38-L42)
- Traffic Shaping: The `PaddingProfile` and `TimingProfile` inject randomized delays and dummy bytes to mask the packet length and frequency distributions of the inner protocol. [src/traffic/mod.rs#48](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic/mod.rs#L48-L48)
- Cover Traffic: To defeat long-term statistical analysis, the `CoverTrafficProfile` generates "empty" encrypted records during periods of inactivity. [src/client/runtime.rs#214-217](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/client/runtime.rs#L214-L217)

For details, see [Client Runtime & SOCKS5 Proxy](#2.1) and [Protocol Commands & Data Records](#2.3).

## Subsystem Index

- [Client Runtime & SOCKS5 Proxy](#2.1): Local proxy handling and handshake initiation.
- [Server Runtime & Probing Resistance](#2.2): Inbound decision logic and fallback mechanics.
- [Protocol Commands & Data Records](#2.3): Wire format, binary layout, and record-layer encryption.

Sources: [src/client/runtime.rs#1-210](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/client/runtime.rs#L1-L210)[src/handshake/server.rs#1-250](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/handshake/server.rs#L1-L250)[src/protocol/data.rs#1-50](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/protocol/data.rs#L1-L50)[src/tls/stateful.rs#1-100](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/stateful.rs#L1-L100)