# Glossary
Relevant source files

- [README.md](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1)
- [src/cli.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs)
- [src/config.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs)
- [src/crypto/auth.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/auth.rs)
- [src/crypto/identity.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/identity.rs)
- [src/crypto/mod.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/mod.rs)
- [src/crypto/pq.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/pq.rs)
- [src/crypto/replay.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/replay.rs)
- [src/crypto/session.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/session.rs)
- [src/fingerprint/http2.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/fingerprint/http2.rs)
- [src/fingerprint/mod.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/fingerprint/mod.rs)
- [src/handshake/server.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/handshake/server.rs)
- [src/lib.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs)
- [src/probe.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs)
- [src/protocol/command.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/protocol/command.rs)
- [src/protocol/data.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/protocol/data.rs)
- [src/tls/client_hello_builder.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs)
- [src/tls/stateful.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/stateful.rs)
- [src/traffic.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs)
- [src/transport/quic.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/transport/quic.rs)

This glossary defines the codebase-specific terminology, domain concepts, and abbreviations used throughout the ParallaX protocol implementation. ParallaX is a censorship-resistant proxy that leverages TLS 1.3 camouflage to tunnel traffic through restricted networks.

## Core Concepts

### Camouflage TLS

The mechanism of mimicking a legitimate TLS 1.3 handshake to hide the ParallaX protocol. ParallaX uses two primary methods for this:

1. Hand-written Builder: Uses `ClientHelloTemplate` to manually construct binary records [src/tls/client_hello_builder.rs#46-50](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L46-L50)
2. Stateful Rustls: Uses `StatefulRustlsCamouflageBackend` to drive a real `rustls` state machine while injecting ParallaX-specific entropy [src/tls/stateful.rs#157-159](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/stateful.rs#L157-L159)

### ClientHello Authentication

A technique where the client proves its identity to the server by embedding a cryptographic tag in the `legacy_session_id` field of the TLS ClientHello [src/crypto/auth.rs#15-19](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/auth.rs#L15-L19)

- Transcript Authentication: The tag covers the entire ClientHello record [src/crypto/auth.rs#217-222](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/auth.rs#L217-L222)
- Stateful Authentication: The tag covers specific fields (SNI, X25519 key) to allow validation before the full record is available [src/crypto/auth.rs#144-152](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/auth.rs#L144-L152)

### Fallback Mechanism

If the server receives a connection that fails authentication or is malformed, it transparently relays the raw bytes to a `fallback_addr` (a legitimate website) [src/handshake/server.rs#204-207](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/handshake/server.rs#L204-L207) This ensures the server appears to be a standard web server to active probers.

## Cryptographic Terms

| Term | Definition | Code Pointer |
| --- | --- | --- |
| AAD | Additional Authenticated Data used in `DataRecordCodec`. | [src/protocol/data.rs#62-63](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/protocol/data.rs#L62-L63) |
| AeadCodec | Wrapper for `XChaCha20Poly1305` handling nonce sequencing. | [src/crypto/session.rs#201-205](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/session.rs#L201-L205) |
| Chain Secret | The root secret derived from ECDH used to generate epoch keys. | [src/crypto/session.rs#165-168](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/session.rs#L165-L168) |
| Hybrid Sandwich | A PQ-secure rekeying construction combining X25519 and ML-KEM. | [src/crypto/pq.rs#1-10](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/pq.rs#L1-L10) |
| ML-KEM | Module-Lattice-Based Key-Encapsulation Mechanism (Post-Quantum). | [src/crypto/pq.rs#12-15](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/pq.rs#L12-L15) |
| ML-DSA | Module-Lattice-Based Digital Signature Algorithm (Post-Quantum). | [src/crypto/identity.rs#10-15](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/identity.rs#L10-L15) |
| PSK | Pre-Shared Key used as a salt for initial HKDF key derivation. | [src/config.rs#78-81](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L78-L81) |
| ReplayCache | A disk-persistent cache preventing reuse of ClientHello records. | [src/crypto/replay.rs#25-30](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/replay.rs#L25-L30) |

## Traffic Obfuscation

### PaddingProfile

Handles the addition and removal of random bytes to application data records to obfuscate packet lengths [src/traffic.rs#19-22](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L19-L22) It uses `OBSERVED_PACKET_TARGETS` to mimic common MTU sizes [src/traffic.rs#36-38](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L36-L38)

### TimingProfile

Introduces artificial delays between packet transmissions to disrupt timing analysis [src/traffic.rs#25-28](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L25-L28) It samples from `OBSERVED_DELAY_MS` to match legitimate network jitter [src/traffic.rs#40](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L40-L40)

### Cover Traffic

Artificial packets sent during idle periods to maintain a baseline traffic pattern, controlled by `CoverTrafficProfile`[src/traffic.rs#31-34](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L31-L34)

## System Components

### Code Entity Association: Handshake Flow

This diagram maps the natural language "Handshake" to the specific code entities responsible for each step.

[Flowchart Diagram]

Sources:[src/client/runtime.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/client/runtime.rs)[src/handshake/server.rs#134-172](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/handshake/server.rs#L134-L172)[src/tls/stateful.rs#159-166](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/stateful.rs#L159-L166)[src/tls/client_hello_builder.rs#52-64](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L52-L64)

### Data Flow: Application Data Relay

This diagram illustrates how data moves from a local SOCKS5 connection through the ParallaX obfuscation layers.

[Flowchart Diagram]

Sources:[src/protocol/data.rs#24-42](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/protocol/data.rs#L24-L42)[src/traffic.rs#54-67](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/traffic.rs#L54-L67)[src/crypto/session.rs#224-238](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/session.rs#L224-L238)

## Abbreviations

- ALPN: Application-Layer Protocol Negotiation. Used in `ProbeReport` to check for `h2` support [src/probe.rs#64](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/probe.rs#L64-L64)
- ECDH: Elliptic Curve Diffie-Hellman. Implemented via `x25519-dalek`[src/crypto/session.rs#11-12](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/session.rs#L11-L12)
- GREASE: Generate Random Extensions And Sustain Extensibility. Injected into TLS headers to prevent middlebox ossification [src/tls/client_hello_builder.rs#85-86](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/tls/client_hello_builder.rs#L85-L86)
- HKDF: HMAC-based Extract-and-Expand Key Derivation Function. Used for all session key generation [src/crypto/session.rs#120-121](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/crypto/session.rs#L120-L121)
- SNI: Server Name Indication. The domain name sent in the clear during TLS handshakes [src/config.rs#87](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/config.rs#L87-L87)

Sources:

- `src/cli.rs:1-109`
- `src/handshake/server.rs:1-132`
- `src/config.rs:1-128`
- `src/protocol/data.rs:1-68`
- `src/tls/stateful.rs:1-157`
- `src/probe.rs:44-69`
- `src/crypto/auth.rs:1-43`
- `src/crypto/session.rs:14-205`
- `src/traffic.rs:1-41`
- `src/tls/client_hello_builder.rs:27-121`