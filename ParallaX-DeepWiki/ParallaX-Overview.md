# ParallaX Overview
Relevant source files

- [README.md](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1)
- [src/cli.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs)
- [src/lib.rs](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs)

ParallaX is a high-performance, censorship-resistant proxy protocol written in Rust. Its primary design goal is to bypass advanced traffic analysis by mimicking legitimate browser-based TLS 1.3 traffic while providing a secure, authenticated tunnel for proxied data [README.md#3-12](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1#L3-L12)

The system operates as a client-server architecture where the client exposes a local SOCKS5 interface and tunnels traffic to a remote server. The server acts as a dual-purpose listener: it provides proxy services to authenticated clients and transparently falls back to a legitimate "camouflage" website for unauthenticated or suspicious probes [README.md#6-12](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1#L6-L12)

### Design Goals

- Mimicry: Constructing TLS 1.3 `ClientHello` messages that are indistinguishable from real browsers (Chrome, Safari) [README.md#6-7](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1#L6-L7)
- Probing Resistance: Using a fallback mechanism to redirect unauthorized scanners to a legitimate backend, such as `cloudflare.com` or `example.com`[README.md#8](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1#L8-L8)
- Security: Leveraging modern cryptographic primitives including X25519 for key exchange, XChaCha20-Poly1305 for data protection, and Post-Quantum (PQ) algorithms for long-term forward secrecy [src/cli.rs#16-19](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L16-L19)[src/lib.rs#5](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs#L5-L5)
- Analysis Resistance: Implementing traffic shaping through padding, timing delays, and cover traffic to defeat packet-length and timing-based analysis [src/lib.rs#11](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs#L11-L11)

### System Components

The ParallaX codebase is organized into several major subsystems that handle different stages of the proxy lifecycle:

| Subsystem | Responsibility | Key Entities |
| --- | --- | --- |
| CLI (`plx`) | Entry point for management and execution. | `Cli`, `Command`[src/cli.rs#25-34](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L25-L34) |
| Handshake | Handles the initial TLS camouflage and authentication. | `server::run`, `client::runtime`[src/cli.rs#149-160](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L149-L160) |
| Crypto | Manages session keys, PQ rekeying, and identity. | `AeadCodec`, `X25519KeyPair`[src/cli.rs#137-138](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L137-L138) |
| Transport | Manages raw TCP or QUIC/UDP data movement. | `quic_runtime`, `server::run`[src/cli.rs#147-151](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L147-L151) |
| Traffic | Applies padding and cover traffic profiles. | `PaddingProfile`, `CoverTrafficProfile`[src/lib.rs#11](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs#L11-L11) |

### Bridge: Natural Language to Code Space

The following diagrams illustrate how high-level protocol concepts map to specific modules and functions within the `parallax` codebase.

#### Diagram 1: Execution Flow and CLI Mapping

This diagram shows how the `plx` CLI commands trigger specific runtime behaviors.

[Flowchart Diagram]

Sources:[src/cli.rs#36-109](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L36-L109)[src/cli.rs#144-161](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L144-L161)[src/lib.rs#1-12](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs#L1-L12)

#### Diagram 2: Cryptographic and Protocol Entities

This diagram maps the protocol's security layers to the internal library modules.

[Flowchart Diagram]

Sources:[src/cli.rs#16-19](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L16-L19)[src/lib.rs#5-9](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs#L5-L9)

### Major Subsystems

#### CLI and Configuration

The `plx` utility is the primary interface for interacting with the protocol. It supports generating keys (`keygen`), initializing configuration files (`init`), and validating settings (`check`) [src/cli.rs#37-46](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L37-L46)
For details, see [Getting Started & CLI Reference](#1.1).

#### TLS Camouflage

ParallaX does not just use TLS; it "camouflages" its traffic within a handshake that looks like a standard web browser [README.md#6](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1#L6-L6) This involves hijacking fields like the `session_id` to carry encrypted authentication tags without breaking the TLS 1.3 state machine [README.md#7](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1#L7-L7)
For details, see [TLS Camouflage Layer](#4).

#### Transport Modes

ParallaX supports two primary transport methods:

1. TCP Camouflage: The default mode, mimicking standard HTTPS traffic [README.md#3-4](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1#L3-L4)
2. QUIC/UDP: A performance-oriented mode that uses the QUIC protocol for lower latency and better congestion control [src/cli.rs#51-53](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L51-L53)
For details, see [Transport Layer](#6).

#### Traffic Obfuscation

To counter traffic analysis, ParallaX uses `PaddingProfile` and `CoverTrafficProfile` to modify the size and timing of packets, ensuring that the proxy stream does not exhibit "unnatural" patterns typical of encrypted tunnels [src/lib.rs#11](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs#L11-L11)
For details, see [Traffic Obfuscation](#5).

### Next Steps

- To set up your first server, refer to [Getting Started & CLI Reference](#1.1).
- To understand the cryptographic handshake, see [Core Architecture](#2).
- To learn about the configuration fields, see [Configuration Reference](#1.2).

Sources:[src/cli.rs#1-189](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/cli.rs#L1-L189)[README.md#1-104](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/README.md?plain=1#L1-L104)[src/lib.rs#1-16](https://github.com/yuzeguitarist/ParallaX/blob/77045cea/src/lib.rs#L1-L16)