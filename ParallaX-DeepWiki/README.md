# ParallaX DeepWiki

> Interlinked technical knowledge base for the current ParallaX `main` branch.
> These pages describe the shipped TCP/TLS product path. Historical QUIC work is
> covered only as research/simulator context, not as an active transport.

## Fast orientation

| If you want to know... | Start here |
|---|---|
| What ParallaX is and what it is not | [ParallaX Overview](ParallaX-Overview.md) |
| How to build, generate configs, run, and verify | [Getting Started & CLI Reference](Getting-Started-&-CLI-Reference.md) |
| How the client, server, TLS camouflage, crypto, and relay fit together | [Core Architecture](Core-Architecture.md) |
| What every TOML field means | [Configuration Reference](Configuration-Reference.md) |
| How VPS deployment works | [Deployment](Deployment.md) and [VPS Deployment Script](VPS-Deployment-Script.md) |
| Definitions for project-specific vocabulary | [Glossary](Glossary.md) |

## Reading paths

### Operator path

1. [ParallaX Overview](ParallaX-Overview.md)
2. [Getting Started & CLI Reference](Getting-Started-&-CLI-Reference.md)
3. [Configuration Reference](Configuration-Reference.md)
4. [Camouflage Target Probe](Camouflage-Target-Probe.md)
5. [Deployment](Deployment.md)
6. [Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md)

### Architecture path

1. [Core Architecture](Core-Architecture.md)
2. [Client Runtime & SOCKS5 Proxy](Client-Runtime-&-SOCKS5-Proxy.md)
3. [Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md)
4. [TLS Camouflage Layer](TLS-Camouflage-Layer.md)
5. [Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md)
6. [Transport Layer](Transport-Layer.md)

### Cryptography path

1. [Cryptographic Subsystems](Cryptographic-Subsystems.md)
2. [ClientHello Authentication (PSK + X25519)](<ClientHello-Authentication-(PSK-+-X25519).md>)
3. [Session Key Derivation & AEAD Transport](Session-Key-Derivation-&-AEAD-Transport.md)
4. [Post-Quantum Cryptography (ML-KEM & ML-DSA)](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>)
5. [Replay Protection](Replay-Protection.md)

### Camouflage and traffic-shaping path

1. [TLS Camouflage Layer](TLS-Camouflage-Layer.md)
2. [ClientHello Builder & Browser Profiles](ClientHello-Builder-&-Browser-Profiles.md)
3. [Stateful Rustls Camouflage Backend](Stateful-Rustls-Camouflage-Backend.md)
4. [HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md)
5. [Traffic Obfuscation](Traffic-Obfuscation.md)
6. [Padding & Timing Profiles](<Padding-&-Timing-Profiles.md>)
7. [Cover Traffic](Cover-Traffic.md)

### Validation and research path

1. [Probing & Benchmarking](<Probing-&-Benchmarking.md>)
2. [Protocol Benchmarks](Protocol-Benchmarks.md)
3. [GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>)
4. Research notes in [`../docs/`](../docs/)

## Complete page index

- [ParallaX Overview](ParallaX-Overview.md)
- [Getting Started & CLI Reference](Getting-Started-&-CLI-Reference.md)
- [Configuration Reference](Configuration-Reference.md)
- [Core Architecture](Core-Architecture.md)
- [Client Runtime & SOCKS5 Proxy](Client-Runtime-&-SOCKS5-Proxy.md)
- [Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md)
- [Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md)
- [Cryptographic Subsystems](Cryptographic-Subsystems.md)
- [ClientHello Authentication (PSK + X25519)](<ClientHello-Authentication-(PSK-+-X25519).md>)
- [Session Key Derivation & AEAD Transport](Session-Key-Derivation-&-AEAD-Transport.md)
- [Post-Quantum Cryptography (ML-KEM & ML-DSA)](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>)
- [Replay Protection](Replay-Protection.md)
- [TLS Camouflage Layer](TLS-Camouflage-Layer.md)
- [ClientHello Builder & Browser Profiles](ClientHello-Builder-&-Browser-Profiles.md)
- [Stateful Rustls Camouflage Backend](Stateful-Rustls-Camouflage-Backend.md)
- [HTTP/2 Fingerprinting](HTTP-2-Fingerprinting.md)
- [Traffic Obfuscation](Traffic-Obfuscation.md)
- [Padding & Timing Profiles](<Padding-&-Timing-Profiles.md>)
- [Cover Traffic](Cover-Traffic.md)
- [Transport Layer](Transport-Layer.md)
- [TCP Camouflage Transport](TCP-Camouflage-Transport.md)
- [GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>)
- [Probing & Benchmarking](<Probing-&-Benchmarking.md>)
- [Camouflage Target Probe](Camouflage-Target-Probe.md)
- [Protocol Benchmarks](Protocol-Benchmarks.md)
- [Deployment](Deployment.md)
- [VPS Deployment Script](VPS-Deployment-Script.md)
- [Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md)
- [Glossary](Glossary.md)

## Maintenance rules

- Prefer relative links to pages and source paths; avoid stale GitHub line links.
- When a code path is removed, update or delete the page instead of leaving a
  historical transport as if it were still active.
- Keep command references aligned with `plx --help`.
- Keep configuration docs aligned with `src/config.rs` and generated templates
  in `src/cli.rs`.
- Keep validation docs aligned with `cargo test`, ignored loopback tests, and
  `tests/gfw_simulator.rs`.
