# Glossary

> Navigation: [Index](README.md) | [Overview](ParallaX-Overview.md) | [Core Architecture](Core-Architecture.md)

## Core terms

| Term | Meaning |
|---|---|
| ParallaX | The Rust proxy/protocol implemented in this repository. |
| `plx` | Short CLI binary alias for the ParallaX command-line interface. |
| Product path | The current shipped operator path: TCP/TLS camouflage, SOCKS5 client, server fallback, AEAD relay. |
| UDP/QUIC fast plane | Experimental, off-by-default QUIC reliable-stream carrier for the single-Connect relay, enabled with `[udp].enabled = true` on both ends. |
| Fallback origin | A real TLS website/origin that unauthenticated or malformed traffic is relayed to. |
| Camouflage | Making ParallaX's visible wire behavior resemble ordinary browser TLS traffic. |
| Probe resistance | Server behavior that prevents scanners from receiving a distinct proxy-shaped failure. |
| Authorized SNI | Server allowlist of SNI names accepted for authenticated ClientHellos. |

## Cryptography

| Term | Meaning |
|---|---|
| PSK | Pre-shared secret in `[crypto].psk`. |
| X25519 | Classical ECDH used for ClientHello authentication and hybrid rekey input. |
| ML-KEM-1024 | Post-quantum KEM used for the data-plane rekey. |
| ML-DSA-87 | Post-quantum signature algorithm used for pinned server identity. |
| AEAD | Authenticated encryption with associated data for ParallaX records. |
| Crypto pool | Process-wide worker pool that fans bulk AEAD seal/open across cores while sequence assignment stays serial. |
| Chain secret | Ratcheted session secret used to derive directional data keys. |
| Sandwich rekey | Hybrid rekey that binds old chain secret, X25519, ML-KEM, and PSK/symmetric material. |
| Replay cache | Persistent server-side cache rejecting reused authenticated handshakes. |

## TLS and protocol terms

| Term | Meaning |
|---|---|
| ClientHello | First TLS handshake message; ParallaX hides auth material in its entropy fields. |
| `ClientHello.random` | TLS field used by ParallaX as one authenticated carrier. |
| SessionID | TLS 1.3 compatibility field used by ParallaX as another authenticated carrier. |
| ALPN | TLS extension negotiating HTTP/2 (`h2`) or other application protocols. |
| TLS ApplicationData | Outer TLS record type used to carry ParallaX encrypted data records. |
| `PX1C` | Connect request command magic. |
| `PX1Q` | PQ rekey request command magic. |
| `PX1K` | Server key-exchange command magic. |
| `PX1S` / `PX1I` | Server identity proof and chunk command magic. |

## Operations

| Term | Meaning |
|---|---|
| `plx probe` | Fallback-origin TLS suitability probe. |
| `plx speed` | Real client/server network speed evidence test. |
| `plx bench` | Fixed local CPU benchmark suite. |
| `--reuse-config` | Deploy-script mode that reuses local generated configs. |
| BBR/fq | Optional Linux TCP congestion/qdisc tuning applied by the deploy script. |
| Polar Signals / parca-agent | Optional profiling integration supported by the deploy script. |

## Research terms

| Term | Meaning |
|---|---|
| GFW simulator | Source-level test model of censorship/DPI behaviors under `tests/gfw_sim/`. |
| QUIC research | Simulator detection logic and adversary-model context, separate from the experimental UDP/QUIC fast plane; neither is a default product transport, and there is no `--quic` CLI flag. |
| JA3/JA4 | TLS fingerprinting families modeled by simulator detectors. |

## Documentation metadata terms

| Term | Meaning |
|---|---|
| `doc-id` | Stable search handle used by [Documentation Metadata & Search Graph](Documentation-Metadata-Search-Graph.md), for example `doc-id:runtime.server`. |
| Source of truth | Code, script, test, or command output that documentation must be checked against before wording is changed. |
| Source-to-document ownership | Mapping from implementation files to the pages that must be updated when those files change. |
| Search tag | Alias, command name, protocol token, or error-domain phrase added so readers can find the right page quickly. |
| Freshness check | Verification command or stale-reference search used to catch docs drifting away from current code. |
