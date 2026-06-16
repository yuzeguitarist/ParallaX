# ParallaX Overview

> Navigation: [Index](README.md) | [Core Architecture](Core-Architecture.md) | [Getting Started](Getting-Started-&-CLI-Reference.md)

## One-sentence summary

ParallaX is a single-binary Rust proxy that accepts local SOCKS5 traffic,
connects to a ParallaX server through a browser-shaped TLS 1.3 flow, hides
authentication inside ClientHello entropy fields, falls back to a real TLS
origin for unauthenticated traffic, and rekeys the encrypted data plane with a
hybrid post-quantum exchange.

## Current product boundary

| In scope on current `main` | Out of scope / research-only |
|---|---|
| TCP/TLS as the default, fingerprint-hardened transport | QUIC/UDP as a default or fingerprint-shaped production transport |
| Safari-shaped TLS 1.3 camouflage | Generic "random bytes" obfuscation |
| Local unauthenticated SOCKS5 bound to loopback | Public SOCKS5 listener |
| Fallback passthrough for unauthenticated/probe traffic | Dropping scanners with proxy-shaped errors |
| ML-KEM-1024 rekey and ML-DSA-87 server identity | CA-based server authentication for the ParallaX identity |
| Source-level GFW simulator tests | Claiming the simulator proves universal bypass |

There is no `--quic` CLI flag. An **experimental** UDP/QUIC fast plane *is* wired
into the client and server runtimes, but it is **off by default**: setting
`[udp].enabled = true` on both ends (with matched binaries) activates a QUIC
reliable-stream carrier for the single-Connect data relay. While disabled, every
path stays byte-identical on TCP. The QUIC handshake is not yet
Safari-fingerprint-shaped, so enabling it is for experimentation, not
censorship-resistant production use. QUIC also appears as research and detector
context in the simulator; see
[GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>).

## Main components

| Component | Role | Code |
|---|---|---|
| CLI | User-facing commands, config generation, benchmark/speed entry points. | `src/cli.rs` |
| Config loader | TOML schema, validation, secret-file permission checks, relative replay-cache paths. | `src/config.rs` |
| Client runtime | Loopback SOCKS5, server dial, TLS camouflage, PQ rekey, identity check, relay. | `src/client/runtime.rs` |
| Server runtime | First-record classification, replay check, fallback passthrough, authenticated relay. | `src/handshake/server.rs` |
| TLS camouflage | Handwritten Safari 26 TLS 1.3 state machine with Safari-shaped ClientHello and HTTP/2 preface support. | `src/tls/safari26.rs`, `src/fingerprint/http2.rs` |
| Cryptography | PSK/X25519 auth, AEAD session keys, ML-KEM, ML-DSA, replay cache. | `src/crypto/` |
| Wire protocol | Binary control commands and encrypted TLS ApplicationData records. | `src/protocol/` |
| Operations | Local-build VPS deploy/uninstall, systemd hardening, BBR/fq setup. | `scripts/` |
| Validation | Unit tests, integration tests, simulator, fixtures, benchmark suite. | `tests/`, `src/bench.rs` |

## Data flow at a glance

```text
SOCKS app
  │
  ▼
plx client
  ├─ accepts loopback SOCKS5 CONNECT
  ├─ starts Safari-shaped TLS camouflage to server_addr
  ├─ sends authenticated ClientHello fields
  ├─ performs ML-KEM/X25519/PSK rekey
  ├─ verifies ML-DSA server identity proof
  └─ relays encrypted data records
        │
        ▼
plx serve
  ├─ authenticates the first ClientHello record
  ├─ falls back to fallback_addr on probe/unauthorized input
  ├─ resolves fixed or client-requested target
  └─ relays application data over TCP
```

## Design principles

1. **Keep one real Safari-shaped protocol path.** The camouflage path is the
   handwritten Safari 26 TLS 1.3 implementation in `src/tls/safari26.rs`, not
   a configurable set of browser profiles.
2. **Make denial indistinguishable from an ordinary website path.** Probe and
   auth failures are forwarded to the fallback origin.
3. **Keep operational defaults speed-first.** Generated traffic shaping is zero
   padding, zero delay, and zero cover traffic, and multiplexing is on by
   default across up to four concurrent SOCKS streams over one authenticated
   session.
4. **Prefer measured evidence over claims.** `plx probe`, `plx speed`,
   `plx bench`, fixtures, and simulator tests all produce repeatable evidence.

## Where to go next

- Operators: [Getting Started & CLI Reference](Getting-Started-&-CLI-Reference.md)
- Maintainers: [Core Architecture](Core-Architecture.md)
- Security reviewers: [Cryptographic Subsystems](Cryptographic-Subsystems.md)
- Deployment owners: [Deployment](Deployment.md)
