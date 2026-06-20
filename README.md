# ParallaX

> **Look like the web. Move like the web.**
>
> A Rust proxy that does not try to hide TLS. It hides that the TLS flow is not
> an ordinary browser session.

ParallaX is a single-binary censorship-resistance proxy. The current product
path is deliberately narrow: local SOCKS5 ingress, a TCP/TLS camouflage
transport, ClientHello-embedded authentication, fallback passthrough for
unauthenticated traffic, and an AEAD data plane that rekeys with ML-KEM-1024.

```text
Application ──SOCKS5──► plx client ──TLS 1.3 / Safari-like ClientHello──► plx serve ──► target
                                      │
                                      └─ unauthenticated or malformed traffic ──► fallback origin
```

The codebase also carries a source-level GFW simulator and censorship research
notes. Those are validation and research assets, not a second production
transport.

There is no `--quic` CLI flag, but an **experimental** UDP/QUIC fast plane (the
"U" in TUDP) *is* wired into the client and server runtimes: setting
`[udp].enabled = true` on **both** ends activates a masquerading-h3 QUIC carrier
for the single-Connect data relay, authenticated by an exporter-bound probe token
(the QUIC leg treats its server certificate as camouflage, not the trust anchor).
It is **off by default**; while disabled, every path stays byte-identical on TCP.
When enabled, its QUIC client already emits a Safari-26 H3-shaped ClientHello by
default, but the fast plane is not yet a production-ready operator mode, so
enabling it is for experimentation, not censorship-resistant production use.

---

## What ParallaX optimizes for

1. **Browser-shaped ingress to the server.** The client drives ParallaX's
   single Safari 26 TLS 1.3 state machine and patches only the entropy fields
   needed for authentication. The visible handshake is shaped around the
   Safari 26 / macOS Tahoe profile implemented in `src/tls/safari26.rs`.
2. **Probe-safe failure behavior.** If the first record is malformed,
   unauthenticated, unauthorized for SNI, or only a partial probe prefix, the
   server relays traffic to a configured fallback TLS origin instead of
   exposing a proxy-shaped rejection.
3. **Hybrid post-quantum rekeying.** After the camouflage TLS handshake,
   the ParallaX data plane performs a bound ML-KEM-1024 + X25519 + PSK
   "sandwich" rekey and verifies a ML-DSA-87 server identity proof.
4. **Operational simplicity.** `plx init`, `plx probe`, `plx check`,
   `plx speed`, and `scripts/deploy-vps.sh` are intended to keep deployment
   reproducible without copying source code onto the VPS.
5. **Evidence-driven validation.** CI and local verification use the Rust test
   suite, ignored loopback relay tests, fixed-parameter benchmarks, and the
   GFW simulator scenarios under `tests/gfw_simulator.rs`.

---

## Feature map

| Area | Current behavior | Main code |
|---|---|---|
| CLI and config | `check`, `keygen`, `crypto-self-test`, `serve`, `client`, `speed`, `netmatrix`, `bench`, `config-template`, `probe`, `init`; TOML config with secret-permission checks. | `src/cli.rs`, `src/config.rs` |
| Client runtime | Loopback-only SOCKS5 listener, authenticated server connection, PQ rekey, ML-DSA identity verification, bidirectional relay. | `src/client/runtime.rs`, `src/client/socks.rs` |
| Server runtime | First-record classification, authorized-SNI check, fallback passthrough, authenticated data relay, fixed `server.data_target` support. | `src/handshake/server.rs` |
| TLS camouflage | Handwritten Safari 26 TLS 1.3 client state machine with Safari cipher/group/extension ordering, GREASE, ALPN, ClientHello authentication fields, certificate verification, and HTTP/2 preface support. | `src/tls/safari26.rs`, `src/tls/client_hello.rs`, `src/fingerprint/http2.rs` |
| Handshake authentication | PSK + X25519 material embedded into `ClientHello.random` and compatibility `SessionID`; replay cache gates authenticated handshakes. | `src/crypto/auth.rs`, `src/crypto/replay.rs` |
| PQ and identity | ML-KEM-1024 rekey, transcript-bound server key exchange, ML-DSA-87 identity proof over the rekey binding. | `src/crypto/pq.rs`, `src/crypto/identity.rs`, `src/protocol/command.rs` |
| Data plane | AEAD records (server-negotiated AES-256-GCM or ChaCha20-Poly1305; 96-bit per-record counter nonce) carried inside TLS `ApplicationData` frames, per-direction nonce ratchets, optional padding/timing/cover traffic; bulk batches seal/open across a shared multi-core crypto pool. | `src/crypto/session.rs`, `src/protocol/data.rs`, `src/crypto/parallel.rs`, `src/traffic.rs` |
| TCP transport | Default TCP product transport with `TCP_NODELAY`, cross-platform TCP keepalive (SO_KEEPALIVE), fd-limit based relay concurrency, and 64 KiB relay buffers. | `src/transport/tcp.rs` |
| Process hardening | Best-effort no-core-dump setup, non-dumpable process flag, `mlock`, `MADV_DONTDUMP`, and strict config file ownership/mode checks. | `src/process_hardening.rs`, `src/config.rs` |
| Operations | Local build, binary-only VPS upload, hardened systemd unit, optional BBR/fq setup, optional Polar Signals / parca-agent profiling. | `scripts/deploy-vps.sh`, `scripts/uninstall-vps.sh` |
| Validation | Unit/integration tests, Safari parity fixtures, ignored loopback tests, GFW simulator, fixed 59-case benchmark suite, speed evidence report. | `tests/`, `src/bench.rs`, `src/speed.rs` |

---

## Build

Requirements:

- A recent stable Rust toolchain (the pinned `Cargo.lock` needs Cargo ≥ 1.85; the `rust-version = 1.80` in `Cargo.toml` is nominal)
- `cargo`
- No `openssl-sys` or system OpenSSL dependency

```bash
cargo build --release
```

The crate builds two entry points:

- `parallax` — canonical package binary
- `plx` — short operational alias used in the docs

Install both from the repository root:

```bash
cargo install --path .
```

---

## Quick start

### 1. Probe a fallback origin

```bash
plx probe cloudflare.com
```

`probe` accepts `domain`, `domain:port`, or `https://domain`. It checks TCP
connectivity, TLS handshake behavior, TLS 1.3, ALPN, post-handshake records,
and prints a score so you can decide whether the origin is a good camouflage
fallback.

### 2. Generate paired configs

```bash
plx init cloudflare.com --server-addr YOUR_VPS_IP:443
```

This writes:

- `parallax.server.toml`
- `parallax.client.toml`

Both files are created with mode `0600` on Unix. `init` refuses to overwrite
existing config files. The generated material includes:

- 32-byte PSK
- X25519 server key pair
- ML-DSA-87 server identity key pair

### 3. Deploy the server

Guided mode:

```bash
bash scripts/deploy-vps.sh
```

Explicit mode:

```bash
bash scripts/deploy-vps.sh root@YOUR_VPS_IP cloudflare.com
```

The deploy script builds a Linux `plx` binary locally, stages files under
`target/parallax-deploy/<host>/`, uploads only the binary/server config/systemd
unit, installs the service, optionally enables BBR + `fq`, and can optionally
wire Polar Signals Cloud profiling through `parca-agent`.

### 4. Run the client

```bash
plx client -c target/parallax-deploy/<host>/parallax.client.toml
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

If you generated configs manually, use the path to your local
`parallax.client.toml` instead.

---

## CLI reference

```text
plx check [-c parallax.toml]
    Validate config syntax, required sections, key lengths, traffic bounds,
    loopback-only client listen addresses, server SNI allowlist, and Unix
    secret-file permissions.

plx keygen
    Print a fresh X25519 key pair.

plx crypto-self-test
    Derive ephemeral AEAD keys, seal and open a local test payload.

plx serve [-c parallax.toml]
    Run the server handshake/fallback listener.

plx client [-c parallax.toml]
    Run the local SOCKS5 client.

plx speed [-c parallax.toml] [--json]
    Run a one-shot network speed evidence test against the configured server.

plx netmatrix [-c parallax.toml] [--json]
    Run a reproducible controlled-network RTT/bandwidth speed matrix against the
    configured server via an emulated loopback shaper.

plx bench [--quick] [--json]
    Run the fixed-parameter CPU benchmark suite.

plx config-template [--server-listen ...] [--client-listen ...]
                    [--server-addr ...] [--fallback-addr ...] [--sni ...]
    Print paired server/client TOML templates to stdout.

plx probe [DEST] [-c parallax.toml]
    Probe an explicit fallback destination, or infer one from config.

plx init <DEST> [--server-addr ...] [--server-listen ...]
                [--client-listen ...] [-o DIR]
    Generate paired config files with fresh key material.
```

Every command supports `--help`.

---

## Configuration shape

Minimal generated server shape:

```toml
mode = "server"

[crypto]
psk = "base64..."

[traffic]
min_padding = 0
max_padding = 0
min_delay_ms = 0
max_delay_ms = 0
cover_min_interval_ms = 0
cover_max_interval_ms = 0
max_concurrent_streams = 4

[server]
listen = "0.0.0.0:443"
fallback_addr = "cloudflare.com:443"
private_key = "base64-x25519-secret"
identity_secret_key = "base64-mldsa87-secret"
replay_cache_path = "/var/lib/parallax/parallax-replay.cache"
authorized_sni = ["cloudflare.com"]
strict_tls13 = true
```

Minimal generated client shape:

```toml
mode = "client"

[crypto]
psk = "same-base64-psk"

[traffic]
min_padding = 0
max_padding = 0
min_delay_ms = 0
max_delay_ms = 0
cover_min_interval_ms = 0
cover_max_interval_ms = 0
max_concurrent_streams = 4

[client]
listen = "127.0.0.1:1080"
server_addr = "YOUR_VPS_IP:443"
sni = "cloudflare.com"
server_public_key = "base64-x25519-public"
server_identity_public_key = "base64-mldsa87-public"
```

See the full configuration reference in
[`ParallaX-DeepWiki/Configuration-Reference.md`](./ParallaX-DeepWiki/Configuration-Reference.md).

---

## Verification

Use these checks after code or documentation changes:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked --no-fail-fast
```

Ignored loopback relay tests open local TCP sockets. Run them separately and
serially:

```bash
cargo test --locked -- --ignored --test-threads=1
```

Run the GFW simulator directly:

```bash
cargo test --test gfw_simulator
```

---

## Benchmarking and speed evidence

Local CPU benchmark:

```bash
plx bench
plx bench --quick
plx bench --json
```

The benchmark suite is intentionally fixed-parameter. Current `main` runs
59 cases across six groups: `handshake.crypto`, `handshake.protocol`,
`record.aead`, `record.pipeline`, `traffic`, and `state`.

Network speed evidence test:

```bash
plx speed -c parallax.client.toml
plx speed -c parallax.client.toml --json
```

`plx speed` is not a local CPU benchmark. It connects to the configured server,
runs a fixed warmup plus three upload/download samples, and emits a structured
report with config fingerprint, server address, SNI, traffic profile, payload
sizes, handshake timing, warmup timing, per-sample throughput, and summary
statistics.

`plx client` and `plx speed` use a runtime guard so a normal client process and
a speed run do not accidentally compete against the same configured server.

---

## Documentation map

The maintained technical knowledge base lives in
[`ParallaX-DeepWiki/`](./ParallaX-DeepWiki/). It is organized as a graph:
operator docs, architecture docs, cryptography docs, camouflage docs,
validation docs, and a metadata/search layer that maps pages back to source
files.

Start with:

- [Knowledge Base Index](./ParallaX-DeepWiki/README.md)
- [Documentation Metadata & Search Graph](./ParallaX-DeepWiki/Documentation-Metadata-Search-Graph.md)
- [ParallaX Overview](./ParallaX-DeepWiki/ParallaX-Overview.md)
- [Getting Started & CLI Reference](./ParallaX-DeepWiki/Getting-Started-&-CLI-Reference.md)
- [Core Architecture](./ParallaX-DeepWiki/Core-Architecture.md)
- [Deployment](./ParallaX-DeepWiki/Deployment.md)
- [Glossary](./ParallaX-DeepWiki/Glossary.md)

Useful searches:

| Search intent | Query terms | Start here |
|---|---|---|
| Source file to documentation owner | `source-to-document ownership`, `doc-id`, a path like `src/handshake/server.rs` | [Documentation Metadata & Search Graph](./ParallaX-DeepWiki/Documentation-Metadata-Search-Graph.md) |
| Operator rollout | `plx init`, `plx probe`, `deploy-vps`, `systemd`, `BBR` | [Getting Started & CLI Reference](./ParallaX-DeepWiki/Getting-Started-&-CLI-Reference.md), [Deployment](./ParallaX-DeepWiki/Deployment.md) |
| Current product boundary | `product path`, `TCP/TLS`, `experimental [udp].enabled QUIC`, `off by default` | [ParallaX Overview](./ParallaX-DeepWiki/ParallaX-Overview.md), [Transport Layer](./ParallaX-DeepWiki/Transport-Layer.md) |
| Validation evidence | `plx speed`, `plx bench`, `gfw_simulator`, `runtime guard` | [Probing & Benchmarking](<./ParallaX-DeepWiki/Probing-&-Benchmarking.md>) |

The source-level censorship research model lives under `tests/gfw_sim/` and is
documented through [GFW Simulator & QUIC Research](<./ParallaX-DeepWiki/GFW-Simulator-&-QUIC-Research.md>).

---

## Repository layout

```text
src/
  cli.rs                  CLI commands and generated config templates
  config.rs               TOML schema, validation, permission checks
  client/                 SOCKS5 parser and client relay runtime
  handshake/              Client/server handshake and data-session state
  crypto/                 X25519, AEAD, parallel crypto pool, ML-KEM, ML-DSA, replay cache
  tls/                    Safari-shaped TLS camouflage and TLS records
  fingerprint/            HTTP/2 Safari preface and header helpers
  protocol/               Binary commands and encrypted data records
  transport/              TCP transport helpers
  traffic.rs              Padding, timing, and cover-traffic profiles
  probe.rs                Camouflage target probing
  speed.rs                Network speed evidence report
  bench.rs                Fixed benchmark suite

scripts/
  deploy-vps.sh           Local-build, binary-only VPS deployment
  uninstall-vps.sh        Guided and explicit VPS cleanup

tests/
  gfw_simulator.rs        Source-level adversary scenarios
  gfw_sim/                Simulator detectors, fixtures, verdicts
  fixtures/               Safari/TLS/HTTP2 baseline captures

ParallaX-DeepWiki/        Interlinked English technical knowledge base
```

---

## License

[PolyForm Noncommercial License 1.0.0](LICENSE). Noncommercial use only —
read, study, run, fork, modify, and contribute freely; **commercial use of any
kind is not permitted**. Forks and modified versions must stay under this same
license and must state that they are based on ParallaX. See `LICENSE` for the
full terms and `NOTICE` for the attribution and noncommercial conditions.
