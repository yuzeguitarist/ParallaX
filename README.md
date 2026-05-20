# ParallaX

> **Look like the web. Move like the web.**
> A censorship-resistant proxy that doesn't hide *that* it's TLS — it hides *that it isn't a browser*.

ParallaX is a single-binary Rust proxy that speaks real TLS 1.3 to the wire,
authenticates clients *inside* the ClientHello, falls back to a legitimate
camouflage origin for everyone else, and re-keys its data plane with
post-quantum ML-KEM-1024 — all behind a one-command VPS deploy.

```
  Browser ──SOCKS5──► plx client ──TLS 1.3 (Safari 26 parity)──► plx serve ──► Internet
                                       │                                   │
                                       │ unauthenticated / malformed       │
                                       └───────────────────────────────────▶ camouflage origin
                                              (cloudflare.com, etc.)
```

---

## Why ParallaX

Most "obfuscated proxies" leak themselves through the parts they didn't
bother to fake. ParallaX is engineered around three uncomfortable truths:

1. **Mimicry has to be stateful.** ParallaX runs an unmodified `rustls` TLS
   1.3 stack, then surgically patches the ClientHello randomness slots so
   the bytes on the wire match a real Safari 26 / macOS Tahoe handshake — extension
   order, GREASE values, ALPN, key shares and SessionID included. The handshake
   is a *real* handshake; the authentication is smuggled inside its entropy.
2. **A proxy that refuses connections *is* a fingerprint.** Unauthenticated
   or malformed traffic transparently flows through to a real camouflage
   origin (`cloudflare.com`, your CDN, whatever you point at). Active
   probers get a real TLS session terminated by a real website.
3. **Post-quantum is now, not "later".** Sessions can re-key mid-stream
   with hybrid ML-KEM-1024 + X25519 + symmetric-chain ("sandwich") KDF,
   and the server identity is signed with ML-DSA-87. Today's recorded
   traffic does not become tomorrow's plaintext.

ParallaX is a single Rust binary, MIT-licensed, with a fixed-parameter
benchmark suite and a source-level GFW simulator wired into CI. No magic.
No telemetry. No "trust us, it's fast".

---

## Feature matrix

| Layer | What ParallaX does | Where |
|---|---|---|
| **TLS 1.3 mimicry** | Stateful rustls patch reproduces Safari 26 (macOS Tahoe) `ClientHello`: extension order, GREASE positions, ALPN, X25519 key share, SessionID. | `src/tls/safari26.rs`, `src/tls/client_hello.rs` |
| **ClientHello authentication** | PSK + ECDH bound into `ClientHello.random` and `SessionID`. No extra round trip; no extension that screams "proxy". | `src/crypto/auth.rs`, `src/handshake/` |
| **HTTP/2 fingerprint** | Replays Safari 26's HTTP/2 preface (`SETTINGS` + `WINDOW_UPDATE`) byte-for-byte, sourced from a captured ground-truth fixture. | `src/fingerprint/http2.rs`, `tests/fixtures/` |
| **Probing resistance** | Server is a dual-role TLS listener: legitimate clients get a tunnel, everyone else gets passthrough to the fallback origin. SNI is allowlisted. | `src/handshake/server.rs` |
| **AEAD data plane** | XChaCha20-Poly1305 framed as TLS `ApplicationData` records, per-direction nonces, per-record HKDF ratchet. | `src/crypto/session.rs`, `src/protocol/data.rs` |
| **Post-quantum rekey** | ML-KEM-1024 hybrid re-key with an X25519 epoch + symmetric chain ("sandwich" KDF) bound to the transcript hash. | `src/crypto/pq.rs` |
| **Server identity** | ML-DSA-87 signature over the transcript. Pinned at the client; not bootstrapped from a CA. | `src/crypto/identity.rs` |
| **Replay protection** | Persistent on-disk replay cache (default `/var/lib/parallax/parallax-replay.cache`). Survives restarts. | `src/crypto/replay.rs` |
| **Traffic shaping** | Padding profile drawn from observed packet-size distributions; timing jitter; configurable cover-traffic generator. | `src/traffic.rs` |
| **Transport** | Plain TCP with TLS records. BBR + `fq` are auto-enabled on the VPS by the deploy script. | `src/transport/tcp.rs`, `scripts/deploy-vps.sh` |
| **Hardening** | `mlock`/`madvise(DONTDUMP)` on every key in memory, `prctl(PR_SET_DUMPABLE, 0)`, no-core-dump rlimit, file-permission checks on every config load. | `src/process_hardening.rs`, `src/config.rs` |
| **Benchmark suite** | 42 fixed cases across 6 groups (asymmetric, KDFs, handshake, AEAD pipeline, traffic shaping, replay cache). Reproducible across releases. | `src/bench.rs` |
| **Red-team validation** | Source-level "GFW simulator" with named adversary scenarios (JA4 drift, ML-KEM burst, active probing, …) run as integration tests. | `tests/gfw_simulator.rs`, `tests/gfw_sim/` |

---

## Build

ParallaX is `rustc 1.80+` and `cargo`. No system crypto, no `openssl-sys`.

```bash
cargo build --release
```

The crate produces two binaries that share a CLI:

- `parallax` — the canonical entry point.
- `plx` — a short alias used throughout the docs.

`cargo install --path .` puts both on your `$PATH`.

---

## Quick start

The fast path is three commands: pick a camouflage origin, generate fresh
configs, deploy.

### 1. Pick a camouflage target

```bash
plx probe cloudflare.com
```

`probe` opens a real TLS 1.3 handshake against the target, checks ALPN,
TLS version, certificate chain, and post-handshake behavior, and prints a
summary. Use the output to confirm the origin is suitable as a fallback
(reachable, TLS 1.3, well-behaved).

### 2. Generate paired configs

```bash
plx init cloudflare.com --server-addr YOUR_VPS_IP:443
```

This writes `parallax.server.toml` and `parallax.client.toml` to the
current directory with **mode 0600** permissions and freshly generated
key material:

- 32-byte PSK
- X25519 server key pair
- ML-KEM-1024 server key pair
- ML-DSA-87 server identity key pair

`init` refuses to overwrite existing config files. Keep the client TOML
on the machine you'll actually browse from; upload the server TOML to the VPS.

### 3. Deploy

```bash
bash scripts/deploy-vps.sh root@YOUR_VPS_IP cloudflare.com
```

This single command builds a Linux `plx` binary on your local machine,
uploads only the binary plus the server config, installs a hardened
`systemd` unit, and verifies that the VPS is running BBR + `fq`. Source
code never leaves your laptop.

Run with **no arguments** for the interactive wizard:

```bash
bash scripts/deploy-vps.sh
```

See [DEPLOYMENT.md](./DEPLOYMENT.md) for the full local-build,
binary-only workflow, including macOS cross-compilation, `--reuse-config`
redeploys, and optional staging profiling with Polar Signals Cloud.

### 4. Use it

On the VPS:

```bash
plx serve -c /etc/parallax/parallax.toml
```

On your machine:

```bash
plx client -c parallax.client.toml
```

Point any SOCKS5-aware client at `127.0.0.1:1080`:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

---

## CLI reference

```text
plx check               Validate parallax.toml and fail fast on unsafe settings.
plx keygen              Print a fresh X25519 key pair.
plx crypto-self-test    Locally verify AEAD key derivation.
plx serve   -c …        Run the server (handshake + fallback listener).
plx client  -c …        Run the SOCKS5 client.
plx speed   -c … [--json]
                        Run a one-shot network speed evidence test.
plx probe   <dest>      Probe a camouflage target's real TLS behavior.
plx init    <dest>      Generate paired server/client configs.
plx config-template …   Print paired configs to stdout (advanced; no file IO).
plx bench [--quick] [--json]
                        Run the fixed-parameter protocol benchmark suite.
```

Every command accepts `--help`. Config defaults to `parallax.toml`.

---

## Verification

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test  --locked --no-fail-fast
```

Loopback integration tests open local TCP sockets and are marked
`#[ignore]`. Run them serially:

```bash
cargo test --locked -- --ignored --test-threads=1
```

CI runs the same checks on every PR, plus the GFW simulator scenarios as
a separate required status check. See [`.github/workflows/`](./.github/workflows/).

---

## Benchmark

ParallaX ships a **non-configurable** benchmark suite. Case counts,
payload sizes, and iteration tiers are baked into the binary so reported
numbers stay comparable across releases — the suite is a long-lived
performance contract, not a tunable knob.

```bash
plx bench              # full suite, human-readable table
plx bench --json       # full suite, machine-readable
plx bench --quick      # ~1% iteration budget, CI smoke profile
```

`plx speed -c parallax.client.toml` is a network evidence test, not the local
CPU benchmark above. It connects directly to the configured `plx serve`, runs a
fixed warmup plus three measured upload/download samples, prints a structured
report, and exits. Use `--json` when the result should be archived by scripts.
The report includes the config fingerprint, server address, SNI, traffic
profile, payload chunk size, handshake timing, warmup timing, every sample, and
median/mean/min/max/stddev throughput summaries.

Do not start `plx client` while a speed test is active; the client command
fails fast until the speed run is finished. If a matching `plx client` is
already active for the same configured server, `plx speed` fails fast and
prints the `kill -TERM …` command for the conflicting process.

The suite covers asymmetric primitives (X25519, ML-KEM-1024 keygen /
encap / decap, ML-DSA-87 sign / verify), KDFs (HKDF, sandwich rekey),
handshake composition (stateful ClientHello build + parse + auth
verification), the AEAD pipeline at 64 B / 1 KiB / 16 KiB / 64 KiB / 1 MiB,
traffic-shaping overhead, and replay-cache bookkeeping.

---

## Red-team validation

`tests/gfw_simulator.rs` is a source-level model of a deep-packet-inspection
adversary. Each test is a named scenario that feeds a synthetic packet
trace into a chain of detectors (`JA3`/`JA4`, burst statistics, TLS-record
heuristics, active-probe behavior, dual-MB TCP analysis, …) and asserts
the resulting verdict layer-by-layer.

```bash
cargo test --test gfw_simulator
```

The intent is not to claim ParallaX always wins — it's to ground-truth
*what each detector sees on ParallaX-shaped traffic*. Scenarios that
correspond to predicted weaknesses (PqRekey burst shape, active-probe
exposure, JA4 drift across rustls upgrades) are explicit tests in this
file, not informal notes.

---

## Security model — short version

- **Authentication is in the handshake bytes themselves.** PSK + ECDH
  shared secret are bound into `ClientHello.random` and `SessionID`.
  No proxy-shaped extension, no second round trip, no JSON-over-TLS.
- **Failure mode is "be a website".** Anything that doesn't authenticate
  is bridged to the fallback origin. A scanner who connects, sends
  garbage, or replays a captured ClientHello gets a perfectly normal
  TLS session terminated by `cloudflare.com` (or whatever you chose).
- **Replays don't compose.** Authenticated ClientHellos are pinned to
  the on-disk replay cache. A captured handshake is single-use across
  restarts.
- **Post-quantum is on, not optional.** Servers generated by `plx init`
  ship with ML-KEM-1024 + ML-DSA-87 key material populated by default;
  the data plane can re-key mid-stream with the hybrid sandwich KDF.
- **Secrets live in locked, non-dumpable memory.** Every key is `mlock`ed,
  marked `MADV_DONTDUMP`, the process disables core dumps and clears its
  `dumpable` flag on startup, and config files are rejected if their
  Unix permissions aren't `0600` owned by the running user.

For the full design — including the stateful rustls patch, the sandwich
KDF, and the camouflage state machine — see [`ParallaX-DeepWiki/`](./ParallaX-DeepWiki).

---

## Repository layout

```
src/
├── cli.rs              # CLI entry point (clap)
├── client/             # SOCKS5 ingress + client runtime
├── handshake/          # Server + client handshake state machines
├── tls/                # Safari 26 stateful camouflage, record I/O
├── crypto/             # X25519, AEAD ratchet, ML-KEM, ML-DSA, replay cache
├── protocol/           # Wire format (commands, data records)
├── transport/          # TCP transport
├── traffic.rs          # Padding / timing / cover-traffic profiles
├── fingerprint/        # HTTP/2 preface emulation
├── probe.rs            # plx probe
├── bench.rs            # plx bench (fixed-parameter suite)
└── config.rs           # parallax.toml schema + secret-aware loader

scripts/
├── deploy-vps.sh       # One-command local-build VPS deployer
└── uninstall-vps.sh    # Symmetric uninstaller

tests/
├── gfw_simulator.rs    # Source-level GFW red-team scenarios
├── gfw_sim/            # Simulator implementation (detection layers, fixtures)
├── safari_parity_baseline.rs
└── safari_h2_parity_baseline.rs

ParallaX-DeepWiki/      # Architecture deep-dive (per-subsystem)
```

---

## Documentation

- **Operations:** [DEPLOYMENT.md](./DEPLOYMENT.md) — VPS deploy, BBR tuning,
  Polar Signals profiling, reuse / redeploy, uninstall.
- **Architecture:** [`ParallaX-DeepWiki/`](./ParallaX-DeepWiki) — per-subsystem
  technical reference.
- **Contributor guidelines:** [AGENTS.md](./AGENTS.md).

---

## License

MIT. See `Cargo.toml`.
