# Getting Started & CLI Reference

> Navigation: [Index](README.md) | [Configuration](Configuration-Reference.md) | [Deployment](Deployment.md)

## Requirements

- Rust `1.80+`
- `cargo`
- A fallback TLS origin that is reachable from the VPS
- A VPS that can listen on the configured TCP port, usually `443`

Build locally:

```bash
cargo build --release
```

Install locally:

```bash
cargo install --path .
```

## Beginner workflow

```bash
# 1. Check a camouflage/fallback origin.
plx probe cloudflare.com

# 2. Generate paired config files in the current directory.
plx init cloudflare.com --server-addr YOUR_VPS_IP:443

# 3. Deploy with the guided wizard.
bash scripts/deploy-vps.sh

# 4. Run the local client and browse through SOCKS5.
plx client -c target/parallax-deploy/<host>/parallax.client.toml
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

`plx init` writes `parallax.server.toml` and `parallax.client.toml` with mode
`0600` on Unix and refuses to overwrite either file.

## Command summary

| Command | Purpose | Notes |
|---|---|---|
| `plx check [-c FILE]` | Validate TOML, keys, traffic bounds, client bind address, server SNI allowlist, and Unix secret-file permissions. | Defaults to `parallax.toml`. |
| `plx keygen` | Print a fresh X25519 key pair. | Useful for manual config work. |
| `plx crypto-self-test` | Run a local AEAD derivation/seal/open sanity check. | Does not contact the network. |
| `plx serve [-c FILE]` | Start the server listener. | Long-lived process hardening runs before config use. |
| `plx client [-c FILE]` | Start the loopback SOCKS5 client. | Uses a runtime guard to avoid conflicts with `plx speed`. |
| `plx speed [-c FILE] [--json]` | Run one network speed evidence test against the configured server. | Fixed warmup + three samples per direction. |
| `plx bench [--quick] [--json]` | Run the fixed CPU benchmark suite. | `--quick` is a smoke profile, not a custom benchmark knob. |
| `plx config-template ...` | Print paired server/client TOML templates to stdout. | Advanced mode; no file writes. |
| `plx probe [DEST] [-c FILE]` | Probe an explicit or config-derived camouflage target. | Accepts `domain`, `domain:port`, or `https://domain`. |
| `plx init <DEST> ...` | Generate paired config files with fresh key material. | Use `-o DIR` to choose the output directory. |

There is no `--quic` option on current `main`.

## Important options

### `plx init`

```text
plx init <DEST>
  --server-addr <HOST:PORT>      client-visible server address
  --server-listen <ADDR:PORT>    server bind address, default 0.0.0.0:443
  --client-listen <ADDR:PORT>    local SOCKS address, default 127.0.0.1:1080
  -o, --output <DIR>             output directory, default .
```

### `plx probe`

```text
plx probe [DEST] -c parallax.toml
```

When `DEST` is omitted, `probe` infers a target from config:

- server mode: `server.fallback_addr` and the first `server.authorized_sni`
- client mode: `client.sni`

### `plx speed`

`plx speed` reads a client config, performs a real ParallaX handshake, and emits
either text or JSON. The JSON schema is `parallax.speed.evidence.v1`.

## Verification commands

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked --no-fail-fast
cargo test --locked -- --ignored --test-threads=1
cargo test --test gfw_simulator
```

Use [Protocol Benchmarks](Protocol-Benchmarks.md) for local CPU timing and
[Camouflage Target Probe](Camouflage-Target-Probe.md) for fallback-origin
selection details.
