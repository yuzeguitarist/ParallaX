# ParallaX

ParallaX is a Rust censorship-resistant proxy prototype focused on a TLS-looking
TCP transport:

- real-looking TLS 1.3 ClientHello with SNI and X25519 key_share
- ECDH-bound ClientHello authentication hidden in SessionID
- unauthenticated or malformed traffic falls back to the camouflage site
- encrypted data mode is carried as TLS ApplicationData records
- XChaCha20-Poly1305 data protection with per-direction nonces
- one stream per TCP connection by default to avoid multiplexing fingerprints

## Build

```bash
cargo build --release
```

The package builds two binaries:

- `parallax`
- `plx`

## Quick start

Pick a camouflage domain first:

```bash
plx probe cloudflare.com
```

Generate a ready-to-edit config:

```bash
plx init cloudflare.com --server-addr YOUR_VPS_IP:443
```

This creates `parallax.server.toml` and `parallax.client.toml` without
overwriting existing files.

For private VPS deployment, keep source code local and upload only the built
binary plus server config:

```bash
bash scripts/deploy-vps.sh root@YOUR_VPS_IP cloudflare.com
```

See `DEPLOYMENT.md` for the full local-build, binary-only workflow.

For advanced/manual setups, the lower-level template command is still available:

```bash
plx config-template \
  --server-listen 0.0.0.0:443 \
  --client-listen 127.0.0.1:1080 \
  --server-addr YOUR_VPS_IP:443 \
  --fallback-addr example.com:443 \
  --sni example.com
```

Split the printed output into server-side and client-side `parallax.toml` files.

## Run

Server:

```bash
plx serve -c parallax.toml
```

Client:

```bash
plx client -c parallax.toml
```

Point local applications at the client SOCKS5 listener, default
`127.0.0.1:1080`.

## Verification

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Loopback integration tests are marked `ignored` because they open local TCP
sockets:

```bash
cargo test -- --ignored
```

## Benchmark

Run local CPU-only protocol benchmarks without changing routes or touching
system proxy/VPN state:

```bash
plx bench --iterations 1000 --warmup 100 --payload-size 1024
plx bench --json
```
