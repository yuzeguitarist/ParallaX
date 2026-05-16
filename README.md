# ParallaX

ParallaX is a Rust censorship-resistant proxy prototype focused on a TLS-looking
TCP transport:

- real-looking TLS 1.3 ClientHello with SNI and X25519 key_share
- ECDH-bound ClientHello authentication hidden in SessionID
- unauthenticated or malformed traffic falls back to the camouflage site
- encrypted data mode is carried as TLS ApplicationData records
- ChaCha20-Poly1305 data protection with per-direction nonces
- one stream per TCP connection by default to avoid multiplexing fingerprints

## Build

```bash
cargo build --release
```

The package builds two binaries:

- `parallax`
- `plx`

## Generate config

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
