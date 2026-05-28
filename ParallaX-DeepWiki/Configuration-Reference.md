# Configuration Reference

> Navigation: [Index](README.md) | [Getting Started](Getting-Started-&-CLI-Reference.md) | [Deployment](Deployment.md)

Configuration is TOML. `Config::load` reads the file, parses it through Serde,
resolves relative replay-cache paths, validates semantic constraints, and on
Unix rejects group/world-readable secret files.

## Top-level fields

| Field | Type | Required | Meaning |
|---|---:|---:|---|
| `mode` | `"client"` or `"server"` | yes | Selects which section must be present. |
| `[crypto]` | table | yes | Shared cryptographic material. |
| `[traffic]` | table | no | Padding, timing, cover traffic, and stream-count settings. Defaults are speed-first. |
| `[client]` | table | client mode | Local SOCKS and remote server settings. |
| `[server]` | table | server mode | Listener, fallback, target, replay, and server secrets. |

## `[crypto]`

| Field | Required | Validation |
|---|---:|---|
| `psk` | yes | Base64 string that decodes to at least 32 bytes. |

The same PSK must appear in both generated configs. It is part of ClientHello
authentication and the hybrid rekey sandwich input.

## `[traffic]`

| Field | Default | Validation |
|---|---:|---|
| `min_padding` | `0` | `max_padding >= min_padding` |
| `max_padding` | `0` | Must leave room for a TLS ApplicationData payload. |
| `min_delay_ms` | `0` | `max_delay_ms >= min_delay_ms` |
| `max_delay_ms` | `0` | `0` disables timing jitter. |
| `cover_min_interval_ms` | `0` | `cover_max_interval_ms >= cover_min_interval_ms` |
| `cover_max_interval_ms` | `0` | `0` disables cover traffic. |
| `max_concurrent_streams` | `1` | Must remain `1` until multiplexing has fingerprint-safe scheduling. |

Generated configs set every traffic-shaping value to `0` except
`max_concurrent_streams = 1`. This keeps the default path speed-first and avoids
claiming unvalidated traffic-shaping behavior.

## `[client]`

| Field | Required | Validation / meaning |
|---|---:|---|
| `listen` | yes | Socket address for local SOCKS5. Must bind to loopback because SOCKS5 has no authentication. |
| `server_addr` | yes | Remote ParallaX server as `host:port`; IPv6 literals must be bracketed. |
| `sni` | yes | SNI sent in the camouflage TLS handshake. |
| `server_public_key` | yes | Base64 X25519 server public key, exactly 32 bytes. |
| `server_pq_public_key` | no | Base64 ML-KEM-1024 server public key. Generated configs include it. |
| `server_identity_public_key` | yes | Base64 ML-DSA-87 server identity public key. |

## `[server]`

| Field | Required | Validation / meaning |
|---|---:|---|
| `listen` | yes | Server bind address, usually `0.0.0.0:443`. |
| `fallback_addr` | yes | Real TLS origin used for unauthenticated/probe traffic. |
| `data_target` | no | Fixed upstream target for authenticated data. If omitted, the client CONNECT command chooses the target. |
| `private_key` | yes | Base64 X25519 server secret key, exactly 32 bytes. |
| `pq_secret_key` | no | Base64 ML-KEM-1024 server secret key. Generated configs include it. |
| `identity_secret_key` | yes | Base64 ML-DSA-87 server identity secret key. |
| `replay_cache_path` | no | Defaults to `/var/lib/parallax/parallax-replay.cache`; relative paths resolve relative to the config file. |
| `authorized_sni` | yes | Non-empty SNI allowlist for authenticated ClientHellos. Matching is case-insensitive. |
| `strict_tls13` | no | Defaults to `true`; fallback ServerHello must negotiate TLS 1.3 when enabled. |

## Generated server example

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
max_concurrent_streams = 1

[server]
listen = "0.0.0.0:443"
fallback_addr = "cloudflare.com:443"
private_key = "base64-x25519-secret"
pq_secret_key = "base64-mlkem-secret"
identity_secret_key = "base64-mldsa-secret"
replay_cache_path = "/var/lib/parallax/parallax-replay.cache"
authorized_sni = ["cloudflare.com"]
strict_tls13 = true
```

## Generated client example

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
max_concurrent_streams = 1

[client]
listen = "127.0.0.1:1080"
server_addr = "203.0.113.10:443"
sni = "cloudflare.com"
server_public_key = "base64-x25519-public"
server_pq_public_key = "base64-mlkem-public"
server_identity_public_key = "base64-mldsa-public"
```

## Security-sensitive loader behavior

- Config files must be owned by the current Unix user.
- Group/world permission bits are rejected.
- The server replay-cache path is normalized before use.
- Secret strings are passed through best-effort memory hardening before the
  long-lived client/server/speed paths continue.

Related pages: [Replay Protection](Replay-Protection.md),
[Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md),
and [Padding & Timing Profiles](<Padding-&-Timing-Profiles.md>).
