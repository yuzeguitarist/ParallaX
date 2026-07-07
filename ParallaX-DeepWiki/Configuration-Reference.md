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
| `[transport]` | table | no | TCP socket-buffer overrides for relay sockets. Off by default (kernel autotuning); see the `[transport]` section below. |
| `[udp]` | table | no | Experimental UDP/QUIC fast plane. Off by default; see the `[udp]` section below. |
| `[client]` | table | client mode | Local SOCKS and remote server settings. |
| `[server]` | table | server mode | Listener, fallback, target, replay, and server secrets. |

## `[crypto]`

| Field | Required | Validation |
|---|---:|---|
| `psk` | yes | CSPRNG-generated base64 string that decodes to at least 32 bytes, **or** a secret reference (see below). Obvious low-entropy PSKs hard-fail in server mode and warn in client/check mode. |

The same PSK must appear in both generated configs. It is part of ClientHello
authentication and the hybrid rekey sandwich input.

## Secret sources (`psk`, `private_key`, `identity_secret_key`)

The three long-lived secret fields are **public-vs-secret aware**: each accepts
either an inline base64 string (back-compat) or an indirection table so the
config file itself is not a bearer credential. `Config::load` resolves every
source to its base64 bytes once, up front, before validation; the rest of the
runtime is unchanged regardless of where the bytes came from.

| Form | Example | Notes |
|---|---|---|
| Inline | `psk = "base64=="` | Legacy. The config file IS a credential — `plx check` warns. |
| File | `psk = { file = "parallax.secrets.toml#psk" }` | Reads a `#key` entry from a 0600 TOML sidecar (the `plx init` default), or the whole file when no `#fragment` is given. Relative paths resolve next to the config. Owner-only `0600` is enforced. |
| Env | `psk = { env = "PARALLAX_PSK" }` | Reads the base64 from an environment variable — composes with systemd `LoadCredential=` / container secrets. |
| Sealed | `psk = { sealed = "parallax.secrets.enc#psk" }` | Machine-bound: decrypted at load with the host keyfile (`$PARALLAX_HOST_KEY_FILE` or `/var/lib/parallax/host.key`). Written by `plx seal`. |

Exactly one of `file` / `env` / `sealed` may be set per reference. Only these
three fields are secret; every other config field is a public parameter. See the
[SECURITY.md threat model](../SECURITY.md#secret-handling--config-threat-model)
for what sealing protects against.

## `[traffic]`

| Field | Default | Validation |
|---|---:|---|
| `min_padding` | `0` | `max_padding >= min_padding` |
| `max_padding` | `0` | Must leave room for a TLS ApplicationData payload. |
| `min_delay_ms` | `0` | `max_delay_ms >= min_delay_ms` |
| `max_delay_ms` | `0` | `0` disables timing jitter. |
| `cover_min_interval_ms` | `0` | `cover_max_interval_ms >= cover_min_interval_ms`; when cover is enabled, must be at least `50`. |
| `cover_max_interval_ms` | `0` | `0` disables cover traffic; enabling cover also requires variable profile padding (`max_padding > min_padding`). |
| `max_concurrent_streams` | `4` | Must be at least `1`; values above `1` enable authenticated session multiplexing. |

Generated configs set every traffic-shaping value to `0` except
`max_concurrent_streams = 4`. This keeps the default path speed-first while
allowing several browser-originated SOCKS streams to share one authenticated
ParallaX session.

## `[transport]`

Optional TCP socket-buffer overrides for the relay sockets, shared by client and
server. Both fields are `Option<u32>` (bytes) and default unset, which keeps
kernel autotuning — the safe default that preserves full Safari parity. Setting a
value disables autotuning for that socket and is clamped by the OS maximum
(`net.core.wmem_max` / `net.core.rmem_max` on Linux, `kern.ipc.maxsockbuf` on
macOS), so only raise it once that maximum has been raised — otherwise the kernel
may clamp it *below* what autotuning would have reached (a logged warning surfaces
such a clamp). See [Deployment](Deployment.md) for the `net.core.*mem_max`
prerequisite.

| Field | Default | Meaning |
|---|---:|---|
| `tcp_send_buffer_bytes` | unset | Explicit `SO_SNDBUF` for relay sockets. Wire-invisible. Sized to the path bandwidth-delay product, it lifts the client→server upload window on high-RTT links where autotuning under-provisions it. |
| `tcp_recv_buffer_bytes` | unset | Explicit `SO_RCVBUF` for relay sockets. **NOT wire-invisible** — it affects the advertised TCP window, so it is applied only post-connect/accept (never on the camouflage SYN) and a fixed value flattens the window curve vs Safari's autotuning. Prefer it on the server data-sink side; leave it unset on the client to keep full browser parity. |

## `[client]`

| Field | Required | Validation / meaning |
|---|---:|---|
| `listen` | yes | Socket address for local SOCKS5. Must bind to loopback because SOCKS5 has no authentication. |
| `server_addr` | yes | Remote ParallaX server as `host:port`; IPv6 literals must be bracketed. |
| `sni` | yes | SNI sent in the camouflage TLS handshake. |
| `server_public_key` | yes | Base64 X25519 server public key, exactly 32 bytes. |
| `server_identity_public_key` | yes | Base64 ML-DSA-87 server identity public key. |
| `accept_language` | no | Optional ASCII, single-line H2/H3 camouflage `accept-language` header override. Defaults to Safari-like `en-US,en;q=0.9`. |

## `[server]`

| Field | Required | Validation / meaning |
|---|---:|---|
| `listen` | yes | Server bind address, usually `0.0.0.0:443`. |
| `fallback_addr` | yes | Real TLS origin used for unauthenticated/probe traffic. |
| `data_target` | no | Fixed upstream target for authenticated data. If omitted, the client CONNECT command chooses the target. |
| `private_key` | yes | Base64 X25519 server secret key, exactly 32 bytes — or a secret reference (see *Secret sources*). |
| `identity_secret_key` | yes | Base64 ML-DSA-87 server identity secret key — or a secret reference (see *Secret sources*). |
| `replay_cache_path` | no | Defaults to `/var/lib/parallax/parallax-replay.cache`; relative paths resolve relative to the config file. |
| `authorized_sni` | yes | Non-empty SNI allowlist for authenticated ClientHellos. Matching is case-insensitive. |
| `strict_tls13` | no | Defaults to `true`; fallback ServerHello must negotiate TLS 1.3 when enabled. |
| `replay_cache_capacity` | no | Default `49152`. Bounded capacity of the persistent replay cache; pairs with the freshness window to fail closed when full. |
| `max_concurrent_per_source_v4` | no | Default `256`. Concurrency cap (not a rate limit) per IPv4 /32 source; high so shared/CGNAT addresses are not throttled. |
| `max_concurrent_per_source_v6` | no | Default `256`. Concurrency cap per IPv6 source prefix; separate from v4 because a prefix aggregates many endpoints. |
| `source_ipv6_prefix_len` | no | Default `64`. Prefix length used to group IPv6 sources for the per-source cap. |
| `first_record_wait_floor_ms` | no | Default `8000`. Floor for the client-facing first-record wait (a measurement-resistant timeout). |
| `first_record_wait_jitter_ms` | no | Default `7000`. Upward jitter added to the first-record wait floor. |
| `fallback_idle_floor_ms` | no | Default `600000` (10 min; min enforced `5000`). Per-gap idle backstop for the camouflage relay; resets on every byte, so it only fires on a fully silent connection. |
| `fallback_idle_jitter_ms` | no | Default `60000`. Upward jitter on the idle backstop. |
| `tcp_congestion` | no | Optional Linux TCP congestion-control algorithm for relay sockets (e.g. `"bbr"`, `"cubic"`) to match the camouflage origin's CDN; unset keeps the kernel default, and an unavailable algorithm is logged and ignored. |

## `[udp]`

The experimental UDP/QUIC fast plane. It is **off by default**; with
`enabled = false` the runtime is byte-identical to TCP-only, so this whole table
can be omitted (generated configs do not include it). Enabling requires matched
binaries on both ends. Only five knobs are LIVE today; the rest are parsed and
validated for forward-compatibility but **not yet honored** (setting one logs a
startup warning so an inert knob is not mistaken for an active one).

| Field | Default | Status | Meaning |
|---|---:|---|---|
| `enabled` | `false` | LIVE | Turn the UDP/QUIC fast plane on (both ends). |
| `probe_timeout_ms` | `1000` | LIVE | Happy-Eyeballs UDP probe timeout floor before committing to TCP-only. The effective budget is RTT-aware (`max(this, 6× observed control-plane RTT)`). Must be ≥ 1 when enabled. |
| `max_udp_payload_bytes` | unset (`2048`) | LIVE | Largest UDP datagram the QUIC carrier reads in one recv (and the origin-splice relay buffer ceiling). Unset keeps the conservative `2048` default (~1.6× the largest datagram ParallaX emits). Oversized datagrams are truncated-and-dropped (truncation fails AEAD), so this caps per-datagram memory. Must be in `1200..=65527` — the floor is the RFC 9000 §14.1 Initial minimum so a legal Initial is always receivable. |
| `send_buffer_bytes` | unset | LIVE | Explicit `SO_SNDBUF` for the UDP carrier socket. `None`/`0` keeps kernel autotuning (byte-identical to today). Clamped by the OS maximum (`net.core.wmem_max` / `kern.ipc.maxsockbuf`), so raise that first; a clamp below autotuning is logged. Sized to the path BDP, it lifts the upload window on high-RTT links. **Wire-invisible** — a UDP socket has no advertised window. |
| `recv_buffer_bytes` | unset | LIVE | Explicit `SO_RCVBUF` for the UDP carrier socket. `None`/`0` keeps autotuning. Same OS-max clamp caveat (`net.core.rmem_max` / `kern.ipc.maxsockbuf`). A larger recv buffer lets the single-threaded driver absorb inbound bursts without socket-layer drops; independent of `max_udp_payload_bytes`. **Wire-invisible.** |
| `cc` | `"bbr"` | RESERVED | Congestion controller: `"bbr"` (safe default) or `"brutal"` (Hysteria-style, opt-in, detectable). Phase 3. |
| `brutal_up_mbps` | `0` | RESERVED | Declared uplink Mbps for Brutal; `0` means unset. Required with `brutal_down_mbps` when `cc = "brutal"` unless `ignore_client_bandwidth` is set. |
| `brutal_down_mbps` | `0` | RESERVED | Declared downlink Mbps for Brutal; `0` means unset. |
| `ignore_client_bandwidth` | `false` | RESERVED | Let the server override the client-declared Brutal bandwidth. |
| `fec_profile` | `"adaptive"` | RESERVED | Forward error correction: `"off"`, `"adaptive"` (loss×RTT-gated), or `"rs"` (Reed-Solomon). Phase 3. |
| `port_hop` | `false` | RESERVED | UDP port hopping. Dropped Phase-2 camouflage (not planned); inert no-op kept only so existing configs still parse. |
| `masque_front` | unset | RESERVED | SNI/host to front the masquerading HTTP/3 face on; unset keeps the TCP `sni`. Dropped Phase-2 camouflage (not planned); inert no-op. |
| `ech` | `false` | RESERVED | Encrypted ClientHello for the QUIC face. Dropped Phase-2 camouflage (not planned); inert no-op. |

Validation only runs when `enabled = true`: `probe_timeout_ms` must be non-zero,
`max_udp_payload_bytes` (if set) must fall in `1200..=65527`, `cc = "brutal"`
requires the two Brutal bandwidths (unless `ignore_client_bandwidth`), and
`masque_front` (if set) must be non-empty. The
QUIC client already emits a Safari-26 H3-shaped ClientHello by default, but the
fast plane stays off by default and is not yet a production-ready operator mode,
so enabling it is for throughput experimentation, not censorship-resistant
production use.

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
max_concurrent_streams = 4

[server]
listen = "0.0.0.0:443"
fallback_addr = "cloudflare.com:443"
private_key = "base64-x25519-secret"
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
max_concurrent_streams = 4

[client]
listen = "127.0.0.1:1080"
server_addr = "203.0.113.10:443"
sni = "cloudflare.com"
server_public_key = "base64-x25519-public"
server_identity_public_key = "base64-mldsa-public"
```

## Security-sensitive loader behavior

- Config files must be owned by the current Unix user.
- Group/world permission bits are rejected.
- The server replay-cache path is normalized before use.
- `plx check` can fall back to structure-only validation when a host key,
  sidecar, or environment-backed secret is unavailable; long-lived
  client/server/speed runs still require all secrets to resolve.
- Secret strings are passed through best-effort memory hardening before the
  long-lived client/server/speed paths continue.

Related pages: [Replay Protection](Replay-Protection.md),
[Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md),
and [Padding & Timing Profiles](<Padding-&-Timing-Profiles.md>).
