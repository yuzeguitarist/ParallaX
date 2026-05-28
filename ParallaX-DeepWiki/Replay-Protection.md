# Replay Protection

> Navigation: [Index](README.md) | [ClientHello Auth](<ClientHello-Authentication-(PSK-+-X25519).md>) | [Configuration](Configuration-Reference.md)

## Purpose

Replay protection prevents a captured authenticated ClientHello from being
resent later to distinguish or access the ParallaX server.

## Current scope

Replay protection applies to the TCP/TLS product handshake. There is no current
product QUIC runtime using a separate QUIC auth frame.

## Replay cache

`src/crypto/replay.rs` stores replay entries derived from authenticated
handshake material. The server wraps the cache in `Arc<Mutex<ReplayCache>>` so
concurrent accepted connections share the same state.

Generated server configs use:

```toml
replay_cache_path = "/var/lib/parallax/parallax-replay.cache"
```

If a relative path is configured, `src/config.rs` resolves it relative to the
config file before validation completes.

## Load/create behavior

The server loads or creates the cache during startup. Deployment installs the
server config under `/etc/parallax/parallax.toml` and gives the service a
writeable `/var/lib/parallax` directory for the replay cache.

## Failure behavior

Replay rejection is treated like authentication failure at the first-record
decision layer: the connection is sent to fallback passthrough instead of
receiving a distinct proxy error.

## Related invariants

- The replay cache path must be writable by the service.
- The config file itself must remain secret (`0600`, current user owner on
  Unix).
- The replay cache is part of the server's probe-resistance story, not only an
  access-control mechanism.

Related pages: [Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md),
[Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md), and
[Deployment](Deployment.md).
