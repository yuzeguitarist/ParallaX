# Replay Protection

> Navigation: [Index](README.md) | [ClientHello Auth](<ClientHello-Authentication-(PSK-+-X25519).md>) | [Configuration](Configuration-Reference.md)

## Purpose

Replay protection prevents a captured authenticated ClientHello from being
resent later to distinguish or access the ParallaX server.

## Current scope

Replay protection applies to the TCP/TLS product handshake. The experimental
UDP/QUIC fast plane has separate replay guards: the QUIC origin-splice marker is
single-use via `src/transport/udp/marker_replay.rs`, and 0-RTT tickets are
single-use via `src/transport/udp/zero_rtt.rs`.

## Replay cache

`src/crypto/replay.rs` stores replay entries derived from authenticated
handshake material. The server wraps the cache in `Arc<Mutex<ReplayCache>>` so
concurrent accepted connections share the same state. The current journal header
is `parallax-replay-cache-v4`; v3 journals are legacy read/upgrade inputs.

Generated server configs use:

```toml
replay_cache_path = "/var/lib/parallax/parallax-replay.cache"
```

If a relative path is configured, `src/config.rs` resolves it relative to the
config file before validation completes.

The effective default freshness window is about 720 seconds: the server's
10-minute fallback idle floor plus the base 120-second replay window, with a
5-second future-skew allowance.

## Load/create behavior

The server loads or creates the cache during startup. Deployment installs the
server config under `/etc/parallax/parallax.toml` and gives the service a
writeable `/var/lib/parallax` directory for the replay cache.

## Failure behavior

Unlike an authentication failure — a bad or absent PSK, which is routed to
fallback passthrough at the first-record decision layer — a replay is only
detected after the authenticated handshake completes and the client proves the
data stream (the post-PQ-rekey commit point). A rejected replay (or a stale
timestamp / full cache) does not receive a distinct proxy error and is not
relayed to the fallback origin: the server gracefully drains and FIN-closes the
connection.

## Related invariants

- The replay cache path must be writable by the service.
- The config file itself must remain secret (`0600`, current user owner on
  Unix).
- The replay cache is part of the server's probe-resistance story, not only an
  access-control mechanism.

Related pages: [Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md),
[Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md), and
[Deployment](Deployment.md).
