# Server Runtime & Probing Resistance

> Navigation: [Index](README.md) | [Client Runtime](Client-Runtime-&-SOCKS5-Proxy.md) | [TLS Camouflage](TLS-Camouflage-Layer.md)

## Scope

The server runtime is implemented primarily in `src/handshake/server.rs`. It
listens on `server.listen`, classifies the first client bytes, forwards
unauthenticated traffic to `server.fallback_addr`, and upgrades authenticated
connections into ParallaX data sessions.

## First-record decision tree

```text
client TCP accepted
  │
  ├─ timeout / partial prefix ─────────────► fallback passthrough
  ├─ not a complete TLS ClientHello ───────► fallback passthrough
  ├─ SNI not in authorized_sni ────────────► fallback passthrough
  ├─ auth tag invalid ─────────────────────► fallback passthrough
  ├─ replay cache rejects ClientHello ─────► fallback passthrough
  └─ authenticated ────────────────────────► ParallaX handshake
```

The important property is uniform external behavior: the server does not close
or emit a proxy-specific error just because a scanner failed authentication.

## Fallback passthrough

Fallback mode connects to `server.fallback_addr`, writes the bytes already
received from the client, and relays in both directions with an idle timeout.

If `strict_tls13 = true`, authenticated mode also validates that the fallback
origin's `ServerHello` selected TLS 1.3 before continuing the camouflage flow.

## Authenticated pre-data mode

After ClientHello authentication succeeds, the server keeps the fallback TLS
flow alive long enough to preserve a browser-like transition. During this phase:

1. Client camouflage records may be forwarded to the fallback origin.
2. A bounded number of fallback records may be forwarded back before PQ rekey.
3. The client sends `PqRekeyRequest`.
4. The server encapsulates ML-KEM-1024, computes the hybrid chain secret, and
   sends `ServerKeyExchange`.
5. The server signs an ML-DSA-87 identity proof bound to the transcript and the
   PQ rekey exchange.
6. Identity proof chunks are sealed and sent as data-plane records.

The fallback forward limit prevents a chatty fallback origin from outrunning
the client's residual camouflage budget before the key exchange arrives.

## Target selection

Authenticated data can go to either:

- `server.data_target`, if configured; or
- the host/port from the encrypted client CONNECT command.

Client-selected targets are resolved through public-address checks before
connecting. Port `0`, malformed authorities, and missing target information are
rejected.

## Replay protection

The authenticated first record is checked against a persistent
`ReplayCache`. The default path is:

```text
/var/lib/parallax/parallax-replay.cache
```

See [Replay Protection](Replay-Protection.md).

## Operational logs

The runtime emits structured `tracing` breadcrumbs for handshake and relay
milestones. Set `RUST_LOG=parallax=info` or a more targeted filter in the
systemd environment when debugging intermittent handshake transitions.

Related pages: [Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md),
[Session Key Derivation & AEAD Transport](Session-Key-Derivation-&-AEAD-Transport.md),
and [Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md).
