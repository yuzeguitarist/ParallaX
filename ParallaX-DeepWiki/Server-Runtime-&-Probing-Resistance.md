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
  ├─ ClientHello does not offer TLS 1.3 ───► fallback passthrough
  ├─ SNI not in authorized_sni ────────────► fallback passthrough
  ├─ auth tag invalid ─────────────────────► fallback passthrough
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

The fallback forward limit (`PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT`, 64 records)
prevents a chatty fallback origin from outrunning the client's residual
camouflage budget (16 records) before the key exchange arrives.

## Target selection

Authenticated data can go to either:

- `server.data_target`, if configured; or
- the host/port from the encrypted client CONNECT command.

Client-selected targets are resolved through public-address checks before
connecting. Port `0`, malformed authorities, and missing target information are
rejected.

## Replay protection

Replay is not a first-record check. The authenticated handshake is committed to a
persistent `ReplayCache` only after the client proves the data stream (the
post-PQ-rekey commit point). A replayed (or stale / cache-full) handshake is
gracefully drained and FIN-closed at that point — it is not relayed to the
fallback origin. The default path is:

```text
/var/lib/parallax/parallax-replay.cache
```

See [Replay Protection](Replay-Protection.md).

## Probing resistance and anti-DoS

Beyond uniform fallback, the server runtime carries several measurement- and
resource-resistance mechanisms. Defaults are configurable under `[server]`; see
[Configuration Reference](Configuration-Reference.md).

- **First-record wait floor + jitter.** The client-facing wait for the first
  record has a floor (`first_record_wait_floor_ms`, default 8000) plus upward
  jitter (`first_record_wait_jitter_ms`, default 7000), so the timeout a prober
  observes is not a fixed, fingerprintable constant.
- **Silent-peer origin pre-dial.** The give-up wait above is client-facing, but it
  must not delay the camouflage origin's own idle clock (which drives the close a
  prober times). Once a connection has stayed silent for
  `FIRST_RECORD_PREDIAL_DELAY` (150 ms, a fixed constant), the server dials the
  fallback origin concurrently with the still-pending read, and the later splice
  adopts that connection instead of dialing a second one. A silent probe's close
  then lands at about 150 ms plus the origin's idle time rather than 8–15 s plus it.
  A pre-dial failure is swallowed (the splice dials at give-up, as before); a client
  that sends its ClientHello promptly never triggers it.
- **Per-source concurrency caps.** A source limiter
  (`src/handshake/source_limit.rs`) bounds concurrent connections per IPv4 /32
  and per IPv6 prefix (`source_ipv6_prefix_len`, default /64), each capped at
  `max_concurrent_per_source_v4` / `_v6` (default 256). A coarser /48 rollup
  ceiling (a small multiple of the per-/64 cap) bounds /64 rotation within one
  routed allocation. These are concurrency caps, not rate limits.
- **Cap-shed fallback.** When the global connection cap is reached, the server
  does not emit a bare FIN; it relays the excess connection to the fallback
  origin under a small independent budget (64 concurrent), so an over-cap probe
  still sees ordinary origin behavior. It uses the same pre-dialing first-record
  reader and the same idle distribution as a healthy splice (the fallback idle
  backstop below), so the cap-shed close is not separable from a healthy one; on a
  read error it releases its speculative origin dial like the authenticated path.
  Past the 64-relay budget it degrades to a graceful FIN. The per-source limiter
  checks the cap before creating a tracking entry, so rejected sources leave no
  permanent state.
- **Fallback idle backstop.** Camouflage relays use a per-gap idle backstop
  (`fallback_idle_floor_ms`, default 600000 = 10 min, min enforced 5000; plus
  `fallback_idle_jitter_ms`, default 60000). The timer resets on every byte in
  either direction, so it only fires on a fully silent connection rather than
  capping a live session.
- **Bounded replay cache.** The persistent replay cache has a bounded capacity
  (`replay_cache_capacity`, default 49152) sized against the handshake freshness
  window; when it is full the server fails closed (`CacheFull`) rather than
  accepting a possibly replayed handshake.

## Mux download scheduling

On the TCP-plane mux, each substream queues its target-to-client frames into its own
bounded channel (an equal share of a 1024-frame per-connection bound, clamped to
4..16 frames), and the single writer serves the queues round-robin, one frame per
substream per turn. A client `RESET` (or a shed) purges that substream's queued
frames first, so a cancelled download stops draining at once. While batched writes
wait 10 ms or more for socket space (the client link is the bottleneck), batches are
capped at 64 KiB for the next second so a newly active substream waits behind at
most one small batch; faster links keep the full 64-frame batches that let the
crypto pool fan out. Connect, dial and target writes run on a per-substream task,
never on the shared reader, so one slow target cannot block the carrier. Before this
change one shared FIFO let a bulk stream delay every other stream's response by
`backlog / link_rate`.

## Operational logs

The runtime emits structured `tracing` breadcrumbs for handshake and relay
milestones. Set `RUST_LOG=parallax=info` or a more targeted filter in the
systemd environment when debugging intermittent handshake transitions.

Related pages: [Protocol Commands & Data Records](Protocol-Commands-&-Data-Records.md),
[Session Key Derivation & AEAD Transport](Session-Key-Derivation-&-AEAD-Transport.md),
and [Systemd Service & Security Hardening](Systemd-Service-&-Security-Hardening.md).
