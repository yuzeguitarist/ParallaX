# QUIC Fast Plane (Experimental UDP Transport)

> Navigation: [Index](README.md) | [Transport Layer](Transport-Layer.md) | [QUIC Origin-Splice & Active-Probing Resistance](QUIC-Origin-Splice-&-Active-Probing-Resistance.md) | [HTTP/3 Fingerprint Façade](HTTP-3-Fingerprint-Facade.md) | [GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>)

## Status

The UDP/QUIC fast plane is **experimental and off by default**. With
`[udp].enabled = false` (the default) every code path stays byte-identical to
TCP-only and this whole subsystem is inert. Enabling it requires `enabled = true`
on **both** ends with matched binaries. The QUIC client already emits a Safari-26
H3-shaped ClientHello by default, but the plane is **not yet a production-ready,
censorship-resistant operator mode** — it is for throughput experimentation. There
is no `--quic` CLI flag; the plane is configured only through the `[udp]` table in
[Configuration Reference](Configuration-Reference.md).

This page documents how the plane is built. For why TCP remains the default and
only fingerprint-hardened transport, see [Transport Layer](Transport-Layer.md).

## What it is

A clean-room, `quinn`-free QUIC stack (`src/transport/udp/quic/`) built directly
from RFC 9000 (transport), RFC 9001 (TLS), and RFC 9002 (loss recovery), carrying
single-Connect relays over a reliable bidirectional QUIC stream, mux-over-QUIC
substreams as separate H3-shaped request bidis, and `plx speed`'s optional QUIC
transport run. The vendored `quinn` + `quinn-proto` fork it replaced is gone from
the dependency tree (Phase 2 of de-vendoring); each module carries its own RFC
round-trip / KAT tests.

When the plane is active, the relay is wrapped in the same `Leg` abstraction
(`src/transport/leg.rs`) that unifies TCP and QUIC stream carriers, so the rest of
the relay machinery does not care which transport it rides on.

## Module map

| Area | Code | Responsibility |
|---|---|---|
| Endpoint / HTTP-3 face | `src/transport/udp/endpoint.rs`, `src/transport/udp/h3.rs` | QUIC connection, the H3 control + QPACK encoder uni streams, and request bidis for the reachability probe, single-Connect relay, mux substreams, and speed run. |
| Happy-Eyeballs probe | `src/transport/udp/probe.rs` | Decide UDP reachability before committing, with a TCP-only fallback on timeout. |
| Stable-:443 carrier | `src/transport/udp/stable.rs` | Process-wide shared endpoint that marker-terminates authenticated clients, splices everything else to the origin, and routes accepted connections back to their session by DCID. |
| Exporter-bound auth | `src/transport/udp/auth.rs` | RFC 5705 keying-material export backing the UDP auth token. |
| 0-RTT resumption | `src/transport/udp/zero_rtt.rs` | Persistent single-use anti-replay guard backing `tls::quic::ZeroRttGuard`. |
| Origin-splice marker replay | `src/transport/udp/marker_replay.rs` | Persistent single-use guard for the origin-splice auth marker. |
| QUIC transport core | `src/transport/udp/quic/` | Hand-written packet/frame codec, packet-number spaces, loss recovery, congestion control, stream mux, and the splice path. |
| QUIC-side TLS 1.3 | `src/tls/quic/` | Hand-written QUIC TLS handshake, key schedule, transcript, ClientHello, and certificate verification. |

## QUIC transport core (`src/transport/udp/quic/`)

| Module | Owns |
|---|---|
| `mod.rs`, `conn.rs`, `endpoint.rs` | Connection state machine and endpoint driver. |
| `packet.rs`, `frame.rs`, `varint.rs` | Long/short header packets, frame encode/decode, QUIC varints. |
| `spaces.rs` | Initial / Handshake / Application packet-number spaces and ACK tracking. |
| `recovery.rs` | RFC 9002 loss detection, PTO, and retransmission. |
| `congestion.rs` | BBR-style congestion control (the safe default). |
| `mux.rs` | Multiplexes the relay over native QUIC streams (mux-over-QUIC). |
| `splice.rs` | Origin-splice decision and verbatim relay of non-ParallaX Initials. |
| `transport_params.rs` | QUIC transport parameters (the Safari-shaped set). |
| `netsim.rs` | Deterministic loss/reorder network simulator used by transport tests. |

### Congestion control

The live default is **BBR-style** congestion control (`congestion.rs`), pacing
output rather than relying on a loss-triggered window collapse. The
config-selectable `"brutal"` controller (Hysteria-style fixed-rate) and the FEC
profiles are **RESERVED** (Phase 3) — parsed and validated but not yet honored;
see the `[udp]` table in [Configuration Reference](Configuration-Reference.md).

### Mux over QUIC

When the mux relay is active, it is multiplexed over native QUIC streams rather
than tunneled inside a single stream. Business connections open as bidirectional
QUIC streams carrying H3 request HEADERS, so the stream-open pattern stays
H3-shaped rather than exposing a ParallaX-specific framing.

## Connection lifecycle

1. **Probe (client).** The client runs a Happy-Eyeballs UDP reachability probe
   (`probe.rs`). The probe budget is RTT-aware: the effective timeout is
   `max(probe_timeout_ms, 6 × observed control-plane RTT)`, so a slow link is not
   prematurely abandoned. If UDP is unreachable within the budget, the client
   commits to TCP-only and the QUIC plane is never used for that session.
2. **Carrier (server).** A process-wide shared QUIC endpoint listens on the
   stable `:443` carrier (`stable.rs`). The very first Initial decides the
   connection's fate: an authenticated ParallaX client (valid + fresh origin-splice
   marker in `ClientHello.random`) is terminated locally; everything else is
   spliced byte-for-byte to the real origin. See
   [QUIC Origin-Splice & Active-Probing Resistance](QUIC-Origin-Splice-&-Active-Probing-Resistance.md).
3. **Handshake.** The hand-written QUIC TLS 1.3 engine (`src/tls/quic/`) completes
   the handshake, emitting a Safari-26 H3-shaped ClientHello and the H3 SETTINGS /
   control-stream flight. Accepted connections are routed back to their waiting
   session by Destination Connection ID.
4. **Auth.** The client proves itself with an exporter-bound UDP auth token
   (`auth.rs`) derived from RFC 5705 keying material, so the token is bound to that
   specific TLS session and cannot be transplanted.
5. **Relay / evidence.** Single-Connect relays, mux-over-QUIC substreams, and
   `plx speed`'s optional QUIC run are carried over reliable QUIC streams behind
   the `Leg` abstraction, unified with the TCP path.

## Resumption (0-RTT)

The plane supports session resumption with single-use 0-RTT. A persistent
anti-replay guard (`zero_rtt.rs`, backing `tls::quic::ZeroRttGuard`) ensures a
0-RTT early-data acceptance happens at most once per ticket: a fresh resumption is
accepted, a replayed one falls back to a 1-RTT handshake instead of replaying early
data. The session ticket's PSK is zeroized after use.

## Configuration

All knobs live in `[udp]` (see [Configuration Reference](Configuration-Reference.md)).
LIVE today: `enabled`, `probe_timeout_ms`, `max_udp_payload_bytes`,
`send_buffer_bytes`, `recv_buffer_bytes`. The
congestion-control (`cc`, `brutal_*`, `fec_profile`) and dropped Phase-2 camouflage
knobs (`port_hop`, `masque_front`, `ech`) are RESERVED no-ops that log a startup
warning if set.

`max_udp_payload_bytes` caps the datagram size the carrier reads in one recv (and
the origin-splice relay buffer); unset keeps the conservative `2048` default, and
the value must stay in `1200..=65527` so a legal RFC 9000 §14.1 Initial is always
receivable.

## Validation

- QUIC transport invariants and codec round-trips: unit tests under
  `src/transport/udp/quic/` (each module carries its own RFC KAT / round-trip
  tests).
- Deterministic loss/reorder behavior: the `netsim.rs` simulator.
- Origin-splice and marker behavior:
  [QUIC Origin-Splice & Active-Probing Resistance](QUIC-Origin-Splice-&-Active-Probing-Resistance.md).
- Adversary / detector context:
  [GFW Simulator & QUIC Research](<GFW-Simulator-&-QUIC-Research.md>).

## Drift risks

This subsystem is under active development and pre-production gated. Treat the
"experimental, off by default, not production-ready" framing as load-bearing: do
not document the plane as a production transport. When the `[udp]` LIVE/RESERVED
split, the congestion controller, or the Safari-26 ClientHello shape changes,
update this page together with [Configuration Reference](Configuration-Reference.md),
[Transport Layer](Transport-Layer.md), and the
[Documentation Metadata & Search Graph](Documentation-Metadata-Search-Graph.md).
