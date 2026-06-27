# QUIC Origin-Splice & Active-Probing Resistance

> Navigation: [Index](README.md) | [QUIC Fast Plane](QUIC-Fast-Plane.md) | [Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md) | [Replay Protection](Replay-Protection.md)

## Purpose

On the experimental UDP/QUIC fast plane, the server's `:443` carrier faces the
same active-probing threat the TCP server answers with fallback passthrough: a
prober that speaks QUIC to the port must see a *real origin*, not a ParallaX
tell. This page describes the QUIC analogue of the TCP fallback — a byte-for-byte
**origin splice** keyed on a covert authentication marker — and the bounded timing
residual it accepts.

The plane is off by default; this mechanism only runs when `[udp].enabled = true`.
For the TCP-side equivalent see
[Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md).

## The marker (`src/crypto/quic_marker.rs`)

A 32-byte authentication marker is hidden in the `ClientHello.random` field of the
client's QUIC Initial. Only a client holding **both** the PSK and the server's
static X25519 key can mint a valid one.

| Property | Value / source |
|---|---|
| Carrier layout | `tag[12] ‖ nonce[12] ‖ timestamp_be[8]` (`MARKER_LEN = 32`) |
| Tag | 96-bit HMAC-SHA256 over a domain-separated `(version, sni, dcid, nonce, timestamp)` input — binds the marker to this Initial's Destination Connection ID and SNI. |
| Key derivation | `HKDF-SHA256(salt = psk, ikm = X25519 shared secret)` expands a keystream key and an auth key under distinct info labels. PSK is the **salt** so a leaked server static key alone cannot derive either key. |
| Freshness | Accepted when `timestamp <= now + 5s` (clock skew) and `now <= timestamp + window`. `FUTURE_SKEW_SECS = 5`. |
| Constant work | `open()` always runs HKDF + HMAC + a constant-time tag comparison, with no early exit — so a forged or stale marker is not distinguishable by timing. |

`seal()` mints a marker (client); `open()` verifies and returns the
`(nonce, timestamp)` on success or `None` on any failure. A `None` result is never
surfaced as an error — it routes to the splice.

## Single-use replay guard (`src/transport/udp/marker_replay.rs`)

A valid marker captured off the wire and replayed within its freshness window must
**not** open a second local termination. A persistent, crash-safe replay cache
records each `(nonce, timestamp)` on first sighting; a later sighting of the same
marker is treated as a replay and spliced to the origin instead of terminated.

- Retention window `MARKER_WINDOW_SECS = 3600` (`MARKER_REPLAY_TTL = 3600s`),
  sized `>=` the marker freshness window so a marker stays detectable for as long
  as it is valid.
- The guard backs onto the same persistent `ReplayCache` machinery described in
  [Replay Protection](Replay-Protection.md).

## The terminate-vs-splice fork (`src/transport/udp/quic/`, `stable.rs`)

The process-wide `:443` carrier decides each connection from its **first Initial**:

1. A cheap pre-check rejects datagrams that are not a v1 long-header Initial padded
   to the RFC 9000 §14.1 minimum.
2. The Safari-26 ClientHello spans **two** Initials (PQ-inflated), so the marker is
   only visible once the first flight reassembles. The carrier buffers up to
   `MAX_PENDING_INITIALS = 4` Initials for one pending decision.
3. **Valid + fresh + first-sighting marker** → terminate locally; the accepted QUIC
   connection is routed back to its waiting session by Destination Connection ID.
4. **No/forged/stale/replayed marker** → splice the flow byte-for-byte to the real
   origin (`splice.rs`), so a prober sees the genuine origin's QUIC behavior.
5. A peer that sends a partial first flight then vanishes is reaped after
   `PENDING_IDLE = 2s`, freeing the held core.

## The bounded timing residual (documented, not closed)

A real QUIC origin ACKs an ack-eliciting Initial within `max_ack_delay` (~25ms). A
held first flight that never completes a ClientHello cannot be decided, and holding
it silently forever would be an active-probing distinguisher (the origin answers
while ParallaX stays silent). To bound this, an undecided held flight is spliced to the
origin after `PENDING_DECIDE_DELAY = 50ms`.

This converts an *infinite* silence into a *fixed* ~50ms one. A prober crafting one
decryptable, non-ClientHello-completing v1 Initial can still measure a bounded
~50ms + RTT offset versus the bare origin. This residual is **irreducible in the
buffer-decide design** — splicing datagram-0 before the marker is visible could never
terminate a marked client — and is an accepted, documented tradeoff. The 50ms value
is a deliberate reliability choice: a smaller value (toward `max_ack_delay`) tightens
the timing match but risks force-splicing a genuine client whose second Initial is
merely reordered under load (which then fails closed on the origin cert and self-heals
by redialing). Do not silently re-characterize this as "fully closed."

## Validation

- Marker seal/open, freshness, and constant-work paths: unit tests in
  `src/crypto/quic_marker.rs`.
- Replay-guard first-sighting / window behavior: tests in
  `src/transport/udp/marker_replay.rs`.
- Routing of a marked client to its registered session and splice of everything
  else: tests in `src/transport/udp/stable.rs` and `src/transport/udp/quic/`.

## Drift risks

The 50ms residual is intentional and load-bearing; do not delete or re-tune the
documented tradeoff without re-deriving it. If the marker layout, the two-secret
key derivation, the freshness window, or the pending-Initial bounds change, update
this page together with [Replay Protection](Replay-Protection.md),
[QUIC Fast Plane](QUIC-Fast-Plane.md), and the
[Documentation Metadata & Search Graph](Documentation-Metadata-Search-Graph.md).
