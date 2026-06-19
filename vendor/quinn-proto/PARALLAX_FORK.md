# ParallaX quinn-proto fork — tracking & re-apply

`vendor/quinn-proto` is a **surgical fork** of upstream quinn-proto, wired in via
`[patch.crates-io] quinn-proto = { path = "vendor/quinn-proto" }` in the workspace
`Cargo.toml`. Because the crate name and version are kept unchanged, the patch
redirects **every** quinn-proto consumer in the build — both ParallaX's direct
`quinn-proto = "=0.11.14"` dependency and `quinn 0.11.9`'s internal `proto`
dependency — to this copy. `cargo tree -i quinn-proto` MUST show exactly one
quinn-proto, resolved to this path. This file is the contract for keeping it in
sync.

## (a) Pin

- **quinn-proto `=0.11.14`** (exact). See `vendor/quinn-proto/Cargo.toml`
  `version` and the workspace `Cargo.lock`.
- Held in **lockstep with `rustls 0.23.40`**: quinn-proto's blanket
  `crypto::PacketKey` / `Quic{Client,Server}Config` impls are written against
  rustls 0.23.x's `rustls::quic` API. The crate name is kept as `quinn-proto`
  (not renamed) so those impls and `quinn 0.11.9`'s `proto` re-export still apply.
- Bumping **either** quinn-proto or rustls is a paired decision — see
  `vendor/rustls/PARALLAX_FORK.md`.

## (b) The fork delta — EXACTLY 1 modified line

Everything else under `vendor/quinn-proto/` is pristine upstream 0.11.14 and the
build must stay byte-for-byte equivalent in behaviour. The one change is:

| File | Change |
| --- | --- |
| `src/cid_queue.rs` | `CidQueue::LEN` raised from `5` to **`64`** (`pub(crate) const LEN: usize = 64;`). |

### Why, and why it is safe

- **Why.** `CidQueue` is the client's receive queue for the PEER's connection IDs;
  its `LEN` both sizes the ring buffer and, via `transport_parameters.rs`
  (`CidQueue::LEN as u32`), sets the advertised `active_connection_id_limit`.
  Safari-26's disassembly-confirmed value is **64**. With the upstream `LEN = 5`,
  ParallaX could only advertise 5 (advertising 64 with a 5-slot queue would let a
  peer issue enough `NEW_CONNECTION_ID` frames to overflow the queue and kill the
  connection with `CONNECTION_ID_LIMIT_ERROR`). Raising `LEN` to 64 makes the
  advertised limit equal the receive capacity, so ParallaX advertises Safari's
  true 64 with no advertised-vs-actual gap. The matching ParallaX-side constant is
  `SAFARI_TP_ACTIVE_CID_LIMIT` in `src/transport/udp/safari_crypto.rs`.
- **Why safe.** `CidQueue` is pure **modular ring-buffer arithmetic**
  (`buffer: [Option<CidData>; LEN]`, `cursor`, `offset`); there is **no**
  power-of-two or bitmask assumption, so any positive `LEN` is correct.
  `MAX_PENDING_RETIRED_CIDS = CidQueue::LEN * 10` (in `src/connection/mod.rs`)
  scales to 640, which is harmless. There is no second CID-count-sized fixed array
  anywhere in the crate. The crate's own `cid_queue.rs` / `tests/mod.rs` unit
  tests reference `CidQueue::LEN` symbolically, so they continue to pass at 64.

## (c) Re-apply procedure (when bumping quinn-proto or rustls)

1. Re-vendor **pristine** upstream quinn-proto at the new exact version into
   `vendor/quinn-proto/` (overwrite the whole directory; keep `Cargo.toml`
   `name = "quinn-proto"` and the exact version).
2. Re-apply the 1-line delta in (b): set `CidQueue::LEN = 64` in
   `src/cid_queue.rs`. Re-confirm the safety conditions still hold (still a pure
   modular ring buffer; no new CID-count-sized array; `MAX_PENDING_RETIRED_CIDS`
   still `LEN * 10`).
3. Confirm the pin lockstep in (a) and in `vendor/rustls/PARALLAX_FORK.md`: the
   quinn-proto and rustls minors must remain mutually compatible.
4. Refresh the workspace lock for the patched crate
   (`cargo update -p quinn-proto --offline`) so `Cargo.lock` records the path
   source, then **re-run the wire oracle and the loopback relay:**
   - `cargo test --locked --test gfw_simulator` — the wire-oracle gate, including
     the `active_connection_id_limit == 64` transport-param assertion in
     `udp_leg_clienthello_matches_safari26_h3_structure`.
   - `cargo test --locked` plus the ignored loopback relay
     (`-- --ignored --test-threads=1`, e.g.
     `socks_relay_succeeds_with_full_udp_negotiation`) — proves a zero-length-SCID
     client advertising 64 completes the handshake and relays end-to-end with the
     64-slot remote-CID queue.
   - `cargo tree -i quinn-proto` — confirm a single copy at this path.

## (d) Security-advisory tracking

- **Watch RUSTSEC for quinn-proto** (https://rustsec.org / the `quinn-proto`
  crate advisories). Because this is a path patch, `cargo audit` does **not** flag
  it by version, so any quinn-proto advisory applies to this copy silently.
- **On every quinn-proto or rustls bump, and on every CI dependency-audit run**
  (`.github/workflows/claude-dependency-audit.yml`, weekly `cargo audit`), check
  whether a quinn-proto advisory landed since `=0.11.14` and, if so, re-vendor +
  re-apply per (c) at the fixed version.
- Plain upstream quinn-proto patch releases (security or otherwise) within the
  pinned minor must be re-applied here — the path patch does NOT receive them
  automatically.
</content>
</invoke>
