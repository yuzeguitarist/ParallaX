# ParallaX rustls fork — tracking & re-apply

`vendor/rustls` is a **surgical fork** of upstream rustls, wired in via
`[patch.crates-io] rustls = { path = "vendor/rustls" }` in the workspace
`Cargo.toml`. The patch redirects **every** rustls consumer in the build (the TCP
camouflage splice, `rustls-native-certs`, and the server `QuicServerConfig`) to
this copy, so this fork sits on the security-critical TLS path and is **off
upstream's security-maintenance track**. This file is the contract for keeping it
in sync.

## (a) Pin

- **rustls `=0.23.40`** (exact). See `vendor/rustls/Cargo.toml` `version` and the
  workspace `Cargo.lock`.
- Held in **lockstep with `quinn-proto 0.11.14`**: quinn-proto's blanket
  `crypto::PacketKey` / `Quic{Client,Server}Config` impls are written against
  rustls 0.23.x's `rustls::quic` API, so the rustls minor MUST match what
  quinn-proto 0.11.14 depends on. The crate name is kept as `rustls` (not
  renamed) precisely so those blanket impls still apply.
- Bumping **either** rustls or quinn-proto is a paired decision — never bump one
  past the other's supported rustls range.

## (b) The fork delta — EXACTLY 6 modified files + 1 surgical behaviour

Everything else under `vendor/rustls/` is pristine upstream 0.23.40 and the build
must stay byte-identical with the profile **off**. The one behavioural change is:
the Safari-26 H3 ClientHello wire shape is assembled onto the typed
`ClientHelloPayload` **only when** `ClientConfig.safari_ch_profile == Some(..)`;
when it is `None` (every non-Safari consumer: TCP splice, native-certs, server),
the code path is upstream-identical.

| File | Change |
| --- | --- |
| `src/client/safari.rs` | **NEW.** Defines `SafariChProfile` / `SafariExt` (the caller-supplied cipher list, extension order incl. raw GREASE/legacy extensions, ALPN override). |
| `src/client/hs.rs` | In `emit_client_hello_for_retry`: `if let Some(profile) = config.safari_ch_profile { apply_safari_profile(..) }` (gated; ~hs.rs:389) + the `apply_safari_profile` helper that writes the plan onto `chp_payload` **before** it is frozen/hashed into the transcript. |
| `src/client/client_conn.rs` | Adds the `pub safari_ch_profile: Option<Arc<SafariChProfile>>` field to `ClientConfig`. |
| `src/client/builder.rs` | Initializes `safari_ch_profile: None` in the config builder (so the default build is upstream-identical). |
| `src/lib.rs` | `pub mod safari;` + `pub use safari::{SafariChProfile, SafariExt};`. |
| `src/msgs/handshake.rs` | Adds the `pub(crate) safari_plan: Option<Vec<SafariExt>>` field to `ClientExtensions` and the encode hook that honors the plan's order / force-last (PSK) / raw-extension passthrough. |

> Note: `src/msgs/message_test.rs` contains an upstream test named
> `can_read_safari_client_hello_...` — that is **pristine upstream**, NOT part of
> this fork. The 6 files above are the complete delta.

The make-or-break invariant: the profile rewrites the wire shape *before* the
ClientHello is hashed into the handshake transcript, so the emitted bytes and the
Finished-MAC transcript stay consistent. Cold-start ONLY — the profile never
injects `pre_shared_key` / `early_data`; the consuming config disables resumption.

## (c) Re-apply procedure (when bumping rustls or quinn-proto)

1. Re-vendor **pristine** upstream rustls at the new exact version into
   `vendor/rustls/` (overwrite; keep `Cargo.toml` `name = "rustls"`).
2. Re-apply the 6-file delta in (b). For each file, port the `safari_ch_profile`
   field, the `safari_plan` extension field + encode hook, the `apply_safari_profile`
   gate in `hs.rs`, and the `safari` module export. The gate MUST stay
   `Some(profile)`-conditional so the `None` path is upstream-identical.
3. Confirm the pin lockstep in (a): the new rustls minor must match the
   quinn-proto version's required rustls range.
4. **Re-run the wire oracle and the transcript-consistency loopback:**
   - `cargo test --locked --test gfw_simulator` — the wire-oracle gate
     (`udp_leg_clienthello_matches_safari26_h3_structure` and the transport-param
     value assertions, incl. the `max_idle_timeout` (0x01) omission assertion
     (omit != value=0)).
   - `cargo test --locked` — including the loopback QUIC handshake tests in
     `src/transport/udp/mod.rs` (`quic_loopback_*`,
     `quic_transport_config_bounds_streams_to_single_bidi_relay`,
     `quic_client_completes_handshake_with_compressed_certificate`) which prove the
     rewritten ClientHello still produces a consistent transcript end-to-end.
   - `cargo test --locked --test gfw_simulator` plus `cargo build --locked` with
     the profile path exercised confirms the `None` (non-Safari) path is unchanged.

## (d) Security-advisory tracking

- **Watch RUSTSEC for rustls** (https://rustsec.org / the `rustls` crate
  advisories). Because the fork sits on the TLS data path, any rustls advisory
  applies to this copy even though `cargo audit` may not flag a `[patch.crates-io]`
  path dependency by version.
- **On every rustls or quinn-proto bump, and on every CI dependency-audit run**
  (`.github/workflows/claude-dependency-audit.yml`, weekly `cargo audit`), check
  whether a rustls advisory landed since `=0.23.40` and, if so, re-vendor +
  re-apply per (c) at the fixed version.
- Plain upstream rustls patch releases (security or otherwise) within the pinned
  minor must be re-applied here — the path patch does NOT receive them
  automatically.
</content>
</invoke>
