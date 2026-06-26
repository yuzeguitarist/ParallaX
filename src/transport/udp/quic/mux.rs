//! Per-substream codec derivation for mux-over-QUIC.
//!
//! When the multiplexed (`max_concurrent_streams > 1`) relay runs over the QUIC
//! fast plane, each logical SOCKS stream gets its OWN QUIC bidirectional stream
//! (native QUIC multiplexing — no head-of-line blocking, in contrast to the
//! TCP-mux path which serializes every substream's [`MuxFrame`]s onto one record
//! stream). Each QUIC bidi carries an independent, ordered record byte-stream
//! inside HTTP/3 DATA frames (see [`crate::transport::leg`]), exactly like the
//! single-Connect QUIC relay — only there are now N of them concurrently.
//!
//! Two concurrent bidis CANNOT share a [`DataRecordCodec`]: the per-record nonce
//! is `nonce_base XOR sequence` with a per-codec monotonic `sequence` bound to one
//! ordered stream, so two streams sharing a base would reuse nonces (catastrophic
//! AEAD failure). This module derives an INDEPENDENT `(key, nonce_base)` pair per
//! substream from the session's `chain_secret`, keyed by the QUIC wire stream id
//! (RFC 9000 §2.1) — the one value both ends observe identically for a given bidi,
//! so they derive matching substream codecs with no extra negotiation. The
//! cross-substream non-reuse property is proven by the Kani harness in
//! `crypto::session` (`substream_info_is_injective_in_stream_id`).
//!
//! [`MuxFrame`]: crate::protocol::command::MuxFrame
//! [`DataRecordCodec`]: crate::protocol::data::DataRecordCodec

use crate::{
    config::TrafficConfig,
    crypto::session::{expand_substream_keys, AeadCodec, SessionError, SessionKeys},
    protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD, SERVER_TO_CLIENT_AAD},
    traffic::PaddingProfile,
};

/// The `(seal_to_server, open_from_server)` codec pair the CLIENT uses on one mux
/// substream, derived for the QUIC bidi `stream_id`. The directions mirror
/// [`crate::handshake::client::data_codecs`]: the client seals with the
/// client→server key and opens the server→client key.
pub(crate) fn client_substream_codecs(
    session_keys: &SessionKeys,
    traffic: TrafficConfig,
    stream_id: u64,
) -> Result<(DataRecordCodec, DataRecordCodec), SubstreamCodecError> {
    let keys = expand_substream_keys(session_keys, stream_id)?;
    let padding = PaddingProfile::from_config(traffic)?;
    let seal_to_server = DataRecordCodec::new(
        AeadCodec::new(keys.client_key, keys.client_nonce),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let open_from_server = DataRecordCodec::new(
        AeadCodec::new(keys.server_key, keys.server_nonce),
        padding,
        SERVER_TO_CLIENT_AAD,
    );
    seal_to_server.protect_secret_memory();
    open_from_server.protect_secret_memory();
    Ok((seal_to_server, open_from_server))
}

/// The `(client_open, server_seal)` codec pair the SERVER uses on one mux
/// substream, derived for the QUIC bidi `stream_id`. Mirrors the server's inline
/// construction in `run_authenticated_data_mode`: the server opens the
/// client→server key and seals with the server→client key. Returns
/// `(client_open, server_seal)` so call-sites read in the server's natural order.
pub(crate) fn server_substream_codecs(
    session_keys: &SessionKeys,
    traffic: TrafficConfig,
    stream_id: u64,
) -> Result<(DataRecordCodec, DataRecordCodec), SubstreamCodecError> {
    let keys = expand_substream_keys(session_keys, stream_id)?;
    let padding = PaddingProfile::from_config(traffic)?;
    let client_open = DataRecordCodec::new(
        AeadCodec::new(keys.client_key, keys.client_nonce),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let server_seal = DataRecordCodec::new(
        AeadCodec::new(keys.server_key, keys.server_nonce),
        padding,
        SERVER_TO_CLIENT_AAD,
    );
    client_open.protect_secret_memory();
    server_seal.protect_secret_memory();
    Ok((client_open, server_seal))
}

/// Errors deriving a per-substream codec: a key-derivation (HKDF) failure or an
/// invalid padding profile. Both are configuration/invariant failures, not
/// peer-controlled, and fail the substream closed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SubstreamCodecError {
    #[error("substream key derivation failed: {0}")]
    Derive(#[from] SessionError),
    #[error("invalid padding profile: {0}")]
    Padding(#[from] crate::traffic::TrafficError),
}
