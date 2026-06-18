//! Safari-faithful QUIC TLS backend (ParallaX-owned quinn crypto Session).
//!
//! This is the S2 seam of the Safari-26 H3 ClientHello work. It supplies a
//! [`SafariQuicClientConfig`] (impl [`quinn::crypto::ClientConfig`]) that quinn
//! drives in place of [`quinn::crypto::rustls::QuicClientConfig`]. The ONE
//! behavioural difference from quinn's stock backend is in [`start_session`]:
//!
//! 1. The inner [`rustls::quic::ClientConnection`] is built from a
//!    [`rustls::ClientConfig`] that carries `safari_ch_profile = Some(..)`, so
//!    the vendored-rustls ClientHello assembly (S1) emits the Safari wire shape.
//! 2. The opaque QUIC transport-parameters blob handed to rustls is our own
//!    hand-encoded ascending `0x39` byte string ([`encode_safari_transport_params`])
//!    instead of quinn's `params.write()` output. rustls treats this blob as an
//!    opaque `Payload` (verified: `quic.rs` `ClientConnection::new` wraps it in
//!    `TransportParameters::Quic(Payload::new(params))`), so no quinn-proto fork
//!    is needed and quinn's TP shuffle / `min_ack_delay` / GREASE-TP are bypassed.
//!
//! Every other [`quinn::crypto::Session`] method is a near-verbatim delegation
//! copied from quinn-proto's own `crypto/rustls.rs` (the upstream `TlsSession`),
//! so the QUIC key schedule, retry validation, and RFC 5705 exporter all run
//! exactly as before.
//!
//! [`start_session`]: SafariQuicClientConfig::start_session

use std::{any::Any, sync::Arc};

use aws_lc_rs::aead;
use quinn::{
    crypto::{self, ExportKeyingMaterialError, KeyPair, Keys, UnsupportedVersion},
    ConnectError, ConnectionId, Side,
};
use quinn_proto::transport_parameters::TransportParameters;
use rustls::{
    pki_types::ServerName,
    quic::{Connection, KeyChange, Secrets, Suite, Version},
};

/// QUIC-compatible TLS client configuration that emits a Safari-26 H3
/// ClientHello.
///
/// Mirrors `quinn::crypto::rustls::QuicClientConfig`: it owns an
/// `Arc<rustls::ClientConfig>` (which must carry `safari_ch_profile = Some(..)`)
/// plus the pre-resolved initial cipher suite. Construct it from a fully-built
/// rustls config via [`SafariQuicClientConfig::new`].
pub struct SafariQuicClientConfig {
    inner: Arc<rustls::ClientConfig>,
    initial: Suite,
}

impl SafariQuicClientConfig {
    /// Wrap a rustls client config for the Safari QUIC carrier.
    ///
    /// The config MUST already have `safari_ch_profile = Some(..)`, TLS 1.3
    /// enabled, and a provider exposing `TLS13_AES_128_GCM_SHA256` (the QUIC v1
    /// Initial suite). Returns `None` if that initial suite is absent — the same
    /// failure mode as quinn's `NoInitialCipherSuite`.
    pub fn new(inner: Arc<rustls::ClientConfig>) -> Option<Self> {
        let initial = initial_suite_from_provider(inner.crypto_provider())?;
        Some(Self { inner, initial })
    }
}

impl crypto::ClientConfig for SafariQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let version = interpret_version(version)?;
        // THE substitution: hand-encoded ascending 0x39 blob, NOT
        // quinn's `params.write()`. rustls keeps it opaque.
        let tp_bytes = encode_safari_transport_params(params);
        Ok(Box::new(SafariTlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            inner: Connection::Client(
                rustls::quic::ClientConnection::new(
                    self.inner.clone(),
                    version,
                    ServerName::try_from(server_name)
                        .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?
                        .to_owned(),
                    tp_bytes,
                )
                // Only fails if TLS 1.3 / a QUIC-capable suite is missing, both
                // guaranteed present by `SafariQuicClientConfig::new`. Matches
                // quinn-proto's own `.unwrap()` at this seam.
                .expect("rustls QUIC ClientConnection: config validated in new()"),
            ),
            suite: self.initial,
        }))
    }
}

/// The live rustls QUIC session driven by quinn. The 11 delegating methods below
/// are copied from quinn-proto's `crypto/rustls.rs::TlsSession`.
struct SafariTlsSession {
    version: Version,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    inner: Connection,
    suite: Suite,
}

impl SafariTlsSession {
    fn side(&self) -> Side {
        match self.inner {
            Connection::Client(_) => Side::Client,
            Connection::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for SafariTlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, *dst_cid, side, &self.suite)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        // quinn-proto returns a `HandshakeData` struct here; that type is
        // private to quinn-proto, so this carrier exposes the negotiated ALPN
        // (the only field a client needs) instead. quinn never downcasts the
        // client's handshake_data, so the concrete type is not observed.
        Some(Box::new(self.inner.alpn_protocol().map(<[u8]>::to_vec)))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_certificates().map(|v| -> Box<dyn Any> {
            Box::new(
                v.iter()
                    .map(|c| c.clone().into_owned())
                    .collect::<Vec<rustls::pki_types::CertificateDer<'static>>>(),
            )
        })
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((Box::new(keys.header), Box::new(keys.packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self.inner {
            Connection::Client(ref session) => Some(session.is_early_data_accepted()),
            Connection::Server(_) => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, quinn_proto::TransportError> {
        self.inner.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.inner.alert() {
                quinn_proto::TransportError {
                    code: quinn_proto::TransportErrorCode::crypto(alert.into()),
                    frame: None,
                    reason: e.to_string(),
                }
            } else {
                // quinn-proto's `PROTOCOL_VIOLATION(reason)` helper is pub(crate);
                // construct the equivalent error from the public field + code.
                quinn_proto::TransportError {
                    code: quinn_proto::TransportErrorCode::PROTOCOL_VIOLATION,
                    frame: None,
                    reason: format!("TLS error: {e}"),
                }
            }
        })?;
        if !self.got_handshake_data {
            // Mirror quinn-proto's hack: it has no explicit "ALPN negotiated"
            // signal, so on a client it treats ALPN-present or
            // handshake-complete as the trigger.
            let have_server_name = match self.inner {
                Connection::Client(_) => false,
                Connection::Server(ref session) => session.server_name().is_some(),
            };
            if self.inner.alpn_protocol().is_some() || have_server_name || !self.is_handshaking() {
                self.got_handshake_data = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(
        &self,
    ) -> Result<Option<TransportParameters>, quinn_proto::TransportError> {
        match self.inner.quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => {
                match TransportParameters::read(self.side(), &mut std::io::Cursor::new(buf)) {
                    Ok(params) => Ok(Some(params)),
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let keys = match self.inner.write_hs(buf)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };
        Some(Keys {
            header: KeyPair {
                local: Box::new(keys.local.header),
                remote: Box::new(keys.remote.header),
            },
            packet: KeyPair {
                local: Box::new(keys.local.packet),
                remote: Box::new(keys.remote.packet),
            },
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        // MUST return Some on Data-space entry or quinn panics
        // (connection/mod.rs `.expect("handshake should be complete")`).
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();
        Some(KeyPair {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let (nonce, key) = match self.version {
            Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
            _ => return false,
        };

        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        // MANDATORY delegate: src/transport/udp/auth.rs (exporter-bound token)
        // and the loopback exporter round-trip test depend on this.
        self.inner
            .export_keying_material(output, label, Some(context))
            .map_err(|_| ExportKeyingMaterialError)?;
        Ok(())
    }
}

// QUIC v1 Retry integrity constants (RFC 9001 §5.8), copied verbatim from
// quinn-proto crypto/rustls.rs.
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Resolve the QUIC v1 Initial cipher suite (`TLS13_AES_128_GCM_SHA256`) from a
/// rustls provider. Mirrors quinn-proto's `initial_suite_from_provider`.
fn initial_suite_from_provider(provider: &Arc<rustls::crypto::CryptoProvider>) -> Option<Suite> {
    provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => suite.quic_suite(),
            _ => None,
        })
}

/// Build the Initial keys for `dst_cid`. Mirrors quinn-proto's `initial_keys`.
fn initial_keys(version: Version, dst_cid: ConnectionId, side: Side, suite: &Suite) -> Keys {
    let rustls_side = match side {
        Side::Client => rustls::Side::Client,
        Side::Server => rustls::Side::Server,
    };
    let keys = suite.keys(&dst_cid, rustls_side, version);
    Keys {
        header: KeyPair {
            local: Box::new(keys.local.header),
            remote: Box::new(keys.remote.header),
        },
        packet: KeyPair {
            local: Box::new(keys.local.packet),
            remote: Box::new(keys.remote.packet),
        },
    }
}

/// Map a QUIC version number to the rustls `Version`. Mirrors quinn-proto's
/// `interpret_version` but only accepts QUIC v1 (the carrier never negotiates
/// drafts or v2).
fn interpret_version(version: u32) -> Result<Version, UnsupportedVersion> {
    match version {
        0x0000_0001 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}

/// The Safari-26 H3 `0x39` transport-parameter id set, in STRICT ASCENDING
/// order (the Apple/libquic signature; see the H3 spec). The presence of `0x20`
/// (`max_datagram_frame_size`) at the end is part of that signature.
///
/// Deliberately OMITS the ids quinn would otherwise emit but Safari does not:
/// `grease_quic_bit` (0x2ab2), `min_ack_delay` (0xff04de1b), and the GREASE-TP
/// (`grease_transport_parameter`, 0x1b). Also omits server-only ids
/// (`stateless_reset_token` 0x02, `original_destination_connection_id` 0x00,
/// etc.) which a client never sends.
const SAFARI_TP_IDS: [u64; 14] = [
    0x01, // max_idle_timeout
    0x03, // max_udp_payload_size
    0x04, // initial_max_data
    0x05, // initial_max_stream_data_bidi_local
    0x06, // initial_max_stream_data_bidi_remote
    0x07, // initial_max_stream_data_uni
    0x08, // initial_max_streams_bidi
    0x09, // initial_max_streams_uni
    0x0a, // ack_delay_exponent
    0x0b, // max_ack_delay
    0x0c, // disable_active_migration (empty value)
    0x0e, // active_connection_id_limit
    0x0f, // initial_source_connection_id (REAL, server-validated)
    0x20, // max_datagram_frame_size (Apple/libquic signature)
];

/// Hand-encode the Safari-26 ascending `0x39` transport-parameters blob.
///
/// Emits exactly [`SAFARI_TP_IDS`] in strict ascending order, each entry as
/// `varint(id) || varint(len) || value`. The VALUES are NOT invented magic
/// numbers: every value that quinn already advertises is read back verbatim from
/// quinn's own `params.write()` output (the only public accessor — quinn keeps
/// every `TransportParameters` field `pub(crate)`), so the wire carries this
/// endpoint's REAL transport config. In particular `initial_source_connection_id`
/// (0x0f) MUST be the genuine source CID quinn chose, or the server rejects the
/// handshake with a `TRANSPORT_PARAMETER_ERROR`.
///
/// Two Safari ids are present that quinn omits for a client and therefore have no
/// value to copy:
/// - `disable_active_migration` (0x0c): an empty-valued flag. quinn only sets it
///   server-side (`server_config.is_some_and(..)`), so the client blob never
///   carries it; Safari always sends it, so we emit it with a zero-length value.
/// - `max_datagram_frame_size` (0x20): quinn only emits it when
///   `datagram_receive_buffer_size` is configured, which the carrier's
///   `udp_transport_config()` does not set. It is the Apple signature id, so it
///   MUST be present; absent a quinn value we fall back to a conservative
///   structure-only default.
///
/// NOTE (capture-gated): the fallback value for 0x20 (and the question of whether
/// Safari emits 0x0c/0x20 at all) is NOT yet calibrated to a real Safari-26 H3
/// capture; the gate asserts STRUCTURE (ascending ids, 0x20 present), never these
/// values. This blob is the DEFAULT QUIC client transport-param image as of S6,
/// but the QUIC plane stays off-by-default at the config level
/// (`[udp].enabled = false`), so it only reaches the wire once an operator turns
/// the fast-plane on; the values are calibrated against a capture before then.
fn encode_safari_transport_params(params: &TransportParameters) -> Vec<u8> {
    let mut quinn_blob = Vec::new();
    params.write(&mut quinn_blob);
    let quinn_values = parse_tp_blob(&quinn_blob);
    encode_safari_tp_from_pairs(&quinn_values)
}

/// Core of [`encode_safari_transport_params`], split out for unit testing because
/// quinn's [`TransportParameters`] cannot be constructed outside quinn-proto
/// (every field is `pub(crate)` and there is no public constructor). Takes the
/// `(id, value_bytes)` pairs already parsed from quinn's `params.write()` blob and
/// emits [`SAFARI_TP_IDS`] in strict ascending order, copying each value quinn
/// supplied and falling back to a structure-only default for the ids quinn omits
/// for a client (see [`encode_safari_transport_params`] doc).
fn encode_safari_tp_from_pairs(quinn_values: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for &id in &SAFARI_TP_IDS {
        match quinn_values.iter().find(|(qid, _)| *qid == id) {
            // Value derived from quinn's real transport config — copy verbatim.
            Some((_, value)) => put_param_bytes(&mut out, id, value),
            // Safari id absent from quinn's blob. quinn's writer OMITS a standard
            // varint param whose value equals its protocol default (verified:
            // transport_parameters.rs `if self.$name.0 != $default`), so the
            // genuine effective value is that default — emit it varint-encoded.
            // The two ids quinn never emits for a client get structure-only
            // fallbacks. An empty/raw value here would be rejected as malformed
            // (the reader requires `len == value.size()` for varint params).
            None => match quinn_default_for_id(id) {
                Some(default) => put_param(&mut out, id, default),
                // disable_active_migration (0x0c): empty-valued flag, never a
                // varint. max_datagram_frame_size (0x20): conservative default
                // (capture-gated), quinn only emits it with a datagram buffer.
                None if id == 0x0c => put_param_bytes(&mut out, id, &[]),
                None => put_param(&mut out, id, 65_535),
            },
        }
    }
    out
}

/// The protocol default value quinn uses for a standard varint transport
/// parameter (from quinn-proto's `apply_params!` table). Returns `None` for ids
/// that are not plain varint params (`disable_active_migration` 0x0c,
/// `max_datagram_frame_size` 0x20, `initial_source_connection_id` 0x0f). Used
/// only as a fallback when quinn omitted the id because its value matched this
/// default — so re-emitting the default carries the genuine effective value.
fn quinn_default_for_id(id: u64) -> Option<u64> {
    match id {
        0x01 => Some(0),      // max_idle_timeout
        0x03 => Some(65_527), // max_udp_payload_size
        0x04 => Some(0),      // initial_max_data
        0x05 => Some(0),      // initial_max_stream_data_bidi_local
        0x06 => Some(0),      // initial_max_stream_data_bidi_remote
        0x07 => Some(0),      // initial_max_stream_data_uni
        0x08 => Some(0),      // initial_max_streams_bidi
        0x09 => Some(0),      // initial_max_streams_uni
        0x0a => Some(3),      // ack_delay_exponent
        0x0b => Some(25),     // max_ack_delay
        0x0e => Some(2),      // active_connection_id_limit
        _ => None,
    }
}

/// QUIC varint encode (RFC 9000 §16) into `out`.
fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0x40 {
        out.push(v as u8);
    } else if v < 0x4000 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 0x4000_0000 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Append one transport parameter `id := value` (value varint-encoded).
fn put_param(out: &mut Vec<u8>, id: u64, value: u64) {
    let mut body = Vec::with_capacity(8);
    put_varint(&mut body, value);
    put_varint(out, id);
    put_varint(out, body.len() as u64);
    out.extend_from_slice(&body);
}

/// Append a transport parameter with a raw (already-bytes) value.
fn put_param_bytes(out: &mut Vec<u8>, id: u64, value: &[u8]) {
    put_varint(out, id);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// Parse a serialized transport-parameters blob into `(id, value_bytes)` pairs,
/// preserving the on-wire order. Stops at the first malformed entry (quinn's own
/// output is always well-formed, so this is a defensive bound only).
fn parse_tp_blob(blob: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut params = Vec::new();
    let mut i = 0usize;
    while i < blob.len() {
        let Some((id, n)) = read_varint(&blob[i..]) else {
            break;
        };
        i += n;
        let Some((len, m)) = read_varint(&blob[i..]) else {
            break;
        };
        i += m;
        let len = len as usize;
        if i + len > blob.len() {
            break;
        }
        params.push((id, blob[i..i + len].to_vec()));
        i += len;
    }
    params
}

/// Read one QUIC varint (RFC 9000 §16) from the front of `buf`, returning
/// `(value, bytes_consumed)` or `None` if `buf` is too short.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode the emitted `0x39` body back into `(id, value_bytes)` pairs using
    /// the same varint reader the production decode path uses.
    fn decode_emitted(blob: &[u8]) -> Vec<(u64, Vec<u8>)> {
        parse_tp_blob(blob)
    }

    #[test]
    fn safari_tp_id_table_is_strictly_ascending() {
        // The Apple/libquic signature is the strict-ascending id order itself.
        for w in SAFARI_TP_IDS.windows(2) {
            assert!(w[0] < w[1], "ids not strictly ascending at {w:?}");
        }
    }

    #[test]
    fn safari_tp_id_table_contains_0x20_and_omits_grease_and_min_ack_delay() {
        assert!(
            SAFARI_TP_IDS.contains(&0x20),
            "max_datagram_frame_size (0x20) must be present"
        );
        assert!(
            !SAFARI_TP_IDS.contains(&0x2ab2),
            "grease_quic_bit (0x2ab2) must be omitted"
        );
        assert!(
            !SAFARI_TP_IDS.contains(&0xff04de1b),
            "min_ack_delay (0xff04de1b) must be omitted"
        );
        assert!(
            !SAFARI_TP_IDS.contains(&0x1b),
            "grease_transport_parameter (0x1b) must be omitted"
        );
    }

    #[test]
    fn emitted_ids_are_exactly_the_safari_set_in_ascending_order() {
        // Feed a quinn-like blob that carries every Safari id (plus the ids
        // Safari omits, to prove they are filtered out) and confirm the output
        // ids match SAFARI_TP_IDS exactly, in order.
        let quinn_pairs: Vec<(u64, Vec<u8>)> = vec![
            (0x01, vec![0x67, 0x08]), // max_idle_timeout
            (0x03, vec![0x44, 0xb8]), // max_udp_payload_size
            (0x04, vec![0x80, 0x10, 0x00, 0x00]),
            (0x05, vec![0x80, 0x04, 0x00, 0x00]),
            (0x06, vec![0x80, 0x04, 0x00, 0x00]),
            (0x07, vec![0x80, 0x04, 0x00, 0x00]),
            (0x08, vec![0x01]),
            (0x09, vec![0x00]),
            (0x0a, vec![0x03]),
            (0x0b, vec![0x19]),
            (0x0e, vec![0x04]),
            (0x0f, vec![0xde, 0xad, 0xbe, 0xef]), // initial_source_connection_id
            // Ids Safari OMITS — must be filtered out of the output.
            (0x2ab2, vec![]),               // grease_quic_bit
            (0xff04de1b, vec![0x40, 0xfa]), // min_ack_delay
            (0x1b, vec![0xca, 0xfe]),       // grease_transport_parameter
            (0x02, vec![0u8; 16]),          // stateless_reset_token (server-only)
        ];

        let emitted = encode_safari_tp_from_pairs(&quinn_pairs);
        let decoded = decode_emitted(&emitted);
        let ids: Vec<u64> = decoded.iter().map(|(id, _)| *id).collect();

        assert_eq!(
            ids,
            SAFARI_TP_IDS.to_vec(),
            "emitted ids must equal the Safari set in strict ascending order"
        );
        // Strictly ascending is implied by equality with the (ascending) table,
        // but assert it directly as the make-or-break invariant.
        for w in ids.windows(2) {
            assert!(w[0] < w[1], "emitted ids not strictly ascending");
        }
    }

    #[test]
    fn values_present_in_quinn_blob_are_copied_verbatim() {
        let cid = vec![0xde, 0xad, 0xbe, 0xef];
        let quinn_pairs: Vec<(u64, Vec<u8>)> = vec![(0x01, vec![0x67, 0x08]), (0x0f, cid.clone())];
        let emitted = encode_safari_tp_from_pairs(&quinn_pairs);
        let decoded = decode_emitted(&emitted);

        let max_idle = decoded.iter().find(|(id, _)| *id == 0x01).unwrap();
        assert_eq!(
            max_idle.1,
            vec![0x67, 0x08],
            "max_idle_timeout copied verbatim"
        );

        let src_cid = decoded.iter().find(|(id, _)| *id == 0x0f).unwrap();
        assert_eq!(
            src_cid.1, cid,
            "initial_source_connection_id must be the real quinn value"
        );
    }

    #[test]
    fn client_omitted_ids_get_structure_only_fallbacks() {
        // quinn omits 0x0c (disable_active_migration, server-only) and 0x20
        // (max_datagram_frame_size, no datagram buffer) for this carrier's
        // client config. Both must still appear with structure-only values.
        let emitted = encode_safari_tp_from_pairs(&[]);
        let decoded = decode_emitted(&emitted);
        let ids: Vec<u64> = decoded.iter().map(|(id, _)| *id).collect();

        assert_eq!(
            ids,
            SAFARI_TP_IDS.to_vec(),
            "every Safari id must be present even when quinn supplies none"
        );

        let mig = decoded.iter().find(|(id, _)| *id == 0x0c).unwrap();
        assert!(
            mig.1.is_empty(),
            "disable_active_migration is an empty-valued flag"
        );

        let dgram = decoded.iter().find(|(id, _)| *id == 0x20).unwrap();
        assert!(
            !dgram.1.is_empty(),
            "max_datagram_frame_size carries a value (Apple signature)"
        );
    }

    #[test]
    fn varint_round_trips_across_size_classes() {
        for v in [0u64, 0x3f, 0x40, 0x3fff, 0x4000, 0x3fff_ffff, 0x4000_0000] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let (decoded, n) = read_varint(&buf).unwrap();
            assert_eq!(decoded, v, "varint value round-trip");
            assert_eq!(n, buf.len(), "varint consumed exactly its bytes");
        }
    }
}
