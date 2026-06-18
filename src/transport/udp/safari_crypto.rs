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

/// `initial_max_data` (0x04) — the SINGLE runtime-read transport-param value in
/// the Safari-26 H3 blob. The confirmed spec ties it to the connection-level
/// receive window; 16 MiB matches CFNetwork/libquic. quinn's real
/// `udp_transport_config` advertises the same number so the wire bytes EQUAL the
/// enforced behaviour (no advertised-vs-actual gap).
pub(crate) const SAFARI_TP_INITIAL_MAX_DATA: u64 = 16 * 1024 * 1024;

/// Per-stream flow-control window (0x05/0x06/0x07) — 2 MiB each, the confirmed
/// libquic value. Mirrored by quinn's `stream_receive_window`.
pub(crate) const SAFARI_TP_INITIAL_MAX_STREAM_DATA: u64 = 2 * 1024 * 1024;

/// `active_connection_id_limit` (0x0e). The confirmed Safari value is 64, but
/// quinn-proto 0.11.14 hardcodes its remote-CID queue to `CidQueue::LEN = 5` and
/// its own `active_connection_id_limit` to 2 with NO public setter, so advertising
/// 64 makes a stock-quinn peer issue `min(64, LOC_CID_COUNT=8)=8` connection IDs,
/// overflowing the 5-slot queue and killing every connection with
/// `CONNECTION_ID_LIMIT_ERROR`. We therefore advertise quinn's REAL enforced value
/// (2) — advertised==actual, the relay works — and accept the divergence from
/// Safari's 64 (it cannot be reconciled without forking quinn-proto; see the gate).
pub(crate) const SAFARI_TP_ACTIVE_CID_LIMIT: u64 = 2;

/// `initial_max_streams_uni` (0x09) — libquic value 8. Mirrored by quinn.
pub(crate) const SAFARI_TP_MAX_STREAMS_UNI: u64 = 8;

/// `max_udp_payload_size` (0x03) — libquic floor 1200. Mirrored by quinn.
pub(crate) const SAFARI_TP_MAX_UDP_PAYLOAD: u64 = 1200;

/// Apple's vendor/GREASE transport-parameter codepoint (value 0). Sorts LAST in
/// the ascending id order (it is the largest id), preserving the Apple/libquic
/// strict-ascending signature.
const SAFARI_TP_VENDOR_GREASE_ID: u64 = 0x17f7586d2cb571;

/// The Safari-26 H3 `0x39` transport-parameter id set, in STRICT ASCENDING order
/// (the Apple/libquic signature; see the H3 spec). `initial_source_connection_id`
/// (0x0f) is the genuine SCID quinn chose (dynamic, server-validated) and
/// `max_datagram_frame_size` (0x20) is quinn's real datagram value; every other id
/// carries a CONFIRMED fixed value (see [`safari_tp_value_for_id`]). The
/// vendor/GREASE codepoint [`SAFARI_TP_VENDOR_GREASE_ID`] is emitted separately,
/// last, by the encoder.
///
/// Deliberately OMITS:
/// - `ack_delay_exponent` (0x0a), `max_ack_delay` (0x0b),
///   `disable_active_migration` (0x0c) — the confirmed spec drops all three.
/// - the ids quinn would otherwise emit but Safari does not: `grease_quic_bit`
///   (0x2ab2), `min_ack_delay` (0xff04de1b), `grease_transport_parameter` (0x1b).
/// - server-only ids (`stateless_reset_token` 0x02, etc.) a client never sends.
///
/// KEEPS `max_datagram_frame_size` (0x20): the confirmed spec sends it only when
/// datagrams are used, and ParallaX's reachability probe (RFC 9221) DOES use QUIC
/// datagrams (quinn enables `datagram_receive_buffer_size` by default), so omitting
/// it would make the peer report `UnsupportedByPeer` and break the probe.
const SAFARI_TP_IDS: [u64; 11] = [
    0x01, // max_idle_timeout = 0
    0x03, // max_udp_payload_size = 1200
    0x04, // initial_max_data = 16 MiB (runtime)
    0x05, // initial_max_stream_data_bidi_local = 2 MiB
    0x06, // initial_max_stream_data_bidi_remote = 2 MiB
    0x07, // initial_max_stream_data_uni = 2 MiB
    0x08, // initial_max_streams_bidi = 0
    0x09, // initial_max_streams_uni = 8
    0x0e, // active_connection_id_limit (quinn's 2; see SAFARI_TP_ACTIVE_CID_LIMIT)
    0x0f, // initial_source_connection_id (REAL, server-validated)
    0x20, // max_datagram_frame_size (datagrams used by the probe; quinn's value)
];

/// The CONFIRMED Safari-26 H3 value for each standard varint transport parameter.
/// Returns `None` for `initial_source_connection_id` (0x0f), which is not a varint
/// param — its value is the dynamic SCID pulled from quinn's blob.
fn safari_tp_value_for_id(id: u64) -> Option<u64> {
    match id {
        0x01 => Some(0),                          // max_idle_timeout (CFNetwork forces 0)
        0x03 => Some(SAFARI_TP_MAX_UDP_PAYLOAD),  // max_udp_payload_size
        0x04 => Some(SAFARI_TP_INITIAL_MAX_DATA), // initial_max_data (runtime)
        0x05 => Some(SAFARI_TP_INITIAL_MAX_STREAM_DATA), // bidi_local
        0x06 => Some(SAFARI_TP_INITIAL_MAX_STREAM_DATA), // bidi_remote
        0x07 => Some(SAFARI_TP_INITIAL_MAX_STREAM_DATA), // uni
        0x08 => Some(0),                          // initial_max_streams_bidi (CFNetwork)
        0x09 => Some(SAFARI_TP_MAX_STREAMS_UNI),  // initial_max_streams_uni (libquic)
        0x0e => Some(SAFARI_TP_ACTIVE_CID_LIMIT), // active_connection_id_limit
        _ => None,
    }
}

/// Hand-encode the Safari-26 ascending `0x39` transport-parameters blob.
///
/// Emits [`SAFARI_TP_IDS`] in strict ascending order, each entry as
/// `varint(id) || varint(len) || value`, then appends the vendor/GREASE codepoint
/// [`SAFARI_TP_VENDOR_GREASE_ID`] (value 0) last. The standard params carry the
/// CONFIRMED Safari values from [`safari_tp_value_for_id`] (these CAP QUIC
/// throughput at Safari's level — exceeding Safari is detectable). The ONLY value
/// read at runtime is `initial_source_connection_id` (0x0f): it MUST be the genuine
/// source CID quinn chose, read back from quinn's own `params.write()` output (the
/// only public accessor — quinn keeps every `TransportParameters` field
/// `pub(crate)`), or the server rejects the handshake with a
/// `TRANSPORT_PARAMETER_ERROR`.
///
/// quinn's real `udp_transport_config` is aligned to the SAME advertised values
/// (see `mod.rs`), so the wire bytes EQUAL quinn's enforced behaviour.
fn encode_safari_transport_params(params: &TransportParameters) -> Vec<u8> {
    let mut quinn_blob = Vec::new();
    params.write(&mut quinn_blob);
    let quinn_values = parse_tp_blob(&quinn_blob);
    encode_safari_tp_from_pairs(&quinn_values)
}

/// Core of [`encode_safari_transport_params`], split out for unit testing because
/// quinn's [`TransportParameters`] cannot be constructed outside quinn-proto
/// (every field is `pub(crate)` and there is no public constructor). Takes the
/// `(id, value_bytes)` pairs already parsed from quinn's `params.write()` blob —
/// used to recover the dynamic `initial_source_connection_id` (0x0f) and the real
/// `max_datagram_frame_size` (0x20) — and emits the confirmed Safari blob:
/// [`SAFARI_TP_IDS`] with their confirmed values in ascending order, then the
/// vendor/GREASE codepoint last.
fn encode_safari_tp_from_pairs(quinn_values: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for &id in &SAFARI_TP_IDS {
        match safari_tp_value_for_id(id) {
            // Confirmed Safari value — emit varint-encoded.
            Some(value) => put_param(&mut out, id, value),
            // Dynamic/quinn-derived values, read back from quinn's own blob:
            // - initial_source_connection_id (0x0f): the REAL SCID quinn chose; an
            //   empty/missing value would fail the server's TP validation, but
            //   quinn always emits 0x0f for a client, so the lookup succeeds.
            // - max_datagram_frame_size (0x20): quinn's effective datagram value
            //   (datagrams are enabled by default); fall back to quinn's clamped
            //   default 65535 so the probe never sees datagrams reported disabled.
            None => match quinn_values.iter().find(|(qid, _)| *qid == id) {
                Some((_, value)) => put_param_bytes(&mut out, id, value),
                None if id == 0x20 => put_param(&mut out, id, 65_535),
                None => put_param_bytes(&mut out, id, &[]),
            },
        }
    }
    // Vendor/GREASE TP (value 0), last in ascending order.
    put_param(&mut out, SAFARI_TP_VENDOR_GREASE_ID, 0);
    out
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
        // The vendor/GREASE id (emitted last by the encoder) is larger than every
        // entry in the table, so the whole on-wire sequence stays ascending.
        for w in SAFARI_TP_IDS.windows(2) {
            assert!(w[0] < w[1], "ids not strictly ascending at {w:?}");
        }
        assert!(
            *SAFARI_TP_IDS.last().unwrap() < SAFARI_TP_VENDOR_GREASE_ID,
            "vendor/GREASE id must sort after every standard id"
        );
    }

    #[test]
    fn safari_tp_id_table_omits_dropped_ids_and_grease_quic_bit() {
        // The confirmed spec drops 0x0a/0x0b/0x0c from the QUIC blob. 0x20
        // (max_datagram_frame_size) is KEPT because the probe uses datagrams.
        for dropped in [0x0a, 0x0b, 0x0c] {
            assert!(
                !SAFARI_TP_IDS.contains(&dropped),
                "id {dropped:#x} must be omitted per the confirmed spec"
            );
        }
        assert!(
            SAFARI_TP_IDS.contains(&0x20),
            "max_datagram_frame_size (0x20) must be kept (probe uses datagrams)"
        );
        // quinn-only ids must never appear.
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
    fn emitted_ids_are_the_safari_set_plus_vendor_grease_ascending() {
        // 0x0f and 0x20 are read from quinn; supply them (plus the ids Safari omits,
        // to prove they are filtered out) and confirm the output ids are
        // SAFARI_TP_IDS followed by the vendor/GREASE codepoint, ascending.
        let quinn_pairs: Vec<(u64, Vec<u8>)> = vec![
            (0x0f, vec![0xde, 0xad, 0xbe, 0xef]), // initial_source_connection_id
            (0x20, vec![0x80, 0x00, 0xff, 0xff]), // max_datagram_frame_size (kept)
            // Ids that must never reach the output.
            (0x0a, vec![0x03]),             // ack_delay_exponent (dropped)
            (0x0b, vec![0x19]),             // max_ack_delay (dropped)
            (0x0c, vec![]),                 // disable_active_migration (dropped)
            (0x2ab2, vec![]),               // grease_quic_bit
            (0xff04de1b, vec![0x40, 0xfa]), // min_ack_delay
            (0x1b, vec![0xca, 0xfe]),       // grease_transport_parameter
            (0x02, vec![0u8; 16]),          // stateless_reset_token (server-only)
        ];

        let emitted = encode_safari_tp_from_pairs(&quinn_pairs);
        let decoded = decode_emitted(&emitted);
        let ids: Vec<u64> = decoded.iter().map(|(id, _)| *id).collect();

        let mut expected = SAFARI_TP_IDS.to_vec();
        expected.push(SAFARI_TP_VENDOR_GREASE_ID);
        assert_eq!(
            ids, expected,
            "emitted ids must be the Safari set + vendor/GREASE, ascending"
        );
        for w in ids.windows(2) {
            assert!(w[0] < w[1], "emitted ids not strictly ascending");
        }
    }

    #[test]
    fn emitted_values_are_the_confirmed_safari_values() {
        // Read each emitted varint value back and compare to the confirmed spec.
        let cid = vec![0xde, 0xad, 0xbe, 0xef];
        let dgram = vec![0x80, 0x00, 0xff, 0xff]; // varint 65535
        let emitted = encode_safari_tp_from_pairs(&[(0x0f, cid.clone()), (0x20, dgram)]);
        let decoded = decode_emitted(&emitted);

        let val = |id: u64| -> u64 {
            let (_, bytes) = decoded.iter().find(|(qid, _)| *qid == id).unwrap();
            read_varint(bytes).unwrap().0
        };

        assert_eq!(val(0x01), 0, "max_idle_timeout = 0");
        assert_eq!(val(0x03), 1200, "max_udp_payload_size = 1200");
        assert_eq!(
            val(0x04),
            SAFARI_TP_INITIAL_MAX_DATA,
            "initial_max_data = 16 MiB"
        );
        assert_eq!(val(0x05), 2 * 1024 * 1024, "stream_data_bidi_local = 2 MiB");
        assert_eq!(
            val(0x06),
            2 * 1024 * 1024,
            "stream_data_bidi_remote = 2 MiB"
        );
        assert_eq!(val(0x07), 2 * 1024 * 1024, "stream_data_uni = 2 MiB");
        assert_eq!(val(0x08), 0, "max_streams_bidi = 0");
        assert_eq!(val(0x09), 8, "max_streams_uni = 8");
        // active_connection_id_limit is quinn's enforced 2 (NOT Safari's 64, which
        // quinn-proto 0.11.14 cannot honor; see SAFARI_TP_ACTIVE_CID_LIMIT).
        assert_eq!(val(0x0e), 2, "active_connection_id_limit = 2 (quinn limit)");

        // The vendor/GREASE TP carries value 0.
        assert_eq!(val(SAFARI_TP_VENDOR_GREASE_ID), 0, "vendor/GREASE TP = 0");

        // initial_source_connection_id is the REAL dynamic SCID quinn chose.
        let (_, src_cid) = decoded.iter().find(|(id, _)| *id == 0x0f).unwrap();
        assert_eq!(
            src_cid, &cid,
            "initial_source_connection_id must be the real quinn SCID"
        );
        // max_datagram_frame_size carries quinn's real value (datagrams enabled).
        assert_eq!(val(0x20), 65_535, "max_datagram_frame_size = quinn value");
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
