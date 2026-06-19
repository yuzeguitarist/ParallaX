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

/// `initial_max_data` (0x04) — the connection-level receive window. This is a
/// FIXED const (NOT read back from quinn's blob at runtime): the spec ties it to
/// the connection-level window and 16 MiB matches CFNetwork/libquic. The only id
/// actually read back from quinn's `params.write()` output is
/// `initial_source_connection_id` (0x0f, the zero-length SCID); every other id
/// (this one included) carries a confirmed fixed value. quinn's real
/// `udp_transport_config` advertises the same number so the wire bytes EQUAL the
/// enforced behaviour (no advertised-vs-actual gap).
pub(crate) const SAFARI_TP_INITIAL_MAX_DATA: u64 = 16 * 1024 * 1024;

/// Per-stream flow-control window (0x05/0x06/0x07) — 2 MiB each, the confirmed
/// libquic value. Mirrored by quinn's `stream_receive_window`.
pub(crate) const SAFARI_TP_INITIAL_MAX_STREAM_DATA: u64 = 2 * 1024 * 1024;

/// `active_connection_id_limit` (0x0e). The confirmed Safari value is 64, but it
/// is unreachable in-tree: this parameter bounds how many of the PEER's connection
/// ids the client will track, and quinn-proto 0.11.14 sizes that remote-CID queue
/// to a fixed `CidQueue::LEN = 5` with NO public setter (cid_queue.rs:14), so
/// advertising 64 makes a peer issue `min(64, LOC_CID_COUNT=8)=8` connection IDs,
/// overflowing the 5-slot queue and killing every connection with
/// `CONNECTION_ID_LIMIT_ERROR`. We therefore advertise `5` = `CidQueue::LEN`: the
/// maximum quinn-safe value (a peer then issues `min(5, 8) = 5` CIDs, filling the
/// queue exactly). This is independent of the client's own (now zero-length)
/// source CID — that governs the ids the client ISSUES, not the ids it tracks, and
/// a zero-length-CID client issues none. quinn's own `params.write()` would emit
/// the default `2` (suppressed) for a zero-length-CID endpoint
/// (transport_parameters.rs:164), but ParallaX's hand-encoded blob substitutes `5`
/// independently of quinn's blob, and 5 matches the client's actual `rem_cids`
/// capacity, so there is no advertised-vs-actual gap. Reaching Safari's 64 needs
/// forking quinn-proto to raise `CidQueue::LEN`; see the gate. `5` narrows the gap
/// to 5-vs-64.
pub(crate) const SAFARI_TP_ACTIVE_CID_LIMIT: u64 = 5;

/// `initial_max_streams_uni` (0x09) — libquic value 8. Mirrored by quinn.
pub(crate) const SAFARI_TP_MAX_STREAMS_UNI: u64 = 8;

/// Apple's vendor/GREASE transport-parameter codepoint (value 0). Sorts LAST in
/// the ascending id order (it is the largest id), preserving the Apple/libquic
/// strict-ascending signature.
const SAFARI_TP_VENDOR_GREASE_ID: u64 = 0x17f7586d2cb571;

/// The Safari-26 H3 `0x39` transport-parameter id set, in STRICT ASCENDING order
/// (the Apple/libquic signature; see the H3 spec). `initial_source_connection_id`
/// (0x0f) is the genuine SCID quinn chose — now ZERO-LENGTH (see
/// `endpoint::client_endpoint_config`), read back from quinn's own blob; every
/// other id carries a CONFIRMED fixed value (see [`safari_tp_value_for_id`]). The
/// vendor/GREASE codepoint [`SAFARI_TP_VENDOR_GREASE_ID`] is emitted separately,
/// last, by the encoder.
///
/// Deliberately OMITS (all confirmed by full disassembly of Safari-26.4):
/// - `max_udp_payload_size` (0x03) — Safari does NOT send it.
/// - `max_datagram_frame_size` (0x20) — Safari does NOT send it for plain H3
///   (non-WebTransport); ParallaX's reachability probe no longer uses RFC-9221
///   datagrams (it uses a QUIC uni-stream round-trip; see `probe.rs`), and quinn's
///   datagram support is disabled in `udp_transport_config`, so there is nothing
///   to advertise.
/// - `ack_delay_exponent` (0x0a), `max_ack_delay` (0x0b),
///   `disable_active_migration` (0x0c) — the confirmed spec drops all three.
/// - the ids quinn would otherwise emit but Safari does not: `grease_quic_bit`
///   (0x2ab2), `min_ack_delay` (0xff04de1b), `grease_transport_parameter` (0x1b).
/// - server-only ids (`stateless_reset_token` 0x02, etc.) a client never sends.
const SAFARI_TP_IDS: [u64; 9] = [
    0x01, // max_idle_timeout = 0
    0x04, // initial_max_data = 16 MiB (runtime)
    0x05, // initial_max_stream_data_bidi_local = 2 MiB
    0x06, // initial_max_stream_data_bidi_remote = 2 MiB
    0x07, // initial_max_stream_data_uni = 2 MiB
    0x08, // initial_max_streams_bidi = 0
    0x09, // initial_max_streams_uni = 8
    0x0e, // active_connection_id_limit = 5 (SAFARI_TP_ACTIVE_CID_LIMIT; quinn CidQueue::LEN)
    0x0f, // initial_source_connection_id (REAL, server-validated, zero-length)
];

/// The CONFIRMED Safari-26 H3 value for each standard varint transport parameter.
/// Returns `None` for `initial_source_connection_id` (0x0f), which is not a varint
/// param — its value is the SCID pulled from quinn's blob (now zero-length).
fn safari_tp_value_for_id(id: u64) -> Option<u64> {
    match id {
        0x01 => Some(0),                          // max_idle_timeout (CFNetwork forces 0)
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
/// throughput at Safari's level — exceeding Safari is detectable). The one value
/// read back at runtime from quinn's own `params.write()` output is
/// `initial_source_connection_id` (0x0f) — that output is the only public
/// accessor, since quinn keeps every `TransportParameters` field `pub(crate)`. The
/// 0x0f value MUST equal the source CID quinn actually used in the Initial header
/// (RFC 9000 §7.3) or the server rejects the handshake with a
/// `TRANSPORT_PARAMETER_ERROR`; the client's zero-length CID generator
/// (`endpoint::client_endpoint_config`) makes quinn emit 0x0f with length 0 for
/// BOTH the header and this TP, so reading it back here preserves the invariant.
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
/// used to recover `initial_source_connection_id` (0x0f) — and emits the confirmed
/// Safari blob: [`SAFARI_TP_IDS`] with their confirmed values in ascending order,
/// then the vendor/GREASE codepoint last.
fn encode_safari_tp_from_pairs(quinn_values: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for &id in &SAFARI_TP_IDS {
        match safari_tp_value_for_id(id) {
            // Confirmed Safari value — emit varint-encoded.
            Some(value) => put_param(&mut out, id, value),
            // initial_source_connection_id (0x0f): the SCID quinn used in the
            // Initial header, read back from quinn's own blob (zero-length under
            // the client's zero-length CID generator). quinn always emits 0x0f for
            // a client — with length 0 here — so the lookup succeeds and the
            // advertised value equals the actual header SCID (RFC 9000 §7.3).
            None => match quinn_values.iter().find(|(qid, _)| *qid == id) {
                Some((_, value)) => put_param_bytes(&mut out, id, value),
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
        // The confirmed spec drops 0x0a/0x0b/0x0c from the QUIC blob, and (per full
        // disassembly) also omits 0x03 (max_udp_payload_size) and 0x20
        // (max_datagram_frame_size, plain H3 sends no datagrams).
        for dropped in [0x03, 0x0a, 0x0b, 0x0c, 0x20] {
            assert!(
                !SAFARI_TP_IDS.contains(&dropped),
                "id {dropped:#x} must be omitted per the confirmed spec"
            );
        }
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
        // 0x0f is read from quinn (zero-length under the zero-length CID generator);
        // supply it plus the ids Safari omits (0x03 and 0x20 included now) to prove
        // they are filtered out, and confirm the output ids are SAFARI_TP_IDS
        // followed by the vendor/GREASE codepoint, ascending.
        let quinn_pairs: Vec<(u64, Vec<u8>)> = vec![
            (0x0f, vec![]), // initial_source_connection_id (zero-length)
            // Ids that must never reach the output.
            (0x03, vec![0x44, 0xb0]), // max_udp_payload_size (now dropped)
            (0x20, vec![0x80, 0x00, 0xff, 0xff]), // max_datagram_frame_size (now dropped)
            (0x0a, vec![0x03]),       // ack_delay_exponent (dropped)
            (0x0b, vec![0x19]),       // max_ack_delay (dropped)
            (0x0c, vec![]),           // disable_active_migration (dropped)
            (0x2ab2, vec![]),         // grease_quic_bit
            (0xff04de1b, vec![0x40, 0xfa]), // min_ack_delay
            (0x1b, vec![0xca, 0xfe]), // grease_transport_parameter
            (0x02, vec![0u8; 16]),    // stateless_reset_token (server-only)
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
        // 0x0f is supplied zero-length (the zero-length CID generator's wire shape).
        let emitted = encode_safari_tp_from_pairs(&[(0x0f, vec![])]);
        let decoded = decode_emitted(&emitted);

        let val = |id: u64| -> u64 {
            let (_, bytes) = decoded.iter().find(|(qid, _)| *qid == id).unwrap();
            read_varint(bytes).unwrap().0
        };

        assert_eq!(val(0x01), 0, "max_idle_timeout = 0");
        assert!(
            !decoded.iter().any(|(id, _)| *id == 0x03),
            "max_udp_payload_size (0x03) must be ABSENT (Safari does not send it)"
        );
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
        // active_connection_id_limit is quinn's real advertised CidQueue::LEN = 5
        // (NOT Safari's 64, which quinn-proto 0.11.14 cannot honor; see
        // SAFARI_TP_ACTIVE_CID_LIMIT).
        assert_eq!(
            val(0x0e),
            5,
            "active_connection_id_limit = 5 (quinn CidQueue::LEN)"
        );

        // The vendor/GREASE TP carries value 0.
        assert_eq!(val(SAFARI_TP_VENDOR_GREASE_ID), 0, "vendor/GREASE TP = 0");

        // initial_source_connection_id is the SCID quinn used — zero-length here, so
        // it is present with an empty value (matching the Initial header SCID).
        let (_, src_cid) = decoded.iter().find(|(id, _)| *id == 0x0f).unwrap();
        assert!(
            src_cid.is_empty(),
            "initial_source_connection_id must be zero-length (matches header SCID)"
        );
        // max_datagram_frame_size (0x20) must be ABSENT (Safari sends no datagrams).
        assert!(
            !decoded.iter().any(|(id, _)| *id == 0x20),
            "max_datagram_frame_size (0x20) must be ABSENT"
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

    /// Walk a handshake-layer ClientHello, returning `(extension_type, body)`
    /// pairs in wire order. Minimal but strict: panics on any truncation so a
    /// malformed flight fails loudly instead of silently passing.
    fn parse_client_hello_extensions(hs: &[u8]) -> Vec<(u16, Vec<u8>)> {
        assert_eq!(
            hs[0], 0x01,
            "handshake flight must start with ClientHello (0x01)"
        );
        let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
        let body = &hs[4..4 + body_len];
        let mut p = 0usize;
        p += 2; // legacy_version
        p += 32; // random
        let sid_len = body[p] as usize;
        p += 1 + sid_len; // session_id
        let cs_len = ((body[p] as usize) << 8) | (body[p + 1] as usize);
        p += 2 + cs_len; // cipher_suites
        let comp_len = body[p] as usize;
        p += 1 + comp_len; // compression_methods
        let ext_total = ((body[p] as usize) << 8) | (body[p + 1] as usize);
        p += 2;
        let exts = &body[p..p + ext_total];
        let mut out = Vec::new();
        let mut q = 0usize;
        while q + 4 <= exts.len() {
            let typ = ((exts[q] as u16) << 8) | (exts[q + 1] as u16);
            let len = ((exts[q + 2] as usize) << 8) | (exts[q + 3] as usize);
            q += 4;
            out.push((typ, exts[q..q + len].to_vec()));
            q += len;
        }
        out
    }

    /// Hermetic (no-network) guard: drive the PRODUCTION `safari_h3_ch_profile`
    /// through the real vendored-rustls ClientHello assembly (the `apply_safari_profile`
    /// and `ClientExtensions::encode` path, exercised end-to-end by
    /// `rustls::quic::ClientConnection::new` then `write_hs`) and assert every
    /// `Managed` extension entry resolves to a PRESENT, NON-EMPTY extension at its
    /// expected ordinal. A `Managed(typ)` whose typed `ClientExtensions` field is
    /// left `None` by a future profile/provider refactor would `encode_one` to
    /// nothing and silently vanish from the wire; today only the networked
    /// `gfw_simulator` gate would catch that, whereas this test catches it in
    /// milliseconds.
    #[test]
    fn managed_extensions_all_present_in_emitted_h3_clienthello() {
        let mut grease_seed = [0u8; 5];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut grease_seed);
        let grease = crate::tls::safari_shape::GreaseSet::from_seed(grease_seed);
        let profile = crate::tls::safari_shape::safari_h3_ch_profile(grease);

        // The Managed entries in `safari_h3_ch_profile`, with their wire ordinals.
        // These are the ones backed by a typed `ClientExtensions` field and so the
        // only ones at risk of silently vanishing if that field is `None`.
        let managed_ordinals: [u16; 7] = [
            0x0000, // server_name
            0x000b, // ec_point_formats
            0x0010, // ALPN (h3)
            0x0005, // status_request
            0x0033, // key_share
            0x002d, // psk_key_exchange_modes
            0x0039, // quic_transport_parameters
        ];

        // Build the H3 rustls config exactly like `client_config`, minus the quinn
        // wrapper: TLS 1.3, resumption disabled (cold-start), the production
        // profile. The aws-lc-rs default provider is sufficient — extension
        // PRESENCE is independent of the camouflage kx-group pinning.
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::transport::udp::test_support::AcceptAnyServerCert,
        ))
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.resumption = rustls::client::Resumption::disabled();
        tls.safari_ch_profile = Some(Arc::new(profile));

        // Non-empty transport-parameters blob so the Managed(TransportParameters)
        // entry has a typed field to encode (production substitutes the ascending
        // 0x39 blob; any non-empty bytes prove the field is populated and emitted).
        let params = vec![0x0f, 0x00];
        let mut conn = rustls::quic::ClientConnection::new(
            Arc::new(tls),
            Version::V1,
            ServerName::try_from("example.com").unwrap().to_owned(),
            params,
        )
        .expect("build in-memory QUIC ClientConnection");

        let mut flight = Vec::new();
        conn.write_hs(&mut flight);
        assert!(
            !flight.is_empty(),
            "write_hs must emit the ClientHello flight"
        );

        let exts = parse_client_hello_extensions(&flight);
        for ord in managed_ordinals {
            let found = exts.iter().find(|(typ, _)| *typ == ord);
            let (_, body) = found.unwrap_or_else(|| {
                panic!(
                    "Managed extension {ord:#06x} vanished from the emitted ClientHello \
                     (its typed ClientExtensions field was None); wire ords: {:#06x?}",
                    exts.iter().map(|(t, _)| *t).collect::<Vec<_>>()
                )
            });
            assert!(
                !body.is_empty(),
                "Managed extension {ord:#06x} is present but EMPTY in the emitted ClientHello",
            );
        }
    }
}
