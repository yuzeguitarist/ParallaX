//! quinn adapter for the hand-written QUIC TLS engine (Phase 1 of de-vendoring).
//!
//! This is the ONLY quinn-aware layer of the QUIC client TLS path. It implements
//! quinn-proto's `crypto::{ClientConfig, Session, PacketKey, HeaderKey}` over the
//! transport-agnostic engine in [`crate::tls::quic`], which carries no quinn (or
//! rustls) types. When the QUIC transport itself is hand-written (Phase 2), only
//! this file is deleted; the engine is reused unchanged.
//!
//! The two behaviours that differ from a stock quinn TLS backend both live in the
//! engine now (the Safari-26 H3 ClientHello shape) or here (the hand-encoded
//! ascending `0x39` transport-parameters blob substituted for quinn's
//! `params.write()`); every other `crypto::Session` method delegates to the
//! engine.

use std::{any::Any, sync::Arc};

use aws_lc_rs::aead;
use bytes::BytesMut;
use quinn::{
    crypto::{self, CryptoError, ExportKeyingMaterialError, KeyPair, Keys},
    ConnectError, ConnectionId, Side,
};
use quinn_proto::{transport_parameters::TransportParameters, TransportError, TransportErrorCode};

use crate::tls::quic::{
    self as engine, ClientHandshake, HeaderProtectionKey, KeyChange, PacketKey, QuicTlsError,
    Side as EngineSide, QUIC_VERSION_V1,
};

/// QUIC-compatible TLS client configuration that drives the hand-written engine.
///
/// Wraps the engine's [`engine::ClientConfig`] (verifier + ALPN); the Safari-26 H3
/// ClientHello shape and the pinned post-quantum-hybrid key exchange are engine
/// invariants, not config fields.
pub struct SafariQuicClientConfig {
    engine: Arc<engine::ClientConfig>,
}

impl SafariQuicClientConfig {
    /// Wrap an engine client config for the Safari QUIC carrier.
    pub fn new(engine: Arc<engine::ClientConfig>) -> Self {
        Self { engine }
    }
}

impl crypto::ClientConfig for SafariQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        // THE substitution: the hand-encoded ascending 0x39 blob, NOT quinn's
        // `params.write()`. The engine emits it verbatim in the ClientHello.
        let tp_bytes = encode_safari_transport_params(params);
        let handshake = ClientHandshake::new(self.engine.clone(), version, server_name, tp_bytes)
            .map_err(|e| match e {
            // The only realistically-reachable failures: an unsupported QUIC
            // version (quinn only offers v1) or a malformed SNI. The remaining
            // crypto variants (ML-KEM keygen, ClientHello assembly) cannot fail
            // for valid inputs; surface them as InvalidServerName rather than
            // panicking the endpoint.
            QuicTlsError::UnsupportedVersion => ConnectError::UnsupportedVersion,
            _ => ConnectError::InvalidServerName(server_name.into()),
        })?;
        Ok(Box::new(SafariTlsSession {
            version,
            got_handshake_data: false,
            handshake,
        }))
    }
}

/// The live hand-written TLS session driven by quinn.
struct SafariTlsSession {
    version: u32,
    got_handshake_data: bool,
    handshake: ClientHandshake,
}

impl crypto::Session for SafariTlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        to_quinn_keys(self.handshake.initial_keys(dst_cid, to_engine_side(side)))
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        // quinn never downcasts the client's handshake_data; expose the negotiated
        // ALPN (the only field a client needs), mirroring the prior backend.
        Some(Box::new(self.handshake.alpn_protocol().map(<[u8]>::to_vec)))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.handshake
            .peer_certificates()
            .map(|certs| -> Box<dyn Any> {
                Box::new(
                    certs
                        .iter()
                        .map(|der| rustls_pki_types::CertificateDer::from(der.clone()))
                        .collect::<Vec<rustls_pki_types::CertificateDer<'static>>>(),
                )
            })
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        // Cold-start only: ParallaX disables resumption, so there are no 0-RTT keys.
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        // Client that never offered 0-RTT: it was not accepted.
        Some(false)
    }

    fn is_handshaking(&self) -> bool {
        self.handshake.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        let ready = self.handshake.read_handshake(buf).map_err(map_tls_error)?;
        if ready {
            self.got_handshake_data = true;
        }
        Ok(ready)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.handshake.peer_transport_parameters() {
            None => Ok(None),
            Some(buf) => TransportParameters::read(Side::Client, &mut std::io::Cursor::new(buf))
                .map(Some)
                .map_err(Into::into),
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.handshake
            .write_handshake(buf)
            .map(|change| match change {
                KeyChange::Handshake { keys } => to_quinn_keys(keys),
                KeyChange::OneRtt { keys } => to_quinn_keys(keys),
            })
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let pair = self.handshake.next_1rtt_keys()?;
        Some(KeyPair {
            local: Box::new(pair.local),
            remote: Box::new(pair.remote),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        if self.version != QUIC_VERSION_V1 {
            return false;
        }
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

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE_V1);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY_V1).unwrap(),
        );

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.handshake
            .export_keying_material(output, label, context)
            .map_err(|_| ExportKeyingMaterialError)
    }
}

/// Convert the engine's per-direction key aggregate into quinn's per-type one.
fn to_quinn_keys(keys: engine::Keys) -> Keys {
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

fn to_engine_side(side: Side) -> EngineSide {
    match side {
        Side::Client => EngineSide::Client,
        Side::Server => EngineSide::Server,
    }
}

/// Map an engine TLS error onto a QUIC transport error: a fatal TLS alert becomes
/// a CRYPTO_ERROR (0x0100 | alert); anything else is a PROTOCOL_VIOLATION. (The
/// `TransportError` helper constructors are `pub(crate)` in quinn-proto, so build
/// the struct by hand.)
fn map_tls_error(e: QuicTlsError) -> TransportError {
    match e.alert_description() {
        Some(alert) => TransportError {
            code: TransportErrorCode::crypto(alert),
            frame: None,
            reason: e.to_string(),
        },
        None => TransportError {
            code: TransportErrorCode::PROTOCOL_VIOLATION,
            frame: None,
            reason: format!("TLS error: {e}"),
        },
    }
}

// --- quinn PacketKey / HeaderKey over the engine key types ---------------------

impl crypto::PacketKey for PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload) = buf.split_at_mut(header_len);
        // Infallible for a well-formed packet buffer (header + payload + reserved
        // tag); the engine only errors if the buffer is shorter than the tag.
        self.encrypt_in_place(packet, header, payload)
            .expect("QUIC packet buffer reserves the AEAD tag");
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let pt_len = self
            .decrypt_in_place(packet, header, payload.as_mut())
            .map_err(|_| CryptoError)?
            .len();
        payload.truncate(pt_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        PacketKey::tag_len(self)
    }

    fn confidentiality_limit(&self) -> u64 {
        PacketKey::confidentiality_limit(self)
    }

    fn integrity_limit(&self) -> u64 {
        PacketKey::integrity_limit(self)
    }
}

impl crypto::HeaderKey for HeaderProtectionKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // Errors only on a packet too short to hold the HP sample (a malformed
        // inbound packet); leaving it unmodified makes AEAD reject it, which is the
        // correct non-panicking outcome. quinn pre-validates length for well-formed
        // packets, so this never fires on the happy path.
        let _ = self.decrypt_header(pn_offset, packet);
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let _ = self.encrypt_header(pn_offset, packet);
    }

    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

// QUIC v1 Retry integrity constants (RFC 9001 §5.8).
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// `initial_max_data` (0x04) — 16 MiB, the confirmed CFNetwork/libquic value.
pub(crate) const SAFARI_TP_INITIAL_MAX_DATA: u64 = 16 * 1024 * 1024;
/// Per-stream flow-control window (0x05/0x06/0x07) — 2 MiB each.
pub(crate) const SAFARI_TP_INITIAL_MAX_STREAM_DATA: u64 = 2 * 1024 * 1024;
/// `active_connection_id_limit` (0x0e) — the confirmed Safari value 64 (matched by
/// the vendored quinn-proto CidQueue::LEN bump).
pub(crate) const SAFARI_TP_ACTIVE_CID_LIMIT: u64 = 64;
/// `initial_max_streams_uni` (0x09) — libquic value 8.
pub(crate) const SAFARI_TP_MAX_STREAMS_UNI: u64 = 8;

/// Apple's vendor/GREASE transport-parameter codepoint (value 0). Sorts LAST in
/// ascending id order (it is the largest id).
const SAFARI_TP_VENDOR_GREASE_ID: u64 = 0x17f7586d2cb571;

/// The Safari-26 H3 `0x39` transport-parameter id set, in STRICT ASCENDING order.
/// `initial_source_connection_id` (0x0f) is read back from quinn's own blob (the
/// zero-length SCID); every other id carries a confirmed fixed value. The
/// vendor/GREASE codepoint is appended separately, last.
const SAFARI_TP_IDS: [u64; 7] = [0x04, 0x05, 0x06, 0x07, 0x09, 0x0e, 0x0f];

/// The confirmed Safari-26 H3 value for each standard varint transport parameter,
/// or `None` for `initial_source_connection_id` (0x0f), whose value is the SCID
/// read back from quinn's blob.
fn safari_tp_value_for_id(id: u64) -> Option<u64> {
    match id {
        0x04 => Some(SAFARI_TP_INITIAL_MAX_DATA),
        0x05 => Some(SAFARI_TP_INITIAL_MAX_STREAM_DATA),
        0x06 => Some(SAFARI_TP_INITIAL_MAX_STREAM_DATA),
        0x07 => Some(SAFARI_TP_INITIAL_MAX_STREAM_DATA),
        0x09 => Some(SAFARI_TP_MAX_STREAMS_UNI),
        0x0e => Some(SAFARI_TP_ACTIVE_CID_LIMIT),
        _ => None,
    }
}

/// Hand-encode the Safari-26 ascending `0x39` transport-parameters blob.
fn encode_safari_transport_params(params: &TransportParameters) -> Vec<u8> {
    let mut quinn_blob = Vec::new();
    params.write(&mut quinn_blob);
    let quinn_values = parse_tp_blob(&quinn_blob);
    encode_safari_tp_from_pairs(&quinn_values)
}

/// Core of [`encode_safari_transport_params`], split out for unit testing because
/// quinn's [`TransportParameters`] cannot be constructed outside quinn-proto. Emits
/// [`SAFARI_TP_IDS`] with their confirmed values in ascending order, then the
/// vendor/GREASE codepoint last.
fn encode_safari_tp_from_pairs(quinn_values: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for &id in &SAFARI_TP_IDS {
        match safari_tp_value_for_id(id) {
            Some(value) => put_param(&mut out, id, value),
            None => match quinn_values.iter().find(|(qid, _)| *qid == id) {
                Some((_, value)) => put_param_bytes(&mut out, id, value),
                None => put_param_bytes(&mut out, id, &[]),
            },
        }
    }
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

/// Parse a serialized transport-parameters blob into `(id, value_bytes)` pairs.
/// Stops at the first malformed entry (quinn's own output is always well-formed).
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

/// Read one QUIC varint (RFC 9000 §16) from the front of `buf`.
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

    fn decode_emitted(blob: &[u8]) -> Vec<(u64, Vec<u8>)> {
        parse_tp_blob(blob)
    }

    #[test]
    fn safari_tp_id_table_is_strictly_ascending() {
        for w in SAFARI_TP_IDS.windows(2) {
            assert!(w[0] < w[1], "ids not strictly ascending at {w:?}");
        }
        assert!(
            *SAFARI_TP_IDS.last().unwrap() < SAFARI_TP_VENDOR_GREASE_ID,
            "vendor/GREASE id must sort after every standard id"
        );
    }

    #[test]
    fn safari_tp_id_table_omits_dropped_ids() {
        for dropped in [0x01, 0x03, 0x08, 0x0a, 0x0b, 0x0c, 0x20] {
            assert!(
                !SAFARI_TP_IDS.contains(&dropped),
                "id {dropped:#x} must be omitted per the confirmed spec"
            );
        }
        assert!(!SAFARI_TP_IDS.contains(&0x2ab2));
        assert!(!SAFARI_TP_IDS.contains(&0xff04de1b));
        assert!(!SAFARI_TP_IDS.contains(&0x1b));
    }

    #[test]
    fn emitted_ids_are_the_safari_set_plus_vendor_grease_ascending() {
        let quinn_pairs: Vec<(u64, Vec<u8>)> = vec![
            (0x0f, vec![]),
            (0x01, vec![0x00]),
            (0x03, vec![0x44, 0xb0]),
            (0x08, vec![0x00]),
            (0x20, vec![0x80, 0x00, 0xff, 0xff]),
            (0x0a, vec![0x03]),
            (0x0b, vec![0x19]),
            (0x0c, vec![]),
            (0x2ab2, vec![]),
            (0xff04de1b, vec![0x40, 0xfa]),
            (0x1b, vec![0xca, 0xfe]),
            (0x02, vec![0u8; 16]),
        ];

        let emitted = encode_safari_tp_from_pairs(&quinn_pairs);
        let decoded = decode_emitted(&emitted);
        let ids: Vec<u64> = decoded.iter().map(|(id, _)| *id).collect();

        let mut expected = SAFARI_TP_IDS.to_vec();
        expected.push(SAFARI_TP_VENDOR_GREASE_ID);
        assert_eq!(ids, expected);
        for w in ids.windows(2) {
            assert!(w[0] < w[1], "emitted ids not strictly ascending");
        }
    }

    #[test]
    fn emitted_values_are_the_confirmed_safari_values() {
        let emitted = encode_safari_tp_from_pairs(&[(0x0f, vec![])]);
        let decoded = decode_emitted(&emitted);

        let val = |id: u64| -> u64 {
            let (_, bytes) = decoded.iter().find(|(qid, _)| *qid == id).unwrap();
            read_varint(bytes).unwrap().0
        };

        assert!(!decoded.iter().any(|(id, _)| *id == 0x01));
        assert!(!decoded.iter().any(|(id, _)| *id == 0x03));
        assert_eq!(val(0x04), SAFARI_TP_INITIAL_MAX_DATA);
        assert_eq!(val(0x05), 2 * 1024 * 1024);
        assert_eq!(val(0x06), 2 * 1024 * 1024);
        assert_eq!(val(0x07), 2 * 1024 * 1024);
        assert!(!decoded.iter().any(|(id, _)| *id == 0x08));
        assert_eq!(val(0x09), 8);
        assert_eq!(val(0x0e), 64);
        assert_eq!(val(SAFARI_TP_VENDOR_GREASE_ID), 0);

        let (_, src_cid) = decoded.iter().find(|(id, _)| *id == 0x0f).unwrap();
        assert!(src_cid.is_empty());
        assert!(!decoded.iter().any(|(id, _)| *id == 0x20));
    }

    #[test]
    fn varint_round_trips_across_size_classes() {
        for v in [0u64, 0x3f, 0x40, 0x3fff, 0x4000, 0x3fff_ffff, 0x4000_0000] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let (decoded, n) = read_varint(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(n, buf.len());
        }
    }
}
