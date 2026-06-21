//! Owned QUIC transport parameters (RFC 9000 §18) for the hand-written stack.
//!
//! `quinn-proto`'s `TransportParameters` keeps every field `pub(crate)`, which
//! forces the carrier to round-trip through `write()`/`read()` bytes just to read
//! one field back (the deepest quinn-proto coupling — see
//! [`crate::transport::udp::safari_crypto::encode_safari_transport_params`], which
//! serializes quinn's blob only to re-parse it). This type exposes its fields
//! directly, so one struct is the single source of truth for BOTH what we
//! advertise on the wire AND what we enforce — no advertised-vs-actual gap.
//!
//! The client encoder reproduces Safari-26 H3's exact `0x39` blob: the confirmed
//! id set in STRICT ASCENDING order, then Apple's vendor/GREASE codepoint last,
//! omitting every id Safari does not send (omit is NOT the same as value 0). This
//! is a byte-exact camouflage invariant: `tests/gfw_simulator.rs` guards the live
//! carrier's wire image, and the in-file drift guard keeps these native constants
//! in lockstep with it (this native encoder is not yet on the wire).

use super::varint;

// --- Transport-parameter ids (RFC 9000 §18.2 codepoints) -----------------------
// Only the ids Safari-26 H3 actually emits; everything else is omitted on the
// client wire and merely recognized on read.
const TP_INITIAL_MAX_DATA: u64 = 0x04;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const TP_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
const TP_INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;

/// Apple's vendor/GREASE transport-parameter codepoint (value 0). It is the
/// largest id, so strict-ascending order places it AFTER every standard id.
const TP_VENDOR_GREASE_ID: u64 = 0x17f7586d2cb571;

// --- Confirmed Safari-26 H3 values (CFNetwork/libquic, disassembly-confirmed) ---
const SAFARI_INITIAL_MAX_DATA: u64 = 16 * 1024 * 1024;
const SAFARI_INITIAL_MAX_STREAM_DATA: u64 = 2 * 1024 * 1024;
const SAFARI_MAX_STREAMS_UNI: u64 = 8;
const SAFARI_ACTIVE_CID_LIMIT: u64 = 64;

/// RFC 9000 §18.2 default for `active_connection_id_limit` when the parameter is
/// absent from a received blob.
const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// RFC 9000 §18.2: the minimum legal `active_connection_id_limit`.
const MIN_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
/// RFC 9000 §4.6: a `max_streams` parameter MUST NOT exceed 2^60.
const MAX_STREAMS_LIMIT: u64 = 1 << 60;

/// Error parsing a peer transport-parameters blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The blob ended in the middle of an id, length, or value field.
    Truncated,
    /// A varint-typed parameter's body was not exactly one varint.
    Malformed,
    /// A transport parameter appeared more than once (RFC 9000 §7.4.1: an endpoint
    /// MUST treat this as a TRANSPORT_PARAMETER_ERROR).
    Duplicate,
    /// A parameter carried a value outside its RFC 9000 §18.2 valid range (e.g.
    /// `max_streams` > 2^60 per §4.6, or `active_connection_id_limit` < 2).
    Invalid,
}

/// QUIC transport parameters as ParallaX advertises and enforces them.
///
/// Fields are the values actually used by the relay; `read` populates them from a
/// peer blob and `encode_safari_client` serializes the client's fixed Safari set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParameters {
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub active_connection_id_limit: u64,
    /// `initial_source_connection_id` (0x0f). Zero-length for the Safari client,
    /// and MUST equal the Initial packet-header SCID (RFC 9000 §7.3).
    pub initial_src_cid: Vec<u8>,
}

impl TransportParameters {
    /// The Safari-26 H3 client's fixed transport parameters.
    ///
    /// `scid` is the Initial-header source connection id (zero-length for Safari);
    /// it is echoed into `initial_source_connection_id` (0x0f) so the §7.3
    /// SCID-match invariant holds by construction. The client grants 0 bidi
    /// streams (the id is omitted on the wire) and 8 uni.
    pub fn safari_client(scid: &[u8]) -> Self {
        Self {
            initial_max_data: SAFARI_INITIAL_MAX_DATA,
            initial_max_stream_data_bidi_local: SAFARI_INITIAL_MAX_STREAM_DATA,
            initial_max_stream_data_bidi_remote: SAFARI_INITIAL_MAX_STREAM_DATA,
            initial_max_stream_data_uni: SAFARI_INITIAL_MAX_STREAM_DATA,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: SAFARI_MAX_STREAMS_UNI,
            active_connection_id_limit: SAFARI_ACTIVE_CID_LIMIT,
            initial_src_cid: scid.to_vec(),
        }
    }

    /// Serialize the client's `0x39` blob: the Safari id set in strict ascending
    /// order, then the vendor/GREASE codepoint last. Every id Safari does not send
    /// is omitted. The emit order below IS ascending by id, by construction.
    pub fn encode_safari_client(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        put_param(&mut out, TP_INITIAL_MAX_DATA, self.initial_max_data);
        put_param(
            &mut out,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        );
        put_param(
            &mut out,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
        );
        put_param(
            &mut out,
            TP_INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
        );
        put_param(
            &mut out,
            TP_INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
        );
        put_param(
            &mut out,
            TP_ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
        );
        put_param_bytes(
            &mut out,
            TP_INITIAL_SOURCE_CONNECTION_ID,
            &self.initial_src_cid,
        );
        put_param(&mut out, TP_VENDOR_GREASE_ID, 0);
        out
    }

    /// Parse a peer's transport-parameters blob (RFC 9000 §18). Recognized ids
    /// populate the matching field; unknown ids (including GREASE) are ignored.
    /// Omitted parameters keep their RFC 9000 §18.2 defaults. Returns [`Error`] on
    /// a truncated or malformed blob.
    pub fn read(blob: &[u8]) -> Result<Self, Error> {
        let mut tp = Self {
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            active_connection_id_limit: DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
            initial_src_cid: Vec::new(),
        };
        let mut seen: Vec<u64> = Vec::new();
        let mut i = 0usize;
        while i < blob.len() {
            let (id, n) = varint::decode(&blob[i..]).ok_or(Error::Truncated)?;
            i += n;
            // RFC 9000 §7.4.1: a transport parameter MUST NOT appear more than once.
            if seen.contains(&id) {
                return Err(Error::Duplicate);
            }
            seen.push(id);
            let (len, m) = varint::decode(&blob[i..]).ok_or(Error::Truncated)?;
            i += m;
            let len = len as usize;
            let body = blob.get(i..i + len).ok_or(Error::Truncated)?;
            i += len;
            match id {
                TP_INITIAL_MAX_DATA => tp.initial_max_data = read_varint_body(body)?,
                TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    tp.initial_max_stream_data_bidi_local = read_varint_body(body)?;
                }
                TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    tp.initial_max_stream_data_bidi_remote = read_varint_body(body)?;
                }
                TP_INITIAL_MAX_STREAM_DATA_UNI => {
                    tp.initial_max_stream_data_uni = read_varint_body(body)?;
                }
                TP_INITIAL_MAX_STREAMS_BIDI => {
                    tp.initial_max_streams_bidi = read_max_streams(body)?;
                }
                TP_INITIAL_MAX_STREAMS_UNI => {
                    tp.initial_max_streams_uni = read_max_streams(body)?;
                }
                TP_ACTIVE_CONNECTION_ID_LIMIT => {
                    // RFC 9000 §18.2: a value below 2 is a TRANSPORT_PARAMETER_ERROR.
                    let v = read_varint_body(body)?;
                    if v < MIN_ACTIVE_CONNECTION_ID_LIMIT {
                        return Err(Error::Invalid);
                    }
                    tp.active_connection_id_limit = v;
                }
                TP_INITIAL_SOURCE_CONNECTION_ID => tp.initial_src_cid = body.to_vec(),
                _ => {} // unknown / GREASE / not-enforced-by-the-relay: ignore
            }
        }
        Ok(tp)
    }
}

/// Append one transport parameter `id := value` (value varint-encoded).
fn put_param(out: &mut Vec<u8>, id: u64, value: u64) {
    varint::encode(id, out);
    varint::encode(varint::size(value) as u64, out);
    varint::encode(value, out);
}

/// Append a transport parameter with a raw (already-bytes) value, e.g. the
/// connection id.
fn put_param_bytes(out: &mut Vec<u8>, id: u64, value: &[u8]) {
    varint::encode(id, out);
    varint::encode(value.len() as u64, out);
    out.extend_from_slice(value);
}

/// Decode a varint-typed parameter body that MUST be exactly one varint.
fn read_varint_body(body: &[u8]) -> Result<u64, Error> {
    let (value, n) = varint::decode(body).ok_or(Error::Truncated)?;
    if n != body.len() {
        return Err(Error::Malformed);
    }
    Ok(value)
}

/// Decode a `max_streams` parameter body, enforcing the RFC 9000 §4.6 cap (2^60):
/// a larger value cannot encode a valid stream id and is a TRANSPORT_PARAMETER_ERROR.
fn read_max_streams(body: &[u8]) -> Result<u64, Error> {
    let value = read_varint_body(body)?;
    if value > MAX_STREAMS_LIMIT {
        return Err(Error::Invalid);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a blob into its `(id, value_bytes)` pairs (test-side reference).
    fn decode_pairs(blob: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let mut pairs = Vec::new();
        let mut i = 0usize;
        while i < blob.len() {
            let (id, n) = varint::decode(&blob[i..]).unwrap();
            i += n;
            let (len, m) = varint::decode(&blob[i..]).unwrap();
            i += m;
            let len = len as usize;
            pairs.push((id, blob[i..i + len].to_vec()));
            i += len;
        }
        pairs
    }

    #[test]
    fn safari_client_blob_ids_are_the_safari_set_plus_grease_ascending() {
        let blob = TransportParameters::safari_client(&[]).encode_safari_client();
        let ids: Vec<u64> = decode_pairs(&blob).into_iter().map(|(id, _)| id).collect();
        assert_eq!(
            ids,
            vec![
                0x04,
                0x05,
                0x06,
                0x07,
                0x09,
                0x0e,
                0x0f,
                TP_VENDOR_GREASE_ID
            ]
        );
        for w in ids.windows(2) {
            assert!(w[0] < w[1], "ids not strictly ascending at {w:?}");
        }
    }

    #[test]
    fn safari_client_blob_omits_every_id_safari_does_not_send() {
        let blob = TransportParameters::safari_client(&[]).encode_safari_client();
        let ids: Vec<u64> = decode_pairs(&blob).into_iter().map(|(id, _)| id).collect();
        // RFC ids Safari omits + quinn-only GREASE TPs that must never appear.
        for absent in [
            0x01, 0x03, 0x08, 0x0a, 0x0b, 0x0c, 0x20, 0x2ab2, 0xff04de1b, 0x1b,
        ] {
            assert!(!ids.contains(&absent), "id {absent:#x} must be omitted");
        }
    }

    #[test]
    fn safari_client_blob_carries_confirmed_values() {
        let blob = TransportParameters::safari_client(&[]).encode_safari_client();
        let pairs = decode_pairs(&blob);
        let val = |id: u64| -> u64 {
            let (_, body) = pairs.iter().find(|(qid, _)| *qid == id).unwrap();
            varint::decode(body).unwrap().0
        };
        assert_eq!(val(0x04), 16 * 1024 * 1024);
        assert_eq!(val(0x05), 2 * 1024 * 1024);
        assert_eq!(val(0x06), 2 * 1024 * 1024);
        assert_eq!(val(0x07), 2 * 1024 * 1024);
        assert_eq!(val(0x09), 8);
        assert_eq!(val(0x0e), 64);
        assert_eq!(val(TP_VENDOR_GREASE_ID), 0);
        let (_, scid) = pairs.iter().find(|(id, _)| *id == 0x0f).unwrap();
        assert!(scid.is_empty(), "Safari client SCID is zero-length");
    }

    #[test]
    fn encode_then_read_recovers_the_emitted_values() {
        let tp = TransportParameters::read(
            &TransportParameters::safari_client(&[]).encode_safari_client(),
        )
        .unwrap();
        assert_eq!(tp.initial_max_data, 16 * 1024 * 1024);
        assert_eq!(tp.initial_max_stream_data_bidi_local, 2 * 1024 * 1024);
        assert_eq!(tp.initial_max_stream_data_uni, 2 * 1024 * 1024);
        assert_eq!(tp.initial_max_streams_uni, 8);
        assert_eq!(tp.active_connection_id_limit, 64);
        assert!(tp.initial_src_cid.is_empty());
    }

    #[test]
    fn read_populates_known_ids_and_ignores_unknown() {
        // A server-style blob: initial_max_data, a bidi grant of 1, the CID limit,
        // and an unknown id that must be ignored without error.
        let mut blob = Vec::new();
        put_param(&mut blob, TP_INITIAL_MAX_DATA, 1234);
        put_param(&mut blob, TP_INITIAL_MAX_STREAMS_BIDI, 1);
        put_param(&mut blob, TP_ACTIVE_CONNECTION_ID_LIMIT, 8);
        put_param(&mut blob, 0x42, 99); // unknown id
        let tp = TransportParameters::read(&blob).unwrap();
        assert_eq!(tp.initial_max_data, 1234);
        assert_eq!(tp.initial_max_streams_bidi, 1);
        assert_eq!(tp.active_connection_id_limit, 8);
    }

    #[test]
    fn read_defaults_active_cid_limit_when_absent() {
        let tp = TransportParameters::read(&[]).unwrap();
        assert_eq!(
            tp.active_connection_id_limit,
            DEFAULT_ACTIVE_CONNECTION_ID_LIMIT
        );
    }

    #[test]
    fn read_rejects_truncated_blob() {
        // id + length present, value truncated.
        let mut blob = Vec::new();
        varint::encode(TP_INITIAL_MAX_DATA, &mut blob);
        varint::encode(4, &mut blob); // claims 4 value bytes
        blob.extend_from_slice(&[0x00, 0x01]); // only 2 present
        assert_eq!(TransportParameters::read(&blob), Err(Error::Truncated));
    }

    /// Drift guard for the migration: the native constants must equal the values
    /// the live `quinn` carrier still advertises/enforces, so the inert native
    /// blob stays byte-identical to today's wire image. When `safari_crypto` is
    /// deleted at cutover these become the sole source of truth.
    #[test]
    fn native_safari_values_match_the_live_carrier() {
        use crate::transport::udp::safari_crypto;
        assert_eq!(
            SAFARI_INITIAL_MAX_DATA,
            safari_crypto::SAFARI_TP_INITIAL_MAX_DATA
        );
        assert_eq!(
            SAFARI_INITIAL_MAX_STREAM_DATA,
            safari_crypto::SAFARI_TP_INITIAL_MAX_STREAM_DATA
        );
        assert_eq!(
            SAFARI_MAX_STREAMS_UNI,
            safari_crypto::SAFARI_TP_MAX_STREAMS_UNI
        );
        assert_eq!(
            SAFARI_ACTIVE_CID_LIMIT,
            safari_crypto::SAFARI_TP_ACTIVE_CID_LIMIT
        );
    }

    #[test]
    fn read_rejects_duplicate_parameter() {
        // RFC 9000 §7.4.1: the same id twice MUST be a TRANSPORT_PARAMETER_ERROR.
        let mut blob = Vec::new();
        put_param(&mut blob, TP_INITIAL_MAX_DATA, 1);
        put_param(&mut blob, TP_INITIAL_MAX_DATA, 2);
        assert_eq!(TransportParameters::read(&blob), Err(Error::Duplicate));
    }

    #[test]
    fn read_rejects_max_streams_above_2_pow_60() {
        let mut bad = Vec::new();
        put_param(&mut bad, TP_INITIAL_MAX_STREAMS_UNI, (1u64 << 60) + 1);
        assert_eq!(TransportParameters::read(&bad), Err(Error::Invalid));
        // Exactly 2^60 is the maximum legal value (RFC 9000 §4.6).
        let mut ok = Vec::new();
        put_param(&mut ok, TP_INITIAL_MAX_STREAMS_UNI, 1u64 << 60);
        assert!(TransportParameters::read(&ok).is_ok());
    }

    #[test]
    fn read_rejects_active_cid_limit_below_2() {
        let mut blob = Vec::new();
        put_param(&mut blob, TP_ACTIVE_CONNECTION_ID_LIMIT, 1);
        assert_eq!(TransportParameters::read(&blob), Err(Error::Invalid));
    }

    #[test]
    fn read_rejects_varint_param_with_non_varint_body() {
        // A varint-typed parameter whose body is two varints (not exactly one)
        // must be Malformed (read_varint_body requires the body to be one varint).
        let mut blob = Vec::new();
        put_param_bytes(&mut blob, TP_INITIAL_MAX_DATA, &[0x01, 0x01]);
        assert_eq!(TransportParameters::read(&blob), Err(Error::Malformed));
    }
}
