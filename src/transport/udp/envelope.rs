//! Wire envelope for carrying a sealed AEAD record over the unreliable UDP fast
//! plane.
//!
//! On the TCP leg, records are self-delimiting (the TLS record length header)
//! and arrive strictly in order, so no envelope is needed. On the UDP leg
//! records ride RFC 9221 datagrams that can arrive out of order, be duplicated
//! (the same record re-sent as a TCP reinjection), or be lost — so each record
//! is tagged with its global per-direction record sequence number, letting the
//! receiver reorder and de-duplicate it (see [`super::reorder`]).
//!
//! SECURITY — the dual-leg nonce invariant (生死项): the `seq` carried here is
//! used ONLY for ordering and de-duplication. It is NEVER fed into the AEAD
//! nonce by this layer. The nonce is already baked into the sealed record at
//! seal time by the single global per-direction sequence
//! (`crypto::session::record_nonce_from`): the same record re-sent on a second
//! leg is byte-identical (same plaintext, same seq, hence same nonce) and so is
//! a safe exact retransmission, while two *different* records always carry
//! different `seq` and therefore different nonces. The unit tests below pin both
//! halves of that invariant.
#![allow(dead_code)] // Wired into the UDP datapath in the next slice; exercised by tests now.

use std::ops::Range;

use thiserror::Error;

/// Fixed envelope header: `seq` (u64, big-endian) followed by `record_len`
/// (u16, big-endian). The sealed record bytes follow. A u16 length suffices
/// because a sealed record never exceeds the TLS record limit (~16 KiB).
pub(crate) const ENVELOPE_HEADER_LEN: usize = 8 + 2;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum EnvelopeError {
    #[error("record envelope is truncated")]
    Truncated,
    #[error("record envelope length {0} exceeds the u16 record limit")]
    RecordTooLarge(usize),
}

/// Appends one enveloped record (`seq` + length header, then `record` bytes) to
/// `out`. Multiple enveloped records may be concatenated into a single datagram
/// and split back apart with repeated [`decode_prefix`] calls.
pub(crate) fn encode_into(seq: u64, record: &[u8], out: &mut Vec<u8>) -> Result<(), EnvelopeError> {
    let len =
        u16::try_from(record.len()).map_err(|_| EnvelopeError::RecordTooLarge(record.len()))?;
    out.reserve(ENVELOPE_HEADER_LEN + record.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(record);
    Ok(())
}

/// A decoded envelope: the record's sequence number, the byte range of its
/// sealed record within `input`, and how many bytes the whole envelope consumed
/// (so the caller can decode the next envelope in a packed datagram).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedEnvelope {
    pub seq: u64,
    pub record: Range<usize>,
    pub consumed: usize,
}

/// Decodes the envelope at the front of `input`. Truncation is reported, never
/// panicked: `input` is attacker-influenced datagram data, so every length is
/// bounds-checked before use.
pub(crate) fn decode_prefix(input: &[u8]) -> Result<DecodedEnvelope, EnvelopeError> {
    if input.len() < ENVELOPE_HEADER_LEN {
        return Err(EnvelopeError::Truncated);
    }
    let seq = u64::from_be_bytes(input[0..8].try_into().expect("8 bytes checked above"));
    let len = u16::from_be_bytes(input[8..10].try_into().expect("2 bytes checked above")) as usize;
    let record_start = ENVELOPE_HEADER_LEN;
    let record_end = record_start
        .checked_add(len)
        .ok_or(EnvelopeError::Truncated)?;
    if input.len() < record_end {
        return Err(EnvelopeError::Truncated);
    }
    Ok(DecodedEnvelope {
        seq,
        record: record_start..record_end,
        consumed: record_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::session::{
        record_nonce_from, seal_in_place_detached_with, AeadCodec, NONCE_LEN,
    };
    use crate::protocol::data::CLIENT_TO_SERVER_AAD;

    #[test]
    fn round_trips_a_single_record() {
        let record = b"sealed-tls-record-bytes";
        let mut buf = Vec::new();
        encode_into(0x0102_0304_0506_0708, record, &mut buf).unwrap();
        let decoded = decode_prefix(&buf).unwrap();
        assert_eq!(decoded.seq, 0x0102_0304_0506_0708);
        assert_eq!(&buf[decoded.record.clone()], record);
        assert_eq!(decoded.consumed, buf.len());
    }

    #[test]
    fn splits_multiple_packed_records() {
        let mut buf = Vec::new();
        encode_into(10, b"first", &mut buf).unwrap();
        encode_into(11, b"second-longer", &mut buf).unwrap();
        encode_into(12, b"", &mut buf).unwrap();

        let mut rest = &buf[..];
        let mut got = Vec::new();
        while !rest.is_empty() {
            let d = decode_prefix(rest).unwrap();
            got.push((d.seq, rest[d.record.clone()].to_vec()));
            rest = &rest[d.consumed..];
        }
        assert_eq!(
            got,
            vec![
                (10, b"first".to_vec()),
                (11, b"second-longer".to_vec()),
                (12, b"".to_vec()),
            ]
        );
    }

    #[test]
    fn rejects_truncated_header_and_body() {
        // Header shorter than 10 bytes.
        assert_eq!(decode_prefix(&[0_u8; 9]), Err(EnvelopeError::Truncated));
        // Header claims 5 record bytes but only 2 follow.
        let mut buf = Vec::new();
        buf.extend_from_slice(&7_u64.to_be_bytes());
        buf.extend_from_slice(&5_u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(decode_prefix(&buf), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn rejects_oversized_record() {
        let too_big = vec![0_u8; usize::from(u16::MAX) + 1];
        assert_eq!(
            encode_into(0, &too_big, &mut Vec::new()),
            Err(EnvelopeError::RecordTooLarge(too_big.len()))
        );
    }

    // --- dual-leg nonce invariant (生死项) ---------------------------------

    #[test]
    fn distinct_seq_yields_distinct_nonce_and_seq_is_carrier_independent() {
        let base = [0x5a_u8; NONCE_LEN];
        // The seq is the SOLE driver of the nonce: two different records (with
        // different seq) can never collide on the same (key, nonce).
        assert_ne!(record_nonce_from(&base, 1), record_nonce_from(&base, 2));
        assert_ne!(
            record_nonce_from(&base, 0),
            record_nonce_from(&base, u64::MAX)
        );
        // The same record re-sent on the other leg keeps its seq, so its nonce is
        // identical regardless of which leg carries it.
        assert_eq!(record_nonce_from(&base, 7), record_nonce_from(&base, 7));
    }

    #[test]
    fn reinjecting_the_same_record_is_byte_identical() {
        // Re-sealing the same plaintext at the same seq yields byte-identical
        // ciphertext + tag, so a record sent on UDP and later reinjected on TCP
        // is a safe exact retransmission — NOT a fatal nonce reuse over
        // *different* plaintext.
        let codec = AeadCodec::new([0x11_u8; 32], [0x22_u8; NONCE_LEN]);
        let cipher = codec.cipher();
        let base = codec.nonce_base();
        let seq = 12_345_u64;

        let mut a = b"identical application payload".to_vec();
        let mut b = a.clone();
        let tag_a =
            seal_in_place_detached_with(&cipher, &base, seq, &mut a, CLIENT_TO_SERVER_AAD).unwrap();
        let tag_b =
            seal_in_place_detached_with(&cipher, &base, seq, &mut b, CLIENT_TO_SERVER_AAD).unwrap();
        assert_eq!(a, b, "same plaintext+seq must seal to identical ciphertext");
        assert_eq!(
            tag_a, tag_b,
            "same plaintext+seq must produce an identical tag"
        );
    }
}
