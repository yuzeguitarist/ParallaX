//! ParallaX source: produce ParallaX's data-plane record-length series from the
//! *real production* encoder, normalised to a [`Trace`].
//!
//! The honest, high-signal way to obtain "ParallaX's record sizing" is not to
//! scrape a socket — it is to drive the production [`DataRecordCodec`] the relay
//! actually uses. `seal_chunks` is the exact function the upload/download relay
//! loops call to turn a plaintext byte stream into on-wire TLS records; feeding
//! it a representative uplink payload and parsing the resulting record headers
//! (`record::parse_header`, the production parser) yields the true ParallaX
//! data-plane length sequence. This mirrors how `tests/gfw_simulator.rs` derives
//! its length series from the same production codec.
//!
//! SCOPE / HONESTY: this captures the **length** dimension end-to-end through
//! production code — the dimension where ParallaX deliberately matches Safari's
//! 16401-byte record regime, so it is exactly where we want a quantitative
//! KS verdict. It does NOT synthesise realistic inter-arrival times or the C2S/
//! S2C interleave (those need a live authenticated session over a socket, which
//! no existing loopback harness drives end-to-end). Timestamps here are a
//! uniform synthetic cadence; the IAT/direction dimensions are left to the
//! socket-capture path and are reported separately so loopback scheduling noise
//! never contaminates the length verdict.

use rand::SeedableRng;

use parallax::crypto::session::AeadCodec;
use parallax::protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD};
use parallax::tls::record::{self, TLS_HEADER_LEN};
// `seal_chunks` returns one `Vec<u8>` per sealed record, so each element is
// already a single on-wire record — we parse its 5-byte header for the length.
use parallax::traffic::PaddingProfile;

use super::trace::{Dir, Record, Trace};

/// Build a production `DataRecordCodec` with the default zero-padding profile —
/// the same construction `gfw_simulator.rs` uses. Keys are fixed test vectors;
/// they affect only the AEAD output bytes, never the record *lengths*.
fn client_codec() -> DataRecordCodec {
    DataRecordCodec::new(
        AeadCodec::new([5_u8; 32], [3_u8; 12]),
        PaddingProfile::new(0, 0).expect("zero padding profile"),
        CLIENT_TO_SERVER_AAD,
    )
}

/// Seal `payload` through the production `seal_chunks` relay path and return the
/// on-wire length of each emitted TLS record, parsed with the production header
/// parser. These are the lengths a censor observes for ParallaX's uplink.
pub fn record_lengths(payload: &[u8]) -> Vec<u32> {
    let mut codec = client_codec();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x9a1c_2026);
    let sealed = codec.seal_chunks(payload, &mut rng).expect("seal_chunks");

    // Each element is one complete on-wire TLS record that the production
    // encoder just sealed, so every header MUST parse — a failure means the
    // encoder produced a malformed record, which is a real bug we want to surface
    // loudly rather than silently drop (which would understate the record count).
    sealed
        .iter()
        .map(|rec| {
            let header = record::parse_header(rec)
                .expect("production seal_chunks emitted an unparsable TLS record");
            (header.total_len - TLS_HEADER_LEN) as u32
        })
        .collect()
}

/// Build a ParallaX C2S [`Trace`] for an uplink `payload`, using the production
/// record sizing and a uniform synthetic cadence. The cadence is a placeholder
/// (see module docs); only the length dimension of this trace is meaningful.
pub fn uplink_trace(payload: &[u8]) -> Trace {
    let lens = record_lengths(payload);
    let mut t = 0u64;
    let records = lens
        .into_iter()
        .map(|len| {
            let r = Record {
                len,
                dir: Dir::C2S,
                t_micros: t,
            };
            t += 1_000; // 1 ms synthetic spacing
            r
        })
        .collect();
    Trace::new(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_records_are_16401() {
        // A payload spanning several max records should produce 16401-byte
        // records (16384 plaintext + 2 pad-len + 16 tag − 1 ... = OUTER limit),
        // matching the Safari uplink full-record bucket. We assert the dominant
        // record size is the documented ParallaX full-record length.
        let payload = vec![0xab_u8; 16384 * 4 + 500];
        let lens = record_lengths(&payload);
        assert!(
            lens.len() >= 4,
            "expected multiple records, got {}",
            lens.len()
        );
        // All but the last record must be the full-size regime; assert they are
        // all equal (one uniform regime — the whole point of the data plane).
        let full = lens[0];
        assert!(
            lens[..lens.len() - 1].iter().all(|&l| l == full),
            "non-uniform full records: {:?}",
            &lens[..lens.len().min(6)]
        );
        // Pin the actual value the test name promises: 16401 is ParallaX's full
        // on-wire record length and exactly the Safari uplink full-record bucket
        // (see `data::OUTER_TLS_RECORD_LIMIT` and the big-POST fixture). Asserted
        // as a literal — not the production constant — so a regression that
        // shifts the regime (e.g. to 16400) is caught instead of tracked.
        assert_eq!(full, 16401, "ParallaX full-record length is not 16401");
    }
}
