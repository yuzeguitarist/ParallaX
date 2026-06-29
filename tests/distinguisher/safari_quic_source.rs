//! Ground-truth source: the real Safari-26 QUIC capture from the large
//! mixed-site browse (`~/Desktop/safari-record-burst/capture.pcap`), normalised
//! to a [`Trace`] via the shared [`udp_tsv`] parser.
//!
//! This is the high-volume QUIC corpus (~6k datagrams across many hosts) used to
//! calibrate the QUIC direction-interleave and datagram-size distinguishers. It
//! supersedes the tiny `safari_h3_source` captures (~55 datagrams) as the
//! comparison baseline: with thousands of datagrams the KS verdicts are
//! statistically meaningful rather than small-sample noise.
//!
//! Same size/direction-only scope as every UDP source — see [`udp_tsv`].

use super::trace::Trace;
use super::udp_tsv;

/// Large mixed-site Safari QUIC capture (server port 443).
pub const SAFARI_QUIC_FIXTURE: &str = "tests/fixtures/safari26_quic_udp_records.tsv";
/// The server port that marks the S2C (downlink) direction.
pub const SAFARI_QUIC_SERVER_PORT: &str = "443";

/// Load the bundled large-corpus QUIC fixture.
pub fn load_fixture() -> Result<Trace, String> {
    udp_tsv::load(SAFARI_QUIC_FIXTURE, SAFARI_QUIC_SERVER_PORT)
}

#[cfg(test)]
mod tests {
    use super::super::trace::Dir;
    use super::*;

    #[test]
    fn loads_high_volume_bidirectional_corpus() {
        let trace = load_fixture().expect("QUIC fixture");
        // Thousands of datagrams, genuinely bidirectional.
        assert!(trace.len() >= 1000, "QUIC datagrams: {}", trace.len());
        assert!(trace.dir(Dir::C2S).len() >= 100, "C2S too few");
        assert!(trace.dir(Dir::S2C).len() >= 100, "S2C too few");
    }
}
