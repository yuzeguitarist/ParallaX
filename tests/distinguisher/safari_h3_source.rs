//! Ground-truth source: the real Safari-26 HTTP/3 (QUIC-over-UDP) capture,
//! normalised to a [`Trace`] via the shared [`udp_tsv`] parser.
//!
//! Input is a tshark UDP-datagram export of `~/Desktop/safari-h3/*.pcap` — the
//! censor's actual vantage point on a QUIC flow. See [`udp_tsv`] for the column
//! layout and the size/direction-only scope (inter-arrival time is never gated
//! on).

use super::trace::Trace;
use super::udp_tsv;

/// Safari H3 1-RTT capture (server port 443).
pub const SAFARI_H3_FIXTURE: &str = "tests/fixtures/safari26_h3_udp_records.tsv";
/// Safari H3 0-RTT resumption capture (server port 443).
pub const SAFARI_H3_0RTT_FIXTURE: &str = "tests/fixtures/safari26_h3_0rtt_udp_records.tsv";
/// The server port that marks the S2C (downlink) direction in both captures.
pub const SAFARI_H3_SERVER_PORT: &str = "443";

/// Load the 1-RTT H3 fixture.
pub fn load_fixture() -> Result<Trace, String> {
    udp_tsv::load(SAFARI_H3_FIXTURE, SAFARI_H3_SERVER_PORT)
}

/// Load the 0-RTT H3 fixture.
pub fn load_0rtt_fixture() -> Result<Trace, String> {
    udp_tsv::load(SAFARI_H3_0RTT_FIXTURE, SAFARI_H3_SERVER_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_bundled_fixtures() {
        let one_rtt = load_fixture().expect("1-RTT fixture");
        let zero_rtt = load_0rtt_fixture().expect("0-RTT fixture");
        assert!(one_rtt.len() >= 50, "1-RTT datagrams: {}", one_rtt.len());
        assert!(zero_rtt.len() >= 90, "0-RTT datagrams: {}", zero_rtt.len());
    }
}
