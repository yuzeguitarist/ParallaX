//! Ground-truth source: the real Safari-26 HTTP/3 (QUIC-over-UDP) capture,
//! normalised to a [`Trace`].
//!
//! Input is a tshark UDP-datagram export of `~/Desktop/safari-h3/*.pcap` — the
//! censor's actual vantage point on a QUIC flow. Columns:
//!
//! ```text
//! frame \t time \t src_port \t udp_length
//! ```
//!
//! Each row is one UDP datagram. Direction is by source port: `443` ⇒ S2C
//! (server downlink), anything else ⇒ C2S (Safari uplink — the behaviour we
//! imitate).
//!
//! SCOPE: only the **length** and **direction** of each datagram are used
//! downstream. The relative time is parsed and retained on the `Trace`, but the
//! battery does NOT gate on inter-arrival time — wall-clock IAT is dominated by
//! host scheduling on a loopback capture and is not censor-faithful in absolute
//! terms. Datagram size and the C2S/S2C interleave, by contrast, are exactly
//! what a censor observes and are compared directly.

use std::path::Path;

use super::trace::{Dir, Record, Trace};

/// Safari H3 1-RTT capture (server port 443).
pub const SAFARI_H3_FIXTURE: &str = "tests/fixtures/safari26_h3_udp_records.tsv";
/// Safari H3 0-RTT resumption capture (server port 443).
pub const SAFARI_H3_0RTT_FIXTURE: &str = "tests/fixtures/safari26_h3_0rtt_udp_records.tsv";
/// The server port that marks the S2C (downlink) direction in both captures.
pub const SAFARI_H3_SERVER_PORT: &str = "443";

/// Parse a Safari H3 UDP TSV into a [`Trace`] of datagrams. `server_port` marks
/// the S2C direction (anything else is C2S uplink). Returns an error string on
/// malformed/empty input rather than panicking.
pub fn load_trace(path: impl AsRef<Path>, server_port: &str) -> Result<Trace, String> {
    let text = std::fs::read_to_string(path.as_ref())
        .map_err(|e| format!("read {}: {e}", path.as_ref().display()))?;
    parse_tsv(&text, server_port)
}

/// Load the 1-RTT H3 fixture.
pub fn load_fixture() -> Result<Trace, String> {
    load_trace(SAFARI_H3_FIXTURE, SAFARI_H3_SERVER_PORT)
}

/// Load the 0-RTT H3 fixture.
pub fn load_0rtt_fixture() -> Result<Trace, String> {
    load_trace(SAFARI_H3_0RTT_FIXTURE, SAFARI_H3_SERVER_PORT)
}

fn parse_tsv(text: &str, server_port: &str) -> Result<Trace, String> {
    let mut records = Vec::new();
    let mut t0: Option<f64> = None;

    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 4 {
            continue;
        }
        let time: f64 = cols[1]
            .parse()
            .map_err(|_| format!("line {}: bad time {:?}", lineno + 1, cols[1]))?;
        let src_port = cols[2];
        let len: u32 = match cols[3].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let dir = if src_port == server_port {
            Dir::S2C
        } else {
            Dir::C2S
        };
        if t0.is_none() {
            t0 = Some(time);
        }
        let t_micros = ((time - t0.unwrap()) * 1_000_000.0).round().max(0.0) as u64;
        records.push(Record { len, dir, t_micros });
    }

    if records.is_empty() {
        return Err("no UDP datagrams parsed from H3 TSV".into());
    }
    Ok(Trace::new(records))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_direction_and_length() {
        let tsv = "1\t0.000000\t32078\t1208\n\
                   2\t0.001455\t443\t48\n\
                   3\t0.001480\t443\t1288\n";
        let trace = parse_tsv(tsv, "443").unwrap();
        assert_eq!(trace.len(), 3);
        assert_eq!(trace.dir(Dir::C2S).len(), 1); // the 32078 uplink datagram
        assert_eq!(trace.dir(Dir::S2C).len(), 2); // two 443 downlink datagrams
        assert_eq!(trace.records[0].len, 1208);
        assert_eq!(trace.records[0].t_micros, 0);
    }

    #[test]
    fn loads_bundled_fixtures() {
        let one_rtt = load_fixture().expect("1-RTT fixture");
        let zero_rtt = load_0rtt_fixture().expect("0-RTT fixture");
        assert!(one_rtt.len() >= 50, "1-RTT datagrams: {}", one_rtt.len());
        assert!(zero_rtt.len() >= 90, "0-RTT datagrams: {}", zero_rtt.len());
    }
}
