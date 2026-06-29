//! Shared parser for tshark UDP-datagram TSV exports → [`Trace`].
//!
//! Both the H3 and QUIC Safari captures are exported in the same per-datagram
//! shape, so the parsing lives here once and the per-corpus modules
//! (`safari_h3_source`, `safari_quic_source`) are thin wrappers that supply the
//! fixture path and the server port.
//!
//! Column layout (tshark `-T fields`):
//!
//! ```text
//! frame_number \t time_relative \t udp_srcport \t udp_length
//! ```
//!
//! Direction is by source port: a datagram from `server_port` is S2C (downlink),
//! anything else is C2S (uplink — the imitated side). Only length and direction
//! are used downstream; the relative time is retained on the [`Trace`] but the
//! battery never gates on inter-arrival time (loopback wall-clock is noise).

use std::path::Path;

use super::trace::{Dir, Record, Trace};

/// Read and parse a UDP-datagram TSV file at `path`. `server_port` marks the S2C
/// direction. Returns an error string (never panics) so callers decide whether a
/// missing/corrupt fixture is fatal.
pub fn load(path: impl AsRef<Path>, server_port: &str) -> Result<Trace, String> {
    let text = std::fs::read_to_string(path.as_ref())
        .map_err(|e| format!("read {}: {e}", path.as_ref().display()))?;
    parse(&text, server_port)
}

/// Parse TSV text into a [`Trace`]. Fails closed on malformed rows (short row,
/// non-numeric time or length) so a corrupted fixture surfaces loudly rather
/// than silently dropping datagrams and shifting the samples tests depend on.
pub fn parse(text: &str, server_port: &str) -> Result<Trace, String> {
    let mut records = Vec::new();
    let mut t0: Option<f64> = None;

    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 4 {
            return Err(format!(
                "line {}: expected >=4 columns, got {}",
                lineno + 1,
                cols.len()
            ));
        }
        let time: f64 = cols[1]
            .parse()
            .map_err(|_| format!("line {}: bad time {:?}", lineno + 1, cols[1]))?;
        let src_port = cols[2];
        let len: u32 = cols[3]
            .trim()
            .parse()
            .map_err(|_| format!("line {}: bad udp_length {:?}", lineno + 1, cols[3]))?;
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
        return Err("no UDP datagrams parsed from TSV".into());
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
        let trace = parse(tsv, "443").unwrap();
        assert_eq!(trace.len(), 3);
        assert_eq!(trace.dir(Dir::C2S).len(), 1); // the 32078 uplink datagram
        assert_eq!(trace.dir(Dir::S2C).len(), 2); // two 443 downlink datagrams
        assert_eq!(trace.records[0].len, 1208);
        assert_eq!(trace.records[0].t_micros, 0);
    }

    #[test]
    fn fails_closed_on_short_row() {
        assert!(parse("1\t0.0\t443\n", "443").is_err());
    }

    #[test]
    fn fails_closed_on_bad_length() {
        assert!(parse("1\t0.0\t443\tNOTNUM\n", "443").is_err());
    }
}
