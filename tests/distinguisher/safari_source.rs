//! Ground-truth source: the real Safari-26 TCP/H2 capture, normalised to a
//! [`Trace`].
//!
//! Input is `tests/fixtures/safari26_tcp_records.tsv`, the tshark per-record
//! export of `~/Desktop/safari-tcp/big.pcap` (one TLS stream). Columns:
//!
//! ```text
//! frame \t time \t src_ip \t src_port \t content_types \t record_lengths \t tcp_len
//! ```
//!
//! `content_types` and `record_lengths` are comma-separated (a TCP segment can
//! carry several TLS records). For TLS 1.3 application-data the content-type
//! column is *empty* — tshark reports the real type as `opaque_type`, which the
//! export drops — so an empty content-type marks an application-data record.
//! This mirrors the `content_type or opaque_type` fallback in
//! `~/Desktop/safari-tcp/analyze_packetization.py`.
//!
//! Direction is by source port: `443` ⇒ S2C (server downlink), anything else
//! ⇒ C2S (Safari uplink — the behaviour we imitate). We do not hard-code IPs.

use std::path::Path;

use super::trace::{Dir, Record, Trace};

/// Control-frame stream: Safari uplink is almost entirely small H2 control
/// records (44 B / 30 B). Server port 443. Good for the direction/timing
/// structure, NOT for the full-record length regime (it has no large POST).
pub const SAFARI_TCP_FIXTURE: &str = "tests/fixtures/safari26_tcp_records.tsv";
pub const SAFARI_TCP_SERVER_PORT: &str = "443";

/// Big-POST stream: a real large uplink transfer with ~900 full 16401-byte
/// records — the "sole full-record bucket" the data plane is tuned to match.
/// Server port 8443. This is the corpus to compare ParallaX record sizing to.
pub const SAFARI_BIGPOST_FIXTURE: &str = "tests/fixtures/safari26_tcp_bigpost_records.tsv";
pub const SAFARI_BIGPOST_SERVER_PORT: &str = "8443";

/// Parse the Safari TSV at `path` into a [`Trace`] of application-data records.
/// `server_port` marks the S2C direction (anything else is C2S uplink).
///
/// Only application-data records (empty content-type column) are kept — the
/// handshake records are the camouflage layer, not the data plane we compare.
/// Returns an error string on malformed input rather than panicking so the
/// caller can decide whether a missing fixture is fatal.
pub fn load_trace(path: impl AsRef<Path>, server_port: &str) -> Result<Trace, String> {
    let text = std::fs::read_to_string(path.as_ref())
        .map_err(|e| format!("read {}: {e}", path.as_ref().display()))?;
    parse_tsv(&text, server_port)
}

/// Load the control-frame fixture.
pub fn load_fixture() -> Result<Trace, String> {
    load_trace(SAFARI_TCP_FIXTURE, SAFARI_TCP_SERVER_PORT)
}

/// Load the big-POST (full-record) fixture.
pub fn load_bigpost() -> Result<Trace, String> {
    load_trace(SAFARI_BIGPOST_FIXTURE, SAFARI_BIGPOST_SERVER_PORT)
}

fn parse_tsv(text: &str, server_port: &str) -> Result<Trace, String> {
    let mut records = Vec::new();
    let mut t0: Option<f64> = None;

    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 6 {
            continue; // tolerate short/odd rows
        }
        let time: f64 = cols[1]
            .parse()
            .map_err(|_| format!("line {}: bad time {:?}", lineno + 1, cols[1]))?;
        let src_port = cols[3];
        let content_types = cols[4];
        let record_lengths = cols[5];

        let dir = if src_port == server_port {
            Dir::S2C
        } else {
            Dir::C2S
        };

        // Split the per-segment record lists. content_types may be shorter than
        // record_lengths (empty string ⇒ all application-data); align by index
        // and treat a missing/empty type as application-data.
        let types: Vec<&str> = if content_types.is_empty() {
            Vec::new()
        } else {
            content_types.split(',').collect()
        };
        for (idx, len_str) in record_lengths.split(',').enumerate() {
            let len_str = len_str.trim();
            if len_str.is_empty() {
                continue;
            }
            let ctype = types.get(idx).copied().unwrap_or("");
            // Keep only application-data: empty type (opaque) is app-data; an
            // explicit "23" would be too, but this capture never labels it.
            if !ctype.is_empty() {
                continue; // handshake / ccs / alert record — skip
            }
            let len: u32 = match len_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            if t0.is_none() {
                t0 = Some(time);
            }
            let t_micros = ((time - t0.unwrap()) * 1_000_000.0).round().max(0.0) as u64;
            records.push(Record { len, dir, t_micros });
        }
    }

    if records.is_empty() {
        return Err("no application-data records parsed from TSV".into());
    }
    Ok(Trace::new(records))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_directions_and_appdata() {
        // Two app-data records (empty type), one handshake (type 22 skipped).
        let tsv = "1\t10.000000\t1.2.3.4\t33760\t\t100,200\t320\n\
                   2\t10.001000\t5.6.7.8\t443\t22\t1500\t1520\n\
                   3\t10.002000\t5.6.7.8\t443\t\t4096\t4116\n";
        let trace = parse_tsv(tsv, "443").unwrap();
        // 100, 200 (C2S) + 4096 (S2C) = 3 app-data records; the 1500 handshake
        // record (type 22) is skipped.
        assert_eq!(trace.len(), 3);
        assert_eq!(trace.dir(Dir::C2S).len(), 2);
        assert_eq!(trace.dir(Dir::S2C).len(), 1);
        // First record anchors t=0.
        assert_eq!(trace.records[0].t_micros, 0);
    }
}
