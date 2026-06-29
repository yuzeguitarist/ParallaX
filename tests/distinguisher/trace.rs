//! Unified intermediate representation for a traffic trace.
//!
//! Every source — the real Safari capture (tshark TSV) and the live ParallaX
//! loopback tap — normalises to a [`Trace`]: an ordered list of TLS
//! application-data records, each carrying its on-wire payload length, its
//! direction, and a relative arrival time in microseconds. This matches the
//! `tls.record.length` / `tcp.srcport` / `frame.time_relative` columns that
//! `~/Desktop/safari-tcp/analyze_packetization.py` already operates on, so the
//! two corpora are byte-for-byte comparable in the same units.
//!
//! Like the GFW simulator's [`burst_statistics`], a trace records *ciphertext
//! record lengths only* — never plaintext. The ParallaX tap reads the cleartext
//! 5-byte TLS record header (`record::parse_header`) and never decrypts.

/// Direction of a record relative to the censored client.
///
/// `C2S` is the client→server (uplink) direction — for Safari this is the real
/// browser's own record sizing, which is the behaviour ParallaX must imitate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dir {
    /// Client → server (uplink). The direction we care most about imitating.
    C2S,
    /// Server → client (downlink).
    S2C,
}

/// A single TLS application-data record on the wire.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Record {
    /// On-wire TLS record payload length (the record `length` field), in bytes.
    /// This is the encrypted length and is observable without decryption.
    pub len: u32,
    /// Direction relative to the client.
    pub dir: Dir,
    /// Relative arrival time in microseconds from the first record in the trace.
    pub t_micros: u64,
}

/// An ordered sequence of records, sorted by arrival time.
#[derive(Debug, Clone, Default)]
pub struct Trace {
    pub records: Vec<Record>,
}

impl Trace {
    pub fn new(mut records: Vec<Record>) -> Self {
        records.sort_by_key(|r| r.t_micros);
        Trace { records }
    }

    /// Records in one direction only, preserving order.
    pub fn dir(&self, dir: Dir) -> Vec<Record> {
        self.records
            .iter()
            .copied()
            .filter(|r| r.dir == dir)
            .collect()
    }

    /// Lengths in one direction (the primary length-distribution sample).
    pub fn lengths(&self, dir: Dir) -> Vec<f64> {
        self.records
            .iter()
            .filter(|r| r.dir == dir)
            .map(|r| r.len as f64)
            .collect()
    }

    /// Inter-arrival times (microseconds) between consecutive records in one
    /// direction. Length-1 or empty samples yield an empty vector.
    pub fn iats(&self, dir: Dir) -> Vec<f64> {
        let ts: Vec<u64> = self
            .records
            .iter()
            .filter(|r| r.dir == dir)
            .map(|r| r.t_micros)
            .collect();
        ts.windows(2).map(|w| (w[1] - w[0]) as f64).collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}
