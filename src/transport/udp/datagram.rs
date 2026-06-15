//! Windowed forward-error-corrected datagram carrier protocol (logic only; the
//! quinn `Leg` wrappers live in `leg.rs`). Crypto-agnostic: it frames, reorders,
//! and FEC-recovers opaque *sealed* AEAD record bytes and never opens them.
//!
//! WHY windowed, delivered window-at-a-time: QUIC datagrams are not retransmitted
//! (RFC 9221), so a lost datagram is a permanent seq gap. We group `FEC_K`
//! consecutive sealed records into a window and send `FEC_R` repair symbols after
//! it, so any `FEC_R` losses in the window recover. The receiver delivers a window
//! ONLY once all `FEC_K` sources are present (directly or via FEC) — never the
//! contiguous-prefix-as-it-arrives — because to FEC-decode a late gap it needs the
//! window's earlier sources still buffered; delivering them early would discard the
//! symbols the decoder needs. Latency cost: up to one window.
//!
//! SAFETY (生死项): symbols are post-seal CIPHERTEXT, so a recovered symbol is the
//! byte-identical sealed record that would have arrived; it opens at its own seq
//! with no (key,nonce) reuse. A wrong recovery (should be impossible for a correct
//! decode) is caught by the AEAD tag when the relay opens it, and the gap demotes —
//! never silent corruption. The recovered record is trimmed to its own TLS record
//! length (`record::parse_header().total_len`), so FEC zero-padding never reaches
//! the AEAD. Every length/count from the wire is bounds-checked; buffers are
//! capacity-bounded (anti-exhaustion); unrecoverable gaps return an error the leg
//! turns into a non-clean-close (reset → demote to the reliable carrier).
//!
//! Not yet wired into a leg (the `Leg` impls + relay wiring are a later slice);
//! kept behind `#![allow(dead_code)]` like `envelope`/`reorder`/`fec`.
#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;

use crate::tls::record;
use crate::transport::leg::{LegReader, LegWriter, QuicStreamLegReader, QuicStreamLegWriter};

use super::envelope::{self, EnvelopeError};
use super::fec::{FecError, RsFec};

/// Source symbols per FEC window.
pub(crate) const FEC_K: usize = 32;
/// Repair symbols per FEC window (~12.5% overhead). Internal constant, not a
/// deploy-time knob; adaptive k/r is a real-network-tuned v2 upgrade.
pub(crate) const FEC_R: usize = 4;

/// Datagram type tags (first byte).
const TAG_SOURCE: u8 = 0x00;
const TAG_REPAIR: u8 = 0x01;

/// Repair datagram header: `[tag u8][window_base u64][repair_idx u8]` then the
/// fixed-length symbol. (`k`/`r`/`symbol_len` are matched-binary constants/config,
/// not sent on the wire.)
const REPAIR_HEADER_LEN: usize = 1 + 8 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatagramError {
    /// A datagram was shorter than its declared framing.
    Truncated,
    /// Unknown type tag.
    BadTag(u8),
    /// A source record / repair symbol had an impossible length for this carrier.
    BadLength,
    /// Pending reorder/repair state hit its capacity bound: treat as an
    /// unrecoverable gap (the leg resets → demotes), never grow unbounded.
    CapacityExceeded,
    /// Window starting at this seq can never reach `FEC_K` symbols (its stragglers
    /// are lost beyond the reorder margin): the relay must reset/demote.
    Unrecoverable(u64),
    /// Internal FEC error (e.g. a decode of a window that turned out singular —
    /// impossible for the Cauchy code, handled rather than panicking).
    Fec(FecError),
}

impl From<FecError> for DatagramError {
    fn from(e: FecError) -> Self {
        DatagramError::Fec(e)
    }
}

impl From<EnvelopeError> for DatagramError {
    fn from(_: EnvelopeError) -> Self {
        DatagramError::Truncated
    }
}

/// Encodes a stream of sealed records (pushed in contiguous seq order) into
/// datagrams: one source datagram per record, plus `FEC_R` repair datagrams each
/// time a `FEC_K`-record window completes.
pub(crate) struct DatagramSender {
    fec: RsFec,
    /// Fixed FEC symbol length = the largest sealed record the carrier permits
    /// (the relay clamps `max_plaintext_len` so every sealed record fits). All
    /// window symbols (sources padded, repairs) are this length.
    symbol_len: usize,
    /// Padded source symbols accumulating for the current window (len < FEC_K).
    window: Vec<Vec<u8>>,
    /// Seq of `window[0]` (the current window's base); valid when `!window.is_empty()`.
    window_base: u64,
    /// Next seq expected by `push` (contiguity guard).
    next_seq: u64,
}

impl DatagramSender {
    pub(crate) fn new(start_seq: u64, symbol_len: usize) -> Result<Self, DatagramError> {
        if symbol_len == 0 || symbol_len > record::MAX_TLS_RECORD_PAYLOAD + record::TLS_HEADER_LEN {
            return Err(DatagramError::BadLength);
        }
        Ok(Self {
            fec: RsFec::new(FEC_K, FEC_R)?,
            symbol_len,
            window: Vec::with_capacity(FEC_K),
            window_base: start_seq,
            next_seq: start_seq,
        })
    }

    /// One past the last seq pushed so far — the download-FIN count the writer
    /// sends so the receiver knows when the stream is complete.
    pub(crate) fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Push one sealed record (its seq MUST be the sender's `next_seq`). Returns the
    /// datagrams to send: always the source datagram, plus `FEC_R` repair datagrams
    /// when this record completes a window.
    pub(crate) fn push(&mut self, seq: u64, record: &[u8]) -> Result<Vec<Vec<u8>>, DatagramError> {
        if seq != self.next_seq {
            // The relay seals strictly in order, so a seq jump is a logic error,
            // not attacker input; fail closed rather than silently misframe.
            return Err(DatagramError::BadLength);
        }
        if record.len() > self.symbol_len {
            return Err(DatagramError::BadLength);
        }
        self.next_seq = self.next_seq.wrapping_add(1);

        let mut out = Vec::with_capacity(1 + FEC_R);
        // Source datagram: [TAG_SOURCE] ++ envelope(seq, record).
        let mut src = Vec::with_capacity(1 + envelope::ENVELOPE_HEADER_LEN + record.len());
        src.push(TAG_SOURCE);
        envelope::encode_into(seq, record, &mut src)?;
        out.push(src);

        // Accumulate the padded symbol for FEC.
        if self.window.is_empty() {
            self.window_base = seq;
        }
        let mut symbol = record.to_vec();
        symbol.resize(self.symbol_len, 0);
        self.window.push(symbol);

        if self.window.len() == FEC_K {
            let refs: Vec<&[u8]> = self.window.iter().map(|s| s.as_slice()).collect();
            let repairs = self.fec.encode(&refs, self.symbol_len)?;
            for (idx, sym) in repairs.into_iter().enumerate() {
                let mut dg = Vec::with_capacity(REPAIR_HEADER_LEN + sym.len());
                dg.push(TAG_REPAIR);
                dg.extend_from_slice(&self.window_base.to_be_bytes());
                dg.push(idx as u8);
                dg.extend_from_slice(&sym);
                out.push(dg);
            }
            self.window.clear();
        }
        Ok(out)
    }
}

/// Reassembles datagrams back into the sealed-record stream, recovering losses via
/// FEC. Delivers the contiguous prefix as soon as it is available (so interactive /
/// request-response flows are not held back), retaining each window's sources only
/// long enough to FEC-recover a later gap in the SAME window, then freeing them once
/// delivery has passed the window.
pub(crate) struct DatagramReceiver {
    fec: RsFec,
    symbol_len: usize,
    /// The window base of the very first record (windows are
    /// `[start_seq + nK, start_seq + (n+1)K)`).
    start_seq: u64,
    /// Next seq to deliver in order. Records below the CURRENT window's base have
    /// been delivered and freed; records in `[window_base(deliver_seq), deliver_seq)`
    /// are delivered but RETAINED in `pending` for FEC of a later gap in this window.
    deliver_seq: u64,
    /// Source records (unpadded sealed bytes) by seq: the current window's delivered
    /// records (retained for FEC) + look-ahead records past a gap. Bounded.
    pending: BTreeMap<u64, Vec<u8>>,
    pending_bytes: usize,
    /// Repair symbols by `window_base -> repair_idx -> symbol` (each `symbol_len`).
    repairs: BTreeMap<u64, BTreeMap<u8, Vec<u8>>>,
    /// Completed records awaiting `pop_ready`, in seq order.
    ready: VecDeque<Vec<u8>>,
    /// One past the highest source seq ever seen (drives unrecoverability).
    high_water: u64,
    /// One past the last source seq the sender will ever send (the download-FIN
    /// count), set via [`Self::set_final_seq`]. The window extending past it is the
    /// FINAL partial window (delivered contiguously, no FEC — the sender emits
    /// repairs only for full windows).
    final_seq: Option<u64>,
    max_pending_records: usize,
    max_pending_bytes: usize,
}

/// How far past a window's end (in seqs) we must have seen before declaring its
/// missing pieces lost — tolerates this many seqs of reordering. One full window.
const REORDER_MARGIN: u64 = FEC_K as u64;

impl DatagramReceiver {
    pub(crate) fn new(
        start_seq: u64,
        symbol_len: usize,
        max_pending_records: usize,
        max_pending_bytes: usize,
    ) -> Result<Self, DatagramError> {
        if symbol_len == 0 || symbol_len > record::MAX_TLS_RECORD_PAYLOAD + record::TLS_HEADER_LEN {
            return Err(DatagramError::BadLength);
        }
        Ok(Self {
            fec: RsFec::new(FEC_K, FEC_R)?,
            symbol_len,
            start_seq,
            deliver_seq: start_seq,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            repairs: BTreeMap::new(),
            ready: VecDeque::new(),
            high_water: start_seq,
            final_seq: None,
            max_pending_records,
            max_pending_bytes,
        })
    }

    /// The base seq of the window containing `seq`.
    fn window_base(&self, seq: u64) -> u64 {
        self.start_seq + ((seq - self.start_seq) / FEC_K as u64) * FEC_K as u64
    }

    /// The number of source records in the window at `base`: `FEC_K`, or the smaller
    /// tail count once the final count is known and this is the final window.
    fn window_k(&self, base: u64) -> usize {
        match self.final_seq {
            Some(fin) if base + FEC_K as u64 > fin => (fin - base) as usize,
            _ => FEC_K,
        }
    }

    /// Ingest one datagram, then deliver whatever became contiguously available.
    /// Returns `Unrecoverable`/`CapacityExceeded` if the stream can no longer be
    /// reassembled (the leg turns this into a reset).
    pub(crate) fn ingest(&mut self, datagram: &[u8]) -> Result<(), DatagramError> {
        let (&tag, rest) = datagram.split_first().ok_or(DatagramError::Truncated)?;
        match tag {
            TAG_SOURCE => self.ingest_source(rest)?,
            TAG_REPAIR => self.ingest_repair(rest)?,
            other => return Err(DatagramError::BadTag(other)),
        }
        self.try_deliver()
    }

    fn ingest_source(&mut self, body: &[u8]) -> Result<(), DatagramError> {
        let env = envelope::decode_prefix(body)?;
        let seq = env.seq;
        if seq >= self.high_water {
            self.high_water = seq.wrapping_add(1);
        }
        // Stale (window already passed + freed) or duplicate (still retained): ignore.
        if seq < self.window_base(self.deliver_seq) || self.pending.contains_key(&seq) {
            return Ok(());
        }
        let rec = body[env.record].to_vec();
        if rec.len() > self.symbol_len {
            return Err(DatagramError::BadLength);
        }
        if self.pending.len() >= self.max_pending_records
            || self.pending_bytes + rec.len() > self.max_pending_bytes
        {
            return Err(DatagramError::CapacityExceeded);
        }
        self.pending_bytes += rec.len();
        self.pending.insert(seq, rec);
        Ok(())
    }

    fn ingest_repair(&mut self, body: &[u8]) -> Result<(), DatagramError> {
        if body.len() < REPAIR_HEADER_LEN - 1 {
            return Err(DatagramError::Truncated);
        }
        let base = u64::from_be_bytes(body[0..8].try_into().expect("8 bytes checked"));
        let idx = body[8];
        let symbol = &body[9..];
        if symbol.len() != self.symbol_len || usize::from(idx) >= FEC_R {
            return Err(DatagramError::BadLength);
        }
        // Stale window (already delivered + freed): ignore.
        if base < self.window_base(self.deliver_seq) {
            return Ok(());
        }
        // Bound the repair store too (one entry per (window, idx); cap windows).
        let window_count = self.repairs.len();
        let slot = self.repairs.entry(base).or_default();
        if !slot.contains_key(&idx) {
            if window_count >= self.max_pending_records {
                self.repairs.remove(&base);
                return Err(DatagramError::CapacityExceeded);
            }
            if self.pending_bytes + symbol.len() > self.max_pending_bytes {
                if slot.is_empty() {
                    self.repairs.remove(&base);
                }
                return Err(DatagramError::CapacityExceeded);
            }
            self.pending_bytes += symbol.len();
            slot.insert(idx, symbol.to_vec());
        }
        Ok(())
    }

    /// Deliver the contiguous prefix, FEC-filling a gap when its window has enough
    /// symbols, until blocked (waiting for more) or done.
    fn try_deliver(&mut self) -> Result<(), DatagramError> {
        loop {
            // Deliver the contiguous prefix. Clone into `ready` but keep the record
            // in `pending` so a later gap in this window can still be FEC-decoded.
            while let Some(rec) = self.pending.get(&self.deliver_seq) {
                self.ready.push_back(rec.clone());
                self.deliver_seq += 1;
            }
            self.free_passed_windows();

            if self.final_seq.is_some_and(|fin| self.deliver_seq >= fin) {
                break; // every record delivered
            }

            // Gap at `deliver_seq`. Try to FEC-fill its window.
            let base = self.window_base(self.deliver_seq);
            let k = self.window_k(base);
            if self.try_fec_fill(base, k)? {
                continue; // filled — loop will deliver the now-contiguous run
            }
            // Cannot fill. A FULL window whose stragglers are lost beyond the reorder
            // margin is unrecoverable; the FINAL window is bounded by the leg's
            // post-FIN deadline instead (it has no FEC).
            let is_final_window = self.final_seq.is_some_and(|fin| base + FEC_K as u64 > fin);
            if !is_final_window && self.high_water >= base + FEC_K as u64 + REORDER_MARGIN {
                return Err(DatagramError::Unrecoverable(base));
            }
            break; // wait for more datagrams
        }
        Ok(())
    }

    /// If the window at `base` (with `k` sources) has `>= k` symbols, FEC-decode it
    /// and insert the recovered sources into `pending`. Returns whether it filled.
    /// A partial final window has no repairs, so this only fires for full windows.
    fn try_fec_fill(&mut self, base: u64, k: usize) -> Result<bool, DatagramError> {
        let present_sources = (0..k as u64)
            .filter(|j| self.pending.contains_key(&(base + j)))
            .count();
        let repair_count = self.repairs.get(&base).map_or(0, |m| m.len());
        if present_sources == k || present_sources + repair_count < k {
            // Either nothing missing (the gap is elsewhere / not yet arrived) or not
            // enough symbols to decode yet.
            return Ok(false);
        }
        // FEC operates on the fixed (FEC_K, FEC_R) code; a partial final window never
        // reaches here (it has no repairs, so present + 0 < k unless all present).
        debug_assert_eq!(k, FEC_K, "FEC fill only runs on full windows");
        let mut symbols: Vec<Option<Vec<u8>>> = Vec::with_capacity(FEC_K + FEC_R);
        for j in 0..FEC_K as u64 {
            match self.pending.get(&(base + j)) {
                Some(rec) => {
                    let mut sym = rec.clone();
                    sym.resize(self.symbol_len, 0);
                    symbols.push(Some(sym));
                }
                None => symbols.push(None),
            }
        }
        for i in 0..FEC_R as u8 {
            symbols.push(self.repairs.get(&base).and_then(|m| m.get(&i)).cloned());
        }
        let refs: Vec<Option<&[u8]>> = symbols.iter().map(|o| o.as_deref()).collect();
        let recovered = self.fec.decode(&refs, self.symbol_len)?;
        for (j, sym) in recovered.into_iter().enumerate() {
            let seq = base + j as u64;
            if self.pending.contains_key(&seq) {
                continue; // already had this source
            }
            // Recovered (lost) source: trim the padded symbol to its own TLS record
            // length so FEC zero-padding never reaches the AEAD.
            let rec = trim_recovered(&sym, self.symbol_len)?;
            self.pending_bytes += rec.len();
            self.pending.insert(seq, rec);
        }
        Ok(true)
    }

    /// Free sources + repairs of every window strictly below the current delivery
    /// window (they are delivered and no longer needed for FEC).
    fn free_passed_windows(&mut self) {
        let floor = self.window_base(self.deliver_seq);
        while let Some((&seq, _)) = self.pending.iter().next() {
            if seq >= floor {
                break;
            }
            let rec = self.pending.remove(&seq).expect("iterated key");
            self.pending_bytes -= rec.len();
        }
        while let Some((&base, _)) = self.repairs.iter().next() {
            if base >= floor {
                break;
            }
            self.drop_window_repairs(base);
        }
    }

    /// Record the download-FIN count (one past the last source seq the sender will
    /// send), then deliver whatever the now-known final window makes deliverable.
    pub(crate) fn set_final_seq(&mut self, one_past_last: u64) -> Result<(), DatagramError> {
        self.final_seq = Some(one_past_last);
        self.try_deliver()
    }

    /// Whether the final count is known AND every record up to it has been delivered.
    pub(crate) fn is_done(&self) -> bool {
        self.final_seq.is_some_and(|fin| self.deliver_seq >= fin)
    }

    fn drop_window_repairs(&mut self, base: u64) {
        if let Some(m) = self.repairs.remove(&base) {
            self.pending_bytes -= m.values().map(Vec::len).sum::<usize>();
        }
    }

    /// Pop the next completed record in seq order, if one is ready.
    pub(crate) fn pop_ready(&mut self) -> Option<Vec<u8>> {
        self.ready.pop_front()
    }

    pub(crate) fn has_ready(&self) -> bool {
        !self.ready.is_empty()
    }
}

/// Trim a recovered, zero-padded symbol to exactly one sealed TLS record using the
/// record's own header length — the length authority for a record we never saw an
/// envelope for. Rejects a symbol whose header claims more than it holds.
fn trim_recovered(symbol: &[u8], symbol_len: usize) -> Result<Vec<u8>, DatagramError> {
    let header = record::parse_header(symbol).map_err(|_| DatagramError::BadLength)?;
    if header.total_len > symbol_len || header.total_len > symbol.len() {
        return Err(DatagramError::BadLength);
    }
    Ok(symbol[..header.total_len].to_vec())
}

/// Fixed FEC symbol length for the datagram carrier — both ends MUST agree (a
/// repair symbol's length is matched-binary, not on the wire), so it is a constant
/// rather than the per-connection `max_datagram_size`. Chosen to leave room for the
/// datagram framing and QUIC overhead inside a conservative path MTU. The relay
/// clamps its seal `max_plaintext_len` so every sealed record fits, and the leg
/// refuses to select the datagram carrier unless `max_datagram_size` accommodates a
/// symbol plus framing.
pub(crate) const DATAGRAM_SYMBOL_LEN: usize = 1024;

/// The largest datagram either kind (source or repair) can occupy on the wire.
pub(crate) const MAX_CARRIER_DATAGRAM: usize =
    1 + envelope::ENVELOPE_HEADER_LEN + DATAGRAM_SYMBOL_LEN;

/// Download-carrier selector, written as the FIRST byte on the bidi download
/// stream (server→client) so the SENDER (server) decides and the receiver (client)
/// obeys — sidestepping any client/server disagreement over `max_datagram_size`.
/// The reliable bidi stream then carries the records (stream carrier) or, for the
/// datagram carrier, only the download-FIN count at teardown.
pub(crate) const CARRIER_STREAM: u8 = 0;
pub(crate) const CARRIER_DATAGRAM: u8 = 1;

/// Whether this connection can carry the datagram download: datagrams must fit a
/// full carrier datagram. (DATAGRAM_SYMBOL_LEN is sized to fit QUIC's minimum
/// path MTU, so this normally holds whenever the probe Verified.)
pub(crate) fn datagram_download_fits(conn: &quinn::Connection) -> bool {
    conn.max_datagram_size()
        .is_some_and(|m| m >= MAX_CARRIER_DATAGRAM)
}

/// Pending reorder bounds for the receiver (anti-exhaustion).
const RX_MAX_PENDING_RECORDS: usize = 8 * FEC_K;
const RX_MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;

fn map_datagram_err(e: DatagramError) -> io::Error {
    match e {
        // An unrecoverable gap is a mid-transfer truncation of the relay: surface
        // it as a non-clean error the relay turns into a reset (→ demote), NOT a
        // clean EOF.
        DatagramError::Unrecoverable(_) | DatagramError::CapacityExceeded => {
            io::Error::new(io::ErrorKind::ConnectionReset, "datagram gap unrecoverable")
        }
        other => io::Error::new(io::ErrorKind::InvalidData, format!("datagram: {other:?}")),
    }
}

/// Test-only counter of record bytes written through the datagram carrier. Lets
/// the relay e2e tests prove the download actually traversed datagrams rather than
/// silently falling back to the stream carrier. Not compiled in release.
#[cfg(test)]
pub(crate) static DATAGRAM_LEG_BYTES_WRITTEN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// QUIC-datagram record-writer leg (one direction). Frames each sealed record into
/// a source datagram + periodic FEC repair datagrams, and on `shutdown` writes the
/// download-FIN count over a reliable bidi stream so the reader knows the stream is
/// complete. Implements [`LegWriter`] so the existing generic relay loops drive it.
pub(crate) struct UdpDatagramLegWriter {
    conn: quinn::Connection,
    /// Reliable side-channel carrying only the 8-byte FIN count at teardown.
    fin: quinn::SendStream,
    sender: DatagramSender,
}

impl UdpDatagramLegWriter {
    pub(crate) fn new(
        conn: quinn::Connection,
        fin: quinn::SendStream,
        start_seq: u64,
    ) -> Result<Self, io::Error> {
        let sender =
            DatagramSender::new(start_seq, DATAGRAM_SYMBOL_LEN).map_err(map_datagram_err)?;
        Ok(Self { conn, fin, sender })
    }

    async fn send_all(&self, datagrams: Vec<Vec<u8>>) -> io::Result<()> {
        for dg in datagrams {
            // Wait for send-buffer space rather than letting quinn drop our own
            // source/repair datagrams (drop-old-on-full would manufacture losses).
            self.conn
                .send_datagram_wait(Bytes::from(dg))
                .await
                .map_err(|e| io::Error::other(format!("send_datagram: {e}")))?;
        }
        Ok(())
    }
}

impl LegWriter for UdpDatagramLegWriter {
    async fn write_records(&mut self, bytes: &[u8]) -> io::Result<()> {
        // No explicit base: the sender's own next_seq is the base for this batch.
        let base = self.sender.next_seq();
        self.write_records_seq(base, bytes).await
    }

    async fn write_records_seq(&mut self, base_seq: u64, bytes: &[u8]) -> io::Result<()> {
        debug_assert_eq!(
            base_seq,
            self.sender.next_seq(),
            "datagram base_seq must match the codec sequence",
        );
        let mut off = 0usize;
        let mut seq = base_seq;
        while off < bytes.len() {
            let header = record::parse_header(&bytes[off..]).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("tls record: {e}"))
            })?;
            let end = off
                .checked_add(header.total_len)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "record runs past buffer")
                })?;
            let datagrams = self
                .sender
                .push(seq, &bytes[off..end])
                .map_err(map_datagram_err)?;
            self.send_all(datagrams).await?;
            off = end;
            seq = seq.wrapping_add(1);
        }
        #[cfg(test)]
        DATAGRAM_LEG_BYTES_WRITTEN
            .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        // Reliable download-FIN: the one-past-last seq, so the reader knows exactly
        // how many records to expect before declaring a clean end-of-download.
        let fin_count = self.sender.next_seq();
        AsyncWriteExt::write_all(&mut self.fin, &fin_count.to_be_bytes()).await?;
        AsyncWriteExt::shutdown(&mut self.fin).await
    }
}

/// QUIC-datagram record-reader leg (one direction): reassembles the datagram
/// stream (reorder + FEC) and turns the reliable FIN into a clean EOF. A loss
/// beyond the window's redundancy, or a lost tail after the FIN, surfaces as a
/// non-clean error the relay turns into a reset (→ demote). Implements
/// [`LegReader`].
pub(crate) struct UdpDatagramLegReader {
    conn: quinn::Connection,
    receiver: DatagramReceiver,
    /// Resolves to the FIN count once the reliable side-channel delivers it.
    fin_rx: oneshot::Receiver<io::Result<u64>>,
    fin_seen: bool,
    /// After the FIN, the deadline by which the (possibly FEC-less) tail must
    /// complete; if it does not, the tail was lost → reset.
    fin_deadline: Option<Instant>,
}

impl UdpDatagramLegReader {
    pub(crate) fn new(
        conn: quinn::Connection,
        mut fin: quinn::RecvStream,
        start_seq: u64,
    ) -> Result<Self, io::Error> {
        let receiver = DatagramReceiver::new(
            start_seq,
            DATAGRAM_SYMBOL_LEN,
            RX_MAX_PENDING_RECORDS,
            RX_MAX_PENDING_BYTES,
        )
        .map_err(map_datagram_err)?;
        let (tx, fin_rx) = oneshot::channel();
        // Read the 8-byte FIN count off the reliable side-channel in the background
        // so the main read loop can select between datagrams and the FIN.
        tokio::spawn(async move {
            let mut buf = [0u8; 8];
            let result = match fin.read_exact(&mut buf).await {
                Ok(()) => Ok(u64::from_be_bytes(buf)),
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("fin: {e}"),
                )),
            };
            let _ = tx.send(result);
        });
        Ok(Self {
            conn,
            receiver,
            fin_rx,
            fin_seen: false,
            fin_deadline: None,
        })
    }

    /// Grace after the FIN for an in-flight (FEC-less) tail to arrive before the
    /// gap is declared lost. Scaled to the path RTT, floored for low-RTT links.
    fn tail_grace(&self) -> Duration {
        (self.conn.rtt() * 4).max(Duration::from_millis(200))
    }
}

impl LegReader for UdpDatagramLegReader {
    async fn read_record_into(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        loop {
            if let Some(rec) = self.receiver.pop_ready() {
                buf.clear();
                buf.extend_from_slice(&rec);
                return Ok(());
            }
            if self.receiver.is_done() {
                // Clean end-of-download: every record up to the FIN count delivered.
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            if let Some(deadline) = self.fin_deadline {
                tokio::select! {
                    biased;
                    dg = self.conn.read_datagram() => {
                        let bytes = dg.map_err(|e| {
                            io::Error::new(io::ErrorKind::ConnectionReset, format!("read_datagram: {e}"))
                        })?;
                        self.receiver.ingest(&bytes).map_err(map_datagram_err)?;
                    }
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        // Post-FIN grace expired with the tail still incomplete: the
                        // missing (FEC-less) tail record is lost → reset.
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "datagram download tail lost after FIN",
                        ));
                    }
                }
            } else {
                tokio::select! {
                    biased;
                    fin = &mut self.fin_rx, if !self.fin_seen => {
                        self.fin_seen = true;
                        let count = fin
                            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "fin channel closed"))??;
                        self.receiver.set_final_seq(count).map_err(map_datagram_err)?;
                        self.fin_deadline = Some(Instant::now() + self.tail_grace());
                    }
                    dg = self.conn.read_datagram() => {
                        let bytes = dg.map_err(|e| {
                            io::Error::new(io::ErrorKind::ConnectionReset, format!("read_datagram: {e}"))
                        })?;
                        self.receiver.ingest(&bytes).map_err(map_datagram_err)?;
                    }
                }
            }
        }
    }

    async fn try_read_record_into(&mut self, buf: &mut Vec<u8>) -> Option<io::Result<()>> {
        // The single-Connect download path uses the blocking `read_record_into`;
        // this opportunistic drain only ever returns an already-completed record (it
        // never waits on a datagram). The mux batch-drain that relies on a richer
        // try-read stays on the TCP/stream carrier.
        self.receiver.pop_ready().map(|rec| {
            buf.clear();
            buf.extend_from_slice(&rec);
            Ok(())
        })
    }

    fn is_clean_close(&self, err: &io::Error) -> bool {
        // Only the FIN-driven UnexpectedEof is clean; a ConnectionReset (gap/tail
        // loss/connection error) is a truncation that must NOT be swallowed.
        err.kind() == io::ErrorKind::UnexpectedEof
    }
}

/// The DOWNLOAD-direction writer the server picks once at relay setup, signaled to
/// the client by the carrier byte. An enum (not a trait object) so the monomorphic
/// generic relay loop has ONE concrete `LegWriter` type; this is a carrier
/// SELECTION (fixed for the relay's life), not a mid-relay demote switch.
pub(crate) enum DownloadWriter {
    Stream(QuicStreamLegWriter),
    Datagram(UdpDatagramLegWriter),
}

impl LegWriter for DownloadWriter {
    async fn write_records(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            DownloadWriter::Stream(w) => w.write_records(bytes).await,
            DownloadWriter::Datagram(w) => w.write_records(bytes).await,
        }
    }

    async fn write_records_seq(&mut self, base_seq: u64, bytes: &[u8]) -> io::Result<()> {
        match self {
            DownloadWriter::Stream(w) => w.write_records_seq(base_seq, bytes).await,
            DownloadWriter::Datagram(w) => w.write_records_seq(base_seq, bytes).await,
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            DownloadWriter::Stream(w) => w.shutdown().await,
            DownloadWriter::Datagram(w) => w.shutdown().await,
        }
    }
}

/// The DOWNLOAD-direction reader the client picks from the carrier byte. Mirror of
/// [`DownloadWriter`]: a fixed carrier selection unifying the relay loop's reader
/// type.
pub(crate) enum DownloadReader {
    Stream(QuicStreamLegReader),
    Datagram(UdpDatagramLegReader),
}

impl LegReader for DownloadReader {
    async fn read_record_into(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        match self {
            DownloadReader::Stream(r) => r.read_record_into(buf).await,
            DownloadReader::Datagram(r) => r.read_record_into(buf).await,
        }
    }

    async fn try_read_record_into(&mut self, buf: &mut Vec<u8>) -> Option<io::Result<()>> {
        match self {
            DownloadReader::Stream(r) => r.try_read_record_into(buf).await,
            DownloadReader::Datagram(r) => r.try_read_record_into(buf).await,
        }
    }

    fn is_clean_close(&self, err: &io::Error) -> bool {
        match self {
            DownloadReader::Stream(r) => r.is_clean_close(err),
            DownloadReader::Datagram(r) => r.is_clean_close(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use crate::crypto::session::{AeadCodec, KEY_LEN, NONCE_LEN};
    use crate::protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD};
    use crate::traffic::PaddingProfile;

    const SYMBOL_LEN: usize = 1200;
    const MAX_REC: usize = 8 * FEC_K;
    const MAX_BYTES: usize = 4 * 1024 * 1024;

    fn codec() -> DataRecordCodec {
        DataRecordCodec::new(
            AeadCodec::new([0x33; KEY_LEN], [0x44; NONCE_LEN]),
            PaddingProfile::new(0, 0).unwrap(),
            CLIENT_TO_SERVER_AAD,
        )
    }

    /// Seal `n` records of varying plaintext sizes starting at the codec's seq,
    /// returning (start_seq, sealed records, plaintexts).
    fn seal_stream(n: usize, seed: u64) -> (u64, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut c = codec();
        let mut rng = StdRng::seed_from_u64(seed);
        let start = 0u64; // a fresh codec starts at seq 0
        let mut sealed = Vec::new();
        let mut plain = Vec::new();
        for _ in 0..n {
            let len = rng.gen_range(1..400);
            let pt: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            sealed.push(c.seal(&pt, &mut rng).unwrap());
            plain.push(pt);
        }
        (start, sealed, plain)
    }

    /// Drive the sender, then feed the receiver under a drop oracle, and assert the
    /// receiver yields every original plaintext in order (opened on a matched codec).
    fn run(
        n: usize,
        seed: u64,
        drop_fn: impl Fn(usize, &[u8]) -> bool,
    ) -> Result<(), DatagramError> {
        let (start, sealed, plain) = seal_stream(n, seed);
        let mut sender = DatagramSender::new(start, SYMBOL_LEN).unwrap();
        let mut rx = DatagramReceiver::new(start, SYMBOL_LEN, MAX_REC, MAX_BYTES).unwrap();

        // Collect all datagrams the sender emits (in send order), tagged by index.
        let mut datagrams: Vec<Vec<u8>> = Vec::new();
        for (i, rec) in sealed.iter().enumerate() {
            for dg in sender.push(start + i as u64, rec).unwrap() {
                datagrams.push(dg);
            }
        }

        // Feed surviving datagrams to the receiver in send order.
        for (i, dg) in datagrams.iter().enumerate() {
            if drop_fn(i, dg) {
                continue;
            }
            rx.ingest(dg)?;
        }

        // Open every delivered record and compare to the originals.
        let mut open = codec();
        let mut got = Vec::new();
        while let Some(rec) = rx.pop_ready() {
            got.push(open.open(&rec).unwrap());
        }
        assert_eq!(got, plain, "delivered plaintexts must match in order");
        Ok(())
    }

    #[test]
    fn lossless_in_order_round_trips_every_record() {
        run(FEC_K * 3, 1, |_, _| false).unwrap();
    }

    /// Reordered (but complete) delivery still yields records in seq order: feed the
    /// datagrams of each window back-to-front.
    #[test]
    fn reordered_complete_delivery_is_in_order() {
        // Custom drive: reverse each chunk of (K+R) datagrams.
        let n = FEC_K * 2;
        let (start, sealed, plain) = seal_stream(n, 7);
        let mut sender = DatagramSender::new(start, SYMBOL_LEN).unwrap();
        let mut rx = DatagramReceiver::new(start, SYMBOL_LEN, MAX_REC, MAX_BYTES).unwrap();
        let mut dgs = Vec::new();
        for (i, rec) in sealed.iter().enumerate() {
            dgs.extend(sender.push(start + i as u64, rec).unwrap());
        }
        for chunk in dgs.chunks(FEC_K + FEC_R) {
            for dg in chunk.iter().rev() {
                rx.ingest(dg).unwrap();
            }
        }
        let mut open = codec();
        let mut got = Vec::new();
        while let Some(rec) = rx.pop_ready() {
            got.push(open.open(&rec).unwrap());
        }
        assert_eq!(got, plain);
    }

    /// THE keystone: dropping up to FEC_R datagrams per window recovers fully (FEC
    /// fills the gaps), so every record is delivered byte-exact and opens.
    #[test]
    fn recovers_up_to_r_losses_per_window() {
        // Drop the i-th datagram of every window of size (K+R) for i in 0..R — i.e.
        // up to R losses spread across each window. Use a couple of patterns.
        for pattern in 0..FEC_R {
            run(FEC_K * 3, 100 + pattern as u64, |i, _| {
                let pos = i % (FEC_K + FEC_R);
                // drop R distinct positions within each window
                pos < FEC_R && (pos + pattern) % FEC_R == 0 || pos == pattern
            })
            .unwrap_or_else(|e| panic!("pattern {pattern} should recover, got {e:?}"));
        }
    }

    /// Dropping a source AND relying on FEC to rebuild it: the rebuilt record opens
    /// under AEAD (the 生死项 ciphertext-composition through the whole carrier).
    #[test]
    fn fec_rebuilt_source_opens_under_aead() {
        // Drop exactly the first source datagram of the first window; its repair(s)
        // rebuild it.
        run(FEC_K, 200, |i, dg| {
            i == 0 && dg.first() == Some(&TAG_SOURCE)
        })
        .unwrap();
    }

    /// Losing MORE than FEC_R in a window is unrecoverable: the receiver surfaces
    /// Unrecoverable once it has seen past the window (the reset trigger), never
    /// wrong bytes, never an unbounded stall.
    #[test]
    fn beyond_r_losses_in_a_window_is_unrecoverable() {
        // Drop R+1 source datagrams of the FIRST window; keep everything after so
        // the high-water mark advances past the window and closes it.
        let n = FEC_K * 3;
        let err = run(n, 300, |i, dg| {
            // first window's source datagrams are interleaved as: each window is
            // K source datagrams then R repairs (sources at positions 0..K).
            dg.first() == Some(&TAG_SOURCE) && i < FEC_R + 1
        })
        .unwrap_err();
        match err {
            DatagramError::Unrecoverable(_) => {}
            other => panic!("expected Unrecoverable, got {other:?}"),
        }
    }

    /// A duplicated datagram is idempotent (no double-delivery, no corruption).
    #[test]
    fn duplicate_datagrams_are_idempotent() {
        let n = FEC_K;
        let (start, sealed, plain) = seal_stream(n, 9);
        let mut sender = DatagramSender::new(start, SYMBOL_LEN).unwrap();
        let mut rx = DatagramReceiver::new(start, SYMBOL_LEN, MAX_REC, MAX_BYTES).unwrap();
        let mut dgs = Vec::new();
        for (i, rec) in sealed.iter().enumerate() {
            dgs.extend(sender.push(start + i as u64, rec).unwrap());
        }
        for dg in &dgs {
            rx.ingest(dg).unwrap();
            rx.ingest(dg).unwrap(); // duplicate
        }
        let mut open = codec();
        let mut got = Vec::new();
        while let Some(rec) = rx.pop_ready() {
            got.push(open.open(&rec).unwrap());
        }
        assert_eq!(got, plain);
    }

    /// Capacity bound: a flood of out-of-window sources without the gap filling is
    /// rejected (CapacityExceeded) rather than growing unboundedly. A small record
    /// cap (below the reorder margin) makes the capacity path trip before the
    /// high-water unrecoverability would.
    #[test]
    fn pending_capacity_is_bounded() {
        let start = 0u64;
        let cap = 4usize;
        let mut rx = DatagramReceiver::new(start, SYMBOL_LEN, cap, 1024 * 1024).unwrap();
        // Feed sources just ABOVE the first window (seq >= K) so window 0 never
        // completes and they pile up in pending until the small cap trips — while
        // high_water stays below the unrecoverability margin (2*K).
        let mut c = codec();
        let mut rng = StdRng::seed_from_u64(11);
        let mut err = None;
        for j in 0..(cap as u64 + 3) {
            let rec = c.seal(b"x", &mut rng).unwrap();
            let mut dg = vec![TAG_SOURCE];
            envelope::encode_into(FEC_K as u64 + j, &rec, &mut dg).unwrap();
            if let Err(e) = rx.ingest(&dg) {
                err = Some(e);
                break;
            }
        }
        assert_eq!(err, Some(DatagramError::CapacityExceeded));
    }

    /// The partial tail (records past the last full FEC window) delivers
    /// contiguously as it arrives; `is_done` flips only once the FIN count is known
    /// and every record up to it has been delivered.
    #[test]
    fn final_partial_window_delivers_on_fin() {
        let n = FEC_K + 5; // one full window + a 5-record partial tail
        let (start, sealed, plain) = seal_stream(n, 13);
        let mut sender = DatagramSender::new(start, SYMBOL_LEN).unwrap();
        let mut rx = DatagramReceiver::new(start, SYMBOL_LEN, MAX_REC, MAX_BYTES).unwrap();
        let mut dgs = Vec::new();
        for (i, rec) in sealed.iter().enumerate() {
            dgs.extend(sender.push(start + i as u64, rec).unwrap());
        }
        for dg in &dgs {
            rx.ingest(dg).unwrap();
        }
        // Lossless + contiguous: every record (incl. the partial tail) is already
        // delivered; the FIN only flips is_done.
        assert!(!rx.is_done());
        rx.set_final_seq(start + n as u64).unwrap();
        assert!(rx.is_done());
        let mut open = codec();
        let mut got = Vec::new();
        while let Some(rec) = rx.pop_ready() {
            got.push(open.open(&rec).unwrap());
        }
        assert_eq!(got, plain);
    }

    /// A loss in the partial final window cannot be FEC-recovered (no repairs for a
    /// partial window), so the receiver never reports done — the leg's post-FIN
    /// deadline turns this into a reset rather than a silent truncation.
    #[test]
    fn final_partial_window_loss_is_not_deliverable() {
        let n = FEC_K + 5;
        let (start, sealed, _plain) = seal_stream(n, 17);
        let mut sender = DatagramSender::new(start, SYMBOL_LEN).unwrap();
        let mut rx = DatagramReceiver::new(start, SYMBOL_LEN, MAX_REC, MAX_BYTES).unwrap();
        for (i, rec) in sealed.iter().enumerate() {
            for dg in sender.push(start + i as u64, rec).unwrap() {
                // Drop the source datagram of the first partial-window record.
                if i == FEC_K && dg.first() == Some(&TAG_SOURCE) {
                    continue;
                }
                rx.ingest(&dg).unwrap();
            }
        }
        rx.set_final_seq(start + n as u64).unwrap();
        assert!(
            !rx.is_done(),
            "a lost final-partial-window source has no FEC and must not be reported delivered",
        );
    }

    /// End-to-end over a REAL quinn loopback connection: the download direction
    /// (server→client) carries sealed records as datagrams + FEC, with the FIN on
    /// the bidi stream's server→client half; the reader yields every record in order
    /// and turns the FIN into a clean EOF. Loopback does not drop, so this proves
    /// the quinn integration + FIN→EOF (loss recovery is covered deterministically
    /// by the protocol tests above).
    #[tokio::test]
    async fn datagram_leg_round_trips_over_real_quinn() {
        use crate::transport::leg::{LegReader, LegWriter};
        use crate::transport::udp::test_support::loopback_pair;

        let (_se, _ce, client_conn, server_conn) = loopback_pair().await;
        let start = 0u64;

        // Build the download payload: several full windows + a partial tail.
        let n = FEC_K * 2 + 7;
        let plaintexts: Vec<Vec<u8>> = {
            let mut rng = StdRng::seed_from_u64(0xD06);
            (0..n)
                .map(|_| {
                    let len = rng.gen_range(1..400);
                    (0..len).map(|_| rng.gen()).collect()
                })
                .collect()
        };

        let server_pts = plaintexts.clone();
        let server = tokio::spawn(async move {
            // Rendezvous: open the bidi stream and write a trigger on the upload
            // (server-recv) half so the client's accept_bi returns immediately; the
            // server→client half is the FIN channel.
            let (fin_send, mut up_recv) = server_conn.accept_bi().await.expect("accept_bi");
            // Drain the client's rendezvous trigger (upload half is unused here).
            let mut t = [0u8; 1];
            let _ = up_recv.read_exact(&mut t).await;

            let mut writer =
                UdpDatagramLegWriter::new(server_conn.clone(), fin_send, start).unwrap();
            let mut seal = codec();
            let mut rng = StdRng::seed_from_u64(0xD06);
            // Send in a few batches to exercise multi-batch base_seq handling.
            let mut seq = start;
            for chunk in server_pts.chunks(20) {
                let mut buf = Vec::new();
                for pt in chunk {
                    buf.extend_from_slice(&seal.seal(pt, &mut rng).unwrap());
                }
                writer.write_records_seq(seq, &buf).await.unwrap();
                seq += chunk.len() as u64;
            }
            writer.shutdown().await.unwrap();
            server_conn // keep the connection alive until the client is done
        });

        // Client: open the bidi stream, write the rendezvous trigger, then read the
        // download via the datagram leg.
        let (mut up_send, fin_recv) = client_conn.open_bi().await.expect("open_bi");
        tokio::io::AsyncWriteExt::write_all(&mut up_send, b"\x00")
            .await
            .unwrap();
        let mut reader = UdpDatagramLegReader::new(client_conn.clone(), fin_recv, start).unwrap();
        let mut open = codec();
        let mut got = Vec::new();
        let mut buf = Vec::new();
        loop {
            match reader.read_record_into(&mut buf).await {
                Ok(()) => got.push(open.open(&buf).unwrap()),
                Err(e) if reader.is_clean_close(&e) => break,
                Err(e) => panic!("unexpected leg error: {e}"),
            }
        }
        assert_eq!(
            got, plaintexts,
            "datagram leg must deliver every record in order"
        );
        let _server_conn = server.await.unwrap();
    }
}
