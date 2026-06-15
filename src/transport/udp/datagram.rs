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

use crate::tls::record;

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
/// FEC and delivering each window's `FEC_K` records in seq order.
pub(crate) struct DatagramReceiver {
    fec: RsFec,
    symbol_len: usize,
    /// Base seq of the window currently being completed. Records below this have
    /// been delivered; sources/repairs for windows below this are stale.
    next_window_base: u64,
    /// Buffered source records (unpadded sealed bytes) by seq, for seqs in the
    /// current and look-ahead windows. Bounded by `max_pending_records`/`_bytes`.
    pending: BTreeMap<u64, Vec<u8>>,
    pending_bytes: usize,
    /// Repair symbols by `window_base -> repair_idx -> symbol` (each `symbol_len`).
    repairs: BTreeMap<u64, BTreeMap<u8, Vec<u8>>>,
    /// Completed records awaiting `pop_ready`, in seq order.
    ready: VecDeque<Vec<u8>>,
    /// One past the highest source seq ever seen (drives unrecoverability).
    high_water: u64,
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
            next_window_base: start_seq,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            repairs: BTreeMap::new(),
            ready: VecDeque::new(),
            high_water: start_seq,
            max_pending_records,
            max_pending_bytes,
        })
    }

    /// Ingest one datagram. May complete one or more windows (pushing their records
    /// onto the ready queue). Returns `Unrecoverable`/`CapacityExceeded` if the
    /// stream can no longer be reassembled (the leg turns this into a reset).
    pub(crate) fn ingest(&mut self, datagram: &[u8]) -> Result<(), DatagramError> {
        let (&tag, rest) = datagram.split_first().ok_or(DatagramError::Truncated)?;
        match tag {
            TAG_SOURCE => self.ingest_source(rest)?,
            TAG_REPAIR => self.ingest_repair(rest)?,
            other => return Err(DatagramError::BadTag(other)),
        }
        self.try_complete()
    }

    fn ingest_source(&mut self, body: &[u8]) -> Result<(), DatagramError> {
        let env = envelope::decode_prefix(body)?;
        let seq = env.seq;
        if seq >= self.high_water {
            self.high_water = seq.wrapping_add(1);
        }
        // Stale (already-delivered window) or duplicate: ignore.
        if seq < self.next_window_base || self.pending.contains_key(&seq) {
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
        // Stale window: ignore.
        if base < self.next_window_base {
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

    /// Complete as many consecutive windows as possible from the current state.
    fn try_complete(&mut self) -> Result<(), DatagramError> {
        loop {
            let base = self.next_window_base;
            let present_sources = (0..FEC_K as u64)
                .filter(|j| self.pending.contains_key(&(base + j)))
                .count();
            let repair_count = self.repairs.get(&base).map_or(0, |m| m.len());

            if present_sources == FEC_K {
                self.deliver_all_present(base);
            } else if present_sources + repair_count >= FEC_K {
                self.decode_and_deliver(base)?;
            } else if self.high_water >= base + FEC_K as u64 + REORDER_MARGIN {
                // The window is closed (we've seen well past it) yet has < FEC_K
                // symbols: its missing sources are lost for good.
                return Err(DatagramError::Unrecoverable(base));
            } else {
                break; // not yet completable; wait for more datagrams
            }
        }
        Ok(())
    }

    /// All `FEC_K` sources of the window arrived: deliver them in order, no FEC.
    fn deliver_all_present(&mut self, base: u64) {
        for j in 0..FEC_K as u64 {
            let rec = self
                .pending
                .remove(&(base + j))
                .expect("all present checked");
            self.pending_bytes -= rec.len();
            self.ready.push_back(rec);
        }
        self.drop_window_repairs(base);
        self.next_window_base = base + FEC_K as u64;
    }

    /// `< FEC_K` sources but enough total symbols: FEC-decode the window, deliver.
    fn decode_and_deliver(&mut self, base: u64) -> Result<(), DatagramError> {
        // Build the K+R `present` array: sources (padded) then repairs.
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
            let rec = match self.pending.remove(&seq) {
                // Prefer the original unpadded source if we had it.
                Some(orig) => {
                    self.pending_bytes -= orig.len();
                    orig
                }
                // Recovered source: trim the padded symbol to its own TLS record
                // length so FEC zero-padding never reaches the AEAD.
                None => trim_recovered(&sym, self.symbol_len)?,
            };
            self.ready.push_back(rec);
        }
        self.drop_window_repairs(base);
        self.next_window_base = base + FEC_K as u64;
        Ok(())
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
}
