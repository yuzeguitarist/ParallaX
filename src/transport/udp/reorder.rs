//! Bounded, sequence-keyed reorder buffer for the receive side of the UDP fast
//! plane.
//!
//! The UDP leg delivers records out of order, possibly duplicated (a record may
//! arrive on UDP and again as a TCP reinjection) or with gaps (a lost datagram
//! that will be reinjected on TCP). The receiver feeds every arriving record
//! here keyed by its global per-direction `seq`, then drains them in strict
//! `seq` order to the AEAD codec, which opens records sequentially. A gap stalls
//! the drain until the missing seq arrives (head-of-line blocking at the record
//! layer — the price of in-order AEAD), and the demote-to-TCP machinery fills
//! the gap by reinjecting the missing record. The buffer is hard-bounded so a
//! lossy or malicious peer that withholds a low seq while flooding high ones
//! cannot exhaust memory.
#![allow(dead_code)] // Wired into the UDP datapath in the next slice; exercised by tests now.

use std::collections::BTreeMap;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ReorderError {
    #[error("reorder buffer capacity exceeded ({records} records / {bytes} bytes pending)")]
    CapacityExceeded { records: usize, bytes: usize },
}

/// Delivers records in `seq` order despite out-of-order arrival, with hard
/// bounds on the count and total size of buffered out-of-order records.
pub(crate) struct ReorderBuffer {
    /// The next sequence number to deliver. Records with `seq < next_seq` were
    /// already delivered and are dropped as duplicates.
    next_seq: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    pending_bytes: usize,
    max_records: usize,
    max_bytes: usize,
}

impl ReorderBuffer {
    pub(crate) fn new(start_seq: u64, max_records: usize, max_bytes: usize) -> Self {
        Self {
            next_seq: start_seq,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            max_records: max_records.max(1),
            max_bytes: max_bytes.max(1),
        }
    }

    pub(crate) fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Accepts a received record. Returns `Ok(true)` if it was buffered,
    /// `Ok(false)` if it was a duplicate (already delivered, or already
    /// buffered) and ignored. If buffering would exceed either bound the record
    /// is rejected with [`ReorderError::CapacityExceeded`] and the buffer is left
    /// UNCHANGED — the caller must then demote/tear down rather than silently
    /// drop a record it cannot later deliver in order.
    pub(crate) fn insert(&mut self, seq: u64, record: Vec<u8>) -> Result<bool, ReorderError> {
        if seq < self.next_seq || self.pending.contains_key(&seq) {
            return Ok(false);
        }
        let projected_records = self.pending.len() + 1;
        let projected_bytes = self.pending_bytes + record.len();
        if projected_records > self.max_records || projected_bytes > self.max_bytes {
            return Err(ReorderError::CapacityExceeded {
                records: projected_records,
                bytes: projected_bytes,
            });
        }
        self.pending_bytes += record.len();
        self.pending.insert(seq, record);
        Ok(true)
    }

    /// Pops the next in-order record if it has arrived, advancing `next_seq`.
    /// Returns `None` when there is a gap (the next seq has not arrived yet).
    /// Drain contiguous runs by calling this in a loop until it returns `None`.
    pub(crate) fn pop_next(&mut self) -> Option<Vec<u8>> {
        let record = self.pending.remove(&self.next_seq)?;
        self.pending_bytes -= record.len();
        // Saturating: next_seq is a monotonic u64; only an extreme start_seq could
        // drive it to u64::MAX, where wrapping back to 0 would corrupt the
        // seq < next_seq duplicate check. Saturate to stay panic-free under
        // overflow-checks. Caught by the udp_reorder fuzz target before this
        // buffer was wired into the datapath.
        self.next_seq = self.next_seq.saturating_add(1);
        Some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(buf: &mut ReorderBuffer) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(r) = buf.pop_next() {
            out.push(r);
        }
        out
    }

    #[test]
    fn delivers_in_order_arrivals_immediately() {
        let mut buf = ReorderBuffer::new(0, 16, 1 << 16);
        assert!(buf.insert(0, b"a".to_vec()).unwrap());
        assert_eq!(drain(&mut buf), vec![b"a".to_vec()]);
        assert!(buf.insert(1, b"b".to_vec()).unwrap());
        assert_eq!(drain(&mut buf), vec![b"b".to_vec()]);
        assert_eq!(buf.next_seq(), 2);
    }

    #[test]
    fn buffers_out_of_order_until_the_gap_fills() {
        let mut buf = ReorderBuffer::new(0, 16, 1 << 16);
        // seq 1 and 2 arrive before seq 0 — nothing is deliverable yet.
        assert!(buf.insert(2, b"c".to_vec()).unwrap());
        assert!(buf.insert(1, b"b".to_vec()).unwrap());
        assert!(buf.pop_next().is_none());
        assert_eq!(buf.pending_len(), 2);
        // seq 0 (the gap) arrives — now 0,1,2 drain contiguously in order.
        assert!(buf.insert(0, b"a".to_vec()).unwrap());
        assert_eq!(
            drain(&mut buf),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
        assert_eq!(buf.next_seq(), 3);
        assert_eq!(buf.pending_len(), 0);
        assert_eq!(buf.pending_bytes(), 0);
    }

    #[test]
    fn ignores_already_delivered_and_buffered_duplicates() {
        let mut buf = ReorderBuffer::new(5, 16, 1 << 16);
        // Stale: below next_seq (already delivered, e.g. a TCP reinjection of a
        // record UDP already delivered).
        assert!(!buf.insert(3, b"stale".to_vec()).unwrap());
        // Fresh out-of-order record, then a duplicate of it.
        assert!(buf.insert(6, b"x".to_vec()).unwrap());
        assert!(!buf.insert(6, b"x-dup".to_vec()).unwrap());
        assert_eq!(buf.pending_len(), 1);
    }

    #[test]
    fn rejects_over_capacity_without_mutating() {
        // Record-count bound.
        let mut buf = ReorderBuffer::new(0, 2, 1 << 16);
        assert!(buf.insert(1, b"a".to_vec()).unwrap());
        assert!(buf.insert(2, b"b".to_vec()).unwrap());
        let err = buf.insert(3, b"c".to_vec()).unwrap_err();
        assert!(matches!(
            err,
            ReorderError::CapacityExceeded { records: 3, .. }
        ));
        assert_eq!(buf.pending_len(), 2, "rejected insert must not mutate");

        // Byte bound.
        let mut buf = ReorderBuffer::new(0, 16, 4);
        assert!(buf.insert(1, vec![0; 3]).unwrap());
        let err = buf.insert(2, vec![0; 3]).unwrap_err();
        assert!(matches!(
            err,
            ReorderError::CapacityExceeded { bytes: 6, .. }
        ));
        assert_eq!(
            buf.pending_bytes(),
            3,
            "rejected insert must not change byte count"
        );
    }

    /// Property test (seeded, no extra deps): for many random arrival orders —
    /// shuffled, with duplicates sprinkled in — the buffer must reconstruct the
    /// records in EXACT seq order, deliver each exactly once, and return its
    /// accounting to zero. This is the fail-safe contract for untrusted,
    /// reorderable, duplicating network input: never a wrong-but-accepted order.
    #[test]
    fn random_permutations_reconstruct_in_order() {
        use rand::seq::SliceRandom;
        use rand::{rngs::StdRng, Rng, SeedableRng};

        for seed in 0..200u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let n: u64 = rng.gen_range(1..=64);
            // Distinct, variable-length content per seq so any misorder, drop, or
            // duplicate delivery is detectable in the reconstructed stream.
            let records: Vec<Vec<u8>> = (0..n)
                .map(|s| vec![(s & 0xff) as u8; (s as usize % 7) + 1])
                .collect();

            // Arrival order: a shuffle of 0..n with extra duplicate arrivals.
            let mut arrivals: Vec<u64> = (0..n).collect();
            arrivals.shuffle(&mut rng);
            for _ in 0..rng.gen_range(0..=n) {
                let dup = rng.gen_range(0..n);
                let pos = rng.gen_range(0..=arrivals.len());
                arrivals.insert(pos, dup);
            }

            // Bounds sized so the ordering property is isolated from the capacity
            // path (capacity rejection is covered by its own test): peak pending
            // is at most n when seq 0 arrives last.
            let mut buf = ReorderBuffer::new(0, n as usize, 1 << 20);
            let mut delivered: Vec<Vec<u8>> = Vec::new();
            for seq in arrivals {
                // Duplicates return Ok(false); a capacity error must never happen
                // with these bounds, so unwrap is a real invariant check.
                buf.insert(seq, records[seq as usize].clone()).unwrap();
                while let Some(record) = buf.pop_next() {
                    delivered.push(record);
                }
            }

            assert_eq!(delivered, records, "seed {seed}: reconstruct 0..n in order");
            assert_eq!(buf.next_seq(), n, "seed {seed}: next_seq advances to n");
            assert_eq!(buf.pending_len(), 0, "seed {seed}: nothing left pending");
            assert_eq!(
                buf.pending_bytes(),
                0,
                "seed {seed}: byte accounting clears"
            );
        }
    }
}
