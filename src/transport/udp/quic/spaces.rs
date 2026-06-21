//! Packet-number space bookkeeping (RFC 9000 §12.3, §13.2), clean-room.
//!
//! Two pieces, both pure logic (no IO, no crypto):
//!
//! - [`PacketNumberSpace`]: the monotonic send-side packet-number allocator for
//!   one space (Initial / Handshake / 1-RTT). RFC 9000 §12.3 forbids reusing a
//!   packet number within a space and caps it at `2^62 - 1`.
//! - [`ReceivedPackets`]: the receive-side record of acknowledged packet numbers
//!   as a coalesced interval set. It does double duty — deduplicating replays
//!   (RFC 9000 §12.3) and generating the ACK ranges ([`crate::transport::udp::quic::frame::Ack`])
//!   that acknowledge them (RFC 9000 §19.3.1).
//!
//! ACK *timing* (max_ack_delay) and pruning below the peer's largest-acked are
//! recovery concerns (RFC 9002) layered on top later; this module only tracks
//! *which* packet numbers have been seen and emits the ranges.

use super::frame::Ack;

/// Largest representable packet number (RFC 9000 §12.3 / §17.1: a packet number
/// is a 62-bit value).
const MAX_PACKET_NUMBER: u64 = (1 << 62) - 1;

/// Upper bound on the number of stored received-packet ranges. A peer sending
/// deliberately gapped packet numbers (0, 2, 4, …) would otherwise grow the set
/// without limit (memory) and make every `insert` scan O(N) (CPU). When the cap
/// is exceeded we drop the lowest (oldest) range; those packet numbers stop being
/// acknowledged, which at worst prompts a retransmit.
const MAX_ACK_RANGES: usize = 32;

/// Monotonic send-side packet-number allocator for one packet-number space.
#[derive(Debug, Default)]
pub struct PacketNumberSpace {
    next: u64,
}

impl PacketNumberSpace {
    pub fn new() -> Self {
        Self { next: 0 }
    }

    /// Allocate the next packet number for an outgoing packet in this space.
    /// Panics only on the (unreachable in practice) 2^62 exhaustion, which RFC
    /// 9000 §12.3 requires the endpoint to treat as fatal rather than wrap.
    pub fn allocate(&mut self) -> u64 {
        let pn = self.next;
        assert!(pn <= MAX_PACKET_NUMBER, "packet-number space exhausted");
        self.next += 1;
        pn
    }

    /// The packet number the next [`allocate`](Self::allocate) will return.
    pub fn peek(&self) -> u64 {
        self.next
    }
}

/// The set of received packet numbers in one space, kept as a coalesced,
/// ascending, non-overlapping, non-adjacent interval set (each entry an inclusive
/// `[low, high]`, with ≥1 unreceived packet number between consecutive entries).
///
/// Typically holds a single range under no loss; reordering/loss splits it and
/// retransmits merge it back. Acknowledging is `O(ranges)`, which stays tiny.
#[derive(Debug, Default)]
pub struct ReceivedPackets {
    /// Ascending, disjoint, non-adjacent inclusive ranges.
    ranges: Vec<(u64, u64)>,
    /// Replay low-water mark: every packet number `<= low_water` is considered
    /// already received, even after its range was evicted by [`Self::enforce_cap`].
    /// Without this, evicting the lowest range would let a captured low-PN packet be
    /// replayed (re-refreshing the idle timer / re-feeding RTT+CC). RFC 9000 §13.2.3
    /// permits bounding the range set; below the watermark we fail safe to "duplicate".
    low_water: Option<u64>,
}

impl ReceivedPackets {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            low_water: None,
        }
    }

    /// Whether `pn` has already been recorded (a duplicate / replay).
    pub fn contains(&self, pn: u64) -> bool {
        self.low_water.is_some_and(|w| pn <= w)
            || self.ranges.iter().any(|&(lo, hi)| lo <= pn && pn <= hi)
    }

    /// True until the first packet is recorded.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The highest packet number recorded, if any.
    pub fn largest(&self) -> Option<u64> {
        self.ranges.last().map(|&(_, hi)| hi)
    }

    /// Record `pn` as received. Returns `true` if it was new, `false` if it was a
    /// duplicate (in which case the set is unchanged — the caller must drop the
    /// replayed packet without reprocessing it).
    pub fn insert(&mut self, pn: u64) -> bool {
        // Below the replay low-water mark: already received (range was evicted), so
        // treat as a duplicate and drop without reprocessing.
        if self.low_water.is_some_and(|w| pn <= w) {
            return false;
        }
        // Find the first range whose high is >= pn-1 (the earliest range pn could
        // touch or extend). A linear scan is fine — the set is tiny.
        let mut i = 0;
        while i < self.ranges.len() && self.ranges[i].1 + 1 < pn {
            i += 1;
        }
        if i == self.ranges.len() {
            // pn is beyond every range: append (it cannot be adjacent below since
            // the loop ran past the last range whose high+1 < pn).
            self.ranges.push((pn, pn));
            self.enforce_cap();
            return true;
        }
        let (lo, hi) = self.ranges[i];
        if lo <= pn && pn <= hi {
            return false; // duplicate
        }
        if pn + 1 == lo {
            // Adjacent below this range: extend it down.
            self.ranges[i].0 = pn;
        } else if hi + 1 == pn {
            // Adjacent above this range: extend it up, then maybe merge with next.
            self.ranges[i].1 = pn;
            if i + 1 < self.ranges.len() && self.ranges[i + 1].0 == pn + 1 {
                let next_hi = self.ranges[i + 1].1;
                self.ranges[i].1 = next_hi;
                self.ranges.remove(i + 1);
            }
        } else {
            // Strictly below this range with a gap: insert a new singleton.
            self.ranges.insert(i, (pn, pn));
            self.enforce_cap();
        }
        true
    }

    /// Bound the stored ranges (see [`MAX_ACK_RANGES`]); drops the lowest (oldest)
    /// range when the cap is exceeded. Each `insert` adds at most one range, so at
    /// most one range is dropped per call.
    fn enforce_cap(&mut self) {
        if self.ranges.len() > MAX_ACK_RANGES {
            let (_, hi) = self.ranges.remove(0);
            // Everything up to the evicted range's high is now considered received
            // (replay protection survives the eviction).
            self.low_water = Some(self.low_water.map_or(hi, |w| w.max(hi)));
        }
    }

    /// Build an ACK frame acknowledging everything recorded so far, with the given
    /// raw (already exponent-scaled) `ack_delay`. Returns `None` if nothing has
    /// been received. Ranges are emitted in the descending order the wire wants.
    pub fn to_ack(&self, ack_delay: u64) -> Option<Ack> {
        let &(_, largest) = self.ranges.last()?;
        let ranges: Vec<(u64, u64)> = self.ranges.iter().rev().copied().collect();
        Some(Ack {
            largest,
            delay: ack_delay,
            ranges,
            ecn: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::frame;
    use super::*;

    #[test]
    fn allocator_is_monotonic_from_zero() {
        let mut space = PacketNumberSpace::new();
        assert_eq!(space.peek(), 0);
        assert_eq!(space.allocate(), 0);
        assert_eq!(space.allocate(), 1);
        assert_eq!(space.allocate(), 2);
        assert_eq!(space.peek(), 3);
    }

    #[test]
    fn insert_dedups_replays() {
        let mut recv = ReceivedPackets::new();
        assert!(recv.insert(5));
        assert!(!recv.insert(5), "second insert of 5 is a duplicate");
        assert!(recv.contains(5));
        assert!(!recv.contains(4));
    }

    #[test]
    fn contiguous_inserts_coalesce_to_one_range() {
        let mut recv = ReceivedPackets::new();
        for pn in [0, 1, 2, 3, 4] {
            assert!(recv.insert(pn));
        }
        assert_eq!(recv.ranges, vec![(0, 4)]);
    }

    #[test]
    fn out_of_order_insert_fills_gap_and_merges() {
        let mut recv = ReceivedPackets::new();
        // Receive 0,1, then 3,4 (gap at 2), then 2 which bridges the two ranges.
        for pn in [0, 1, 3, 4] {
            recv.insert(pn);
        }
        assert_eq!(recv.ranges, vec![(0, 1), (3, 4)]);
        assert!(recv.insert(2));
        assert_eq!(
            recv.ranges,
            vec![(0, 4)],
            "2 bridges the gap into one range"
        );
    }

    #[test]
    fn descending_insert_extends_low_edge() {
        let mut recv = ReceivedPackets::new();
        for pn in [10, 9, 8] {
            recv.insert(pn);
        }
        assert_eq!(recv.ranges, vec![(8, 10)]);
        assert_eq!(recv.largest(), Some(10));
    }

    #[test]
    fn to_ack_emits_descending_ranges_that_re_encode() {
        let mut recv = ReceivedPackets::new();
        // Two disjoint ranges: [0,1] and [3,4].
        for pn in [0, 1, 3, 4] {
            recv.insert(pn);
        }
        let ack = recv.to_ack(25).unwrap();
        assert_eq!(ack.largest, 4);
        assert_eq!(ack.delay, 25);
        assert_eq!(ack.ranges, vec![(3, 4), (0, 1)]); // descending
                                                      // The emitted ACK survives an encode/decode round-trip through the codec.
        let mut buf = Vec::new();
        frame::Frame::Ack(ack.clone()).encode(&mut buf);
        let decoded = frame::Iter::new(&buf).next().unwrap().unwrap();
        assert_eq!(decoded, frame::Frame::Ack(ack));
    }

    #[test]
    fn to_ack_is_none_when_empty() {
        assert!(ReceivedPackets::new().to_ack(0).is_none());
    }

    #[test]
    fn received_ranges_are_capped_under_gappy_input() {
        let mut recv = ReceivedPackets::new();
        // 100 gapped packets (0, 2, 4, …) would otherwise create 100 singleton
        // ranges; the cap must bound the stored set.
        for k in 0..100u64 {
            recv.insert(k * 2);
        }
        assert!(
            recv.ranges.len() <= MAX_ACK_RANGES,
            "ranges must be capped at {MAX_ACK_RANGES}"
        );
        assert_eq!(recv.largest(), Some(198), "the newest packet is retained");
        // The capped set still produces a well-formed, codec-round-trippable ACK.
        let ack = recv.to_ack(0).unwrap();
        let mut buf = Vec::new();
        frame::Frame::Ack(ack.clone()).encode(&mut buf);
        assert_eq!(
            frame::Iter::new(&buf).next().unwrap().unwrap(),
            frame::Frame::Ack(ack)
        );
    }

    #[test]
    fn evicted_low_packets_stay_rejected_as_replays() {
        let mut recv = ReceivedPackets::new();
        // Force range eviction with a gappy stream so the lowest ranges are dropped.
        for k in 0..100u64 {
            recv.insert(k * 2);
        }
        assert!(recv.ranges.len() <= MAX_ACK_RANGES);
        // Packet 0 was evicted from the explicit ranges, but it WAS received — a
        // replay of it must still be rejected (not re-processed) via the low-water
        // mark, or the idle timer / RTT+CC could be re-fed by a captured old packet.
        assert!(
            recv.contains(0),
            "an evicted-but-received PN is still 'contained'"
        );
        assert!(
            !recv.insert(0),
            "replay of an evicted low packet is rejected, not treated as new"
        );
    }
}
