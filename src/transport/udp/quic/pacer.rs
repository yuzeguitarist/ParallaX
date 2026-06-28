//! Send pacing for the QUIC data plane.
//!
//! Smooths a full-window line-rate burst into a stream paced at the congestion
//! controller's target rate, so the send curve matches a real BBR stack instead
//! of cwnd-gated bursts. Purely additive: it only ever DELAYS a packet the cwnd
//! would already allow, never sends more, and is fully bypassed before a
//! bandwidth model exists, below the min rate, and while burst tokens remain —
//! so it cannot reduce throughput.

use std::time::{Duration, Instant};

/// Unpaced packets allowed back-to-back when leaving quiescence. A short burst
/// out of quiescence is what a real stack does and is what keeps pacing from
/// adding latency to interactive / bursty flows. Replenished whenever the pipe
/// is empty (nothing in flight).
const PACING_BURST_PACKETS: u32 = 10;

/// Below this pacing rate, do not pace at all — a single full-size datagram
/// already represents ~10ms of transmit time at this rate, so pacing buys
/// nothing and only risks under-utilizing the link. Mirrors quiche's
/// lumpy-pacing low-bandwidth bypass (~1.2 Mbps). 150_000 B/s ≈ 1.2 Mbit/s.
const PACING_MIN_RATE_BYTES_PER_SEC: u64 = 150_000;

/// Smooths a full-window line-rate burst into a stream paced at the congestion
/// controller's target rate (`bytes / pacing_rate` between packets). See the
/// module docs for the no-regression guarantees.
#[derive(Debug, Clone)]
pub(crate) struct Pacer {
    /// Earliest instant the next paced (ack-eliciting DATA) packet may be sent.
    /// `None` = no restriction (send immediately).
    next_send_time: Option<Instant>,
    /// Remaining unpaced "leaving quiescence" burst credit.
    burst_tokens: u32,
}

impl Pacer {
    pub(crate) fn new() -> Self {
        Self {
            next_send_time: None,
            burst_tokens: PACING_BURST_PACKETS,
        }
    }

    /// The earliest instant the next paced packet may be sent, or `None` when
    /// unpaced (send immediately).
    pub(crate) fn next_send_time(&self) -> Option<Instant> {
        self.next_send_time
    }

    /// May a paced DATA packet be sent at `now`? True if bursting, unpaced, or the
    /// pacing deadline has passed.
    pub(crate) fn can_send(&self, now: Instant) -> bool {
        if self.burst_tokens > 0 {
            return true;
        }
        // MSRV 1.80: `map_or(true, ...)` instead of the 1.82 `is_none_or`.
        self.next_send_time.map_or(true, |t| now >= t)
    }

    /// Account for one sent DATA packet of `size` bytes at rate `pacing_rate`
    /// (bytes/sec). `in_flight_before` is bytes in flight BEFORE this packet — zero
    /// means the connection just left quiescence, which replenishes the burst.
    pub(crate) fn on_sent(
        &mut self,
        now: Instant,
        size: usize,
        pacing_rate: u64,
        in_flight_before: u64,
    ) {
        // Leaving quiescence (idle → active): refill the burst so a bursty/interactive
        // flow is never throttled on its first packets.
        if in_flight_before == 0 {
            self.burst_tokens = PACING_BURST_PACKETS;
        }
        if self.burst_tokens > 0 {
            self.burst_tokens -= 1;
            // Spend the token. Only AFTER the last token is spent do we start pacing,
            // so arm the deadline now (rather than leaving it None) — otherwise the
            // first post-burst packet would also see `next_send_time == None` and slip
            // through unpaced, making the effective burst PACING_BURST_PACKETS + 1.
            if self.burst_tokens == 0 {
                self.next_send_time = self.armed_deadline(now, size, pacing_rate);
            } else {
                self.next_send_time = None;
            }
            return;
        }
        self.next_send_time = self.armed_deadline(now, size, pacing_rate);
    }

    /// The pacing deadline after sending a `size`-byte packet at `pacing_rate`: `None`
    /// (unpaced) before a model exists or below the min rate, else `base + size/rate`
    /// where `base = max(now, prior deadline)` so a late send cannot bank credit and
    /// then burst to catch up.
    fn armed_deadline(&self, now: Instant, size: usize, pacing_rate: u64) -> Option<Instant> {
        if pacing_rate == u64::MAX || pacing_rate < PACING_MIN_RATE_BYTES_PER_SEC {
            return None;
        }
        let delay = Duration::from_secs_f64(size as f64 / pacing_rate as f64);
        let base = self.next_send_time.map_or(now, |t| t.max(now));
        Some(base + delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_bursts_then_paces_then_bypasses() {
        let t0 = Instant::now();
        let mut pacer = Pacer::new();
        let rate = 1_000_000u64; // 1 MB/s, well above the low-bandwidth bypass
        let pkt = 1200usize;

        // Burst phase: EXACTLY PACING_BURST_PACKETS may send back-to-back at t0. Each
        // sends immediately; the deadline stays unset until the LAST token is spent,
        // which arms pacing so the very next packet is throttled (no off-by-one extra
        // unpaced packet).
        for i in 0..PACING_BURST_PACKETS {
            assert!(pacer.can_send(t0), "burst packet {i} sends immediately");
            pacer.on_sent(t0, pkt, rate, 1); // in_flight_before > 0 (not quiescence)
            if i + 1 < PACING_BURST_PACKETS {
                assert!(pacer.next_send_time.is_none(), "no deadline mid-burst");
            }
        }

        // The last burst token armed the deadline transfer_time ahead, so the NEXT
        // packet is already blocked — the burst is exactly PACING_BURST_PACKETS, not
        // one more.
        let deadline = pacer.next_send_time.expect("last burst token arms pacing");
        let expected = t0 + Duration::from_secs_f64(pkt as f64 / rate as f64);
        assert_eq!(deadline, expected, "deadline = transfer_time ahead");
        assert!(
            !pacer.can_send(t0),
            "the post-burst packet is blocked, no off-by-one"
        );
        assert!(pacer.can_send(deadline), "unblocked at the deadline");

        // The next paced send advances the deadline by another transfer_time.
        pacer.on_sent(deadline, pkt, rate, pkt as u64);
        let deadline2 = pacer.next_send_time.expect("still paced");
        assert_eq!(
            deadline2,
            deadline + Duration::from_secs_f64(pkt as f64 / rate as f64)
        );
        let deadline = deadline2;

        // Leaving quiescence (in_flight_before == 0) refills the burst → unpaced again.
        pacer.on_sent(deadline, pkt, rate, 0);
        assert!(pacer.can_send(deadline), "quiescence refilled the burst");

        // Unpaced sentinel and sub-min rate never arm a deadline (no-regression paths).
        let mut p2 = Pacer::new();
        for _ in 0..PACING_BURST_PACKETS {
            p2.on_sent(t0, pkt, u64::MAX, 1);
        }
        p2.on_sent(t0, pkt, u64::MAX, pkt as u64);
        assert!(p2.next_send_time.is_none(), "u64::MAX rate is unpaced");
        p2.on_sent(t0, pkt, PACING_MIN_RATE_BYTES_PER_SEC - 1, pkt as u64);
        assert!(p2.next_send_time.is_none(), "sub-min rate bypasses pacing");
    }
}
