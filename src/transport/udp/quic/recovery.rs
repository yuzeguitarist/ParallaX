//! Loss recovery (RFC 9002): RTT estimation, clean-room.
//!
//! Pure arithmetic over RTT samples — no IO, no clock reads (the caller supplies
//! the measured `rtt_sample`). The connection feeds samples on ACK and reads
//! [`RttEstimator::pto_base`] to arm the loss-detection / PTO timer. Sent-packet
//! accounting, loss detection, and the congestion controllers build on top in
//! later slices.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// RFC 9002 §6.2: the timer granularity (1 ms) flooring the PTO RTT-variance term.
const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
/// RFC 9002 §6.2.2: assumed RTT before the first sample.
pub const INITIAL_RTT: Duration = Duration::from_millis(333);

/// Smoothed-RTT estimator (RFC 9002 §5 / RFC 6298).
#[derive(Debug, Clone)]
pub struct RttEstimator {
    latest: Duration,
    smoothed: Option<Duration>,
    rttvar: Duration,
    min: Duration,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            latest: INITIAL_RTT,
            smoothed: None,
            rttvar: INITIAL_RTT / 2,
            min: Duration::ZERO,
        }
    }

    /// Fold in one RTT sample (RFC 9002 §5.3). `ack_delay` is the peer-reported
    /// delay, subtracted only when it keeps the sample at or above `min_rtt`.
    pub fn update(&mut self, ack_delay: Duration, rtt_sample: Duration) {
        self.latest = rtt_sample;
        let Some(smoothed) = self.smoothed else {
            // First sample (RFC 9002 §5.2): seed the estimator.
            self.min = rtt_sample;
            self.smoothed = Some(rtt_sample);
            self.rttvar = rtt_sample / 2;
            return;
        };
        self.min = self.min.min(rtt_sample);
        // Adjust for ack_delay only if the adjusted sample stays >= min_rtt.
        let adjusted = if rtt_sample >= self.min + ack_delay {
            rtt_sample - ack_delay
        } else {
            rtt_sample
        };
        // rttvar = 3/4 * rttvar + 1/4 * |smoothed - adjusted|
        let var_sample = if smoothed > adjusted {
            smoothed - adjusted
        } else {
            adjusted - smoothed
        };
        self.rttvar = (self.rttvar * 3 + var_sample) / 4;
        // smoothed = 7/8 * smoothed + 1/8 * adjusted
        self.smoothed = Some((smoothed * 7 + adjusted) / 8);
    }

    /// The smoothed RTT (or [`INITIAL_RTT`] before the first sample).
    pub fn smoothed(&self) -> Duration {
        self.smoothed.unwrap_or(INITIAL_RTT)
    }

    /// The most recent RTT sample.
    pub fn latest(&self) -> Duration {
        self.latest
    }

    /// The minimum RTT observed (RFC 9002 §5.2).
    pub fn min(&self) -> Duration {
        self.min
    }

    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    /// PTO base = `smoothed_rtt + max(4 * rttvar, granularity)` (RFC 9002 §6.2.1).
    /// The caller adds `max_ack_delay` for the Application packet-number space.
    pub fn pto_base(&self) -> Duration {
        self.smoothed() + (self.rttvar * 4).max(TIMER_GRANULARITY)
    }

    /// Time-threshold loss delay = `max(9/8 * max(smoothed, latest), granularity)`
    /// (RFC 9002 §6.1.2): a packet sent earlier than `now - loss_delay` is lost.
    pub fn loss_delay(&self) -> Duration {
        let base = self.smoothed().max(self.latest);
        (base * 9 / 8).max(TIMER_GRANULARITY)
    }
}

/// RFC 9002 §6.1.1 packet-reordering threshold: a packet is lost once a packet at
/// least this many numbers higher has been acknowledged.
const PACKET_THRESHOLD: u64 = 3;

/// One sent ack-eliciting-or-not packet awaiting acknowledgement (keyed by its
/// packet number in [`SentPackets`]).
#[derive(Debug, Clone)]
pub struct SentPacket {
    pub time_sent: Instant,
    pub size: u64,
    pub ack_eliciting: bool,
}

/// One packet-number space's sent-packet bookkeeping + RFC 9002 §6.1 loss
/// detection. The connection records each send, feeds received ACKs, and asks for
/// the packets to declare lost (and retransmit). Bytes-in-flight feed the
/// congestion controller.
#[derive(Debug, Default)]
pub struct SentPackets {
    packets: BTreeMap<u64, SentPacket>,
    largest_acked: Option<u64>,
    in_flight: u64,
}

impl SentPackets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an outgoing packet.
    pub fn on_sent(&mut self, pn: u64, sent: SentPacket) {
        // Only ack-eliciting packets count toward bytes-in-flight (RFC 9002 §2);
        // pure-ACK packets must not inflate congestion-window usage.
        if sent.ack_eliciting {
            self.in_flight += sent.size;
        }
        self.packets.insert(pn, sent);
    }

    /// Total bytes of unacknowledged in-flight packets (for the CC window gate).
    pub fn in_flight(&self) -> u64 {
        self.in_flight
    }

    pub fn largest_acked(&self) -> Option<u64> {
        self.largest_acked
    }

    /// Apply an ACK: drop the acknowledged packets and return them (newly-acked,
    /// for RTT + congestion-control feedback). `ranges` are inclusive `[low, high]`.
    pub fn on_ack(&mut self, largest: u64, ranges: &[(u64, u64)]) -> Vec<(u64, SentPacket)> {
        self.largest_acked = Some(self.largest_acked.map_or(largest, |l| l.max(largest)));
        let mut acked = Vec::new();
        for &(low, high) in ranges {
            let keys: Vec<u64> = self.packets.range(low..=high).map(|(&k, _)| k).collect();
            for k in keys {
                if let Some(p) = self.packets.remove(&k) {
                    if p.ack_eliciting {
                        self.in_flight = self.in_flight.saturating_sub(p.size);
                    }
                    acked.push((k, p));
                }
            }
        }
        acked
    }

    /// Declare lost packets (RFC 9002 §6.1): a packet below `largest_acked` is lost
    /// when a packet ≥ `pn + PACKET_THRESHOLD` is acked (packet threshold) OR it was
    /// sent at or before `now - loss_delay` (time threshold). Returns the lost
    /// `(pn, packet)` and the earliest future time-threshold deadline (to arm the
    /// loss timer), if any packets remain only-time-threshold-eligible.
    pub fn detect_lost(
        &mut self,
        loss_delay: Duration,
        now: Instant,
    ) -> (Vec<(u64, SentPacket)>, Option<Instant>) {
        let Some(largest) = self.largest_acked else {
            return (Vec::new(), None);
        };
        let lost_send_time = now.checked_sub(loss_delay);
        let mut lost = Vec::new();
        let mut loss_time: Option<Instant> = None;
        let candidates: Vec<u64> = self.packets.range(..largest).map(|(&k, _)| k).collect();
        for k in candidates {
            let p = &self.packets[&k];
            let by_packet = largest >= k.saturating_add(PACKET_THRESHOLD);
            let by_time = lost_send_time.is_some_and(|t| p.time_sent <= t);
            if by_packet || by_time {
                let p = self.packets.remove(&k).expect("candidate still present");
                if p.ack_eliciting {
                    self.in_flight = self.in_flight.saturating_sub(p.size);
                }
                lost.push((k, p));
            } else {
                let deadline = p.time_sent + loss_delay;
                loss_time = Some(loss_time.map_or(deadline, |lt| lt.min(deadline)));
            }
        }
        (lost, loss_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn before_any_sample_uses_rfc_defaults() {
        let rtt = RttEstimator::new();
        assert_eq!(rtt.smoothed(), INITIAL_RTT);
        // PTO base = 333 + max(4 * 166.5, 1) = 333 + 666 = 999 ms.
        assert_eq!(rtt.pto_base(), Duration::from_millis(999));
    }

    #[test]
    fn first_sample_seeds_smoothed_var_and_min() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::ZERO, Duration::from_millis(100));
        assert_eq!(rtt.smoothed(), Duration::from_millis(100));
        assert_eq!(rtt.rttvar(), Duration::from_millis(50));
        assert_eq!(rtt.min(), Duration::from_millis(100));
        // PTO = 100 + max(4 * 50, 1) = 300 ms.
        assert_eq!(rtt.pto_base(), Duration::from_millis(300));
    }

    #[test]
    fn second_sample_follows_the_rfc9002_ewma() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::ZERO, Duration::from_millis(100));
        rtt.update(Duration::ZERO, Duration::from_millis(200));
        // adjusted = 200; rttvar = (3*50 + |100-200|)/4 = 62.5; smoothed = (7*100+200)/8 = 112.5.
        assert_eq!(rtt.smoothed(), Duration::from_micros(112_500));
        assert_eq!(rtt.rttvar(), Duration::from_micros(62_500));
        assert_eq!(rtt.min(), Duration::from_millis(100));
    }

    #[test]
    fn ack_delay_is_subtracted_only_above_min_rtt() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::ZERO, Duration::from_millis(100)); // min = 100
                                                                // sample 120, ack_delay 10: 120 >= 100 + 10, so adjusted = 110.
        rtt.update(Duration::from_millis(10), Duration::from_millis(120));
        // smoothed = (7*100 + 110)/8 = 101.25 ms.
        assert_eq!(rtt.smoothed(), Duration::from_micros(101_250));

        // A sample that would dip below min after subtracting ack_delay is NOT
        // adjusted: min stays 100, sample 105, ack_delay 20 -> 105 < 120 -> use 105.
        let mut rtt2 = RttEstimator::new();
        rtt2.update(Duration::ZERO, Duration::from_millis(100));
        rtt2.update(Duration::from_millis(20), Duration::from_millis(105));
        // smoothed = (7*100 + 105)/8 = 100.625 ms (adjusted == raw 105).
        assert_eq!(rtt2.smoothed(), Duration::from_micros(100_625));
    }

    #[test]
    fn min_rtt_tracks_the_smallest_sample() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::ZERO, Duration::from_millis(100));
        rtt.update(Duration::ZERO, Duration::from_millis(60));
        rtt.update(Duration::ZERO, Duration::from_millis(80));
        assert_eq!(rtt.min(), Duration::from_millis(60));
    }

    #[test]
    fn loss_delay_is_nine_eighths_of_rtt() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::ZERO, Duration::from_millis(80)); // smoothed = latest = 80
        assert_eq!(rtt.loss_delay(), Duration::from_millis(90)); // 9/8 * 80
    }

    fn sent(now: Instant) -> SentPacket {
        SentPacket {
            time_sent: now,
            size: 1200,
            ack_eliciting: true,
        }
    }

    fn lost_pns(lost: &[(u64, SentPacket)]) -> Vec<u64> {
        lost.iter().map(|(k, _)| *k).collect()
    }

    #[test]
    fn on_ack_removes_acked_and_tracks_in_flight() {
        let now = Instant::now();
        let mut sp = SentPackets::new();
        for pn in 0..5 {
            sp.on_sent(pn, sent(now));
        }
        assert_eq!(sp.in_flight(), 5 * 1200);
        let acked = sp.on_ack(4, &[(3, 4)]);
        assert_eq!(acked.len(), 2, "pn 3 and 4 acknowledged");
        assert_eq!(sp.in_flight(), 3 * 1200);
        assert_eq!(sp.largest_acked(), Some(4));
    }

    #[test]
    fn non_ack_eliciting_packets_are_not_in_flight() {
        let now = Instant::now();
        let mut sp = SentPackets::new();
        sp.on_sent(
            0,
            SentPacket {
                time_sent: now,
                size: 1200,
                ack_eliciting: false,
            },
        );
        assert_eq!(sp.in_flight(), 0, "a pure-ACK packet does not count in flight");
        sp.on_sent(
            1,
            SentPacket {
                time_sent: now,
                size: 1200,
                ack_eliciting: true,
            },
        );
        assert_eq!(sp.in_flight(), 1200, "only the ack-eliciting packet counts");
        // Acking the non-ack-eliciting packet must not decrement in_flight below
        // what its ack-eliciting siblings hold.
        sp.on_ack(0, &[(0, 0)]);
        assert_eq!(sp.in_flight(), 1200);
    }

    #[test]
    fn detect_lost_by_packet_threshold() {
        let now = Instant::now();
        let mut sp = SentPackets::new();
        for pn in 0..5 {
            sp.on_sent(pn, sent(now));
        }
        sp.on_ack(4, &[(4, 4)]); // only pn 4 acked
                                 // A huge loss_delay disables the time threshold; only the packet threshold
                                 // fires: largest(4) >= pn + 3 ⇒ pn <= 1.
        let (lost, _) = sp.detect_lost(Duration::from_secs(3600), now);
        assert_eq!(lost_pns(&lost), vec![0, 1]);
    }

    #[test]
    fn detect_lost_by_time_threshold_only() {
        let now = Instant::now();
        let later = now + Duration::from_millis(100);
        let mut sp = SentPackets::new();
        sp.on_sent(0, sent(now)); // old packet
        sp.on_sent(2, sent(later)); // acked; largest 2 < 0+3 so pn0 is NOT packet-lost
        sp.on_ack(2, &[(2, 2)]);
        let (lost, _) = sp.detect_lost(Duration::from_millis(10), later);
        assert_eq!(lost_pns(&lost), vec![0], "pn 0 lost by time threshold only");
    }

    #[test]
    fn detect_lost_arms_loss_time_for_not_yet_lost() {
        let now = Instant::now();
        let mut sp = SentPackets::new();
        sp.on_sent(0, sent(now));
        sp.on_sent(2, sent(now));
        sp.on_ack(2, &[(2, 2)]);
        // pn 0: 2 < 0+3 (no packet threshold) and just sent (no time threshold yet).
        let (lost, loss_time) = sp.detect_lost(Duration::from_secs(1), now);
        assert!(lost.is_empty());
        assert_eq!(loss_time, Some(now + Duration::from_secs(1)));
    }
}
