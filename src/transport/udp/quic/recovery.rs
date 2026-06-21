//! Loss recovery (RFC 9002): RTT estimation, clean-room.
//!
//! Pure arithmetic over RTT samples — no IO, no clock reads (the caller supplies
//! the measured `rtt_sample`). The connection feeds samples on ACK and reads
//! [`RttEstimator::pto_base`] to arm the loss-detection / PTO timer. Sent-packet
//! accounting, loss detection, and the congestion controllers build on top in
//! later slices.

use std::time::Duration;

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
}
