//! QUIC send-behavior plausibility: does a QUIC flow pace like real HTTP/3?
//!
//! Real HTTP/3-over-QUIC is bursty: inter-packet gaps vary widely because they
//! follow application data availability and a congestion controller's cwnd
//! dynamics. A naive proxy fast-plane betrays itself with overly-regular timing
//! -- constant-rate FEC repair padding, or an aggressive "brutal" congestion
//! controller that sends at a fixed pace regardless of feedback. Such a flat,
//! low-variance cadence is statistically classifiable and does not occur in
//! ordinary H3.
//!
//! ParallaX's QUIC fast-plane is off by default and explicitly NOT H3-shaped, so
//! any future FEC (Track B / B2) or pacing change (B5) must keep the send
//! behavior inside the real-H3 envelope. This detector models the coarsest
//! discriminator -- pacing regularity, via the coefficient of variation (CV =
//! stddev/mean) of inter-packet gaps. Real H3 has a high CV (bursty); a
//! constant-rate sender has a CV near zero. It is a gate, not a full classifier:
//! a design that passes it has merely cleared the most obvious timing tell.

use std::time::Instant;

/// One observed outbound QUIC packet on a flow.
#[derive(Debug, Clone, Copy)]
pub struct QuicPacket {
    pub size: usize,
    pub at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QuicTimingVerdict {
    /// Inter-packet timing varies like real bursty HTTP/3.
    H3Like,
    /// Inter-packet gaps are too uniform -- the constant-rate FEC / brutal-CC
    /// tell that does not occur in ordinary H3.
    OverlyRegular { inter_arrival_cv: f64 },
}

pub struct QuicTimingDetector {
    /// Minimum coefficient of variation of inter-packet gaps for a flow to look
    /// like bursty H3. Below this the pacing is suspiciously flat.
    pub min_inter_arrival_cv: f64,
    /// Need at least this many packets before judging (too few = no signal).
    pub min_packets: usize,
}

impl Default for QuicTimingDetector {
    fn default() -> Self {
        Self {
            // Real H3 inter-arrival CV is well above 0.5; a constant-rate sender
            // sits near 0. 0.25 is a conservative floor that flags only clearly
            // flat pacing.
            min_inter_arrival_cv: 0.25,
            min_packets: 8,
        }
    }
}

impl QuicTimingDetector {
    pub fn evaluate(&self, packets: &[QuicPacket]) -> QuicTimingVerdict {
        if packets.len() < self.min_packets {
            return QuicTimingVerdict::H3Like;
        }
        let mut sorted: Vec<Instant> = packets.iter().map(|p| p.at).collect();
        sorted.sort();
        let gaps: Vec<f64> = sorted
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .collect();
        if gaps.is_empty() {
            return QuicTimingVerdict::H3Like;
        }
        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        if mean <= 0.0 {
            // All packets at the same instant: maximally regular (zero spread).
            return QuicTimingVerdict::OverlyRegular {
                inter_arrival_cv: 0.0,
            };
        }
        let variance = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
        let cv = variance.sqrt() / mean;
        if cv < self.min_inter_arrival_cv {
            QuicTimingVerdict::OverlyRegular {
                inter_arrival_cv: cv,
            }
        } else {
            QuicTimingVerdict::H3Like
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn flow(gaps_ms: &[u64]) -> Vec<QuicPacket> {
        let start = Instant::now();
        let mut at = start;
        let mut out = vec![QuicPacket { size: 1200, at }];
        for &g in gaps_ms {
            at += Duration::from_millis(g);
            out.push(QuicPacket { size: 1200, at });
        }
        out
    }

    #[test]
    fn bursty_h3_like_timing_is_clean() {
        // Variable gaps (app data + cwnd dynamics): high CV -> H3Like.
        let packets = flow(&[1, 0, 0, 18, 2, 1, 40, 0, 0, 3, 25, 1]);
        assert_eq!(
            QuicTimingDetector::default().evaluate(&packets),
            QuicTimingVerdict::H3Like
        );
    }

    #[test]
    fn constant_rate_pacing_is_flagged() {
        // A constant-rate sender (FEC padding / brutal CC): every gap identical,
        // CV ~ 0 -> OverlyRegular.
        let packets = flow(&[5; 12]);
        match QuicTimingDetector::default().evaluate(&packets) {
            QuicTimingVerdict::OverlyRegular { inter_arrival_cv } => {
                assert!(
                    inter_arrival_cv < 0.25,
                    "constant pacing must have near-zero CV, got {inter_arrival_cv}"
                );
            }
            other => panic!("expected OverlyRegular, got {other:?}"),
        }
    }

    #[test]
    fn too_few_packets_are_not_judged() {
        // Below min_packets there is no timing signal -- must not false-positive.
        let packets = flow(&[5, 5, 5]);
        assert_eq!(
            QuicTimingDetector::default().evaluate(&packets),
            QuicTimingVerdict::H3Like
        );
    }
}
