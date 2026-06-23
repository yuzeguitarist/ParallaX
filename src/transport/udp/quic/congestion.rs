//! Congestion control (RFC 9002 §7 + the BBR algorithm), clean-room.
//!
//! The [`Controller`] trait is the connection↔CC seam: the connection feeds each
//! ACK's outcome (newly-acked bytes, the latest RTT, a delivery-rate sample, and
//! bytes-in-flight) and gates its send budget on [`Controller::window`] minus
//! bytes-in-flight. One controller lives behind it:
//!
//! - [`Bbr`] — a clean-room BBRv1 (Cardwell et al. / draft-cardwell-iccrg-bbr):
//!   a model of the path (bottleneck bandwidth × round-trip propagation) drives a
//!   window of `gain × BDP`, and — crucially for the cross-border links this UDP
//!   leg exists for — it does NOT collapse the window on random loss the way
//!   Cubic/Reno do. This is the shipping controller.
//!
//! This is endpoint-local (peers need not agree on a CC — RFC 9002 / the `mod.rs`
//! camouflage note: CC is performance, not fingerprint). Pacing (sending at
//! `pacing_gain × BtlBw` rather than purely cwnd-gated) is a later refinement; this
//! slice is cwnd-based, which already gives BBR's loss-resilience.

use std::time::{Duration, Instant};

/// RFC 9002 §7.2 sender constants (fixed MTU; MTU discovery is out of scope).
const MAX_DATAGRAM_SIZE: u64 = 1200;
/// Initial window: `min(10*mss, max(2*mss, 14720))` (RFC 9002 §7.2) = 12000.
const INITIAL_WINDOW: u64 = 10 * MAX_DATAGRAM_SIZE;

/// The outcome of one received ACK, fed to the congestion controller.
#[derive(Debug, Clone, Copy)]
pub struct AckInfo {
    /// When the ACK was processed.
    pub now: Instant,
    /// Newly-acknowledged ack-eliciting bytes.
    pub bytes_acked: u64,
    /// The latest RTT sample (RFC 9002 §5).
    pub rtt: Duration,
    /// Delivery-rate sample in bytes/sec (0 if not measurable this ACK).
    pub delivery_rate: u64,
    /// Bytes still in flight after this ACK.
    pub in_flight: u64,
    /// Connection-wide cumulative delivered bytes after this ACK (BBR round count).
    pub delivered: u64,
    /// The sender was application-limited (not cwnd-limited) — suppresses growth.
    pub app_limited: bool,
}

/// A congestion controller behind the connection↔CC seam.
pub trait Controller: Send {
    /// Fold in one ACK's outcome.
    fn on_ack(&mut self, info: &AckInfo);
    /// A congestion signal (declared loss / ECN-CE) at `now` — the caller collapses
    /// a loss batch into a single call.
    fn on_congestion_event(&mut self, now: Instant);
    /// The current congestion window, in bytes.
    fn window(&self) -> u64;
}

/// BBR's high gain `2/ln(2) ≈ 2.885`: the startup pacing/cwnd gain that doubles the
/// sending rate each round until the pipe is full (Cardwell et al.).
const BBR_HIGH_GAIN: f64 = 2.885;
/// Steady-state cwnd gain in ProbeBW (two BDPs of headroom).
const BBR_CWND_GAIN: f64 = 2.0;
/// Minimum cwnd (4 packets), used as the floor and during ProbeRTT (RFC/draft).
const BBR_MIN_PIPE_CWND: u64 = 4 * MAX_DATAGRAM_SIZE;
/// RTprop min-filter window: re-take the minimum RTT at least this often.
const BBR_RTPROP_WINDOW: Duration = Duration::from_secs(10);
/// How often to dip into ProbeRTT to re-measure RTprop.
const BBR_PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);
/// How long a ProbeRTT dip holds cwnd at the floor.
const BBR_PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
/// BtlBw must grow by ≥25% per round during Startup, or the pipe is deemed full.
const BBR_FULL_BW_THRESHOLD: f64 = 1.25;
/// Rounds without ≥25% BtlBw growth before declaring the pipe full.
const BBR_FULL_BW_COUNT: u32 = 3;
/// Length of the BtlBw max-filter (rounds).
const BBR_BTLBW_FILTER_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BbrMode {
    Startup,
    ProbeBw,
    ProbeRtt,
}

/// Clean-room BBRv1 (cwnd-based). Models the path as bottleneck bandwidth
/// (`BtlBw`, a max-filter of delivery-rate samples) × round-trip propagation
/// (`RTprop`, a min-filter of RTT), and sizes the window at `gain × BDP`. It does
/// not reduce the window on loss — the property that keeps cross-border throughput
/// up where Cubic/Reno collapse.
#[derive(Debug, Clone)]
pub struct Bbr {
    mode: BbrMode,
    cwnd: u64,
    /// Bottleneck bandwidth estimate (bytes/sec), the max over the round filter.
    btlbw: u64,
    /// Per-round max delivery-rate samples (a sliding max-filter).
    rate_filter: [u64; BBR_BTLBW_FILTER_LEN],
    filter_idx: usize,
    round_rate_max: u64,
    /// Round-trip propagation estimate (min RTT), with its sample time.
    rtprop: Duration,
    rtprop_stamp: Option<Instant>,
    /// Round counting: a round ends when `delivered` passes this mark.
    next_round_delivered: u64,
    /// Startup full-pipe detection.
    filled_pipe: bool,
    full_bw: u64,
    full_bw_count: u32,
    /// ProbeRTT scheduling.
    last_probe_rtt: Option<Instant>,
    probe_rtt_done: Option<Instant>,
    prior_cwnd: u64,
}

impl Default for Bbr {
    fn default() -> Self {
        Self::new()
    }
}

impl Bbr {
    pub fn new() -> Self {
        Self {
            mode: BbrMode::Startup,
            cwnd: INITIAL_WINDOW,
            btlbw: 0,
            rate_filter: [0; BBR_BTLBW_FILTER_LEN],
            filter_idx: 0,
            round_rate_max: 0,
            rtprop: Duration::ZERO,
            rtprop_stamp: None,
            next_round_delivered: 0,
            filled_pipe: false,
            full_bw: 0,
            full_bw_count: 0,
            last_probe_rtt: None,
            probe_rtt_done: None,
            prior_cwnd: INITIAL_WINDOW,
        }
    }

    /// Bandwidth-delay product in bytes (0 until both estimates exist).
    fn bdp(&self) -> u64 {
        (self.btlbw as f64 * self.rtprop.as_secs_f64()) as u64
    }

    /// Fold the delivery-rate sample into the per-round max + the immediate max.
    fn update_btlbw(&mut self, rate: u64) {
        if rate > self.round_rate_max {
            self.round_rate_max = rate;
        }
        if rate > self.btlbw {
            self.btlbw = rate;
        }
    }

    /// Advance the round filter at a round boundary and run Startup detection.
    fn on_round_start(&mut self, now: Instant) {
        self.rate_filter[self.filter_idx] = self.round_rate_max;
        self.filter_idx = (self.filter_idx + 1) % BBR_BTLBW_FILTER_LEN;
        self.round_rate_max = 0;
        self.btlbw = self.rate_filter.iter().copied().max().unwrap_or(0);

        if !self.filled_pipe {
            if self.btlbw as f64 >= self.full_bw as f64 * BBR_FULL_BW_THRESHOLD {
                self.full_bw = self.btlbw;
                self.full_bw_count = 0;
            } else {
                self.full_bw_count += 1;
                if self.full_bw_count >= BBR_FULL_BW_COUNT {
                    self.filled_pipe = true;
                    self.mode = BbrMode::ProbeBw;
                    // Seed the ProbeRTT clock when the pipe first fills, so the first
                    // dip is deferred ~BBR_PROBE_RTT_INTERVAL rather than firing on
                    // this very ack (which would stall cwnd to 4 packets the instant
                    // we reach full bandwidth).
                    self.last_probe_rtt = Some(now);
                }
            }
        }
    }

    fn update_rtprop(&mut self, rtt: Duration, now: Instant) {
        if rtt.is_zero() {
            return;
        }
        let expired = self
            .rtprop_stamp
            .map_or(true, |s| now.duration_since(s) > BBR_RTPROP_WINDOW);
        if self.rtprop.is_zero() || rtt < self.rtprop || expired {
            self.rtprop = rtt;
            self.rtprop_stamp = Some(now);
        }
    }

    /// Enter/exit ProbeRTT to re-measure RTprop with a near-empty pipe.
    fn check_probe_rtt(&mut self, now: Instant, in_flight: u64) {
        match self.mode {
            BbrMode::ProbeRtt => {
                // Arm the 200ms timer only once the pipe has actually drained to the
                // floor, so RTprop is re-measured at a near-empty pipe (not while
                // queueing still inflates the RTT). Until then cwnd stays at the floor.
                if self.probe_rtt_done.is_none() && in_flight <= BBR_MIN_PIPE_CWND {
                    self.probe_rtt_done = Some(now + BBR_PROBE_RTT_DURATION);
                }
                if self.probe_rtt_done.is_some_and(|d| now >= d) {
                    self.last_probe_rtt = Some(now);
                    self.probe_rtt_done = None;
                    self.cwnd = self.prior_cwnd;
                    self.mode = if self.filled_pipe {
                        BbrMode::ProbeBw
                    } else {
                        BbrMode::Startup
                    };
                }
            }
            _ => {
                let due = self
                    .last_probe_rtt
                    .map_or(true, |t| now.duration_since(t) >= BBR_PROBE_RTT_INTERVAL);
                // Only probe once we have a model worth re-measuring against.
                if due && self.filled_pipe {
                    self.prior_cwnd = self.cwnd;
                    self.mode = BbrMode::ProbeRtt;
                    // Arm the timer later, after the pipe drains (see above).
                    self.probe_rtt_done = None;
                }
            }
        }
    }

    fn set_cwnd(&mut self, bytes_acked: u64) {
        if self.mode == BbrMode::ProbeRtt {
            self.cwnd = BBR_MIN_PIPE_CWND;
            return;
        }
        let bdp = self.bdp();
        if bdp == 0 {
            // Bootstrap before the model exists: grow like slow start so the first
            // RTTs ramp up and produce delivery-rate samples.
            self.cwnd = (self.cwnd + bytes_acked).max(BBR_MIN_PIPE_CWND);
            return;
        }
        let gain = if self.mode == BbrMode::Startup {
            BBR_HIGH_GAIN
        } else {
            BBR_CWND_GAIN
        };
        let target = (gain * bdp as f64) as u64;
        self.cwnd = target.max(BBR_MIN_PIPE_CWND);
    }
}

impl Controller for Bbr {
    fn on_ack(&mut self, info: &AckInfo) {
        self.update_rtprop(info.rtt, info.now);
        // An app-limited sample (the sender ran out of data, not bandwidth) must not
        // raise the bottleneck-bandwidth estimate or advance the round model, or BBR
        // would lock in an under-estimate of the path (RFC draft / AckInfo contract).
        if !info.app_limited {
            self.update_btlbw(info.delivery_rate);
            if info.delivered >= self.next_round_delivered {
                // ~one window of data per round (a cheap proxy for one RTT).
                self.next_round_delivered = info.delivered + self.cwnd.max(MAX_DATAGRAM_SIZE);
                self.on_round_start(info.now);
            }
        }
        self.check_probe_rtt(info.now, info.in_flight);
        self.set_cwnd(info.bytes_acked);
    }

    fn on_congestion_event(&mut self, _now: Instant) {
        // BBR does NOT multiplicatively reduce cwnd on loss: its model (BtlBw ×
        // RTprop) already bounds the window, and treating random cross-border loss
        // as congestion is exactly the Cubic failure mode this controller avoids.
    }

    fn window(&self) -> u64 {
        self.cwnd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A delivery-rate sample at a known RTT yields `cwnd ≈ gain × BDP`.
    fn bbr_ack(rate: u64, rtt_ms: u64, delivered: u64, now: Instant) -> AckInfo {
        AckInfo {
            now,
            bytes_acked: MAX_DATAGRAM_SIZE,
            rtt: Duration::from_millis(rtt_ms),
            delivery_rate: rate,
            in_flight: 0,
            delivered,
            app_limited: false,
        }
    }

    #[test]
    fn bbr_starts_at_the_initial_window() {
        assert_eq!(Bbr::new().window(), 12_000);
    }

    #[test]
    fn bbr_does_not_collapse_the_window_on_loss() {
        // The defining property vs Cubic/Reno: a loss event must NOT shrink cwnd.
        let now = Instant::now();
        let mut cc = Bbr::new();
        // Ramp the model up with a few delivery-rate samples.
        let mut delivered = 0;
        for i in 0..40 {
            delivered += 100_000;
            cc.on_ack(&bbr_ack(
                10_000_000,
                50,
                delivered,
                now + Duration::from_millis(i * 50),
            ));
        }
        let before = cc.window();
        assert!(
            before > BBR_MIN_PIPE_CWND,
            "model lifted cwnd above the floor"
        );
        cc.on_congestion_event(now + Duration::from_secs(3));
        assert_eq!(
            cc.window(),
            before,
            "BBR must hold its window through a loss event (no Cubic-style collapse)"
        );
    }

    #[test]
    fn bbr_window_tracks_bandwidth_delay_product() {
        // 10 MB/s over a 50 ms RTprop ⇒ BDP = 500 KB; ProbeBW cwnd ≈ 2×BDP = 1 MB.
        let now = Instant::now();
        let mut cc = Bbr::new();
        let mut delivered = 0;
        // Plateau the bandwidth so Startup detects a full pipe and enters ProbeBW.
        for i in 0..40 {
            delivered += 500_000;
            cc.on_ack(&bbr_ack(
                10_000_000,
                50,
                delivered,
                now + Duration::from_millis(i * 50),
            ));
        }
        let bdp = 10_000_000 / 20; // bytes over 50 ms
        let cwnd = cc.window();
        assert!(
            cwnd >= bdp && cwnd <= 3 * bdp,
            "cwnd ({cwnd}) should be ~2×BDP ({bdp}) once the model is built",
        );
    }

    #[test]
    fn bbr_does_not_enter_probe_rtt_the_instant_the_pipe_fills() {
        // Regression for the immediate-ProbeRTT bug: with last_probe_rtt unseeded,
        // BBR entered ProbeRTT on the very ack that filled the pipe, pinning cwnd to
        // the 4-packet floor for 200 ms exactly when full bandwidth was reached.
        let now = Instant::now();
        let mut cc = Bbr::new();
        let mut delivered = 0;
        let mut checked = false;
        for i in 0..40 {
            delivered += 500_000;
            cc.on_ack(&bbr_ack(
                10_000_000,
                50,
                delivered,
                now + Duration::from_millis(i * 50),
            ));
            if cc.filled_pipe && !checked {
                checked = true;
                assert!(
                    cc.window() > BBR_MIN_PIPE_CWND,
                    "cwnd collapsed to the ProbeRTT floor the instant the pipe filled",
                );
            }
        }
        assert!(checked, "the pipe should fill within the run");
    }

    #[test]
    fn bbr_ignores_app_limited_samples_for_bandwidth() {
        // An app-limited ACK (sender out of data, not bandwidth) must not raise the
        // bottleneck-bandwidth model, even with a high reported delivery rate.
        let now = Instant::now();
        let mut cc = Bbr::new();
        let mut limited = bbr_ack(10_000_000, 50, 500_000, now);
        limited.app_limited = true;
        cc.on_ack(&limited);
        assert_eq!(
            cc.btlbw, 0,
            "app-limited samples must not raise the bottleneck-bandwidth estimate"
        );
    }
}
