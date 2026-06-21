//! Congestion control (RFC 9002 §7), clean-room.
//!
//! The [`Controller`] trait is the connection↔CC seam; the connection gates its
//! send budget on [`Controller::window`] minus bytes-in-flight. [`NewReno`] is the
//! RFC 9002 §7 reference controller — a correctness scaffold for the loss-event →
//! window plumbing. The production controller is BBR (the loss-resilient
//! cross-border throughput the UDP leg exists for), which lands behind this same
//! trait in a later slice; NewReno is NOT the shipping default.

/// RFC 9002 §7.2 sender constants (fixed MTU; MTU discovery is out of scope).
const MAX_DATAGRAM_SIZE: u64 = 1200;
/// Initial window: `min(10*mss, max(2*mss, 14720))` (RFC 9002 §7.2) = 12000.
const INITIAL_WINDOW: u64 = 10 * MAX_DATAGRAM_SIZE;
/// The window never shrinks below `2*mss` (RFC 9002 §7.2).
const MINIMUM_WINDOW: u64 = 2 * MAX_DATAGRAM_SIZE;

/// A congestion controller behind the connection↔CC seam. Endpoint-local — peers
/// need not agree (RFC 9002 / `mod.rs` camouflage note: CC is performance, not
/// fingerprint).
pub trait Controller: Send {
    /// Fold in `bytes` of newly-acknowledged data. `app_limited` suppresses window
    /// growth when the sender was not congestion-window-limited (RFC 9002 §7.8).
    fn on_ack(&mut self, bytes: u64, app_limited: bool);
    /// A congestion signal (declared loss / ECN-CE) — reduce the window once per
    /// event (the caller collapses a loss batch into a single call).
    fn on_congestion_event(&mut self);
    /// The current congestion window, in bytes.
    fn window(&self) -> u64;
}

/// RFC 9002 §7 NewReno: slow start until `ssthresh`, then congestion avoidance;
/// a congestion event halves the window.
#[derive(Debug, Clone)]
pub struct NewReno {
    window: u64,
    ssthresh: u64,
    /// Acked-bytes accumulator for congestion avoidance. The per-ack increment
    /// `MSS * acked / cwnd` truncates to 0 once `cwnd > MSS * acked`, which stalls
    /// growth at high windows; accumulating acked bytes and adding one MSS per
    /// window keeps additive increase working (RFC 9002 §7.3.2).
    bytes_acked: u64,
}

impl Default for NewReno {
    fn default() -> Self {
        Self::new()
    }
}

impl NewReno {
    pub fn new() -> Self {
        Self {
            window: INITIAL_WINDOW,
            ssthresh: u64::MAX,
            bytes_acked: 0,
        }
    }
}

impl Controller for NewReno {
    fn on_ack(&mut self, bytes: u64, app_limited: bool) {
        if app_limited {
            return;
        }
        if self.window < self.ssthresh {
            // Slow start: exponential growth (RFC 9002 §7.3.1).
            self.window += bytes;
        } else {
            // Congestion avoidance (RFC 9002 §7.3.2): ~1 MSS per RTT. Accumulate
            // acked bytes and add one MSS per window so growth does not stall at
            // high windows, where `MAX_DATAGRAM_SIZE * bytes / window` truncates
            // to 0.
            self.bytes_acked += bytes;
            while self.bytes_acked >= self.window {
                self.bytes_acked -= self.window;
                self.window += MAX_DATAGRAM_SIZE;
            }
        }
    }

    fn on_congestion_event(&mut self) {
        // RFC 9002 §7.3.2: ssthresh = cwnd / 2 (loss reduction factor), floored.
        self.ssthresh = (self.window / 2).max(MINIMUM_WINDOW);
        self.window = self.ssthresh;
        self.bytes_acked = 0;
    }

    fn window(&self) -> u64 {
        self.window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_the_rfc_initial_window() {
        assert_eq!(NewReno::new().window(), 12_000);
    }

    #[test]
    fn slow_start_grows_by_bytes_acked() {
        let mut cc = NewReno::new();
        cc.on_ack(MAX_DATAGRAM_SIZE, false);
        assert_eq!(cc.window(), 12_000 + 1_200, "slow start adds bytes-acked");
    }

    #[test]
    fn app_limited_acks_do_not_grow_the_window() {
        let mut cc = NewReno::new();
        cc.on_ack(MAX_DATAGRAM_SIZE, true);
        assert_eq!(cc.window(), 12_000, "app-limited ack does not grow cwnd");
    }

    #[test]
    fn congestion_event_halves_then_avoids() {
        let mut cc = NewReno::new();
        cc.on_congestion_event();
        assert_eq!(cc.window(), 6_000, "loss halves the window");
        // Congestion avoidance grows cwnd by ~1 MSS per window of acked bytes
        // (accumulator), not a truncating per-ack increment.
        for _ in 0..5 {
            cc.on_ack(MAX_DATAGRAM_SIZE, false); // 5 * 1200 == one 6000-byte window
        }
        assert_eq!(cc.window(), 6_000 + MAX_DATAGRAM_SIZE, "one MSS per window in CA");
    }

    #[test]
    fn congestion_avoidance_does_not_stall_at_high_window() {
        let mut cc = NewReno::new();
        // Slow-start to a window large enough that MSS*MSS/cwnd truncates to 0.
        for _ in 0..3_000 {
            cc.on_ack(MAX_DATAGRAM_SIZE, false);
        }
        cc.on_congestion_event(); // enter congestion avoidance at a high window
        let start = cc.window();
        assert!(
            start > MAX_DATAGRAM_SIZE * MAX_DATAGRAM_SIZE,
            "window must be high enough that MSS*MSS/cwnd would truncate to 0"
        );
        // Ack one window of bytes; the accumulator must still grow cwnd by ~1 MSS
        // (the old `MSS * bytes / cwnd` increment would add 0 here).
        for _ in 0..(start / MAX_DATAGRAM_SIZE) {
            cc.on_ack(MAX_DATAGRAM_SIZE, false);
        }
        assert!(cc.window() > start, "cwnd must still grow at a high window");
    }

    #[test]
    fn window_never_drops_below_minimum() {
        let mut cc = NewReno::new();
        for _ in 0..20 {
            cc.on_congestion_event();
        }
        assert_eq!(cc.window(), MINIMUM_WINDOW, "cwnd floors at 2*mss");
    }
}
