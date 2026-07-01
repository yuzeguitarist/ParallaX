//! Datagram Packetization Layer Path MTU Discovery (DPLPMTUD, RFC 8899) for the QUIC
//! data plane, clean-room.
//!
//! The carrier shipped a fixed 1252-byte datagram ceiling: safe on any path, but it
//! leaves ~17% of an Ethernet 1500-byte MTU's payload unused on the common case where
//! the path actually carries 1500. This module discovers the real path MTU by probing
//! upward and lets the connection packetize bulk DATA up to the validated size.
//!
//! ## Shape (RFC 8899 §5 adapted to QUIC, RFC 9000 §14.3–14.4)
//!
//! * **BASE = 1200** — the validated baseline every path must carry (the QUIC minimum
//!   a server enforces on Initials). The connection always starts here, so before any
//!   probe completes the wire behaviour is byte-identical to the old fixed path.
//! * **Searching** — a binary search between the largest validated size and `MAX`
//!   (1452 = 1500 − 20 IPv4 − 8 UDP). Each step emits ONE probe: an ack-eliciting
//!   packet (PING + PADDING) inflated to the candidate size. A probe that is
//!   acknowledged validates that size (raise the floor); a probe declared lost retries
//!   a few times, then lowers the ceiling. The search ends when the window closes.
//! * **black-hole** — once a larger MTU is in use, sustained loss of full-size data
//!   packets means the path stopped carrying that size (a route change). The
//!   connection resets to BASE and stops searching, so a transfer self-heals rather
//!   than stalling on a silently-too-big MTU.
//!
//! ## QUIC-specific rules baked in
//!
//! * A lost PMTU **probe is NOT a congestion signal** (RFC 9000 §14.4): the caller
//!   must feed probe loss here and NOT to the congestion controller, or a probe of a
//!   too-big size would wrongly shrink the window.
//! * A probe does not count toward bytes-in-flight congestion gating; it is a
//!   single small extra packet the caller emits out-of-band.
//!
//! Pure state machine: no IO, no clock beyond what the caller passes. Unit-tested
//! against the search/black-hole contract on every target.

/// The validated baseline MTU the connection starts and resets to. Set to the
/// carrier's long-standing fixed datagram ceiling (1252), which the shipping code
/// already trusts on every path — so before any probe completes, and after a
/// black-hole reset, the wire shape is byte-identical to the pre-DPLPMTUD behaviour
/// (no shrink below today's size). It sits just above QUIC's 1200-byte hard minimum
/// (RFC 9000 §14.1), so it is always carriable.
pub const BASE_MTU: usize = 1252;

/// The search ceiling: a 1500-byte Ethernet MTU minus a 20-byte IPv4 header and an
/// 8-byte UDP header. Conservative for IPv4; an IPv6 path (40-byte header) would cap
/// at 1452 too, which is still ≤ its own limit, so this single ceiling is safe on both.
pub const MAX_MTU: usize = 1452;

/// Probes of one candidate size retried before the size is declared unreachable and
/// the search ceiling is lowered (RFC 8899 §5.1.3 MAX_PROBES = 3).
const MAX_PROBES: u32 = 3;

/// The smallest MTU increment worth a probe. Once the search window (high − low) drops
/// below this, the search is complete: a sub-`STEP` gain is not worth a round-trip.
const SEARCH_STEP: usize = 16;

/// Consecutive losses of full-`current`-size data packets that condemn the current MTU
/// as a black hole and reset the path to BASE. Kept above a handful so ordinary random
/// loss on a working path does not trip a reset.
const BLACKHOLE_LOSS_THRESHOLD: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// At BASE, no probe outstanding, a search not yet started or just reset.
    Base,
    /// A binary search is in progress between `low` (validated) and `high` (ceiling).
    Searching,
    /// The search converged; `current` is the discovered MTU. No more probes until a
    /// black hole forces a reset.
    Complete,
}

/// DPLPMTUD state for one connection/path.
#[derive(Debug, Clone)]
pub struct Pmtud {
    state: State,
    /// The validated MTU in use for packetization (always ≥ BASE).
    current: usize,
    /// Binary-search bounds: `low` is the largest validated size, `high` the largest
    /// not-yet-failed candidate ceiling.
    low: usize,
    high: usize,
    /// The size of the in-flight probe, if any (its loss/ack drives the search).
    probe_size: Option<usize>,
    /// Probes already spent at the current candidate before lowering the ceiling.
    probes_at_size: u32,
    /// Consecutive full-size data-packet losses, for black-hole detection.
    blackhole_losses: u32,
}

impl Default for Pmtud {
    fn default() -> Self {
        Self::new()
    }
}

impl Pmtud {
    pub fn new() -> Self {
        Self {
            state: State::Base,
            current: BASE_MTU,
            low: BASE_MTU,
            high: MAX_MTU,
            probe_size: None,
            probes_at_size: 0,
            blackhole_losses: 0,
        }
    }

    /// The validated MTU bulk DATA packets are built to. Always ≥ [`BASE_MTU`]; equals
    /// BASE until the first probe is acknowledged, so the pre-discovery wire shape is
    /// unchanged.
    pub fn current_mtu(&self) -> usize {
        self.current
    }

    /// The next probe size to emit, or `None` if no probe is due (one already in
    /// flight, search complete, or the window has closed). The caller emits a single
    /// ack-eliciting packet padded to this size and reports the outcome via
    /// [`Self::on_probe_acked`] / [`Self::on_probe_lost`].
    ///
    /// Probing starts only when the caller asks (it gates on having 1-RTT keys and a
    /// confirmed handshake), so a probe never races the handshake.
    pub fn next_probe_size(&mut self) -> Option<usize> {
        if self.probe_size.is_some() {
            return None; // one probe at a time
        }
        match self.state {
            State::Complete => None,
            State::Base => {
                // Kick off the search: aim at the midpoint of (current, MAX].
                if self.high.saturating_sub(self.low) < SEARCH_STEP {
                    self.state = State::Complete;
                    return None;
                }
                self.state = State::Searching;
                let candidate = self.midpoint();
                self.probe_size = Some(candidate);
                self.probes_at_size = 0;
                Some(candidate)
            }
            State::Searching => {
                if self.high.saturating_sub(self.low) < SEARCH_STEP {
                    self.state = State::Complete;
                    return None;
                }
                let candidate = self.midpoint();
                self.probe_size = Some(candidate);
                Some(candidate)
            }
        }
    }

    /// Midpoint of the open search interval `(low, high]`, rounded up so a probe is
    /// always strictly above the validated floor (never re-probes `low`).
    fn midpoint(&self) -> usize {
        let mid = self.low + (self.high - self.low).div_ceil(2);
        mid.clamp(self.low + 1, self.high)
    }

    /// A probe of `probe_size` was acknowledged: that size is validated. Raise the
    /// floor and keep searching upward. (Acknowledging any size also clears the
    /// black-hole loss counter — the path is demonstrably carrying large packets.)
    pub fn on_probe_acked(&mut self) {
        let Some(size) = self.probe_size.take() else {
            return;
        };
        self.probes_at_size = 0;
        self.blackhole_losses = 0;
        if size > self.current {
            self.current = size;
        }
        self.low = self.low.max(size);
        if self.high.saturating_sub(self.low) < SEARCH_STEP {
            self.state = State::Complete;
        } else {
            self.state = State::Searching;
        }
    }

    /// A probe of `probe_size` was declared lost. Retry the same size up to
    /// [`MAX_PROBES`]; past that, lower the ceiling below it (binary search down) and
    /// continue. A lost probe is NEVER a congestion signal (RFC 9000 §14.4) — the
    /// caller must not also feed it to the congestion controller.
    pub fn on_probe_lost(&mut self) {
        let Some(size) = self.probe_size.take() else {
            return;
        };
        self.probes_at_size += 1;
        if self.probes_at_size < MAX_PROBES {
            // Retry the same candidate (re-emitted on the next `next_probe_size`).
            return;
        }
        // The candidate is unreachable: drop the ceiling just below it and reset the
        // retry counter for the next, smaller candidate.
        self.probes_at_size = 0;
        self.high = size.saturating_sub(1).max(self.low);
        if self.high.saturating_sub(self.low) < SEARCH_STEP {
            self.state = State::Complete;
        } else {
            self.state = State::Searching;
        }
    }

    /// Report the loss of a full-`current`-size DATA packet (not a probe). Sustained
    /// such losses while `current > BASE` mean the path stopped carrying the current
    /// MTU (a black hole, e.g. a route change to a smaller-MTU path); reset to BASE and
    /// re-open the search so the transfer self-heals. A loss at BASE, or an isolated
    /// loss, is ignored — ordinary random loss must not trip a reset.
    ///
    /// Returns `true` if this loss triggered a black-hole reset (so the caller can log
    /// it); `false` otherwise.
    pub fn on_full_size_loss(&mut self) -> bool {
        if self.current <= BASE_MTU {
            return false;
        }
        self.blackhole_losses += 1;
        if self.blackhole_losses >= BLACKHOLE_LOSS_THRESHOLD {
            *self = Pmtud::new();
            return true;
        }
        false
    }

    /// A full-size DATA packet was acknowledged: the path is carrying the current MTU,
    /// so clear the black-hole loss streak.
    pub fn on_full_size_acked(&mut self) {
        self.blackhole_losses = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_base_with_no_probe_until_asked() {
        let p = Pmtud::new();
        assert_eq!(p.current_mtu(), BASE_MTU);
    }

    #[test]
    fn binary_search_converges_upward_when_every_probe_acks() {
        // Every probe up to MAX succeeds: the search must climb to (near) MAX and stop,
        // never proposing a probe above MAX or below the validated floor.
        let mut p = Pmtud::new();
        let mut last = BASE_MTU;
        for _ in 0..32 {
            match p.next_probe_size() {
                Some(size) => {
                    assert!(size > p.low && size <= MAX_MTU, "probe in (low, MAX]");
                    last = size;
                    p.on_probe_acked();
                }
                None => break,
            }
        }
        assert!(
            p.current_mtu() >= MAX_MTU - SEARCH_STEP,
            "converged near the ceiling ({} vs {MAX_MTU})",
            p.current_mtu()
        );
        assert!(last <= MAX_MTU);
        // No further probes once complete.
        assert_eq!(p.next_probe_size(), None);
    }

    #[test]
    fn a_failing_probe_lowers_the_ceiling_and_keeps_a_validated_mtu() {
        // First probe acks (validates a mid size), the next size fails all retries:
        // the search must settle at the validated size, never adopting the failed one.
        let mut p = Pmtud::new();
        let first = p.next_probe_size().expect("first probe");
        p.on_probe_acked();
        assert_eq!(p.current_mtu(), first, "first acked size adopted");

        // Drive the remaining search; force every subsequent probe to fail.
        let mut probes = 0;
        while let Some(size) = p.next_probe_size() {
            assert!(size > first, "search probes above the validated floor");
            p.on_probe_lost();
            probes += 1;
            if probes > 64 {
                panic!("search did not converge");
            }
        }
        assert_eq!(
            p.current_mtu(),
            first,
            "MTU stays at the last validated size when larger probes fail"
        );
    }

    #[test]
    fn lost_probe_retries_before_lowering_the_ceiling() {
        let mut p = Pmtud::new();
        let candidate = p.next_probe_size().expect("first probe");
        // The same candidate is retried MAX_PROBES-1 times (high unchanged) before the
        // ceiling drops.
        for _ in 0..(MAX_PROBES - 1) {
            p.on_probe_lost();
            let retry = p.next_probe_size().expect("retry probe");
            assert_eq!(
                retry, candidate,
                "same size retried before lowering ceiling"
            );
        }
        // The final failure lowers the ceiling: the next candidate is strictly smaller.
        p.on_probe_lost();
        if let Some(next) = p.next_probe_size() {
            assert!(
                next < candidate,
                "ceiling lowered after MAX_PROBES failures"
            );
        }
    }

    #[test]
    fn blackhole_resets_to_base_after_sustained_full_size_loss() {
        // Climb to a larger MTU, then lose full-size packets until the black-hole
        // threshold trips a reset to BASE.
        let mut p = Pmtud::new();
        let size = p.next_probe_size().expect("probe");
        p.on_probe_acked();
        assert!(p.current_mtu() > BASE_MTU);
        let _ = size;

        let mut reset = false;
        for _ in 0..BLACKHOLE_LOSS_THRESHOLD {
            reset = p.on_full_size_loss();
        }
        assert!(reset, "the threshold loss reported a reset");
        assert_eq!(
            p.current_mtu(),
            BASE_MTU,
            "path reset to BASE after black hole"
        );
    }

    #[test]
    fn an_ack_clears_the_blackhole_streak() {
        let mut p = Pmtud::new();
        p.next_probe_size();
        p.on_probe_acked();
        // A few losses, then an ack: the streak resets, so it takes the full threshold
        // again to trip — ordinary intermittent loss never accumulates to a reset.
        p.on_full_size_loss();
        p.on_full_size_loss();
        p.on_full_size_acked();
        let mut reset = false;
        for _ in 0..(BLACKHOLE_LOSS_THRESHOLD - 1) {
            reset = p.on_full_size_loss();
        }
        assert!(!reset, "an intervening ack prevented a premature reset");
    }

    #[test]
    fn loss_at_base_never_resets() {
        // With no larger MTU validated, full-size loss is just ordinary loss.
        let mut p = Pmtud::new();
        for _ in 0..(BLACKHOLE_LOSS_THRESHOLD * 2) {
            assert!(!p.on_full_size_loss(), "no reset while at BASE");
        }
        assert_eq!(p.current_mtu(), BASE_MTU);
    }
}
