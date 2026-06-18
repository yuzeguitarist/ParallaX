//! Cross-flow correlation: a censor that aggregates ONE source's connections.
//!
//! Every other detector in this suite is per-flow (keyed by `FlowKey`), so it is
//! structurally blind to coordination ACROSS a source's flows. That blindness is
//! exactly the gap the 2026 performance R&D campaign flagged: the highest-scoring
//! throughput ideas (multipath aggregation, a fleet of egresses behind one DNS
//! name) make every individual leg a byte-perfect browser flow, yet the *set* of
//! legs can betray the proxy.
//!
//! The discriminating signal is connection topology over a short window:
//!  - A real browser connection-races (RFC 8305 Happy Eyeballs v2) to ONE site's
//!    handful of IPs -- a small number of distinct destination networks -- and
//!    staggers the attempts (~250 ms). Subresource fetches add more connections,
//!    but still to a small cluster of CDNs, spread over time.
//!  - A naive multipath/fleet client opens many connections to many DISTINCT,
//!    diverse destination networks (different ASNs / cities) near-simultaneously,
//!    to race or aggregate. One source fanning out to N diverse networks in a few
//!    milliseconds is not browser behavior.
//!
//! So the gate Track B's multipath/fleet designs must pass is: not only must each
//! leg look like a browser flow individually, the *cadence and destination
//! diversity of the set* must look like browser connection behavior. The signal
//! is simultaneity AND diversity together -- diversity alone (a user browsing
//! many sites over time) is benign, and is not flagged.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// One outbound connection a single source opened, tagged by a coarse
/// destination group (an ASN or a /16) so "distinct destinations" counts
/// distinct *networks*, not distinct IPs of one CDN.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionEvent {
    pub dest_group: u32,
    pub at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossFlowVerdict {
    /// Consistent with a browser: few distinct destination networks in any
    /// window, or diverse destinations but spread out in time.
    BrowserLike,
    /// Many distinct destination networks opened near-simultaneously from one
    /// source -- the multipath/fleet fan-out signature.
    CoordinatedFanOut {
        distinct_groups: usize,
        span: Duration,
    },
}

pub struct CrossFlowDetector {
    /// Window over which near-simultaneous opens are correlated.
    pub window: Duration,
    /// A browser races to at most a handful of a site's networks; more than this
    /// many DISTINCT destination groups inside `window` is the fan-out signal.
    pub max_distinct_groups: usize,
}

impl Default for CrossFlowDetector {
    fn default() -> Self {
        Self {
            window: Duration::from_millis(500),
            max_distinct_groups: 3,
        }
    }
}

impl CrossFlowDetector {
    /// Reports the worst (most fan-out-like) `window` across `events`: the maximum
    /// number of distinct destination groups opened within any `window`-long
    /// span. Above `max_distinct_groups` distinct networks in one window is
    /// flagged as a coordinated fan-out.
    pub fn evaluate(&self, events: &[ConnectionEvent]) -> CrossFlowVerdict {
        if events.len() < 2 {
            return CrossFlowVerdict::BrowserLike;
        }
        let mut sorted: Vec<ConnectionEvent> = events.to_vec();
        sorted.sort_by_key(|event| event.at);

        let mut worst_groups = 0;
        let mut worst_span = Duration::ZERO;
        for (i, anchor) in sorted.iter().enumerate() {
            let mut groups = BTreeSet::new();
            let mut span = Duration::ZERO;
            for event in &sorted[i..] {
                let offset = event.at.duration_since(anchor.at);
                if offset > self.window {
                    break;
                }
                groups.insert(event.dest_group);
                span = offset;
            }
            if groups.len() > worst_groups {
                worst_groups = groups.len();
                worst_span = span;
            }
        }

        if worst_groups > self.max_distinct_groups {
            CrossFlowVerdict::CoordinatedFanOut {
                distinct_groups: worst_groups,
                span: worst_span,
            }
        } else {
            CrossFlowVerdict::BrowserLike
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_racing_one_site_is_clean() {
        // RFC 8305: several connections to one site's two IPs (two networks),
        // staggered. Many connections, but few distinct networks -> BrowserLike.
        let start = Instant::now();
        let events: Vec<ConnectionEvent> = (0..6)
            .map(|i| ConnectionEvent {
                dest_group: (i % 2) as u32,
                at: start + Duration::from_millis(i as u64 * 120),
            })
            .collect();
        assert_eq!(
            CrossFlowDetector::default().evaluate(&events),
            CrossFlowVerdict::BrowserLike
        );
    }

    #[test]
    fn simultaneous_fan_out_to_many_networks_is_flagged() {
        // A naive fleet/multipath client opens six connections to six DISTINCT
        // networks within a few milliseconds -- not browser behavior.
        let start = Instant::now();
        let events: Vec<ConnectionEvent> = (0..6)
            .map(|i| ConnectionEvent {
                dest_group: i as u32,
                at: start + Duration::from_millis(i as u64),
            })
            .collect();
        match CrossFlowDetector::default().evaluate(&events) {
            CrossFlowVerdict::CoordinatedFanOut {
                distinct_groups,
                span,
            } => {
                assert_eq!(distinct_groups, 6);
                assert!(span <= Duration::from_millis(500));
            }
            other => panic!("expected CoordinatedFanOut, got {other:?}"),
        }
    }

    #[test]
    fn diverse_destinations_spread_over_time_are_clean() {
        // The same six diverse networks, but opened ~1s apart (a user browsing
        // many sites over time). The signal is simultaneity AND diversity, so
        // diversity alone must NOT be flagged -- otherwise the gate is a tautology
        // that no real multi-tab session could pass.
        let start = Instant::now();
        let events: Vec<ConnectionEvent> = (0..6)
            .map(|i| ConnectionEvent {
                dest_group: i as u32,
                at: start + Duration::from_millis(i as u64 * 1000),
            })
            .collect();
        assert_eq!(
            CrossFlowDetector::default().evaluate(&events),
            CrossFlowVerdict::BrowserLike
        );
    }
}
