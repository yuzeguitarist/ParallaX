#![cfg_attr(not(test), no_main)]
#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
use parallax::crypto::replay::{ReplayCache, ReplayEntry, ReplayInsertOutcome};
use std::collections::{HashSet, VecDeque};

// Differential oracle for the replay-cache dedup decision
// (src/crypto/replay.rs `insert_new_outcome`). Coverage of the existing
// `replay_journal` target showed it only exercised PARSING; the dedup core
// (Inserted / Replayed / Stale / CacheFull) was never reached.
//
// We drive a real in-memory `ReplayCache` and an INDEPENDENT reference model
// with the same sequence of (timestamp, nonce, transcript, now) operations and
// assert they agree on every step. The reference re-derives the outcome from
// first principles — it never calls into replay.rs — so a divergence is a real
// behaviour bug in the cache (nonce/transcript dedup, the freshness window, the
// prune order, or the Replayed-before-CacheFull precedence), NOT a restatement
// of the parser's own arithmetic.
//
// `ReplayCache::new` leaves path = None, so `persist()` is a no-op: `Inserted`
// never fails on I/O and the returned outcome is purely the dedup decision.

// Mirror of replay.rs's private `MAX_FUTURE_SKEW_SECS`. Hard-coded on purpose:
// if the cache's future bound ever changes, this reference MUST diverge and trip
// the fuzzer, flagging that the freshness semantics moved (so both are updated
// deliberately rather than silently drifting apart).
const MAX_FUTURE_SKEW_SECS: u64 = 5;

/// Independent re-derivation of `ReplayCache`'s dedup decision. Holds the same
/// state (arrival-ordered entries + nonce/transcript sets) but is written from
/// the spec, not by calling the implementation.
struct RefModel {
    capacity: usize,
    window_secs: u64,
    order: VecDeque<(u64, [u8; 8], [u8; 32])>, // arrival order: (timestamp, nonce, transcript)
    nonces: HashSet<[u8; 8]>,
    transcripts: HashSet<[u8; 32]>,
}

impl RefModel {
    fn new(capacity: usize, window_secs: u64) -> Self {
        Self {
            capacity,
            window_secs,
            order: VecDeque::new(),
            nonces: HashSet::new(),
            transcripts: HashSet::new(),
        }
    }

    // Same freshness test as ReplayCache::is_fresh: saturating, with an
    // asymmetric future bound (MAX_FUTURE_SKEW_SECS) vs past bound (window_secs).
    fn is_fresh(&self, timestamp: u64, now: u64) -> bool {
        timestamp <= now.saturating_add(MAX_FUTURE_SKEW_SECS)
            && timestamp.saturating_add(self.window_secs) >= now
    }

    // Retain every unexpired arrival, including entries behind a fresh front.
    // Future-dated entries must survive clock rollback to keep blocking replays.
    fn prune(&mut self, now: u64) {
        self.order
            .retain(|(ts, _, _)| ts.saturating_add(self.window_secs) >= now);
        self.nonces = self.order.iter().map(|(_, n, _)| *n).collect();
        self.transcripts = self.order.iter().map(|(_, _, t)| *t).collect();
    }

    fn insert(
        &mut self,
        timestamp: u64,
        nonce: [u8; 8],
        transcript: [u8; 32],
        now: u64,
    ) -> ReplayInsertOutcome {
        if self.capacity == 0 {
            return ReplayInsertOutcome::Inserted;
        }
        self.prune(now);
        if !self.is_fresh(timestamp, now) {
            return ReplayInsertOutcome::Stale;
        }
        // Replayed takes precedence over CacheFull: a seen nonce OR transcript is
        // a replay regardless of capacity.
        if self.nonces.contains(&nonce) || self.transcripts.contains(&transcript) {
            return ReplayInsertOutcome::Replayed;
        }
        if self.order.len() >= self.capacity {
            return ReplayInsertOutcome::CacheFull;
        }
        self.nonces.insert(nonce);
        self.transcripts.insert(transcript);
        self.order.push_back((timestamp, nonce, transcript));
        ReplayInsertOutcome::Inserted
    }
}

fn check_input(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    // Small capacity (0..=4) so CacheFull is reachable; 0 exercises the
    // replay-protection-off fast path (everything Inserted).
    let capacity = (data[0] % 5) as usize;
    // A few window regimes incl. 0 (degenerate) and the production defaults.
    let window_secs: u64 = match data[1] % 4 {
        0 => 0,
        1 => 5,
        2 => 120,
        _ => 720,
    };

    let mut real = ReplayCache::new(capacity).with_window_secs(window_secs);
    let mut model = RefModel::new(capacity, window_secs);

    // Start `now` well above any window so saturating math at the u64 floor never
    // masks a divergence; advance it as operations are consumed.
    let mut now: u64 = 1_000_000;

    // 4 bytes per op: nonce seed, transcript seed, signed ts offset, now delta.
    // Narrow nonce/transcript value spaces (1 byte each) make collisions — and
    // thus Replayed — frequent under mutation; the signed offset reaches both the
    // stale-past and future-skew sides of the window.
    for op in data[2..].chunks_exact(4) {
        let nonce = [op[0], 0, 0, 0, 0, 0, 0, 0];
        let transcript = [op[1]; 32];
        let offset = op[2] as i8 as i64;
        now = now.saturating_add(op[3] as u64);
        let timestamp = (now as i64).saturating_add(offset).max(0) as u64;

        let entry = ReplayEntry {
            timestamp,
            nonce,
            transcript_fingerprint: transcript,
        };
        let got = real
            .insert_new_outcome(entry, now)
            .expect("in-memory cache (path=None) never performs I/O");
        let want = model.insert(timestamp, nonce, transcript, now);
        assert_eq!(
            got, want,
            "replay dedup divergence: real={got:?} ref={want:?} \
             (cap={capacity} window={window_secs} ts={timestamp} now={now} \
             nonce_seed={} transcript_seed={})",
            nonce[0], transcript[0]
        );
    }
}

#[cfg(not(test))]
fuzz_target!(|data: &[u8]| check_input(data));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_223_out_of_order_expiry() {
        // Minimized nightly crash: cap=2, window=120. The second arrival
        // expires behind the still-fresh first one, freeing the third slot.
        check_input(&[
            0xbb, 0xba, 0xba, 0xba, 0xff, 0, 0xff, 0xff, 0xa6, 0x31, 0, 0, 0, 0x3a,
        ]);
    }

    #[test]
    fn clock_rollback_retains_previously_accepted_future_entries() {
        let mut model = RefModel::new(2, 120);
        assert_eq!(
            model.insert(1_005, [1; 8], [1; 32], 1_000),
            ReplayInsertOutcome::Inserted
        );
        model.prune(900);
        assert_eq!(
            model.insert(1_005, [1; 8], [1; 32], 1_005),
            ReplayInsertOutcome::Replayed
        );
    }
}
