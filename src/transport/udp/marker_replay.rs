//! Persistent single-use anti-replay for the QUIC origin-splice auth marker.
//!
//! The stable-:443 carrier terminates a v1 Initial locally only when its
//! `ClientHello.random` carries a valid + fresh marker on its FIRST sighting; a
//! captured marker replayed within its freshness window must instead be spliced to
//! the real origin, so the local-termination path is never re-exposed to a replayed
//! probe (see [`crate::crypto::quic_marker`]).
//!
//! The original in-memory `HashMap<(nonce, timestamp), Instant>` lost that property
//! on a process / carrier restart: a marker captured before a restart became
//! reusable after it. This guard backs the first-sighting record with the same
//! MAC-authenticated, crash-safe [`ReplayCache`] the 0-RTT guard uses
//! ([`crate::transport::udp::zero_rtt`]), so single-use survives ordinary restarts.
//!
//! Key derivation mirrors the 0-RTT guard: the marker's `(nonce, timestamp)` is
//! hashed with SHA-256; the full digest is the strong replay key and its leading 8
//! bytes the cache's nonce slot. A hash collision could only cause a false *reject*
//! (a real marker treated as a replay → spliced to the origin), which fails safe —
//! never a false accept. The cache window MUST be at least the marker freshness
//! window so a marker is retained for replay detection for as long as it is valid.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::crypto::quic_marker::Marker;
use crate::crypto::replay::{
    ReplayCache, ReplayEntry, ReplayInsertOutcome, BACKGROUND_PERSIST_RETRY_BACKOFF,
    MAX_PENDING_PERSISTS,
};

struct MarkerGateState {
    mirror: ReplayCache,
    pending: VecDeque<(ReplayEntry, u64)>,
    max_observed_now: Option<u64>,
    worker_running: bool,
}

struct WorkerResetGuard<'a> {
    gate: &'a Mutex<MarkerGateState>,
    armed: bool,
}

impl Drop for WorkerResetGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .worker_running = false;
        }
    }
}

/// A persistent first-sighting guard for origin-splice auth markers, backed by the
/// crash-safe [`ReplayCache`]. Build the wrapped cache with a freshness window `>=`
/// the marker freshness window so a replay stays detectable for as long as the
/// marker is valid.
pub struct MarkerReplayGuard {
    /// Resident in-memory gate: never held across disk I/O and never checked out,
    /// so concurrent distinct markers keep terminating locally while a background
    /// journal `fsync` is in flight.
    gate: Arc<Mutex<MarkerGateState>>,
    /// Disk-backed journal state owned exclusively by the background persister.
    persister: Arc<Mutex<ReplayCache>>,
}

impl MarkerReplayGuard {
    pub(crate) fn new(cache: ReplayCache) -> Self {
        let mirror = cache.in_memory_mirror();
        Self {
            gate: Arc::new(Mutex::new(MarkerGateState {
                mirror,
                pending: VecDeque::new(),
                max_observed_now: None,
                worker_running: false,
            })),
            persister: Arc::new(Mutex::new(cache)),
        }
    }

    /// Record the marker and report whether this is its FIRST sighting. `true` means
    /// the connection may terminate locally (a real, non-replayed ParallaX client);
    /// On replay, lock contention, stale markers or exhausted cache/queue
    /// capacity this returns `false` and the flow is spliced to the origin.
    /// `now_unix` is the current Unix time in seconds.
    ///
    /// The dedup decision is made synchronously in memory under the fast `gate`
    /// lock (so a replayed marker is gated the instant its first sighting returns,
    /// and distinct concurrent markers are accepted even while an earlier marker's
    /// journal `fsync` is running), while the durable journal write is offloaded to
    /// a single-flight blocking worker (issue #24). The gate lock is taken
    /// NON-BLOCKING (`try_lock`): if it cannot be consulted immediately the marker
    /// FAILS CLOSED to a splice rather than stall the QUIC endpoint driver.
    pub(crate) fn first_sighting(&self, m: &Marker, now_unix: u64) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(m.nonce);
        hasher.update(m.timestamp.to_be_bytes());
        let digest = hasher.finalize();
        let mut nonce = [0_u8; 8];
        nonce.copy_from_slice(&digest[..8]);
        let mut transcript_fingerprint = [0_u8; 32];
        transcript_fingerprint.copy_from_slice(&digest);
        // Retain the entry by the MARKER's own timestamp, not the observation time, so
        // replay protection lasts exactly as long as the marker would still be
        // accepted. Timestamping by `now` could expire the entry while the marker is
        // still valid (e.g. a marker first seen near mint time, retained only until
        // `now+window`, but acceptable until `marker.ts+window+skew`), reopening a
        // brief replay gap in the validity tail. The cache window is sized `>=` the
        // marker freshness window so `is_fresh` keeps the entry for the marker's whole
        // life (its future/past skew bounds mirror the marker's own).
        let entry = ReplayEntry {
            timestamp: m.timestamp,
            nonce,
            transcript_fingerprint,
        };
        let mut spawn_worker = false;
        let inserted = match self.gate.try_lock() {
            Ok(gate) if gate.pending.len() >= MAX_PENDING_PERSISTS => false,
            Ok(mut gate) => {
                gate.max_observed_now = Some(
                    gate.max_observed_now
                        .map_or(now_unix, |prev| prev.max(now_unix)),
                );
                let inserted = gate.mirror.insert_in_memory(entry.clone(), now_unix)
                    == ReplayInsertOutcome::Inserted;
                if inserted {
                    gate.pending.push_back((entry, now_unix));
                    if !gate.worker_running {
                        gate.worker_running = true;
                        spawn_worker = true;
                    }
                }
                inserted
            }
            // A poisoned or contended lock fails closed: treat as a replay (splice
            // to origin) rather than block the driver or risk re-exposing the
            // local termination path.
            Err(_) => false,
        };
        if spawn_worker {
            self.persist_in_background();
        }
        inserted
    }

    /// Runs the single-flight durable persist worker off the async executor via
    /// `spawn_blocking`. Outside a tokio runtime (sync tests) it persists inline.
    /// A persist failure is logged and retried with bounded backoff; the resident `gate` mirror keeps gating replays either way.
    fn persist_in_background(&self) {
        let gate = Arc::clone(&self.gate);
        let persister = Arc::clone(&self.persister);
        let persist = move || Self::run_persist_worker(&gate, &persister);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(persist);
            }
            Err(_) => persist(),
        }
    }

    fn run_persist_worker(gate: &Mutex<MarkerGateState>, persister: &Mutex<ReplayCache>) {
        let mut reset = WorkerResetGuard { gate, armed: true };
        loop {
            let (batch, max_now): (Vec<(ReplayEntry, u64)>, Option<u64>) = {
                let mut state = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if state.pending.is_empty() {
                    state.worker_running = false;
                    reset.armed = false;
                    return;
                }
                let batch = state.pending.drain(..).collect();
                let max_now = state.max_observed_now.take();
                (batch, max_now)
            };

            let result = {
                let mut cache = persister
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(now) = max_now {
                    cache.prune_expired_at(now);
                }
                // Do not prune again at the batch maximum after inserting: after a
                // clock rollback an entry admitted at a lower `now` would be pruned
                // before it is journaled, and a restart would then admit its replay
                // even though the live gate rejected it.
                for (entry, now) in batch {
                    let _ = cache.insert_new_outcome_deferred(entry, now);
                }
                cache.persist_pending()
            };

            if let Err(err) = result {
                tracing::warn!(
                    error = %err,
                    "marker replay cache persist failed; first sighting recorded \
                     in memory only (retrying)"
                );
                if Self::retry_failed_persist(gate, persister) {
                    reset.armed = false;
                    return;
                }
            }
        }
    }

    /// Retries a failed persist with bounded backoff while nothing new is queued.
    /// Replays never enqueue work, so without this an entry whose persist failed
    /// would reach disk only on the next admission, and a restart before then
    /// would admit its replay. Returns `true` once the worker has stopped (queue
    /// empty and the worker marked idle); `false` hands control back to the main
    /// loop, which journals the next batch together with any still-pending entry.
    fn retry_failed_persist(gate: &Mutex<MarkerGateState>, persister: &Mutex<ReplayCache>) -> bool {
        for delay in BACKGROUND_PERSIST_RETRY_BACKOFF {
            if !gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pending
                .is_empty()
            {
                return false;
            }
            std::thread::sleep(delay);
            let result = persister
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .persist_pending();
            match result {
                Ok(()) => return false,
                Err(err) => tracing::warn!(
                    error = %err,
                    "marker replay cache persist retry failed"
                ),
            }
        }
        let still_pending = persister
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .has_pending_persist();
        let mut state = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.pending.is_empty() {
            return false;
        }
        if still_pending {
            tracing::error!(
                "marker replay cache persist kept failing; the entry stays in memory \
                 only and is retried on the next admission"
            );
        }
        state.worker_running = false;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mirror the production retention window (`MARKER_REPLAY_WINDOW_SECS` ==
    // `crate::tls::quic::server::MARKER_WINDOW_SECS`), so the tests exercise the real
    // marker validity envelope rather than an arbitrarily long one.
    const MARKER_WINDOW_SECS: u64 = 3600;

    fn marker(nonce_byte: u8, timestamp: u64) -> Marker {
        Marker {
            nonce: [nonce_byte; 12],
            timestamp,
        }
    }

    fn guard() -> MarkerReplayGuard {
        MarkerReplayGuard::new(ReplayCache::new(64).with_window_secs(MARKER_WINDOW_SECS))
    }

    #[test]
    fn first_sighting_accepts_then_replay_rejects() {
        let g = guard();
        let m = marker(0xab, 1_900_000_000);
        let now = 1_900_000_000;
        assert!(
            g.first_sighting(&m, now),
            "first sighting terminates locally"
        );
        assert!(
            !g.first_sighting(&m, now),
            "replayed marker is spliced, not terminated"
        );
        assert!(
            !g.first_sighting(&m, now + MARKER_WINDOW_SECS - 1),
            "replay anywhere within the marker's validity window is still rejected"
        );
    }

    #[test]
    fn replay_in_the_validity_tail_is_rejected() {
        // Regression (cubic P1): a marker first seen at its mint time must stay
        // replay-protected for its WHOLE validity window — the entry is retained by
        // the marker's own timestamp, not the observation time, so a replay at the
        // very end of the window (where `open()` would still accept a fresh marker)
        // is still caught.
        let g = guard();
        let mint = 1_900_000_000;
        let m = marker(0x77, mint);
        // First seen right at mint.
        assert!(g.first_sighting(&m, mint), "first sighting accepted");
        // Replayed at the last second the marker is still valid.
        assert!(
            !g.first_sighting(&m, mint + MARKER_WINDOW_SECS),
            "a replay at the end of the validity window is rejected (no tail gap)"
        );
    }

    #[test]
    fn distinct_markers_each_terminate_once() {
        let g = guard();
        let now = 1_900_000_000;
        // Distinct nonces AND distinct timestamps are independent first sightings.
        assert!(g.first_sighting(&marker(0x01, now), now));
        assert!(g.first_sighting(&marker(0x02, now), now));
        assert!(g.first_sighting(&marker(0x01, now + 1), now + 1));
        // ...but each exact (nonce, timestamp) is single-use.
        assert!(!g.first_sighting(&marker(0x02, now), now));
    }

    #[test]
    fn stalled_persistence_bounds_the_marker_queue() {
        let g = guard();
        let now = 1_900_000_000;
        {
            let mut gate = g.gate.lock().unwrap();
            gate.worker_running = true;
            gate.pending.resize_with(MAX_PENDING_PERSISTS, || {
                (
                    ReplayEntry {
                        timestamp: now,
                        nonce: [0; 8],
                        transcript_fingerprint: [0; 32],
                    },
                    now,
                )
            });
        }
        let m = marker(0x02, now);
        assert!(!g.first_sighting(&m, now));
        {
            let mut gate = g.gate.lock().unwrap();
            assert_eq!(gate.pending.len(), MAX_PENDING_PERSISTS);
            gate.pending.clear();
            gate.worker_running = false;
        }
        assert!(g.first_sighting(&m, now));
        assert!(!g.first_sighting(&m, now));
    }

    #[test]
    fn replay_detected_after_reload_from_disk() {
        // The single-use property must survive a carrier restart: a marker that
        // terminated locally before the restart is spliced (rejected) after it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marker-replay.cache");
        let key = b"server-static-key-derived-mac-material";
        let now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let m = marker(0x5a, now);

        let cache = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            MARKER_WINDOW_SECS,
        )
        .unwrap();
        let g = MarkerReplayGuard::new(cache);
        assert!(g.first_sighting(&m, now), "first sighting terminates");
        drop(g);

        // Reload (simulating a restart) and replay the same marker.
        let reloaded = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            MARKER_WINDOW_SECS,
        )
        .unwrap();
        let g2 = MarkerReplayGuard::new(reloaded);
        assert!(
            !g2.first_sighting(&m, now),
            "replay spliced across a restart (persistent single-use)"
        );
    }

    #[test]
    fn failed_persist_is_retried_without_a_later_sighting() {
        // A persist failure with nothing queued behind it must still reach disk:
        // replays never enqueue work, so waiting for the next first sighting
        // would leave a restart free to admit the replay.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marker-replay-retry.cache");
        let key = b"server-static-key-derived-mac-material";
        let now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let m = marker(0x6b, now);

        let mut cache = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            MARKER_WINDOW_SECS,
        )
        .unwrap();
        cache.fail_next_persists_for_test(1);
        let g = MarkerReplayGuard::new(cache);
        // Outside a runtime the worker runs inline, retry included.
        assert!(g.first_sighting(&m, now), "first sighting terminates");
        assert!(!g.first_sighting(&m, now), "replay stays gated in memory");
        drop(g);

        let reloaded = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            MARKER_WINDOW_SECS,
        )
        .unwrap();
        let g2 = MarkerReplayGuard::new(reloaded);
        assert!(
            !g2.first_sighting(&m, now),
            "the retried persist made the first sighting durable"
        );
    }

    #[test]
    fn first_sighting_never_blocks_on_a_contended_lock() {
        // `first_sighting` runs on the QUIC endpoint driver task: raw mutex
        // contention on the fast gate must fail closed (splice to origin)
        // immediately rather than block the driver, and single-use is still
        // enforced once contention clears.
        use std::sync::mpsc;

        let g = Arc::new(guard());
        let now = 1_900_000_000;
        let m = marker(0x44, now);

        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = {
            let g = Arc::clone(&g);
            std::thread::spawn(move || {
                let gate = g.gate.lock().unwrap();
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                drop(gate);
            })
        };
        locked_rx.recv().unwrap();

        let start = std::time::Instant::now();
        let sighted = g.first_sighting(&m, now);
        let elapsed = start.elapsed();
        assert!(
            !sighted,
            "contended gate lock fails closed (splice to origin)"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "first_sighting must not wait for the lock holder (took {elapsed:?})"
        );
        release_tx.send(()).unwrap();
        holder.join().unwrap();

        assert!(
            g.first_sighting(&m, now),
            "terminates once contention cleared"
        );
        assert!(!g.first_sighting(&m, now), "replay is still gated");
    }

    #[tokio::test]
    async fn async_first_sighting_gates_replays_inline_and_persists_in_background() {
        // Issue #24: inside a runtime the fsync is offloaded to the blocking pool,
        // but the in-memory dedup must still gate a replay SYNCHRONOUSLY — before
        // the background persist has landed — and the persist must still land so
        // single-use survives a restart.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marker-replay-async.cache");
        let key = b"server-static-key-derived-mac-material";
        let now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let m = marker(0x3c, now);

        let cache = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            MARKER_WINDOW_SECS,
        )
        .unwrap();
        let g = MarkerReplayGuard::new(cache);
        assert!(g.first_sighting(&m, now), "first sighting terminates");
        assert!(
            !g.first_sighting(&m, now),
            "immediate replay is gated by the in-memory record, without waiting \
             for the background persist"
        );

        // Wait for the background persist to land (header + one entry line).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let lines = std::fs::read_to_string(&path)
                .map(|raw| raw.lines().count())
                .unwrap_or(0);
            if lines >= 2 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "background persist never landed on disk"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Reload (simulating a restart): the marker is still single-use.
        let reloaded = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            MARKER_WINDOW_SECS,
        )
        .unwrap();
        let g2 = MarkerReplayGuard::new(reloaded);
        assert!(
            !g2.first_sighting(&m, now),
            "replay spliced across a restart (background persist was durable)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_distinct_marker_terminates_while_persist_is_in_flight_and_both_survive_restart(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marker-replay-concurrent.cache");
        let key = b"server-static-key-derived-mac-material";
        let now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let m1 = marker(0x11, now);
        let m2 = marker(0x22, now);

        let mut cache = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            MARKER_WINDOW_SECS,
        )
        .unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        cache.set_pause_persist_once(entered_tx, resume_rx);

        let g = MarkerReplayGuard::new(cache);
        assert!(g.first_sighting(&m1, now), "first marker terminates");

        // Deterministically park inside the background persist for m1.
        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("background persist must enter persist_pending");
        })
        .await
        .unwrap();

        // While m1's fsync is in flight, a distinct valid marker m2 MUST still
        // terminate locally without blocking, and replays of either m1 or m2
        // MUST be rejected synchronously.
        let start = std::time::Instant::now();
        let m2_sighted = g.first_sighting(&m2, now);
        let elapsed = start.elapsed();
        let m1_replay = g.first_sighting(&m1, now);
        let m2_replay = g.first_sighting(&m2, now);
        let _ = resume_tx.send(());

        assert!(
            m2_sighted,
            "distinct valid marker arriving during an in-flight persist must terminate locally, not get spliced"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "first_sighting must stay non-blocking during disk I/O (took {elapsed:?})"
        );
        assert!(
            !m1_replay,
            "replay of m1 during persist must stay gated in memory"
        );
        assert!(
            !m2_replay,
            "replay of m2 during persist must stay gated in memory"
        );

        // Wait until both entries have landed durably (2 header slots + 2 entry lines = 4 lines).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let reloaded = ReplayCache::load_or_create_authenticated_with_window(
                &path,
                64,
                key,
                MARKER_WINDOW_SECS,
            );
            if let Ok(reloaded) = reloaded {
                let g2 = MarkerReplayGuard::new(reloaded);
                if !g2.first_sighting(&m1, now) && !g2.first_sighting(&m2, now) {
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "both m1 and m2 must become durable on disk after background persist completes"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
