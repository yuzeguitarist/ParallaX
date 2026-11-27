//! Persistent single-use 0-RTT anti-replay, backing [`crate::tls::quic::ZeroRttGuard`].
//!
//! A resumed (0-RTT) ClientHello carries an opaque ticket identity. The server
//! accepts that ticket's early data exactly once: the first presentation is
//! recorded and accepted; any later presentation of the same identity — a replay,
//! including a GFW-captured flight resent ahead of the genuine client — is rejected,
//! so the connection falls back to a full 1-RTT handshake (RFC 8446 §8). The record
//! is kept in the existing MAC-authenticated, crash-safe [`ReplayCache`], so the
//! single-use property survives a server restart.
//!
//! The ticket identity is hashed with SHA-256; the digest keys the replay cache (the
//! full 32-byte digest is the strong key, the leading 8 bytes the cache's nonce
//! slot). A hash collision could only cause a false *reject* — which fails safe to a
//! 1-RTT handshake, never a false accept. The replay window MUST be at least the
//! ticket lifetime (a ticket is replayable until it expires), so the caller
//! constructs the cache with a window `>=` the issued ticket lifetime.
//!
//! # Durability is deferred off the driver task (issue #24)
//!
//! [`ReplayCacheGuard::accept_ticket`] runs on the single per-endpoint QUIC driver
//! task (the one that owns the socket + every connection), inline in ClientHello
//! processing. A blocking journal `fsync` there stalls ALL connections/splices on
//! that endpoint — a head-of-line availability hazard a slow disk (or repeated
//! 0-RTT attempts) turns into a DoS, and a latency tell. So, exactly like the auth
//! marker guard ([`crate::transport::udp::marker_replay`]), the single-use decision
//! is made SYNCHRONOUSLY in memory (the replay is gated the instant `accept_ticket`
//! returns) via [`ReplayCache::insert_new_outcome_deferred`], and only the durable
//! journal write is offloaded to a blocking thread via `spawn_blocking`.
//!
//! Tradeoff (accepted, and identical to the marker guard): RFC 8446 §8 prefers
//! persist-before-accept, so that a ticket accepted just before a crash is still
//! rejected after the restart. Deferring the fsync opens a narrow crash window —
//! a ticket accepted in-memory but not yet persisted when the process dies is NOT
//! recorded across that restart. The in-memory gate still enforces single-use for
//! the whole life of a running process; only cross-restart durability is delayed
//! until the background persist lands. This trades a sub-second, crash-only replay
//! window for keeping the shared driver responsive — the availability of every
//! connection on the endpoint outweighs a single ticket's cross-restart durability
//! in the rare crash-at-exactly-that-instant case.
//!
//! # Locking discipline: the driver never blocks on disk I/O
//!
//! Deferring the fsync alone is not enough: if the background persist held the
//! admission mutex ACROSS its fsync, or checked the in-memory replay set out into
//! `None` for the duration of the disk write, concurrent valid tickets arriving
//! during that fsync would either stall the driver or fail closed spuriously. Two
//! rules close both hazards:
//!
//! 1. The fast `gate` mutex guards ONLY an in-memory mirror (`mirror`) plus a
//!    bounded pending queue. A single-flight background worker drains `pending`
//!    under a nanosecond lock, releases `gate`, and runs the blocking journal
//!    write + `fsync` on a separate `persister` mutex that the driver never touches.
//! 2. `accept_ticket` takes `gate` with `try_lock` and FAILS CLOSED when it
//!    cannot consult the in-memory gate immediately (contended or poisoned lock).
//!    Rejecting 0-RTT is always safe: the client completes a full 1-RTT handshake
//!    and the ticket's early data is never processed.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::crypto::replay::{
    ReplayCache, ReplayEntry, ReplayInsertOutcome, BACKGROUND_PERSIST_RETRY_BACKOFF,
    MAX_PENDING_PERSISTS,
};
use crate::tls::quic::ZeroRttGuard;

struct ZeroRttGateState {
    mirror: ReplayCache,
    pending: VecDeque<(ReplayEntry, u64)>,
    max_observed_now: Option<u64>,
    worker_running: bool,
}

struct WorkerResetGuard<'a> {
    gate: &'a Mutex<ZeroRttGateState>,
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

/// A [`ZeroRttGuard`] backed by the persistent [`ReplayCache`]. The wrapped cache
/// should be built with a freshness window `>=` the issued ticket lifetime so a
/// replay is still detected for as long as the ticket is valid.
pub(crate) struct ReplayCacheGuard {
    /// Resident in-memory gate: never held across disk I/O and never checked out,
    /// so concurrent distinct 0-RTT tickets stay accepted while an earlier ticket's
    /// journal `fsync` runs on the blocking pool.
    gate: Arc<Mutex<ZeroRttGateState>>,
    /// Disk-backed journal state owned exclusively by the background persister.
    persister: Arc<Mutex<ReplayCache>>,
}

impl ReplayCacheGuard {
    pub(crate) fn new(cache: ReplayCache) -> Self {
        let mirror = cache.in_memory_mirror();
        Self {
            gate: Arc::new(Mutex::new(ZeroRttGateState {
                mirror,
                pending: VecDeque::new(),
                max_observed_now: None,
                worker_running: false,
            })),
            persister: Arc::new(Mutex::new(cache)),
        }
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

    fn run_persist_worker(gate: &Mutex<ZeroRttGateState>, persister: &Mutex<ReplayCache>) {
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
                    "0-RTT replay cache persist failed; ticket accept recorded \
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
    fn retry_failed_persist(
        gate: &Mutex<ZeroRttGateState>,
        persister: &Mutex<ReplayCache>,
    ) -> bool {
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
                    "0-RTT replay cache persist retry failed"
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
                "0-RTT replay cache persist kept failing; the entry stays in memory \
                 only and is retried on the next admission"
            );
        }
        state.worker_running = false;
        true
    }

    /// Test-only: synchronously drain any queued durable persist so a test can
    /// observe cross-restart durability deterministically without racing the
    /// `spawn_blocking` fsync. Never holds `gate` and `persister` simultaneously.
    #[cfg(test)]
    pub(crate) fn flush_pending_for_test(&self) {
        for _ in 0..1000 {
            let (batch, max_now, worker_running) = {
                let mut state = self
                    .gate
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let batch: Vec<(ReplayEntry, u64)> = state.pending.drain(..).collect();
                let max_now = state.max_observed_now.take();
                (batch, max_now, state.worker_running)
            };
            {
                let mut cache = self
                    .persister
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
                cache
                    .persist_pending()
                    .expect("flush_pending_for_test: persist failed");
            }
            if !worker_running {
                let done = {
                    let state = self
                        .gate
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.pending.is_empty() && !state.worker_running
                };
                if done {
                    self.persister
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .persist_pending()
                        .expect("flush_pending_for_test: final persist failed");
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("flush_pending_for_test: background persist worker never settled");
    }
}

impl ZeroRttGuard for ReplayCacheGuard {
    fn accept_ticket(&self, ticket_identity: &[u8], now_unix: u64) -> bool {
        let digest = Sha256::digest(ticket_identity);
        let mut nonce = [0_u8; 8];
        nonce.copy_from_slice(&digest[..8]);
        let mut transcript_fingerprint = [0_u8; 32];
        transcript_fingerprint.copy_from_slice(&digest);
        // `timestamp = now` so the entry is always within the freshness window at
        // insert; the window then governs how long it is RETAINED for replay
        // detection (>= ticket lifetime). Only a brand-new ticket yields `Inserted`;
        // a replay yields `Replayed`, and capacity/stale conditions also reject
        // (fail safe to 1-RTT).
        let entry = ReplayEntry {
            timestamp: now_unix,
            nonce,
            transcript_fingerprint,
        };
        let mut spawn_worker = false;
        let accepted = match self.gate.try_lock() {
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
            Err(_) => false,
        };
        if spawn_worker {
            self.persist_in_background();
        }
        accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TICKET_LIFETIME_SECS: u64 = 604_800;

    fn guard() -> ReplayCacheGuard {
        ReplayCacheGuard::new(ReplayCache::new(64).with_window_secs(TICKET_LIFETIME_SECS))
    }

    #[test]
    fn first_use_accepts_then_replay_rejects() {
        let g = guard();
        let ticket = b"opaque-ticket-identity-AAAA";
        let now = 2_000_000;
        assert!(g.accept_ticket(ticket, now), "first use accepted");
        assert!(
            !g.accept_ticket(ticket, now),
            "replay of the same ticket rejected"
        );
        // Even much later (within the window) the replay is still caught.
        assert!(
            !g.accept_ticket(ticket, now + 600_000),
            "replay within the ticket lifetime still rejected"
        );
    }

    #[test]
    fn distinct_tickets_are_each_accepted_once() {
        let g = guard();
        let now = 3_000_000;
        assert!(g.accept_ticket(b"ticket-one", now));
        assert!(g.accept_ticket(b"ticket-two", now));
        assert!(g.accept_ticket(b"ticket-three", now));
        // ...and each is single-use.
        assert!(!g.accept_ticket(b"ticket-two", now));
    }

    #[test]
    fn ticket_admitted_after_clock_rollback_is_journaled_before_pruning() {
        // Two tickets land in one persist batch: one at a later time, then one
        // after the clock stepped back by more than the window. The earlier-time
        // entry must reach the journal, not be pruned at the batch maximum.
        const WINDOW_SECS: u64 = 60;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero-rtt-rollback.cache");
        let key = b"server-host-key-derived-mac-material";
        let real_now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let rolled_back = real_now - 30;
        let later = rolled_back + WINDOW_SECS + 100;

        let cache =
            ReplayCache::load_or_create_authenticated_with_window(&path, 64, key, WINDOW_SECS)
                .unwrap();
        let g = ReplayCacheGuard::new(cache);
        // Keep both accepts in one batch by holding off the inline worker.
        g.gate.lock().unwrap().worker_running = true;
        assert!(g.accept_ticket(b"ticket-at-later-time", later));
        assert!(g.accept_ticket(b"ticket-after-rollback", rolled_back));
        g.gate.lock().unwrap().worker_running = false;
        g.flush_pending_for_test();
        drop(g);

        let reloaded =
            ReplayCache::load_or_create_authenticated_with_window(&path, 64, key, WINDOW_SECS)
                .unwrap();
        let g2 = ReplayCacheGuard::new(reloaded);
        assert!(
            !g2.accept_ticket(b"ticket-after-rollback", rolled_back),
            "a ticket the live gate accepted must stay single-use across a restart"
        );
    }

    #[test]
    fn stalled_persistence_bounds_the_pending_queue() {
        let g = guard();
        g.gate.lock().unwrap().worker_running = true;
        let now = 4_000_000;
        for i in 0..MAX_PENDING_PERSISTS {
            g.gate.lock().unwrap().pending.push_back((
                ReplayEntry {
                    timestamp: now,
                    nonce: (i as u64).to_le_bytes(),
                    transcript_fingerprint: [0; 32],
                },
                now,
            ));
        }
        assert!(
            !g.accept_ticket(b"ticket-while-persist-stalled", now),
            "a full pending queue falls back to 1-RTT"
        );
        assert_eq!(g.gate.lock().unwrap().pending.len(), MAX_PENDING_PERSISTS);
    }

    #[test]
    fn replay_detected_after_reload_from_disk() {
        // The single-use property must survive a server restart: a ticket accepted
        // before the restart is still rejected as a replay after it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero-rtt-replay.cache");
        let key = b"server-host-key-derived-mac-material";
        let now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let ticket = b"persisted-ticket-identity";

        let cache = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let g = ReplayCacheGuard::new(cache);
        assert!(g.accept_ticket(ticket, now), "first use accepted");
        drop(g);

        // Reload (simulating a restart) and replay the same ticket.
        let reloaded = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let g2 = ReplayCacheGuard::new(reloaded);
        assert!(
            !g2.accept_ticket(ticket, now),
            "replay rejected across a restart (persistent single-use)"
        );
    }

    #[test]
    fn failed_persist_is_retried_without_a_later_ticket() {
        // A persist failure with nothing queued behind it must still reach disk:
        // replays never enqueue work, so waiting for the next accepted ticket
        // would leave a restart free to admit the replay.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero-rtt-replay-retry.cache");
        let key = b"server-host-key-derived-mac-material";
        let now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let ticket = b"retried-ticket-identity";

        let mut cache = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        cache.fail_next_persists_for_test(1);
        let g = ReplayCacheGuard::new(cache);
        // Outside a runtime the worker runs inline, retry included.
        assert!(g.accept_ticket(ticket, now), "first use accepted");
        assert!(
            !g.accept_ticket(ticket, now),
            "replay stays gated in memory"
        );
        drop(g);

        let reloaded = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let g2 = ReplayCacheGuard::new(reloaded);
        assert!(
            !g2.accept_ticket(ticket, now),
            "the retried persist made the first use durable"
        );
    }

    #[test]
    fn accept_never_blocks_on_a_contended_lock() {
        // Raw mutex contention on the fast gate (another thread holding `gate`)
        // must not block the driver — `try_lock` fails closed to 1-RTT
        // immediately, and single-use is enforced once contention clears.
        use std::sync::mpsc;

        let g = Arc::new(guard());
        let now = 5_000_000;
        let ticket = b"ticket-under-contention";

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
        assert!(
            !g.accept_ticket(ticket, now),
            "contended lock fails closed to 1-RTT"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(100),
            "accept must not wait for the lock holder"
        );
        release_tx.send(()).unwrap();
        holder.join().unwrap();

        // Once contention clears, the same ticket is accepted once, then gated.
        assert!(g.accept_ticket(ticket, now));
        assert!(!g.accept_ticket(ticket, now));
    }

    #[tokio::test]
    async fn async_accept_gates_replays_inline_and_persists_in_background() {
        // Issue #24: inside a runtime the fsync is offloaded to the blocking pool
        // (so the single QUIC driver task is never stalled on disk), but the
        // in-memory dedup must still gate a replay SYNCHRONOUSLY — before the
        // background persist has landed — and the persist must still land so the
        // single-use property survives a restart.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero-rtt-replay-async.cache");
        let key = b"server-host-key-derived-mac-material";
        let now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let ticket = b"async-persisted-ticket-identity";

        let cache = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let g = ReplayCacheGuard::new(cache);
        assert!(g.accept_ticket(ticket, now), "first use accepted");
        assert!(
            !g.accept_ticket(ticket, now),
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

        // Reload (simulating a restart): the ticket is still single-use.
        let reloaded = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let g2 = ReplayCacheGuard::new(reloaded);
        assert!(
            !g2.accept_ticket(ticket, now),
            "replay rejected across a restart (background persist was durable)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_distinct_ticket_accepts_while_persist_is_in_flight_and_both_survive_restart(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero-rtt-replay-concurrent.cache");
        let key = b"server-host-key-derived-mac-material";
        let now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let t1 = b"concurrent-ticket-identity-one";
        let t2 = b"concurrent-ticket-identity-two";

        let mut cache = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        cache.set_pause_persist_once(entered_tx, resume_rx);

        let g = ReplayCacheGuard::new(cache);
        assert!(g.accept_ticket(t1, now), "first ticket accepted");

        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("background persist must enter persist_pending");
        })
        .await
        .unwrap();

        let start = std::time::Instant::now();
        let t2_accepted = g.accept_ticket(t2, now);
        let elapsed = start.elapsed();
        let t1_replay = g.accept_ticket(t1, now);
        let t2_replay = g.accept_ticket(t2, now);
        let _ = resume_tx.send(());

        assert!(
            t2_accepted,
            "distinct valid 0-RTT ticket arriving during an in-flight persist must be accepted"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "accept_ticket must stay non-blocking during disk I/O (took {elapsed:?})"
        );
        assert!(
            !t1_replay,
            "replay of t1 during persist must stay gated in memory"
        );
        assert!(
            !t2_replay,
            "replay of t2 during persist must stay gated in memory"
        );

        g.flush_pending_for_test();
        let reloaded = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let g2 = ReplayCacheGuard::new(reloaded);
        assert!(
            !g2.accept_ticket(t1, now),
            "t1 must survive restart as single-use"
        );
        assert!(
            !g2.accept_ticket(t2, now),
            "t2 must survive restart as single-use"
        );
    }

    #[test]
    fn persist_failure_keeps_in_memory_replay_gate_and_retries_without_a_later_ticket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero-rtt-persist-retry.cache");
        let key = b"server-host-key-derived-mac-material";
        let now = crate::crypto::replay::current_unix_timestamp().unwrap();
        let t0 = b"seed-ticket";
        let t1 = b"failed-commit-ticket";
        let t2 = b"retry-compaction-ticket";

        let cache = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let g = ReplayCacheGuard::new(cache);
        // Seed one committed entry so the next persist takes the incremental
        // append+header-commit path where `fail_header_commit` fires.
        assert!(g.accept_ticket(t0, now));

        g.persister
            .lock()
            .unwrap()
            .fail_next_header_commit_before_write_for_test();
        assert!(g.accept_ticket(t1, now));
        // Even though the disk commit failed, the in-memory gate STILL blocks replays.
        assert!(!g.accept_ticket(t1, now));

        // The worker retries the failed commit with backoff instead of waiting
        // for the next accepted ticket (outside a runtime it runs inline), so
        // `t1` is already durable without any further admission.
        let snapshot_path = dir.path().join("zero-rtt-persist-retry.snapshot.cache");
        std::fs::copy(&path, &snapshot_path).unwrap();
        let after_retry = ReplayCache::load_or_create_authenticated_with_window(
            &snapshot_path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let g_mid = ReplayCacheGuard::new(after_retry);
        assert!(!g_mid.accept_ticket(t0, now));
        assert!(
            !g_mid.accept_ticket(t1, now),
            "t1 must be durable after the background retry, before any later ticket"
        );

        // A later fresh accept still journals normally alongside the retried entries.
        assert!(g.accept_ticket(t2, now));
        let reloaded = ReplayCache::load_or_create_authenticated_with_window(
            &path,
            64,
            key,
            TICKET_LIFETIME_SECS,
        )
        .unwrap();
        let g2 = ReplayCacheGuard::new(reloaded);
        assert!(!g2.accept_ticket(t0, now));
        assert!(!g2.accept_ticket(t1, now));
        assert!(!g2.accept_ticket(t2, now));
    }
}
