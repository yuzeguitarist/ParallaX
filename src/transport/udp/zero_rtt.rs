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
//! # Locking discipline: the driver never blocks on the cache mutex
//!
//! Deferring the fsync alone is not enough: if the background persist held the
//! cache mutex ACROSS its fsync while `accept_ticket` took a blocking `lock()`,
//! the driver would stall on the mutex for the whole disk write — the same
//! head-of-line hazard, one lock removed. Two rules close it:
//!
//! 1. The background persist never holds the mutex across the fsync. It CHECKS
//!    the cache OUT of the slot (`Option::take`) under a short lock, runs the
//!    journal write + fsync with the lock RELEASED, and puts the cache back
//!    under another short lock. The mutex only ever guards memory-fast
//!    operations (gate insert, take, put-back).
//! 2. `accept_ticket` takes the mutex with `try_lock` and FAILS CLOSED when it
//!    cannot consult the in-memory gate immediately — lock contended, poisoned,
//!    or the cache checked out by an in-flight persist. Rejecting 0-RTT is
//!    always safe: the client completes a full 1-RTT handshake and the ticket's
//!    early data is never processed, so replay safety is preserved (early data
//!    is only ever accepted when the gate was actually consulted).

use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::crypto::replay::{ReplayCache, ReplayEntry, ReplayInsertOutcome};
use crate::tls::quic::ZeroRttGuard;

/// A [`ZeroRttGuard`] backed by the persistent [`ReplayCache`]. The wrapped cache
/// should be built with a freshness window `>=` the issued ticket lifetime so a
/// replay is still detected for as long as the ticket is valid.
pub(crate) struct ReplayCacheGuard {
    /// The cache normally lives in this slot; a background persist checks it out
    /// (slot -> `None`) for the duration of the journal fsync and puts it back
    /// after, so the mutex is only ever held for memory-fast operations — never
    /// across disk I/O (see the module docs' locking discipline).
    cache: Arc<Mutex<Option<ReplayCache>>>,
}

impl ReplayCacheGuard {
    pub(crate) fn new(cache: ReplayCache) -> Self {
        Self {
            cache: Arc::new(Mutex::new(Some(cache))),
        }
    }

    /// Runs the queued durable persist (journal append + fsync) off the async
    /// executor via `spawn_blocking`. Outside a tokio runtime (sync tests) it
    /// persists inline, matching the pre-deferral behavior. A persist failure is
    /// logged and the queued entry retried on the next accepted ticket; the
    /// in-memory record keeps gating replays either way — only its restart
    /// durability is delayed. Mirrors the marker guard's `persist_in_background`
    /// ([`crate::transport::udp::marker_replay`]).
    fn persist_in_background(&self) {
        let slot = Arc::clone(&self.cache);
        let persist = move || Self::persist_checked_out(&slot);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(persist);
            }
            Err(_) => persist(),
        }
    }

    /// Drain the queued durable persist (journal append + fsync) for `slot`.
    /// Checks the cache OUT under a short lock and runs the blocking fsync with
    /// the lock RELEASED — holding the mutex across the fsync would make the
    /// driver-side `try_lock` in `accept_ticket` fail for the whole disk write
    /// (see the module docs' locking discipline). Recovers from a poisoned lock
    /// rather than dropping durability (cache invariants are restored on each
    /// insert, so persisting the recovered state is safe).
    fn persist_checked_out(slot: &Arc<Mutex<Option<ReplayCache>>>) {
        let checked_out = slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(mut cache) = checked_out else {
            // Another persist has the cache checked out. Inserts are impossible
            // while it is out (accept fails closed), so every queued entry —
            // including the one that triggered this call — is already inside that
            // persist's cache and will be drained by it.
            return;
        };
        let result = cache.persist_pending();
        // Put the cache back BEFORE acting on the outcome so 0-RTT accepts resume
        // even when the persist failed.
        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(cache);
        if let Err(err) = result {
            tracing::warn!(
                error = %err,
                "0-RTT replay cache persist failed; ticket accept recorded \
                 in memory only (retried on the next accepted ticket)"
            );
        }
    }

    /// Test-only: synchronously drain any queued durable persist so a test can
    /// observe cross-restart durability deterministically without racing the
    /// `spawn_blocking` fsync. Blocks on `try_lock`-free take/fsync/put-back and
    /// retries briefly if a background persist is momentarily mid-flight.
    #[cfg(test)]
    pub(crate) fn flush_pending_for_test(&self) {
        // Retry until we ourselves successfully TAKE the cache and drain it — do
        // not just check `is_some()` (which races a concurrent take) or fall back
        // to `persist_checked_out` (which early-returns on a checked-out `None`,
        // leaving the pending write unflushed). Taking the cache atomically and
        // persisting guarantees that on return every entry that existed is durable:
        // either an in-flight background persist already wrote it (and we then drain
        // an empty queue), or we write it ourselves.
        for _ in 0..1000 {
            let taken = self
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            match taken {
                Some(mut cache) => {
                    let result = cache.persist_pending();
                    *self
                        .cache
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(cache);
                    result.expect("flush_pending_for_test: persist failed");
                    return;
                }
                None => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
        panic!("flush_pending_for_test: background persist never released the cache");
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
        // The single-use decision is made SYNCHRONOUSLY under the lock (a replay is
        // gated the instant this returns); only the durable journal fsync is
        // deferred to a blocking thread, so the shared driver task is never stalled
        // on disk (issue #24 — see the module docs for the accepted crash-window
        // tradeoff). This runs on the single QUIC driver task, so the lock is taken
        // NON-BLOCKING: if it is contended, poisoned, or the cache is checked out
        // by an in-flight background persist, the 0-RTT attempt FAILS CLOSED — the
        // client falls back to a full 1-RTT handshake, which is always safe — rather
        // than block the driver or risk accepting a replay (see the module docs'
        // locking discipline). This mirrors the marker guard exactly.
        let accepted = match self.cache.try_lock() {
            Ok(mut slot) => match slot.as_mut() {
                Some(cache) => {
                    cache.insert_new_outcome_deferred(entry, now_unix)
                        == ReplayInsertOutcome::Inserted
                }
                // A background persist has the cache checked out for its fsync:
                // fail closed to 1-RTT instead of waiting on the disk.
                None => false,
            },
            Err(_) => false,
        };
        if accepted {
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
    fn accept_during_in_flight_persist_fails_closed_without_blocking() {
        // `accept_ticket` runs on the single QUIC driver task. While a background
        // persist has the cache checked out for its fsync, the driver must NOT
        // block on the lock: the 0-RTT attempt fails closed (the client falls back
        // to a full 1-RTT handshake) immediately, and single-use is still enforced
        // once the persist completes.
        let g = guard();
        let now = 4_000_000;
        let ticket = b"ticket-during-persist";

        // Simulate an in-flight background persist exactly as
        // `persist_in_background` does: check the cache out of the slot.
        let checked_out = g
            .cache
            .lock()
            .unwrap()
            .take()
            .expect("cache starts in the slot");
        let start = std::time::Instant::now();
        let accepted = g.accept_ticket(ticket, now);
        let elapsed = start.elapsed();
        assert!(
            !accepted,
            "0-RTT fails closed to 1-RTT while a persist is in flight"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "accept must not block while the persist runs (took {elapsed:?})"
        );

        // Persist finishes: the cache returns to the slot. The failed-closed
        // attempt was never recorded — its early data was never accepted — so the
        // ticket's first ACCEPTED use happens now, and stays single-use.
        *g.cache.lock().unwrap() = Some(checked_out);
        assert!(
            g.accept_ticket(ticket, now),
            "accepted once the persist completed"
        );
        assert!(!g.accept_ticket(ticket, now), "replay is still gated");
    }

    #[test]
    fn accept_never_blocks_on_a_contended_lock() {
        // Complement to the checked-out case: raw mutex contention (another thread
        // holding the slot lock) must not block the driver either — `try_lock`
        // fails closed to 1-RTT immediately.
        use std::sync::mpsc;

        let g = Arc::new(guard());
        let now = 5_000_000;
        let ticket = b"ticket-under-contention";

        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = {
            let g = Arc::clone(&g);
            std::thread::spawn(move || {
                let slot = g.cache.lock().unwrap();
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                drop(slot);
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
}
