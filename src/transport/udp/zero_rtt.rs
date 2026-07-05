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

use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::crypto::replay::{ReplayCache, ReplayEntry, ReplayInsertOutcome};
use crate::tls::quic::ZeroRttGuard;

/// A [`ZeroRttGuard`] backed by the persistent [`ReplayCache`]. The wrapped cache
/// should be built with a freshness window `>=` the issued ticket lifetime so a
/// replay is still detected for as long as the ticket is valid.
pub(crate) struct ReplayCacheGuard {
    cache: Arc<Mutex<ReplayCache>>,
}

impl ReplayCacheGuard {
    pub(crate) fn new(cache: ReplayCache) -> Self {
        Self {
            cache: Arc::new(Mutex::new(cache)),
        }
    }

    /// Runs the queued durable persist (journal append + fsync) off the async
    /// executor via `spawn_blocking`, reacquiring the lock only inside the
    /// blocking pool. Outside a tokio runtime (sync tests) it persists inline,
    /// matching the pre-deferral behavior. A persist failure is logged and the
    /// queued entry retried on the next accepted ticket; the in-memory record keeps
    /// gating replays either way — only its restart durability is delayed. Mirrors
    /// the marker guard's `persist_in_background`
    /// ([`crate::transport::udp::marker_replay`]).
    fn persist_in_background(&self) {
        let cache = Arc::clone(&self.cache);
        let persist = move || {
            // Recover from a poisoned lock rather than dropping durability: the
            // cache invariants are restored on each insert, so persisting the
            // recovered state is safe (mirrors the marker guard's persist path).
            let mut cache = cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Err(err) = cache.persist_pending() {
                tracing::warn!(
                    error = %err,
                    "0-RTT replay cache persist failed; ticket accept recorded \
                     in memory only (retried on the next accepted ticket)"
                );
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(persist);
            }
            Err(_) => persist(),
        }
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
        // tradeoff). This mirrors the marker guard exactly.
        let accepted = match self.cache.lock() {
            Ok(mut cache) => {
                cache.insert_new_outcome_deferred(entry, now_unix) == ReplayInsertOutcome::Inserted
            }
            // A poisoned lock fails closed: reject 0-RTT (the client falls back to
            // a full 1-RTT handshake) rather than risk accepting a replay.
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
