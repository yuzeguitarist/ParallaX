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

use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::crypto::replay::{ReplayCache, ReplayEntry, ReplayInsertOutcome};
use crate::tls::quic::ZeroRttGuard;

/// A [`ZeroRttGuard`] backed by the persistent [`ReplayCache`]. The wrapped cache
/// should be built with a freshness window `>=` the issued ticket lifetime so a
/// replay is still detected for as long as the ticket is valid.
pub(crate) struct ReplayCacheGuard {
    cache: Mutex<ReplayCache>,
}

impl ReplayCacheGuard {
    pub(crate) fn new(cache: ReplayCache) -> Self {
        Self {
            cache: Mutex::new(cache),
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
        match self.cache.lock() {
            Ok(mut cache) => matches!(
                cache.insert_new_outcome(entry, now_unix),
                Ok(ReplayInsertOutcome::Inserted)
            ),
            // A poisoned lock fails closed: reject 0-RTT (the client falls back to
            // a full 1-RTT handshake) rather than risk accepting a replay.
            Err(_) => false,
        }
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
}
