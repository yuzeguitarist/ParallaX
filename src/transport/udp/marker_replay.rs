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

use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::crypto::quic_marker::Marker;
use crate::crypto::replay::{ReplayCache, ReplayEntry, ReplayInsertOutcome};

/// A persistent first-sighting guard for origin-splice auth markers, backed by the
/// crash-safe [`ReplayCache`]. Build the wrapped cache with a freshness window `>=`
/// the marker freshness window so a replay stays detectable for as long as the
/// marker is valid.
pub struct MarkerReplayGuard {
    cache: Mutex<ReplayCache>,
}

impl MarkerReplayGuard {
    pub(crate) fn new(cache: ReplayCache) -> Self {
        Self {
            cache: Mutex::new(cache),
        }
    }

    /// Record the marker and report whether this is its FIRST sighting. `true` means
    /// the connection may terminate locally (a real, non-replayed ParallaX client);
    /// `false` means a replay (or a poisoned lock / full or stale cache) and the flow
    /// must be spliced to the origin. `now_unix` is the current Unix time in seconds.
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
        match self.cache.lock() {
            Ok(mut cache) => matches!(
                cache.insert_new_outcome(entry, now_unix),
                Ok(ReplayInsertOutcome::Inserted)
            ),
            // A poisoned lock fails closed: treat as a replay (splice to origin)
            // rather than risk re-exposing the local termination path.
            Err(_) => false,
        }
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
}
