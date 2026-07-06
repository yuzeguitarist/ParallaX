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

use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::crypto::quic_marker::Marker;
use crate::crypto::replay::{ReplayCache, ReplayEntry, ReplayInsertOutcome};

/// A persistent first-sighting guard for origin-splice auth markers, backed by the
/// crash-safe [`ReplayCache`]. Build the wrapped cache with a freshness window `>=`
/// the marker freshness window so a replay stays detectable for as long as the
/// marker is valid.
pub struct MarkerReplayGuard {
    /// The cache normally lives in this slot; a background persist checks it out
    /// (slot -> `None`) for the duration of the journal fsync and puts it back
    /// after, so the mutex is only ever held for memory-fast operations — never
    /// across disk I/O (same locking discipline as the 0-RTT guard, see
    /// [`crate::transport::udp::zero_rtt`]).
    cache: Arc<Mutex<Option<ReplayCache>>>,
}

impl MarkerReplayGuard {
    pub(crate) fn new(cache: ReplayCache) -> Self {
        Self {
            cache: Arc::new(Mutex::new(Some(cache))),
        }
    }

    /// Record the marker and report whether this is its FIRST sighting. `true` means
    /// the connection may terminate locally (a real, non-replayed ParallaX client);
    /// `false` means a replay (or a poisoned/contended lock, an in-flight background
    /// persist, or a full or stale cache) and the flow must be spliced to the
    /// origin. `now_unix` is the current Unix time in seconds.
    ///
    /// The dedup decision is made synchronously in memory under the lock (so a
    /// replayed marker is gated the instant its first sighting returns), but the
    /// durable journal write — an fsync — is offloaded to a blocking thread
    /// (issue #24): this method runs on the async QUIC endpoint driver task, and a
    /// blocking fsync held under the mutex there stalls the whole executor. For the
    /// same reason the lock here is taken NON-BLOCKING (`try_lock`): if the gate
    /// cannot be consulted immediately the marker FAILS CLOSED to a splice rather
    /// than stall the driver waiting for a persist's fsync.
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
        let inserted = match self.cache.try_lock() {
            Ok(mut slot) => match slot.as_mut() {
                Some(cache) => {
                    cache.insert_new_outcome_deferred(entry, now_unix)
                        == ReplayInsertOutcome::Inserted
                }
                // A background persist has the cache checked out for its fsync:
                // fail closed (splice to origin) instead of waiting on the disk.
                None => false,
            },
            // A poisoned or contended lock fails closed: treat as a replay (splice
            // to origin) rather than block the driver or risk re-exposing the
            // local termination path.
            Err(_) => false,
        };
        if inserted {
            self.persist_in_background();
        }
        inserted
    }

    /// Runs the queued durable persist (journal append + fsync) off the async
    /// executor via `spawn_blocking`. Outside a tokio runtime (sync tests) it
    /// persists inline, matching the pre-deferral behavior. A persist failure is
    /// logged and the queued entry retried on the next sighting; the in-memory
    /// record keeps gating replays either way — only its restart durability is
    /// delayed.
    fn persist_in_background(&self) {
        let slot = Arc::clone(&self.cache);
        let persist = move || {
            // Check the cache OUT under a short lock and run the blocking journal
            // fsync with the lock RELEASED: holding the mutex across the fsync
            // would make the driver-side `try_lock` in `first_sighting` fail for
            // the whole disk write (same locking discipline as the 0-RTT guard).
            //
            // Recover from a poisoned lock rather than dropping durability: the
            // cache invariants are restored on each insert, so persisting the
            // recovered state is safe (mirrors the auth handshake's replay insert).
            let checked_out = slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            let Some(mut cache) = checked_out else {
                // Another persist has the cache checked out. Inserts are
                // impossible while it is out (first_sighting fails closed), so
                // every queued entry — including the one that triggered this call
                // — is already inside that persist's cache and will be drained by
                // it.
                return;
            };
            let result = cache.persist_pending();
            // Put the cache back BEFORE acting on the outcome so first sightings
            // resume even when the persist failed.
            *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(cache);
            if let Err(err) = result {
                tracing::warn!(
                    error = %err,
                    "marker replay cache persist failed; first sighting recorded \
                     in memory only (retried on the next sighting)"
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

    #[test]
    fn first_sighting_during_in_flight_persist_fails_closed_without_blocking() {
        // Same driver-side invariant as the 0-RTT guard: `first_sighting` runs on
        // the QUIC endpoint driver task. While a background persist has the cache
        // checked out for its fsync the driver must NOT block on the lock — the
        // marker fails closed (spliced to the origin) immediately, and single-use
        // is still enforced once the persist completes.
        let g = guard();
        let now = 1_900_000_000;
        let m = marker(0x44, now);

        // Simulate an in-flight background persist exactly as
        // `persist_in_background` does: check the cache out of the slot.
        let checked_out = g
            .cache
            .lock()
            .unwrap()
            .take()
            .expect("cache starts in the slot");
        let start = std::time::Instant::now();
        let sighted = g.first_sighting(&m, now);
        let elapsed = start.elapsed();
        assert!(
            !sighted,
            "fails closed (splice to origin) while a persist is in flight"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "first_sighting must not block while the persist runs (took {elapsed:?})"
        );

        // Persist finishes: the cache returns to the slot. The failed-closed
        // sighting was never recorded (the flow was spliced, not terminated), so
        // the first RECORDED sighting happens now — and stays single-use.
        *g.cache.lock().unwrap() = Some(checked_out);
        assert!(
            g.first_sighting(&m, now),
            "terminates once the persist completed"
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
}
