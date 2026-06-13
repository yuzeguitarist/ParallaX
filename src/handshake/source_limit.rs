//! Per-source admission control for the camouflage relay.
//!
//! The global connection semaphore caps the *total* number of concurrent
//! relays, but with the fallback idle backstop raised to 600s a single source
//! that triggers fallback can pin global slots for up to ten minutes. This
//! limiter caps how many concurrent connections one source (an IPv4 /32 or an
//! IPv6 prefix) may hold at once, so no single source can monopolize the global
//! pool while the backstop is high.
//!
//! It is intentionally a *concurrency* cap, not a rate limiter: a per-second
//! token bucket would falsely reject legitimate bursts from shared/CGNAT
//! addresses (an office, a school, a mobile carrier behind one public IP) and,
//! worse, the clean-close-without-ServerHello it would emit is itself an
//! observable "this box rate-limits" tell. The concurrency cap plus the global
//! semaphore already bound single-source slot monopolization, which is the only
//! threat the 600s backstop introduces.
//!
//! Spoofed source IPs cannot reach this limiter: `accept()` returns only after
//! the TCP handshake completes, so `peer.ip()` is return-routable. The bounded,
//! self-expiring map defends against *many distinct real sources* (a botnet),
//! not spoofing.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Idle entries (no active connections) are evicted this long after going idle.
const SOURCE_IDLE_GRACE: Duration = Duration::from_secs(120);
/// Lower bound on the map size so a tiny `relay_connection_limit` still leaves
/// headroom for idle entries before eviction kicks in.
const MIN_SOURCE_MAP_ENTRIES: usize = 4096;
/// Max idle-log entries inspected per admission so the accept path stays cheap.
const PRUNE_BUDGET: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum SourceKey {
    /// IPv4 /32 (also used for IPv4-mapped IPv6).
    V4([u8; 4]),
    /// IPv6 masked to the configured prefix (default /64).
    V6([u8; 16]),
}

struct Entry {
    active: u32,
    /// `Some(t)` when `active == 0`, recording when it went idle. Compared
    /// against the idle-log timestamp so a re-activated-then-re-idled entry is
    /// not evicted by a stale log record.
    idle_since: Option<Instant>,
}

struct Inner {
    map: HashMap<SourceKey, Entry>,
    /// `(key, time-it-went-idle)`. A key may appear several times; stale records
    /// are skipped on prune by comparing against the live `idle_since`.
    idle_log: VecDeque<(SourceKey, Instant)>,
}

/// Caps concurrent connections per source. Cheap to clone via `Arc`.
pub struct SourceLimiter {
    inner: Mutex<Inner>,
    cap_v4: u32,
    cap_v6: u32,
    v6_prefix_len: u8,
    max_entries: usize,
    idle_grace: Duration,
}

/// Held for the whole connection lifetime; decrements the source's active count
/// on drop and stamps the entry idle when it reaches zero.
pub struct SourcePermit {
    limiter: Arc<SourceLimiter>,
    key: SourceKey,
}

impl Drop for SourcePermit {
    fn drop(&mut self) {
        let now = Instant::now();
        let mut inner = self
            .limiter
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let became_idle = match inner.map.get_mut(&self.key) {
            Some(entry) => {
                entry.active = entry.active.saturating_sub(1);
                if entry.active == 0 {
                    entry.idle_since = Some(now);
                    true
                } else {
                    false
                }
            }
            None => false,
        };
        if became_idle {
            inner.idle_log.push_back((self.key, now));
        }
    }
}

impl SourceLimiter {
    /// Build a limiter sized against the global connection limit. `max_entries`
    /// is kept comfortably above `connection_limit` so active entries (which can
    /// never exceed the global limit) always fit and only idle entries are ever
    /// evicted.
    pub fn new(cap_v4: u32, cap_v6: u32, v6_prefix_len: u8, connection_limit: usize) -> Arc<Self> {
        let max_entries = connection_limit
            .saturating_mul(4)
            .max(MIN_SOURCE_MAP_ENTRIES);
        Self::with_params(
            cap_v4,
            cap_v6,
            v6_prefix_len,
            max_entries,
            SOURCE_IDLE_GRACE,
        )
    }

    fn with_params(
        cap_v4: u32,
        cap_v6: u32,
        v6_prefix_len: u8,
        max_entries: usize,
        idle_grace: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                idle_log: VecDeque::new(),
            }),
            cap_v4,
            cap_v6,
            v6_prefix_len,
            max_entries,
            idle_grace,
        })
    }

    /// Admit a connection from `ip`, returning a permit that must be held for the
    /// connection's lifetime, or `None` if the source is at its concurrency cap.
    pub fn try_admit(self: Arc<Self>, ip: IpAddr) -> Option<SourcePermit> {
        let key = self.key_for(ip);
        let cap = self.cap_for(&key);
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.prune_locked(&mut inner);
        let entry = inner.map.entry(key).or_insert(Entry {
            active: 0,
            idle_since: None,
        });
        if entry.active >= cap {
            return None;
        }
        entry.active += 1;
        entry.idle_since = None;
        drop(inner);
        Some(SourcePermit { limiter: self, key })
    }

    fn key_for(&self, ip: IpAddr) -> SourceKey {
        match ip {
            IpAddr::V4(v4) => SourceKey::V4(v4.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => SourceKey::V4(v4.octets()),
                None => SourceKey::V6(masked_v6(v6, self.v6_prefix_len)),
            },
        }
    }

    fn cap_for(&self, key: &SourceKey) -> u32 {
        match key {
            SourceKey::V4(_) => self.cap_v4,
            SourceKey::V6(_) => self.cap_v6,
        }
    }

    /// Evicts idle entries past the grace period, plus -- when the map is over
    /// its bound -- the oldest idle entries regardless of grace. Bounded work per
    /// call; always makes progress (pops one log record per iteration).
    fn prune_locked(&self, inner: &mut Inner) {
        let now = Instant::now();
        for _ in 0..PRUNE_BUDGET {
            let Some(&(key, logged)) = inner.idle_log.front() else {
                break;
            };
            let over_capacity = inner.map.len() > self.max_entries;
            let expired = now.saturating_duration_since(logged) >= self.idle_grace;
            if !expired && !over_capacity {
                break;
            }
            inner.idle_log.pop_front();
            if let Some(entry) = inner.map.get(&key) {
                if entry.active == 0 && entry.idle_since == Some(logged) {
                    inner.map.remove(&key);
                }
            }
        }
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .map
            .len()
    }
}

/// Masks an IPv6 address to `prefix_len` bits (host bits zeroed).
fn masked_v6(addr: Ipv6Addr, prefix_len: u8) -> [u8; 16] {
    let mut octets = addr.octets();
    let prefix = prefix_len.min(128) as usize;
    let full_bytes = prefix / 8;
    let rem_bits = prefix % 8;
    if rem_bits != 0 && full_bytes < 16 {
        let mask = 0xFFu8 << (8 - rem_bits);
        octets[full_bytes] &= mask;
        for byte in octets.iter_mut().skip(full_bytes + 1) {
            *byte = 0;
        }
    } else {
        for byte in octets.iter_mut().skip(full_bytes) {
            *byte = 0;
        }
    }
    octets
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn admits_up_to_cap_then_rejects() {
        let limiter = SourceLimiter::with_params(2, 2, 64, 4096, SOURCE_IDLE_GRACE);
        let ip = v4(203, 0, 113, 7);
        let p1 = Arc::clone(&limiter).try_admit(ip);
        let p2 = Arc::clone(&limiter).try_admit(ip);
        assert!(p1.is_some() && p2.is_some(), "within cap must admit");
        assert!(
            Arc::clone(&limiter).try_admit(ip).is_none(),
            "over cap must reject"
        );
        // A different source is unaffected.
        assert!(Arc::clone(&limiter)
            .try_admit(v4(198, 51, 100, 1))
            .is_some());
    }

    #[test]
    fn permit_drop_frees_a_slot() {
        let limiter = SourceLimiter::with_params(1, 1, 64, 4096, SOURCE_IDLE_GRACE);
        let ip = v4(203, 0, 113, 9);
        let p1 = Arc::clone(&limiter).try_admit(ip);
        assert!(p1.is_some());
        assert!(Arc::clone(&limiter).try_admit(ip).is_none(), "at cap");
        drop(p1);
        assert!(
            Arc::clone(&limiter).try_admit(ip).is_some(),
            "freed slot must re-admit"
        );
    }

    #[test]
    fn v4_and_v6_caps_are_independent() {
        let limiter = SourceLimiter::with_params(1, 3, 64, 4096, SOURCE_IDLE_GRACE);
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 1, 2, 3, 4));
        // v6 cap is 3, so three admits succeed regardless of the v4 cap of 1.
        let _a = Arc::clone(&limiter).try_admit(v6);
        let _b = Arc::clone(&limiter).try_admit(v6);
        let _c = Arc::clone(&limiter).try_admit(v6);
        assert!(_a.is_some() && _b.is_some() && _c.is_some());
        assert!(Arc::clone(&limiter).try_admit(v6).is_none());
    }

    #[test]
    fn v6_prefix_groups_addresses_in_the_same_block() {
        // /64 prefix: two addresses sharing the first 64 bits are one source.
        let limiter = SourceLimiter::with_params(8, 1, 64, 4096, SOURCE_IDLE_GRACE);
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x1, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x1, 0xffff, 0, 0, 2));
        let _a = Arc::clone(&limiter).try_admit(a);
        assert!(_a.is_some());
        assert!(
            Arc::clone(&limiter).try_admit(b).is_none(),
            "same /64 must share the cap"
        );
        // A different /64 is a different source.
        let c = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x2, 0, 0, 0, 1));
        assert!(Arc::clone(&limiter).try_admit(c).is_some());
    }

    #[test]
    fn ipv4_mapped_ipv6_is_treated_as_ipv4() {
        let limiter = SourceLimiter::with_params(1, 9, 64, 4096, SOURCE_IDLE_GRACE);
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 5).to_ipv6_mapped());
        let plain = v4(203, 0, 113, 5);
        let _a = Arc::clone(&limiter).try_admit(mapped);
        assert!(_a.is_some());
        assert!(
            Arc::clone(&limiter).try_admit(plain).is_none(),
            "mapped and plain v4 must share the v4 cap"
        );
    }

    #[test]
    fn idle_entries_are_evicted_when_over_capacity() {
        // Tiny map: 2 entries. Each admit-then-drop leaves an idle entry; the map
        // must not grow without bound as distinct sources churn through.
        let limiter = SourceLimiter::with_params(4, 4, 64, 2, Duration::from_secs(120));
        for i in 0..200u32 {
            let octet = (i % 251) as u8;
            let permit = Arc::clone(&limiter).try_admit(v4(10, 0, (i / 251) as u8, octet));
            drop(permit); // becomes idle immediately
        }
        // Over-capacity eviction keeps the map bounded near max_entries even
        // though grace has not elapsed.
        assert!(
            limiter.entry_count() <= 2 + PRUNE_BUDGET,
            "idle map must stay bounded, got {}",
            limiter.entry_count()
        );
    }

    #[test]
    fn masked_v6_zeroes_host_bits() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0xdead, 0xbeef, 0x1, 0x2, 0x3, 0x4);
        let masked = masked_v6(addr, 64);
        assert_eq!(
            masked,
            Ipv6Addr::new(0x2001, 0xdb8, 0xdead, 0xbeef, 0, 0, 0, 0).octets()
        );
        // /128 keeps the whole address; /0 zeroes everything.
        assert_eq!(masked_v6(addr, 128), addr.octets());
        assert_eq!(masked_v6(addr, 0), [0u8; 16]);
        // /56 is byte-aligned: keep bytes 0..7, zero the rest. addr byte 6 is
        // 0xbe (high byte of the 4th hextet 0xbeef), byte 7 is zeroed.
        let masked56 = masked_v6(addr, 56);
        assert_eq!(masked56[6], 0xbe);
        assert_eq!(masked56[7], 0);
        // /60 is NOT byte-aligned: byte 7 (0xef) keeps its top 4 bits -> 0xe0.
        let masked60 = masked_v6(addr, 60);
        assert_eq!(masked60[6], 0xbe);
        assert_eq!(masked60[7], 0xe0);
        assert_eq!(masked60[8], 0);
    }
}
