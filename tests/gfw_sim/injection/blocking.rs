//! Concrete blocking actions and the residual-block 3-tuple table.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 3-tuple used by the residual rule: identical (client_ip, server_ip,
/// server_port) triples are dropped for 180 s after a blocking event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResidualBlockTuple {
    pub client_ip: IpAddr,
    pub server_ip: IpAddr,
    pub server_port: u16,
    /// Layer-4 protocol: 6 = TCP, 17 = UDP.
    pub protocol: u8,
}

impl ResidualBlockTuple {
    pub fn tcp(client_ip: IpAddr, server_ip: IpAddr, server_port: u16) -> Self {
        Self {
            client_ip,
            server_ip,
            server_port,
            protocol: 6,
        }
    }
    pub fn udp(client_ip: IpAddr, server_ip: IpAddr, server_port: u16) -> Self {
        Self {
            client_ip,
            server_ip,
            server_port,
            protocol: 17,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpResetReason {
    SniBlocklist,
    EncryptedClientHello,
    HttpHostBlocklist,
    KnownProxyFingerprint,
    FullyEncryptedSampling,
    DualMbReinforcement,
    ActiveProberConfirmed,
    BurstStatisticsAnomaly,
    ResidualBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDropReason {
    QuicSniBlocklist,
    QuicInitialDecryptFailed,
    ResidualBlock,
}

/// Composite egress action taken by the simulator on a per-packet basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressAction {
    Allow,
    TcpReset {
        reason: TcpResetReason,
        seq_ack_note: String,
    },
    UdpDrop {
        reason: UdpDropReason,
    },
    DnsInjectionEmitted,
}

/// Per-action log entry preserved for the red-team scenarios.
#[derive(Debug, Clone)]
pub struct ActionLog {
    pub at: Instant,
    pub action: EgressAction,
    pub triple: Option<ResidualBlockTuple>,
}

/// The residual block table - O(1) lookup with explicit TTL.
pub struct ResidualBlockTable {
    entries: HashMap<ResidualBlockTuple, Instant>,
    ttl: Duration,
}

impl Default for ResidualBlockTable {
    fn default() -> Self {
        Self::with_ttl(Duration::from_secs(180))
    }
}

impl ResidualBlockTable {
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn record(&mut self, triple: ResidualBlockTuple) {
        self.entries.insert(triple, Instant::now());
    }

    pub fn is_blocked(&mut self, triple: &ResidualBlockTuple) -> bool {
        let now = Instant::now();
        self.gc(now);
        match self.entries.get(triple) {
            Some(when) => now.duration_since(*when) < self.ttl,
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn gc(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, when| now.duration_since(*when) < ttl);
    }
}

/// Blocking policy: the runtime queries this on every verdict to translate
/// detection results into a concrete `EgressAction`. Configurable knobs let
/// red-team scenarios disable individual layers (e.g. "what if the GFW had no
/// active prober?").
#[derive(Debug, Clone)]
pub struct BlockingPolicy {
    pub enforce_sni_blocklist: bool,
    pub enforce_encrypted_client_hello: bool,
    pub enforce_http_host_blocklist: bool,
    pub enforce_fully_encrypted_sampling: bool,
    pub enforce_known_proxy_fingerprint: bool,
    pub enforce_active_probe_confirmation: bool,
    pub enforce_burst_anomaly: bool,
    pub residual_block_seconds: u64,
}

impl Default for BlockingPolicy {
    fn default() -> Self {
        Self {
            enforce_sni_blocklist: true,
            enforce_encrypted_client_hello: true,
            enforce_http_host_blocklist: true,
            enforce_fully_encrypted_sampling: true,
            enforce_known_proxy_fingerprint: true,
            enforce_active_probe_confirmation: true,
            enforce_burst_anomaly: true,
            residual_block_seconds: 180,
        }
    }
}

impl BlockingPolicy {
    pub fn permissive() -> Self {
        Self {
            enforce_sni_blocklist: false,
            enforce_encrypted_client_hello: false,
            enforce_http_host_blocklist: false,
            enforce_fully_encrypted_sampling: false,
            enforce_known_proxy_fingerprint: false,
            enforce_active_probe_confirmation: false,
            enforce_burst_anomaly: false,
            residual_block_seconds: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread::sleep;

    fn tcp_triple() -> ResidualBlockTuple {
        ResidualBlockTuple::tcp(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        )
    }

    #[test]
    fn residual_table_remembers_block_within_ttl() {
        let mut t = ResidualBlockTable::with_ttl(Duration::from_secs(1));
        let triple = tcp_triple();
        assert!(!t.is_blocked(&triple));
        t.record(triple);
        assert!(t.is_blocked(&triple));
    }

    #[test]
    fn residual_table_expires_after_ttl() {
        let mut t = ResidualBlockTable::with_ttl(Duration::from_millis(20));
        let triple = tcp_triple();
        t.record(triple);
        assert!(t.is_blocked(&triple));
        sleep(Duration::from_millis(30));
        assert!(!t.is_blocked(&triple));
    }

    #[test]
    fn tcp_and_udp_tuples_are_distinct() {
        let mut t = ResidualBlockTable::default();
        let tcp = tcp_triple();
        let udp = ResidualBlockTuple::udp(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        );
        t.record(tcp);
        assert!(t.is_blocked(&tcp));
        assert!(!t.is_blocked(&udp));
    }

    #[test]
    fn permissive_policy_disables_all_enforcement() {
        let p = BlockingPolicy::permissive();
        assert!(!p.enforce_sni_blocklist);
        assert!(!p.enforce_encrypted_client_hello);
        assert!(!p.enforce_http_host_blocklist);
        assert!(!p.enforce_fully_encrypted_sampling);
        assert!(!p.enforce_known_proxy_fingerprint);
        assert!(!p.enforce_active_probe_confirmation);
        assert!(!p.enforce_burst_anomaly);
    }
}
