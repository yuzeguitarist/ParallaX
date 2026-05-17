//! Verdict aggregation + scenario reports.

use std::time::Duration;

use crate::gfw_sim::detection::{
    active_prober::ProbeAggregate, burst_statistics::BurstVerdict, dns_inject::DnsAction,
    fully_encrypted::FullyEncryptedVerdict, http_host::HttpHostVerdict,
    quic_initial::QuicInitialVerdict, sni_filter::SniVerdict, tcp_dual_mb::DualMbDecision,
    tls_fingerprint::TlsFingerprintVerdict,
};
use crate::gfw_sim::injection::EgressAction;

#[derive(Debug, Clone, PartialEq)]
pub enum VerdictKind {
    Allow,
    Block,
    Suspicious,
    Inconclusive,
}

#[derive(Debug, Clone)]
pub struct LayerVerdict {
    pub layer: &'static str,
    pub kind: VerdictKind,
    pub detail: String,
}

impl LayerVerdict {
    pub fn allow(layer: &'static str, detail: impl Into<String>) -> Self {
        Self {
            layer,
            kind: VerdictKind::Allow,
            detail: detail.into(),
        }
    }
    pub fn block(layer: &'static str, detail: impl Into<String>) -> Self {
        Self {
            layer,
            kind: VerdictKind::Block,
            detail: detail.into(),
        }
    }
    pub fn suspicious(layer: &'static str, detail: impl Into<String>) -> Self {
        Self {
            layer,
            kind: VerdictKind::Suspicious,
            detail: detail.into(),
        }
    }
    pub fn inconclusive(layer: &'static str, detail: impl Into<String>) -> Self {
        Self {
            layer,
            kind: VerdictKind::Inconclusive,
            detail: detail.into(),
        }
    }
}

impl From<SniVerdict> for LayerVerdict {
    fn from(v: SniVerdict) -> Self {
        match v {
            SniVerdict::Allow { sni } => LayerVerdict::allow("sni_filter", format!("SNI={sni}")),
            SniVerdict::Block { sni, matched_rule } => LayerVerdict::block(
                "sni_filter",
                format!("SNI={sni} matched_rule={matched_rule}"),
            ),
            SniVerdict::BlockEncryptedClientHello { kind, ext_type } => LayerVerdict::block(
                "sni_filter",
                format!("{} extension type=0x{ext_type:04x}", kind.label()),
            ),
            SniVerdict::NoSni => LayerVerdict::suspicious("sni_filter", "no SNI extension"),
            SniVerdict::NotTls => LayerVerdict::inconclusive("sni_filter", "not a TLS record"),
        }
    }
}

impl From<DualMbDecision> for LayerVerdict {
    fn from(d: DualMbDecision) -> Self {
        match d {
            DualMbDecision::Allow => LayerVerdict::allow("tcp_dual_mb", "allow"),
            DualMbDecision::BlockSni { sni, matched_rule } => LayerVerdict::block(
                "tcp_dual_mb",
                format!("SNI={sni} matched_rule={matched_rule}"),
            ),
            DualMbDecision::BlockEncryptedClientHello { kind, ext_type } => LayerVerdict::block(
                "tcp_dual_mb",
                format!("{kind} extension type=0x{ext_type:04x}"),
            ),
            DualMbDecision::BlockFingerprint {
                fingerprint_summary,
            } => LayerVerdict::block("tcp_dual_mb", fingerprint_summary),
            DualMbDecision::BlockNoSni => LayerVerdict::block("tcp_dual_mb", "no SNI"),
            DualMbDecision::Suspicious { reason } => {
                LayerVerdict::suspicious("tcp_dual_mb", reason)
            }
        }
    }
}

impl From<HttpHostVerdict> for LayerVerdict {
    fn from(v: HttpHostVerdict) -> Self {
        match v {
            HttpHostVerdict::Allow { host } => {
                LayerVerdict::allow("http_host", format!("Host={host}"))
            }
            HttpHostVerdict::Block { host, matched_rule } => LayerVerdict::block(
                "http_host",
                format!("Host={host} matched_rule={matched_rule}"),
            ),
            HttpHostVerdict::NoHost => LayerVerdict::suspicious("http_host", "no Host header"),
            HttpHostVerdict::NotHttp => LayerVerdict::inconclusive("http_host", "not HTTP"),
        }
    }
}

impl From<FullyEncryptedVerdict> for LayerVerdict {
    fn from(v: FullyEncryptedVerdict) -> Self {
        match v {
            FullyEncryptedVerdict::Exempt { signals } => LayerVerdict::allow(
                "fully_encrypted",
                format!(
                    "exempt (density={:.2} printable={:.2} run={} proto={:?})",
                    signals.bit_density,
                    signals.printable_fraction,
                    signals.longest_printable_run,
                    signals.protocol_match,
                ),
            ),
            FullyEncryptedVerdict::CandidateForBlock {
                signals,
                block_sampled,
            } => {
                if block_sampled {
                    LayerVerdict::block(
                        "fully_encrypted",
                        format!(
                            "candidate, 26.3% sampling fired (density={:.2})",
                            signals.bit_density
                        ),
                    )
                } else {
                    LayerVerdict::suspicious(
                        "fully_encrypted",
                        format!(
                            "candidate, 26.3% sampling did not fire (density={:.2})",
                            signals.bit_density
                        ),
                    )
                }
            }
        }
    }
}

impl From<TlsFingerprintVerdict> for LayerVerdict {
    fn from(v: TlsFingerprintVerdict) -> Self {
        match v {
            TlsFingerprintVerdict::KnownBrowser { fingerprints } => LayerVerdict::allow(
                "tls_fingerprint",
                format!("JA3={} JA4={}", fingerprints.ja3, fingerprints.ja4),
            ),
            TlsFingerprintVerdict::KnownProxy { fingerprints } => LayerVerdict::block(
                "tls_fingerprint",
                format!(
                    "known proxy fingerprint JA3={} JA4={}",
                    fingerprints.ja3, fingerprints.ja4
                ),
            ),
            TlsFingerprintVerdict::Unknown { fingerprints } => LayerVerdict::suspicious(
                "tls_fingerprint",
                format!(
                    "unknown fingerprint JA3={} JA4={}",
                    fingerprints.ja3, fingerprints.ja4
                ),
            ),
            TlsFingerprintVerdict::NotTls => {
                LayerVerdict::inconclusive("tls_fingerprint", "not a TLS record")
            }
        }
    }
}

impl From<QuicInitialVerdict> for LayerVerdict {
    fn from(v: QuicInitialVerdict) -> Self {
        match v {
            QuicInitialVerdict::AllowSni { sni, .. } => {
                LayerVerdict::allow("quic_initial", format!("SNI={sni}"))
            }
            QuicInitialVerdict::BlockSni {
                sni, matched_rule, ..
            } => LayerVerdict::block(
                "quic_initial",
                format!("SNI={sni} matched_rule={matched_rule}"),
            ),
            QuicInitialVerdict::NoSni { .. } => {
                LayerVerdict::suspicious("quic_initial", "no SNI extension")
            }
            QuicInitialVerdict::Failed(reason) => {
                LayerVerdict::inconclusive("quic_initial", reason)
            }
        }
    }
}

impl From<BurstVerdict> for LayerVerdict {
    fn from(v: BurstVerdict) -> Self {
        match v {
            BurstVerdict::LooksClean { chi_squared } => LayerVerdict::allow(
                "burst_statistics",
                format!("chi^2={:.2} (below threshold)", chi_squared),
            ),
            BurstVerdict::AnomalousLengths { chi_squared } => LayerVerdict::suspicious(
                "burst_statistics",
                format!("chi^2={:.2} (anomalous)", chi_squared),
            ),
            BurstVerdict::LooksLikeProxy {
                chi_squared,
                mahalanobis,
            } => LayerVerdict::block(
                "burst_statistics",
                format!(
                    "chi^2={:.2} mahalanobis to {} = {:.2}",
                    chi_squared, mahalanobis.closest_label, mahalanobis.closest_distance
                ),
            ),
        }
    }
}

impl From<ProbeAggregate> for LayerVerdict {
    fn from(v: ProbeAggregate) -> Self {
        let detail = format!(
            "max={:.2} top2={:.2} per_probe={:?}",
            v.max_score, v.top_two_avg, v.per_probe
        );
        match v.verdict {
            crate::gfw_sim::detection::active_prober::ProbeAggregateVerdict::ConfirmedProxy => {
                LayerVerdict::block("active_prober", detail)
            }
            crate::gfw_sim::detection::active_prober::ProbeAggregateVerdict::Suspicious => {
                LayerVerdict::suspicious("active_prober", detail)
            }
            crate::gfw_sim::detection::active_prober::ProbeAggregateVerdict::Inconclusive => {
                LayerVerdict::inconclusive("active_prober", detail)
            }
        }
    }
}

impl From<DnsAction> for LayerVerdict {
    fn from(v: DnsAction) -> Self {
        match v {
            DnsAction::Allow => LayerVerdict::allow("dns_inject", "no keyword match"),
            DnsAction::InjectFakeResponse {
                matched_keyword,
                injector_trace,
                ..
            } => LayerVerdict::block(
                "dns_inject",
                format!(
                    "injected fake A-record for keyword={matched_keyword} via {} injectors",
                    injector_trace.len()
                ),
            ),
            DnsAction::Drop { matched_keyword } => LayerVerdict::block(
                "dns_inject",
                format!("dropped query (keyword={matched_keyword})"),
            ),
        }
    }
}

/// Aggregate report for one red-team scenario.
#[derive(Debug, Clone)]
pub struct ScenarioReport {
    pub scenario: String,
    pub flow_label: String,
    pub layer_verdicts: Vec<LayerVerdict>,
    pub egress_actions: Vec<EgressAction>,
    pub duration: Duration,
}

impl ScenarioReport {
    pub fn final_verdict(&self) -> VerdictKind {
        if self
            .layer_verdicts
            .iter()
            .any(|v| v.kind == VerdictKind::Block)
        {
            VerdictKind::Block
        } else if self
            .layer_verdicts
            .iter()
            .any(|v| v.kind == VerdictKind::Suspicious)
        {
            VerdictKind::Suspicious
        } else if self
            .layer_verdicts
            .iter()
            .any(|v| v.kind == VerdictKind::Allow)
        {
            VerdictKind::Allow
        } else {
            VerdictKind::Inconclusive
        }
    }

    /// Generate a human-readable summary suitable for printing in test output.
    pub fn pretty(&self) -> String {
        let mut s = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(
            s,
            "============== {} ({}) ==============",
            self.scenario, self.flow_label
        );
        let _ = writeln!(s, "elapsed:  {:?}", self.duration);
        let _ = writeln!(s, "verdict:  {:?}", self.final_verdict());
        let _ = writeln!(s, "layers:");
        for v in &self.layer_verdicts {
            let _ = writeln!(s, "  - [{}] {:?} :: {}", v.layer, v.kind, v.detail);
        }
        if !self.egress_actions.is_empty() {
            let _ = writeln!(s, "egress actions:");
            for a in &self.egress_actions {
                let _ = writeln!(s, "  - {:?}", a);
            }
        }
        s
    }
}
