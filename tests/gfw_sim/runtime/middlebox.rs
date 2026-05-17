//! Transparent middlebox: drives the full detection pipeline.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use rand::{rngs::StdRng, SeedableRng};

use crate::gfw_sim::detection::{
    active_prober::{ActiveProber, ProbeObservation},
    burst_statistics::{BurstDetector, LengthObservation},
    dns_inject::{DnsAction, DnsInjector},
    fully_encrypted::{evaluate as fe_evaluate, FullyEncryptedVerdict},
    quic_initial::{QuicInitialDetector, QuicInitialVerdict, QuicTriple},
    sni_filter::{SniFilter, SniVerdict},
    tcp_dual_mb::{DualMbDecision, DualMiddlebox, FlowKey, MbrStage},
    tls_fingerprint::{evaluate as tls_fp_evaluate, TlsFingerprintVerdict},
};
use crate::gfw_sim::injection::{
    BlockingPolicy, EgressAction, ResidualBlockTable, ResidualBlockTuple, TcpResetReason,
    UdpDropReason,
};
use crate::gfw_sim::runtime::verdict::{LayerVerdict, ScenarioReport};

#[derive(Debug, Clone)]
pub struct GfwSimulatorConfig {
    pub blocking_policy: BlockingPolicy,
    pub flag_unknown_fingerprints: bool,
    pub rng_seed: u64,
}

impl Default for GfwSimulatorConfig {
    fn default() -> Self {
        Self {
            blocking_policy: BlockingPolicy::default(),
            flag_unknown_fingerprints: false,
            rng_seed: 0xCFCF_CFCF,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ClientToServerEvent {
    /// TCP payload from client - the first such event of a flow is treated as
    /// the candidate ClientHello / first packet.
    TcpPayload { bytes: Vec<u8> },
    /// UDP datagram (QUIC) from client.
    UdpDatagram { bytes: Vec<u8> },
    /// DNS query (UDP/53).
    DnsQuery { bytes: Vec<u8> },
}

#[derive(Debug, Clone)]
pub enum ServerToClientEvent {
    /// TLS record from server - used to drive MB-R transitions (ServerHello /
    /// ChangeCipherSpec / first ApplicationData).
    TcpPayload {
        bytes: Vec<u8>,
        /// `true` if this record contains the first ChangeCipherSpec for the
        /// flow.
        is_change_cipher_spec: bool,
        /// `true` if this is the first ApplicationData record.
        is_first_app_data: bool,
        /// `true` if this is the first ServerHello.
        is_server_hello: bool,
    },
}

/// Top-level GFW simulator. Owns one detector per layer and stitches them
/// into the canonical pipeline.
pub struct GfwSimulator {
    config: GfwSimulatorConfig,
    sni_filter: SniFilter,
    dual_mb: DualMiddlebox,
    quic_detector: QuicInitialDetector,
    dns_injector: DnsInjector,
    burst_detector: BurstDetector,
    active_prober: ActiveProber,
    residual: ResidualBlockTable,
    rng: StdRng,
}

impl GfwSimulator {
    pub fn new(config: GfwSimulatorConfig) -> Self {
        let dual_mb = DualMiddlebox::default()
            .with_unknown_fingerprint_flagging(config.flag_unknown_fingerprints);
        let residual = ResidualBlockTable::with_ttl(Duration::from_secs(
            config.blocking_policy.residual_block_seconds,
        ));
        let rng = StdRng::seed_from_u64(config.rng_seed);
        Self {
            config,
            sni_filter: SniFilter::default(),
            dual_mb,
            quic_detector: QuicInitialDetector::default(),
            dns_injector: DnsInjector::default(),
            burst_detector: BurstDetector::default(),
            active_prober: ActiveProber::default(),
            residual,
            rng,
        }
    }

    pub fn config(&self) -> &GfwSimulatorConfig {
        &self.config
    }

    pub fn residual_table(&mut self) -> &mut ResidualBlockTable {
        &mut self.residual
    }

    /// Top-level scenario driver. `events_c2s` is the stream of client→server
    /// events; `events_s2c` is the stream of server→client TLS records (so MB-R
    /// can transition). `length_series` is the post-handshake length series
    /// fed to the burst-statistics detector. `probe_observations` carries any
    /// active-prober results, if applicable for this scenario.
    pub fn run_scenario(&mut self, scenario: ScenarioInputs) -> ScenarioReport {
        let started = Instant::now();
        let mut layer_verdicts: Vec<LayerVerdict> = Vec::new();
        let mut egress_actions: Vec<EgressAction> = Vec::new();

        // ---------------- 1. Pre-screen residual rule ----------------
        if let Some(triple) = scenario.precheck_residual_tuple {
            if self.residual.is_blocked(&triple) {
                let reason = match triple.protocol {
                    6 => TcpResetReason::ResidualBlock,
                    17 => TcpResetReason::ResidualBlock,
                    _ => TcpResetReason::ResidualBlock,
                };
                egress_actions.push(EgressAction::TcpReset {
                    reason,
                    seq_ack_note: format!(
                        "residual-block(triple={:?}, ttl={}s)",
                        triple, self.config.blocking_policy.residual_block_seconds
                    ),
                });
                layer_verdicts.push(LayerVerdict::block(
                    "residual_block",
                    format!("3-tuple matched, drop {triple:?}"),
                ));
                return ScenarioReport {
                    scenario: scenario.label.to_owned(),
                    flow_label: scenario.flow_label.to_owned(),
                    layer_verdicts,
                    egress_actions,
                    duration: started.elapsed(),
                };
            }
        }

        // ---------------- 2. DNS path ----------------
        if let Some(dns_query) = &scenario.dns_query {
            let action = self.dns_injector.inspect(dns_query);
            match &action {
                DnsAction::InjectFakeResponse { .. } => {
                    egress_actions.push(EgressAction::DnsInjectionEmitted);
                }
                DnsAction::Drop { .. } => {
                    egress_actions.push(EgressAction::UdpDrop {
                        reason: UdpDropReason::QuicSniBlocklist,
                    });
                }
                DnsAction::Allow => {}
            }
            layer_verdicts.push(LayerVerdict::from(action));
        }

        // ---------------- 3. Client→server TCP/UDP ----------------
        for event in &scenario.events_c2s {
            match event {
                ClientToServerEvent::DnsQuery { bytes } => {
                    let act = self.dns_injector.inspect(bytes);
                    match &act {
                        DnsAction::InjectFakeResponse { .. } => {
                            egress_actions.push(EgressAction::DnsInjectionEmitted);
                        }
                        DnsAction::Drop { .. } => {
                            egress_actions.push(EgressAction::UdpDrop {
                                reason: UdpDropReason::QuicSniBlocklist,
                            });
                        }
                        DnsAction::Allow => {}
                    }
                    layer_verdicts.push(LayerVerdict::from(act));
                }
                ClientToServerEvent::TcpPayload { bytes } => {
                    self.handle_tcp_payload(
                        bytes,
                        &scenario,
                        &mut layer_verdicts,
                        &mut egress_actions,
                    );
                }
                ClientToServerEvent::UdpDatagram { bytes } => {
                    self.handle_udp_datagram(
                        bytes,
                        &scenario,
                        &mut layer_verdicts,
                        &mut egress_actions,
                    );
                }
            }
        }

        // ---------------- 4. Server→client (MB-R driver) ----------------
        if let Some(flow_key) = scenario.flow_key {
            for sevt in &scenario.events_s2c {
                let ServerToClientEvent::TcpPayload {
                    bytes,
                    is_change_cipher_spec,
                    is_first_app_data,
                    is_server_hello,
                } = sevt;
                if *is_server_hello {
                    let _ = self.dual_mb.on_server_hello(flow_key, bytes);
                }
                if *is_change_cipher_spec {
                    let _ = self.dual_mb.on_change_cipher_spec(flow_key);
                }
                if *is_first_app_data {
                    let decision = self.dual_mb.on_first_app_data(flow_key);
                    layer_verdicts.push(LayerVerdict::from(decision));
                }
            }
        }

        // ---------------- 5. Burst statistics on length series ----------------
        if !scenario.length_series.is_empty() {
            let v = self.burst_detector.evaluate(&scenario.length_series);
            let derived = LayerVerdict::from(v.clone());
            if matches!(
                derived.kind,
                crate::gfw_sim::runtime::verdict::VerdictKind::Block
            ) && self.config.blocking_policy.enforce_burst_anomaly
            {
                let triple = scenario.tcp_triple();
                egress_actions.push(EgressAction::TcpReset {
                    reason: TcpResetReason::BurstStatisticsAnomaly,
                    seq_ack_note: format!("burst_statistics {derived:?}"),
                });
                if let Some(triple) = triple {
                    self.residual.record(triple);
                }
            }
            layer_verdicts.push(derived);
        }

        // ---------------- 6. Active prober ----------------
        if !scenario.probe_observations.is_empty() {
            let agg = self
                .active_prober
                .score_observations(&scenario.probe_observations);
            let derived = LayerVerdict::from(agg.clone());
            if matches!(
                derived.kind,
                crate::gfw_sim::runtime::verdict::VerdictKind::Block
            ) && self
                .config
                .blocking_policy
                .enforce_active_probe_confirmation
            {
                if let Some(triple) = scenario.tcp_triple() {
                    egress_actions.push(EgressAction::TcpReset {
                        reason: TcpResetReason::ActiveProberConfirmed,
                        seq_ack_note: "active prober ensemble flagged".to_owned(),
                    });
                    self.residual.record(triple);
                }
            }
            layer_verdicts.push(derived);
        }

        ScenarioReport {
            scenario: scenario.label.to_owned(),
            flow_label: scenario.flow_label.to_owned(),
            layer_verdicts,
            egress_actions,
            duration: started.elapsed(),
        }
    }

    fn handle_tcp_payload(
        &mut self,
        bytes: &[u8],
        scenario: &ScenarioInputs<'_>,
        layer_verdicts: &mut Vec<LayerVerdict>,
        egress_actions: &mut Vec<EgressAction>,
    ) {
        // (a) SNI / dual middlebox.
        if let Some(flow_key) = scenario.flow_key {
            let decision = self.dual_mb.on_client_record(flow_key, bytes);
            let derived = LayerVerdict::from(decision.clone());
            if matches!(decision, DualMbDecision::BlockSni { .. })
                && self.config.blocking_policy.enforce_sni_blocklist
            {
                if let Some(triple) = scenario.tcp_triple() {
                    egress_actions.push(EgressAction::TcpReset {
                        reason: TcpResetReason::SniBlocklist,
                        seq_ack_note: format!("MB-RA block on flow {flow_key:?}"),
                    });
                    self.residual.record(triple);
                }
            } else if matches!(decision, DualMbDecision::BlockFingerprint { .. })
                && self.config.blocking_policy.enforce_known_proxy_fingerprint
            {
                if let Some(triple) = scenario.tcp_triple() {
                    egress_actions.push(EgressAction::TcpReset {
                        reason: TcpResetReason::KnownProxyFingerprint,
                        seq_ack_note: format!("MB-RA fingerprint block on flow {flow_key:?}"),
                    });
                    self.residual.record(triple);
                }
            }
            layer_verdicts.push(derived);
        } else {
            // No flow context: standalone SNI evaluation.
            let v = self.sni_filter.evaluate(bytes);
            if let SniVerdict::Block { .. } = &v {
                egress_actions.push(EgressAction::TcpReset {
                    reason: TcpResetReason::SniBlocklist,
                    seq_ack_note: "MB-RA block (no flow ctx)".to_owned(),
                });
            }
            layer_verdicts.push(LayerVerdict::from(v));
        }

        // (b) JA3/JA4 fingerprint as a separate verdict line for visibility.
        let fp = tls_fp_evaluate(bytes);
        let mark = LayerVerdict::from(fp.clone());
        layer_verdicts.push(mark);
        if let TlsFingerprintVerdict::KnownProxy { .. } = fp {
            if self.config.blocking_policy.enforce_known_proxy_fingerprint {
                if let Some(triple) = scenario.tcp_triple() {
                    egress_actions.push(EgressAction::TcpReset {
                        reason: TcpResetReason::KnownProxyFingerprint,
                        seq_ack_note: "JA3/JA4 hit".to_owned(),
                    });
                    self.residual.record(triple);
                }
            }
        }

        // (c) USENIX'23 fully-encrypted heuristic.
        let fe = fe_evaluate(bytes, &mut self.rng);
        let mark = LayerVerdict::from(fe.clone());
        layer_verdicts.push(mark);
        if let FullyEncryptedVerdict::CandidateForBlock {
            block_sampled: true,
            ..
        } = fe
        {
            if self.config.blocking_policy.enforce_fully_encrypted_sampling {
                if let Some(triple) = scenario.tcp_triple() {
                    egress_actions.push(EgressAction::TcpReset {
                        reason: TcpResetReason::FullyEncryptedSampling,
                        seq_ack_note: "USENIX'23 26.3% sampling hit".to_owned(),
                    });
                    self.residual.record(triple);
                }
            }
        }
    }

    fn handle_udp_datagram(
        &mut self,
        bytes: &[u8],
        scenario: &ScenarioInputs<'_>,
        layer_verdicts: &mut Vec<LayerVerdict>,
        egress_actions: &mut Vec<EgressAction>,
    ) {
        let triple = scenario.quic_triple();
        let verdict = self.quic_detector.inspect(bytes, triple.clone());
        let derived = LayerVerdict::from(verdict.clone());
        if let QuicInitialVerdict::BlockSni { .. } = verdict {
            if self.config.blocking_policy.enforce_sni_blocklist {
                egress_actions.push(EgressAction::UdpDrop {
                    reason: UdpDropReason::QuicSniBlocklist,
                });
                if let Some(triple) = triple {
                    if let Some(udp_triple) = scenario.residual_udp_tuple(&triple) {
                        self.residual.record(udp_triple);
                    }
                }
            }
        }
        layer_verdicts.push(derived);
    }
}

/// Inputs for a single scenario run.
pub struct ScenarioInputs<'a> {
    pub label: &'a str,
    pub flow_label: &'a str,
    pub flow_key: Option<FlowKey>,
    pub dns_query: Option<Vec<u8>>,
    pub events_c2s: Vec<ClientToServerEvent>,
    pub events_s2c: Vec<ServerToClientEvent>,
    pub length_series: Vec<LengthObservation>,
    pub probe_observations: Vec<ProbeObservation>,
    pub precheck_residual_tuple: Option<ResidualBlockTuple>,
    pub client_ip: Option<IpAddr>,
    pub server_ip: Option<IpAddr>,
    pub server_port: Option<u16>,
}

impl<'a> ScenarioInputs<'a> {
    pub fn tcp_triple(&self) -> Option<ResidualBlockTuple> {
        let (Some(c), Some(s), Some(p)) = (self.client_ip, self.server_ip, self.server_port) else {
            return None;
        };
        Some(ResidualBlockTuple::tcp(c, s, p))
    }

    pub fn quic_triple(&self) -> Option<QuicTriple> {
        let (Some(c), Some(s), Some(p)) = (self.client_ip, self.server_ip, self.server_port) else {
            return None;
        };
        Some(QuicTriple {
            client_ip: c,
            server_ip: s,
            server_port: p,
        })
    }

    pub fn residual_udp_tuple(&self, triple: &QuicTriple) -> Option<ResidualBlockTuple> {
        Some(ResidualBlockTuple::udp(
            triple.client_ip,
            triple.server_ip,
            triple.server_port,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct FlowSummary {
    pub flow: FlowKey,
    pub mbr_stage: MbrStage,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
}
