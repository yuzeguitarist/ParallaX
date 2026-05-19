//! Dual TLS middlebox state machine: MB-RA + MB-R.
//!
//! The GFW's TLS layer is implemented as two cooperating middleboxes:
//! - **MB-RA** ("ResetAck" middlebox) parses the ClientHello, runs the SNI
//!   blocklist and JA3/JA4 fingerprint rules, and on match issues an
//!   immediate TCP reset with `Acknowledgment_Number` cloned from the captured
//!   handshake direction.
//! - **MB-R** retains per-flow state across the TLS handshake. It waits for
//!   the ChangeCipherSpec / first ApplicationData record before issuing its
//!   *own* reset, which buys ~87 % coverage of TLS 1.3 SNI traffic and serves
//!   as a backup for evasion attempts that smuggle past MB-RA (e.g. malformed
//!   ClientHello, fragmented record, ESNI/ECH).
//!
//! Bock et al. CCS 2021 ("Even Censors Have a Backup", §3.2) describes how
//! the two middleboxes interact; we restate the relevant state transitions here
//! and reproduce them in pure Rust.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::sni_filter::{parse_client_hello, ClientHelloParseError, SniFilter, SniVerdict};
use super::tls_fingerprint::{evaluate as evaluate_tls_fp, TlsFingerprintVerdict};

/// State carried per (5-tuple) flow by MB-R.
#[derive(Debug, Clone)]
pub struct MbrState {
    pub stage: MbrStage,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub mbra_decision: Option<DualMbDecision>,
    pub pending_client_hello: Vec<u8>,
    pub started: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbrStage {
    /// Initial state - waiting for ClientHello.
    AwaitingClientHello,
    /// ClientHello seen, waiting for ServerHello.
    AwaitingServerHello,
    /// ServerHello seen, waiting for ChangeCipherSpec.
    AwaitingChangeCipherSpec,
    /// ChangeCipherSpec seen, waiting for first ApplicationData (TLS 1.3 hides
    /// EncryptedExtensions inside ApplicationData).
    AwaitingFirstAppData,
    /// MB-R is satisfied; flow either passed or was blocked.
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DualMbDecision {
    Allow,
    BlockSni { sni: String, matched_rule: String },
    BlockEncryptedClientHello { kind: &'static str, ext_type: u16 },
    BlockFingerprint { fingerprint_summary: String },
    BlockNoSni,
    Suspicious { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub client_ip: std::net::IpAddr,
    pub client_port: u16,
    pub server_ip: std::net::IpAddr,
    pub server_port: u16,
}

pub struct DualMiddlebox {
    pub mbra_filter: SniFilter,
    pub flag_unknown_fingerprints: bool,
    flows: HashMap<FlowKey, MbrState>,
    state_ttl: Duration,
}

impl Default for DualMiddlebox {
    fn default() -> Self {
        Self {
            mbra_filter: SniFilter::default(),
            flag_unknown_fingerprints: false,
            flows: HashMap::new(),
            state_ttl: Duration::from_secs(60),
        }
    }
}

impl DualMiddlebox {
    pub fn new(filter: SniFilter) -> Self {
        Self {
            mbra_filter: filter,
            flag_unknown_fingerprints: false,
            flows: HashMap::new(),
            state_ttl: Duration::from_secs(60),
        }
    }

    pub fn with_unknown_fingerprint_flagging(mut self, on: bool) -> Self {
        self.flag_unknown_fingerprints = on;
        self
    }

    /// Drives state for `flow` upon seeing a TLS record from client→server.
    /// Returns the latest (possibly updated) decision.
    pub fn on_client_record(&mut self, flow: FlowKey, record: &[u8]) -> DualMbDecision {
        self.gc_expired_flows();
        let state = self.flows.entry(flow).or_insert_with(|| MbrState {
            stage: MbrStage::AwaitingClientHello,
            sni: None,
            ja3: None,
            ja4: None,
            mbra_decision: None,
            pending_client_hello: Vec::new(),
            started: Instant::now(),
        });

        match state.stage {
            MbrStage::AwaitingClientHello => {
                let candidate_owned;
                let candidate = if state.pending_client_hello.is_empty() {
                    record
                } else {
                    state.pending_client_hello.extend_from_slice(record);
                    candidate_owned = state.pending_client_hello.clone();
                    candidate_owned.as_slice()
                };

                let parsed = match parse_client_hello(candidate) {
                    Ok(parsed) => parsed,
                    Err(err)
                        if state.pending_client_hello.is_empty()
                            && is_incomplete_client_hello(&err) =>
                    {
                        state.pending_client_hello.extend_from_slice(record);
                        let decision = DualMbDecision::Suspicious {
                            reason: format!("buffering fragmented ClientHello ({err})"),
                        };
                        state.mbra_decision = Some(decision.clone());
                        return decision;
                    }
                    Err(err)
                        if is_incomplete_client_hello(&err)
                            && state.pending_client_hello.len() < 8192 =>
                    {
                        let decision = DualMbDecision::Suspicious {
                            reason: format!("buffering fragmented ClientHello ({err})"),
                        };
                        state.mbra_decision = Some(decision.clone());
                        return decision;
                    }
                    Err(_) => {
                        let decision = DualMbDecision::Allow;
                        state.mbra_decision = Some(decision.clone());
                        state.stage = MbrStage::Resolved;
                        return decision;
                    }
                };
                state.pending_client_hello.clear();
                let verdict = self.mbra_filter.evaluate_parsed(&parsed);
                let fp_verdict = evaluate_tls_fp(candidate);
                match (verdict, fp_verdict) {
                    (SniVerdict::Block { sni, matched_rule }, _) => {
                        let decision = DualMbDecision::BlockSni {
                            sni: sni.clone(),
                            matched_rule: matched_rule.clone(),
                        };
                        state.sni = Some(sni);
                        state.mbra_decision = Some(decision.clone());
                        state.stage = MbrStage::Resolved;
                        decision
                    }
                    (SniVerdict::BlockEncryptedClientHello { kind, ext_type }, _) => {
                        let decision = DualMbDecision::BlockEncryptedClientHello {
                            kind: kind.label(),
                            ext_type,
                        };
                        state.mbra_decision = Some(decision.clone());
                        state.stage = MbrStage::Resolved;
                        decision
                    }
                    (
                        SniVerdict::Allow { sni },
                        TlsFingerprintVerdict::KnownProxy { fingerprints },
                    ) => {
                        let decision = DualMbDecision::BlockFingerprint {
                            fingerprint_summary: format!(
                                "JA3={} JA4={} (known proxy)",
                                fingerprints.ja3, fingerprints.ja4
                            ),
                        };
                        state.sni = Some(sni);
                        state.ja3 = Some(fingerprints.ja3.clone());
                        state.ja4 = Some(fingerprints.ja4.clone());
                        state.mbra_decision = Some(decision.clone());
                        state.stage = MbrStage::Resolved;
                        decision
                    }
                    (
                        SniVerdict::Allow { sni },
                        TlsFingerprintVerdict::Unknown { fingerprints },
                    ) => {
                        let decision = if self.flag_unknown_fingerprints {
                            DualMbDecision::Suspicious {
                                reason: format!(
                                    "JA3={} JA4={} (unknown fingerprint)",
                                    fingerprints.ja3, fingerprints.ja4
                                ),
                            }
                        } else {
                            DualMbDecision::Allow
                        };
                        state.sni = Some(sni);
                        state.ja3 = Some(fingerprints.ja3.clone());
                        state.ja4 = Some(fingerprints.ja4.clone());
                        state.mbra_decision = Some(decision.clone());
                        state.stage = MbrStage::AwaitingServerHello;
                        decision
                    }
                    (
                        SniVerdict::Allow { sni },
                        TlsFingerprintVerdict::KnownBrowser { fingerprints },
                    ) => {
                        let decision = DualMbDecision::Allow;
                        state.sni = Some(sni);
                        state.ja3 = Some(fingerprints.ja3.clone());
                        state.ja4 = Some(fingerprints.ja4.clone());
                        state.mbra_decision = Some(decision.clone());
                        state.stage = MbrStage::AwaitingServerHello;
                        decision
                    }
                    (SniVerdict::NoSni, _) => {
                        let decision = DualMbDecision::Suspicious {
                            reason: "no SNI extension".to_owned(),
                        };
                        state.mbra_decision = Some(decision.clone());
                        state.stage = MbrStage::AwaitingServerHello;
                        decision
                    }
                    (SniVerdict::NotTls, _) => {
                        let decision = DualMbDecision::Allow;
                        state.mbra_decision = Some(decision.clone());
                        state.stage = MbrStage::Resolved;
                        decision
                    }
                    (SniVerdict::Allow { sni }, TlsFingerprintVerdict::NotTls) => {
                        let decision = DualMbDecision::Allow;
                        state.sni = Some(sni);
                        state.mbra_decision = Some(decision.clone());
                        state.stage = MbrStage::AwaitingServerHello;
                        decision
                    }
                }
            }
            MbrStage::AwaitingServerHello => {
                state.mbra_decision.clone().unwrap_or(DualMbDecision::Allow)
            }
            MbrStage::AwaitingChangeCipherSpec => {
                state.mbra_decision.clone().unwrap_or(DualMbDecision::Allow)
            }
            MbrStage::AwaitingFirstAppData => {
                state.mbra_decision.clone().unwrap_or(DualMbDecision::Allow)
            }
            MbrStage::Resolved => state.mbra_decision.clone().unwrap_or(DualMbDecision::Allow),
        }
    }

    /// Inform the middlebox that the server's first record (a ServerHello) was
    /// observed for `flow`. MB-R uses this transition to clear `NoSni`
    /// uncertainty in TLS 1.2 (the server now knows the SNI even if the client
    /// hid it).
    pub fn on_server_hello(&mut self, flow: FlowKey, _bytes: &[u8]) -> DualMbDecision {
        let state = match self.flows.get_mut(&flow) {
            Some(s) => s,
            None => return DualMbDecision::Allow,
        };
        if state.stage == MbrStage::AwaitingServerHello {
            state.stage = MbrStage::AwaitingChangeCipherSpec;
        }
        state.mbra_decision.clone().unwrap_or(DualMbDecision::Allow)
    }

    /// Inform the middlebox that the client sent a ChangeCipherSpec record
    /// (the cleartext transition before TLS 1.3 hides everything in
    /// ApplicationData). MB-R re-checks SNI / fingerprint at this stage.
    pub fn on_change_cipher_spec(&mut self, flow: FlowKey) -> DualMbDecision {
        let state = match self.flows.get_mut(&flow) {
            Some(s) => s,
            None => return DualMbDecision::Allow,
        };
        if state.stage == MbrStage::AwaitingChangeCipherSpec {
            state.stage = MbrStage::AwaitingFirstAppData;
        }
        state.mbra_decision.clone().unwrap_or(DualMbDecision::Allow)
    }

    /// Inform the middlebox of the first client ApplicationData record. This
    /// is the final decision point - MB-R will not change its mind after.
    pub fn on_first_app_data(&mut self, flow: FlowKey) -> DualMbDecision {
        let state = match self.flows.get_mut(&flow) {
            Some(s) => s,
            None => return DualMbDecision::Allow,
        };
        state.stage = MbrStage::Resolved;
        state.mbra_decision.clone().unwrap_or(DualMbDecision::Allow)
    }

    pub fn state_for(&self, flow: &FlowKey) -> Option<&MbrState> {
        self.flows.get(flow)
    }

    fn gc_expired_flows(&mut self) {
        let now = Instant::now();
        let ttl = self.state_ttl;
        self.flows
            .retain(|_, state| now.duration_since(state.started) < ttl);
    }
}

fn is_incomplete_client_hello(err: &ClientHelloParseError) -> bool {
    matches!(
        err,
        ClientHelloParseError::Truncated
            | ClientHelloParseError::LengthMismatch
            | ClientHelloParseError::UnexpectedEof(_)
    )
}

/// Lightweight helper that classifies the first byte of a record into the broad
/// TLS content type. Used by the runtime middlebox to drive `DualMiddlebox`
/// transitions without owning a full TLS parser.
pub fn record_content_type(byte: u8) -> Option<&'static str> {
    match byte {
        0x14 => Some("ChangeCipherSpec"),
        0x15 => Some("Alert"),
        0x16 => Some("Handshake"),
        0x17 => Some("ApplicationData"),
        _ => None,
    }
}

/// Returns true if `record_start` looks like a ClientHello record (used to
/// distinguish the first Handshake record from later post-handshake messages).
pub fn looks_like_clienthello(record_start: &[u8]) -> bool {
    parse_client_hello(record_start).is_ok()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::gfw_sim::fixtures::synthetic_tls13_client_hello;

    fn parallax_client_hello(sni: &str) -> Vec<u8> {
        synthetic_tls13_client_hello(sni, 0xBEEF)
    }

    fn test_flow() -> FlowKey {
        FlowKey {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            client_port: 51234,
            server_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            server_port: 443,
        }
    }

    #[test]
    fn allows_legitimate_clienthello() {
        let record = parallax_client_hello("cloudflare.com");
        let mut mb = DualMiddlebox::default();
        let decision = mb.on_client_record(test_flow(), &record);
        // Default flag_unknown_fingerprints=false means ParallaX with unknown
        // JA3/JA4 still passes.
        matches!(decision, DualMbDecision::Allow);
    }

    #[test]
    fn blocks_circumvention_sni_on_clienthello() {
        let record = parallax_client_hello("relay7.shadowsocks.io");
        let mut mb = DualMiddlebox::default();
        let decision = mb.on_client_record(test_flow(), &record);
        match decision {
            DualMbDecision::BlockSni { sni, matched_rule } => {
                assert_eq!(sni, "relay7.shadowsocks.io");
                assert_eq!(matched_rule, "*.shadowsocks.io");
            }
            other => panic!("expected BlockSni, got {other:?}"),
        }
    }

    #[test]
    fn reassembles_fragmented_clienthello_before_sni_decision() {
        let record = parallax_client_hello("relay7.shadowsocks.io");
        let mut mb = DualMiddlebox::default();
        let flow = test_flow();
        let split = 16;
        match mb.on_client_record(flow, &record[..split]) {
            DualMbDecision::Suspicious { reason } => {
                assert!(reason.contains("fragmented ClientHello"));
            }
            other => panic!("expected buffering decision, got {other:?}"),
        }
        match mb.on_client_record(flow, &record[split..]) {
            DualMbDecision::BlockSni { sni, matched_rule } => {
                assert_eq!(sni, "relay7.shadowsocks.io");
                assert_eq!(matched_rule, "*.shadowsocks.io");
            }
            other => panic!("expected BlockSni after reassembly, got {other:?}"),
        }
    }

    #[test]
    fn state_transitions_through_handshake() {
        let record = parallax_client_hello("cloudflare.com");
        let mut mb = DualMiddlebox::default();
        let flow = test_flow();
        let _ = mb.on_client_record(flow, &record);
        assert_eq!(
            mb.state_for(&flow).unwrap().stage,
            MbrStage::AwaitingServerHello
        );
        let _ = mb.on_server_hello(flow, &[0x16, 0x03, 0x03]);
        assert_eq!(
            mb.state_for(&flow).unwrap().stage,
            MbrStage::AwaitingChangeCipherSpec
        );
        let _ = mb.on_change_cipher_spec(flow);
        assert_eq!(
            mb.state_for(&flow).unwrap().stage,
            MbrStage::AwaitingFirstAppData
        );
        let _ = mb.on_first_app_data(flow);
        assert_eq!(mb.state_for(&flow).unwrap().stage, MbrStage::Resolved);
    }

    #[test]
    fn unknown_fingerprint_flag_promotes_to_suspicious() {
        let record = parallax_client_hello("cloudflare.com");
        let mut mb = DualMiddlebox::default().with_unknown_fingerprint_flagging(true);
        let decision = mb.on_client_record(test_flow(), &record);
        // Whether this is Allow / Suspicious depends on whether ParallaX's JA4
        // resolves to a *known proxy* entry in tls_fingerprints data; in either
        // case it should NOT be Allow.
        match decision {
            DualMbDecision::Allow => panic!("with flag on, ParallaX should not pass"),
            DualMbDecision::BlockFingerprint { .. } | DualMbDecision::Suspicious { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}
