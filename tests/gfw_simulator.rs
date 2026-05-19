//! Red-team integration tests for the source-level GFW simulator.
//!
//! Each test in this file is a separate red-team scenario: it builds an input
//! stream that emulates one mode of ParallaX (or a baseline) and feeds it into
//! the [`GfwSimulator`]. The simulator returns a [`ScenarioReport`] with one
//! verdict per detection layer plus a final aggregated verdict; the test then
//! asserts the high-level outcome and prints the full layer-by-layer breakdown
//! so reviewers can see *why* the GFW would block or pass.
//!
//! The intent is *not* to prove that ParallaX always evades or always loses -
//! it's to ground-truth what each detector sees on ParallaX-shaped traffic.
//! Scenarios that the analysis report predicts as ParallaX weaknesses
//! (PqRekey burst, active-probe behavior, JA4 drift) are exercised here.

mod gfw_sim;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::gfw_sim::detection::active_prober::ProbeObservation;
use crate::gfw_sim::detection::burst_statistics::LengthObservation;
use crate::gfw_sim::detection::tcp_dual_mb::FlowKey;
use crate::gfw_sim::fixtures::synthetic_tls13_client_hello;
use crate::gfw_sim::injection::BlockingPolicy;
use crate::gfw_sim::runtime::{
    middlebox::{ClientToServerEvent, ScenarioInputs, ServerToClientEvent},
    verdict::{ScenarioReport, VerdictKind},
    GfwSimulator, GfwSimulatorConfig,
};

// --------------------- helpers ---------------------

fn build_parallax_tcp_client_hello(sni: &str, seed: u64) -> Vec<u8> {
    synthetic_tls13_client_hello(sni, seed)
}

fn synthetic_random_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut bytes = vec![0_u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn pfs_rekey_fragmented_identity_lengths() -> Vec<LengthObservation> {
    // Current ParallaX sends an encrypted server key exchange, then fragments
    // the ML-DSA identity proof into browser-sized records with >40 ms spacing.
    // This keeps the largest post-handshake record below the old ~4.7 KB
    // signature spike and prevents the signature chunks from aggregating into
    // one ParallaX-specific burst.
    let start = Instant::now();
    vec![
        LengthObservation {
            length: 1550,
            at: start,
            client_to_server: false,
        },
        LengthObservation {
            length: 1320,
            at: start + Duration::from_millis(8),
            client_to_server: false,
        },
        LengthObservation {
            length: 1310,
            at: start + Duration::from_millis(55),
            client_to_server: false,
        },
        LengthObservation {
            length: 1290,
            at: start + Duration::from_millis(103),
            client_to_server: false,
        },
        LengthObservation {
            length: 1250,
            at: start + Duration::from_millis(151),
            client_to_server: false,
        },
    ]
}

fn chrome_like_burst_lengths() -> Vec<LengthObservation> {
    let start = Instant::now();
    let lengths = [517, 75, 89, 1200, 1200, 1380, 1380, 75, 410, 89];
    lengths
        .iter()
        .enumerate()
        .map(|(i, l)| LengthObservation {
            length: *l,
            at: start + Duration::from_millis(i as u64 * 4),
            client_to_server: i % 3 == 0,
        })
        .collect()
}

fn test_flow_key() -> FlowKey {
    FlowKey {
        client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)),
        client_port: 49152,
        server_ip: IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)),
        server_port: 443,
    }
}

fn test_endpoints() -> (Option<IpAddr>, Option<IpAddr>, Option<u16>) {
    (
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11))),
        Some(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229))),
        Some(443),
    )
}

fn print_report(report: &ScenarioReport) {
    eprintln!("{}", report.pretty());
}

// --------------------- scenario 1: baseline ---------------------

/// Baseline: real-Chrome-style TLS 1.3 ClientHello to a Cloudflare-hosted
/// domain, followed by a Chrome-like burst sequence. The GFW should treat this
/// as legitimate.
#[test]
fn scenario_1_chrome_to_cloudflare_baseline_passes() {
    let mut sim = GfwSimulator::new(GfwSimulatorConfig::default());
    let record = build_parallax_tcp_client_hello("cloudflare.com", 1001);
    let (cip, sip, port) = test_endpoints();
    let scenario = ScenarioInputs {
        label: "Chrome→Cloudflare baseline",
        flow_label: "chrome-baseline",
        flow_key: Some(test_flow_key()),
        dns_query: None,
        events_c2s: vec![ClientToServerEvent::TcpPayload { bytes: record }],
        events_s2c: vec![
            ServerToClientEvent::TcpPayload {
                bytes: vec![0x16, 0x03, 0x03, 0x00, 0x40],
                is_change_cipher_spec: false,
                is_first_app_data: false,
                is_server_hello: true,
            },
            ServerToClientEvent::TcpPayload {
                bytes: vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01],
                is_change_cipher_spec: true,
                is_first_app_data: false,
                is_server_hello: false,
            },
            ServerToClientEvent::TcpPayload {
                bytes: vec![0x17, 0x03, 0x03, 0x00, 0x20],
                is_change_cipher_spec: false,
                is_first_app_data: true,
                is_server_hello: false,
            },
        ],
        length_series: chrome_like_burst_lengths(),
        probe_observations: vec![],
        precheck_residual_tuple: None,
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    };
    let report = sim.run_scenario(scenario);
    print_report(&report);
    // We allow Suspicious because parallax's mimicry leaves unknown JA4 in
    // strict mode; in default config it should not be Block.
    assert_ne!(
        report.final_verdict(),
        VerdictKind::Block,
        "Chrome→Cloudflare baseline must not be blocked"
    );
}

// --------------------- scenario 2: random TCP ---------------------

/// Known-bad: a flow where the first TCP payload is 64 random bytes. The
/// USENIX'23 heuristic should treat this as a fully-encrypted candidate and
/// flag it (block sampling fires at 26.3 %).
#[test]
fn scenario_2_random_tcp_is_flagged_by_usenix23() {
    let mut sim = GfwSimulator::new(GfwSimulatorConfig::default());
    let payload = synthetic_random_payload(0xCAFE, 64);
    let (cip, sip, port) = test_endpoints();
    let scenario = ScenarioInputs {
        label: "random TCP first packet",
        flow_label: "random-tcp",
        flow_key: Some(test_flow_key()),
        dns_query: None,
        events_c2s: vec![ClientToServerEvent::TcpPayload { bytes: payload }],
        events_s2c: vec![],
        length_series: vec![],
        probe_observations: vec![],
        precheck_residual_tuple: None,
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    };
    let report = sim.run_scenario(scenario);
    print_report(&report);
    // The USENIX heuristic must produce *some* non-allow verdict on random
    // bytes (Suspicious or Block depending on sampling).
    let fe_verdict = report
        .layer_verdicts
        .iter()
        .find(|v| v.layer == "fully_encrypted")
        .expect("fully_encrypted layer must run");
    assert_ne!(fe_verdict.kind, VerdictKind::Allow);
}

// --------------------- scenario 3: ParallaX TCP w/ blocked SNI ---------------------

/// ParallaX over TCP, but the user accidentally configured a SNI that is in the
/// circumvention keyword list. The SNI filter (MB-RA) must block immediately.
#[test]
fn scenario_3_parallax_tcp_with_blocked_sni_is_reset_by_mbra() {
    let mut sim = GfwSimulator::new(GfwSimulatorConfig::default());
    let record = build_parallax_tcp_client_hello("relay7.shadowsocks.io", 3003);
    let (cip, sip, port) = test_endpoints();
    let scenario = ScenarioInputs {
        label: "ParallaX TCP, blocked SNI",
        flow_label: "parallax-tcp-blocked-sni",
        flow_key: Some(test_flow_key()),
        dns_query: None,
        events_c2s: vec![ClientToServerEvent::TcpPayload { bytes: record }],
        events_s2c: vec![],
        length_series: vec![],
        probe_observations: vec![],
        precheck_residual_tuple: None,
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    };
    let report = sim.run_scenario(scenario);
    print_report(&report);
    assert_eq!(report.final_verdict(), VerdictKind::Block);
    let sni_verdict = report
        .layer_verdicts
        .iter()
        .find(|v| v.layer == "tcp_dual_mb")
        .expect("dual MB must run");
    assert_eq!(sni_verdict.kind, VerdictKind::Block);
}

// --------------------- scenario 4: ParallaX TCP w/ safe SNI ---------------------

/// ParallaX over TCP with a Cloudflare-fronted SNI. The SNI layer cannot block,
/// and the current PFS rekey + fragmented identity proof should not recreate
/// the old PqRekey/ServerIdentity length spike.
#[test]
fn scenario_4_parallax_tcp_with_fragmented_identity_avoids_burst_signature() {
    let mut sim = GfwSimulator::new(GfwSimulatorConfig::default());
    let record = build_parallax_tcp_client_hello("cloudflare.com", 4004);
    let (cip, sip, port) = test_endpoints();
    let scenario = ScenarioInputs {
        label: "ParallaX TCP, safe SNI, fragmented identity",
        flow_label: "parallax-tcp-fragmented-identity",
        flow_key: Some(test_flow_key()),
        dns_query: None,
        events_c2s: vec![ClientToServerEvent::TcpPayload { bytes: record }],
        events_s2c: vec![],
        length_series: pfs_rekey_fragmented_identity_lengths(),
        probe_observations: vec![],
        precheck_residual_tuple: None,
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    };
    let report = sim.run_scenario(scenario);
    print_report(&report);
    let burst_verdict = report
        .layer_verdicts
        .iter()
        .find(|v| v.layer == "burst_statistics")
        .expect("burst statistics layer must run");
    assert_ne!(
        burst_verdict.kind,
        VerdictKind::Block,
        "fragmented identity proof must not match the old ParallaX burst signature"
    );
    assert_ne!(report.final_verdict(), VerdictKind::Block);
}

// --------------------- scenario 6: active probe exchange ---------------------

/// Active-prober scenario: the GFW issues 5 probes against a candidate proxy
/// server. The first three probes elicit "hold the connection without
/// responding" behavior (classic Shadowsocks). ParallaX's defense (fallback to
/// legitimate site) is modelled in scenario 6b.
#[test]
fn scenario_6_active_prober_confirms_shadowsocks_like_endpoint() {
    let mut sim = GfwSimulator::new(GfwSimulatorConfig::default());
    let (cip, sip, port) = test_endpoints();
    let observations = vec![
        ProbeObservation {
            probe_label: "random-bytes",
            server_held_connection: true,
            server_replied_with_bytes: false,
            server_response_looks_legitimate: false,
            server_immediately_reset: false,
            delay: Duration::from_millis(50),
        },
        ProbeObservation {
            probe_label: "tor-pt",
            server_held_connection: true,
            server_replied_with_bytes: false,
            server_response_looks_legitimate: false,
            server_immediately_reset: false,
            delay: Duration::from_millis(50),
        },
        ProbeObservation {
            probe_label: "replay",
            server_held_connection: true,
            server_replied_with_bytes: false,
            server_response_looks_legitimate: false,
            server_immediately_reset: false,
            delay: Duration::from_millis(50),
        },
    ];
    let scenario = ScenarioInputs {
        label: "Active probe vs. Shadowsocks-like endpoint",
        flow_label: "ss-like-probe",
        flow_key: None,
        dns_query: None,
        events_c2s: vec![],
        events_s2c: vec![],
        length_series: vec![],
        probe_observations: observations,
        precheck_residual_tuple: None,
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    };
    let report = sim.run_scenario(scenario);
    print_report(&report);
    let probe_verdict = report
        .layer_verdicts
        .iter()
        .find(|v| v.layer == "active_prober")
        .expect("active_prober must run");
    assert_eq!(probe_verdict.kind, VerdictKind::Block);
}

#[test]
fn scenario_6b_active_prober_passes_parallax_fallback() {
    let mut sim = GfwSimulator::new(GfwSimulatorConfig::default());
    let (cip, sip, port) = test_endpoints();
    // ParallaX's fallback defense: every failed-auth probe gets forwarded to a
    // legitimate site, so the server replies with believable TLS records. The
    // prober should NOT confirm.
    let observations = vec![
        ProbeObservation {
            probe_label: "random-bytes",
            server_held_connection: false,
            server_replied_with_bytes: true,
            server_response_looks_legitimate: true,
            server_immediately_reset: false,
            delay: Duration::from_millis(30),
        },
        ProbeObservation {
            probe_label: "tor-pt",
            server_held_connection: false,
            server_replied_with_bytes: true,
            server_response_looks_legitimate: true,
            server_immediately_reset: false,
            delay: Duration::from_millis(35),
        },
        ProbeObservation {
            probe_label: "replay",
            server_held_connection: false,
            server_replied_with_bytes: true,
            server_response_looks_legitimate: true,
            server_immediately_reset: false,
            delay: Duration::from_millis(40),
        },
    ];
    let scenario = ScenarioInputs {
        label: "Active probe vs. ParallaX-with-fallback",
        flow_label: "parallax-fallback-probe",
        flow_key: None,
        dns_query: None,
        events_c2s: vec![],
        events_s2c: vec![],
        length_series: vec![],
        probe_observations: observations,
        precheck_residual_tuple: None,
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    };
    let report = sim.run_scenario(scenario);
    print_report(&report);
    let probe_verdict = report
        .layer_verdicts
        .iter()
        .find(|v| v.layer == "active_prober")
        .expect("active_prober must run");
    // Either Allow (legitimate-looking traffic) or Inconclusive - we just need
    // to NOT flag it as a confirmed proxy.
    assert_ne!(probe_verdict.kind, VerdictKind::Block);
}

// --------------------- scenario 7: DNS injection ---------------------

#[test]
fn scenario_7_dns_query_for_blocked_keyword_is_injected() {
    let mut sim = GfwSimulator::new(GfwSimulatorConfig::default());
    let mut query = Vec::new();
    query.extend_from_slice(&0x42_42_u16.to_be_bytes());
    query.extend_from_slice(&0x01_00_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    // Name: v2ray.cdn.example
    for label in ["v2ray", "cdn", "example"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1_u16.to_be_bytes()); // A
    query.extend_from_slice(&1_u16.to_be_bytes()); // IN

    let (cip, sip, port) = test_endpoints();
    let scenario = ScenarioInputs {
        label: "DNS query for blocked keyword",
        flow_label: "dns-blocked-keyword",
        flow_key: None,
        dns_query: Some(query),
        events_c2s: vec![],
        events_s2c: vec![],
        length_series: vec![],
        probe_observations: vec![],
        precheck_residual_tuple: None,
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    };
    let report = sim.run_scenario(scenario);
    print_report(&report);
    let dns_verdict = report
        .layer_verdicts
        .iter()
        .find(|v| v.layer == "dns_inject")
        .expect("dns_inject must run");
    assert_eq!(dns_verdict.kind, VerdictKind::Block);
}

// --------------------- scenario 8: residual block ---------------------

#[test]
fn scenario_8_residual_block_prevents_retry() {
    let mut sim = GfwSimulator::new(GfwSimulatorConfig::default());
    let (cip, sip, port) = test_endpoints();

    // First pass: block on SNI.
    let blocked = build_parallax_tcp_client_hello("relay.shadowsocks.io", 8081);
    let _first = sim.run_scenario(ScenarioInputs {
        label: "Blocked first pass",
        flow_label: "first",
        flow_key: Some(test_flow_key()),
        dns_query: None,
        events_c2s: vec![ClientToServerEvent::TcpPayload { bytes: blocked }],
        events_s2c: vec![],
        length_series: vec![],
        probe_observations: vec![],
        precheck_residual_tuple: None,
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    });

    // Second pass: same 3-tuple, but new (legitimate) SNI. Residual rule must
    // still block.
    let triple = crate::gfw_sim::injection::ResidualBlockTuple::tcp(
        cip.unwrap(),
        sip.unwrap(),
        port.unwrap(),
    );
    let legit = build_parallax_tcp_client_hello("cloudflare.com", 8082);
    let report = sim.run_scenario(ScenarioInputs {
        label: "Residual-block retry",
        flow_label: "second",
        flow_key: Some(FlowKey {
            client_port: 52000,
            ..test_flow_key()
        }),
        dns_query: None,
        events_c2s: vec![ClientToServerEvent::TcpPayload { bytes: legit }],
        events_s2c: vec![],
        length_series: vec![],
        probe_observations: vec![],
        precheck_residual_tuple: Some(triple),
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    });
    print_report(&report);
    let residual_verdict = report
        .layer_verdicts
        .iter()
        .find(|v| v.layer == "residual_block")
        .expect("residual_block must run on retry");
    assert_eq!(residual_verdict.kind, VerdictKind::Block);
}

// --------------------- scenario 9: permissive policy ---------------------

#[test]
fn scenario_9_permissive_policy_disables_all_enforcement() {
    let cfg = GfwSimulatorConfig {
        blocking_policy: BlockingPolicy::permissive(),
        flag_unknown_fingerprints: false,
        rng_seed: 1,
    };
    let mut sim = GfwSimulator::new(cfg);
    let record = build_parallax_tcp_client_hello("relay7.shadowsocks.io", 9009);
    let (cip, sip, port) = test_endpoints();
    let scenario = ScenarioInputs {
        label: "Permissive policy (audit-only)",
        flow_label: "audit",
        flow_key: Some(test_flow_key()),
        dns_query: None,
        events_c2s: vec![ClientToServerEvent::TcpPayload { bytes: record }],
        events_s2c: vec![],
        length_series: pfs_rekey_fragmented_identity_lengths(),
        probe_observations: vec![],
        precheck_residual_tuple: None,
        client_ip: cip,
        server_ip: sip,
        server_port: port,
    };
    let report = sim.run_scenario(scenario);
    print_report(&report);
    // Verdicts are still emitted (audit-only), but no egress action is taken.
    assert!(
        report.egress_actions.is_empty(),
        "permissive policy must not emit egress actions"
    );
}
