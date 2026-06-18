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

use parallax::crypto::session::{AeadCodec, X25519KeyPair, AEAD_TAG_LEN};
use parallax::crypto::{identity, pq};
use parallax::protocol::command::{ServerIdentityChunk, ServerIdentityProof, ServerKeyExchange};
use parallax::protocol::data::{DataRecordCodec, SERVER_TO_CLIENT_AAD};
use parallax::tls::record::TLS_HEADER_LEN;
use parallax::tls::safari26::Safari26TlsCamouflage;
use parallax::traffic::PaddingProfile;

use crate::gfw_sim::detection::active_prober::ProbeObservation;
use crate::gfw_sim::detection::burst_statistics::LengthObservation;
use crate::gfw_sim::detection::tcp_dual_mb::FlowKey;
use crate::gfw_sim::injection::BlockingPolicy;
use crate::gfw_sim::runtime::{
    middlebox::{ClientToServerEvent, ScenarioInputs, ServerToClientEvent},
    verdict::{ScenarioReport, VerdictKind},
    GfwSimulator, GfwSimulatorConfig,
};

// --------------------- helpers ---------------------

/// Drive the REAL Safari 26 ParallaX camouflage emitter to produce the actual
/// product ClientHello bytes the server sends on the wire — the same drive
/// pattern as `safari_parity_baseline.rs`. The GFW simulator's detectors then
/// judge the real 20-cipher/13-extension/GREASE product instead of a synthetic
/// stand-in. `seed` is unused (the real path draws GREASE/randoms from OsRng).
fn build_parallax_tcp_client_hello(sni: &str, _seed: u64) -> Vec<u8> {
    let server = X25519KeyPair::generate();
    let psk = b"0123456789abcdef0123456789abcdef";
    Safari26TlsCamouflage
        .start(sni.to_owned(), psk, &server.public)
        .expect("start Safari 26 ParallaX TLS camouflage")
        .client_hello_bytes()
        .to_vec()
}

fn synthetic_random_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut bytes = vec![0_u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Server-side identity-proof chunk plaintext size. The product server draws this
/// per connection from `rng.gen_range(SERVER_IDENTITY_CHUNK_MIN_PLAINTEXT
/// ..=SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT)` (960..=1320) in `server.rs`. We pin the
/// high end of that real range here so the reconstruction is deterministic while
/// still being a value the server actually emits; it also matches the in-tree
/// `server.rs` chunking test that exercises `SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT`.
const IDENTITY_CHUNK_PLAINTEXT_LEN: usize = 1320;

/// Reconstruct scenario_4's server->client length series from the REAL product
/// encoders instead of hand-typed magic numbers.
///
/// The authenticated server (see `run_authenticated_data_mode` in
/// `src/handshake/server.rs`) emits, after the client's PQ rekey, exactly:
///   1. one sealed `ServerKeyExchange` record (X25519 pub + ML-KEM-1024
///      ciphertext + framing), then
///   2. the ML-DSA-87 identity proof, fragmented by
///      `ServerIdentityChunk::encode_all` into browser-sized records sealed one at
///      a time with >40 ms spacing.
///
/// We drive those same public encoders here, seal each frame with the real
/// `DataRecordCodec` (default `TrafficConfig` padding: min=max=0), and report each
/// record's on-wire length minus the TLS header and AEAD tag -- i.e. the
/// padded-plaintext length the burst detector documents `LengthObservation.length`
/// to be. Nothing is hardcoded: the ML-DSA-87 signature length (~4.6 KB) and the
/// chunk count fall out of the encoders. Timestamps are SYNTHESIZED with fixed
/// deltas (one ~8 ms intra-burst gap, then >`BURST_GAP` spacings) so the test stays
/// deterministic while preserving scenario_4's "fragmentation spreads the records
/// across bursts so no burst recreates the 2-record PqRekey/ServerIdentity spike".
fn pfs_rekey_fragmented_identity_lengths() -> Vec<LengthObservation> {
    // Real ML-KEM-1024 ciphertext + real ServerKeyExchange framing.
    let mlkem = pq::keypair();
    let encapsulation = pq::encapsulate(&mlkem.public).expect("ML-KEM-1024 encapsulation");
    let server_ephemeral = X25519KeyPair::generate();
    let key_exchange_payload = ServerKeyExchange {
        server_x25519_public: server_ephemeral.public,
        mlkem_ciphertext: encapsulation.ciphertext,
    }
    .encode()
    .expect("encode ServerKeyExchange");

    // Real ML-DSA-87 signature -> real ServerIdentityProof -> real chunking. The
    // signing inputs are arbitrary fixed test vectors; only the signature's true
    // length (and thus the chunk count) matters for the length series.
    let identity_keys = identity::keypair();
    let signature = identity::sign_server_identity(
        &identity_keys.secret,
        &[0x11_u8; 32], // transcript hash
        &server_ephemeral.public,
        &[0x22_u8; 32], // pq rekey binding
        1,              // epoch
    )
    .expect("ML-DSA-87 sign_server_identity");
    assert!(
        signature.len() > 4000,
        "ML-DSA-87 identity signature should be ~4.6 KB; got {} bytes",
        signature.len()
    );
    let identity_payload = ServerIdentityProof {
        signature: signature.clone(),
    }
    .encode()
    .expect("encode ServerIdentityProof");
    let identity_chunks =
        ServerIdentityChunk::encode_all(&identity_payload, IDENTITY_CHUNK_PLAINTEXT_LEN)
            .expect("chunk ServerIdentityProof");
    let identity_chunk_count = identity_chunks.len();

    // Real server->client record sealer with the default padding profile the
    // product server uses (TrafficConfig::default => min=max=0). The AEAD key/nonce
    // are irrelevant to the sealed *length*, so any value works.
    let padding = PaddingProfile::new(0, 0).expect("zero padding profile");
    let mut server_seal = DataRecordCodec::new(
        AeadCodec::new([7_u8; 32], [9_u8; 12]),
        padding,
        SERVER_TO_CLIENT_AAD,
    );
    let mut rng = StdRng::seed_from_u64(0x5EA1);

    // The detector defines `length` as the record length after the 5-byte TLS
    // header is stripped and before the AEAD tag, i.e. the padded plaintext. Derive
    // it from the REAL sealed record so a future framing/padding change is reflected.
    let sealed_plaintext_len = |codec: &mut DataRecordCodec, payload: &[u8], rng: &mut StdRng| {
        let record = codec
            .seal(payload, rng)
            .expect("seal server->client record");
        record.len() - TLS_HEADER_LEN - AEAD_TAG_LEN
    };

    // Same wire order as the server: ServerKeyExchange first, then the identity
    // chunks. Same direction (server->client) as the original.
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(1 + identity_chunk_count);
    payloads.push(key_exchange_payload);
    payloads.extend(identity_chunks);

    // Synthesized deterministic arrival times: an ~8 ms intra-burst gap between the
    // first two records, then >BURST_GAP (40 ms) spacing so each later chunk lands
    // in its own burst -- the timing shape the original helper used.
    let arrival_offsets_ms = |idx: usize| -> u64 {
        match idx {
            0 => 0,
            1 => 8,
            n => 8 + (n as u64 - 1) * 48,
        }
    };

    let start = Instant::now();
    let series: Vec<LengthObservation> = payloads
        .iter()
        .enumerate()
        .map(|(idx, payload)| LengthObservation {
            length: sealed_plaintext_len(&mut server_seal, payload, &mut rng),
            at: start + Duration::from_millis(arrival_offsets_ms(idx)),
            client_to_server: false,
        })
        .collect();

    // Anti-tautology guard: the series must come from the measured signature/chunk
    // sizes, not a stale hardcoded shape. If a future change stops fragmenting the
    // identity proof (or stops sending the key exchange), these break instead of
    // silently keeping the old verdict.
    assert!(!series.is_empty(), "length series must be non-empty");
    assert!(
        identity_chunk_count >= 2,
        "ML-DSA-87 proof ({} B) must fragment into multiple records at chunk size {}; got {}",
        identity_payload.len(),
        IDENTITY_CHUNK_PLAINTEXT_LEN,
        identity_chunk_count
    );
    assert_eq!(
        series.len(),
        1 + identity_chunk_count,
        "series must be exactly one ServerKeyExchange record plus every identity chunk"
    );
    series
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

/// Data-plane stealth gate (offline form of the planned netmatrix_stealth_parity):
/// the REAL per-record length series the AEAD data plane emits must not match a
/// known-proxy centroid, and switching the negotiated cipher suite
/// (ChaCha20-Poly1305 vs AES-256-GCM) must NOT move that series at all -- both
/// AEADs share the 12-byte nonce / 16-byte tag / record framing. This guards every
/// record-sizing/cipher change (A2 zero-copy, A10 AES-GCM, future shaping) against
/// an indistinguishability regression on the length channel.
#[test]
fn data_plane_record_lengths_stay_non_proxy_across_cipher_suites() {
    use crate::gfw_sim::detection::burst_statistics::{BurstDetector, BurstVerdict};
    use parallax::crypto::session::CipherSuite;

    // A representative client->server transfer: a small Connect-sized record, a
    // bulk body that chunks into full max-size records, then small interactive
    // writes -- the shape an HTTP request + response body produces.
    let payloads: Vec<Vec<u8>> = vec![
        vec![0x11; 512],
        vec![0x22; 16 * 1024],
        vec![0x22; 16 * 1024],
        vec![0x22; 9 * 1024],
        vec![0x33; 280],
        vec![0x33; 64],
    ];

    let lengths_for = |suite: CipherSuite| -> Vec<usize> {
        let padding = PaddingProfile::new(0, 0).expect("zero padding");
        let mut codec = DataRecordCodec::new(
            AeadCodec::new_with_suite(suite, [7_u8; 32], [9_u8; 12]),
            padding,
            SERVER_TO_CLIENT_AAD,
        );
        let mut rng = StdRng::seed_from_u64(0xD47A);
        let mut out = Vec::new();
        for payload in &payloads {
            for record in codec.seal_chunks(payload, &mut rng).expect("seal chunks") {
                out.push(record.len() - TLS_HEADER_LEN - AEAD_TAG_LEN);
            }
        }
        out
    };

    let chacha_lengths = lengths_for(CipherSuite::ChaCha20Poly1305);
    let aes_lengths = lengths_for(CipherSuite::Aes256Gcm);
    assert_eq!(
        chacha_lengths, aes_lengths,
        "AES-256-GCM must produce byte-identical record lengths to ChaCha"
    );

    let start = Instant::now();
    let series: Vec<LengthObservation> = chacha_lengths
        .iter()
        .enumerate()
        .map(|(i, &length)| LengthObservation {
            length,
            at: start + Duration::from_millis(i as u64),
            client_to_server: true,
        })
        .collect();
    assert!(!series.is_empty(), "length series must be non-empty");

    let verdict = BurstDetector::default().evaluate(&series);
    assert!(
        !matches!(verdict, BurstVerdict::LooksLikeProxy { .. }),
        "data-plane record lengths must not match a proxy centroid: {verdict:?}"
    );
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
    // Strong indistinguishability check (not just "did not get blocked"): the
    // real ParallaX ClientHello must be fingerprinted as a genuine known browser
    // (Safari). The tls_fingerprint layer maps KnownBrowser -> Allow, Unknown ->
    // Suspicious, KnownProxy -> Block, so asserting Allow proves the product was
    // positively recognized as Safari, not merely left unclassified. Before the
    // Safari reference JA3/JA4 was corrected to the real first-party value this
    // flow scored Unknown -> Suspicious and this assertion would have failed.
    let tls_fp = report
        .layer_verdicts
        .iter()
        .find(|v| v.layer == "tls_fingerprint")
        .expect("tls_fingerprint layer must run on a ClientHello flow");
    assert_eq!(
        tls_fp.kind,
        VerdictKind::Allow,
        "real ParallaX must be recognized as a known browser (Safari), not just avoid Block"
    );
    assert_ne!(
        report.final_verdict(),
        VerdictKind::Block,
        "a flow fingerprinted as real Safari must not be blocked"
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

// --------------------- UDP fast-plane (TUDP) QUIC Initial gate ---------------------
//
// These tests feed the REAL quinn QUIC Initial produced by ParallaX's UDP-leg
// client config (`parallax::transport::udp::client_config`) into the GFW QUIC
// Initial detector, grounding the camouflage "gate" in actual on-wire bytes
// rather than synthetic packets. Today they CHARACTERIZE the un-hardened leg:
// the Initial is a standard, decryptable v1 Initial whose SNI is readable from a
// single datagram. When a later camouflage slice adds SNI-slicing across CRYPTO
// frames/datagrams and a browser-matched JA4q, the first assertion flips (SNI no
// longer extractable from the first datagram) and a JA4q-match assertion is
// added — that is when this becomes a hard pass/fail gate.

/// Drive ParallaX's UDP-leg quinn client far enough to emit its QUIC Initial and
/// capture that first datagram off a plain UDP socket standing in for the server.
async fn capture_udp_leg_initial(server_name: &str) -> Vec<u8> {
    use std::sync::Arc;

    use parallax::transport::udp::client_config;
    use quinn::Endpoint;
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    };

    // The Initial is sent before any ServerHello arrives, so the cert verifier is
    // never invoked; a never-called accept-any verifier is enough to build the
    // client config for capture.
    #[derive(Debug)]
    struct NeverCalled;
    impl ServerCertVerifier for NeverCalled {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }

    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config(Arc::new(NeverCalled)).unwrap());

    // Registering the connection makes quinn's driver transmit the Initial; it
    // never completes (no real QUIC server replies), so hold it on a task while
    // we capture the first datagram.
    let connecting = endpoint.connect(server_addr, server_name).unwrap();
    let drive = tokio::spawn(async move {
        let _ = connecting.await;
    });

    let mut buf = vec![0_u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), listener.recv_from(&mut buf))
        .await
        .expect("UDP-leg QUIC Initial captured within 5s")
        .expect("recv_from the captured Initial");
    buf.truncate(n);
    drive.abort();
    buf
}

/// Drive the UDP-leg quinn client and capture *all* Initial datagrams that carry
/// its ClientHello, then reassemble the full ClientHello handshake bytes across
/// CRYPTO frames spanning multiple datagrams.
///
/// ParallaX's H3 ClientHello carries the ~1216 B X25519MLKEM768 key_share, which
/// pushes it well past a single 1200 B QUIC Initial — quinn fragments the CH
/// across several Initial packets, one per datagram. The single-datagram
/// [`capture_udp_leg_initial`] helper cannot see the whole hello; this loop recvs
/// each Initial datagram, decrypts it via the in-repo RFC-9001 path, collects its
/// CRYPTO frames, and stops once the offset-0 reassembled stream covers the
/// declared ClientHello length (bounded by a per-recv timeout and an 8-datagram
/// cap so a regression that never completes the CH fails fast instead of hanging).
async fn capture_udp_leg_full_client_hello(server_name: &str) -> Vec<u8> {
    use std::sync::Arc;

    use crate::gfw_sim::detection::quic_initial::{
        decrypt_payload, derive_client_initial_keys_v2, parse_initial_frames,
        parse_protected_long_header, reassemble_crypto_stream, unprotect_header, InitialFrame,
    };
    use parallax::transport::udp::client_config;
    use quinn::Endpoint;
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    };

    // Same never-invoked verifier as `capture_udp_leg_initial`: the Initial is
    // emitted before any ServerHello, so the cert path never runs.
    #[derive(Debug)]
    struct NeverCalled;
    impl ServerCertVerifier for NeverCalled {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }

    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config(Arc::new(NeverCalled)).unwrap());

    let connecting = endpoint.connect(server_addr, server_name).unwrap();
    let drive = tokio::spawn(async move {
        let _ = connecting.await;
    });

    // Decrypt one Initial datagram and return its CRYPTO frames. A single
    // datagram may coalesce a padded Initial; the Length field bounds the payload
    // so trailing bytes are ignored. Out-of-band/handshake packets that fail to
    // parse as a v1 Initial are skipped (return no frames).
    let crypto_frames_from = |datagram: &[u8]| -> Vec<InitialFrame> {
        let mut pkt = datagram.to_vec();
        let mut hdr = match parse_protected_long_header(&pkt) {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };
        let keys = match derive_client_initial_keys_v2(&hdr.dcid) {
            Ok(k) => k,
            Err(_) => return Vec::new(),
        };
        if unprotect_header(&mut pkt, &mut hdr, &keys).is_err() {
            return Vec::new();
        }
        let payload = match decrypt_payload(&pkt, &hdr, &keys) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };
        parse_initial_frames(&payload).unwrap_or_default()
    };

    let mut all_frames: Vec<InitialFrame> = Vec::new();
    let mut buf = vec![0_u8; 2048];
    // 8-datagram / 5s overall cap: the CH fits in 2-3 Initial datagrams, so this
    // is generous but still fails fast if reassembly never completes.
    for _ in 0..8 {
        let recv =
            tokio::time::timeout(Duration::from_millis(2000), listener.recv_from(&mut buf)).await;
        let n = match recv {
            Ok(Ok((n, _))) => n,
            // No more datagrams arriving (client done with the initial flight) or
            // socket error: stop and reassemble whatever we have.
            _ => break,
        };
        all_frames.extend(crypto_frames_from(&buf[..n]));

        // Stop once the offset-0 reassembled stream covers the full declared CH.
        let crypto = reassemble_crypto_stream(&all_frames);
        if crypto.len() >= 4 && crypto[0] == 0x01 {
            let declared = 4
                + (((crypto[1] as usize) << 16)
                    | ((crypto[2] as usize) << 8)
                    | (crypto[3] as usize));
            if crypto.len() >= declared {
                break;
            }
        }
    }
    drive.abort();

    reassemble_crypto_stream(&all_frames)
}

#[tokio::test]
async fn udp_leg_initial_is_standard_decryptable_quic_v1() {
    use crate::gfw_sim::detection::quic_initial::{
        decrypt_payload, derive_client_initial_keys_v2, parse_initial_frames,
        parse_protected_long_header, reassemble_crypto_stream, unprotect_header,
    };

    // The UDP face does NOT obfuscate the QUIC header/Initial: an on-path GFW can
    // derive the Initial keys from the cleartext DCID and decrypt it, exactly like
    // a browser HTTP/3 flow. Camouflage comes from looking like real H3, not from
    // hiding that it is QUIC, so this asserts the realistic baseline (the adversary
    // CAN decrypt) and that what is carried is a TLS ClientHello.
    let initial = capture_udp_leg_initial("cloudflare.com").await;
    let mut pkt = initial.clone();
    let mut hdr = parse_protected_long_header(&pkt).expect("v1 long header parses");
    let keys = derive_client_initial_keys_v2(&hdr.dcid).expect("v1 Initial keys derive from DCID");
    unprotect_header(&mut pkt, &mut hdr, &keys).expect("header protection removed");
    let payload = decrypt_payload(&pkt, &hdr, &keys).expect("Initial payload decrypts");
    let frames = parse_initial_frames(&payload).expect("Initial frames parse");
    let crypto = reassemble_crypto_stream(&frames);
    assert_eq!(
        crypto.first(),
        Some(&0x01_u8),
        "the QUIC Initial carries a TLS ClientHello (handshake type 0x01)"
    );
}

#[tokio::test]
async fn udp_leg_initial_first_datagram_holds_only_partial_clienthello() {
    use crate::gfw_sim::detection::quic_initial::{
        decrypt_payload, derive_client_initial_keys_v2, parse_initial_frames,
        parse_protected_long_header, reassemble_crypto_stream, unprotect_header,
        QuicInitialDetector, QuicInitialVerdict,
    };

    // ParallaX's UDP-leg ClientHello carries the post-quantum hybrid key share
    // (X25519MLKEM768, ~1.2 KB), pushing it past 1200 bytes so quinn fragments it
    // across multiple QUIC Initial datagrams — the same mechanism that incidentally
    // defeats the GFW's single-datagram SNI extraction for Chrome's HTTP/3.
    //
    // IMPORTANT (do not over-read this test): the SNI is NOT hidden. It is present
    // in cleartext across the full multi-datagram ClientHello and, because rustls
    // randomizes order-insensitive extension order per connection, may even sit in
    // this first datagram. What is proven is narrower: a GFW model that buffers the
    // WHOLE declared ClientHello before parsing (as the in-repo detector does, and
    // as the live GFW reportedly does — it does not reassemble across datagrams)
    // extracts nothing from a single datagram. A streaming SNI extractor, or a
    // censor that buffers a flow's Initial datagrams by 5-tuple, WOULD reassemble
    // the CH and read the SNI (note reassemble_crypto_stream already stitches CRYPTO
    // frames WITHIN a packet). Treat this as a decaying external blind spot, not a
    // hardened ParallaX property. The real SNI-slice camouflage slice must make the
    // fragmentation a deliberate, asserted invariant rather than an incidental side
    // effect of the key-share size; if a quinn/rustls change ever shrinks the
    // ClientHello back under one datagram, this test flips and flags the regression.
    let detector = QuicInitialDetector::default();
    for sni in ["cloudflare.com", "blocked.example"] {
        // Loopback + quinn emit the offset-0 Initial datagram first; assertion (a)
        // below relies on that (out-of-order delivery would zero-pad the gap).
        let initial = capture_udp_leg_initial(sni).await;

        // (a) Prove the captured datagram holds only a PARTIAL ClientHello: the
        // declared handshake length must exceed the bytes present in this datagram.
        // This ties the no-SNI result below to genuine multi-datagram fragmentation,
        // not to some unrelated decode failure.
        let mut pkt = initial.clone();
        let mut hdr = parse_protected_long_header(&pkt).expect("v1 long header");
        let keys = derive_client_initial_keys_v2(&hdr.dcid).expect("Initial keys");
        unprotect_header(&mut pkt, &mut hdr, &keys).expect("unprotect header");
        let payload = decrypt_payload(&pkt, &hdr, &keys).expect("decrypt payload");
        let crypto = reassemble_crypto_stream(&parse_initial_frames(&payload).expect("frames"));
        assert!(
            crypto.len() >= 4 && crypto[0] == 0x01,
            "first datagram starts a TLS ClientHello"
        );
        let declared_ch_len =
            4 + (((crypto[1] as usize) << 16) | ((crypto[2] as usize) << 8) | (crypto[3] as usize));
        assert!(
            declared_ch_len > crypto.len(),
            "ClientHello ({declared_ch_len} B) must span beyond this single datagram ({} B)",
            crypto.len()
        );

        // (b) Therefore a whole-CH-buffering GFW filter extracts no SNI / fires no
        // rule from this single datagram. Pin the expected outcome to the partial-CH
        // reassembly failure so a future decrypt/framing regression cannot pass here.
        match detector.inspect(&initial, None) {
            QuicInitialVerdict::AllowSni { sni: got, .. }
            | QuicInitialVerdict::BlockSni { sni: got, .. } => panic!(
                "GFW model extracted SNI {got:?} from a single datagram for {sni:?}; \
                 multi-datagram ClientHello fragmentation no longer protects the SNI"
            ),
            // IncompleteClientHello's Display is "could not reassemble a complete
            // ClientHello from crypto frames"; match on the stable "reassemble"
            // substring (the complete-CH parse-failure variant also says "ClientHello").
            QuicInitialVerdict::Failed(msg) if msg.contains("reassemble") => {}
            QuicInitialVerdict::NoSni { .. } => {
                // A complete CH with no server_name; unreachable for this partial-CH
                // input, but harmless — still means no SNI was extracted.
            }
            QuicInitialVerdict::Failed(other) => {
                panic!("unexpected decrypt/parse failure (not SNI fragmentation): {other}")
            }
        }
    }
}

// --------------------- S5: Safari-26 H3 ClientHello structural gate ---------------------
//
// This gate drives the REAL UDP-leg QUIC client backend
// (`parallax::transport::udp::client_config`), reassembles its multi-datagram
// ClientHello via the in-repo RFC-9001 decryptor, and asserts STRUCTURE ONLY:
// the 20-cipher GREASE-led list, the static Safari extension order (GREASE matched
// by class), and the ascending `quic_transport_parameters` (0x39) id set with
// `max_datagram_frame_size` (0x20) present and `grease_quic_bit`/`min_ack_delay`
// omitted. It NEVER asserts transport-param VALUES, nor `extended_master_secret`
// (0x17) / `renegotiation_info` (0xff01) presence (both capture-gated unknowns).
//
// It turns GREEN only when the vendored-rustls fork + the Safari QUIC Session are
// wired and selected (S6: production `safari_ch_profile` set in `client_config`
// and the Safari backend made the default). Until then the stock quinn/rustls
// backend emits a 3-suite, shuffled-extension, ascending-only-by-accident hello,
// so the assertions below fail — exactly characterizing the fix.

/// RFC 8701 GREASE values: `0x?a?a` with both bytes equal.
fn is_grease_u16(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}

/// Wrap reassembled ClientHello handshake bytes (starting at type 0x01) in a
/// synthetic TLS record so the standard parser accepts them, mirroring the
/// detector's `parse_tls_handshake_clienthello`.
fn wrap_handshake_as_tls_record(crypto: &[u8]) -> Vec<u8> {
    use crate::gfw_sim::detection::sni_filter::TLS_CONTENT_HANDSHAKE;
    let mut wrapped = Vec::with_capacity(5 + crypto.len());
    wrapped.push(TLS_CONTENT_HANDSHAKE);
    wrapped.extend_from_slice(&[0x03, 0x03]);
    wrapped.extend_from_slice(&(crypto.len() as u16).to_be_bytes());
    wrapped.extend_from_slice(crypto);
    wrapped
}

/// Walk the extensions of a wrapped ClientHello TLS record and return the raw
/// body of the first extension whose type equals `want`. The standard parser
/// (`parse_client_hello`) exposes `extensions_order` but not raw bodies; the
/// `quic_transport_parameters` (0x39) body needs its own walk.
fn extension_body(record: &[u8], want: u16) -> Option<Vec<u8>> {
    // record: [type][0x0303][len(2)] then handshake: [0x01][hs_len(3)] body...
    let mut p = 5 + 4; // skip record header + handshake header
    let r = record;
    let rd16 = |b: &[u8], i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    p += 2; // legacy_version
    p += 32; // client_random
    let sid_len = *r.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = rd16(r, p) as usize;
    p += 2 + cs_len;
    let comp_len = *r.get(p)? as usize;
    p += 1 + comp_len;
    let exts_len = rd16(r, p) as usize;
    p += 2;
    let exts_end = p + exts_len;
    while p + 4 <= exts_end && p + 4 <= r.len() {
        let ext_type = rd16(r, p);
        let ext_len = rd16(r, p + 2) as usize;
        let body_start = p + 4;
        let body_end = body_start + ext_len;
        if body_end > r.len() {
            return None;
        }
        if ext_type == want {
            return Some(r[body_start..body_end].to_vec());
        }
        p = body_end;
    }
    None
}

/// Minimal QUIC-varint reader (RFC 9000 §16): returns (value, bytes_consumed).
fn read_quic_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for &byte in &b[1..len] {
        v = (v << 8) | u64::from(byte);
    }
    Some((v, len))
}

/// Parse a `quic_transport_parameters` (0x39) extension body into the ordered
/// list of parameter ids on the wire. Each entry is varint(id) || varint(len) ||
/// value[len]; we only need the id sequence for the structural gate.
fn parse_transport_param_ids(body: &[u8]) -> Option<Vec<u64>> {
    let mut ids = Vec::new();
    let mut p = 0;
    while p < body.len() {
        let (id, n) = read_quic_varint(&body[p..])?;
        p += n;
        let (len, n) = read_quic_varint(&body[p..])?;
        p += n;
        let len = len as usize;
        if p + len > body.len() {
            return None;
        }
        p += len;
        ids.push(id);
    }
    Some(ids)
}

#[tokio::test]
async fn udp_leg_clienthello_matches_safari26_h3_structure() {
    use crate::gfw_sim::detection::sni_filter::parse_client_hello;

    // 1) Drive the real UDP-leg QUIC client and reassemble the full multi-datagram
    //    ClientHello, then parse it.
    let crypto = capture_udp_leg_full_client_hello("cloudflare.com").await;
    assert!(
        crypto.len() >= 4 && crypto[0] == 0x01,
        "reassembled bytes must start a TLS ClientHello (type 0x01)"
    );
    let declared =
        4 + (((crypto[1] as usize) << 16) | ((crypto[2] as usize) << 8) | (crypto[3] as usize));
    assert!(
        crypto.len() >= declared,
        "ClientHello not fully reassembled across datagrams: have {} B, declared {} B",
        crypto.len(),
        declared
    );
    let record = wrap_handshake_as_tls_record(&crypto[..declared]);
    let parsed = parse_client_hello(&record).expect("reassembled ClientHello parses");

    // 2) Cipher suites: 20 Safari suites + 1 GREASE in slot 0 = 21 entries.
    assert_eq!(
        parsed.cipher_suites.len(),
        21,
        "Safari-26 H3 advertises 20 cipher suites led by one GREASE value; got {:?}",
        parsed.cipher_suites
    );
    assert!(
        is_grease_u16(parsed.cipher_suites[0]),
        "cipher slot 0 must be a GREASE value; got {:#06x}",
        parsed.cipher_suites[0]
    );
    // The three TLS 1.3 suites follow the GREASE lead, in Safari's order (no
    // pruning to pure-1.3 — a legacy suite must survive).
    assert_eq!(
        &parsed.cipher_suites[1..4],
        &[0x1302, 0x1303, 0x1301],
        "TLS 1.3 suites must follow the GREASE lead in Safari order"
    );
    assert!(
        parsed.cipher_suites.contains(&0x000a),
        "legacy suite 0x000a must survive (no pure-1.3 pruning tell)"
    );

    // 3) Extension order: the static Safari table, GREASE matched by CLASS, with
    //    extended_master_secret (0x17) / renegotiation_info (0xff01) IGNORED
    //    (capture-gated — never assert their presence/absence). Project the wire
    //    order onto class tokens, drop the legacy capture-gated pair, then compare.
    const TOKEN_GREASE: u16 = 0xFFFF; // sentinel class token for any GREASE codepoint
    let order: Vec<u16> = parsed
        .extensions_order
        .iter()
        .copied()
        .filter(|&e| e != 0x0017 && e != 0xff01) // ignore EMS / reneg (capture-gated)
        .map(|e| if is_grease_u16(e) { TOKEN_GREASE } else { e })
        .collect();
    let expected_order: Vec<u16> = vec![
        TOKEN_GREASE, // leading GREASE (len 0)
        0x0000,       // server_name
        0x000a,       // supported_groups
        0x000b,       // ec_point_formats
        0x0010,       // ALPN (h3)
        0x0005,       // status_request
        0x000d,       // signature_algorithms (Apple's dup 0x0805 kept)
        0x0012,       // signed_certificate_timestamp
        0x0033,       // key_share
        0x002d,       // psk_key_exchange_modes
        0x002b,       // supported_versions
        0x0039,       // quic_transport_parameters
        0x001b,       // compress_certificate
        TOKEN_GREASE, // trailing GREASE (len 1)
    ];
    assert_eq!(
        order, expected_order,
        "extension order must be the static Safari-26 H3 table (GREASE by class, EMS/reneg ignored)"
    );
    // The two GREASE bookends must be DISTINCT values (RFC 8701), and the hello is
    // cold-start: no pre_shared_key (0x29) / early_data (0x2a).
    let greases: Vec<u16> = parsed
        .extensions_order
        .iter()
        .copied()
        .filter(|&e| is_grease_u16(e))
        .collect();
    assert_eq!(greases.len(), 2, "exactly two GREASE extensions (bookends)");
    assert_ne!(greases[0], greases[1], "GREASE bookends must differ");
    assert_eq!(
        *parsed.extensions_order.last().unwrap(),
        greases[1],
        "cold-start: the trailing GREASE is the LAST extension (no pre_shared_key after it)"
    );
    assert!(
        !parsed.extensions_order.contains(&0x0029) && !parsed.extensions_order.contains(&0x002a),
        "cold-start: pre_shared_key (0x29) and early_data (0x2a) must be absent"
    );

    // 4) quic_transport_parameters (0x39): present, ids strictly ascending, the
    //    exact Safari id set, 0x20 present, grease_quic_bit/min_ack_delay omitted.
    //    Structure only — NEVER assert the parameter VALUES.
    let tp_body =
        extension_body(&record, 0x0039).expect("quic_transport_parameters (0x39) present");
    let tp_ids = parse_transport_param_ids(&tp_body).expect("0x39 body parses as TP id list");
    for w in tp_ids.windows(2) {
        assert!(
            w[0] < w[1],
            "transport-param ids must be STRICTLY ascending; saw {:#x} then {:#x} in {:x?}",
            w[0],
            w[1],
            tp_ids
        );
    }
    let expected_tp_ids: Vec<u64> = vec![
        0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0e, 0x0f, 0x20,
    ];
    assert_eq!(
        tp_ids, expected_tp_ids,
        "transport-param id set must be exactly Safari's ascending set"
    );
    assert!(
        tp_ids.contains(&0x20),
        "max_datagram_frame_size (0x20) is the Apple/libquic signature and must be present"
    );
    assert!(
        !tp_ids.contains(&0x2ab2),
        "grease_quic_bit (0x2ab2) must be omitted"
    );
    assert!(
        !tp_ids.contains(&0xff04de1b),
        "min_ack_delay (0xff04de1b) must be omitted"
    );
}
