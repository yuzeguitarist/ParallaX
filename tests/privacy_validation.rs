//! Bounded metadata checks on the actual CONNECT construction and decode path.
//! These do not establish system-wide DNS/IP leak prevention, traffic-analysis
//! resistance or website/correlation indistinguishability.

use parallax::config::TrafficConfig;
use parallax::crypto::session::{self, AeadCodec};
use parallax::handshake::client::ClientDataSession;
use parallax::protocol::command::{connect_record_size_is_shaped, ConnectRequest};
use parallax::protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD};
use parallax::tls::record;
use parallax::traffic::PaddingProfile;
use rand::{rngs::StdRng, SeedableRng};

fn traffic() -> TrafficConfig {
    TrafficConfig {
        min_padding: 0,
        max_padding: 0,
        ..TrafficConfig::default()
    }
}

#[test]
fn encrypted_connect_hides_metadata_and_recovers_exact_server_fields() {
    let psk = *b"public-fixture-psk-not-a-live-key!";
    let hash = [0x53; 32];
    let keys = session::derive_client_keys_from_shared(&psk, &[0x42; 32], &hash).unwrap();
    let server_keys = session::derive_server_keys_from_shared(&psk, &[0x42; 32], &hash).unwrap();
    let domain = "sensitive-destination-7e952f3d4b1a9c68.unresolvable.invalid";
    let initial = b"PRIVATE-INITIAL-PAYLOAD-253a2adc5cab489da6bef130c0cc9e93";
    let request = ConnectRequest {
        host: domain.to_owned(),
        port: 443,
        initial_payload: initial.to_vec(),
    };
    let mut client = ClientDataSession::new(keys, traffic()).unwrap();
    let mut rng = StdRng::seed_from_u64(0x50524956414359);
    let wire = client
        .build_connect_record(request.clone(), &mut rng)
        .unwrap();
    for sensitive in [domain.as_bytes(), initial.as_slice(), psk.as_slice()] {
        assert!(
            !wire
                .windows(sensitive.len())
                .any(|window| window == sensitive),
            "the encrypted CONNECT wire exposed an entire sensitive sentinel"
        );
    }
    let header = record::parse_header(&wire).unwrap();
    assert_eq!(header.total_len, wire.len());
    assert!(connect_record_size_is_shaped(header.payload_len));
    let mut server = DataRecordCodec::new(
        AeadCodec::new(server_keys.client_key, server_keys.client_nonce),
        PaddingProfile::from_config(traffic()).unwrap(),
        CLIENT_TO_SERVER_AAD,
    );
    let plaintext = server.open(&wire).unwrap();
    assert_eq!(ConnectRequest::decode(&plaintext).unwrap(), request);
    // This reproduces the server's record/command decode exactly. The separate
    // binary .invalid-domain test checks that the SOCKS runtime does not require
    // local resolution; neither fixture is a system DNS-packet monitor.
}

#[test]
fn connect_shaping_keeps_small_domain_and_payload_lengths_in_browser_bands() {
    let domains = [
        "a.invalid".to_owned(),
        format!("{}.invalid", "a".repeat(63)),
        format!("{}.{}.invalid", "a".repeat(63), "b".repeat(63)),
        format!(
            "{}.{}.{}.{}.invalid",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(53)
        ),
    ];
    assert_eq!(domains.last().unwrap().len(), 253);
    let keys =
        session::derive_client_keys_from_shared(&[0x31; 32], &[0x42; 32], &[0x53; 32]).unwrap();
    for (case, domain) in domains.iter().enumerate() {
        for length in [0, 1, 31, 127, 511] {
            let request = ConnectRequest {
                host: domain.clone(),
                port: 443,
                initial_payload: vec![0x61; length],
            };
            let mut client = ClientDataSession::new(keys.clone(), traffic()).unwrap();
            let mut rng = StdRng::seed_from_u64((case * 1000 + length) as u64);
            let wire = client
                .build_connect_record(request.clone(), &mut rng)
                .unwrap();
            let header = record::parse_header(&wire).unwrap();
            assert_eq!(header.total_len, wire.len());
            assert!(connect_record_size_is_shaped(header.payload_len));
            let mut server = DataRecordCodec::new(
                AeadCodec::new(keys.client_key, keys.client_nonce),
                PaddingProfile::from_config(traffic()).unwrap(),
                CLIENT_TO_SERVER_AAD,
            );
            assert_eq!(
                ConnectRequest::decode(&server.open(&wire).unwrap()).unwrap(),
                request
            );
        }
    }
    // Band membership bounds direct size leakage for these twenty requests;
    // it is not an estimate of mutual information or classifier accuracy.
}
