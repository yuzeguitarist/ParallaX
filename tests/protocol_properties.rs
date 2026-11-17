//! Generated protocol invariants with bounded byte/scalar shrinking. See
//! support/property.rs for the deterministic generator and replay controls.

#[macro_use]
#[path = "support/property.rs"]
mod property;

use parallax::crypto::auth::{
    build_masked_stateful_auth_session_id, build_masked_stateful_client_random,
    derive_client_auth_key, derive_server_auth_key, recover_stateful_auth_material,
};
use parallax::crypto::quic_marker;
use parallax::crypto::replay::{ReplayCache, ReplayEntry, ReplayInsertOutcome};
use parallax::crypto::session::{x25519_public_from_private, AeadCodec, CipherSuite};
use parallax::protocol::command::*;
use parallax::protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD, SERVER_TO_CLIENT_AAD};
use parallax::tls::client_hello::parse_client_hello;
use parallax::traffic::PaddingProfile;
use rand::{rngs::StdRng, SeedableRng};

fn suite(chacha: bool) -> CipherSuite {
    if chacha {
        CipherSuite::ChaCha20Poly1305
    } else {
        CipherSuite::Aes256Gcm
    }
}

fn record_codec(
    key: [u8; 32],
    nonce: [u8; 12],
    chacha: bool,
    padding: u16,
    reverse: bool,
) -> DataRecordCodec {
    DataRecordCodec::new(
        AeadCodec::new_with_suite(suite(chacha), key, nonce),
        PaddingProfile::new(padding, padding).unwrap(),
        if reverse {
            SERVER_TO_CLIENT_AAD
        } else {
            CLIENT_TO_SERVER_AAD
        },
    )
}

#[test]
fn connect_lengths_are_exact_and_prefixes_cannot_decode() {
    property::check("connect", |case| {
        let host: String = case
            .payload(255)
            .iter()
            .map(|b| char::from(b'a' + b % 26))
            .collect();
        let host = if host.is_empty() {
            "x".to_owned()
        } else {
            host
        };
        let request = ConnectRequest {
            host,
            port: (case.a as u16).max(1),
            initial_payload: case.payload(2048).to_vec(),
        };
        let wire = request.encode().unwrap();
        prop_assert_eq!(wire.len(), request.encoded_len());
        prop_assert_eq!(ConnectRequest::decode(&wire).unwrap(), request);
        prop_assert!(ConnectRequest::decode(&wire[..case.b as usize % wire.len()]).is_err());
        let mut suffixed = wire;
        suffixed.push(0);
        prop_assert!(ConnectRequest::decode(&suffixed).is_err());
        Ok(())
    });
}

#[test]
fn pq_and_identity_messages_reject_changed_declared_lengths() {
    property::check("pq-identity", |case| {
        let public = case.array::<32>(0);
        let bytes = if case.bytes.is_empty() {
            vec![0]
        } else {
            case.payload(2048).to_vec()
        };
        let rekey = PqRekeyRequest {
            client_x25519_public: public,
            client_mlkem_public_key: bytes.clone(),
        };
        let mut wire = rekey.encode().unwrap();
        prop_assert_eq!(PqRekeyRequest::decode(&wire).unwrap(), rekey);
        wire[39] ^= 1;
        prop_assert!(PqRekeyRequest::decode(&wire).is_err());
        for negotiated in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            let exchange = ServerKeyExchange {
                server_x25519_public: public,
                mlkem_ciphertext: bytes.clone(),
            };
            let mut wire = exchange.encode_with_suite(negotiated).unwrap();
            let (view, actual) = ServerKeyExchange::decode_ref_with_suite(&wire).unwrap();
            prop_assert_eq!(view.server_x25519_public, public);
            prop_assert_eq!(view.mlkem_ciphertext, bytes.as_slice());
            prop_assert_eq!(actual, negotiated);
            *wire.last_mut().unwrap() = 0xff;
            prop_assert!(ServerKeyExchange::decode(&wire).is_err());
        }
        let identity = ServerIdentityProof { signature: bytes };
        let mut wire = identity.encode().unwrap();
        prop_assert_eq!(ServerIdentityProof::decode(&wire).unwrap(), identity);
        wire.push(0);
        prop_assert!(ServerIdentityProof::decode(&wire).is_err());
        Ok(())
    });
}

#[test]
fn chunks_are_bounded_ordered_and_reassembler_is_reusable() {
    property::check("chunks", |case| {
        let payload = if case.bytes.is_empty() {
            vec![0]
        } else {
            case.bytes.clone()
        };
        let chunks = FramedChunk::encode_all(&payload, 1 + case.a as usize % 512).unwrap();
        let mut assembler = FramedReassembler::default();
        for _ in 0..2 {
            for (index, chunk) in chunks.iter().enumerate() {
                let decoded = FramedChunk::decode_ref(chunk).unwrap();
                prop_assert_eq!(decoded.total_len as usize, payload.len());
                prop_assert!(decoded.offset as usize + decoded.bytes.len() <= payload.len());
                let result = assembler.push(chunk, payload.len()).unwrap();
                if index + 1 == chunks.len() {
                    prop_assert_eq!(result.as_deref(), Some(payload.as_slice()));
                } else {
                    prop_assert_eq!(result, None);
                }
            }
        }
        prop_assert!(FramedReassembler::default()
            .push(&chunks[0], payload.len() - 1)
            .is_err());
        if chunks.len() > 1 {
            prop_assert!(FramedReassembler::default()
                .push(&chunks[1], payload.len())
                .is_err());
            let mut duplicate = FramedReassembler::default();
            prop_assert_eq!(duplicate.push(&chunks[0], payload.len()).unwrap(), None);
            prop_assert!(duplicate.push(&chunks[0], payload.len()).is_err());
        }
        Ok(())
    });
}

#[test]
fn mux_concatenation_preserves_each_frame_and_exact_consumption() {
    property::check("mux", |case| {
        let mut expected = Vec::new();
        let mut wire = Vec::new();
        for kind in [
            MuxFrameKind::Open,
            MuxFrameKind::Data,
            MuxFrameKind::Fin,
            MuxFrameKind::Reset,
            MuxFrameKind::Cover,
        ] {
            let stream_id = if kind == MuxFrameKind::Cover {
                0
            } else {
                (case.a as u32).max(1)
            };
            let frame = MuxFrame {
                stream_id,
                kind,
                payload: case.payload(256).to_vec(),
            };
            wire.extend_from_slice(&frame.encode().unwrap());
            expected.push(frame);
        }
        prop_assert_eq!(MuxFrame::decode_all(&wire).unwrap(), expected.clone());
        let mut cursor = 0;
        for frame in expected {
            let (decoded, used) = MuxFrame::decode_prefix(&wire[cursor..]).unwrap();
            prop_assert_eq!(decoded, frame);
            prop_assert!(used > 0);
            cursor += used;
        }
        prop_assert_eq!(cursor, wire.len());
        wire.pop();
        prop_assert!(MuxFrame::decode_all(&wire).is_err());
        Ok(())
    });
}

#[test]
fn udp_and_speed_control_commands_enforce_exact_framing() {
    property::check("udp-speed", |case| {
        let offer_id = case.array::<16>(0);
        let offer = UdpOffer {
            offer_id,
            udp_port: (case.a as u16).max(1),
            port_hop_seed: case.b,
            cc: case.a as u8,
            fec_profile: case.b as u8,
            ignore_client_bandwidth: case.c & 1 != 0,
        };
        let request = UdpRequest {
            version: case.a as u8,
        };
        let decline = UdpDecline {
            reason: case.b as u8,
        };
        let speed = SpeedTestRequest {
            warmup_bytes: case.a.max(1),
            download_bytes: case.b.max(1),
            upload_bytes: case.c.max(1),
            sample_count: (case.c as u16).max(1),
        };
        prop_assert_eq!(
            UdpOffer::decode(&offer.encode().unwrap()).unwrap(),
            offer.clone()
        );
        prop_assert_eq!(UdpRequest::decode(&request.encode()).unwrap(), request);
        prop_assert_eq!(UdpDecline::decode(&decline.encode()).unwrap(), decline);
        prop_assert_eq!(
            SpeedTestRequest::decode(&speed.encode().unwrap()).unwrap(),
            speed
        );
        for status in [
            UdpProbeStatus::Verified,
            UdpProbeStatus::Unreachable,
            UdpProbeStatus::Failed,
        ] {
            let ack = UdpProbeAck {
                offer_id,
                status,
                rtt_micros: case.c as u32,
            };
            prop_assert_eq!(UdpProbeAck::decode(&ack.encode()).unwrap(), ack);
        }
        for ack in [
            SpeedTestAck::warmup_download_done(case.a),
            SpeedTestAck::warmup_upload_done(case.b),
            SpeedTestAck::download_done(case.b),
            SpeedTestAck::upload_done(case.c),
        ] {
            prop_assert_eq!(SpeedTestAck::decode(&ack.encode()).unwrap(), ack);
        }
        let mut bad = offer.encode().unwrap();
        bad.push(0);
        prop_assert!(UdpOffer::decode(&bad).is_err());
        let mut bad = speed.encode().unwrap();
        bad[4..12].fill(0);
        prop_assert!(SpeedTestRequest::decode(&bad).is_err());
        Ok(())
    });
}

#[test]
fn aead_tampering_reflection_and_replay_never_yield_plaintext() {
    property::check("aead", |case| {
        let key = case.array::<32>(0);
        let nonce = case.array::<12>(32);
        let padding = (case.a % 512) as u16;
        for chacha in [false, true] {
            for reverse in [false, true] {
                let mut sender = record_codec(key, nonce, chacha, padding, reverse);
                let mut receiver = record_codec(key, nonce, chacha, padding, reverse);
                let mut rng = StdRng::seed_from_u64(case.b);
                for payload in [case.payload(1024), &[]] {
                    let wire = sender.seal(payload, &mut rng).unwrap();
                    let mut bad = wire.clone();
                    let at = 5 + case.b as usize % (bad.len() - 5);
                    bad[at] ^= 1 << (case.c % 8);
                    prop_assert!(receiver.open(&bad).is_err());
                    prop_assert_eq!(receiver.open(&wire).unwrap(), payload);
                    prop_assert!(receiver.open(&wire).is_err());
                    prop_assert!(record_codec(key, nonce, chacha, padding, !reverse)
                        .open(&wire)
                        .is_err());
                }
            }
        }
        Ok(())
    });
}

#[test]
fn replay_cache_matches_generated_histories_without_evicting_fresh_entries() {
    property::check("replay", |case| {
        let capacity = 1 + case.a as usize % 8;
        let window = case.b % 40;
        let mut cache = ReplayCache::new(capacity).with_window_secs(window);
        let mut live: Vec<ReplayEntry> = Vec::new();
        let mut now = 1000u64;
        for bytes in case.payload(400).chunks(4).filter(|bytes| bytes.len() == 4) {
            now += u64::from(bytes[0] % 10);
            let timestamp = (now as i64 + i64::from(bytes[1] % 58) - 45) as u64;
            let entry = ReplayEntry {
                timestamp,
                nonce: [bytes[2] % 8; 8],
                transcript_fingerprint: [bytes[3] % 8; 32],
            };
            live.retain(|entry| now <= entry.timestamp.saturating_add(window));
            let expected = if timestamp > now + 5 || now > timestamp + window {
                ReplayInsertOutcome::Stale
            } else if live.iter().any(|old| {
                old.nonce == entry.nonce
                    || old.transcript_fingerprint == entry.transcript_fingerprint
            }) {
                ReplayInsertOutcome::Replayed
            } else if live.len() == capacity {
                ReplayInsertOutcome::CacheFull
            } else {
                live.push(entry.clone());
                ReplayInsertOutcome::Inserted
            };
            prop_assert_eq!(cache.insert_new_outcome(entry, now).unwrap(), expected);
        }
        Ok(())
    });
}

#[test]
fn tcp_auth_keys_and_masked_carrier_recover_generated_material() {
    property::check("tcp-auth", |case| {
        let psk = case.array::<32>(0);
        let client_private = case.array::<32>(32);
        let server_private = case.array::<32>(64);
        let public = case.array::<32>(96);
        let tail = case.array::<16>(128);
        let client_public = x25519_public_from_private(&client_private);
        let server_public = x25519_public_from_private(&server_private);
        let client_key = derive_client_auth_key(&psk, &client_private, &server_public).unwrap();
        let server_key = derive_server_auth_key(&psk, &server_private, &client_public).unwrap();
        prop_assert_eq!(&*client_key, &*server_key);
        let shared =
            parallax::crypto::session::x25519_shared_secret(&client_private, &server_public);
        let mut hello = include_bytes!("fixtures/safari26_cloudflare_com_clienthello.bin").to_vec();
        let parsed = parse_client_hello(&hello).unwrap();
        let sni = parsed.sni.as_deref().unwrap();
        let random =
            build_masked_stateful_client_random(&psk, &shared, sni, &public, &tail).unwrap();
        let session_id = build_masked_stateful_auth_session_id(
            &psk,
            &shared,
            &client_key[..],
            sni,
            &public,
            &random,
            &tail,
        )
        .unwrap();
        hello[11..43].copy_from_slice(&random);
        hello[parsed.session_id_range].copy_from_slice(&session_id);
        let recovered = recover_stateful_auth_material(&hello, &psk, &shared)
            .unwrap()
            .unwrap();
        prop_assert_eq!(recovered.x25519_public, public);
        prop_assert_eq!(recovered.tail, tail);
        Ok(())
    });
}

#[test]
fn quic_marker_binds_context_freshness_and_each_carrier_bit() {
    property::check("quic-marker", |case| {
        let psk = case.array::<32>(0);
        let shared = case.array::<32>(32);
        let nonce = case.array::<12>(64);
        let dcid = case.payload(20);
        let timestamp = 1000 + case.a % (u64::MAX - 2000);
        let window = case.b % 300;
        let marker = quic_marker::seal(&psk, &shared, b"test.example", dcid, timestamp, &nonce);
        let accepted = quic_marker::open(
            &psk,
            &shared,
            b"test.example",
            dcid,
            &marker,
            timestamp,
            window,
        )
        .unwrap();
        prop_assert_eq!(accepted.nonce, nonce);
        prop_assert_eq!(accepted.timestamp, timestamp);
        let mut bad = marker;
        bad[case.b as usize % 32] ^= 1 << (case.c % 8);
        prop_assert!(quic_marker::open(
            &psk,
            &shared,
            b"test.example",
            dcid,
            &bad,
            timestamp,
            window
        )
        .is_none());
        let mut wrong_dcid = dcid.to_vec();
        wrong_dcid.push(0);
        prop_assert!(quic_marker::open(
            &psk,
            &shared,
            b"test.example",
            &wrong_dcid,
            &marker,
            timestamp,
            window
        )
        .is_none());
        prop_assert!(quic_marker::open(
            &psk,
            &shared,
            b"other.example",
            dcid,
            &marker,
            timestamp,
            window
        )
        .is_none());
        prop_assert!(quic_marker::open(
            &psk,
            &shared,
            b"test.example",
            dcid,
            &marker,
            timestamp + window + 1,
            window
        )
        .is_none());
        prop_assert!(quic_marker::open(
            &psk,
            &shared,
            b"test.example",
            dcid,
            &marker,
            timestamp - 6,
            window
        )
        .is_none());
        Ok(())
    });
}
