//! Independent oracles for the protocol surfaces not covered by
//! `security_protocol_differential`: authentication, key schedules, signed
//! transcript serialization, PQ/diagnostic/UDP commands, and TLS framing.
//! The cryptographic oracle implements RFC 5869 using aws-lc HMAC, independently
//! of production RustCrypto HKDF/HMAC. Wire oracles use SPEC.md's literal labels,
//! offsets and bounds, never production parsers or framing helpers. These are
//! bounded conformance checks, not an independent complete TLS/QUIC peer.

use aws_lc_rs::{digest, hmac};
use parallax::crypto::{auth, identity, pq, quic_marker, session};
use parallax::handshake::transcript::transcript_hash;
use parallax::protocol::command::*;
use parallax::tls::record;
use parallax::transport::udp::auth::derive_udp_auth_token;

fn mac(key: &[u8], input: &[u8]) -> [u8; 32] {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), input)
        .as_ref()
        .try_into()
        .unwrap()
}

// All protocol outputs here are <= SHA-256's 32-byte block. RFC 5869 Expand
// therefore consists of exactly T(1) = HMAC(PRK, info || 0x01).
fn expand<const N: usize>(prk: &[u8], info: &[u8]) -> [u8; N] {
    assert!(N <= 32);
    let mut block = info.to_vec();
    block.push(1);
    mac(prk, &block)[..N].try_into().unwrap()
}

fn prefixed(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u16).to_be_bytes());
    out.extend_from_slice(field);
}

fn key_info(label: &[u8], epoch: u64, stream: Option<u64>, hash: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::new();
    prefixed(&mut info, label);
    info.extend_from_slice(&epoch.to_be_bytes());
    if let Some(id) = stream {
        info.extend_from_slice(&id.to_be_bytes());
    }
    prefixed(&mut info, hash);
    info
}

fn check_keys(keys: &session::SessionKeys, stream: Option<u64>) {
    let labels: [&[u8]; 4] = if stream.is_some() {
        [
            b"ParallaX v1 mux substream client key",
            b"ParallaX v1 mux substream server key",
            b"ParallaX v1 mux substream client nonce",
            b"ParallaX v1 mux substream server nonce",
        ]
    } else {
        [
            b"client appdata key",
            b"server appdata key",
            b"client appdata nonce",
            b"server appdata nonce",
        ]
    };
    let info = labels.map(|label| key_info(label, keys.epoch, stream, &keys.transcript_hash));
    assert_eq!(keys.client_key, expand::<32>(&keys.chain_secret, &info[0]));
    assert_eq!(keys.server_key, expand::<32>(&keys.chain_secret, &info[1]));
    assert_eq!(
        keys.client_nonce,
        expand::<12>(&keys.chain_secret, &info[2])
    );
    assert_eq!(
        keys.server_nonce,
        expand::<12>(&keys.chain_secret, &info[3])
    );
}

fn check_metadata(
    keys: &session::SessionKeys,
    chain: &[u8; 32],
    epoch: u64,
    hash: &[u8; 32],
    shared: &[u8; 32],
) {
    assert_eq!(&keys.chain_secret, chain);
    assert_eq!(keys.epoch, epoch);
    assert_eq!(&keys.transcript_hash, hash);
    assert_eq!(&keys.x25519_shared_secret, shared);
}

#[test]
fn initial_hybrid_epoch_and_substream_schedules_match_rfc5869_oracle() {
    for size in [1, 31, 32, 64, 65, 255, 256, 300] {
        let psk = vec![size as u8; size];
        let shared = [0x42; 32];
        let pq_shared = [0x91; 32];
        let hash = [size as u8; 32];
        let initial = session::derive_client_keys_from_shared(&psk, &shared, &hash).unwrap();
        let server = session::derive_server_keys_from_shared(&psk, &shared, &hash).unwrap();
        let prk = mac(&psk, &shared);
        let info = key_info(
            b"ParallaX v2 initial psk+x25519 chain secret",
            0,
            None,
            &hash,
        );
        let expected_chain = expand::<32>(&prk, &info);
        check_metadata(&initial, &expected_chain, 0, &hash, &shared);
        check_metadata(&server, &expected_chain, 0, &hash, &shared);
        check_keys(&initial, None);
        check_keys(&server, None);

        let mut ikm = b"x25519:".to_vec();
        ikm.extend_from_slice(&shared);
        ikm.extend_from_slice(b"|mlkem1024:");
        ikm.extend_from_slice(&pq_shared);
        ikm.extend_from_slice(b"|psk:");
        ikm.extend_from_slice(&(psk.len() as u32).to_be_bytes());
        ikm.extend_from_slice(&psk);
        let chain =
            pq::hybrid_sandwich_rekey(&initial.chain_secret, &shared, &pq_shared, &psk).unwrap();
        assert_eq!(chain, mac(&initial.chain_secret, &ikm));
        for epoch in [0, 1, 255, 256, u64::MAX] {
            let keys = session::expand_epoch_keys(chain, epoch, hash, shared).unwrap();
            check_metadata(&keys, &chain, epoch, &hash, &shared);
            check_keys(&keys, None);
            for id in [0, 1, 255, 256, u32::MAX as u64, u64::MAX] {
                let sub = session::expand_substream_keys(&keys, id).unwrap();
                check_metadata(&sub, &chain, epoch, &hash, &shared);
                check_keys(&sub, Some(id));
            }
        }
        let auth_key = auth::derive_client_auth_key_from_shared(&psk, &shared).unwrap();
        assert_eq!(
            *auth_key,
            expand::<32>(&prk, b"ParallaX v1 ClientHello authentication")
        );
        let token = derive_udp_auth_token(&shared, &psk).unwrap();
        assert_eq!(*token, expand::<32>(&prk, b"ParallaX v1 TUDP auth key"));
    }
}

fn carrier_mask(key: &[u8], label: &[u8], sni: &[u8], first: &[u8]) -> [u8; 32] {
    let mut msg = label.to_vec();
    prefixed(&mut msg, sni);
    prefixed(&mut msg, first);
    prefixed(&mut msg, b"");
    mac(key, &msg)
}

#[test]
fn tcp_auth_carrier_bytes_match_independent_hkdf_hmac_oracle() {
    let psk = b"0123456789abcdef0123456789abcdef";
    let shared = [0x51; 32];
    let public = [0x92; 32];
    let tail = [0x37; 16];
    let auth_key = mac(psk, b"different authentication ECDH");
    let key = expand::<32>(
        &mac(psk, &shared),
        b"ParallaX v4 ClientHello carrier mask key",
    );
    for sni in ["x", "cloudflare.com", "bücher.example"] {
        let mask = carrier_mask(
            &key,
            b"ParallaX v4 ClientHello.random mask",
            sni.as_bytes(),
            &tail,
        );
        let random = std::array::from_fn(|i| mask[i] ^ public[i]);
        assert_eq!(
            auth::build_masked_stateful_client_random(psk, &shared, sni, &public, &tail).unwrap(),
            random
        );
        let mask = carrier_mask(
            &key,
            b"ParallaX v4 ClientHello session_id tail mask",
            sni.as_bytes(),
            &random,
        );
        let encoded_tail: [u8; 16] = std::array::from_fn(|i| tail[i] ^ mask[i]);
        let mut msg = b"ParallaX v3 masked stateful rustls ClientHello auth".to_vec();
        prefixed(&mut msg, sni.as_bytes());
        msg.extend_from_slice(&public);
        msg.extend_from_slice(&tail);
        msg.extend_from_slice(&random);
        msg.extend_from_slice(&encoded_tail);
        let mut expected = mac(&auth_key, &msg)[..16].to_vec();
        expected.extend_from_slice(&encoded_tail);
        assert_eq!(
            auth::build_masked_stateful_auth_session_id(
                psk, &shared, &auth_key, sni, &public, &random, &tail
            )
            .unwrap()
            .as_slice(),
            expected
        );
        // Feed oracle-produced carrier bytes to the server's recovery path in
        // an independently serialized TLS ClientHello (RFC 8446 section 4.1.2).
        let mut names = Vec::new();
        names.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
        names.push(0);
        prefixed(&mut names, sni.as_bytes());
        let mut extensions = vec![0, 0];
        prefixed(&mut extensions, &names);
        let mut body = vec![3, 3];
        body.extend_from_slice(&random);
        body.push(32);
        body.extend_from_slice(&expected);
        body.extend_from_slice(&[0, 2, 0x13, 1, 1, 0]);
        prefixed(&mut body, &extensions);
        let mut handshake = vec![1];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let mut hello = vec![0x16, 3, 3];
        prefixed(&mut hello, &handshake);
        let recovered = auth::recover_stateful_auth_material(&hello, psk, &shared)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.x25519_public, public);
        assert_eq!(recovered.tail, tail);
    }
}

#[test]
fn quic_marker_bytes_tampering_and_freshness_match_independent_oracle() {
    let psk = b"0123456789abcdef0123456789abcdef";
    let shared = [0x51; 32];
    let prk = mac(psk, &shared);
    let mask = expand::<32>(&prk, b"ParallaX v1 QUIC marker keystream");
    let key = expand::<32>(&prk, b"ParallaX v1 QUIC marker auth key");
    let nonce = [0xa5; 12];
    let dcid = [0x75; 8];
    for sni in [b"x".as_slice(), b"cloudflare.com"] {
        for timestamp in [0, 1, 255, 256, u64::MAX - 5, u64::MAX] {
            let mut msg = b"ParallaX v1 QUIC marker tag".to_vec();
            prefixed(&mut msg, sni);
            prefixed(&mut msg, &dcid);
            msg.extend_from_slice(&nonce);
            msg.extend_from_slice(&timestamp.to_be_bytes());
            let mut plain = mac(&key, &msg)[..12].to_vec();
            plain.extend_from_slice(&nonce);
            plain.extend_from_slice(&timestamp.to_be_bytes());
            let expected: [u8; 32] = std::array::from_fn(|i| plain[i] ^ mask[i]);
            assert_eq!(
                quic_marker::seal(psk, &shared, sni, &dcid, timestamp, &nonce),
                expected
            );
            for now in [
                0,
                timestamp.saturating_sub(6),
                timestamp.saturating_sub(5),
                timestamp,
                timestamp.saturating_add(60),
                timestamp.saturating_add(61),
                u64::MAX,
            ] {
                // u128 arithmetic expresses mathematical freshness without
                // copying production's saturating-add implementation.
                let fresh = u128::from(timestamp) <= u128::from(now) + 5
                    && u128::from(now) <= u128::from(timestamp) + 60;
                let actual = quic_marker::open(psk, &shared, sni, &dcid, &expected, now, 60);
                assert_eq!(
                    actual.map(|m| (m.nonce, m.timestamp)),
                    fresh.then_some((nonce, timestamp))
                );
            }
            for at in 0..32 {
                let mut bad = expected;
                bad[at] ^= 1;
                assert!(quic_marker::open(psk, &shared, sni, &dcid, &bad, timestamp, 60).is_none());
            }
        }
    }
}

fn hashed_pair(label: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut msg = label.to_vec();
    msg.extend_from_slice(&(a.len() as u32).to_be_bytes());
    msg.extend_from_slice(a);
    msg.extend_from_slice(&(b.len() as u32).to_be_bytes());
    msg.extend_from_slice(b);
    digest::digest(&digest::SHA256, &msg)
        .as_ref()
        .try_into()
        .unwrap()
}

#[test]
fn transcript_and_identity_bindings_match_independent_serialization() {
    for (a, b) in [
        (b"".as_slice(), b"".as_slice()),
        (b"a", b"bc"),
        (b"ab", b"c"),
        (&[0x31; 256], &[0x42; 257]),
    ] {
        let hash = hashed_pair(b"ParallaX v1 handshake transcript", a, b);
        assert_eq!(transcript_hash(a, b), hash);
        let binding = hashed_pair(b"ParallaX v1 PQ rekey identity binding", a, b);
        assert_eq!(identity::pq_rekey_binding(a, b), binding);
        for epoch in [0, 1, 256, u64::MAX] {
            let mut msg = b"ParallaX v2 server identity proof".to_vec();
            msg.extend_from_slice(&epoch.to_be_bytes());
            msg.extend_from_slice(&hash);
            msg.extend_from_slice(&[0x93; 32]);
            msg.extend_from_slice(&binding);
            assert_eq!(
                identity::identity_message(&hash, &[0x93; 32], &binding, epoch),
                msg
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Control {
    Rekey,
    Exchange,
    Identity,
    Speed,
    Ack,
    Offer,
    Probe,
    Request,
    Decline,
}

#[derive(Debug, PartialEq, Eq)]
struct View {
    bytes: Vec<u8>,
    numbers: Vec<u64>,
}

fn uint(input: &[u8], at: usize, width: usize) -> Option<u64> {
    Some(
        input
            .get(at..at + width)?
            .iter()
            .fold(0, |n, &b| n * 256 + u64::from(b)),
    )
}

fn spec_control(kind: Control, input: &[u8]) -> Option<View> {
    let mut view = View {
        bytes: Vec::new(),
        numbers: Vec::new(),
    };
    let (magic, size) = match kind {
        Control::Rekey | Control::Exchange | Control::Identity => {
            let (magic, start, length_at, suffix) = match kind {
                Control::Rekey => (b"PX1Q", 40, 36, 0),
                Control::Exchange => (b"PX1K", 40, 36, 1),
                _ => (b"PX1S", 8, 4, 0),
            };
            let size = usize::try_from(uint(input, length_at, 4)?).ok()?;
            if size == 0 || input.len().checked_sub(start + suffix)? != size {
                return None;
            }
            if suffix == 1 {
                let suite = u64::from(*input.last()?);
                if suite > 1 {
                    return None;
                }
                view.numbers.push(suite);
            }
            if start == 40 {
                view.bytes.extend_from_slice(input.get(4..36)?);
            }
            view.bytes
                .extend_from_slice(input.get(start..start + size)?);
            (magic, start + size + suffix)
        }
        Control::Speed => {
            view.numbers = vec![
                uint(input, 4, 8)?,
                uint(input, 12, 8)?,
                uint(input, 20, 8)?,
                uint(input, 28, 2)?,
            ];
            if view.numbers.contains(&0) {
                return None;
            }
            (b"PX1T", 30)
        }
        Control::Ack => {
            let code = match input.get(..4)? {
                b"PX1W" => 0,
                b"PX1V" => 1,
                b"PX1D" => 2,
                b"PX1U" => 3,
                _ => return None,
            };
            view.numbers = vec![code, uint(input, 4, 8)?];
            (input.get(..4)?.try_into().ok()?, 12)
        }
        Control::Offer => {
            view.bytes.extend_from_slice(input.get(4..20)?);
            let port = uint(input, 20, 2)?;
            if port == 0 {
                return None;
            }
            // Unknown CC/FEC codes are deliberately retained for forward
            // compatibility; the deployed bool decoder normalizes nonzero.
            view.numbers = vec![
                port,
                uint(input, 22, 8)?,
                uint(input, 30, 1)?,
                uint(input, 31, 1)?,
                u64::from(*input.get(32)? != 0),
            ];
            (b"PX1O", 33)
        }
        Control::Probe => {
            view.bytes.extend_from_slice(input.get(4..20)?);
            let status = uint(input, 20, 1)?;
            if status > 2 {
                return None;
            }
            view.numbers = vec![status, uint(input, 21, 4)?];
            (b"PX1P", 25)
        }
        Control::Request | Control::Decline => {
            view.numbers.push(uint(input, 4, 1)?);
            (
                if matches!(kind, Control::Request) {
                    b"PX1G"
                } else {
                    b"PX1N"
                },
                5,
            )
        }
    };
    (input.len() == size && input.starts_with(magic)).then_some(view)
}

fn production_control(kind: Control, input: &[u8]) -> Option<(View, Result<Vec<u8>, String>)> {
    let mut view = View {
        bytes: Vec::new(),
        numbers: Vec::new(),
    };
    let encoded = match kind {
        Control::Rekey => {
            let v = PqRekeyRequest::decode(input).ok()?;
            view.bytes.extend_from_slice(&v.client_x25519_public);
            view.bytes.extend_from_slice(&v.client_mlkem_public_key);
            v.encode().map_err(|error| error.to_string())
        }
        Control::Exchange => {
            let (v, suite) = ServerKeyExchange::decode_ref_with_suite(input).ok()?;
            view.bytes.extend_from_slice(&v.server_x25519_public);
            view.bytes.extend_from_slice(v.mlkem_ciphertext);
            view.numbers.push(match suite {
                session::CipherSuite::ChaCha20Poly1305 => 0,
                session::CipherSuite::Aes256Gcm => 1,
            });
            ServerKeyExchange {
                server_x25519_public: v.server_x25519_public,
                mlkem_ciphertext: v.mlkem_ciphertext.to_vec(),
            }
            .encode_with_suite(suite)
            .map_err(|error| error.to_string())
        }
        Control::Identity => {
            let v = ServerIdentityProof::decode(input).ok()?;
            view.bytes.extend_from_slice(&v.signature);
            v.encode().map_err(|error| error.to_string())
        }
        Control::Speed => {
            let v = SpeedTestRequest::decode(input).ok()?;
            view.numbers = vec![
                v.warmup_bytes,
                v.download_bytes,
                v.upload_bytes,
                u64::from(v.sample_count),
            ];
            v.encode().map_err(|error| error.to_string())
        }
        Control::Ack => {
            let v = SpeedTestAck::decode(input).ok()?;
            view.numbers = vec![
                match v.kind {
                    SpeedTestAckKind::WarmupDownloadDone => 0,
                    SpeedTestAckKind::WarmupUploadDone => 1,
                    SpeedTestAckKind::DownloadDone => 2,
                    SpeedTestAckKind::UploadDone => 3,
                },
                v.bytes,
            ];
            Ok(v.encode())
        }
        Control::Offer => {
            let v = UdpOffer::decode(input).ok()?;
            view.bytes.extend_from_slice(&v.offer_id);
            view.numbers = vec![
                u64::from(v.udp_port),
                v.port_hop_seed,
                u64::from(v.cc),
                u64::from(v.fec_profile),
                u64::from(v.ignore_client_bandwidth),
            ];
            v.encode().map_err(|error| error.to_string())
        }
        Control::Probe => {
            let v = UdpProbeAck::decode(input).ok()?;
            view.bytes.extend_from_slice(&v.offer_id);
            view.numbers = vec![
                match v.status {
                    UdpProbeStatus::Verified => 0,
                    UdpProbeStatus::Unreachable => 1,
                    UdpProbeStatus::Failed => 2,
                },
                u64::from(v.rtt_micros),
            ];
            Ok(v.encode())
        }
        Control::Request => {
            let v = UdpRequest::decode(input).ok()?;
            view.numbers.push(u64::from(v.version));
            Ok(v.encode())
        }
        Control::Decline => {
            let v = UdpDecline::decode(input).ok()?;
            view.numbers.push(u64::from(v.reason));
            Ok(v.encode())
        }
    };
    Some((view, encoded))
}

fn assert_control_matches(
    kind: Control,
    expected: Option<View>,
    actual: Option<(View, Result<Vec<u8>, String>)>,
    canonical: &[u8],
) -> bool {
    // Compare the decoder result before inspecting the encoder result. An
    // invalid false accept must fail even when re-encoding it returns Err.
    assert_eq!(
        actual.as_ref().map(|(view, _)| view),
        expected.as_ref(),
        "{kind:?} decoder acceptance/fields"
    );
    if let Some((_, encoded)) = actual {
        assert_eq!(
            encoded.expect("an accepted control message must be encodable"),
            canonical,
            "{kind:?} encoder bytes"
        );
        true
    } else {
        false
    }
}

#[test]
fn differential_helper_catches_false_accept_even_when_encoder_rejects() {
    let invalid = b"PX1T";
    let expected = spec_control(Control::Speed, invalid);
    assert!(expected.is_none());
    let false_accept = Some((
        View {
            bytes: Vec::new(),
            numbers: vec![0, 1, 1, 1],
        },
        Err("simulated encoder rejection".to_owned()),
    ));
    let failure = std::panic::catch_unwind(|| {
        assert_control_matches(Control::Speed, expected, false_accept, invalid);
    })
    .expect_err("the differential helper must detect decoder false acceptance");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .unwrap();
    assert!(
        message.contains("decoder acceptance/fields"),
        "the decoder comparison must fail before re-encoding is checked"
    );
}

fn corpus(seed: &[u8], mut visit: impl FnMut(&[u8])) {
    visit(seed);
    for end in 0..seed.len() {
        visit(&seed[..end]);
    }
    for at in 0..seed.len() {
        for bit in 0..8 {
            let mut changed = seed.to_vec();
            changed[at] ^= 1 << bit;
            visit(&changed);
        }
    }
    let mut extra = seed.to_vec();
    extra.push(0);
    visit(&extra);
}

#[test]
fn remaining_control_codecs_match_independent_wire_oracle() {
    let mut seeds = Vec::new();
    for (kind, magic, start, size) in [
        (Control::Rekey, b"PX1Q", 40, 1568u32),
        (Control::Exchange, b"PX1K", 40, 1568),
        (Control::Identity, b"PX1S", 8, 4627),
    ] {
        let mut wire = magic.to_vec();
        if start == 40 {
            wire.extend_from_slice(&[0x52; 32]);
        }
        wire.extend_from_slice(&size.to_be_bytes());
        wire.resize(start + size as usize, 0xa5);
        if matches!(kind, Control::Exchange) {
            wire.push(1);
        }
        seeds.push((kind, wire));
    }
    let mut speed = b"PX1T".to_vec();
    for n in [1u64, 256, u64::MAX] {
        speed.extend_from_slice(&n.to_be_bytes());
    }
    speed.extend_from_slice(&257u16.to_be_bytes());
    seeds.push((Control::Speed, speed));
    for magic in [b"PX1W", b"PX1V", b"PX1D", b"PX1U"] {
        let mut wire = magic.to_vec();
        wire.extend_from_slice(&u64::MAX.to_be_bytes());
        seeds.push((Control::Ack, wire));
    }
    let mut offer = b"PX1O".to_vec();
    offer.extend_from_slice(&[0x53; 16]);
    offer.extend_from_slice(&443u16.to_be_bytes());
    offer.extend_from_slice(&u64::MAX.to_be_bytes());
    offer.extend_from_slice(&[0, 2, 1]);
    seeds.push((Control::Offer, offer));
    for status in 0..=2 {
        let mut wire = b"PX1P".to_vec();
        wire.extend_from_slice(&[0x53; 16]);
        wire.push(status);
        wire.extend_from_slice(&257u32.to_be_bytes());
        seeds.push((Control::Probe, wire));
    }
    seeds.push((Control::Request, b"PX1G\x01".to_vec()));
    seeds.push((Control::Decline, b"PX1N\x00".to_vec()));
    for (kind, seed) in seeds {
        let (mut accepted, mut rejected) = (0, 0);
        corpus(&seed, |input| {
            let expected = spec_control(kind, input);
            let actual = production_control(kind, input);
            let mut canonical = input.to_vec();
            if matches!(kind, Control::Offer) && canonical.len() == 33 {
                canonical[32] = u8::from(canonical[32] != 0);
            }
            if assert_control_matches(kind, expected, actual, &canonical) {
                accepted += 1;
            } else {
                rejected += 1;
            }
        });
        assert!(
            accepted > 0 && rejected > 0,
            "{kind:?} corpus must exercise both outcomes"
        );
    }
}

#[test]
fn tls_record_header_acceptance_matches_length_oracle() {
    // Sweep every wire length and every possible content type. parse_exact
    // intentionally consumes one prefix record even if more bytes follow.
    for length in 0..=u16::MAX {
        let input = [0x17, 3, 3, (length >> 8) as u8, length as u8];
        let actual = record::parse_header(&input).ok();
        assert_eq!(actual.is_some(), length <= 16640);
        if let Some(header) = actual {
            assert_eq!(header.payload_len, usize::from(length));
            assert_eq!(header.total_len, 5 + usize::from(length));
        }
    }
    for content_type in 0..=255 {
        for length in [0u16, 1, 16384, 16401, 16640, 16641] {
            let mut wire = vec![content_type, 3, 3, (length >> 8) as u8, length as u8];
            wire.resize(5 + usize::from(length), 0x6a);
            for available in [0, 4, 5, wire.len() - 1, wire.len()] {
                let actual = record::parse_exact(&wire[..available]).ok();
                assert_eq!(
                    actual.is_some(),
                    length <= 16640 && available >= 5 + usize::from(length)
                );
                if let Some((header, payload)) = actual {
                    assert_eq!(header.content_type, content_type);
                    assert_eq!(payload, &wire[5..]);
                }
            }
        }
    }
}
