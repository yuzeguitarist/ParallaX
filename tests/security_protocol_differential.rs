//! Independent wire oracles for SPEC.md sections 4, 5.5, 5.8, 6.1 and 6.5.
//! Reference parsers use the documented offsets and literal wire constants;
//! they do not call production parsing, length, framing, or nonce helpers.
//! RustCrypto supplies a different AEAD implementation from production aws-lc.
//! This is bounded conformance evidence, not an independent full TLS/QUIC stack.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use parallax::crypto::parallel::CryptoPool;
use parallax::crypto::session::{AeadCodec, CipherSuite};
use parallax::protocol::command::{
    ConnectRequest, FramedChunk, MuxFrame, MuxFrameKind, ServerIdentityChunk,
};
use parallax::protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD, SERVER_TO_CLIENT_AAD};
use parallax::traffic::PaddingProfile;
use rand::{rngs::StdRng, Rng, SeedableRng};

const CORPUS_SEED: u64 = 0x5058_315f_5350_4543;
// Keep the oracle's labels literal: a production-label change must disagree.
const DIRECTIONS: [(&[u8], &[u8]); 2] = [
    (CLIENT_TO_SERVER_AAD, b"ParallaX v1 client appdata"),
    (SERVER_TO_CLIENT_AAD, b"ParallaX v1 server appdata"),
];

fn uint(input: &[u8], at: usize, width: usize) -> Option<u64> {
    Some(
        input
            .get(at..at.checked_add(width)?)?
            .iter()
            .fold(0, |n, b| n * 256 + u64::from(*b)),
    )
}

#[derive(Debug, PartialEq, Eq)]
struct ConnectView<'a> {
    host: &'a str,
    port: u16,
    payload: &'a [u8],
}

fn spec_connect(input: &[u8]) -> Option<ConnectView<'_>> {
    input.strip_prefix(b"PX1C")?;
    let host_len = usize::try_from(uint(input, 4, 2)?).ok()?;
    if !(1..=255).contains(&host_len) {
        return None;
    }
    let host = std::str::from_utf8(input.get(6..6 + host_len)?).ok()?;
    let port = uint(input, 6 + host_len, 2)? as u16;
    let payload_len = usize::try_from(uint(input, 8 + host_len, 4)?).ok()?;
    let payload = input.get(12 + host_len..)?;
    (port != 0 && payload.len() == payload_len).then_some(ConnectView {
        host,
        port,
        payload,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct MuxView<'a> {
    stream: u32,
    kind: u8,
    payload: &'a [u8],
}

fn spec_mux(input: &[u8]) -> Option<(MuxView<'_>, usize)> {
    input.strip_prefix(b"PX1M")?;
    let stream = uint(input, 4, 4)? as u32;
    let kind = *input.get(8)?;
    if !(1..=5).contains(&kind) || (kind == 5) != (stream == 0) {
        return None;
    }
    let size = usize::try_from(uint(input, 9, 4)?).ok()?;
    let consumed = 13usize.checked_add(size)?;
    Some((
        MuxView {
            stream,
            kind,
            payload: input.get(13..consumed)?,
        },
        consumed,
    ))
}

#[derive(Debug, PartialEq, Eq)]
struct ChunkView<'a> {
    total: u32,
    offset: u32,
    bytes: &'a [u8],
}

fn spec_chunk<'a>(input: &'a [u8], magic: &[u8; 4]) -> Option<ChunkView<'a>> {
    input.strip_prefix(magic)?;
    let total = uint(input, 4, 4)?;
    let offset = uint(input, 8, 4)?;
    let size = uint(input, 12, 4)?;
    let bytes = input.get(16..)?;
    if total == 0 || size == 0 || bytes.len() as u64 != size || offset + size > total {
        return None;
    }
    Some(ChunkView {
        total: total as u32,
        offset: offset as u32,
        bytes,
    })
}

fn wire_connect(host: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = b"PX1C".to_vec();
    out.extend_from_slice(&(host.len() as u16).to_be_bytes());
    out.extend_from_slice(host);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn wire_mux(stream: u32, kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = b"PX1M".to_vec();
    out.extend_from_slice(&stream.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn wire_chunk(magic: &[u8; 4], total: u32, offset: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

// Every seed, every truncation, both high/low bit flips at every byte, a suffix,
// then 64 reproducible multi-byte mutations. No random chance of missing an
// entire field or boundary. Failure indices and this seed reproduce the corpus.
fn visit_corpus(seed: &[u8], mut visit: impl FnMut(&[u8])) {
    visit(seed);
    for end in 0..seed.len() {
        visit(&seed[..end]);
    }
    for at in 0..seed.len() {
        for mask in [1, 0x80] {
            let mut changed = seed.to_vec();
            changed[at] ^= mask;
            visit(&changed);
        }
    }
    let mut suffixed = seed.to_vec();
    suffixed.push(0xa5);
    visit(&suffixed);
    let mut rng = StdRng::seed_from_u64(CORPUS_SEED);
    for _ in 0..64 {
        let mut changed = seed.to_vec();
        if !changed.is_empty() {
            for _ in 0..3 {
                let at = rng.gen_range(0..changed.len());
                changed[at] = rng.gen();
            }
        }
        visit(&changed);
    }
}

#[derive(Default)]
struct Counts {
    accepted: usize,
    rejected: usize,
}

impl Counts {
    fn observe(&mut self, accepted: bool) -> usize {
        let index = self.accepted + self.rejected;
        if accepted {
            self.accepted += 1;
        } else {
            self.rejected += 1;
        }
        index
    }

    fn finish(&self, label: &str) {
        assert!(
            self.accepted > 10 && self.rejected > 100,
            "{label}: vacuous corpus"
        );
        eprintln!(
            "{label}: seed={CORPUS_SEED:#x}, accepted={}, rejected={}",
            self.accepted, self.rejected
        );
    }
}

#[test]
fn connect_acceptance_fields_and_encoding_match_the_spec_oracle() {
    let seeds = [
        wire_connect(b"example.com", 443, b"GET /"),
        wire_connect(b"x", 1, b""),
        wire_connect("bücher.example".as_bytes(), 65535, &[0, 1, 2]),
        wire_connect(&[b'a'; 255], 443, &[0; 33]),
        wire_connect(&[b'a'; 256], 443, b""),
        wire_connect(b"", 443, b""),
        wire_connect(&[0xff], 443, b""),
        wire_connect(b"example.com", 0, b""),
    ];
    let mut counts = Counts::default();
    for seed in seeds {
        visit_corpus(&seed, |input| {
            let reference = spec_connect(input);
            let actual = ConnectRequest::decode_ref(input).ok().map(|v| ConnectView {
                host: v.host,
                port: v.port,
                payload: v.initial_payload,
            });
            let index = counts.observe(reference.is_some());
            assert_eq!(
                actual, reference,
                "CONNECT case={index}, seed={CORPUS_SEED:#x}"
            );
            if let Some(expected) = reference {
                let owned = ConnectRequest::decode(input).unwrap();
                assert_eq!(owned.host, expected.host);
                assert_eq!(owned.port, expected.port);
                assert_eq!(owned.initial_payload, expected.payload);
                assert_eq!(
                    owned.encode().unwrap(),
                    input,
                    "CONNECT encoder case={index}"
                );
            }
        });
    }
    counts.finish("CONNECT");
}

fn kind_byte(kind: MuxFrameKind) -> u8 {
    match kind {
        MuxFrameKind::Open => 1,
        MuxFrameKind::Data => 2,
        MuxFrameKind::Fin => 3,
        MuxFrameKind::Reset => 4,
        MuxFrameKind::Cover => 5,
    }
}

#[test]
fn mux_acceptance_fields_and_prefix_consumption_match_the_spec_oracle() {
    let mut counts = Counts::default();
    for kind in 0..=6 {
        for stream in [0, 1, u32::MAX] {
            let seed = wire_mux(stream, kind, b"payload");
            visit_corpus(&seed, |input| {
                let reference = spec_mux(input);
                let actual = MuxFrame::decode_ref_prefix(input).ok().map(|(v, used)| {
                    (
                        MuxView {
                            stream: v.stream_id,
                            kind: kind_byte(v.kind),
                            payload: v.payload,
                        },
                        used,
                    )
                });
                let index = counts.observe(reference.is_some());
                assert_eq!(
                    actual, reference,
                    "MUX prefix case={index}, seed={CORPUS_SEED:#x}"
                );
                let exact = reference
                    .as_ref()
                    .is_some_and(|(_, used)| *used == input.len());
                assert_eq!(
                    MuxFrame::decode(input).is_ok(),
                    exact,
                    "MUX exact case={index}"
                );
                if let Some((expected, used)) = reference {
                    let (owned, consumed) = MuxFrame::decode_prefix(input).unwrap();
                    assert_eq!(consumed, used);
                    assert_eq!(owned.stream_id, expected.stream);
                    assert_eq!(kind_byte(owned.kind), expected.kind);
                    assert_eq!(owned.payload, expected.payload);
                    assert_eq!(owned.encode().unwrap(), input[..used]);
                }
            });
        }
    }
    // A valid next frame is not a malformed suffix for prefix/all decoding.
    let joined = [
        wire_mux(1, 2, b"a"),
        wire_mux(1, 3, b""),
        wire_mux(0, 5, b"cover"),
    ]
    .concat();
    let frames = MuxFrame::decode_all(&joined).unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].payload, b"a");
    assert_eq!(frames[1].kind, MuxFrameKind::Fin);
    assert_eq!(frames[2].payload, b"cover");
    assert!(MuxFrame::decode(&joined).is_err());
    counts.finish("MUX");
}

#[test]
fn chunk_acceptance_fields_and_ranges_match_the_spec_oracle() {
    let mut counts = Counts::default();
    for magic in [b"PX1F", b"PX1I"] {
        for (total, offset, bytes) in [
            (6, 0, b"abc".as_slice()),
            (6, 3, b"def".as_slice()),
            (1, 0, b"x".as_slice()),
            (0, 0, b"x".as_slice()),
            (u32::MAX, u32::MAX, b"x".as_slice()),
            (6, 0, b"".as_slice()),
        ] {
            let seed = wire_chunk(magic, total, offset, bytes);
            visit_corpus(&seed, |input| {
                let reference = spec_chunk(input, magic);
                let actual = if magic == b"PX1F" {
                    FramedChunk::decode_ref(input).ok().map(|v| ChunkView {
                        total: v.total_len,
                        offset: v.offset,
                        bytes: v.bytes,
                    })
                } else {
                    ServerIdentityChunk::decode_ref(input)
                        .ok()
                        .map(|v| ChunkView {
                            total: v.total_len,
                            offset: v.offset,
                            bytes: v.bytes,
                        })
                };
                let index = counts.observe(reference.is_some());
                assert_eq!(
                    actual, reference,
                    "chunk case={index}, seed={CORPUS_SEED:#x}"
                );
                if magic == b"PX1I" && reference.is_some() {
                    assert_eq!(
                        ServerIdentityChunk::decode(input)
                            .unwrap()
                            .encode()
                            .unwrap(),
                        input
                    );
                }
            });
        }
    }
    counts.finish("PX1F/PX1I");
}

#[test]
fn oracle_controls_detect_false_accept_false_reject_and_wrong_field() {
    // Independent literal vector, not output from either encoder under test.
    let good = b"PX1C\x00\x01x\x01\xbb\x00\x00\x00\x01!";
    let mut bad = good.to_vec();
    bad.push(0);
    let expected = ConnectView {
        host: "x",
        port: 443,
        payload: b"!",
    };
    assert_eq!(spec_connect(good), Some(expected));
    assert!(spec_connect(&bad).is_none());
    // A decoder that always rejects, always accepts, or misreads the BE port
    // would disagree with this same reference-comparison predicate.
    assert_ne!(spec_connect(good), None);
    assert_ne!(spec_connect(&bad), spec_connect(good));
    assert_ne!(
        spec_connect(good),
        Some(ConnectView {
            host: "x",
            port: 0xbb01,
            payload: b"!"
        })
    );
    assert_eq!(
        spec_mux(b"PX1M\x00\x00\x00\x01\x02\x00\x00\x00\x01!")
            .unwrap()
            .1,
        14
    );
    assert!(spec_chunk(
        b"PX1F\x00\x00\x00\x01\xff\xff\xff\xff\x00\x00\x00\x01!",
        b"PX1F"
    )
    .is_none());
}

// Integer XOR, deliberately independent from production's byte-wise zip.
fn spec_nonce(base: [u8; 12], sequence: u64) -> [u8; 12] {
    let mut wide = [0; 16];
    wide[4..].copy_from_slice(&base);
    let value = (u128::from_be_bytes(wide) ^ u128::from(sequence)).to_be_bytes();
    value[4..].try_into().unwrap()
}

fn oracle_encrypt(
    suite: CipherSuite,
    key: [u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    bytes: &[u8],
) -> Vec<u8> {
    let payload = Payload { msg: bytes, aad };
    match suite {
        CipherSuite::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(aes_gcm::Nonce::from_slice(&nonce), payload)
            .unwrap(),
        CipherSuite::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), payload)
            .unwrap(),
    }
}

fn oracle_decrypt(
    suite: CipherSuite,
    key: [u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    bytes: &[u8],
) -> Option<Vec<u8>> {
    let payload = Payload { msg: bytes, aad };
    match suite {
        CipherSuite::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(aes_gcm::Nonce::from_slice(&nonce), payload)
            .ok(),
        CipherSuite::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), payload)
            .ok(),
    }
}

fn oracle_record(
    suite: CipherSuite,
    key: [u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    payload: &[u8],
    padding: u16,
) -> Vec<u8> {
    let mut padded = payload.to_vec();
    padded.resize(padded.len() + padding as usize, 0xa5);
    padded.extend_from_slice(&padding.to_be_bytes());
    let encrypted = oracle_encrypt(suite, key, nonce, aad, &padded);
    let mut wire = vec![0x17, 3, 3];
    wire.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
    wire.extend_from_slice(&encrypted);
    wire
}

fn codec(
    suite: CipherSuite,
    key: [u8; 32],
    nonce: [u8; 12],
    padding: u16,
    aad: &'static [u8],
) -> DataRecordCodec {
    DataRecordCodec::new(
        AeadCodec::new_with_suite(suite, key, nonce),
        PaddingProfile::new(padding, padding).unwrap(),
        aad,
    )
}

#[test]
fn framed_aead_matches_independent_backend_in_both_directions_across_counter_carry_and_rekey() {
    let key = [0x73; 32];
    let base = [0x95; 12];
    let mut checked = 0;
    for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        for (aad, reference_aad) in DIRECTIONS {
            for padding in [0, 1, 16, 127] {
                let mut sender = codec(suite, key, base, padding, aad);
                let mut receiver = codec(suite, key, base, padding, aad);
                let mut rng = StdRng::seed_from_u64(CORPUS_SEED);
                // 260 records explicitly cross the 255 -> 256 nonce-byte carry.
                for seq in 0..260 {
                    let len = [0, 1, 15, 16, 17, 255, 1024, 4096, 15700][seq as usize % 9];
                    let payload: Vec<u8> = (0..len)
                        .map(|i| (i as u8).wrapping_add(seq as u8))
                        .collect();
                    let nonce = spec_nonce(base, seq);
                    let wire = sender.seal(&payload, &mut rng).unwrap();
                    assert_eq!(&wire[..3], &[0x17, 3, 3]);
                    assert_eq!(uint(&wire, 3, 2).unwrap() as usize, wire.len() - 5);
                    assert!(wire.len() - 5 <= 16401);
                    let decoded =
                        oracle_decrypt(suite, key, nonce, reference_aad, &wire[5..]).unwrap();
                    assert_eq!(decoded.len(), payload.len() + padding as usize + 2);
                    assert_eq!(&decoded[..payload.len()], payload);
                    assert_eq!(&decoded[decoded.len() - 2..], padding.to_be_bytes());
                    let reference =
                        oracle_record(suite, key, nonce, reference_aad, &payload, padding);
                    if padding == 0 {
                        assert_eq!(wire, reference);
                    }
                    assert_eq!(receiver.open(&reference).unwrap(), payload);
                    checked += 1;
                }
                let next_suite = if suite == CipherSuite::Aes256Gcm {
                    CipherSuite::ChaCha20Poly1305
                } else {
                    CipherSuite::Aes256Gcm
                };
                sender.rekey_with_suite(next_suite, [0xb1; 32], [0xc3; 12]);
                receiver.rekey_with_suite(next_suite, [0xb1; 32], [0xc3; 12]);
                let wire = sender.seal(b"rekey resets sequence", &mut rng).unwrap();
                let decoded = oracle_decrypt(
                    next_suite,
                    [0xb1; 32],
                    spec_nonce([0xc3; 12], 0),
                    reference_aad,
                    &wire[5..],
                )
                .unwrap();
                assert_eq!(&decoded[..21], b"rekey resets sequence");
                assert!(oracle_decrypt(
                    suite,
                    key,
                    spec_nonce(base, 260),
                    reference_aad,
                    &wire[5..]
                )
                .is_none());
                let reference = oracle_record(
                    next_suite,
                    [0xb1; 32],
                    spec_nonce([0xc3; 12], 0),
                    reference_aad,
                    b"rekey resets sequence",
                    padding,
                );
                assert_eq!(receiver.open(&reference).unwrap(), b"rekey resets sequence");
            }
        }
    }
    assert_eq!(checked, 4160);
}

#[test]
fn serial_and_parallel_record_paths_match_the_independent_batch_oracle() {
    let pool = CryptoPool::new(3);
    for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        for (aad, reference_aad) in DIRECTIONS {
            let key = [0x81; 32];
            let base = [0x2a; 12];
            let mut payload = Vec::new();
            let mut lens = Vec::new();
            let mut expected_wire = Vec::new();
            for seq in 0..260 {
                let len = [0, 1, 17, 16383][seq as usize % 4];
                let bytes = vec![(seq as u8).wrapping_mul(29); len];
                expected_wire.extend_from_slice(&oracle_record(
                    suite,
                    key,
                    spec_nonce(base, seq),
                    reference_aad,
                    &bytes,
                    0,
                ));
                payload.extend_from_slice(&bytes);
                lens.push(len);
            }
            let mut rng = StdRng::seed_from_u64(CORPUS_SEED);
            let mut serial = codec(suite, key, base, 0, aad);
            let mut parallel = codec(suite, key, base, 0, aad);
            let mut a = Vec::new();
            let mut b = Vec::new();
            serial
                .seal_records_into(&payload, &lens, &mut rng, &mut a)
                .unwrap();
            parallel
                .seal_records_into_parallel(&pool, &payload, &lens, &mut rng, &mut b)
                .unwrap();
            assert_eq!(a, expected_wire);
            assert_eq!(b, expected_wire);
            let mut out = Vec::new();
            codec(suite, key, base, 0, aad)
                .open_concat_records(&mut a, &mut out)
                .unwrap();
            assert_eq!(out, payload);
            out.clear();
            codec(suite, key, base, 0, aad)
                .open_concat_records_parallel(&pool, &expected_wire, &mut out)
                .unwrap();
            assert_eq!(out, payload);
            let wrong_aad = if aad == CLIENT_TO_SERVER_AAD {
                SERVER_TO_CLIENT_AAD
            } else {
                CLIENT_TO_SERVER_AAD
            };
            let first_record_len = 5 + uint(&expected_wire, 3, 2).unwrap() as usize;
            let first_record = &expected_wire[..first_record_len];
            assert_eq!(
                codec(suite, key, base, 0, aad).open(first_record).unwrap(),
                b""
            );
            assert!(codec(suite, key, base, 0, wrong_aad)
                .open(first_record)
                .is_err());
        }
    }
}
