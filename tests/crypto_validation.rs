//! Fixed-answer and rejection checks through the shipping crypto entry points.
//! These are implementation tests, not CAVP/CMVP certification or an entropy
//! assessment. Published primitive vectors and protocol-specific frozen answers
//! are identified separately below.

use std::collections::BTreeSet;

use parallax::crypto::session::{AeadCodec, CipherSuite, SessionError};
use parallax::crypto::{auth, pq, session};
use parallax::transport::udp::auth::derive_udp_auth_token;

fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

#[test]
fn rfc7748_x25519_public_and_shared_known_answers() {
    // RFC 7748 section 6.1, not a local round-trip-generated oracle:
    // https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
    let alice = array("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob = array("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let alice_public = array("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_public = array("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = array("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(session::x25519_public_from_private(&alice), alice_public);
    assert_eq!(session::x25519_public_from_private(&bob), bob_public);
    assert_eq!(session::x25519_shared_secret(&alice, &bob_public), shared);
    assert_eq!(session::x25519_shared_secret(&bob, &alice_public), shared);
}

struct AeadVector {
    suite: CipherSuite,
    key: [u8; 32],
    nonce: [u8; 12],
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn chacha_vector() -> AeadVector {
    // RFC 8439 section 2.8.2. The 96-bit nonce is the fixed-common
    // part 07000000 followed by the published 64-bit IV.
    // https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2
    AeadVector {
        suite: CipherSuite::ChaCha20Poly1305,
        key: array("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        nonce: array("070000004041424344454647"),
        aad: bytes("50515253c0c1c2c3c4c5c6c7"),
        plaintext: bytes(concat!(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c61737320",
            "6f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c7920",
            "6f6e652074697020666f7220746865206675747572652c2073756e73637265656e20",
            "776f756c642062652069742e"
        )),
        ciphertext: bytes(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691"
        )),
    }
}

fn aes_vector(plaintext: bool, aad: bool) -> AeadVector {
    // NIST GCM-AES256 Examples 1--4, 128-bit tags and 96-bit IV:
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
    let mut ciphertext = if plaintext {
        bytes(concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
        ))
    } else {
        Vec::new()
    };
    ciphertext.extend(bytes(match (plaintext, aad) {
        (false, false) => "fd2caa16a5832e76aa132c1453eeda7e",
        (true, false) => "b094dac5d93471bdec1a502270e3cc6c",
        (false, true) => "de34b6dcd4cee2fdbec3cea01af1ee44",
        (true, true) => "c06d76f31930fef37acae23ed465ae62",
    }));
    AeadVector {
        suite: CipherSuite::Aes256Gcm,
        key: array(concat!(
            "feffe9928665731c6d6a8f9467308308",
            "feffe9928665731c6d6a8f9467308308"
        )),
        nonce: array("cafebabefacedbaddecaf888"),
        aad: if aad {
            bytes(concat!(
                "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf",
                "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
            ))
        } else {
            Vec::new()
        },
        plaintext: if plaintext {
            bytes(concat!(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
                "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
            ))
        } else {
            Vec::new()
        },
        ciphertext,
    }
}

fn check_aead_answer(vector: AeadVector) {
    // Sequence zero must use the provided nonce unchanged. Sealing and opening
    // are checked against published bytes, not against each other's output.
    let mut sealer = AeadCodec::new_with_suite(vector.suite, vector.key, vector.nonce);
    assert_eq!(
        sealer.seal(&vector.plaintext, &vector.aad).unwrap(),
        vector.ciphertext
    );
    let mut opener = AeadCodec::new_with_suite(vector.suite, vector.key, vector.nonce);
    assert_eq!(
        opener.open(&vector.ciphertext, &vector.aad).unwrap(),
        vector.plaintext
    );
}

#[test]
fn rfc8439_chacha20poly1305_known_answer_through_production_codec() {
    check_aead_answer(chacha_vector());
}

#[test]
fn nist_aes256gcm_known_answers_through_production_codec() {
    for plaintext in [false, true] {
        for aad in [false, true] {
            check_aead_answer(aes_vector(plaintext, aad));
        }
    }
}

#[test]
fn published_aead_vectors_reject_every_bit_change_and_truncation_without_output() {
    for vector in [chacha_vector(), aes_vector(true, true)] {
        for index in 0..vector.ciphertext.len() {
            for bit in 0..8 {
                let mut changed = vector.ciphertext.clone();
                changed[index] ^= 1 << bit;
                let mut opener = AeadCodec::new_with_suite(vector.suite, vector.key, vector.nonce);
                assert!(matches!(
                    opener.open(&changed, &vector.aad),
                    Err(SessionError::Aead)
                ));
                // A failed primitive open must not consume the next nonce.
                assert_eq!(
                    opener.open(&vector.ciphertext, &vector.aad).unwrap(),
                    vector.plaintext
                );
            }
        }
        for end in 0..vector.ciphertext.len() {
            let mut opener = AeadCodec::new_with_suite(vector.suite, vector.key, vector.nonce);
            assert!(opener.open(&vector.ciphertext[..end], &vector.aad).is_err());
        }
        let mut longer = vector.ciphertext.clone();
        longer.push(0);
        let mut opener = AeadCodec::new_with_suite(vector.suite, vector.key, vector.nonce);
        assert!(opener.open(&longer, &vector.aad).is_err());
        // Err returns no plaintext Vec. In-place backend buffers are deliberately
        // not asserted unchanged: their contents on authentication failure are
        // unspecified, and higher-level plaintext disposal has separate tests.
    }
}

#[test]
fn published_aead_vectors_bind_every_key_nonce_and_aad_bit() {
    for vector in [chacha_vector(), aes_vector(true, true)] {
        for index in 0..vector.key.len() {
            for bit in 0..8 {
                let mut key = vector.key;
                key[index] ^= 1 << bit;
                let mut opener = AeadCodec::new_with_suite(vector.suite, key, vector.nonce);
                assert!(opener.open(&vector.ciphertext, &vector.aad).is_err());
            }
        }
        for index in 0..vector.nonce.len() {
            for bit in 0..8 {
                let mut nonce = vector.nonce;
                nonce[index] ^= 1 << bit;
                let mut opener = AeadCodec::new_with_suite(vector.suite, vector.key, nonce);
                assert!(opener.open(&vector.ciphertext, &vector.aad).is_err());
            }
        }
        for index in 0..vector.aad.len() {
            for bit in 0..8 {
                let mut aad = vector.aad.clone();
                aad[index] ^= 1 << bit;
                let mut opener = AeadCodec::new_with_suite(vector.suite, vector.key, vector.nonce);
                assert!(opener.open(&vector.ciphertext, &aad).is_err());
            }
        }
    }
}

#[test]
fn protocol_hkdf_and_hmac_known_answers_are_frozen_independently() {
    // These protocol-specific answers were calculated with Python stdlib
    // hashlib/hmac, following RFC 5869 Extract/Expand and SPEC's literal labels
    // and lengths. They are not the RFC's arbitrary-info Appendix A vectors:
    // production APIs intentionally fix the domain-separation info.
    // https://www.rfc-editor.org/rfc/rfc5869.html#section-2
    let psk: [u8; 32] = std::array::from_fn(|i| i as u8);
    let shared = array("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let hash = [1; 32];
    let keys = session::derive_client_keys_from_shared(&psk, &shared, &hash).unwrap();
    assert_eq!(
        keys.chain_secret,
        array("59df735524acb023e9008511d1566279408cd105dbb129ab772d25e133bcf512")
    );
    assert_eq!(
        keys.client_key,
        array("9af43a06ca4330a83ab86023adc5c380064f13ad447b2023b3b4858a344659a0")
    );
    assert_eq!(
        keys.server_key,
        array("4115614da87e6ab74458f0e85b41c5ca1037e3e20429b5cdfb451fe0b67824d8")
    );
    assert_eq!(keys.client_nonce, array("f098eb57a2f91c0d636e775e"));
    assert_eq!(keys.server_nonce, array("7a7ee875ca68290438809d3a"));
    let auth_key = auth::derive_client_auth_key_from_shared(&psk, &shared).unwrap();
    assert_eq!(
        *auth_key,
        array("51b7cd5b7ef1d25e23a862691bf305baf14f66937208796bf3bf0d0f4b01950a")
    );
    assert_eq!(
        *derive_udp_auth_token(&shared, &psk).unwrap(),
        array("a9097041b03b9ff52575487d4e90018781f40805431940a7ad3c9f85d0e5a205")
    );
    let public = array("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let tail = std::array::from_fn(|i| (i + 1) as u8);
    let random = std::array::from_fn(|i| (i + 32) as u8);
    assert_eq!(
        auth::build_masked_stateful_client_random(&psk, &[0x51; 32], "sni.example", &public, &tail)
            .unwrap(),
        array("a641c6031de672ca406046faaf20e2326febf00cc0922085b421d9bd42c3b210")
    );
    assert_eq!(
        auth::build_masked_stateful_auth_session_id(
            &psk,
            &[0x51; 32],
            &*auth_key,
            "sni.example",
            &public,
            &random,
            &tail
        )
        .unwrap(),
        array("2f86a93f2341c3f799f72504e5656d44ad95a8b99a7269c08bee44b8f163cc0b")
    );
}

#[test]
fn derived_keys_separate_session_direction_epoch_substream_and_hybrid_components() {
    let psk = [0x31; 32];
    let shared = [0x42; 32];
    let hash = [0x53; 32];
    let parent = session::derive_client_keys_from_shared(&psk, &shared, &hash).unwrap();
    let mut all_keys = BTreeSet::new();
    for epoch in [0, 1, 255, u64::MAX] {
        let keys = session::expand_epoch_keys(parent.chain_secret, epoch, hash, shared).unwrap();
        assert!(all_keys.insert(keys.client_key));
        assert!(all_keys.insert(keys.server_key));
        for stream in [0, 1, u32::MAX as u64, u64::MAX] {
            let sub = session::expand_substream_keys(&keys, stream).unwrap();
            assert!(all_keys.insert(sub.client_key));
            assert!(all_keys.insert(sub.server_key));
        }
    }
    for (salt, ecdh, transcript) in [
        ([0x32; 32], shared, hash),
        (psk, [0x43; 32], hash),
        (psk, shared, [0x54; 32]),
    ] {
        let keys = session::derive_client_keys_from_shared(&salt, &ecdh, &transcript).unwrap();
        assert!(all_keys.insert(keys.client_key));
        assert!(all_keys.insert(keys.server_key));
    }
    let first =
        pq::hybrid_sandwich_rekey(&parent.chain_secret, &shared, &[0x64; 32], &psk).unwrap();
    for (old, dh, kem, symmetric) in [
        ([0x75; 32], shared, [0x64; 32], psk),
        (parent.chain_secret, [0x43; 32], [0x64; 32], psk),
        (parent.chain_secret, shared, [0x65; 32], psk),
        (parent.chain_secret, shared, [0x64; 32], [0x32; 32]),
    ] {
        assert_ne!(
            pq::hybrid_sandwich_rekey(&old, &dh, &kem, &symmetric).unwrap(),
            first
        );
    }
    // Finite non-collision and dependency checks, not a cryptographic proof of
    // key independence or forward secrecy after secret disclosure.
}

#[test]
fn both_record_suites_advance_nonces_reject_replay_and_rekey_to_a_new_key() {
    for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
        let mut sealer = AeadCodec::new_with_suite(suite, [0x11; 32], [0x22; 12]);
        let first = sealer.seal(b"identical payload", b"direction").unwrap();
        let second = sealer.seal(b"identical payload", b"direction").unwrap();
        assert_ne!(first, second);
        let mut opener = AeadCodec::new_with_suite(suite, [0x11; 32], [0x22; 12]);
        assert_eq!(
            opener.open(&first, b"direction").unwrap(),
            b"identical payload"
        );
        assert!(opener.open(&first, b"direction").is_err());
        assert_eq!(
            opener.open(&second, b"direction").unwrap(),
            b"identical payload"
        );
        sealer.rekey([0x33; 32], [0x44; 12]);
        let fresh = sealer.seal(b"identical payload", b"direction").unwrap();
        assert_ne!(fresh, first);
        assert_ne!(fresh, second);
        opener.rekey([0x33; 32], [0x44; 12]);
        assert!(opener.open(&first, b"direction").is_err());
        assert_eq!(
            opener.open(&fresh, b"direction").unwrap(),
            b"identical payload"
        );
    }
}

#[test]
fn malformed_crypto_parameters_fail_before_producing_session_material() {
    let hash = [0x53; 32];
    assert!(matches!(
        session::derive_client_keys_from_shared(&[], &[0x42; 32], &hash),
        Err(SessionError::EmptyPsk)
    ));
    assert!(matches!(
        session::derive_server_keys_from_shared(&[], &[0x42; 32], &hash),
        Err(SessionError::EmptyPsk)
    ));
    assert!(matches!(
        session::derive_client_keys_from_shared(&[0x31; 32], &[0; 32], &hash),
        Err(SessionError::DegenerateSharedSecret)
    ));
    assert!(auth::derive_client_auth_key_from_shared(&[], &[0x42; 32]).is_err());
    assert!(auth::derive_client_auth_key_from_shared(&[0x31; 32], &[0; 32]).is_err());
    assert!(derive_udp_auth_token(&[0x42; 32], &[]).is_err());
    assert!(pq::hybrid_sandwich_rekey(&[0x31; 32], &[0; 32], &[0x64; 32], b"psk").is_err());
    for tag in 0..=u8::MAX {
        assert_eq!(CipherSuite::from_wire(tag).is_some(), tag <= 1);
    }
    // Fixed-size key/nonce arrays make malformed AEAD lengths unrepresentable;
    // variable-size KEM inputs still need actual runtime rejection.
    let kem = pq::keypair();
    let encapsulated = pq::encapsulate(&kem.public).unwrap();
    assert_eq!(
        *pq::decapsulate(&encapsulated.ciphertext, &kem.secret).unwrap(),
        *encapsulated.shared_secret
    );
    for length in [0, 1, pq::public_key_bytes() - 1, pq::public_key_bytes() + 1] {
        assert!(pq::encapsulate(&vec![0; length]).is_err());
    }
    for length in [0, 1, pq::secret_key_bytes() - 1, pq::secret_key_bytes() + 1] {
        assert!(pq::decapsulate(&encapsulated.ciphertext, &vec![0; length]).is_err());
    }
    for length in [0, 1, pq::ciphertext_bytes() - 1, pq::ciphertext_bytes() + 1] {
        assert!(pq::decapsulate(&vec![0; length], &kem.secret).is_err());
    }
}
