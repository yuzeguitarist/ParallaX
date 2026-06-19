//! Differential interop tests: the hand-rolled `crypto::mldsa` ML-DSA-87 against
//! the in-tree `pqcrypto-mldsa` (PQClean C FFI) oracle (plan §4.3, gates 5 & 6).
//!
//! The ACVP KATs (`tests/mldsa_acvp.rs`) already pin byte-exact agreement with the
//! FIPS 204 reference. These tests add the cross-implementation check the C oracle
//! *can* provide: signatures are randomized and the oracle is hedged-only (no
//! seed/`rnd` injection), so we cannot demand byte-identical signatures *from* it —
//! instead we check both directions of verification interop:
//!
//!   Gate 5 (differential accept): every signature produced by the hand-rolled
//!     `signature_ctx` (over hand-rolled keys) is accepted by the oracle's
//!     `verify_detached_signature_ctx`.
//!   Gate 6 (round-trip interop): every signature produced by the oracle's
//!     `detached_sign_ctx` is accepted by the hand-rolled `verify`.
//!
//! Both sides must agree on the FIPS 204 external "pure" context construction
//! (`mu = SHAKE256(tr || 0x00 || ctxlen || ctx || msg)`), so each case is run
//! across several context lengths including the empty and 255-byte boundaries.
//!
//! The keys are byte-compatible across the two implementations (proven by the
//! ACVP keyGen KAT), so a hand-rolled key's raw bytes load straight into the
//! oracle's `PublicKey` / `SecretKey` via `from_bytes`, and vice versa.
//!
//! These run by default (no sockets / no network). They exist only while
//! `pqcrypto-mldsa` is kept in-tree as the oracle (plan §6); when it is removed,
//! this file goes with it and the ACVP KATs remain the permanent gate.

use parallax::crypto::mldsa;
use parallax::crypto::mldsa::params::{
    CTILDEBYTES, K, L, OMEGA, POLYZ_PACKEDBYTES, RNDBYTES, SECRETKEYBYTES, SIGNBYTES,
};
use parallax::crypto::mldsa::sign;

use pqcrypto_mldsa::mldsa87 as oracle;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

use rand::RngCore;

/// A spread of context strings to exercise the shared FIPS 204 ctx construction,
/// including the empty context and the 255-byte upper boundary.
fn context_cases() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"ParallaX v2 ML-DSA-87 server identity".to_vec(),
        vec![0xA5u8; 255],
    ]
}

/// Deterministic-ish pseudo message of a requested length, seeded by `n` so each
/// iteration differs without pulling more OS randomness than necessary.
fn message(n: u64, len: usize) -> Vec<u8> {
    let mut m = vec![0u8; len];
    let mut x = n.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    for b in m.iter_mut() {
        // xorshift64*, just to get well-mixed, reproducible bytes.
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *b = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
    }
    m
}

/// Gate 5 — the oracle accepts hand-rolled signatures.
///
/// For several keypairs / messages / context lengths: generate a hand-rolled
/// keypair, sign with the hand-rolled `signature_ctx` (hedged, fresh `rnd`), then
/// load the public key and signature into the oracle and require its
/// `verify_detached_signature_ctx` to accept. Also flips one signature bit and
/// requires the oracle to reject, so acceptance is not vacuous.
#[test]
fn oracle_accepts_handrolled_signatures() {
    let mut rng = rand::rngs::OsRng;
    let mut iters = 0usize;
    for round in 0u64..6 {
        let (pk, sk) = mldsa::keypair();
        let oracle_pk =
            oracle::PublicKey::from_bytes(&pk).expect("hand-rolled pk loads into oracle");
        let sk_arr: [u8; SECRETKEYBYTES] = sk.as_slice().try_into().unwrap();

        for (ci, ctx) in context_cases().iter().enumerate() {
            let msg = message(round * 17 + ci as u64, 1 + ci * 96);

            let mut rnd = [0u8; RNDBYTES];
            rng.fill_bytes(&mut rnd);
            let sig = sign::signature_ctx(&sk_arr, &msg, ctx, &rnd)
                .expect("hand-rolled signing succeeds for ctx <= 255");

            let oracle_sig = oracle::DetachedSignature::from_bytes(&sig)
                .expect("hand-rolled signature loads into oracle");
            assert!(
                oracle::verify_detached_signature_ctx(&oracle_sig, &msg, ctx, &oracle_pk).is_ok(),
                "oracle rejected a valid hand-rolled signature (round {round}, ctx#{ci})"
            );

            // Tamper one bit: the oracle must reject (acceptance above is real).
            let mut bad = sig;
            bad[0] ^= 0x01;
            let oracle_bad = oracle::DetachedSignature::from_bytes(&bad)
                .expect("tampered signature still loads (length unchanged)");
            assert!(
                oracle::verify_detached_signature_ctx(&oracle_bad, &msg, ctx, &oracle_pk).is_err(),
                "oracle accepted a bit-flipped hand-rolled signature (round {round}, ctx#{ci})"
            );
            iters += 1;
        }
    }
    assert!(iters > 0);
    eprintln!("differential gate 5: oracle accepted {iters} hand-rolled signatures");
}

/// Gate 6 — the hand-rolled `verify` accepts the oracle's signatures.
///
/// For several oracle keypairs / messages / context lengths: sign with the
/// oracle's `detached_sign_ctx`, then require the hand-rolled `verify` to accept
/// the oracle's public key + signature bytes. Tampering the message must make the
/// hand-rolled `verify` reject.
#[test]
fn handrolled_verify_accepts_oracle_signatures() {
    let mut iters = 0usize;
    for round in 0u64..6 {
        let (oracle_pk, oracle_sk) = oracle::keypair();
        let pk_bytes = oracle_pk.as_bytes();

        for (ci, ctx) in context_cases().iter().enumerate() {
            let msg = message(1000 + round * 17 + ci as u64, 1 + ci * 64);

            let sig = oracle::detached_sign_ctx(&msg, ctx, &oracle_sk);
            let sig_bytes = sig.as_bytes();

            mldsa::verify(pk_bytes, sig_bytes, &msg, ctx).unwrap_or_else(|e| {
                panic!("hand-rolled verify rejected a valid oracle signature (round {round}, ctx#{ci}): {e}")
            });

            // Tamper the message: hand-rolled verify must reject.
            let mut bad_msg = msg.clone();
            bad_msg.push(0xFF);
            assert_eq!(
                mldsa::verify(pk_bytes, sig_bytes, &bad_msg, ctx),
                Err(mldsa::MlDsaError::VerificationFailed),
                "hand-rolled verify accepted an oracle signature over a tampered message \
                 (round {round}, ctx#{ci})"
            );
            iters += 1;
        }
    }
    assert!(iters > 0);
    eprintln!("differential gate 6: hand-rolled verify accepted {iters} oracle signatures");
}

/// Full cross round-trip: a hand-rolled keypair signs with the hand-rolled signer,
/// and the *same key bytes* loaded into the oracle verify; and the oracle signs
/// with that key and the hand-rolled `verify` accepts. This exercises both signers
/// and both verifiers against a single shared key, confirming the key encodings,
/// the `tr = H(pk)` binding, and the ctx construction line up end-to-end.
#[test]
fn shared_key_cross_sign_and_verify() {
    let mut rng = rand::rngs::OsRng;
    let (pk, sk) = mldsa::keypair();
    let sk_arr: [u8; SECRETKEYBYTES] = sk.as_slice().try_into().unwrap();
    let oracle_pk = oracle::PublicKey::from_bytes(&pk).expect("pk into oracle");
    let oracle_sk = oracle::SecretKey::from_bytes(&sk).expect("sk into oracle");

    let ctx = b"shared-key cross check";
    let msg = b"ML-DSA-87 differential shared-key message";

    // Hand-rolled sign -> oracle verify.
    let mut rnd = [0u8; RNDBYTES];
    rng.fill_bytes(&mut rnd);
    let hr_sig = sign::signature_ctx(&sk_arr, msg, ctx, &rnd).expect("hand-rolled sign");
    let hr_sig_oracle =
        oracle::DetachedSignature::from_bytes(&hr_sig).expect("hand-rolled sig into oracle");
    assert!(
        oracle::verify_detached_signature_ctx(&hr_sig_oracle, msg, ctx, &oracle_pk).is_ok(),
        "oracle rejected hand-rolled signature under shared key"
    );

    // Oracle sign -> hand-rolled verify (same shared key).
    let oracle_sig = oracle::detached_sign_ctx(msg, ctx, &oracle_sk);
    mldsa::verify(&pk, oracle_sig.as_bytes(), msg, ctx)
        .expect("hand-rolled verify rejected oracle signature under shared key");
}

/// Production-path differential: drive the *high-level hedged* `mldsa::sign`
/// (the exact entry `crypto::identity` calls — fresh OS `rnd`, byte-slice in/out),
/// not the lower-level `signature_ctx` seam, and require the pqcrypto oracle to
/// accept every signature. This guards the production signer end-to-end (key bytes
/// -> hedged sign -> oracle verify), so a regression in the public surface — not
/// just the deterministic core — is caught. Tampering one bit must make the oracle
/// reject, so acceptance is never vacuous.
#[test]
fn oracle_accepts_handrolled_hedged_sign() {
    let mut iters = 0usize;
    for round in 0u64..6 {
        let (pk, sk) = mldsa::keypair();
        let oracle_pk =
            oracle::PublicKey::from_bytes(&pk).expect("hand-rolled pk loads into oracle");

        for (ci, ctx) in context_cases().iter().enumerate() {
            let msg = message(round * 23 + ci as u64, 1 + ci * 80);

            // Production hedged sign: takes byte slices, draws its own `rnd`.
            let sig = mldsa::sign(&sk, &msg, ctx)
                .expect("hand-rolled hedged sign succeeds for ctx <= 255");
            assert_eq!(sig.len(), mldsa::SIG_BYTES);

            let oracle_sig = oracle::DetachedSignature::from_bytes(&sig)
                .expect("hand-rolled hedged signature loads into oracle");
            assert!(
                oracle::verify_detached_signature_ctx(&oracle_sig, &msg, ctx, &oracle_pk).is_ok(),
                "oracle rejected a valid hand-rolled hedged signature (round {round}, ctx#{ci})"
            );

            // Tamper one bit: the oracle must reject.
            let mut bad = sig;
            bad[0] ^= 0x01;
            let oracle_bad = oracle::DetachedSignature::from_bytes(&bad)
                .expect("tampered signature still loads (length unchanged)");
            assert!(
                oracle::verify_detached_signature_ctx(&oracle_bad, &msg, ctx, &oracle_pk).is_err(),
                "oracle accepted a bit-flipped hand-rolled hedged signature (round {round}, ctx#{ci})"
            );
            iters += 1;
        }
    }
    assert!(iters > 0);
    eprintln!("differential production-path: oracle accepted {iters} hedged signatures");
}

/// Hint-region tamper: flipping a byte inside the run-length-encoded hint region
/// of a valid hand-rolled signature must be rejected by BOTH the hand-rolled
/// `verify` and the pqcrypto oracle. The hint encoding is the SUF-CMA-critical
/// part of the signature (its decode rejections are what stop hint-forgery), so a
/// regression that accepted a malformed hint would be a forgery hole the
/// happy-path interop tests above would miss.
///
/// The hint region is the trailing `OMEGA + K` bytes: `OMEGA` index bytes then
/// `K` running-count bytes. We sweep one bit-flip across both sub-regions (an
/// index byte and a count byte) so the malformation is exercised on each.
#[test]
fn hint_region_tamper_rejected_by_both() {
    // Offset of the hint region inside the packed signature (matches packing.rs).
    const HINT_OFF: usize = CTILDEBYTES + L * POLYZ_PACKEDBYTES;
    assert_eq!(HINT_OFF + OMEGA + K, SIGNBYTES, "hint region layout");

    let mut rng = rand::rngs::OsRng;
    let (pk, sk) = mldsa::keypair();
    let oracle_pk = oracle::PublicKey::from_bytes(&pk).expect("hand-rolled pk loads into oracle");
    let sk_arr: [u8; SECRETKEYBYTES] = sk.as_slice().try_into().unwrap();

    let ctx: &[u8] = b"ParallaX v2 ML-DSA-87 hint tamper";

    // A few signatures so the hint weight varies (different runs / count bytes).
    let mut checked = 0usize;
    for round in 0u64..6 {
        let msg = message(7000 + round, 1 + (round as usize) * 48);
        let mut rnd = [0u8; RNDBYTES];
        rng.fill_bytes(&mut rnd);
        let sig = sign::signature_ctx(&sk_arr, &msg, ctx, &rnd).expect("hand-rolled sign");

        // Sanity: the pristine signature is accepted by both, so any rejection
        // below is caused by the tamper, not a pre-existing failure.
        mldsa::verify(&pk, &sig, &msg, ctx).expect("pristine sig verifies (hand-rolled)");
        let oracle_ok =
            oracle::DetachedSignature::from_bytes(&sig).expect("pristine sig loads into oracle");
        assert!(
            oracle::verify_detached_signature_ctx(&oracle_ok, &msg, ctx, &oracle_pk).is_ok(),
            "pristine sig verifies (oracle)"
        );

        // Tamper one byte in the index sub-region and one in the count sub-region.
        // The last K bytes are the per-poly running counts (always meaningful for
        // a valid signature); the first OMEGA bytes are the index list.
        for &pos in &[HINT_OFF, HINT_OFF + OMEGA + K - 1] {
            let mut bad = sig;
            bad[pos] ^= 0x01;
            if bad == sig {
                continue; // (cannot happen for XOR 0x01, but stay defensive)
            }

            // Hand-rolled verify must reject the tampered hint.
            assert_eq!(
                mldsa::verify(&pk, &bad, &msg, ctx),
                Err(mldsa::MlDsaError::VerificationFailed),
                "hand-rolled verify accepted a hint-region tamper at byte {pos} (round {round})"
            );

            // The oracle must reject it too (length unchanged, so it still loads).
            let oracle_bad = oracle::DetachedSignature::from_bytes(&bad)
                .expect("tampered signature still loads (length unchanged)");
            assert!(
                oracle::verify_detached_signature_ctx(&oracle_bad, &msg, ctx, &oracle_pk).is_err(),
                "oracle accepted a hint-region tamper at byte {pos} (round {round})"
            );
            checked += 1;
        }
    }
    assert!(checked > 0);
    eprintln!("differential hint-tamper: {checked} hint-region flips rejected by both");
}
