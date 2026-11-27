//! Differential interop tests: the hand-rolled `crypto::mldsa` ML-DSA-87 against
//! the AWS-LC ML-DSA-87 oracle (plan §4.3, gates 5 & 6).
//!
//! The ACVP KATs (`tests/mldsa_acvp.rs`) already pin byte-exact agreement with the
//! FIPS 204 reference. These tests exercise bidirectional verification interop
//! for randomized signatures:
//!
//!   Gate 5 (differential accept): every signature produced by the hand-rolled
//!     `signature_ctx` (over hand-rolled keys) is accepted by the oracle's
//!     FIPS 204 verifier.
//!   Gate 6 (round-trip interop): every signature produced by the oracle's
//!     FIPS 204 signer is accepted by the hand-rolled `verify`.
//!
//! Both sides must agree on the FIPS 204 external "pure" context construction
//! (`mu = SHAKE256(tr || 0x00 || ctxlen || ctx || msg)`), so each case is run
//! across several context lengths including the empty and 255-byte boundaries.
//!
//! Both implementations accept and produce the FIPS 204 raw key encodings.
//!
//! These run by default without sockets or network access.

use aws_lc_sys as aws_lc;
use parallax::crypto::mldsa;
use parallax::crypto::mldsa::params::{
    CTILDEBYTES, K, L, OMEGA, POLYZ_PACKEDBYTES, PUBLICKEYBYTES, RNDBYTES, SECRETKEYBYTES,
    SEEDBYTES, SIGNBYTES,
};
use parallax::crypto::mldsa::sign;
use rand::RngCore;
use std::ptr::{null, null_mut, NonNull};
use zeroize::Zeroizing;

// The Rust AWS-LC API supports empty-context ML-DSA. Use the message-signing
// EVP functions here to keep coverage of nonempty and maximum-length contexts.
struct OracleKey(NonNull<aws_lc::EVP_PKEY>);

impl OracleKey {
    fn generate() -> Self {
        let mut seed = Zeroizing::new([0; SEEDBYTES]);
        rand::rngs::OsRng.fill_bytes(&mut *seed);
        Self::private_key(&*seed)
    }

    fn private_key(bytes: &[u8]) -> Self {
        // SAFETY: The input is readable for its length and AWS-LC copies it.
        let key = unsafe {
            aws_lc::EVP_PKEY_pqdsa_new_raw_private_key(
                aws_lc::NID_MLDSA87,
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        Self(NonNull::new(key).expect("import AWS-LC ML-DSA-87 private key"))
    }

    fn public_key(bytes: &[u8]) -> Self {
        // SAFETY: The input is readable for its length and AWS-LC copies it.
        let key = unsafe {
            aws_lc::EVP_PKEY_pqdsa_new_raw_public_key(
                aws_lc::NID_MLDSA87,
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        Self(NonNull::new(key).expect("import AWS-LC ML-DSA-87 public key"))
    }

    fn public_key_bytes(&self) -> [u8; PUBLICKEYBYTES] {
        let mut bytes = [0; PUBLICKEYBYTES];
        let mut len = bytes.len();
        // SAFETY: The key is live and the output is writable for its stated length.
        let result = unsafe {
            aws_lc::EVP_PKEY_get_raw_public_key(self.0.as_ptr(), bytes.as_mut_ptr(), &mut len)
        };
        assert_eq!(result, 1, "export AWS-LC ML-DSA-87 public key");
        assert_eq!(len, bytes.len());
        bytes
    }

    fn sign(&self, message: &[u8], context: &[u8]) -> [u8; SIGNBYTES] {
        let ctx = DigestContext::new(self, context, true);
        let mut signature = [0; SIGNBYTES];
        let mut len = signature.len();
        // SAFETY: The initialized context is live and both buffers match their lengths.
        let result = unsafe {
            aws_lc::EVP_DigestSign(
                ctx.0.as_ptr(),
                signature.as_mut_ptr(),
                &mut len,
                message.as_ptr(),
                message.len(),
            )
        };
        assert_eq!(result, 1, "AWS-LC ML-DSA-87 signing");
        assert_eq!(len, signature.len());
        signature
    }

    fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> bool {
        let ctx = DigestContext::new(self, context, false);
        // SAFETY: The initialized context is live and both inputs match their lengths.
        let result = unsafe {
            aws_lc::EVP_DigestVerify(
                ctx.0.as_ptr(),
                signature.as_ptr(),
                signature.len(),
                message.as_ptr(),
                message.len(),
            )
        };
        result == 1
    }
}

impl Drop for OracleKey {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the key returned by AWS-LC.
        unsafe { aws_lc::EVP_PKEY_free(self.0.as_ptr()) };
    }
}

struct DigestContext(NonNull<aws_lc::EVP_MD_CTX>);

impl DigestContext {
    fn new(key: &OracleKey, context: &[u8], signing: bool) -> Self {
        // SAFETY: EVP_MD_CTX_new requires no inputs and returns an owned context.
        let raw = unsafe { aws_lc::EVP_MD_CTX_new() };
        let ctx = Self(NonNull::new(raw).expect("allocate AWS-LC message context"));
        let mut pkey_ctx = null_mut();
        let init = if signing {
            aws_lc::EVP_DigestSignInit
        } else {
            aws_lc::EVP_DigestVerifyInit
        };
        // SAFETY: The context and key are live. AWS-LC owns the returned pkey_ctx.
        let result = unsafe { init(raw, &mut pkey_ctx, null(), null_mut(), key.0.as_ptr()) };
        assert_eq!(result, 1, "initialize AWS-LC ML-DSA-87 operation");
        assert!(!pkey_ctx.is_null());
        // SAFETY: Initialization succeeded and AWS-LC copies the context bytes.
        let result = unsafe {
            aws_lc::EVP_PKEY_CTX_set1_signature_context_string(
                pkey_ctx,
                context.as_ptr(),
                context.len(),
            )
        };
        assert_eq!(result, 1, "set FIPS 204 context");
        ctx
    }
}

impl Drop for DigestContext {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the message context and frees it once.
        unsafe { aws_lc::EVP_MD_CTX_free(self.0.as_ptr()) };
    }
}

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
/// verifier to accept. Also flips one signature bit and
/// requires the oracle to reject, so acceptance is not vacuous.
#[test]
fn oracle_accepts_handrolled_signatures() {
    let mut rng = rand::rngs::OsRng;
    let mut iters = 0usize;
    for round in 0u64..6 {
        let (pk, sk) = mldsa::keypair();
        let oracle_pk = OracleKey::public_key(&pk);
        let sk_arr: [u8; SECRETKEYBYTES] = sk.as_slice().try_into().unwrap();

        for (ci, ctx) in context_cases().iter().enumerate() {
            let msg = message(round * 17 + ci as u64, 1 + ci * 96);

            let mut rnd = [0u8; RNDBYTES];
            rng.fill_bytes(&mut rnd);
            let sig = sign::signature_ctx(&sk_arr, &msg, ctx, &rnd)
                .expect("hand-rolled signing succeeds for ctx <= 255");

            assert!(
                oracle_pk.verify(&msg, ctx, &sig),
                "oracle rejected a valid hand-rolled signature (round {round}, ctx#{ci})"
            );

            // Tamper one bit: the oracle must reject (acceptance above is real).
            let mut bad = sig;
            bad[0] ^= 0x01;
            assert!(
                !oracle_pk.verify(&msg, ctx, &bad),
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
/// oracle, then require the hand-rolled `verify` to accept
/// the oracle's public key + signature bytes. Tampering the message must make the
/// hand-rolled `verify` reject.
#[test]
fn handrolled_verify_accepts_oracle_signatures() {
    let mut iters = 0usize;
    for round in 0u64..6 {
        let oracle_sk = OracleKey::generate();
        let pk_bytes = oracle_sk.public_key_bytes();

        for (ci, ctx) in context_cases().iter().enumerate() {
            let msg = message(1000 + round * 17 + ci as u64, 1 + ci * 64);

            let signature = oracle_sk.sign(&msg, ctx);

            mldsa::verify(&pk_bytes, &signature, &msg, ctx).unwrap_or_else(|e| {
                panic!("hand-rolled verify rejected a valid oracle signature (round {round}, ctx#{ci}): {e}")
            });

            // Tamper the message: hand-rolled verify must reject.
            let mut bad_msg = msg.clone();
            bad_msg.push(0xFF);
            assert_eq!(
                mldsa::verify(&pk_bytes, &signature, &bad_msg, ctx),
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
    let oracle_pk = OracleKey::public_key(&pk);
    let oracle_sk = OracleKey::private_key(&sk);

    let ctx = b"shared-key cross check";
    let msg = b"ML-DSA-87 differential shared-key message";

    // Hand-rolled sign -> oracle verify.
    let mut rnd = [0u8; RNDBYTES];
    rng.fill_bytes(&mut rnd);
    let hr_sig = sign::signature_ctx(&sk_arr, msg, ctx, &rnd).expect("hand-rolled sign");
    assert!(
        oracle_pk.verify(msg, ctx, &hr_sig),
        "oracle rejected hand-rolled signature under shared key"
    );

    // Oracle sign -> hand-rolled verify (same shared key).
    let oracle_sig = oracle_sk.sign(msg, ctx);
    mldsa::verify(&pk, &oracle_sig, msg, ctx)
        .expect("hand-rolled verify rejected oracle signature under shared key");
}

/// Production-path differential: drive the *high-level hedged* `mldsa::sign`
/// (the exact entry `crypto::identity` calls — fresh OS `rnd`, byte-slice in/out),
/// not the lower-level `signature_ctx` seam, and require the AWS-LC oracle to
/// accept every signature. This guards the production signer end-to-end (key bytes
/// -> hedged sign -> oracle verify), so a regression in the public surface — not
/// just the deterministic core — is caught. Tampering one bit must make the oracle
/// reject, so acceptance is never vacuous.
#[test]
fn oracle_accepts_handrolled_hedged_sign() {
    let mut iters = 0usize;
    for round in 0u64..6 {
        let (pk, sk) = mldsa::keypair();
        let oracle_pk = OracleKey::public_key(&pk);

        for (ci, ctx) in context_cases().iter().enumerate() {
            let msg = message(round * 23 + ci as u64, 1 + ci * 80);

            // Production hedged sign: takes byte slices, draws its own `rnd`.
            let sig = mldsa::sign(&sk, &msg, ctx)
                .expect("hand-rolled hedged sign succeeds for ctx <= 255");
            assert_eq!(sig.len(), mldsa::SIG_BYTES);

            assert!(
                oracle_pk.verify(&msg, ctx, &sig),
                "oracle rejected a valid hand-rolled hedged signature (round {round}, ctx#{ci})"
            );

            // Tamper one bit: the oracle must reject.
            let mut bad = sig;
            bad[0] ^= 0x01;
            assert!(
                !oracle_pk.verify(&msg, ctx, &bad),
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
/// `verify` and the AWS-LC oracle. The hint encoding is the SUF-CMA-critical
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
    let oracle_pk = OracleKey::public_key(&pk);
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
        assert!(
            oracle_pk.verify(&msg, ctx, &sig),
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

            assert!(
                !oracle_pk.verify(&msg, ctx, &bad),
                "oracle accepted a hint-region tamper at byte {pos} (round {round})"
            );
            checked += 1;
        }
    }
    assert!(checked > 0);
    eprintln!("differential hint-tamper: {checked} hint-region flips rejected by both");
}
