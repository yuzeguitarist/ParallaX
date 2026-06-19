//! Hand-rolled ML-DSA-87 (FIPS 204) — pure-Rust port of the PQClean *clean* C
//! reference for ParallaX server-identity signing.
//!
//! A forgery here is a server-identity bypass, so this is a faithful, byte-for-byte
//! port of the PQClean `ml-dsa-87/clean` C (the same code `pqcrypto-mldsa 0.1.2`
//! compiles, which is also kept in-tree as the differential oracle). It is
//! validated against the NIST ACVP KAT vectors; see `tests/mldsa_acvp.rs`.
//!
//! Module layout mirrors the C files 1:1 so each Rust function can be diffed
//! against exactly one C function (the `PQCLEAN_MLDSA87_CLEAN_` prefix is dropped
//! but the C function names are preserved). The only file that touches a crypto
//! dependency is `fips202`, which wraps the audited `sha3` crate (SHAKE128/256)
//! instead of hand-rolling Keccak.
//!
//! Build is staged bottom-up (see `target/mldsa_handroll_plan.md`). This file is
//! the only `pub` surface of the module: byte-oriented `keypair` / `sign` /
//! `verify` plus the key/signature size constants. It mirrors the role of
//! pqcrypto's `mldsa87` wrapper and is shaped to drop into `crypto::identity`'s
//! call sites (plan §6) — keys and signatures cross the boundary as plain byte
//! vectors / slices, with length validation done here so callers never panic on
//! a wrong-sized buffer from a config file.
//!
//! Threat-model note for callers: for THIS product the secret key is used only
//! for signing, so only the signing path is required to be constant-time. The
//! `verify` path operates on public data only and is NOT written to be
//! constant-time for secret inputs — do not feed secret-dependent data to verify.

// Submodules mirror the C translation units (see the table in the module plan).
// They are declared here so the crate compiles as a coherent skeleton while each
// is filled in by its own build step.
pub mod params;

pub mod fips202;
pub mod ntt;
pub mod packing;
pub mod poly;
pub mod polyvec;
pub mod reduce;
pub mod rounding;
pub mod sign;

use thiserror::Error;
use zeroize::Zeroize;

use params::{PUBLICKEYBYTES, RNDBYTES, SECRETKEYBYTES, SIGNBYTES};

/// Public-key length in bytes (`2592`). Re-exported so callers can size buffers
/// / validate config without reaching into `params`.
pub const PUBLICKEY_BYTES: usize = PUBLICKEYBYTES;
/// Secret-key length in bytes (`4896`).
pub const SECRETKEY_BYTES: usize = SECRETKEYBYTES;
/// Signature length in bytes (`4627`).
pub const SIG_BYTES: usize = SIGNBYTES;

/// FIPS 204 ML-DSA-87 serialized public-key length (bytes). The `fn` form mirrors
/// the retired `pqcrypto_mldsa::mldsa87::public_key_bytes()` (and `crypto::pq`'s
/// ML-KEM accessors) so config/probe/speed call sites only change the path.
pub fn public_key_bytes() -> usize {
    PUBLICKEYBYTES
}
/// FIPS 204 ML-DSA-87 serialized secret-key length (bytes). Mirrors the retired
/// `pqcrypto_mldsa::mldsa87::secret_key_bytes()`.
pub fn secret_key_bytes() -> usize {
    SECRETKEYBYTES
}
/// FIPS 204 ML-DSA-87 detached-signature length (bytes). Mirrors the retired
/// `pqcrypto_mldsa::mldsa87::signature_bytes()`.
pub fn signature_bytes() -> usize {
    SIGNBYTES
}

/// Errors from the byte-oriented public API.
///
/// The variants mirror what `crypto::identity` needs to distinguish (plan §6):
/// a wrong-sized key/signature (config / deserialization problem) is reported
/// separately from a cryptographic verification failure, and `ContextTooLong`
/// surfaces the FIPS 204 255-byte context cap as an error rather than a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MlDsaError {
    /// Secret key was not exactly [`SECRETKEY_BYTES`] long.
    #[error("invalid ML-DSA-87 secret key length")]
    InvalidSecretKeyLength,
    /// Public key was not exactly [`PUBLICKEY_BYTES`] long.
    #[error("invalid ML-DSA-87 public key length")]
    InvalidPublicKeyLength,
    /// Signature was not exactly [`SIG_BYTES`] long.
    #[error("invalid ML-DSA-87 signature length")]
    InvalidSignatureLength,
    /// Context string exceeded the FIPS 204 cap of 255 bytes.
    #[error("ML-DSA-87 context string longer than 255 bytes")]
    ContextTooLong,
    /// The signature did not verify against the message, context, and key.
    #[error("ML-DSA-87 signature verification failed")]
    VerificationFailed,
}

/// Generate a fresh ML-DSA-87 key pair, drawing the seed from the OS CSPRNG
/// (FIPS 204 Alg 1 `ML-DSA.KeyGen`). Returns `(public_key, secret_key)` as byte
/// vectors of length [`PUBLICKEY_BYTES`] / [`SECRETKEY_BYTES`].
pub fn keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = sign::keypair();
    (pk.to_vec(), sk.to_vec())
}

/// Sign `msg` under context `ctx` with the bit-packed secret key `sk`, hedged
/// signing (FIPS 204 Alg 2, hedged variant — fresh `rnd` from the OS CSPRNG).
///
/// `sk` must be exactly [`SECRETKEY_BYTES`] long and `ctx` at most 255 bytes;
/// otherwise an error is returned (never a panic). Returns the detached
/// signature ([`SIG_BYTES`] bytes).
pub fn sign(sk: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, MlDsaError> {
    let sk_arr = to_sk_array(sk)?;
    let mut rnd = [0u8; RNDBYTES];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
    let res = sign::signature_ctx(&sk_arr, msg, ctx, &rnd);
    rnd.zeroize();
    drop_sk_array(sk_arr);
    // Exhaustive match (not `map_err(|_| ...)`): if `signature_ctx` ever grows a
    // second failure mode, this stops compiling instead of silently relabeling
    // the new error as `ContextTooLong` (security-review fix #4).
    let sig = res.map_err(|e| match e {
        sign::SignatureCtxError::ContextTooLong => MlDsaError::ContextTooLong,
    })?;
    Ok(sig.to_vec())
}

/// Verify detached `sig` over `msg` under context `ctx` with public key `pk`
/// (FIPS 204 Alg 3 `ML-DSA.Verify`). `Ok(())` iff the signature is valid.
///
/// Wrong-sized `pk`/`sig` and an over-long `ctx` return the matching error
/// variant (not a panic); a cryptographic mismatch returns
/// [`MlDsaError::VerificationFailed`]. All inputs are treated as public.
pub fn verify(pk: &[u8], sig: &[u8], msg: &[u8], ctx: &[u8]) -> Result<(), MlDsaError> {
    if pk.len() != PUBLICKEYBYTES {
        return Err(MlDsaError::InvalidPublicKeyLength);
    }
    if sig.len() != SIGNBYTES {
        return Err(MlDsaError::InvalidSignatureLength);
    }
    if ctx.len() > 255 {
        return Err(MlDsaError::ContextTooLong);
    }
    let pk_arr: [u8; PUBLICKEYBYTES] = core::array::from_fn(|i| pk[i]);
    let sig_arr: [u8; SIGNBYTES] = core::array::from_fn(|i| sig[i]);
    sign::verify_ctx(&pk_arr, &sig_arr, msg, ctx).map_err(|()| MlDsaError::VerificationFailed)
}

/// Deterministic signing with an injected 32-byte `rnd` (test-only).
///
/// This is the determinism seam the ACVP sigGen KATs need (plan §4.1, §4.3):
/// pass `rnd = [0u8; 32]` for the `deterministic:true` groups, or the vector's
/// `rnd` field for the hedged groups, to reproduce byte-identical signatures.
/// Not exposed in production — production signing is hedged via [`sign`].
#[cfg(test)]
#[allow(dead_code)]
pub fn sign_deterministic(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    rnd: &[u8; RNDBYTES],
) -> Result<Vec<u8>, MlDsaError> {
    let sk_arr = to_sk_array(sk)?;
    let res = sign::signature_ctx(&sk_arr, msg, ctx, rnd);
    drop_sk_array(sk_arr);
    let sig = res.map_err(|e| match e {
        sign::SignatureCtxError::ContextTooLong => MlDsaError::ContextTooLong,
    })?;
    Ok(sig.to_vec())
}

/// Copy a secret-key slice into a fixed-size array, validating its length.
/// The fixed array (not the caller's slice) is what the signing core consumes;
/// the caller is responsible for zeroizing its own copy.
fn to_sk_array(sk: &[u8]) -> Result<[u8; SECRETKEYBYTES], MlDsaError> {
    if sk.len() != SECRETKEYBYTES {
        return Err(MlDsaError::InvalidSecretKeyLength);
    }
    Ok(core::array::from_fn(|i| sk[i]))
}

/// Zeroize the local secret-key copy made by [`to_sk_array`] before it is
/// dropped, so the unpacked-then-discarded secret does not linger on the stack
/// (plan §5; the C reference does not do this — we exceed it).
fn drop_sk_array(mut sk: [u8; SECRETKEYBYTES]) {
    sk.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Step 10 self-test for the public byte-oriented surface (the shape
    /// `crypto::identity` will call, plan §6): keypair sizes, a hedged
    /// sign/verify round-trip, and that every error path returns an `Err`
    /// (matching variant) instead of panicking on a bad buffer.
    #[test]
    fn public_api_round_trip_and_error_paths() {
        // Size constants are re-exported correctly.
        assert_eq!(PUBLICKEY_BYTES, 2592);
        assert_eq!(SECRETKEY_BYTES, 4896);
        assert_eq!(SIG_BYTES, 4627);

        let (pk, sk) = keypair();
        assert_eq!(pk.len(), PUBLICKEY_BYTES);
        assert_eq!(sk.len(), SECRETKEY_BYTES);

        let msg = b"ParallaX ml-dsa-87 step 10 public-api self-test";
        let ctx = b"ParallaX v2 ML-DSA-87 server identity";

        // Hedged sign/verify round-trips through the slice-based API.
        let sig = sign(&sk, msg, ctx).expect("hedged sign must succeed");
        assert_eq!(sig.len(), SIG_BYTES);
        verify(&pk, &sig, msg, ctx).expect("fresh signature must verify");

        // Negative: wrong message / context / public key all reject (so the
        // round-trip above cannot pass vacuously).
        assert_eq!(
            verify(&pk, &sig, b"tampered", ctx),
            Err(MlDsaError::VerificationFailed)
        );
        assert_eq!(
            verify(&pk, &sig, msg, b"wrong ctx"),
            Err(MlDsaError::VerificationFailed)
        );
        let (other_pk, _) = keypair();
        assert_eq!(
            verify(&other_pk, &sig, msg, ctx),
            Err(MlDsaError::VerificationFailed)
        );

        // Wrong-length buffers return the matching error, never panic.
        assert_eq!(
            sign(&sk[..SECRETKEY_BYTES - 1], msg, ctx),
            Err(MlDsaError::InvalidSecretKeyLength)
        );
        assert_eq!(
            verify(&pk[..PUBLICKEY_BYTES - 1], &sig, msg, ctx),
            Err(MlDsaError::InvalidPublicKeyLength)
        );
        assert_eq!(
            verify(&pk, &sig[..SIG_BYTES - 1], msg, ctx),
            Err(MlDsaError::InvalidSignatureLength)
        );

        // ctx > 255 errors (not panics) on both sign and verify.
        let long_ctx = vec![0u8; 256];
        assert_eq!(sign(&sk, msg, &long_ctx), Err(MlDsaError::ContextTooLong));
        assert_eq!(
            verify(&pk, &sig, msg, &long_ctx),
            Err(MlDsaError::ContextTooLong)
        );
        // ctx == 255 is the boundary and must round-trip.
        let max_ctx = vec![0xABu8; 255];
        let sig_max = sign(&sk, msg, &max_ctx).expect("ctx==255 must sign");
        verify(&pk, &sig_max, msg, &max_ctx).expect("ctx==255 must verify");
    }

    /// `sign_deterministic` is reproducible in its injected `rnd` (the seam the
    /// ACVP sigGen KATs rely on, plan §4.1) and its output verifies. Distinct
    /// `rnd` yields distinct signatures (both still valid — ML-DSA signatures
    /// are randomized).
    #[test]
    fn sign_deterministic_is_reproducible() {
        let (pk, sk) = keypair();
        let msg = b"deterministic seam";
        let ctx: &[u8] = b"";

        let rnd0 = [0u8; RNDBYTES];
        let a = sign_deterministic(&sk, msg, ctx, &rnd0).unwrap();
        let b = sign_deterministic(&sk, msg, ctx, &rnd0).unwrap();
        assert_eq!(a, b, "same (sk,msg,ctx,rnd) must give identical signature");
        verify(&pk, &a, msg, ctx).expect("deterministic signature must verify");

        let rnd1 = [0x5Au8; RNDBYTES];
        let c = sign_deterministic(&sk, msg, ctx, &rnd1).unwrap();
        assert_ne!(a, c, "different rnd must give a different signature");
        verify(&pk, &c, msg, ctx).expect("hedged-rnd signature must verify");
    }

    /// Empty-message (`msg = b""`) end-to-end: keygen -> sign -> verify must
    /// round-trip, and a tampered signature over the empty message must reject.
    /// FIPS 204 places no lower bound on the message length, so the zero-length
    /// case must be a first-class input, not an accidental panic / silent accept.
    #[test]
    fn empty_message_round_trip_and_tamper_rejects() {
        let (pk, sk) = keypair();
        let msg: &[u8] = b"";
        let ctx: &[u8] = b"ParallaX v2 ML-DSA-87 server identity";

        let sig = sign(&sk, msg, ctx).expect("empty-message sign must succeed");
        assert_eq!(sig.len(), SIG_BYTES);
        verify(&pk, &sig, msg, ctx).expect("empty-message signature must verify");

        // Tamper one signature byte: verification of the empty message must fail.
        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert_eq!(
            verify(&pk, &bad, msg, ctx),
            Err(MlDsaError::VerificationFailed),
            "tampered empty-message signature must reject"
        );

        // A non-empty message must not verify against the empty-message signature
        // (so the empty case is genuinely bound, not ignored).
        assert_eq!(
            verify(&pk, &sig, b"x", ctx),
            Err(MlDsaError::VerificationFailed),
            "non-empty message must not verify under empty-message signature"
        );
    }
}
