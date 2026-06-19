//! Key generation, signing, and verification — the top-level scheme assembled
//! from the lower layers. Mirrors `sign.c` (the PQClean `ml-dsa-87/clean`
//! reference that `pqcrypto-mldsa 0.1.2` compiles).
//!
//! Holds the deterministic `keygen_internal` / `sign_internal` cores plus the
//! context-taking `signature_ctx` / `verify_ctx`. The public `keypair`/`sign`/
//! `verify` surface and size constants are re-exported from `mod.rs`.
//!
//! Determinism seams (plan §3 step 9-10, §4.1): `pqcrypto-mldsa` exposes only
//! OS-randomness entry points, so byte-identical ACVP KATs can only be hit by
//! injecting the seed (`keygen_internal(xi)`) and the hedging nonce
//! (`sign_internal(.., rnd)`). The public `keypair`/`sign` draw `xi`/`rnd` from
//! the OS CSPRNG (hedged signing, FIPS 204 §3.4); the deterministic `rnd = 0^32`
//! path is `#[cfg(test)]`-only for ACVP.
//!
//! Constant-time / zeroize note (plan §5): the signing path runs on the secret
//! `sk = (rho, key, tr, s1, s2, t0)` and the per-iteration secrets
//! (`y, z, cs1=h(cp,s1), cs2=h(cp,s2), ct0, w0, rhoprime`). The arithmetic it
//! calls is straight-line; the rejection-loop iteration count / nonce are public
//! by design. Secret seed material and the unpacked secret-key polys are zeroized
//! after use, exceeding the C reference (which does not zeroize). `verify_ctx`
//! operates on public data only and is NOT written to be constant-time for secret
//! inputs.

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use super::fips202;
use super::packing::{pack_pk, pack_sig, pack_sk, unpack_pk, unpack_sig, unpack_sk};
use super::params::{
    CRHBYTES, CTILDEBYTES, GAMMA1_MINUS_BETA, GAMMA2, GAMMA2_MINUS_BETA, K, L, OMEGA,
    POLYW1_PACKEDBYTES, PUBLICKEYBYTES, RNDBYTES, SECRETKEYBYTES, SEEDBYTES, SIGNBYTES, TRBYTES,
};
use super::poly::Poly;
use super::polyvec::{matrix_expand, matrix_pointwise_montgomery, Polyveck, Polyvecl};

/// The single failure mode of [`signature_ctx`]: the FIPS 204 context string
/// exceeded the 255-byte cap. Modeled as an enum (not a unit `Err(())`) so the
/// invariant "the only way signing fails is an over-long context" is pinned in
/// the type: any future second failure mode must add a variant here, which makes
/// the exhaustive match in `mod.rs` fail to compile rather than silently
/// mislabel the new error as `ContextTooLong` (security-review fix #4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCtxError {
    /// `ctx` was longer than the FIPS 204 limit of 255 bytes.
    ContextTooLong,
}

/// FIPS 204 Alg 6 `ML-DSA.KeyGen_internal` — `sign.c`
/// `crypto_sign_keypair`, but with the 32-byte seed `xi` injected instead of
/// drawn from `randombytes`. Returns `(pk, sk)` as fixed-size byte arrays
/// (`PUBLICKEYBYTES` / `SECRETKEYBYTES`).
///
/// Deterministic: identical `xi` yields identical `(pk, sk)` — the ACVP keyGen
/// gate (plan §4.3 gate 1) relies on this.
pub fn keygen_internal(xi: &[u8; SEEDBYTES]) -> ([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]) {
    // seedbuf = xi || K || L, then expanded in place to rho || rhoprime || key.
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut tr = [0u8; TRBYTES];

    // H(xi || IntToBytes(K,1) || IntToBytes(L,1)) -> 128 bytes (rho|rhoprime|key).
    seedbuf[..SEEDBYTES].copy_from_slice(xi);
    seedbuf[SEEDBYTES] = K as u8;
    seedbuf[SEEDBYTES + 1] = L as u8;
    // `absorbed` is a copy of the secret seed `xi` (|| K || L); zeroize it on drop
    // so the cleartext seed is not left in an unnamed Copy temporary (plan §5).
    let absorbed: zeroize::Zeroizing<[u8; SEEDBYTES + 2]> =
        zeroize::Zeroizing::new(core::array::from_fn(|i| seedbuf[i]));
    fips202::shake256(&mut seedbuf, &[&absorbed[..]]);

    let rho: [u8; SEEDBYTES] = core::array::from_fn(|i| seedbuf[i]);
    let rhoprime: [u8; CRHBYTES] = core::array::from_fn(|i| seedbuf[SEEDBYTES + i]);
    let key: [u8; SEEDBYTES] = core::array::from_fn(|i| seedbuf[SEEDBYTES + CRHBYTES + i]);

    // Expand matrix A from rho.
    let mut mat = [Polyvecl::zero(); K];
    matrix_expand(&mut mat, &rho);

    // Sample short vectors s1, s2 (ExpandS).
    let mut s1 = Polyvecl::zero();
    s1.uniform_eta(&rhoprime, 0);
    let mut s2 = Polyveck::zero();
    s2.uniform_eta(&rhoprime, L as u16);

    // t = A * s1 (in NTT domain) -> invntt; + s2.
    let mut s1hat = s1;
    s1hat.ntt();
    let mut t1 = Polyveck::zero();
    matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);
    t1.reduce();
    t1.invntt_tomont();

    t1.add_assign(&s2);

    // Extract (t1, t0) = Power2Round(t), write pk.
    t1.caddq();
    let mut t0 = Polyveck::zero();
    // C: power2round(&t1, &t0, &t1) — in place; we write the high part to a fresh
    // Polyveck (read from `t1`) then move it back to avoid aliasing borrows.
    let mut t1_hi = Polyveck::zero();
    t1.power2round(&mut t1_hi, &mut t0);
    t1 = t1_hi;

    let mut pk = [0u8; PUBLICKEYBYTES];
    pack_pk(&mut pk, &rho, &t1);

    // tr = H(pk); write sk = (rho, key, tr, s1, s2, t0).
    fips202::shake256(&mut tr, &[&pk]);
    let mut sk = [0u8; SECRETKEYBYTES];
    pack_sk(&mut sk, &rho, &tr, &key, &t0, &s1, &s2);

    // Zeroize secret seed material and secret-bearing temporaries (plan §5).
    // pk/sk/tr/rho are (or become) public; rhoprime/key and s1/s2/t0 are secret.
    seedbuf.zeroize();
    let mut rhoprime = rhoprime;
    rhoprime.zeroize();
    let mut key = key;
    key.zeroize();
    s1.zeroize();
    s1hat.zeroize();
    s2.zeroize();
    t0.zeroize();

    (pk, sk)
}

/// FIPS 204 Alg 7 `ML-DSA.Sign_internal` wrapped with the external-context mu
/// construction — `sign.c` `crypto_sign_signature_ctx`, with the 32-byte hedging
/// nonce `rnd` injected instead of drawn from `randombytes`.
///
/// Builds `mu = SHAKE256(tr || 0x00 || IntToBytes(ctxlen,1) || ctx || m)` (the
/// "pure" / `preHash="pure"` external interface, separator `0x00`) and
/// `rhoprime = SHAKE256(key || rnd || mu)`, then runs the rejection loop. Returns
/// the `SIGNBYTES`-long signature, or [`SignatureCtxError::ContextTooLong`] if
/// `ctx` is longer than 255 bytes (FIPS 204 caps the context string at 255).
pub fn signature_ctx(
    sk: &[u8; SECRETKEYBYTES],
    m: &[u8],
    ctx: &[u8],
    rnd: &[u8; RNDBYTES],
) -> Result<[u8; SIGNBYTES], SignatureCtxError> {
    if ctx.len() > 255 {
        return Err(SignatureCtxError::ContextTooLong);
    }

    // Unpack the secret key.
    let mut rho = [0u8; SEEDBYTES];
    let mut tr = [0u8; TRBYTES];
    let mut key = [0u8; SEEDBYTES];
    let mut t0 = Polyveck::zero();
    let mut s1 = Polyvecl::zero();
    let mut s2 = Polyveck::zero();
    unpack_sk(&mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, sk);

    // mu = CRH(tr || 0 || ctxlen || ctx || m).
    let mut mu = [0u8; CRHBYTES];
    let pre = [0u8, ctx.len() as u8];
    fips202::shake256(&mut mu, &[&tr, &pre, ctx, m]);

    // rhoprime = CRH(key || rnd || mu).
    let mut rhoprime = [0u8; CRHBYTES];
    fips202::shake256(&mut rhoprime, &[&key, rnd, &mu]);

    // Expand matrix and transform secret vectors into the NTT domain.
    let mut mat = [Polyvecl::zero(); K];
    matrix_expand(&mut mat, &rho);
    s1.ntt();
    s2.ntt();
    t0.ntt();

    let mut nonce: u16 = 0;
    let mut sig = [0u8; SIGNBYTES];
    // `w0` (the secret low part of `w`) is hoisted out of the loop so it can be
    // zeroized exactly once after the loop, rather than at each reject `continue`.
    // It is fully overwritten by `decompose` every iteration before any read, so
    // hoisting does not leak state across iterations (plan §5 BLOCKER 1).
    let mut w0 = Polyveck::zero();

    let result = loop {
        // Sample intermediate vector y (ExpandMask).
        let mut y = Polyvecl::zero();
        y.uniform_gamma1(&rhoprime, nonce);
        nonce = nonce.wrapping_add(1);

        // w = A * y (NTT domain) -> invntt.
        let mut z = y;
        z.ntt();
        let mut w1 = Polyveck::zero();
        matrix_pointwise_montgomery(&mut w1, &mat, &z);
        w1.reduce();
        w1.invntt_tomont();

        // Decompose w and call the random oracle.
        w1.caddq();
        // C: decompose(&w1, &w0, &w1) — in place. `w0` is the hoisted buffer,
        // fully rewritten here each iteration.
        let mut w1_hi = Polyveck::zero();
        w1.decompose(&mut w1_hi, &mut w0);
        w1 = w1_hi;
        w1.pack_w1(&mut sig[..K * POLYW1_PACKEDBYTES]);

        // c~ = H(mu || w1packed); cp = SampleInBall(c~).
        {
            let w1_packed: [u8; K * POLYW1_PACKEDBYTES] = core::array::from_fn(|i| sig[i]);
            let mut ctilde = [0u8; CTILDEBYTES];
            fips202::shake256(&mut ctilde, &[&mu, &w1_packed]);
            sig[..CTILDEBYTES].copy_from_slice(&ctilde);
        }
        let ctilde: [u8; CTILDEBYTES] = core::array::from_fn(|i| sig[i]);
        let mut cp = Poly::zero();
        cp.poly_challenge(&ctilde);
        cp.ntt();

        // z = y + c*s1; reject if it reveals the secret.
        z.pointwise_poly_montgomery(&cp, &s1);
        z.invntt_tomont();
        z.add_assign(&y);
        z.reduce();
        if z.chknorm(GAMMA1_MINUS_BETA) {
            y.zeroize();
            z.zeroize();
            continue;
        }

        // Check that subtracting c*s2 does not change the high bits of w and that
        // the low bits do not reveal the secret.
        let mut h = Polyveck::zero();
        h.pointwise_poly_montgomery(&cp, &s2);
        h.invntt_tomont();
        w0.sub_assign(&h);
        w0.reduce();
        if w0.chknorm(GAMMA2_MINUS_BETA) {
            y.zeroize();
            z.zeroize();
            h.zeroize();
            continue;
        }

        // Compute hints for w1: h = c*t0.
        h.pointwise_poly_montgomery(&cp, &t0);
        h.invntt_tomont();
        h.reduce();
        if h.chknorm(GAMMA2) {
            y.zeroize();
            z.zeroize();
            h.zeroize();
            continue;
        }

        w0.add_assign(&h);
        let n = h.make_hint(&w0, &w1);
        if n as usize > OMEGA {
            y.zeroize();
            z.zeroize();
            h.zeroize();
            continue;
        }

        // Write the signature (c~ is already in sig[..CTILDEBYTES]).
        pack_sig(&mut sig, &ctilde, &z, &h);

        y.zeroize();
        z.zeroize();
        // h is the public hint at this point, no need to zeroize.
        break Ok(sig);
    };

    // Zeroize the unpacked secret-key material and its NTT forms (plan §5).
    key.zeroize();
    rhoprime.zeroize();
    s1.zeroize();
    s2.zeroize();
    t0.zeroize();
    // `w0` holds the secret low part of `w` from the final iteration; scrub it
    // once here (it was hoisted out of the loop for exactly this).
    w0.zeroize();

    result
}

/// FIPS 204 Alg 8 `ML-DSA.Verify_internal` wrapped with the external-context mu
/// construction — `sign.c` `crypto_sign_verify_ctx`. Returns `Ok(())` iff the
/// signature verifies, `Err(())` otherwise (bad length, malformed hint, norm
/// violation, or challenge mismatch).
///
/// All inputs are public for this product, so this is NOT constant-time for
/// secret inputs (plan §5) — callers must not feed it secret-dependent data.
#[allow(clippy::result_unit_err)]
pub fn verify_ctx(
    pk: &[u8; PUBLICKEYBYTES],
    sig: &[u8; SIGNBYTES],
    m: &[u8],
    ctx: &[u8],
) -> Result<(), ()> {
    if ctx.len() > 255 {
        return Err(());
    }

    let mut rho = [0u8; SEEDBYTES];
    let mut t1 = Polyveck::zero();
    unpack_pk(&mut rho, &mut t1, pk);

    let mut c = [0u8; CTILDEBYTES];
    let mut z = Polyvecl::zero();
    let mut h = Polyveck::zero();
    unpack_sig(&mut c, &mut z, &mut h, sig)?;

    if z.chknorm(GAMMA1_MINUS_BETA) {
        return Err(());
    }

    // mu = CRH(H(pk) || 0 || ctxlen || ctx || m).
    let mut tr = [0u8; TRBYTES];
    fips202::shake256(&mut tr, &[pk]);
    let mut mu = [0u8; CRHBYTES];
    let pre = [0u8, ctx.len() as u8];
    fips202::shake256(&mut mu, &[&tr, &pre, ctx, m]);

    // Matrix-vector multiplication; compute w' = A*z - c*2^d*t1.
    let mut cp = Poly::zero();
    cp.poly_challenge(&c);
    let mut mat = [Polyvecl::zero(); K];
    matrix_expand(&mut mat, &rho);

    z.ntt();
    let mut w1 = Polyveck::zero();
    matrix_pointwise_montgomery(&mut w1, &mat, &z);

    cp.ntt();
    t1.shiftl();
    t1.ntt();
    let cp_poly = cp;
    t1.pointwise_poly_montgomery(&cp_poly, &{ t1 });

    w1.sub(&{ w1 }, &t1);
    w1.reduce();
    w1.invntt_tomont();

    // Reconstruct w1.
    w1.caddq();
    let mut w1_used = Polyveck::zero();
    w1_used.use_hint(&w1, &h);
    let mut buf = [0u8; K * POLYW1_PACKEDBYTES];
    w1_used.pack_w1(&mut buf);

    // Call the random oracle and verify the challenge.
    let mut c2 = [0u8; CTILDEBYTES];
    fips202::shake256(&mut c2, &[&mu, &buf]);

    if c == c2 {
        Ok(())
    } else {
        Err(())
    }
}

/// Public key generation (FIPS 204 Alg 1 `ML-DSA.KeyGen`): draw the 32-byte seed
/// `xi` from the OS CSPRNG and run [`keygen_internal`]. Returns `(pk, sk)` byte
/// arrays. The `mod.rs` public surface wraps this into `Vec<u8>` for callers.
pub fn keypair() -> ([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]) {
    let mut xi = [0u8; SEEDBYTES];
    OsRng.fill_bytes(&mut xi);
    let out = keygen_internal(&xi);
    xi.zeroize();
    out
}

/// Hedged signing (FIPS 204 Alg 2 `ML-DSA.Sign`, hedged variant): draw the
/// 32-byte hedging nonce `rnd` from the OS CSPRNG and run [`signature_ctx`].
pub fn sign(
    sk: &[u8; SECRETKEYBYTES],
    m: &[u8],
    ctx: &[u8],
) -> Result<[u8; SIGNBYTES], SignatureCtxError> {
    let mut rnd = [0u8; RNDBYTES];
    OsRng.fill_bytes(&mut rnd);
    let out = signature_ctx(sk, m, ctx, &rnd);
    rnd.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Step 9 self-test: keygen yields correctly sized keys and a fresh
    /// sign/verify round-trips (including a non-empty context). Also checks the
    /// negative cases that a wrong key / tampered signature / tampered message are
    /// rejected, so the round-trip cannot pass vacuously.
    #[test]
    fn keygen_sign_verify_round_trip() {
        // Deterministic seed so the test is reproducible without depending on the
        // OS RNG; keygen_internal is the deterministic core public uses via OsRng.
        let xi: [u8; SEEDBYTES] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let (pk, sk) = keygen_internal(&xi);

        // Size gate (plan §3 step 9 / api.h).
        assert_eq!(pk.len(), 2592, "public key must be 2592 bytes");
        assert_eq!(sk.len(), 4896, "secret key must be 4896 bytes");
        assert_eq!(SIGNBYTES, 4627);

        let msg = b"ParallaX ml-dsa-87 step 9 self-test message";
        let ctx = b"ParallaX v2 ML-DSA-87 server identity";

        // Deterministic rnd = 0^32 so the round-trip is reproducible.
        let rnd = [0u8; RNDBYTES];
        let sig = signature_ctx(&sk, msg, ctx, &rnd).expect("sign must succeed");
        assert_eq!(sig.len(), 4627, "signature must be 4627 bytes");

        // A fresh sign/verify must round-trip.
        verify_ctx(&pk, &sig, msg, ctx).expect("fresh signature must verify");

        // Hedged public sign/keypair also round-trips (exercises OsRng paths).
        let (pk2, sk2) = keypair();
        let sig2 = sign(&sk2, msg, ctx).expect("hedged sign must succeed");
        verify_ctx(&pk2, &sig2, msg, ctx).expect("hedged signature must verify");

        // Negative: wrong public key rejects.
        assert!(
            verify_ctx(&pk2, &sig, msg, ctx).is_err(),
            "wrong public key must reject"
        );

        // Negative: a single flipped signature byte rejects.
        let mut bad_sig = sig;
        bad_sig[0] ^= 0x01;
        assert!(
            verify_ctx(&pk, &bad_sig, msg, ctx).is_err(),
            "tampered signature must reject"
        );

        // Negative: a flipped message byte rejects.
        let mut bad_msg = msg.to_vec();
        bad_msg[0] ^= 0x01;
        assert!(
            verify_ctx(&pk, &sig, &bad_msg, ctx).is_err(),
            "tampered message must reject"
        );

        // Negative: a different context rejects.
        assert!(
            verify_ctx(&pk, &sig, msg, b"different context").is_err(),
            "wrong context must reject"
        );

        // ctx > 255 bytes must error, not panic.
        let long_ctx = [0u8; 256];
        assert!(
            signature_ctx(&sk, msg, &long_ctx, &rnd).is_err(),
            "ctx > 255 must error on sign"
        );
        assert!(
            verify_ctx(&pk, &sig, msg, &long_ctx).is_err(),
            "ctx > 255 must error on verify"
        );
    }

    /// keygen_internal is deterministic in its seed: identical `xi` -> identical
    /// `(pk, sk)`; distinct `xi` -> distinct keys. (Pins the determinism seam the
    /// ACVP keyGen KAT relies on, ahead of wiring the full vector harness.)
    #[test]
    fn keygen_internal_is_deterministic() {
        let xi_a = [0x11u8; SEEDBYTES];
        let xi_b = [0x22u8; SEEDBYTES];
        let (pk_a1, sk_a1) = keygen_internal(&xi_a);
        let (pk_a2, sk_a2) = keygen_internal(&xi_a);
        assert_eq!(pk_a1, pk_a2, "same seed must give same pk");
        assert_eq!(sk_a1, sk_a2, "same seed must give same sk");

        let (pk_b, _) = keygen_internal(&xi_b);
        assert_ne!(pk_a1, pk_b, "different seeds must give different pk");
    }

    /// The signing path must be panic-free across many fresh hedged signatures
    /// (plan §5 BLOCKER 1 regression guard). A panic anywhere between secret
    /// population and the trailing manual `zeroize()` of `w0` / the secret-key
    /// vectors would unwind past the scrub and leave cleartext secrets on the
    /// stack. This drives `keygen` + many hedged `signature_ctx` (so the rejection
    /// loop runs to completion repeatedly, exercising every reject `continue`) and
    /// a verify round-trip; reaching the end without a panic is the assertion.
    #[test]
    fn signing_path_is_panic_free() {
        let xi: [u8; SEEDBYTES] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(5));
        let (pk, sk) = keygen_internal(&xi);

        let msg = b"ParallaX ml-dsa-87 panic-free signing-path regression guard";
        let ctx = b"ParallaX v2 ML-DSA-87 server identity";

        // Many distinct hedging nonces so the rejection loop iterates a varying
        // number of times across runs (covering the reject `continue` paths that
        // carry secret `w0`/`z`). Each signature must succeed and verify, with no
        // panic from secret population through the trailing zeroize.
        for k in 0u8..16 {
            let rnd = [k.wrapping_mul(31).wrapping_add(1); RNDBYTES];
            let sig = signature_ctx(&sk, msg, ctx, &rnd).expect("sign must not fail");
            verify_ctx(&pk, &sig, msg, ctx).expect("fresh signature must verify");
        }
    }
}
