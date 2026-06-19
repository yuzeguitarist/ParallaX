//! (De)serialization of the public key, secret key, and signature byte strings.
//! Mirrors `packing.c`. `unpack_sig` is fallible (hint-decode can reject) and
//! returns a `Result`.
//!
//! Each function is a 1:1 port of one `PQCLEAN_MLDSA87_CLEAN_*` function so it can
//! be diffed against the C. The per-polynomial bit-(un)packers it composes
//! (`polyt1_pack`, `polyeta_pack`, `polyt0_pack`, `polyz_pack` + their unpack
//! inverses) live in `poly.rs`, exactly as in the C, where `packing.c` only does
//! the field layout (`rho || key || tr || s1 || s2 || t0`, `rho || t1`,
//! `c~ || z || h`) and the hint run-length encode/decode.
//!
//! Constant-time note (plan §5): `pack_sig`'s hint encoding branches on a nonzero
//! coefficient, but the hint `h` is public signature output, so that is sanctioned
//! (do NOT reuse that branch-on-nonzero pattern for the secret polys `s1/s2/t0`).
//! The three `unpack_sig` rejection checks operate on the untrusted signature
//! bytes during verification, which is an all-public operation for this product.

use super::params::{
    CTILDEBYTES, K, L, OMEGA, POLYETA_PACKEDBYTES, POLYT0_PACKEDBYTES, POLYT1_PACKEDBYTES,
    POLYZ_PACKEDBYTES, PUBLICKEYBYTES, SECRETKEYBYTES, SEEDBYTES, SIGNBYTES, TRBYTES,
};
use super::polyvec::{Polyveck, Polyvecl};

/// Bit-pack the public key `pk = (rho, t1)` (`packing.c` `pack_pk`).
///
/// Layout: `rho` (`SEEDBYTES`) followed by the `K` polynomials of `t1`, each
/// `POLYT1_PACKEDBYTES`. Writes exactly `PUBLICKEYBYTES` bytes into `pk`.
pub fn pack_pk(pk: &mut [u8; PUBLICKEYBYTES], rho: &[u8; SEEDBYTES], t1: &Polyveck) {
    pk[..SEEDBYTES].copy_from_slice(rho);

    for i in 0..K {
        let off = SEEDBYTES + i * POLYT1_PACKEDBYTES;
        t1.vec[i].polyt1_pack(&mut pk[off..off + POLYT1_PACKEDBYTES]);
    }
}

/// Unpack the public key `pk = (rho, t1)` (`packing.c` `unpack_pk`).
///
/// Inverse of [`pack_pk`]; reads `PUBLICKEYBYTES` bytes. Always succeeds (every
/// 10-bit `t1` coefficient is a valid standard representative).
pub fn unpack_pk(rho: &mut [u8; SEEDBYTES], t1: &mut Polyveck, pk: &[u8; PUBLICKEYBYTES]) {
    rho.copy_from_slice(&pk[..SEEDBYTES]);

    for i in 0..K {
        let off = SEEDBYTES + i * POLYT1_PACKEDBYTES;
        t1.vec[i].polyt1_unpack(&pk[off..off + POLYT1_PACKEDBYTES]);
    }
}

/// Bit-pack the secret key `sk = (rho, key, tr, s1, s2, t0)` (`packing.c`
/// `pack_sk`).
///
/// Field order (mirrors the C exactly): `rho` (`SEEDBYTES`), `key`
/// (`SEEDBYTES`), `tr` (`TRBYTES`), then `s1` (`L` × `POLYETA_PACKEDBYTES`),
/// `s2` (`K` × `POLYETA_PACKEDBYTES`), `t0` (`K` × `POLYT0_PACKEDBYTES`). Writes
/// exactly `SECRETKEYBYTES` bytes. `s1`, `s2`, `t0` are secret, so the
/// per-poly packers are branchless.
#[allow(clippy::too_many_arguments)]
pub fn pack_sk(
    sk: &mut [u8; SECRETKEYBYTES],
    rho: &[u8; SEEDBYTES],
    tr: &[u8; TRBYTES],
    key: &[u8; SEEDBYTES],
    t0: &Polyveck,
    s1: &Polyvecl,
    s2: &Polyveck,
) {
    let mut off = 0;

    sk[off..off + SEEDBYTES].copy_from_slice(rho);
    off += SEEDBYTES;

    sk[off..off + SEEDBYTES].copy_from_slice(key);
    off += SEEDBYTES;

    sk[off..off + TRBYTES].copy_from_slice(tr);
    off += TRBYTES;

    for i in 0..L {
        let o = off + i * POLYETA_PACKEDBYTES;
        s1.vec[i].polyeta_pack(&mut sk[o..o + POLYETA_PACKEDBYTES]);
    }
    off += L * POLYETA_PACKEDBYTES;

    for i in 0..K {
        let o = off + i * POLYETA_PACKEDBYTES;
        s2.vec[i].polyeta_pack(&mut sk[o..o + POLYETA_PACKEDBYTES]);
    }
    off += K * POLYETA_PACKEDBYTES;

    for i in 0..K {
        let o = off + i * POLYT0_PACKEDBYTES;
        t0.vec[i].polyt0_pack(&mut sk[o..o + POLYT0_PACKEDBYTES]);
    }
}

/// Unpack the secret key `sk = (rho, key, tr, s1, s2, t0)` (`packing.c`
/// `unpack_sk`).
///
/// Inverse of [`pack_sk`]; reads `SECRETKEYBYTES` bytes. Always succeeds (the
/// eta/t0 encodings have no out-of-range representation that needs rejecting).
#[allow(clippy::too_many_arguments)]
pub fn unpack_sk(
    rho: &mut [u8; SEEDBYTES],
    tr: &mut [u8; TRBYTES],
    key: &mut [u8; SEEDBYTES],
    t0: &mut Polyveck,
    s1: &mut Polyvecl,
    s2: &mut Polyveck,
    sk: &[u8; SECRETKEYBYTES],
) {
    let mut off = 0;

    rho.copy_from_slice(&sk[off..off + SEEDBYTES]);
    off += SEEDBYTES;

    key.copy_from_slice(&sk[off..off + SEEDBYTES]);
    off += SEEDBYTES;

    tr.copy_from_slice(&sk[off..off + TRBYTES]);
    off += TRBYTES;

    for i in 0..L {
        let o = off + i * POLYETA_PACKEDBYTES;
        s1.vec[i].polyeta_unpack(&sk[o..o + POLYETA_PACKEDBYTES]);
    }
    off += L * POLYETA_PACKEDBYTES;

    for i in 0..K {
        let o = off + i * POLYETA_PACKEDBYTES;
        s2.vec[i].polyeta_unpack(&sk[o..o + POLYETA_PACKEDBYTES]);
    }
    off += K * POLYETA_PACKEDBYTES;

    for i in 0..K {
        let o = off + i * POLYT0_PACKEDBYTES;
        t0.vec[i].polyt0_unpack(&sk[o..o + POLYT0_PACKEDBYTES]);
    }
}

/// Bit-pack the signature `sig = (c~, z, h)` (`packing.c` `pack_sig`).
///
/// Layout: `c~` (`CTILDEBYTES`), then `z` (`L` × `POLYZ_PACKEDBYTES`), then the
/// hint region of `OMEGA + K` bytes. The hint is run-length encoded: the first
/// `OMEGA` bytes hold the sorted nonzero coefficient indices (concatenated across
/// the `K` polynomials), and `sig[OMEGA + i]` holds the running count of indices
/// emitted through polynomial `i`. Unused index bytes stay zero. Writes exactly
/// `SIGNBYTES` bytes.
pub fn pack_sig(sig: &mut [u8; SIGNBYTES], c: &[u8; CTILDEBYTES], z: &Polyvecl, h: &Polyveck) {
    sig[..CTILDEBYTES].copy_from_slice(c);

    for i in 0..L {
        let off = CTILDEBYTES + i * POLYZ_PACKEDBYTES;
        z.vec[i].polyz_pack(&mut sig[off..off + POLYZ_PACKEDBYTES]);
    }

    // Encode h into the trailing OMEGA + K bytes.
    let hint = &mut sig[CTILDEBYTES + L * POLYZ_PACKEDBYTES..];
    for b in hint[..OMEGA + K].iter_mut() {
        *b = 0;
    }

    let mut k = 0usize;
    for i in 0..K {
        for j in 0..super::params::N {
            // Hint `h` is public signature output, so the branch on a nonzero
            // coefficient is sanctioned (plan §5).
            if h.vec[i].coeffs[j] != 0 {
                hint[k] = j as u8;
                k += 1;
            }
        }
        hint[OMEGA + i] = k as u8;
    }
}

/// Unpack the signature `sig = (c~, z, h)` (`packing.c` `unpack_sig`).
///
/// Inverse of [`pack_sig`]. Returns `Err(())` for a malformed signature (matching
/// the C `return 1`), otherwise writes `c`, `z`, `h` and returns `Ok(())`.
///
/// Three hint-decode rejection checks are enforced; each one is required for
/// strong unforgeability (SUF-CMA) — skipping any of them is a silent forgery
/// hole that the ACVP "modified hint" sigVer vectors are designed to catch:
///   1. each running count `sig[OMEGA + i]` is monotone non-decreasing (`>= k`)
///      and does not exceed `OMEGA`;
///   2. the indices within each polynomial's run are strictly ascending;
///   3. all unused index bytes (those past the final count, up to `OMEGA`) are
///      zero.
// The unit error mirrors the C `return 1` (malformed) vs `return 0`: `verify`
// only needs accept/reject, not a reason. Matches the same pattern at
// `transport::udp` (`#[allow(clippy::result_unit_err)]`).
#[allow(clippy::result_unit_err)]
pub fn unpack_sig(
    c: &mut [u8; CTILDEBYTES],
    z: &mut Polyvecl,
    h: &mut Polyveck,
    sig: &[u8; SIGNBYTES],
) -> Result<(), ()> {
    c.copy_from_slice(&sig[..CTILDEBYTES]);

    for i in 0..L {
        let off = CTILDEBYTES + i * POLYZ_PACKEDBYTES;
        z.vec[i].polyz_unpack(&sig[off..off + POLYZ_PACKEDBYTES]);
    }

    // Decode h from the trailing OMEGA + K bytes.
    let hint = &sig[CTILDEBYTES + L * POLYZ_PACKEDBYTES..];

    let mut k = 0usize;
    for i in 0..K {
        h.vec[i].coeffs = [0i32; super::params::N];

        let cnt = hint[OMEGA + i] as usize;
        // Check 1: counts must be monotone non-decreasing and at most OMEGA.
        if cnt < k || cnt > OMEGA {
            return Err(());
        }

        for j in k..cnt {
            // Check 2: indices are strictly ascending within this run (ordered
            // for strong unforgeability).
            if j > k && hint[j] <= hint[j - 1] {
                return Err(());
            }
            h.vec[i].coeffs[hint[j] as usize] = 1;
        }

        k = cnt;
    }

    // Check 3: extra (unused) index bytes must be zero for strong unforgeability.
    for &b in &hint[k..OMEGA] {
        if b != 0 {
            return Err(());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mldsa::params::{GAMMA1, N};

    // --- Deterministic LCG so the round-trip tests need no external RNG -------

    struct Lcg(u64);
    impl Lcg {
        fn next_u32(&mut self) -> u32 {
            // Numerical Recipes LCG; we only need spread, not quality.
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 32) as u32
        }
        fn range(&mut self, lo: i32, hi: i32) -> i32 {
            // Inclusive [lo, hi].
            let span = (hi - lo + 1) as u32;
            lo + (self.next_u32() % span) as i32
        }
    }

    /// `t1` coefficients are 10-bit standard representatives: `[0, 1023]`.
    fn random_t1(rng: &mut Lcg) -> Polyveck {
        let mut v = Polyveck::zero();
        for p in v.vec.iter_mut() {
            for cc in p.coeffs.iter_mut() {
                *cc = rng.range(0, (1 << 10) - 1);
            }
        }
        v
    }

    /// eta-range coefficients: `[-ETA, ETA]` with `ETA = 2`.
    fn random_eta_l(rng: &mut Lcg) -> Polyvecl {
        let mut v = Polyvecl::zero();
        for p in v.vec.iter_mut() {
            for cc in p.coeffs.iter_mut() {
                *cc = rng.range(-2, 2);
            }
        }
        v
    }
    fn random_eta_k(rng: &mut Lcg) -> Polyveck {
        let mut v = Polyveck::zero();
        for p in v.vec.iter_mut() {
            for cc in p.coeffs.iter_mut() {
                *cc = rng.range(-2, 2);
            }
        }
        v
    }

    /// `t0` coefficients lie in `]-2^{D-1}, 2^{D-1}]` = `[-4095, 4096]`.
    fn random_t0(rng: &mut Lcg) -> Polyveck {
        let mut v = Polyveck::zero();
        for p in v.vec.iter_mut() {
            for cc in p.coeffs.iter_mut() {
                *cc = rng.range(-4095, 4096);
            }
        }
        v
    }

    /// `z` coefficients lie in `[-(GAMMA1 - 1), GAMMA1]` (centered, as produced by
    /// the masking vector before packing).
    fn random_z(rng: &mut Lcg) -> Polyvecl {
        let mut v = Polyvecl::zero();
        for p in v.vec.iter_mut() {
            for cc in p.coeffs.iter_mut() {
                *cc = rng.range(-(GAMMA1 - 1), GAMMA1);
            }
        }
        v
    }

    #[test]
    fn pk_pack_unpack_roundtrip() {
        let mut rng = Lcg(0x1234_5678_9abc_def0);
        for _ in 0..32 {
            let rho: [u8; SEEDBYTES] = core::array::from_fn(|_| rng.next_u32() as u8);
            let t1 = random_t1(&mut rng);

            let mut pk = [0u8; PUBLICKEYBYTES];
            pack_pk(&mut pk, &rho, &t1);

            let mut rho2 = [0u8; SEEDBYTES];
            let mut t1_2 = Polyveck::zero();
            unpack_pk(&mut rho2, &mut t1_2, &pk);

            assert_eq!(rho, rho2, "rho mismatch");
            assert_eq!(t1, t1_2, "t1 mismatch");

            // Re-pack must reproduce the same bytes.
            let mut pk2 = [0u8; PUBLICKEYBYTES];
            pack_pk(&mut pk2, &rho2, &t1_2);
            assert_eq!(&pk[..], &pk2[..], "pk re-pack mismatch");
        }
    }

    #[test]
    fn sk_pack_unpack_roundtrip() {
        let mut rng = Lcg(0xdead_beef_cafe_babe);
        for _ in 0..32 {
            let rho: [u8; SEEDBYTES] = core::array::from_fn(|_| rng.next_u32() as u8);
            let key: [u8; SEEDBYTES] = core::array::from_fn(|_| rng.next_u32() as u8);
            let tr: [u8; TRBYTES] = core::array::from_fn(|_| rng.next_u32() as u8);
            let s1 = random_eta_l(&mut rng);
            let s2 = random_eta_k(&mut rng);
            let t0 = random_t0(&mut rng);

            let mut sk = [0u8; SECRETKEYBYTES];
            pack_sk(&mut sk, &rho, &tr, &key, &t0, &s1, &s2);

            let mut rho2 = [0u8; SEEDBYTES];
            let mut tr2 = [0u8; TRBYTES];
            let mut key2 = [0u8; SEEDBYTES];
            let mut t0_2 = Polyveck::zero();
            let mut s1_2 = Polyvecl::zero();
            let mut s2_2 = Polyveck::zero();
            unpack_sk(
                &mut rho2, &mut tr2, &mut key2, &mut t0_2, &mut s1_2, &mut s2_2, &sk,
            );

            assert_eq!(rho, rho2, "rho mismatch");
            assert_eq!(key, key2, "key mismatch");
            assert_eq!(tr, tr2, "tr mismatch");
            assert_eq!(s1, s1_2, "s1 mismatch");
            assert_eq!(s2, s2_2, "s2 mismatch");
            assert_eq!(t0, t0_2, "t0 mismatch");

            let mut sk2 = [0u8; SECRETKEYBYTES];
            pack_sk(&mut sk2, &rho2, &tr2, &key2, &t0_2, &s1_2, &s2_2);
            assert_eq!(&sk[..], &sk2[..], "sk re-pack mismatch");
        }
    }

    /// Build a valid hint vector with `total` ones spread across the K polys, in
    /// strictly ascending per-poly order, using deterministic indices.
    fn make_valid_hint(total: usize, rng: &mut Lcg) -> Polyveck {
        assert!(total <= OMEGA);
        let mut h = Polyveck::zero();
        let mut remaining = total;
        for i in 0..K {
            if remaining == 0 {
                break;
            }
            // Put up to a few ones in this poly at distinct ascending indices.
            let here = core::cmp::min(remaining, 1 + (rng.next_u32() as usize % 4));
            // Choose `here` distinct indices in [0, N) and set them.
            let mut chosen = 0;
            let mut idx = (rng.next_u32() as usize) % (N - OMEGA);
            while chosen < here && idx < N {
                if h.vec[i].coeffs[idx] == 0 {
                    h.vec[i].coeffs[idx] = 1;
                    chosen += 1;
                }
                idx += 1 + (rng.next_u32() as usize % 3);
            }
            remaining -= chosen;
        }
        h
    }

    #[test]
    fn sig_pack_unpack_roundtrip() {
        let mut rng = Lcg(0x0f0f_0f0f_1212_3434);
        for trial in 0..64 {
            let c: [u8; CTILDEBYTES] = core::array::from_fn(|_| rng.next_u32() as u8);
            let z = random_z(&mut rng);
            // Vary the hint weight, including the empty and maximal cases.
            let total = match trial {
                0 => 0,
                1 => OMEGA,
                _ => rng.next_u32() as usize % (OMEGA + 1),
            };
            let h = make_valid_hint(total, &mut rng);

            let mut sig = [0u8; SIGNBYTES];
            pack_sig(&mut sig, &c, &z, &h);

            let mut c2 = [0u8; CTILDEBYTES];
            let mut z2 = Polyvecl::zero();
            let mut h2 = Polyveck::zero();
            unpack_sig(&mut c2, &mut z2, &mut h2, &sig).expect("valid sig must unpack");

            assert_eq!(c, c2, "c~ mismatch (trial {trial})");
            assert_eq!(z, z2, "z mismatch (trial {trial})");
            assert_eq!(h, h2, "h mismatch (trial {trial})");

            let mut sig2 = [0u8; SIGNBYTES];
            pack_sig(&mut sig2, &c2, &z2, &h2);
            assert_eq!(&sig[..], &sig2[..], "sig re-pack mismatch (trial {trial})");
        }
    }

    /// Offset of the hint region inside the packed signature.
    const HINT_OFF: usize = CTILDEBYTES + L * POLYZ_PACKEDBYTES;

    /// A baseline valid signature (a few hint ones) we then mutate per test.
    fn baseline_sig() -> [u8; SIGNBYTES] {
        let mut rng = Lcg(0xa5a5_5a5a_3c3c_c3c3);
        let c: [u8; CTILDEBYTES] = core::array::from_fn(|_| rng.next_u32() as u8);
        let z = random_z(&mut rng);
        let h = make_valid_hint(10, &mut rng);
        let mut sig = [0u8; SIGNBYTES];
        pack_sig(&mut sig, &c, &z, &h);
        sig
    }

    #[allow(clippy::result_unit_err)]
    fn try_unpack(sig: &[u8; SIGNBYTES]) -> Result<(), ()> {
        let mut c = [0u8; CTILDEBYTES];
        let mut z = Polyvecl::zero();
        let mut h = Polyveck::zero();
        unpack_sig(&mut c, &mut z, &mut h, sig)
    }

    #[test]
    fn rejects_count_above_omega() {
        // Check 1: a per-poly running count exceeding OMEGA must be rejected.
        let mut sig = baseline_sig();
        sig[HINT_OFF + OMEGA] = (OMEGA + 1) as u8; // count for poly 0
        assert!(try_unpack(&sig).is_err(), "count > OMEGA must reject");
    }

    #[test]
    fn rejects_non_monotone_counts() {
        // Check 1: counts must be monotone non-decreasing. Make poly 0's count
        // large (but <= OMEGA) and poly 1's smaller -> cnt < k for poly 1.
        let mut rng = Lcg(0x7777_8888_9999_aaaa);
        let c: [u8; CTILDEBYTES] = core::array::from_fn(|_| rng.next_u32() as u8);
        let z = random_z(&mut rng);
        // 5 ones all in poly 0, ascending; poly 0 count = 5.
        let mut h = Polyveck::zero();
        for (set, idx) in (0..5).map(|j| (true, 3 + j * 7)) {
            if set {
                h.vec[0].coeffs[idx] = 1;
            }
        }
        let mut sig = [0u8; SIGNBYTES];
        pack_sig(&mut sig, &c, &z, &h);
        // Now corrupt poly 1's count to 3 (< running k = 5) -> reject.
        sig[HINT_OFF + OMEGA + 1] = 3;
        assert!(try_unpack(&sig).is_err(), "non-monotone count must reject");
    }

    #[test]
    fn rejects_non_ascending_indices() {
        // Check 2: indices within a poly's run must be strictly ascending.
        let mut rng = Lcg(0xbbbb_cccc_dddd_eeee);
        let c: [u8; CTILDEBYTES] = core::array::from_fn(|_| rng.next_u32() as u8);
        let z = random_z(&mut rng);
        // Three ones in poly 0 at indices 10, 20, 30; count = 3.
        let mut h = Polyveck::zero();
        h.vec[0].coeffs[10] = 1;
        h.vec[0].coeffs[20] = 1;
        h.vec[0].coeffs[30] = 1;
        let mut sig = [0u8; SIGNBYTES];
        pack_sig(&mut sig, &c, &z, &h);
        // Swap first two indices so they are out of order (20, 10, 30).
        sig.swap(HINT_OFF, HINT_OFF + 1);
        assert!(try_unpack(&sig).is_err(), "descending indices must reject");

        // Also reject an exact duplicate (10, 10, 30): equal is not strictly
        // ascending.
        let mut sig2 = [0u8; SIGNBYTES];
        pack_sig(&mut sig2, &c, &z, &h);
        sig2[HINT_OFF + 1] = sig2[HINT_OFF]; // duplicate the first index
        assert!(try_unpack(&sig2).is_err(), "duplicate indices must reject");
    }

    #[test]
    fn rejects_nonzero_trailing() {
        // Check 3: unused index bytes (past the final count) must be zero.
        let mut sig = baseline_sig();
        // The baseline has 10 ones, so byte at HINT_OFF + 10 .. OMEGA is unused
        // and zero. Poke one of them.
        sig[HINT_OFF + OMEGA - 1] = 0xff;
        assert!(
            try_unpack(&sig).is_err(),
            "nonzero trailing byte must reject"
        );
    }

    #[test]
    fn accepts_baseline() {
        // Sanity: the unmutated baseline must unpack cleanly (guards against a
        // rejection check that is too aggressive).
        let sig = baseline_sig();
        assert!(try_unpack(&sig).is_ok(), "valid baseline must accept");
    }
}
