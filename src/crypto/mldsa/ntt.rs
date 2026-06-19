//! Number-theoretic transform and its inverse, plus the zeta table. Mirrors
//! `ntt.c`, ported verbatim from the PQClean `ml-dsa-87/clean` reference that
//! `pqcrypto-mldsa 0.1.2` compiles.
//!
//! The forward [`ntt`] maps a polynomial in `R_q = Z_q[X]/(X^256+1)` to the NTT
//! (point-value) domain in bit-reversed order; [`invntt_tomont`] inverts it and
//! folds in a Montgomery factor of `2^32`, exactly as the C does.
//!
//! Constant-time (plan §5): `ZETAS` is indexed ONLY by the loop counter `k`,
//! never by coefficient data, and the butterflies are straight-line arithmetic.
//! These run on secret coefficients in the signing path, so they must stay
//! data-oblivious — do not add a value- or sign-dependent branch.
//!
//! Rust vs C integer semantics (plan §5): the C relies on two's-complement wrap
//! of `int32_t` adds/subs that are proven in-range; Rust debug builds panic on
//! overflow. Each add/sub the C performs is written here with `wrapping_*` so the
//! result is bit-identical to C and never panics. (Within the documented
//! preconditions the values do stay in range; `wrapping_*` just makes the port
//! faithful and robust at the edge.)

use super::params::N;
use super::reduce::montgomery_reduce;

/// Powers of the 512th root of unity in Montgomery form and bit-reversed order,
/// **copied verbatim** from `ntt.c:6-39` (the `static const int32_t zetas[N]`
/// table). `ZETAS[i] = center(ROOT_OF_UNITY^brv8(i) * 2^32 mod Q)`.
///
/// `ZETAS[0]` is `0` in the reference (an unused slot: the NTT loops start at
/// `++k` / `--k`, so index 0 is never read). The `re_derive_zetas` self-test
/// below regenerates every entry from `ROOT_OF_UNITY` and asserts equality with
/// this table (special-casing the unused index 0) to catch a single-digit typo.
// One wrong entry here silently corrupts every signature; this is a literal
// transcription of the C table — do NOT reformat the values.
pub const ZETAS: [i32; N] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];

/// `mont^2 / 256` (`ntt.c:80`): the inverse-NTT final scale that folds the
/// `1/256` of the inverse transform together with the Montgomery factor.
const F: i32 = 41978;

/// Forward NTT, in-place (`ntt.c`, `PQCLEAN_MLDSA87_CLEAN_ntt`). No modular
/// reduction is performed after additions or subtractions; the output is in
/// bit-reversed order and in the NTT domain.
pub fn ntt(a: &mut [i32; N]) {
    let mut k: usize = 0;
    let mut len: usize = 128;
    while len > 0 {
        let mut start: usize = 0;
        while start < N {
            k += 1; // C: zeta = zetas[++k];
            let zeta = ZETAS[k];
            let mut j = start;
            while j < start + len {
                // t = montgomery_reduce((int64_t)zeta * a[j + len]);
                let t = montgomery_reduce(zeta as i64 * a[j + len] as i64);
                // a[j + len] = a[j] - t;  a[j] = a[j] + t;  (no reduction)
                a[j + len] = a[j].wrapping_sub(t);
                a[j] = a[j].wrapping_add(t);
                j += 1;
            }
            start = j + len;
        }
        len >>= 1;
    }
}

/// Inverse NTT with multiplication by the Montgomery factor `2^32`, in-place
/// (`ntt.c`, `PQCLEAN_MLDSA87_CLEAN_invntt_tomont`). No modular reductions after
/// additions/subtractions; input coefficients must be smaller than `Q` in
/// absolute value, and outputs are smaller than `Q` in absolute value.
pub fn invntt_tomont(a: &mut [i32; N]) {
    let mut k: usize = 256;
    let mut len: usize = 1;
    while len < N {
        let mut start: usize = 0;
        while start < N {
            k -= 1; // C: zeta = -zetas[--k];
            let zeta = -ZETAS[k];
            let mut j = start;
            while j < start + len {
                // Gentleman-Sande butterfly.
                let t = a[j];
                a[j] = t.wrapping_add(a[j + len]);
                a[j + len] = t.wrapping_sub(a[j + len]);
                a[j + len] = montgomery_reduce(zeta as i64 * a[j + len] as i64);
                j += 1;
            }
            start = j + len;
        }
        len <<= 1;
    }

    // Final scale by f = mont^2 / 256.
    for x in a.iter_mut() {
        *x = montgomery_reduce(F as i64 * *x as i64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mldsa::params::{Q, ROOT_OF_UNITY};

    /// 8-bit bit-reversal, matching the index permutation baked into `ZETAS`.
    fn brv8(i: usize) -> u32 {
        let mut r = 0u32;
        for b in 0..8 {
            r |= (((i >> b) & 1) as u32) << (7 - b);
        }
        r
    }

    /// `base^exp mod Q` (modular exponentiation in `i64`, no overflow concern
    /// since each factor is `< Q < 2^23`).
    fn pow_mod(base: i64, mut exp: u64, q: i64) -> i64 {
        let mut b = base % q;
        if b < 0 {
            b += q;
        }
        let mut acc = 1i64;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = (acc * b) % q;
            }
            b = (b * b) % q;
            exp >>= 1;
        }
        acc
    }

    /// Map a residue into the centered representative `(-Q/2, Q/2]` that the C
    /// table stores.
    fn center(mut x: i64, q: i64) -> i64 {
        x %= q;
        if x < 0 {
            x += q;
        }
        if x > q / 2 {
            x -= q;
        }
        x
    }

    /// Re-derive the whole `ZETAS` table from `ROOT_OF_UNITY` (independently of
    /// the copied literals) and assert equality, so a single-digit transcription
    /// error in the table fails the test (plan §2.3).
    ///
    /// `ZETAS[i] = center(ROOT_OF_UNITY^brv8(i) * 2^32 mod Q)`. Index 0 is the
    /// reference's unused slot, hardcoded to `0` (the NTT loops never read it),
    /// so it is checked against `0` rather than the derived `mont` value.
    //
    // `i` both indexes `ZETAS` and drives the bit-reversal `brv8(i)`, so the
    // indexed loop is the substance of the re-derivation; enumerate would hide it.
    #[allow(clippy::needless_range_loop)]
    #[test]
    fn re_derive_zetas() {
        let q = Q as i64;
        let mont = (1i64 << 32) % q; // 2^32 mod Q

        assert_eq!(
            ZETAS[0], 0,
            "ZETAS[0] must be the reference's unused 0 slot"
        );

        for i in 1..N {
            let e = brv8(i) as u64;
            let want = center(pow_mod(ROOT_OF_UNITY as i64, e, q) * mont, q);
            assert_eq!(
                ZETAS[i] as i64, want,
                "ZETAS[{i}] = {} disagrees with re-derived {want}",
                ZETAS[i]
            );
        }
    }

    /// Sanity: every table entry (except the unused slot 0) is a centered,
    /// nonzero representative within `(-Q, Q)`. A redundant guard in case a typo
    /// somehow slipped past the re-derivation.
    #[test]
    fn zetas_are_centered_field_elements() {
        for (i, &z) in ZETAS.iter().enumerate() {
            assert!(z > -Q && z < Q, "ZETAS[{i}] = {z} out of (-Q, Q)");
            if i != 0 {
                assert_ne!(z, 0, "ZETAS[{i}] unexpectedly zero");
            }
        }
    }

    /// End-to-end NTT consistency: `invntt_tomont(ntt(p))` must equal
    /// `p * 2^32 mod^± Q` coefficient-wise.
    ///
    /// Reason for the `2^32`: the forward `ntt` introduces no net Montgomery
    /// factor (each butterfly multiplies by a Montgomery-form zeta and then
    /// `montgomery_reduce` divides by `2^32`, so the point values are the plain
    /// evaluations), while `invntt_tomont` deliberately folds in one extra factor
    /// of `2^32` (its name says `_tomont`). So the round trip scales `p` by
    /// `2^32`. Residues are compared mod `Q`, which sidesteps representative
    /// choice.
    #[test]
    fn ntt_invntt_roundtrip_scales_by_mont() {
        let q = Q as i64;
        let mont = (1i64 << 32) % q;

        // A few deterministic pseudo-random polynomials, coefficients in [0, Q).
        let mut s: u64 = 0xC0FF_EE12_3456_789A;
        for _ in 0..64 {
            let mut p = [0i32; N];
            for c in p.iter_mut() {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *c = (s % Q as u64) as i32;
            }
            let orig = p;

            ntt(&mut p);
            invntt_tomont(&mut p);

            for j in 0..N {
                let got = ((p[j] as i64 % q) + q) % q;
                let want = ((orig[j] as i64 * mont) % q + q) % q;
                assert_eq!(got, want, "coeff {j}: round-trip residue mismatch");
            }
        }
    }
}
