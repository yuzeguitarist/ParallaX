//! Per-coefficient rounding helpers: `power2round`, `decompose`, `make_hint`,
//! `use_hint`. Mirrors `rounding.c`, ported verbatim from the PQClean
//! `ml-dsa-87/clean` reference that `pqcrypto-mldsa 0.1.2` compiles.
//!
//! Constant-time (plan §5): every function is branchless straight-line
//! arithmetic. In particular `decompose` centers `a0` with the sign-mask
//! `a0 -= (((Q-1)/2 - a0) >> 31) & Q` rather than an `if`, so these are safe to
//! run on secret coefficients in the signing path.
//!
//! Rust vs C integer semantics (plan §5): the C relies on two's-complement wrap
//! of `int32_t` ops that are proven in-range; Rust debug builds panic on
//! overflow. Each op the C performs as a wrapping `int32_t` op is written with
//! the explicit `wrapping_*` method here, so the result is bit-identical to C for
//! every in-spec input and never panics. (Within each function's documented
//! precondition the values stay in range; `wrapping_*` just makes the port
//! faithful and robust at the edge.) The intermediates are sized exactly as the
//! C proves them: `decompose`'s `a1*1025 + (1<<21)` peaks below `2^31`, so plain
//! `i32` suffices, matching `rounding.c`.

use super::params::{D, GAMMA2, Q};

/// For a standard representative `a`, compute `(a1, a0)` with
/// `a mod^+ Q = a1*2^D + a0` and `-2^{D-1} < a0 <= 2^{D-1}` (`rounding.c:17-23`).
/// Returns `(a1, a0)` (C returns `a1` and writes `a0` through a pointer).
#[inline]
pub fn power2round(a: i32) -> (i32, i32) {
    // a1 = (a + (1 << (D - 1)) - 1) >> D;
    let a1 = (a.wrapping_add((1 << (D - 1)) - 1)) >> D;
    // *a0 = a - (a1 << D);
    let a0 = a.wrapping_sub(a1 << D);
    (a1, a0)
}

/// For a standard representative `a`, compute high/low bits `(a1, a0)` with
/// `a mod^+ Q = a1*ALPHA + a0`, `-ALPHA/2 < a0 <= ALPHA/2`, except for the
/// wraparound case `a1 = (Q-1)/ALPHA` where `a1 = 0` and `a0 < 0`
/// (`rounding.c:39-49`, `ALPHA = 2*GAMMA2`). Returns `(a1, a0)`.
#[inline]
pub fn decompose(a: i32) -> (i32, i32) {
    // a1  = (a + 127) >> 7;
    let mut a1 = (a.wrapping_add(127)) >> 7;
    // a1  = (a1 * 1025 + (1 << 21)) >> 22;
    a1 = (a1.wrapping_mul(1025).wrapping_add(1 << 21)) >> 22;
    // a1 &= 15;   (wraps a1 = 16 -> 0, ML-DSA-87 specific)
    a1 &= 15;

    // *a0  = a - a1 * 2 * GAMMA2;
    let mut a0 = a.wrapping_sub(a1.wrapping_mul(2).wrapping_mul(GAMMA2));
    // *a0 -= (((Q - 1) / 2 - *a0) >> 31) & Q;   (branchless centering)
    // The sign mask `(... >> 31)` is fed through `black_box` so the optimizer
    // cannot recognize it as `a0 > (Q-1)/2` and lower the centering to a branch
    // (constant-time defense-in-depth, plan §5). `black_box` is a value-level
    // identity, so `a0` — and every byte of the ACVP output — is unchanged.
    let mask = core::hint::black_box((((Q - 1) / 2).wrapping_sub(a0)) >> 31) & Q;
    a0 = a0.wrapping_sub(mask);
    (a1, a0)
}

/// Hint bit: `1` iff the low bits `a0` overflow into the high bits `a1`
/// (`rounding.c:62-68`). The boundary is asymmetric: `+GAMMA2` is NOT a hint;
/// `-GAMMA2` is a hint only when `a1 != 0`.
///
/// This is sanctioned as variable-time on the reference's terms: it is only ever
/// applied to the public hint polynomial during signing/verification, never to
/// secret coefficients.
#[inline]
pub fn make_hint(a0: i32, a1: i32) -> u32 {
    // Kept as the literal `rounding.c:63` predicate (NOT rewritten to a
    // `RangeInclusive::contains`) so this line diffs 1:1 against the C reference;
    // the asymmetric `-GAMMA2 && a1 != 0` arm is part of the same condition.
    #[allow(clippy::manual_range_contains)]
    if a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0) {
        1
    } else {
        0
    }
}

/// Correct the high bits of `a` according to the `hint` bit (`rounding.c:80-92`).
/// With `hint == 0` returns `a1`; otherwise steps `a1` by `±1` (depending on the
/// sign of `a0`) modulo 16 via `& 15`.
///
/// `(a1 - 1) & 15` in Rust evaluates in `i32` then masks, so for `a1 = 0` it
/// yields `(-1i32) & 15 == 15`, matching the C wrap.
#[inline]
pub fn use_hint(a: i32, hint: u32) -> i32 {
    let (a1, a0) = decompose(a);
    if hint == 0 {
        return a1;
    }
    if a0 > 0 {
        (a1 + 1) & 15
    } else {
        (a1 - 1) & 15
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mldsa::params::N;

    /// `a mod^+ Q` via `i128`, the trusted reference for the rounding identities.
    fn modp(a: i64) -> i32 {
        let q = Q as i64;
        let mut r = (a as i128 % q as i128) as i64;
        if r < 0 {
            r += q;
        }
        r as i32
    }

    /// `power2round`: reconstruct `a == a1*2^D + a0 (mod Q)` and check the bound
    /// `-2^{D-1} < a0 <= 2^{D-1}`, over all standard representatives.
    #[test]
    fn power2round_identity_and_bound() {
        let half = 1i32 << (D - 1); // 2^{D-1} = 4096
        for a in 0..Q {
            let (a1, a0) = power2round(a);
            // Bound on a0: (-2^{D-1}, 2^{D-1}].
            assert!(
                a0 > -half && a0 <= half,
                "power2round({a}): a0 = {a0} out of (-{half}, {half}]"
            );
            // Reconstruction modulo Q.
            let recon = (a1 as i64) * (1i64 << D) + a0 as i64;
            assert_eq!(modp(recon), a, "power2round({a}) reconstruction failed");
        }
    }

    /// `decompose`: reconstruct `a == a1*ALPHA + a0 (mod Q)`, check `a1 in [0,15]`
    /// and the centered-a0 bound including the documented wraparound exception,
    /// over all standard representatives.
    #[test]
    fn decompose_identity_and_bounds() {
        let alpha = 2 * GAMMA2; // ALPHA = 2*GAMMA2 = 523776
        for a in 0..Q {
            let (a1, a0) = decompose(a);
            assert!(
                (0..=15).contains(&a1),
                "decompose({a}): a1 = {a1} not in [0,15]"
            );

            // Reconstruction modulo Q.
            let recon = (a1 as i64) * (alpha as i64) + a0 as i64;
            assert_eq!(modp(recon), a, "decompose({a}) reconstruction failed");

            // a0 bound. The normal case is -ALPHA/2 < a0 <= ALPHA/2; the
            // wraparound case (a1 forced to 0) gives -ALPHA/2 <= a0 < 0.
            if a1 == 0 && a0 < 0 {
                assert!(
                    a0 >= -(alpha / 2),
                    "decompose({a}): wraparound a0 = {a0} < -ALPHA/2"
                );
            } else {
                assert!(
                    a0 > -(alpha / 2) && a0 <= alpha / 2,
                    "decompose({a}): a0 = {a0} out of (-ALPHA/2, ALPHA/2]"
                );
            }
        }
    }

    /// `make_hint` / `use_hint` recover the true high bits, checked against an
    /// INDEPENDENT reference (not the module's own `decompose`).
    ///
    /// The FIPS 204 contract this pins (as the signing/verification rely on it):
    /// for a value `w` and a small correction `z` with `|z| <= GAMMA2`, with
    /// `(r1, r0) = decompose(w)`, the hint `make_hint(r0 + z, r1)` lets
    /// `use_hint(w + z, hint)` recover `HighBits(w)` — where `HighBits(w)` is
    /// computed here directly from the spec in `i128` (`highbits_ref`), so a
    /// `make_hint` boundary regression (dropping the `a1 != 0` guard, or `>` vs
    /// `>=`) makes the recovered value disagree with the reference and turns this
    /// RED. The sweep also asserts BOTH hint branches actually fire (counts > 0)
    /// and explicitly drives the asymmetric `a0 == -GAMMA2` boundary on both the
    /// `a1 == 0` (no hint) and `a1 != 0` (hint) sides.
    #[test]
    fn make_use_hint_recover_high_bits() {
        // Independent HighBits(w): spec Decompose_q in i128, NOT this module's
        // `decompose`. alpha = 2*GAMMA2; r0 is w centered mod alpha; the
        // wraparound r1 = (Q-1)/alpha collapses to 0 (matching `& 15`).
        let alpha = 2 * GAMMA2;
        fn highbits_ref(w: i32, alpha: i32) -> i32 {
            let rp = modp(w as i64); // w mod^+ Q, in [0, Q)
            let mut r0 = rp % alpha; // [0, alpha)
            if r0 > alpha / 2 {
                r0 -= alpha; // center into (-alpha/2, alpha/2]
            }
            if rp - r0 == Q - 1 {
                0 // wraparound case: high bits wrap to 0
            } else {
                (rp - r0) / alpha
            }
        }

        let mut hint0_seen = 0u64;
        let mut hint1_seen = 0u64;
        let mut check = |w: i32, z: i32| {
            let (r1, r0) = decompose(w);
            // Reference high bits of w, computed independently of `decompose`.
            assert_eq!(
                r1,
                highbits_ref(w, alpha),
                "decompose r1 != reference for w={w}"
            );
            // make_hint sees the low part AFTER adding the correction z (which may
            // push it out of the centered range — exactly what the hint exists
            // for), with the ORIGINAL high part r1.
            let hint = make_hint(r0 + z, r1);
            // use_hint must recover the original high bits HighBits(w).
            let recovered = use_hint(w.wrapping_add(z), hint);
            assert_eq!(
                recovered,
                highbits_ref(w, alpha),
                "use_hint(w+z, make_hint(r0+z, r1)) != HighBits(w): w={w} z={z} hint={hint}"
            );
            if hint == 0 {
                hint0_seen += 1;
            } else {
                hint1_seen += 1;
            }
        };

        // Deterministic sweep with a small signed perturbation in [-GAMMA2, GAMMA2].
        let mut s: u64 = 0x5151_5151_2727_2727;
        for _ in 0..300_000 {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let w = (s % Q as u64) as i32; // standard representative
            let z = ((s >> 40) as i32 % (2 * GAMMA2 + 1)) - GAMMA2;
            check(w, z);
        }

        // Explicit asymmetric-boundary inputs: w = r1*alpha decomposes to
        // (r1, 0), so z = -GAMMA2 makes a0 == -GAMMA2 exactly. r1 == 0 must NOT
        // set the hint (the `a1 != 0` guard); r1 in [1,15] MUST set it.
        for r1 in 0..16i32 {
            let w = r1 * alpha;
            check(w, -GAMMA2); // a0 == -GAMMA2, a1 == r1
            check(w, GAMMA2); // a0 == +GAMMA2 boundary (never a hint)
        }

        // Both branches of the hint must have been exercised, or the test would
        // be vacuous (the old version only ever hit the hint==0 identity path).
        assert!(hint0_seen > 0, "hint==0 branch never exercised");
        assert!(hint1_seen > 0, "hint==1 branch never exercised");
    }

    /// `use_hint` matches the literal `rounding.c` branch table for the explicit
    /// modular-wrap edges `a1 = 0` (→ 15) and `a1 = 15` (→ 0).
    #[test]
    fn use_hint_modular_wrap_edges() {
        // Find an `a` whose decompose gives a1 == 0 and a0 <= 0 (so the hint
        // branch takes (a1-1)&15 == 15), and one with a1 == 15, a0 > 0
        // (→ (a1+1)&15 == 0). Scan standard representatives.
        let mut saw_zero_wrap = false;
        let mut saw_fifteen_wrap = false;
        for a in 0..Q {
            let (a1, a0) = decompose(a);
            if a1 == 0 && a0 <= 0 {
                assert_eq!(use_hint(a, 1), 15, "a1=0,a0<=0 must wrap to 15 at a={a}");
                saw_zero_wrap = true;
            }
            if a1 == 15 && a0 > 0 {
                assert_eq!(use_hint(a, 1), 0, "a1=15,a0>0 must wrap to 0 at a={a}");
                saw_fifteen_wrap = true;
            }
            if saw_zero_wrap && saw_fifteen_wrap {
                break;
            }
        }
        assert!(
            saw_zero_wrap && saw_fifteen_wrap,
            "did not exercise both wrap edges"
        );
    }

    /// Guard that the module's `N` import is the ring dimension the C uses; keeps
    /// the rounding tests anchored to the same params as `poly.rs`.
    #[test]
    fn ring_dimension_is_256() {
        assert_eq!(N, 256);
    }
}
