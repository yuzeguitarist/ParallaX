//! Montgomery / Barrett-style modular reductions mod `Q`. Mirrors `reduce.c`
//! (and the `MONT`/`QINV` macros from `reduce.h`), ported verbatim from the
//! PQClean `ml-dsa-87/clean` reference.
//!
//! All four functions are straight-line arithmetic with no secret-dependent
//! branch, index, or value-dependent timing, as required for the signing path
//! (plan §5): `caddq` uses the sign-mask `a += (a >> 31) & Q` rather than
//! `if a < 0`. They are therefore safe to call on secret coefficients.
//!
//! Rust vs C integer semantics (plan §5): the C relies on two's-complement wrap
//! within proven bounds, but Rust debug builds panic on overflow. Each operation
//! that the C performs as a wrapping `int32_t`/`int64_t` op is written with the
//! explicit `wrapping_*` method and explicit casts here, so the result is
//! bit-identical to C for every in-spec input and never panics. (Within each
//! function's documented precondition the values actually stay in range, but the
//! `wrapping_*` calls make that faithful to C and robust at the boundary.)

use super::params::Q;

/// `2^32 mod Q` (`reduce.h:6`). Not used by `reduce.c` itself — it is consumed by
/// `ntt.c` (the `invntt_tomont` final scale `F = mont^2 / 256`). Kept here, with
/// `QINV`, to mirror `reduce.h` so `ntt.rs` can reference it (build step 4).
pub const MONT: i32 = -4186625;

/// `Q^-1 mod 2^32` (`reduce.h:7`). The Montgomery multiplier used by
/// [`montgomery_reduce`].
pub const QINV: i32 = 58728449;

/// For a field element `a` with `-2^31 * Q <= a <= Q * 2^31`, compute
/// `r ≡ a * 2^-32 (mod Q)` such that `-Q < r < Q` (`reduce.c:15-21`).
///
/// The low 32 bits of `a * QINV` are computed mod `2^32` (hence the `u64`
/// wrapping multiply and the `as i32` truncation, exactly as the C casts through
/// `(int32_t)((uint64_t)a * (uint64_t)QINV)`); the result is the Montgomery
/// reduction word.
#[inline]
pub fn montgomery_reduce(a: i64) -> i32 {
    // t = (int32_t)((uint64_t)a * (uint64_t)QINV);
    let t = (a as u64).wrapping_mul(QINV as u64) as i32;
    // t = (a - (int64_t)t * Q) >> 32;  (arithmetic shift; signed i64 `>>`)
    ((a - (t as i64) * (Q as i64)) >> 32) as i32
}

/// For a field element `a` with `a <= 2^31 - 2^22 - 1`, compute `r ≡ a (mod Q)`
/// such that `-6283008 <= r <= 6283008` (`reduce.c:33-39`).
///
/// NOTE: the output is centered in `[-6283008, 6283008]`, **not** `[0, Q)`; use
/// [`caddq`] (or [`freeze`]) to map to the standard representative.
#[inline]
pub fn reduce32(a: i32) -> i32 {
    // t = (a + (1 << 22)) >> 23;  (arithmetic shift)
    let t = (a.wrapping_add(1 << 22)) >> 23;
    // t = a - t * Q;
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// Add `Q` if the input coefficient is negative (`reduce.c:50-53`).
///
/// Constant-time: `a >> 31` is an arithmetic right shift yielding `0` (for
/// `a >= 0`) or `-1` (all ones, for `a < 0`); `& Q` then adds `0` or `Q`. No
/// branch on the sign of `a`.
#[inline]
pub fn caddq(a: i32) -> i32 {
    // a += (a >> 31) & Q;
    a.wrapping_add((a >> 31) & Q)
}

/// Standard representative `r = a mod^+ Q` for a field element `a`
/// (`reduce.c:65-69`): [`reduce32`] followed by [`caddq`].
#[inline]
pub fn freeze(a: i32) -> i32 {
    caddq(reduce32(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Slow, obviously-correct reference modmul: `(a * b) mod Q` mapped into
    /// `[0, Q)`, computed in `i128` to avoid any overflow concern.
    fn ref_mulmod(a: i64, b: i64) -> i32 {
        let q = Q as i128;
        let mut r = ((a as i128) * (b as i128)) % q;
        if r < 0 {
            r += q;
        }
        r as i32
    }

    /// `a mod^+ Q` via `i128`, the trusted reference for the centered reductions.
    fn ref_modp(a: i64) -> i32 {
        let q = Q as i128;
        let mut r = (a as i128) % q;
        if r < 0 {
            r += q;
        }
        r as i32
    }

    /// 2^-32 mod Q, computed independently (modular inverse of 2^32 mod Q) so the
    /// montgomery_reduce check does not reuse any constant under test.
    fn inv_2pow32_modq() -> i64 {
        // Fermat: x^-1 = x^(Q-2) mod Q, Q prime.
        let q = Q as i64;
        let mut base = (1i64 << 32) % q;
        let mut exp = q - 2;
        let mut acc = 1i64;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = (acc * base) % q;
            }
            base = (base * base) % q;
            exp >>= 1;
        }
        acc
    }

    // ---- constants ---------------------------------------------------------

    #[test]
    fn constants_match_reference() {
        // reduce.h:6-7
        assert_eq!(MONT, -4186625);
        assert_eq!(QINV, 58728449);
        // QINV is Q^-1 mod 2^32: (Q * QINV) mod 2^32 == 1.
        assert_eq!((Q as u32).wrapping_mul(QINV as u32), 1);
        // MONT is 2^32 mod Q (as a centered representative): MONT + Q == 2^32 mod Q.
        assert_eq!(ref_modp(MONT as i64), ((1u64 << 32) % (Q as u64)) as i32);
    }

    // ---- montgomery_reduce -------------------------------------------------

    #[test]
    fn montgomery_reduce_range_and_value() {
        let inv = inv_2pow32_modq();
        // Boundary inputs at the precondition edges plus a deterministic sweep.
        let edge = [
            0i64,
            1,
            -1,
            Q as i64,
            -(Q as i64),
            (1i64 << 31) * (Q as i64),    // upper precondition bound
            -((1i64 << 31) * (Q as i64)), // lower precondition bound
            (1i64 << 31) * (Q as i64) - 1,
            -((1i64 << 31) * (Q as i64)) + 1,
        ];
        for &a in &edge {
            check_montgomery(a, inv);
        }
        // Deterministic LCG sweep across the open interior (|a| < 2^31*Q): this
        // is where the strict (-Q, Q) bound must hold and where the algorithm
        // actually operates. The exact endpoints are pinned by `edge` above.
        let mut s: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..200_000 {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Map into [-(2^31*Q - 1), 2^31*Q - 1].
            let span = (1i128 << 31) * (Q as i128) - 1;
            let a = ((s as i128 % (2 * span + 1)) - span) as i64;
            check_montgomery(a, inv);
        }
    }

    fn check_montgomery(a: i64, inv_2pow32: i64) {
        let r = montgomery_reduce(a);
        // The C documents `-Q < r < Q` for `-2^31*Q <= a <= 2^31*Q`. That strict
        // bound holds across the OPEN interval; at the two exact endpoints
        // `a = ±2^31*Q` the reduction can land ON a boundary (verified
        // bit-identical to the C reference: `+2^31*Q -> +Q`, `-2^31*Q -> 0`).
        // These degenerate inputs never occur in the algorithm, where
        // montgomery_reduce only sees products `|zeta * coeff|` far below 2^31*Q.
        // Assert the strict bound in the interior and the inclusive bound at the
        // endpoints; the exact value is pinned by the residue check below.
        let span = (1i64 << 31) * (Q as i64);
        if a.abs() == span {
            assert!(
                (-Q..=Q).contains(&r),
                "montgomery_reduce({a}) = {r} out of [-Q, Q] at boundary"
            );
        } else {
            assert!(
                r > -Q && r < Q,
                "montgomery_reduce({a}) = {r} out of (-Q, Q)"
            );
        }
        // Value: r ≡ a * 2^-32 (mod Q) for every legal input, endpoints included.
        let want = ref_mulmod(a, inv_2pow32);
        assert_eq!(
            ref_modp(r as i64),
            want,
            "montgomery_reduce({a}) wrong residue"
        );
    }

    // ---- reduce32 ----------------------------------------------------------

    #[test]
    fn reduce32_range_and_value() {
        let lo = i32::MIN; // C precondition bounds a from above; sweep the rest.
        let hi = (1i64 << 31) - (1i64 << 22) - 1; // a <= 2^31 - 2^22 - 1
        let edge = [0i32, 1, -1, Q, -Q, Q - 1, -(Q - 1), hi as i32, lo, lo + 1];
        for &a in &edge {
            check_reduce32(a);
        }
        let mut s: u64 = 0x1234_5678_9ABC_DEF0;
        for _ in 0..200_000 {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Map into [i32::MIN, hi].
            let range = (hi - lo as i64) as u64;
            let a = (lo as i64 + (s % (range + 1)) as i64) as i32;
            check_reduce32(a);
        }
    }

    fn check_reduce32(a: i32) {
        let r = reduce32(a);
        assert!(
            (-6_283_008..=6_283_008).contains(&r),
            "reduce32({a}) = {r} out of [-6283008, 6283008]"
        );
        assert_eq!(
            ref_modp(r as i64),
            ref_modp(a as i64),
            "reduce32({a}) wrong residue"
        );
    }

    // ---- caddq / freeze ----------------------------------------------------

    #[test]
    fn caddq_maps_negatives_into_range() {
        // caddq's contract is over reduce32 outputs: [-6283008, 6283008].
        for a in (-6_283_008..=6_283_008).step_by(97) {
            let r = caddq(a);
            if a < 0 {
                assert_eq!(r, a + Q);
            } else {
                assert_eq!(r, a);
            }
            // Residue preserved.
            assert_eq!(ref_modp(r as i64), ref_modp(a as i64));
        }
        // Explicit sign-mask edges.
        assert_eq!(caddq(-1), Q - 1);
        assert_eq!(caddq(0), 0);
        assert_eq!(caddq(-Q), 0);
    }

    #[test]
    fn freeze_is_standard_representative() {
        let hi = (1i64 << 31) - (1i64 << 22) - 1;
        let mut s: u64 = 0xDEAD_BEEF_CAFE_F00D;
        for _ in 0..200_000 {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let a = (i32::MIN as i64 + (s % ((hi - i32::MIN as i64) as u64 + 1)) as i64) as i32;
            let r = freeze(a);
            assert!((0..Q).contains(&r), "freeze({a}) = {r} out of [0, Q)");
            assert_eq!(
                r,
                ref_modp(a as i64),
                "freeze({a}) wrong standard representative"
            );
        }
        // A few explicit edge cases.
        assert_eq!(freeze(0), 0);
        assert_eq!(freeze(-1), Q - 1);
        assert_eq!(freeze(Q), 0);
    }
}
