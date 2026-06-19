//! ML-DSA-87 parameters. Mirrors `ml-dsa-87/clean/params.h` (+ sizes from
//! `api.h`), taken verbatim from the PQClean *clean* reference that
//! `pqcrypto-mldsa 0.1.2` compiles.
//!
//! These are the ML-DSA-87 values ONLY — never cross-wire ML-DSA-44/65 numbers
//! (`GAMMA1 = 2^19` not `2^17`; `GAMMA2 = (Q-1)/32` not `/88`; `CTILDEBYTES = 64`
//! not `32`; `POLYW1_PACKEDBYTES = 128` for 4-bit w1, not 6-bit).
//!
//! Type choices match how each value is used in the C port:
//! - byte/index/length/loop-bound constants are `usize` (array sizing, slicing);
//! - modular-arithmetic constants (`Q`, `GAMMA1`, `GAMMA2`, `BETA`, `ETA`,
//!   `ROOT_OF_UNITY`) are `i32`, matching the `int32_t`/`int64_t` arithmetic of
//!   `reduce.c`/`ntt.c`/`rounding.c` (cast to `i64`/`u64` at the call site as the
//!   C does, e.g. `(a as i64) * (Q as i64)`).

// --- params.h:6-13 ----------------------------------------------------------

/// Seed length in bytes (params.h:6). `rho`, `key`, `xi`, ACVP `seed`.
pub const SEEDBYTES: usize = 32;
/// Collision-resistant hash output length (params.h:7). Length of `mu` and
/// `rhoprime`.
pub const CRHBYTES: usize = 64;
/// `tr = H(pk)` length in bytes (params.h:8).
pub const TRBYTES: usize = 64;
/// Hedging nonce length in bytes (params.h:9). `0^32` for the deterministic
/// (ACVP) path.
pub const RNDBYTES: usize = 32;
/// Polynomial degree / ring dimension (params.h:10). `R_q = Z_q[X]/(X^256+1)`.
pub const N: usize = 256;
/// Modulus `q = 2^23 - 2^13 + 1` (params.h:11).
pub const Q: i32 = 8380417;
/// Dropped low-order bits in `power2round` (params.h:12).
pub const D: usize = 13;
/// 512th root of unity generating the NTT `ZETAS` table (params.h:13). Used only
/// to re-derive/validate the table in `ntt.rs`; the table itself lives there.
pub const ROOT_OF_UNITY: i32 = 1753;

// --- params.h:15-23 ---------------------------------------------------------

/// Number of rows of the public matrix `A` / length of `t`, `s2`, `w` (params.h:15).
pub const K: usize = 8;
/// Number of columns of `A` / length of `s1`, `y`, `z` (params.h:16).
pub const L: usize = 7;
/// Coefficient range of the secret vectors `s1`, `s2`: `[-ETA, ETA]` (params.h:17).
pub const ETA: i32 = 2;
/// Number of `+/-1` coefficients in the challenge `c` (params.h:18).
pub const TAU: usize = 60;
/// Rejection bound margin `BETA = TAU * ETA` (params.h:19).
pub const BETA: i32 = 120;
/// `gamma1 = 2^19`, the coefficient range of the masking vector `y` (params.h:20).
pub const GAMMA1: i32 = 1 << 19;
/// `gamma2 = (q-1)/32`, the low-order rounding range (params.h:21).
pub const GAMMA2: i32 = (Q - 1) / 32;
/// Maximum total number of `1`s in the hint `h` (params.h:22).
pub const OMEGA: usize = 75;
/// Challenge-hash (`c~`) length in bytes, `= lambda/4` with `lambda = 256`
/// (params.h:23).
pub const CTILDEBYTES: usize = 64;

// --- params.h:26-34 : per-poly packed sizes ---------------------------------

/// Packed `t1` size: 10 bits/coeff over 256 coeffs (params.h:26).
pub const POLYT1_PACKEDBYTES: usize = 320;
/// Packed `t0` size: 13 bits/coeff (params.h:27).
pub const POLYT0_PACKEDBYTES: usize = 416;
/// Packed hint vector size, `OMEGA + K` (params.h:28).
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
/// Packed `z` size: 20 bits/coeff for `gamma1 = 2^19` (params.h:30).
pub const POLYZ_PACKEDBYTES: usize = 640;
/// Packed `w1` size: 4 bits/coeff (ML-DSA-87 specific; params.h:32).
pub const POLYW1_PACKEDBYTES: usize = 128;
/// Packed `eta`-range poly size: 3 bits/coeff (params.h:34).
pub const POLYETA_PACKEDBYTES: usize = 96;

// --- params.h:36-42 / api.h:7-9 : top-level byte sizes ----------------------

/// Public-key length in bytes: `SEEDBYTES + K*POLYT1_PACKEDBYTES`
/// (params.h:36 == api.h:7 == 2592).
pub const PUBLICKEYBYTES: usize = SEEDBYTES + K * POLYT1_PACKEDBYTES;
/// Secret-key length in bytes:
/// `2*SEEDBYTES + TRBYTES + L*POLYETA_PACKEDBYTES + K*POLYETA_PACKEDBYTES + K*POLYT0_PACKEDBYTES`
/// (params.h:37 == api.h:8 == 4896).
pub const SECRETKEYBYTES: usize = 2 * SEEDBYTES
    + TRBYTES
    + L * POLYETA_PACKEDBYTES
    + K * POLYETA_PACKEDBYTES
    + K * POLYT0_PACKEDBYTES;
/// Signature length in bytes:
/// `CTILDEBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES`
/// (params.h:42 == api.h:9 == 4627).
pub const SIGNBYTES: usize = CTILDEBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;

// --- Derived rejection bounds (plan §2.1) -----------------------------------

/// `gamma1 - beta = 524168`. Norm bound checked against `z` in the signing loop.
pub const GAMMA1_MINUS_BETA: i32 = GAMMA1 - BETA;
/// `gamma2 - beta = 261768`. Norm bound checked against `w0` (and `ct0`) in the
/// signing loop.
pub const GAMMA2_MINUS_BETA: i32 = GAMMA2 - BETA;

// --- Compile-time self-check (plan Step 1 "Verify") -------------------------
// Pin the three top-level sizes against api.h's literal values so a mistake in
// any contributing constant (or in the formulas above) fails the build.
const _: () = assert!(PUBLICKEYBYTES == 2592);
const _: () = assert!(SECRETKEYBYTES == 4896);
const _: () = assert!(SIGNBYTES == 4627);

#[cfg(test)]
mod tests {
    use super::*;

    /// Every constant against its verbatim value in `params.h` / `api.h`.
    /// A redundant-but-cheap guard: catches an accidental edit to any literal.
    #[test]
    fn constants_match_reference() {
        // params.h:6-13
        assert_eq!(SEEDBYTES, 32);
        assert_eq!(CRHBYTES, 64);
        assert_eq!(TRBYTES, 64);
        assert_eq!(RNDBYTES, 32);
        assert_eq!(N, 256);
        assert_eq!(Q, 8380417);
        assert_eq!(Q, (1 << 23) - (1 << 13) + 1); // q = 2^23 - 2^13 + 1
        assert_eq!(D, 13);
        assert_eq!(ROOT_OF_UNITY, 1753);

        // params.h:15-23
        assert_eq!(K, 8);
        assert_eq!(L, 7);
        assert_eq!(ETA, 2);
        assert_eq!(TAU, 60);
        assert_eq!(BETA, 120);
        assert_eq!(BETA, TAU as i32 * ETA); // beta = tau * eta
        assert_eq!(GAMMA1, 524288);
        assert_eq!(GAMMA1, 1 << 19); // ML-DSA-87 uses 2^19, NOT 2^17
        assert_eq!(GAMMA2, 261888);
        assert_eq!(GAMMA2, (Q - 1) / 32); // ML-DSA-87 uses /32, NOT /88
        assert_eq!(OMEGA, 75);
        assert_eq!(CTILDEBYTES, 64); // lambda/4 with lambda=256, NOT 32

        // params.h:26-34
        assert_eq!(POLYT1_PACKEDBYTES, 320);
        assert_eq!(POLYT0_PACKEDBYTES, 416);
        assert_eq!(POLYVECH_PACKEDBYTES, 83); // OMEGA + K = 75 + 8
        assert_eq!(POLYZ_PACKEDBYTES, 640);
        assert_eq!(POLYW1_PACKEDBYTES, 128); // 4-bit w1
        assert_eq!(POLYETA_PACKEDBYTES, 96);

        // params.h:36-42 / api.h:7-9
        assert_eq!(PUBLICKEYBYTES, 2592);
        assert_eq!(SECRETKEYBYTES, 4896);
        assert_eq!(SIGNBYTES, 4627);

        // Derived bounds (plan §2.1)
        assert_eq!(GAMMA1_MINUS_BETA, 524168);
        assert_eq!(GAMMA2_MINUS_BETA, 261768);
    }
}
