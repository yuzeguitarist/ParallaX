//! Single polynomial `Poly([i32; N])`: the arithmetic core, the per-coefficient
//! rounding wrappers, the infinity-norm check, and the rejection samplers.
//! Mirrors `poly.c` (the `poly_*` functions up to `poly_chknorm`, plus the
//! samplers `poly_uniform`/`poly_uniform_eta`/`poly_uniform_gamma1`/
//! `poly_challenge`), ported from the PQClean `ml-dsa-87/clean` reference that
//! `pqcrypto-mldsa 0.1.2` compiles.
//!
//! The coefficient bit-packers (`poly{eta,t1,t0,z,w1}_pack`/`_unpack`) are added
//! in the next build step (7); they live in this same file in the finished
//! module, matching the C split, but are out of scope here — except
//! [`Poly::polyz_unpack`], which `poly_uniform_gamma1` (ExpandMask) calls and so
//! must exist now, exactly as `poly.c` defines `polyz_unpack` ahead of its use by
//! both the sampler and `unpack_sig`.
//!
//! Constant-time (plan §5): the arithmetic and rounding wrappers are plain `for`
//! loops over straight-line, branchless per-coefficient ops, so they are safe on
//! secret coefficients in the signing path. `make_hint`/`use_hint` are applied
//! only to the public hint and are documented in `rounding.rs` accordingly.
//! `chknorm` computes the centered absolute value branchlessly (it must not leak
//! the SIGN of a `z` coefficient, which depends on secret `s1`); only *which*
//! coefficient violates the bound may leak, which is secret-independent.
//!
//! Rust vs C integer semantics (plan §5): the C `poly_add`/`poly_sub`/
//! `poly_shiftl` rely on two's-complement wrap of `int32_t` within proven
//! bounds; Rust debug builds panic on overflow. Each such op is written with the
//! explicit `wrapping_*` method here so the result is bit-identical to C and
//! never panics. The reductions/NTT/rounding are delegated to the already-ported
//! `reduce`/`ntt`/`rounding` modules, which apply the same discipline.

use super::fips202::{Shake128Stream, Shake256Stream, SHAKE128_RATE, SHAKE256_RATE};
use super::ntt::{invntt_tomont, ntt};
use super::params::{CTILDEBYTES, ETA, GAMMA1, N, POLYZ_PACKEDBYTES, Q, SEEDBYTES, TAU};
use super::reduce::{caddq, montgomery_reduce, reduce32};
use super::rounding;

/// A polynomial in `R_q = Z_q[X]/(X^256+1)`, i.e. the C `poly { int32_t
/// coeffs[N]; }`. Coefficients are kept as `i32`, in whichever representation the
/// caller's stage requires (standard, centered, or NTT-domain), exactly as in C.
///
/// `coeffs` is `pub(crate)` so `polyvec`/`packing` (later steps) can read and
/// write coefficients the way `polyvec.c`/`packing.c` index `a->coeffs[i]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    pub(crate) coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Poly { coeffs: [0i32; N] }
    }
}

// Secret-bearing polynomials (`y`, `s1`, `s2`, `t0`, and the rejection-loop
// temporaries) are zeroized after use in the signing path (plan §5). `Poly` is a
// plain `Copy + Default` integer array whose zero value is the all-zero
// polynomial, so `DefaultIsZeroes` gives a `Zeroize` that overwrites the
// coefficients with zeros via volatile writes.
impl zeroize::DefaultIsZeroes for Poly {}

impl Poly {
    /// A zero polynomial (all coefficients `0`).
    #[inline]
    pub fn zero() -> Self {
        Poly { coeffs: [0i32; N] }
    }

    /// Inplace reduction of all coefficients to the representative
    /// `[-6283008, 6283008]` (`poly.c` `poly_reduce`).
    #[inline]
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = reduce32(*c);
        }
    }

    /// Add `Q` to every negative coefficient (`poly.c` `poly_caddq`).
    #[inline]
    pub fn caddq(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = caddq(*c);
        }
    }

    /// `self = a + b`, no modular reduction (`poly.c` `poly_add`).
    #[inline]
    pub fn add(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = a.coeffs[i].wrapping_add(b.coeffs[i]);
        }
    }

    /// In-place `self = self + b`, no modular reduction. The C `poly_add` aliases
    /// dest=src safely (`poly_add(&z,&z,&y)`); this mirrors that with an explicit
    /// read-modify-write per coefficient so no Copy temporary of the secret `self`
    /// is spilled (plan §5).
    #[inline]
    pub fn add_assign(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_add(b.coeffs[i]);
        }
    }

    /// `self = a - b`, no modular reduction (`poly.c` `poly_sub`).
    #[inline]
    pub fn sub(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = a.coeffs[i].wrapping_sub(b.coeffs[i]);
        }
    }

    /// In-place `self = self - b`, no modular reduction. Mirrors the C `poly_sub`
    /// aliasing dest=src (`poly_sub(&w0,&w0,&h)`) with an explicit
    /// read-modify-write per coefficient, avoiding a Copy temporary of the secret
    /// `self` (plan §5).
    #[inline]
    pub fn sub_assign(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_sub(b.coeffs[i]);
        }
    }

    /// Multiply by `2^D` without modular reduction (`poly.c` `poly_shiftl`).
    /// Assumes coefficients are less than `2^{31-D}` in absolute value.
    #[inline]
    pub fn shiftl(&mut self) {
        for c in self.coeffs.iter_mut() {
            // C: a->coeffs[i] <<= D;  (wrapping left shift of int32_t)
            *c = c.wrapping_shl(super::params::D as u32);
        }
    }

    /// Inplace forward NTT (`poly.c` `poly_ntt`). Coefficients can grow by `8*Q`
    /// in absolute value.
    #[inline]
    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    /// Inplace inverse NTT and multiplication by `2^32` (`poly.c`
    /// `poly_invntt_tomont`). Input coefficients must be `< Q` in absolute value.
    #[inline]
    pub fn invntt_tomont(&mut self) {
        invntt_tomont(&mut self.coeffs);
    }

    /// Pointwise multiply in NTT domain, then multiply by `2^-32`
    /// (`poly.c` `poly_pointwise_montgomery`): `self[i] = montgomery_reduce(a[i]
    /// * b[i])`.
    #[inline]
    pub fn pointwise_montgomery(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
        }
    }

    /// Per-coefficient `power2round` (`poly.c` `poly_power2round`): writes high
    /// bits into `a1` and low bits into `a0`, both reading from `self`.
    #[inline]
    pub fn power2round(&self, a1: &mut Poly, a0: &mut Poly) {
        for i in 0..N {
            let (h, l) = rounding::power2round(self.coeffs[i]);
            a1.coeffs[i] = h;
            a0.coeffs[i] = l;
        }
    }

    /// Per-coefficient `decompose` (`poly.c` `poly_decompose`): writes high bits
    /// into `a1` and low bits into `a0`, both reading from `self`.
    #[inline]
    pub fn decompose(&self, a1: &mut Poly, a0: &mut Poly) {
        for i in 0..N {
            let (h, l) = rounding::decompose(self.coeffs[i]);
            a1.coeffs[i] = h;
            a0.coeffs[i] = l;
        }
    }

    /// Per-coefficient `make_hint` (`poly.c` `poly_make_hint`): writes the hint
    /// polynomial into `self` from low/high parts `a0`/`a1`, returns the number of
    /// set bits.
    #[inline]
    pub fn make_hint(&mut self, a0: &Poly, a1: &Poly) -> u32 {
        let mut s: u32 = 0;
        for i in 0..N {
            let h = rounding::make_hint(a0.coeffs[i], a1.coeffs[i]);
            self.coeffs[i] = h as i32;
            s += h;
        }
        s
    }

    /// Per-coefficient `use_hint` (`poly.c` `poly_use_hint`): writes corrected
    /// high bits into `self` from input `a` and hint `h`.
    #[inline]
    pub fn use_hint(&mut self, a: &Poly, h: &Poly) {
        for i in 0..N {
            self.coeffs[i] = rounding::use_hint(a.coeffs[i], h.coeffs[i] as u32);
        }
    }

    /// Infinity-norm check (`poly.c` `poly_chknorm`): returns `false` (C `0`) iff
    /// every centered coefficient has absolute value strictly less than `b`, where
    /// `b <= (Q-1)/8`; otherwise `true` (C `1`). Coefficients are assumed to have
    /// been `reduce32`-reduced.
    ///
    /// The centered absolute value is computed branchlessly
    /// (`t = a >> 31; t = a - (t & 2*a)`) so the SIGN of a coefficient never
    /// affects timing; only which coefficient first violates the bound may leak,
    /// which is secret-independent (plan §5).
    #[inline]
    pub fn chknorm(&self, b: i32) -> bool {
        if b > (Q - 1) / 8 {
            return true;
        }
        for i in 0..N {
            // Branchless absolute value of the centered representative.
            let mut t = self.coeffs[i] >> 31;
            t = self.coeffs[i].wrapping_sub(t & self.coeffs[i].wrapping_mul(2));
            if t >= b {
                return true;
            }
        }
        false
    }

    /// Sample a polynomial with uniformly random coefficients in `[0, Q-1]` by
    /// rejection sampling on the SHAKE128(`seed` || LE16(`nonce`)) stream
    /// (`poly.c` `poly_uniform`; this is the inner kernel of ExpandA / FIPS Alg
    /// `RejNTTPoly`). `seed` is `SEEDBYTES` (32) long. Writes into `self`.
    ///
    /// Variable-time by design (plan §5): the rejection-loop iteration count and
    /// stream consumption leak nothing — `seed` is the public `rho`, and the
    /// accept condition `t < Q` is on public bytes. The C `POLY_UNIFORM_NBLOCKS`
    /// = `ceil(768 / 168) = 5` is the initial squeeze; the refill carries the
    /// `buflen % 3` unconsumed tail bytes so 3-byte words are never split across a
    /// squeeze boundary.
    pub fn poly_uniform(&mut self, seed: &[u8; SEEDBYTES], nonce: u16) {
        const POLY_UNIFORM_NBLOCKS: usize = 768usize.div_ceil(SHAKE128_RATE);
        // C uses `buf[NBLOCKS*RATE + 2]`; the +2 head-room lets a refill prepend
        // up to `buflen % 3 < 3` carried tail bytes before the fresh block.
        let mut buf = [0u8; POLY_UNIFORM_NBLOCKS * SHAKE128_RATE + 2];

        let mut state = Shake128Stream::init(seed, nonce);
        let mut buflen = POLY_UNIFORM_NBLOCKS * SHAKE128_RATE;
        state.read(&mut buf[..buflen]);

        let mut ctr = rej_uniform(&mut self.coeffs, N, &buf[..buflen]);

        while ctr < N {
            let off = buflen % 3;
            for i in 0..off {
                buf[i] = buf[buflen - off + i];
            }
            state.read(&mut buf[off..off + SHAKE128_RATE]);
            buflen = SHAKE128_RATE + off;
            ctr += rej_uniform(&mut self.coeffs[ctr..], N - ctr, &buf[..buflen]);
        }
    }

    /// Sample a polynomial with uniformly random coefficients in `[-ETA, ETA]`
    /// (`ETA = 2`) by rejection sampling on the SHAKE256(`seed` || LE16(`nonce`))
    /// stream (`poly.c` `poly_uniform_eta`; the inner kernel of ExpandS).
    /// `seed` is `CRHBYTES` (64) long. Writes into `self`.
    ///
    /// Constant-time map note (plan §5): the rejection *count* leaks nothing
    /// about the accepted secret values, but the accept→value map must be
    /// branchless. It is: `t = t - (205*t >> 10)*5` is `t mod 5` for `t < 15`
    /// computed without a branch/divide, and the value is `2 - (t mod 5)`.
    pub fn poly_uniform_eta(&mut self, seed: &[u8], nonce: u16) {
        const POLY_UNIFORM_ETA_NBLOCKS: usize = 136usize.div_ceil(SHAKE256_RATE);
        // `buf` holds secret-derived bytes (the s1/s2 sample stream); zeroize it
        // on drop so the cleartext is not left on the stack (plan §5).
        let mut buf = zeroize::Zeroizing::new([0u8; POLY_UNIFORM_ETA_NBLOCKS * SHAKE256_RATE]);

        let mut state = Shake256Stream::init(seed, nonce);
        state.read(&mut buf[..]);

        let mut ctr = rej_eta(&mut self.coeffs, N, &buf[..]);

        while ctr < N {
            state.read(&mut buf[..SHAKE256_RATE]);
            ctr += rej_eta(&mut self.coeffs[ctr..], N - ctr, &buf[..SHAKE256_RATE]);
        }
    }

    /// Sample a polynomial with uniformly random coefficients in
    /// `[-(GAMMA1 - 1), GAMMA1]` by unpacking the SHAKE256(`seed` || LE16(`nonce`))
    /// stream (`poly.c` `poly_uniform_gamma1`; ExpandMask). `seed` is `CRHBYTES`
    /// (64) long. Writes into `self`.
    ///
    /// Not rejection-based: it squeezes `POLY_UNIFORM_GAMMA1_NBLOCKS` =
    /// `ceil(POLYZ_PACKEDBYTES / 136) = 5` blocks (680 bytes) and feeds the first
    /// `POLYZ_PACKEDBYTES` (640) into [`polyz_unpack`](Self::polyz_unpack), so the
    /// whole 256-coefficient draw is deterministic in the stream (no branch on
    /// secret data).
    pub fn poly_uniform_gamma1(&mut self, seed: &[u8], nonce: u16) {
        const POLY_UNIFORM_GAMMA1_NBLOCKS: usize = POLYZ_PACKEDBYTES.div_ceil(SHAKE256_RATE);
        // `buf` IS the packed secret mask `y` (ExpandMask output); zeroize it on
        // drop so the cleartext mask is not left on the stack (plan §5).
        let mut buf = zeroize::Zeroizing::new([0u8; POLY_UNIFORM_GAMMA1_NBLOCKS * SHAKE256_RATE]);

        let mut state = Shake256Stream::init(seed, nonce);
        state.read(&mut buf[..]);
        self.polyz_unpack(&buf[..]);
    }

    /// Unpack a `z`-range polynomial (coefficients in `[-(GAMMA1-1), GAMMA1]`,
    /// 20 bits each, little-endian) from `a` (`poly.c` `polyz_unpack`). Reads the
    /// first `POLYZ_PACKEDBYTES` (640) bytes of `a`. Writes into `self`.
    ///
    /// Lives here (rather than with the step-7 packers) because
    /// `poly_uniform_gamma1` calls it, matching `poly.c`'s ordering where
    /// `polyz_unpack` is defined ahead of its uses (the sampler and `unpack_sig`).
    /// Implemented as a method on `self` so the next step's `unpack_sig` reuses it
    /// in place; `BitPack` stores the complement `GAMMA1 - coeff`, undone here.
    pub fn polyz_unpack(&mut self, a: &[u8]) {
        for i in 0..N / 2 {
            let mut c0: u32 = a[5 * i] as u32;
            c0 |= (a[5 * i + 1] as u32) << 8;
            c0 |= (a[5 * i + 2] as u32) << 16;
            c0 &= 0xFFFFF;

            let mut c1: u32 = (a[5 * i + 2] as u32) >> 4;
            c1 |= (a[5 * i + 3] as u32) << 4;
            c1 |= (a[5 * i + 4] as u32) << 12;
            // No mask needed: c1 is already exactly 20 bits.

            self.coeffs[2 * i] = GAMMA1 - c0 as i32;
            self.coeffs[2 * i + 1] = GAMMA1 - c1 as i32;
        }
    }

    /// Implementation of `H` / SampleInBall (`poly.c` `poly_challenge`): build a
    /// challenge polynomial with exactly `TAU` (60) nonzero coefficients in
    /// `{-1, +1}` from the SHAKE256(`seed`) stream. `seed` is `CTILDEBYTES` (64)
    /// long (the `c~` commitment hash). Writes into `self`.
    ///
    /// Variable-time by design (plan §5): the Fisher-Yates rejection (`b > i`)
    /// and the resulting `c[b]` index derive from `c~`, which is public signature
    /// output, so leaking them is fine. First 8 bytes form the LE `signs` word;
    /// `pos` starts at 8 and the block is refilled (one `SHAKE256_RATE` block)
    /// whenever it is exhausted.
    pub fn poly_challenge(&mut self, seed: &[u8; CTILDEBYTES]) {
        let mut buf = [0u8; SHAKE256_RATE];
        let mut state = Shake256Stream::init_xof(seed);
        state.read(&mut buf);

        let mut signs: u64 = 0;
        for (i, &byte) in buf.iter().enumerate().take(8) {
            signs |= (byte as u64) << (8 * i);
        }
        let mut pos: usize = 8;

        for c in self.coeffs.iter_mut() {
            *c = 0;
        }
        for i in (N - TAU)..N {
            let b = loop {
                if pos >= SHAKE256_RATE {
                    state.read(&mut buf);
                    pos = 0;
                }
                let cand = buf[pos] as usize;
                pos += 1;
                if cand <= i {
                    break cand;
                }
            };

            self.coeffs[i] = self.coeffs[b];
            self.coeffs[b] = 1 - 2 * (signs & 1) as i32;
            signs >>= 1;
        }
    }

    // ===== Coefficient bit-packers (poly.c, step 7) =========================
    //
    // BitPack/BitUnpack per FIPS 204. Each `*_pack` writes the canonical encoding
    // of one polynomial into the caller's byte slice; each `*_unpack` reads it
    // back. The encodings store the COMPLEMENT for the signed ranges (eta, t0, z)
    // so the packed value is always non-negative: `polyeta` stores `ETA - c`,
    // `polyt0` stores `2^{D-1} - c`, `polyz` stores `GAMMA1 - c`; `polyt1`/`polyw1`
    // store the (already non-negative) value directly. `polyw1` is write-only
    // (verify recomputes w1, never unpacks it), matching the C, which has no
    // `polyw1_unpack`.
    //
    // Constant-time note (plan §5): these are straight-line per-block loops with
    // no data-dependent branch or index. `polyeta`/`polyt0` pack the SECRET
    // `s1`/`s2`/`t0`, so they must stay branchless — they are. The hint encoding
    // (which DOES branch on a nonzero coefficient) lives in `packing.rs`, not
    // here, and acts only on the public hint.

    /// Bit-pack a polynomial with coefficients in `[-ETA, ETA]` (`poly.c`
    /// `polyeta_pack`): stores `ETA - coeff` in 3 bits each, 8 coeffs per 3 bytes.
    /// Writes the first `POLYETA_PACKEDBYTES` (96) bytes of `r`.
    pub fn polyeta_pack(&self, r: &mut [u8]) {
        let mut t = [0u8; 8];
        for i in 0..N / 8 {
            t[0] = (ETA - self.coeffs[8 * i]) as u8;
            t[1] = (ETA - self.coeffs[8 * i + 1]) as u8;
            t[2] = (ETA - self.coeffs[8 * i + 2]) as u8;
            t[3] = (ETA - self.coeffs[8 * i + 3]) as u8;
            t[4] = (ETA - self.coeffs[8 * i + 4]) as u8;
            t[5] = (ETA - self.coeffs[8 * i + 5]) as u8;
            t[6] = (ETA - self.coeffs[8 * i + 6]) as u8;
            t[7] = (ETA - self.coeffs[8 * i + 7]) as u8;

            r[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
            r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
            r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        }
    }

    /// Unpack a polynomial with coefficients in `[-ETA, ETA]` (`poly.c`
    /// `polyeta_unpack`): inverse of [`polyeta_pack`]. Reads the first
    /// `POLYETA_PACKEDBYTES` (96) bytes of `a`. Writes into `self`.
    pub fn polyeta_unpack(&mut self, a: &[u8]) {
        for i in 0..N / 8 {
            self.coeffs[8 * i] = (a[3 * i] & 7) as i32;
            self.coeffs[8 * i + 1] = ((a[3 * i] >> 3) & 7) as i32;
            self.coeffs[8 * i + 2] = (((a[3 * i] >> 6) | (a[3 * i + 1] << 2)) & 7) as i32;
            self.coeffs[8 * i + 3] = ((a[3 * i + 1] >> 1) & 7) as i32;
            self.coeffs[8 * i + 4] = ((a[3 * i + 1] >> 4) & 7) as i32;
            self.coeffs[8 * i + 5] = (((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7) as i32;
            self.coeffs[8 * i + 6] = ((a[3 * i + 2] >> 2) & 7) as i32;
            self.coeffs[8 * i + 7] = ((a[3 * i + 2] >> 5) & 7) as i32;

            self.coeffs[8 * i] = ETA - self.coeffs[8 * i];
            self.coeffs[8 * i + 1] = ETA - self.coeffs[8 * i + 1];
            self.coeffs[8 * i + 2] = ETA - self.coeffs[8 * i + 2];
            self.coeffs[8 * i + 3] = ETA - self.coeffs[8 * i + 3];
            self.coeffs[8 * i + 4] = ETA - self.coeffs[8 * i + 4];
            self.coeffs[8 * i + 5] = ETA - self.coeffs[8 * i + 5];
            self.coeffs[8 * i + 6] = ETA - self.coeffs[8 * i + 6];
            self.coeffs[8 * i + 7] = ETA - self.coeffs[8 * i + 7];
        }
    }

    /// Bit-pack `t1` with coefficients fitting in 10 bits (`poly.c`
    /// `polyt1_pack`): 4 coeffs per 5 bytes. Coefficients are assumed to be
    /// standard representatives. Writes the first `POLYT1_PACKEDBYTES` (320) bytes.
    pub fn polyt1_pack(&self, r: &mut [u8]) {
        for i in 0..N / 4 {
            r[5 * i] = self.coeffs[4 * i] as u8;
            r[5 * i + 1] = ((self.coeffs[4 * i] >> 8) | (self.coeffs[4 * i + 1] << 2)) as u8;
            r[5 * i + 2] = ((self.coeffs[4 * i + 1] >> 6) | (self.coeffs[4 * i + 2] << 4)) as u8;
            r[5 * i + 3] = ((self.coeffs[4 * i + 2] >> 4) | (self.coeffs[4 * i + 3] << 6)) as u8;
            r[5 * i + 4] = (self.coeffs[4 * i + 3] >> 2) as u8;
        }
    }

    /// Unpack `t1` with 10-bit coefficients (`poly.c` `polyt1_unpack`): inverse of
    /// [`polyt1_pack`]; output coefficients are standard representatives. Reads the
    /// first `POLYT1_PACKEDBYTES` (320) bytes of `a`. Writes into `self`.
    pub fn polyt1_unpack(&mut self, a: &[u8]) {
        for i in 0..N / 4 {
            self.coeffs[4 * i] = ((a[5 * i] as u32 | ((a[5 * i + 1] as u32) << 8)) & 0x3FF) as i32;
            self.coeffs[4 * i + 1] =
                (((a[5 * i + 1] as u32) >> 2 | ((a[5 * i + 2] as u32) << 6)) & 0x3FF) as i32;
            self.coeffs[4 * i + 2] =
                (((a[5 * i + 2] as u32) >> 4 | ((a[5 * i + 3] as u32) << 4)) & 0x3FF) as i32;
            self.coeffs[4 * i + 3] =
                (((a[5 * i + 3] as u32) >> 6 | ((a[5 * i + 4] as u32) << 2)) & 0x3FF) as i32;
        }
    }

    /// Bit-pack `t0` with coefficients in `]-2^{D-1}, 2^{D-1}]` (`poly.c`
    /// `polyt0_pack`): stores `2^{D-1} - coeff` in 13 bits each, 8 coeffs per 13
    /// bytes. Writes the first `POLYT0_PACKEDBYTES` (416) bytes. Packs the SECRET
    /// `t0`, so it is branchless.
    pub fn polyt0_pack(&self, r: &mut [u8]) {
        const HALF: i32 = 1 << (super::params::D - 1);
        let mut t = [0u32; 8];
        for i in 0..N / 8 {
            t[0] = (HALF - self.coeffs[8 * i]) as u32;
            t[1] = (HALF - self.coeffs[8 * i + 1]) as u32;
            t[2] = (HALF - self.coeffs[8 * i + 2]) as u32;
            t[3] = (HALF - self.coeffs[8 * i + 3]) as u32;
            t[4] = (HALF - self.coeffs[8 * i + 4]) as u32;
            t[5] = (HALF - self.coeffs[8 * i + 5]) as u32;
            t[6] = (HALF - self.coeffs[8 * i + 6]) as u32;
            t[7] = (HALF - self.coeffs[8 * i + 7]) as u32;

            r[13 * i] = t[0] as u8;
            r[13 * i + 1] = (t[0] >> 8) as u8;
            r[13 * i + 1] |= (t[1] << 5) as u8;
            r[13 * i + 2] = (t[1] >> 3) as u8;
            r[13 * i + 3] = (t[1] >> 11) as u8;
            r[13 * i + 3] |= (t[2] << 2) as u8;
            r[13 * i + 4] = (t[2] >> 6) as u8;
            r[13 * i + 4] |= (t[3] << 7) as u8;
            r[13 * i + 5] = (t[3] >> 1) as u8;
            r[13 * i + 6] = (t[3] >> 9) as u8;
            r[13 * i + 6] |= (t[4] << 4) as u8;
            r[13 * i + 7] = (t[4] >> 4) as u8;
            r[13 * i + 8] = (t[4] >> 12) as u8;
            r[13 * i + 8] |= (t[5] << 1) as u8;
            r[13 * i + 9] = (t[5] >> 7) as u8;
            r[13 * i + 9] |= (t[6] << 6) as u8;
            r[13 * i + 10] = (t[6] >> 2) as u8;
            r[13 * i + 11] = (t[6] >> 10) as u8;
            r[13 * i + 11] |= (t[7] << 3) as u8;
            r[13 * i + 12] = (t[7] >> 5) as u8;
        }
    }

    /// Unpack `t0` with coefficients in `]-2^{D-1}, 2^{D-1}]` (`poly.c`
    /// `polyt0_unpack`): inverse of [`polyt0_pack`]. Reads the first
    /// `POLYT0_PACKEDBYTES` (416) bytes of `a`. Writes into `self`.
    pub fn polyt0_unpack(&mut self, a: &[u8]) {
        const HALF: i32 = 1 << (super::params::D - 1);
        for i in 0..N / 8 {
            let mut c0 = a[13 * i] as u32;
            c0 |= (a[13 * i + 1] as u32) << 8;
            c0 &= 0x1FFF;

            let mut c1 = (a[13 * i + 1] as u32) >> 5;
            c1 |= (a[13 * i + 2] as u32) << 3;
            c1 |= (a[13 * i + 3] as u32) << 11;
            c1 &= 0x1FFF;

            let mut c2 = (a[13 * i + 3] as u32) >> 2;
            c2 |= (a[13 * i + 4] as u32) << 6;
            c2 &= 0x1FFF;

            let mut c3 = (a[13 * i + 4] as u32) >> 7;
            c3 |= (a[13 * i + 5] as u32) << 1;
            c3 |= (a[13 * i + 6] as u32) << 9;
            c3 &= 0x1FFF;

            let mut c4 = (a[13 * i + 6] as u32) >> 4;
            c4 |= (a[13 * i + 7] as u32) << 4;
            c4 |= (a[13 * i + 8] as u32) << 12;
            c4 &= 0x1FFF;

            let mut c5 = (a[13 * i + 8] as u32) >> 1;
            c5 |= (a[13 * i + 9] as u32) << 7;
            c5 &= 0x1FFF;

            let mut c6 = (a[13 * i + 9] as u32) >> 6;
            c6 |= (a[13 * i + 10] as u32) << 2;
            c6 |= (a[13 * i + 11] as u32) << 10;
            c6 &= 0x1FFF;

            let mut c7 = (a[13 * i + 11] as u32) >> 3;
            c7 |= (a[13 * i + 12] as u32) << 5;
            c7 &= 0x1FFF;

            self.coeffs[8 * i] = HALF - c0 as i32;
            self.coeffs[8 * i + 1] = HALF - c1 as i32;
            self.coeffs[8 * i + 2] = HALF - c2 as i32;
            self.coeffs[8 * i + 3] = HALF - c3 as i32;
            self.coeffs[8 * i + 4] = HALF - c4 as i32;
            self.coeffs[8 * i + 5] = HALF - c5 as i32;
            self.coeffs[8 * i + 6] = HALF - c6 as i32;
            self.coeffs[8 * i + 7] = HALF - c7 as i32;
        }
    }

    /// Bit-pack a `z`-range polynomial (coefficients in `[-(GAMMA1-1), GAMMA1]`,
    /// `poly.c` `polyz_pack`): stores `GAMMA1 - coeff` in 20 bits each, 2 coeffs
    /// per 5 bytes. Writes the first `POLYZ_PACKEDBYTES` (640) bytes. The inverse
    /// [`polyz_unpack`](Self::polyz_unpack) is defined above (it is also used by
    /// the ExpandMask sampler), matching `poly.c`'s ordering.
    pub fn polyz_pack(&self, r: &mut [u8]) {
        let mut t = [0u32; 2];
        for i in 0..N / 2 {
            t[0] = (GAMMA1 - self.coeffs[2 * i]) as u32;
            t[1] = (GAMMA1 - self.coeffs[2 * i + 1]) as u32;

            r[5 * i] = t[0] as u8;
            r[5 * i + 1] = (t[0] >> 8) as u8;
            r[5 * i + 2] = (t[0] >> 16) as u8;
            r[5 * i + 2] |= (t[1] << 4) as u8;
            r[5 * i + 3] = (t[1] >> 4) as u8;
            r[5 * i + 4] = (t[1] >> 12) as u8;
        }
    }

    /// Bit-pack `w1` with coefficients in `[0, 15]` (`poly.c` `polyw1_pack`):
    /// 4 bits each, 2 coeffs per byte. ML-DSA-87 has 4-bit `w1`, so there is no
    /// `polyw1_unpack` (verify recomputes `w1` from scratch). Writes the first
    /// `POLYW1_PACKEDBYTES` (128) bytes of `r`.
    pub fn polyw1_pack(&self, r: &mut [u8]) {
        for (i, byte) in r[..N / 2].iter_mut().enumerate() {
            *byte = (self.coeffs[2 * i] | (self.coeffs[2 * i + 1] << 4)) as u8;
        }
    }
}

/// `rej_uniform` (`poly.c`, static): write up to `len` coefficients in `[0, Q-1]`
/// into `a`, by reading little-endian 3-byte words from `buf`, masking to 23 bits,
/// and accepting those `< Q`. Returns how many were written (may be `< len` if the
/// buffer runs out). On secret-independent (public `rho`) bytes, so the rejection
/// branch is sanctioned variable-time (plan §5).
fn rej_uniform(a: &mut [i32], len: usize, buf: &[u8]) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < len && pos + 3 <= buf.len() {
        let mut t: u32 = buf[pos] as u32;
        t |= (buf[pos + 1] as u32) << 8;
        t |= (buf[pos + 2] as u32) << 16;
        t &= 0x7FFFFF;
        pos += 3;

        if t < Q as u32 {
            a[ctr] = t as i32;
            ctr += 1;
        }
    }
    ctr
}

/// `rej_eta` (`poly.c`, static): write up to `len` coefficients in `[-ETA, ETA]`
/// (`ETA = 2`) into `a`. Each input byte yields two nibbles; a nibble `< 15` is
/// accepted and mapped `2 - (nibble mod 5)` with `mod 5` done branchlessly as
/// `n - (205*n >> 10)*5`. Returns how many were written. The accept→value map is
/// branchless (required on secret values); the rejection count is sanctioned
/// variable-time (plan §5).
fn rej_eta(a: &mut [i32], len: usize, buf: &[u8]) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < len && pos < buf.len() {
        let t0 = (buf[pos] & 0x0F) as u32;
        let t1 = (buf[pos] >> 4) as u32;
        pos += 1;

        if t0 < 15 {
            let t0 = t0 - ((205 * t0) >> 10) * 5;
            a[ctr] = 2 - t0 as i32;
            ctr += 1;
        }
        if t1 < 15 && ctr < len {
            let t1 = t1 - ((205 * t1) >> 10) * 5;
            a[ctr] = 2 - t1 as i32;
            ctr += 1;
        }
    }
    ctr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mldsa::params::D;

    /// Deterministic LCG, used to build pseudo-random test polynomials without a
    /// dev-dependency on `rand`.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        /// A coefficient in the standard range `[0, Q)`.
        fn coeff_modq(&mut self) -> i32 {
            (self.next_u64() % Q as u64) as i32
        }
    }

    /// `a mod^+ Q` in `i128`, the trusted reference representative.
    fn modp(a: i128) -> i64 {
        let q = Q as i128;
        let mut r = a % q;
        if r < 0 {
            r += q;
        }
        r as i64
    }

    /// Schoolbook negacyclic convolution `c = a * b mod (X^256 + 1, Q)`, computed
    /// independently of the NTT in `i128` so it cannot share a bug with the code
    /// under test. The wrap `X^256 = -1` flips the sign of the overflow term.
    //
    // The folded index `k = i + j` (and the `k - N` wrap) is the substance of the
    // negacyclic reduction, so the indexed double loop is the clearest form here;
    // an `enumerate()` rewrite would hide the index arithmetic that is the point.
    #[allow(clippy::needless_range_loop)]
    fn schoolbook_negacyclic(a: &[i32; N], b: &[i32; N]) -> [i64; N] {
        let mut acc = [0i128; N];
        for i in 0..N {
            for j in 0..N {
                let prod = a[i] as i128 * b[j] as i128;
                let k = i + j;
                if k < N {
                    acc[k] += prod;
                } else {
                    // X^{k} = X^{k-N} * X^N = -X^{k-N}.
                    acc[k - N] -= prod;
                }
            }
        }
        let mut out = [0i64; N];
        for (o, &a) in out.iter_mut().zip(acc.iter()) {
            *o = modp(a);
        }
        out
    }

    /// HEADLINE STEP-5 SELF-TEST (plan §3 step 5): multiply two polynomials two
    /// independent ways and assert equality mod Q.
    ///
    /// Path A (the code under test): `invntt_tomont(pointwise_montgomery(ntt(a),
    /// ntt(b)))`. Path B (trusted): schoolbook negacyclic convolution.
    ///
    /// Montgomery bookkeeping note: `ntt` leaves plain point values (the
    /// per-butterfly Montgomery-form zeta is cancelled by the `montgomery_reduce`
    /// inside it), so `pointwise_montgomery` of two such polys yields
    /// `a_i * b_i * 2^-32` per point. `invntt_tomont` then folds in exactly one
    /// `2^32`, cancelling that factor, so Path A returns the true product
    /// `a * b mod (X^256+1, Q)` with NO residual Montgomery factor — it must match
    /// Path B directly (compared as residues mod Q). This single test validates
    /// `ntt` + `pointwise_montgomery` + `invntt_tomont` end-to-end, which is the
    /// whole point of building NTT bottom-up.
    #[test]
    fn ntt_mul_equals_schoolbook_convolution() {
        let mut rng = Lcg(0x0BADC0DE_F00DCAFE);

        for _ in 0..100 {
            let mut a = Poly::zero();
            let mut b = Poly::zero();
            for i in 0..N {
                a.coeffs[i] = rng.coeff_modq();
                b.coeffs[i] = rng.coeff_modq();
            }
            let a_orig = a.coeffs;
            let b_orig = b.coeffs;

            // Path A: NTT-domain multiply.
            a.ntt();
            b.ntt();
            let mut c = Poly::zero();
            c.pointwise_montgomery(&a, &b);
            c.invntt_tomont();

            // Path B: schoolbook negacyclic convolution.
            let want = schoolbook_negacyclic(&a_orig, &b_orig);

            for (i, &want_i) in want.iter().enumerate() {
                let got = modp(c.coeffs[i] as i128);
                assert_eq!(
                    got, want_i,
                    "coeff {i}: NTT product {} != schoolbook {} (mod Q)",
                    got, want_i
                );
            }
        }
    }

    /// Edge polynomials for the multiply check: `1`, `X`, `X^255`, and the
    /// all-`Q-1` poly. `1 * b == b`; `X * b` is a negacyclic shift of `b`;
    /// `X^255 * X == X^256 == -1`. Catches sign/index errors the random test
    /// might statistically miss.
    #[test]
    fn ntt_mul_edge_polynomials() {
        // Helper: multiply via the NTT path, return standard residues.
        fn ntt_mul(a0: &[i32; N], b0: &[i32; N]) -> [i64; N] {
            let mut a = Poly { coeffs: *a0 };
            let mut b = Poly { coeffs: *b0 };
            a.ntt();
            b.ntt();
            let mut c = Poly::zero();
            c.pointwise_montgomery(&a, &b);
            c.invntt_tomont();
            let mut out = [0i64; N];
            for (o, &c_i) in out.iter_mut().zip(c.coeffs.iter()) {
                *o = modp(c_i as i128);
            }
            out
        }

        let mut rng = Lcg(0xDEAD_BEEF_1234_5678);
        let mut b = [0i32; N];
        for x in b.iter_mut() {
            *x = rng.coeff_modq();
        }

        // 1 * b == b.
        let mut one = [0i32; N];
        one[0] = 1;
        let got = ntt_mul(&one, &b);
        for i in 0..N {
            assert_eq!(got[i], modp(b[i] as i128), "1*b coeff {i}");
        }

        // X * b: (X*b)[i] = b[i-1] for i>=1, and (X*b)[0] = -b[N-1].
        let mut x = [0i32; N];
        x[1] = 1;
        let got = ntt_mul(&x, &b);
        assert_eq!(got[0], modp(-(b[N - 1] as i128)), "X*b coeff 0 (wrap sign)");
        for (i, &got_i) in got.iter().enumerate().skip(1) {
            assert_eq!(got_i, modp(b[i - 1] as i128), "X*b coeff {i}");
        }

        // X^255 * X == X^256 == -1  ->  the constant poly -1 mod Q.
        let mut x255 = [0i32; N];
        x255[255] = 1;
        let got = ntt_mul(&x255, &x);
        assert_eq!(got[0], modp(-1), "X^255 * X coeff 0 must be -1 mod Q");
        for (i, &got_i) in got.iter().enumerate().skip(1) {
            assert_eq!(got_i, 0, "X^255 * X coeff {i} must be 0");
        }
    }

    /// `add`/`sub` are coefficientwise and exactly invert each other:
    /// `(a + b) - b == a` and the residues match an `i128` reference.
    #[test]
    fn add_sub_are_coefficientwise() {
        let mut rng = Lcg(0xA5A5_5A5A_0F0F_F0F0);
        for _ in 0..1000 {
            let mut a = Poly::zero();
            let mut b = Poly::zero();
            for i in 0..N {
                // Use the full centered range so wrapping semantics are exercised.
                a.coeffs[i] = rng.next_u64() as i32;
                b.coeffs[i] = rng.next_u64() as i32;
            }
            let mut s = Poly::zero();
            s.add(&a, &b);
            for i in 0..N {
                assert_eq!(s.coeffs[i], a.coeffs[i].wrapping_add(b.coeffs[i]));
            }
            let mut d = Poly::zero();
            d.sub(&s, &b); // (a+b) - b
            assert_eq!(d.coeffs, a.coeffs, "(a+b)-b must equal a");
        }
    }

    /// `reduce`/`caddq` produce the standard representative `[0, Q)` and preserve
    /// the residue mod Q (per coefficient).
    #[test]
    fn reduce_then_caddq_is_standard_rep() {
        let mut rng = Lcg(0x1357_9BDF_2468_ACE0);
        let hi = (1i64 << 31) - (1i64 << 22) - 1; // reduce32 precondition upper bound
        for _ in 0..1000 {
            let mut p = Poly::zero();
            for i in 0..N {
                // In [i32::MIN, hi], the documented reduce32 input range.
                let range = (hi - i32::MIN as i64) as u64;
                p.coeffs[i] = (i32::MIN as i64 + (rng.next_u64() % (range + 1)) as i64) as i32;
            }
            let orig = p.coeffs;
            p.reduce();
            p.caddq();
            for (i, (&got, &was)) in p.coeffs.iter().zip(orig.iter()).enumerate() {
                assert!((0..Q).contains(&got), "coeff {i} = {got} not in [0,Q)");
                assert_eq!(got as i64, modp(was as i128), "coeff {i} residue changed");
            }
        }
    }

    /// `shiftl` multiplies every coefficient by `2^D` (within the documented
    /// `< 2^{31-D}` input bound, where no wraparound occurs).
    #[test]
    fn shiftl_multiplies_by_2pow_d() {
        let mut rng = Lcg(0x2222_3333_4444_5555);
        let bound = 1i32 << (31 - D); // 2^{31-D} = 2^18
        for _ in 0..1000 {
            let mut p = Poly::zero();
            for i in 0..N {
                // Centered in (-2^{31-D}, 2^{31-D}).
                p.coeffs[i] = (rng.next_u64() % (2 * bound as u64)) as i32 - bound;
            }
            let orig = p.coeffs;
            p.shiftl();
            for (i, (&got, &was)) in p.coeffs.iter().zip(orig.iter()).enumerate() {
                assert_eq!(got, was << D, "coeff {i} shiftl mismatch");
            }
        }
    }

    /// `pointwise_montgomery` computes `montgomery_reduce(a_i * b_i)`, i.e. the
    /// product carries a `2^-32` factor — checked against an `i128` reference.
    #[test]
    fn pointwise_montgomery_has_mont_factor() {
        let q = Q as i128;
        // 2^-32 mod Q via Fermat (Q prime): (2^32)^(Q-2).
        let inv2pow32 = {
            let mut acc = 1i128;
            let mut base = (1i128 << 32) % q;
            let mut e = (Q as i128) - 2;
            while e > 0 {
                if e & 1 == 1 {
                    acc = acc * base % q;
                }
                base = base * base % q;
                e >>= 1;
            }
            acc
        };
        let mut rng = Lcg(0x9999_8888_7777_6666);
        for _ in 0..2000 {
            let mut a = Poly::zero();
            let mut b = Poly::zero();
            for i in 0..N {
                a.coeffs[i] = rng.coeff_modq();
                b.coeffs[i] = rng.coeff_modq();
            }
            let mut c = Poly::zero();
            c.pointwise_montgomery(&a, &b);
            for i in 0..N {
                let want = modp(a.coeffs[i] as i128 * b.coeffs[i] as i128 % q * inv2pow32 % q);
                assert_eq!(modp(c.coeffs[i] as i128), want, "coeff {i}");
            }
        }
    }

    /// `chknorm` returns `true` iff some centered coefficient has abs value `>= b`.
    /// Cross-checked against a naive (allowed-to-branch, test-only) reference, with
    /// the `b > (Q-1)/8` short-circuit also verified.
    #[test]
    fn chknorm_matches_naive_reference() {
        // Naive reference: centered abs value with an ordinary branch.
        fn naive_chknorm(p: &Poly, b: i32) -> bool {
            if b > (Q - 1) / 8 {
                return true;
            }
            for &c in p.coeffs.iter() {
                let abs = c.abs();
                if abs >= b {
                    return true;
                }
            }
            false
        }

        let mut rng = Lcg(0xF0E1_D2C3_B4A5_9687);
        // Centered coeffs in [-(Q-1)/8 - margin, ...] so we straddle the bound.
        let bounds = [
            1i32,
            100,
            GAMMA1_BOUND_FOR_TEST,
            (Q - 1) / 8,
            (Q - 1) / 8 + 1, // triggers the short-circuit
        ];
        for &b in &bounds {
            for _ in 0..2000 {
                let mut p = Poly::zero();
                for i in 0..N {
                    // Range a touch wider than b so both branches fire often.
                    let span = (b as i64).saturating_mul(2).max(4) as u64;
                    p.coeffs[i] = (rng.next_u64() % (2 * span + 1)) as i32 - span as i32;
                }
                assert_eq!(
                    p.chknorm(b),
                    naive_chknorm(&p, b),
                    "chknorm disagrees with naive reference at b={b}"
                );
            }
        }
    }

    // A representative norm bound from the signing loop (gamma1 - beta), used to
    // exercise chknorm at a realistic magnitude.
    const GAMMA1_BOUND_FOR_TEST: i32 = (1 << 19) - 120;

    /// `power2round`/`decompose` wrappers apply the per-coeff `rounding` fns over
    /// the whole array; spot-check against `rounding` directly on a standard-rep
    /// input.
    #[test]
    fn rounding_wrappers_match_per_coeff() {
        let mut rng = Lcg(0x0011_2233_4455_6677);
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = rng.coeff_modq();
        }
        let (mut h1, mut l1) = (Poly::zero(), Poly::zero());
        p.power2round(&mut h1, &mut l1);
        let (mut h2, mut l2) = (Poly::zero(), Poly::zero());
        p.decompose(&mut h2, &mut l2);
        for i in 0..N {
            assert_eq!(
                (h1.coeffs[i], l1.coeffs[i]),
                rounding::power2round(p.coeffs[i])
            );
            assert_eq!(
                (h2.coeffs[i], l2.coeffs[i]),
                rounding::decompose(p.coeffs[i])
            );
        }
    }

    // ===== Step 6 samplers ==================================================
    //
    // No deterministic C oracle exists (pqcrypto is OS-random only; full
    // byte-equality is gated on the ACVP KATs in steps 9-10, which exercise
    // ExpandA/ExpandS/ExpandMask/SampleInBall transitively and exactly). These
    // tests therefore (a) check the structural properties the plan §3 step 6
    // names, and (b) cross-check each sampler against an INDEPENDENT in-test
    // reimplementation driven by the very same SHAKE stream (recomputed via the
    // `fips202` shim), which pins the byte-consumption / block-refill / rejection
    // logic exactly without a C oracle.

    use crate::crypto::mldsa::fips202::{Shake128Stream, Shake256Stream};
    use crate::crypto::mldsa::params::{CTILDEBYTES, GAMMA1, SEEDBYTES, TAU};

    /// Trusted in-test ExpandA: squeeze the SHAKE128(seed||nonce) stream the same
    /// way `poly_uniform` does and apply 3-byte/23-bit rejection, written here in
    /// the most obvious form so it cannot share a bug with the code under test.
    fn ref_uniform(seed: &[u8; SEEDBYTES], nonce: u16) -> [i32; N] {
        let mut st = Shake128Stream::init(seed, nonce);
        let mut out = [0i32; N];
        let mut ctr = 0usize;
        // Pull plenty of bytes one Keccak block at a time; 256 accepts out of a
        // ~1/(1 - tiny) rate need far fewer than this many bytes.
        let mut stream = Vec::new();
        while ctr < N {
            let mut blk = [0u8; super::SHAKE128_RATE];
            st.read(&mut blk);
            stream.extend_from_slice(&blk);
            // Re-scan from scratch each time over the bytes we have, in 3-byte
            // words, counting accepts (simple + obviously correct).
            ctr = 0;
            let mut pos = 0;
            while ctr < N && pos + 3 <= stream.len() {
                let t = (stream[pos] as u32)
                    | ((stream[pos + 1] as u32) << 8)
                    | ((stream[pos + 2] as u32) << 16);
                let t = t & 0x7FFFFF;
                pos += 3;
                if t < Q as u32 {
                    out[ctr] = t as i32;
                    ctr += 1;
                }
            }
        }
        out
    }

    /// `poly_uniform` (ExpandA inner): coeffs in `[0, Q)`, and byte-identical to
    /// the trusted reference over several seeds/nonces (validates the
    /// `buflen % 3` carry across the squeeze-block refill boundary).
    #[test]
    fn poly_uniform_matches_reference_and_in_range() {
        for nonce in [0u16, 1, 7, 0x0102, 0xFFFF] {
            let mut seed = [0u8; SEEDBYTES];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(nonce as u8);
            }
            let mut p = Poly::zero();
            p.poly_uniform(&seed, nonce);

            for (i, &c) in p.coeffs.iter().enumerate() {
                assert!((0..Q).contains(&c), "ExpandA coeff {i} = {c} out of [0,Q)");
            }
            assert_eq!(
                p.coeffs,
                ref_uniform(&seed, nonce),
                "poly_uniform disagrees with independent reference (nonce={nonce})"
            );
        }
    }

    /// Trusted in-test ExpandS: SHAKE256(seed||nonce) stream + nibble rejection
    /// (`t < 15` accepted, value `2 - (t mod 5)`), written plainly.
    fn ref_uniform_eta(seed: &[u8], nonce: u16) -> [i32; N] {
        let mut st = Shake256Stream::init(seed, nonce);
        let mut out = [0i32; N];
        let mut ctr = 0usize;
        let mut stream = Vec::new();
        while ctr < N {
            let mut blk = [0u8; super::SHAKE256_RATE];
            st.read(&mut blk);
            stream.extend_from_slice(&blk);
            ctr = 0;
            let mut pos = 0;
            while ctr < N && pos < stream.len() {
                let nibbles = [(stream[pos] & 0x0F) as u32, (stream[pos] >> 4) as u32];
                pos += 1;
                for &t in &nibbles {
                    if ctr < N && t < 15 {
                        let m = t % 5; // trusted reference: real modulo
                        out[ctr] = 2 - m as i32;
                        ctr += 1;
                    }
                }
            }
        }
        out
    }

    /// `poly_uniform_eta` (ExpandS, eta=2): coeffs in `[-2, 2]`, and byte-identical
    /// to the trusted reference (also confirms the branchless `2 - (n - (205*n>>10)*5)`
    /// equals a real `2 - (n mod 5)`).
    #[test]
    fn poly_uniform_eta_matches_reference_and_in_range() {
        for nonce in [0u16, 3, 14, 0x0201, 0xFFFE] {
            let mut seed = [0u8; super::super::params::CRHBYTES];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(17).wrapping_add(nonce as u8 ^ 0x5A);
            }
            let mut p = Poly::zero();
            p.poly_uniform_eta(&seed, nonce);

            for (i, &c) in p.coeffs.iter().enumerate() {
                assert!((-2..=2).contains(&c), "eta coeff {i} = {c} out of [-2,2]");
            }
            assert_eq!(
                p.coeffs,
                ref_uniform_eta(&seed, nonce),
                "poly_uniform_eta disagrees with reference (nonce={nonce})"
            );
        }
    }

    /// `poly_uniform_gamma1` (ExpandMask): every coeff in `[-(GAMMA1-1), GAMMA1]`,
    /// and byte-identical to feeding the first POLYZ_PACKEDBYTES of the
    /// SHAKE256(seed||nonce) stream through `polyz_unpack`.
    #[test]
    fn poly_uniform_gamma1_matches_reference_and_in_range() {
        for nonce in [0u16, 5, 0x0304, 0x8000, 0xFFFF] {
            let mut seed = [0u8; super::super::params::CRHBYTES];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(13).wrapping_add(nonce as u8 ^ 0xA5);
            }
            let mut p = Poly::zero();
            p.poly_uniform_gamma1(&seed, nonce);

            for (i, &c) in p.coeffs.iter().enumerate() {
                assert!(
                    (-(GAMMA1 - 1)..=GAMMA1).contains(&c),
                    "gamma1 coeff {i} = {c} out of [-(GAMMA1-1), GAMMA1]"
                );
            }

            // Reference: squeeze the stream independently, unpack the first 640B.
            let mut st = Shake256Stream::init(&seed, nonce);
            let mut buf = [0u8; POLYZ_PACKEDBYTES];
            st.read(&mut buf);
            let mut want = Poly::zero();
            want.polyz_unpack(&buf);
            assert_eq!(
                p.coeffs, want.coeffs,
                "poly_uniform_gamma1 disagrees with stream||polyz_unpack (nonce={nonce})"
            );
        }
    }

    /// `polyz_unpack` is the exact inverse of the `BitPack(GAMMA1 - c)` 20-bit
    /// little-endian layout: pack random in-range coeffs by that rule, unpack, and
    /// recover them. Locks the bit layout independently of the sampler.
    #[test]
    fn polyz_unpack_inverts_bitpack() {
        // Pack one coefficient pair (c0,c1) into 5 bytes the way BitPack does:
        // store t = GAMMA1 - c as 20-bit LE, two per 5 bytes.
        fn pack_pair(c0: i32, c1: i32) -> [u8; 5] {
            let t0 = (GAMMA1 - c0) as u32;
            let t1 = (GAMMA1 - c1) as u32;
            [
                t0 as u8,
                (t0 >> 8) as u8,
                ((t0 >> 16) as u8 & 0x0F) | ((t1 << 4) as u8),
                (t1 >> 4) as u8,
                (t1 >> 12) as u8,
            ]
        }

        let mut rng = Lcg(0x5151_2424_9696_3030);
        for _ in 0..200 {
            let mut coeffs = [0i32; N];
            let mut bytes = [0u8; POLYZ_PACKEDBYTES];
            for i in 0..N / 2 {
                // Range of valid z coeffs: [-(GAMMA1-1), GAMMA1].
                let span = (2 * GAMMA1) as u64; // 0..=2*GAMMA1-1 -> shift to range
                let c0 = (rng.next_u64() % span) as i32 - (GAMMA1 - 1);
                let c1 = (rng.next_u64() % span) as i32 - (GAMMA1 - 1);
                coeffs[2 * i] = c0;
                coeffs[2 * i + 1] = c1;
                bytes[5 * i..5 * i + 5].copy_from_slice(&pack_pair(c0, c1));
            }
            let mut got = Poly::zero();
            got.polyz_unpack(&bytes);
            assert_eq!(got.coeffs, coeffs, "polyz_unpack did not invert BitPack");
        }
    }

    /// Trusted in-test SampleInBall: SHAKE256(seed) stream, first 8 bytes = signs,
    /// Fisher-Yates with `b <= i` acceptance and block refill at the rate, written
    /// in the most direct form.
    fn ref_challenge(seed: &[u8; CTILDEBYTES]) -> [i32; N] {
        let mut st = Shake256Stream::init_xof(seed);
        let mut block = [0u8; super::SHAKE256_RATE];
        st.read(&mut block); // first block (matches the code's first squeeze)
        let mut stream = block.to_vec();

        let mut signs: u64 = 0;
        for (i, &byte) in stream.iter().enumerate().take(8) {
            signs |= (byte as u64) << (8 * i);
        }
        let mut pos = 8usize;
        let mut c = [0i32; N];
        for i in (N - TAU)..N {
            let b = loop {
                if pos >= stream.len() {
                    st.read(&mut block);
                    stream.extend_from_slice(&block);
                }
                let cand = stream[pos] as usize;
                pos += 1;
                if cand <= i {
                    break cand;
                }
            };
            c[i] = c[b];
            c[b] = 1 - 2 * (signs & 1) as i32;
            signs >>= 1;
        }
        c
    }

    /// `poly_challenge` (SampleInBall, tau=60): exactly TAU nonzero coefficients,
    /// all in `{-1, +1}`, and byte-identical to the trusted reference.
    #[test]
    fn poly_challenge_has_tau_pm1_and_matches_reference() {
        for k in 0..16u8 {
            let mut seed = [0u8; CTILDEBYTES];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7).wrapping_add(k.wrapping_mul(101));
            }
            let mut c = Poly::zero();
            c.poly_challenge(&seed);

            let nonzero = c.coeffs.iter().filter(|&&x| x != 0).count();
            assert_eq!(nonzero, TAU, "challenge must have exactly TAU nonzeros");
            for (i, &x) in c.coeffs.iter().enumerate() {
                assert!(
                    x == 0 || x == 1 || x == -1,
                    "challenge coeff {i} = {x} not in {{-1,0,1}}"
                );
            }
            assert_eq!(
                c.coeffs,
                ref_challenge(&seed),
                "poly_challenge disagrees with independent reference (k={k})"
            );
        }
    }

    // ===== Step 7 bit-packers ===============================================
    //
    // Each `*_pack` followed by its `*_unpack` must recover the original
    // coefficients exactly, for every coefficient drawn from the canonical
    // in-range domain of that encoding. This locks the bit layout (offsets,
    // shifts, masks, complement) independently of the rest of the module.
    // (`polyz_unpack` already has its own inverse test above; here we also
    // exercise the matching `polyz_pack` round-trip.) `polyw1_pack` has no
    // unpack in ML-DSA-87, so it is checked against a hand-computed nibble layout.

    use crate::crypto::mldsa::params::{
        POLYETA_PACKEDBYTES, POLYT0_PACKEDBYTES, POLYT1_PACKEDBYTES, POLYW1_PACKEDBYTES,
    };

    /// `polyeta_pack` ∘ `polyeta_unpack` == identity over coeffs in `[-ETA, ETA]`,
    /// and the packed length is exactly `POLYETA_PACKEDBYTES` (96).
    #[test]
    fn polyeta_pack_unpack_roundtrip() {
        let mut rng = Lcg(0x1010_2020_3030_4040);
        for _ in 0..500 {
            let mut p = Poly::zero();
            for c in p.coeffs.iter_mut() {
                // Uniform in [-ETA, ETA] = [-2, 2].
                *c = (rng.next_u64() % (2 * ETA as u64 + 1)) as i32 - ETA;
            }
            let mut buf = [0u8; POLYETA_PACKEDBYTES];
            p.polyeta_pack(&mut buf);
            let mut got = Poly::zero();
            got.polyeta_unpack(&buf);
            assert_eq!(got.coeffs, p.coeffs, "polyeta pack/unpack not identity");
        }
    }

    /// `polyt1_pack` ∘ `polyt1_unpack` == identity over coeffs in `[0, 1023]`
    /// (10-bit), packed length `POLYT1_PACKEDBYTES` (320).
    #[test]
    fn polyt1_pack_unpack_roundtrip() {
        let mut rng = Lcg(0x5050_6060_7070_8080);
        for _ in 0..500 {
            let mut p = Poly::zero();
            for c in p.coeffs.iter_mut() {
                *c = (rng.next_u64() % 1024) as i32; // 10 bits
            }
            let mut buf = [0u8; POLYT1_PACKEDBYTES];
            p.polyt1_pack(&mut buf);
            let mut got = Poly::zero();
            got.polyt1_unpack(&buf);
            assert_eq!(got.coeffs, p.coeffs, "polyt1 pack/unpack not identity");
        }
    }

    /// `polyt0_pack` ∘ `polyt0_unpack` == identity over coeffs in
    /// `]-2^{D-1}, 2^{D-1}]`, packed length `POLYT0_PACKEDBYTES` (416).
    #[test]
    fn polyt0_pack_unpack_roundtrip() {
        let half = 1i32 << (D - 1); // 4096
        let mut rng = Lcg(0x9090_A0A0_B0B0_C0C0);
        for _ in 0..500 {
            let mut p = Poly::zero();
            for c in p.coeffs.iter_mut() {
                // Domain is (-2^{D-1}, 2^{D-1}] = [-4095, 4096].
                *c = (rng.next_u64() % (2 * half as u64)) as i32 - (half - 1);
            }
            let mut buf = [0u8; POLYT0_PACKEDBYTES];
            p.polyt0_pack(&mut buf);
            let mut got = Poly::zero();
            got.polyt0_unpack(&buf);
            assert_eq!(got.coeffs, p.coeffs, "polyt0 pack/unpack not identity");
        }
    }

    /// `polyz_pack` ∘ `polyz_unpack` == identity over coeffs in
    /// `[-(GAMMA1-1), GAMMA1]`, packed length `POLYZ_PACKEDBYTES` (640).
    #[test]
    fn polyz_pack_unpack_roundtrip() {
        let mut rng = Lcg(0xC0C0_D0D0_E0E0_F0F0);
        for _ in 0..500 {
            let mut p = Poly::zero();
            for c in p.coeffs.iter_mut() {
                // Domain [-(GAMMA1-1), GAMMA1]: 2*GAMMA1 values.
                *c = (rng.next_u64() % (2 * GAMMA1 as u64)) as i32 - (GAMMA1 - 1);
            }
            let mut buf = [0u8; POLYZ_PACKEDBYTES];
            p.polyz_pack(&mut buf);
            let mut got = Poly::zero();
            got.polyz_unpack(&buf);
            assert_eq!(got.coeffs, p.coeffs, "polyz pack/unpack not identity");
        }
    }

    /// `polyw1_pack` (write-only in ML-DSA-87): 4 bits/coeff, 2 coeffs per byte,
    /// low coeff in the low nibble. Checked against a direct nibble computation and
    /// for the exact packed length `POLYW1_PACKEDBYTES` (128).
    #[test]
    fn polyw1_pack_matches_nibble_layout() {
        let mut rng = Lcg(0x0F0F_1E1E_2D2D_3C3C);
        for _ in 0..500 {
            let mut p = Poly::zero();
            for c in p.coeffs.iter_mut() {
                *c = (rng.next_u64() % 16) as i32; // w1 in [0,15]
            }
            let mut buf = [0u8; POLYW1_PACKEDBYTES];
            p.polyw1_pack(&mut buf);
            for (i, &byte) in buf.iter().enumerate() {
                let lo = p.coeffs[2 * i] as u8;
                let hi = p.coeffs[2 * i + 1] as u8;
                assert_eq!(byte, lo | (hi << 4), "w1 byte {i} nibble layout");
            }
        }
    }
}
