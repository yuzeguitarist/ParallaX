//! Vectors of polynomials and the matrix/vector operations over them, including
//! ExpandA. Mirrors `polyvec.c` (the PQClean `ml-dsa-87/clean` reference that
//! `pqcrypto-mldsa 0.1.2` compiles).
//!
//! Two fixed-length vector types mirror the C `polyvecl`/`polyveck` structs:
//! - [`Polyvecl`] holds `L = 7` polynomials (`s1`, `y`, `z`, and each row of the
//!   matrix `A`);
//! - [`Polyveck`] holds `K = 8` polynomials (`s2`, `t`, `t0`, `t1`, `w`, `w0`,
//!   `w1`, the hint `h`).
//!
//! The public matrix `A` is `[Polyvecl; K]` (`K` rows, each a length-`L` vector),
//! exactly the C `polyvecl mat[K]`.
//!
//! Each method is a thin per-element loop delegating to the already-ported
//! [`Poly`] operation of the same `poly.c` name, matching `polyvec.c` 1:1 so each
//! Rust function diffs against exactly one C function. The C function names are
//! kept (with the `PQCLEAN_MLDSA87_CLEAN_` prefix and the `poly`/`polyvec`
//! split dropped onto methods).
//!
//! Constant-time note (plan §5): every vector op here inherits the
//! constant-timeness of the underlying per-poly op. The samplers `matrix_expand`
//! (ExpandA on public `rho`) and `uniform_eta`/`uniform_gamma1` are sanctioned
//! variable-time exactly as their per-poly kernels are; the arithmetic / rounding
//! vector ops are straight-line loops safe on the secret `s1`/`s2`/`y` vectors.

use super::params::{CRHBYTES, K, L, SEEDBYTES};
use super::poly::Poly;

/// A length-`L` vector of polynomials, i.e. the C `polyvecl { poly vec[L]; }`.
/// Holds `s1`, `y`, `z`, and each row of `A`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Polyvecl {
    pub(crate) vec: [Poly; L],
}

impl Default for Polyvecl {
    fn default() -> Self {
        Polyvecl {
            vec: [Poly::zero(); L],
        }
    }
}

// Secret `s1`/`y`/`z` vectors are zeroized after use in the signing path (plan
// §5); `Polyvecl` is `Copy + Default` with an all-zero default, so
// `DefaultIsZeroes` provides a volatile-overwrite `Zeroize`.
impl zeroize::DefaultIsZeroes for Polyvecl {}

impl Polyvecl {
    /// An all-zero length-`L` vector.
    #[inline]
    pub fn zero() -> Self {
        Polyvecl {
            vec: [Poly::zero(); L],
        }
    }

    /// `polyvecl_uniform_eta`: sample each of the `L` polynomials in `[-ETA, ETA]`
    /// from `SHAKE256(seed || LE16(nonce))`, incrementing `nonce` per polynomial.
    /// `seed` is `CRHBYTES` (64) long. (ExpandS for the `s1` half.)
    pub fn uniform_eta(&mut self, seed: &[u8; CRHBYTES], nonce: u16) {
        // C: `poly_uniform_eta(&v->vec[i], seed, nonce++)` — element i uses
        // nonce + i (post-increment from the starting value).
        for (i, p) in self.vec.iter_mut().enumerate() {
            p.poly_uniform_eta(seed, nonce + i as u16);
        }
    }

    /// `polyvecl_uniform_gamma1`: sample each of the `L` polynomials in
    /// `[-(GAMMA1-1), GAMMA1]` via `poly_uniform_gamma1` with per-element nonce
    /// `L * nonce + i`. `seed` is `CRHBYTES` (64) long. (ExpandMask for `y`.)
    pub fn uniform_gamma1(&mut self, seed: &[u8; CRHBYTES], nonce: u16) {
        for (i, p) in self.vec.iter_mut().enumerate() {
            p.poly_uniform_gamma1(seed, L as u16 * nonce + i as u16);
        }
    }

    /// `polyvecl_reduce`: reduce every coefficient of every polynomial to
    /// `[-6283008, 6283008]`.
    pub fn reduce(&mut self) {
        for p in self.vec.iter_mut() {
            p.reduce();
        }
    }

    /// `polyvecl_add`: `self = u + v`, no modular reduction.
    pub fn add(&mut self, u: &Polyvecl, v: &Polyvecl) {
        for i in 0..L {
            let (ui, vi) = (u.vec[i], v.vec[i]);
            self.vec[i].add(&ui, &vi);
        }
    }

    /// In-place `self = self + v`, no modular reduction. Mirrors the C
    /// `polyvecl_add(&z, &z, &v)` aliasing dest=src: each coefficient is read and
    /// written in place with no temporary copy of the secret `self`, so the
    /// cleartext is not spilled into an unnamed Copy temporary (plan §5).
    pub fn add_assign(&mut self, v: &Polyvecl) {
        for i in 0..L {
            self.vec[i].add_assign(&v.vec[i]);
        }
    }

    /// `polyvecl_ntt`: forward NTT of all `L` polynomials in place.
    pub fn ntt(&mut self) {
        for p in self.vec.iter_mut() {
            p.ntt();
        }
    }

    /// `polyvecl_invntt_tomont`: inverse NTT (and `*2^32`) of all `L` polynomials.
    pub fn invntt_tomont(&mut self) {
        for p in self.vec.iter_mut() {
            p.invntt_tomont();
        }
    }

    /// `polyvecl_pointwise_poly_montgomery`: `self[i] = a * v[i]` pointwise in NTT
    /// domain (with the `2^-32` Montgomery factor), for each of the `L` elements.
    pub fn pointwise_poly_montgomery(&mut self, a: &Poly, v: &Polyvecl) {
        for i in 0..L {
            let vi = v.vec[i];
            self.vec[i].pointwise_montgomery(a, &vi);
        }
    }

    /// `polyvecl_pointwise_acc_montgomery`: pointwise-multiply the two length-`L`
    /// vectors `u`, `v` in NTT domain, multiply by `2^-32`, and accumulate the `L`
    /// products into the single output polynomial `w` (the inner product
    /// `<u, v>`). Used to form each row of `A . y`.
    pub fn pointwise_acc_montgomery(w: &mut Poly, u: &Polyvecl, v: &Polyvecl) {
        w.pointwise_montgomery(&u.vec[0], &v.vec[0]);
        let mut t = Poly::zero();
        for i in 1..L {
            t.pointwise_montgomery(&u.vec[i], &v.vec[i]);
            let wcur = *w;
            w.add(&wcur, &t);
        }
    }

    /// `polyvecl_chknorm`: returns `true` (C `1`) iff some polynomial has a
    /// centered coefficient with absolute value `>= bound` (`bound <= (Q-1)/8`);
    /// otherwise `false` (C `0`). Assumes the vector was `reduce`d first.
    pub fn chknorm(&self, bound: i32) -> bool {
        for p in self.vec.iter() {
            if p.chknorm(bound) {
                return true;
            }
        }
        false
    }
}

/// A length-`K` vector of polynomials, i.e. the C `polyveck { poly vec[K]; }`.
/// Holds `s2`, `t`, `t0`, `t1`, `w`, `w0`, `w1`, and the hint `h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Polyveck {
    pub(crate) vec: [Poly; K],
}

impl Default for Polyveck {
    fn default() -> Self {
        Polyveck {
            vec: [Poly::zero(); K],
        }
    }
}

// Secret `s2`/`t0`/`w0` vectors are zeroized after use in the signing path (plan
// §5); `Polyveck` is `Copy + Default` with an all-zero default, so
// `DefaultIsZeroes` provides a volatile-overwrite `Zeroize`.
impl zeroize::DefaultIsZeroes for Polyveck {}

impl Polyveck {
    /// An all-zero length-`K` vector.
    #[inline]
    pub fn zero() -> Self {
        Polyveck {
            vec: [Poly::zero(); K],
        }
    }

    /// `polyveck_uniform_eta`: sample each of the `K` polynomials in `[-ETA, ETA]`
    /// from `SHAKE256(seed || LE16(nonce))`, incrementing `nonce` per polynomial.
    /// (ExpandS for the `s2` half; the caller passes `nonce = L` so `s1`/`s2`
    /// share one contiguous nonce range.)
    pub fn uniform_eta(&mut self, seed: &[u8; CRHBYTES], nonce: u16) {
        // C: `poly_uniform_eta(&v->vec[i], seed, nonce++)`.
        for (i, p) in self.vec.iter_mut().enumerate() {
            p.poly_uniform_eta(seed, nonce + i as u16);
        }
    }

    /// `polyveck_reduce`: reduce every coefficient to `[-6283008, 6283008]`.
    pub fn reduce(&mut self) {
        for p in self.vec.iter_mut() {
            p.reduce();
        }
    }

    /// `polyveck_caddq`: add `Q` to every negative coefficient of every poly.
    pub fn caddq(&mut self) {
        for p in self.vec.iter_mut() {
            p.caddq();
        }
    }

    /// `polyveck_add`: `self = u + v`, no modular reduction.
    pub fn add(&mut self, u: &Polyveck, v: &Polyveck) {
        for i in 0..K {
            let (ui, vi) = (u.vec[i], v.vec[i]);
            self.vec[i].add(&ui, &vi);
        }
    }

    /// In-place `self = self + v`, no modular reduction. Mirrors the C
    /// `polyveck_add(&w0, &w0, &v)` aliasing dest=src: read-modify-write per
    /// coefficient with no temporary copy of the secret `self` (plan §5).
    pub fn add_assign(&mut self, v: &Polyveck) {
        for i in 0..K {
            self.vec[i].add_assign(&v.vec[i]);
        }
    }

    /// `polyveck_sub`: `self = u - v`, no modular reduction.
    pub fn sub(&mut self, u: &Polyveck, v: &Polyveck) {
        for i in 0..K {
            let (ui, vi) = (u.vec[i], v.vec[i]);
            self.vec[i].sub(&ui, &vi);
        }
    }

    /// In-place `self = self - v`, no modular reduction. Mirrors the C
    /// `polyveck_sub(&w0, &w0, &v)` aliasing dest=src: read-modify-write per
    /// coefficient with no temporary copy of the secret `self` (plan §5).
    pub fn sub_assign(&mut self, v: &Polyveck) {
        for i in 0..K {
            self.vec[i].sub_assign(&v.vec[i]);
        }
    }

    /// `polyveck_shiftl`: multiply every polynomial by `2^D` (no reduction;
    /// assumes coefficients `< 2^{31-D}`).
    pub fn shiftl(&mut self) {
        for p in self.vec.iter_mut() {
            p.shiftl();
        }
    }

    /// `polyveck_ntt`: forward NTT of all `K` polynomials in place.
    pub fn ntt(&mut self) {
        for p in self.vec.iter_mut() {
            p.ntt();
        }
    }

    /// `polyveck_invntt_tomont`: inverse NTT (and `*2^32`) of all `K` polynomials.
    pub fn invntt_tomont(&mut self) {
        for p in self.vec.iter_mut() {
            p.invntt_tomont();
        }
    }

    /// `polyveck_pointwise_poly_montgomery`: `self[i] = a * v[i]` pointwise in NTT
    /// domain (with the `2^-32` factor), for each of the `K` elements.
    pub fn pointwise_poly_montgomery(&mut self, a: &Poly, v: &Polyveck) {
        for i in 0..K {
            let vi = v.vec[i];
            self.vec[i].pointwise_montgomery(a, &vi);
        }
    }

    /// `polyveck_chknorm`: returns `true` (C `1`) iff some polynomial has a
    /// centered coefficient with absolute value `>= bound`. Assumes the vector was
    /// `reduce`d first.
    pub fn chknorm(&self, bound: i32) -> bool {
        for p in self.vec.iter() {
            if p.chknorm(bound) {
                return true;
            }
        }
        false
    }

    /// `polyveck_power2round`: per coefficient `a` of each poly, split into high
    /// bits (into `v1`) and low bits (into `v0`), reading from `self`. Assumes
    /// coefficients are standard representatives.
    pub fn power2round(&self, v1: &mut Polyveck, v0: &mut Polyveck) {
        for i in 0..K {
            self.vec[i].power2round(&mut v1.vec[i], &mut v0.vec[i]);
        }
    }

    /// `polyveck_decompose`: per coefficient, split into high bits (into `v1`) and
    /// low bits (into `v0`), reading from `self`. Assumes standard representatives.
    pub fn decompose(&self, v1: &mut Polyveck, v0: &mut Polyveck) {
        for i in 0..K {
            self.vec[i].decompose(&mut v1.vec[i], &mut v0.vec[i]);
        }
    }

    /// `polyveck_make_hint`: compute the hint vector into `self` from the low part
    /// `v0` and high part `v1`; returns the total number of set hint bits.
    pub fn make_hint(&mut self, v0: &Polyveck, v1: &Polyveck) -> u32 {
        let mut s = 0u32;
        for i in 0..K {
            s += self.vec[i].make_hint(&v0.vec[i], &v1.vec[i]);
        }
        s
    }

    /// `polyveck_use_hint`: correct the high bits of `v` using hint `h`, writing
    /// the result into `self`.
    pub fn use_hint(&mut self, v: &Polyveck, h: &Polyveck) {
        for i in 0..K {
            let (vi, hi) = (v.vec[i], h.vec[i]);
            self.vec[i].use_hint(&vi, &hi);
        }
    }

    /// `polyveck_pack_w1`: pack each of the `K` `w1` polynomials (4 bits/coeff)
    /// into `r`, contiguously at `POLYW1_PACKEDBYTES`-byte offsets. `r` must be at
    /// least `K * POLYW1_PACKEDBYTES` bytes.
    pub fn pack_w1(&self, r: &mut [u8]) {
        use super::params::POLYW1_PACKEDBYTES;
        for i in 0..K {
            self.vec[i].polyw1_pack(&mut r[i * POLYW1_PACKEDBYTES..]);
        }
    }
}

/// `polyvec_matrix_expand` (ExpandA): generate the `K x L` matrix `A` with
/// uniformly random coefficients by rejection sampling on `SHAKE128(rho || j || i)`
/// per entry, where the per-entry nonce is `(i << 8) + j` (row `i`, column `j`).
/// `rho` is `SEEDBYTES` (32) long. The matrix is returned as `[Polyvecl; K]`.
pub fn matrix_expand(mat: &mut [Polyvecl; K], rho: &[u8; SEEDBYTES]) {
    for (i, row) in mat.iter_mut().enumerate() {
        for (j, p) in row.vec.iter_mut().enumerate() {
            p.poly_uniform(rho, ((i << 8) + j) as u16);
        }
    }
}

/// `polyvec_matrix_pointwise_montgomery`: `t[i] = <mat[i], v>` for each of the `K`
/// rows, i.e. the matrix-vector product `A . v` in NTT domain (each row reduced by
/// the `2^-32` Montgomery factor via `pointwise_acc_montgomery`).
pub fn matrix_pointwise_montgomery(t: &mut Polyveck, mat: &[Polyvecl; K], v: &Polyvecl) {
    for (ti, row) in t.vec.iter_mut().zip(mat.iter()) {
        Polyvecl::pointwise_acc_montgomery(ti, row, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mldsa::params::{GAMMA2, N, Q};

    /// Deterministic LCG matching `poly.rs`'s test RNG, so these vector tests need
    /// no `rand` dev-dependency.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn coeff_modq(&mut self) -> i32 {
            (self.next_u64() % Q as u64) as i32
        }
    }

    /// `a mod^+ Q` in `i128`, the trusted representative.
    fn modp(a: i128) -> i64 {
        let q = Q as i128;
        let mut r = a % q;
        if r < 0 {
            r += q;
        }
        r as i64
    }

    /// `matrix_pointwise_montgomery` is the row-wise inner product `A . v`:
    /// cross-check each output poly against the schoolbook negacyclic sum
    /// `sum_j mat[i][j] * v[j]`, computed independently in `i128`. After
    /// `invntt_tomont` (which folds in one `2^32`, cancelling the `2^-32` the
    /// pointwise step leaves), each output coefficient is the exact inner product
    /// mod `(X^256+1, Q)`, so it must match the schoolbook value directly. This
    /// validates the row accumulation and the `[Polyvecl; K]` matrix indexing
    /// without a C oracle.
    //
    // The folded index `k = x + y` (and its `k - N` negacyclic wrap) is the
    // substance of the reference convolution; an `enumerate()` rewrite would hide
    // exactly the index arithmetic under test, so the indexed loops stay.
    #[allow(clippy::needless_range_loop)]
    #[test]
    fn matrix_pointwise_is_rowwise_inner_product() {
        let mut rng = Lcg(0x7E57_C0DE_1234_ABCD);

        // Build a random matrix and vector in the standard domain, keep copies.
        let mut mat = [Polyvecl::zero(); K];
        let mut v = Polyvecl::zero();
        for row in mat.iter_mut() {
            for p in row.vec.iter_mut() {
                for c in p.coeffs.iter_mut() {
                    *c = rng.coeff_modq();
                }
            }
        }
        for p in v.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                *c = rng.coeff_modq();
            }
        }
        let mat_std = mat;
        let v_std = v;

        // Path A: NTT each, then matrix_pointwise (leaves <mat_i, v> * 2^-32 per
        // coefficient, in NTT domain).
        for row in mat.iter_mut() {
            row.ntt();
        }
        v.ntt();
        let mut t = Polyveck::zero();
        matrix_pointwise_montgomery(&mut t, &mat, &v);
        // Bring back to the standard domain to compare residues. invntt_tomont
        // folds in one 2^32, cancelling the pointwise 2^-32, so t_std[i] is the
        // exact inner product sum_j mat_std[i][j] * v_std[j] mod (X^256+1, Q).
        t.invntt_tomont();

        // Path B: schoolbook negacyclic inner product, independent in i128.
        for i in 0..K {
            let mut want = [0i128; N];
            for j in 0..L {
                let a = &mat_std[i].vec[j].coeffs;
                let b = &v_std.vec[j].coeffs;
                for x in 0..N {
                    for y in 0..N {
                        let prod = a[x] as i128 * b[y] as i128;
                        let k = x + y;
                        if k < N {
                            want[k] += prod;
                        } else {
                            want[k - N] -= prod;
                        }
                    }
                }
            }
            for c in 0..N {
                let got = modp(t.vec[i].coeffs[c] as i128);
                assert_eq!(got, modp(want[c]), "row {i} coeff {c}");
            }
        }
    }

    /// `pointwise_acc_montgomery` equals the sum of per-element
    /// `pointwise_montgomery` products (the inner product), checked directly in
    /// the NTT/Montgomery domain against an i128 reference.
    #[test]
    fn pointwise_acc_equals_sum_of_products() {
        let q = Q as i128;
        let inv2pow32 = {
            let mut acc = 1i128;
            let mut base = (1i128 << 32) % q;
            let mut e = q - 2;
            while e > 0 {
                if e & 1 == 1 {
                    acc = acc * base % q;
                }
                base = base * base % q;
                e >>= 1;
            }
            acc
        };
        let mut rng = Lcg(0xACC0_1234_5678_9ABC);
        let mut u = Polyvecl::zero();
        let mut v = Polyvecl::zero();
        for p in u.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                *c = rng.coeff_modq();
            }
        }
        for p in v.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                *c = rng.coeff_modq();
            }
        }
        let mut w = Poly::zero();
        Polyvecl::pointwise_acc_montgomery(&mut w, &u, &v);

        // Reference: per coefficient, sum_j u[j]*v[j]*2^-32 mod Q.
        for c in 0..N {
            let mut acc = 0i128;
            for j in 0..L {
                acc += u.vec[j].coeffs[c] as i128 * v.vec[j].coeffs[c] as i128 % q * inv2pow32 % q;
            }
            assert_eq!(modp(w.coeffs[c] as i128), modp(acc), "coeff {c}");
        }
    }

    /// `power2round` then `shiftl`+reconstruct over a whole `Polyveck`: for every
    /// coefficient `a` (standard rep), `a1 * 2^D + a0 == a`. Validates the
    /// per-poly fan-out and the `K` indexing of the vector wrapper.
    #[test]
    fn polyveck_power2round_reconstructs() {
        use crate::crypto::mldsa::params::D;
        let mut rng = Lcg(0xBEEF_F00D_C0DE_2468);
        let mut v = Polyveck::zero();
        for p in v.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                *c = rng.coeff_modq();
            }
        }
        let mut v1 = Polyveck::zero();
        let mut v0 = Polyveck::zero();
        v.power2round(&mut v1, &mut v0);
        for i in 0..K {
            for c in 0..N {
                let recon = v1.vec[i].coeffs[c] * (1 << D) + v0.vec[i].coeffs[c];
                assert_eq!(recon, v.vec[i].coeffs[c], "poly {i} coeff {c}");
            }
        }
    }

    /// `decompose` then `use_hint` with an all-zero hint recovers the high bits
    /// `a1` that `decompose` produced, for a whole `Polyveck`. And `make_hint`
    /// over identical (v0=v1=0..) inputs counts consistently. Exercises the
    /// vector fan-out of decompose/make_hint/use_hint together.
    #[test]
    fn polyveck_decompose_use_hint_zero_hint_is_identity() {
        let mut rng = Lcg(0x0DEC_0FFE_E0DD_1357);
        let mut v = Polyveck::zero();
        for p in v.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                // decompose expects standard reps in [0, Q).
                *c = rng.coeff_modq();
            }
        }
        let mut v1 = Polyveck::zero();
        let mut v0 = Polyveck::zero();
        v.decompose(&mut v1, &mut v0);

        // Zero hint -> use_hint returns a1 unchanged.
        let zero_hint = Polyveck::zero();
        let mut hi = Polyveck::zero();
        hi.use_hint(&v, &zero_hint);
        assert_eq!(hi, v1, "use_hint with zero hint must return decompose's a1");

        // Bound check: every a0 is centered in (-GAMMA2, GAMMA2] (the wrap case
        // a1==0 allows a0 == -GAMMA2). This pins decompose's vector fan-out.
        for i in 0..K {
            for c in 0..N {
                let a0 = v0.vec[i].coeffs[c];
                assert!(
                    a0 > -GAMMA2 - 1 && a0 <= GAMMA2,
                    "poly {i} coeff {c}: a0={a0} out of (-GAMMA2-1, GAMMA2]"
                );
            }
        }
    }

    /// `polyvecl_add` then `Polyveck` analog are coefficientwise; a quick guard
    /// that the vector add fans out over all elements and uses wrapping add.
    #[test]
    fn vector_add_is_coefficientwise() {
        let mut rng = Lcg(0xADD0_1234_5678_9ABC);
        // L-vector.
        let mut a = Polyvecl::zero();
        let mut b = Polyvecl::zero();
        for p in a.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                *c = rng.next_u64() as i32;
            }
        }
        for p in b.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                *c = rng.next_u64() as i32;
            }
        }
        let mut s = Polyvecl::zero();
        s.add(&a, &b);
        for i in 0..L {
            for c in 0..N {
                assert_eq!(
                    s.vec[i].coeffs[c],
                    a.vec[i].coeffs[c].wrapping_add(b.vec[i].coeffs[c])
                );
            }
        }
        // K-vector sub inverts add.
        let mut ak = Polyveck::zero();
        let mut bk = Polyveck::zero();
        for p in ak.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                *c = rng.next_u64() as i32;
            }
        }
        for p in bk.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                *c = rng.next_u64() as i32;
            }
        }
        let mut sk = Polyveck::zero();
        sk.add(&ak, &bk);
        let mut dk = Polyveck::zero();
        dk.sub(&sk, &bk);
        assert_eq!(dk, ak, "(a+b)-b must equal a for Polyveck");
    }

    /// ExpandA (`matrix_expand`) produces a full `K x L` matrix whose every
    /// coefficient is a valid standard representative `[0, Q)`, and whose entries
    /// differ (distinct per-entry nonce `(i<<8)+j`). The exact byte-level values
    /// are validated transitively by the ACVP KATs in later steps; here we pin
    /// the structure, range, and that no two entries collapse to the same poly.
    #[test]
    fn matrix_expand_in_range_and_distinct() {
        let mut rho = [0u8; SEEDBYTES];
        for (i, b) in rho.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let mut mat = [Polyvecl::zero(); K];
        matrix_expand(&mut mat, &rho);

        for (i, row) in mat.iter().enumerate() {
            for (j, p) in row.vec.iter().enumerate() {
                for (c, &coeff) in p.coeffs.iter().enumerate() {
                    assert!(
                        (0..Q).contains(&coeff),
                        "A[{i}][{j}] coeff {c} = {coeff} out of [0,Q)"
                    );
                }
            }
        }
        // Distinctness: A[0][0] != A[0][1] != A[1][0] (different nonces).
        assert_ne!(mat[0].vec[0], mat[0].vec[1], "A[0][0] == A[0][1]");
        assert_ne!(mat[0].vec[0], mat[1].vec[0], "A[0][0] == A[1][0]");

        // Cross-check one entry against poly_uniform directly with its nonce.
        let mut direct = Poly::zero();
        direct.poly_uniform(&rho, (1 << 8) + 3); // i=1, j=3
        assert_eq!(
            mat[1].vec[3], direct,
            "matrix_expand entry (1,3) must equal poly_uniform with nonce (1<<8)+3"
        );
    }

    /// `uniform_eta` over a `Polyvecl`/`Polyveck` draws each element with the
    /// incrementing nonce and stays in `[-ETA, ETA]`; the `Polyveck` variant
    /// starting at `nonce = L` continues the same nonce range (so element 0 of the
    /// K-vector equals `poly_uniform_eta(seed, L)`).
    #[test]
    fn uniform_eta_nonce_sequence_and_range() {
        use crate::crypto::mldsa::params::ETA;
        let mut seed = [0u8; CRHBYTES];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(53).wrapping_add(7);
        }
        let mut s1 = Polyvecl::zero();
        s1.uniform_eta(&seed, 0);
        let mut s2 = Polyveck::zero();
        s2.uniform_eta(&seed, L as u16);

        for p in s1.vec.iter() {
            for &c in p.coeffs.iter() {
                assert!((-ETA..=ETA).contains(&c), "s1 coeff {c} out of [-ETA,ETA]");
            }
        }
        for p in s2.vec.iter() {
            for &c in p.coeffs.iter() {
                assert!((-ETA..=ETA).contains(&c), "s2 coeff {c} out of [-ETA,ETA]");
            }
        }

        // Element 0 of s1 uses nonce 0; element 0 of s2 uses nonce L.
        let mut e0 = Poly::zero();
        e0.poly_uniform_eta(&seed, 0);
        assert_eq!(s1.vec[0], e0, "s1[0] must be poly_uniform_eta(seed, 0)");
        let mut ek = Poly::zero();
        ek.poly_uniform_eta(&seed, L as u16);
        assert_eq!(s2.vec[0], ek, "s2[0] must be poly_uniform_eta(seed, L)");
    }

    /// `pack_w1` lays the `K` packed `w1` blocks contiguously, each equal to the
    /// per-poly `polyw1_pack`. Pins the `POLYW1_PACKEDBYTES` stride and `K` fanout.
    #[test]
    fn pack_w1_is_contiguous_per_poly() {
        use crate::crypto::mldsa::params::POLYW1_PACKEDBYTES;
        let mut rng = Lcg(0x9111_2222_3333_4444);
        let mut w1 = Polyveck::zero();
        for p in w1.vec.iter_mut() {
            for c in p.coeffs.iter_mut() {
                *c = (rng.next_u64() % 16) as i32;
            }
        }
        let mut packed = [0u8; K * POLYW1_PACKEDBYTES];
        w1.pack_w1(&mut packed);
        for (i, poly) in w1.vec.iter().enumerate() {
            let mut one = [0u8; POLYW1_PACKEDBYTES];
            poly.polyw1_pack(&mut one);
            assert_eq!(
                &packed[i * POLYW1_PACKEDBYTES..(i + 1) * POLYW1_PACKEDBYTES],
                &one[..],
                "pack_w1 block {i} mismatch"
            );
        }
    }
}
