//! Systematic block Reed-Solomon erasure code over GF(2^8), for the UDP datagram
//! fast plane's forward error correction.
//!
//! WHY hand-rolled (not a crate): this is a censorship-resistance tool that prizes
//! a tiny, auditable dependency set; the requirement here is the minimal one —
//! "recover up to `r` lost symbols out of a `k`-source window" — which is exactly a
//! bounded block code, not a fountain code or a sliding-window RLC. The dangerous
//! finite-field math is small, fully table-driven, and EXHAUSTIVELY testable
//! (encode -> drop every r-subset -> decode -> assert byte-identical).
//!
//! WHY it is safe to hand-roll: we ONLY ever do ERASURE decoding (the missing
//! symbol indices are known a priori — a datagram either arrived or it did not),
//! never error-correction. And — at the carrier integration layer, NOT here — the
//! symbols are the post-seal AEAD *ciphertext* records, each carrying its own
//! Poly1305 tag: a recovered symbol that is wrong fails to open and is treated as
//! still-missing (then the gap demotes). So a bug in this module can only ever
//! turn into a recoverable-loss-not-recovered (a demote), never silent plaintext
//! corruption. This module itself is crypto-agnostic: it erasure-codes opaque
//! fixed-length byte symbols and knows nothing of AEAD.
//!
//! MDS construction: the encoding matrix is `[ I_k ; C ]` where `C` is an `r x k`
//! Cauchy matrix `C[i][j] = 1 / (x_i ^ y_j)` over GF(2^8) with the `x_i` and `y_j`
//! drawn from disjoint sets. Every Cauchy matrix is invertible and, crucially,
//! every square submatrix of a Cauchy matrix is invertible, so ANY `k` of the
//! `k + r` encoded symbols suffice to recover the `k` sources. This sidesteps the
//! well-known trap that a Vandermonde matrix made systematic is NOT guaranteed MDS
//! for all (k, r) over GF(2^8).
//!
//! Not yet wired into any carrier (the datagram leg lands in a later slice); kept
//! behind `#![allow(dead_code)]` exactly like `envelope`/`reorder`.
#![allow(dead_code)]

/// Primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D) with generator α = 2 —
/// the standard GF(2^8) field used by QR codes, chosen because α = 2 is primitive
/// for this polynomial (the table build below asserts full period 255).
const GF_POLY: u16 = 0x11D;

/// `(exp, log)` tables built at compile time. `exp` is doubled (length 512) so a
/// multiply can index `exp[log[a] + log[b]]` without a modular reduction.
const fn build_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= GF_POLY;
        }
        i += 1;
    }
    // Mirror the first 255 entries so exp[i + 255] == exp[i] for i in 0..255,
    // letting the multiply add two logs (each <= 254) and index directly.
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = build_tables();

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = &TABLES;
    exp[log[a as usize] as usize + log[b as usize] as usize]
}

/// Multiplicative inverse in GF(2^8). `a` must be non-zero.
#[inline]
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "GF(2^8) inverse of zero is undefined");
    let (exp, log) = &TABLES;
    // a^-1 = α^(255 - log a)
    exp[255 - log[a as usize] as usize]
}

/// Errors from the erasure coder. None of these can be a silent miscorrection: a
/// decode either reconstructs every source byte-exactly or returns an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FecError {
    /// `k`/`r` out of range: require `k >= 1`, `r >= 1`, and `k + r <= 255` (the
    /// Cauchy `x_i`/`y_j` must be distinct GF(2^8) elements).
    InvalidParams,
    /// A symbol slice had the wrong length, or `sources`/`present` had the wrong
    /// count for this code's `k`/`r`.
    ShapeMismatch,
    /// Fewer than `k` of the `k + r` symbols are present: the loss exceeded the
    /// code's redundancy and the window is unrecoverable. NEVER returns wrong
    /// bytes — the caller must treat this as a gap (demote), not as data.
    Insufficient,
}

/// A systematic `(k, r)` Reed-Solomon erasure coder over GF(2^8): `k` source
/// symbols are encoded into `r` repair symbols; any `k` of the `k + r` recover all.
pub(crate) struct RsFec {
    k: usize,
    r: usize,
    /// Row-major `r x k` Cauchy parity matrix: `parity[i * k + j]`.
    parity: Vec<u8>,
}

impl RsFec {
    pub(crate) fn new(k: usize, r: usize) -> Result<Self, FecError> {
        if k == 0 || r == 0 || k + r > 255 {
            return Err(FecError::InvalidParams);
        }
        // Cauchy parity: y_j = j (0..k), x_i = k + i (k..k+r). The two ranges are
        // disjoint, so x_i ^ y_j != 0 for all i, j. parity[i][j] = 1 / (x_i ^ y_j).
        let mut parity = vec![0u8; r * k];
        for i in 0..r {
            let x = (k + i) as u8;
            for j in 0..k {
                let y = j as u8;
                parity[i * k + j] = gf_inv(x ^ y);
            }
        }
        Ok(Self { k, r, parity })
    }

    pub(crate) fn k(&self) -> usize {
        self.k
    }

    pub(crate) fn r(&self) -> usize {
        self.r
    }

    /// Encode `k` source symbols (each exactly `len` bytes) into `r` repair
    /// symbols (each `len` bytes). Repair symbol `i` byte `b` is
    /// `Σ_j parity[i][j] * source[j][b]` over GF(2^8).
    pub(crate) fn encode(&self, sources: &[&[u8]], len: usize) -> Result<Vec<Vec<u8>>, FecError> {
        if sources.len() != self.k || sources.iter().any(|s| s.len() != len) {
            return Err(FecError::ShapeMismatch);
        }
        let mut repair = vec![vec![0u8; len]; self.r];
        for (i, out) in repair.iter_mut().enumerate() {
            let row = &self.parity[i * self.k..(i + 1) * self.k];
            for (j, &coeff) in row.iter().enumerate() {
                if coeff == 0 {
                    continue;
                }
                let src = sources[j];
                for b in 0..len {
                    out[b] ^= gf_mul(coeff, src[b]);
                }
            }
        }
        Ok(repair)
    }

    /// Erasure-decode. `present` has length `k + r`: index `0..k` are the source
    /// symbols (in order), `k..k+r` the repair symbols; each entry is `Some(sym)`
    /// if that symbol arrived (exactly `len` bytes) or `None` if it was lost.
    /// Returns the `k` source symbols, reconstructing any that were lost.
    ///
    /// Solves `source = M^-1 * received`, where `M` is the `k x k` matrix formed by
    /// the encoding-matrix rows of the first `k` present symbols. Because every
    /// square submatrix of `[I; Cauchy]` is invertible, any `k` present symbols
    /// yield an invertible `M`.
    pub(crate) fn decode(
        &self,
        present: &[Option<&[u8]>],
        len: usize,
    ) -> Result<Vec<Vec<u8>>, FecError> {
        let n = self.k + self.r;
        if present.len() != n {
            return Err(FecError::ShapeMismatch);
        }
        if present.iter().flatten().any(|s| s.len() != len) {
            return Err(FecError::ShapeMismatch);
        }

        // Fast path: all k source symbols arrived — no reconstruction needed.
        if (0..self.k).all(|j| present[j].is_some()) {
            return Ok((0..self.k)
                .map(|j| present[j].expect("source present").to_vec())
                .collect());
        }

        // Pick the first k present symbols and build the k x k matrix M of their
        // encoding-matrix rows (identity row e_j for source j, Cauchy row for
        // repair i), alongside the received symbol data for each chosen row.
        let mut m = vec![0u8; self.k * self.k]; // row-major k x k
        let mut rhs: Vec<&[u8]> = Vec::with_capacity(self.k);
        let mut chosen = 0usize;
        for (idx, sym) in present.iter().enumerate() {
            let Some(data) = sym else { continue };
            if chosen == self.k {
                break;
            }
            let row = &mut m[chosen * self.k..(chosen + 1) * self.k];
            if idx < self.k {
                // Source symbol idx -> unit row e_idx.
                row[idx] = 1;
            } else {
                // Repair symbol (idx - k) -> its Cauchy row.
                let i = idx - self.k;
                row.copy_from_slice(&self.parity[i * self.k..(i + 1) * self.k]);
            }
            rhs.push(data);
            chosen += 1;
        }
        if chosen < self.k {
            return Err(FecError::Insufficient);
        }

        let inv = gf_invert_matrix(&m, self.k)?;

        // source[j] = Σ_c inv[j][c] * rhs[c]   (per byte position).
        let mut out = vec![vec![0u8; len]; self.k];
        for (j, dst) in out.iter_mut().enumerate() {
            let inv_row = &inv[j * self.k..(j + 1) * self.k];
            for (c, &coeff) in inv_row.iter().enumerate() {
                if coeff == 0 {
                    continue;
                }
                let src = rhs[c];
                for b in 0..len {
                    dst[b] ^= gf_mul(coeff, src[b]);
                }
            }
        }
        Ok(out)
    }
}

/// Invert a `dim x dim` GF(2^8) matrix (row-major) by Gauss-Jordan elimination.
/// Returns `Insufficient` if the matrix is singular — which cannot happen for the
/// Cauchy-derived matrices this module builds, but is handled rather than
/// panicking so a future misuse degrades to a demote, not a crash.
fn gf_invert_matrix(src: &[u8], dim: usize) -> Result<Vec<u8>, FecError> {
    let mut a = src.to_vec();
    let mut inv = vec![0u8; dim * dim];
    for i in 0..dim {
        inv[i * dim + i] = 1;
    }
    for col in 0..dim {
        // Find a pivot row at or below `col` with a non-zero entry in `col`.
        let mut pivot = col;
        while pivot < dim && a[pivot * dim + col] == 0 {
            pivot += 1;
        }
        if pivot == dim {
            return Err(FecError::Insufficient);
        }
        if pivot != col {
            for c in 0..dim {
                a.swap(pivot * dim + c, col * dim + c);
                inv.swap(pivot * dim + c, col * dim + c);
            }
        }
        // Normalize the pivot row so a[col][col] == 1.
        let p = a[col * dim + col];
        if p != 1 {
            let pinv = gf_inv(p);
            for c in 0..dim {
                a[col * dim + c] = gf_mul(a[col * dim + c], pinv);
                inv[col * dim + c] = gf_mul(inv[col * dim + c], pinv);
            }
        }
        // Eliminate `col` from every other row.
        for row in 0..dim {
            if row == col {
                continue;
            }
            let f = a[row * dim + col];
            if f == 0 {
                continue;
            }
            for c in 0..dim {
                a[row * dim + c] ^= gf_mul(f, a[col * dim + c]);
                inv[row * dim + c] ^= gf_mul(f, inv[col * dim + c]);
            }
        }
    }
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn gf_tables_have_full_period_and_consistent_log_exp() {
        let (exp, log) = &TABLES;
        // α = 2 is primitive: the 255 powers cover every non-zero element exactly
        // once (if 2 were not primitive, some element would be missing/duplicated).
        let mut seen = [false; 256];
        for &v in exp.iter().take(255) {
            assert_ne!(v, 0, "no power of a generator is zero");
            assert!(
                !seen[v as usize],
                "period < 255: 2 is not primitive for 0x11D"
            );
            seen[v as usize] = true;
        }
        assert_eq!(seen.iter().filter(|&&s| s).count(), 255);
        // log/exp are inverses for every non-zero element.
        for a in 1u16..=255 {
            assert_eq!(exp[log[a as usize] as usize], a as u8);
        }
    }

    #[test]
    fn gf_mul_inv_are_consistent() {
        for a in 1u16..=255 {
            let a = a as u8;
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "a * a^-1 must be 1");
            assert_eq!(gf_mul(a, 0), 0);
            assert_eq!(gf_mul(0, a), 0);
            assert_eq!(gf_mul(a, 1), a);
        }
    }

    /// Helper: all r-subsets of 0..n, as boolean "lost" masks.
    fn for_each_subset(n: usize, r: usize, mut f: impl FnMut(&[usize])) {
        let mut idx: Vec<usize> = (0..r).collect();
        if r == 0 {
            f(&[]);
            return;
        }
        loop {
            f(&idx);
            // advance to the next r-combination of 0..n
            let mut i = r;
            loop {
                if i == 0 {
                    return;
                }
                i -= 1;
                if idx[i] != i + n - r {
                    break;
                }
            }
            idx[i] += 1;
            for j in i + 1..r {
                idx[j] = idx[j - 1] + 1;
            }
        }
    }

    /// THE keystone test: for small (k, r), for EVERY size-r subset of lost
    /// symbols among the k+r encoded symbols, decode reconstructs all k sources
    /// byte-exactly. r erasures is the code's exact redundancy — the worst case.
    #[test]
    fn recovers_every_size_r_loss_pattern_exactly() {
        let len = 23; // deliberately not a power of two
        for k in 1usize..=10 {
            for r in 1usize..=6 {
                if k + r > 16 {
                    continue;
                }
                let fec = RsFec::new(k, r).unwrap();
                let mut rng = StdRng::seed_from_u64(0xF0_00 + (k * 17 + r) as u64);
                let sources: Vec<Vec<u8>> = (0..k)
                    .map(|_| (0..len).map(|_| rng.gen()).collect())
                    .collect();
                let src_refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
                let repair = fec.encode(&src_refs, len).unwrap();

                let n = k + r;
                for_each_subset(n, r, |lost| {
                    let mut present: Vec<Option<&[u8]>> = Vec::with_capacity(n);
                    for idx in 0..n {
                        if lost.contains(&idx) {
                            present.push(None);
                        } else if idx < k {
                            present.push(Some(sources[idx].as_slice()));
                        } else {
                            present.push(Some(repair[idx - k].as_slice()));
                        }
                    }
                    let recovered = fec.decode(&present, len).unwrap();
                    assert_eq!(recovered, sources, "k={k} r={r} lost={lost:?}");
                });
            }
        }
    }

    /// Losing MORE than r symbols is unrecoverable and MUST return a typed error,
    /// never wrong bytes — the property that lets a decode bug degrade to a demote
    /// rather than corruption.
    #[test]
    fn beyond_redundancy_returns_insufficient_never_wrong_bytes() {
        let (k, r, len) = (8usize, 3usize, 40usize);
        let fec = RsFec::new(k, r).unwrap();
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        let sources: Vec<Vec<u8>> = (0..k)
            .map(|_| (0..len).map(|_| rng.gen()).collect())
            .collect();
        let src_refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
        let repair = fec.encode(&src_refs, len).unwrap();
        let n = k + r;
        // Drop r+1 symbols (every such subset): always Insufficient.
        for_each_subset(n, r + 1, |lost| {
            let present: Vec<Option<&[u8]>> = (0..n)
                .map(|idx| {
                    if lost.contains(&idx) {
                        None
                    } else if idx < k {
                        Some(sources[idx].as_slice())
                    } else {
                        Some(repair[idx - k].as_slice())
                    }
                })
                .collect();
            assert_eq!(fec.decode(&present, len), Err(FecError::Insufficient));
        });
    }

    /// A repair symbol computed over already-SEALED ciphertext records recovers the
    /// EXACT sealed bytes (not just "some valid record") — the property the carrier
    /// relies on for nonce-safety: a recovered symbol == the sealed record that
    /// would have arrived, so it opens at its own seq with no (key,nonce) reuse.
    /// This mirrors how the datagram carrier will use the coder (FEC over sealed
    /// bytes), proving the math composes with the AEAD layer above it.
    #[test]
    fn repair_recovers_exact_sealed_ciphertext_then_opens_under_aead() {
        use crate::crypto::session::{AeadCodec, KEY_LEN, NONCE_LEN};
        use crate::protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD};
        use crate::traffic::PaddingProfile;

        let key = [0x33u8; KEY_LEN];
        let nonce = [0x44u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap(); // deterministic bytes
        let mut seal =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut rng = StdRng::seed_from_u64(0x5EA1ED);

        let k = 4usize;
        let r = 2usize;
        let plaintexts: Vec<Vec<u8>> = vec![
            b"hello".to_vec(),
            vec![0xABu8; 17],
            b"datagram-fec".to_vec(),
            vec![0xCDu8; 5],
        ];
        // Seal each plaintext into its own record (seq 0..k), then pad to L_max.
        let sealed: Vec<Vec<u8>> = plaintexts
            .iter()
            .map(|p| seal.seal(p, &mut rng).unwrap())
            .collect();
        let l_max = sealed.iter().map(|s| s.len()).max().unwrap();
        let padded: Vec<Vec<u8>> = sealed
            .iter()
            .map(|s| {
                let mut v = s.clone();
                v.resize(l_max, 0);
                v
            })
            .collect();

        let fec = RsFec::new(k, r).unwrap();
        let src_refs: Vec<&[u8]> = padded.iter().map(|s| s.as_slice()).collect();
        let repair = fec.encode(&src_refs, l_max).unwrap();

        // Lose source symbols 1 and 2; recover them purely from repairs.
        let present: Vec<Option<&[u8]>> = vec![
            Some(padded[0].as_slice()),
            None,
            None,
            Some(padded[3].as_slice()),
            Some(repair[0].as_slice()),
            Some(repair[1].as_slice()),
        ];
        let recovered = fec.decode(&present, l_max).unwrap();
        assert_eq!(
            recovered, padded,
            "recovered symbols must be the exact padded sealed bytes"
        );

        // The recovered record (un-padded back to its sealed length) opens to the
        // original plaintext at its seq on a matched receive codec.
        let mut open = DataRecordCodec::new(
            AeadCodec::new(key, nonce),
            PaddingProfile::new(0, 0).unwrap(),
            CLIENT_TO_SERVER_AAD,
        );
        for (i, pt) in plaintexts.iter().enumerate() {
            let sealed_len = sealed[i].len();
            let rec = &recovered[i][..sealed_len];
            let opened = open.open(rec).unwrap();
            assert_eq!(
                &opened, pt,
                "record {i} must open to its original plaintext"
            );
        }
    }

    #[test]
    fn rejects_invalid_params_and_shapes() {
        assert_eq!(RsFec::new(0, 1).err(), Some(FecError::InvalidParams));
        assert_eq!(RsFec::new(1, 0).err(), Some(FecError::InvalidParams));
        assert_eq!(RsFec::new(200, 60).err(), Some(FecError::InvalidParams)); // k+r > 255
        let fec = RsFec::new(4, 2).unwrap();
        assert_eq!(
            fec.encode(&[&[0u8; 4]], 4).err(),
            Some(FecError::ShapeMismatch)
        ); // wrong source count
        assert_eq!(
            fec.decode(&[None, None, None], 4).err(),
            Some(FecError::ShapeMismatch) // wrong present count
        );
    }

    /// Encoding is deterministic: the same sources always yield the same repairs
    /// (no RNG, no global state) — required so a re-seal/replay is byte-identical.
    #[test]
    fn encode_is_deterministic() {
        let fec = RsFec::new(6, 3).unwrap();
        let sources: Vec<Vec<u8>> = (0..6).map(|j| vec![j as u8; 30]).collect();
        let refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
        assert_eq!(
            fec.encode(&refs, 30).unwrap(),
            fec.encode(&refs, 30).unwrap()
        );
    }
}
