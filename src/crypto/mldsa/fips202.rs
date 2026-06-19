//! SHAKE128/256 helpers over the `sha3` crate. Mirrors `symmetric-shake.c` plus
//! the `fips202.c` `shake128`/`shake256` one-shots — the C `fips202.c` itself is
//! NOT ported, because Keccak-f1600 (its 24-entry round-constant table and rho
//! rotation offsets) is exactly as transcription-error-prone as the NTT zeta
//! table and a single wrong constant silently corrupts every signature. Instead
//! Keccak comes from the audited, KAT-tested, constant-time `sha3` (RustCrypto)
//! crate. **This is the ONLY file in the module that touches `sha3`.**
//!
//! Constant-time note (plan §5): SHAKE absorbs the secret seeds `key`,
//! `rhoprime`, and the `s1`/`s2` expansion, so the Keccak permutation must be
//! constant-time. `sha3`/`keccak` is straight-line ARX with loop-counter-indexed
//! round constants — required; do not swap it for a table/branchy Keccak.
//!
//! API mapping to PQClean's `fips202`/`symmetric.h` incremental usage:
//! - `shake128`/`shake256` one-shots → `fips202.c` `shake{128,256}`.
//! - [`Shake128Stream`]/[`Shake256Stream`] → `symmetric.h`'s
//!   `stream{128,256}_{init,squeezeblocks}` and `dilithium_shake{128,256}_stream_init`.
//!   The `sha3` `XofReader` carries sponge state across `.read()` calls, so a
//!   single reader replaces PQClean's `_inc_squeeze` block loop with no manual
//!   block bookkeeping; callers still control how many bytes they pull per step.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

/// SHAKE128 sponge rate in bytes (`fips202.h:7`). One squeezed Keccak block.
/// Used by the ExpandA sampler's block refill (`poly_uniform`).
pub const SHAKE128_RATE: usize = 168;
/// SHAKE256 sponge rate in bytes (`fips202.h:8`). One squeezed Keccak block.
/// Used by the ExpandS / ExpandMask / SampleInBall block refills.
pub const SHAKE256_RATE: usize = 136;

/// One-shot SHAKE256: absorb each slice in `inputs` (in order, equivalent to
/// absorbing their concatenation), then squeeze exactly `out.len()` bytes.
///
/// Mirrors `fips202.c`'s `shake256(out, outlen, in, inlen)`; the slice list lets
/// callers build the ML-DSA hash inputs directly, e.g.
/// `mu = SHAKE256(tr || 0x00 || ctxlen || ctx || msg)` or
/// `rhoprime = SHAKE256(key || rnd || mu)` (plan §3 step 10), and the keygen
/// `H(seed || K || L)` / `tr = H(pk)` calls.
pub fn shake256(out: &mut [u8], inputs: &[&[u8]]) {
    let mut h = Shake256::default();
    for chunk in inputs {
        h.update(chunk);
    }
    let mut reader = h.finalize_xof();
    reader.read(out);
    // `sha3`'s `zeroize` feature makes `Sha3State` (the [u64;25] Keccak sponge)
    // ZeroizeOnDrop; both `h` and `reader` (which owns the post-finalize
    // Sha3State) scrub it on drop, so secret-derived absorbed material — e.g.
    // `key`/`rnd` in the rhoprime derivation — leaves no sponge residue here.
    // (Source secrets are also zeroized at their bindings; squeezed output is
    // captured into Zeroizing buffers by callers.)
}

/// One-shot SHAKE128: absorb each slice in `inputs` (in order), then squeeze
/// exactly `out.len()` bytes. Mirrors `fips202.c`'s `shake128`.
pub fn shake128(out: &mut [u8], inputs: &[&[u8]]) {
    let mut h = Shake128::default();
    for chunk in inputs {
        h.update(chunk);
    }
    let mut reader = h.finalize_xof();
    reader.read(out);
}

/// Encode the 16-bit domain-separation nonce as 2 little-endian bytes, exactly
/// as `dilithium_shake{128,256}_stream_init` does
/// (`t[0] = nonce & 0xff; t[1] = nonce >> 8`).
#[inline]
fn nonce_bytes(nonce: u16) -> [u8; 2] {
    nonce.to_le_bytes()
}

/// Incremental SHAKE128 absorb-once / squeeze-many stream, mirroring
/// `symmetric.h`'s `stream128` over `dilithium_shake128_stream_init`.
///
/// Construction (`symmetric-shake.c`): absorb `seed` (32 bytes), then the 2-byte
/// little-endian `nonce`, finalize, then squeeze. Used by ExpandA (`poly_uniform`).
/// The underlying `XofReader` persists sponge state, so repeated [`read`] calls
/// continue the same output stream — the caller decides how many bytes to pull
/// (full `SHAKE128_RATE` blocks, then single-block refills, in the C sampler).
///
/// [`read`]: Shake128Stream::read
pub struct Shake128Stream {
    reader: sha3::Shake128Reader,
}

impl Shake128Stream {
    /// `stream128_init`: absorb `seed || LE16(nonce)` and finalize.
    pub fn init(seed: &[u8], nonce: u16) -> Self {
        let mut h = Shake128::default();
        h.update(seed);
        h.update(&nonce_bytes(nonce));
        Self {
            reader: h.finalize_xof(),
        }
    }

    /// Squeeze the next `out.len()` bytes from the persistent stream.
    /// Equivalent to PQClean's `stream128_squeezeblocks` but byte-granular.
    pub fn read(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

/// Incremental SHAKE256 absorb-once / squeeze-many stream, mirroring
/// `symmetric.h`'s `stream256` over `dilithium_shake256_stream_init`.
///
/// Construction (`symmetric-shake.c`): absorb `seed` (64 bytes for the ML-DSA
/// callers), then the 2-byte little-endian `nonce`, finalize, then squeeze. Used
/// by ExpandS (`poly_uniform_eta`) and ExpandMask (`poly_uniform_gamma1`). State
/// persists across [`read`] calls.
///
/// [`read`]: Shake256Stream::read
pub struct Shake256Stream {
    reader: sha3::Shake256Reader,
}

impl Shake256Stream {
    /// `stream256_init`: absorb `seed || LE16(nonce)` and finalize.
    pub fn init(seed: &[u8], nonce: u16) -> Self {
        let mut h = Shake256::default();
        h.update(seed);
        h.update(&nonce_bytes(nonce));
        Self {
            reader: h.finalize_xof(),
        }
    }

    /// Absorb `seed` ALONE (no nonce) and finalize. Mirrors `poly_challenge`'s
    /// `shake256_inc_init; shake256_inc_absorb(seed); shake256_inc_finalize`
    /// (SampleInBall hashes only the `c~` commitment, with no domain nonce). The
    /// caller squeezes a `SHAKE256_RATE` block at a time, persisting sponge state.
    pub fn init_xof(seed: &[u8]) -> Self {
        let mut h = Shake256::default();
        h.update(seed);
        Self {
            reader: h.finalize_xof(),
        }
    }

    /// Squeeze the next `out.len()` bytes from the persistent stream.
    /// Equivalent to PQClean's `stream256_squeezeblocks` but byte-granular.
    pub fn read(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a lowercase hex string into a byte vector (test-only helper, so the
    /// self-test does not depend on the `hex` dev-dep being wired for unit tests).
    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Published SHAKE known-answer values (FIPS 202), independently confirmed
    // with Python `hashlib.shake_{128,256}` before being baked in here.
    // SHAKE128("abc")[0..10] also matches the `sha3` crate's own doctest.

    #[test]
    fn shake128_kat() {
        // SHAKE128("")[0..16]
        let mut out = [0u8; 16];
        shake128(&mut out, &[b""]);
        assert_eq!(out.to_vec(), unhex("7f9c2ba4e88f827d616045507605853e"));

        // SHAKE128("abc")[0..10]
        let mut out = [0u8; 10];
        shake128(&mut out, &[b"abc"]);
        assert_eq!(out.to_vec(), unhex("5881092dd818bf5cf8a3"));
    }

    #[test]
    fn shake256_kat() {
        // SHAKE256("")[0..32]
        let mut out = [0u8; 32];
        shake256(&mut out, &[b""]);
        assert_eq!(
            out.to_vec(),
            unhex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        );

        // SHAKE256("abc")[0..32]
        let mut out = [0u8; 32];
        shake256(&mut out, &[b"abc"]);
        assert_eq!(
            out.to_vec(),
            unhex("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")
        );
    }

    /// Absorbing a split input must equal the one-shot over its concatenation:
    /// validates the multi-slice absorb used to build ML-DSA hash inputs.
    #[test]
    fn incremental_absorb_equals_concat() {
        let whole = b"ParallaX ML-DSA-87 fips202 self-test absorb concatenation";
        let mut one_shot = [0u8; 48];
        shake256(&mut one_shot, &[whole]);

        // Same bytes, fed as three separate slices.
        let mut split = [0u8; 48];
        shake256(&mut split, &[&whole[..10], &whole[10..30], &whole[30..]]);
        assert_eq!(one_shot, split);

        // And SHAKE256("abc") via two slices "ab" || "c".
        let mut joined = [0u8; 32];
        shake256(&mut joined, &[b"ab", b"c"]);
        assert_eq!(
            joined.to_vec(),
            unhex("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")
        );
    }

    /// The 2-byte little-endian nonce encoding must match
    /// `dilithium_shake*_stream_init` (`t[0]=nonce&0xff; t[1]=nonce>>8`).
    #[test]
    fn stream_nonce_is_le16_and_state_persists() {
        let seed = [0xA5u8; 32];
        let nonce: u16 = 0x0102; // -> bytes [0x02, 0x01]

        // Stream output must equal a one-shot over seed || [0x02,0x01],
        // and must continue (persistent sponge) across two reads.
        let mut stream = Shake128Stream::init(&seed, nonce);
        let mut s_first = [0u8; SHAKE128_RATE];
        let mut s_second = [0u8; 40];
        stream.read(&mut s_first);
        stream.read(&mut s_second);

        let mut expected = [0u8; SHAKE128_RATE + 40];
        shake128(&mut expected, &[&seed, &[0x02, 0x01]]);
        assert_eq!(s_first.as_slice(), &expected[..SHAKE128_RATE]);
        assert_eq!(s_second.as_slice(), &expected[SHAKE128_RATE..]);

        // Same for SHAKE256 stream (64-byte seed in the real callers; the
        // construction is identical regardless of seed length).
        let seed256 = [0x3Cu8; 64];
        let mut stream = Shake256Stream::init(&seed256, nonce);
        let mut got = [0u8; SHAKE256_RATE + 16];
        stream.read(&mut got);
        let mut expected = [0u8; SHAKE256_RATE + 16];
        shake256(&mut expected, &[&seed256, &[0x02, 0x01]]);
        assert_eq!(got, expected);
    }
}
