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
//!   The `sha3` core carries sponge state, while this module owns and clears
//!   the absorb/output buffers across reads. Callers still control how many
//!   bytes they pull per step.

use sha3::digest::core_api::{
    Block, Buffer, BufferKindUser, ExtendableOutputCore, UpdateCore, XofReaderCore,
};
use sha3::digest::typenum::{IsLess, Le, NonZero, U256};
use sha3::{Shake128Core, Shake128ReaderCore, Shake256Core, Shake256ReaderCore};
use zeroize::{Zeroize, Zeroizing};

/// SHAKE128 sponge rate in bytes (`fips202.h:7`). One squeezed Keccak block.
/// Used by the ExpandA sampler's block refill (`poly_uniform`).
pub const SHAKE128_RATE: usize = 168;
/// SHAKE256 sponge rate in bytes (`fips202.h:8`). One squeezed Keccak block.
/// Used by the ExpandS / ExpandMask / SampleInBall block refills.
pub const SHAKE256_RATE: usize = 136;

fn wipe_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

// sha3's zeroize feature clears its Keccak state, but digest's generic wrappers
// do not clear their input/output block buffers. Own these bytes explicitly.
struct WipingBuffer<C>(Buffer<C>)
where
    C: BufferKindUser,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero;

impl<C> WipingBuffer<C>
where
    C: BufferKindUser,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
    fn clear(&mut self) {
        wipe_bytes(self.0.pad_with_zeros().as_mut_slice());
    }
}

impl<C> Drop for WipingBuffer<C>
where
    C: BufferKindUser,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
    fn drop(&mut self) {
        self.clear();
    }
}

// GenericArray's optional Zeroize implementation is not enabled in the locked
// dependency graph. This local byte-only adapter needs no feature/dependency
// changes and does not inspect the layout of any external type.
struct BlockBytes<R: XofReaderCore> {
    bytes: Block<R>,
}

impl<R: XofReaderCore> Zeroize for BlockBytes<R> {
    fn zeroize(&mut self) {
        wipe_bytes(self.bytes.as_mut_slice());
    }
}

struct WipingReader<R: XofReaderCore> {
    core: R,
    block: Zeroizing<BlockBytes<R>>,
    offset: usize,
}

impl<R: XofReaderCore> WipingReader<R> {
    fn new(core: R) -> Self {
        let block = Zeroizing::new(BlockBytes {
            bytes: Block::<R>::default(),
        });
        let offset = block.bytes.len();
        Self {
            core,
            block,
            offset,
        }
    }

    fn read(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.offset == self.block.bytes.len() {
                self.block = Zeroizing::new(BlockBytes {
                    bytes: self.core.read_block(),
                });
                self.offset = 0;
            }
            let count = self.read_cached_prefix(out);
            out = &mut out[count..];
        }
    }

    fn read_cached_prefix(&mut self, out: &mut [u8]) -> usize {
        let count = (self.block.bytes.len() - self.offset).min(out.len());
        let end = self.offset + count;
        out[..count].copy_from_slice(&self.block.bytes[self.offset..end]);
        wipe_bytes(&mut self.block.bytes[self.offset..end]);
        self.offset = end;
        count
    }
}

fn new_reader<C>(inputs: &[&[u8]]) -> WipingReader<C::ReaderCore>
where
    C: ExtendableOutputCore + Default,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
    let mut core = C::default();
    let mut buffer = WipingBuffer::<C>(Buffer::<C>::default());
    for chunk in inputs {
        buffer
            .0
            .digest_blocks(chunk, |blocks| UpdateCore::update_blocks(&mut core, blocks));
    }
    WipingReader::new(core.finalize_xof_core(&mut buffer.0))
}

/// One-shot SHAKE256: absorb each slice in `inputs` (in order, equivalent to
/// absorbing their concatenation), then squeeze exactly `out.len()` bytes.
///
/// Mirrors `fips202.c`'s `shake256(out, outlen, in, inlen)`; the slice list lets
/// callers build the ML-DSA hash inputs directly, e.g.
/// `mu = SHAKE256(tr || 0x00 || ctxlen || ctx || msg)` or
/// `rhoprime = SHAKE256(key || rnd || mu)` (plan §3 step 10), and the keygen
/// `H(seed || K || L)` / `tr = H(pk)` calls.
pub fn shake256(out: &mut [u8], inputs: &[&[u8]]) {
    new_reader::<Shake256Core>(inputs).read(out);
}

/// One-shot SHAKE128: absorb each slice in `inputs` (in order), then squeeze
/// exactly `out.len()` bytes. Mirrors `fips202.c`'s `shake128`.
pub fn shake128(out: &mut [u8], inputs: &[&[u8]]) {
    new_reader::<Shake128Core>(inputs).read(out);
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
/// The underlying core persists sponge state, so repeated [`read`] calls
/// continue the same output stream — the caller decides how many bytes to pull
/// (full `SHAKE128_RATE` blocks, then single-block refills, in the C sampler).
///
/// [`read`]: Shake128Stream::read
pub struct Shake128Stream {
    reader: WipingReader<Shake128ReaderCore>,
}

impl Shake128Stream {
    /// `stream128_init`: absorb `seed || LE16(nonce)` and finalize.
    pub fn init(seed: &[u8], nonce: u16) -> Self {
        Self {
            reader: new_reader::<Shake128Core>(&[seed, &nonce_bytes(nonce)]),
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
    reader: WipingReader<Shake256ReaderCore>,
}

impl Shake256Stream {
    /// `stream256_init`: absorb `seed || LE16(nonce)` and finalize.
    pub fn init(seed: &[u8], nonce: u16) -> Self {
        Self {
            reader: new_reader::<Shake256Core>(&[seed, &nonce_bytes(nonce)]),
        }
    }

    /// Absorb `seed` ALONE (no nonce) and finalize. Mirrors `poly_challenge`'s
    /// `shake256_inc_init; shake256_inc_absorb(seed); shake256_inc_finalize`
    /// (SampleInBall hashes only the `c~` commitment, with no domain nonce). The
    /// caller squeezes a `SHAKE256_RATE` block at a time, persisting sponge state.
    pub fn init_xof(seed: &[u8]) -> Self {
        Self {
            reader: new_reader::<Shake256Core>(&[seed]),
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
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    fn reference128(input: &[u8], output_len: usize) -> Vec<u8> {
        let mut reference = sha3::Shake128::default();
        reference.update(input);
        let mut result = vec![0; output_len];
        reference.finalize_xof().read(&mut result);
        result
    }

    fn reference256(input: &[u8], output_len: usize) -> Vec<u8> {
        let mut reference = sha3::Shake256::default();
        reference.update(input);
        let mut result = vec![0; output_len];
        reference.finalize_xof().read(&mut result);
        result
    }

    #[test]
    fn arbitrary_input_and_output_splits_match_locked_sha3() {
        let lengths = [0, 1, 135, 136, 137, 167, 168, 169, 272, 336, 509];
        for input_len in lengths {
            let input: Vec<_> = (0..input_len).map(|index| (index % 251) as u8).collect();
            for split in [0, input_len / 2, input_len] {
                let inputs = [&input[..split], &[][..], &input[split..]];
                for output_len in lengths {
                    let mut output = vec![0; output_len];
                    shake128(&mut output, &inputs);
                    assert_eq!(output, reference128(&input, output_len));
                    shake256(&mut output, &inputs);
                    assert_eq!(output, reference256(&input, output_len));
                }
            }
        }
    }

    #[test]
    fn arbitrary_stream_reads_preserve_unconsumed_output_and_empty_reads() {
        let seed = [0x5a; 169];
        let nonce = 0x0201;
        let input = [&seed[..], &nonce_bytes(nonce)].concat();
        let chunks = [0, 1, 135, 0, 136, 137, 167, 0, 168, 169, 0];
        let output_len = chunks.iter().sum();
        let mut stream128 = Shake128Stream::init(&seed, nonce);
        let mut stream256 = Shake256Stream::init(&seed, nonce);
        let mut result128 = vec![];
        let mut result256 = vec![];
        for length in chunks {
            let mut output = vec![0; length];
            stream128.read(&mut output);
            result128.extend_from_slice(&output);
            stream256.read(&mut output);
            result256.extend_from_slice(&output);
        }
        assert_eq!(result128, reference128(&input, output_len));
        assert_eq!(result256, reference256(&input, output_len));
    }

    #[test]
    fn live_wipe_slice_and_output_buffers_are_cleared() {
        // Observe the same live slice passed to the shipping wipe, without an
        // additional mutating BlockBuffer API masking an omitted wipe. The
        // absorb-owner/drop wiring is checked by the AST regression guards.
        let mut bytes = [0x5a; SHAKE256_RATE];
        wipe_bytes(&mut bytes);
        assert!(bytes.iter().all(|byte| *byte == 0));

        let secret = [0x5a; 128];
        let mut reader = new_reader::<Shake256Core>(&[&secret]);
        reader.read(&mut [0; 1]);
        assert_eq!(reader.offset, 1);
        assert_eq!(reader.block.bytes[0], 0);
        assert!(reader.block.bytes[1..].iter().any(|byte| *byte != 0));
        reader.read(&mut [0; SHAKE256_RATE - 1]);
        assert_eq!(reader.offset, SHAKE256_RATE);
        assert!(reader.block.bytes.iter().all(|byte| *byte == 0));
        reader.read(&mut [0; 1]);
        reader.block.zeroize();
        assert!(reader.block.bytes.iter().all(|byte| *byte == 0));
    }

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

#[cfg(kani)]
mod buffer_proofs {
    use super::*;
    use core::marker::PhantomData;
    use sha3::digest::core_api::BlockSizeUser;
    use sha3::digest::generic_array::ArrayLength;
    use sha3::digest::typenum::{U136, U168};

    // The shipping cached-prefix method executes below with its real
    // buffer/cursor. These proofs cover a single-block window, not Keccak,
    // refill/outer-loop behavior, Drop, or compiler-created copies.
    struct NoRefillCore<N: ArrayLength<u8>>(PhantomData<N>);

    impl<N: ArrayLength<u8>> BlockSizeUser for NoRefillCore<N> {
        type BlockSize = N;
    }

    impl<N: ArrayLength<u8>> XofReaderCore for NoRefillCore<N> {
        fn read_block(&mut self) -> Block<Self> {
            panic!("a bounded prefilled window must not refill");
        }
    }

    macro_rules! prove_rate {
        ($wipe:ident, $read:ident, $len:expr, $rate:ty, $read_unwind:literal) => {
            #[kani::proof]
            #[kani::unwind(192)] // Covers either fixed rate, with unwinding assertions.
            fn $wipe() {
                let original: [u8; $len] = kani::any();
                let mut bytes = original;
                wipe_bytes(&mut bytes);
                for byte in bytes {
                    assert_eq!(byte, 0);
                }

                let mut block = Block::<NoRefillCore<$rate>>::default();
                block.copy_from_slice(&original);
                let mut owned = BlockBytes::<NoRefillCore<$rate>> { bytes: block };
                owned.zeroize();
                for byte in owned.bytes.iter() {
                    assert_eq!(*byte, 0);
                }
            }

            #[kani::proof]
            #[kani::unwind($read_unwind)] // Full rate plus the loop exit; assertions remain enabled.
            fn $read() {
                let original: [u8; $len] = kani::any();
                // Both fixed rates are below256. This byte-sized encoding
                // covers exactly the same legal usize offsets/lengths/indices
                // while avoiding irrelevant symbolic high pointer bits.
                let offset = usize::from(kani::any::<u8>());
                kani::assume(offset <= $len);
                let length = usize::from(kani::any::<u8>());
                kani::assume(length <= $len);
                let expected = ($len - offset).min(length);
                let block = *Block::<NoRefillCore<$rate>>::from_slice(&original);
                let mut reader = WipingReader {
                    core: NoRefillCore::<$rate>(PhantomData),
                    block: Zeroizing::new(BlockBytes { bytes: block }),
                    offset,
                };
                let mut output: [u8; $len] = kani::any();
                let before = output;
                let copied = reader.read_cached_prefix(&mut output[..length]);
                assert!(copied == expected);
                assert!(reader.offset == offset + expected);
                // Universal byte coverage via an arbitrary index avoids an
                // extra rate-sized assertion loop; no byte/offset/length
                // domain is removed from the property.
                let index = usize::from(kani::any::<u8>());
                kani::assume(index < $len);
                if index < expected {
                    assert!(output[index] == original[offset + index]);
                } else {
                    assert!(output[index] == before[index]);
                }
                if offset <= index && index < offset + expected {
                    assert!(reader.block.bytes[index] == 0);
                } else {
                    assert!(reader.block.bytes[index] == original[index]);
                }
                // This slice ends at the prefix postcondition. Whole-block
                // zeroization is proved separately; Drop wiring is AST-guarded.
                core::mem::forget(reader);
            }
        };
    }

    prove_rate!(
        wipe_bytes_and_owned_block_136,
        cached_prefix_window_136,
        136,
        U136,
        137
    );
    prove_rate!(
        wipe_bytes_and_owned_block_168,
        cached_prefix_window_168,
        168,
        U168,
        169
    );
}
