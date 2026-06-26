use std::ops::Range;

use aws_lc_rs::aead::LessSafeKey;
use rand::{rngs::StdRng, Rng, SeedableRng};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    crypto::{
        parallel::{self, CryptoPool},
        session::{
            self, AeadCodec, CipherSuite, SessionError, SharedCipher, AEAD_TAG_LEN, KEY_LEN,
            NONCE_LEN,
        },
    },
    tls::record::{self, TLS_CONTENT_APPLICATION_DATA, TLS_LEGACY_VERSION},
    traffic::{PaddingProfile, TrafficError},
};

/// Maximum on-wire TLS record payload (the record `length` field: encrypted
/// content + AEAD tag) the data plane emits. Real Safari 26 over TLS 1.3 emits
/// full application-data records of exactly **16401** bytes — `16384` plaintext
/// `+ 1` TLS 1.3 inner content-type `+ 16` AEAD tag — measured across a bulk
/// download (`~/Desktop/safari-tcp/big.pcap`, sole full-record bucket). The
/// camouflage handshake/H2 path already emits 16401 (see
/// `Tls13Keys::encrypt_record`). The data plane must match so a length
/// classifier sees ONE record-size regime across the whole connection rather
/// than the camouflage→data `16401`→`16384` switch that was uniquely ParallaX
/// (A1). This caps the wire `length` field; with ParallaX's 2-byte self-pad
/// trailer a full record carries 16383 plaintext (16383 + 2 + 16 = 16401) — the
/// 1-byte-less-than-Safari plaintext split is invisible on the wire, only the
/// 16401 `length` field is observable. Deliberately NOT aliased to
/// `record::MAX_TLS_RECORD_PAYLOAD` (16384), which is the camouflage path's
/// *plaintext* chunk size and must stay 16384.
pub const OUTER_TLS_RECORD_LIMIT: usize = record::MAX_TLS_RECORD_PAYLOAD + 17;
/// Target size of a single relay read (`drain_ready_tcp_read` coalesces all
/// immediately-ready bytes up to this bound before sealing). Larger reads gather
/// more plaintext per cycle, so the bulk seal/open fans out across more crypto
/// pool workers in one dispatch (16 full records here vs 4 at 64 KiB), better
/// amortizing the pool's per-batch lock/dispatch cost on multi-core machines.
///
/// This is a read-coalescing/CPU-batching knob: records are still capped at
/// `max_plaintext_len` each, so the on-wire record sizes, count-per-byte, and
/// padding are unchanged — only how many records are sealed/written per relay
/// cycle changes (and TCP already coalesces segments regardless). With the
/// default config (timing jitter off, `max_delay_ms = 0`) the externally
/// observable behavior is identical. CAVEAT: when an operator enables timing
/// jitter, the server download loop samples one `TimingProfile::sample_delay`
/// per read burst, so a larger burst spaces the same per-burst pause over more
/// bytes — the inter-burst delay cadence under that opt-in knob does shift. That
/// shaping mechanism is an explicitly-deferred area; this knob does not aim to
/// change it and leaves the default (off) untouched. The worst-case up-front
/// `out.reserve` for one read stays bounded: with the `MIN_USABLE_PLAINTEXT_LEN`
/// floor a 256 KiB read is at most ~256 records, a few MiB of reserve even under
/// near-record-sized padding.
pub const RELAY_READ_BUFFER_TARGET: usize = 256 * 1024;

const PADDING_LEN_FIELD: usize = 2;

#[derive(Debug, Error)]
pub enum DataRecordError {
    #[error("TLS record error: {0}")]
    TlsRecord(#[from] record::TlsRecordError),
    #[error("record is not TLS ApplicationData")]
    NotApplicationData,
    #[error("AEAD error: {0}")]
    Aead(#[from] SessionError),
    #[error("traffic shaping error: {0}")]
    Traffic(#[from] TrafficError),
    #[error("record_lens do not sum to plaintext length")]
    InvalidRecordLens,
}

pub struct DataRecordCodec {
    aead: AeadCodec,
    padding: PaddingProfile,
    aad: &'static [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRecord {
    pub range: Range<usize>,
    pub plaintext_len: usize,
}

/// Token returned by [`DataRecordCodec::begin_record`]; consumed by
/// [`DataRecordCodec::finish_record`].
#[derive(Debug)]
#[must_use = "an unfinished record leaves a dangling TLS header in the output buffer"]
pub struct RecordBuilder {
    record_start: usize,
}

impl DataRecordCodec {
    pub fn new(aead: AeadCodec, padding: PaddingProfile, aad: &'static [u8]) -> Self {
        Self { aead, padding, aad }
    }

    pub fn protect_secret_memory(&self) {
        self.aead.protect_secret_memory();
    }

    pub fn seal<R>(&mut self, payload: &[u8], rng: &mut R) -> Result<Vec<u8>, DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        let mut out = Vec::with_capacity(record_capacity(payload.len(), self.padding.max_len()));
        self.seal_into(payload, rng, &mut out)?;
        Ok(out)
    }

    pub fn seal_into<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<std::ops::Range<usize>, DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        self.seal_into_reserved(payload, rng, out, true)
    }

    fn seal_into_reserved<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
        out: &mut Vec<u8>,
        reserve_capacity: bool,
    ) -> Result<std::ops::Range<usize>, DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        if reserve_capacity {
            out.reserve(record_capacity(payload.len(), self.padding.max_len()));
        }
        let builder = self.begin_record(out);
        out.extend_from_slice(payload);
        self.finish_record(builder, rng, out)
    }

    /// Starts a record in `out` and returns a builder token. The caller
    /// appends plaintext directly to `out` and then seals it with
    /// [`Self::finish_record`], avoiding an intermediate plaintext buffer.
    pub fn begin_record(&self, out: &mut Vec<u8>) -> RecordBuilder {
        let record_start = out.len();
        out.extend_from_slice(&[
            TLS_CONTENT_APPLICATION_DATA,
            TLS_LEGACY_VERSION[0],
            TLS_LEGACY_VERSION[1],
            0,
            0,
        ]);
        RecordBuilder { record_start }
    }

    /// Pads, encrypts, and frames the plaintext appended to `out` since the
    /// matching [`Self::begin_record`] call. On error the record bytes are
    /// removed from `out` and any written plaintext is zeroized.
    pub fn finish_record<R>(
        &mut self,
        builder: RecordBuilder,
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<std::ops::Range<usize>, DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        let record_start = builder.record_start;
        let ciphertext_start = record_start + record::TLS_HEADER_LEN;
        let payload_len = out.len() - ciphertext_start;
        self.padding.apply_suffix_into(payload_len, rng, out);
        let padded_len = out.len() - ciphertext_start;
        if padded_len + AEAD_TAG_LEN > OUTER_TLS_RECORD_LIMIT {
            out[ciphertext_start..].zeroize();
            out.truncate(record_start);
            return Err(record::TlsRecordError::PayloadTooLarge(padded_len + AEAD_TAG_LEN).into());
        }

        crate::process_hardening::exclude_transient_from_core_dump(
            "data_record.seal_plaintext",
            &out[ciphertext_start..],
        );
        let tag = match self
            .aead
            .seal_in_place_detached(&mut out[ciphertext_start..], self.aad)
        {
            Ok(tag) => tag,
            Err(err) => {
                out[ciphertext_start..].zeroize();
                out.truncate(record_start);
                return Err(err.into());
            }
        };
        out.extend_from_slice(&tag);

        let tls_payload_len = out.len() - ciphertext_start;
        let len = (tls_payload_len as u16).to_be_bytes();
        out[record_start + 3] = len[0];
        out[record_start + 4] = len[1];

        Ok(record_start..out.len())
    }

    /// Seal one record carrying `payload` plus exactly `extra_pad` extra
    /// padding-suffix bytes, on TOP of whatever this codec's [`PaddingProfile`] would
    /// add. Used by the PQ handshake flight (PAR-35) to apply per-session aggregate
    /// decorrelation padding to a single record without enabling padding on the shared
    /// relay codec (whose profile stays 0/0, so the steady-state hot path is
    /// untouched). The receiver strips it transparently via the self-describing 2-byte
    /// pad-length trailer — no wire-format or decode change. Bounded by the outer TLS
    /// record limit exactly like a normal seal.
    pub fn seal_into_extra_padded<R>(
        &mut self,
        payload: &[u8],
        extra_pad: usize,
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<std::ops::Range<usize>, DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        out.reserve(record_capacity(
            payload.len() + extra_pad,
            self.padding.max_len(),
        ));
        let record_start = out.len();
        out.extend_from_slice(&[
            TLS_CONTENT_APPLICATION_DATA,
            TLS_LEGACY_VERSION[0],
            TLS_LEGACY_VERSION[1],
            0,
            0,
        ]);
        out.extend_from_slice(payload);
        // Write one padding suffix = this codec's normal sampled padding PLUS the
        // per-session `extra_pad` (the self-describing 2-byte trailer makes the
        // receiver strip the whole thing). With the default 0/0 profile this is exactly
        // `extra_pad`; with a configured profile the record still honors the profile
        // and adds the aggregate pad on top. Only PQ-handshake records take this path,
        // so the relay hot path is unaffected.
        let ciphertext_start = record_start + record::TLS_HEADER_LEN;
        self.padding
            .write_extra_padded_suffix_into(payload.len(), extra_pad, rng, out);
        let padded_len = out.len() - ciphertext_start;
        if padded_len + AEAD_TAG_LEN > OUTER_TLS_RECORD_LIMIT {
            out[ciphertext_start..].zeroize();
            out.truncate(record_start);
            return Err(record::TlsRecordError::PayloadTooLarge(padded_len + AEAD_TAG_LEN).into());
        }
        crate::process_hardening::exclude_transient_from_core_dump(
            "data_record.seal_plaintext",
            &out[ciphertext_start..],
        );
        let tag = match self
            .aead
            .seal_in_place_detached(&mut out[ciphertext_start..], self.aad)
        {
            Ok(tag) => tag,
            Err(err) => {
                out[ciphertext_start..].zeroize();
                out.truncate(record_start);
                return Err(err.into());
            }
        };
        out.extend_from_slice(&tag);
        let tls_payload_len = out.len() - ciphertext_start;
        let len = (tls_payload_len as u16).to_be_bytes();
        out[record_start + 3] = len[0];
        out[record_start + 4] = len[1];
        Ok(record_start..out.len())
    }

    /// Seal a browser-shaped PQ handshake flight (PAR-35): each `FramedChunk` record
    /// in `chunks` is sealed in order into `out`, and a single per-session aggregate
    /// decorrelation pad (`crate::protocol::command::FramedChunk::aggregate_pad_len`)
    /// is applied to ONE record so the flight's total on-wire size varies across
    /// sessions. All records are written into one buffer => one write => one flight
    /// (no added round trip). The pad is decode-transparent (stripped by the receiver's
    /// per-record trailer) and never touches the steady-state relay codec.
    ///
    /// The padded record is the LAST one: padding the tail keeps every earlier record
    /// at its shaped browser-modeled size, and a tail record that runs a little larger
    /// matches a real H2 response whose final DATA frame need not be full.
    pub fn seal_pq_flight<R>(
        &mut self,
        chunks: &[Vec<u8>],
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<(), DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        let aggregate_pad = crate::protocol::command::FramedChunk::aggregate_pad_len(rng);
        let last = chunks.len().saturating_sub(1);
        for (idx, chunk) in chunks.iter().enumerate() {
            if idx == last {
                self.seal_into_extra_padded(chunk, aggregate_pad, rng, out)?;
            } else {
                self.seal_into(chunk, rng, out)?;
            }
        }
        Ok(())
    }

    pub fn seal_chunks_into<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<Vec<SealedRecord>, DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        let mut records = Vec::new();
        self.seal_chunks_into_reusing(payload, rng, out, &mut records)?;
        Ok(records)
    }

    pub fn seal_chunks_into_reusing<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
        out: &mut Vec<u8>,
        records: &mut Vec<SealedRecord>,
    ) -> Result<(), DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        records.clear();
        let max_chunk_len = self.max_plaintext_len();
        if max_chunk_len == 0 {
            return Err(record::TlsRecordError::PayloadTooLarge(payload.len()).into());
        }
        let max_padding = self.padding.max_len();
        if payload.len() <= max_chunk_len {
            out.reserve(record_capacity(payload.len(), max_padding));
            let range = self.seal_into_reserved(payload, rng, out, false)?;
            records.push(SealedRecord {
                range,
                plaintext_len: payload.len(),
            });
            return Ok(());
        }
        let chunk_count = chunk_count(payload.len(), max_chunk_len);
        records.reserve(chunk_count);
        out.reserve(chunked_records_capacity(
            payload.len(),
            chunk_count,
            max_padding,
        ));

        for chunk in payload.chunks(max_chunk_len) {
            let range = self.seal_into_reserved(chunk, rng, out, false)?;
            records.push(SealedRecord {
                range,
                plaintext_len: chunk.len(),
            });
        }
        Ok(())
    }

    pub fn seal_chunks_into_untracked<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<(), DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        let max_chunk_len = self.max_plaintext_len();
        if max_chunk_len == 0 {
            return Err(record::TlsRecordError::PayloadTooLarge(payload.len()).into());
        }
        let max_padding = self.padding.max_len();
        if payload.len() <= max_chunk_len {
            out.reserve(record_capacity(payload.len(), max_padding));
            self.seal_into_reserved(payload, rng, out, false)?;
            return Ok(());
        }
        let chunk_count = chunk_count(payload.len(), max_chunk_len);
        out.reserve(chunked_records_capacity(
            payload.len(),
            chunk_count,
            max_padding,
        ));

        for chunk in payload.chunks(max_chunk_len) {
            self.seal_into_reserved(chunk, rng, out, false)?;
        }
        Ok(())
    }

    pub fn seal_chunks<R>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<Vec<u8>>, DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        let max_chunk_len = self.max_plaintext_len();
        if max_chunk_len == 0 {
            return Err(record::TlsRecordError::PayloadTooLarge(payload.len()).into());
        }
        if payload.is_empty() {
            return Ok(vec![self.seal(payload, rng)?]);
        }

        let mut records = Vec::with_capacity(payload.len().div_ceil(max_chunk_len));
        for chunk in payload.chunks(max_chunk_len) {
            records.push(self.seal(chunk, rng)?);
        }
        Ok(records)
    }

    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, DataRecordError> {
        let header = record::parse_header(record)?;
        if header.content_type != TLS_CONTENT_APPLICATION_DATA {
            return Err(DataRecordError::NotApplicationData);
        }
        if record.len() < header.total_len {
            return Err(record::TlsRecordError::IncompletePayload.into());
        }
        if header.payload_len < AEAD_TAG_LEN {
            return Err(SessionError::Aead.into());
        }

        let payload = &record[record::TLS_HEADER_LEN..header.total_len];
        let mut padded = payload.to_vec();
        crate::process_hardening::exclude_transient_from_core_dump(
            "data_record.open_plaintext",
            &padded,
        );
        match self.aead.open_in_place_split(&mut padded, self.aad) {
            Ok(plaintext_len) => padded.truncate(plaintext_len),
            Err(err) => {
                padded.zeroize();
                return Err(err.into());
            }
        }
        if let Err(err) = PaddingProfile::remove_in_place(&mut padded) {
            padded.zeroize();
            return Err(err.into());
        }
        Ok(padded)
    }

    pub fn open_owned(&mut self, mut record: Vec<u8>) -> Result<Vec<u8>, DataRecordError> {
        self.open_in_place(&mut record)?;
        Ok(record)
    }

    pub fn open_in_place(&mut self, record: &mut Vec<u8>) -> Result<(), DataRecordError> {
        let plaintext = self.open_in_place_payload_range(record)?;
        record.copy_within(plaintext.clone(), 0);
        record.truncate(plaintext.len());
        Ok(())
    }

    pub fn open_in_place_payload_range(
        &mut self,
        record: &mut Vec<u8>,
    ) -> Result<std::ops::Range<usize>, DataRecordError> {
        let header = record::parse_header(record)?;
        if header.content_type != TLS_CONTENT_APPLICATION_DATA {
            return Err(DataRecordError::NotApplicationData);
        }
        if record.len() < header.total_len {
            return Err(record::TlsRecordError::IncompletePayload.into());
        }
        if header.payload_len < AEAD_TAG_LEN {
            return Err(SessionError::Aead.into());
        }

        record.truncate(header.total_len);
        let ciphertext_start = record::TLS_HEADER_LEN;
        let plaintext_len = {
            let payload = &mut record[ciphertext_start..header.total_len];
            crate::process_hardening::exclude_transient_from_core_dump(
                "data_record.open_in_place_plaintext",
                payload,
            );
            let padded_len = match self.aead.open_in_place_split(payload, self.aad) {
                Ok(len) => len,
                Err(err) => {
                    payload.zeroize();
                    return Err(err.into());
                }
            };
            match PaddingProfile::unpadded_len(&payload[..padded_len]) {
                Ok(len) => len,
                Err(err) => {
                    payload.zeroize();
                    return Err(err.into());
                }
            }
        };
        let plaintext = ciphertext_start..ciphertext_start + plaintext_len;
        record.truncate(plaintext.end);
        Ok(plaintext)
    }

    pub fn rekey(&mut self, key: [u8; KEY_LEN], nonce_base: [u8; NONCE_LEN]) {
        self.aead.rekey(key, nonce_base);
    }

    /// Rekeys and switches the data-plane cipher suite (used by the PQ rekey to
    /// adopt the server-negotiated suite). On-wire record sizes are unchanged.
    pub fn rekey_with_suite(
        &mut self,
        suite: CipherSuite,
        key: [u8; KEY_LEN],
        nonce_base: [u8; NONCE_LEN],
    ) {
        self.aead.rekey_with_suite(suite, key, nonce_base);
    }

    pub fn max_plaintext_len(&self) -> usize {
        max_plaintext_len(self.padding.max_len())
    }

    pub(crate) fn max_sealed_len(&self, payload_len: usize) -> usize {
        record_capacity(payload_len, self.padding.max_len())
    }

    /// Serial seal for a pre-framed plaintext partitioned into `record_lens`
    /// (which must sum to `plaintext.len()`). Byte-identical to sealing each
    /// record slice with [`Self::seal_into`] in order; this is the low-latency
    /// path for small batches and the reference the parallel path matches.
    pub fn seal_records_into<R>(
        &mut self,
        plaintext: &[u8],
        record_lens: &[usize],
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<(), DataRecordError>
    where
        R: Rng + rand::RngCore + ?Sized,
    {
        // Contract: record_lens must sum to plaintext.len(). Enforce it at runtime in
        // every build — the previous debug_assert was compiled out in release, where a
        // mismatch then OOB-panicked on `&plaintext[offset..offset + len]` (sum too
        // large) or silently under-sealed the tail (sum too small). Internal callers
        // always satisfy this; the guard turns a contract violation into a clean error.
        let sum = record_lens
            .iter()
            .try_fold(0usize, |acc, &len| acc.checked_add(len))
            .ok_or(DataRecordError::InvalidRecordLens)?;
        if sum != plaintext.len() {
            return Err(DataRecordError::InvalidRecordLens);
        }
        let mut offset = 0;
        for &len in record_lens {
            self.seal_into(&plaintext[offset..offset + len], rng, out)?;
            offset += len;
        }
        Ok(())
    }

    /// Like [`Self::seal_records_into`] but each record's plaintext is written
    /// directly into `out` by `fill(i, out)` between begin/finish, so the caller
    /// need not stage the plaintext in a separate buffer first. Byte-identical to
    /// `seal_records_into` when `fill` appends the same per-record slices; this is
    /// an alternative in-place seal path intended for a future relay/mux writer
    /// wiring (Track A2). It is not currently on the hot path — the live writers
    /// use `seal_records_into_parallel`/`seal_records_into` — but it is retained
    /// and kept byte-for-byte equivalence-tested against `seal_records_into`.
    /// `record_lens` gives the per-record plaintext lengths used to size the
    /// up-front reserve (and, in debug, to assert `fill` appends exactly that
    /// many bytes).
    pub fn seal_records_into_inplace<R, F>(
        &mut self,
        record_lens: &[usize],
        rng: &mut R,
        out: &mut Vec<u8>,
        mut fill: F,
    ) -> Result<(), DataRecordError>
    where
        R: Rng + rand::RngCore + ?Sized,
        F: FnMut(usize, &mut Vec<u8>),
    {
        let total: usize = record_lens.iter().sum();
        out.reserve(chunked_records_capacity(
            total,
            record_lens.len().max(1),
            self.padding.max_len(),
        ));
        for (i, &len) in record_lens.iter().enumerate() {
            let builder = self.begin_record(out);
            let before = out.len();
            fill(i, out);
            debug_assert_eq!(
                out.len() - before,
                len,
                "fill must append exactly record_lens[i] plaintext bytes"
            );
            self.finish_record(builder, rng, out)?;
        }
        Ok(())
    }

    /// Parallel counterpart of [`Self::seal_chunks_into_untracked`]: splits
    /// `payload` into `max_plaintext_len`-sized records and seals them across
    /// `pool`'s worker threads, appending the records to `out` in order. The
    /// wire output is byte-identical to the serial path for a given padding
    /// stream, and the per-direction sequence counter advances by the same
    /// number of records, so the two paths are interchangeable mid-stream.
    pub fn seal_chunks_into_parallel<R>(
        &mut self,
        pool: &CryptoPool,
        payload: &[u8],
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<(), DataRecordError>
    where
        R: Rng + rand::RngCore + ?Sized,
    {
        let max_chunk_len = self.max_plaintext_len();
        if max_chunk_len == 0 {
            return Err(record::TlsRecordError::PayloadTooLarge(payload.len()).into());
        }
        let mut record_lens = Vec::with_capacity(chunk_count(payload.len(), max_chunk_len));
        if payload.is_empty() {
            record_lens.push(0);
        } else {
            let mut remaining = payload.len();
            while remaining > 0 {
                let len = remaining.min(max_chunk_len);
                record_lens.push(len);
                remaining -= len;
            }
        }
        self.seal_records_into_parallel(pool, payload, &record_lens, rng, out)
    }

    /// Parallel seal for a pre-framed plaintext partitioned into records of the
    /// given lengths (`record_lens` must sum to `plaintext.len()`). The mux
    /// writers use this to keep each record frame-aligned — identical record
    /// boundaries to the serial path — while still spreading the AEAD work
    /// across `pool`. Records map to sequence numbers `base..base+n` in order.
    pub fn seal_records_into_parallel<R>(
        &mut self,
        pool: &CryptoPool,
        plaintext: &[u8],
        record_lens: &[usize],
        rng: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<(), DataRecordError>
    where
        R: Rng + rand::RngCore + ?Sized,
    {
        // Contract: record_lens must sum to plaintext.len(). Checked first — before the
        // empty-batch early-return and `ensure_usable` — so an empty `record_lens` with a
        // non-empty plaintext is rejected consistently with the serial `seal_records_into`
        // instead of being silently sealed as nothing. (Also prevents an OOB panic on the
        // `plaintext[byte_offset..byte_offset + span]` slice below in release, where the
        // prior debug_assert was compiled out.)
        let sum = record_lens
            .iter()
            .try_fold(0usize, |acc, &len| acc.checked_add(len))
            .ok_or(DataRecordError::InvalidRecordLens)?;
        if sum != plaintext.len() {
            return Err(DataRecordError::InvalidRecordLens);
        }
        let record_count = record_lens.len();
        if record_count == 0 {
            return Ok(());
        }
        self.aead.ensure_usable()?;
        let group_count = pool.width().max(1).min(record_count);

        let cipher = self.aead.cipher();
        let nonce_base = self.aead.nonce_base();
        let base_sequence = self.aead.sequence();
        // Defense in depth: reject a batch that would wrap the per-direction
        // sequence counter past u64::MAX before any record is sealed.
        if base_sequence.checked_add(record_count as u64).is_none() {
            return Err(SessionError::NonceExhausted.into());
        }
        let aad = self.aad;
        let padding = self.padding;

        let mut jobs = Vec::with_capacity(group_count);
        let mut next_record = 0;
        let mut byte_offset = 0;
        for group in 0..group_count {
            let records_here = (record_count - next_record).div_ceil(group_count - group);
            let record_end = next_record + records_here;
            let lens = record_lens[next_record..record_end].to_vec();
            let span: usize = lens.iter().sum();
            let group_plaintext = plaintext[byte_offset..byte_offset + span].to_vec();
            let group_base_sequence = base_sequence + next_record as u64;
            let seed = rng.gen::<u64>();
            let cipher = SharedCipher::clone(&cipher);
            jobs.push(move || {
                seal_records_segment(
                    &cipher,
                    &nonce_base,
                    aad,
                    &padding,
                    group_base_sequence,
                    &group_plaintext,
                    &lens,
                    seed,
                )
            });
            next_record = record_end;
            byte_offset += span;
        }

        let segments = parallel::dispatch_blocking(|| pool.run_ordered(jobs));
        let mut sealed = Vec::with_capacity(segments.len());
        for segment in segments {
            sealed.push(segment?);
        }
        out.reserve(sealed.iter().map(Vec::len).sum());
        for segment in &sealed {
            out.extend_from_slice(segment);
        }
        self.aead.advance_sequence(record_count as u64);
        Ok(())
    }

    /// Serial counterpart of [`Self::open_concat_records_parallel`]: opens a
    /// buffer of consecutive sealed TLS records in place, appending the
    /// concatenated plaintext to `out`. Identical validation and AEAD checks
    /// to the per-record `open*` methods; any failure must fail-close the
    /// session, as the sequence counter has already advanced past the records
    /// opened before the failure.
    pub fn open_concat_records(
        &mut self,
        records: &mut [u8],
        out: &mut Vec<u8>,
    ) -> Result<(), DataRecordError> {
        self.aead.ensure_usable()?;
        let result = self.open_concat_records_inner(records, out);
        if result.is_err() {
            self.aead.poison();
        }
        result
    }

    fn open_concat_records_inner(
        &mut self,
        records: &mut [u8],
        out: &mut Vec<u8>,
    ) -> Result<(), DataRecordError> {
        let mut offset = 0;
        while offset < records.len() {
            let header = record::parse_header(&records[offset..])?;
            if header.content_type != TLS_CONTENT_APPLICATION_DATA {
                return Err(DataRecordError::NotApplicationData);
            }
            if records.len() < offset + header.total_len {
                return Err(record::TlsRecordError::IncompletePayload.into());
            }
            if header.payload_len < AEAD_TAG_LEN {
                return Err(SessionError::Aead.into());
            }
            let ciphertext =
                &mut records[offset + record::TLS_HEADER_LEN..offset + header.total_len];
            crate::process_hardening::exclude_transient_from_core_dump(
                "data_record.open_concat_plaintext",
                ciphertext,
            );
            let padded_len = match self.aead.open_in_place_split(ciphertext, self.aad) {
                Ok(len) => len,
                Err(err) => {
                    ciphertext.zeroize();
                    return Err(err.into());
                }
            };
            let unpadded_len = match PaddingProfile::unpadded_len(&ciphertext[..padded_len]) {
                Ok(len) => len,
                Err(err) => {
                    ciphertext.zeroize();
                    return Err(err.into());
                }
            };
            out.extend_from_slice(&ciphertext[..unpadded_len]);
            offset += header.total_len;
        }
        Ok(())
    }

    /// Opens a buffer of consecutive sealed TLS records in parallel across
    /// `pool`, appending the concatenated plaintext to `out`. The records must
    /// be exactly those produced for this direction in order; the sequence
    /// counter advances by the number of records opened. On any AEAD failure
    /// the counter is left untouched (mirroring the serial `open*` methods, so
    /// a rejected record cannot silently desynchronize the stream).
    pub fn open_concat_records_parallel(
        &mut self,
        pool: &CryptoPool,
        records: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), DataRecordError> {
        self.aead.ensure_usable()?;
        let result = self.open_concat_records_parallel_inner(pool, records, out);
        if result.is_err() {
            self.aead.poison();
        }
        result
    }

    fn open_concat_records_parallel_inner(
        &mut self,
        pool: &CryptoPool,
        records: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), DataRecordError> {
        let mut bounds: Vec<(usize, usize)> = Vec::new();
        let mut offset = 0;
        while offset < records.len() {
            let header = record::parse_header(&records[offset..])?;
            if header.content_type != TLS_CONTENT_APPLICATION_DATA {
                return Err(DataRecordError::NotApplicationData);
            }
            if records.len() < offset + header.total_len {
                return Err(record::TlsRecordError::IncompletePayload.into());
            }
            if header.payload_len < AEAD_TAG_LEN {
                return Err(SessionError::Aead.into());
            }
            bounds.push((offset, header.total_len));
            offset += header.total_len;
        }

        let record_count = bounds.len();
        if record_count == 0 {
            return Ok(());
        }
        let group_count = pool.width().max(1).min(record_count);

        let cipher = self.aead.cipher();
        let nonce_base = self.aead.nonce_base();
        let base_sequence = self.aead.sequence();
        // Defense in depth: reject a batch that would wrap the per-direction
        // sequence counter past u64::MAX before any record is opened.
        if base_sequence.checked_add(record_count as u64).is_none() {
            return Err(SessionError::NonceExhausted.into());
        }
        let aad = self.aad;

        let mut jobs = Vec::with_capacity(group_count);
        let mut next_record = 0;
        for group in 0..group_count {
            let records_here = (record_count - next_record).div_ceil(group_count - group);
            let record_end = next_record + records_here;
            let byte_start = bounds[next_record].0;
            let (last_start, last_len) = bounds[record_end - 1];
            let byte_end = last_start + last_len;
            let group_bytes = records[byte_start..byte_end].to_vec();
            let group_bounds: Vec<(usize, usize)> = bounds[next_record..record_end]
                .iter()
                .map(|(record_offset, total_len)| (record_offset - byte_start, *total_len))
                .collect();
            let group_base_sequence = base_sequence + next_record as u64;
            let cipher = SharedCipher::clone(&cipher);
            jobs.push(move || {
                open_record_group(
                    &cipher,
                    &nonce_base,
                    aad,
                    group_base_sequence,
                    group_bytes,
                    &group_bounds,
                )
            });
            next_record = record_end;
        }

        let segments = parallel::dispatch_blocking(|| pool.run_ordered(jobs));
        let mut plaintexts = Vec::with_capacity(segments.len());
        for segment in segments {
            plaintexts.push(segment?);
        }
        out.reserve(plaintexts.iter().map(Vec::len).sum());
        for plaintext in &plaintexts {
            out.extend_from_slice(plaintext);
        }
        self.aead.advance_sequence(record_count as u64);
        Ok(())
    }
}

/// Seals one record into `out`: frames the header, copies `plaintext`, applies
/// the padding suffix, encrypts in place with the explicit `sequence`, and
/// fixes up the length field. Stateless mirror of
/// [`DataRecordCodec::begin_record`]/[`DataRecordCodec::finish_record`] used by
/// the parallel crypto workers.
#[allow(clippy::too_many_arguments)]
fn seal_one_record_into<R>(
    cipher: &LessSafeKey,
    nonce_base: &[u8; NONCE_LEN],
    sequence: u64,
    padding: &PaddingProfile,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
    out: &mut Vec<u8>,
) -> Result<(), DataRecordError>
where
    R: Rng + rand::RngCore + ?Sized,
{
    let record_start = out.len();
    out.extend_from_slice(&[
        TLS_CONTENT_APPLICATION_DATA,
        TLS_LEGACY_VERSION[0],
        TLS_LEGACY_VERSION[1],
        0,
        0,
    ]);
    let ciphertext_start = record_start + record::TLS_HEADER_LEN;
    out.extend_from_slice(plaintext);
    padding.apply_suffix_into(plaintext.len(), rng, out);
    let padded_len = out.len() - ciphertext_start;
    if padded_len + AEAD_TAG_LEN > OUTER_TLS_RECORD_LIMIT {
        out[ciphertext_start..].zeroize();
        out.truncate(record_start);
        return Err(record::TlsRecordError::PayloadTooLarge(padded_len + AEAD_TAG_LEN).into());
    }
    crate::process_hardening::exclude_transient_from_core_dump(
        "data_record.seal_plaintext",
        &out[ciphertext_start..],
    );
    let tag = match session::seal_in_place_detached_with(
        cipher,
        nonce_base,
        sequence,
        &mut out[ciphertext_start..],
        aad,
    ) {
        Ok(tag) => tag,
        Err(err) => {
            out[ciphertext_start..].zeroize();
            out.truncate(record_start);
            return Err(err.into());
        }
    };
    out.extend_from_slice(&tag);
    let tls_payload_len = out.len() - ciphertext_start;
    let len = (tls_payload_len as u16).to_be_bytes();
    out[record_start + 3] = len[0];
    out[record_start + 4] = len[1];
    Ok(())
}

/// Seals a contiguous run of records (one worker's share) into a fresh buffer,
/// slicing `plaintext` by the supplied per-record lengths.
#[allow(clippy::too_many_arguments)]
fn seal_records_segment(
    cipher: &LessSafeKey,
    nonce_base: &[u8; NONCE_LEN],
    aad: &'static [u8],
    padding: &PaddingProfile,
    base_sequence: u64,
    plaintext: &[u8],
    record_lens: &[usize],
    seed: u64,
) -> Result<Vec<u8>, DataRecordError> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut out =
        Vec::with_capacity(plaintext.len() + record_lens.len() * record_overhead(padding));
    let mut offset = 0;
    for (index, &len) in record_lens.iter().enumerate() {
        seal_one_record_into(
            cipher,
            nonce_base,
            base_sequence + index as u64,
            padding,
            aad,
            &plaintext[offset..offset + len],
            &mut rng,
            &mut out,
        )?;
        offset += len;
    }
    Ok(out)
}

/// Opens a contiguous run of records (one worker's share) in place, returning
/// the concatenated, unpadded plaintext.
fn open_record_group(
    cipher: &LessSafeKey,
    nonce_base: &[u8; NONCE_LEN],
    aad: &'static [u8],
    base_sequence: u64,
    mut bytes: Vec<u8>,
    bounds: &[(usize, usize)],
) -> Result<Vec<u8>, DataRecordError> {
    let mut out = Vec::with_capacity(bytes.len());
    for (index, &(record_offset, total_len)) in bounds.iter().enumerate() {
        let sequence = base_sequence + index as u64;
        let ciphertext_start = record_offset + record::TLS_HEADER_LEN;
        let ciphertext_end = record_offset + total_len;
        crate::process_hardening::exclude_transient_from_core_dump(
            "data_record.open_concat_plaintext",
            &bytes[ciphertext_start..ciphertext_end],
        );
        let plaintext_len = match session::open_in_place_split_with(
            cipher,
            nonce_base,
            sequence,
            &mut bytes[ciphertext_start..ciphertext_end],
            aad,
        ) {
            Ok(len) => len,
            Err(err) => {
                bytes[ciphertext_start..ciphertext_end].zeroize();
                return Err(err.into());
            }
        };
        let padded = &bytes[ciphertext_start..ciphertext_start + plaintext_len];
        let unpadded_len = match PaddingProfile::unpadded_len(padded) {
            Ok(len) => len,
            Err(err) => {
                bytes[ciphertext_start..ciphertext_end].zeroize();
                return Err(err.into());
            }
        };
        out.extend_from_slice(&bytes[ciphertext_start..ciphertext_start + unpadded_len]);
    }
    Ok(out)
}

fn record_overhead(padding: &PaddingProfile) -> usize {
    record::TLS_HEADER_LEN + padding.max_len() as usize + PADDING_LEN_FIELD + AEAD_TAG_LEN
}

/// A batch must clear both thresholds before the AEAD work is fanned out across
/// the crypto pool. Smaller batches (interactive traffic, control frames) seal
/// and open inline so they never pay the cross-thread dispatch latency; only
/// bulk transfers — where a single core's AEAD throughput is the ceiling — go
/// parallel. Tuned against the loopback throughput/latency benchmark.
pub const PARALLEL_AEAD_MIN_RECORDS: usize = 3;
pub const PARALLEL_AEAD_MIN_BYTES: usize = 48 * 1024;

/// Whether a batch of `record_count` records totalling `total_bytes` of payload
/// is large enough to seal/open across the crypto pool rather than inline.
pub fn should_parallelize_aead(record_count: usize, total_bytes: usize) -> bool {
    record_count >= PARALLEL_AEAD_MIN_RECORDS && total_bytes >= PARALLEL_AEAD_MIN_BYTES
}

pub const CLIENT_TO_SERVER_AAD: &[u8] = b"ParallaX v1 client appdata";
pub const SERVER_TO_CLIENT_AAD: &[u8] = b"ParallaX v1 server appdata";

/// Fixed plaintext payload of the QUIC fast-plane teardown DONE marker. After a
/// side has fully drained both relay directions (its `try_join` is Ok), it seals
/// exactly one record carrying this marker on its send-direction codec and
/// writes it over the reliable TCP control stream; the peer opens one record on
/// the matching receive-direction codec and verifies this payload. It is a
/// normal sealed ApplicationData record on the wire (camouflage-consistent), and
/// it consumes exactly the next per-direction sequence number — the codec
/// continues monotonically (Connect rode TCP, the relay rode the QUIC stream,
/// this DONE is the next record on each direction over TCP). The payload is a
/// fixed, non-empty marker so it can never be confused with the empty
/// cover/rendezvous records (whose plaintext is `&[]` and which the relay loops
/// skip). Follows the PX1* command convention used elsewhere on the wire.
pub const QUIC_RELAY_DONE_MARKER: &[u8] = b"PX1Z-quic-relay-done";

/// QUIC application close code for a graceful, mutually-recognized idle teardown
/// of the fast-plane relay. Code 0 stays the generic/abrupt close; when one side's
/// idle watchdog fires it closes the connection with this code so the peer can
/// distinguish a benign idle teardown (return Ok) from a real relay error — making
/// the outcome symmetric regardless of which side's watchdog fires first.
pub const RELAY_IDLE_CLOSE_CODE: u32 = 1;

/// True iff a QUIC connection's close reason is the agreed relay idle teardown
/// (`ApplicationClosed` carrying exactly [`RELAY_IDLE_CLOSE_CODE`]). A pure
/// classifier so the client and server idle-close recognizers share one tested
/// implementation; it must match ONLY the agreed code — never a generic code-0
/// application close, a transport close, or the QUIC idle-timeout abort — so a
/// real relay error is never mistaken for a benign idle teardown.
pub(crate) fn is_relay_idle_close_reason(
    reason: Option<&crate::transport::udp::quic::endpoint::ConnectionError>,
) -> bool {
    use crate::transport::udp::quic::endpoint::{ApplicationClose, ConnectionError, VarInt};
    matches!(
        reason,
        Some(ConnectionError::ApplicationClosed(ApplicationClose { error_code, .. }))
            if *error_code == VarInt::from_u32(RELAY_IDLE_CLOSE_CODE)
    )
}

pub fn max_plaintext_len(max_padding: u16) -> usize {
    OUTER_TLS_RECORD_LIMIT.saturating_sub(max_padding as usize + AEAD_TAG_LEN + PADDING_LEN_FIELD)
}

/// Minimum plaintext bytes that must remain per record after padding overhead.
/// Configs whose `max_padding` drives `max_plaintext_len` below this are rejected
/// at validation: a near-record-sized padding (e.g. leaving 1 plaintext byte)
/// makes a single `RELAY_READ_BUFFER_TARGET`-sized relay read split into tens of
/// thousands of records, and the up-front `out.reserve(...)` for that would
/// attempt a multi-GiB allocation (an availability footgun). 1 KiB still permits
/// very heavy padding (>90% of the record) while bounding worst-case buffering to
/// a few MiB per relay read.
pub const MIN_USABLE_PLAINTEXT_LEN: usize = 1024;

pub fn relay_read_buffer_len(max_payload_chunk_len: usize) -> usize {
    if max_payload_chunk_len == 0 {
        0
    } else {
        RELAY_READ_BUFFER_TARGET.max(max_payload_chunk_len)
    }
}

fn record_capacity(payload_len: usize, max_padding: u16) -> usize {
    record::TLS_HEADER_LEN + payload_len + max_padding as usize + PADDING_LEN_FIELD + AEAD_TAG_LEN
}

fn chunk_count(payload_len: usize, max_chunk_len: usize) -> usize {
    if payload_len == 0 {
        1
    } else {
        payload_len.div_ceil(max_chunk_len)
    }
}

fn chunked_records_capacity(payload_len: usize, record_count: usize, max_padding: u16) -> usize {
    payload_len
        + record_count
            * (record::TLS_HEADER_LEN + max_padding as usize + PADDING_LEN_FIELD + AEAD_TAG_LEN)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    #[test]
    fn data_record_round_trip() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(4, 4).unwrap();
        let mut rng = StdRng::seed_from_u64(11);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);

        let record = enc.seal(b"hello", &mut rng).unwrap();
        assert_eq!(dec.open(&record).unwrap(), b"hello");
    }

    #[test]
    fn seal_into_extra_padded_is_decode_transparent_on_a_zero_profile_codec() {
        // PAR-35: the aggregate decorrelation pad is applied via seal_into_extra_padded
        // on a codec whose PaddingProfile is 0/0 (the relay codec's setting). The
        // receiver must recover the EXACT original payload regardless of the extra pad,
        // and the on-wire record must be larger by exactly (extra_pad + 2-byte trailer).
        let key = [9_u8; KEY_LEN];
        let nonce = [3_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap(); // relay/PQ codec setting
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);

        let payload = vec![0x42_u8; 700];
        // Baseline: same payload with no extra pad.
        let mut base = Vec::new();
        enc.seal_into_extra_padded(&payload, 0, &mut rng, &mut base)
            .unwrap();
        // Reset the AEAD sequence by rebuilding enc so the two records use the same
        // nonce position (we only compare lengths, not the decrypt of `base`).
        let mut enc2 =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut padded = Vec::new();
        let extra = 257_usize;
        enc2.seal_into_extra_padded(&payload, extra, &mut rng, &mut padded)
            .unwrap();
        assert_eq!(
            padded.len(),
            base.len() + extra,
            "extra pad must grow the record by exactly `extra` bytes (the 2-byte trailer is present in both)"
        );
        // The receiver recovers the exact payload, pad stripped.
        assert_eq!(dec.open(&padded).unwrap(), payload);
    }

    #[test]
    fn seal_pq_flight_round_trips_every_chunk_with_one_aggregate_pad() {
        // The whole PQ flight seals into one buffer; each FramedChunk record opens back
        // to its exact bytes (the aggregate pad on the last record is stripped). Proves
        // the seal-side shaping does not corrupt any chunk.
        use crate::protocol::command::{FramedChunk, FramedReassembler, MAX_PQ_HANDSHAKE_FRAME};
        let key = [5_u8; KEY_LEN];
        let nonce = [6_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD);

        let payload: Vec<u8> = (0..1609_u32).map(|i| (i % 251) as u8).collect();
        let chunks = FramedChunk::encode_all_browser_shaped(&payload, &mut rng).unwrap();
        let mut sealed = Vec::new();
        enc.seal_pq_flight(&chunks, &mut rng, &mut sealed).unwrap();

        // Open each record off the wire and reassemble the original payload.
        let mut reassembler = FramedReassembler::default();
        let mut assembled = None;
        let mut offset = 0usize;
        while offset < sealed.len() {
            let header = record::parse_header(&sealed[offset..]).unwrap();
            let end = offset + header.total_len;
            let chunk = dec.open(&sealed[offset..end]).unwrap();
            if let Some(done) = reassembler
                .push(&chunk, MAX_PQ_HANDSHAKE_FRAME * 2)
                .unwrap()
            {
                assembled = Some(done);
            }
            offset = end;
        }
        assert_eq!(assembled.unwrap(), payload);
    }

    #[test]
    fn seal_records_into_rejects_mismatched_record_lens() {
        // Internal contract: record_lens must sum to plaintext.len(). A violation must
        // return a clean Err in EVERY build, not OOB-panic on the per-record slice in
        // release (the prior debug_assert was compiled out there). Not attacker-
        // reachable today, but the release path must never panic on a caller bug.
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(4, 4).unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);

        // sum (5) > plaintext.len() (4): would OOB-slice without the guard.
        let mut out = Vec::new();
        assert!(matches!(
            enc.seal_records_into(b"abcd", &[2, 3], &mut rng, &mut out),
            Err(DataRecordError::InvalidRecordLens)
        ));
        // sum (2) < plaintext.len() (4): would silently under-seal without the guard.
        let mut out2 = Vec::new();
        assert!(matches!(
            enc.seal_records_into(b"abcd", &[1, 1], &mut rng, &mut out2),
            Err(DataRecordError::InvalidRecordLens)
        ));
        // The matching partition still seals fine.
        let mut out3 = Vec::new();
        assert!(enc
            .seal_records_into(b"abcd", &[1, 3], &mut rng, &mut out3)
            .is_ok());
    }

    #[test]
    fn seal_chunks_splits_large_payload_into_tls_sized_records() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 128).unwrap();
        let mut rng = StdRng::seed_from_u64(13);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let payload = (0..64 * 1024)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();

        let records = enc.seal_chunks(&payload, &mut rng).unwrap();

        assert!(records.len() > 1);
        let mut opened = Vec::with_capacity(payload.len());
        for record in records {
            let header = record::parse_header(&record).unwrap();
            assert_eq!(header.content_type, TLS_CONTENT_APPLICATION_DATA);
            assert!(header.payload_len <= OUTER_TLS_RECORD_LIMIT);
            opened.extend_from_slice(&dec.open(&record).unwrap());
        }
        assert_eq!(opened, payload);
    }

    #[test]
    fn seal_into_appends_record_without_clearing_existing_buffer() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut rng = StdRng::seed_from_u64(15);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut out = b"prefix".to_vec();

        let range = enc.seal_into(b"hello", &mut rng, &mut out).unwrap();

        assert_eq!(&out[..6], b"prefix");
        assert_eq!(range.start, 6);
        assert_eq!(dec.open(&out[range]).unwrap(), b"hello");
    }

    #[test]
    fn seal_chunks_into_batches_records_in_one_buffer() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut rng = StdRng::seed_from_u64(16);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let payload = (0..64 * 1024)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();
        let mut out = Vec::new();

        let records = enc.seal_chunks_into(&payload, &mut rng, &mut out).unwrap();

        assert!(records.len() > 1);
        let mut opened = Vec::with_capacity(payload.len());
        for record in records {
            assert!(record.range.end <= out.len());
            opened.extend_from_slice(&dec.open(&out[record.range]).unwrap());
        }
        assert_eq!(opened, payload);
    }

    #[test]
    fn open_owned_round_trips_without_changing_wire_format() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(4, 4).unwrap();
        let mut rng = StdRng::seed_from_u64(18);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);

        let record = enc.seal(b"hello", &mut rng).unwrap();
        let plaintext = dec.open_owned(record).unwrap();

        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn open_in_place_reuses_record_buffer_for_plaintext() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(4, 4).unwrap();
        let mut rng = StdRng::seed_from_u64(19);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);

        let mut record = enc.seal(b"hello", &mut rng).unwrap();
        let capacity = record.capacity();
        dec.open_in_place(&mut record).unwrap();

        assert_eq!(record, b"hello");
        assert_eq!(record.capacity(), capacity);
    }

    #[test]
    fn open_in_place_payload_range_avoids_plaintext_front_copy() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(4, 4).unwrap();
        let mut rng = StdRng::seed_from_u64(21);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);

        let mut record = enc.seal(b"hello", &mut rng).unwrap();
        let plaintext = dec.open_in_place_payload_range(&mut record).unwrap();

        assert_eq!(
            plaintext,
            record::TLS_HEADER_LEN..record::TLS_HEADER_LEN + 5
        );
        assert_eq!(&record[plaintext], b"hello");
    }

    #[test]
    fn seal_chunks_into_reusing_reuses_record_metadata() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut rng = StdRng::seed_from_u64(17);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut out = Vec::new();
        let mut records = vec![SealedRecord {
            range: 0..0,
            plaintext_len: usize::MAX,
        }];

        enc.seal_chunks_into_reusing(b"hello", &mut rng, &mut out, &mut records)
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].plaintext_len, 5);
        assert_eq!(dec.open(&out[records[0].range.clone()]).unwrap(), b"hello");
    }

    #[test]
    fn seal_chunks_into_untracked_batches_without_metadata() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut rng = StdRng::seed_from_u64(22);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let payload = (0..64 * 1024)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();
        let mut out = Vec::new();

        enc.seal_chunks_into_untracked(&payload, &mut rng, &mut out)
            .unwrap();

        let mut offset = 0;
        let mut opened = Vec::with_capacity(payload.len());
        while offset < out.len() {
            let header = record::parse_header(&out[offset..]).unwrap();
            let end = offset + header.total_len;
            opened.extend_from_slice(&dec.open(&out[offset..end]).unwrap());
            offset = end;
        }
        assert_eq!(opened, payload);
    }

    #[test]
    fn record_builder_matches_seal_into_byte_for_byte() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(3, 900).unwrap();
        let payload = b"builder parity payload";

        let mut seal_rng = StdRng::seed_from_u64(77);
        let mut enc_seal =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut sealed = Vec::new();
        enc_seal
            .seal_into(payload, &mut seal_rng, &mut sealed)
            .unwrap();

        let mut builder_rng = StdRng::seed_from_u64(77);
        let mut enc_builder =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut built = Vec::new();
        let builder = enc_builder.begin_record(&mut built);
        built.extend_from_slice(payload);
        let range = enc_builder
            .finish_record(builder, &mut builder_rng, &mut built)
            .unwrap();

        assert_eq!(range, 0..built.len());
        assert_eq!(sealed, built);

        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        assert_eq!(dec.open(&built).unwrap(), payload);
    }

    #[test]
    fn record_builder_rejects_oversized_plaintext_and_resets_buffer() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut rng = StdRng::seed_from_u64(5);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);

        let mut out = vec![0xAA_u8; 7];
        let builder = enc.begin_record(&mut out);
        out.resize(7 + OUTER_TLS_RECORD_LIMIT + 1, 0x42);
        let err = enc.finish_record(builder, &mut rng, &mut out).unwrap_err();
        assert!(matches!(
            err,
            DataRecordError::TlsRecord(record::TlsRecordError::PayloadTooLarge(_))
        ));
        assert_eq!(out.len(), 7);
        assert!(out.iter().all(|&b| b == 0xAA));

        let builder = enc.begin_record(&mut out);
        out.extend_from_slice(b"recovers");
        let range = enc.finish_record(builder, &mut rng, &mut out).unwrap();
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        assert_eq!(dec.open(&out[range]).unwrap(), b"recovers");
    }

    #[test]
    fn seal_chunks_into_untracked_single_record_keeps_wire_format() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut rng = StdRng::seed_from_u64(23);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut out = Vec::new();

        enc.seal_chunks_into_untracked(b"hello", &mut rng, &mut out)
            .unwrap();

        let header = record::parse_header(&out).unwrap();
        assert_eq!(header.total_len, out.len());
        assert_eq!(dec.open(&out).unwrap(), b"hello");
    }

    #[test]
    fn full_data_record_wire_length_matches_safari_16401() {
        // A1: a full data record's on-wire TLS `length` field must equal 16401 —
        // identical to real Safari 26 (16384 plaintext + 1 inner-type + 16 tag)
        // and to ParallaX's own camouflage path — so no camouflage→data record-size
        // switch is observable. With the default (0,0) padding profile a full
        // record carries `max_plaintext_len()` = 16383 plaintext, then +2 self-pad
        // trailer +16 tag = 16401 on the wire.
        let key = [5_u8; KEY_LEN];
        let nonce = [6_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        assert_eq!(enc.max_plaintext_len(), 16383);

        // Two full records' worth of payload, so the first record is full-size.
        let payload = vec![0xab_u8; enc.max_plaintext_len() * 2];
        let mut rng = StdRng::seed_from_u64(99);
        let records = enc.seal_chunks(&payload, &mut rng).unwrap();

        let header = record::parse_header(&records[0]).unwrap();
        assert_eq!(
            header.payload_len, 16401,
            "full data record wire length must be 16401 (Safari-matched)"
        );

        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut opened = Vec::new();
        for record in &records {
            opened.extend_from_slice(&dec.open(record).unwrap());
        }
        assert_eq!(opened, payload);
    }

    #[test]
    fn seal_chunks_round_trips_5mb_in_both_directions() {
        let payload = (0..5 * 1024 * 1024)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();

        for (aad, key, nonce) in [
            (CLIENT_TO_SERVER_AAD, [1_u8; KEY_LEN], [2_u8; NONCE_LEN]),
            (SERVER_TO_CLIENT_AAD, [3_u8; KEY_LEN], [4_u8; NONCE_LEN]),
        ] {
            let padding = PaddingProfile::new(0, 128).unwrap();
            let mut rng = StdRng::seed_from_u64(14);
            let mut enc = DataRecordCodec::new(AeadCodec::new(key, nonce), padding, aad);
            let mut dec = DataRecordCodec::new(AeadCodec::new(key, nonce), padding, aad);

            let records = enc.seal_chunks(&payload, &mut rng).unwrap();

            assert!(records.len() > 300);
            let mut opened = Vec::with_capacity(payload.len());
            for record in records {
                let header = record::parse_header(&record).unwrap();
                assert_eq!(header.content_type, TLS_CONTENT_APPLICATION_DATA);
                assert!(header.payload_len <= OUTER_TLS_RECORD_LIMIT);
                assert_eq!(record.len(), record::TLS_HEADER_LEN + header.payload_len);
                opened.extend_from_slice(&dec.open(&record).unwrap());
            }
            assert_eq!(opened, payload);
        }
    }

    #[test]
    fn failed_open_does_not_advance_nonce() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut rng = StdRng::seed_from_u64(12);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let bad = record::wrap_application_data(b"not-valid-ciphertext").unwrap();

        assert!(matches!(dec.open(&bad), Err(DataRecordError::Aead(_))));
        let good = enc.seal(b"hello", &mut rng).unwrap();
        assert_eq!(dec.open(&good).unwrap(), b"hello");
    }

    #[test]
    fn failed_open_in_place_does_not_advance_nonce() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut rng = StdRng::seed_from_u64(21);
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut bad = record::wrap_application_data(b"not-valid-ciphertext").unwrap();

        assert!(matches!(
            dec.open_in_place(&mut bad),
            Err(DataRecordError::Aead(_))
        ));
        let mut good = enc.seal(b"hello", &mut rng).unwrap();
        dec.open_in_place(&mut good).unwrap();
        assert_eq!(good, b"hello");
    }

    fn test_pool() -> CryptoPool {
        CryptoPool::new(4)
    }

    #[test]
    fn parallel_seal_matches_serial_byte_for_byte_without_padding() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let payload = (0..200 * 1024)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();

        let mut serial =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut serial_rng = StdRng::seed_from_u64(101);
        let mut serial_out = Vec::new();
        serial
            .seal_chunks_into_untracked(&payload, &mut serial_rng, &mut serial_out)
            .unwrap();

        let mut parallel =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut parallel_rng = StdRng::seed_from_u64(202);
        let mut parallel_out = Vec::new();
        parallel
            .seal_chunks_into_parallel(&test_pool(), &payload, &mut parallel_rng, &mut parallel_out)
            .unwrap();

        // With zero padding no rng is consumed, so output is fully deterministic
        // and the parallel path must match the serial wire bytes exactly.
        assert_eq!(parallel_out, serial_out);
    }

    #[test]
    fn parallel_seal_round_trips_through_serial_open_with_padding() {
        let key = [3_u8; KEY_LEN];
        let nonce = [4_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 256).unwrap();
        let payload = (0..300 * 1024)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();

        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD);
        let mut rng = StdRng::seed_from_u64(7);
        let mut sealed = Vec::new();
        enc.seal_chunks_into_parallel(&test_pool(), &payload, &mut rng, &mut sealed)
            .unwrap();

        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD);
        let mut offset = 0;
        let mut opened = Vec::with_capacity(payload.len());
        while offset < sealed.len() {
            let header = record::parse_header(&sealed[offset..]).unwrap();
            let end = offset + header.total_len;
            opened.extend_from_slice(&dec.open(&sealed[offset..end]).unwrap());
            offset = end;
        }
        assert_eq!(opened, payload);
    }

    /// Property test (seeded, no extra deps): random payloads spanning one to
    /// several records, with random padding profiles and both AADs, must
    /// round-trip byte-for-byte through the real chunked seal -> concat open
    /// path. Locks the core AEAD record contract the relay/seal optimizations
    /// build on (padding RNG draw, chunk boundaries, in-place open).
    #[test]
    fn random_payloads_round_trip_through_seal_and_open() {
        use rand::{rngs::StdRng, Rng, SeedableRng};

        for seed in 0..120u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let key = [seed as u8; KEY_LEN];
            let nonce = [seed.wrapping_mul(7) as u8; NONCE_LEN];
            let max_pad = rng.gen_range(0..=512u16);
            let min_pad = rng.gen_range(0..=max_pad);
            let padding = PaddingProfile::new(min_pad, max_pad).unwrap();
            let len = rng.gen_range(1..=80 * 1024usize);
            let payload: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let aad = if seed % 2 == 0 {
                CLIENT_TO_SERVER_AAD
            } else {
                SERVER_TO_CLIENT_AAD
            };

            let mut enc = DataRecordCodec::new(AeadCodec::new(key, nonce), padding, aad);
            let mut seal_rng = StdRng::seed_from_u64(seed ^ 0x5050);
            let mut sealed = Vec::new();
            enc.seal_chunks_into_untracked(&payload, &mut seal_rng, &mut sealed)
                .unwrap();

            let mut dec = DataRecordCodec::new(AeadCodec::new(key, nonce), padding, aad);
            let mut opened = Vec::new();
            dec.open_concat_records(&mut sealed, &mut opened).unwrap();
            assert_eq!(
                opened, payload,
                "seed {seed}: round-trip must reconstruct payload"
            );
        }
    }

    #[test]
    fn parallel_open_matches_serial_open_across_many_records() {
        let key = [5_u8; KEY_LEN];
        let nonce = [6_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 200).unwrap();
        let payload = (0..400 * 1024)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();

        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut rng = StdRng::seed_from_u64(31);
        let mut sealed = Vec::new();
        enc.seal_chunks_into_untracked(&payload, &mut rng, &mut sealed)
            .unwrap();

        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut opened = Vec::new();
        dec.open_concat_records_parallel(&test_pool(), &sealed, &mut opened)
            .unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn parallel_seal_then_parallel_open_round_trips_both_directions() {
        let pool = test_pool();
        for (aad, key, nonce) in [
            (CLIENT_TO_SERVER_AAD, [1_u8; KEY_LEN], [2_u8; NONCE_LEN]),
            (SERVER_TO_CLIENT_AAD, [9_u8; KEY_LEN], [8_u8; NONCE_LEN]),
        ] {
            let padding = PaddingProfile::new(0, 128).unwrap();
            let payload = (0..(1024 * 1024 + 7))
                .map(|idx| (idx % 251) as u8)
                .collect::<Vec<_>>();
            let mut enc = DataRecordCodec::new(AeadCodec::new(key, nonce), padding, aad);
            let mut dec = DataRecordCodec::new(AeadCodec::new(key, nonce), padding, aad);
            let mut rng = StdRng::seed_from_u64(55);

            let mut sealed = Vec::new();
            enc.seal_chunks_into_parallel(&pool, &payload, &mut rng, &mut sealed)
                .unwrap();
            let mut opened = Vec::new();
            dec.open_concat_records_parallel(&pool, &sealed, &mut opened)
                .unwrap();
            assert_eq!(opened, payload);
        }
    }

    #[test]
    fn parallel_seal_advances_sequence_like_serial() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let payload = vec![0x33_u8; 70 * 1024];

        // After sealing the same payload, a follow-up single record must use the
        // same nonce in both paths, so the serial decoder accepts both streams.
        let mut serial =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut serial_rng = StdRng::seed_from_u64(1);
        let mut serial_out = Vec::new();
        serial
            .seal_chunks_into_untracked(&payload, &mut serial_rng, &mut serial_out)
            .unwrap();
        let serial_tail = serial.seal(b"tail", &mut serial_rng).unwrap();

        let mut parallel =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut parallel_rng = StdRng::seed_from_u64(2);
        let mut parallel_out = Vec::new();
        parallel
            .seal_chunks_into_parallel(&test_pool(), &payload, &mut parallel_rng, &mut parallel_out)
            .unwrap();
        let parallel_tail = parallel.seal(b"tail", &mut parallel_rng).unwrap();

        assert_eq!(serial_tail, parallel_tail);
    }

    #[test]
    fn parallel_open_rejects_tampered_record() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let payload = vec![0x44_u8; 80 * 1024];

        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut rng = StdRng::seed_from_u64(9);
        let mut sealed = Vec::new();
        enc.seal_chunks_into_untracked(&payload, &mut rng, &mut sealed)
            .unwrap();
        let flip = sealed.len() / 2;
        sealed[flip] ^= 0x01;

        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut opened = Vec::new();
        assert!(matches!(
            dec.open_concat_records_parallel(&test_pool(), &sealed, &mut opened),
            Err(DataRecordError::Aead(_))
        ));
    }

    /// Frame-aligned style record partition: mixed sizes, including one
    /// maximum-length record, mirroring what the mux writers produce.
    fn variable_record_lens(max_len: usize) -> Vec<usize> {
        vec![5, max_len, 1, 700, max_len / 2, 13, 4096]
    }

    fn patterned_payload(len: usize) -> Vec<u8> {
        (0..len).map(|idx| (idx % 251) as u8).collect()
    }

    #[test]
    fn seal_records_into_matches_per_record_seal_into() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut reference =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let lens = variable_record_lens(reference.max_plaintext_len());
        let payload = patterned_payload(lens.iter().sum());

        let mut reference_rng = StdRng::seed_from_u64(41);
        let mut reference_out = Vec::new();
        let mut offset = 0;
        for &len in &lens {
            reference
                .seal_into(
                    &payload[offset..offset + len],
                    &mut reference_rng,
                    &mut reference_out,
                )
                .unwrap();
            offset += len;
        }

        let mut batched =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut batched_rng = StdRng::seed_from_u64(42);
        let mut batched_out = Vec::new();
        batched
            .seal_records_into(&payload, &lens, &mut batched_rng, &mut batched_out)
            .unwrap();

        // Zero padding consumes no rng, so the wire bytes are deterministic.
        assert_eq!(batched_out, reference_out);
    }

    #[test]
    fn seal_records_into_inplace_matches_seal_records_into_byte_for_byte() {
        let key = [5_u8; KEY_LEN];
        let nonce = [6_u8; NONCE_LEN];
        let padding = PaddingProfile::new(3, 900).unwrap();
        let lens = variable_record_lens(
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD)
                .max_plaintext_len(),
        );
        let payload = patterned_payload(lens.iter().sum());

        // Reference: the staging-buffer path (seal_records_into copies each slice).
        let mut reference =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut reference_rng = StdRng::seed_from_u64(61);
        let mut reference_out = Vec::new();
        reference
            .seal_records_into(&payload, &lens, &mut reference_rng, &mut reference_out)
            .unwrap();

        // In-place: each record's plaintext is written straight into `out`. SAME
        // seed as the reference so the per-record padding draws line up.
        let mut inplace =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut inplace_rng = StdRng::seed_from_u64(61);
        let mut inplace_out = Vec::new();
        let mut off = 0usize;
        inplace
            .seal_records_into_inplace(&lens, &mut inplace_rng, &mut inplace_out, |i, out| {
                let len = lens[i];
                out.extend_from_slice(&payload[off..off + len]);
                off += len;
            })
            .unwrap();

        // NON-zero padding (3..=900) is drawn per record from the SAME seeded RNG
        // on both paths, so byte-for-byte equality here also proves the padding
        // draw ORDER and COUNT match — the exact divergence a zero-padding test
        // (which draws no rng) could not catch. inplace therefore round-trips too,
        // since the reference output is proven to round-trip elsewhere.
        assert_eq!(inplace_out, reference_out);
    }

    #[test]
    fn record_lens_parallel_seal_matches_serial_and_advances_sequence() {
        let key = [3_u8; KEY_LEN];
        let nonce = [4_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut serial =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD);
        let lens = variable_record_lens(serial.max_plaintext_len());
        let payload = patterned_payload(lens.iter().sum());

        let mut serial_rng = StdRng::seed_from_u64(51);
        let mut serial_out = Vec::new();
        serial
            .seal_records_into(&payload, &lens, &mut serial_rng, &mut serial_out)
            .unwrap();
        let serial_tail = serial.seal(b"tail", &mut serial_rng).unwrap();

        let mut parallel =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD);
        let mut parallel_rng = StdRng::seed_from_u64(52);
        let mut parallel_out = Vec::new();
        parallel
            .seal_records_into_parallel(
                &test_pool(),
                &payload,
                &lens,
                &mut parallel_rng,
                &mut parallel_out,
            )
            .unwrap();
        let parallel_tail = parallel.seal(b"tail", &mut parallel_rng).unwrap();

        assert_eq!(parallel_out, serial_out);
        // Identical follow-up record proves both paths advanced the sequence
        // counter by the same number of records.
        assert_eq!(parallel_tail, serial_tail);
    }

    #[test]
    fn open_concat_records_serial_matches_parallel_round_trip() {
        let key = [5_u8; KEY_LEN];
        let nonce = [6_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 128).unwrap();
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let lens = variable_record_lens(enc.max_plaintext_len());
        let payload = patterned_payload(lens.iter().sum());
        let mut rng = StdRng::seed_from_u64(61);
        let mut sealed = Vec::new();
        enc.seal_records_into(&payload, &lens, &mut rng, &mut sealed)
            .unwrap();
        let tail = enc.seal(b"tail", &mut rng).unwrap();

        let mut serial_dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut serial_sealed = sealed.clone();
        let mut serial_opened = Vec::new();
        serial_dec
            .open_concat_records(&mut serial_sealed, &mut serial_opened)
            .unwrap();
        assert_eq!(serial_opened, payload);
        // The serial concat open advanced the sequence once per record.
        assert_eq!(serial_dec.open(&tail).unwrap(), b"tail");

        let mut parallel_dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut parallel_opened = Vec::new();
        parallel_dec
            .open_concat_records_parallel(&test_pool(), &sealed, &mut parallel_opened)
            .unwrap();
        assert_eq!(parallel_opened, payload);
        assert_eq!(parallel_dec.open(&tail).unwrap(), b"tail");
    }

    #[test]
    fn open_concat_records_rejects_tampered_record() {
        let key = [7_u8; KEY_LEN];
        let nonce = [8_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut rng = StdRng::seed_from_u64(71);
        let mut sealed = Vec::new();
        enc.seal_chunks_into_untracked(&vec![0x55_u8; 80 * 1024], &mut rng, &mut sealed)
            .unwrap();
        let flip = sealed.len() / 2;
        sealed[flip] ^= 0x01;

        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut opened = Vec::new();
        assert!(matches!(
            dec.open_concat_records(&mut sealed, &mut opened),
            Err(DataRecordError::Aead(_))
        ));
    }

    #[test]
    fn batch_open_failure_poisons_codec() {
        let key = [9_u8; KEY_LEN];
        let nonce = [10_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut rng = StdRng::seed_from_u64(81);
        // Record sealed at sequence 0; keep a pristine copy.
        let good = enc.seal(b"first", &mut rng).unwrap();

        let mut dec =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        let mut tampered = good.clone();
        let flip = tampered.len() - 1;
        tampered[flip] ^= 0x01;
        let mut opened = Vec::new();
        // Batch open of the tampered (first) record fails without advancing the
        // sequence counter, so the failure is only detectable as a poison.
        assert!(matches!(
            dec.open_concat_records(&mut tampered, &mut opened),
            Err(DataRecordError::Aead(_))
        ));
        // The pristine record still matches sequence 0, so without poisoning the
        // codec this open would succeed. Poisoning makes every later op fail-close.
        assert!(matches!(dec.open(&good), Err(DataRecordError::Aead(_))));
    }

    #[test]
    fn parallel_seal_rejects_sequence_overflow() {
        let key = [11_u8; KEY_LEN];
        let nonce = [12_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let mut enc =
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
        // Drive the per-direction sequence counter to the edge so a 2-record
        // batch would wrap past u64::MAX.
        enc.aead.advance_sequence(u64::MAX - 1);
        let payload = vec![0_u8; 8];
        let lens = vec![4_usize, 4_usize];
        let mut rng = StdRng::seed_from_u64(91);
        let mut out = Vec::new();
        assert!(matches!(
            enc.seal_records_into_parallel(&test_pool(), &payload, &lens, &mut rng, &mut out),
            Err(DataRecordError::Aead(SessionError::NonceExhausted))
        ));
    }

    #[test]
    fn should_parallelize_aead_requires_both_thresholds() {
        assert!(should_parallelize_aead(
            PARALLEL_AEAD_MIN_RECORDS,
            PARALLEL_AEAD_MIN_BYTES
        ));
        assert!(!should_parallelize_aead(
            PARALLEL_AEAD_MIN_RECORDS - 1,
            PARALLEL_AEAD_MIN_BYTES
        ));
        assert!(!should_parallelize_aead(
            PARALLEL_AEAD_MIN_RECORDS,
            PARALLEL_AEAD_MIN_BYTES - 1
        ));
        // One full-size record alone must stay inline regardless of bytes.
        assert!(!should_parallelize_aead(1, 1024 * 1024));
    }

    #[test]
    fn parallel_seal_handles_empty_and_tiny_payloads() {
        let key = [1_u8; KEY_LEN];
        let nonce = [2_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let pool = test_pool();

        for payload in [Vec::new(), b"x".to_vec(), b"short payload".to_vec()] {
            let mut enc =
                DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
            let mut rng = StdRng::seed_from_u64(3);
            let mut sealed = Vec::new();
            enc.seal_chunks_into_parallel(&pool, &payload, &mut rng, &mut sealed)
                .unwrap();

            let mut dec =
                DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD);
            let mut opened = Vec::new();
            dec.open_concat_records_parallel(&pool, &sealed, &mut opened)
                .unwrap();
            assert_eq!(opened, payload);
        }
    }

    #[test]
    fn max_plaintext_len_saturates_when_padding_exceeds_record_capacity() {
        assert_eq!(max_plaintext_len(u16::MAX), 0);
        assert_eq!(
            max_plaintext_len((OUTER_TLS_RECORD_LIMIT - AEAD_TAG_LEN - PADDING_LEN_FIELD) as u16),
            0
        );
        assert_eq!(
            max_plaintext_len(
                (OUTER_TLS_RECORD_LIMIT - AEAD_TAG_LEN - PADDING_LEN_FIELD - 1) as u16
            ),
            1
        );
    }

    #[test]
    fn relay_read_buffer_is_large_enough_to_batch_records() {
        assert_eq!(relay_read_buffer_len(0), 0);
        assert_eq!(relay_read_buffer_len(1), RELAY_READ_BUFFER_TARGET);
        assert_eq!(
            relay_read_buffer_len(RELAY_READ_BUFFER_TARGET + 1),
            RELAY_READ_BUFFER_TARGET + 1
        );
    }

    #[test]
    fn relay_idle_close_reason_matches_only_the_agreed_code() {
        use crate::transport::udp::quic::endpoint::{ApplicationClose, ConnectionError, VarInt};

        let idle = ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: VarInt::from_u32(RELAY_IDLE_CLOSE_CODE),
            reason: Vec::new(),
        });
        assert!(is_relay_idle_close_reason(Some(&idle)));

        // A generic code-0 application close, a transport close, and "no reason
        // yet" (live connection) must NOT be mistaken for the idle teardown.
        let generic = ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: VarInt::from_u32(0),
            reason: Vec::new(),
        });
        assert!(!is_relay_idle_close_reason(Some(&generic)));
        assert!(!is_relay_idle_close_reason(Some(
            &ConnectionError::TimedOut
        )));
        assert!(!is_relay_idle_close_reason(None));
    }
}
