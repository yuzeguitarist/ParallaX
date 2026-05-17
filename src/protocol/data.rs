use std::ops::Range;

use thiserror::Error;

use crate::{
    crypto::session::{AeadCodec, SessionError, AEAD_TAG_LEN, KEY_LEN, NONCE_LEN},
    tls::record::{self, TLS_CONTENT_APPLICATION_DATA, TLS_LEGACY_VERSION},
    traffic::{PaddingProfile, TrafficError},
};

pub const OUTER_TLS_RECORD_LIMIT: usize = record::MAX_TLS_RECORD_PAYLOAD;
pub const RELAY_READ_BUFFER_TARGET: usize = 64 * 1024;

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

impl DataRecordCodec {
    pub fn new(aead: AeadCodec, padding: PaddingProfile, aad: &'static [u8]) -> Self {
        Self { aead, padding, aad }
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
        let record_start = out.len();
        if reserve_capacity {
            out.reserve(record_capacity(payload.len(), self.padding.max_len()));
        }
        out.extend_from_slice(&[
            TLS_CONTENT_APPLICATION_DATA,
            TLS_LEGACY_VERSION[0],
            TLS_LEGACY_VERSION[1],
            0,
            0,
        ]);

        let ciphertext_start = out.len();
        self.padding.apply_into(payload, rng, out);
        let padded_len = out.len() - ciphertext_start;
        if padded_len + AEAD_TAG_LEN > OUTER_TLS_RECORD_LIMIT {
            out.truncate(record_start);
            return Err(record::TlsRecordError::PayloadTooLarge(padded_len + AEAD_TAG_LEN).into());
        }

        let tag = self
            .aead
            .seal_in_place_detached(&mut out[ciphertext_start..], self.aad)?;
        out.extend_from_slice(&tag);

        let tls_payload_len = out.len() - ciphertext_start;
        let len = (tls_payload_len as u16).to_be_bytes();
        out[record_start + 3] = len[0];
        out[record_start + 4] = len[1];

        Ok(record_start..out.len())
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
        let chunk_count = chunk_count(payload.len(), max_chunk_len);
        records.reserve(chunk_count);
        out.reserve(chunked_records_capacity(
            payload.len(),
            chunk_count,
            self.padding.max_len(),
        ));
        if payload.is_empty() {
            let range = self.seal_into_reserved(payload, rng, out, false)?;
            records.push(SealedRecord {
                range,
                plaintext_len: 0,
            });
            return Ok(());
        }

        for chunk in payload.chunks(max_chunk_len) {
            let range = self.seal_into_reserved(chunk, rng, out, false)?;
            records.push(SealedRecord {
                range,
                plaintext_len: chunk.len(),
            });
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
        let mut padded = record[record::TLS_HEADER_LEN..header.total_len].to_vec();
        self.aead.open_in_place(&mut padded, self.aad)?;
        PaddingProfile::remove_in_place(&mut padded)?;
        Ok(padded)
    }

    pub fn open_owned(&mut self, mut record: Vec<u8>) -> Result<Vec<u8>, DataRecordError> {
        self.open_in_place(&mut record)?;
        Ok(record)
    }

    pub fn open_in_place(&mut self, record: &mut Vec<u8>) -> Result<(), DataRecordError> {
        let header = record::parse_header(record)?;
        if header.content_type != TLS_CONTENT_APPLICATION_DATA {
            return Err(DataRecordError::NotApplicationData);
        }
        if record.len() < header.total_len {
            return Err(record::TlsRecordError::IncompletePayload.into());
        }

        record.truncate(header.total_len);
        record.copy_within(record::TLS_HEADER_LEN..header.total_len, 0);
        record.truncate(header.payload_len);
        self.aead.open_in_place(record, self.aad)?;
        PaddingProfile::remove_in_place(record)?;
        Ok(())
    }

    pub fn rekey(&mut self, key: [u8; KEY_LEN], nonce_base: [u8; NONCE_LEN]) {
        self.aead.rekey(key, nonce_base);
    }

    pub fn max_plaintext_len(&self) -> usize {
        max_plaintext_len(self.padding.max_len())
    }
}

pub const CLIENT_TO_SERVER_AAD: &[u8] = b"ParallaX v1 client appdata";
pub const SERVER_TO_CLIENT_AAD: &[u8] = b"ParallaX v1 server appdata";

pub fn max_plaintext_len(max_padding: u16) -> usize {
    OUTER_TLS_RECORD_LIMIT.saturating_sub(max_padding as usize + AEAD_TAG_LEN + PADDING_LEN_FIELD)
}

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
    fn max_plaintext_len_saturates_when_padding_exceeds_record_capacity() {
        assert_eq!(max_plaintext_len(u16::MAX), 0);
        assert_eq!(
            max_plaintext_len(
                (record::MAX_TLS_RECORD_PAYLOAD - AEAD_TAG_LEN - PADDING_LEN_FIELD) as u16
            ),
            0
        );
        assert_eq!(
            max_plaintext_len(
                (record::MAX_TLS_RECORD_PAYLOAD - AEAD_TAG_LEN - PADDING_LEN_FIELD - 1) as u16
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
}
