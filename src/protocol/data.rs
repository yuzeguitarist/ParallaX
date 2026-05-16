use thiserror::Error;

use crate::{
    crypto::session::{AeadCodec, SessionError},
    tls::record::{self, TLS_CONTENT_APPLICATION_DATA},
    traffic::{PaddingProfile, TrafficError},
};

const AEAD_TAG_LEN: usize = 16;
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

impl DataRecordCodec {
    pub fn new(aead: AeadCodec, padding: PaddingProfile, aad: &'static [u8]) -> Self {
        Self { aead, padding, aad }
    }

    pub fn seal<R>(&mut self, payload: &[u8], rng: &mut R) -> Result<Vec<u8>, DataRecordError>
    where
        R: rand::Rng + rand::RngCore + ?Sized,
    {
        let padded = self.padding.apply(payload, rng);
        let encrypted = self.aead.seal(&padded, self.aad)?;
        Ok(record::wrap_application_data(&encrypted)?)
    }

    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, DataRecordError> {
        let header = record::parse_header(record)?;
        if header.content_type != TLS_CONTENT_APPLICATION_DATA {
            return Err(DataRecordError::NotApplicationData);
        }
        if record.len() < header.total_len {
            return Err(record::TlsRecordError::IncompletePayload.into());
        }
        let ciphertext = &record[record::TLS_HEADER_LEN..header.total_len];
        let padded = self.aead.open(ciphertext, self.aad)?;
        Ok(PaddingProfile::remove(&padded)?)
    }

    pub fn rekey(&mut self, key: [u8; 32], nonce_base: [u8; 12]) {
        self.aead.rekey(key, nonce_base);
    }
}

pub const CLIENT_TO_SERVER_AAD: &[u8] = b"ParallaX v1 client appdata";
pub const SERVER_TO_CLIENT_AAD: &[u8] = b"ParallaX v1 server appdata";

pub fn max_plaintext_len(max_padding: u16) -> usize {
    record::MAX_TLS_RECORD_PAYLOAD
        .saturating_sub(max_padding as usize + AEAD_TAG_LEN + PADDING_LEN_FIELD)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::crypto::session::{KEY_LEN, NONCE_LEN};

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
}
