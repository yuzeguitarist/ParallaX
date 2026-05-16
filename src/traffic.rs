use std::time::Duration;

use rand::{Rng, RngCore};
use thiserror::Error;

use crate::config::TrafficConfig;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TrafficError {
    #[error("padding range is invalid")]
    InvalidPaddingRange,
    #[error("padded frame is too short")]
    PaddedFrameTooShort,
    #[error("padding length exceeds frame length")]
    PaddingLengthOutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingProfile {
    min: u16,
    max: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingProfile {
    min: Duration,
    max: Duration,
}

impl PaddingProfile {
    pub fn new(min: u16, max: u16) -> Result<Self, TrafficError> {
        if max < min {
            return Err(TrafficError::InvalidPaddingRange);
        }
        Ok(Self { min, max })
    }

    pub fn from_config(config: TrafficConfig) -> Result<Self, TrafficError> {
        Self::new(config.min_padding, config.max_padding)
    }

    pub fn apply<R>(&self, payload: &[u8], rng: &mut R) -> Vec<u8>
    where
        R: Rng + RngCore + ?Sized,
    {
        let pad_len = rng.gen_range(self.min..=self.max) as usize;
        let mut out = Vec::with_capacity(payload.len() + pad_len + 2);
        out.extend_from_slice(payload);

        let start = out.len();
        out.resize(start + pad_len, 0);
        rng.fill_bytes(&mut out[start..]);
        out.extend_from_slice(&(pad_len as u16).to_be_bytes());
        out
    }

    pub fn remove(padded: &[u8]) -> Result<Vec<u8>, TrafficError> {
        if padded.len() < 2 {
            return Err(TrafficError::PaddedFrameTooShort);
        }

        let pad_len =
            u16::from_be_bytes([padded[padded.len() - 2], padded[padded.len() - 1]]) as usize;
        if pad_len + 2 > padded.len() {
            return Err(TrafficError::PaddingLengthOutOfRange);
        }

        Ok(padded[..padded.len() - pad_len - 2].to_vec())
    }
}

impl TimingProfile {
    pub fn from_config(config: TrafficConfig) -> Self {
        Self {
            min: Duration::from_millis(config.min_delay_ms as u64),
            max: Duration::from_millis(config.max_delay_ms as u64),
        }
    }

    pub fn sample_delay<R>(&self, rng: &mut R) -> Duration
    where
        R: Rng + ?Sized,
    {
        if self.min >= self.max {
            return self.min;
        }
        let min = self.min.as_millis() as u64;
        let max = self.max.as_millis() as u64;
        Duration::from_millis(rng.gen_range(min..=max))
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn padding_round_trip() {
        let profile = PaddingProfile::new(8, 8).unwrap();
        let mut rng = StdRng::seed_from_u64(9);

        let padded = profile.apply(b"hello", &mut rng);
        assert_eq!(padded.len(), 5 + 8 + 2);
        assert_eq!(PaddingProfile::remove(&padded).unwrap(), b"hello");
    }

    #[test]
    fn rejects_invalid_padding() {
        assert!(matches!(
            PaddingProfile::remove(&[0, 10]),
            Err(TrafficError::PaddingLengthOutOfRange)
        ));
    }
}
