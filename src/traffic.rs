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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverTrafficProfile {
    min_interval: Duration,
    max_interval: Duration,
}

const OBSERVED_PACKET_TARGETS: [u16; 18] = [
    64, 83, 91, 132, 144, 191, 286, 339, 469, 519, 569, 713, 735, 1353, 1440, 1459, 1500, 1500,
];

const OBSERVED_DELAY_MS: [u16; 12] = [0, 3, 7, 12, 25, 25, 41, 218, 410, 747, 790, 804];

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

    pub fn max_len(&self) -> u16 {
        self.max
    }

    pub fn apply<R>(&self, payload: &[u8], rng: &mut R) -> Vec<u8>
    where
        R: Rng + RngCore + ?Sized,
    {
        let mut out = Vec::with_capacity(payload.len() + self.max as usize + 2);
        self.apply_into(payload, rng, &mut out);
        out
    }

    pub fn apply_into<R>(&self, payload: &[u8], rng: &mut R, out: &mut Vec<u8>)
    where
        R: Rng + RngCore + ?Sized,
    {
        let pad_len = self.sample_padding_len(payload.len(), rng) as usize;
        out.extend_from_slice(payload);
        self.write_padding_suffix(pad_len, rng, out);
    }

    /// Appends the padding suffix (pad bytes + length field) for a payload of
    /// `payload_len` bytes that the caller already wrote into `out`.
    pub fn apply_suffix_into<R>(&self, payload_len: usize, rng: &mut R, out: &mut Vec<u8>)
    where
        R: Rng + RngCore + ?Sized,
    {
        let pad_len = self.sample_padding_len(payload_len, rng) as usize;
        self.write_padding_suffix(pad_len, rng, out);
    }

    fn write_padding_suffix<R>(&self, pad_len: usize, rng: &mut R, out: &mut Vec<u8>)
    where
        R: Rng + RngCore + ?Sized,
    {
        if pad_len != 0 {
            let start = out.len();
            out.resize(start + pad_len, 0);
            rng.fill_bytes(&mut out[start..]);
        }
        out.extend_from_slice(&(pad_len as u16).to_be_bytes());
    }

    fn sample_padding_len<R>(&self, payload_len: usize, rng: &mut R) -> u16
    where
        R: Rng + ?Sized,
    {
        if self.min == self.max {
            return self.min;
        }

        if rng.gen_range(0..100) < 55 {
            let target = OBSERVED_PACKET_TARGETS[rng.gen_range(0..OBSERVED_PACKET_TARGETS.len())];
            let overhead = 2_usize;
            // Only aim for an observed packet size when it leaves room to pad
            // above the floor. Full-size relay chunks already have
            // payload_len + overhead >= every observed target, so the old code
            // collapsed to `self.min` here, spiking the padding distribution at a
            // single value. Fall through to the random-span branch in that case.
            if payload_len + overhead + (self.min as usize) < (target as usize) {
                let needed = target
                    .saturating_sub(payload_len as u16)
                    .saturating_sub(overhead as u16);
                return needed.clamp(self.min, self.max);
            }
        }

        let span = self.max - self.min;
        let bucket = rng.gen_range(0..100);
        let capped_span = if bucket < 70 {
            span.min(64)
        } else if bucket < 92 {
            span.min(256)
        } else {
            span
        };
        self.min + rng.gen_range(0..=capped_span)
    }

    pub fn remove(padded: &[u8]) -> Result<Vec<u8>, TrafficError> {
        let plaintext_len = Self::unpadded_len(padded)?;
        Ok(padded[..plaintext_len].to_vec())
    }

    pub fn remove_in_place(padded: &mut Vec<u8>) -> Result<(), TrafficError> {
        let plaintext_len = Self::unpadded_len(padded)?;
        padded.truncate(plaintext_len);
        Ok(())
    }

    pub(crate) fn unpadded_len(padded: &[u8]) -> Result<usize, TrafficError> {
        if padded.len() < 2 {
            return Err(TrafficError::PaddedFrameTooShort);
        }

        let pad_len =
            u16::from_be_bytes([padded[padded.len() - 2], padded[padded.len() - 1]]) as usize;
        if pad_len + 2 > padded.len() {
            return Err(TrafficError::PaddingLengthOutOfRange);
        }

        Ok(padded.len() - pad_len - 2)
    }
}

impl TimingProfile {
    pub fn from_config(config: TrafficConfig) -> Self {
        Self {
            min: Duration::from_millis(config.min_delay_ms as u64),
            max: Duration::from_millis(config.max_delay_ms as u64),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.max.is_zero()
    }

    pub fn sample_delay<R>(&self, rng: &mut R) -> Duration
    where
        R: Rng + ?Sized,
    {
        if self.min >= self.max {
            return self.min;
        }
        if rng.gen_range(0..100) < 60 {
            let sampled = OBSERVED_DELAY_MS[rng.gen_range(0..OBSERVED_DELAY_MS.len())] as u64;
            let clamped = sampled.clamp(self.min.as_millis() as u64, self.max.as_millis() as u64);
            return Duration::from_millis(clamped);
        }
        let min = self.min.as_millis() as u64;
        let max = self.max.as_millis() as u64;
        Duration::from_millis(rng.gen_range(min..=max))
    }
}

impl CoverTrafficProfile {
    pub fn from_config(config: TrafficConfig) -> Self {
        Self {
            min_interval: Duration::from_millis(config.cover_min_interval_ms as u64),
            max_interval: Duration::from_millis(config.cover_max_interval_ms as u64),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.max_interval.is_zero()
    }

    pub fn sample_interval<R>(&self, rng: &mut R) -> Duration
    where
        R: Rng + ?Sized,
    {
        if !self.is_enabled() || self.min_interval >= self.max_interval {
            return self.min_interval;
        }

        let min = self.min_interval.as_millis() as u64;
        let max = self.max_interval.as_millis() as u64;
        Duration::from_millis(rng.gen_range(min..=max))
    }
}

/// Formal proofs (Kani) over the padding parser. Compiled ONLY under `cargo
/// kani` (which sets `cfg(kani)`); absent from a normal build/test.
#[cfg(kani)]
mod kani_proofs {
    use super::PaddingProfile;

    /// The 2-byte padding-length trailer is attacker-controlled. `unpadded_len`
    /// must NEVER panic (no integer underflow, no OOB index) for ANY input.
    /// Proven here over all byte contents for every length up to a bound that
    /// spans the guard boundary (len < 2, the 2-byte trailer, and pad_len vs
    /// len), complementing the randomized + Miri property test with an exhaustive
    /// check of the dangerous arithmetic.
    #[kani::proof]
    fn unpadded_len_never_panics() {
        const N: usize = 8;
        let len: usize = kani::any();
        kani::assume(len <= N);
        let mut buf = [0_u8; N];
        for b in buf.iter_mut() {
            *b = kani::any();
        }
        let _ = PaddingProfile::unpadded_len(&buf[..len]);
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

        let mut in_place = padded.clone();
        PaddingProfile::remove_in_place(&mut in_place).unwrap();
        assert_eq!(in_place, b"hello");
    }

    #[test]
    fn unpadded_len_never_panics_on_arbitrary_bytes() {
        // The 2-byte padding-length trailer is attacker-controlled untrusted
        // input. `remove` must reject malformed framing with an error and NEVER
        // panic (no integer underflow, no OOB slice) for ANY byte string and any
        // claimed pad_len. With the Miri lane over `traffic::`, this fuzzes the
        // parser for UB across diverse inputs and boundary pad_len values.
        let mut rng = StdRng::seed_from_u64(0x0BAD_F00D);
        // Full input coverage under normal `cargo test`; a smaller sweep under
        // the (much slower) Miri interpreter, which only needs a handful of
        // diverse inputs to surface any UB.
        let iters = if cfg!(miri) { 200 } else { 5000 };
        for _ in 0..iters {
            let len = rng.gen_range(0_usize..2048);
            let mut bytes: Vec<u8> = (0..len).map(|_| rng.gen::<u8>()).collect();
            // Half the time force the trailer to a uniformly-random u16 claimed
            // pad_len so the `pad_len + 2 > len` guard sees both far-over-length
            // values (the common case) and, occasionally, near-boundary ones.
            if len >= 2 && rng.gen_bool(0.5) {
                let [hi, lo] = rng.gen::<u16>().to_be_bytes();
                let n = bytes.len();
                bytes[n - 2] = hi;
                bytes[n - 1] = lo;
            }
            if let Ok(inner) = PaddingProfile::remove(&bytes) {
                // When accepted, framing is self-consistent: `inner` is the
                // leading prefix and inner + pad_len + 2 reconstructs the input.
                let pad_len =
                    u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]) as usize;
                assert_eq!(inner.len() + pad_len + 2, bytes.len());
                assert_eq!(&inner[..], &bytes[..inner.len()]);
            }
        }
    }

    #[test]
    fn padding_round_trips_for_random_payloads_and_profiles() {
        // remove(apply(x)) == x across random (min,max) profiles and payloads,
        // and the padded length always lands in [payload+min+2, payload+max+2]
        // (the observed-target branch clamps pad_len into [min,max]).
        let mut rng = StdRng::seed_from_u64(0x5EED_CAFE);
        let iters = if cfg!(miri) { 100 } else { 2000 };
        for _ in 0..iters {
            let a = rng.gen_range(0..=300_u16);
            let b = rng.gen_range(0..=300_u16);
            let (min, max) = (a.min(b), a.max(b));
            let profile = PaddingProfile::new(min, max).unwrap();
            let payload_len = rng.gen_range(0_usize..512);
            let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen::<u8>()).collect();

            let padded = profile.apply(&payload, &mut rng);
            assert!(padded.len() >= payload.len() + min as usize + 2);
            assert!(padded.len() <= payload.len() + max as usize + 2);

            assert_eq!(
                PaddingProfile::remove(&padded).unwrap(),
                payload,
                "remove(apply(x)) must equal x"
            );
            let mut in_place = padded.clone();
            PaddingProfile::remove_in_place(&mut in_place).unwrap();
            assert_eq!(in_place, payload);
        }
    }

    #[test]
    fn rejects_invalid_padding() {
        assert!(matches!(
            PaddingProfile::remove(&[0, 10]),
            Err(TrafficError::PaddingLengthOutOfRange)
        ));
    }

    #[test]
    fn sampled_padding_stays_in_range() {
        let profile = PaddingProfile::new(3, 777).unwrap();
        let mut rng = StdRng::seed_from_u64(10);

        for _ in 0..1000 {
            let padded = profile.apply(b"x", &mut rng);
            let pad_len = u16::from_be_bytes([padded[padded.len() - 2], padded[padded.len() - 1]]);
            assert!((3..=777).contains(&pad_len));
        }
    }

    #[test]
    fn observed_profile_can_pad_toward_large_packets() {
        let profile = PaddingProfile::new(0, 1500).unwrap();
        let mut rng = StdRng::seed_from_u64(44);
        let mut saw_large = false;

        for _ in 0..200 {
            let padded = profile.apply(&[0_u8; 32], &mut rng);
            if padded.len() > 1000 {
                saw_large = true;
                break;
            }
        }

        assert!(saw_large);
    }

    #[test]
    fn cover_profile_can_be_disabled_or_jittered() {
        let disabled = CoverTrafficProfile::from_config(TrafficConfig {
            cover_min_interval_ms: 0,
            cover_max_interval_ms: 0,
            ..TrafficConfig::default()
        });
        assert!(!disabled.is_enabled());

        let cover = CoverTrafficProfile::from_config(TrafficConfig {
            cover_min_interval_ms: 10,
            cover_max_interval_ms: 20,
            ..TrafficConfig::default()
        });
        let mut rng = StdRng::seed_from_u64(55);
        for _ in 0..64 {
            let sampled = cover.sample_interval(&mut rng);
            assert!(sampled >= Duration::from_millis(10));
            assert!(sampled <= Duration::from_millis(20));
        }
    }

    #[test]
    fn timing_profile_can_be_disabled_or_enabled() {
        let disabled = TimingProfile::from_config(TrafficConfig::default());
        assert!(!disabled.is_enabled());

        let enabled = TimingProfile::from_config(TrafficConfig {
            min_delay_ms: 0,
            max_delay_ms: 1,
            ..TrafficConfig::default()
        });
        assert!(enabled.is_enabled());
    }

    #[test]
    fn padding_profile_rejects_inverted_range() {
        assert!(matches!(
            PaddingProfile::new(20, 10),
            Err(TrafficError::InvalidPaddingRange)
        ));
        assert!(matches!(
            PaddingProfile::from_config(TrafficConfig {
                min_padding: 10,
                max_padding: 5,
                ..TrafficConfig::default()
            }),
            Err(TrafficError::InvalidPaddingRange)
        ));
    }

    #[test]
    fn padding_profile_exposes_max_len() {
        let profile = PaddingProfile::new(0, 42).unwrap();
        assert_eq!(profile.max_len(), 42);
    }

    #[test]
    fn padding_remove_rejects_short_buffer() {
        assert!(matches!(
            PaddingProfile::remove(&[]),
            Err(TrafficError::PaddedFrameTooShort)
        ));
        assert!(matches!(
            PaddingProfile::remove(&[0x55]),
            Err(TrafficError::PaddedFrameTooShort)
        ));

        let mut buf = vec![0_u8];
        assert!(matches!(
            PaddingProfile::remove_in_place(&mut buf),
            Err(TrafficError::PaddedFrameTooShort)
        ));
        assert_eq!(buf, vec![0_u8]);
    }

    #[test]
    fn padding_remove_in_place_rejects_oversized_pad_length() {
        let mut buf = vec![0xAA_u8, 0x00, 0x10];
        assert!(matches!(
            PaddingProfile::remove_in_place(&mut buf),
            Err(TrafficError::PaddingLengthOutOfRange)
        ));
    }

    #[test]
    fn padding_remove_in_place_trims_to_unpadded_len() {
        let profile = PaddingProfile::new(4, 4).unwrap();
        let mut rng = StdRng::seed_from_u64(0);
        let padded = profile.apply(b"abcd", &mut rng);
        let mut buf = padded.clone();
        PaddingProfile::remove_in_place(&mut buf).unwrap();
        assert_eq!(buf, b"abcd");
    }

    #[test]
    fn timing_profile_returns_min_when_range_is_inverted_or_collapsed() {
        let profile = TimingProfile::from_config(TrafficConfig {
            min_delay_ms: 5,
            max_delay_ms: 5,
            ..TrafficConfig::default()
        });
        let mut rng = StdRng::seed_from_u64(0);
        for _ in 0..32 {
            assert_eq!(profile.sample_delay(&mut rng), Duration::from_millis(5));
        }
    }

    #[test]
    fn timing_profile_samples_within_range() {
        let profile = TimingProfile::from_config(TrafficConfig {
            min_delay_ms: 1,
            max_delay_ms: 7,
            ..TrafficConfig::default()
        });
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..256 {
            let sample = profile.sample_delay(&mut rng);
            assert!(sample >= Duration::from_millis(1));
            assert!(sample <= Duration::from_millis(7));
        }
    }

    #[test]
    fn cover_profile_returns_min_when_disabled_or_inverted() {
        let disabled = CoverTrafficProfile::from_config(TrafficConfig::default());
        let mut rng = StdRng::seed_from_u64(2);
        assert_eq!(disabled.sample_interval(&mut rng), Duration::ZERO);

        let inverted = CoverTrafficProfile::from_config(TrafficConfig {
            cover_min_interval_ms: 50,
            cover_max_interval_ms: 25,
            ..TrafficConfig::default()
        });
        // sample_interval first checks is_enabled(); since cover_max_interval_ms
        // is non-zero the profile is enabled, but min >= max collapses to min.
        assert_eq!(
            inverted.sample_interval(&mut rng),
            Duration::from_millis(50)
        );
    }
}
