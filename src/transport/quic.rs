use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use rand::{CryptoRng, RngCore};
use thiserror::Error;

const SALT_LEN: usize = 8;
const HASH_LEN: usize = 32;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QuicTransportError {
    #[error("obfuscated QUIC packet is truncated")]
    Truncated,
    #[error("BLAKE2b output size is invalid")]
    Blake2,
    #[error("QUIC SNI is not in the allowlist")]
    SniNotAllowed,
}

#[derive(Debug, Clone)]
pub struct Salamander {
    key: Vec<u8>,
}

impl Salamander {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self {
            key: key.as_ref().to_vec(),
        }
    }

    pub fn obfuscate<R>(&self, packet: &[u8], rng: &mut R) -> Result<Vec<u8>, QuicTransportError>
    where
        R: RngCore + CryptoRng,
    {
        let mut salt = [0_u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mask = self.mask(&salt)?;

        let mut out = Vec::with_capacity(SALT_LEN + packet.len());
        out.extend_from_slice(&salt);
        out.extend(
            packet
                .iter()
                .enumerate()
                .map(|(idx, byte)| byte ^ mask[idx % HASH_LEN]),
        );
        Ok(out)
    }

    pub fn deobfuscate(&self, packet: &[u8]) -> Result<Vec<u8>, QuicTransportError> {
        if packet.len() < SALT_LEN {
            return Err(QuicTransportError::Truncated);
        }
        let (salt, payload) = packet.split_at(SALT_LEN);
        let mask = self.mask(salt)?;
        Ok(payload
            .iter()
            .enumerate()
            .map(|(idx, byte)| byte ^ mask[idx % HASH_LEN])
            .collect())
    }

    fn mask(&self, salt: &[u8]) -> Result<[u8; HASH_LEN], QuicTransportError> {
        let mut hasher = Blake2bVar::new(HASH_LEN).map_err(|_| QuicTransportError::Blake2)?;
        hasher.update(&self.key);
        hasher.update(salt);
        let mut out = [0_u8; HASH_LEN];
        hasher
            .finalize_variable(&mut out)
            .map_err(|_| QuicTransportError::Blake2)?;
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct QuicSniPolicy {
    allowed: Vec<String>,
}

impl QuicSniPolicy {
    pub fn new(allowed: Vec<String>) -> Self {
        Self { allowed }
    }

    pub fn validate(&self, sni: &str) -> Result<(), QuicTransportError> {
        if self
            .allowed
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(sni))
        {
            Ok(())
        } else {
            Err(QuicTransportError::SniNotAllowed)
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn salamander_round_trip() {
        let salamander = Salamander::new(b"shared-secret");
        let mut rng = StdRng::seed_from_u64(9);
        let packet = b"quic initial bytes";

        let obfuscated = salamander.obfuscate(packet, &mut rng).unwrap();
        assert_ne!(&obfuscated[SALT_LEN..], packet);
        assert_eq!(salamander.deobfuscate(&obfuscated).unwrap(), packet);
    }

    #[test]
    fn sni_policy_is_strict() {
        let policy = QuicSniPolicy::new(vec!["example.com".to_owned()]);
        assert!(policy.validate("EXAMPLE.com").is_ok());
        assert_eq!(
            policy.validate("blocked.example").unwrap_err(),
            QuicTransportError::SniNotAllowed
        );
    }
}
