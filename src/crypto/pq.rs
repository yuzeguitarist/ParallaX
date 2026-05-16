use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum PqError {
    #[error("invalid ML-KEM public key")]
    InvalidPublicKey,
    #[error("invalid ML-KEM secret key")]
    InvalidSecretKey,
    #[error("invalid ML-KEM ciphertext")]
    InvalidCiphertext,
    #[error("HKDF expansion failed")]
    Hkdf,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: [u8; 32],
}

pub fn keypair() -> MlKemKeyPair {
    let (public, secret) = mlkem768::keypair();
    MlKemKeyPair {
        public: public.as_bytes().to_vec(),
        secret: secret.as_bytes().to_vec(),
    }
}

pub fn encapsulate(public_key: &[u8]) -> Result<MlKemEncapsulation, PqError> {
    let public =
        mlkem768::PublicKey::from_bytes(public_key).map_err(|_| PqError::InvalidPublicKey)?;
    let (shared_secret, ciphertext) = mlkem768::encapsulate(&public);
    Ok(MlKemEncapsulation {
        ciphertext: ciphertext.as_bytes().to_vec(),
        shared_secret: shared_secret_32(shared_secret.as_bytes())?,
    })
}

pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32], PqError> {
    let ciphertext =
        mlkem768::Ciphertext::from_bytes(ciphertext).map_err(|_| PqError::InvalidCiphertext)?;
    let secret =
        mlkem768::SecretKey::from_bytes(secret_key).map_err(|_| PqError::InvalidSecretKey)?;
    let shared_secret = mlkem768::decapsulate(&ciphertext, &secret);
    shared_secret_32(shared_secret.as_bytes())
}

pub fn hybrid_rekey(
    old_key: &[u8; 32],
    old_nonce: &[u8; 12],
    pq_shared_secret: &[u8; 32],
    label: &[u8],
) -> Result<([u8; 32], [u8; 12]), PqError> {
    let hk = Hkdf::<Sha256>::new(Some(b"ParallaX v1 ML-KEM hybrid rekey"), pq_shared_secret);
    let mut key = [0_u8; 32];
    let mut nonce = [0_u8; 12];

    let mut key_info = Vec::with_capacity(label.len() + old_key.len() + 4);
    key_info.extend_from_slice(label);
    key_info.extend_from_slice(b" key");
    key_info.extend_from_slice(old_key);
    hk.expand(&key_info, &mut key).map_err(|_| PqError::Hkdf)?;

    let mut nonce_info = Vec::with_capacity(label.len() + old_nonce.len() + 6);
    nonce_info.extend_from_slice(label);
    nonce_info.extend_from_slice(b" nonce");
    nonce_info.extend_from_slice(old_nonce);
    hk.expand(&nonce_info, &mut nonce)
        .map_err(|_| PqError::Hkdf)?;

    Ok((key, nonce))
}

fn shared_secret_32(shared_secret: &[u8]) -> Result<[u8; 32], PqError> {
    if shared_secret.len() != 32 {
        return Err(PqError::InvalidCiphertext);
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(shared_secret);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_round_trip() {
        let keys = keypair();
        let enc = encapsulate(&keys.public).unwrap();
        let dec = decapsulate(&enc.ciphertext, &keys.secret).unwrap();
        assert_eq!(enc.shared_secret, dec);
    }

    #[test]
    fn hybrid_rekey_changes_key_material() {
        let (key, nonce) = hybrid_rekey(&[1; 32], &[2; 12], &[3; 32], b"C").unwrap();
        assert_ne!(key, [1; 32]);
        assert_ne!(nonce, [2; 12]);
    }
}
