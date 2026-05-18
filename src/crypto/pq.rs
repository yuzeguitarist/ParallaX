use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const HYBRID_REKEY_IKM_FIXED_LEN: usize = 7 + 32 + 11 + 32 + 5 + 4;
const HYBRID_REKEY_IKM_STACK_LEN: usize = 128;

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
    let (public, secret) = mlkem1024::keypair();
    MlKemKeyPair {
        public: public.as_bytes().to_vec(),
        secret: secret.as_bytes().to_vec(),
    }
}

pub fn encapsulate(public_key: &[u8]) -> Result<MlKemEncapsulation, PqError> {
    let public =
        mlkem1024::PublicKey::from_bytes(public_key).map_err(|_| PqError::InvalidPublicKey)?;
    let (shared_secret, ciphertext) = mlkem1024::encapsulate(&public);
    Ok(MlKemEncapsulation {
        ciphertext: ciphertext.as_bytes().to_vec(),
        shared_secret: shared_secret_32(shared_secret.as_bytes())?,
    })
}

pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32], PqError> {
    let ciphertext =
        mlkem1024::Ciphertext::from_bytes(ciphertext).map_err(|_| PqError::InvalidCiphertext)?;
    let secret =
        mlkem1024::SecretKey::from_bytes(secret_key).map_err(|_| PqError::InvalidSecretKey)?;
    let shared_secret = mlkem1024::decapsulate(&ciphertext, &secret);
    shared_secret_32(shared_secret.as_bytes())
}

pub fn hybrid_rekey(
    old_chain_secret: &[u8; 32],
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
) -> Result<[u8; 32], PqError> {
    hybrid_sandwich_rekey(
        old_chain_secret,
        x25519_shared_secret,
        pq_shared_secret,
        &[],
    )
}

pub fn hybrid_sandwich_rekey(
    old_chain_secret: &[u8; 32],
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
    symmetric_secret: &[u8],
) -> Result<[u8; 32], PqError> {
    let mut chain_secret = [0_u8; 32];
    let ikm_len = HYBRID_REKEY_IKM_FIXED_LEN + symmetric_secret.len();
    if ikm_len <= HYBRID_REKEY_IKM_STACK_LEN {
        let mut ikm = [0_u8; HYBRID_REKEY_IKM_STACK_LEN];
        let used = write_hybrid_rekey_ikm(
            &mut ikm,
            x25519_shared_secret,
            pq_shared_secret,
            symmetric_secret,
        );
        let (prk, _) = Hkdf::<Sha256>::extract(Some(old_chain_secret), &ikm[..used]);
        chain_secret.copy_from_slice(&prk);
        ikm[..used].zeroize();
    } else {
        let mut ikm = Vec::with_capacity(ikm_len);
        write_hybrid_rekey_ikm_vec(
            &mut ikm,
            x25519_shared_secret,
            pq_shared_secret,
            symmetric_secret,
        );
        let (prk, _) = Hkdf::<Sha256>::extract(Some(old_chain_secret), &ikm);
        chain_secret.copy_from_slice(&prk);
        ikm.zeroize();
    }
    Ok(chain_secret)
}
fn write_hybrid_rekey_ikm(
    out: &mut [u8; HYBRID_REKEY_IKM_STACK_LEN],
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
    symmetric_secret: &[u8],
) -> usize {
    let mut offset = 0;
    write_ikm_bytes(out, &mut offset, b"x25519:");
    write_ikm_bytes(out, &mut offset, x25519_shared_secret);
    write_ikm_bytes(out, &mut offset, b"|mlkem1024:");
    write_ikm_bytes(out, &mut offset, pq_shared_secret);
    write_ikm_bytes(out, &mut offset, b"|psk:");
    write_ikm_bytes(
        out,
        &mut offset,
        &(symmetric_secret.len() as u32).to_be_bytes(),
    );
    write_ikm_bytes(out, &mut offset, symmetric_secret);
    offset
}

fn write_ikm_bytes(out: &mut [u8; HYBRID_REKEY_IKM_STACK_LEN], offset: &mut usize, bytes: &[u8]) {
    let end = *offset + bytes.len();
    out[*offset..end].copy_from_slice(bytes);
    *offset = end;
}

fn write_hybrid_rekey_ikm_vec(
    out: &mut Vec<u8>,
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
    symmetric_secret: &[u8],
) {
    out.extend_from_slice(b"x25519:");
    out.extend_from_slice(x25519_shared_secret);
    out.extend_from_slice(b"|mlkem1024:");
    out.extend_from_slice(pq_shared_secret);
    out.extend_from_slice(b"|psk:");
    out.extend_from_slice(&(symmetric_secret.len() as u32).to_be_bytes());
    out.extend_from_slice(symmetric_secret);
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
        assert_eq!(keys.public.len(), mlkem1024::public_key_bytes());
        assert_eq!(keys.secret.len(), mlkem1024::secret_key_bytes());
        assert_eq!(enc.ciphertext.len(), mlkem1024::ciphertext_bytes());
    }

    #[test]
    fn hybrid_rekey_changes_key_material() {
        let chain_secret = hybrid_rekey(&[1; 32], &[2; 32], &[3; 32]).unwrap();
        assert_ne!(chain_secret, [1; 32]);
    }

    #[test]
    fn hybrid_rekey_binds_old_chain_x25519_and_mlkem_secrets() {
        let baseline = hybrid_rekey(&[1; 32], &[2; 32], &[3; 32]).unwrap();
        assert_ne!(
            baseline,
            hybrid_rekey(&[9; 32], &[2; 32], &[3; 32]).unwrap()
        );
        assert_ne!(
            baseline,
            hybrid_rekey(&[1; 32], &[9; 32], &[3; 32]).unwrap()
        );
        assert_ne!(
            baseline,
            hybrid_rekey(&[1; 32], &[2; 32], &[9; 32]).unwrap()
        );
    }

    #[test]
    fn hybrid_sandwich_rekey_binds_symmetric_secret() {
        let baseline = hybrid_sandwich_rekey(&[1; 32], &[2; 32], &[3; 32], b"psk-a").unwrap();
        assert_ne!(
            baseline,
            hybrid_sandwich_rekey(&[1; 32], &[2; 32], &[3; 32], b"psk-b").unwrap()
        );
        assert_ne!(
            baseline,
            hybrid_rekey(&[1; 32], &[2; 32], &[3; 32]).unwrap()
        );
    }
}
