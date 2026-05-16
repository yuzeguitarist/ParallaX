use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as SignPublicKey,
    SecretKey as SignSecretKey,
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const IDENTITY_CONTEXT: &[u8] = b"ParallaX v1 ML-DSA-87 server identity";
const IDENTITY_MESSAGE_LABEL: &[u8] = b"ParallaX v1 server identity proof";

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid ML-DSA-87 public key")]
    InvalidPublicKey,
    #[error("invalid ML-DSA-87 secret key")]
    InvalidSecretKey,
    #[error("invalid ML-DSA-87 signature")]
    InvalidSignature,
    #[error("ML-DSA-87 signature verification failed")]
    VerificationFailed,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

pub fn keypair() -> MlDsaKeyPair {
    let (public, secret) = mldsa87::keypair();
    MlDsaKeyPair {
        public: public.as_bytes().to_vec(),
        secret: secret.as_bytes().to_vec(),
    }
}

pub fn identity_message(
    transcript_hash: &[u8; 32],
    server_x25519_public_key: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        IDENTITY_MESSAGE_LABEL.len() + transcript_hash.len() + server_x25519_public_key.len() + 8,
    );
    message.extend_from_slice(IDENTITY_MESSAGE_LABEL);
    message.extend_from_slice(&epoch.to_be_bytes());
    message.extend_from_slice(transcript_hash);
    message.extend_from_slice(server_x25519_public_key);
    message
}

pub fn sign_server_identity(
    secret_key: &[u8],
    transcript_hash: &[u8; 32],
    server_x25519_public_key: &[u8; 32],
    epoch: u64,
) -> Result<Vec<u8>, IdentityError> {
    let secret =
        mldsa87::SecretKey::from_bytes(secret_key).map_err(|_| IdentityError::InvalidSecretKey)?;
    let message = identity_message(transcript_hash, server_x25519_public_key, epoch);
    let signature = mldsa87::detached_sign_ctx(&message, IDENTITY_CONTEXT, &secret);
    Ok(signature.as_bytes().to_vec())
}

pub fn verify_server_identity(
    public_key: &[u8],
    signature: &[u8],
    transcript_hash: &[u8; 32],
    server_x25519_public_key: &[u8; 32],
    epoch: u64,
) -> Result<(), IdentityError> {
    let public =
        mldsa87::PublicKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidPublicKey)?;
    let signature = mldsa87::DetachedSignature::from_bytes(signature)
        .map_err(|_| IdentityError::InvalidSignature)?;
    let message = identity_message(transcript_hash, server_x25519_public_key, epoch);
    mldsa87::verify_detached_signature_ctx(&signature, &message, IDENTITY_CONTEXT, &public)
        .map_err(|_| IdentityError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa87_identity_signature_round_trip() {
        let keys = keypair();
        let transcript_hash = [7_u8; 32];
        let x25519 = [9_u8; 32];
        let signature = sign_server_identity(&keys.secret, &transcript_hash, &x25519, 0).unwrap();

        verify_server_identity(&keys.public, &signature, &transcript_hash, &x25519, 0).unwrap();
        assert!(verify_server_identity(&keys.public, &signature, &[8_u8; 32], &x25519, 0).is_err());
    }
}
