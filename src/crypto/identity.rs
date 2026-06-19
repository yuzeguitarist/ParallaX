use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::mldsa::{self, MlDsaError};

const IDENTITY_CONTEXT: &[u8] = b"ParallaX v2 ML-DSA-87 server identity";
const IDENTITY_MESSAGE_LABEL: &[u8] = b"ParallaX v2 server identity proof";
const PQ_REKEY_BINDING_LABEL: &[u8] = b"ParallaX v1 PQ rekey identity binding";

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

impl From<MlDsaError> for IdentityError {
    /// Exhaustively map the hand-rolled `crypto::mldsa` error surface onto the
    /// identity error surface. `ContextTooLong` cannot occur here — the only
    /// context this module signs/verifies under is the fixed 37-byte
    /// `IDENTITY_CONTEXT`, well within the FIPS 204 255-byte cap — but it is mapped
    /// explicitly (to `InvalidSignature`, the malformed-input bucket) so no variant
    /// is silently dropped if the upstream enum grows.
    fn from(e: MlDsaError) -> Self {
        match e {
            MlDsaError::InvalidPublicKeyLength => IdentityError::InvalidPublicKey,
            MlDsaError::InvalidSecretKeyLength => IdentityError::InvalidSecretKey,
            MlDsaError::InvalidSignatureLength => IdentityError::InvalidSignature,
            MlDsaError::ContextTooLong => IdentityError::InvalidSignature,
            MlDsaError::VerificationFailed => IdentityError::VerificationFailed,
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

pub fn keypair() -> MlDsaKeyPair {
    let (public, secret) = mldsa::keypair();
    MlDsaKeyPair { public, secret }
}

pub fn identity_message(
    transcript_hash: &[u8; 32],
    server_x25519_public_key: &[u8; 32],
    pq_rekey_binding: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        IDENTITY_MESSAGE_LABEL.len()
            + transcript_hash.len()
            + server_x25519_public_key.len()
            + pq_rekey_binding.len()
            + 8,
    );
    message.extend_from_slice(IDENTITY_MESSAGE_LABEL);
    message.extend_from_slice(&epoch.to_be_bytes());
    message.extend_from_slice(transcript_hash);
    message.extend_from_slice(server_x25519_public_key);
    message.extend_from_slice(pq_rekey_binding);
    message
}

pub fn pq_rekey_binding(client_pq_rekey_request: &[u8], server_key_exchange: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PQ_REKEY_BINDING_LABEL);
    hasher.update((client_pq_rekey_request.len() as u32).to_be_bytes());
    hasher.update(client_pq_rekey_request);
    hasher.update((server_key_exchange.len() as u32).to_be_bytes());
    hasher.update(server_key_exchange);
    hasher.finalize().into()
}

pub fn sign_server_identity(
    secret_key: &[u8],
    transcript_hash: &[u8; 32],
    server_x25519_public_key: &[u8; 32],
    pq_rekey_binding: &[u8; 32],
    epoch: u64,
) -> Result<Vec<u8>, IdentityError> {
    let message = identity_message(
        transcript_hash,
        server_x25519_public_key,
        pq_rekey_binding,
        epoch,
    );
    Ok(mldsa::sign(secret_key, &message, IDENTITY_CONTEXT)?)
}

pub fn verify_server_identity(
    public_key: &[u8],
    signature: &[u8],
    transcript_hash: &[u8; 32],
    server_x25519_public_key: &[u8; 32],
    pq_rekey_binding: &[u8; 32],
    epoch: u64,
) -> Result<(), IdentityError> {
    let message = identity_message(
        transcript_hash,
        server_x25519_public_key,
        pq_rekey_binding,
        epoch,
    );
    Ok(mldsa::verify(
        public_key,
        signature,
        &message,
        IDENTITY_CONTEXT,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa87_identity_signature_round_trip() {
        let keys = keypair();
        let transcript_hash = [7_u8; 32];
        let x25519 = [9_u8; 32];
        let binding = pq_rekey_binding(b"client pq", b"server kex");
        let signature =
            sign_server_identity(&keys.secret, &transcript_hash, &x25519, &binding, 0).unwrap();

        verify_server_identity(
            &keys.public,
            &signature,
            &transcript_hash,
            &x25519,
            &binding,
            0,
        )
        .unwrap();
        assert!(verify_server_identity(
            &keys.public,
            &signature,
            &[8_u8; 32],
            &x25519,
            &binding,
            0
        )
        .is_err());
    }

    #[test]
    fn mldsa87_identity_signature_binds_pq_rekey_exchange() {
        let keys = keypair();
        let transcript_hash = [7_u8; 32];
        let x25519 = [9_u8; 32];
        let first_binding = pq_rekey_binding(b"client pq request", b"server key exchange");
        let second_binding = pq_rekey_binding(b"other client pq request", b"server key exchange");
        let signature =
            sign_server_identity(&keys.secret, &transcript_hash, &x25519, &first_binding, 1)
                .unwrap();

        assert!(verify_server_identity(
            &keys.public,
            &signature,
            &transcript_hash,
            &x25519,
            &second_binding,
            1,
        )
        .is_err());
    }
}
