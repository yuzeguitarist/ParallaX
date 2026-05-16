use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519KeyPair {
    pub private: [u8; KEY_LEN],
    pub public: [u8; KEY_LEN],
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        Self {
            private: private.to_bytes(),
            public: public.to_bytes(),
        }
    }
}

impl fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("private", &"<redacted>")
            .field("public", &self.public)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    pub client_key: [u8; KEY_LEN],
    pub server_key: [u8; KEY_LEN],
    pub client_nonce: [u8; NONCE_LEN],
    pub server_nonce: [u8; NONCE_LEN],
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("HKDF expansion failed")]
    Hkdf,
    #[error("AEAD operation failed")]
    Aead,
    #[error("AEAD nonce sequence exhausted")]
    NonceExhausted,
}

pub fn derive_client_keys(
    client_private: &[u8; KEY_LEN],
    server_public: &[u8; KEY_LEN],
    context: &[u8],
) -> Result<SessionKeys, SessionError> {
    derive_keys(client_private, server_public, context)
}

pub fn derive_server_keys(
    server_private: &[u8; KEY_LEN],
    client_public: &[u8; KEY_LEN],
    context: &[u8],
) -> Result<SessionKeys, SessionError> {
    derive_keys(server_private, client_public, context)
}

fn derive_keys(
    private: &[u8; KEY_LEN],
    peer_public: &[u8; KEY_LEN],
    context: &[u8],
) -> Result<SessionKeys, SessionError> {
    let private = StaticSecret::from(*private);
    let peer_public = PublicKey::from(*peer_public);
    let shared = private.diffie_hellman(&peer_public);
    let hk = Hkdf::<Sha256>::new(Some(b"ParallaX v1 x25519"), shared.as_bytes());

    let mut out = SessionKeys {
        client_key: [0; KEY_LEN],
        server_key: [0; KEY_LEN],
        client_nonce: [0; NONCE_LEN],
        server_nonce: [0; NONCE_LEN],
    };

    expand(&hk, b"client appdata key", context, &mut out.client_key)?;
    expand(&hk, b"server appdata key", context, &mut out.server_key)?;
    expand(&hk, b"client appdata nonce", context, &mut out.client_nonce)?;
    expand(&hk, b"server appdata nonce", context, &mut out.server_nonce)?;

    Ok(out)
}

fn expand(
    hk: &Hkdf<Sha256>,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), SessionError> {
    let mut info = Vec::with_capacity(label.len() + context.len() + 1);
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(context);
    hk.expand(&info, out).map_err(|_| SessionError::Hkdf)
}

pub struct AeadCodec {
    cipher: ChaCha20Poly1305,
    nonce_base: [u8; NONCE_LEN],
    sequence: u64,
}

impl AeadCodec {
    pub fn new(key: [u8; KEY_LEN], nonce_base: [u8; NONCE_LEN]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(&key)
                .expect("ChaCha20-Poly1305 key length is fixed"),
            nonce_base,
            sequence: 0,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce = self.current_nonce();
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| SessionError::Aead)?;
        self.advance_nonce()?;
        Ok(ciphertext)
    }

    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce = self.current_nonce();
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| SessionError::Aead)?;
        self.advance_nonce()?;
        Ok(plaintext)
    }

    fn current_nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = self.nonce_base;
        let seq = self.sequence.to_be_bytes();
        for (dst, src) in nonce[NONCE_LEN - 8..].iter_mut().zip(seq) {
            *dst ^= src;
        }
        nonce
    }

    fn advance_nonce(&mut self) -> Result<(), SessionError> {
        if self.sequence == u64::MAX {
            return Err(SessionError::NonceExhausted);
        }
        self.sequence += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_derives_same_session_keys() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let context = b"clienthello || serverhello";

        let client_keys = derive_client_keys(&client.private, &server.public, context).unwrap();
        let server_keys = derive_server_keys(&server.private, &client.public, context).unwrap();

        assert_eq!(client_keys, server_keys);
    }

    #[test]
    fn aead_round_trip_and_tamper_reject() {
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut enc = AeadCodec::new(key, nonce);
        let mut dec = AeadCodec::new(key, nonce);

        let mut ciphertext = enc.seal(b"payload", b"tls-appdata").unwrap();
        assert_eq!(dec.open(&ciphertext, b"tls-appdata").unwrap(), b"payload");

        let mut enc = AeadCodec::new(key, nonce);
        let mut dec = AeadCodec::new(key, nonce);
        ciphertext = enc.seal(b"payload", b"tls-appdata").unwrap();
        ciphertext[0] ^= 1;
        assert!(matches!(
            dec.open(&ciphertext, b"tls-appdata"),
            Err(SessionError::Aead)
        ));
    }
}
