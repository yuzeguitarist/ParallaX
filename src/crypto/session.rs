use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

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

pub fn x25519_public_from_private(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let private = StaticSecret::from(*private);
    PublicKey::from(&private).to_bytes()
}

pub fn x25519_shared_secret(private: &[u8; KEY_LEN], peer_public: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let private = StaticSecret::from(*private);
    let peer_public = PublicKey::from(*peer_public);
    let shared = private.diffie_hellman(&peer_public);
    *shared.as_bytes()
}

impl fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("private", &"<redacted>")
            .field("public", &self.public)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub client_key: [u8; KEY_LEN],
    pub server_key: [u8; KEY_LEN],
    pub client_nonce: [u8; NONCE_LEN],
    pub server_nonce: [u8; NONCE_LEN],
    pub chain_secret: [u8; KEY_LEN],
    pub epoch: u64,
    pub transcript_hash: [u8; KEY_LEN],
    pub x25519_shared_secret: [u8; KEY_LEN],
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("client_key", &"<redacted>")
            .field("server_key", &"<redacted>")
            .field("client_nonce", &"<redacted>")
            .field("server_nonce", &"<redacted>")
            .field("chain_secret", &"<redacted>")
            .field("epoch", &self.epoch)
            .field("transcript_hash", &self.transcript_hash)
            .field("x25519_shared_secret", &"<redacted>")
            .finish()
    }
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
    transcript_hash: &[u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    derive_keys(client_private, server_public, transcript_hash)
}

pub fn derive_server_keys(
    server_private: &[u8; KEY_LEN],
    client_public: &[u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    derive_keys(server_private, client_public, transcript_hash)
}

fn derive_keys(
    private: &[u8; KEY_LEN],
    peer_public: &[u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    let x25519_shared_secret = x25519_shared_secret(private, peer_public);
    let chain_secret = initial_chain_secret(&x25519_shared_secret, transcript_hash)?;
    expand_epoch_keys(chain_secret, 0, *transcript_hash, x25519_shared_secret)
}

pub fn expand_epoch_keys(
    chain_secret: [u8; KEY_LEN],
    epoch: u64,
    transcript_hash: [u8; KEY_LEN],
    x25519_shared_secret: [u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    let hk = Hkdf::<Sha256>::from_prk(&chain_secret).map_err(|_| SessionError::Hkdf)?;

    let mut out = SessionKeys {
        client_key: [0; KEY_LEN],
        server_key: [0; KEY_LEN],
        client_nonce: [0; NONCE_LEN],
        server_nonce: [0; NONCE_LEN],
        chain_secret,
        epoch,
        transcript_hash,
        x25519_shared_secret,
    };

    expand(
        &hk,
        b"client appdata key",
        epoch,
        &transcript_hash,
        &mut out.client_key,
    )?;
    expand(
        &hk,
        b"server appdata key",
        epoch,
        &transcript_hash,
        &mut out.server_key,
    )?;
    expand(
        &hk,
        b"client appdata nonce",
        epoch,
        &transcript_hash,
        &mut out.client_nonce,
    )?;
    expand(
        &hk,
        b"server appdata nonce",
        epoch,
        &transcript_hash,
        &mut out.server_nonce,
    )?;

    Ok(out)
}

fn initial_chain_secret(
    x25519_shared_secret: &[u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<[u8; KEY_LEN], SessionError> {
    let hk = Hkdf::<Sha256>::new(
        Some(b"ParallaX v1 initial x25519 chain"),
        x25519_shared_secret,
    );
    let mut chain_secret = [0_u8; KEY_LEN];
    expand(
        &hk,
        b"initial chain secret",
        0,
        transcript_hash,
        &mut chain_secret,
    )?;
    Ok(chain_secret)
}

fn expand(
    hk: &Hkdf<Sha256>,
    label: &[u8],
    epoch: u64,
    transcript_hash: &[u8; KEY_LEN],
    out: &mut [u8],
) -> Result<(), SessionError> {
    let epoch = epoch.to_be_bytes();
    let mut info = Vec::with_capacity(label.len() + epoch.len() + transcript_hash.len() + 2);
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(&epoch);
    info.push(0);
    info.extend_from_slice(transcript_hash);
    hk.expand(&info, out).map_err(|_| SessionError::Hkdf)
}

pub struct AeadCodec {
    cipher: XChaCha20Poly1305,
    nonce_base: [u8; NONCE_LEN],
    sequence: u64,
}

impl AeadCodec {
    pub fn new(key: [u8; KEY_LEN], nonce_base: [u8; NONCE_LEN]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new_from_slice(&key)
                .expect("XChaCha20-Poly1305 key length is fixed"),
            nonce_base,
            sequence: 0,
        }
    }

    pub fn rekey(&mut self, key: [u8; KEY_LEN], nonce_base: [u8; NONCE_LEN]) {
        self.cipher = XChaCha20Poly1305::new_from_slice(&key)
            .expect("XChaCha20-Poly1305 key length is fixed");
        self.nonce_base = nonce_base;
        self.sequence = 0;
    }

    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce = self.current_nonce();
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
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
                XNonce::from_slice(&nonce),
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
        let transcript_hash = [7_u8; 32];

        let client_keys =
            derive_client_keys(&client.private, &server.public, &transcript_hash).unwrap();
        let server_keys =
            derive_server_keys(&server.private, &client.public, &transcript_hash).unwrap();

        assert_eq!(client_keys, server_keys);
        assert_eq!(client_keys.epoch, 0);
        assert_eq!(client_keys.transcript_hash, transcript_hash);
    }

    #[test]
    fn x25519_shared_secret_matches_both_directions() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();

        assert_eq!(
            x25519_shared_secret(&client.private, &server.public),
            x25519_shared_secret(&server.private, &client.public)
        );
    }

    #[test]
    fn epoch_keys_change_when_epoch_changes() {
        let chain_secret = [1_u8; 32];
        let transcript_hash = [2_u8; 32];
        let x25519_shared_secret = [3_u8; 32];

        let epoch0 =
            expand_epoch_keys(chain_secret, 0, transcript_hash, x25519_shared_secret).unwrap();
        let epoch1 =
            expand_epoch_keys(chain_secret, 1, transcript_hash, x25519_shared_secret).unwrap();

        assert_ne!(epoch0.client_key, epoch1.client_key);
        assert_ne!(epoch0.client_nonce, epoch1.client_nonce);
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
