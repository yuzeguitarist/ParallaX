use std::fmt;

use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit, Payload},
    Tag, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const AEAD_TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

const RECORD_RATCHET_INIT_LABEL: &[u8] = b"ParallaX v2 record ratchet init";
const RECORD_RATCHET_KEY_LABEL: &[u8] = b"ParallaX v2 record ratchet key";
const RECORD_RATCHET_NONCE_LABEL: &[u8] = b"ParallaX v2 record ratchet nonce";
const RECORD_RATCHET_ADVANCE_LABEL: &[u8] = b"ParallaX v2 record ratchet advance";
const HKDF_INFO_STACK_LEN: usize = 128;

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
    let info_len = 2 + label.len() + 8 + 2 + transcript_hash.len();
    if info_len <= HKDF_INFO_STACK_LEN {
        let mut info = [0_u8; HKDF_INFO_STACK_LEN];
        let used = write_epoch_hkdf_info(&mut info, label, epoch, transcript_hash);
        hk.expand(&info[..used], out)
            .map_err(|_| SessionError::Hkdf)
    } else {
        let epoch = epoch.to_be_bytes();
        let mut info = Vec::with_capacity(info_len);
        info.extend_from_slice(&(label.len() as u16).to_be_bytes());
        info.extend_from_slice(label);
        info.extend_from_slice(&epoch);
        info.extend_from_slice(&(transcript_hash.len() as u16).to_be_bytes());
        info.extend_from_slice(transcript_hash);
        hk.expand(&info, out).map_err(|_| SessionError::Hkdf)
    }
}

fn write_epoch_hkdf_info(
    out: &mut [u8; HKDF_INFO_STACK_LEN],
    label: &[u8],
    epoch: u64,
    transcript_hash: &[u8; KEY_LEN],
) -> usize {
    let mut offset = 0;
    write_bytes(out, &mut offset, &(label.len() as u16).to_be_bytes());
    write_bytes(out, &mut offset, label);
    write_bytes(out, &mut offset, &epoch.to_be_bytes());
    write_bytes(
        out,
        &mut offset,
        &(transcript_hash.len() as u16).to_be_bytes(),
    );
    write_bytes(out, &mut offset, transcript_hash);
    offset
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadCodec {
    root_secret: [u8; KEY_LEN],
    sequence: u64,
}

impl AeadCodec {
    pub fn new(key: [u8; KEY_LEN], nonce_base: [u8; NONCE_LEN]) -> Self {
        Self {
            root_secret: initial_record_root(&key, &nonce_base),
            sequence: 0,
        }
    }

    pub fn rekey(&mut self, key: [u8; KEY_LEN], nonce_base: [u8; NONCE_LEN]) {
        self.root_secret = initial_record_root(&key, &nonce_base);
        self.sequence = 0;
    }

    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SessionError> {
        let mut ciphertext = Vec::with_capacity(plaintext.len() + AEAD_TAG_LEN);
        ciphertext.extend_from_slice(plaintext);
        let tag = self.seal_in_place_detached(&mut ciphertext, aad)?;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    pub fn seal_in_place_detached(
        &mut self,
        plaintext: &mut [u8],
        aad: &[u8],
    ) -> Result<[u8; AEAD_TAG_LEN], SessionError> {
        self.ensure_can_process_next_record()?;
        let material = self.derive_record_material(aad)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&material.key)
            .expect("XChaCha20-Poly1305 key length is fixed");
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&material.nonce), aad, plaintext)
            .map_err(|_| SessionError::Aead)?;

        let mut out = [0_u8; AEAD_TAG_LEN];
        out.copy_from_slice(tag.as_slice());
        self.advance_record_ratchet(aad, plaintext, &out)?;
        Ok(out)
    }

    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SessionError> {
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(SessionError::Aead);
        }
        self.ensure_can_process_next_record()?;
        let material = self.derive_record_material(aad)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&material.key)
            .expect("XChaCha20-Poly1305 key length is fixed");
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&material.nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| SessionError::Aead)?;
        let tag_start = ciphertext.len() - AEAD_TAG_LEN;
        self.advance_record_ratchet(aad, &ciphertext[..tag_start], &ciphertext[tag_start..])?;
        Ok(plaintext)
    }

    pub fn open_in_place(
        &mut self,
        ciphertext_with_tag: &mut Vec<u8>,
        aad: &[u8],
    ) -> Result<(), SessionError> {
        if ciphertext_with_tag.len() < AEAD_TAG_LEN {
            return Err(SessionError::Aead);
        }

        let tag_start = ciphertext_with_tag.len() - AEAD_TAG_LEN;
        let (ciphertext_without_tag, tag) = ciphertext_with_tag.split_at_mut(tag_start);
        self.open_in_place_detached(ciphertext_without_tag, tag, aad)?;
        ciphertext_with_tag.truncate(tag_start);
        Ok(())
    }

    pub(crate) fn open_in_place_detached(
        &mut self,
        ciphertext_without_tag: &mut [u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<(), SessionError> {
        if tag.len() != AEAD_TAG_LEN {
            return Err(SessionError::Aead);
        }
        self.ensure_can_process_next_record()?;
        let material = self.derive_record_material(aad)?;
        let next_root = self.next_record_root(aad, ciphertext_without_tag, tag)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&material.key)
            .expect("XChaCha20-Poly1305 key length is fixed");
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&material.nonce),
                aad,
                ciphertext_without_tag,
                Tag::from_slice(tag),
            )
            .map_err(|_| SessionError::Aead)?;
        self.root_secret = next_root;
        self.sequence += 1;
        Ok(())
    }

    fn ensure_can_process_next_record(&self) -> Result<(), SessionError> {
        if self.sequence == u64::MAX {
            return Err(SessionError::NonceExhausted);
        }
        Ok(())
    }

    fn derive_record_material(&self, aad: &[u8]) -> Result<RecordMaterial, SessionError> {
        let hk = Hkdf::<Sha256>::from_prk(&self.root_secret).map_err(|_| SessionError::Hkdf)?;
        let mut material = RecordMaterial {
            key: [0; KEY_LEN],
            nonce: [0; NONCE_LEN],
        };
        expand_record_secret(
            &hk,
            RECORD_RATCHET_KEY_LABEL,
            self.sequence,
            aad,
            &mut material.key,
        )?;
        expand_record_secret(
            &hk,
            RECORD_RATCHET_NONCE_LABEL,
            self.sequence,
            aad,
            &mut material.nonce,
        )?;
        Ok(material)
    }

    fn advance_record_ratchet(
        &mut self,
        aad: &[u8],
        ciphertext_without_tag: &[u8],
        tag: &[u8],
    ) -> Result<(), SessionError> {
        self.root_secret = self.next_record_root(aad, ciphertext_without_tag, tag)?;
        self.sequence += 1;
        Ok(())
    }

    fn next_record_root(
        &self,
        aad: &[u8],
        ciphertext_without_tag: &[u8],
        tag: &[u8],
    ) -> Result<[u8; KEY_LEN], SessionError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.root_secret)
            .map_err(|_| SessionError::Hkdf)?;
        mac.update(RECORD_RATCHET_ADVANCE_LABEL);
        mac.update(&self.sequence.to_be_bytes());
        mac.update(&(aad.len() as u64).to_be_bytes());
        mac.update(aad);
        mac.update(&(ciphertext_without_tag.len() as u64).to_be_bytes());
        mac.update(ciphertext_without_tag);
        mac.update(tag);
        let digest = mac.finalize().into_bytes();
        let mut next_root = [0_u8; KEY_LEN];
        next_root.copy_from_slice(&digest[..KEY_LEN]);
        Ok(next_root)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct RecordMaterial {
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
}

fn initial_record_root(key: &[u8; KEY_LEN], nonce_base: &[u8; NONCE_LEN]) -> [u8; KEY_LEN] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key length is unrestricted");
    mac.update(RECORD_RATCHET_INIT_LABEL);
    mac.update(nonce_base);
    let digest = mac.finalize().into_bytes();
    let mut out = [0_u8; KEY_LEN];
    out.copy_from_slice(&digest[..KEY_LEN]);
    out
}

fn expand_record_secret(
    hk: &Hkdf<Sha256>,
    label: &[u8],
    sequence: u64,
    aad: &[u8],
    out: &mut [u8],
) -> Result<(), SessionError> {
    let info_len = 2 + label.len() + 8 + 8 + aad.len();
    if info_len <= HKDF_INFO_STACK_LEN {
        let mut info = [0_u8; HKDF_INFO_STACK_LEN];
        let used = write_record_hkdf_info(&mut info, label, sequence, aad);
        hk.expand(&info[..used], out)
            .map_err(|_| SessionError::Hkdf)
    } else {
        let mut info = Vec::with_capacity(info_len);
        info.extend_from_slice(&(label.len() as u16).to_be_bytes());
        info.extend_from_slice(label);
        info.extend_from_slice(&sequence.to_be_bytes());
        info.extend_from_slice(&(aad.len() as u64).to_be_bytes());
        info.extend_from_slice(aad);
        hk.expand(&info, out).map_err(|_| SessionError::Hkdf)
    }
}

fn write_record_hkdf_info(
    out: &mut [u8; HKDF_INFO_STACK_LEN],
    label: &[u8],
    sequence: u64,
    aad: &[u8],
) -> usize {
    let mut offset = 0;
    write_bytes(out, &mut offset, &(label.len() as u16).to_be_bytes());
    write_bytes(out, &mut offset, label);
    write_bytes(out, &mut offset, &sequence.to_be_bytes());
    write_bytes(out, &mut offset, &(aad.len() as u64).to_be_bytes());
    write_bytes(out, &mut offset, aad);
    offset
}

fn write_bytes(out: &mut [u8; HKDF_INFO_STACK_LEN], offset: &mut usize, bytes: &[u8]) {
    let end = *offset + bytes.len();
    out[*offset..end].copy_from_slice(bytes);
    *offset = end;
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
    fn hkdf_info_uses_length_prefixes() {
        let hk = Hkdf::<Sha256>::new(None, b"test secret");
        let transcript_hash = [2_u8; 32];
        let mut with_nul = [0_u8; 32];
        let mut without_nul = [0_u8; 32];

        expand(&hk, b"label\0suffix", 1, &transcript_hash, &mut with_nul).unwrap();
        expand(&hk, b"label", 1, &transcript_hash, &mut without_nul).unwrap();

        assert_ne!(with_nul, without_nul);
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

    #[test]
    fn aead_opens_in_place() {
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut enc = AeadCodec::new(key, nonce);
        let mut dec = AeadCodec::new(key, nonce);

        let mut ciphertext = enc.seal(b"payload", b"tls-appdata").unwrap();
        dec.open_in_place(&mut ciphertext, b"tls-appdata").unwrap();

        assert_eq!(ciphertext, b"payload");
    }

    #[test]
    fn aead_ratchet_rejects_replayed_record_after_success() {
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut enc = AeadCodec::new(key, nonce);
        let mut dec = AeadCodec::new(key, nonce);

        let first = enc.seal(b"same payload", b"tls-appdata").unwrap();
        let second = enc.seal(b"same payload", b"tls-appdata").unwrap();

        assert_eq!(dec.open(&first, b"tls-appdata").unwrap(), b"same payload");
        assert!(matches!(
            dec.open(&first, b"tls-appdata"),
            Err(SessionError::Aead)
        ));
        assert_eq!(dec.open(&second, b"tls-appdata").unwrap(), b"same payload");
    }

    #[test]
    fn aead_ratchet_changes_ciphertext_for_repeated_plaintext() {
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut enc = AeadCodec::new(key, nonce);

        let first = enc.seal(b"same payload", b"tls-appdata").unwrap();
        let second = enc.seal(b"same payload", b"tls-appdata").unwrap();

        assert_ne!(first, second);
    }
}
