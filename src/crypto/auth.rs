use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::tls::client_hello::{parse_client_hello, ClientHelloError};

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_ID_LEN: usize = 32;
pub const AUTH_TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuth {
    pub authenticated: bool,
    pub sni: Option<String>,
    pub x25519_key_share: Option<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("psk must not be empty")]
    EmptyPsk,
    #[error("client hello parse failed: {0}")]
    ClientHello(#[from] ClientHelloError),
    #[error("ClientHello session_id must be 32 bytes for ParallaX authentication")]
    InvalidSessionIdLen,
    #[error("ClientHello auth key derivation failed")]
    Hkdf,
}

pub fn sign_client_hello_session_id<R>(
    record: &mut [u8],
    auth_key: &[u8],
    rng: &mut R,
) -> Result<[u8; AUTH_TAG_LEN], AuthError>
where
    R: RngCore + CryptoRng,
{
    if auth_key.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let parsed = parse_client_hello(record)?;
    let range = parsed.session_id_range.clone();
    if range.len() != SESSION_ID_LEN {
        return Err(AuthError::InvalidSessionIdLen);
    }

    record[range.start..range.start + AUTH_TAG_LEN].fill(0);
    rng.fill_bytes(&mut record[range.start + AUTH_TAG_LEN..range.end]);

    let tag = compute_tag(record, parsed.record_len, &range, auth_key)?;
    record[range.start..range.start + AUTH_TAG_LEN].copy_from_slice(&tag);
    Ok(tag)
}

pub fn verify_client_hello_auth(record: &[u8], auth_key: &[u8]) -> Result<ClientAuth, AuthError> {
    if auth_key.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let parsed = parse_client_hello(record)?;
    if parsed.session_id_range.len() != SESSION_ID_LEN {
        return Ok(ClientAuth {
            authenticated: false,
            sni: parsed.sni,
            x25519_key_share: parsed.x25519_key_share,
        });
    }

    let actual =
        &record[parsed.session_id_range.start..parsed.session_id_range.start + AUTH_TAG_LEN];
    let expected = compute_tag(
        record,
        parsed.record_len,
        &parsed.session_id_range,
        auth_key,
    )?;
    let authenticated = actual.ct_eq(&expected).into();

    Ok(ClientAuth {
        authenticated,
        sni: parsed.sni,
        x25519_key_share: parsed.x25519_key_share,
    })
}

pub fn derive_client_auth_key(
    psk: &[u8],
    client_private: &[u8; 32],
    server_public: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    derive_auth_key(psk, client_private, server_public)
}

pub fn derive_server_auth_key(
    psk: &[u8],
    server_private: &[u8; 32],
    client_public: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    derive_auth_key(psk, server_private, client_public)
}

fn derive_auth_key(
    psk: &[u8],
    private: &[u8; 32],
    peer_public: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    if psk.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let private = StaticSecret::from(*private);
    let peer_public = PublicKey::from(*peer_public);
    let shared = private.diffie_hellman(&peer_public);
    let hk = Hkdf::<Sha256>::new(Some(psk), shared.as_bytes());
    let mut out = [0_u8; 32];
    hk.expand(b"ParallaX v1 ClientHello authentication", &mut out)
        .map_err(|_| AuthError::Hkdf)?;
    Ok(out)
}

fn compute_tag(
    record: &[u8],
    record_len: usize,
    session_id_range: &std::ops::Range<usize>,
    psk: &[u8],
) -> Result<[u8; AUTH_TAG_LEN], AuthError> {
    let mut signed = record[..record_len].to_vec();
    signed[session_id_range.start..session_id_range.start + AUTH_TAG_LEN].fill(0);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(psk).map_err(|_| AuthError::EmptyPsk)?;
    mac.update(&signed[crate::tls::record::TLS_HEADER_LEN..record_len]);
    let digest = mac.finalize().into_bytes();

    let mut tag = [0_u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&digest[..AUTH_TAG_LEN]);
    Ok(tag)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::crypto::session::X25519KeyPair;
    use crate::tls::client_hello::tests::client_hello_fixture;

    #[test]
    fn signs_and_verifies_client_hello_session_id() {
        let mut hello = client_hello_fixture("example.com");
        let mut rng = StdRng::seed_from_u64(7);
        let psk = b"0123456789abcdef0123456789abcdef";

        sign_client_hello_session_id(&mut hello, psk, &mut rng).unwrap();
        let auth = verify_client_hello_auth(&hello, psk).unwrap();

        assert!(auth.authenticated);
        assert_eq!(auth.sni.as_deref(), Some("example.com"));
        assert!(auth.x25519_key_share.is_some());
    }

    #[test]
    fn derives_same_ecdh_bound_auth_key() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let psk = b"0123456789abcdef0123456789abcdef";

        let client_key = derive_client_auth_key(psk, &client.private, &server.public).unwrap();
        let server_key = derive_server_auth_key(psk, &server.private, &client.public).unwrap();

        assert_eq!(client_key, server_key);
    }

    #[test]
    fn rejects_modified_client_hello() {
        let mut hello = client_hello_fixture("example.com");
        let mut rng = StdRng::seed_from_u64(7);
        let psk = b"0123456789abcdef0123456789abcdef";

        sign_client_hello_session_id(&mut hello, psk, &mut rng).unwrap();
        let last = hello.len() - 1;
        hello[last] ^= 0x55;

        let auth = verify_client_hello_auth(&hello, psk).unwrap();
        assert!(!auth.authenticated);
    }
}
