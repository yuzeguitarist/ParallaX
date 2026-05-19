use std::time::{SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::tls::client_hello::{parse_client_hello, ClientHello, ClientHelloError};

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_ID_LEN: usize = 32;
pub const AUTH_TAG_LEN: usize = 16;
pub const STATEFUL_AUTH_TAIL_LEN: usize = SESSION_ID_LEN - AUTH_TAG_LEN;
pub const AUTH_TIMESTAMP_LEN: usize = 8;
pub const AUTH_NONCE_LEN: usize = STATEFUL_AUTH_TAIL_LEN - AUTH_TIMESTAMP_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuth {
    pub authenticated: bool,
    pub sni: Option<String>,
    /// ParallaX ephemeral X25519 public key recovered from the authenticated
    /// ClientHello carrier.
    pub x25519_key_share: Option<[u8; 32]>,
    pub timestamp: Option<u64>,
    pub nonce: Option<[u8; AUTH_NONCE_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatefulAuthMaterial {
    pub x25519_public: [u8; 32],
    pub tail: [u8; STATEFUL_AUTH_TAIL_LEN],
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
    #[error("system clock is before UNIX epoch")]
    Clock,
}

pub fn sign_client_hello_session_id<R>(
    record: &mut [u8],
    auth_key: &[u8],
    rng: &mut R,
) -> Result<[u8; AUTH_TAG_LEN], AuthError>
where
    R: RngCore + CryptoRng,
{
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Clock)?
        .as_secs();
    sign_client_hello_session_id_at(record, auth_key, timestamp, rng)
}

pub fn sign_client_hello_session_id_at<R>(
    record: &mut [u8],
    auth_key: &[u8],
    timestamp: u64,
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
    let tail = build_auth_tail_at(timestamp, rng);
    record[range.start + AUTH_TAG_LEN..range.end].copy_from_slice(&tail);

    let tag = compute_tag(record, parsed.record_len, &range, auth_key)?;
    record[range.start..range.start + AUTH_TAG_LEN].copy_from_slice(&tag);
    Ok(tag)
}

pub fn build_stateful_auth_session_id(
    auth_key: &[u8],
    sni: &str,
    parallax_x25519_public: &[u8; 32],
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; SESSION_ID_LEN], AuthError> {
    let tag = compute_stateful_tag(auth_key, sni, parallax_x25519_public, tail)?;
    let mut session_id = [0_u8; SESSION_ID_LEN];
    session_id[..AUTH_TAG_LEN].copy_from_slice(&tag);
    session_id[AUTH_TAG_LEN..].copy_from_slice(tail);
    Ok(session_id)
}

pub fn build_masked_stateful_client_random(
    psk: &[u8],
    sni: &str,
    parallax_x25519_public: &[u8; 32],
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; 32], AuthError> {
    let mask = stateful_client_random_mask(psk, sni, tail)?;
    let mut encoded = [0_u8; 32];
    for (dst, (public, mask)) in encoded
        .iter_mut()
        .zip(parallax_x25519_public.iter().zip(mask))
    {
        *dst = public ^ mask;
    }
    Ok(encoded)
}

pub fn build_masked_stateful_auth_session_id(
    psk: &[u8],
    auth_key: &[u8],
    sni: &str,
    parallax_x25519_public: &[u8; 32],
    encoded_client_random: &[u8; 32],
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; SESSION_ID_LEN], AuthError> {
    let encoded_tail = encode_stateful_auth_tail(psk, sni, encoded_client_random, tail)?;
    let tag = compute_masked_stateful_tag(
        auth_key,
        sni,
        parallax_x25519_public,
        tail,
        encoded_client_random,
        &encoded_tail,
    )?;
    let mut session_id = [0_u8; SESSION_ID_LEN];
    session_id[..AUTH_TAG_LEN].copy_from_slice(&tag);
    session_id[AUTH_TAG_LEN..].copy_from_slice(&encoded_tail);
    Ok(session_id)
}

pub fn recover_stateful_auth_material(
    record: &[u8],
    psk: &[u8],
) -> Result<Option<StatefulAuthMaterial>, AuthError> {
    let parsed = parse_client_hello(record)?;
    recover_stateful_auth_material_from_parsed(record, psk, &parsed)
}

pub(crate) fn recover_stateful_auth_material_from_parsed(
    record: &[u8],
    psk: &[u8],
    parsed: &ClientHello,
) -> Result<Option<StatefulAuthMaterial>, AuthError> {
    if parsed.session_id_range.len() != SESSION_ID_LEN {
        return Ok(None);
    }
    let Some(sni) = parsed.sni.as_deref() else {
        return Ok(None);
    };
    let mut encoded_tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
    encoded_tail.copy_from_slice(
        &record[parsed.session_id_range.start + AUTH_TAG_LEN..parsed.session_id_range.end],
    );
    Ok(Some(decode_stateful_auth_material(
        psk,
        sni,
        &parsed.client_random,
        &encoded_tail,
    )?))
}

pub fn build_auth_tail<R>(rng: &mut R) -> Result<[u8; STATEFUL_AUTH_TAIL_LEN], AuthError>
where
    R: RngCore + CryptoRng,
{
    let timestamp = current_unix_timestamp()?;
    Ok(build_auth_tail_at(timestamp, rng))
}

pub fn build_auth_tail_at<R>(timestamp: u64, rng: &mut R) -> [u8; STATEFUL_AUTH_TAIL_LEN]
where
    R: RngCore + CryptoRng,
{
    let mut tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
    tail[..AUTH_TIMESTAMP_LEN].copy_from_slice(&timestamp.to_be_bytes());
    rng.fill_bytes(&mut tail[AUTH_TIMESTAMP_LEN..]);
    tail
}

pub fn verify_client_hello_auth(record: &[u8], auth_key: &[u8]) -> Result<ClientAuth, AuthError> {
    let parsed = parse_client_hello(record)?;
    verify_client_hello_auth_with_parsed(record, auth_key, None, parsed)
}

pub(crate) fn verify_masked_stateful_client_hello_auth_with_material(
    record: &[u8],
    auth_key: &[u8],
    material: &StatefulAuthMaterial,
) -> Result<ClientAuth, AuthError> {
    if auth_key.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let parsed = parse_client_hello(record)?;
    if parsed.session_id_range.len() != SESSION_ID_LEN {
        return Ok(ClientAuth {
            authenticated: false,
            sni: parsed.sni,
            x25519_key_share: Some(material.x25519_public),
            timestamp: None,
            nonce: None,
        });
    }

    let Some(sni) = parsed.sni.as_deref() else {
        let (timestamp, nonce) = auth_tail_timestamp_nonce(&material.tail);
        return Ok(ClientAuth {
            authenticated: false,
            sni: parsed.sni,
            x25519_key_share: Some(material.x25519_public),
            timestamp: Some(timestamp),
            nonce: Some(nonce),
        });
    };

    let actual =
        &record[parsed.session_id_range.start..parsed.session_id_range.start + AUTH_TAG_LEN];
    let mut encoded_tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
    encoded_tail.copy_from_slice(
        &record[parsed.session_id_range.start + AUTH_TAG_LEN..parsed.session_id_range.end],
    );
    let expected = compute_masked_stateful_tag(
        auth_key,
        sni,
        &material.x25519_public,
        &material.tail,
        &parsed.client_random,
        &encoded_tail,
    )?;
    let authenticated = bool::from(actual.ct_eq(&expected));
    let (timestamp, nonce) = auth_tail_timestamp_nonce(&material.tail);

    Ok(ClientAuth {
        authenticated,
        sni: parsed.sni,
        x25519_key_share: Some(material.x25519_public),
        timestamp: Some(timestamp),
        nonce: Some(nonce),
    })
}

pub fn verify_client_hello_auth_with_material(
    record: &[u8],
    auth_key: &[u8],
    material: Option<StatefulAuthMaterial>,
) -> Result<ClientAuth, AuthError> {
    let parsed = parse_client_hello(record)?;
    verify_client_hello_auth_with_parsed(record, auth_key, material, parsed)
}

pub(crate) fn verify_client_hello_auth_with_parsed(
    record: &[u8],
    auth_key: &[u8],
    material: Option<StatefulAuthMaterial>,
    parsed: ClientHello,
) -> Result<ClientAuth, AuthError> {
    if auth_key.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    if parsed.session_id_range.len() != SESSION_ID_LEN {
        return Ok(ClientAuth {
            authenticated: false,
            sni: parsed.sni,
            x25519_key_share: material
                .as_ref()
                .map(|material| material.x25519_public)
                .or(Some(parsed.client_random)),
            timestamp: None,
            nonce: None,
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
    let transcript_authenticated: bool = actual.ct_eq(&expected).into();
    let stateful_authenticated = match parsed.sni.as_deref() {
        Some(sni) => {
            let mut encoded_tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
            encoded_tail.copy_from_slice(
                &record[parsed.session_id_range.start + AUTH_TAG_LEN..parsed.session_id_range.end],
            );
            let expected = match material.as_ref() {
                Some(material) => compute_masked_stateful_tag(
                    auth_key,
                    sni,
                    &material.x25519_public,
                    &material.tail,
                    &parsed.client_random,
                    &encoded_tail,
                )?,
                None => compute_stateful_tag(auth_key, sni, &parsed.client_random, &encoded_tail)?,
            };
            bool::from(actual.ct_eq(&expected))
        }
        None => false,
    };
    let timestamp_start = parsed.session_id_range.start + AUTH_TAG_LEN;
    let mut tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
    if let Some(material) = material.as_ref() {
        tail.copy_from_slice(&material.tail);
    } else {
        tail.copy_from_slice(&record[timestamp_start..parsed.session_id_range.end]);
    }
    let (timestamp, nonce) = auth_tail_timestamp_nonce(&tail);

    Ok(ClientAuth {
        authenticated: transcript_authenticated || stateful_authenticated,
        sni: parsed.sni,
        x25519_key_share: material
            .as_ref()
            .map(|material| material.x25519_public)
            .or(Some(parsed.client_random)),
        timestamp: Some(timestamp),
        nonce: Some(nonce),
    })
}

fn auth_tail_timestamp_nonce(tail: &[u8; STATEFUL_AUTH_TAIL_LEN]) -> (u64, [u8; AUTH_NONCE_LEN]) {
    let timestamp = u64::from_be_bytes(
        tail[..AUTH_TIMESTAMP_LEN]
            .try_into()
            .expect("timestamp range is fixed"),
    );
    let mut nonce = [0_u8; AUTH_NONCE_LEN];
    nonce.copy_from_slice(&tail[AUTH_TIMESTAMP_LEN..]);
    (timestamp, nonce)
}

fn current_unix_timestamp() -> Result<u64, AuthError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Clock)?
        .as_secs())
}

pub fn derive_client_auth_key(
    psk: &[u8],
    client_private: &[u8; 32],
    server_public: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    derive_auth_key(psk, client_private, server_public)
}

pub fn derive_client_auth_key_from_shared(
    psk: &[u8],
    x25519_shared_secret: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    derive_auth_key_from_shared(psk, x25519_shared_secret)
}

pub fn derive_server_auth_key_from_shared(
    psk: &[u8],
    x25519_shared_secret: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    derive_auth_key_from_shared(psk, x25519_shared_secret)
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
    derive_auth_key_from_shared(psk, shared.as_bytes())
}

fn derive_auth_key_from_shared(
    psk: &[u8],
    x25519_shared_secret: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    if psk.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let hk = Hkdf::<Sha256>::new(Some(psk), x25519_shared_secret);
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
    let mut mac = <HmacSha256 as Mac>::new_from_slice(psk).map_err(|_| AuthError::EmptyPsk)?;
    mac.update(b"ParallaX v2 transcript ClientHello auth");
    mac.update(&record[crate::tls::record::TLS_HEADER_LEN..session_id_range.start]);
    mac.update(&[0_u8; AUTH_TAG_LEN]);
    mac.update(&record[session_id_range.start + AUTH_TAG_LEN..record_len]);
    let digest = mac.finalize().into_bytes();

    let mut tag = [0_u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&digest[..AUTH_TAG_LEN]);
    Ok(tag)
}

fn compute_stateful_tag(
    auth_key: &[u8],
    sni: &str,
    parallax_x25519_public: &[u8; 32],
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; AUTH_TAG_LEN], AuthError> {
    if auth_key.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let mut mac = <HmacSha256 as Mac>::new_from_slice(auth_key).map_err(|_| AuthError::EmptyPsk)?;
    mac.update(b"ParallaX v2 stateful rustls ClientHello auth");
    mac.update(&(sni.len() as u16).to_be_bytes());
    mac.update(sni.as_bytes());
    // v2 binds the ParallaX ephemeral X25519 public key carried in ClientHello.random.
    mac.update(parallax_x25519_public);
    mac.update(tail);
    let digest = mac.finalize().into_bytes();

    let mut tag = [0_u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&digest[..AUTH_TAG_LEN]);
    Ok(tag)
}

fn compute_masked_stateful_tag(
    auth_key: &[u8],
    sni: &str,
    parallax_x25519_public: &[u8; 32],
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
    encoded_client_random: &[u8; 32],
    encoded_tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; AUTH_TAG_LEN], AuthError> {
    if auth_key.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let mut mac = <HmacSha256 as Mac>::new_from_slice(auth_key).map_err(|_| AuthError::EmptyPsk)?;
    mac.update(b"ParallaX v3 masked stateful rustls ClientHello auth");
    mac.update(&(sni.len() as u16).to_be_bytes());
    mac.update(sni.as_bytes());
    mac.update(parallax_x25519_public);
    mac.update(tail);
    mac.update(encoded_client_random);
    mac.update(encoded_tail);
    let digest = mac.finalize().into_bytes();

    let mut tag = [0_u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&digest[..AUTH_TAG_LEN]);
    Ok(tag)
}

fn decode_stateful_auth_material(
    psk: &[u8],
    sni: &str,
    encoded_client_random: &[u8; 32],
    encoded_tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<StatefulAuthMaterial, AuthError> {
    let tail = decode_stateful_auth_tail(psk, sni, encoded_client_random, encoded_tail)?;
    let mask = stateful_client_random_mask(psk, sni, &tail)?;
    let mut x25519_public = [0_u8; 32];
    for (dst, (encoded, mask)) in x25519_public
        .iter_mut()
        .zip(encoded_client_random.iter().zip(mask))
    {
        *dst = encoded ^ mask;
    }
    Ok(StatefulAuthMaterial {
        x25519_public,
        tail,
    })
}

fn encode_stateful_auth_tail(
    psk: &[u8],
    sni: &str,
    encoded_client_random: &[u8; 32],
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; STATEFUL_AUTH_TAIL_LEN], AuthError> {
    let mask = stateful_auth_tail_mask(psk, sni, encoded_client_random)?;
    let mut encoded = [0_u8; STATEFUL_AUTH_TAIL_LEN];
    for (dst, (plain, mask)) in encoded.iter_mut().zip(tail.iter().zip(mask)) {
        *dst = plain ^ mask;
    }
    Ok(encoded)
}

fn decode_stateful_auth_tail(
    psk: &[u8],
    sni: &str,
    encoded_client_random: &[u8; 32],
    encoded_tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; STATEFUL_AUTH_TAIL_LEN], AuthError> {
    let mask = stateful_auth_tail_mask(psk, sni, encoded_client_random)?;
    let mut tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
    for (dst, (encoded, mask)) in tail.iter_mut().zip(encoded_tail.iter().zip(mask)) {
        *dst = encoded ^ mask;
    }
    Ok(tail)
}

fn stateful_client_random_mask(
    psk: &[u8],
    sni: &str,
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; 32], AuthError> {
    stateful_mask(psk, b"ParallaX v3 ClientHello.random mask", sni, tail, &[])
}

fn stateful_auth_tail_mask(
    psk: &[u8],
    sni: &str,
    encoded_client_random: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    stateful_mask(
        psk,
        b"ParallaX v3 ClientHello session_id tail mask",
        sni,
        encoded_client_random,
        &[],
    )
}

fn stateful_mask(
    psk: &[u8],
    label: &[u8],
    sni: &str,
    first: &[u8],
    second: &[u8],
) -> Result<[u8; 32], AuthError> {
    if psk.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let mut mac = <HmacSha256 as Mac>::new_from_slice(psk).map_err(|_| AuthError::EmptyPsk)?;
    mac.update(label);
    mac.update(&(sni.len() as u16).to_be_bytes());
    mac.update(sni.as_bytes());
    mac.update(&(first.len() as u16).to_be_bytes());
    mac.update(first);
    mac.update(&(second.len() as u16).to_be_bytes());
    mac.update(second);
    Ok(mac.finalize().into_bytes().into())
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
        assert!(auth.timestamp.is_some());
        assert!(auth.nonce.is_some());
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
    fn derives_same_client_auth_key_from_cached_shared_secret() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let psk = b"0123456789abcdef0123456789abcdef";
        let shared = crate::crypto::session::x25519_shared_secret(&client.private, &server.public);

        let from_private = derive_client_auth_key(psk, &client.private, &server.public).unwrap();
        let from_shared = derive_client_auth_key_from_shared(psk, &shared).unwrap();

        assert_eq!(from_private, from_shared);
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

    #[test]
    fn rejects_modified_stateful_client_random() {
        let mut hello = client_hello_fixture("example.com");
        let parsed = parse_client_hello(&hello).unwrap();
        let parallax_public = parsed.client_random;
        let tail = [9_u8; STATEFUL_AUTH_TAIL_LEN];
        let psk = b"0123456789abcdef0123456789abcdef";
        let session_id =
            build_stateful_auth_session_id(psk, "example.com", &parallax_public, &tail).unwrap();
        hello[parsed.session_id_range].copy_from_slice(&session_id);

        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        hello[random_offset] ^= 0x55;

        let auth = verify_client_hello_auth(&hello, psk).unwrap();
        assert!(!auth.authenticated);
    }

    #[test]
    fn verifies_stateful_rustls_session_id_auth() {
        let mut hello = client_hello_fixture("example.com");
        let parsed = parse_client_hello(&hello).unwrap();
        let key_share = parsed.client_random;
        let tail = [9_u8; STATEFUL_AUTH_TAIL_LEN];
        let psk = b"0123456789abcdef0123456789abcdef";
        let session_id =
            build_stateful_auth_session_id(psk, "example.com", &key_share, &tail).unwrap();
        hello[parsed.session_id_range].copy_from_slice(&session_id);

        let auth = verify_client_hello_auth(&hello, psk).unwrap();

        assert!(auth.authenticated);
        assert_eq!(auth.sni.as_deref(), Some("example.com"));
        assert_eq!(auth.x25519_key_share, Some(key_share));
    }

    #[test]
    fn verifies_masked_stateful_client_random_and_tail() {
        let mut hello = client_hello_fixture("example.com");
        let parsed = parse_client_hello(&hello).unwrap();
        let public = parsed.client_random;
        let psk = b"0123456789abcdef0123456789abcdef";
        let auth_key = psk;
        let mut tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
        tail[..AUTH_TIMESTAMP_LEN].copy_from_slice(&1234_u64.to_be_bytes());
        tail[AUTH_TIMESTAMP_LEN..].copy_from_slice(&[7_u8; AUTH_NONCE_LEN]);
        let encoded_random =
            build_masked_stateful_client_random(psk, "example.com", &public, &tail).unwrap();
        assert_ne!(encoded_random, public);
        let session_id = build_masked_stateful_auth_session_id(
            psk,
            auth_key,
            "example.com",
            &public,
            &encoded_random,
            &tail,
        )
        .unwrap();
        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        hello[random_offset..random_offset + 32].copy_from_slice(&encoded_random);
        hello[parsed.session_id_range].copy_from_slice(&session_id);

        let material = recover_stateful_auth_material(&hello, psk)
            .unwrap()
            .unwrap();
        let auth =
            verify_client_hello_auth_with_material(&hello, auth_key, Some(material)).unwrap();

        assert!(auth.authenticated);
        assert_eq!(auth.x25519_key_share, Some(public));
        assert_eq!(auth.timestamp, Some(1234));
        assert_eq!(auth.nonce, Some([7_u8; AUTH_NONCE_LEN]));
    }

    #[test]
    fn verifies_masked_stateful_auth_without_transcript_fallback_work() {
        let mut hello = client_hello_fixture("example.com");
        let parsed = parse_client_hello(&hello).unwrap();
        let public = parsed.client_random;
        let psk = b"0123456789abcdef0123456789abcdef";
        let auth_key = psk;
        let mut tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
        tail[..AUTH_TIMESTAMP_LEN].copy_from_slice(&1234_u64.to_be_bytes());
        tail[AUTH_TIMESTAMP_LEN..].copy_from_slice(&[7_u8; AUTH_NONCE_LEN]);
        let encoded_random =
            build_masked_stateful_client_random(psk, "example.com", &public, &tail).unwrap();
        let session_id = build_masked_stateful_auth_session_id(
            psk,
            auth_key,
            "example.com",
            &public,
            &encoded_random,
            &tail,
        )
        .unwrap();
        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        hello[random_offset..random_offset + 32].copy_from_slice(&encoded_random);
        hello[parsed.session_id_range].copy_from_slice(&session_id);
        let material = recover_stateful_auth_material(&hello, psk)
            .unwrap()
            .unwrap();

        let auth =
            verify_masked_stateful_client_hello_auth_with_material(&hello, auth_key, &material)
                .unwrap();

        assert!(auth.authenticated);
        assert_eq!(auth.x25519_key_share, Some(public));
        assert_eq!(auth.timestamp, Some(1234));
        assert_eq!(auth.nonce, Some([7_u8; AUTH_NONCE_LEN]));
    }
}
