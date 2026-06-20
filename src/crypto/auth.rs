use std::time::{SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

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

pub fn build_masked_stateful_client_random(
    psk: &[u8],
    mask_ecdh: &[u8; 32],
    sni: &str,
    parallax_x25519_public: &[u8; 32],
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; 32], AuthError> {
    let mask_key = derive_mask_key(psk, mask_ecdh)?;
    let mask = stateful_client_random_mask(&mask_key, sni, tail)?;
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
    mask_ecdh: &[u8; 32],
    auth_key: &[u8],
    sni: &str,
    parallax_x25519_public: &[u8; 32],
    encoded_client_random: &[u8; 32],
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; SESSION_ID_LEN], AuthError> {
    let mask_key = derive_mask_key(psk, mask_ecdh)?;
    let encoded_tail = encode_stateful_auth_tail(&mask_key, sni, encoded_client_random, tail)?;
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
    mask_ecdh: &[u8; 32],
) -> Result<Option<StatefulAuthMaterial>, AuthError> {
    let parsed = parse_client_hello(record)?;
    recover_stateful_auth_material_from_parsed(record, psk, mask_ecdh, &parsed)
}

pub(crate) fn recover_stateful_auth_material_from_parsed(
    record: &[u8],
    psk: &[u8],
    mask_ecdh: &[u8; 32],
    parsed: &ClientHello,
) -> Result<Option<StatefulAuthMaterial>, AuthError> {
    if parsed.session_id_range.len() != SESSION_ID_LEN {
        return Ok(None);
    }
    let Some(sni) = parsed.sni.as_deref() else {
        return Ok(None);
    };
    let mask_key = derive_mask_key(psk, mask_ecdh)?;
    let mut encoded_tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
    encoded_tail.copy_from_slice(
        &record[parsed.session_id_range.start + AUTH_TAG_LEN..parsed.session_id_range.end],
    );
    Ok(Some(decode_stateful_auth_material(
        &mask_key,
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

pub(crate) fn verify_masked_stateful_client_hello_auth_with_material(
    record: &[u8],
    auth_key: &[u8],
    material: &StatefulAuthMaterial,
) -> Result<ClientAuth, AuthError> {
    let parsed = parse_client_hello(record)?;
    verify_masked_stateful_client_hello_auth_with_parsed_material(
        record, auth_key, material, &parsed,
    )
}

pub(crate) fn verify_masked_stateful_client_hello_auth_with_parsed_material(
    record: &[u8],
    auth_key: &[u8],
    material: &StatefulAuthMaterial,
    parsed: &ClientHello,
) -> Result<ClientAuth, AuthError> {
    if auth_key.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    if parsed.session_id_range.len() != SESSION_ID_LEN {
        return Ok(ClientAuth {
            authenticated: false,
            sni: parsed.sni.clone(),
            x25519_key_share: Some(material.x25519_public),
            timestamp: None,
            nonce: None,
        });
    }

    let Some(sni) = parsed.sni.as_deref() else {
        let (timestamp, nonce) = auth_tail_timestamp_nonce(&material.tail);
        return Ok(ClientAuth {
            authenticated: false,
            sni: parsed.sni.clone(),
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
        sni: parsed.sni.clone(),
        x25519_key_share: Some(material.x25519_public),
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

/// Derives the v4 carrier-mask key for the stateful ClientHello masks.
///
/// salt = psk, IKM = `mask_ecdh` = X25519(server_static, tls_ephemeral). Binding
/// the PSK as the HKDF salt (NOT the IKM) preserves the two-secret property: a
/// leaked server static private key ALONE does not reveal the masks, because the
/// HKDF-Extract PRK is unknown without the PSK — both secrets are required, just
/// as [`derive_auth_key_from_shared`] requires both for the auth tag. Do NOT
/// swap salt and IKM.
fn derive_mask_key(psk: &[u8], mask_ecdh: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, AuthError> {
    if psk.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let hk = Hkdf::<Sha256>::new(Some(psk), mask_ecdh);
    let mut out = Zeroizing::new([0_u8; 32]);
    hk.expand(b"ParallaX v4 ClientHello carrier mask key", out.as_mut())
        .map_err(|_| AuthError::Hkdf)?;
    Ok(out)
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
    mask_key: &[u8; 32],
    sni: &str,
    encoded_client_random: &[u8; 32],
    encoded_tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<StatefulAuthMaterial, AuthError> {
    let tail = decode_stateful_auth_tail(mask_key, sni, encoded_client_random, encoded_tail)?;
    let mask = stateful_client_random_mask(mask_key, sni, &tail)?;
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
    mask_key: &[u8; 32],
    sni: &str,
    encoded_client_random: &[u8; 32],
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; STATEFUL_AUTH_TAIL_LEN], AuthError> {
    let mask = stateful_auth_tail_mask(mask_key, sni, encoded_client_random)?;
    let mut encoded = [0_u8; STATEFUL_AUTH_TAIL_LEN];
    for (dst, (plain, mask)) in encoded.iter_mut().zip(tail.iter().zip(mask)) {
        *dst = plain ^ mask;
    }
    Ok(encoded)
}

fn decode_stateful_auth_tail(
    mask_key: &[u8; 32],
    sni: &str,
    encoded_client_random: &[u8; 32],
    encoded_tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; STATEFUL_AUTH_TAIL_LEN], AuthError> {
    let mask = stateful_auth_tail_mask(mask_key, sni, encoded_client_random)?;
    let mut tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
    for (dst, (encoded, mask)) in tail.iter_mut().zip(encoded_tail.iter().zip(mask)) {
        *dst = encoded ^ mask;
    }
    Ok(tail)
}

fn stateful_client_random_mask(
    mask_key: &[u8; 32],
    sni: &str,
    tail: &[u8; STATEFUL_AUTH_TAIL_LEN],
) -> Result<[u8; 32], AuthError> {
    stateful_mask(
        mask_key,
        b"ParallaX v4 ClientHello.random mask",
        sni,
        tail,
        &[],
    )
}

fn stateful_auth_tail_mask(
    mask_key: &[u8; 32],
    sni: &str,
    encoded_client_random: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    stateful_mask(
        mask_key,
        b"ParallaX v4 ClientHello session_id tail mask",
        sni,
        encoded_client_random,
        &[],
    )
}

/// Keystream for an XOR carrier mask.
///
/// v4: keyed by `mask_key` = HKDF(salt=psk, IKM=X25519(server_static,
/// tls_ephemeral)) — see [`derive_mask_key`] — NOT the raw PSK. A passive
/// observer who captures the ClientHello sees the unmasked TLS ephemeral key
/// share and at most the server's static public key, but recovering the shared
/// secret is the X25519 CDH problem, so the mask key (and therefore the masked
/// carrier) is pseudorandom to them. This closes the v3 offline PSK-guessing
/// oracle, where the mask was HMAC(raw psk, observable bytes).
fn stateful_mask(
    mask_key: &[u8; 32],
    label: &[u8],
    sni: &str,
    first: &[u8],
    second: &[u8],
) -> Result<[u8; 32], AuthError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(mask_key).expect("HMAC accepts any key length");
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
    use super::*;
    use crate::crypto::session::X25519KeyPair;
    use crate::tls::client_hello::tests::client_hello_fixture;

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
    fn wrong_mask_ecdh_cannot_recover_timestamp_oracle_closed() {
        // Finding #10 regression: the v3 masks were HMAC(raw psk, observable),
        // so a passive attacker could offline-guess the PSK by recomputing the
        // mask and checking the recovered tail's leading-timestamp redundancy.
        // v4 keys the mask on HKDF(psk, X25519(server_static, tls_ephemeral)); an
        // attacker without the server static key cannot derive the mask key, so
        // with ANY wrong mask_ecdh the recovered timestamp is not the real one and
        // the oracle yields no PSK signal.
        let mut hello = client_hello_fixture("example.com");
        let parsed = parse_client_hello(&hello).unwrap();
        let public = parsed.client_random;
        let psk = b"0123456789abcdef0123456789abcdef";
        let auth_key = psk;
        let real_mask_ecdh = [0x55_u8; 32];
        let mut tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
        tail[..AUTH_TIMESTAMP_LEN].copy_from_slice(&1_700_000_000_u64.to_be_bytes());
        tail[AUTH_TIMESTAMP_LEN..].copy_from_slice(&[7_u8; AUTH_NONCE_LEN]);
        let encoded_random = build_masked_stateful_client_random(
            psk,
            &real_mask_ecdh,
            "example.com",
            &public,
            &tail,
        )
        .unwrap();
        let session_id = build_masked_stateful_auth_session_id(
            psk,
            &real_mask_ecdh,
            auth_key,
            "example.com",
            &public,
            &encoded_random,
            &tail,
        )
        .unwrap();
        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        hello[random_offset..random_offset + 32].copy_from_slice(&encoded_random);
        hello[parsed.session_id_range.clone()].copy_from_slice(&session_id);

        for wrong in [[0_u8; 32], [0x11_u8; 32], [0xAB_u8; 32]] {
            let material = recover_stateful_auth_material(&hello, psk, &wrong)
                .unwrap()
                .unwrap();
            let recovered_ts =
                u64::from_be_bytes(material.tail[..AUTH_TIMESTAMP_LEN].try_into().unwrap());
            assert_ne!(
                recovered_ts, 1_700_000_000,
                "a wrong mask_ecdh must not recover the real timestamp"
            );
        }

        // The correct mask_ecdh still recovers it (sanity).
        let material = recover_stateful_auth_material(&hello, psk, &real_mask_ecdh)
            .unwrap()
            .unwrap();
        assert_eq!(
            u64::from_be_bytes(material.tail[..AUTH_TIMESTAMP_LEN].try_into().unwrap()),
            1_700_000_000
        );
    }

    #[test]
    fn verifies_masked_stateful_client_random_and_tail() {
        let mut hello = client_hello_fixture("example.com");
        let parsed = parse_client_hello(&hello).unwrap();
        let public = parsed.client_random;
        let psk = b"0123456789abcdef0123456789abcdef";
        let auth_key = psk;
        let mask_ecdh = [0x55_u8; 32];
        let mut tail = [0_u8; STATEFUL_AUTH_TAIL_LEN];
        tail[..AUTH_TIMESTAMP_LEN].copy_from_slice(&1234_u64.to_be_bytes());
        tail[AUTH_TIMESTAMP_LEN..].copy_from_slice(&[7_u8; AUTH_NONCE_LEN]);
        let encoded_random =
            build_masked_stateful_client_random(psk, &mask_ecdh, "example.com", &public, &tail)
                .unwrap();
        assert_ne!(encoded_random, public);
        let session_id = build_masked_stateful_auth_session_id(
            psk,
            &mask_ecdh,
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

        let material = recover_stateful_auth_material(&hello, psk, &mask_ecdh)
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
