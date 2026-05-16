use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

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
}

pub fn sign_client_hello_session_id<R>(
    record: &mut [u8],
    psk: &[u8],
    rng: &mut R,
) -> Result<[u8; AUTH_TAG_LEN], AuthError>
where
    R: RngCore + CryptoRng,
{
    if psk.is_empty() {
        return Err(AuthError::EmptyPsk);
    }

    let parsed = parse_client_hello(record)?;
    let range = parsed.session_id_range.clone();
    if range.len() != SESSION_ID_LEN {
        return Err(AuthError::InvalidSessionIdLen);
    }

    record[range.start..range.start + AUTH_TAG_LEN].fill(0);
    rng.fill_bytes(&mut record[range.start + AUTH_TAG_LEN..range.end]);

    let tag = compute_tag(record, parsed.record_len, &range, psk)?;
    record[range.start..range.start + AUTH_TAG_LEN].copy_from_slice(&tag);
    Ok(tag)
}

pub fn verify_client_hello_auth(record: &[u8], psk: &[u8]) -> Result<ClientAuth, AuthError> {
    if psk.is_empty() {
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
    let expected = compute_tag(record, parsed.record_len, &parsed.session_id_range, psk)?;
    let authenticated = actual.ct_eq(&expected).into();

    Ok(ClientAuth {
        authenticated,
        sni: parsed.sni,
        x25519_key_share: parsed.x25519_key_share,
    })
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
