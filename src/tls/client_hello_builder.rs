use rand::{CryptoRng, RngCore};
use thiserror::Error;

use crate::crypto::auth::{self, AuthError};

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const TLS12_LEGACY_VERSION: u16 = 0x0303;
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;

#[derive(Debug, Error)]
pub enum ClientHelloBuildError {
    #[error("SNI must not be empty")]
    EmptySni,
    #[error("SNI is too long")]
    SniTooLong,
    #[error("ClientHello authentication failed: {0}")]
    Auth(#[from] AuthError),
}

#[derive(Debug, Clone)]
pub struct ClientHelloTemplate {
    pub sni: String,
    pub x25519_public_key: [u8; 32],
}

impl ClientHelloTemplate {
    pub fn build_signed<R>(
        &self,
        auth_key: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, ClientHelloBuildError>
    where
        R: RngCore + CryptoRng,
    {
        let mut record = self.build_unsigned(rng)?;
        auth::sign_client_hello_session_id(&mut record, auth_key, rng)?;
        Ok(record)
    }

    pub fn build_unsigned<R>(&self, rng: &mut R) -> Result<Vec<u8>, ClientHelloBuildError>
    where
        R: RngCore + CryptoRng,
    {
        let sni = self.sni.as_bytes();
        if sni.is_empty() {
            return Err(ClientHelloBuildError::EmptySni);
        }
        if sni.len() > u16::MAX as usize {
            return Err(ClientHelloBuildError::SniTooLong);
        }

        let mut body = Vec::with_capacity(512);
        body.extend_from_slice(&TLS12_LEGACY_VERSION.to_be_bytes());
        push_random(&mut body, rng);
        body.push(32);
        body.extend_from_slice(&[0_u8; 32]);

        let cipher_suites = [
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ];
        body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
        for suite in cipher_suites {
            body.extend_from_slice(&suite.to_be_bytes());
        }

        body.push(1);
        body.push(0);

        let mut extensions = Vec::with_capacity(256);
        push_sni(&mut extensions, sni);
        push_supported_groups(&mut extensions);
        push_signature_algorithms(&mut extensions);
        push_alpn(&mut extensions);
        push_supported_versions(&mut extensions);
        push_psk_modes(&mut extensions);
        push_key_share(&mut extensions, &self.x25519_public_key);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::with_capacity(4 + body.len());
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        push_u24(&mut handshake, body.len() as u32);
        handshake.extend_from_slice(&body);

        let mut record = Vec::with_capacity(5 + handshake.len());
        record.push(super::record::TLS_CONTENT_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        Ok(record)
    }
}

fn push_random<R>(out: &mut Vec<u8>, rng: &mut R)
where
    R: RngCore + CryptoRng,
{
    let mut random = [0_u8; 32];
    rng.fill_bytes(&mut random);
    out.extend_from_slice(&random);
}

fn push_sni(out: &mut Vec<u8>, sni: &[u8]) {
    let mut data = Vec::with_capacity(5 + sni.len());
    data.extend_from_slice(&((1 + 2 + sni.len()) as u16).to_be_bytes());
    data.push(0);
    data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    data.extend_from_slice(sni);
    extension(out, EXT_SERVER_NAME, &data);
}

fn push_supported_groups(out: &mut Vec<u8>) {
    let groups = [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
    let mut data = Vec::with_capacity(2 + groups.len() * 2);
    data.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for group in groups {
        data.extend_from_slice(&group.to_be_bytes());
    }
    extension(out, EXT_SUPPORTED_GROUPS, &data);
}

fn push_signature_algorithms(out: &mut Vec<u8>) {
    let schemes = [
        0x0403_u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let mut data = Vec::with_capacity(2 + schemes.len() * 2);
    data.extend_from_slice(&((schemes.len() * 2) as u16).to_be_bytes());
    for scheme in schemes {
        data.extend_from_slice(&scheme.to_be_bytes());
    }
    extension(out, EXT_SIGNATURE_ALGORITHMS, &data);
}

fn push_alpn(out: &mut Vec<u8>) {
    let protocols: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let list_len: usize = protocols.iter().map(|p| p.len() + 1).sum();
    let mut data = Vec::with_capacity(2 + list_len);
    data.extend_from_slice(&(list_len as u16).to_be_bytes());
    for protocol in protocols {
        data.push(protocol.len() as u8);
        data.extend_from_slice(protocol);
    }
    extension(out, EXT_ALPN, &data);
}

fn push_supported_versions(out: &mut Vec<u8>) {
    extension(out, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
}

fn push_psk_modes(out: &mut Vec<u8>) {
    extension(out, EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1]);
}

fn push_key_share(out: &mut Vec<u8>, x25519_public_key: &[u8; 32]) {
    let mut share = Vec::with_capacity(4 + x25519_public_key.len());
    share.extend_from_slice(&GROUP_X25519.to_be_bytes());
    share.extend_from_slice(&(x25519_public_key.len() as u16).to_be_bytes());
    share.extend_from_slice(x25519_public_key);

    let mut data = Vec::with_capacity(2 + share.len());
    data.extend_from_slice(&(share.len() as u16).to_be_bytes());
    data.extend_from_slice(&share);
    extension(out, EXT_KEY_SHARE, &data);
}

fn extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

fn push_u24(out: &mut Vec<u8>, value: u32) {
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{
        crypto::{
            auth::{derive_client_auth_key, derive_server_auth_key, verify_client_hello_auth},
            session::X25519KeyPair,
        },
        tls::client_hello::parse_client_hello,
    };

    #[test]
    fn builds_signed_client_hello() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let psk = b"0123456789abcdef0123456789abcdef";
        let client_auth = derive_client_auth_key(psk, &client.private, &server.public).unwrap();
        let server_auth = derive_server_auth_key(psk, &server.private, &client.public).unwrap();
        let mut rng = StdRng::seed_from_u64(100);

        let record = ClientHelloTemplate {
            sni: "example.com".to_owned(),
            x25519_public_key: client.public,
        }
        .build_signed(&client_auth, &mut rng)
        .unwrap();
        let parsed = parse_client_hello(&record).unwrap();
        let verified = verify_client_hello_auth(&record, &server_auth).unwrap();

        assert_eq!(parsed.sni.as_deref(), Some("example.com"));
        assert_eq!(parsed.x25519_key_share, Some(client.public));
        assert!(parsed.tls13_supported);
        assert!(verified.authenticated);
    }
}
