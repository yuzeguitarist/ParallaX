use std::io;

use rand::{CryptoRng, RngCore};
use thiserror::Error;

use super::{
    client_hello::ClientHelloError,
    client_hello_builder::{ClientHelloBuildError, ClientHelloTemplate},
    server_hello::ServerHelloError,
};
use crate::crypto::auth::AuthError;

#[derive(Debug, Error)]
pub enum TlsBackendError {
    #[error("ClientHello build failed: {0}")]
    ClientHello(#[from] ClientHelloBuildError),
    #[error("ClientHello parse failed: {0}")]
    ClientHelloParse(#[from] ClientHelloError),
    #[error("ClientHello authentication failed: {0}")]
    Auth(#[from] AuthError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("rustls state machine error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("rustls config error: {0}")]
    RustlsConfig(String),
    #[error("invalid SNI for rustls ServerName: {0}")]
    InvalidServerName(String),
    #[error("ServerHello parse failed: {0}")]
    ServerHello(#[from] ServerHelloError),
    #[error("stateful TLS backend did not observe a TLS 1.3 ServerHello")]
    MissingServerHello,
    #[error("stateful TLS backend generated an unauthenticated ClientHello")]
    UnauthenticatedClientHello,
    #[error("stateful rustls hook was used outside a ParallaX handshake context")]
    MissingPatchContext,
}

pub trait CamouflageTlsBackend {
    fn client_hello<R>(
        &self,
        template: &ClientHelloTemplate,
        auth_key: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, TlsBackendError>
    where
        R: RngCore + CryptoRng;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NativeCamouflageBackend;

impl CamouflageTlsBackend for NativeCamouflageBackend {
    fn client_hello<R>(
        &self,
        template: &ClientHelloTemplate,
        auth_key: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, TlsBackendError>
    where
        R: RngCore + CryptoRng,
    {
        Ok(template.build_signed(auth_key, rng)?)
    }
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
        tls::client_hello_builder::BrowserProfile,
    };

    #[test]
    fn native_backend_builds_verifiable_client_hello() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let psk = b"0123456789abcdef0123456789abcdef";
        let client_auth = derive_client_auth_key(psk, &client.private, &server.public).unwrap();
        let server_auth = derive_server_auth_key(psk, &server.private, &client.public).unwrap();
        let mut rng = StdRng::seed_from_u64(77);
        let template = ClientHelloTemplate {
            sni: "example.com".to_owned(),
            x25519_public_key: client.public,
            profile: BrowserProfile::Chrome124,
        };

        let hello = NativeCamouflageBackend
            .client_hello(&template, &client_auth, &mut rng)
            .unwrap();

        assert!(
            verify_client_hello_auth(&hello, &server_auth)
                .unwrap()
                .authenticated
        );
    }
}
