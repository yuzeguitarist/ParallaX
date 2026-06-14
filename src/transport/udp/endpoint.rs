//! Production QUIC endpoint construction for the UDP fast plane.
//!
//! The server presents an ephemeral self-signed certificate; the client does not
//! validate it — authenticity is the exporter-bound auth token (REALITY-style),
//! so a self-signed cert is sufficient until a real masquerade cert / CDN front
//! is wired in a later slice. Not yet called by the runtime; the server-side
//! offer (PX1O) and the client-side connect/probe consume these next.

use std::{net::SocketAddr, sync::Arc};

use quinn::Endpoint;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};

use super::{client_config, server_config, UdpTransportError};

/// Certificate verifier that accepts any server certificate. The UDP leg does
/// not derive security from cert validation (REALITY-style: the cert is
/// camouflage); authenticity is the exporter-bound auth token. A wrong/forged
/// cert therefore changes nothing — only a peer holding the live TLS exporter +
/// PSK can pass the probe.
#[derive(Debug)]
pub(crate) struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Generate an ephemeral self-signed certificate for the UDP QUIC server.
pub fn ephemeral_self_signed(
    sni: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), UdpTransportError> {
    let certified = rcgen::generate_simple_self_signed(vec![sni.to_owned()])
        .map_err(|err| UdpTransportError::TlsConfig(err.to_string()))?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    Ok((cert, key))
}

/// Bind a UDP QUIC server endpoint presenting an ephemeral self-signed cert for
/// `sni`. The bound port is available via `endpoint.local_addr()`.
pub fn bind_server_endpoint(addr: SocketAddr, sni: &str) -> Result<Endpoint, UdpTransportError> {
    let (cert, key) = ephemeral_self_signed(sni)?;
    Ok(Endpoint::server(server_config(cert, key)?, addr)?)
}

/// Bind a UDP QUIC client endpoint using `verifier` for the server certificate.
pub fn bind_client_endpoint(
    addr: SocketAddr,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<Endpoint, UdpTransportError> {
    let mut endpoint = Endpoint::client(addr)?;
    endpoint.set_default_client_config(client_config(verifier)?);
    Ok(endpoint)
}

/// Bind a UDP QUIC client endpoint that accepts any server certificate
/// (authenticity is the exporter-bound auth token, not the cert).
pub fn bind_client_endpoint_accept_any(addr: SocketAddr) -> Result<Endpoint, UdpTransportError> {
    bind_client_endpoint(addr, Arc::new(AcceptAnyServerCert))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::udp::test_support::AcceptAnyServerCert;

    #[tokio::test]
    async fn loopback_endpoints_connect() {
        let server = bind_server_endpoint("127.0.0.1:0".parse().unwrap(), "localhost").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = bind_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(AcceptAnyServerCert),
        )
        .unwrap();

        let acceptor = tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });
        let conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let _server_conn = acceptor.await.unwrap();
        assert!(conn.close_reason().is_none());
    }
}
