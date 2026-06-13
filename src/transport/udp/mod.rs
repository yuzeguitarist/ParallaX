//! UDP fast-plane transport (the "U" in TUDP).
//!
//! Phase 1 scaffolding. This module currently provides only the QUIC endpoint
//! building blocks for the masquerading HTTP/3 face on UDP, and a loopback test
//! that proves the plumbing: a QUIC connection, bidirectional unreliable
//! datagrams (RFC 9221), and RFC 5705 keying-material export (which the
//! exporter-bound UDP auth token in a later slice depends on).
//!
//! It is deliberately NOT wired into the client/server runtimes yet; the
//! `[udp]` config section defaults to disabled, so today this is dead weight at
//! runtime and a no-op for every existing code path. The `Leg` abstraction that
//! unifies this with the TCP carrier is extracted once both legs exist.

pub mod auth;
pub mod probe;

use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use thiserror::Error;

/// ALPN for the masquerading HTTP/3 face: the UDP leg presents itself as h3.
pub const UDP_ALPN: &[u8] = b"h3";

#[derive(Debug, Error)]
pub enum UdpTransportError {
    #[error("QUIC TLS configuration failed: {0}")]
    TlsConfig(String),
}

/// Build a quinn server config from a DER certificate leaf + private key.
///
/// TLS 1.3 only, aws-lc-rs provider (matching the rest of ParallaX), advertising
/// the h3 ALPN so the flow looks like an ordinary HTTP/3 server.
pub fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, UdpTransportError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|err| UdpTransportError::TlsConfig(err.to_string()))?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .map_err(|err| UdpTransportError::TlsConfig(err.to_string()))?;
    tls.alpn_protocols = vec![UDP_ALPN.to_vec()];

    let crypto = QuicServerConfig::try_from(Arc::new(tls))
        .map_err(|err| UdpTransportError::TlsConfig(err.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Build a quinn client config with a caller-supplied certificate verifier.
///
/// Like REALITY, the UDP leg does not derive its security from validating the
/// server certificate — the masquerade may legitimately borrow a real origin's
/// cert, and authenticity is instead established by the exporter-bound auth
/// token (a later slice). The verifier is therefore injected by the caller so
/// this module ships no built-in "accept anything" default in production code.
pub fn client_config(
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<quinn::ClientConfig, UdpTransportError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|err| UdpTransportError::TlsConfig(err.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    tls.alpn_protocols = vec![UDP_ALPN.to_vec()];

    let crypto = QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|err| UdpTransportError::TlsConfig(err.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use quinn::{Connection, Endpoint};
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    };

    use super::{client_config, server_config};

    /// Test-only verifier that accepts any certificate. Mirrors REALITY's posture
    /// (the cert is camouflage, not the trust anchor); real authenticity is the
    /// exporter-bound auth token.
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

    pub(crate) fn self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate self-signed cert");
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        (cert, key)
    }

    /// Establish a connected loopback QUIC client/server pair. Returns both
    /// endpoints (keep them alive for the connections' lifetime) and the two
    /// connection handles (client, server).
    pub(crate) async fn loopback_pair() -> (Endpoint, Endpoint, Connection, Connection) {
        let (cert, key) = self_signed_cert();
        let server_endpoint = Endpoint::server(
            server_config(cert, key).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint
            .set_default_client_config(client_config(Arc::new(AcceptAnyServerCert)).unwrap());

        let acceptor = {
            let server_endpoint = server_endpoint.clone();
            tokio::spawn(async move {
                server_endpoint
                    .accept()
                    .await
                    .expect("incoming connection")
                    .await
                    .expect("server-side connection")
            })
        };
        let client_conn = client_endpoint
            .connect(server_addr, "localhost")
            .expect("start connect")
            .await
            .expect("client-side connection");
        let server_conn = acceptor.await.expect("accept task");
        (server_endpoint, client_endpoint, client_conn, server_conn)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use quinn::Endpoint;

    use super::test_support::{self_signed_cert, AcceptAnyServerCert};
    use super::*;

    /// Non-empty PSK for the exporter-bound auth-token round-trip assertions.
    const TEST_PSK: &[u8] = b"parallax-tudp-loopback-psk-012345";

    /// Proves the QUIC fast-plane plumbing on loopback: connection establishment,
    /// bidirectional unreliable datagrams, and that the RFC 5705 keying-material
    /// exporter (open question #1 for the exporter-bound auth token) is available
    /// and agrees on both ends under the aws-lc-rs backend.
    #[tokio::test]
    async fn quic_loopback_datagram_and_exporter_round_trip() {
        let (cert, key) = self_signed_cert();
        let server_endpoint = Endpoint::server(
            server_config(cert, key).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint
            .set_default_client_config(client_config(Arc::new(AcceptAnyServerCert)).unwrap());

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("server-side connection");
            let datagram = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
                .await
                .expect("server datagram timeout")
                .expect("read client datagram");
            conn.send_datagram(datagram).expect("echo datagram");
            let mut ekm = [0_u8; 32];
            conn.export_keying_material(&mut ekm, b"tudp-loopback", b"context")
                .expect("server export_keying_material");
            let token = auth::export_udp_auth_token(&conn, TEST_PSK, b"offer-context")
                .expect("server auth token");
            // Hold the connection open long enough for the client to read the echo.
            tokio::time::sleep(Duration::from_millis(200)).await;
            (ekm, token)
        });

        let conn = client_endpoint
            .connect(server_addr, "localhost")
            .expect("start connect")
            .await
            .expect("client-side connection");

        conn.send_datagram(Bytes::from_static(b"ping"))
            .expect("client send datagram");
        let echo = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("client datagram timeout")
            .expect("read echoed datagram");
        assert_eq!(&echo[..], b"ping");

        let mut client_ekm = [0_u8; 32];
        conn.export_keying_material(&mut client_ekm, b"tudp-loopback", b"context")
            .expect("client export_keying_material");
        let client_token = auth::export_udp_auth_token(&conn, TEST_PSK, b"offer-context")
            .expect("client auth token");
        let other_context_token =
            auth::export_udp_auth_token(&conn, TEST_PSK, b"different-context")
                .expect("client auth token (other context)");

        let (server_ekm, server_token) = server_task.await.unwrap();
        assert_eq!(
            client_ekm, server_ekm,
            "RFC 5705 exporter output must match on both ends",
        );
        assert_eq!(
            client_token, server_token,
            "exporter-bound UDP auth token must match on both ends",
        );
        assert_ne!(
            client_token, other_context_token,
            "the exporter-bound auth token must be bound to its context",
        );
    }
}
