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
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

use super::{client_config, server_config, UdpTransportError};

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
