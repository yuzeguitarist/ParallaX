//! Production QUIC endpoint construction for the UDP fast plane.
//!
//! The server presents an ephemeral self-signed certificate; the client does not
//! validate it — authenticity is the exporter-bound auth token (REALITY-style),
//! so a self-signed cert is sufficient until a real masquerade cert / CDN front
//! is wired in a later slice. The server-side offer (PX1O) and the client-side
//! connect/probe consume these, and on a Verified probe the same connection
//! carries the single-Connect data relay over a reliable bidi stream.

use std::{net::SocketAddr, sync::Arc};

use quinn::{ConnectionIdGenerator, Endpoint, EndpointConfig};
use quinn_proto::RandomConnectionIdGenerator;
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

/// Build the [`EndpointConfig`] for the UDP-leg QUIC **client**.
///
/// The one deviation from `EndpointConfig::default()` is the connection-id
/// generator: the client uses a ZERO-LENGTH source connection id. Safari-26 H3
/// emits `initial_source_connection_id` (0x39 TP 0x0f) with length 0 (confirmed
/// by full disassembly), and RFC 9000 §7.3 requires that transport parameter to
/// equal the Source Connection ID in the client's first Initial packet header.
/// Setting `cid_len = 0` here makes quinn use the empty CID for BOTH the packet
/// header AND `initial_source_connection_id` (quinn derives the TP from the same
/// `loc_cid`), so the advertised value always equals the actual wire SCID — no
/// advertised-vs-actual gap, and the hand-encoded 0x39 blob in `safari_crypto.rs`
/// reads the zero-length 0x0f straight back from quinn's own `params.write()`.
///
/// `RandomConnectionIdGenerator::new(0)` yields an empty CID; quinn-proto handles
/// the zero-length local CID explicitly (`new_cid`/`issue_first_cids`/
/// `cids_exhausted` all special-case `cid_len == 0`), so the client simply never
/// issues alternate CIDs — which is exactly the zero-length-CID endpoint posture.
///
/// TRADEOFF — no NAT-rebinding survival. With a zero-length local SCID the server
/// can only index this connection by the UDP 4-tuple (there is no client CID to
/// route on), so if the client's NAT remaps its source port mid-connection the
/// server cannot re-associate the datagrams and the connection drops. This is a
/// deliberate Safari-faithful choice: Safari-26 itself emits a zero-length SCID,
/// and ParallaX's UDP leg is a short-lived single-Connect relay, so the exposure
/// window is small and a rebind simply surfaces as the existing clean
/// connection-reset failure mode (the caller re-probes / falls back).
fn client_endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.cid_generator(|| -> Box<dyn ConnectionIdGenerator> {
        Box::new(RandomConnectionIdGenerator::new(0))
    });
    config
}

/// Bind a UDP QUIC client endpoint using the zero-length-SCID
/// [`client_endpoint_config`] (Safari fidelity; see that fn).
///
/// `quinn::Endpoint::client` hardcodes `EndpointConfig::default()` (an 8-byte
/// CID), so the endpoint is built via `Endpoint::new` with a plain bound
/// `std::net::UdpSocket`. The production caller already selects the bind address
/// family to match the peer (`0.0.0.0:0` vs `[::]:0`), so the dual-stack socket
/// option `Endpoint::client` sets is not needed here.
pub fn bind_client_endpoint(
    addr: SocketAddr,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<Endpoint, UdpTransportError> {
    let socket = std::net::UdpSocket::bind(addr)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| UdpTransportError::TlsConfig("no async runtime for QUIC endpoint".into()))?;
    let mut endpoint = Endpoint::new(client_endpoint_config(), None, socket, runtime)?;
    endpoint.set_default_client_config(client_config(verifier)?);
    Ok(endpoint)
}

/// Bind a UDP QUIC client endpoint that accepts any server certificate
/// (authenticity is the exporter-bound auth token, not the cert).
///
/// FOOTGUN — this disables TLS certificate validation entirely. It is sound ONLY
/// on the UDP leg, whose trust derives from the exporter-bound auth token
/// ([`AcceptAnyServerCert`]), NOT from the cert. It is crate-public solely so the
/// production probe path (`client::runtime`) and the `gfw_simulator` integration
/// test crate can build the same endpoint; it is `#[doc(hidden)]` to keep it out
/// of the public API surface. NEVER wire this into a path whose security depends
/// on certificate validation.
#[doc(hidden)]
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
