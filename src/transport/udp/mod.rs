//! UDP fast-plane transport (the "U" in TUDP).
//!
//! Provides the QUIC endpoint building blocks for the masquerading HTTP/3 face on
//! UDP: a QUIC connection, bidirectional unreliable datagrams (RFC 9221) used by
//! the reachability probe, and RFC 5705 keying-material export backing the
//! exporter-bound UDP auth token.
//!
//! Wired into the client/server runtimes for the single-Connect data relay: when
//! `[udp].enabled` is set on both ends and the client's probe is Verified, the
//! relay is carried over a reliable bidi QUIC stream through the `Leg`
//! abstraction (which unifies it with the TCP carrier). With `enabled = false`
//! (the default) this is a no-op for every existing code path and the relay stays
//! byte-identical on TCP. Mux and speed-test paths remain on TCP.

pub mod auth;
pub mod endpoint;
pub(crate) mod envelope;
pub mod probe;
pub(crate) mod reorder;

/// Fuzz-only re-exports of the internal TUDP wire parsers. Compiled ONLY under
/// `--cfg fuzzing` (which cargo-fuzz sets); absent from normal `cargo build` /
/// `cargo test` / CI. Returns std types so the external fuzz crate needs no
/// access to the pub(crate) envelope types.
#[cfg(fuzzing)]
#[allow(clippy::result_unit_err)]
pub mod fuzz {
    use std::ops::Range;

    /// Decode one envelope prefix → (seq, record byte-range within `input`, bytes consumed).
    pub fn decode_envelope_prefix(input: &[u8]) -> Result<(u64, Range<usize>, usize), ()> {
        super::envelope::decode_prefix(input)
            .map(|e| (e.seq, e.record, e.consumed))
            .map_err(|_| ())
    }

    /// Append one enveloped record to `out`.
    pub fn encode_envelope_into(seq: u64, record: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
        super::envelope::encode_into(seq, record, out).map_err(|_| ())
    }

    /// Drive a bounded ReorderBuffer with an attacker-derived op stream and
    /// assert its hard memory bounds always hold (the anti-exhaustion guarantee:
    /// a peer must never be able to push pending state past max_records/max_bytes).
    pub fn reorder_drive(data: &[u8]) {
        if data.len() < 11 {
            return;
        }
        let start_seq = u64::from_be_bytes(data[0..8].try_into().expect("8 bytes checked"));
        let max_records = 1 + (data[8] as usize % 64);
        let max_bytes = 1 + (u16::from_be_bytes([data[9], data[10]]) as usize % 65536);
        let mut buf = super::reorder::ReorderBuffer::new(start_seq, max_records, max_bytes);
        let mut rest = &data[11..];
        while !rest.is_empty() {
            let op = rest[0];
            rest = &rest[1..];
            if op & 1 == 0 {
                if rest.len() < 9 {
                    break;
                }
                let seq = u64::from_be_bytes(rest[0..8].try_into().expect("8 bytes checked"));
                let len = rest[8] as usize;
                let take = len.min(rest.len() - 9);
                let record = rest[9..9 + take].to_vec();
                rest = &rest[9 + take..];
                let _ = buf.insert(seq, record);
            } else {
                let _ = buf.pop_next();
            }
            assert!(buf.pending_len() <= max_records, "reorder pending_len exceeded its bound");
            assert!(buf.pending_bytes() <= max_bytes, "reorder pending_bytes exceeded its bound");
        }
    }
}

use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use thiserror::Error;

/// ALPN for the masquerading HTTP/3 face: the UDP leg presents itself as h3.
pub const UDP_ALPN: &[u8] = b"h3";

/// Maximum idle time before quinn tears the connection down. quinn's default is
/// 30s, but the fast-plane connection is retained across the probe and then sits
/// idle through the TCP control exchange (PX1P) and the outbound target connect
/// before the relay's first stream byte. A slow outbound connect can exceed 30s,
/// which would silently kill the retained connection and force a desync-prone
/// fallback. Raise the ceiling and pair it with an active keep-alive so the
/// connection survives the probe -> accept_bi/open_bi gap without traffic.
const UDP_MAX_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Active keep-alive interval, comfortably below [`UDP_MAX_IDLE_TIMEOUT`] so a
/// fully idle retained connection is kept alive by PING frames rather than
/// timing out. quinn defaults keep-alive to None (off).
const UDP_KEEP_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Shared QUIC transport tuning applied to both the server and client endpoints
/// so the two ends agree on idle/keep-alive behavior. The effective idle timeout
/// is the minimum of the two peers' values, so configuring both keeps it
/// deterministic.
fn udp_transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        UDP_MAX_IDLE_TIMEOUT
            .try_into()
            .expect("60s is a valid quinn idle timeout"),
    ));
    transport.keep_alive_interval(Some(UDP_KEEP_ALIVE_INTERVAL));
    Arc::new(transport)
}

#[derive(Debug, Error)]
pub enum UdpTransportError {
    #[error("QUIC TLS configuration failed: {0}")]
    TlsConfig(String),
    #[error("UDP endpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
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
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(udp_transport_config());
    Ok(config)
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
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(udp_transport_config());
    Ok(config)
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
