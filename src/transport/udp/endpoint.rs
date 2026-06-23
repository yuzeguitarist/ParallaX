//! Production QUIC endpoint construction for the UDP fast plane.
//!
//! The server presents an ephemeral self-signed certificate; the client does not
//! validate it — authenticity is the exporter-bound auth token (REALITY-style),
//! so a self-signed cert is sufficient until a real masquerade cert / CDN front
//! is wired in a later slice. The server-side offer (PX1O) and the client-side
//! connect/probe consume these, and on a Verified probe the same connection
//! carries the single-Connect data relay over a reliable bidi stream.

use std::{net::SocketAddr, sync::Arc};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zeroize::Zeroizing;

use crate::tls::quic::{AcceptAnyServerCert, ServerCertVerifier, ZeroRttGuard};
use crate::transport::udp::quic::endpoint::Endpoint;

use super::{client_config, server_config, server_config_0rtt, UdpTransportError};

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
pub async fn bind_server_endpoint(
    addr: SocketAddr,
    sni: &str,
) -> Result<Endpoint, UdpTransportError> {
    let (cert, key) = ephemeral_self_signed(sni)?;
    Ok(Endpoint::server(addr, server_config(cert, key)?).await?)
}

/// Bind a UDP QUIC server endpoint with 0-RTT resumption enabled: it issues
/// NewSessionTickets sealed under `stek` and accepts a resumed ticket's early
/// data, with `guard` enforcing single-use anti-replay across connections. See
/// [`bind_server_endpoint`] for the cold-start (1-RTT-only) variant. `stek` must
/// be stable + server-only so a ticket survives the per-session ephemeral
/// endpoints (the server runtime derives it from the static private key).
pub async fn bind_server_endpoint_0rtt(
    addr: SocketAddr,
    sni: &str,
    stek: Zeroizing<[u8; 32]>,
    guard: Arc<dyn ZeroRttGuard>,
) -> Result<Endpoint, UdpTransportError> {
    let (cert, key) = ephemeral_self_signed(sni)?;
    Ok(Endpoint::server(addr, server_config_0rtt(cert, key, stek, guard)?).await?)
}

/// Bind a UDP QUIC client endpoint with the production wire shape.
///
/// The client uses a ZERO-LENGTH source connection id. Safari-26 H3 emits
/// `initial_source_connection_id` (0x39 TP 0x0f) with length 0 (confirmed by full
/// disassembly), and RFC 9000 §7.3 requires that transport parameter to equal the
/// Source Connection ID in the client's first Initial packet header. The
/// hand-rolled [`Endpoint::client`] constructs every client connection with the
/// empty CID for BOTH the packet header AND `initial_source_connection_id`, so the
/// advertised value always equals the actual wire SCID — no advertised-vs-actual
/// gap. The empty SCID and the ascending `0x39` transport-parameters blob are
/// emitted internally by the hand-rolled `Connection::new_client`.
///
/// TRADEOFF — no NAT-rebinding survival. With a zero-length local SCID the server
/// can only index this connection by the UDP 4-tuple (there is no client CID to
/// route on), so if the client's NAT remaps its source port mid-connection the
/// server cannot re-associate the datagrams and the connection drops. This is a
/// deliberate Safari-faithful choice: Safari-26 itself emits a zero-length SCID,
/// and ParallaX's UDP leg is a short-lived single-Connect relay, so the exposure
/// window is small and a rebind simply surfaces as the existing clean
/// connection-reset failure mode (the caller re-probes / falls back).
pub async fn bind_client_endpoint(
    addr: SocketAddr,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<Endpoint, UdpTransportError> {
    let endpoint = Endpoint::client(addr).await?;
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
pub async fn bind_client_endpoint_accept_any(
    addr: SocketAddr,
) -> Result<Endpoint, UdpTransportError> {
    bind_client_endpoint(addr, Arc::new(AcceptAnyServerCert)).await
}

/// Resolve once the connection has closed (peer close, local close, or idle
/// timeout), the hand-rolled analogue of quinn's `Connection::closed()`.
///
/// The hand-rolled [`Connection`] exposes the close state synchronously
/// ([`Connection::is_closed`]) rather than as a future, so this polls it on a
/// short interval. Both call sites (the fast-plane teardown DONE handshakes in
/// the client/server runtimes) `select!` it against a reliable TCP record read
/// and wrap the whole thing in a generous wall-clock backstop, so the poll
/// interval only bounds how promptly the `closed()` arm wins after the peer
/// actually closes — never correctness.
pub(crate) async fn conn_closed(conn: &crate::transport::udp::quic::endpoint::Connection) {
    use std::time::Duration;
    loop {
        if conn.is_closed() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::udp::test_support::AcceptAnyServerCert;

    #[tokio::test]
    async fn loopback_endpoints_connect() {
        let server = bind_server_endpoint("127.0.0.1:0".parse().unwrap(), "localhost")
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = bind_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(AcceptAnyServerCert),
        )
        .await
        .unwrap();

        let acceptor = tokio::spawn(async move { server.accept().await.unwrap() });
        let conn = client.connect(server_addr, "localhost").await.unwrap();
        let _server_conn = acceptor.await.unwrap();
        assert!(conn.close_reason().is_none());
    }
}
