//! UDP fast-plane transport (the "U" in TUDP).
//!
//! Provides the QUIC endpoint building blocks for the masquerading HTTP/3 face on
//! UDP: a QUIC connection, the HTTP/3 control/encoder uni streams plus the request
//! bidi that carries the reachability probe and relay, and RFC 5705 keying-material
//! export backing the exporter-bound UDP auth token.
//!
//! Wired into the client/server runtimes for the single-Connect data relay: when
//! `[udp].enabled` is set on both ends and the client's probe is Verified, the
//! relay is carried over a reliable bidi QUIC stream through the `Leg`
//! abstraction (which unifies it with the TCP carrier). With `enabled = false`
//! (the default) this is a no-op for every existing code path and the relay stays
//! byte-identical on TCP. Mux and speed-test paths remain on TCP.

pub mod auth;
pub mod endpoint;
pub(crate) mod h3;
/// Persistent single-use anti-replay guard for the origin-splice auth marker.
pub(crate) mod marker_replay;
pub mod probe;
/// Hand-written, quinn-free QUIC transport stack (Phase 2 of de-vendoring): the
/// live production carrier for the UDP fast plane, built clean-room from RFC
/// 9000/9001/9002. The `quinn` + vendored `quinn-proto` fork it replaced are gone
/// from the dependency tree; each module carries its own RFC KAT / round-trip tests.
///
/// `pub(crate)` in every normal build; widened to `pub` ONLY under `--cfg fuzzing`
/// (which cargo-fuzz sets) so the QUIC wire parsers — which run on
/// attacker-controlled, pre-authentication datagram bytes on the server — are
/// reachable from the external `parallax-fuzz` crate. This adds no production API
/// surface, matching the `tls::safari26::fuzz` / `client::socks::fuzz` seams.
#[cfg(not(fuzzing))]
pub(crate) mod quic;
#[cfg(fuzzing)]
pub mod quic;
/// Stable-:443 origin-splice QUIC carrier: a process-wide shared endpoint that
/// marker-terminates authenticated ParallaX clients, splices every other Initial to
/// the real origin, and routes accepted connections back to their session by DCID.
pub(crate) mod stable;
/// Persistent single-use 0-RTT anti-replay guard (backs `tls::quic::ZeroRttGuard`).
pub(crate) mod zero_rtt;

/// Fuzz-only re-export of the QUIC frame-codec driver. Compiled ONLY under
/// `--cfg fuzzing`; gives the `quic_frame_decode` fuzz target a crate-public path
/// (`parallax::transport::udp::quic_frame_fuzz`) into the `pub(crate)` codec
/// without adding any production API surface.
#[cfg(fuzzing)]
pub use quic::frame_fuzz as quic_frame_fuzz;

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::tls::quic::{ServerCertVerifier, ZeroRttGuard};

/// ALPN for the masquerading HTTP/3 face: the UDP leg presents itself as h3.
pub const UDP_ALPN: &[u8] = b"h3";

#[derive(Debug, Error)]
pub enum UdpTransportError {
    #[error("QUIC TLS configuration failed: {0}")]
    TlsConfig(String),
    #[error("UDP endpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Build the hand-rolled QUIC server config from a DER certificate leaf + private
/// key.
///
/// The certificate is presented in the TLS Certificate message and the PKCS#8
/// ECDSA P-256 key (the rcgen default, what `ephemeral_self_signed` produces)
/// signs the CertificateVerify. The h3 ALPN is offered so the flow looks like an
/// ordinary HTTP/3 server. The transport parameters are the relay server's set
/// (one bidi grant + the Safari uni budget); see
/// [`crate::transport::udp::quic::transport_params::TransportParameters::server`].
pub fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<quic::endpoint::ServerConfig>, UdpTransportError> {
    Ok(Arc::new(quic::endpoint::ServerConfig {
        cert_chain: vec![cert.as_ref().to_vec()],
        // rcgen emits ECDSA P-256 PKCS#8 DER, which `secret_der` returns verbatim
        // — exactly what the hand-rolled ServerHandshake's signer expects.
        signing_key_pkcs8: key.secret_der().to_vec(),
        alpn_protocols: vec![UDP_ALPN.to_vec()],
        // Cold-start only here; the server runtime enables 0-RTT by setting the
        // STEK + anti-replay guard pair on the config (see the server runtime wiring).
        zero_rtt: None,
        // The origin-fallback splice is dormant until the server runtime supplies the
        // resolved camouflage-origin UDP address (the gating brick); cold-start drops
        // non-Initial probe traffic, the prior behaviour.
        origin_udp_addr: None,
        // Marker fork dormant until the server runtime supplies the key; every v1
        // Initial terminates locally (the prior behaviour).
        marker_key: None,
        marker_replay_guard: None,
        // No marker key here, so the authorized-SNI gate never runs; empty.
        authorized_sni: Vec::new(),
        // 0 => use the built-in default recv cap (issue #75).
        max_udp_payload: 0,
    }))
}

/// Like [`server_config`] but enables 0-RTT resumption: the server issues
/// NewSessionTickets sealed under `stek` and accepts a resumed ticket's early
/// data, with `guard` enforcing single-use anti-replay across connections (a
/// replayed ticket's 0-RTT is rejected and that connection falls back to a full
/// 1-RTT handshake; RFC 8446 §8). `stek` MUST be a stable, server-only secret so
/// a ticket issued by one per-session ephemeral endpoint still opens at the next
/// (the server runtime derives it from the server's static private key).
pub fn server_config_0rtt(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    stek: Zeroizing<[u8; 32]>,
    guard: Arc<dyn ZeroRttGuard>,
) -> Result<Arc<quic::endpoint::ServerConfig>, UdpTransportError> {
    Ok(Arc::new(quic::endpoint::ServerConfig {
        cert_chain: vec![cert.as_ref().to_vec()],
        signing_key_pkcs8: key.secret_der().to_vec(),
        alpn_protocols: vec![UDP_ALPN.to_vec()],
        zero_rtt: Some(quic::endpoint::ZeroRttKeys { stek, guard }),
        // Splice dormant until the server runtime supplies the origin address.
        origin_udp_addr: None,
        // Marker fork dormant until the server runtime supplies the key.
        marker_key: None,
        marker_replay_guard: None,
        // No marker key here, so the authorized-SNI gate never runs; empty.
        authorized_sni: Vec::new(),
        // 0 => use the built-in default recv cap (issue #75).
        max_udp_payload: 0,
    }))
}

/// Build a server config for the **stable-:443 origin-splice carrier**: the marker
/// fork and origin fallback are LIVE. Every v1 Initial whose ClientHello.random is
/// not a valid + fresh + non-replayed auth marker is spliced verbatim to
/// `origin_udp_addr` (the resolved camouflage origin's UDP :443), so an active
/// prober reaches the TRUE origin and ParallaX emits nothing of its own; only a
/// marked client terminates locally. `marker_key` is `(psk, server static X25519
/// private)` and `stek`/`guard` enable 0-RTT resumption as in [`server_config_0rtt`].
/// `marker_replay_guard` makes the accepted-marker single-use property persistent
/// across restarts (issue #74); `None` falls back to the in-memory cache.
/// `max_udp_payload` is the inbound recv cap (`0` => default; issue #75).
#[allow(clippy::too_many_arguments)]
pub fn server_config_stable(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    zero_rtt: Option<quic::endpoint::ZeroRttKeys>,
    marker_key: crate::crypto::quic_marker::MarkerKey,
    marker_replay_guard: Option<Arc<marker_replay::MarkerReplayGuard>>,
    origin_udp_addr: SocketAddr,
    authorized_sni: Vec<String>,
    max_udp_payload: usize,
) -> Result<Arc<quic::endpoint::ServerConfig>, UdpTransportError> {
    Ok(Arc::new(quic::endpoint::ServerConfig {
        cert_chain: vec![cert.as_ref().to_vec()],
        signing_key_pkcs8: key.secret_der().to_vec(),
        alpn_protocols: vec![UDP_ALPN.to_vec()],
        zero_rtt,
        origin_udp_addr: Some(origin_udp_addr),
        marker_key: Some(marker_key),
        marker_replay_guard,
        // The authorized-SNI allowlist a valid marker's SNI must be on to terminate
        // locally (parity with the TCP plane); any other SNI is fronted to the origin.
        authorized_sni,
        max_udp_payload,
    }))
}

/// Build the hand-rolled QUIC client config with a caller-supplied certificate
/// verifier.
///
/// Like REALITY, the UDP leg does not derive its security from validating the
/// server certificate — the masquerade may legitimately borrow a real origin's
/// cert, and authenticity is instead established by the exporter-bound auth
/// token (a later slice). The verifier is therefore injected by the caller so
/// this module ships no built-in "accept anything" default in production code.
///
/// The TLS engine is ParallaX's hand-written, rustls-free [`crate::tls::quic`]
/// client. It emits the byte-faithful Safari-26 H3 ClientHello (pinned
/// post-quantum-hybrid key share, TLS 1.3 only, cold-start, internal zlib
/// certificate decompression); the ascending `0x39` transport-parameters blob and
/// the zero-length source connection id are emitted internally by the hand-rolled
/// `Connection`, so no rustls config / provider / profile is built on the client
/// path anymore.
pub fn client_config(
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<Arc<crate::tls::quic::ClientConfig>, UdpTransportError> {
    Ok(Arc::new(crate::tls::quic::ClientConfig::new(
        verifier,
        vec![UDP_ALPN.to_vec()],
    )))
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::quic::endpoint::{Connection, Endpoint};
    use super::server_config;

    /// Test verifier that accepts any certificate (REALITY posture; trust is the
    /// exporter-bound auth token). Re-exports the engine's own no-op verifier so
    /// the loopback tests drive the production TLS engine's trust path.
    pub(crate) use crate::tls::quic::AcceptAnyServerCert;

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
            "127.0.0.1:0".parse().unwrap(),
            server_config(cert, key).unwrap(),
        )
        .await
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        // PRODUCTION client builder: zero-length source connection id (Safari
        // fidelity), so the loopback pair exercises the real wire shape.
        let client_endpoint = super::endpoint::bind_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(AcceptAnyServerCert),
        )
        .await
        .unwrap();

        let acceptor = {
            let server_endpoint = server_endpoint.clone();
            tokio::spawn(async move {
                server_endpoint
                    .accept()
                    .await
                    .expect("server-side connection")
            })
        };
        let client_conn = client_endpoint
            .connect(server_addr, "localhost")
            .await
            .expect("client-side connection");
        let server_conn = acceptor.await.expect("accept task");
        (server_endpoint, client_endpoint, client_conn, server_conn)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::test_support::loopback_pair;
    use super::*;

    /// Non-empty PSK for the exporter-bound auth-token round-trip assertions.
    const TEST_PSK: &[u8] = b"parallax-tudp-loopback-psk-012345";

    /// Proves the QUIC fast-plane plumbing on loopback: connection establishment,
    /// a uni-stream round-trip (the earlier probe carrier, still exercised here as
    /// raw uni-stream plumbing), and that the RFC 5705 keying-material exporter
    /// (open question #1 for the exporter-bound auth token) is available and agrees
    /// on both ends under the aws-lc-rs backend.
    #[tokio::test]
    async fn quic_loopback_stream_and_exporter_round_trip() {
        // `loopback_pair` already returns a connected client/server pair (the server
        // grants one bidi + the Safari uni budget). The unique coverage here is the
        // exporter + auth-token agreement across the two ends.
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        let server_task = tokio::spawn(async move {
            // Echo the client's uni-stream request back on a server uni stream.
            let mut recv = tokio::time::timeout(Duration::from_secs(5), server_conn.accept_uni())
                .await
                .expect("server accept_uni timeout")
                .expect("accept client uni stream");
            let mut got = Vec::new();
            recv.read_to_end(&mut got)
                .await
                .expect("read client uni payload");
            let mut send = server_conn.open_uni();
            send.write_all(&got).await.expect("echo uni payload");
            send.finish();
            let mut ekm = [0_u8; 32];
            server_conn
                .export_keying_material(&mut ekm, b"tudp-loopback", b"context")
                .expect("server export_keying_material");
            let token = auth::export_udp_auth_token(&server_conn, TEST_PSK, b"offer-context")
                .expect("server auth token");
            // Hold the connection open long enough for the client to read the echo.
            tokio::time::sleep(Duration::from_millis(200)).await;
            (ekm, token)
        });

        let mut send = client_conn.open_uni();
        send.write_all(b"ping").await.expect("client write uni");
        send.finish();
        let mut recv = tokio::time::timeout(Duration::from_secs(5), client_conn.accept_uni())
            .await
            .expect("client accept_uni timeout")
            .expect("accept echoed uni stream");
        let mut echo = Vec::new();
        recv.read_to_end(&mut echo)
            .await
            .expect("read echoed uni payload");
        assert_eq!(&echo[..], b"ping");

        let mut client_ekm = [0_u8; 32];
        client_conn
            .export_keying_material(&mut client_ekm, b"tudp-loopback", b"context")
            .expect("client export_keying_material");
        let client_token = auth::export_udp_auth_token(&client_conn, TEST_PSK, b"offer-context")
            .expect("client auth token");
        let other_context_token =
            auth::export_udp_auth_token(&client_conn, TEST_PSK, b"different-context")
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

    /// The production 0-RTT server bind path (`bind_server_endpoint_0rtt`) issues a
    /// NewSessionTicket the client can take for a future resumption. This exercises
    /// the transport-layer wiring the server runtime uses (STEK + shared guard on
    /// the `ServerConfig`), end to end over the async endpoint.
    #[tokio::test]
    async fn zero_rtt_bound_server_issues_a_resumption_ticket() {
        use crate::crypto::replay::ReplayCache;
        use crate::tls::quic::derive_stek;
        use crate::transport::udp::endpoint::{
            bind_client_endpoint_accept_any, bind_server_endpoint_0rtt,
        };
        use crate::transport::udp::zero_rtt::ReplayCacheGuard;

        let stek = derive_stek(&[7_u8; 32]);
        let guard = Arc::new(ReplayCacheGuard::new(
            ReplayCache::new(64).with_window_secs(604_800),
        ));
        let server =
            bind_server_endpoint_0rtt("127.0.0.1:0".parse().unwrap(), "localhost", stek, guard)
                .await
                .unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = bind_client_endpoint_accept_any("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let conn = client.connect(server_addr, "localhost").await.unwrap();
        let _server_conn = acceptor
            .await
            .unwrap()
            .expect("server accepts the connection");

        // The server sends its NewSessionTicket right after the handshake; poll
        // briefly for it to reach the client driver, then take it.
        let mut ticket = None;
        for _ in 0..50 {
            if let Some(t) = conn.take_session_ticket(1_000) {
                ticket = Some(t);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            ticket.is_some(),
            "client received a NewSessionTicket from the 0-RTT-enabled server"
        );
    }

    /// End-to-end 0-RTT resumption over the async endpoint: a client takes a ticket
    /// from a 0-RTT server, reconnects with `connect_resumption_0rtt`, writes early
    /// data before awaiting the handshake, and the server receives it. Exercises the
    /// async early-data send primitive the client runtime builds on (delivery holds
    /// whether the server accepts 0-RTT or falls back to 1-RTT retransmit).
    #[tokio::test]
    async fn zero_rtt_resumption_delivers_early_data_over_the_async_endpoint() {
        use crate::crypto::replay::ReplayCache;
        use crate::tls::quic::derive_stek;
        use crate::transport::udp::endpoint::{
            bind_client_endpoint_accept_any, bind_server_endpoint_0rtt,
        };
        use crate::transport::udp::zero_rtt::ReplayCacheGuard;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stek = derive_stek(&[9_u8; 32]);
        let guard = Arc::new(ReplayCacheGuard::new(
            ReplayCache::new(64).with_window_secs(604_800),
        ));
        let server =
            bind_server_endpoint_0rtt("127.0.0.1:0".parse().unwrap(), "localhost", stek, guard)
                .await
                .unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = bind_client_endpoint_accept_any("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Phase 1: cold connect, take a resumption ticket.
        let ticket = {
            let acceptor = {
                let server = server.clone();
                tokio::spawn(async move { server.accept().await })
            };
            let conn = client.connect(server_addr, "localhost").await.unwrap();
            let _s = acceptor
                .await
                .unwrap()
                .expect("server accepts cold connection");
            let mut t = None;
            for _ in 0..50 {
                if let Some(ticket) = conn.take_session_ticket(1_000) {
                    t = Some(ticket);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            t.expect("client took a resumption ticket")
        };

        // Phase 2: resume with 0-RTT and write early data before awaiting handshake.
        // A FRESH client endpoint (new local port), mirroring production: each data
        // session binds its own endpoint, so the resumption never collides with the
        // dropped cold connection's 4-tuple.
        let client2 = bind_client_endpoint_accept_any("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_for_relay = server.clone();
        let srv = tokio::spawn(async move {
            let conn = server_for_relay
                .accept()
                .await
                .expect("server accepts resumption");
            let (_send, mut recv) = conn.accept_bi().await.expect("server accepts bidi");
            let mut got = Vec::new();
            recv.read_to_end(&mut got)
                .await
                .expect("server reads early data");
            got
        });

        let early = b"GET /0rtt early data over the async endpoint";
        let conn = client2
            .connect_resumption_0rtt(server_addr, "localhost", ticket, 2_000)
            .await
            .unwrap();
        let (mut send, _recv) = conn.open_bi();
        send.write_all(early).await.expect("write early data");
        send.finish();
        conn.wait_established().await.expect("handshake completes");

        let got = tokio::time::timeout(Duration::from_secs(5), srv)
            .await
            .expect("server task timed out")
            .expect("server task panicked");
        assert_eq!(got, early, "server received the resumed early data");
    }
}

/// Realistic two-session 0-RTT resumption tests. These drive the PRODUCTION QUIC
/// endpoints (`bind_server_endpoint_0rtt` / `bind_client_endpoint_accept_any`) and
/// the REAL H3 probe (`probe_client_*` / `serve_probe_over_bidi`) across two
/// sessions over loopback UDP — exactly as `client::runtime::run_client_udp_probe`
/// does, minus only the TCP/SOCKS control wrapper (orthogonal to 0-RTT). They prove
/// the ticket rotation, that the server ACCEPTS a fresh ticket's 0-RTT early data,
/// that a REPLAYED ticket's 0-RTT is rejected (single-use) with a graceful 1-RTT
/// fallback, and that the single-use property PERSISTS across a server restart.
#[cfg(test)]
mod zero_rtt_resumption {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::crypto::replay::ReplayCache;
    use crate::tls::quic::{derive_stek, ClientTicket};
    use crate::transport::udp::endpoint::{
        bind_client_endpoint_accept_any, bind_server_endpoint_0rtt,
    };
    use crate::transport::udp::probe::{
        probe_client_over_bidi, probe_client_read_and_verify, probe_client_send_request_early,
        serve_probe_over_bidi, ProbeOutcome,
    };
    use crate::transport::udp::quic::endpoint::{Connection, Endpoint, RecvStream, SendStream};
    use crate::transport::udp::zero_rtt::ReplayCacheGuard;

    const ZR_PSK: &[u8] = b"parallax-0rtt-resumption-test-psk";
    const ZR_CTX: &[u8] = b"0rtt-resumption-offer-context";
    const ZR_LIFETIME: u64 = 604_800;
    const ZR_TIMEOUT: Duration = Duration::from_secs(5);

    fn unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    async fn client() -> Endpoint {
        bind_client_endpoint_accept_any("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
    }

    /// Accept one connection and serve one H3 probe round-trip on it, returning the
    /// server connection (so the caller can query `zero_rtt_keys_installed`) plus the
    /// probe streams (held so the queued reply flushes before they drop).
    async fn accept_and_serve_probe(server: &Endpoint) -> (Connection, SendStream, RecvStream) {
        let conn = server.accept().await.expect("server accepts");
        let (mut send, mut recv) = conn.accept_bi().await.expect("server accept_bi");
        serve_probe_over_bidi(&conn, &mut send, &mut recv, ZR_PSK, ZR_CTX)
            .await
            .expect("server serve_probe_over_bidi");
        (conn, send, recv)
    }

    /// One COLD session (client probe + server serve, concurrent); returns a
    /// resumption ticket the client took from the post-handshake NewSessionTicket.
    async fn cold_session_take_ticket(
        client: &Endpoint,
        server: &Endpoint,
        addr: SocketAddr,
    ) -> ClientTicket {
        let srv = accept_and_serve_probe(server);
        let cli = async {
            let conn = client
                .connect(addr, "localhost")
                .await
                .expect("cold connect");
            let _control = crate::transport::udp::h3::open_h3_control_stream(&conn)
                .await
                .expect("client control stream");
            let (mut send, mut recv) = conn.open_bi();
            let outcome = probe_client_over_bidi(
                &conn,
                &mut send,
                &mut recv,
                "localhost",
                ZR_PSK,
                ZR_CTX,
                ZR_TIMEOUT,
            )
            .await
            .expect("client cold probe");
            (conn, outcome)
        };
        let (_held, (conn, outcome)) = tokio::join!(srv, cli);
        assert!(
            matches!(outcome, ProbeOutcome::Verified { .. }),
            "cold session must Verify, got {outcome:?}"
        );
        // The NST arrives post-handshake (before the probe round-trip completes);
        // poll briefly for it.
        for _ in 0..50 {
            if let Some(ticket) = conn.take_session_ticket(unix_ms()) {
                return ticket;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("cold session issued no resumption ticket");
    }

    /// One RESUMED session: the client sends the H3 control SETTINGS and the probe
    /// request as 0-RTT early data, awaits the handshake, then verifies the response.
    /// Returns `(server_accepted_0rtt, client_outcome)`. Mirrors the resumption branch
    /// of `run_client_udp_probe`.
    async fn resume_session(
        client: &Endpoint,
        server: &Endpoint,
        addr: SocketAddr,
        ticket: ClientTicket,
    ) -> (bool, ProbeOutcome) {
        let srv = accept_and_serve_probe(server);
        let cli = async {
            let conn = client
                .connect_resumption_0rtt(addr, "localhost", ticket, unix_ms())
                .await
                .expect("resumption connect");
            let _control = crate::transport::udp::h3::open_h3_control_stream(&conn)
                .await
                .expect("control stream (0-RTT)");
            let (mut send, mut recv) = conn.open_bi();
            let nonce = probe_client_send_request_early(&mut send, "localhost")
                .await
                .expect("send probe request (0-RTT)");
            conn.wait_established().await.expect("handshake completes");
            let outcome =
                probe_client_read_and_verify(&conn, &mut recv, &nonce, ZR_PSK, ZR_CTX, ZR_TIMEOUT)
                    .await
                    .expect("read + verify probe response");
            outcome
        };
        let ((server_conn, _s, _r), outcome) = tokio::join!(srv, cli);
        (server_conn.zero_rtt_keys_installed(), outcome)
    }

    async fn in_memory_server(stek_seed: [u8; 32]) -> (Endpoint, SocketAddr) {
        let guard = Arc::new(ReplayCacheGuard::new(
            ReplayCache::new(64).with_window_secs(ZR_LIFETIME),
        ));
        let server = bind_server_endpoint_0rtt(
            "127.0.0.1:0".parse().unwrap(),
            "localhost",
            derive_stek(&stek_seed),
            guard,
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();
        (server, addr)
    }

    /// Two sessions: a cold session deposits a ticket; the next session resumes with
    /// it and the server ACCEPTS the fresh ticket's 0-RTT early data.
    #[tokio::test]
    async fn two_session_resumption_accepts_early_data() {
        let (server, addr) = in_memory_server([0x5a; 32]).await;

        let ticket = cold_session_take_ticket(&client().await, &server, addr).await;

        let (accepted, outcome) = resume_session(&client().await, &server, addr, ticket).await;
        assert!(
            matches!(outcome, ProbeOutcome::Verified { .. }),
            "resumed session must Verify, got {outcome:?}"
        );
        assert!(
            accepted,
            "server must ACCEPT a fresh ticket's 0-RTT early data"
        );
    }

    /// A REPLAYED ticket (the same ticket offered twice) is accepted once, then its
    /// 0-RTT is rejected by the single-use guard — the replay falls back to a full
    /// 1-RTT handshake and still Verifies (no data loss, no double 0-RTT accept).
    #[tokio::test]
    async fn replayed_ticket_is_rejected_and_falls_back_to_1rtt() {
        let (server, addr) = in_memory_server([0x5b; 32]).await;

        let ticket = cold_session_take_ticket(&client().await, &server, addr).await;

        let (accepted1, outcome1) =
            resume_session(&client().await, &server, addr, ticket.clone()).await;
        assert!(accepted1, "first use: 0-RTT accepted");
        assert!(matches!(outcome1, ProbeOutcome::Verified { .. }));

        // Replay the SAME ticket: single-use guard rejects the 0-RTT.
        let (accepted2, outcome2) = resume_session(&client().await, &server, addr, ticket).await;
        assert!(!accepted2, "replay: 0-RTT REJECTED by the single-use guard");
        assert!(
            matches!(outcome2, ProbeOutcome::Verified { .. }),
            "replay still Verifies via the 1-RTT fallback, got {outcome2:?}"
        );
    }

    /// The single-use property survives a server restart: a ticket accepted before
    /// the restart is rejected (0-RTT) after it, because the anti-replay record is in
    /// the persistent cache. The restarted server keeps the SAME STEK (so it can
    /// still OPEN the ticket) and reloads the SAME cache file.
    #[tokio::test]
    async fn single_use_persists_across_server_restart() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("zero-rtt-replay.cache");
        let mac_key = b"persistent-0rtt-guard-mac-key";
        let stek_seed = [0x5c; 32];

        let load_guard = || {
            Arc::new(ReplayCacheGuard::new(
                ReplayCache::load_or_create_authenticated_with_window(
                    &cache_path,
                    64,
                    mac_key,
                    ZR_LIFETIME,
                )
                .unwrap(),
            ))
        };

        // Server 1 (file-backed guard): cold session deposits a ticket, then a first
        // resumption is accepted (recording the ticket in the persistent cache).
        let server1 = bind_server_endpoint_0rtt(
            "127.0.0.1:0".parse().unwrap(),
            "localhost",
            derive_stek(&stek_seed),
            load_guard(),
        )
        .await
        .unwrap();
        let addr1 = server1.local_addr().unwrap();
        let ticket = cold_session_take_ticket(&client().await, &server1, addr1).await;
        let (accepted1, _o1) =
            resume_session(&client().await, &server1, addr1, ticket.clone()).await;
        assert!(accepted1, "before restart: fresh ticket's 0-RTT accepted");

        // "Restart": drop server 1, rebuild on a fresh ephemeral endpoint with the
        // SAME STEK and a guard RELOADED from the same persistent cache file.
        drop(server1);
        let server2 = bind_server_endpoint_0rtt(
            "127.0.0.1:0".parse().unwrap(),
            "localhost",
            derive_stek(&stek_seed),
            load_guard(),
        )
        .await
        .unwrap();
        let addr2 = server2.local_addr().unwrap();

        // Replay the same ticket against the restarted server: the persisted record
        // rejects the 0-RTT; the session falls back to 1-RTT and still Verifies.
        let (accepted2, outcome2) = resume_session(&client().await, &server2, addr2, ticket).await;
        assert!(
            !accepted2,
            "after restart: replayed ticket's 0-RTT REJECTED (persistent single-use)"
        );
        assert!(
            matches!(outcome2, ProbeOutcome::Verified { .. }),
            "restart replay still Verifies via 1-RTT, got {outcome2:?}"
        );
    }
}
