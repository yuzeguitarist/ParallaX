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
            assert!(
                buf.pending_len() <= max_records,
                "reorder pending_len exceeded its bound"
            );
            assert!(
                buf.pending_bytes() <= max_bytes,
                "reorder pending_bytes exceeded its bound"
            );
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

/// Connection + single-stream flow-control window for the fast-plane relay.
///
/// quinn's default `stream_receive_window` is ~1.25 MB (sized for a 12.5 MB/s x
/// 100 ms path) and the previous config also pinned `receive_window` to 1.25 MB.
/// On a 160-320 ms cross-border path that window caps a single stream at
/// window/RTT — measured ~3.9 MB/s at 160 ms, i.e. BELOW the ~11 MB/s TCP
/// baseline, which is the real reason the QUIC fast plane could not beat TCP. See
/// the `quic_fast_plane_goodput_under_cross_border_loss` harness: 1.25 MB ->
/// ~4 MB/s, 16 MiB -> ~15 MB/s, holding ~13 MB/s at 3% loss where TCP collapses.
///
/// Size it to the worst-case BDP the relay should saturate (320 ms RTT at
/// ~400 Mbit/s ≈ 16 MiB) so the single relay stream is never flow-control-bound
/// on a realistic cross-border link. This is also MORE browser-like — Safari /
/// Chromium H3 use large flow-control windows; the 1.25 MB pin was the anomaly.
/// DoS exposure stays bounded (at most this many bytes of un-drained buffer per
/// authenticated single-stream connection, vs quinn's unbounded `VarInt::MAX`
/// connection default).
const UDP_FLOW_CONTROL_WINDOW: u32 = 16 * 1024 * 1024;

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

    // The fast-plane relay multiplexes BOTH directions onto a SINGLE reliable
    // bidi QUIC stream (client `open_bi` / server `accept_bi`) and never opens a
    // uni stream; the reachability probe uses unreliable datagrams, governed
    // separately by `datagram_receive_buffer_size`. quinn's defaults (100 bidi +
    // 100 uni concurrent streams, connection `receive_window = VarInt::MAX`) let
    // an authenticated peer pin hundreds of MB of un-drained receive buffers
    // against this one-stream relay. Bound it to the relay reality: at most one
    // incoming bidi stream and no uni streams. The flow-control WINDOW, however,
    // must be sized to the cross-border BDP, not minimized — quinn's ~1.25 MB
    // default throttles a single stream to window/RTT (~4 MB/s at 160 ms, below
    // the TCP baseline). Set the connection and single-stream receive windows to
    // UDP_FLOW_CONTROL_WINDOW so the relay stream can saturate the link, and the
    // sender's send_window to match so neither end is the bottleneck.
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    transport.receive_window(quinn::VarInt::from_u32(UDP_FLOW_CONTROL_WINDOW));
    transport.stream_receive_window(quinn::VarInt::from_u32(UDP_FLOW_CONTROL_WINDOW));
    transport.send_window(u64::from(UDP_FLOW_CONTROL_WINDOW));

    // Congestion control: BBR, not quinn's default Cubic. The fast plane only
    // earns its keep on lossy links, where Cubic's loss-as-congestion backoff
    // collapses throughput but BBR's model-based send rate holds up — that is the
    // entire reason this UDP leg exists. BBR is also the camouflage-safe choice:
    // an aggressive flat loss-response (Brutal) is statistically classifiable,
    // whereas BBR blends in with ordinary HTTP/3 traffic. This is endpoint-local
    // (peers need not agree on a CC) and only affects the UDP-active data path, so
    // the default-off TCP path stays byte-identical. Stock BBR with quinn's
    // defaults needs no per-network tuning; a custom Brutal controller is a later,
    // opt-in, real-network-tuned slice.
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    Arc::new(transport)
}

#[derive(Debug, Error)]
pub enum UdpTransportError {
    #[error("QUIC TLS configuration failed: {0}")]
    TlsConfig(String),
    #[error("UDP endpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// rustls crypto provider for the QUIC face with the key-exchange groups pinned
/// so the post-quantum hybrid `X25519MLKEM768` is the default key share.
///
/// This is camouflage-critical, not a performance choice. The GFW passively
/// decrypts the QUIC v1 Initial to read the SNI but does NOT reassemble a
/// ClientHello that spans multiple datagrams. The first kx group is the default
/// key-share algorithm (rustls sends a key share for it in the ClientHello), so
/// leading with the ~1.2 KB `X25519MLKEM768` hybrid pushes the Initial past one
/// datagram and the SNI is not single-packet-extractable. It also matches current
/// Chromium, which leads with `X25519MLKEM768` on its own h3 flows.
///
/// aws-lc-rs's default order ALSO leads with the hybrid, but only while rustls's
/// `prefer-post-quantum` default feature is active. Pinning the list here makes
/// the property independent of that implicit upstream feature — a
/// `default-features = false` on the rustls dependency would otherwise silently
/// drop the hybrid to last, shrink the Initial below one datagram, and re-expose
/// the SNI. The gfw_simulator
/// `udp_leg_initial_first_datagram_holds_only_partial_clienthello` test guards
/// the observable property.
fn camouflage_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs;
    rustls::crypto::CryptoProvider {
        // Mirror aws-lc-rs's prefer-post-quantum DEFAULT_KX_GROUPS order EXACTLY
        // (X25519MLKEM768, X25519, SECP256R1, SECP384R1). Pinning it makes the
        // hybrid-leads property independent of the upstream feature flag WITHOUT
        // changing the on-wire supported_groups vs the current default — dropping
        // any of these (e.g. SECP384R1, which Chromium also offers) would itself be
        // a fingerprint divergence.
        kx_groups: vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
            aws_lc_rs::kx_group::SECP256R1,
            aws_lc_rs::kx_group::SECP384R1,
        ],
        ..aws_lc_rs::default_provider()
    }
}

/// Build a quinn server config from a DER certificate leaf + private key.
///
/// TLS 1.3 only, aws-lc-rs provider (matching the rest of ParallaX), advertising
/// the h3 ALPN so the flow looks like an ordinary HTTP/3 server.
pub fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, UdpTransportError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(camouflage_provider()))
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
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(camouflage_provider()))
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

    use super::test_support::{loopback_pair, self_signed_cert, AcceptAnyServerCert};
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

    /// M-6: the relay endpoint's QUIC transport config bounds flow control to the
    /// single-bidi-stream relay shape — uni streams are forbidden and at most one
    /// concurrent bidi stream is granted — so an authenticated peer cannot pin
    /// hundreds of MB of un-drained receive buffers by over-opening streams.
    /// TransportConfig fields have no getters, so this drives a loopback pair and
    /// observes the peer being denied stream credit.
    #[tokio::test]
    async fn quic_transport_config_bounds_streams_to_single_bidi_relay() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        // (1) The single-stream relay shape still works: one bidi stream opens
        // and the server accepts it. Keep both ends' handles alive (dropping the
        // send half would free the bidi credit and defeat assertion (3)).
        let (mut s1, _r1) = client_conn.open_bi().await.expect("open_bi #1");
        s1.write_all(b"x").await.expect("write stream #1");
        let _srv1 = tokio::time::timeout(Duration::from_secs(2), server_conn.accept_bi())
            .await
            .expect("server must accept the first bidi stream")
            .expect("accept_bi #1");

        // (2) Uni streams are forbidden (max_concurrent_uni_streams = 0): the peer
        // grants no uni credit, so open_uni never resolves.
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client_conn.open_uni())
                .await
                .is_err(),
            "uni streams must be forbidden on the single-stream relay endpoint",
        );

        // (3) Bidi is capped at 1: stream #1 is still open, so a second open_bi
        // gets no further credit and never resolves.
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client_conn.open_bi())
                .await
                .is_err(),
            "a second concurrent bidi stream must not be granted (cap = 1)",
        );

        drop(s1);
    }

    /// Pins the camouflage-critical key-exchange ordering: the QUIC face MUST lead
    /// with `X25519MLKEM768` so the post-quantum hybrid key share inflates the
    /// ClientHello past one datagram (SNI not single-packet-extractable) and the
    /// flow matches current Chromium. This guards the EXPLICIT intent at the unit
    /// level, independent of rustls's `prefer-post-quantum` default feature — the
    /// gfw_simulator test guards the resulting on-wire fragmentation.
    #[test]
    fn camouflage_provider_leads_with_pq_hybrid_kx() {
        let provider = camouflage_provider();
        // Assert the FULL ordered list, not just the leader: the hybrid must lead
        // (so its key share inflates the Initial), AND the list must mirror
        // aws-lc-rs's prefer-post-quantum DEFAULT_KX_GROUPS exactly so the on-wire
        // supported_groups stays Chrome-like (dropping/reordering any of these is a
        // fingerprint divergence the leader-only check would miss).
        let names: Vec<_> = provider.kx_groups.iter().map(|kx| kx.name()).collect();
        assert_eq!(
            names,
            vec![
                rustls::NamedGroup::X25519MLKEM768,
                rustls::NamedGroup::X25519,
                rustls::NamedGroup::secp256r1,
                rustls::NamedGroup::secp384r1,
            ],
            "QUIC kx groups must mirror aws-lc-rs prefer-post-quantum default order",
        );
    }

    // --- Cross-border loss/RTT harness ------------------------------------
    // Offline evidence (no netem, no second host): a userspace UDP relay injects
    // one-way delay + Bernoulli loss into a REAL quinn connection, so we can see
    // whether the fast plane survives lossy high-RTT links and whether the
    // connection/stream receive_window throttles a high-BDP path.

    use quinn::Connection;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;
    use tokio::time::Instant;

    /// Loopback UDP relay adding `delay` one-way and Bernoulli `loss` in each
    /// direction between a client (which dials the returned addr) and
    /// `server_addr`. Abort the handle to stop it.
    async fn delay_loss_relay(
        server_addr: SocketAddr,
        delay: Duration,
        loss: f64,
        seed: u64,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut client_addr: Option<SocketAddr> = None;
            let mut buf = vec![0_u8; 2048];
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let dest = if from == server_addr {
                    match client_addr {
                        Some(a) => a,
                        None => continue,
                    }
                } else {
                    client_addr = Some(from);
                    server_addr
                };
                if rng.gen::<f64>() < loss {
                    continue; // drop this packet
                }
                let pkt = buf[..n].to_vec();
                let sock = sock.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sock.send_to(&pkt, dest).await;
                });
            }
        });
        (relay_addr, handle)
    }

    /// Production fast-plane bounds, but with the connection + stream
    /// receive_window set to `window`, so the harness can isolate the high-BDP
    /// throughput cap. BBR matches production.
    fn relay_test_transport(window: u32) -> Arc<quinn::TransportConfig> {
        let mut t = quinn::TransportConfig::default();
        t.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1));
        t.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
        t.receive_window(quinn::VarInt::from_u32(window));
        t.stream_receive_window(quinn::VarInt::from_u32(window));
        t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        Arc::new(t)
    }

    /// Establish a client/server QUIC pair whose packets traverse a delay+loss
    /// relay, both ends using `transport`.
    async fn relay_pair(
        transport: Arc<quinn::TransportConfig>,
        delay: Duration,
        loss: f64,
        seed: u64,
    ) -> (
        Endpoint,
        Endpoint,
        Connection,
        Connection,
        tokio::task::JoinHandle<()>,
    ) {
        let (cert, key) = self_signed_cert();
        let mut server_cfg = server_config(cert, key).unwrap();
        server_cfg.transport_config(transport.clone());
        let server_endpoint = Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let (relay_addr, relay) = delay_loss_relay(server_addr, delay, loss, seed).await;

        let mut client_cfg = client_config(Arc::new(AcceptAnyServerCert)).unwrap();
        client_cfg.transport_config(transport);
        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_cfg);

        let acceptor = {
            let server_endpoint = server_endpoint.clone();
            tokio::spawn(async move {
                server_endpoint
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("server conn")
            })
        };
        let client_conn = tokio::time::timeout(
            Duration::from_secs(25),
            client_endpoint
                .connect(relay_addr, "localhost")
                .expect("start connect"),
        )
        .await
        .expect("client connect timed out through relay")
        .expect("client conn");
        let server_conn = tokio::time::timeout(Duration::from_secs(25), acceptor)
            .await
            .expect("server accept timed out")
            .expect("accept task");
        (
            server_endpoint,
            client_endpoint,
            client_conn,
            server_conn,
            relay,
        )
    }

    /// Measure single-bidi-stream download goodput (server -> client) in MB/s,
    /// timed from first byte received to last (excludes the initial RTT).
    async fn download_goodput(client: &Connection, server: &Connection, n: usize) -> f64 {
        let server = server.clone();
        let server_task = tokio::spawn(async move {
            let (mut send, _recv) = server.accept_bi().await.expect("accept_bi");
            let chunk = vec![0xAB_u8; 64 * 1024];
            let mut written = 0;
            while written < n {
                let take = (n - written).min(chunk.len());
                send.write_all(&chunk[..take]).await.expect("write");
                written += take;
            }
            send.finish().expect("finish");
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        // Open the relay's single bidi stream and kick a byte so the server's
        // accept_bi resolves; keep the send half alive for the stream's lifetime.
        let (mut _kick, mut recv) = client.open_bi().await.expect("open_bi");
        _kick.write_all(b"go").await.expect("kick");
        let mut got = 0_usize;
        let mut start: Option<Instant> = None;
        let mut buf = vec![0_u8; 64 * 1024];
        while let Some(read) = recv.read(&mut buf).await.expect("read") {
            if start.is_none() {
                start = Some(Instant::now());
            }
            got += read;
        }
        let secs = start.expect("at least one byte").elapsed().as_secs_f64();
        server_task.await.unwrap();
        assert_eq!(got, n, "must receive the whole object");
        (got as f64 / 1_048_576.0) / secs.max(1e-6)
    }

    /// Evidence harness: does the 1.25 MB production receive_window throttle a
    /// 160 ms cross-border path, and does a BDP-sized window lift it? Prints a
    /// goodput table across loss levels for both windows. Heavy; run with
    /// `--ignored`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "heavy QUIC network-emulation benchmark; run with --ignored"]
    async fn quic_fast_plane_goodput_under_cross_border_loss() {
        let n = 16 * 1024 * 1024; // 16 MiB download per cell
        let delay = Duration::from_millis(80); // ~160 ms RTT
        let loss_levels = [0.0_f64, 0.01, 0.03];

        // "old": the previous 1.25 MB window. "prod-fixed": the real shipping
        // config (udp_transport_config, now BDP-sized). Same BBR, same relay.
        let cases: [(&str, Arc<quinn::TransportConfig>); 2] = [
            ("old-1.25MB", relay_test_transport(1_250_000)),
            ("prod-fixed", udp_transport_config()),
        ];

        let mut old_clean = 0.0_f64;
        let mut prod_worst = f64::INFINITY;
        for (label, transport) in cases {
            for (i, &loss) in loss_levels.iter().enumerate() {
                let (_se, _ce, cc, sc, relay) =
                    relay_pair(transport.clone(), delay, loss, 0x0C0FFEE0).await;
                let mbps = download_goodput(&cc, &sc, n).await;
                println!(
                    "[{label}] rtt=160ms loss={:>4.1}% goodput={:>7.2} MB/s",
                    loss * 100.0,
                    mbps
                );
                relay.abort();
                if label == "old-1.25MB" && i == 0 {
                    old_clean = mbps;
                }
                if label == "prod-fixed" {
                    prod_worst = prod_worst.min(mbps);
                }
            }
        }

        // The fix is decisive: the shipping (BDP-sized) config at its WORST
        // modeled loss still beats the old 1.25 MB window on a CLEAN link.
        assert!(
            prod_worst > old_clean,
            "BDP-sized window worst-case ({prod_worst:.2} MB/s) must beat old 1.25MB clean ({old_clean:.2} MB/s)"
        );
    }

    /// Same bounds + window as `relay_test_transport`, but quinn's DEFAULT
    /// congestion controller (Cubic) rather than BBR, so the harness can measure
    /// the loss response that motivates the BBR choice.
    fn relay_test_transport_cubic(window: u32) -> Arc<quinn::TransportConfig> {
        let mut t = quinn::TransportConfig::default();
        t.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1));
        t.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
        t.receive_window(quinn::VarInt::from_u32(window));
        t.stream_receive_window(quinn::VarInt::from_u32(window));
        Arc::new(t)
    }

    /// Measure MB/s actually delivered within `cap` (timed from the first byte,
    /// so the initial RTT is excluded). The right tool when a controller
    /// collapses: a fixed-SIZE transfer would take minutes at ~0.05 MB/s.
    async fn download_rate_in_window(
        client: &Connection,
        server: &Connection,
        cap: Duration,
    ) -> f64 {
        let server = server.clone();
        let server_task = tokio::spawn(async move {
            if let Ok((mut send, _recv)) = server.accept_bi().await {
                let chunk = vec![0xAB_u8; 64 * 1024];
                while send.write_all(&chunk).await.is_ok() {} // until flow-control/close
            }
        });
        let (mut _kick, mut recv) = client.open_bi().await.expect("open_bi");
        _kick.write_all(b"go").await.expect("kick");
        let mut buf = vec![0_u8; 64 * 1024];
        // Block for the first byte so the initial RTT is excluded from the rate.
        let mut got = recv.read(&mut buf).await.expect("read").unwrap_or(0);
        let start = Instant::now();
        while start.elapsed() < cap {
            match tokio::time::timeout(cap - start.elapsed(), recv.read(&mut buf)).await {
                Ok(Ok(Some(read))) => got += read,
                _ => break,
            }
        }
        let secs = start.elapsed().as_secs_f64();
        server_task.abort();
        (got as f64 / 1_048_576.0) / secs.max(1e-6)
    }

    /// Evidence for the BBR choice (mod.rs:144): on a lossy cross-border path
    /// Cubic reads every random loss as congestion and collapses its window,
    /// while BBR's model-based rate holds up. With the BDP window in place, this
    /// isolates the congestion-controller's loss response. Heavy; `--ignored`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "heavy QUIC network-emulation benchmark; run with --ignored"]
    async fn quic_bbr_beats_cubic_under_cross_border_loss() {
        let delay = Duration::from_millis(80); // ~160 ms RTT
        let loss = 0.03; // 3% — the worst modeled cross-border loss
        let window = UDP_FLOW_CONTROL_WINDOW;
        let cap = Duration::from_secs(8);

        let (_se1, _ce1, cc1, sc1, r1) =
            relay_pair(relay_test_transport(window), delay, loss, 0xB0BB).await;
        let bbr = download_rate_in_window(&cc1, &sc1, cap).await;
        r1.abort();

        let (_se2, _ce2, cc2, sc2, r2) =
            relay_pair(relay_test_transport_cubic(window), delay, loss, 0xB0BB).await;
        let cubic = download_rate_in_window(&cc2, &sc2, cap).await;
        r2.abort();

        println!("rtt=160ms loss=3.0% (8s window)  BBR={bbr:.2} MB/s  Cubic={cubic:.2} MB/s");
        assert!(
            bbr > cubic * 2.0,
            "BBR ({bbr:.2}) must clearly beat Cubic ({cubic:.2}) under cross-border loss"
        );
    }
}
