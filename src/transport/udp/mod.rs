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
pub(crate) mod envelope;
pub(crate) mod h3;
pub mod probe;
/// Hand-written, quinn-free QUIC transport stack (Phase 2 of de-vendoring).
///
/// Built clean-room from RFC 9000/9001/9002 to replace `quinn` + the vendored
/// `quinn-proto` fork. Lands incrementally: each module is verified by its own
/// RFC KAT / round-trip tests and is INERT (not yet wired into the live data
/// path) until the cutover PR repoints the carrier off `quinn`. `#![allow(dead_code)]`
/// in the module marks that staged, not-yet-referenced status.
pub(crate) mod quic;
pub(crate) mod reorder;
/// Persistent single-use 0-RTT anti-replay guard (backs `tls::quic::ZeroRttGuard`).
pub(crate) mod zero_rtt;

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
        // Cold-start only here; the server runtime enables 0-RTT by setting a STEK +
        // anti-replay guard on the config (see the server runtime wiring).
        stek: None,
        replay_guard: None,
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
        stek: Some(stek),
        replay_guard: Some(guard),
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
}
