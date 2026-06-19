//! UDP fast-plane transport (the "U" in TUDP).
//!
//! Provides the QUIC endpoint building blocks for the masquerading HTTP/3 face on
//! UDP: a QUIC connection, a uni-stream round-trip used by the reachability probe,
//! and RFC 5705 keying-material export backing the exporter-bound UDP auth token.
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
/// Safari-26 H3 QUIC ClientHello carrier (S2). This is now the DEFAULT QUIC
/// client backend (S6): `client_config` drives the Safari Session so the
/// emitted ClientHello is byte/structurally indistinguishable from Safari-26 H3.
/// The QUIC plane itself is gated at the config level (`[udp].enabled = false`).
pub mod safari_crypto;

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

use quinn::crypto::rustls::QuicServerConfig;
use rustls::{
    client::danger::ServerCertVerifier,
    compress::{CertDecompressor, DecompressionFailed},
    pki_types::{CertificateDer, PrivateKeyDer},
    CertificateCompressionAlgorithm,
};
use thiserror::Error;

/// ALPN for the masquerading HTTP/3 face: the UDP leg presents itself as h3.
pub const UDP_ALPN: &[u8] = b"h3";

/// Zlib certificate decompressor for the QUIC client, implemented with the
/// existing `flate2` dependency.
///
/// The Safari-26 H3 ClientHello advertises `compress_certificate` = zlib (the
/// `[len=2, zlib=0x0001]` body in `safari_shape.rs` / `safari26.rs`), so a
/// TLS-1.3 server MAY answer with a `CompressedCertificate` message. The
/// vendored rustls ships zlib support only behind its `zlib` cargo feature
/// (which would pull in `zlib-rs`); that feature is OFF here, so
/// `default_cert_decompressors()` is EMPTY and rustls would reject any
/// `CompressedCertificate` with `SelectedUnofferedCertCompression`, failing the
/// handshake. Installing this decompressor closes that gap WITHOUT a new
/// dependency, reusing the same `flate2` zlib backend the TCP camouflage path
/// already uses for the identical message (`safari26.rs`
/// `parse_compressed_certificate_body`).
///
/// In production the QUIC client only ever reaches ParallaX's own QUIC server,
/// whose `server_config` installs no compressor, so today this is latent
/// robustness/fidelity hardening; it becomes load-bearing the moment the
/// masquerade fronts a real (compressing) H3 origin.
#[derive(Debug)]
struct Flate2ZlibCertDecompressor;

/// Installed on the QUIC client config's `cert_decompressors`.
static FLATE2_ZLIB_CERT_DECOMPRESSOR: &dyn CertDecompressor = &Flate2ZlibCertDecompressor;

impl CertDecompressor for Flate2ZlibCertDecompressor {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        // rustls pre-sizes `output` to the server's declared `uncompressed_len`
        // (already bounded by rustls against `CERTIFICATE_MAX_SIZE_LIMIT` before
        // this call, so a lying length cannot force a large allocation here). The
        // contract — mirroring rustls's own `zlib-rs` decompressor — is to fill
        // `output` EXACTLY: a stream that inflates to more or fewer bytes than
        // `output.len()`, or is otherwise malformed, must fail.
        let mut decompress = flate2::Decompress::new(/* zlib_header = */ true);
        match decompress.decompress(input, output, flate2::FlushDecompress::Finish) {
            // StreamEnd having consumed all input and filled the buffer exactly is
            // the only success: total_out == output.len() rejects a short inflate,
            // and BufError on a full output buffer rejects an over-long one (the
            // decoder cannot drain the remaining stream).
            Ok(flate2::Status::StreamEnd)
                if decompress.total_in() == input.len() as u64
                    && decompress.total_out() == output.len() as u64 =>
            {
                Ok(())
            }
            _ => Err(DecompressionFailed),
        }
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

/// Active keep-alive interval. The fast-plane connection is retained across the
/// probe and then sits idle through the TCP control exchange (PX1P) and the
/// outbound target connect before the relay's first stream byte; keep-alive PING
/// frames keep it (and any NAT binding) alive across that gap without traffic.
///
/// This must stay comfortably below [`UDP_LOCAL_IDLE_TIMEOUT`] so a healthy idle
/// connection keeps refreshing the local idle timer and is never reaped. quinn
/// defaults keep-alive to None (off).
const UDP_KEEP_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// LOCAL idle-timeout backstop for reaping a black-holed connection.
///
/// This is the only transport-level connection reaper: quinn-proto 0.11 loss
/// detection on a vanished peer only PTO-retransmits the unacknowledged
/// keep-alive PINGs — it does NOT terminate the connection — so without an idle
/// timeout a peer that silently disappears would pin its connection and up to
/// `conn_window` (16 MiB) of receive buffers forever. A generous 60 s timeout
/// reclaims those resources well after [`UDP_KEEP_ALIVE_INTERVAL`] (15 s) has had
/// several chances to refresh a live connection.
///
/// CRITICAL — this is purely LOCAL and does NOT change the on-wire advertised
/// value. The Safari-26 H3 wire shape advertises `max_idle_timeout = 0` (the
/// confirmed CFNetwork value), and that 0 is emitted by the hand-encoded `0x39`
/// blob in `safari_crypto.rs` (`start_session` substitutes our blob for quinn's
/// `params.write()`), so quinn's config value here never reaches the wire — it
/// only drives quinn's local idle timer. The advertised `0` (no peer-negotiated
/// idle timeout) and this locally-enforced backstop are independent: the peer
/// sees Safari fidelity while this endpoint still reaps a dead connection.
const UDP_LOCAL_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Flow-control windows for the fast-plane relay's single reliable stream.
///
/// These EQUAL the values advertised in the Safari-26 H3 `quic_transport_parameters`
/// blob (see `safari_crypto.rs`): the per-stream window is `initial_max_stream_data_*`
/// (2 MiB) and the connection window is `initial_max_data` (16 MiB). Keeping quinn's
/// ENFORCED flow control equal to the advertised wire bytes closes the
/// advertised-vs-actual gap — a censor that decrypts the QUIC v1 Initial sees
/// transport params that match the connection's real behaviour, and the throughput
/// is capped at Safari's level (exceeding Safari is itself detectable).
///
/// The connection window (16 MiB) is larger than the per-stream window (2 MiB),
/// matching real Safari/Chrome H3 (connection > stream); a single shared window
/// would emit all four flow-control params equal, a shape no browser sends.
///
/// HARD PRE-ENABLE GATE — DoS surface. BEFORE setting `[udp].enabled = true` in
/// production, a global concurrent-QUIC-relay cap (analogous to the TCP carrier's
/// kernel-splice relay cap, `MAX_CONCURRENT_KERNEL_SPLICE_RELAYS`) is REQUIRED.
/// This is the DoS surface: the relay endpoint grants each authenticated peer a
/// `conn_window` (16 MiB) connection-level receive window, and a peer that stalls
/// its read side can pin that full window; with no global cap the aggregate
/// worst-case un-drained buffer is 16 MiB x the 16384 per-endpoint connection
/// limit (~256 GiB). The local idle-timeout backstop ([`UDP_LOCAL_IDLE_TIMEOUT`])
/// reaps a black-holed peer but does NOT bound concurrent live stallers; only a
/// concurrency cap does.
const UDP_STREAM_RECV_WINDOW: u32 = safari_crypto::SAFARI_TP_INITIAL_MAX_STREAM_DATA as u32;
const UDP_CONN_RECV_WINDOW: u32 = safari_crypto::SAFARI_TP_INITIAL_MAX_DATA as u32;

/// Shared QUIC transport tuning for the fast-plane endpoints.
///
/// The flow-control and stream limits EQUAL the values advertised in the Safari-26
/// H3 transport-parameters blob (`safari_crypto.rs`), so quinn's enforced behaviour
/// matches the camouflaged wire bytes (no advertised-vs-actual gap). The one
/// asymmetry is `peer_bidi`: it sets `initial_max_streams_bidi`, i.e. how many bidi
/// streams THIS endpoint grants the PEER to open.
///
/// * Client: `peer_bidi = 0` — the client grants the server NO server-initiated
///   bidi streams, matching Safari's advertised `initial_max_streams_bidi = 0`. The
///   relay's client-initiated bidi stream is governed by the SERVER's grant, not
///   this value, so the relay still works.
/// * Server: `peer_bidi = 1` — the server grants the client exactly one bidi stream,
///   which is the relay's single multiplexed stream (client `open_bi` /
///   server `accept_bi`). The server emits its own quinn transport params (not the
///   Safari blob), so it is not bound to the client's advertised bidi value.
///
/// The advertised `max_idle_timeout = 0` (Safari fidelity) is emitted by the
/// hand-encoded `0x39` blob in `safari_crypto.rs`, NOT from quinn's config, so
/// this function sets a LOCAL idle-timeout backstop ([`UDP_LOCAL_IDLE_TIMEOUT`])
/// to reap a black-holed connection without changing the wire value; liveness of
/// a healthy connection rests on the keep-alive (see [`UDP_KEEP_ALIVE_INTERVAL`]).
fn udp_transport_config(peer_bidi: u32) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    // LOCAL idle-timeout backstop ONLY: the wire advertises max_idle_timeout = 0
    // (Safari's value), hand-encoded in safari_crypto.rs independently of this
    // config, so this value never reaches the peer — it just lets quinn reap a
    // vanished peer's connection (loss detection alone never would; see
    // UDP_LOCAL_IDLE_TIMEOUT). Keep-alive refreshes the timer for a live
    // connection across the probe -> accept_bi/open_bi gap.
    transport.max_idle_timeout(Some(
        UDP_LOCAL_IDLE_TIMEOUT
            .try_into()
            .expect("60s fits a QUIC idle-timeout VarInt"),
    ));
    transport.keep_alive_interval(Some(UDP_KEEP_ALIVE_INTERVAL));

    // Stream limits and flow-control windows EQUAL the advertised Safari values:
    // bidi grant per the `peer_bidi` asymmetry above; uni = 8
    // (`initial_max_streams_uni`); per-stream window 2 MiB; connection window
    // 16 MiB. The relay carries its payload over a single client-initiated BIDI
    // stream; the reachability probe rides a uni-stream round-trip (one client uni
    // + one server uni), well within the advertised 8 uni budget. Granting the
    // advertised 8 uni is bounded by the 2 MiB per-uni-stream window under the
    // 16 MiB connection window; send_window matches the connection window so the
    // sender is not the bottleneck.
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(peer_bidi));
    transport.max_concurrent_uni_streams(
        quinn::VarInt::from_u64(safari_crypto::SAFARI_TP_MAX_STREAMS_UNI)
            .expect("8 fits a QUIC VarInt"),
    );
    transport.receive_window(quinn::VarInt::from_u32(UDP_CONN_RECV_WINDOW));
    transport.stream_receive_window(quinn::VarInt::from_u32(UDP_STREAM_RECV_WINDOW));
    transport.send_window(u64::from(UDP_CONN_RECV_WINDOW));

    // Disable QUIC datagrams (RFC 9221). Safari-26 H3 advertises no
    // `max_datagram_frame_size` for plain H3 (it sends no datagrams), so the
    // camouflaged transport params omit 0x20; disabling datagrams here makes
    // quinn's enforced behaviour match the wire (it neither advertises 0x20 in its
    // own `params.write()` nor accepts datagram frames). The reachability probe no
    // longer needs them — it rides a QUIC uni-stream round-trip (see `probe.rs`),
    // which uses the advertised `initial_max_streams_uni = 8` budget. quinn's
    // default enables datagrams (`datagram_receive_buffer_size = Some(..)`), so this
    // explicit `None` is required.
    transport.datagram_receive_buffer_size(None);

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
    // Server grants the client exactly one bidi stream (the relay's stream).
    config.transport_config(udp_transport_config(1));
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

    // The Safari profile advertises `compress_certificate` = zlib, so install a
    // zlib decompressor to handle a server that answers with a
    // `CompressedCertificate`. The vendored rustls leaves `cert_decompressors`
    // empty (its `zlib` feature is off to avoid the `zlib-rs` dep), which would
    // otherwise make any compressed cert fail the handshake; this reuses the
    // existing `flate2` backend (no new dependency). See
    // [`Flate2ZlibCertDecompressor`].
    tls.cert_decompressors = vec![FLATE2_ZLIB_CERT_DECOMPRESSOR];

    // S6: the Safari-26 H3 Session is the DEFAULT QUIC client backend. The rustls
    // config carries the production `safari_ch_profile`, so the vendored-rustls
    // ClientHello assembly (S1) emits the exact Safari wire shape, and the Safari
    // Session substitutes the hand-encoded ascending 0x39 transport-param blob
    // (S4) for quinn's `params.write()`. Cold-start ONLY: resumption is disabled
    // so no `pre_shared_key` / `early_data` is emitted (`psk_key_exchange_modes`
    // is still present in the profile). True 0-RTT is a later capture-gated slice.
    tls.resumption = rustls::client::Resumption::disabled();

    let mut grease_seed = [0_u8; 5];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut grease_seed);
    let grease = crate::tls::safari_shape::GreaseSet::from_seed(grease_seed);
    tls.safari_ch_profile = Some(Arc::new(crate::tls::safari_shape::safari_h3_ch_profile(
        grease,
    )));

    let crypto: Arc<dyn quinn::crypto::ClientConfig> = Arc::new(
        safari_crypto::SafariQuicClientConfig::new(Arc::new(tls))
            .ok_or_else(|| UdpTransportError::TlsConfig("no QUIC initial cipher suite".into()))?,
    );

    let mut config = quinn::ClientConfig::new(crypto);
    // Client grants the server NO bidi streams (Safari advertises bidi=0); the
    // relay's client-initiated bidi is governed by the server's grant above.
    config.transport_config(udp_transport_config(0));
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

    use super::server_config;

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

        // PRODUCTION client builder: zero-length source connection id (Safari
        // fidelity), so the loopback pair exercises the real wire shape.
        let client_endpoint = super::endpoint::bind_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(AcceptAnyServerCert),
        )
        .unwrap();

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

    use quinn::Endpoint;

    use super::test_support::{loopback_pair, self_signed_cert, AcceptAnyServerCert};
    use super::*;

    /// Non-empty PSK for the exporter-bound auth-token round-trip assertions.
    const TEST_PSK: &[u8] = b"parallax-tudp-loopback-psk-012345";

    /// Proves the QUIC fast-plane plumbing on loopback: connection establishment,
    /// a uni-stream round-trip (the transport the reachability probe now uses), and
    /// that the RFC 5705 keying-material exporter (open question #1 for the
    /// exporter-bound auth token) is available and agrees on both ends under the
    /// aws-lc-rs backend.
    #[tokio::test]
    async fn quic_loopback_stream_and_exporter_round_trip() {
        let (cert, key) = self_signed_cert();
        let server_endpoint = Endpoint::server(
            server_config(cert, key).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        // PRODUCTION client builder (zero-length source connection id).
        let client_endpoint = super::endpoint::bind_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(AcceptAnyServerCert),
        )
        .unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("server-side connection");
            // Echo the client's uni-stream request back on a server uni stream.
            let mut recv = tokio::time::timeout(Duration::from_secs(5), conn.accept_uni())
                .await
                .expect("server accept_uni timeout")
                .expect("accept client uni stream");
            let got = recv.read_to_end(64).await.expect("read client uni payload");
            let mut send = conn.open_uni().await.expect("server open_uni");
            send.write_all(&got).await.expect("echo uni payload");
            send.finish().expect("finish echo uni stream");
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

        let mut send = conn.open_uni().await.expect("client open_uni");
        send.write_all(b"ping").await.expect("client write uni");
        send.finish().expect("finish client uni stream");
        let mut recv = tokio::time::timeout(Duration::from_secs(5), conn.accept_uni())
            .await
            .expect("client accept_uni timeout")
            .expect("accept echoed uni stream");
        let echo = recv.read_to_end(64).await.expect("read echoed uni payload");
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

    /// The relay endpoint's QUIC transport config matches the advertised Safari
    /// values: the server grants the client exactly ONE bidi stream (the relay's
    /// stream; a second is denied) and the advertised EIGHT uni streams
    /// (`initial_max_streams_uni = 8`). It also proves the CRITICAL property that
    /// after the bidi=0-on-client / bidi=1-on-server split, the client-initiated
    /// relay stream still opens AND transfers data both directions. TransportConfig
    /// fields have no getters, so this drives a loopback pair and observes the
    /// granted/denied stream credit.
    #[tokio::test]
    async fn quic_transport_config_bounds_streams_to_single_bidi_relay() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        // (1) The client-initiated relay bidi stream opens (governed by the
        // server's bidi=1 grant, NOT the client's advertised bidi=0) and the server
        // accepts it. Keep both ends' handles alive (dropping the send half would
        // free the bidi credit and defeat assertion (3)).
        let (mut s1, mut r1) = client_conn.open_bi().await.expect("open_bi #1");
        s1.write_all(b"ping").await.expect("write stream #1");
        let (mut srv_s, mut srv_r) =
            tokio::time::timeout(Duration::from_secs(2), server_conn.accept_bi())
                .await
                .expect("server must accept the first bidi stream")
                .expect("accept_bi #1");

        // (1b) CRITICAL: data transfers both directions over the relay stream.
        let mut got = [0_u8; 4];
        srv_r
            .read_exact(&mut got)
            .await
            .expect("server reads client->server bytes");
        assert_eq!(&got, b"ping", "client->server relay data must arrive");
        srv_s.write_all(b"pong").await.expect("server echoes");
        let mut echoed = [0_u8; 4];
        r1.read_exact(&mut echoed)
            .await
            .expect("client reads server->client bytes");
        assert_eq!(&echoed, b"pong", "server->client relay data must arrive");

        // (2) Uni streams: the server advertises the Safari value of 8, so the
        // client can open a uni stream (and several more), unlike the old
        // forbidden-uni posture. Opening one must succeed promptly.
        tokio::time::timeout(Duration::from_secs(2), client_conn.open_uni())
            .await
            .expect("uni open must not time out (server grants 8)")
            .expect("first uni stream opens");

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

    /// The `flate2` zlib cert decompressor installed on the QUIC client config
    /// round-trips a real zlib stream into an exactly-sized buffer and rejects
    /// every malformed/length-mismatched input — the contract rustls's
    /// `ExpectCompressedCertificate` relies on (it pre-sizes `output` to the
    /// server's declared `uncompressed_len` and treats any failure as a fatal
    /// `InvalidCertCompression`).
    #[test]
    fn flate2_zlib_cert_decompressor_round_trips_and_rejects_malformed() {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;

        let plaintext = b"the quick brown fox jumps over the lazy dog, repeatedly. \
                          the quick brown fox jumps over the lazy dog, repeatedly.";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(plaintext).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressor = Flate2ZlibCertDecompressor;
        assert_eq!(
            decompressor.algorithm(),
            CertificateCompressionAlgorithm::Zlib
        );

        // Exact-length buffer: succeeds and reproduces the plaintext.
        let mut out = vec![0u8; plaintext.len()];
        decompressor
            .decompress(&compressed, &mut out)
            .expect("exact-length zlib decompress must succeed");
        assert_eq!(out, plaintext, "decompressed bytes must match the original");

        // Declared length too SHORT: the stream inflates past the buffer; reject.
        let mut short = vec![0u8; plaintext.len() - 1];
        assert!(
            decompressor.decompress(&compressed, &mut short).is_err(),
            "a too-short output buffer must fail (over-long inflation)"
        );

        // Declared length too LONG: the stream fills fewer bytes than the buffer;
        // reject (total_out != output.len()).
        let mut long = vec![0u8; plaintext.len() + 1];
        assert!(
            decompressor.decompress(&compressed, &mut long).is_err(),
            "a too-long output buffer must fail (short inflation)"
        );

        // Garbage input: not a valid zlib stream; reject without panicking.
        let mut out = vec![0u8; plaintext.len()];
        assert!(
            decompressor
                .decompress(b"not a zlib stream at all", &mut out)
                .is_err(),
            "malformed input must fail"
        );
    }

    /// End-to-end proof of the fix: a QUIC server that answers with a
    /// `CompressedCertificate` (zlib) completes the handshake with the PRODUCTION
    /// `client_config`. Before installing the `flate2` decompressor, the vendored
    /// rustls had no zlib decompressor (its `zlib` feature is off), so rustls
    /// rejected the compressed cert with `SelectedUnofferedCertCompression` and
    /// the handshake failed despite the ClientHello advertising
    /// `compress_certificate` = zlib. The production server installs no compressor,
    /// so this test builds a compressing server config to exercise the receive
    /// path the advertised extension promises a real (e.g. CDN-fronted) origin
    /// could use.
    #[tokio::test]
    async fn quic_client_completes_handshake_with_compressed_certificate() {
        use flate2::{write::ZlibEncoder, Compression};
        use rustls::compress::{CertCompressor, CompressionFailed, CompressionLevel};
        use std::io::Write;

        /// Test-only zlib certificate compressor (flate2) so the loopback server
        /// emits a `CompressedCertificate`; production servers ship none.
        #[derive(Debug)]
        struct Flate2ZlibCertCompressor;

        impl CertCompressor for Flate2ZlibCertCompressor {
            fn compress(
                &self,
                input: Vec<u8>,
                _level: CompressionLevel,
            ) -> Result<Vec<u8>, CompressionFailed> {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&input).map_err(|_| CompressionFailed)?;
                encoder.finish().map_err(|_| CompressionFailed)
            }

            fn algorithm(&self) -> CertificateCompressionAlgorithm {
                CertificateCompressionAlgorithm::Zlib
            }
        }

        static COMPRESSOR: &dyn CertCompressor = &Flate2ZlibCertCompressor;

        // Server config mirroring production `server_config`, but with a zlib
        // compressor installed so it answers a zlib-advertising client with a
        // CompressedCertificate.
        let (cert, key) = self_signed_cert();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(camouflage_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        tls.alpn_protocols = vec![UDP_ALPN.to_vec()];
        tls.cert_compressors = vec![COMPRESSOR];
        let crypto = QuicServerConfig::try_from(Arc::new(tls)).unwrap();
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_cfg.transport_config(udp_transport_config(1));

        let server_endpoint = Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        // Production client config (carries the Safari profile advertising zlib +
        // the flate2 decompressor under test) via the production endpoint builder
        // (zero-length source connection id).
        let client_endpoint = super::endpoint::bind_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(AcceptAnyServerCert),
        )
        .unwrap();

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

        // The handshake completing is the assertion: a missing/incompatible
        // decompressor would fail `.connect(..).await` with the rustls alert.
        let client_conn = tokio::time::timeout(
            Duration::from_secs(5),
            client_endpoint
                .connect(server_addr, "localhost")
                .expect("start connect"),
        )
        .await
        .expect("handshake with a CompressedCertificate server must not time out")
        .expect("client must complete the handshake despite the compressed certificate");

        let _server_conn = acceptor.await.expect("accept task");

        // The client received and decompressed the server's certificate chain.
        let peer = client_conn
            .peer_identity()
            .expect("peer identity present after a verified handshake")
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .expect("peer identity is the server certificate chain");
        assert!(
            !peer.is_empty(),
            "the decompressed certificate chain must be non-empty"
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
        t.send_window(u64::from(window));
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
        if std::env::var_os("PLX_RUN_NET_BENCH").is_none() {
            eprintln!("skipping: set PLX_RUN_NET_BENCH=1 to run this heavy QUIC benchmark");
            return;
        }
        let n = 16 * 1024 * 1024; // 16 MiB download per cell
        let delay = Duration::from_millis(80); // ~160 ms RTT
        let loss_levels = [0.0_f64, 0.01, 0.03];

        // "old": the previous 1.25 MB window. "prod-fixed": the real shipping
        // config (udp_transport_config; the server grant is bidi=1 so the client's
        // download stream opens). Same BBR, same relay.
        let cases: [(&str, Arc<quinn::TransportConfig>); 2] = [
            ("old-1.25MB", relay_test_transport(1_250_000)),
            ("prod-fixed", udp_transport_config(1)),
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
        t.send_window(u64::from(window));
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
        // Block for the first byte so the initial RTT is excluded, then start the
        // clock and the byte counter together (the first read's bytes are dropped
        // from the numerator so numerator and denominator cover the same window).
        let _ = recv.read(&mut buf).await.expect("read");
        let start = Instant::now();
        let mut got = 0_usize;
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
        if std::env::var_os("PLX_RUN_NET_BENCH").is_none() {
            eprintln!("skipping: set PLX_RUN_NET_BENCH=1 to run this heavy QUIC benchmark");
            return;
        }
        let delay = Duration::from_millis(80); // ~160 ms RTT
        let loss = 0.03; // 3% — the worst modeled cross-border loss
        let window = UDP_STREAM_RECV_WINDOW;
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
