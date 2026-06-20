//! Differential transparency of the unauthenticated-traffic fallback splice
//! (Phase 2 #6, Part B).
//!
//! ParallaX's security promise for traffic it cannot authenticate (a plain TLS
//! ClientHello carries no ParallaX authenticator, so `decide_inbound` returns
//! `Fallback(AuthFailed)`) is that the server *splices* the whole TLS flow --
//! including the first record it already read -- straight to a real fallback
//! origin. A prober or a real client must then see the genuine origin, exactly
//! as if it had dialed the origin directly.
//!
//! These tests prove that with two REAL live TLS endpoints. A `rustls` client
//! reaches a `rustls` origin (a) DIRECTLY and (b) THROUGH the ParallaX fallback
//! splice, and we assert the two paths reach the SAME TLS outcome on success and
//! FAIL identically when the origin is untrusted:
//!
//! * Success: with a verifier trusting the origin's cert and the matching SNI,
//!   both handshakes succeed and their captured [`HandshakeInfo`] are EQUAL --
//!   same protocol version, cipher suite, key-exchange group, and peer
//!   certificate chain. The splice is byte-transparent at the TLS-outcome level.
//! * Failure: with an EMPTY trust store (trusts nothing), both handshakes fail
//!   and fail with the SAME rustls error *category* (the `Error` variant, not
//!   its inner detail). The splice adds no certificate-validation soft spot and
//!   emits no extra alert that would change the failure the client observes.
//!
//! The client runs full, genuine WebPKI verification (real chain build + name
//! check, fails closed as `UnknownIssuer` against an empty trust store). The
//! ONE concession is that the validity clock is pinned to a moment inside the
//! camouflage fixture's window: that fixture is a deliberately short-lived
//! (1-day) self-signed leaf that has since lapsed, so an unmodified rustls
//! verifier rejects it with `ExpiredContext` on BOTH paths. Pinning the clock
//! neutralises the expiry -- and only the expiry -- leaving the
//! trusted-vs-untrusted differential we are testing fully intact (see
//! [`PinnedTimeVerifier`]).
//!
//! This is DIFFERENTIAL transparency: proxied-vs-direct equivalence plus
//! equivalent failure. It deliberately does NOT assert byte-identical record
//! sequences (unsound over a TCP byte pump -- record boundaries and coalescing
//! are not preserved end to end) nor any FIN/RST behaviour (the rejection-path
//! timing/teardown is covered by `rejection_path_*` in
//! `src/handshake/server.rs`). The 0/1/2-DH reject timing test is likewise out
//! of scope here.
//!
//! The live-socket tests are `#[ignore]`d ("requires loopback TCP sockets",
//! matching the repo convention) and run with:
//!   cargo test --test splice_equivalence -- --ignored --test-threads=1

use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use parallax::config::{ServerConfig, TrafficConfig, UdpConfig};
use parallax::crypto::identity;
use parallax::crypto::session::X25519KeyPair;
use parallax::handshake::server;

// ---------------------------------------------------------------------------
// Test fixtures.
//
// The camouflage cert/key and the rustls server-config builder live in
// `#[cfg(test)]` modules inside `src/`, so they are unreachable from an
// integration test. They are pure test fixtures, so we duplicate them here
// (copied verbatim from `src/client/runtime.rs`). The cert is a self-signed
// leaf for `example.com`; we trust *it* directly as a root, which is exactly
// what makes a self-signed origin verifiable in the success case.
// ---------------------------------------------------------------------------

const CAMOUFLAGE_CERT_DER_B64: &str = concat!(
    "MIIC9jCCAd6gAwIBAgIJAPNzR81y9p7pMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4X",
    "DTI2MDUxNjEyNDA0NloXDTI2MDUxNzEyNDA0NlowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3",
    "DQEBAQUAA4IBDwAwggEKAoIBAQCnjSfVPv1Xy5razuOYABOSvGvlddr0MMVWQCSmjE47PMQEzvETytmburNZEdqQ",
    "BzSjDVxTExxd8eIHFTp8ylkztsxma5yJftQo81uqxZEnwT00tJRaazg10OYTf0ZrH6PMNC2izwJML0GkYz7s6OMF",
    "qImMCG3v00PIAYknlDrlKoDjdmANco8V5FNrbQYp2kqIcFyXrbgYurcMIKCE9Wu8L2W0oKhW6DNyRVoBGTn5zN1w",
    "jXLBO+6TJsBj4thI4tM0mUcLc+YohOfoGVq7na/wgCESoK1B+m8PdrXIEuZ7gZ0x3ZqdZ7jxL23sTmkfm+AeNdp+",
    "XshxAS77l3dcrAV9AgMBAAGjRzBFMBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAkGA1UdEwQCMAAwCwYDVR0PBAQD",
    "AgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4IBAQA8KHWHoA4otNmYh9q+X8cZnYx9y0LU",
    "NfdbHLR8ebnk/9T+/WP5CgIGWvn3+L2ulEvuSMhDC23C20SnX0h815JfMBY/PiAbLKGp3UXrgIq1dWc8t40HQBGR",
    "uBKi2fc743Sup5kPQgNAqev+8kKs4WFDXaWBpdwqI55PADVPOX66h0WiObB7crp5YTEVEe37G6UsxX40HUAAZJXt",
    "CI9eqPLISNuuNOAjJEMDMjdRH7ZjcMyrqQSweuKLAwdvUam8UJQsUNe7rM2II6GlgPS/mKZx1Nihn70GIo0yu0Bs",
    "xc9cpSHbggzQarE3g8WRp+jI9GpWXXdjno7cyim5KEQVMZcz",
);
const CAMOUFLAGE_KEY_DER_B64: &str = concat!(
    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCnjSfVPv1Xy5razuOYABOSvGvlddr0MMVWQCSm",
    "jE47PMQEzvETytmburNZEdqQBzSjDVxTExxd8eIHFTp8ylkztsxma5yJftQo81uqxZEnwT00tJRaazg10OYTf0Zr",
    "H6PMNC2izwJML0GkYz7s6OMFqImMCG3v00PIAYknlDrlKoDjdmANco8V5FNrbQYp2kqIcFyXrbgYurcMIKCE9Wu8",
    "L2W0oKhW6DNyRVoBGTn5zN1wjXLBO+6TJsBj4thI4tM0mUcLc+YohOfoGVq7na/wgCESoK1B+m8PdrXIEuZ7gZ0x",
    "3ZqdZ7jxL23sTmkfm+AeNdp+XshxAS77l3dcrAV9AgMBAAECggEAcsH8cVMWRAbBBnLDcX1D6rHBGMVy9ONelaeT",
    "MrtQbcQ94ak3dz3tc3sZkbznvNQimjbxcDjbqgCctgs1JvmUxRXDw7aa3ZWPjIi51SpCND9nQ20XWyKqujldDCeV",
    "PJPMJXXrd+JfCX0ocYZEOBF+RIbdxpqTabqCZz+eCAy/les95pv5YkkAjxEJkzhEfFTJtJRVIjIUBL/Gg8KwG4qs",
    "5nESoD1oiNGr8tgnbsS2KNXdozIsM1awitqNJ7drpDpEpkwDUoQGAqzuvyDiN2pPqsyg1UwZWH8kuA9RyXIAOWQo",
    "R9rIX/rUsYB5F4tKg6Tdy0n9Jb9ytTINYaletNjuIQKBgQDSEzvmO4Zan1Bz+0Eb4NWfnU1yyGKb7bBFBvcuigXP",
    "W/+as1yET2Zkc4qQBudye7DUgr+zXj0s+ZeXvv+HeGggD3Blnq5bl+gPkiPSeGd24QkfO38MF2RTpW5SoUT6Z9vT",
    "iaHjIgkwZIgQf3dfSPV/MskRVemqxB5o+Phd4NRzpQKBgQDMLhkoYeRurmFQ3iuWCLOaHWAwtA28j3ymknsHyP6E",
    "OkiHBVl3YWTpZ1ZcDGMJznHdkSrj4mNsnnDM71iFM0srgKKp07T4bumowOhmyeg/hYIblFGSoZS/nTl8tAusNzXt",
    "RJeVLa9GjkFjXihiC3E+t3J2s9ij2eE8bAM0tatC+QKBgCsAQuea0aKlL8u955L0T+YPRfYz7HNskQNgLKK7H/tV",
    "IpohEtQGiLgRKpDWyPOXPBgT93eY177oDE7EivvI+s9tOZ2jgJ9BFgBx8qE3gj5ETCC3hgcMlr3EhDOnzT3Qmp/P",
    "cXLT2butKGjwHphDj/UMiTniMyWAZZUpOXXF+tb9AoGAEKvG5BQyGZNlYLvzJRnqyC+T1gYthPLWQ6d8IiOYHGXB",
    "3DxklKnAGoqUc4mTYI6Zn3Sl4ttuMMUzApicSqvofFHRdjpR8WLk8yFlGFdt/hnBiMzwaB+HTKnisrrkpRgQ8CGE",
    "muqTABjHX/ylIXQ7t9o0n1qJ2r8Ec/GBxYD7zckCgYBZzU7u9Ujq8XL+Ok6T2Zqgf3O8H3VBlKPjeYpfH6mqBRdj",
    "+773IfoifCs19Y31OL8Sb28N98XnutTlHo6xs4li0zE2KDN1O3i00K7S0dO3250Fr1QSm86CML8fSDuS1BcuMHH+",
    "RNkQkMb9Q49K23t6B1s0xnIFfBarwbusw9onAw==",
);

/// SNI / cert subject the camouflage leaf is issued for.
const ORIGIN_SNI: &str = "example.com";

/// Any 32-byte PSK works: the rustls client never presents a ParallaX
/// authenticator, so `decide_inbound` always takes the fallback path regardless
/// of the PSK value.
const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

fn camouflage_cert_der() -> CertificateDer<'static> {
    CertificateDer::from(STANDARD.decode(CAMOUFLAGE_CERT_DER_B64).unwrap())
}

/// rustls SERVER config serving the camouflage cert. Copied from
/// `rustls_server_config` in `src/client/runtime.rs`. MUST use
/// `builder_with_provider(aws_lc_rs)`: rustls is compiled with both ring and
/// aws_lc_rs providers and installs NO process default, so the bare `builder()`
/// would panic (see the `Cargo.toml` rustls comment).
fn rustls_server_config() -> Arc<rustls::ServerConfig> {
    let cert_der = camouflage_cert_der();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        STANDARD.decode(CAMOUFLAGE_KEY_DER_B64).unwrap(),
    ));
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("aws_lc_rs provider supports rustls default protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap(),
    )
}

/// rustls CLIENT config whose certificate verification is delegated to
/// `verifier`. Same provider rule as above. We install a custom verifier (rather
/// than `with_root_certificates`) for ONE reason: the camouflage fixture is a
/// deliberately short-lived (1-day) self-signed leaf that has since expired, so
/// rustls's stock verifier rejects it with `ExpiredContext` on BOTH paths. The
/// custom verifier ([`PinnedTimeVerifier`]) performs the SAME genuine chain +
/// name verification as the stock one -- it still fails closed with
/// `UnknownIssuer` against an empty trust store -- but pins the validity clock
/// to a moment inside the fixture's window so the *expiry* (and only the expiry)
/// is neutralised. The trusted-vs-untrusted differential we are testing is fully
/// preserved.
fn rustls_client_config(verifier: Arc<dyn ServerCertVerifier>) -> Arc<rustls::ClientConfig> {
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("aws_lc_rs provider supports rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth(),
    )
}

/// A `ServerCertVerifier` that does real WebPKI chain + name verification
/// against a fixed root store, but with the validity clock PINNED to
/// [`PINNED_NOW`] (a moment inside the camouflage fixture's 1-day window). It is
/// otherwise faithful: it fails closed (`UnknownIssuer`) when the chain does not
/// reach a trusted anchor, and delegates handshake-signature verification to the
/// aws_lc_rs provider's algorithms. Only the cert's *expiry* is bypassed.
#[derive(Debug)]
struct PinnedTimeVerifier {
    roots: rustls::RootCertStore,
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

/// Unix seconds inside the camouflage leaf's validity window (issued
/// 2026-05-16 12:40:46Z, `notAfter` 2026-05-17 12:40:46Z = 1779021646). Roughly
/// the window midpoint, so it is comfortably `notBefore < PINNED_NOW < notAfter`.
const PINNED_NOW: u64 = 1_778_978_446;

impl PinnedTimeVerifier {
    fn new(roots: rustls::RootCertStore) -> Self {
        Self {
            roots,
            supported_algs: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedTimeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime, // ignored: we pin the clock to PINNED_NOW (see above)
    ) -> Result<ServerCertVerified, rustls::Error> {
        // `ParsedCertificate` is re-exported under `rustls::server` (it is shared
        // machinery); the `verify_*` free functions live under `rustls::client`.
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
        // Genuine chain build to a trusted anchor; fails `UnknownIssuer` if the
        // root store is empty -- this is the differential the tests rely on.
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(PINNED_NOW)),
            self.supported_algs.all,
        )?;
        rustls::client::verify_server_name(&cert, server_name)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Verifier that trusts the camouflage leaf directly (success case).
fn trusting_verifier() -> Arc<dyn ServerCertVerifier> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(camouflage_cert_der()).unwrap();
    Arc::new(PinnedTimeVerifier::new(roots))
}

/// Verifier with an EMPTY trust store: trusts nothing, so every chain fails
/// `UnknownIssuer` (failure case).
fn untrusting_verifier() -> Arc<dyn ServerCertVerifier> {
    Arc::new(PinnedTimeVerifier::new(rustls::RootCertStore::empty()))
}

/// A minimal valid `ServerConfig` whose fallback splices to `fallback_addr`.
/// The keys only have to *decode* (the fallback path never uses them for a
/// handshake), but they must be real keypairs because `ServerRuntimeSecrets`
/// validates them. `data_target` is unset: the fallback path ignores it.
fn fallback_server_config(fallback_addr: SocketAddr) -> ServerConfig {
    let server_keys = X25519KeyPair::generate();
    let server_identity_keys = identity::keypair();
    // Use a private tempdir (like prober_loop.rs / chaos_liveness.rs) rather than
    // a predictable name in the shared temp dir. The fallback path never opens
    // this file, but a unique, non-world-guessable path is the right default; we
    // leak the handle so the path stays valid for the whole test process.
    let replay_dir = tempfile::tempdir().unwrap();
    let replay_cache_path = replay_dir.path().join("parallax-replay.cache");
    std::mem::forget(replay_dir);
    ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        fallback_addr: fallback_addr.to_string(),
        data_target: None,
        private_key: STANDARD.encode(server_keys.private).into(),
        identity_secret_key: STANDARD.encode(&server_identity_keys.secret).into(),
        replay_cache_path,
        // The fallback path never touches the replay cache; any positive
        // capacity is fine. (`DEFAULT_REPLAY_CACHE_CAPACITY` is `pub(crate)` and
        // unreachable from an integration test.)
        replay_cache_capacity: 1024,
        authorized_sni: vec![ORIGIN_SNI.to_owned()],
        strict_tls13: true,
        max_concurrent_per_source_v4: 256,
        max_concurrent_per_source_v6: 256,
        source_ipv6_prefix_len: 64,
        first_record_wait_floor_ms: 8_000,
        first_record_wait_jitter_ms: 7_000,
        fallback_idle_floor_ms: 600_000,
        fallback_idle_jitter_ms: 0,
        tcp_congestion: None,
    }
}

// ---------------------------------------------------------------------------
// Live endpoints.
// ---------------------------------------------------------------------------

/// Spawn the rustls ORIGIN on `127.0.0.1:0`, returning its bound address and an
/// accept loop that completes TLS handshakes for `expected` connections. Each
/// connection is driven by a raw `ServerConnection` byte pump (mirroring
/// `run_camouflage_tls_server` in `src/client/runtime.rs`) because the crate
/// has no `tokio-rustls` dependency.
async fn spawn_origin(expected: usize) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..expected {
            let (stream, _) = listener.accept().await.unwrap();
            // Each origin connection is independent; serve it on its own task so
            // a client that aborts mid-handshake (the failure case) cannot stall
            // the next accept.
            tokio::spawn(async move {
                let _ = serve_origin_tls(stream).await;
            });
        }
    });
    (addr, task)
}

/// Complete one TLS handshake as the origin, then idle briefly so the client
/// drives the close. Returns `Err` if the peer aborts (expected in the
/// untrusted case, where the client sends a fatal alert and disconnects).
async fn serve_origin_tls(mut stream: TcpStream) -> std::io::Result<()> {
    let mut conn =
        rustls::ServerConnection::new(rustls_server_config()).expect("rustls server config");
    let mut buf = [0_u8; 4096];

    while conn.is_handshaking() {
        flush_tls(&mut conn, &mut stream).await?;
        if !conn.wants_read() {
            continue;
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            // Peer hung up before completing the handshake (untrusted case).
            return Ok(());
        }
        let mut cursor = Cursor::new(&buf[..n]);
        conn.read_tls(&mut cursor)?;
        if conn.process_new_packets().is_err() {
            // Client sent a fatal alert (e.g. it rejected our cert). Flush any
            // pending bytes and stop -- this is the expected untrusted outcome.
            let _ = flush_tls(&mut conn, &mut stream).await;
            return Ok(());
        }
    }

    flush_tls(&mut conn, &mut stream).await?;
    let mut one = [0_u8; 1];
    let _ = timeout(Duration::from_millis(500), stream.read(&mut one)).await;
    Ok(())
}

/// Spawn a ParallaX server on `127.0.0.1:0` whose fallback splices to
/// `fallback_addr`. The rustls ClientHello is unauthenticated, so
/// `handle_connection` returns `Fallback(AuthFailed)` and transparently splices
/// the flow to the origin. The relay returning `Err` once the client closes is
/// the expected clean teardown, so we tolerate it.
async fn spawn_parallax(fallback_addr: SocketAddr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = fallback_server_config(fallback_addr);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = server::handle_connection(
            stream,
            &config,
            TrafficConfig::default(),
            &UdpConfig::default(),
            PSK,
        )
        .await;
    });
    (addr, task)
}

/// Write out all currently-pending TLS bytes for `conn` onto `stream`.
///
/// Takes `&mut ConnectionCommon<D>` so both `ClientConnection` and
/// `ServerConnection` (which `DerefMut` to it) coerce at the call site.
async fn flush_tls<D: rustls::SideData>(
    conn: &mut rustls::ConnectionCommon<D>,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    while conn.wants_write() {
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        if out.is_empty() {
            break;
        }
        stream.write_all(&out).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// rustls client handshake driver + captured outcome.
// ---------------------------------------------------------------------------

/// The TLS outcome we compare across the direct and spliced paths. Every field
/// is derived from negotiated state, not from configuration, so equality here
/// means the two connections genuinely converged on the same TLS session shape
/// against the same peer identity.
#[derive(Debug, PartialEq, Eq)]
struct HandshakeInfo {
    version: Option<rustls::ProtocolVersion>,
    /// `CipherSuite` (an Eq enum) rather than `SupportedCipherSuite` so the
    /// value is hashable/comparable and prints meaningfully on mismatch.
    cipher_suite: Option<rustls::CipherSuite>,
    /// `NamedGroup` of the negotiated key-exchange group (`SupportedKxGroup` is
    /// a trait object and not directly comparable).
    kx_group: Option<rustls::NamedGroup>,
    peer_certs: Option<Vec<CertificateDer<'static>>>,
}

impl HandshakeInfo {
    fn capture(conn: &rustls::ClientConnection) -> Self {
        Self {
            version: conn.protocol_version(),
            cipher_suite: conn.negotiated_cipher_suite().map(|s| s.suite()),
            kx_group: conn.negotiated_key_exchange_group().map(|g| g.name()),
            peer_certs: conn.peer_certificates().map(<[_]>::to_vec),
        }
    }
}

/// Run a real rustls client handshake to `target_addr`, verifying with
/// `verifier` and `sni`. On success returns the captured [`HandshakeInfo`]; on
/// failure returns the `rustls::Error` exactly as the client saw it. Driven by
/// a raw `ClientConnection` byte pump (no `tokio-rustls` dependency).
async fn tls_handshake(
    target_addr: SocketAddr,
    verifier: Arc<dyn ServerCertVerifier>,
    sni: &str,
) -> Result<HandshakeInfo, rustls::Error> {
    let server_name = ServerName::try_from(sni.to_owned()).expect("valid SNI");
    let mut conn = rustls::ClientConnection::new(rustls_client_config(verifier), server_name)?;
    let mut stream = TcpStream::connect(target_addr)
        .await
        .expect("connect to target");
    let mut buf = [0_u8; 4096];

    while conn.is_handshaking() {
        // Send our pending handshake flight.
        flush_tls(&mut conn, &mut stream)
            .await
            .map_err(io_to_rustls)?;
        if !conn.is_handshaking() {
            break;
        }
        if !conn.wants_read() {
            continue;
        }
        let n = stream.read(&mut buf).await.map_err(io_to_rustls)?;
        if n == 0 {
            return Err(rustls::Error::General(
                "origin closed before completing handshake".into(),
            ));
        }
        let mut cursor = Cursor::new(&buf[..n]);
        conn.read_tls(&mut cursor).map_err(io_to_rustls)?;
        // `process_new_packets` surfaces certificate-verification failures as a
        // `rustls::Error` -- this is the error category we compare in the
        // untrusted case. Flush first so the fatal alert reaches the peer, then
        // propagate it.
        if let Err(e) = conn.process_new_packets() {
            let _ = flush_tls(&mut conn, &mut stream).await;
            return Err(e);
        }
    }

    let info = HandshakeInfo::capture(&conn);
    conn.send_close_notify();
    let _ = flush_tls(&mut conn, &mut stream).await;
    Ok(info)
}

/// Map a transport-level IO error to a rustls error so both transport and
/// protocol failures flow through one `Result<_, rustls::Error>` channel.
fn io_to_rustls(e: std::io::Error) -> rustls::Error {
    rustls::Error::General(format!("io error during handshake: {e}"))
}

/// Stable category for a `rustls::Error`: the top-level `Error` *variant*, not
/// its inner detail. Two failures are "the same kind of failure" iff this
/// matches. We deliberately collapse `InvalidCertificate(_)` to one category so
/// the comparison is about *which validation step rejected*, not the exact
/// `CertificateError` code (which can carry path-specific detail).
fn error_category(e: &rustls::Error) -> &'static str {
    match e {
        rustls::Error::InvalidCertificate(_) => "InvalidCertificate",
        rustls::Error::InvalidMessage(_) => "InvalidMessage",
        rustls::Error::AlertReceived(_) => "AlertReceived",
        rustls::Error::PeerIncompatible(_) => "PeerIncompatible",
        rustls::Error::PeerMisbehaved(_) => "PeerMisbehaved",
        rustls::Error::General(_) => "General",
        _ => "Other",
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Success equivalence: a trusted origin reached directly and through the
/// fallback splice yields byte-transparent, identical TLS outcomes.
#[tokio::test]
#[ignore = "requires loopback TCP sockets"]
async fn proxied_and_direct_tls_outcomes_are_equivalent() {
    // One origin connection for the direct handshake, one for the spliced one.
    let (origin_addr, origin_task) = spawn_origin(2).await;
    let (parallax_addr, parallax_task) = spawn_parallax(origin_addr).await;

    let direct = tls_handshake(origin_addr, trusting_verifier(), ORIGIN_SNI)
        .await
        .expect("direct handshake to trusted origin succeeds");
    let spliced = tls_handshake(parallax_addr, trusting_verifier(), ORIGIN_SNI)
        .await
        .expect("spliced handshake to trusted origin succeeds");

    // Sanity: the handshake actually negotiated TLS 1.3 against the real leaf,
    // so the equality below is comparing populated state, not two `None`s.
    assert_eq!(direct.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert!(direct.cipher_suite.is_some());
    assert!(direct.kx_group.is_some());
    let direct_chain = direct
        .peer_certs
        .as_ref()
        .expect("direct peer presented a certificate chain");
    assert_eq!(direct_chain.as_slice(), &[camouflage_cert_der()]);

    // The core claim: proxied == direct on every negotiated field (version,
    // cipher suite, key-exchange group, and the full peer certificate chain).
    assert_eq!(
        direct, spliced,
        "spliced TLS outcome must equal the direct one (version/cipher/kx/peer-cert)"
    );

    // The assertions above are the test's contract; the server/origin tasks need
    // not run to completion. `handle_connection`'s fallback relay can otherwise
    // block up to the 600s idle backstop if teardown races, so abort them rather
    // than await (matching the prober_loop.rs abort pattern).
    parallax_task.abort();
    origin_task.abort();
}

/// Failure equivalence: an UNtrusted origin (empty root store) is rejected the
/// same way directly and through the splice -- same `rustls::Error` category --
/// so the splice introduces no certificate-validation soft spot and no extra
/// alert that would change the observed failure.
#[tokio::test]
#[ignore = "requires loopback TCP sockets"]
async fn proxied_and_direct_tls_failures_are_equivalent() {
    let (origin_addr, origin_task) = spawn_origin(2).await;
    let (parallax_addr, parallax_task) = spawn_parallax(origin_addr).await;

    let direct_err = tls_handshake(origin_addr, untrusting_verifier(), ORIGIN_SNI)
        .await
        .expect_err("direct handshake to untrusted origin must fail");
    let spliced_err = tls_handshake(parallax_addr, untrusting_verifier(), ORIGIN_SNI)
        .await
        .expect_err("spliced handshake to untrusted origin must fail");

    // The empty trust anchor set means the leaf has no path to a root, so the
    // direct failure is a certificate-validation rejection. Pin that so the
    // equivalence below is anchored to the real, expected failure mode rather
    // than to some incidental transport hiccup.
    assert_eq!(
        error_category(&direct_err),
        "InvalidCertificate",
        "direct failure should be a certificate-validation rejection, got: {direct_err:?}"
    );

    // The core claim: the spliced path fails in the SAME category as direct.
    assert_eq!(
        error_category(&direct_err),
        error_category(&spliced_err),
        "spliced failure category ({spliced_err:?}) must match direct ({direct_err:?})"
    );

    // As above: the failure-category assertions are the contract; abort the tasks
    // rather than await them, so a racing teardown cannot block on the 600s idle
    // backstop in `handle_connection`'s fallback relay.
    parallax_task.abort();
    origin_task.abort();
}
