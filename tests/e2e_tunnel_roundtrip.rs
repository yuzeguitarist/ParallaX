//! End-to-end tunnel round-trip: the REAL ParallaX client + server data path
//! over loopback, driven by a SOCKS5 application through the authenticated
//! tunnel to a loopback echo target.
//!
//! What this covers that the rest of the suite does not
//! ----------------------------------------------------
//! The crate's in-crate `#[cfg(test)]` loopback tests
//! (`src/client/runtime.rs::socks_client_reaches_target_through_parallax_server_with_large_payloads`
//! and friends) already drive the full client+server path, but they can only do
//! so because `verify_server_certificate` in `src/tls/safari26.rs` has a
//! `#[cfg(test)]`-only escape that accepts a fixed loopback camouflage cert by
//! SHA-256. That escape is compiled ONLY when the crate itself is built with
//! `--cfg test` (i.e. `cargo test --lib`); it does NOT exist in the library an
//! integration test links against. So an integration binary in `tests/` exercises
//! the client's REAL production certificate-verification path (webpki against the
//! trust store) — coverage the in-crate tests structurally cannot provide.
//!
//! To keep the whole flow on loopback (no outbound internet) while still going
//! through real webpki verification, the test mints a throwaway CA + an
//! `example.com` leaf with `rcgen`, installs the CA into the process trust store
//! via `SSL_CERT_FILE` (honored by `rustls-native-certs`, which
//! `safari26::native_roots()` calls), and has the loopback camouflage origin
//! present the leaf. The client then validates the origin exactly as in
//! production: SNI match + a chain that terminates at a trusted root.
//!
//! What it asserts
//! ---------------
//! Driving a SOCKS5 app through the tunnel to a loopback echo target:
//!   (a) the full authenticated handshake completes — Safari26 camouflage TLS
//!       (spliced client<->origin through the ParallaX server) -> PQ rekey (PX1Q)
//!       -> ML-DSA server-identity verify — because the SOCKS relay only comes up
//!       after every one of those stages succeeds;
//!   (b) client->target bytes arrive unchanged, and
//!   (c) target->client bytes arrive unchanged, for a >= 256 KiB position-encoded
//!       payload that spans many 16 KiB TLS records and multiple 256 KiB relay
//!       reads in both directions; and
//!   (d) teardown is a clean FIN, not a RST: after the app half-closes, its read
//!       side observes a graceful EOF (`read_to_end` returns `Ok`), which a RST
//!       would surface as a `ConnectionReset` error instead.
//!
//! Live-socket test: `#[ignore]`d and run serially, matching the repo's loopback
//! convention (`requires loopback TCP sockets`). Run with:
//!   cargo test --test e2e_tunnel_roundtrip -- --ignored --test-threads=1

use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use parallax::client::runtime::handle_local_connection;
use parallax::config::{ClientConfig, ServerConfig, TrafficConfig, UdpConfig};
use parallax::crypto::identity::{self, MlDsaKeyPair};
use parallax::crypto::session::X25519KeyPair;
use parallax::handshake::server;

/// Any 32-byte PSK works; both ends must simply agree. Matches the value the
/// in-crate loopback tests use.
const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

/// The camouflage SNI. It must be (1) in the server's `authorized_sni`, (2) the
/// client's configured `sni`, and (3) a `dNSName` SAN on the leaf the origin
/// presents so the client's webpki check passes.
const SNI: &str = "example.com";

/// At least 256 KiB so the payload spans many 16 KiB TLS records and more than
/// one 256 KiB relay read in each direction. 1 MiB gives comfortable headroom.
const PAYLOAD_LEN: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Throwaway PKI: a CA trusted via SSL_CERT_FILE + an example.com leaf the
// loopback camouflage origin presents. This is what lets the client run its
// REAL production webpki verification against a purely-loopback origin.
// ---------------------------------------------------------------------------

struct CamouflagePki {
    /// DER leaf presented by the origin (and signed by `ca`).
    leaf_cert_der: CertificateDer<'static>,
    /// PKCS#8 DER private key matching `leaf_cert_der`.
    leaf_key_der: PrivateKeyDer<'static>,
    /// PEM of the CA cert, to drop into the trust store.
    ca_cert_pem: String,
}

fn generate_camouflage_pki() -> CamouflagePki {
    // CA: self-signed, may sign the leaf. rcgen defaults to ECDSA P-256, which
    // the aws-lc-rs rustls provider serves and webpki's ALL_VERIFICATION_ALGS
    // verify.
    let ca_key = KeyPair::generate().expect("generate CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "ParallaX E2E Test Root CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");

    // Leaf: an end-entity serverAuth cert for the camouflage SNI, signed by the CA.
    let leaf_key = KeyPair::generate().expect("generate leaf key");
    let mut leaf_params = CertificateParams::new(vec![SNI.to_owned()]).expect("leaf params");
    leaf_params.distinguished_name.push(DnType::CommonName, SNI);
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("sign leaf with CA");

    CamouflagePki {
        leaf_cert_der: leaf_cert.der().clone(),
        leaf_key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        ca_cert_pem: ca_cert.pem(),
    }
}

/// Write the CA to a temp file and point `SSL_CERT_FILE` at it so the client's
/// `safari26::native_roots()` (via `rustls-native-certs`) trusts the loopback
/// origin's chain. Must run BEFORE the client's first handshake, since
/// `native_roots()` memoizes the loaded roots in a process `OnceLock`. The
/// returned guard owns the temp file; keep it alive for the whole test.
fn install_trust_root(ca_cert_pem: &str) -> tempfile::NamedTempFile {
    let mut ca_file = tempfile::Builder::new()
        .prefix("parallax-e2e-ca")
        .suffix(".pem")
        .tempfile()
        .expect("create CA temp file");
    use std::io::Write as _;
    ca_file
        .write_all(ca_cert_pem.as_bytes())
        .expect("write CA PEM");
    ca_file.flush().expect("flush CA PEM");
    // SAFETY: edition 2021 `set_var` is a safe fn. Set once, at the very top of
    // the test, before any TLS root load or worker touches the environment.
    std::env::set_var("SSL_CERT_FILE", ca_file.path());
    ca_file
}

// ---------------------------------------------------------------------------
// Loopback endpoints.
// ---------------------------------------------------------------------------

/// A camouflage origin: a real TLS 1.3 server (rustls) presenting the CA-signed
/// leaf. The ParallaX server splices the authenticated client straight through
/// to this origin for the camouflage TLS handshake, and the client verifies this
/// origin's certificate against `SNI` using the trust root installed above.
///
/// It completes the handshake, then drains whatever the client's spliced
/// post-handshake camouflage bytes are (with a short idle bound) so it reaches a
/// graceful close rather than RST-ing on unread data.
async fn spawn_camouflage_origin(pki: &CamouflagePki) -> (SocketAddr, JoinHandle<()>) {
    let server_config = rustls_server_config(pki);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut server =
            rustls::ServerConnection::new(server_config).expect("rustls server connection");
        let mut buf = [0_u8; 8192];

        while server.is_handshaking() {
            flush_rustls_server(&mut server, &mut stream).await;
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "camouflage origin saw EOF mid-handshake");
            let mut cursor = Cursor::new(&buf[..n]);
            server.read_tls(&mut cursor).unwrap();
            server.process_new_packets().unwrap();
        }
        flush_rustls_server(&mut server, &mut stream).await;

        // Drain the spliced client camouflage traffic until it goes quiet, so the
        // origin never RSTs on unread bytes. Once the ParallaX server detects the
        // client's PX1Q it stops splicing to us, so this naturally idles out.
        loop {
            match timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(_)) => {}
            }
        }
    });
    (addr, task)
}

async fn flush_rustls_server(server: &mut rustls::ServerConnection, stream: &mut TcpStream) {
    while server.wants_write() {
        let mut out = Vec::new();
        server.write_tls(&mut out).unwrap();
        if out.is_empty() {
            break;
        }
        stream.write_all(&out).await.unwrap();
    }
}

fn rustls_server_config(pki: &CamouflagePki) -> Arc<rustls::ServerConfig> {
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("aws_lc_rs provider supports rustls default protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![pki.leaf_cert_der.clone()],
            pki.leaf_key_der.clone_key(),
        )
        .expect("rustls server config with loopback leaf"),
    )
}

/// A loopback echo target: reads and echoes every byte until EOF, then returns
/// (dropping its stream, which FINs the read side). This is the destination the
/// SOCKS app talks to through the tunnel.
async fn spawn_echo_target() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 64 * 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
        // The app half-closes first; after echoing everything we FIN back so the
        // app's read side sees a clean EOF (asserted below), not a RST.
        stream.shutdown().await.unwrap();
    });
    (addr, task)
}

// ---------------------------------------------------------------------------
// Real ParallaX runtimes over loopback.
// ---------------------------------------------------------------------------

fn server_config(
    fallback_addr: SocketAddr,
    target_addr: SocketAddr,
    server_keys: &X25519KeyPair,
    server_identity_keys: &MlDsaKeyPair,
    replay_cache_path: std::path::PathBuf,
) -> ServerConfig {
    ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        fallback_addr: fallback_addr.to_string(),
        data_target: Some(target_addr.to_string()),
        private_key: STANDARD.encode(server_keys.private).into(),
        identity_secret_key: STANDARD.encode(&server_identity_keys.secret).into(),
        replay_cache_path,
        // DEFAULT_REPLAY_CACHE_CAPACITY is pub(crate); a literal mirrors the
        // value the in-crate loopback tests use.
        replay_cache_capacity: 49_152,
        authorized_sni: vec![SNI.to_owned()],
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

/// Bind the REAL ParallaX server on loopback and serve one accepted connection
/// through `handle_connection` (the production entry point).
async fn spawn_parallax_server(config: ServerConfig) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        server::handle_connection(
            stream,
            &config,
            TrafficConfig::default(),
            &UdpConfig::default(),
            PSK,
        )
        .await
        .unwrap();
    });
    (addr, task)
}

/// Bind the REAL ParallaX client SOCKS5 listener on loopback and serve one
/// accepted local connection through `handle_local_connection` (the production
/// entry point). `single-connect` mode (max_concurrent_streams == 1 default).
async fn spawn_local_client(
    parallax_addr: SocketAddr,
    server_keys: &X25519KeyPair,
    server_identity_keys: &MlDsaKeyPair,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_config = ClientConfig {
        listen: addr,
        server_addr: parallax_addr.to_string(),
        sni: SNI.to_owned(),
        server_public_key: STANDARD.encode(server_keys.public),
        server_identity_public_key: STANDARD.encode(&server_identity_keys.public),
        accept_language: None,
    };
    let server_public_key = server_keys.public;
    let server_identity_public_key = server_identity_keys.public.clone();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_local_connection(
            stream,
            &client_config,
            TrafficConfig::default(),
            &UdpConfig::default(),
            PSK,
            &server_public_key,
            &server_identity_public_key,
        )
        .await
        .unwrap();
    });
    (addr, task)
}

// ---------------------------------------------------------------------------
// SOCKS5 app driver.
// ---------------------------------------------------------------------------

/// Complete the SOCKS5 no-auth negotiation + CONNECT to `target_addr` against the
/// client's local listener, returning the connected app socket (tunnelled).
async fn connect_socks_target(local_addr: SocketAddr, target_addr: SocketAddr) -> TcpStream {
    let mut app = TcpStream::connect(local_addr).await.unwrap();
    app.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0_u8; 2];
    app.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0], "SOCKS5 no-auth method must be selected");

    app.write_all(&[
        5,
        1,
        0,
        1,
        127,
        0,
        0,
        1,
        (target_addr.port() >> 8) as u8,
        (target_addr.port() & 0xff) as u8,
    ])
    .await
    .unwrap();
    let mut reply = [0_u8; 10];
    app.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0..2], [5, 0], "SOCKS5 CONNECT must succeed");
    app
}

/// A position-encoded payload: byte `i` is `(i % 251)`. Any reorder, drop,
/// duplication, or offset shift shows up as a mismatch rather than being masked
/// by repeated bytes.
fn position_encoded_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

// ---------------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------------

/// Full authenticated tunnel round-trip with a large bidirectional payload and a
/// clean FIN teardown, exercising the client's real webpki cert verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets"]
async fn tunnel_roundtrips_large_payload_and_closes_cleanly() {
    // Mint the throwaway PKI and trust its CA BEFORE any handshake so the client's
    // production cert verification accepts the loopback origin.
    let pki = generate_camouflage_pki();
    let _ca_guard = install_trust_root(&pki.ca_cert_pem);

    // Loopback camouflage origin + echo target.
    let (fallback_addr, origin_task) = spawn_camouflage_origin(&pki).await;
    let (target_addr, target_task) = spawn_echo_target().await;

    // Freshly generated server keys: X25519 static (session) + ML-DSA identity.
    let server_keys = X25519KeyPair::generate();
    let server_identity_keys = identity::keypair();

    let replay_dir = tempfile::tempdir().unwrap();
    let replay_cache_path = replay_dir.path().join("parallax-replay.cache");

    let config = server_config(
        fallback_addr,
        target_addr,
        &server_keys,
        &server_identity_keys,
        replay_cache_path,
    );
    let (parallax_addr, server_task) = spawn_parallax_server(config).await;
    let (local_addr, client_task) =
        spawn_local_client(parallax_addr, &server_keys, &server_identity_keys).await;

    // Drive a SOCKS5 app through the tunnel to the echo target. Reaching an
    // accepted SOCKS CONNECT already proves the full authenticated handshake
    // (Safari26 camouflage -> PQ rekey -> ML-DSA identity verify) completed.
    let app = connect_socks_target(local_addr, target_addr).await;
    let (mut app_read, mut app_write) = app.into_split();

    // (b)+(c) bidirectional byte transparency for a >= 256 KiB payload. Write and
    // read concurrently in 64 KiB chunks so neither direction wedges when the
    // socket/relay buffers fill.
    let payload = position_encoded_payload(PAYLOAD_LEN);
    let mut echoed = vec![0_u8; PAYLOAD_LEN];
    for (send, recv) in payload.chunks(64 * 1024).zip(echoed.chunks_mut(64 * 1024)) {
        let (write_result, read_result) = timeout(Duration::from_secs(30), async {
            tokio::join!(app_write.write_all(send), app_read.read_exact(recv))
        })
        .await
        .expect("large payload round trip timed out");
        write_result.expect("client->target write");
        read_result.expect("target->client read");
    }
    assert_eq!(
        echoed, payload,
        "tunnelled bytes must round-trip unchanged in both directions"
    );

    // (d) clean teardown: half-close the app write side. The echo target reads
    // EOF, echoes nothing more, and FINs; the client relays that FIN so the app's
    // read side sees a graceful EOF. A RST would instead surface as an error here.
    app_write.shutdown().await.expect("app half-close");
    drop(app_write);

    let mut trailing = Vec::new();
    let eof = timeout(Duration::from_secs(10), app_read.read_to_end(&mut trailing))
        .await
        .expect("clean-EOF read timed out");
    let read_bytes = eof.expect("teardown must be a clean FIN/EOF, not a RST");
    assert_eq!(
        read_bytes, 0,
        "all payload already consumed; teardown must add no bytes"
    );
    assert!(
        trailing.is_empty(),
        "no unexpected trailing bytes after EOF"
    );
    drop(app_read);

    // Both real runtimes must return cleanly (Ok), proving no error teardown.
    wait_for_task("client", client_task).await;
    wait_for_task("server", server_task).await;
    wait_for_task("target", target_task).await;
    origin_task.abort();
}

async fn wait_for_task(name: &str, task: JoinHandle<()>) {
    timeout(Duration::from_secs(10), task)
        .await
        .unwrap_or_else(|_| panic!("{name} task timed out"))
        .unwrap_or_else(|err| panic!("{name} task failed: {err:?}"));
}
