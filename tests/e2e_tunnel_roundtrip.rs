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
//!       -> ML-DSA server-identity verify — because the target payload only
//!       round-trips after every one of those stages succeeds (the local SOCKS
//!       success reply is optimistic and is not proof of authentication);
//!   (b) client->target bytes arrive unchanged, and
//!   (c) target->client bytes arrive unchanged, for a >= 256 KiB position-encoded
//!       payload that spans many 16 KiB TLS records and multiple 256 KiB relay
//!       reads in both directions; and
//!   (d) teardown is a clean FIN, not a RST: after the app half-closes, its read
//!       side observes a graceful EOF (`read_to_end` returns `Ok`), which a RST
//!       would surface as a `ConnectionReset` error instead; and
//!   (e) on the direct path, a transparent TCP forwarder records TLS record sizes,
//!       directions, and completion times throughout the authenticated session.
//!       This userspace stream tap changes packetization and includes loopback
//!       scheduling noise; it does not establish field indistinguishability.
//! Both the direct path and a first-byte-gated path retain assertions (a)-(d).
//! The gate waits for an observed speculative origin pre-dial before releasing
//! ClientHello bytes, so this also covers slow/instrumented client preparation.
//!
//! Set `PARALLAX_TCP_TRACE_PATH` to write direct-path metadata as a TSV artifact.
//! The capture contains no payload or keys and refuses to overwrite a file.
//! Set `PARALLAX_TCP_CAPTURE_PORT` to a u16 port for a packet-capture filter;
//! the forwarder always binds 127.0.0.1 and otherwise uses an ephemeral port.
//!
//! Live-socket test: `#[ignore]`d and run serially, matching the repo's loopback
//! convention (`requires loopback TCP sockets`). Run with:
//!   cargo test --locked --test e2e_tunnel_roundtrip -- --ignored --test-threads=1

#[path = "distinguisher/tcp_capture.rs"]
mod tcp_capture;
#[allow(dead_code)]
#[path = "distinguisher/trace.rs"]
mod trace;

use std::io::{self, Cursor};
use std::net::SocketAddr;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
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
use tokio::sync::oneshot;
use tokio::task::JoinSet;
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
const ORIGIN_BUDGET: Duration = Duration::from_secs(30);
type FixtureTasks = JoinSet<&'static str>;

#[derive(Debug)]
struct OriginReport {
    empty_predials: usize,
    tls_handshakes: usize,
}

#[derive(Debug)]
enum OriginConnection {
    EmptyPredial,
    TlsComplete,
}

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
/// A slow first client byte permits one speculative origin TCP connection which
/// the authenticated path closes without sending TLS bytes. Accept at most that
/// empty spare and one real TLS connection. An EOF after a TLS byte must fail
/// until the handshake completes.
/// After TLS completes, drain to the ParallaX server's EOF, with an overall bound
/// instead of closing the origin while an instrumented client is still working.
async fn spawn_camouflage_origin(
    pki: &CamouflagePki,
    tasks: &mut FixtureTasks,
) -> (
    SocketAddr,
    oneshot::Receiver<()>,
    oneshot::Receiver<OriginReport>,
) {
    let server_config = rustls_server_config(pki);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (first_accepted, accepted) = oneshot::channel();
    let (completed, report) = oneshot::channel();
    tasks.spawn(async move {
        let report = timeout(ORIGIN_BUDGET, async move {
            let mut first_accepted = Some(first_accepted);
            let mut empty_predials = 0;
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                if let Some(accepted) = first_accepted.take() {
                    let _ = accepted.send(());
                }
                match serve_origin_connection(stream, Arc::clone(&server_config))
                    .await
                    .expect("camouflage origin TLS/transport failure")
                {
                    OriginConnection::EmptyPredial => empty_predials += 1,
                    OriginConnection::TlsComplete => {
                        return OriginReport {
                            empty_predials,
                            tls_handshakes: 1,
                        };
                    }
                }
            }
            panic!("origin did not complete TLS after its bounded pre-dial allowance");
        })
        .await
        .expect("camouflage origin fixture exceeded its overall deadline");
        completed.send(report).unwrap();
        "origin"
    });
    (addr, accepted, report)
}

async fn serve_origin_connection(
    mut stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> io::Result<OriginConnection> {
    let mut first = [0_u8; 1];
    if stream.read(&mut first).await? == 0 {
        return Ok(OriginConnection::EmptyPredial);
    }
    let mut server = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
    server.read_tls(&mut Cursor::new(&first))?;
    server.process_new_packets().map_err(io::Error::other)?;
    let mut buf = [0_u8; 8192];
    while server.is_handshaking() {
        flush_rustls_server(&mut server, &mut stream).await?;
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "camouflage origin saw EOF mid-handshake",
            ));
        }
        server.read_tls(&mut Cursor::new(&buf[..n]))?;
        server.process_new_packets().map_err(io::Error::other)?;
    }
    flush_rustls_server(&mut server, &mut stream).await?;
    // Do not convert a timeout or reset into a successful origin completion.
    // The enclosing fixture deadline bounds a server that never closes.
    while stream.read(&mut buf).await? != 0 {}
    stream.shutdown().await?;
    Ok(OriginConnection::TlsComplete)
}

async fn flush_rustls_server(
    server: &mut rustls::ServerConnection,
    stream: &mut TcpStream,
) -> io::Result<()> {
    while server.wants_write() {
        let mut out = Vec::new();
        server.write_tls(&mut out)?;
        if out.is_empty() {
            break;
        }
        stream.write_all(&out).await?;
    }
    Ok(())
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
async fn spawn_echo_target(tasks: &mut FixtureTasks) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tasks.spawn(async move {
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
        "target"
    });
    addr
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
async fn spawn_parallax_server(config: ServerConfig, tasks: &mut FixtureTasks) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tasks.spawn(async move {
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
        "server"
    });
    addr
}

/// Bind the REAL ParallaX client SOCKS5 listener on loopback and serve one
/// accepted local connection through `handle_local_connection` (the production
/// entry point). `single-connect` mode (max_concurrent_streams == 1 default).
async fn spawn_local_client(
    parallax_addr: SocketAddr,
    server_keys: &X25519KeyPair,
    server_identity_keys: &MlDsaKeyPair,
    tasks: &mut FixtureTasks,
) -> SocketAddr {
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
    tasks.spawn(async move {
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
        "client"
    });
    addr
}

/// Connect to the real ParallaX server, withholding all client bytes until its
/// production pre-dial has actually reached the origin. This forces the race
/// boundary without assuming a wall-clock delay is long enough on a busy host.
async fn spawn_first_byte_gate(
    server_addr: SocketAddr,
    origin_accepted: oneshot::Receiver<()>,
    tasks: &mut FixtureTasks,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tasks.spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut server = TcpStream::connect(server_addr).await.unwrap();
        timeout(Duration::from_secs(10), origin_accepted)
            .await
            .expect("production origin pre-dial did not occur before any client byte")
            .expect("origin accept observer disappeared");
        tokio::io::copy_bidirectional(&mut client, &mut server)
            .await
            .expect("first-byte proxy must relay both directions without transport errors");
        "first-byte proxy"
    });
    addr
}

// ---------------------------------------------------------------------------
// SOCKS5 app driver.
// ---------------------------------------------------------------------------

/// Complete the SOCKS5 no-auth negotiation + CONNECT to `target_addr` against the
/// client's local listener. The success reply is optimistic; the payload
/// round-trip below, not this reply, proves the authenticated tunnel works.
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
#[test]
#[ignore = "requires loopback TCP sockets"]
fn tunnel_roundtrips_large_payload_and_closes_cleanly() {
    // Install one shared CA before starting workers. native_roots() is cached,
    // so the direct and delayed scenarios must use this same PKI.
    let pki = generate_camouflage_pki();
    let _ca_guard = install_trust_root(&pki.ca_cert_pem);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let mut tasks = FixtureTasks::new();
    let result = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async {
            timeout(Duration::from_secs(180), async {
                origin_rejects_mid_handshake_eof(&pki).await;
                run_roundtrip(&pki, false, &mut tasks).await;
                run_roundtrip(&pki, true, &mut tasks).await;
            })
            .await
            .expect("end-to-end fixtures exceeded their overall deadline");
        });
    }));
    // Keep the runtime alive while aborting AND awaiting all fixture tasks on
    // failure. Dropping a JoinHandle alone would detach a lingering listener.
    runtime.block_on(tasks.shutdown());
    if let Err(panic) = result {
        resume_unwind(panic);
    }
}

async fn run_roundtrip(pki: &CamouflagePki, force_predial: bool, tasks: &mut FixtureTasks) {
    assert!(tasks.is_empty(), "previous fixture tasks must be joined");
    // Loopback camouflage origin + echo target.
    let (fallback_addr, origin_accepted, origin_report) = spawn_camouflage_origin(pki, tasks).await;
    let target_addr = spawn_echo_target(tasks).await;

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
    let parallax_addr = spawn_parallax_server(config, tasks).await;
    let (upstream, forwarder) = if force_predial {
        (
            spawn_first_byte_gate(parallax_addr, origin_accepted, tasks).await,
            None,
        )
    } else {
        drop(origin_accepted);
        let capture_port = std::env::var_os("PARALLAX_TCP_CAPTURE_PORT")
            .map(|port| {
                port.to_str()
                    .expect("PARALLAX_TCP_CAPTURE_PORT must be Unicode")
                    .parse::<u16>()
                    .expect("PARALLAX_TCP_CAPTURE_PORT must be a u16 port")
            })
            .unwrap_or(0);
        let forwarder = tcp_capture::RecordingForwarder::spawn(parallax_addr, capture_port)
            .await
            .expect("start TCP record capture");
        (forwarder.front_addr, Some(forwarder))
    };
    let local_addr = spawn_local_client(upstream, &server_keys, &server_identity_keys, tasks).await;

    // SOCKS success is sent optimistically. Only the authenticated payload
    // exchange below proves Safari26 TLS, PQ rekey and identity verification.
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

    // Every real runtime, origin and optional proxy must finish successfully.
    // In particular, do not abort the origin and hide its TLS/EOF outcome.
    wait_for_tasks(tasks, force_predial).await;
    let report = origin_report
        .await
        .expect("origin did not report successful TLS completion");
    assert_eq!(report.tls_handshakes, 1);
    assert!(report.empty_predials <= 1);
    if force_predial {
        assert_eq!(
            report.empty_predials, 1,
            "first-byte gate did not exercise the empty pre-dial"
        );
    }
    eprintln!(
        "{}: empty_predials={}, completed_tls={}, payload_bytes={PAYLOAD_LEN}",
        if force_predial { "gated" } else { "direct" },
        report.empty_predials,
        report.tls_handshakes,
    );
    if let Some(forwarder) = forwarder {
        let capture = timeout(Duration::from_secs(10), forwarder.finish())
            .await
            .expect("TCP record capture timed out")
            .expect("TCP record capture failed");
        let trace = capture.application_data();
        let c2s = trace.dir(trace::Dir::C2S).len();
        let s2c = trace.dir(trace::Dir::S2C).len();
        assert!(
            c2s >= 64 && s2c >= 64,
            "incomplete bidirectional capture: {c2s}/{s2c}"
        );
        for dir in [trace::Dir::C2S, trace::Dir::S2C] {
            assert!(
                capture
                    .records
                    .iter()
                    .any(|r| r.dir == dir && r.content_type == 22),
                "capture missed a direction of the camouflage handshake"
            );
        }
        let span = capture.records.last().unwrap().t_micros;
        assert!(span > 0, "capture must retain elapsed socket time");
        eprintln!(
            "[authenticated-tcp-record-capture] records={} appdata_c2s={c2s} appdata_s2c={s2c} \
         span_us={span}; loopback measurement only",
            capture.records.len(),
        );
        if let Some(path) = std::env::var_os("PARALLAX_TCP_TRACE_PATH") {
            capture
                .write_tsv(&path)
                .expect("write TCP capture metadata");
            eprintln!(
                "TCP record metadata: {}",
                std::path::Path::new(&path).display()
            );
        }
    }
}

async fn wait_for_tasks(tasks: &mut FixtureTasks, has_proxy: bool) {
    let mut completed = timeout(Duration::from_secs(10), async {
        let mut completed = Vec::new();
        while let Some(result) = tasks.join_next().await {
            completed.push(result.expect("end-to-end fixture task failed"));
        }
        completed
    })
    .await
    .expect("end-to-end fixture tasks did not finish");
    let mut expected = vec!["client", "origin", "server", "target"];
    if has_proxy {
        expected.push("first-byte proxy");
    }
    completed.sort_unstable();
    expected.sort_unstable();
    assert_eq!(completed, expected, "every fixture task must be joined");
}

async fn origin_rejects_mid_handshake_eof(pki: &CamouflagePki) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    peer.write_all(&[0x16]).await.unwrap();
    peer.shutdown().await.unwrap();
    let error = timeout(
        Duration::from_secs(5),
        serve_origin_connection(stream, rustls_server_config(pki)),
    )
    .await
    .expect("partial-TLS EOF control timed out")
    .expect_err("an EOF after any TLS byte must not be treated as an empty pre-dial");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(error.to_string(), "camouflage origin saw EOF mid-handshake");
}
