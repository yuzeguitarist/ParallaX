//! Contract tests for `parallax::embed`, the API an iOS packet tunnel (or any
//! other host process) uses instead of the CLI. See `EMBEDDING.md`.
//!
//! What is pinned here:
//!   * profile parsing: inline secrets only, `client.listen` optional, CLI
//!     validation otherwise, no secret in `Debug`;
//!   * the relay works on a current-thread runtime with the constrained memory
//!     profile, trusting the camouflage origin ONLY through the injected
//!     verifier (no native root store, no `SSL_CERT_FILE`);
//!   * 64 concurrent streams keep their bytes apart;
//!   * a rejecting verifier fails the relay;
//!   * `network_changed` ends live sessions and the client keeps working;
//!   * `shutdown` leaves no task alive on the host runtime;
//!   * cancelling a relay while its session is still being built does not wedge
//!     the pool (the build finishes and the next relay reuses it).
//!
//! The ParallaX server and its fixtures run on their own runtime so the client
//! runtime's task count measures only the embedded client.
//!
//! Loopback tests are `#[ignore]`d like the rest of the suite's socket tests:
//!   cargo test --locked --test embed_contract -- --ignored --test-threads=1

use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use parallax::config::{ServerConfig, TrafficConfig, UdpConfig};
use parallax::crypto::identity::{self, MlDsaKeyPair};
use parallax::crypto::session::X25519KeyPair;
use parallax::embed::{
    Client, ClientOptions, ClientProfile, EmbedError, MemoryProfile, ServerCertVerifier, Target,
    API_VERSION,
};
use parallax::handshake::server;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::time::timeout;

const PSK: &[u8] = b"embed-contract-psk-0123456789abcdef!";
const SNI: &str = "example.com";

// ---------------------------------------------------------------------------
// Profiles.
// ---------------------------------------------------------------------------

fn profile_toml(server_addr: &str, server: &ServerKeys, max_streams: u8) -> String {
    format!(
        "mode = \"client\"\n\
         [crypto]\n\
         psk = \"{psk}\"\n\
         [traffic]\n\
         max_concurrent_streams = {max_streams}\n\
         [client]\n\
         server_addr = \"{server_addr}\"\n\
         sni = \"{SNI}\"\n\
         server_public_key = \"{public}\"\n\
         server_identity_public_key = \"{identity}\"\n",
        psk = STANDARD.encode(PSK),
        public = STANDARD.encode(server.x25519.public),
        identity = STANDARD.encode(&server.identity.public),
    )
}

struct ServerKeys {
    x25519: X25519KeyPair,
    identity: MlDsaKeyPair,
}

impl ServerKeys {
    fn generate() -> Self {
        Self {
            x25519: X25519KeyPair::generate(),
            identity: identity::keypair(),
        }
    }
}

#[test]
fn api_version_is_pinned() {
    assert_eq!(
        API_VERSION, 1,
        "bump EMBEDDING.md's changelog with this value"
    );
}

#[test]
fn profiles_accept_inline_secrets_without_a_listener() {
    let keys = ServerKeys::generate();
    let profile = ClientProfile::from_toml_str(&profile_toml("198.51.100.7:443", &keys, 4))
        .expect("a plx-init client profile without `listen` parses");
    assert_eq!(profile.server_addr(), "198.51.100.7:443");
    assert_eq!(profile.sni(), SNI);
    assert_eq!(profile.max_concurrent_streams(), 4);
    let debug = format!("{profile:?}");
    assert!(
        !debug.contains(&STANDARD.encode(PSK)),
        "Debug must not render secrets: {debug}"
    );

    let with_listen = profile_toml("198.51.100.7:443", &keys, 4)
        .replace("[client]\n", "[client]\nlisten = \"127.0.0.1:1080\"\n");
    ClientProfile::from_toml_str(&with_listen).expect("the CLI's own client file also parses");
}

#[test]
fn profiles_reject_secret_references_and_non_client_configs() {
    let keys = ServerKeys::generate();
    let base = profile_toml("198.51.100.7:443", &keys, 4);
    let psk_line = format!("psk = \"{}\"", STANDARD.encode(PSK));
    for reference in [
        "psk = { file = \"secrets.toml#psk\" }",
        "psk = { env = \"PARALLAX_PSK\" }",
        "psk = { sealed = \"bundle.enc#psk\" }",
    ] {
        let text = base.replace(&psk_line, reference);
        let err = ClientProfile::from_toml_str(&text).unwrap_err();
        assert!(
            err.to_string().contains("inline"),
            "{reference} must be rejected as a secret reference: {err}"
        );
    }

    let server_mode = base.replace("mode = \"client\"", "mode = \"server\"");
    assert!(ClientProfile::from_toml_str(&server_mode).is_err());
    assert!(matches!(
        ClientProfile::from_toml_str("mode = [").unwrap_err(),
        EmbedError::Profile(_)
    ));
    let bad_key = base.replace(&STANDARD.encode(keys.x25519.public), "AAAA");
    assert!(ClientProfile::from_toml_str(&bad_key).is_err());
}

/// The numbers EMBEDDING.md promises an iOS packet tunnel.
#[test]
fn constrained_memory_budget_meets_the_contract() {
    let budget = MemoryProfile::Constrained.budget();
    assert!(budget.stream_steady_bytes <= 64 * 1024, "{budget:?}");
    assert!(budget.stream_peak_bytes <= 160 * 1024, "{budget:?}");
    assert!(budget.session_bytes <= 512 * 1024, "{budget:?}");
    assert_eq!(budget.idle_sessions, 1);
    assert!(
        !budget.crypto_pool_threads,
        "no crypto pool threads in an extension"
    );
    let standard = MemoryProfile::Standard.budget();
    assert!(standard.crypto_pool_threads);
    assert!(standard.stream_peak_bytes > budget.stream_peak_bytes);
}

#[test]
fn start_requires_a_tokio_runtime() {
    let keys = ServerKeys::generate();
    let profile =
        ClientProfile::from_toml_str(&profile_toml("198.51.100.7:443", &keys, 4)).unwrap();
    assert!(matches!(
        Client::start(profile, ClientOptions::default()),
        Err(EmbedError::NoRuntime)
    ));
}

// ---------------------------------------------------------------------------
// Loopback fixtures (server side, on their own runtime).
// ---------------------------------------------------------------------------

struct Pki {
    ca_der: CertificateDer<'static>,
    leaf_der: CertificateDer<'static>,
    leaf_key: PrivateKeyDer<'static>,
}

fn generate_pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.distinguished_name
        .push(DnType::CommonName, "ParallaX embed contract CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec![SNI.to_owned()]).unwrap();
    leaf.distinguished_name.push(DnType::CommonName, SNI);
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    Pki {
        ca_der: ca_cert.der().clone(),
        leaf_der: leaf_cert.der().clone(),
        leaf_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

/// What an iOS host does with `SecTrust`: validate the chain against its own
/// trust anchors. Here the anchor is the test CA, checked with webpki.
#[derive(Debug)]
struct TestCaVerifier {
    ca_der: CertificateDer<'static>,
    calls: AtomicUsize,
}

impl ServerCertVerifier for TestCaVerifier {
    fn verify(
        &self,
        end_entity: &[u8],
        intermediates: &[&[u8]],
        server_name: &str,
        now_unix_secs: u64,
    ) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let anchor = webpki::anchor_from_trusted_cert(&self.ca_der).map_err(|e| e.to_string())?;
        let leaf = CertificateDer::from(end_entity);
        let cert = webpki::EndEntityCert::try_from(&leaf).map_err(|e| e.to_string())?;
        let intermediates: Vec<_> = intermediates
            .iter()
            .map(|der| CertificateDer::from(*der))
            .collect();
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(now_unix_secs)),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| e.to_string())?;
        let name = ServerName::try_from(server_name).map_err(|e| e.to_string())?;
        cert.verify_is_valid_for_subject_name(&name)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug)]
struct RejectingVerifier;

impl ServerCertVerifier for RejectingVerifier {
    fn verify(&self, _: &[u8], _: &[&[u8]], _: &str, _: u64) -> Result<(), String> {
        Err("rejected by the host trust policy".to_owned())
    }
}

struct Fixture {
    /// Keeps the fixtures' runtime (and every server task) alive.
    _runtime: tokio::runtime::Runtime,
    _replay_dir: tempfile::TempDir,
    server_addr: SocketAddr,
    keys: ServerKeys,
    pki: Pki,
    /// Opened by `gate_addr` connections once `release_gate` fires.
    gate_addr: SocketAddr,
    gate_seen: Arc<Notify>,
    gate_release: Arc<Notify>,
}

impl Fixture {
    fn start() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let pki = generate_pki();
        let keys = ServerKeys::generate();
        let replay_dir = tempfile::tempdir().unwrap();
        let (server_addr, gate_addr, gate_seen, gate_release) = runtime.block_on(async {
            let origin = spawn_origin(rustls_config(&pki)).await;
            let echo = spawn_echo().await;
            let config = server_config(origin, echo, &keys, replay_dir.path().to_path_buf());
            let server_addr = spawn_parallax_server(config).await;
            let gate_seen = Arc::new(Notify::new());
            let gate_release = Arc::new(Notify::new());
            let gate_addr = spawn_gate(
                server_addr,
                Arc::clone(&gate_seen),
                Arc::clone(&gate_release),
            )
            .await;
            (server_addr, gate_addr, gate_seen, gate_release)
        });
        Self {
            _runtime: runtime,
            _replay_dir: replay_dir,
            server_addr,
            keys,
            pki,
            gate_addr,
            gate_seen,
            gate_release,
        }
    }

    fn profile(&self, addr: SocketAddr, max_streams: u8) -> ClientProfile {
        ClientProfile::from_toml_str(&profile_toml(&addr.to_string(), &self.keys, max_streams))
            .unwrap()
    }

    fn verifier(&self) -> Arc<TestCaVerifier> {
        Arc::new(TestCaVerifier {
            ca_der: self.pki.ca_der.clone(),
            calls: AtomicUsize::new(0),
        })
    }
}

fn rustls_config(pki: &Pki) -> Arc<rustls::ServerConfig> {
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![pki.leaf_der.clone()], pki.leaf_key.clone_key())
        .unwrap(),
    )
}

/// The camouflage origin: completes TLS 1.3 for every spliced session, then
/// drains until the ParallaX server closes its side.
async fn spawn_origin(config: Arc<rustls::ServerConfig>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                let _ = serve_origin(stream, config).await;
            });
        }
    });
    addr
}

async fn serve_origin(
    mut stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
    let mut tls = rustls::ServerConnection::new(config).map_err(std::io::Error::other)?;
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out)?;
            stream.write_all(&out).await?;
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        tls.read_tls(&mut Cursor::new(&buf[..n]))?;
        tls.process_new_packets().map_err(std::io::Error::other)?;
    }
}

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    addr
}

fn server_config(
    origin: SocketAddr,
    echo: SocketAddr,
    keys: &ServerKeys,
    replay_dir: std::path::PathBuf,
) -> ServerConfig {
    ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        fallback_addr: origin.to_string(),
        // Every stream reaches the loopback echo whatever target it names.
        data_target: Some(echo.to_string()),
        nat64_prefixes: vec![],
        private_key: STANDARD.encode(keys.x25519.private).into(),
        identity_secret_key: STANDARD.encode(&keys.identity.secret).into(),
        replay_cache_path: replay_dir.join("parallax-replay.cache"),
        replay_cache_capacity: 49_152,
        authorized_sni: vec![SNI.to_owned()],
        strict_tls13: true,
        max_concurrent_per_source_v4: 1024,
        max_concurrent_per_source_v6: 1024,
        source_ipv6_prefix_len: 64,
        first_record_wait_floor_ms: 8_000,
        first_record_wait_jitter_ms: 7_000,
        fallback_idle_floor_ms: 600_000,
        fallback_idle_jitter_ms: 0,
        tcp_congestion: None,
    }
}

async fn spawn_parallax_server(config: ServerConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(config);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                let traffic = TrafficConfig {
                    max_concurrent_streams: 64,
                    ..TrafficConfig::default()
                };
                let _ =
                    server::handle_connection(stream, &config, traffic, &UdpConfig::default(), PSK)
                        .await;
            });
        }
    });
    addr
}

/// A TCP forwarder in front of the server that reports each connection and
/// holds it until released: it freezes a session build mid-handshake.
async fn spawn_gate(target: SocketAddr, seen: Arc<Notify>, release: Arc<Notify>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            seen.notify_one();
            release.notified().await;
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    addr
}

// ---------------------------------------------------------------------------
// Client side helpers (on the test's own runtime).
// ---------------------------------------------------------------------------

fn client_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Relays `payload` through the client and returns what the echo sent back.
async fn echo_through(
    client: &Client,
    payload: Vec<u8>,
) -> (Vec<u8>, parallax::embed::RelayReport) {
    let (app, relay_side) = tokio::io::duplex(64 * 1024);
    let (relay_read, relay_write) = tokio::io::split(relay_side);
    let relay = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .relay_tcp(
                    Target::Domain("echo.invalid".to_owned(), 7),
                    relay_read,
                    relay_write,
                )
                .await
        }
    });
    let (mut app_read, mut app_write) = tokio::io::split(app);
    let writer = tokio::spawn(async move {
        app_write.write_all(&payload).await.unwrap();
        app_write.shutdown().await.unwrap();
    });
    let mut echoed = Vec::new();
    timeout(Duration::from_secs(30), app_read.read_to_end(&mut echoed))
        .await
        .expect("echo did not finish in time")
        .unwrap();
    writer.await.unwrap();
    let report = timeout(Duration::from_secs(30), relay)
        .await
        .expect("relay did not finish in time")
        .unwrap()
        .expect("relay failed");
    (echoed, report)
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
}

async fn wait_for_no_alive_tasks() -> usize {
    let metrics = tokio::runtime::Handle::current().metrics();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while metrics.num_alive_tasks() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    metrics.num_alive_tasks()
}

// ---------------------------------------------------------------------------
// Loopback contract tests.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires loopback TCP sockets"]
fn constrained_client_relays_on_a_current_thread_runtime_through_the_injected_verifier() {
    let fixture = Fixture::start();
    let verifier = fixture.verifier();
    client_runtime().block_on(async {
        let client = Client::start(
            fixture.profile(fixture.server_addr, 4),
            ClientOptions::default()
                .with_memory(MemoryProfile::Constrained)
                .with_cert_verifier(verifier.clone()),
        )
        .unwrap();
        let sent = payload(256 * 1024, 0x11);
        let (echoed, report) = echo_through(&client, sent.clone()).await;
        assert_eq!(echoed, sent);
        assert_eq!(report.bytes_up, sent.len() as u64);
        assert_eq!(report.bytes_down, sent.len() as u64);
        assert!(
            verifier.calls.load(Ordering::Relaxed) >= 1,
            "the origin chain must be judged by the injected verifier"
        );
        client.shutdown();
    });
}

#[test]
#[ignore = "requires loopback TCP sockets"]
fn sixty_four_concurrent_streams_keep_their_bytes_apart() {
    let fixture = Fixture::start();
    client_runtime().block_on(async {
        let client = Client::start(
            fixture.profile(fixture.server_addr, 8),
            ClientOptions::default()
                .with_memory(MemoryProfile::Constrained)
                .with_cert_verifier(fixture.verifier()),
        )
        .unwrap();
        let mut streams = tokio::task::JoinSet::new();
        for seed in 0..64_u8 {
            let client = client.clone();
            streams.spawn(async move {
                let sent = payload(24 * 1024 + seed as usize * 97, seed);
                let (echoed, _) = echo_through(&client, sent.clone()).await;
                assert_eq!(echoed, sent, "stream {seed} got another stream's bytes");
            });
        }
        while let Some(joined) = streams.join_next().await {
            joined.unwrap();
        }
        client.shutdown();
    });
}

#[test]
#[ignore = "requires loopback TCP sockets"]
fn a_rejecting_verifier_fails_the_relay() {
    let fixture = Fixture::start();
    client_runtime().block_on(async {
        let client = Client::start(
            fixture.profile(fixture.server_addr, 4),
            ClientOptions::default().with_cert_verifier(Arc::new(RejectingVerifier)),
        )
        .unwrap();
        let (_app, relay_side) = tokio::io::duplex(1024);
        let (read, write) = tokio::io::split(relay_side);
        let result = timeout(
            Duration::from_secs(30),
            client.relay_tcp(Target::Domain("echo.invalid".to_owned(), 7), read, write),
        )
        .await
        .expect("a rejected origin must fail promptly");
        let err = result.expect_err("an untrusted origin must not carry data");
        assert!(
            err.to_string()
                .contains("rejected by the host trust policy"),
            "{err}"
        );
        client.shutdown();
    });
}

#[test]
#[ignore = "requires loopback TCP sockets"]
fn network_change_ends_live_sessions_and_the_client_keeps_working() {
    let fixture = Fixture::start();
    client_runtime().block_on(async {
        let client = Client::start(
            fixture.profile(fixture.server_addr, 4),
            ClientOptions::default()
                .with_memory(MemoryProfile::Constrained)
                .with_cert_verifier(fixture.verifier()),
        )
        .unwrap();
        // A stream that stays open across the change.
        let (mut app, relay_side) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(relay_side);
        let held = tokio::spawn({
            let client = client.clone();
            async move {
                client
                    .relay_tcp(Target::Domain("echo.invalid".to_owned(), 7), read, write)
                    .await
            }
        });
        app.write_all(b"before").await.unwrap();
        let mut echoed = [0_u8; 6];
        timeout(Duration::from_secs(30), app.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"before");

        client.network_changed();
        let ended = timeout(Duration::from_secs(5), held)
            .await
            .expect("a stream on a retired session must end promptly")
            .unwrap();
        assert!(
            ended.is_err(),
            "the held stream must fail, not finish cleanly"
        );

        let sent = payload(64 * 1024, 0x5C);
        let (echoed, _) = echo_through(&client, sent.clone()).await;
        assert_eq!(
            echoed, sent,
            "a new session serves traffic after the change"
        );
        client.shutdown();
    });
}

#[test]
#[ignore = "requires loopback TCP sockets"]
fn shutdown_leaves_no_live_task_on_the_host_runtime() {
    let fixture = Fixture::start();
    client_runtime().block_on(async {
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            0
        );
        let client = Client::start(
            fixture.profile(fixture.server_addr, 4),
            ClientOptions::default()
                .with_memory(MemoryProfile::Constrained)
                .with_cert_verifier(fixture.verifier()),
        )
        .unwrap();
        let (echoed, _) = echo_through(&client, b"ping".to_vec()).await;
        assert_eq!(echoed, b"ping");
        assert!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
                > 0,
            "a live session runs tasks"
        );

        client.shutdown();
        assert!(client.is_shut_down());
        assert_eq!(
            wait_for_no_alive_tasks().await,
            0,
            "nothing may survive shutdown"
        );
        let (_app, relay_side) = tokio::io::duplex(1024);
        let (read, write) = tokio::io::split(relay_side);
        let after = client
            .relay_tcp(Target::Domain("echo.invalid".to_owned(), 7), read, write)
            .await;
        assert!(matches!(after, Err(EmbedError::Shutdown)), "{after:?}");
        drop(client);
        assert_eq!(wait_for_no_alive_tasks().await, 0);
    });
}

#[test]
#[ignore = "requires loopback TCP sockets"]
fn dropping_the_last_client_shuts_it_down() {
    let fixture = Fixture::start();
    client_runtime().block_on(async {
        let client = Client::start(
            fixture.profile(fixture.server_addr, 4),
            ClientOptions::default().with_cert_verifier(fixture.verifier()),
        )
        .unwrap();
        let (echoed, _) = echo_through(&client, b"pong".to_vec()).await;
        assert_eq!(echoed, b"pong");
        drop(client);
        assert_eq!(
            wait_for_no_alive_tasks().await,
            0,
            "no client task outlives the client"
        );
    });
}

#[test]
#[ignore = "requires loopback TCP sockets"]
fn cancelling_a_relay_mid_build_does_not_wedge_the_pool() {
    let fixture = Fixture::start();
    client_runtime().block_on(async {
        let client = Client::start(
            fixture.profile(fixture.gate_addr, 4),
            ClientOptions::default()
                .with_memory(MemoryProfile::Constrained)
                .with_cert_verifier(fixture.verifier()),
        )
        .unwrap();
        // The first relay starts the pool's only build, which the gate freezes
        // before the camouflage handshake.
        let (_app, relay_side) = tokio::io::duplex(1024);
        let (read, write) = tokio::io::split(relay_side);
        let cancelled = tokio::spawn({
            let client = client.clone();
            async move {
                client
                    .relay_tcp(Target::Domain("echo.invalid".to_owned(), 7), read, write)
                    .await
            }
        });
        timeout(Duration::from_secs(10), fixture.gate_seen.notified())
            .await
            .expect("the build reached the gate");
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());

        // Release the frozen build; the next relay must not be stuck behind a
        // leaked build counter.
        fixture.gate_release.notify_waiters();
        let release_more = {
            let release = Arc::clone(&fixture.gate_release);
            tokio::spawn(async move {
                loop {
                    release.notify_waiters();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
        };
        let sent = payload(8 * 1024, 0x2A);
        let (echoed, _) = echo_through(&client, sent.clone()).await;
        assert_eq!(echoed, sent);
        release_more.abort();
        client.shutdown();
    });
}
