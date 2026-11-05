//! Scoped, loopback-only checks of the shipped server listener and its startup,
//! replay-journal and source-admission boundaries. Unlike handle_connection,
//! the child binary installs the real replay cache and admission permits.
//!
//! One test owns SSL_CERT_FILE before starting any Tokio worker or TLS handshake.
//! This target deliberately runs outside sanitizer lanes: its child process uses
//! normal production hardening and is terminated by a kill-and-reap guard.
//! Run explicitly: cargo test --locked --test security_listener -- --ignored --test-threads=1
//!
//! These are reproducible local security checks, not an external penetration test
//! or evidence of universal resistance to active probing.

#![cfg(unix)]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{self, Cursor, Write};
use std::net::{SocketAddr, TcpListener as StdListener};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use parallax::client::runtime::handle_local_connection;
use parallax::config::{ClientConfig, TrafficConfig, UdpConfig};
use parallax::crypto::identity::{self, MlDsaKeyPair};
use parallax::crypto::replay::{
    current_unix_timestamp, ReplayCache, ReplayEntry, ReplayInsertOutcome,
};
use parallax::crypto::session::X25519KeyPair;
use parallax::handshake::server::{self, InboundDecision};
use parallax::tls::record::TlsRecordReader;
use rand::{rngs::OsRng, RngCore};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::{NamedTempFile, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout, Instant};
use zeroize::Zeroizing;

const SNI: &str = "example.com";
const STEP: Duration = Duration::from_secs(12);
// Production rejection waits up to 60s, then has a 2s graceful-drain budget.
// Keep observing after the library client's separate 15s establishment timeout.
const REPLAY_TERMINAL: Duration = Duration::from_secs(75);
const MAX_CAPTURE_BYTES: usize = 256 * 1024;
type WireCapture = Arc<Mutex<Vec<u8>>>;
const REJECTED: &str = "closing on replayed ClientHello after data proof";
const AT_CAPACITY: &str = "replay cache at capacity with fresh entries";
const SOURCE_SHED: &str = "per-source connection limit reached; cap-shedding to origin";

struct Pki {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    ca_pem: String,
}

impl Pki {
    fn new() -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca.self_signed(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut leaf = CertificateParams::new(vec![SNI.to_owned()]).unwrap();
        leaf.is_ca = IsCa::ExplicitNoCa;
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();
        Self {
            certificate: leaf.der().clone(),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            ca_pem: ca.pem(),
        }
    }

    fn server_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![self.certificate.clone()], self.key.clone_key())
            .unwrap(),
        )
    }
}

struct TrustRoot {
    _file: NamedTempFile,
    previous: Option<OsString>,
}

impl TrustRoot {
    fn install(pem: &str) -> Self {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        file.flush().unwrap();
        let previous = std::env::var_os("SSL_CERT_FILE");
        // This integration target has exactly one test. Install before creating
        // its runtime; native_roots memoizes the first trust-store load.
        std::env::set_var("SSL_CERT_FILE", file.path());
        Self {
            _file: file,
            previous,
        }
    }
}

impl Drop for TrustRoot {
    fn drop(&mut self) {
        // The runtime has already dropped when this guard is destroyed.
        match &self.previous {
            Some(previous) => std::env::set_var("SSL_CERT_FILE", previous),
            None => std::env::remove_var("SSL_CERT_FILE"),
        }
    }
}

struct Secrets {
    psk: Zeroizing<[u8; 32]>,
    session: X25519KeyPair,
    identity: MlDsaKeyPair,
}

impl Secrets {
    fn new() -> Self {
        let mut psk = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(&mut *psk);
        Self {
            psk,
            session: X25519KeyPair::generate(),
            identity: identity::keypair(),
        }
    }
}

#[derive(Default)]
struct Tasks(Vec<JoinHandle<()>>);

impl Tasks {
    fn spawn(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        self.0.push(tokio::spawn(future));
    }

    async fn stop(mut self) {
        for task in &self.0 {
            task.abort();
        }
        for task in self.0.drain(..) {
            let _ = task.await;
        }
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

struct ServerFiles {
    _dir: TempDir,
    config: PathBuf,
    replay: PathBuf,
    address: SocketAddr,
    reservation: Option<StdListener>,
}

impl ServerFiles {
    fn new(
        keys: &Secrets,
        origin: SocketAddr,
        target: SocketAddr,
        replay_capacity: usize,
        source_capacity: u32,
    ) -> Self {
        assert!(origin.ip().is_loopback() && target.ip().is_loopback());
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("server.toml");
        let replay = dir.path().join("replay.cache");
        let reservation = StdListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        let replay_literal = toml::Value::String(replay.to_str().unwrap().to_owned());
        let text = Zeroizing::new(format!(
            r#"mode = "server"
[crypto]
psk = "{}"
[server]
listen = "{}"
fallback_addr = "{}"
data_target = "{}"
private_key = "{}"
identity_secret_key = "{}"
replay_cache_path = {}
replay_cache_capacity = {}
authorized_sni = ["{}"]
strict_tls13 = true
max_concurrent_per_source_v4 = {}
max_concurrent_per_source_v6 = {}
source_ipv6_prefix_len = 64
first_record_wait_floor_ms = 120000
first_record_wait_jitter_ms = 0
fallback_idle_floor_ms = 5000
fallback_idle_jitter_ms = 0
"#,
            STANDARD.encode(keys.psk.as_slice()),
            address,
            origin,
            target,
            STANDARD.encode(keys.session.private),
            STANDARD.encode(&keys.identity.secret),
            replay_literal,
            replay_capacity,
            SNI,
            source_capacity,
            source_capacity,
        ));
        write_private(&config, text.as_bytes());
        Self {
            _dir: dir,
            config,
            replay,
            address,
            reservation: Some(reservation),
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
}

struct ChildServer {
    child: Child,
    log: NamedTempFile,
}

impl ChildServer {
    fn spawn(files: &mut ServerFiles) -> Self {
        let log = NamedTempFile::new().unwrap();
        // The OS cannot transfer a reserved TCP port to this CLI. Release just
        // before spawn; startup failures are fatal, never silently retried.
        drop(files.reservation.take());
        let child = Command::new(env!("CARGO_BIN_EXE_parallax"))
            .args(["serve", "-c"])
            .arg(&files.config)
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.as_file().try_clone().unwrap()))
            .stderr(Stdio::from(log.as_file().try_clone().unwrap()))
            .spawn()
            .expect("spawn the actual ParallaX server binary");
        Self { child, log }
    }

    fn log_count(&self, marker: &str) -> usize {
        // Logs stay in a private temporary file and are never emitted as CI
        // artifacts. Readiness does not open a connection and consume a permit.
        let raw = fs::read_to_string(self.log.path()).unwrap();
        assert!(raw.len() <= 256 * 1024, "unexpected child log volume");
        raw.matches(marker).count()
    }

    async fn wait_for(&mut self, marker: &str) {
        let deadline = Instant::now() + STEP;
        while self.log_count(marker) == 0 {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "server exited before expected lifecycle event"
            );
            assert!(
                Instant::now() < deadline,
                "server lifecycle event timed out: {marker}"
            );
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn ready(&mut self) {
        self.wait_for("ParallaX server listening").await;
    }

    async fn rejected_startup(&mut self) {
        let status = timeout(STEP, async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("corrupt-journal startup did not terminate");
        assert!(!status.success(), "corrupt journal was accepted");
        assert_eq!(self.log_count("ParallaX server listening"), 0);
        assert!(self.log_count("replay cache MAC mismatch") > 0);
    }

    fn stop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().expect("kill child server");
        }
        self.child.wait().expect("reap child server");
    }
}

impl Drop for ChildServer {
    fn drop(&mut self) {
        // Also runs during assertion unwinding and outer timeouts.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn echo_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return stream.shutdown().await;
        }
        stream.write_all(&buffer[..n]).await?;
    }
}

async fn echo_service(tasks: &mut Tasks) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tasks.spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                connection = listener.accept() => {
                    let (stream, _) = connection.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    children.spawn(echo_connection(stream));
                }
                _ = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    (address, accepted)
}

async fn flush_tls(
    server: &mut rustls::ServerConnection,
    stream: &mut TcpStream,
    capture: Option<&WireCapture>,
) -> io::Result<()> {
    while server.wants_write() {
        let mut wire = Vec::new();
        server.write_tls(&mut wire)?;
        if wire.is_empty() {
            break;
        }
        if let Some(capture) = capture {
            let mut offset = 0;
            while offset < wire.len() {
                stream.writable().await?;
                // Record only bytes actually written. The lock spans try_write
                // and append, so an EOF observer cannot see an incomplete trace
                // while another worker has already delivered those bytes.
                let written = {
                    let mut trace = capture.lock().unwrap();
                    match stream.try_write(&wire[offset..]) {
                        Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                        Ok(n) => {
                            assert!(trace.len() + n <= MAX_CAPTURE_BYTES);
                            trace.extend_from_slice(&wire[offset..offset + n]);
                            Ok(n)
                        }
                        Err(err) => Err(err),
                    }
                };
                match written {
                    Ok(n) => offset += n,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(err) => return Err(err),
                }
            }
        } else {
            stream.write_all(&wire).await?;
        }
    }
    Ok(())
}

async fn tls_connection(
    mut stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    echo_probe: bool,
    capture: Option<WireCapture>,
) -> io::Result<()> {
    let mut header = [0; 5];
    stream.read_exact(&mut header).await?;
    // Only the quota fixture enables this exact synthetic probe. All other
    // traffic gets the real rustls handshake, including the recovery control.
    if echo_probe && header == *b"\x16\x03\x01\x00\x05" {
        stream.write_all(&header).await?;
        return echo_connection(stream).await;
    }
    let mut server = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
    server.read_tls(&mut Cursor::new(&header))?;
    server.process_new_packets().map_err(io::Error::other)?;
    let mut buffer = [0; 8192];
    while server.is_handshaking() {
        flush_tls(&mut server, &mut stream, capture.as_ref()).await?;
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        server.read_tls(&mut Cursor::new(&buffer[..n]))?;
        server.process_new_packets().map_err(io::Error::other)?;
    }
    flush_tls(&mut server, &mut stream, capture.as_ref()).await?;
    while let Ok(Ok(n)) = timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        if n == 0 {
            break;
        }
    }
    Ok(())
}

async fn tls_service(
    pki: &Pki,
    tasks: &mut Tasks,
    echo_probe: bool,
    capture: Option<WireCapture>,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = pki.server_config();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tasks.spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                connection = listener.accept() => {
                    let (stream, _) = connection.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    children.spawn(tls_connection(
                        stream, Arc::clone(&config), echo_probe, capture.clone(),
                    ));
                }
                _ = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    (address, accepted)
}

async fn local_client(
    upstream: SocketAddr,
    keys: &Secrets,
    tasks: &mut Tasks,
) -> (SocketAddr, oneshot::Receiver<bool>) {
    assert!(upstream.ip().is_loopback());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = ClientConfig {
        listen: address,
        server_addr: upstream.to_string(),
        sni: SNI.to_owned(),
        server_public_key: STANDARD.encode(keys.session.public),
        server_identity_public_key: STANDARD.encode(&keys.identity.public),
        accept_language: None,
    };
    let psk = keys.psk.clone();
    let public = keys.session.public;
    let identity_public = keys.identity.public.clone();
    let (done, result) = oneshot::channel();
    tasks.spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let success = handle_local_connection(
            stream,
            &config,
            TrafficConfig::default(),
            &UdpConfig::default(),
            &*psk,
            &public,
            &identity_public,
        )
        .await
        .is_ok();
        let _ = done.send(success);
    });
    (address, result)
}

async fn begin_socks(local: SocketAddr, target: SocketAddr) -> TcpStream {
    assert!(local.ip().is_loopback() && target.ip().is_loopback());
    let mut app = TcpStream::connect(local).await.unwrap();
    app.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    app.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    app.write_all(&[
        5,
        1,
        0,
        1,
        127,
        0,
        0,
        1,
        (target.port() >> 8) as u8,
        target.port() as u8,
    ])
    .await
    .unwrap();
    app
}

async fn tunnel_roundtrip(app: &mut TcpStream) {
    let mut reply = [0; 10];
    app.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..2], [5, 0]);
    let payload: Vec<u8> = (0..32768).map(|i| (i % 251) as u8).collect();
    let mut echoed = vec![0; payload.len()];
    let (mut read, mut write) = app.split();
    let (sent, received) = tokio::join!(write.write_all(&payload), read.read_exact(&mut echoed));
    sent.unwrap();
    received.unwrap();
    assert_eq!(echoed, payload);
    write.shutdown().await.unwrap();
    let mut trailing = Vec::new();
    read.read_to_end(&mut trailing).await.unwrap();
    assert!(trailing.is_empty());
}

// This tap deliberately does not propagate client EOF upstream. A timed-out
// client must not cause the server close which the rejection assertion observes.
// Download stays active even if the client no longer accepts forwarded bytes.
async fn observe_server_rejection(captured: TcpStream, upstream: TcpStream) -> io::Result<Vec<u8>> {
    let (mut client_read, mut client_write) = captured.into_split();
    let (mut server_read, mut server_write) = upstream.into_split();
    let result = {
        let upload = async {
            let mut buffer = [0; 8192];
            loop {
                match client_read.read(&mut buffer).await {
                    Ok(0) | Err(_) => {
                        // Keep server_write owned and open until *server* EOF.
                        return std::future::pending::<io::Result<()>>().await;
                    }
                    Ok(n) => server_write.write_all(&buffer[..n]).await?,
                }
            }
        };
        let download = async {
            let mut wire = Vec::new();
            let mut buffer = [0; 8192];
            let mut client_open = true;
            loop {
                let n = server_read.read(&mut buffer).await?;
                if n == 0 {
                    return Ok(wire);
                }
                if wire.len() + n > MAX_CAPTURE_BYTES {
                    return Err(io::Error::other("rejected server exceeded capture bound"));
                }
                wire.extend_from_slice(&buffer[..n]);
                if client_open {
                    client_open = matches!(
                        timeout(STEP, client_write.write_all(&buffer[..n])).await,
                        Ok(Ok(()))
                    );
                }
            }
        };
        tokio::select! {
            result = download => result,
            result = upload => {
                result?;
                Err(io::Error::other("tap upload unexpectedly completed"))
            }
        }
    };
    if result.is_ok() {
        // Only after genuine upstream read == 0, cooperate with the server's
        // lingering drain. Reset/read errors and task cancellation are failures.
        server_write.shutdown().await?;
        let _ = client_write.shutdown().await;
    }
    result
}

#[derive(Clone, Copy, Debug)]
enum ReplayCase {
    Fresh,
    Duplicate,
    Full,
}

async fn listener_replay_case(pki: &Pki, case: ReplayCase) {
    let keys = Secrets::new();
    let mut tasks = Tasks::default();
    let origin_wire = Arc::new(Mutex::new(Vec::new()));
    let (origin, origin_accepts) =
        tls_service(pki, &mut tasks, false, Some(Arc::clone(&origin_wire))).await;
    let (target, target_accepts) = echo_service(&mut tasks).await;
    let capacity = if matches!(case, ReplayCase::Full) {
        1
    } else {
        8
    };
    let mut files = ServerFiles::new(&keys, origin, target, capacity, 8);
    let tap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (local, client_done) = local_client(tap.local_addr().unwrap(), &keys, &mut tasks).await;
    let mut app = timeout(STEP, begin_socks(local, target)).await.unwrap();
    let (mut captured, _) = timeout(STEP, tap.accept()).await.unwrap().unwrap();
    let hello = timeout(STEP, TlsRecordReader::new(&mut captured).read_record())
        .await
        .unwrap()
        .unwrap();
    // Setup only: derive the identity of this *live* client's captured hello.
    // The real child independently authenticates it, completes PQ proof and
    // consults its durable cache. The client's ephemerals remain alive.
    let InboundDecision::Authenticated(authenticated) =
        server::decide_inbound(&hello, &*keys.psk, &[SNI.to_owned()], &keys.session.private)
            .unwrap()
    else {
        panic!("captured ClientHello must be a valid positive control");
    };
    let entry = ReplayEntry {
        timestamp: authenticated.timestamp,
        nonce: authenticated.nonce,
        transcript_fingerprint: authenticated.transcript_fingerprint,
    };
    let mut seeded = entry.clone();
    seeded.nonce[0] ^= 1;
    seeded.transcript_fingerprint[0] ^= 1;
    if !matches!(case, ReplayCase::Fresh) {
        let mut cache =
            ReplayCache::load_or_create_authenticated(&files.replay, capacity, &*keys.psk).unwrap();
        let seed = if matches!(case, ReplayCase::Duplicate) {
            &entry
        } else {
            &seeded
        };
        assert_eq!(
            cache
                .insert_new_outcome(seed.clone(), current_unix_timestamp().unwrap())
                .unwrap(),
            ReplayInsertOutcome::Inserted,
        );
    }

    let mut child = ChildServer::spawn(&mut files);
    child.ready().await;
    let address = files.address;
    let (closed, terminal) = oneshot::channel();
    tasks.spawn(async move {
        let result = async {
            let mut upstream = TcpStream::connect(address).await?;
            upstream.write_all(&hello).await?;
            if matches!(case, ReplayCase::Fresh) {
                tokio::io::copy_bidirectional(&mut captured, &mut upstream).await?;
                Ok(Vec::new())
            } else {
                observe_server_rejection(captured, upstream).await
            }
        }
        .await;
        let _ = closed.send(result);
    });
    if matches!(case, ReplayCase::Fresh) {
        timeout(STEP, tunnel_roundtrip(&mut app))
            .await
            .expect("fresh tunnel failed");
        assert!(timeout(STEP, client_done).await.unwrap().unwrap());
        assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    } else {
        // This marker proves the valid client reached the post-PQ decision; it
        // is not proof of rejection. Continue until independent upstream EOF.
        child.wait_for(REJECTED).await;
        if matches!(case, ReplayCase::Full) {
            assert!(child.log_count(AT_CAPACITY) > 0);
        } else {
            assert_eq!(child.log_count(AT_CAPACITY), 0);
        }
        assert_eq!(target_accepts.load(Ordering::SeqCst), 0);
        let rejected_wire = timeout(REPLAY_TERMINAL, terminal)
            .await
            .expect("server did not close within the full replay rejection budget")
            .expect("independent rejection tap failed")
            .expect("server rejection was not a clean upstream EOF");
        assert_eq!(origin_accepts.load(Ordering::SeqCst), 1);
        assert!(!rejected_wire.is_empty(), "missing TLS positive control");
        // The rejected connection may forward a prefix of the real origin's
        // TLS output (including tickets), but must generate no PQ/identity/data
        // continuation of its own, even after the library client times out.
        assert!(
            origin_wire.lock().unwrap().starts_with(&rejected_wire),
            "{case:?}: rejected server emitted an authenticated continuation",
        );
        assert_eq!(target_accepts.load(Ordering::SeqCst), 0);
        // SOCKS success is optimistic (sent before upstream establishment), and
        // the client has its own 15s timeout. Neither is a rejection oracle.
        assert!(
            child.child.try_wait().unwrap().is_none(),
            "server process exit must not masquerade as connection rejection",
        );
    }
    drop(app);
    child.stop();
    assert_eq!(
        fs::metadata(&files.replay).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut persisted =
        ReplayCache::load_or_create_authenticated(&files.replay, capacity, &*keys.psk).unwrap();
    let expected = if matches!(case, ReplayCase::Full) {
        ReplayInsertOutcome::CacheFull
    } else {
        ReplayInsertOutcome::Replayed
    };
    assert_eq!(
        persisted
            .insert_new_outcome(entry, current_unix_timestamp().unwrap())
            .unwrap(),
        expected,
        "durable replay state must survive a process restart",
    );
    if matches!(case, ReplayCase::Full) {
        assert_eq!(
            persisted
                .insert_new_outcome(seeded, current_unix_timestamp().unwrap())
                .unwrap(),
            ReplayInsertOutcome::Replayed,
            "capacity exhaustion must not evict a fresh entry",
        );
    }
    tasks.stop().await;
}

async fn corrupted_journal_refuses_startup() {
    let keys = Secrets::new();
    let mut tasks = Tasks::default();
    let (origin, origin_accepts) = echo_service(&mut tasks).await;
    let (target, target_accepts) = echo_service(&mut tasks).await;
    let mut files = ServerFiles::new(&keys, origin, target, 8, 8);
    let mut nonce = [0; 8];
    let mut fingerprint = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    OsRng.fill_bytes(&mut fingerprint);
    let mut cache =
        ReplayCache::load_or_create_authenticated(&files.replay, 8, &*keys.psk).unwrap();
    assert!(cache
        .insert_new(
            ReplayEntry {
                timestamp: current_unix_timestamp().unwrap(),
                nonce,
                transcript_fingerprint: fingerprint,
            },
            current_unix_timestamp().unwrap()
        )
        .unwrap());
    drop(cache);
    ReplayCache::load_or_create_authenticated(&files.replay, 8, &*keys.psk)
        .expect("untampered journal is a valid control");
    let mut raw = fs::read(&files.replay).unwrap();
    // v4 has two recoverable header slots. Tamper the committed entry, so the
    // expected failure is authentication, not legitimate single-slot repair.
    let body = raw
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .nth(1)
        .unwrap()
        .0
        + 1;
    assert!(raw[body].is_ascii_digit());
    raw[body] = if raw[body] == b'0' { b'1' } else { b'0' };
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&files.replay)
        .unwrap();
    file.write_all(&raw).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let mut child = ChildServer::spawn(&mut files);
    child.rejected_startup().await;
    assert_eq!(origin_accepts.load(Ordering::SeqCst), 0);
    assert_eq!(target_accepts.load(Ordering::SeqCst), 0);
    assert!(
        StdListener::bind(files.address).is_ok(),
        "failed startup left a listener"
    );
    tasks.stop().await;
}

async fn wait_accepts(counter: &AtomicUsize, minimum: usize) {
    timeout(STEP, async {
        while counter.load(Ordering::SeqCst) < minimum {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("loopback accept control timed out");
}

async fn raw_fallback_roundtrip(address: SocketAddr) {
    let mut peer = TcpStream::connect(address).await.unwrap();
    let bytes = b"\x16\x03\x01\x00\x05probe";
    peer.write_all(bytes).await.unwrap();
    let mut echoed = vec![0; bytes.len()];
    peer.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, bytes, "cap-shed origin relay changed bytes");
    peer.shutdown().await.unwrap();
    let mut trailing = Vec::new();
    peer.read_to_end(&mut trailing).await.unwrap();
    assert!(trailing.is_empty());
}

async fn source_quota_sheds_then_recovers(pki: &Pki) {
    let keys = Secrets::new();
    let mut tasks = Tasks::default();
    let (origin, origin_accepts) = tls_service(pki, &mut tasks, true, None).await;
    let (target, target_accepts) = echo_service(&mut tasks).await;
    let mut files = ServerFiles::new(&keys, origin, target, 8, 1);
    let mut child = ChildServer::spawn(&mut files);
    child.ready().await;
    let mut held = TcpStream::connect(files.address).await.unwrap();
    held.write_all(&[0x16]).await.unwrap();
    // The normal admitted path pre-dials the origin while awaiting the rest of
    // its header. Observing that dial proves the first source permit is held.
    wait_accepts(&origin_accepts, 1).await;
    timeout(STEP, raw_fallback_roundtrip(files.address))
        .await
        .unwrap();
    child.wait_for(SOURCE_SHED).await;
    assert_eq!(child.log_count(SOURCE_SHED), 1);
    assert_eq!(origin_accepts.load(Ordering::SeqCst), 2);
    assert_eq!(target_accepts.load(Ordering::SeqCst), 0);
    held.shutdown().await.unwrap();
    drop(held);

    // Both capped and normal fallback paths echo, so successful I/O alone
    // cannot prove permit recovery. Require a subsequent complete probe which
    // does not increase the source-cap counter, after the held socket closes.
    timeout(STEP, async {
        loop {
            let before = child.log_count(SOURCE_SHED);
            raw_fallback_roundtrip(files.address).await;
            let after = child.log_count(SOURCE_SHED);
            if after == before {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("source permit was not released after disconnect");
    assert_eq!(target_accepts.load(Ordering::SeqCst), 0);
    // Close the observability gap: a fresh authenticated tunnel must now reach
    // the target. Recovery is not established solely from log disappearance.
    let (local, client_done) = local_client(files.address, &keys, &mut tasks).await;
    let mut app = timeout(STEP, begin_socks(local, target)).await.unwrap();
    timeout(STEP, tunnel_roundtrip(&mut app)).await.unwrap();
    assert!(timeout(STEP, client_done).await.unwrap().unwrap());
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    child.stop();
    tasks.stop().await;
}

#[test]
#[ignore = "requires loopback sockets and the production server child process"]
fn real_listener_enforces_replay_integrity_capacity_and_source_admission() {
    let pki = Pki::new();
    let _trust = TrustRoot::install(&pki.ca_pem);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        timeout(Duration::from_secs(160), async {
            listener_replay_case(&pki, ReplayCase::Fresh).await;
            tokio::join!(
                listener_replay_case(&pki, ReplayCase::Duplicate),
                listener_replay_case(&pki, ReplayCase::Full),
            );
            corrupted_journal_refuses_startup().await;
            source_quota_sheds_then_recovers(&pki).await;
        })
        .await
        .expect("listener security battery exceeded its overall deadline");
    });
}
