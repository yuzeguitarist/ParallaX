//! Shipped-binary E2E: SOCKS5 -> authenticated TLS/PQ/identity -> TCP or
//! QUIC/H3 relay -> local target. By default every endpoint is loopback; only
//! the child client trusts the temporary CA. No cfg(test) certificate bypass is involved.
//!
//! Run: cargo test --locked --test protocol_e2e -- --ignored --test-threads=1
//! QUIC assertions require both a Verified probe and the server's actual relay
//! selection, so silent TCP fallback cannot make a QUIC case pass. Two sequential
//! QUIC sessions also exercise ticket-cache reuse, but acceptance of 0-RTT is
//! asserted separately by the library's dedicated resumption test.
//! Successful loopback relays use the operator's fixed-target setting: client-
//! chosen loopback destinations are deliberately denied by the production SSRF
//! policy. A separate case omits that setting and verifies the denial after a
//! real encrypted ConnectRequest, without adding a test escape to that policy.
//! With PARALLAX_TEST_PUBLIC_TARGET=<IP>, only binary_tcp_socks_pq_identity_roundtrip
//! binds its echo target at that explicitly supplied IP and omits data_target.
//! Run that exact test with --ignored --nocapture inside an isolated Linux
//! network namespace where the public-shaped IP is already assigned. Only this
//! mode emits PUBLIC_ROUTE_VERIFIED after two actual client-selected relays.

#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener as StdListener};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use parallax::crypto::{identity, session::X25519KeyPair};
use rand::{rngs::OsRng, RngCore};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

const SNI: &str = "example.com";
const STEP: Duration = Duration::from_secs(25);

fn write_private(path: &Path, contents: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(contents).unwrap();
    file.sync_all().unwrap();
}

struct Binary {
    child: Child,
    log: NamedTempFile,
}

impl Binary {
    fn spawn(command: &str, config: &Path, ca: &Path) -> Self {
        let log = NamedTempFile::new().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_parallax"))
            .args([command, "--config"])
            .arg(config)
            .env("SSL_CERT_FILE", ca)
            .env(
                "RUST_LOG",
                "info,parallax::client::runtime=debug,parallax::handshake::server=debug",
            )
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.as_file().try_clone().unwrap()))
            .stderr(Stdio::from(log.as_file().try_clone().unwrap()))
            .spawn()
            .expect("start the shipped ParallaX binary");
        Self { child, log }
    }

    fn logs(&self) -> String {
        let logs = fs::read_to_string(self.log.path()).unwrap();
        assert!(logs.len() < 1024 * 1024, "unexpected child log volume");
        logs
    }

    async fn wait_for(&mut self, marker: &str) {
        timeout(STEP, async {
            loop {
                if self.logs().contains(marker) {
                    return;
                }
                assert!(
                    self.child.try_wait().unwrap().is_none(),
                    "binary exited before lifecycle event {marker}:\n{}",
                    self.logs()
                );
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "binary lifecycle event timed out: {marker}:\n{}",
                self.logs()
            )
        });
    }
}

impl Drop for Binary {
    fn drop(&mut self) {
        // Only these owned children are terminated; always reap, including panic.
        let _ = self.child.kill();
        self.child.wait().expect("reap the E2E child");
    }
}

fn local_pki(root_name: &str) -> (Arc<rustls::ServerConfig>, String, CertificateDer<'static>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.distinguished_name.push(DnType::CommonName, root_name);
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec![SNI.to_owned()]).unwrap();
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    (Arc::new(config), ca.pem(), ca.der().clone())
}

async fn serve_origin(mut stream: TcpStream, config: Arc<rustls::ServerConfig>) -> io::Result<()> {
    let mut tls = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        while tls.wants_write() {
            let mut flight = Vec::new();
            tls.write_tls(&mut flight)?;
            stream.write_all(&flight).await?;
        }
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        tls.read_tls(&mut Cursor::new(&buffer[..n]))?;
        tls.process_new_packets().map_err(io::Error::other)?;
        // Ordinary browsers must receive real TLS application traffic through
        // the unauthenticated splice. The authenticated path can abandon this
        // origin at PQ cutover, independently of this application echo.
        loop {
            match tls.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => tls.writer().write_all(&buffer[..n])?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
    }
}

async fn browser_tls_echo(server: SocketAddr, ca: CertificateDer<'static>) {
    timeout(STEP, async {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut tls =
            rustls::ClientConnection::new(Arc::new(config), ServerName::try_from(SNI).unwrap())
                .unwrap();
        let mut wire = TcpStream::connect(server).await.unwrap();
        let payload = b"ordinary TLS application bytes through the origin splice";
        tls.writer().write_all(payload).unwrap();
        let mut echoed = Vec::new();
        let mut buffer = [0; 16 * 1024];
        while echoed.len() < payload.len() {
            while tls.wants_write() {
                let mut flight = Vec::new();
                tls.write_tls(&mut flight).unwrap();
                wire.write_all(&flight).await.unwrap();
            }
            let n = wire.read(&mut buffer).await.unwrap();
            assert_ne!(
                n, 0,
                "ordinary TLS splice closed before the application reply"
            );
            tls.read_tls(&mut Cursor::new(&buffer[..n])).unwrap();
            tls.process_new_packets().unwrap();
            loop {
                match tls.reader().read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => echoed.extend_from_slice(&buffer[..n]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("ordinary TLS splice application read failed: {error}"),
                }
            }
        }
        assert_eq!(echoed, payload);
        tls.send_close_notify();
        let mut close = Vec::new();
        tls.write_tls(&mut close).unwrap();
        wire.write_all(&close).await.unwrap();
        wire.shutdown().await.unwrap();
    })
    .await
    .expect("unauthenticated TLS splice must complete with verified origin identity");
}

async fn connect_socks(local: SocketAddr, target: SocketAddr) -> TcpStream {
    timeout(STEP, connect_socks_inner(local, target, 3, &[]))
        .await
        .expect("SOCKS connect and negotiation must complete")
}

async fn connect_socks_inner(
    local: SocketAddr,
    target: SocketAddr,
    atyp: u8,
    initial_payload: &[u8],
) -> TcpStream {
    let mut app = TcpStream::connect(local).await.unwrap();
    // Fragment negotiation and use the DOMAIN address form, rather than calling
    // a protocol helper. The actual SOCKS listener must parse these wire bytes.
    for byte in [5, 1, 0] {
        app.write_all(&[byte]).await.unwrap();
    }
    let mut method = [0; 2];
    app.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0, atyp];
    match atyp {
        1 => match target.ip() {
            std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
            std::net::IpAddr::V6(_) => unreachable!("IPv6 targets require SOCKS ATYP 4 or DOMAIN"),
        },
        3 => {
            let host = target.ip().to_string();
            request.push(u8::try_from(host.len()).unwrap());
            request.extend_from_slice(host.as_bytes());
        }
        4 => {
            let ip = match target.ip() {
                std::net::IpAddr::V6(ip) => ip,
                // Existing fixed-target mux cases intentionally test the IPv6
                // address form while the operator routes to the IPv4 fixture.
                std::net::IpAddr::V4(_) => std::net::Ipv6Addr::LOCALHOST,
            };
            request.extend_from_slice(&ip.octets());
        }
        _ => unreachable!("E2E driver only sends the three SOCKS address forms"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(initial_payload);
    app.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    app.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..2], &[5, 0]);
    // This reply is optimistic; only target bytes below prove authentication.
    app
}

async fn roundtrip(local: SocketAddr, target: SocketAddr, stream: u8) {
    let payload: Vec<_> = (0..(256 * 1024 + 37))
        .map(|i| ((i * 37 + usize::from(stream)) % 251) as u8)
        .collect();
    let atyp = if target.is_ipv6() && stream == 1 {
        4
    } else {
        [1, 3, 4][usize::from(stream - 1) % 3]
    };
    let mut app = timeout(
        STEP,
        connect_socks_inner(local, target, atyp, &payload[..4096]),
    )
    .await
    .expect("SOCKS request pipelined with initial application payload must succeed");
    let (mut read, mut write) = app.split();
    let send = async {
        for chunk in payload[4096..].chunks(8191) {
            write.write_all(chunk).await.unwrap();
        }
        write.shutdown().await.unwrap();
    };
    let receive = async {
        let mut echoed = vec![0; payload.len()];
        read.read_exact(&mut echoed)
            .await
            .expect("receive complete target payload");
        assert_eq!(
            echoed, payload,
            "bytes must retain stream identity and ordering"
        );
        let mut tail = [0];
        assert_eq!(read.read(&mut tail).await.expect("clean FIN, not reset"), 0);
    };
    timeout(STEP, async { tokio::join!(send, receive) })
        .await
        .expect("SOCKS authenticated roundtrip and half-close must complete");
}

async fn malformed_socks(local: SocketAddr, client: &mut Binary) {
    for (greeting, reason) in [
        (&[4, 1, 0][..], "unsupported SOCKS version: 4"),
        (
            &[5, 0][..],
            "SOCKS client offered no authentication methods",
        ),
    ] {
        timeout(STEP, async {
            let mut app = TcpStream::connect(local).await.unwrap();
            app.write_all(greeting).await.unwrap();
            app.shutdown().await.unwrap();
            let mut byte = [0];
            assert!(matches!(app.read(&mut byte).await, Ok(0) | Err(_)));
        })
        .await
        .expect("invalid SOCKS greeting must close locally");
        client.wait_for(reason).await;
    }
    for (request, reason) in [
        (
            &[5, 2, 0, 1, 127, 0, 0, 1, 0, 80][..],
            "unsupported SOCKS command: 2",
        ),
        (
            &[5, 1, 1, 1, 127, 0, 0, 1, 0, 80][..],
            "SOCKS reserved byte must be zero",
        ),
        (&[5, 1, 0, 1, 127][..], "SOCKS error: I/O error:"),
        (&[5, 1, 0, 4, 0, 0, 0][..], "SOCKS error: I/O error:"),
        (&[5, 1, 0, 3, 3, b'a'][..], "SOCKS error: I/O error:"),
        (&[5, 1, 0, 3, 0, 0, 80][..], "SOCKS domain name is empty"),
        (
            &[5, 1, 0, 3, 1, 0xff, 0, 80][..],
            "SOCKS domain name is not valid UTF-8",
        ),
        (
            &[5, 1, 0, 1, 127, 0, 0, 1, 0, 0][..],
            "SOCKS target port must not be zero",
        ),
        (&[5, 1, 0, 9][..], "unsupported SOCKS address type: 9"),
    ] {
        timeout(STEP, async {
            let mut app = TcpStream::connect(local).await.unwrap();
            app.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            app.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            app.write_all(request).await.unwrap();
            app.shutdown().await.unwrap();
            let mut byte = [0];
            assert!(matches!(app.read(&mut byte).await, Ok(0) | Err(_)));
        })
        .await
        .expect("invalid SOCKS request must close locally");
        client.wait_for(reason).await;
    }
}

#[derive(Clone, Copy)]
enum Case {
    Tcp,
    TcpMux,
    Quic,
    QuicMux,
    DeclineUdp,
    WrongIdentity,
    DeniedTarget,
    WrongPsk,
    WrongX25519,
    UntrustedOrigin,
    WrongOriginName,
    OriginSplice,
    SocksBoundaries,
}

async fn scenario(case: Case) {
    let dir = tempfile::tempdir().unwrap();
    let (origin_config, ca, ca_der) = local_pki("ParallaX E2E Trusted Root");
    let ca_path = dir.path().join("ca.pem");
    write_private(&ca_path, ca.as_bytes());
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let public_target = if matches!(case, Case::Tcp) {
        std::env::var_os("PARALLAX_TEST_PUBLIC_TARGET").map(|value| {
            value
                .into_string()
                .expect("PARALLAX_TEST_PUBLIC_TARGET must be an IP address")
                .parse::<std::net::IpAddr>()
                .expect("PARALLAX_TEST_PUBLIC_TARGET must be an IP address")
        })
    } else {
        None
    };
    let target_ip = public_target.unwrap_or(std::net::Ipv4Addr::LOCALHOST.into());
    let target = TcpListener::bind(SocketAddr::new(target_ip, 0))
        .await
        .expect("bind the exact requested E2E echo target address");
    let target_addr = target.local_addr().unwrap();
    assert_eq!(
        target_addr.ip(),
        target_ip,
        "fixture must bind the requested IP"
    );
    let target_accepts = Arc::new(AtomicUsize::new(0));
    let mut fixtures = JoinSet::new();
    fixtures.spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = origin.accept() => {
                    let (stream, _) = accepted.unwrap();
                    let config = Arc::clone(&origin_config);
                    connections.spawn(async move {
                        // Cancellation at the PQ handoff may close the origin
                        // mid-flight. The application roundtrip is the success oracle.
                        let _ = timeout(STEP, serve_origin(stream, config)).await;
                    });
                }
                Some(result) = connections.join_next() => result.unwrap(),
            }
        }
    });
    let accepts = Arc::clone(&target_accepts);
    fixtures.spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = target.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    accepts.fetch_add(1, Ordering::SeqCst);
                    connections.spawn(async move {
                        let (mut read, mut write) = stream.split();
                        tokio::io::copy(&mut read, &mut write).await.unwrap();
                        write.shutdown().await.unwrap();
                    });
                }
                Some(result) = connections.join_next() => result.unwrap(),
            }
        }
    });

    let server_reservation = StdListener::bind("127.0.0.1:0").unwrap();
    let server_addr = server_reservation.local_addr().unwrap();
    let client_reservation = StdListener::bind("127.0.0.1:0").unwrap();
    let client_addr = client_reservation.local_addr().unwrap();
    let session = X25519KeyPair::generate();
    let identity = identity::keypair();
    let pinned_identity = if matches!(case, Case::WrongIdentity) {
        identity::keypair().public.clone()
    } else {
        identity.public.clone()
    };
    let mut psk = [0; 32];
    OsRng.fill_bytes(&mut psk);
    let server_udp = matches!(case, Case::Quic | Case::QuicMux);
    let client_udp = server_udp || matches!(case, Case::DeclineUdp);
    let mux = matches!(case, Case::TcpMux | Case::QuicMux);
    let server_path = dir.path().join("server.toml");
    let client_path = dir.path().join("client.toml");
    let traffic = if mux { 8 } else { 1 };
    let fixed_target = if matches!(case, Case::DeniedTarget) || public_target.is_some() {
        String::new()
    } else {
        format!("data_target = \"{target_addr}\"")
    };
    let allowed_sni = if matches!(case, Case::WrongOriginName) {
        "\"example.com\", \"mismatch.example\""
    } else {
        "\"example.com\""
    };
    let server_text = format!(
        r#"mode = "server"
[crypto]
psk = "{}"
[traffic]
max_concurrent_streams = {traffic}
[udp]
enabled = {server_udp}
probe_timeout_ms = 3000
[server]
listen = "{server_addr}"
fallback_addr = "{origin_addr}"
{fixed_target}
private_key = "{}"
identity_secret_key = "{}"
replay_cache_path = {}
authorized_sni = [{allowed_sni}]
"#,
        STANDARD.encode(psk),
        STANDARD.encode(session.private),
        STANDARD.encode(&identity.secret),
        toml::Value::String(dir.path().join("replay.cache").to_str().unwrap().to_owned()),
    );
    let make_client_config = |client_psk: &[u8], public: &[u8; 32], sni: &str, pin: &[u8]| {
        format!(
            r#"mode = "client"
[crypto]
psk = "{}"
[traffic]
max_concurrent_streams = {traffic}
[udp]
enabled = {client_udp}
probe_timeout_ms = 3000
[client]
listen = "{client_addr}"
server_addr = "{server_addr}"
sni = "{sni}"
server_public_key = "{}"
server_identity_public_key = "{}"
"#,
            STANDARD.encode(client_psk),
            STANDARD.encode(public),
            STANDARD.encode(pin),
        )
    };
    let mut client_psk = psk;
    if matches!(case, Case::WrongPsk) {
        client_psk[0] ^= 1;
    }
    let client_public = if matches!(case, Case::WrongX25519) {
        X25519KeyPair::generate().public
    } else {
        session.public
    };
    let client_sni = if matches!(case, Case::WrongOriginName) {
        "mismatch.example"
    } else {
        SNI
    };
    let client_text = make_client_config(&client_psk, &client_public, client_sni, &pinned_identity);
    let initial_ca = if matches!(case, Case::UntrustedOrigin) {
        let (_, unrelated_ca, _) = local_pki("ParallaX E2E Unrelated Root");
        let path = dir.path().join("unrelated-ca.pem");
        write_private(&path, unrelated_ca.as_bytes());
        path
    } else {
        ca_path.clone()
    };
    write_private(&server_path, server_text.as_bytes());
    write_private(&client_path, client_text.as_bytes());
    drop(server_reservation);
    let mut server = Binary::spawn("serve", &server_path, &ca_path);
    server.wait_for("ParallaX server listening").await;
    drop(client_reservation);
    let mut client = Binary::spawn("client", &client_path, &initial_ca);
    client.wait_for("ParallaX client SOCKS5 listening").await;

    // Invalid SOCKS methods must be rejected locally, without opening a target.
    let mut invalid = TcpStream::connect(client_addr).await.unwrap();
    invalid.write_all(&[5, 1, 2]).await.unwrap();
    let mut rejected = [0; 2];
    timeout(STEP, invalid.read_exact(&mut rejected))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rejected, [5, 0xff]);
    drop(invalid);
    assert_eq!(target_accepts.load(Ordering::SeqCst), 0);

    if matches!(case, Case::OriginSplice) {
        browser_tls_echo(server_addr, ca_der).await;
        server.wait_for("AuthFailed").await;
        assert_eq!(target_accepts.load(Ordering::SeqCst), 0);
        assert!(!server
            .logs()
            .contains("authenticated pre-data mode started"));
    }
    if matches!(case, Case::SocksBoundaries) {
        malformed_socks(client_addr, &mut client).await;
        assert_eq!(target_accepts.load(Ordering::SeqCst), 0);
        assert_eq!(
            server.logs().matches("accepted outer connection").count(),
            0
        );
    }

    let failed_then_recover = matches!(
        case,
        Case::WrongPsk | Case::WrongX25519 | Case::UntrustedOrigin | Case::WrongOriginName
    );
    if matches!(case, Case::WrongIdentity | Case::DeniedTarget) || failed_then_recover {
        let mut app = connect_socks(client_addr, target_addr).await;
        let _ = app.write_all(b"must never reach target").await;
        let mut byte = [0];
        let closed = timeout(STEP, app.read(&mut byte))
            .await
            .expect("rejected session must fail closed");
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "rejected session delivered target data"
        );
        if matches!(case, Case::WrongIdentity) {
            client.wait_for("server identity verification failed").await;
        } else if matches!(case, Case::DeniedTarget) {
            server
                .wait_for("client-selected outbound target is denied by server egress policy")
                .await;
        } else if matches!(case, Case::WrongPsk | Case::WrongX25519) {
            server.wait_for("AuthFailed").await;
            assert!(!server
                .logs()
                .contains("authenticated pre-data mode started"));
        } else {
            client.wait_for("TLS certificate verification failed").await;
            let reason = if matches!(case, Case::UntrustedOrigin) {
                "UnknownIssuer"
            } else {
                "CertNotValidForName"
            };
            client.wait_for(reason).await;
        }
        assert_eq!(
            target_accepts.load(Ordering::SeqCst),
            0,
            "identity and egress checks must precede target dial"
        );
        if failed_then_recover {
            drop(app);
            drop(client);
            let recovered_config = dir.path().join("recovered-client.toml");
            write_private(
                &recovered_config,
                make_client_config(&psk, &session.public, SNI, &identity.public).as_bytes(),
            );
            client = Binary::spawn("client", &recovered_config, &ca_path);
            client.wait_for("ParallaX client SOCKS5 listening").await;
            roundtrip(client_addr, target_addr, 1).await;
            assert_eq!(
                target_accepts.load(Ordering::SeqCst),
                1,
                "corrected credentials must recover against the same server"
            );
        }
    } else {
        if mux {
            tokio::join!(
                roundtrip(client_addr, target_addr, 1),
                roundtrip(client_addr, target_addr, 2),
                roundtrip(client_addr, target_addr, 3),
            );
            assert_eq!(target_accepts.load(Ordering::SeqCst), 3);
        } else {
            roundtrip(client_addr, target_addr, 1).await;
            // A second independent control session reuses the same client process
            // (and, for QUIC, its single-use ticket cache and exporter binding).
            roundtrip(client_addr, target_addr, 2).await;
            assert_eq!(target_accepts.load(Ordering::SeqCst), 2);
        }
        if server_udp {
            let logs = client.logs();
            let probes: Vec<_> = logs
                .lines()
                .filter(|line| line.contains("UDP fast-plane probe outcome"))
                .collect();
            assert!(!probes.is_empty(), "QUIC probe must run");
            assert!(
                probes.iter().all(|line| line.contains("Verified")),
                "every QUIC probe must verify: {probes:?}"
            );
            let marker = if mux {
                "ParallaX mux-over-QUIC data mode started"
            } else {
                "QUIC fast-plane relay continuing on the H3 request bidi"
            };
            server.wait_for(marker).await;
            if !mux {
                assert_eq!(
                    server.logs().matches(marker).count(),
                    2,
                    "both independent sessions must relay over QUIC"
                );
            }
        } else if mux {
            server.wait_for("ParallaX mux data mode started").await;
        } else if client_udp {
            client
                .wait_for("UDP fast plane declined by server; continuing on TCP")
                .await;
            assert_eq!(
                client
                    .logs()
                    .matches("UDP fast plane declined by server")
                    .count(),
                1,
                "decline must trip the shared circuit breaker"
            );
        }
        if matches!(case, Case::SocksBoundaries) {
            assert_eq!(
                server.logs().matches("accepted outer connection").count(),
                2,
                "malformed SOCKS must not launch detached handshakes"
            );
        }
    }
    assert!(
        server.child.try_wait().unwrap().is_none(),
        "server must remain available after session teardown"
    );
    assert!(
        client.child.try_wait().unwrap().is_none(),
        "client must remain available after session teardown"
    );
    drop(client);
    drop(server);
    // JoinSet aborts all fixture listeners and their owned connections on panic.
    fixtures.shutdown().await;
    if let Some(ip) = public_target {
        assert_eq!(target_accepts.load(Ordering::SeqCst), 2);
        println!("\nPUBLIC_ROUTE_VERIFIED {ip}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_tcp_socks_pq_identity_roundtrip() {
    scenario(Case::Tcp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_tcp_mux_isolates_concurrent_streams() {
    scenario(Case::TcpMux).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP/UDP sockets and shipped child binaries"]
async fn binary_quic_socks_pq_identity_roundtrip() {
    scenario(Case::Quic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP/UDP sockets and shipped child binaries"]
async fn binary_quic_mux_isolates_concurrent_streams() {
    scenario(Case::QuicMux).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_udp_decline_falls_back_and_suppresses_repeated_probes() {
    scenario(Case::DeclineUdp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_wrong_identity_never_opens_a_target() {
    scenario(Case::WrongIdentity).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_client_selected_private_target_is_denied_after_authentication() {
    scenario(Case::DeniedTarget).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_wrong_psk_falls_back_without_target_and_recovers() {
    scenario(Case::WrongPsk).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_wrong_x25519_pin_falls_back_without_target_and_recovers() {
    scenario(Case::WrongX25519).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_untrusted_origin_is_rejected_and_trust_correction_recovers() {
    scenario(Case::UntrustedOrigin).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_origin_name_mismatch_is_rejected_and_sni_correction_recovers() {
    scenario(Case::WrongOriginName).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_unauthenticated_tls_splice_preserves_origin_and_recovers() {
    scenario(Case::OriginSplice).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets and shipped child binaries"]
async fn binary_malformed_socks_stays_local_then_valid_requests_recover() {
    scenario(Case::SocksBoundaries).await;
}
