//! Real TLS 1.3 origins send tickets and two HTTP/2 SETTINGS either before the
//! client preface or only after receiving it. Both must be ACKed independently.

use std::{io::Cursor, sync::Arc, time::Duration};

use parallax::{
    crypto::session::X25519KeyPair,
    fingerprint::http2::{Http2Fingerprint, Http2FrameHeader},
    tls::safari26::Safari26TlsCamouflage,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

async fn flush_tls(server: &mut rustls::ServerConnection, stream: &mut TcpStream) {
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    stream.write_all(&wire).await.unwrap();
}

#[tokio::test]
#[ignore = "requires loopback TCP sockets"]
async fn complete_handshake_acks_every_early_settings_frame() {
    // This integration binary has its own root-store cache, so a throwaway CA
    // exercises production certificate verification without changing system trust.
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["example.com".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    let mut ca_file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut ca_file, ca.pem().as_bytes()).unwrap();
    std::env::set_var("SSL_CERT_FILE", ca_file.path());

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.send_tls13_tickets = 2;
    // Test-only extraction exposes the receive sequence after the response. It
    // verifies rustls actually accepted a KU response and reset receive keys;
    // merely ACKing SETTINGS under the old keys cannot satisfy that assertion.
    config.enable_secret_extraction = true;
    let config = Arc::new(config);
    for withhold_post_finished in [false, true] {
        for key_update in [false, true] {
            exercise_origin(config.clone(), withhold_post_finished, key_update).await;
        }
    }
}

async fn exercise_origin(
    config: Arc<rustls::ServerConfig>,
    withhold_post_finished: bool,
    key_update: bool,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut server = rustls::ServerConnection::new(config).unwrap();
        let mut wire = [0; 8192];
        while server.is_handshaking() {
            flush_tls(&mut server, &mut stream).await;
            let n = stream.read(&mut wire).await.unwrap();
            assert_ne!(n, 0, "EOF during TLS handshake");
            server.read_tls(&mut Cursor::new(&wire[..n])).unwrap();
            server.process_new_packets().unwrap();
        }

        let mut plaintext = Vec::new();
        if withhold_post_finished {
            assert!(server.wants_write(), "the genuine tickets are queued");
            // Do not flush even rustls's genuine NewSessionTickets until the
            // opening arrives. A client waiting 180ms for absent tickets fails
            // this deadline; TLS certificate verification remains production.
            timeout(Duration::from_millis(100), async {
                loop {
                    read_plaintext(&mut server, &mut plaintext);
                    if plaintext.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
                        break;
                    }
                    let n = stream.read(&mut wire).await.unwrap();
                    assert_ne!(n, 0, "EOF before the client opening flight");
                    server.read_tls(&mut Cursor::new(&wire[..n])).unwrap();
                    server.process_new_packets().unwrap();
                }
            })
            .await
            .expect("client opening must not wait for post-Finished server data");
        }

        // Two SETTINGS follow genuine NewSessionTickets, including when the
        // tickets arrive late and must share the H2 phase's receive sequence.
        if key_update {
            server.refresh_traffic_keys().unwrap();
        }
        let settings = Http2Fingerprint::safari26().settings_frame().unwrap();
        std::io::Write::write_all(&mut server.writer(), &settings.repeat(2)).unwrap();
        flush_tls(&mut server, &mut stream).await;

        let mut saw_preface = false;
        let mut ack_count = 0;
        while ack_count < 2 {
            read_plaintext(&mut server, &mut plaintext);
            if !saw_preface {
                let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                if plaintext.len() >= preface.len() {
                    assert!(plaintext.starts_with(preface));
                    plaintext.drain(..preface.len());
                    saw_preface = true;
                }
            }
            let mut offset = 0;
            while let Some((header, total)) = saw_preface
                .then(|| Http2FrameHeader::parse_complete(&plaintext[offset..]))
                .flatten()
            {
                if header.is_settings_ack() {
                    ack_count += 1;
                } else if header.is_settings() {
                    std::io::Write::write_all(
                        &mut server.writer(),
                        &Http2Fingerprint::settings_ack_frame().unwrap(),
                    )
                    .unwrap();
                }
                offset += total;
            }
            plaintext.drain(..offset);
            flush_tls(&mut server, &mut stream).await;
            if ack_count < 2 {
                let n = timeout(Duration::from_secs(2), stream.read(&mut wire))
                    .await
                    .expect("both SETTINGS must receive an ACK")
                    .unwrap();
                assert_ne!(n, 0, "client closed before ACKing both SETTINGS");
                server.read_tls(&mut Cursor::new(&wire[..n])).unwrap();
                server.process_new_packets().unwrap();
            }
        }
        assert_eq!(ack_count, 2);
        if key_update {
            let secrets = server.dangerous_extract_secrets().unwrap();
            assert_eq!(
                secrets.rx.0, 2,
                "KU response reset the receive sequence before both ACKs"
            );
        }
    });

    let server_keys = X25519KeyPair::generate();
    let session = Safari26TlsCamouflage
        .start(
            "example.com".to_owned(),
            b"0123456789abcdef0123456789abcdef",
            &server_keys.public,
        )
        .unwrap();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let handshake = timeout(Duration::from_secs(5), session.complete(&mut stream))
        .await
        .expect("TLS and HTTP/2 camouflage complete")
        .unwrap();
    assert_eq!(handshake.negotiated_alpn.as_deref(), Some(b"h2".as_slice()));
    if withhold_post_finished {
        assert_eq!(handshake.post_handshake_records, 0);
    }
    origin.await.unwrap();
}

fn read_plaintext(server: &mut rustls::ServerConnection, plaintext: &mut Vec<u8>) {
    if let Err(err) = std::io::Read::read_to_end(&mut server.reader(), plaintext) {
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }
}
