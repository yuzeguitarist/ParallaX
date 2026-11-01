//! Real TLS 1.3 handshake with an origin that sends HTTP/2 SETTINGS before the
//! client's HTTP/2 preface, alongside rustls's post-handshake session tickets.

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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut wire = [0; 8192];
        while server.is_handshaking() {
            flush_tls(&mut server, &mut stream).await;
            let n = stream.read(&mut wire).await.unwrap();
            assert_ne!(n, 0, "EOF during TLS handshake");
            server.read_tls(&mut Cursor::new(&wire[..n])).unwrap();
            server.process_new_packets().unwrap();
        }

        // Queue two SETTINGS before reading any client application data. They
        // follow the genuine TLS NewSessionTickets in the same server flight.
        let settings = Http2Fingerprint::safari26().settings_frame().unwrap();
        std::io::Write::write_all(&mut server.writer(), &settings.repeat(2)).unwrap();
        flush_tls(&mut server, &mut stream).await;

        let mut plaintext = Vec::new();
        let mut saw_preface = false;
        let mut ack_count = 0;
        while ack_count < 2 {
            let n = timeout(Duration::from_secs(2), stream.read(&mut wire))
                .await
                .expect("both early SETTINGS must receive an ACK")
                .unwrap();
            assert_ne!(n, 0, "client closed before ACKing both SETTINGS");
            server.read_tls(&mut Cursor::new(&wire[..n])).unwrap();
            server.process_new_packets().unwrap();
            if let Err(err) = std::io::Read::read_to_end(&mut server.reader(), &mut plaintext) {
                assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
            }
            if !saw_preface {
                let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                if plaintext.len() < preface.len() {
                    continue;
                }
                assert!(plaintext.starts_with(preface));
                plaintext.drain(..preface.len());
                saw_preface = true;
            }
            let mut offset = 0;
            while let Some((header, total)) = Http2FrameHeader::parse_complete(&plaintext[offset..])
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
        }
        assert_eq!(ack_count, 2);
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
    origin.await.unwrap();
}
