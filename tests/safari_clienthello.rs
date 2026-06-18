//! S1 gate (the linchpin): prove that the vendored-rustls `SafariChProfile`
//! mutation lands on the typed `ClientHelloPayload` BEFORE the single
//! `transcript_buffer.add_message(&ch)` in `client/hs.rs`. If the wire bytes and
//! the transcript-hash bytes diverged by even one byte, the server's Finished
//! MAC would fail to verify. So a COMPLETED handshake (patched client carrying a
//! representative Safari shape, against a STOCK rustls server) is exactly the
//! proof that the transcript stayed consistent.
//!
//! This is an in-memory loopback over byte buffers (no sockets): we pump
//! `write_tls`/`read_tls` between a `ClientConnection` and a `ServerConnection`
//! until both finish handshaking.

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{SafariChProfile, SafariExt};
use rustls::internal::msgs::enums::ExtensionType;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig,
    ServerConnection, SignatureScheme,
};

/// A verifier that accepts any server certificate. The S1 gate is about
/// ClientHello transcript consistency, not certificate trust, so we sidestep
/// chain validation entirely (the self-signed loopback cert has no trust anchor).
#[derive(Debug)]
struct AcceptAnyServerCert;

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
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn loopback_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    (cert, key)
}

/// A representative Safari-26 cipher-suite list: GREASE-led, 20 suites,
/// including the TLS 1.3 suites the loopback will actually negotiate. The exact
/// production list lives in S3; here we just need the GREASE codepoint + the
/// duplicate-friendly shape to prove the typed `Vec<CipherSuite>` survives
/// verbatim into the transcript.
fn safari_cipher_suites() -> Vec<CipherSuite> {
    vec![
        CipherSuite::Unknown(0x0a0a), // GREASE
        CipherSuite::Unknown(0x1302), // TLS13_AES_256_GCM_SHA384
        CipherSuite::Unknown(0x1303), // TLS13_CHACHA20_POLY1305_SHA256
        CipherSuite::Unknown(0x1301), // TLS13_AES_128_GCM_SHA256
        CipherSuite::Unknown(0xc02c),
        CipherSuite::Unknown(0xc02b),
        CipherSuite::Unknown(0xcca9),
        CipherSuite::Unknown(0xc030),
        CipherSuite::Unknown(0xc02f),
        CipherSuite::Unknown(0xcca8),
        CipherSuite::Unknown(0xc00a),
        CipherSuite::Unknown(0xc009),
        CipherSuite::Unknown(0xc014),
        CipherSuite::Unknown(0xc013),
        CipherSuite::Unknown(0x009d),
        CipherSuite::Unknown(0x009c),
        CipherSuite::Unknown(0x0035),
        CipherSuite::Unknown(0x002f),
        CipherSuite::Unknown(0xc008),
        CipherSuite::Unknown(0x000a),
    ]
}

/// A representative Safari-faithful extension plan. Managed entries name the
/// extensions the TLS-1.3 assembly populates for this loopback; raw entries are
/// the leading/trailing GREASE plus the capture-gated EMS/reneg. PSK/early_data
/// are ABSENT (cold-start). Order mirrors the Safari static table where the
/// populated extensions overlap.
fn safari_extension_plan() -> Vec<SafariExt> {
    vec![
        // Leading GREASE, len 0.
        SafariExt::Raw(0x0a0a, vec![]),
        SafariExt::Managed(ExtensionType::ServerName),
        // Capture-gated legacy extensions (match the TCP fixture).
        SafariExt::Raw(0x0017, vec![]),     // extended_master_secret
        SafariExt::Raw(0xff01, vec![0x00]), // renegotiation_info (empty)
        SafariExt::Managed(ExtensionType::EllipticCurves), // supported_groups
        SafariExt::Managed(ExtensionType::ECPointFormats),
        SafariExt::Managed(ExtensionType::ALProtocolNegotiation), // h3
        SafariExt::Managed(ExtensionType::StatusRequest),
        SafariExt::Managed(ExtensionType::SignatureAlgorithms),
        SafariExt::Managed(ExtensionType::KeyShare),
        SafariExt::Managed(ExtensionType::PSKKeyExchangeModes),
        SafariExt::Managed(ExtensionType::SupportedVersions),
        SafariExt::Managed(ExtensionType::CompressCertificate),
        // Trailing GREASE, len 1.
        SafariExt::Raw(0x1a1a, vec![0x00]),
    ]
}

fn safari_profile() -> SafariChProfile {
    SafariChProfile {
        cipher_suites: safari_cipher_suites(),
        extension_plan: safari_extension_plan(),
        alpn: vec![b"h3".to_vec()],
        key_share_grease_group: 0x0a0a,
    }
}

/// Pump a TLS handshake to completion over in-memory buffers. Panics if it does
/// not converge (which is precisely how a transcript desync would surface).
fn drive_handshake(mut client: ClientConnection, mut server: ServerConnection) {
    let mut buf = Vec::new();
    for _ in 0..32 {
        // Client -> server.
        buf.clear();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            let mut cursor = std::io::Cursor::new(&buf);
            while server.read_tls(&mut cursor).unwrap() > 0 {}
            server
                .process_new_packets()
                .expect("server processes patched ClientHello flight");
        }

        // Server -> client.
        buf.clear();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            let mut cursor = std::io::Cursor::new(&buf);
            while client.read_tls(&mut cursor).unwrap() > 0 {}
            client
                .process_new_packets()
                .expect("client processes server flight (Finished MAC verifies)");
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }
    panic!("handshake did not complete within iteration budget");
}

#[test]
fn safari_profile_handshake_completes_against_stock_server() {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    // STOCK rustls server (unmodified assembly path).
    let (cert, key) = loopback_cert();
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );

    // PATCHED client carrying the Safari profile (cold-start: resumption off).
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    client_config.resumption = rustls::client::Resumption::disabled();
    client_config.alpn_protocols = vec![b"h3".to_vec()];
    client_config.safari_ch_profile = Some(Arc::new(safari_profile()));
    let client_config = Arc::new(client_config);

    let client =
        ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap()).unwrap();
    let server = ServerConnection::new(server_config).unwrap();

    // If the profile mutation had landed AFTER add_message, the server Finished
    // MAC would reject and `process_new_packets` would error inside this call.
    drive_handshake(client, server);
}
