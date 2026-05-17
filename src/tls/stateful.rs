//! Stateful rustls camouflage backend.
//!
//! V2 keeps rustls in charge of the TLS 1.3 state machine, disables resumption
//! so PSK binders cannot invalidate ParallaX authentication, and injects only
//! two narrow hooks: the ParallaX X25519 public key in ClientHello.random and an
//! authenticated legacy SessionID. The hand-written ClientHello builder remains
//! available for tests, probes, and emergency fallback paths.

use std::{
    cell::RefCell,
    io::{Cursor, Read, Write},
    sync::Arc,
    time::Duration,
};

use rand::{rngs::OsRng, RngCore};
use rustls::{
    client::danger::HandshakeSignatureValid,
    client::Resumption,
    crypto::{GetRandomFailed, SecureRandom},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{sleep, timeout},
};

use super::{
    backend::TlsBackendError, client_hello_builder::BrowserProfile, record::read_record,
    server_hello::parse_server_hello,
};
use crate::crypto::{
    auth::{
        build_auth_tail, build_stateful_auth_session_id, derive_client_auth_key,
        verify_client_hello_auth,
    },
    session::X25519KeyPair,
};
use crate::fingerprint::http2::{Http2Fingerprint, Http2FrameHeader, Http2PeerProfile};

const POST_HANDSHAKE_DRAIN_LIMIT: usize = 4;
const POST_HANDSHAKE_DRAIN_TIMEOUT: Duration = Duration::from_millis(180);
const H2_SETTINGS_ACK_RECORD_LIMIT: usize = 8;
const H2_SETTINGS_ACK_TIMEOUT: Duration = Duration::from_millis(250);
const H2_OPEN_HEADERS_DELAY: Duration = Duration::from_millis(12);
const H2_FRAME_BUFFER_LIMIT: usize = 64 * 1024;

thread_local! {
    static PATCH_CONTEXT: RefCell<Option<PatchContext>> = const { RefCell::new(None) };
}

#[derive(Clone)]
struct PatchContext {
    sni: String,
    auth_key: [u8; 32],
    x25519: X25519KeyPair,
    session_id_pending: bool,
    random_pending: bool,
}

impl PatchContext {
    fn new(sni: String, auth_key: [u8; 32], x25519: X25519KeyPair) -> Self {
        Self {
            sni,
            auth_key,
            x25519,
            session_id_pending: true,
            random_pending: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RecordDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Copy)]
pub struct RecordEvent {
    pub direction: RecordDirection,
    pub content_type: u8,
    pub len: usize,
}

pub trait RecordEventTap {
    fn on_record(&mut self, event: RecordEvent);
}

#[derive(Debug, Default)]
pub struct VecRecordTap {
    events: Vec<RecordEvent>,
}

impl VecRecordTap {
    pub fn events(&self) -> &[RecordEvent] {
        &self.events
    }
}

impl RecordEventTap for VecRecordTap {
    fn on_record(&mut self, event: RecordEvent) {
        self.events.push(event);
    }
}

pub trait PostHandshakeDrain {
    fn drain_record_limit(&self) -> usize;
    fn drain_timeout(&self) -> Duration;
}

#[derive(Debug, Clone)]
pub struct ProfileConfig {
    pub browser: BrowserProfile,
    pub http2_profile: Http2PeerProfile,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub max_fragment_size: Option<usize>,
    pub post_handshake_records: usize,
    pub post_handshake_timeout: Duration,
}

impl ProfileConfig {
    pub fn for_browser(browser: BrowserProfile) -> Self {
        let alpn_protocols = match browser {
            BrowserProfile::Safari17 | BrowserProfile::Chrome124 => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
        };
        let http2_profile = match browser {
            BrowserProfile::Safari17 => Http2PeerProfile::Safari17,
            BrowserProfile::Chrome124 => Http2PeerProfile::Chrome124,
        };
        Self {
            browser,
            http2_profile,
            alpn_protocols,
            max_fragment_size: None,
            post_handshake_records: POST_HANDSHAKE_DRAIN_LIMIT,
            post_handshake_timeout: POST_HANDSHAKE_DRAIN_TIMEOUT,
        }
    }
}

impl PostHandshakeDrain for ProfileConfig {
    fn drain_record_limit(&self) -> usize {
        self.post_handshake_records
    }

    fn drain_timeout(&self) -> Duration {
        self.post_handshake_timeout
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StatefulRustlsCamouflageBackend;

impl StatefulRustlsCamouflageBackend {
    pub fn start(
        &self,
        sni: String,
        psk: &[u8],
        server_public_key: &[u8; 32],
        browser: BrowserProfile,
    ) -> Result<StatefulRustlsSession, TlsBackendError> {
        let x25519 = X25519KeyPair::generate();
        let auth_key = derive_client_auth_key(psk, &x25519.private, server_public_key)?;
        let profile = ProfileConfig::for_browser(browser);
        let context = PatchContext::new(sni.clone(), auth_key, x25519.clone());

        let (connection, client_hello) = with_patch_context(context, || {
            let config = build_client_config(&profile)?;
            let server_name = ServerName::try_from(sni.clone())
                .map_err(|_| TlsBackendError::InvalidServerName(sni.clone()))?;
            let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name)?;
            let mut client_hello = Vec::new();
            connection.write_tls(&mut client_hello)?;
            Ok((connection, client_hello))
        })?;

        let auth = verify_client_hello_auth(&client_hello, &auth_key)?;
        if !auth.authenticated || auth.x25519_key_share != Some(x25519.public) {
            return Err(TlsBackendError::UnauthenticatedClientHello);
        }

        Ok(StatefulRustlsSession {
            connection,
            client_hello,
            x25519,
            sni,
            profile,
            tap: VecRecordTap::default(),
        })
    }
}

pub struct StatefulRustlsSession {
    connection: rustls::ClientConnection,
    client_hello: Vec<u8>,
    x25519: X25519KeyPair,
    sni: String,
    profile: ProfileConfig,
    tap: VecRecordTap,
}

impl StatefulRustlsSession {
    pub async fn complete(
        mut self,
        stream: &mut TcpStream,
    ) -> Result<CompletedStatefulHandshake, TlsBackendError> {
        let client_hello = self.client_hello.clone();
        self.tap_records(RecordDirection::Outbound, &client_hello);
        stream.write_all(&self.client_hello).await?;

        let mut server_hello_record = None;
        while self.connection.is_handshaking() {
            let record = read_record(stream).await?;
            if server_hello_record.is_none() {
                if let Ok(server_hello) = parse_server_hello(&record) {
                    if server_hello.tls13_selected {
                        server_hello_record = Some(record.clone());
                    }
                }
            }
            self.feed_inbound_record(&record)?;
            self.flush_outbound(stream).await?;
        }

        let server_hello_record = server_hello_record.ok_or(TlsBackendError::MissingServerHello)?;
        self.drain_post_handshake(stream).await?;
        self.open_http2_connection(stream).await?;

        Ok(CompletedStatefulHandshake {
            client_hello: self.client_hello,
            client_x25519: self.x25519,
            server_hello_record,
            record_events: self.tap.events,
        })
    }

    fn feed_inbound_record(&mut self, record: &[u8]) -> Result<(), TlsBackendError> {
        self.feed_inbound_record_collect_plaintext(record)
            .map(|_| ())
    }

    fn feed_inbound_record_collect_plaintext(
        &mut self,
        record: &[u8],
    ) -> Result<Vec<u8>, TlsBackendError> {
        self.tap_records(RecordDirection::Inbound, record);
        let mut cursor = Cursor::new(record);
        self.connection.read_tls(&mut cursor)?;
        self.connection.process_new_packets()?;

        let mut plaintext = Vec::new();
        match self.connection.reader().read_to_end(&mut plaintext) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err.into()),
        }
        Ok(plaintext)
    }

    async fn flush_outbound(&mut self, stream: &mut TcpStream) -> Result<(), TlsBackendError> {
        while self.connection.wants_write() {
            let mut out = Vec::new();
            let written = self.connection.write_tls(&mut out)?;
            if written == 0 || out.is_empty() {
                break;
            }
            self.tap_records(RecordDirection::Outbound, &out);
            stream.write_all(&out).await?;
        }
        Ok(())
    }

    async fn drain_post_handshake(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<(), TlsBackendError> {
        for _ in 0..self.profile.drain_record_limit() {
            let record = match timeout(self.profile.drain_timeout(), read_record(stream)).await {
                Ok(Ok(record)) => record,
                Ok(Err(err)) if is_clean_close(&err) => return Ok(()),
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => return Ok(()),
            };
            self.feed_inbound_record(&record)?;
            self.flush_outbound(stream).await?;
        }
        Ok(())
    }

    async fn open_http2_connection(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<(), TlsBackendError> {
        if !self.negotiated_h2() {
            return Ok(());
        }

        let fingerprint = Http2Fingerprint::for_profile(self.profile.http2_profile);
        let preface = fingerprint.connection_preface()?;
        self.write_application_data(stream, &preface).await?;
        self.await_http2_settings_ack(stream).await?;

        let headers = fingerprint.headers_frame(&self.sni)?;
        self.write_application_data(stream, &headers).await?;
        sleep(H2_OPEN_HEADERS_DELAY).await;
        Ok(())
    }

    fn negotiated_h2(&self) -> bool {
        matches!(self.connection.alpn_protocol(), Some(protocol) if protocol == b"h2")
    }

    async fn write_application_data(
        &mut self,
        stream: &mut TcpStream,
        plaintext: &[u8],
    ) -> Result<(), TlsBackendError> {
        self.connection.writer().write_all(plaintext)?;
        self.flush_outbound(stream).await
    }

    async fn await_http2_settings_ack(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<(), TlsBackendError> {
        let mut plaintext = Vec::new();
        for _ in 0..H2_SETTINGS_ACK_RECORD_LIMIT {
            let record = match timeout(H2_SETTINGS_ACK_TIMEOUT, read_record(stream)).await {
                Ok(Ok(record)) => record,
                Ok(Err(err)) if is_clean_close(&err) => return Ok(()),
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => return Ok(()),
            };
            let chunk = self.feed_inbound_record_collect_plaintext(&record)?;
            plaintext.extend_from_slice(&chunk);
            if plaintext.len() > H2_FRAME_BUFFER_LIMIT {
                plaintext.clear();
            }
            if self.process_http2_frames(&mut plaintext, stream).await? {
                return Ok(());
            }
        }
        Ok(())
    }

    async fn process_http2_frames(
        &mut self,
        plaintext: &mut Vec<u8>,
        stream: &mut TcpStream,
    ) -> Result<bool, TlsBackendError> {
        let mut offset = 0;
        let mut saw_settings_ack = false;
        let mut should_ack_peer_settings = false;

        while let Some((header, total)) = Http2FrameHeader::parse_complete(&plaintext[offset..]) {
            if header.is_settings_ack() {
                saw_settings_ack = true;
            } else if header.is_settings() {
                should_ack_peer_settings = true;
            }
            offset += total;
        }

        if offset > 0 {
            plaintext.drain(..offset);
        }

        if should_ack_peer_settings {
            let ack = Http2Fingerprint::settings_ack_frame()?;
            self.write_application_data(stream, &ack).await?;
        }

        Ok(saw_settings_ack)
    }

    fn tap_records(&mut self, direction: RecordDirection, records: &[u8]) {
        let mut offset = 0;
        while offset + super::record::TLS_HEADER_LEN <= records.len() {
            let len = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;
            let total = super::record::TLS_HEADER_LEN + len;
            if offset + total > records.len() {
                break;
            }
            self.tap.on_record(RecordEvent {
                direction,
                content_type: records[offset],
                len,
            });
            offset += total;
        }
    }
}

#[derive(Debug)]
pub struct CompletedStatefulHandshake {
    pub client_hello: Vec<u8>,
    pub client_x25519: X25519KeyPair,
    pub server_hello_record: Vec<u8>,
    pub record_events: Vec<RecordEvent>,
}

fn with_patch_context<T>(
    context: PatchContext,
    f: impl FnOnce() -> Result<T, TlsBackendError>,
) -> Result<T, TlsBackendError> {
    PATCH_CONTEXT.with(|slot| {
        *slot.borrow_mut() = Some(context);
    });
    let result = f();
    PATCH_CONTEXT.with(|slot| {
        *slot.borrow_mut() = None;
    });
    result
}

fn build_client_config(profile: &ProfileConfig) -> Result<rustls::ClientConfig, TlsBackendError> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.secure_random = &PARALLAX_RANDOM;

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|err| TlsBackendError::RustlsConfig(err.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CamouflageVerifier))
        .with_no_client_auth();
    config.alpn_protocols = profile.alpn_protocols.clone();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.max_fragment_size = profile.max_fragment_size;
    Ok(config)
}

#[derive(Debug)]
struct ParallaxSecureRandom;

static PARALLAX_RANDOM: ParallaxSecureRandom = ParallaxSecureRandom;

impl SecureRandom for ParallaxSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let mut handled = false;
        PATCH_CONTEXT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(context) = slot.as_mut() else {
                return;
            };
            if buf.len() != crate::crypto::auth::SESSION_ID_LEN {
                return;
            }

            if context.session_id_pending {
                // rustls 0.23 constructs the TLS 1.3 compatibility SessionID
                // before ClientHello.random for non-QUIC clients.
                let tail =
                    build_auth_tail(&mut OsRng).expect("system clock must be after UNIX epoch");
                let session_id = build_stateful_auth_session_id(
                    &context.auth_key,
                    &context.sni,
                    &context.x25519.public,
                    &tail,
                )
                .expect("stateful auth inputs are fixed length");
                buf.copy_from_slice(&session_id);
                context.session_id_pending = false;
                handled = true;
                return;
            }

            if context.random_pending {
                buf.copy_from_slice(&context.x25519.public);
                context.random_pending = false;
                handled = true;
            }
        });

        if !handled {
            OsRng.fill_bytes(buf);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CamouflageVerifier;

impl rustls::client::danger::ServerCertVerifier for CamouflageVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, RustlsError> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn is_clean_close(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{auth::derive_server_auth_key, session::X25519KeyPair};
    use crate::tls::client_hello::parse_client_hello;

    #[test]
    fn stateful_backend_emits_authenticated_client_hello() {
        let server = X25519KeyPair::generate();
        let psk = b"0123456789abcdef0123456789abcdef";
        let session = StatefulRustlsCamouflageBackend
            .start(
                "example.com".to_owned(),
                psk,
                &server.public,
                BrowserProfile::Safari17,
            )
            .unwrap();

        let parsed = parse_client_hello(&session.client_hello).unwrap();
        let auth_key = derive_server_auth_key(psk, &server.private, &parsed.client_random).unwrap();
        let auth = verify_client_hello_auth(&session.client_hello, &auth_key).unwrap();

        assert_eq!(parsed.client_random, session.x25519.public);
        assert!(auth.authenticated);
        assert_eq!(auth.sni.as_deref(), Some("example.com"));
        assert_eq!(auth.x25519_key_share, Some(session.x25519.public));
        assert!(session.connection.is_handshaking());
    }

    #[test]
    fn client_hello_carries_x25519_mlkem768_key_share() {
        let server = X25519KeyPair::generate();
        let psk = b"0123456789abcdef0123456789abcdef";
        let session = StatefulRustlsCamouflageBackend
            .start(
                "example.com".to_owned(),
                psk,
                &server.public,
                BrowserProfile::Chrome124,
            )
            .unwrap();

        eprintln!("len={}", session.client_hello.len());
        for chunk in session.client_hello.chunks(32) {
            for b in chunk {
                eprint!("{b:02x}");
            }
            eprintln!();
        }

        let parsed = parse_client_hello(&session.client_hello).unwrap();
        assert_eq!(parsed.client_random, session.x25519.public);
        assert!(
            session
                .client_hello
                .windows(4)
                .any(|w| w == [0x11, 0xec, 0x04, 0xc0].as_slice()),
            "X25519MLKEM768 key_share header (0x11ec, len 0x04c0) not found in ClientHello"
        );
    }
}
