//! Stateful rustls camouflage backend.
//!
//! V1 keeps rustls in charge of the TLS 1.3 state machine, disables resumption
//! so PSK binders cannot invalidate ParallaX authentication, and injects only
//! two narrow hooks: an externally supplied X25519 key share and an authenticated
//! legacy SessionID. The hand-written ClientHello builder remains available for
//! tests, probes, and emergency fallback paths.

use std::{
    cell::RefCell,
    fmt,
    io::{Cursor, Read},
    sync::Arc,
    time::Duration,
};

use rand::{rngs::OsRng, RngCore};
use rustls::{
    client::danger::HandshakeSignatureValid,
    client::Resumption,
    crypto::{
        ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
        SupportedKxGroup,
    },
    ffdhe_groups::FfdheGroup,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as RustlsError, NamedGroup, SignatureScheme,
};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    backend::TlsBackendError, client_hello::parse_client_hello,
    client_hello_builder::BrowserProfile, record::read_record, server_hello::parse_server_hello,
};
use crate::crypto::{
    auth::{
        build_auth_tail, build_stateful_auth_session_id, derive_client_auth_key,
        verify_client_hello_auth,
    },
    session::X25519KeyPair,
};

const POST_HANDSHAKE_DRAIN_LIMIT: usize = 4;
const POST_HANDSHAKE_DRAIN_TIMEOUT: Duration = Duration::from_millis(180);

thread_local! {
    static PATCH_CONTEXT: RefCell<Option<PatchContext>> = const { RefCell::new(None) };
}

#[derive(Clone)]
struct PatchContext {
    sni: String,
    auth_key: [u8; 32],
    x25519: X25519KeyPair,
    session_id_pending: bool,
}

impl PatchContext {
    fn new(sni: String, auth_key: [u8; 32], x25519: X25519KeyPair) -> Self {
        Self {
            sni,
            auth_key,
            x25519,
            session_id_pending: true,
        }
    }
}

impl ExternalKeyShareProvider for PatchContext {
    fn x25519_keypair(&self) -> X25519KeyPair {
        self.x25519.clone()
    }
}

impl ClientHelloMutator for PatchContext {
    fn install_auth_session_id(&self, out: &mut [u8]) -> Result<(), TlsBackendError> {
        let parsed = parse_client_hello(out)?;
        let Some(key_share) = parsed.x25519_key_share else {
            return Err(TlsBackendError::UnauthenticatedClientHello);
        };
        let tail = build_auth_tail(&mut OsRng)?;
        let session_id =
            build_stateful_auth_session_id(&self.auth_key, &self.sni, &key_share, &tail)?;
        out[parsed.session_id_range].copy_from_slice(&session_id);
        Ok(())
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

pub trait ExternalKeyShareProvider {
    fn x25519_keypair(&self) -> X25519KeyPair;
}

pub trait ClientHelloMutator {
    fn install_auth_session_id(&self, out: &mut [u8]) -> Result<(), TlsBackendError>;
}

pub trait PostHandshakeDrain {
    fn drain_record_limit(&self) -> usize;
    fn drain_timeout(&self) -> Duration;
}

#[derive(Debug, Clone)]
pub struct ProfileConfig {
    pub browser: BrowserProfile,
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
        Self {
            browser,
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
            profile,
            tap: VecRecordTap::default(),
        })
    }
}

pub struct StatefulRustlsSession {
    connection: rustls::ClientConnection,
    client_hello: Vec<u8>,
    x25519: X25519KeyPair,
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

        Ok(CompletedStatefulHandshake {
            client_hello: self.client_hello,
            client_x25519: self.x25519,
            server_hello_record,
            record_events: self.tap.events,
        })
    }

    fn feed_inbound_record(&mut self, record: &[u8]) -> Result<(), TlsBackendError> {
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
        Ok(())
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
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = patched_kx_groups(&provider);
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

fn patched_kx_groups(provider: &CryptoProvider) -> Vec<&'static dyn SupportedKxGroup> {
    provider
        .kx_groups
        .iter()
        .map(|group| {
            if group.name() == NamedGroup::X25519 {
                &PARALLAX_X25519 as &'static dyn SupportedKxGroup
            } else {
                *group
            }
        })
        .collect()
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
            if !context.session_id_pending || buf.len() != crate::crypto::auth::SESSION_ID_LEN {
                return;
            }

            let tail = build_auth_tail(&mut OsRng).expect("system clock must be after UNIX epoch");
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
        });

        if !handled {
            OsRng.fill_bytes(buf);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ParallaxX25519Group;

static PARALLAX_X25519: ParallaxX25519Group = ParallaxX25519Group;

impl SupportedKxGroup for ParallaxX25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        let keypair = PATCH_CONTEXT
            .with(|slot| slot.borrow().as_ref().map(|context| context.x25519.clone()))
            .ok_or(TlsBackendError::MissingPatchContext)
            .map_err(|err| RustlsError::General(err.to_string()))?;

        Ok(Box::new(ParallaxActiveX25519 { keypair }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct ParallaxActiveX25519 {
    keypair: X25519KeyPair,
}

impl ActiveKeyExchange for ParallaxActiveX25519 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        let peer_pub_key: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| RustlsError::General("invalid X25519 peer key length".to_owned()))?;
        let private = StaticSecret::from(self.keypair.private);
        let public = PublicKey::from(peer_pub_key);
        let shared = private.diffie_hellman(&public);
        if bool::from(shared.as_bytes().ct_eq(&[0_u8; 32])) {
            return Err(RustlsError::General(
                "invalid all-zero X25519 shared secret".to_owned(),
            ));
        }
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn pub_key(&self) -> &[u8] {
        &self.keypair.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
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

impl fmt::Debug for ParallaxActiveX25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParallaxActiveX25519")
            .field("public", &self.keypair.public)
            .finish_non_exhaustive()
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
        let auth_key =
            derive_server_auth_key(psk, &server.private, &parsed.x25519_key_share.unwrap())
                .unwrap();
        let auth = verify_client_hello_auth(&session.client_hello, &auth_key).unwrap();

        assert!(auth.authenticated);
        assert_eq!(auth.sni.as_deref(), Some("example.com"));
        assert_eq!(auth.x25519_key_share, Some(session.x25519.public));
        assert!(session.connection.is_handshaking());
    }
}
