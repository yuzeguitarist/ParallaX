//! Stateful rustls camouflage backend.
//!
//! V2 keeps rustls in charge of the TLS 1.3 state machine, uses an isolated
//! per-handshake resumption cache so cached PSK binders cannot invalidate
//! ParallaX authentication, and injects only two narrow hooks: the ParallaX
//! X25519 public key in ClientHello.random and an authenticated legacy
//! SessionID. The hand-written ClientHello builder remains available for tests,
//! probes, and emergency fallback paths.

use std::{
    cell::RefCell,
    io::{Cursor, Read, Write},
    sync::{Arc, OnceLock},
    time::Duration,
};

use rand::{rngs::OsRng, RngCore};
use rustls::{
    client::danger::HandshakeSignatureValid,
    client::Resumption,
    crypto::{
        cipher::{
            AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
            MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, Tls13AeadAlgorithm,
            UnsupportedOperationError,
        },
        ActiveKeyExchange, GetRandomFailed, SecureRandom, SupportedKxGroup,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, DigitallySignedStruct,
    Error as RustlsError, NamedGroup, SignatureScheme, SupportedCipherSuite, Tls13CipherSuite,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{sleep, timeout},
};
use zeroize::{Zeroize, Zeroizing};

use super::{
    backend::TlsBackendError, client_hello_builder::BrowserProfile, record::read_record,
    server_hello::parse_server_hello,
};
use crate::crypto::{
    auth::{
        build_auth_tail, build_masked_stateful_auth_session_id,
        build_masked_stateful_client_random, derive_client_auth_key,
        recover_stateful_auth_material, verify_client_hello_auth_with_material,
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
/// Standard GREASE values from RFC 8701. Both Chrome (BoringSSL) and Safari
/// (CoreCrypto) sample from this set when injecting GREASE into ClientHello.
const BROWSER_GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

thread_local! {
    static PATCH_CONTEXT: RefCell<Option<PatchContext>> = const { RefCell::new(None) };
}

#[derive(Clone)]
struct PatchContext {
    sni: String,
    psk: Zeroizing<Vec<u8>>,
    auth_key: [u8; 32],
    x25519: X25519KeyPair,
    encoded_client_random: Option<[u8; 32]>,
    session_id_pending: bool,
    random_pending: bool,
}

impl PatchContext {
    fn new(sni: String, psk: &[u8], auth_key: [u8; 32], x25519: X25519KeyPair) -> Self {
        Self {
            sni,
            psk: Zeroizing::new(psk.to_vec()),
            auth_key,
            x25519,
            encoded_client_random: None,
            session_id_pending: true,
            random_pending: true,
        }
    }
}

impl Drop for PatchContext {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.encoded_client_random.zeroize();
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
        let context = PatchContext::new(sni.clone(), psk, auth_key, x25519.clone());

        let (connection, client_hello) = with_patch_context(context, || {
            let config = build_client_config(&profile)?;
            let server_name = ServerName::try_from(sni.clone())
                .map_err(|_| TlsBackendError::InvalidServerName(sni.clone()))?;
            let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name)?;
            let mut client_hello = Vec::new();
            connection.write_tls(&mut client_hello)?;
            Ok((connection, client_hello))
        })?;

        let material = recover_stateful_auth_material(&client_hello, psk)?;
        let auth = verify_client_hello_auth_with_material(&client_hello, &auth_key, material)?;
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
    /// Borrow the raw ClientHello TLS record that was emitted during
    /// [`StatefulRustlsCamouflageBackend::start`]. Useful for fingerprint
    /// regression tests that need to inspect the on-the-wire bytes without
    /// driving a full handshake against a real peer.
    pub fn client_hello_bytes(&self) -> &[u8] {
        &self.client_hello
    }

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
    let (cipher_grease, group_grease) = browser_grease_indices_from_context();
    shape_cipher_suites_for_profile(&mut provider, profile.browser, cipher_grease);
    shape_key_exchange_groups_for_profile(&mut provider, profile.browser, group_grease);
    provider.secure_random = &PARALLAX_RANDOM;

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|err| TlsBackendError::RustlsConfig(err.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CamouflageVerifier::for_browser(
            profile.browser,
        )))
        .with_no_client_auth();
    config.alpn_protocols = profile.alpn_protocols.clone();
    // A fresh, non-shared cache lets rustls emit Chrome's empty TLS 1.2
    // session_ticket request extension while preventing cached PSK binders from
    // ever appearing in ParallaX's authenticated ClientHello.
    config.resumption = Resumption::in_memory_sessions(1);
    config.enable_early_data = false;
    config.max_fragment_size = profile.max_fragment_size;
    Ok(config)
}

fn shape_cipher_suites_for_profile(
    provider: &mut rustls::crypto::CryptoProvider,
    browser: BrowserProfile,
    grease_index: usize,
) {
    use rustls::crypto::aws_lc_rs::cipher_suite;

    match browser {
        BrowserProfile::Chrome124 => {
            // Chrome 148 offers AES-128 TLS 1.3 first, then AES-256, CHACHA, then the
            // ECDHE GCM/CHACHA TLS 1.2 suites. rustls/aws-lc-rs cannot implement
            // Chrome's legacy CBC/RSA-GCM tail, so we order the supported subset to
            // match BoringSSL and let rustls append SCSV when TLS 1.2 is enabled.
            provider.cipher_suites = vec![
                grease_cipher_suite(grease_index),
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ];
        }
        BrowserProfile::Safari17 => {
            // Safari 26.4 ClientHello order (apple.com capture):
            //   GREASE, TLS13_AES_256_GCM, TLS13_CHACHA20, TLS13_AES_128_GCM,
            //   ECDHE_ECDSA(AES256/AES128/CHACHA), ECDHE_RSA(AES256/AES128/CHACHA),
            //   <legacy ECDHE-CBC, RSA, 3DES tail>.
            // rustls + aws-lc-rs cannot emit the legacy CBC / RSA-only tail, so we
            // match the front of Apple's list exactly and let rustls append SCSV
            // (00ff) at the end when TLS 1.2 stays enabled.
            provider.cipher_suites = vec![
                grease_cipher_suite(grease_index),
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ];
        }
    }
}

fn shape_key_exchange_groups_for_profile(
    provider: &mut rustls::crypto::CryptoProvider,
    browser: BrowserProfile,
    grease_index: usize,
) {
    use rustls::crypto::aws_lc_rs::kx_group;

    // BoringSSL/CoreCrypto both place a GREASE named group before the real
    // hybrid/classical groups. The GREASE provider delegates its actual
    // key-share generation to X25519MLKEM768, so rustls' transcript and key
    // schedule stay internally consistent while the supported_groups vector
    // becomes browser-shaped.
    match browser {
        BrowserProfile::Chrome124 => {
            provider.kx_groups = vec![
                grease_kx_group(grease_index),
                kx_group::X25519MLKEM768,
                kx_group::X25519,
                kx_group::SECP256R1,
                kx_group::SECP384R1,
            ];
        }
        BrowserProfile::Safari17 => {
            // Safari 26.4 supported_groups (apple.com capture):
            //   GREASE, X25519MLKEM768, X25519, secp256r1, secp384r1, secp521r1.
            //
            // rustls 0.23 + aws-lc-rs only exposes SupportedKxGroup statics for
            // SECP256R1 / SECP384R1, so we announce secp521r1 via the
            // announce-only stub below. rustls picks key_share entries from the
            // front of this list (GREASE + the hybrid group + its classical
            // pair), so the stub's `start()` is never reached in practice.
            provider.kx_groups = vec![
                grease_kx_group(grease_index),
                kx_group::X25519MLKEM768,
                kx_group::X25519,
                kx_group::SECP256R1,
                kx_group::SECP384R1,
                &ANNOUNCE_ONLY_SECP521R1,
            ];
        }
    }
}

fn browser_grease_indices_from_context() -> (usize, usize) {
    PATCH_CONTEXT.with(|slot| {
        let slot = slot.borrow();
        let Some(context) = slot.as_ref() else {
            return (0, 1);
        };
        (
            (context.x25519.public[0] as usize) % BROWSER_GREASE_VALUES.len(),
            (context.x25519.public[1] as usize) % BROWSER_GREASE_VALUES.len(),
        )
    })
}

fn grease_cipher_suite(index: usize) -> SupportedCipherSuite {
    static GREASE_CIPHER_0: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_1: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_2: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_3: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_4: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_5: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_6: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_7: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_8: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_9: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_10: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_11: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_12: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_13: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_14: OnceLock<Tls13CipherSuite> = OnceLock::new();
    static GREASE_CIPHER_15: OnceLock<Tls13CipherSuite> = OnceLock::new();

    let index = index % BROWSER_GREASE_VALUES.len();
    let lock = match index {
        0 => &GREASE_CIPHER_0,
        1 => &GREASE_CIPHER_1,
        2 => &GREASE_CIPHER_2,
        3 => &GREASE_CIPHER_3,
        4 => &GREASE_CIPHER_4,
        5 => &GREASE_CIPHER_5,
        6 => &GREASE_CIPHER_6,
        7 => &GREASE_CIPHER_7,
        8 => &GREASE_CIPHER_8,
        9 => &GREASE_CIPHER_9,
        10 => &GREASE_CIPHER_10,
        11 => &GREASE_CIPHER_11,
        12 => &GREASE_CIPHER_12,
        13 => &GREASE_CIPHER_13,
        14 => &GREASE_CIPHER_14,
        _ => &GREASE_CIPHER_15,
    };
    let grease_value = BROWSER_GREASE_VALUES[index];
    let base = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("AES-128-GCM is a TLS 1.3 cipher suite");
    SupportedCipherSuite::Tls13(lock.get_or_init(|| Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::Unknown(grease_value),
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        hkdf_provider: base.hkdf_provider,
        aead_alg: &GREASE_REJECTING_AEAD,
        quic: None,
    }))
}

#[derive(Debug)]
struct GreaseKxGroup {
    value: u16,
}

static GREASE_KX_GROUPS: [GreaseKxGroup; 16] = [
    GreaseKxGroup { value: 0x0a0a },
    GreaseKxGroup { value: 0x1a1a },
    GreaseKxGroup { value: 0x2a2a },
    GreaseKxGroup { value: 0x3a3a },
    GreaseKxGroup { value: 0x4a4a },
    GreaseKxGroup { value: 0x5a5a },
    GreaseKxGroup { value: 0x6a6a },
    GreaseKxGroup { value: 0x7a7a },
    GreaseKxGroup { value: 0x8a8a },
    GreaseKxGroup { value: 0x9a9a },
    GreaseKxGroup { value: 0xaaaa },
    GreaseKxGroup { value: 0xbaba },
    GreaseKxGroup { value: 0xcaca },
    GreaseKxGroup { value: 0xdada },
    GreaseKxGroup { value: 0xeaea },
    GreaseKxGroup { value: 0xfafa },
];

fn grease_kx_group(index: usize) -> &'static dyn SupportedKxGroup {
    &GREASE_KX_GROUPS[index % GREASE_KX_GROUPS.len()]
}

/// Announce-only `secp521r1`: present so Apple's supported_groups vector is
/// reproducible, but never picked by rustls because the hybrid/x25519/p256/p384
/// groups are listed first and rustls only generates `key_share` entries for
/// the front of the list. If anything ever does call `start()` we delegate to
/// X25519 so the connection still completes; the wire-level `NamedGroup` value
/// stays `secp521r1` (0x0019).
#[derive(Debug)]
struct AnnounceOnlySecp521r1;

static ANNOUNCE_ONLY_SECP521R1: AnnounceOnlySecp521r1 = AnnounceOnlySecp521r1;

impl SupportedKxGroup for AnnounceOnlySecp521r1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        rustls::crypto::aws_lc_rs::kx_group::X25519.start()
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }

    fn fips(&self) -> bool {
        false
    }
}

impl SupportedKxGroup for GreaseKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768.start()
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::Unknown(self.value)
    }

    fn fips(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct RejectingGreaseAead;

static GREASE_REJECTING_AEAD: RejectingGreaseAead = RejectingGreaseAead;

impl Tls13AeadAlgorithm for RejectingGreaseAead {
    fn encrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(RejectingGreaseCipher)
    }

    fn decrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(RejectingGreaseCipher)
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

struct RejectingGreaseCipher;

impl MessageEncrypter for RejectingGreaseCipher {
    fn encrypt(
        &mut self,
        _msg: OutboundPlainMessage<'_>,
        _seq: u64,
    ) -> Result<OutboundOpaqueMessage, RustlsError> {
        Err(grease_selected_error())
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

impl MessageDecrypter for RejectingGreaseCipher {
    fn decrypt<'a>(
        &mut self,
        _msg: InboundOpaqueMessage<'a>,
        _seq: u64,
    ) -> Result<InboundPlainMessage<'a>, RustlsError> {
        Err(grease_selected_error())
    }
}

fn grease_selected_error() -> RustlsError {
    RustlsError::General("peer selected a GREASE cipher suite".to_owned())
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
                let encoded_client_random = build_masked_stateful_client_random(
                    &context.psk,
                    &context.sni,
                    &context.x25519.public,
                    &tail,
                )
                .expect("stateful ClientHello.random mask inputs are valid");
                let session_id = build_masked_stateful_auth_session_id(
                    &context.psk,
                    &context.auth_key,
                    &context.sni,
                    &context.x25519.public,
                    &encoded_client_random,
                    &tail,
                )
                .expect("stateful auth inputs are fixed length");
                context.encoded_client_random = Some(encoded_client_random);
                buf.copy_from_slice(&session_id);
                context.session_id_pending = false;
                handled = true;
                return;
            }

            if context.random_pending {
                let encoded_client_random = context
                    .encoded_client_random
                    .expect("SessionID must be generated before ClientHello.random");
                buf.copy_from_slice(&encoded_client_random);
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
struct CamouflageVerifier {
    browser: BrowserProfile,
}

impl CamouflageVerifier {
    fn for_browser(browser: BrowserProfile) -> Self {
        Self { browser }
    }
}

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
        // rustls 0.23 builds the ClientHello `signature_algorithms` extension
        // from this list, so it is the only seam we have for matching the
        // browser-specific scheme order without forking rustls.
        match self.browser {
            BrowserProfile::Chrome124 => vec![
                // Chrome/BoringSSL order.
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA512,
            ],
            BrowserProfile::Safari17 => vec![
                // Safari 26.4 / CoreCrypto wire order (verified against
                // apple.com + cloudflare.com captures). Apple emits
                // `rsa_pss_rsae_sha384` twice in a row; rustls 0.23 stores
                // signature_schemes as a plain `Vec<SignatureScheme>` and
                // does NOT dedupe, so the duplicate survives end-to-end on
                // the wire, giving us byte-for-byte JA4 sig-algs parity.
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA1,
            ],
        }
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
        let material = recover_stateful_auth_material(&session.client_hello, psk)
            .unwrap()
            .unwrap();
        let auth_key =
            derive_server_auth_key(psk, &server.private, &material.x25519_public).unwrap();
        let auth = verify_client_hello_auth_with_material(
            &session.client_hello,
            &auth_key,
            Some(material),
        )
        .unwrap();

        assert_ne!(parsed.client_random, session.x25519.public);
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
        let material = recover_stateful_auth_material(&session.client_hello, psk)
            .unwrap()
            .unwrap();
        assert_ne!(parsed.client_random, session.x25519.public);
        assert_eq!(material.x25519_public, session.x25519.public);
        assert!(
            session
                .client_hello
                .windows(4)
                .any(|w| w == [0x11, 0xec, 0x04, 0xc0].as_slice()),
            "X25519MLKEM768 key_share header (0x11ec, len 0x04c0) not found in ClientHello"
        );
    }
}
