//! Safari 26 single-path TLS camouflage backend.
//!
//! ParallaX intentionally owns the visible TLS 1.3 wire image here instead of
//! delegating the client state machine to rustls. The implementation is narrow
//! on purpose: Safari 26-style ClientHello, TLS 1.3 server-authenticated
//! handshake, and the small amount of encrypted HTTP/2 camouflage traffic that
//! ParallaX sends before switching to its own data records.

use std::{
    fmt,
    io::{self, Cursor, Read},
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_768};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use flate2::read::ZlibDecoder;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use zeroize::Zeroizing;

use super::{
    record::{
        change_cipher_spec, parse_header, read_record, TlsRecordReader, TLS_CONTENT_ALERT,
        TLS_CONTENT_APPLICATION_DATA,
    },
    safari_shape::{
        key_share_extension, signature_algorithms_extension, supported_groups_extension,
        supported_versions_extension, GreaseSet, GROUP_X25519, GROUP_X25519_MLKEM768,
        MLKEM768_PUBLIC_KEY_LEN, SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384,
        SIG_RSA_PKCS1_SHA256, SIG_RSA_PKCS1_SHA384, SIG_RSA_PKCS1_SHA512, SIG_RSA_PSS_RSAE_SHA256,
        SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512, TLS12, TLS13, TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, X25519_KEY_LEN,
    },
    server_hello::parse_server_hello,
};
use crate::crypto::{
    auth::{
        build_auth_tail, build_masked_stateful_auth_session_id,
        build_masked_stateful_client_random, derive_client_auth_key_from_shared,
        recover_stateful_auth_material, verify_masked_stateful_client_hello_auth_with_material,
        AuthError,
    },
    session::{x25519_shared_secret, X25519KeyPair},
};
use crate::fingerprint::http2::{Http2Fingerprint, Http2FingerprintError, Http2FrameHeader};
use crate::tls::server_hello::ServerHelloError;

const POST_HANDSHAKE_DRAIN_LIMIT: usize = 4;
const POST_HANDSHAKE_DRAIN_TIMEOUT: Duration = Duration::from_millis(180);
const H2_SETTINGS_ACK_RECORD_LIMIT: usize = 8;
const H2_SETTINGS_ACK_TIMEOUT: Duration = Duration::from_millis(250);
const H2_FRAME_BUFFER_LIMIT: usize = 64 * 1024;

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_RECORD_VERSION_CLIENT_HELLO: [u8; 2] = [0x03, 0x01];
const TLS_RECORD_VERSION_TLS13: [u8; 2] = [0x03, 0x03];

// RFC 8446 alert bytes. A warning-level close_notify (level 1, description 0) is
// the graceful end-of-stream a served origin sends before/around its FIN; it is
// the only alert value tolerated as a clean close (see is_warning_close_notify).
const TLS_ALERT_LEVEL_WARNING: u8 = 0x01;
const TLS_ALERT_DESC_CLOSE_NOTIFY: u8 = 0x00;

/// Upper bound on a decompressed server certificate chain (TLS 1.3 cert
/// compression). Real chains are a few KiB; 256 KiB is generous headroom while
/// bounding the memory an attacker-supplied CompressedCertificate can force.
const MAX_DECOMPRESSED_CERT_CHAIN: usize = 256 * 1024;

/// Maximum ChangeCipherSpec records tolerated across a handshake. RFC 8446 allows
/// at most one (a middlebox-compatibility no-op); accepting unbounded CCS lets an
/// on-path attacker (CCS is unauthenticated/pre-AEAD) trickle them to stall the
/// client handshake indefinitely.
const MAX_CHANGE_CIPHER_SPEC_RECORDS: usize = 2;

/// Upper bound on a single encrypted handshake message length declared by the
/// (still-unauthenticated, at this stage) server. Must exceed
/// `MAX_DECOMPRESSED_CERT_CHAIN` (256 KiB) plus Certificate framing — the largest
/// legitimate member of the flight — while killing the ~16 MiB memory-amplification
/// vector a malicious cover origin could otherwise force via one length field.
const MAX_ENCRYPTED_HANDSHAKE_MESSAGE: usize = 512 * 1024;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HANDSHAKE_CERTIFICATE: u8 = 0x0b;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0f;
const HANDSHAKE_FINISHED: u8 = 0x14;
const HANDSHAKE_COMPRESSED_CERTIFICATE: u8 = 0x19;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

const CERT_COMPRESSION_ZLIB: u16 = 0x0001;

const AEAD_TAG_LEN: usize = 16;
const TLS13_IV_LEN: usize = 12;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

#[cfg(test)]
const LOOPBACK_CAMOUFLAGE_CERT_SHA256: [u8; 32] = [
    0x2b, 0x05, 0xc7, 0x0a, 0x17, 0x2e, 0xe9, 0x87, 0x32, 0xd1, 0xf5, 0xd0, 0x49, 0x48, 0xa2, 0x46,
    0xa8, 0xf7, 0x33, 0xa8, 0x48, 0x04, 0x64, 0xa5, 0x35, 0x42, 0xd2, 0x72, 0x03, 0x92, 0xa1, 0xc0,
];

#[derive(Debug, Error)]
pub enum Safari26TlsError {
    #[error("ClientHello authentication failed: {0}")]
    Auth(#[from] AuthError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP/2 fingerprint build failed: {0}")]
    Http2Fingerprint(#[from] Http2FingerprintError),
    #[error("invalid SNI for Safari TLS ServerName: {0}")]
    InvalidServerName(String),
    #[error("ServerHello parse failed: {0}")]
    ServerHello(#[from] ServerHelloError),
    #[error("Safari 26 TLS camouflage did not observe a TLS 1.3 ServerHello")]
    MissingServerHello,
    #[error("Safari 26 TLS camouflage generated an unauthenticated ClientHello")]
    UnauthenticatedClientHello,
    #[error("TLS handshake parse failed: {0}")]
    Handshake(String),
    #[error("unsupported TLS handshake path: {0}")]
    Unsupported(&'static str),
    #[error("TLS alert from fallback origin: level={level} description={description}")]
    Alert { level: u8, description: u8 },
    #[error("TLS certificate verification failed: {0}")]
    Certificate(String),
    #[error("TLS AEAD operation failed")]
    Aead,
    #[error("TLS HKDF operation failed")]
    Hkdf,
    #[error("TLS ML-KEM operation failed")]
    MlKem,
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

#[derive(Debug, Default, Clone, Copy)]
pub struct Safari26TlsCamouflage;

impl Safari26TlsCamouflage {
    pub fn start(
        &self,
        sni: String,
        psk: &[u8],
        server_public_key: &[u8; 32],
    ) -> Result<Safari26TlsSession, Safari26TlsError> {
        ServerName::try_from(sni.as_str())
            .map_err(|_| Safari26TlsError::InvalidServerName(sni.clone()))?;

        let parallax_x25519 = X25519KeyPair::generate();
        let parallax_shared_secret = Zeroizing::new(x25519_shared_secret(
            &parallax_x25519.private,
            server_public_key,
        ));
        let auth_key = derive_client_auth_key_from_shared(psk, &parallax_shared_secret)?;

        // Generate the TLS handshake ephemeral up-front: its public half is
        // carried UNMASKED in the key_share, and the v4 carrier-mask key is
        // derived from X25519(server_static, this ephemeral) so a passive
        // observer (who lacks the server static private key) cannot recompute the
        // masks and therefore cannot run the v3 offline PSK-guessing oracle. This
        // MUST precede the mask builds below.
        let tls_x25519 = X25519KeyPair::generate();
        let mask_ecdh =
            Zeroizing::new(x25519_shared_secret(&tls_x25519.private, server_public_key));

        let tail = build_auth_tail(&mut OsRng)?;
        let encoded_client_random = build_masked_stateful_client_random(
            psk,
            &mask_ecdh,
            &sni,
            &parallax_x25519.public,
            &tail,
        )?;
        let session_id = build_masked_stateful_auth_session_id(
            psk,
            &mask_ecdh,
            auth_key.as_slice(),
            &sni,
            &parallax_x25519.public,
            &encoded_client_random,
            &tail,
        )?;

        let mlkem_dk =
            DecapsulationKey::generate(&ML_KEM_768).map_err(|_| Safari26TlsError::MlKem)?;
        let mlkem_public = mlkem_dk
            .encapsulation_key()
            .and_then(|ek| ek.key_bytes())
            .map_err(|_| Safari26TlsError::MlKem)?
            .as_ref()
            .to_vec();
        let mlkem_secret = Zeroizing::new(
            mlkem_dk
                .key_bytes()
                .map_err(|_| Safari26TlsError::MlKem)?
                .as_ref()
                .to_vec(),
        );
        let mut grease_seed = [0_u8; 6];
        OsRng.fill_bytes(&mut grease_seed);
        let grease = GreaseSet::from_seed(grease_seed);
        let client_hello = build_safari_client_hello(
            &sni,
            encoded_client_random,
            session_id,
            &tls_x25519.public,
            &mlkem_public,
            grease,
        )?;

        let Some(material) = recover_stateful_auth_material(&client_hello, psk, &mask_ecdh)? else {
            return Err(Safari26TlsError::UnauthenticatedClientHello);
        };
        let auth = verify_masked_stateful_client_hello_auth_with_material(
            &client_hello,
            auth_key.as_slice(),
            &material,
        )?;
        if !auth.authenticated || auth.x25519_key_share != Some(parallax_x25519.public) {
            return Err(Safari26TlsError::UnauthenticatedClientHello);
        }

        Ok(Safari26TlsSession {
            client_hello,
            parallax_x25519,
            parallax_x25519_shared_secret: parallax_shared_secret,
            tls_x25519,
            tls_mlkem768_secret: mlkem_secret,
            sni,
            tap: VecRecordTap::default(),
        })
    }
}

pub struct Safari26TlsSession {
    client_hello: Vec<u8>,
    parallax_x25519: X25519KeyPair,
    parallax_x25519_shared_secret: Zeroizing<[u8; 32]>,
    tls_x25519: X25519KeyPair,
    tls_mlkem768_secret: Zeroizing<Vec<u8>>,
    sni: String,
    tap: VecRecordTap,
}

impl Safari26TlsSession {
    /// Borrow the raw ClientHello TLS record emitted by the handwritten Safari
    /// 26 path.
    pub fn client_hello_bytes(&self) -> &[u8] {
        &self.client_hello
    }

    pub async fn complete(
        mut self,
        stream: &mut TcpStream,
    ) -> Result<CompletedSafari26Handshake, Safari26TlsError> {
        let mut transcript = HandshakeTranscript::new();
        transcript.push_handshake_record(&self.client_hello)?;

        let client_hello = self.client_hello.clone();
        self.tap_records(RecordDirection::Outbound, &client_hello);
        stream.write_all(&self.client_hello).await?;

        let server_hello_record = self.read_server_hello_record(stream).await?;
        transcript.push_handshake_record(&server_hello_record)?;
        let server_hello = parse_safari_server_hello(&server_hello_record)?;
        let shared_secret = self.tls_shared_secret(&server_hello)?;
        let mut keys = Tls13Keys::new(server_hello.cipher_suite, &shared_secret, &transcript)?;

        let server_flight = self
            .read_encrypted_server_flight(stream, &mut keys, &mut transcript)
            .await?;
        verify_server_certificate(&self.sni, &server_flight, &transcript)?;
        keys.install_application_keys(&transcript)?;
        self.write_client_finished(stream, &mut keys, &mut transcript)
            .await?;

        let negotiated_alpn = keys.negotiated_alpn.clone();
        let post_handshake_records = self.drain_post_handshake(stream, &mut keys).await?;
        self.open_http2_connection(stream, &mut keys).await?;

        Ok(CompletedSafari26Handshake {
            client_hello: self.client_hello,
            client_x25519: self.parallax_x25519,
            x25519_shared_secret: self.parallax_x25519_shared_secret,
            server_hello_record,
            record_events: self.tap.events,
            negotiated_alpn,
            post_handshake_records,
        })
    }

    async fn read_server_hello_record(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<Vec<u8>, Safari26TlsError> {
        let mut ccs_records = 0_usize;
        loop {
            let record = read_record(stream).await?;
            self.tap_records(RecordDirection::Inbound, &record);
            let header = parse_header(&record)
                .map_err(|err| Safari26TlsError::Handshake(err.to_string()))?;
            match header.content_type {
                TLS_RECORD_CHANGE_CIPHER_SPEC => {
                    ccs_records += 1;
                    if ccs_records > MAX_CHANGE_CIPHER_SPEC_RECORDS {
                        return Err(Safari26TlsError::Handshake(
                            "too many ChangeCipherSpec records before ServerHello".to_owned(),
                        ));
                    }
                    continue;
                }
                TLS_CONTENT_ALERT => return parse_alert(&record),
                TLS_RECORD_HANDSHAKE => {
                    let _ = parse_server_hello(&record)?;
                    return Ok(record);
                }
                _ => return Err(Safari26TlsError::MissingServerHello),
            }
        }
    }

    fn tls_shared_secret(
        &self,
        server_hello: &ParsedServerHello,
    ) -> Result<Zeroizing<Vec<u8>>, Safari26TlsError> {
        match server_hello.key_share_group {
            GROUP_X25519 => {
                if server_hello.key_share.len() != X25519_KEY_LEN {
                    return Err(Safari26TlsError::Handshake(
                        "invalid X25519 server key_share length".to_owned(),
                    ));
                }
                let mut server_public = [0_u8; X25519_KEY_LEN];
                server_public.copy_from_slice(&server_hello.key_share);
                Ok(Zeroizing::new(
                    x25519_shared_secret(&self.tls_x25519.private, &server_public).to_vec(),
                ))
            }
            GROUP_X25519_MLKEM768 => {
                if server_hello.key_share.len() != MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN {
                    return Err(Safari26TlsError::Handshake(
                        "invalid X25519MLKEM768 server key_share length".to_owned(),
                    ));
                }
                let (mlkem_ciphertext, server_x25519) =
                    server_hello.key_share.split_at(MLKEM768_CIPHERTEXT_LEN);
                let secret = DecapsulationKey::new(&ML_KEM_768, &self.tls_mlkem768_secret)
                    .map_err(|_| Safari26TlsError::MlKem)?;
                let mlkem_shared = secret
                    .decapsulate(Ciphertext::from(mlkem_ciphertext))
                    .map_err(|_| Safari26TlsError::MlKem)?;
                let mut server_public = [0_u8; X25519_KEY_LEN];
                server_public.copy_from_slice(server_x25519);
                let x25519_shared = x25519_shared_secret(&self.tls_x25519.private, &server_public);
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(mlkem_shared.as_ref());
                combined.extend_from_slice(&x25519_shared);
                Ok(Zeroizing::new(combined))
            }
            _ => Err(Safari26TlsError::Unsupported(
                "unsupported TLS key_share group",
            )),
        }
    }

    async fn read_encrypted_server_flight(
        &mut self,
        stream: &mut TcpStream,
        keys: &mut Tls13Keys,
        transcript: &mut HandshakeTranscript,
    ) -> Result<ServerFlight, Safari26TlsError> {
        let mut flight = ServerFlight::default();
        let mut handshake_buf = Vec::new();
        let mut ccs_records = 0_usize;

        while !flight.finished {
            let record = read_record(stream).await?;
            self.tap_records(RecordDirection::Inbound, &record);
            let header = parse_header(&record)
                .map_err(|err| Safari26TlsError::Handshake(err.to_string()))?;
            match header.content_type {
                TLS_RECORD_CHANGE_CIPHER_SPEC => {
                    ccs_records += 1;
                    if ccs_records > MAX_CHANGE_CIPHER_SPEC_RECORDS {
                        return Err(Safari26TlsError::Handshake(
                            "too many ChangeCipherSpec records in server flight".to_owned(),
                        ));
                    }
                    continue;
                }
                TLS_CONTENT_ALERT => return parse_alert(&record),
                TLS_RECORD_APPLICATION_DATA => {
                    let decrypted = keys.server_handshake.decrypt_record(&record)?;
                    if decrypted.content_type != TLS_RECORD_HANDSHAKE {
                        if decrypted.content_type == TLS_CONTENT_ALERT
                            && decrypted.plaintext.len() >= 2
                        {
                            return Err(Safari26TlsError::Alert {
                                level: decrypted.plaintext[0],
                                description: decrypted.plaintext[1],
                            });
                        }
                        return Err(Safari26TlsError::Handshake(
                            "expected encrypted handshake record".to_owned(),
                        ));
                    }
                    handshake_buf.extend_from_slice(&decrypted.plaintext);
                    process_server_handshake_messages(
                        &mut handshake_buf,
                        &mut flight,
                        transcript,
                        keys,
                    )?;
                }
                _ => {
                    return Err(Safari26TlsError::Handshake(format!(
                        "unexpected TLS record type {} in server flight",
                        header.content_type
                    )));
                }
            }
        }

        Ok(flight)
    }

    async fn write_client_finished(
        &mut self,
        stream: &mut TcpStream,
        keys: &mut Tls13Keys,
        transcript: &mut HandshakeTranscript,
    ) -> Result<(), Safari26TlsError> {
        // TLS 1.3 middlebox-compatibility ChangeCipherSpec (RFC 8446 §D.4). Our
        // ClientHello always carries a non-empty (32-byte) legacy_session_id and
        // offers neither early_data nor pre_shared_key (a full handshake), so a real
        // BoringSSL/Safari client sends `14 03 03 00 01 01` immediately before its
        // SECOND flight — the encrypted Finished — i.e. AFTER the ServerHello, not
        // after the ClientHello (that earlier position only matches a 0-RTT/early-data
        // handshake, which this is not, and is itself a passive distinguisher).
        // Omitting it entirely is also a distinguisher. The CCS is a non-handshake
        // record, so it is written straight to the socket and deliberately NOT folded
        // into the handshake transcript (which must remain CH || SH || ... for the
        // Finished verify_data). The server treats it as undecryptable camouflage and
        // forwards it verbatim to the origin, so no server-side change is required.
        let ccs = change_cipher_spec();
        self.tap_records(RecordDirection::Outbound, &ccs);
        stream.write_all(&ccs).await?;

        let verify_data = keys.client_finished_verify_data(transcript)?;
        let mut message = Vec::with_capacity(4 + verify_data.len());
        message.push(HANDSHAKE_FINISHED);
        push_u24(&mut message, verify_data.len())?;
        message.extend_from_slice(&verify_data);
        let record = keys
            .client_handshake
            .encrypt_record(TLS_RECORD_HANDSHAKE, &message)?;
        self.tap_records(RecordDirection::Outbound, &record);
        stream.write_all(&record).await?;
        transcript.push(&message);
        Ok(())
    }

    async fn drain_post_handshake(
        &mut self,
        stream: &mut TcpStream,
        keys: &mut Tls13Keys,
    ) -> Result<usize, Safari26TlsError> {
        let mut observed = 0usize;
        // One long-lived UNBUFFERED reader across the loop: a per-record timeout
        // mid-read must NOT discard bytes already pulled off the socket. A
        // throwaway reader (the old `read_record(stream)` per iteration) would
        // drop the partially-read header/payload on timeout, desyncing the
        // data-phase stream we hand off. On timeout we stop cleanly only when the
        // reader is at a record boundary (the benign slow/absent NewSessionTicket
        // case); a mid-record stall fails honestly so the connection is dropped
        // rather than silently desynced.
        let mut reader = TlsRecordReader::new(&mut *stream);
        let mut record = Vec::new();
        for _ in 0..POST_HANDSHAKE_DRAIN_LIMIT {
            match timeout(
                POST_HANDSHAKE_DRAIN_TIMEOUT,
                reader.read_record_into(&mut record),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) if is_clean_close(&err) => return Ok(observed),
                Ok(Err(err)) => return Err(err.into()),
                Err(_) if reader.at_record_boundary() => return Ok(observed),
                Err(_) => {
                    return Err(Safari26TlsError::Handshake(
                        "post-handshake drain timed out mid-record".to_owned(),
                    ))
                }
            }
            observed += 1;
            self.tap_records(RecordDirection::Inbound, &record);
            let header = parse_header(&record)
                .map_err(|err| Safari26TlsError::Handshake(err.to_string()))?;
            match header.content_type {
                TLS_CONTENT_ALERT => return parse_alert(&record),
                TLS_RECORD_APPLICATION_DATA => {
                    let decrypted = keys.server_application.decrypt_record(&record)?;
                    if decrypted.content_type == TLS_CONTENT_ALERT && decrypted.plaintext.len() >= 2
                    {
                        let (level, description) = (decrypted.plaintext[0], decrypted.plaintext[1]);
                        // A warning close_notify is the origin's clean end-of-drain
                        // (same benign class as the bare FIN handled at :541); a real
                        // client treats it as end-of-stream, not a failure. Report the
                        // count WITHOUT this terminator record (`observed` was already
                        // incremented above): a close_notify is an end-of-stream signal,
                        // not a post-handshake data record, so it must match the bare-FIN
                        // path's count exactly — otherwise a clean close would score as a
                        // spurious post-handshake/ticket signal in `plx probe`.
                        if is_warning_close_notify(level, description) {
                            return Ok(observed - 1);
                        }
                        return Err(Safari26TlsError::Alert { level, description });
                    }
                }
                _ => {}
            }
        }
        Ok(observed)
    }

    async fn open_http2_connection(
        &mut self,
        stream: &mut TcpStream,
        keys: &mut Tls13Keys,
    ) -> Result<(), Safari26TlsError> {
        if !keys.negotiated_h2() {
            return Ok(());
        }

        // HTTP/2 clients send their opening request right after their own preface,
        // without first waiting for the server's SETTINGS — the standard behavior
        // that saves a round trip (a client may send requests as soon as it has
        // sent its preface; the server buffers them). Writing the preface, blocking
        // on the server's SETTINGS, then sending HEADERS made the first
        // client->server flight preface-only and added a
        // server-round-trip-before-request pattern no browser exhibits. Send the
        // preface and the opening HEADERS back-to-back as one flight, then drain
        // and ACK the server's SETTINGS afterward.
        //
        // Keep them as two separate writes (their existing record framing) rather
        // than coalescing into one TLS record: no capture pins the real Safari
        // opening-flight record boundary — the committed fixture is a plaintext
        // reassembly that proves byte shape, not record count. Change only the
        // proven tell (the wait), not the on-wire record framing.
        let fingerprint = Http2Fingerprint::safari26();
        let preface = fingerprint.connection_preface()?;
        self.write_application_data(stream, keys, &preface).await?;
        let headers = fingerprint.headers_frame(&self.sni)?;
        self.write_application_data(stream, keys, &headers).await?;
        self.await_http2_settings_ack(stream, keys).await?;
        Ok(())
    }

    async fn write_application_data(
        &mut self,
        stream: &mut TcpStream,
        keys: &mut Tls13Keys,
        plaintext: &[u8],
    ) -> Result<(), Safari26TlsError> {
        for chunk in plaintext.chunks(super::record::MAX_TLS_RECORD_PAYLOAD) {
            let record = keys
                .client_application
                .encrypt_record(TLS_RECORD_APPLICATION_DATA, chunk)?;
            self.tap_records(RecordDirection::Outbound, &record);
            stream.write_all(&record).await?;
        }
        Ok(())
    }

    async fn await_http2_settings_ack(
        &mut self,
        stream: &mut TcpStream,
        keys: &mut Tls13Keys,
    ) -> Result<(), Safari26TlsError> {
        let mut plaintext = Vec::new();
        // Long-lived UNBUFFERED reader (see drain_post_handshake): a mid-record
        // timeout must not discard buffered bytes and desync the stream. The
        // settings-ack write is routed through reader.get_mut() because the reader
        // holds the stream borrow for the loop's lifetime.
        let mut reader = TlsRecordReader::new(&mut *stream);
        let mut record = Vec::new();
        for _ in 0..H2_SETTINGS_ACK_RECORD_LIMIT {
            match timeout(
                H2_SETTINGS_ACK_TIMEOUT,
                reader.read_record_into(&mut record),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) if is_clean_close(&err) => return Ok(()),
                Ok(Err(err)) => return Err(err.into()),
                Err(_) if reader.at_record_boundary() => return Ok(()),
                Err(_) => {
                    return Err(Safari26TlsError::Handshake(
                        "http/2 settings ack timed out mid-record".to_owned(),
                    ))
                }
            }
            self.tap_records(RecordDirection::Inbound, &record);
            let header = parse_header(&record)
                .map_err(|err| Safari26TlsError::Handshake(err.to_string()))?;
            match header.content_type {
                TLS_CONTENT_ALERT => return parse_alert(&record),
                TLS_RECORD_APPLICATION_DATA => {
                    let chunk = keys.server_application.decrypt_record(&record)?;
                    if chunk.content_type != TLS_RECORD_APPLICATION_DATA {
                        if chunk.content_type == TLS_CONTENT_ALERT && chunk.plaintext.len() >= 2 {
                            let (level, description) = (chunk.plaintext[0], chunk.plaintext[1]);
                            // Origin closed before/around its SETTINGS: a warning
                            // close_notify is a clean close, identical to the bare-FIN
                            // path at :641 (no ACK, no responding write).
                            if is_warning_close_notify(level, description) {
                                return Ok(());
                            }
                            return Err(Safari26TlsError::Alert { level, description });
                        }
                        continue;
                    }
                    plaintext.extend_from_slice(&chunk.plaintext);
                    if self
                        .process_http2_frames(&mut plaintext, reader.get_mut(), keys)
                        .await?
                    {
                        return Ok(());
                    }
                    // Bound only the UNCONSUMED remainder, AFTER draining complete
                    // frames above. A residual past the limit means a single frame
                    // larger than we will buffer (abnormal for a server preface); stop
                    // waiting cleanly rather than clear() mid-frame, which would drop a
                    // partial frame header and desync the parser for the rest of the
                    // loop.
                    if plaintext.len() > H2_FRAME_BUFFER_LIMIT {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn process_http2_frames(
        &mut self,
        plaintext: &mut Vec<u8>,
        stream: &mut TcpStream,
        keys: &mut Tls13Keys,
    ) -> Result<bool, Safari26TlsError> {
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
            self.write_application_data(stream, keys, &ack).await?;
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

pub struct CompletedSafari26Handshake {
    pub client_hello: Vec<u8>,
    pub client_x25519: X25519KeyPair,
    pub server_hello_record: Vec<u8>,
    pub record_events: Vec<RecordEvent>,
    pub negotiated_alpn: Option<Vec<u8>>,
    pub post_handshake_records: usize,
    x25519_shared_secret: Zeroizing<[u8; 32]>,
}

impl CompletedSafari26Handshake {
    pub fn x25519_shared_secret(&self) -> &[u8; 32] {
        &self.x25519_shared_secret
    }
}

impl fmt::Debug for CompletedSafari26Handshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompletedSafari26Handshake")
            .field("client_hello", &self.client_hello)
            .field("client_x25519", &self.client_x25519)
            .field("x25519_shared_secret", &"<redacted>")
            .field("server_hello_record", &self.server_hello_record)
            .field("record_events", &self.record_events)
            .field("negotiated_alpn", &self.negotiated_alpn)
            .field("post_handshake_records", &self.post_handshake_records)
            .finish()
    }
}

fn build_safari_client_hello(
    sni: &str,
    client_random: [u8; 32],
    session_id: [u8; 32],
    x25519_public: &[u8; 32],
    mlkem768_public: &[u8],
    grease: GreaseSet,
) -> Result<Vec<u8>, Safari26TlsError> {
    if mlkem768_public.len() != MLKEM768_PUBLIC_KEY_LEN {
        return Err(Safari26TlsError::MlKem);
    }

    let mut body = Vec::with_capacity(1536);
    body.extend_from_slice(&TLS12.to_be_bytes());
    body.extend_from_slice(&client_random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);

    push_u16_len_prefixed_u16s(
        &mut body,
        &super::safari_shape::safari_cipher_suites(grease),
    )?;
    body.push(1);
    body.push(0);

    let mut extensions = Vec::with_capacity(1410);
    push_extension(&mut extensions, grease.extension, &[])?;
    push_extension(
        &mut extensions,
        EXT_SERVER_NAME,
        &server_name_extension(sni)?,
    )?;
    push_extension(&mut extensions, EXT_EXTENDED_MASTER_SECRET, &[])?;
    push_extension(&mut extensions, EXT_RENEGOTIATION_INFO, &[0])?;
    push_extension(
        &mut extensions,
        EXT_SUPPORTED_GROUPS,
        &supported_groups_extension(grease.group),
    )?;
    push_extension(&mut extensions, EXT_EC_POINT_FORMATS, &[1, 0])?;
    push_extension(&mut extensions, EXT_ALPN, &alpn_extension()?)?;
    push_extension(&mut extensions, EXT_STATUS_REQUEST, &[1, 0, 0, 0, 0])?;
    push_extension(
        &mut extensions,
        EXT_SIGNATURE_ALGORITHMS,
        &signature_algorithms_extension(),
    )?;
    push_extension(&mut extensions, EXT_SIGNED_CERTIFICATE_TIMESTAMP, &[])?;
    push_extension(
        &mut extensions,
        EXT_KEY_SHARE,
        &key_share_extension(grease.group, mlkem768_public, x25519_public),
    )?;
    push_extension(&mut extensions, EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1])?;
    push_extension(
        &mut extensions,
        EXT_SUPPORTED_VERSIONS,
        &supported_versions_extension(grease.version),
    )?;
    push_extension(&mut extensions, EXT_COMPRESS_CERTIFICATE, &[2, 0, 1])?;
    push_extension(&mut extensions, grease.final_extension, &[0])?;

    push_vec_u16(&mut body, &extensions)?;
    handshake_record(
        TLS_RECORD_VERSION_CLIENT_HELLO,
        HANDSHAKE_CLIENT_HELLO,
        &body,
    )
}

fn server_name_extension(sni: &str) -> Result<Vec<u8>, Safari26TlsError> {
    let name = sni.as_bytes();
    let name_len = u16::try_from(name.len())
        .map_err(|_| Safari26TlsError::Handshake("SNI too long".to_owned()))?;
    let list_len = name_len
        .checked_add(3)
        .ok_or_else(|| Safari26TlsError::Handshake("SNI too long".to_owned()))?;
    let mut out = Vec::with_capacity(2 + list_len as usize);
    out.extend_from_slice(&list_len.to_be_bytes());
    out.push(0);
    out.extend_from_slice(&name_len.to_be_bytes());
    out.extend_from_slice(name);
    Ok(out)
}

fn alpn_extension() -> Result<Vec<u8>, Safari26TlsError> {
    let mut out = Vec::with_capacity(14);
    push_u16_len(&mut out, 12)?;
    out.push(2);
    out.extend_from_slice(b"h2");
    out.push(8);
    out.extend_from_slice(b"http/1.1");
    Ok(out)
}

fn push_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) -> Result<(), Safari26TlsError> {
    out.extend_from_slice(&ext_type.to_be_bytes());
    push_vec_u16(out, data)
}

fn handshake_record(
    record_version: [u8; 2],
    handshake_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, Safari26TlsError> {
    let handshake_len = 4 + body.len();
    let mut record = Vec::with_capacity(5 + handshake_len);
    record.push(TLS_RECORD_HANDSHAKE);
    record.extend_from_slice(&record_version);
    push_u16_len(&mut record, handshake_len)?;
    record.push(handshake_type);
    push_u24(&mut record, body.len())?;
    record.extend_from_slice(body);
    Ok(record)
}

fn push_u16_len_prefixed_u16s(out: &mut Vec<u8>, values: &[u16]) -> Result<(), Safari26TlsError> {
    push_u16_len(out, values.len() * 2)?;
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
    Ok(())
}

fn push_vec_u16(out: &mut Vec<u8>, data: &[u8]) -> Result<(), Safari26TlsError> {
    push_u16_len(out, data.len())?;
    out.extend_from_slice(data);
    Ok(())
}

fn push_u16_len(out: &mut Vec<u8>, len: usize) -> Result<(), Safari26TlsError> {
    let len = u16::try_from(len)
        .map_err(|_| Safari26TlsError::Handshake("TLS vector too large".to_owned()))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn push_u24(out: &mut Vec<u8>, len: usize) -> Result<(), Safari26TlsError> {
    if len > 0x00ff_ffff {
        return Err(Safari26TlsError::Handshake(
            "TLS handshake message too large".to_owned(),
        ));
    }
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    Ok(())
}

#[derive(Clone)]
struct ParsedServerHello {
    cipher_suite: TlsCipherSuite,
    key_share_group: u16,
    key_share: Vec<u8>,
}

fn parse_safari_server_hello(record: &[u8]) -> Result<ParsedServerHello, Safari26TlsError> {
    let _ = parse_server_hello(record)?;
    let (_, payload) = super::record::parse_exact(record)
        .map_err(|err| Safari26TlsError::Handshake(err.to_string()))?;
    let mut c = TlsCursor::new(payload);
    let handshake_type = c.u8()?;
    if handshake_type != HANDSHAKE_SERVER_HELLO {
        return Err(Safari26TlsError::Handshake(
            "expected ServerHello".to_owned(),
        ));
    }
    let body_len = c.u24()? as usize;
    let body = c.bytes(body_len)?;
    let mut b = TlsCursor::new(body);
    let legacy_version = b.u16()?;
    if legacy_version != TLS12 {
        return Err(Safari26TlsError::Handshake(
            "ServerHello legacy_version is not TLS 1.2".to_owned(),
        ));
    }
    let random = b.bytes(32)?;
    if random == hrr_random() {
        return Err(Safari26TlsError::Unsupported("HelloRetryRequest"));
    }
    let session_id = b.vec_u8()?;
    if session_id.len() != 32 {
        return Err(Safari26TlsError::Handshake(
            "ServerHello did not echo a 32-byte session_id".to_owned(),
        ));
    }
    let cipher_suite = TlsCipherSuite::from_u16(b.u16()?)?;
    if b.u8()? != 0 {
        return Err(Safari26TlsError::Handshake(
            "ServerHello compression_method is not null".to_owned(),
        ));
    }
    let extensions = b.vec_u16()?;
    let mut e = TlsCursor::new(extensions);
    let mut tls13_selected = false;
    let mut key_share_group = None;
    let mut key_share = None;
    while e.remaining() > 0 {
        let ext_type = e.u16()?;
        let data = e.vec_u16()?;
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                if data.len() == 2 && u16::from_be_bytes([data[0], data[1]]) == TLS13 {
                    tls13_selected = true;
                }
            }
            EXT_KEY_SHARE => {
                let mut ks = TlsCursor::new(data);
                key_share_group = Some(ks.u16()?);
                key_share = Some(ks.vec_u16()?.to_vec());
            }
            _ => {}
        }
    }
    if !tls13_selected {
        return Err(Safari26TlsError::MissingServerHello);
    }
    Ok(ParsedServerHello {
        cipher_suite,
        key_share_group: key_share_group.ok_or_else(|| {
            Safari26TlsError::Handshake("ServerHello missing key_share".to_owned())
        })?,
        key_share: key_share.ok_or_else(|| {
            Safari26TlsError::Handshake("ServerHello missing key_share data".to_owned())
        })?,
    })
}

fn hrr_random() -> &'static [u8] {
    &[
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ]
}

#[derive(Debug, Clone, Copy)]
enum TlsCipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl TlsCipherSuite {
    fn from_u16(value: u16) -> Result<Self, Safari26TlsError> {
        match value {
            TLS_AES_128_GCM_SHA256 => Ok(Self::Aes128GcmSha256),
            TLS_AES_256_GCM_SHA384 => Ok(Self::Aes256GcmSha384),
            TLS_CHACHA20_POLY1305_SHA256 => Ok(Self::Chacha20Poly1305Sha256),
            _ => Err(Safari26TlsError::Unsupported(
                "unsupported TLS cipher suite",
            )),
        }
    }

    fn hash_len(self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 48,
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => 32,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::Chacha20Poly1305Sha256 => 32,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes256GcmSha384 => Sha384::digest(data).to_vec(),
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => Sha256::digest(data).to_vec(),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Safari26TlsError> {
        match self {
            Self::Aes256GcmSha384 => {
                let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key)
                    .map_err(|_| Safari26TlsError::Hkdf)?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
                    .map_err(|_| Safari26TlsError::Hkdf)?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }

    fn hkdf_extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes256GcmSha384 => {
                let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
                prk.to_vec()
            }
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => {
                let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
                prk.to_vec()
            }
        }
    }

    fn hkdf_expand_label(
        self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, Safari26TlsError> {
        let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
        push_u16_len(&mut info, len)?;
        let full_label = format!("tls13 {label}");
        info.push(full_label.len() as u8);
        info.extend_from_slice(full_label.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        let mut out = vec![0_u8; len];
        match self {
            Self::Aes256GcmSha384 => Hkdf::<Sha384>::from_prk(secret)
                .map_err(|_| Safari26TlsError::Hkdf)?
                .expand(&info, &mut out)
                .map_err(|_| Safari26TlsError::Hkdf)?,
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => {
                Hkdf::<Sha256>::from_prk(secret)
                    .map_err(|_| Safari26TlsError::Hkdf)?
                    .expand(&info, &mut out)
                    .map_err(|_| Safari26TlsError::Hkdf)?
            }
        }
        Ok(out)
    }

    fn derive_secret(
        self,
        secret: &[u8],
        label: &str,
        transcript: &[u8],
    ) -> Result<Vec<u8>, Safari26TlsError> {
        let hash = self.digest(transcript);
        self.hkdf_expand_label(secret, label, &hash, self.hash_len())
    }
}

struct Tls13Keys {
    suite: TlsCipherSuite,
    client_handshake: RecordCipher,
    server_handshake: RecordCipher,
    client_application: RecordCipher,
    server_application: RecordCipher,
    client_handshake_secret: Vec<u8>,
    server_handshake_secret: Vec<u8>,
    master_secret: Vec<u8>,
    negotiated_alpn: Option<Vec<u8>>,
}

impl Tls13Keys {
    fn new(
        suite: TlsCipherSuite,
        shared_secret: &[u8],
        transcript: &HandshakeTranscript,
    ) -> Result<Self, Safari26TlsError> {
        let zeros = vec![0_u8; suite.hash_len()];
        let early_secret = suite.hkdf_extract(&zeros, &zeros);
        let derived = suite.derive_secret(&early_secret, "derived", &[])?;
        let handshake_secret = suite.hkdf_extract(&derived, shared_secret);
        let client_handshake_secret =
            suite.derive_secret(&handshake_secret, "c hs traffic", transcript.bytes())?;
        let server_handshake_secret =
            suite.derive_secret(&handshake_secret, "s hs traffic", transcript.bytes())?;
        let derived = suite.derive_secret(&handshake_secret, "derived", &[])?;
        let master_secret = suite.hkdf_extract(&derived, &zeros);
        Ok(Self {
            suite,
            client_handshake: RecordCipher::new(suite, &client_handshake_secret)?,
            server_handshake: RecordCipher::new(suite, &server_handshake_secret)?,
            client_application: RecordCipher::zero(suite),
            server_application: RecordCipher::zero(suite),
            client_handshake_secret,
            server_handshake_secret,
            master_secret,
            negotiated_alpn: None,
        })
    }

    fn install_application_keys(
        &mut self,
        transcript: &HandshakeTranscript,
    ) -> Result<(), Safari26TlsError> {
        let client_application_secret =
            self.suite
                .derive_secret(&self.master_secret, "c ap traffic", transcript.bytes())?;
        let server_application_secret =
            self.suite
                .derive_secret(&self.master_secret, "s ap traffic", transcript.bytes())?;
        self.client_application = RecordCipher::new(self.suite, &client_application_secret)?;
        self.server_application = RecordCipher::new(self.suite, &server_application_secret)?;
        Ok(())
    }

    fn server_finished_verify_data(
        &self,
        transcript: &HandshakeTranscript,
    ) -> Result<Vec<u8>, Safari26TlsError> {
        finished_verify_data(
            self.suite,
            &self.server_handshake_secret,
            transcript.bytes(),
        )
    }

    fn client_finished_verify_data(
        &self,
        transcript: &HandshakeTranscript,
    ) -> Result<Vec<u8>, Safari26TlsError> {
        finished_verify_data(
            self.suite,
            &self.client_handshake_secret,
            transcript.bytes(),
        )
    }

    fn negotiated_h2(&self) -> bool {
        matches!(self.negotiated_alpn.as_deref(), Some(b"h2"))
    }
}

fn finished_verify_data(
    suite: TlsCipherSuite,
    traffic_secret: &[u8],
    transcript: &[u8],
) -> Result<Vec<u8>, Safari26TlsError> {
    let finished_key =
        suite.hkdf_expand_label(traffic_secret, "finished", &[], suite.hash_len())?;
    let transcript_hash = suite.digest(transcript);
    suite.hmac(&finished_key, &transcript_hash)
}

struct RecordCipher {
    suite: TlsCipherSuite,
    key: Vec<u8>,
    iv: [u8; TLS13_IV_LEN],
    seq: u64,
}

impl RecordCipher {
    fn zero(suite: TlsCipherSuite) -> Self {
        Self {
            suite,
            key: vec![0_u8; suite.key_len()],
            iv: [0_u8; TLS13_IV_LEN],
            seq: 0,
        }
    }

    fn new(suite: TlsCipherSuite, traffic_secret: &[u8]) -> Result<Self, Safari26TlsError> {
        let key = suite.hkdf_expand_label(traffic_secret, "key", &[], suite.key_len())?;
        let iv_vec = suite.hkdf_expand_label(traffic_secret, "iv", &[], TLS13_IV_LEN)?;
        let mut iv = [0_u8; TLS13_IV_LEN];
        iv.copy_from_slice(&iv_vec);
        Ok(Self {
            suite,
            key,
            iv,
            seq: 0,
        })
    }

    fn encrypt_record(
        &mut self,
        inner_type: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Safari26TlsError> {
        let mut payload = Vec::with_capacity(plaintext.len() + 1 + AEAD_TAG_LEN);
        payload.extend_from_slice(plaintext);
        payload.push(inner_type);
        let encrypted_len = payload.len() + AEAD_TAG_LEN;
        let mut record = Vec::with_capacity(5 + encrypted_len);
        record.push(TLS_RECORD_APPLICATION_DATA);
        record.extend_from_slice(&TLS_RECORD_VERSION_TLS13);
        push_u16_len(&mut record, encrypted_len)?;
        let aad = record.clone();
        let nonce = self.nonce();
        match self.suite {
            TlsCipherSuite::Aes128GcmSha256 => {
                let cipher =
                    Aes128Gcm::new_from_slice(&self.key).map_err(|_| Safari26TlsError::Aead)?;
                let tag = cipher
                    .encrypt_in_place_detached((&nonce).into(), &aad, &mut payload)
                    .map_err(|_| Safari26TlsError::Aead)?;
                record.extend_from_slice(&payload);
                record.extend_from_slice(&tag);
            }
            TlsCipherSuite::Aes256GcmSha384 => {
                let cipher =
                    Aes256Gcm::new_from_slice(&self.key).map_err(|_| Safari26TlsError::Aead)?;
                let tag = cipher
                    .encrypt_in_place_detached((&nonce).into(), &aad, &mut payload)
                    .map_err(|_| Safari26TlsError::Aead)?;
                record.extend_from_slice(&payload);
                record.extend_from_slice(&tag);
            }
            TlsCipherSuite::Chacha20Poly1305Sha256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|_| Safari26TlsError::Aead)?;
                let tag = cipher
                    .encrypt_in_place_detached((&nonce).into(), &aad, &mut payload)
                    .map_err(|_| Safari26TlsError::Aead)?;
                record.extend_from_slice(&payload);
                record.extend_from_slice(&tag);
            }
        }
        self.seq = self.seq.wrapping_add(1);
        Ok(record)
    }

    fn decrypt_record(&mut self, record: &[u8]) -> Result<PlainRecord, Safari26TlsError> {
        let header =
            parse_header(record).map_err(|err| Safari26TlsError::Handshake(err.to_string()))?;
        if header.content_type != TLS_CONTENT_APPLICATION_DATA {
            return Err(Safari26TlsError::Handshake(
                "expected encrypted TLS application record".to_owned(),
            ));
        }
        if record.len() < header.total_len || header.payload_len < AEAD_TAG_LEN + 1 {
            return Err(Safari26TlsError::Aead);
        }
        let aad = &record[..super::record::TLS_HEADER_LEN];
        let mut payload = record[super::record::TLS_HEADER_LEN..header.total_len].to_vec();
        let tag_start = payload.len() - AEAD_TAG_LEN;
        let tag = payload.split_off(tag_start);
        let nonce = self.nonce();
        match self.suite {
            TlsCipherSuite::Aes128GcmSha256 => {
                let cipher =
                    Aes128Gcm::new_from_slice(&self.key).map_err(|_| Safari26TlsError::Aead)?;
                cipher
                    .decrypt_in_place_detached((&nonce).into(), aad, &mut payload, (&*tag).into())
                    .map_err(|_| Safari26TlsError::Aead)?;
            }
            TlsCipherSuite::Aes256GcmSha384 => {
                let cipher =
                    Aes256Gcm::new_from_slice(&self.key).map_err(|_| Safari26TlsError::Aead)?;
                cipher
                    .decrypt_in_place_detached((&nonce).into(), aad, &mut payload, (&*tag).into())
                    .map_err(|_| Safari26TlsError::Aead)?;
            }
            TlsCipherSuite::Chacha20Poly1305Sha256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|_| Safari26TlsError::Aead)?;
                cipher
                    .decrypt_in_place_detached((&nonce).into(), aad, &mut payload, (&*tag).into())
                    .map_err(|_| Safari26TlsError::Aead)?;
            }
        }
        self.seq = self.seq.wrapping_add(1);

        let content_type_pos = payload
            .iter()
            .rposition(|b| *b != 0)
            .ok_or(Safari26TlsError::Aead)?;
        let content_type = payload[content_type_pos];
        payload.truncate(content_type_pos);
        Ok(PlainRecord {
            content_type,
            plaintext: payload,
        })
    }

    fn nonce(&self) -> [u8; TLS13_IV_LEN] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for (dst, src) in nonce[4..].iter_mut().zip(seq) {
            *dst ^= src;
        }
        nonce
    }
}

struct PlainRecord {
    content_type: u8,
    plaintext: Vec<u8>,
}

#[derive(Default)]
struct ServerFlight {
    encrypted_extensions_seen: bool,
    certificates: Vec<Vec<u8>>,
    certificate_verify_seen: bool,
    finished: bool,
}

/// Rejects a Certificate/CompressedCertificate that is a duplicate or arrives
/// after CertificateVerify. This binds the leaf that CertificateVerify proves
/// possession of to the leaf that is finally validated: without it, a second
/// Certificate could overwrite `flight.certificates` while `certificate_verify_seen`
/// stays true, letting an active MITM prove possession of an attacker key
/// (Certificate#1 + CV) and then present the real chain (Certificate#2) before
/// Finished — defeating the cover-origin TLS authentication.
fn reject_out_of_order_certificate(flight: &ServerFlight) -> Result<(), Safari26TlsError> {
    if !flight.certificates.is_empty() || flight.certificate_verify_seen {
        return Err(Safari26TlsError::Handshake(
            "duplicate or out-of-order Certificate message in server flight".to_owned(),
        ));
    }
    Ok(())
}

fn process_server_handshake_messages(
    buf: &mut Vec<u8>,
    flight: &mut ServerFlight,
    transcript: &mut HandshakeTranscript,
    keys: &mut Tls13Keys,
) -> Result<(), Safari26TlsError> {
    loop {
        if buf.len() < 4 {
            return Ok(());
        }
        let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
        // Reject on the FIRST record carrying an oversized length header, before
        // the buffer can accumulate toward the declared target — this bounds the
        // handshake buffer to ~MAX_ENCRYPTED_HANDSHAKE_MESSAGE plus one in-flight
        // record, closing the memory-amplification vector from an unauthenticated
        // cover origin.
        if len > MAX_ENCRYPTED_HANDSHAKE_MESSAGE {
            return Err(Safari26TlsError::Handshake(
                "encrypted handshake message length exceeds maximum".to_owned(),
            ));
        }
        if buf.len() < 4 + len {
            return Ok(());
        }
        let message = buf[..4 + len].to_vec();
        buf.drain(..4 + len);
        let body = &message[4..];
        match message[0] {
            HANDSHAKE_ENCRYPTED_EXTENSIONS => {
                if flight.encrypted_extensions_seen {
                    return Err(Safari26TlsError::Handshake(
                        "duplicate EncryptedExtensions in server flight".to_owned(),
                    ));
                }
                parse_encrypted_extensions(body, keys)?;
                flight.encrypted_extensions_seen = true;
                transcript.push(&message);
            }
            HANDSHAKE_CERTIFICATE => {
                reject_out_of_order_certificate(flight)?;
                flight.certificates = parse_certificate_body(body)?;
                transcript.push(&message);
            }
            HANDSHAKE_COMPRESSED_CERTIFICATE => {
                reject_out_of_order_certificate(flight)?;
                flight.certificates = parse_compressed_certificate_body(body)?;
                transcript.push(&message);
            }
            HANDSHAKE_CERTIFICATE_VERIFY => {
                if flight.certificate_verify_seen {
                    return Err(Safari26TlsError::Handshake(
                        "duplicate CertificateVerify in server flight".to_owned(),
                    ));
                }
                verify_certificate_verify(body, flight, transcript, keys)?;
                flight.certificate_verify_seen = true;
                transcript.push(&message);
            }
            HANDSHAKE_FINISHED => {
                if !flight.encrypted_extensions_seen
                    || flight.certificates.is_empty()
                    || !flight.certificate_verify_seen
                {
                    return Err(Safari26TlsError::Handshake(
                        "server Finished arrived before the authenticated flight".to_owned(),
                    ));
                }
                let expected = keys.server_finished_verify_data(transcript)?;
                // Constant-time compare: matches the QUIC TLS paths
                // (handshake.rs / server.rs verify the Finished MAC via `ct_eq`)
                // and avoids a per-byte timing distinguisher on the verify_data.
                if !bool::from(body.ct_eq(&expected)) {
                    return Err(Safari26TlsError::Handshake(
                        "server Finished verify_data mismatch".to_owned(),
                    ));
                }
                transcript.push(&message);
                flight.finished = true;
                return Ok(());
            }
            _ => {
                return Err(Safari26TlsError::Unsupported(
                    "unexpected encrypted TLS handshake message",
                ));
            }
        }
    }
}

fn parse_encrypted_extensions(body: &[u8], keys: &mut Tls13Keys) -> Result<(), Safari26TlsError> {
    let mut c = TlsCursor::new(body);
    let extensions = c.vec_u16()?;
    let mut e = TlsCursor::new(extensions);
    while e.remaining() > 0 {
        let ext_type = e.u16()?;
        let data = e.vec_u16()?;
        if ext_type == EXT_ALPN {
            keys.negotiated_alpn = Some(parse_selected_alpn(data)?.to_vec());
        }
    }
    Ok(())
}

fn parse_selected_alpn(data: &[u8]) -> Result<&[u8], Safari26TlsError> {
    let mut c = TlsCursor::new(data);
    let list = c.vec_u16()?;
    let mut l = TlsCursor::new(list);
    let proto = l.vec_u8()?;
    Ok(proto)
}

fn parse_certificate_body(body: &[u8]) -> Result<Vec<Vec<u8>>, Safari26TlsError> {
    let mut c = TlsCursor::new(body);
    let _request_context = c.vec_u8()?;
    let list = c.vec_u24()?;
    let mut l = TlsCursor::new(list);
    let mut certs = Vec::new();
    while l.remaining() > 0 {
        let cert = l.vec_u24()?;
        certs.push(cert.to_vec());
        let _extensions = l.vec_u16()?;
    }
    Ok(certs)
}

fn parse_compressed_certificate_body(body: &[u8]) -> Result<Vec<Vec<u8>>, Safari26TlsError> {
    let mut c = TlsCursor::new(body);
    let algorithm = c.u16()?;
    if algorithm != CERT_COMPRESSION_ZLIB {
        return Err(Safari26TlsError::Unsupported(
            "unsupported compressed_certificate algorithm",
        ));
    }
    let uncompressed_len = c.u24()? as usize;
    // Reject an oversized declared length BEFORE allocating: a real server
    // certificate chain is a few KiB, and zlib's ~1000:1 ratio means a tiny
    // attacker-supplied blob can declare (and inflate to) gigabytes. Without this
    // an on-path attacker — reachable here BEFORE certificate verification, since
    // the handshake keys come from the still-unauthenticated server key_share —
    // could OOM-kill the client/prober with one small CompressedCertificate.
    if uncompressed_len > MAX_DECOMPRESSED_CERT_CHAIN {
        return Err(Safari26TlsError::Handshake(
            "compressed_certificate uncompressed_length exceeds maximum".to_owned(),
        ));
    }
    let compressed = c.vec_u24()?;
    let decoder = ZlibDecoder::new(Cursor::new(compressed));
    // Cap the actual inflation independently of the declared length so a lying
    // header (small uncompressed_len, huge real output) cannot exhaust memory
    // either. take() bounds the bytes pulled from the decoder; reading one extra
    // byte past the cap lets us detect an over-cap stream.
    let mut decompressed = Vec::with_capacity(uncompressed_len.min(MAX_DECOMPRESSED_CERT_CHAIN));
    let mut limited = decoder.take((MAX_DECOMPRESSED_CERT_CHAIN as u64) + 1);
    limited.read_to_end(&mut decompressed)?;
    if decompressed.len() > MAX_DECOMPRESSED_CERT_CHAIN {
        return Err(Safari26TlsError::Handshake(
            "compressed_certificate inflates beyond maximum".to_owned(),
        ));
    }
    if decompressed.len() != uncompressed_len {
        return Err(Safari26TlsError::Handshake(
            "compressed_certificate length mismatch".to_owned(),
        ));
    }
    parse_certificate_body(&decompressed)
}

fn verify_certificate_verify(
    body: &[u8],
    flight: &ServerFlight,
    transcript: &HandshakeTranscript,
    keys: &Tls13Keys,
) -> Result<(), Safari26TlsError> {
    let leaf = flight
        .certificates
        .first()
        .ok_or_else(|| Safari26TlsError::Handshake("missing server certificate".to_owned()))?;
    let mut c = TlsCursor::new(body);
    let scheme = c.u16()?;
    let signature = c.vec_u16()?;
    let alg = certificate_verify_algorithm(scheme)?;
    let cert_der = CertificateDer::from(leaf.as_slice());
    let cert = webpki::EndEntityCert::try_from(&cert_der)
        .map_err(|err| Safari26TlsError::Certificate(err.to_string()))?;
    let transcript_hash = keys.suite.digest(transcript.bytes());
    let mut signed = Vec::with_capacity(64 + 34 + transcript_hash.len());
    signed.extend_from_slice(&[0x20; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0);
    signed.extend_from_slice(&transcript_hash);
    cert.verify_signature(alg, &signed, signature)
        .map_err(|err| Safari26TlsError::Certificate(err.to_string()))
}

fn certificate_verify_algorithm(
    scheme: u16,
) -> Result<&'static dyn rustls_pki_types::SignatureVerificationAlgorithm, Safari26TlsError> {
    match scheme {
        SIG_ECDSA_SECP256R1_SHA256 => Ok(webpki::aws_lc_rs::ECDSA_P256_SHA256),
        SIG_RSA_PSS_RSAE_SHA256 => Ok(webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        SIG_RSA_PKCS1_SHA256 => Ok(webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256),
        SIG_ECDSA_SECP384R1_SHA384 => Ok(webpki::aws_lc_rs::ECDSA_P384_SHA384),
        SIG_RSA_PSS_RSAE_SHA384 => Ok(webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        SIG_RSA_PKCS1_SHA384 => Ok(webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384),
        SIG_RSA_PSS_RSAE_SHA512 => Ok(webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),
        SIG_RSA_PKCS1_SHA512 => Ok(webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512),
        _ => Err(Safari26TlsError::Unsupported(
            "unsupported CertificateVerify signature scheme",
        )),
    }
}

fn verify_server_certificate(
    sni: &str,
    flight: &ServerFlight,
    transcript: &HandshakeTranscript,
) -> Result<(), Safari26TlsError> {
    let _ = transcript;
    let leaf = flight
        .certificates
        .first()
        .ok_or_else(|| Safari26TlsError::Certificate("missing server certificate".to_owned()))?;
    #[cfg(test)]
    if sni == "example.com" && Sha256::digest(leaf)[..] == LOOPBACK_CAMOUFLAGE_CERT_SHA256 {
        return Ok(());
    }

    let leaf_der = CertificateDer::from(leaf.as_slice());
    let cert = webpki::EndEntityCert::try_from(&leaf_der)
        .map_err(|err| Safari26TlsError::Certificate(err.to_string()))?;
    let intermediates = flight
        .certificates
        .iter()
        .skip(1)
        .map(|cert| CertificateDer::from(cert.as_slice()))
        .collect::<Vec<_>>();
    let server_name = ServerName::try_from(sni)
        .map_err(|_| Safari26TlsError::InvalidServerName(sni.to_owned()))?;
    cert.verify_is_valid_for_subject_name(&server_name)
        .map_err(|err| Safari26TlsError::Certificate(err.to_string()))?;

    let roots = native_roots()?;
    let anchors = roots
        .iter()
        .filter_map(|root| webpki::anchor_from_trusted_cert(root).ok())
        .collect::<Vec<_>>();
    let now = UnixTime::since_unix_epoch(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| Safari26TlsError::Certificate(err.to_string()))?,
    );
    cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediates,
        now,
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|err| Safari26TlsError::Certificate(err.to_string()))?;
    Ok(())
}

fn native_roots() -> Result<&'static [CertificateDer<'static>], Safari26TlsError> {
    // Cache only the SUCCESS value: a transient empty/error load (boot-time
    // trust-store rotation, a momentary sandbox denial) must NOT be memoized, or
    // it would poison certificate verification for the whole process lifetime.
    // Each failed load returns an error and the next handshake retries.
    static ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
    if let Some(roots) = ROOTS.get() {
        return Ok(roots.as_slice());
    }
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        let detail = loaded
            .errors
            .first()
            .map(ToString::to_string)
            .unwrap_or_else(|| "platform root store returned no certificates".to_owned());
        return Err(Safari26TlsError::Certificate(detail));
    }
    // Another thread may win the init race; both then observe the winner's value.
    let _ = ROOTS.set(loaded.certs);
    Ok(ROOTS.get().expect("ROOTS populated above").as_slice())
}

struct HandshakeTranscript {
    bytes: Vec<u8>,
}

impl HandshakeTranscript {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn push(&mut self, message: &[u8]) {
        self.bytes.extend_from_slice(message);
    }

    fn push_handshake_record(&mut self, record: &[u8]) -> Result<(), Safari26TlsError> {
        let (_, payload) = super::record::parse_exact(record)
            .map_err(|err| Safari26TlsError::Handshake(err.to_string()))?;
        self.bytes.extend_from_slice(payload);
        Ok(())
    }
}

fn parse_alert<T>(record: &[u8]) -> Result<T, Safari26TlsError> {
    if record.len() >= 7 {
        Err(Safari26TlsError::Alert {
            level: record[5],
            description: record[6],
        })
    } else {
        Err(Safari26TlsError::Alert {
            level: 0,
            description: 0,
        })
    }
}

/// A warning-level close_notify (level 1, description 0) is the origin's graceful
/// end-of-stream. It is tolerated as a clean close only on the AEAD-authenticated
/// post-handshake alert branches; every fatal alert (level 2) and every other
/// warning (e.g. user_canceled, desc 90) still aborts. Scoped precisely per
/// RFC 8446 6.1 so real handshake failures are never masked.
fn is_warning_close_notify(level: u8, description: u8) -> bool {
    level == TLS_ALERT_LEVEL_WARNING && description == TLS_ALERT_DESC_CLOSE_NOTIFY
}

fn is_clean_close(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}

struct TlsCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TlsCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8, Safari26TlsError> {
        if self.remaining() < 1 {
            return Err(Safari26TlsError::Handshake("TLS data truncated".to_owned()));
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, Safari26TlsError> {
        if self.remaining() < 2 {
            return Err(Safari26TlsError::Handshake("TLS data truncated".to_owned()));
        }
        let value = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    fn u24(&mut self) -> Result<u32, Safari26TlsError> {
        if self.remaining() < 3 {
            return Err(Safari26TlsError::Handshake("TLS data truncated".to_owned()));
        }
        let value = ((self.data[self.pos] as u32) << 16)
            | ((self.data[self.pos + 1] as u32) << 8)
            | self.data[self.pos + 2] as u32;
        self.pos += 3;
        Ok(value)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], Safari26TlsError> {
        if self.remaining() < len {
            return Err(Safari26TlsError::Handshake("TLS data truncated".to_owned()));
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.data[start..start + len])
    }

    fn vec_u8(&mut self) -> Result<&'a [u8], Safari26TlsError> {
        let len = self.u8()? as usize;
        self.bytes(len)
    }

    fn vec_u16(&mut self) -> Result<&'a [u8], Safari26TlsError> {
        let len = self.u16()? as usize;
        self.bytes(len)
    }

    fn vec_u24(&mut self) -> Result<&'a [u8], Safari26TlsError> {
        let len = self.u24()? as usize;
        self.bytes(len)
    }
}

/// Fuzz-only entry points for internal handshake parsers. Compiled ONLY under
/// `--cfg fuzzing` (which cargo-fuzz sets automatically); absent from normal
/// `cargo build` / `cargo test` and from CI builds, so it cannot widen the
/// production API surface. These are thin wrappers (not `pub use`, which would
/// hit E0364 on the private fns) and erase the crate-internal error type.
#[cfg(fuzzing)]
#[allow(clippy::result_unit_err)] // fuzz-only wrappers intentionally erase the crate error type
pub mod fuzz {
    pub fn parse_compressed_certificate_body(body: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
        super::parse_compressed_certificate_body(body).map_err(|_| ())
    }

    pub fn parse_certificate_body(body: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
        super::parse_certificate_body(body).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        auth::{derive_server_auth_key, verify_masked_stateful_client_hello_auth_with_material},
        session::X25519KeyPair,
    };
    use crate::tls::client_hello::parse_client_hello;
    // AsyncWriteExt, TcpStream, and Zeroizing are already in scope via `use
    // super::*` (parent imports at the top of this file); only TcpListener is new.
    use tokio::net::TcpListener;

    fn build_compressed_cert_body(declared_uncompressed_len: usize, plaintext: &[u8]) -> Vec<u8> {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(plaintext).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&CERT_COMPRESSION_ZLIB.to_be_bytes());
        push_u24(&mut body, declared_uncompressed_len).unwrap();
        push_u24(&mut body, compressed.len()).unwrap();
        body.extend_from_slice(&compressed);
        body
    }

    #[test]
    fn compressed_certificate_rejects_oversized_declared_length_before_allocating() {
        // A declared uncompressed length above the cap must be refused outright
        // (no multi-GiB Vec::with_capacity), regardless of the compressed body.
        let body = build_compressed_cert_body(MAX_DECOMPRESSED_CERT_CHAIN + 1, b"hi");
        let err = parse_compressed_certificate_body(&body).unwrap_err();
        assert!(
            matches!(err, Safari26TlsError::Handshake(ref m) if m.contains("exceeds maximum")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn compressed_certificate_rejects_inflation_beyond_cap_with_lying_header() {
        // Declared length is small (passes the pre-check), but the stream inflates
        // far beyond the cap. The bounded reader must stop and reject rather than
        // inflating gigabytes.
        let plaintext = vec![0_u8; MAX_DECOMPRESSED_CERT_CHAIN + 4096];
        let body = build_compressed_cert_body(64, &plaintext);
        let err = parse_compressed_certificate_body(&body).unwrap_err();
        assert!(
            matches!(err, Safari26TlsError::Handshake(ref m) if m.contains("beyond maximum")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn safari26_camouflage_emits_authenticated_client_hello() {
        let server = X25519KeyPair::generate();
        let psk = b"0123456789abcdef0123456789abcdef";
        let session = Safari26TlsCamouflage
            .start("example.com".to_owned(), psk, &server.public)
            .unwrap();

        let parsed = parse_client_hello(&session.client_hello).unwrap();
        let mask_ecdh = x25519_shared_secret(
            &server.private,
            &parsed
                .x25519_key_share
                .expect("Safari26 carries a standalone X25519 key_share"),
        );
        let material = recover_stateful_auth_material(&session.client_hello, psk, &mask_ecdh)
            .unwrap()
            .unwrap();
        let auth_key =
            *derive_server_auth_key(psk, &server.private, &material.x25519_public).unwrap();
        let auth = verify_masked_stateful_client_hello_auth_with_material(
            &session.client_hello,
            &auth_key,
            &material,
        )
        .unwrap();

        assert_ne!(parsed.client_random, session.parallax_x25519.public);
        assert!(auth.authenticated);
        assert_eq!(auth.sni.as_deref(), Some("example.com"));
        assert_eq!(auth.x25519_key_share, Some(session.parallax_x25519.public));
    }

    #[test]
    fn handwritten_client_hello_uses_safari_wire_order() {
        let server = X25519KeyPair::generate();
        let psk = b"0123456789abcdef0123456789abcdef";
        let session = Safari26TlsCamouflage
            .start("apple.com".to_owned(), psk, &server.public)
            .unwrap();
        let (_, payload) = super::super::record::parse_exact(&session.client_hello).unwrap();
        assert_eq!(session.client_hello[0], TLS_RECORD_HANDSHAKE);
        assert_eq!(
            &session.client_hello[1..3],
            &TLS_RECORD_VERSION_CLIENT_HELLO
        );
        assert_eq!(payload[0], HANDSHAKE_CLIENT_HELLO);

        let mut c = TlsCursor::new(&payload[4..]);
        assert_eq!(c.u16().unwrap(), TLS12);
        let _random = c.bytes(32).unwrap();
        assert_eq!(c.vec_u8().unwrap().len(), 32);
        let ciphers = c.vec_u16().unwrap();
        assert_eq!(&ciphers[2..8], &[0x13, 0x02, 0x13, 0x03, 0x13, 0x01]);
        assert!(ciphers.windows(2).any(|w| w == [0x00, 0x0a]));
        assert_eq!(c.vec_u8().unwrap(), &[0]);
        let extensions = c.vec_u16().unwrap();
        let mut e = TlsCursor::new(extensions);
        let mut order = Vec::new();
        while e.remaining() > 0 {
            let ext = e.u16().unwrap();
            let _ = e.vec_u16().unwrap();
            order.push(ext);
        }
        assert!(is_grease(order[0]));
        assert!(is_grease(*order.last().unwrap()));
        assert_eq!(
            &order[1..order.len() - 1],
            &[
                EXT_SERVER_NAME,
                EXT_EXTENDED_MASTER_SECRET,
                EXT_RENEGOTIATION_INFO,
                EXT_SUPPORTED_GROUPS,
                EXT_EC_POINT_FORMATS,
                EXT_ALPN,
                EXT_STATUS_REQUEST,
                EXT_SIGNATURE_ALGORITHMS,
                EXT_SIGNED_CERTIFICATE_TIMESTAMP,
                EXT_KEY_SHARE,
                EXT_PSK_KEY_EXCHANGE_MODES,
                EXT_SUPPORTED_VERSIONS,
                EXT_COMPRESS_CERTIFICATE,
            ]
        );
    }

    #[test]
    fn vec_record_tap_records_events_in_order() {
        let mut tap = VecRecordTap::default();
        assert!(tap.events().is_empty());

        tap.on_record(RecordEvent {
            direction: RecordDirection::Outbound,
            content_type: 0x16,
            len: 512,
        });
        tap.on_record(RecordEvent {
            direction: RecordDirection::Inbound,
            content_type: 0x17,
            len: 42,
        });

        assert_eq!(tap.events().len(), 2);
        assert!(matches!(
            tap.events()[0].direction,
            RecordDirection::Outbound
        ));
        assert!(matches!(
            tap.events()[1].direction,
            RecordDirection::Inbound
        ));
    }

    fn is_grease(value: u16) -> bool {
        value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
    }

    // ---- Helpers for the HTTP/2 camouflage tail tests ----

    fn test_session() -> Safari26TlsSession {
        let server = X25519KeyPair::generate();
        let psk = b"0123456789abcdef0123456789abcdef";
        Safari26TlsCamouflage
            .start("example.com".to_owned(), psk, &server.public)
            .unwrap()
    }

    /// The client's SECOND flight, in order, MUST be the TLS 1.3 middlebox-
    /// compatibility ChangeCipherSpec (`14 03 03 00 01 01`) immediately followed by
    /// the encrypted (application-data record type) Finished. Per RFC 8446 §D.4 a
    /// client offering neither early_data nor a PSK (our full-handshake CH) sends the
    /// dummy CCS immediately before its second flight — i.e. AFTER the ServerHello —
    /// not after the ClientHello (that earlier position only matches a 0-RTT
    /// handshake and is itself a distinguisher). `write_client_finished` is the second
    /// flight, so we drive it directly and assert the two records.
    #[tokio::test]
    async fn client_second_flight_emits_compat_ccs_then_encrypted_finished() {
        let mut session = test_session();
        let mut keys = app_keys();
        let mut transcript = HandshakeTranscript::new();
        let (mut client, mut peer) = loopback().await;

        session
            .write_client_finished(&mut client, &mut keys, &mut transcript)
            .await
            .expect("write_client_finished");
        drop(client);

        let read_timeout = Duration::from_secs(5);
        let mut first = Vec::new();
        let mut second = Vec::new();
        let mut reader = TlsRecordReader::new(&mut peer);
        timeout(read_timeout, reader.read_record_into(&mut first))
            .await
            .expect("timed out reading the compat CCS record")
            .unwrap();
        timeout(read_timeout, reader.read_record_into(&mut second))
            .await
            .expect("timed out reading the encrypted Finished record")
            .unwrap();

        // First record of the second flight: the exact TLS 1.3 compat CCS.
        assert_eq!(
            first,
            change_cipher_spec(),
            "second flight must lead with `14 03 03 00 01 01` (compat CCS)"
        );
        // Second record: the encrypted Finished, carried as an application-data record.
        assert_eq!(
            second[0], TLS_RECORD_APPLICATION_DATA,
            "the Finished must be an encrypted application-data record, after the CCS"
        );
    }

    async fn loopback() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    // Two independently-seq'd key sets derived from identical, deterministic
    // inputs: records encrypted with one decrypt cleanly under the other, which
    // lets a test "server" feed encrypted records the session decrypts.
    fn app_keys() -> Tls13Keys {
        let transcript = HandshakeTranscript::new();
        let mut keys =
            Tls13Keys::new(TlsCipherSuite::Aes128GcmSha256, &[7_u8; 32], &transcript).unwrap();
        keys.install_application_keys(&transcript).unwrap();
        keys
    }

    fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = vec![content_type, 0x03, 0x03];
        record.push((payload.len() >> 8) as u8);
        record.push(payload.len() as u8);
        record.extend_from_slice(payload);
        record
    }

    fn h2_frame(frame_type: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(Http2FrameHeader::SIZE + payload.len());
        frame.push((payload.len() >> 16) as u8);
        frame.push((payload.len() >> 8) as u8);
        frame.push(payload.len() as u8);
        frame.push(frame_type);
        frame.push(flags);
        frame.extend_from_slice(&[0, 0, 0, 0]); // stream id 0
        frame.extend_from_slice(payload);
        frame
    }

    fn sample_handshake(shared_secret: [u8; 32]) -> CompletedSafari26Handshake {
        CompletedSafari26Handshake {
            client_hello: vec![1, 2, 3],
            // Deterministic so the Debug-redaction test never scans random public
            // bytes: X25519KeyPair's Debug prints `public` verbatim, so a random
            // keypair could coincidentally render the secret's byte sentinel.
            client_x25519: X25519KeyPair {
                private: [1_u8; 32],
                public: [1_u8; 32],
            },
            server_hello_record: vec![4, 5, 6],
            record_events: Vec::new(),
            negotiated_alpn: Some(b"h2".to_vec()),
            post_handshake_records: 2,
            x25519_shared_secret: Zeroizing::new(shared_secret),
        }
    }

    // ---- tap_records ----

    #[test]
    fn tap_records_emits_one_event_per_complete_record() {
        let mut session = test_session();
        let mut buf = tls_record(0x17, &[0xaa, 0xbb, 0xcc]); // payload len 3
        buf.extend_from_slice(&tls_record(0x16, &[0xdd])); // payload len 1, ends at buf end

        let before = session.tap.events().len();
        session.tap_records(RecordDirection::Inbound, &buf);
        let events = &session.tap.events()[before..];

        // Exact counts and lengths pin the offset arithmetic and the loop/boundary
        // guards: the second record ends exactly at buf.len(), so an off-by-one in
        // the `offset + total > len` guard would drop it.
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].content_type, 0x17);
        assert_eq!(events[0].len, 3);
        assert!(matches!(events[0].direction, RecordDirection::Inbound));
        assert_eq!(events[1].content_type, 0x16);
        assert_eq!(events[1].len, 1);
        assert!(matches!(events[1].direction, RecordDirection::Inbound));
    }

    #[test]
    fn tap_records_ignores_truncated_trailing_record() {
        let mut session = test_session();
        let mut buf = tls_record(0x17, &[0x01, 0x02]);
        // Header announces 4 payload bytes but only 1 is present: incomplete.
        buf.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x99]);

        let before = session.tap.events().len();
        session.tap_records(RecordDirection::Outbound, &buf);
        let events = &session.tap.events()[before..];

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].len, 2);
        assert!(matches!(events[0].direction, RecordDirection::Outbound));
    }

    #[test]
    fn tap_records_counts_zero_payload_record_ending_on_boundary() {
        let mut session = test_session();
        let mut buf = tls_record(0x17, &[0xaa, 0xbb]); // payload len 2
        buf.extend_from_slice(&tls_record(0x17, &[])); // zero-payload header only

        let before = session.tap.events().len();
        session.tap_records(RecordDirection::Inbound, &buf);
        let events = &session.tap.events()[before..];

        // The trailing record starts at offset 7 and is header-only, so it ends
        // exactly at `offset + TLS_HEADER_LEN == buf.len()`. The loop-entry guard
        // must use `<=`; a mutation to `<` would skip this final record.
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].content_type, 0x17);
        assert_eq!(events[1].len, 0);
    }

    // ---- process_http2_frames ----

    #[tokio::test]
    async fn process_http2_frames_detects_ack_and_drains_consumed_frames() {
        let mut session = test_session();
        let (mut stream, _peer) = loopback().await;
        let mut keys = app_keys();

        let ack = h2_frame(0x4, 0x1, &[]); // SETTINGS with ACK flag, empty payload
        let mut plaintext = ack.clone();
        plaintext.extend_from_slice(&ack); // two complete frames: offset must advance twice
        plaintext.extend_from_slice(&[0x00, 0x00, 0x05, 0x04]); // partial trailing header

        let saw_ack = session
            .process_http2_frames(&mut plaintext, &mut stream, &mut keys)
            .await
            .unwrap();

        assert!(saw_ack);
        // Both complete frames drained; only the partial header is retained.
        assert_eq!(plaintext, vec![0x00, 0x00, 0x05, 0x04]);
    }

    #[tokio::test]
    async fn process_http2_frames_returns_false_without_ack() {
        let mut session = test_session();
        let (mut stream, _peer) = loopback().await;
        let mut keys = app_keys();

        // WINDOW_UPDATE (type 0x8): neither a SETTINGS nor an ACK, so no peer write.
        let mut plaintext = h2_frame(0x8, 0x0, &[0, 0, 0, 1]);
        let saw_ack = session
            .process_http2_frames(&mut plaintext, &mut stream, &mut keys)
            .await
            .unwrap();

        assert!(!saw_ack);
        assert!(plaintext.is_empty());
    }

    #[tokio::test]
    async fn process_http2_frames_acks_a_plain_settings_frame() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // A plain (non-ACK) SETTINGS frame drives the `else if header.is_settings()`
        // arm and the `should_ack_peer_settings` write block: the session must
        // encrypt and send a SETTINGS-ACK back to the peer.
        let mut plaintext = h2_frame(0x4, 0x0, &[0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);
        let saw_ack = session
            .process_http2_frames(&mut plaintext, &mut stream, &mut session_keys)
            .await
            .unwrap();

        assert!(!saw_ack); // a peer SETTINGS frame is not itself our ack signal
        assert!(plaintext.is_empty()); // the complete frame was drained

        // The reply is written via client_application.encrypt_record, so decrypt it
        // with the matching (identical, deterministic) peer key set and confirm the
        // inner bytes are exactly an HTTP/2 SETTINGS-ACK frame.
        let mut record = Vec::new();
        let mut reader = TlsRecordReader::new(&mut peer);
        reader.read_record_into(&mut record).await.unwrap();
        let chunk = peer_keys
            .client_application
            .decrypt_record(&record)
            .unwrap();
        assert_eq!(
            chunk.plaintext,
            Http2Fingerprint::settings_ack_frame().unwrap()
        );
    }

    // ---- drain_post_handshake ----

    #[tokio::test]
    async fn drain_post_handshake_tolerates_encrypted_close_notify() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // The real TLS 1.3 origin close_notify: an AEAD-wrapped warning alert
        // [level 1, close_notify 0]. It must resolve to a clean end-of-drain (Ok),
        // exactly as the bare-FIN path does.
        let record = peer_keys
            .server_application
            .encrypt_record(TLS_CONTENT_ALERT, &[0x01, 0x00])
            .unwrap();
        peer.write_all(&record).await.unwrap();
        drop(peer);

        let observed = session
            .drain_post_handshake(&mut stream, &mut session_keys)
            .await
            .unwrap();
        // The close_notify is an end-of-stream terminator, not a post-handshake
        // data record: it must NOT be counted, matching the bare-FIN path (which
        // returns without incrementing). A single close_notify => 0 observed
        // records, so `plx probe` cannot score a clean close as a ticket signal.
        assert_eq!(observed, 0);
    }

    #[tokio::test]
    async fn drain_post_handshake_errors_on_encrypted_fatal_alert() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // A fatal alert (level 2) must still abort even at drain time so real
        // handshake failures are never swallowed.
        let record = peer_keys
            .server_application
            .encrypt_record(TLS_CONTENT_ALERT, &[0x02, 0x28])
            .unwrap();
        peer.write_all(&record).await.unwrap();
        drop(peer);

        let err = session
            .drain_post_handshake(&mut stream, &mut session_keys)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Alert {
                level: 0x02,
                description: 0x28
            }
        ));
    }

    #[tokio::test]
    async fn drain_post_handshake_errors_on_plaintext_close_notify() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut keys = app_keys();

        // Tolerance is scoped to the AEAD-authenticated branch only. A plaintext
        // post-handshake close_notify is unauthenticated and not real-origin
        // behavior, so it must still surface as an error.
        peer.write_all(&tls_record(TLS_CONTENT_ALERT, &[0x01, 0x00]))
            .await
            .unwrap();
        drop(peer);

        let err = session
            .drain_post_handshake(&mut stream, &mut keys)
            .await
            .unwrap_err();
        assert!(matches!(err, Safari26TlsError::Alert { .. }));
    }

    // ---- await_http2_settings_ack ----

    #[tokio::test]
    async fn await_http2_settings_ack_propagates_outer_alert() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut keys = app_keys();

        peer.write_all(&tls_record(TLS_CONTENT_ALERT, &[0x02, 0x28]))
            .await
            .unwrap();
        drop(peer);

        let err = session
            .await_http2_settings_ack(&mut stream, &mut keys)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Alert {
                level: 0x02,
                description: 0x28
            }
        ));
    }

    #[tokio::test]
    async fn await_http2_settings_ack_surfaces_encrypted_alert() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        let record = peer_keys
            .server_application
            .encrypt_record(TLS_CONTENT_ALERT, &[0x02, 0x2a])
            .unwrap();
        peer.write_all(&record).await.unwrap();
        drop(peer);

        let err = session
            .await_http2_settings_ack(&mut stream, &mut session_keys)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Alert {
                level: 0x02,
                description: 0x2a
            }
        ));
    }

    #[tokio::test]
    async fn await_http2_settings_ack_tolerates_encrypted_close_notify() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // Origin closes before ACKing SETTINGS by sending an encrypted warning
        // close_notify [1, 0]. The client must treat it as a clean close (Ok), the
        // core fix for the pre-existing client-side race.
        let record = peer_keys
            .server_application
            .encrypt_record(TLS_CONTENT_ALERT, &[0x01, 0x00])
            .unwrap();
        peer.write_all(&record).await.unwrap();
        drop(peer);

        session
            .await_http2_settings_ack(&mut stream, &mut session_keys)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn await_http2_settings_ack_rejects_encrypted_fatal_close_notify() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // A close_notify wrongly marked fatal (level 2, desc 0) must still abort:
        // the predicate keys on level==1, so this is not a benign close.
        let record = peer_keys
            .server_application
            .encrypt_record(TLS_CONTENT_ALERT, &[0x02, 0x00])
            .unwrap();
        peer.write_all(&record).await.unwrap();
        drop(peer);

        let err = session
            .await_http2_settings_ack(&mut stream, &mut session_keys)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Alert {
                level: 0x02,
                description: 0x00
            }
        ));
    }

    #[tokio::test]
    async fn await_http2_settings_ack_rejects_encrypted_warning_user_canceled() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // A warning alert that is NOT close_notify (user_canceled, desc 0x5a) must
        // still abort: the predicate keys on desc==0, pinning the scope precisely.
        let record = peer_keys
            .server_application
            .encrypt_record(TLS_CONTENT_ALERT, &[0x01, 0x5a])
            .unwrap();
        peer.write_all(&record).await.unwrap();
        drop(peer);

        let err = session
            .await_http2_settings_ack(&mut stream, &mut session_keys)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Alert {
                level: 0x01,
                description: 0x5a
            }
        ));
    }

    #[tokio::test]
    async fn await_http2_settings_ack_rejects_plaintext_close_notify() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut keys = app_keys();

        // Tolerance is encrypted-only; an unauthenticated plaintext close_notify
        // must still error (documents the intentional scope boundary).
        peer.write_all(&tls_record(TLS_CONTENT_ALERT, &[0x01, 0x00]))
            .await
            .unwrap();
        drop(peer);

        let err = session
            .await_http2_settings_ack(&mut stream, &mut keys)
            .await
            .unwrap_err();
        assert!(matches!(err, Safari26TlsError::Alert { .. }));
    }

    #[tokio::test]
    async fn await_http2_settings_ack_ignores_non_alert_inner_record() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // Inner HANDSHAKE record (not application-data, not an alert) with a >=2
        // byte body: must be skipped, not mis-read as an alert.
        let record = peer_keys
            .server_application
            .encrypt_record(TLS_RECORD_HANDSHAKE, &[0xaa, 0xbb])
            .unwrap();
        peer.write_all(&record).await.unwrap();
        drop(peer);

        session
            .await_http2_settings_ack(&mut stream, &mut session_keys)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn await_http2_settings_ack_skips_short_inner_alert() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // A 1-byte inner ALERT: too short to carry level+description. The
        // `chunk.plaintext.len() >= 2` guard must skip it via `continue`; without
        // that guard, indexing `plaintext[1]` would panic.
        let record = peer_keys
            .server_application
            .encrypt_record(TLS_CONTENT_ALERT, &[0x02])
            .unwrap();
        peer.write_all(&record).await.unwrap();
        drop(peer);

        session
            .await_http2_settings_ack(&mut stream, &mut session_keys)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn await_http2_settings_ack_returns_via_inner_appdata_ack() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // An inner application-data record carrying an HTTP/2 SETTINGS-ACK frame
        // drives the APPDATA -> process_http2_frames -> `return Ok(())` path.
        let ack = h2_frame(0x4, 0x1, &[]);
        let record = peer_keys
            .server_application
            .encrypt_record(TLS_RECORD_APPLICATION_DATA, &ack)
            .unwrap();
        peer.write_all(&record).await.unwrap();
        // A trailing outer alert that must NOT be reached: if the ACK path failed
        // to return early, the loop would consume this and surface an Alert error.
        peer.write_all(&tls_record(TLS_CONTENT_ALERT, &[0x02, 0x28]))
            .await
            .unwrap();
        drop(peer);

        session
            .await_http2_settings_ack(&mut stream, &mut session_keys)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn await_http2_settings_ack_times_out_cleanly_at_record_boundary() {
        let mut session = test_session();
        let (mut stream, _peer) = loopback().await; // peer stays open and silent
        let mut keys = app_keys();

        // Nothing is ever sent: the read times out at a clean record boundary and
        // must resolve to Ok rather than a mid-record error.
        session
            .await_http2_settings_ack(&mut stream, &mut keys)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn await_http2_settings_ack_errors_on_mid_record_timeout() {
        let mut session = test_session();
        let (mut stream, mut peer) = loopback().await;
        let mut keys = app_keys();

        // A header announcing 16 payload bytes, but only 4 sent, then silence:
        // the timeout fires mid-record and must surface as an error.
        peer.write_all(&[
            TLS_CONTENT_APPLICATION_DATA,
            0x03,
            0x03,
            0x00,
            0x10,
            1,
            2,
            3,
            4,
        ])
        .await
        .unwrap();

        let err = session
            .await_http2_settings_ack(&mut stream, &mut keys)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Handshake(ref m) if m.contains("mid-record")
        ));
        drop(peer);
    }

    #[tokio::test]
    async fn await_http2_settings_ack_keeps_reading_at_exactly_the_buffer_limit() {
        let mut session = test_session();
        let (mut stream, peer) = loopback().await;
        let mut session_keys = app_keys();
        let mut peer_keys = app_keys();

        // Accumulate EXACTLY H2_FRAME_BUFFER_LIMIT (64 KiB) of inner application-data
        // that never completes a single HTTP/2 frame: the first 9 bytes are a header
        // announcing a ~16 MiB DATA frame (type 0x0, not SETTINGS) and the rest is
        // filler, so `process_http2_frames` consumes nothing and `plaintext` grows to
        // exactly the limit. At the limit the guard `plaintext.len() > LIMIT` is FALSE,
        // so the real code keeps reading and surfaces the trailing alert as an error.
        // This pins the STRICT `>`: a `<`, `==`, or `>=` there would instead return Ok
        // early and never read the alert (verified against all three by manual mutation),
        // so this one case kills every comparison mutant cargo-mutants flagged here.
        const CHUNK: usize = 16_000;
        let sizes = [
            CHUNK,
            CHUNK,
            CHUNK,
            CHUNK,
            H2_FRAME_BUFFER_LIMIT - 4 * CHUNK,
        ];
        let mut records = Vec::new();
        for (i, &size) in sizes.iter().enumerate() {
            let mut inner = vec![0_u8; size];
            if i == 0 {
                // 3-byte length = 0x00FF_FFFF, then frame type 0x0 (DATA).
                inner[0..4].copy_from_slice(&[0xff, 0xff, 0xff, 0x00]);
            }
            records.push(
                peer_keys
                    .server_application
                    .encrypt_record(TLS_RECORD_APPLICATION_DATA, &inner)
                    .unwrap(),
            );
        }
        // The trailing outer alert is reached ONLY if the guard did not stop the loop.
        let trailing_alert = tls_record(TLS_CONTENT_ALERT, &[0x02, 0x28]);

        // Feed concurrently: 64 KB can exceed the loopback socket buffer, so a
        // sequential write-then-read would deadlock; the reader drains as we fill.
        let writer = tokio::spawn(async move {
            let mut peer = peer;
            for record in records {
                if peer.write_all(&record).await.is_err() {
                    return;
                }
            }
            let _ = peer.write_all(&trailing_alert).await;
        });

        let err = session
            .await_http2_settings_ack(&mut stream, &mut session_keys)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Alert {
                level: 0x02,
                description: 0x28
            }
        ));
        let _ = writer.await;
    }

    // ---- CompletedSafari26Handshake accessors ----

    #[test]
    fn completed_handshake_exposes_stored_shared_secret() {
        let mut secret = [0_u8; 32];
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = i as u8; // distinct from both [0; 32] and [1; 32]
        }
        let handshake = sample_handshake(secret);
        assert_eq!(handshake.x25519_shared_secret(), &secret);
    }

    #[test]
    fn completed_handshake_debug_redacts_secret_and_lists_fields() {
        let handshake = sample_handshake([9_u8; 32]);
        let rendered = format!("{handshake:?}");
        assert!(rendered.contains("CompletedSafari26Handshake"));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("negotiated_alpn"));
        assert!(!rendered.contains("9, 9, 9")); // raw secret bytes never printed
    }

    // ---- Issue #54: tls_shared_secret group dispatch + length guards ----

    fn server_hello_with(group: u16, key_share: Vec<u8>) -> ParsedServerHello {
        ParsedServerHello {
            cipher_suite: TlsCipherSuite::Aes128GcmSha256,
            key_share_group: group,
            key_share,
        }
    }

    #[test]
    fn tls_shared_secret_x25519_returns_a_deterministic_32_byte_secret() {
        // Kills the GROUP_X25519 delete-arm, the constant-return mutants
        // (Ok(vec![])/[0]/[1]), and the length-guard `!=`->`==`: a valid 32-byte
        // server share yields a 32-byte secret that depends on the share.
        let session = test_session();
        let server_a = X25519KeyPair::generate();
        let server_b = X25519KeyPair::generate();
        let sa = session
            .tls_shared_secret(&server_hello_with(GROUP_X25519, server_a.public.to_vec()))
            .unwrap();
        assert_eq!(sa.len(), 32, "X25519 shared secret is 32 bytes (not empty)");
        assert_ne!(&sa[..], &[0_u8; 32], "secret is not the all-zero mutant");
        // The same share is deterministic; a different share gives a different secret.
        let sa2 = session
            .tls_shared_secret(&server_hello_with(GROUP_X25519, server_a.public.to_vec()))
            .unwrap();
        assert_eq!(sa, sa2, "deterministic for a fixed server share");
        let sb = session
            .tls_shared_secret(&server_hello_with(GROUP_X25519, server_b.public.to_vec()))
            .unwrap();
        assert_ne!(sa, sb, "the secret binds the server key_share");
    }

    #[test]
    fn tls_shared_secret_rejects_wrong_length_and_unknown_groups() {
        // Kills the length-guard `!=`->`==` for BOTH groups, the `+`->`-`/`*`
        // mutants on `MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN`, and proves the
        // group match is exhaustive (an unknown group is Unsupported, not silently
        // accepted by a deleted arm).
        let session = test_session();
        // X25519 with a 31-byte (wrong) share is rejected.
        assert!(matches!(
            session.tls_shared_secret(&server_hello_with(GROUP_X25519, vec![0u8; 31])),
            Err(Safari26TlsError::Handshake(_))
        ));
        // X25519MLKEM768 requires exactly 1088 + 32 bytes; one short is rejected.
        assert!(matches!(
            session.tls_shared_secret(&server_hello_with(
                GROUP_X25519_MLKEM768,
                vec![0u8; MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN - 1],
            )),
            Err(Safari26TlsError::Handshake(_) | Safari26TlsError::MlKem)
        ));
        // An unknown group is Unsupported.
        assert!(matches!(
            session.tls_shared_secret(&server_hello_with(0x4242, vec![0u8; 32])),
            Err(Safari26TlsError::Unsupported(_))
        ));
    }

    // ---- Issue #54: byte-limit constants (kill the `*`->`+`/`/` mutants) ----

    #[test]
    fn handshake_byte_limit_constants_are_exact() {
        // The `* 1024` / `* 1024` factors define memory bounds; a `*`->`+` or `*`->`/`
        // mutation would silently shrink them. Pin the exact values.
        assert_eq!(H2_FRAME_BUFFER_LIMIT, 64 * 1024);
        assert_eq!(MAX_DECOMPRESSED_CERT_CHAIN, 256 * 1024);
        assert_eq!(MAX_ENCRYPTED_HANDSHAKE_MESSAGE, 512 * 1024);
    }

    // ---- push_u24 ----

    #[test]
    fn push_u24_accepts_max_three_byte_length() {
        // 0x00ff_ffff is the largest value encodable in 24 bits and must be
        // accepted: a `>`->`==` or `>`->`>=` mutation of the bound would reject
        // this boundary value.
        let mut out = Vec::new();
        push_u24(&mut out, 0x00ff_ffff).unwrap();
        assert_eq!(out, vec![0xff, 0xff, 0xff]);
    }

    #[test]
    fn push_u24_rejects_oversized_length() {
        let mut out = Vec::new();
        let err = push_u24(&mut out, 0x0100_0000).unwrap_err();
        assert!(matches!(err, Safari26TlsError::Handshake(_)));
    }

    // ---- hrr_random ----

    #[test]
    fn hrr_random_returns_known_sentinel() {
        // Pins the full 32-byte HelloRetryRequest sentinel; the empty / [0] / [1]
        // return mutants and any interior-byte mutation all fail this comparison.
        assert_eq!(
            hrr_random(),
            &[
                0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
                0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
                0xc8, 0xa8, 0x33, 0x9c,
            ]
        );
    }

    // ---- TlsCipherSuite ----

    #[test]
    fn cipher_suite_from_u16_maps_each_registered_suite() {
        assert!(matches!(
            TlsCipherSuite::from_u16(TLS_AES_128_GCM_SHA256).unwrap(),
            TlsCipherSuite::Aes128GcmSha256
        ));
        assert!(matches!(
            TlsCipherSuite::from_u16(TLS_AES_256_GCM_SHA384).unwrap(),
            TlsCipherSuite::Aes256GcmSha384
        ));
        assert!(matches!(
            TlsCipherSuite::from_u16(TLS_CHACHA20_POLY1305_SHA256).unwrap(),
            TlsCipherSuite::Chacha20Poly1305Sha256
        ));
        assert!(TlsCipherSuite::from_u16(0x0000).is_err());
    }

    #[test]
    fn cipher_suite_hash_and_key_lengths_are_exact() {
        assert_eq!(TlsCipherSuite::Aes128GcmSha256.hash_len(), 32);
        assert_eq!(TlsCipherSuite::Aes256GcmSha384.hash_len(), 48);
        assert_eq!(TlsCipherSuite::Chacha20Poly1305Sha256.hash_len(), 32);
        assert_eq!(TlsCipherSuite::Aes128GcmSha256.key_len(), 16);
        assert_eq!(TlsCipherSuite::Aes256GcmSha384.key_len(), 32);
        assert_eq!(TlsCipherSuite::Chacha20Poly1305Sha256.key_len(), 32);
    }

    #[test]
    fn cipher_suite_digest_uses_the_suite_hash() {
        // Known SHA-256("") / SHA-384("") prefixes: the vec![] / vec![0] / vec![1]
        // mutants fail on both length and leading byte.
        let sha256 = TlsCipherSuite::Aes128GcmSha256.digest(b"");
        assert_eq!(sha256.len(), 32);
        assert_eq!(sha256[0], 0xe3);
        let sha384 = TlsCipherSuite::Aes256GcmSha384.digest(b"");
        assert_eq!(sha384.len(), 48);
        assert_eq!(sha384[0], 0x38);
    }

    #[test]
    fn cipher_suite_hmac_is_keyed_hash_of_expected_length() {
        let mac = TlsCipherSuite::Aes128GcmSha256
            .hmac(b"key", b"data")
            .unwrap();
        assert_eq!(mac.len(), 32); // kills Ok(vec![]) / Ok(vec![0]) / Ok(vec![1])
                                   // The MAC actually depends on the key, not a constant.
        let other = TlsCipherSuite::Aes128GcmSha256
            .hmac(b"other-key", b"data")
            .unwrap();
        assert_ne!(mac, other);
        let mac384 = TlsCipherSuite::Aes256GcmSha384
            .hmac(b"key", b"data")
            .unwrap();
        assert_eq!(mac384.len(), 48);
    }

    // ---- parse_safari_server_hello ----

    // Extensions a valid Safari ServerHello must carry: supported_versions=TLS1.3
    // plus a key_share group/key. Returned separately so negative tests can drop
    // or corrupt one arm without rebuilding the rest.
    fn valid_sh_extensions() -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        ext.extend_from_slice(&2_u16.to_be_bytes());
        ext.extend_from_slice(&TLS13.to_be_bytes());

        let mut key_share = Vec::new();
        key_share.extend_from_slice(&0x001d_u16.to_be_bytes()); // x25519 group id
        key_share.extend_from_slice(&32_u16.to_be_bytes());
        key_share.extend_from_slice(&[0x42; 32]);
        ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        ext.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
        ext.extend_from_slice(&key_share);
        ext
    }

    fn build_safari_server_hello(
        handshake_type: u8,
        legacy_version: u16,
        random: &[u8; 32],
        session_id_len: usize,
        cipher: u16,
        compression: u8,
        extensions: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&legacy_version.to_be_bytes());
        body.extend_from_slice(random);
        body.push(session_id_len as u8);
        body.extend(std::iter::repeat(0x55).take(session_id_len));
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(compression);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = vec![handshake_type];
        push_u24(&mut handshake, body.len()).unwrap();
        handshake.extend_from_slice(&body);

        let mut record = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn valid_safari_server_hello() -> Vec<u8> {
        build_safari_server_hello(
            HANDSHAKE_SERVER_HELLO,
            TLS12,
            &[0x11; 32],
            32,
            TLS_AES_128_GCM_SHA256,
            0,
            &valid_sh_extensions(),
        )
    }

    #[test]
    fn parse_safari_server_hello_accepts_a_valid_record() {
        // A fully valid record must parse. This single happy-path assertion kills a
        // large family of mutants that flip an acceptance check into a rejection:
        // the `!=`->`==` guards on handshake_type / legacy_version / session_id /
        // compression, the `==`->`!=` HRR-random check, the deletion of either the
        // supported_versions or key_share match arm, and the `>` mutations of the
        // `e.remaining() > 0` extension-loop guard (all of which would make this
        // valid record error out).
        let parsed = parse_safari_server_hello(&valid_safari_server_hello()).unwrap();
        assert!(matches!(
            parsed.cipher_suite,
            TlsCipherSuite::Aes128GcmSha256
        ));
        assert_eq!(parsed.key_share_group, 0x001d);
        assert_eq!(parsed.key_share, vec![0x42; 32]);
    }

    #[test]
    fn parse_safari_server_hello_rejects_wrong_handshake_type() {
        let record = build_safari_server_hello(
            HANDSHAKE_SERVER_HELLO + 1,
            TLS12,
            &[0x11; 32],
            32,
            TLS_AES_128_GCM_SHA256,
            0,
            &valid_sh_extensions(),
        );
        assert!(matches!(
            parse_safari_server_hello(&record),
            Err(Safari26TlsError::ServerHello(
                ServerHelloError::NotServerHello
            ))
        ));
    }

    #[test]
    fn parse_safari_server_hello_rejects_non_tls12_legacy_version() {
        let record = build_safari_server_hello(
            HANDSHAKE_SERVER_HELLO,
            TLS13,
            &[0x11; 32],
            32,
            TLS_AES_128_GCM_SHA256,
            0,
            &valid_sh_extensions(),
        );
        assert!(matches!(
            parse_safari_server_hello(&record),
            Err(Safari26TlsError::Handshake(_))
        ));
    }

    #[test]
    fn parse_safari_server_hello_rejects_hello_retry_request() {
        // random == hrr_random() must be rejected as HRR; kills the `==`->`!=`
        // mutation of that comparison.
        let mut hrr = [0_u8; 32];
        hrr.copy_from_slice(hrr_random());
        let record = build_safari_server_hello(
            HANDSHAKE_SERVER_HELLO,
            TLS12,
            &hrr,
            32,
            TLS_AES_128_GCM_SHA256,
            0,
            &valid_sh_extensions(),
        );
        assert!(matches!(
            parse_safari_server_hello(&record),
            Err(Safari26TlsError::Unsupported("HelloRetryRequest"))
        ));
    }

    #[test]
    fn parse_safari_server_hello_rejects_short_session_id() {
        let record = build_safari_server_hello(
            HANDSHAKE_SERVER_HELLO,
            TLS12,
            &[0x11; 32],
            31,
            TLS_AES_128_GCM_SHA256,
            0,
            &valid_sh_extensions(),
        );
        assert!(matches!(
            parse_safari_server_hello(&record),
            Err(Safari26TlsError::Handshake(_))
        ));
    }

    #[test]
    fn parse_safari_server_hello_rejects_nonzero_compression() {
        let record = build_safari_server_hello(
            HANDSHAKE_SERVER_HELLO,
            TLS12,
            &[0x11; 32],
            32,
            TLS_AES_128_GCM_SHA256,
            1,
            &valid_sh_extensions(),
        );
        assert!(matches!(
            parse_safari_server_hello(&record),
            Err(Safari26TlsError::Handshake(_))
        ));
    }

    #[test]
    fn parse_safari_server_hello_rejects_supported_versions_not_tls13() {
        // supported_versions present and 2 bytes long, but announcing TLS 1.2.
        // The `data.len() == 2 && version == TLS13` guard must NOT mark TLS 1.3 as
        // selected, so the record is rejected (MissingServerHello). Kills the
        // `==`->`!=` and `&&`->`||` mutants on that line.
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        ext.extend_from_slice(&2_u16.to_be_bytes());
        ext.extend_from_slice(&TLS12.to_be_bytes());
        // include a key_share so only the version selection is at fault
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&0x001d_u16.to_be_bytes());
        key_share.extend_from_slice(&32_u16.to_be_bytes());
        key_share.extend_from_slice(&[0x42; 32]);
        ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        ext.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
        ext.extend_from_slice(&key_share);

        let record = build_safari_server_hello(
            HANDSHAKE_SERVER_HELLO,
            TLS12,
            &[0x11; 32],
            32,
            TLS_AES_128_GCM_SHA256,
            0,
            &ext,
        );
        assert!(matches!(
            parse_safari_server_hello(&record),
            Err(Safari26TlsError::MissingServerHello)
        ));
    }

    // ---- Tls13Keys::negotiated_h2 ----

    #[test]
    fn tls13_keys_negotiated_h2_reflects_alpn() {
        let mut keys = app_keys();
        assert!(!keys.negotiated_h2()); // no ALPN negotiated yet
        keys.negotiated_alpn = Some(b"h2".to_vec());
        assert!(keys.negotiated_h2()); // kills the `-> false` mutant
        keys.negotiated_alpn = Some(b"http/1.1".to_vec());
        assert!(!keys.negotiated_h2());
    }

    // ---- finished_verify_data ----

    #[test]
    fn finished_verify_data_is_a_nonempty_keyed_hash() {
        let out = finished_verify_data(TlsCipherSuite::Aes128GcmSha256, &[3_u8; 32], b"transcript")
            .unwrap();
        assert_eq!(out.len(), 32); // kills Ok(vec![]) / Ok(vec![0]) / Ok(vec![1])
        assert_ne!(out, vec![0_u8; out.len()]);
        // Depends on the traffic secret.
        let other =
            finished_verify_data(TlsCipherSuite::Aes128GcmSha256, &[4_u8; 32], b"transcript")
                .unwrap();
        assert_ne!(out, other);
    }

    // ---- RecordCipher ----

    #[test]
    fn record_cipher_nonce_xors_sequence_into_iv() {
        let mut cipher = RecordCipher::zero(TlsCipherSuite::Aes128GcmSha256);
        cipher.iv = [0xff; TLS13_IV_LEN];
        cipher.seq = 0x01;
        let nonce = cipher.nonce();
        // The high 4 bytes are never XORed; replacing the whole nonce with
        // [0; _] or [1; _] would change them.
        assert_eq!(&nonce[..4], &[0xff; 4]);
        // 0xff ^ 0x01 = 0xfe in the last byte distinguishes `^=` from `|=` (0xff).
        assert_eq!(nonce[TLS13_IV_LEN - 1], 0xfe);
        // With seq == 0 the iv must be returned unchanged: `&=` would zero the low
        // 8 bytes (0xff & 0 == 0), so this pins `^=` against `&=`.
        cipher.seq = 0;
        assert_eq!(cipher.nonce(), [0xff; TLS13_IV_LEN]);
    }

    #[test]
    fn record_cipher_round_trips_through_encrypt_decrypt() {
        let mut enc = RecordCipher::new(TlsCipherSuite::Aes128GcmSha256, &[5_u8; 32]).unwrap();
        let mut dec = RecordCipher::new(TlsCipherSuite::Aes128GcmSha256, &[5_u8; 32]).unwrap();

        let r1 = enc
            .encrypt_record(TLS_RECORD_HANDSHAKE, b"hello world")
            .unwrap();
        // An empty inner payload yields payload_len == AEAD_TAG_LEN + 1: this exact
        // minimum must still decrypt, killing the `<`->`<=` mutant of the
        // `payload_len < AEAD_TAG_LEN + 1` length guard.
        let r2 = enc.encrypt_record(TLS_RECORD_HANDSHAKE, b"").unwrap();

        let p1 = dec.decrypt_record(&r1).unwrap();
        assert_eq!(p1.content_type, TLS_RECORD_HANDSHAKE);
        assert_eq!(p1.plaintext, b"hello world");
        let p2 = dec.decrypt_record(&r2).unwrap();
        assert_eq!(p2.content_type, TLS_RECORD_HANDSHAKE);
        assert!(p2.plaintext.is_empty());
    }

    #[test]
    fn record_cipher_decrypt_rejects_truncated_record() {
        let mut enc = RecordCipher::new(TlsCipherSuite::Aes128GcmSha256, &[5_u8; 32]).unwrap();
        let mut dec = RecordCipher::new(TlsCipherSuite::Aes128GcmSha256, &[5_u8; 32]).unwrap();
        let mut record = enc.encrypt_record(TLS_RECORD_HANDSHAKE, b"hello").unwrap();
        record.pop(); // record.len() now < header.total_len
        assert!(matches!(
            dec.decrypt_record(&record),
            Err(Safari26TlsError::Aead)
        ));
    }

    #[test]
    fn record_cipher_decrypt_rejects_undersized_payload() {
        let mut dec = RecordCipher::new(TlsCipherSuite::Aes128GcmSha256, &[5_u8; 32]).unwrap();
        // application-data record whose payload (4 bytes) is shorter than
        // AEAD_TAG_LEN + 1: must be rejected before any AEAD work.
        let mut record = vec![TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x04];
        record.extend_from_slice(&[0xaa; 4]);
        assert!(matches!(
            dec.decrypt_record(&record),
            Err(Safari26TlsError::Aead)
        ));
    }

    // ---- reject_out_of_order_certificate ----

    #[test]
    fn reject_out_of_order_certificate_accepts_first_certificate() {
        // Empty flight, no CertificateVerify yet: must be accepted. Kills the
        // `delete !` mutant (which would reject the first, in-order Certificate).
        reject_out_of_order_certificate(&ServerFlight::default()).unwrap();
    }

    #[test]
    fn reject_out_of_order_certificate_rejects_duplicate_certificate() {
        let flight = ServerFlight {
            certificates: vec![vec![0xaa]],
            ..ServerFlight::default()
        };
        assert!(reject_out_of_order_certificate(&flight).is_err());
    }

    #[test]
    fn reject_out_of_order_certificate_rejects_after_certificate_verify() {
        let flight = ServerFlight {
            certificate_verify_seen: true,
            ..ServerFlight::default()
        };
        // Together with the duplicate case, this pins the `||` (a `&&` mutant would
        // accept each single-condition case) and the unconditional `Ok(())` mutant.
        assert!(reject_out_of_order_certificate(&flight).is_err());
    }

    // ---- process_server_handshake_messages ----

    #[test]
    fn process_server_handshake_messages_waits_for_a_full_header() {
        // Fewer than 4 bytes: must return Ok and leave the buffer untouched. Kills
        // the `<`->`==`/`>` mutants of the `buf.len() < 4` guard (which would index
        // past the end and panic).
        let mut buf = vec![0x08, 0x00];
        let mut flight = ServerFlight::default();
        let mut transcript = HandshakeTranscript::new();
        let mut keys = app_keys();
        process_server_handshake_messages(&mut buf, &mut flight, &mut transcript, &mut keys)
            .unwrap();
        assert_eq!(buf, vec![0x08, 0x00]);
    }

    #[test]
    fn process_server_handshake_messages_processes_a_complete_zero_body_message() {
        // A complete 4-byte message (declared body length 0) of an unknown type
        // must be *processed* (and rejected as unsupported), not treated as a
        // too-short header. Kills the `<`->`<=`/`==` mutants of `buf.len() < 4`.
        let mut buf = vec![0xff, 0x00, 0x00, 0x00];
        let mut flight = ServerFlight::default();
        let mut transcript = HandshakeTranscript::new();
        let mut keys = app_keys();
        let err =
            process_server_handshake_messages(&mut buf, &mut flight, &mut transcript, &mut keys)
                .unwrap_err();
        assert!(matches!(err, Safari26TlsError::Unsupported(_)));
        assert!(buf.is_empty()); // the complete 4-byte frame was consumed before rejection
    }

    #[test]
    fn process_server_handshake_messages_rejects_oversized_length() {
        // Declared length 0x080100 (524544) is just above MAX_ENCRYPTED_HANDSHAKE_
        // MESSAGE (524288). The non-zero high and middle length bytes pin the
        // `<< 16` / `<< 8` shifts and the `|` merges, and the value being strictly
        // greater than the cap pins `>` against `==`/`<`.
        let mut buf = vec![HANDSHAKE_ENCRYPTED_EXTENSIONS, 0x08, 0x01, 0x00];
        let mut flight = ServerFlight::default();
        let mut transcript = HandshakeTranscript::new();
        let mut keys = app_keys();
        let err =
            process_server_handshake_messages(&mut buf, &mut flight, &mut transcript, &mut keys)
                .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Handshake(ref m) if m.contains("exceeds maximum")
        ));
    }

    #[test]
    fn process_server_handshake_messages_allows_length_exactly_at_cap() {
        // A declared length equal to the cap is allowed (the body may still
        // arrive): with only the header buffered the call returns Ok and retains
        // the bytes. Kills the `>`->`>=` mutant of the oversize check.
        let max = MAX_ENCRYPTED_HANDSHAKE_MESSAGE;
        let mut buf = vec![
            HANDSHAKE_ENCRYPTED_EXTENSIONS,
            ((max >> 16) & 0xff) as u8,
            ((max >> 8) & 0xff) as u8,
            (max & 0xff) as u8,
        ];
        let mut flight = ServerFlight::default();
        let mut transcript = HandshakeTranscript::new();
        let mut keys = app_keys();
        process_server_handshake_messages(&mut buf, &mut flight, &mut transcript, &mut keys)
            .unwrap();
        assert_eq!(buf.len(), 4); // header retained, nothing drained
    }

    // ---- shard 6/8: EncryptedExtensions / Certificate / verify path ----

    fn u8_len_prefixed(data: &[u8]) -> Vec<u8> {
        assert!(
            u8::try_from(data.len()).is_ok(),
            "u8 length prefix overflow"
        );
        let mut out = vec![data.len() as u8];
        out.extend_from_slice(data);
        out
    }

    fn u16_len_prefixed(data: &[u8]) -> Vec<u8> {
        assert!(
            u16::try_from(data.len()).is_ok(),
            "u16 length prefix overflow"
        );
        let mut out = (data.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(data);
        out
    }

    fn u24_len_prefixed(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_u24(&mut out, data.len()).unwrap();
        out.extend_from_slice(data);
        out
    }

    /// `ProtocolNameList`: a u16-length-prefixed list of u8-length-prefixed names.
    fn alpn_selection(proto: &[u8]) -> Vec<u8> {
        u16_len_prefixed(&u8_len_prefixed(proto))
    }

    #[test]
    fn parse_selected_alpn_returns_the_negotiated_protocol() {
        // A concrete protocol name must be returned verbatim, which kills the
        // `-> Ok(Vec::leak(empty/[0]/[1]))` body mutants.
        let data = alpn_selection(b"h2");
        assert_eq!(parse_selected_alpn(&data).unwrap(), b"h2");
    }

    #[test]
    fn parse_encrypted_extensions_records_the_negotiated_alpn() {
        // One ALPN extension carrying "h2". The original parses it and stores the
        // protocol; the `-> Ok(())` body mutant, the `ext_type == EXT_ALPN`->`!=`
        // mutant, and every `e.remaining() > 0` loop-guard mutant either skip the
        // store (alpn stays None) or run the cursor off the end (Err) — both fail
        // the assertion below.
        let mut ext = EXT_ALPN.to_be_bytes().to_vec();
        ext.extend_from_slice(&u16_len_prefixed(&alpn_selection(b"h2")));
        let body = u16_len_prefixed(&ext);

        let mut keys = app_keys();
        parse_encrypted_extensions(&body, &mut keys).unwrap();
        assert_eq!(keys.negotiated_alpn.as_deref(), Some(b"h2".as_slice()));
    }

    fn certificate_entry(cert: &[u8]) -> Vec<u8> {
        let mut entry = u24_len_prefixed(cert);
        entry.extend_from_slice(&u16_len_prefixed(&[])); // empty cert extensions
        entry
    }

    fn certificate_body(certs: &[&[u8]]) -> Vec<u8> {
        let mut list = Vec::new();
        for cert in certs {
            list.extend_from_slice(&certificate_entry(cert));
        }
        let mut body = u8_len_prefixed(&[]); // empty certificate_request_context
        body.extend_from_slice(&u24_len_prefixed(&list));
        body
    }

    #[test]
    fn parse_certificate_body_returns_each_certificate_in_order() {
        // Two distinct certs pin the `-> Ok(vec![...])` body mutants (none of the
        // constant replacements equal this list) and force the
        // `l.remaining() > 0` loop to iterate exactly twice, killing the
        // ==/</>= guard mutants (which would read zero certs or run off the end).
        let body = certificate_body(&[&[0xAA, 0xBB], &[0xCC]]);
        let certs = parse_certificate_body(&body).unwrap();
        assert_eq!(certs, vec![vec![0xAA, 0xBB], vec![0xCC]]);
    }

    #[test]
    fn parse_compressed_certificate_body_accepts_a_chain_exactly_at_the_cap() {
        // Build a valid certificate body whose total length is EXACTLY
        // MAX_DECOMPRESSED_CERT_CHAIN and declare that same length. The original's
        // bounds are strict `>`, so a chain sitting on the boundary is accepted;
        // the `>`->`>=` mutants at the declared-length (1499) and inflated-length
        // (1513) guards would wrongly reject it, and the `!=`->`==` length-match
        // mutant (1518) would reject the matching lengths.
        let max = MAX_DECOMPRESSED_CERT_CHAIN;
        let cert = vec![0_u8; max - 9];
        let plaintext = certificate_body(&[&cert]);
        assert_eq!(plaintext.len(), max); // exactly on the boundary

        let body = build_compressed_cert_body(max, &plaintext);
        let certs = parse_compressed_certificate_body(&body).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].len(), max - 9);
    }

    fn finished_message(verify_data: &[u8]) -> Vec<u8> {
        let mut msg = vec![HANDSHAKE_FINISHED];
        push_u24(&mut msg, verify_data.len()).unwrap();
        msg.extend_from_slice(verify_data);
        msg
    }

    fn authenticated_flight() -> ServerFlight {
        ServerFlight {
            encrypted_extensions_seen: true,
            certificates: vec![vec![1]],
            certificate_verify_seen: true,
            finished: false,
        }
    }

    #[test]
    fn process_handshake_rejects_finished_before_encrypted_extensions() {
        // Only `encrypted_extensions_seen` is missing. The original's
        // `!encrypted_extensions_seen` term makes the guard fire; deleting that
        // `!` (mutant 1421) lets the Finished through to the verify_data check,
        // which then reports a *different* error — so the message assertion fails.
        let mut buf = finished_message(&[0_u8; 32]);
        let mut flight = ServerFlight {
            encrypted_extensions_seen: false,
            ..authenticated_flight()
        };
        let mut transcript = HandshakeTranscript::new();
        let mut keys = app_keys();
        let err =
            process_server_handshake_messages(&mut buf, &mut flight, &mut transcript, &mut keys)
                .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Handshake(ref m) if m.contains("before the authenticated flight")
        ));
    }

    #[test]
    fn process_handshake_rejects_finished_before_certificate_verify() {
        // Symmetric to the test above, isolating the `!certificate_verify_seen`
        // term so deleting its `!` (mutant 1423) is observable.
        let mut buf = finished_message(&[0_u8; 32]);
        let mut flight = ServerFlight {
            certificate_verify_seen: false,
            ..authenticated_flight()
        };
        let mut transcript = HandshakeTranscript::new();
        let mut keys = app_keys();
        let err =
            process_server_handshake_messages(&mut buf, &mut flight, &mut transcript, &mut keys)
                .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Handshake(ref m) if m.contains("before the authenticated flight")
        ));
    }

    #[test]
    fn process_handshake_accepts_finished_with_correct_verify_data() {
        // A fully authenticated flight plus the *correct* server verify_data must
        // be accepted. The `body != expected`->`==` mutant (1430) would reject
        // matching data, so `.unwrap()` would panic.
        let mut flight = authenticated_flight();
        let mut transcript = HandshakeTranscript::new();
        transcript.push(&[HANDSHAKE_ENCRYPTED_EXTENSIONS, 0, 0, 0]);
        let mut keys = app_keys();
        let expected = keys.server_finished_verify_data(&transcript).unwrap();
        let mut buf = finished_message(&expected);

        process_server_handshake_messages(&mut buf, &mut flight, &mut transcript, &mut keys)
            .unwrap();
        assert!(flight.finished);
        assert!(buf.is_empty());
    }

    #[test]
    fn process_handshake_rejects_finished_with_wrong_verify_data() {
        // The other direction of the `!=` comparison: bogus verify_data must be
        // rejected. The `==` mutant (1430) would accept it and mark the flight
        // finished.
        let mut flight = authenticated_flight();
        let mut transcript = HandshakeTranscript::new();
        let mut keys = app_keys();
        let mut buf = finished_message(&[0xAB; 32]);

        let err =
            process_server_handshake_messages(&mut buf, &mut flight, &mut transcript, &mut keys)
                .unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Handshake(ref m) if m.contains("verify_data mismatch")
        ));
        assert!(!flight.finished);
    }

    #[test]
    fn verify_certificate_verify_requires_a_leaf_certificate() {
        // With no certificate in the flight the function must error out before any
        // signature work. The whole-body `-> Ok(())` mutant (1532) would silently
        // accept an unauthenticated flight.
        let flight = ServerFlight::default();
        let transcript = HandshakeTranscript::new();
        let keys = app_keys();
        let err = verify_certificate_verify(&[], &flight, &transcript, &keys).unwrap_err();
        assert!(matches!(
            err,
            Safari26TlsError::Handshake(ref m) if m.contains("missing server certificate")
        ));
    }

    #[test]
    fn certificate_verify_algorithm_maps_every_supported_scheme() {
        // Each registered signature scheme must resolve to a verification
        // algorithm; an unknown scheme must not. Deleting any match arm
        // (mutants 1557–1564) drops that scheme to the `_ => Err` fallback.
        for scheme in [
            SIG_ECDSA_SECP256R1_SHA256,
            SIG_RSA_PSS_RSAE_SHA256,
            SIG_RSA_PKCS1_SHA256,
            SIG_ECDSA_SECP384R1_SHA384,
            SIG_RSA_PSS_RSAE_SHA384,
            SIG_RSA_PKCS1_SHA384,
            SIG_RSA_PSS_RSAE_SHA512,
            SIG_RSA_PKCS1_SHA512,
        ] {
            assert!(
                certificate_verify_algorithm(scheme).is_ok(),
                "scheme {scheme:#06x} must be supported"
            );
        }
        assert!(certificate_verify_algorithm(0x0000).is_err());
    }
}
