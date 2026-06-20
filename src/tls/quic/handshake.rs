//! The hand-written TLS 1.3 client handshake state machine for QUIC.
//!
//! Transport-agnostic: it consumes/produces raw CRYPTO-stream handshake bytes and
//! emits [`KeyChange`]s with ParallaX-owned [`Keys`]. The quinn adapter drives it;
//! a future hand-written QUIC transport will drive the same API unchanged.
//!
//! Flow (cold-start, no client auth, no 0-RTT):
//! 1. [`ClientHandshake::new`] generates the X25519 + ML-KEM-768 hybrid key share
//!    and the Safari-26 H3 ClientHello.
//! 2. [`write_handshake`] emits the ClientHello (Initial CRYPTO).
//! 3. [`read_handshake`] consumes the ServerHello (Initial), derives the handshake
//!    secrets; the next [`write_handshake`] returns [`KeyChange::Handshake`].
//! 4. [`read_handshake`] consumes EE / Certificate / CertificateVerify / Finished
//!    (Handshake CRYPTO), verifies the server Finished MAC, derives the 1-RTT and
//!    exporter secrets; the next [`write_handshake`] emits the client Finished and
//!    returns [`KeyChange::OneRtt`].
//!
//! [`write_handshake`]: ClientHandshake::write_handshake
//! [`read_handshake`]: ClientHandshake::read_handshake

use std::io::Read;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_768};
use flate2::read::ZlibDecoder;
use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::session::{x25519_shared_secret, X25519KeyPair};
use crate::tls::safari_shape::{GreaseSet, GROUP_X25519, GROUP_X25519_MLKEM768, X25519_KEY_LEN};

use super::client_hello::{build_client_hello, ClientHelloParams};
use super::keys::{KeyPair, Keys, PacketKey};
use super::schedule::{initial_keys, KeySchedule};
use super::suite::CipherSuite;
use super::{
    ClientConfig, QuicTlsError, Side, ALERT_BAD_CERTIFICATE, ALERT_DECODE_ERROR,
    ALERT_DECRYPT_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER, ALERT_MISSING_EXTENSION,
    ALERT_UNEXPECTED_MESSAGE, QUIC_VERSION_V1,
};

const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HANDSHAKE_CERTIFICATE: u8 = 0x0b;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0f;
const HANDSHAKE_FINISHED: u8 = 0x14;
const HANDSHAKE_COMPRESSED_CERTIFICATE: u8 = 0x19;
const HANDSHAKE_NEW_SESSION_TICKET: u8 = 0x04;

const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;

const TLS13_LEGACY_VERSION: u16 = 0x0303;
const TLS13_SELECTED_VERSION: u16 = 0x0304;
const CERT_COMPRESSION_ZLIB: u16 = 0x0001;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

/// Cap on one (unauthenticated, at this stage) handshake message. Must exceed the
/// decompressed-cert cap plus framing while bounding the memory a malicious cover
/// origin can force from a single length field. Mirrors the TCP path.
const MAX_HANDSHAKE_MESSAGE: usize = 512 * 1024;
/// Cap on a decompressed certificate chain (RFC 8879). Real chains are a few KiB.
const MAX_DECOMPRESSED_CERT_CHAIN: usize = 256 * 1024;

/// HelloRetryRequest sentinel random (RFC 8446 §4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// A change of QUIC packet-protection keys, emitted by [`ClientHandshake::write_handshake`].
pub enum KeyChange {
    /// Install Handshake-space keys.
    Handshake { keys: Keys },
    /// Install 1-RTT (Data-space) keys; the handshake is now complete.
    OneRtt { keys: Keys },
}

/// What the inbound state machine expects next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
    Complete,
}

/// The TLS 1.3 client handshake.
pub struct ClientHandshake {
    config: Arc<ClientConfig>,
    server_name: String,

    // Client key-exchange material.
    x25519: X25519KeyPair,
    mlkem_secret: Zeroizing<Vec<u8>>,

    // Outbound sequencing.
    client_hello: Vec<u8>,
    client_hello_sent: bool,
    pending_handshake_keys: Option<Keys>,
    pending_client_finished: Option<Vec<u8>>,
    pending_1rtt_keys: Option<Keys>,
    handshake_complete: bool,

    // Inbound.
    inbound: Vec<u8>,
    read_state: ReadState,
    notified_handshake_data: bool,

    // Negotiated state.
    suite: Option<CipherSuite>,
    schedule: Option<KeySchedule>,
    transcript: Vec<u8>,
    server_certs: Vec<Vec<u8>>,
    alpn: Option<Vec<u8>>,
    peer_transport_params: Option<Vec<u8>>,
}

impl ClientHandshake {
    /// Build a fresh client handshake for `server_name`, carrying `transport_params`
    /// (the opaque QUIC 0x39 blob). Generates the ephemeral hybrid key share and
    /// the Safari-26 H3 ClientHello.
    pub fn new(
        config: Arc<ClientConfig>,
        version: u32,
        server_name: &str,
        transport_params: Vec<u8>,
    ) -> Result<Self, QuicTlsError> {
        if version != QUIC_VERSION_V1 {
            return Err(QuicTlsError::UnsupportedVersion);
        }
        if server_name.is_empty() {
            return Err(QuicTlsError::InvalidServerName("empty SNI".into()));
        }

        let x25519 = X25519KeyPair::generate();
        let mlkem_dk = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 keygen".into()))?;
        let mlkem_public = mlkem_dk
            .encapsulation_key()
            .and_then(|ek| ek.key_bytes())
            .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 public key".into()))?
            .as_ref()
            .to_vec();
        let mlkem_secret = Zeroizing::new(
            mlkem_dk
                .key_bytes()
                .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 secret key".into()))?
                .as_ref()
                .to_vec(),
        );

        let mut grease_seed = [0_u8; 5];
        OsRng.fill_bytes(&mut grease_seed);
        let grease = GreaseSet::from_seed(grease_seed);
        let mut random = [0_u8; 32];
        OsRng.fill_bytes(&mut random);

        let client_hello = build_client_hello(&ClientHelloParams {
            server_name,
            alpn_protocols: &config.alpn_protocols,
            x25519_public: &x25519.public,
            mlkem768_public: &mlkem_public,
            transport_params: &transport_params,
            grease,
            random: &random,
        })?;

        let transcript = client_hello.clone();

        Ok(Self {
            config,
            server_name: server_name.to_owned(),
            x25519,
            mlkem_secret,
            client_hello,
            client_hello_sent: false,
            pending_handshake_keys: None,
            pending_client_finished: None,
            pending_1rtt_keys: None,
            handshake_complete: false,
            inbound: Vec::new(),
            read_state: ReadState::ServerHello,
            notified_handshake_data: false,
            suite: None,
            schedule: None,
            transcript,
            server_certs: Vec::new(),
            alpn: None,
            peer_transport_params: None,
        })
    }

    /// Derive the Initial-space keys for `dst_cid` (RFC 9001 §5.2).
    pub fn initial_keys(&self, dst_cid: &[u8], side: Side) -> Keys {
        initial_keys(dst_cid, side)
    }

    /// Whether the handshake is still in progress (false once the client Finished
    /// + 1-RTT keys have been emitted).
    pub fn is_handshaking(&self) -> bool {
        !self.handshake_complete
    }

    /// The negotiated ALPN protocol, once EncryptedExtensions has been processed.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The peer's raw QUIC transport-parameters blob, once EE has been processed.
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.peer_transport_params.as_deref()
    }

    /// The server certificate chain (DER), once Certificate has been processed.
    pub fn peer_certificates(&self) -> Option<&[Vec<u8>]> {
        if self.server_certs.is_empty() {
            None
        } else {
            Some(&self.server_certs)
        }
    }

    /// Append outgoing CRYPTO bytes to `out`; return a [`KeyChange`] when crossing
    /// into the next packet-number space (Handshake, then 1-RTT), else `None`.
    pub fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        if !self.client_hello_sent {
            out.extend_from_slice(&self.client_hello);
            self.client_hello_sent = true;
            // Initial keys are derived via `initial_keys`, not returned here.
            return None;
        }
        if let Some(keys) = self.pending_handshake_keys.take() {
            return Some(KeyChange::Handshake { keys });
        }
        if let Some(finished) = self.pending_client_finished.take() {
            out.extend_from_slice(&finished);
            let keys = self
                .pending_1rtt_keys
                .take()
                .expect("1-RTT keys are derived together with the client Finished");
            self.handshake_complete = true;
            return Some(KeyChange::OneRtt { keys });
        }
        None
    }

    /// Return the next 1-RTT packet-key generation for a key update (RFC 9001 §6).
    pub fn next_1rtt_keys(&mut self) -> Option<KeyPair<PacketKey>> {
        self.schedule.as_mut()?.next_1rtt_packet_keys().ok()
    }

    /// RFC 5705 exporter; available once the handshake completes.
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), QuicTlsError> {
        self.schedule
            .as_ref()
            .ok_or_else(|| QuicTlsError::Crypto("exporter before handshake".into()))?
            .export_keying_material(out, label, context)
    }

    /// Feed reassembled CRYPTO-stream bytes. Returns `Ok(true)` the first time
    /// handshake data (ALPN / completion) becomes available, else `Ok(false)`.
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<bool, QuicTlsError> {
        self.inbound.extend_from_slice(data);
        let mut newly_ready = false;
        loop {
            if self.inbound.len() < 4 {
                break;
            }
            let len = ((self.inbound[1] as usize) << 16)
                | ((self.inbound[2] as usize) << 8)
                | (self.inbound[3] as usize);
            if len > MAX_HANDSHAKE_MESSAGE {
                return Err(QuicTlsError::alert(
                    ALERT_DECODE_ERROR,
                    "handshake message exceeds maximum",
                ));
            }
            if self.inbound.len() < 4 + len {
                break;
            }
            let message = self.inbound[..4 + len].to_vec();
            self.inbound.drain(..4 + len);
            self.process_message(&message)?;
            // Handshake data is "ready" once EncryptedExtensions has been processed
            // (the negotiated ALPN + peer transport parameters are then available),
            // or once the handshake completes. Keyed on `peer_transport_params`
            // rather than ALPN so the signal still fires if no ALPN was offered.
            if !self.notified_handshake_data
                && (self.peer_transport_params.is_some() || !self.is_handshaking())
            {
                self.notified_handshake_data = true;
                newly_ready = true;
            }
        }
        Ok(newly_ready)
    }

    fn process_message(&mut self, message: &[u8]) -> Result<(), QuicTlsError> {
        let msg_type = message[0];
        let body = &message[4..];
        match (self.read_state, msg_type) {
            (ReadState::ServerHello, HANDSHAKE_SERVER_HELLO) => {
                // Append BEFORE deriving: the handshake secrets hash over
                // ClientHello..ServerHello (ServerHello included).
                self.transcript.extend_from_slice(message);
                self.handle_server_hello(body)?;
                self.read_state = ReadState::EncryptedExtensions;
                Ok(())
            }
            (ReadState::EncryptedExtensions, HANDSHAKE_ENCRYPTED_EXTENSIONS) => {
                self.handle_encrypted_extensions(body)?;
                self.transcript.extend_from_slice(message);
                self.read_state = ReadState::Certificate;
                Ok(())
            }
            (ReadState::Certificate, HANDSHAKE_CERTIFICATE) => {
                self.server_certs = parse_certificate_body(body)?;
                self.verify_cert_chain()?;
                self.transcript.extend_from_slice(message);
                self.read_state = ReadState::CertificateVerify;
                Ok(())
            }
            (ReadState::Certificate, HANDSHAKE_COMPRESSED_CERTIFICATE) => {
                self.server_certs = parse_compressed_certificate_body(body)?;
                self.verify_cert_chain()?;
                self.transcript.extend_from_slice(message);
                self.read_state = ReadState::CertificateVerify;
                Ok(())
            }
            (ReadState::CertificateVerify, HANDSHAKE_CERTIFICATE_VERIFY) => {
                // The CertificateVerify signature is over ClientHello..Certificate
                // (CertificateVerify EXCLUDED), so verify BEFORE appending.
                self.handle_certificate_verify(body)?;
                self.transcript.extend_from_slice(message);
                self.read_state = ReadState::Finished;
                Ok(())
            }
            (ReadState::Finished, HANDSHAKE_FINISHED) => {
                // The server Finished MAC is over ClientHello..CertificateVerify
                // (server Finished EXCLUDED); the handler verifies, then appends it
                // and derives the 1-RTT/exporter secrets over the included hash.
                self.handle_server_finished(body, message)?;
                self.read_state = ReadState::Complete;
                Ok(())
            }
            // Post-handshake NewSessionTickets (1-RTT CRYPTO) are accepted and
            // ignored — ParallaX does not resume.
            (ReadState::Complete, HANDSHAKE_NEW_SESSION_TICKET) => Ok(()),
            (state, ty) => Err(QuicTlsError::alert(
                ALERT_UNEXPECTED_MESSAGE,
                format!("unexpected handshake message {ty:#04x} in state {state:?}"),
            )),
        }
    }

    fn handle_server_hello(&mut self, body: &[u8]) -> Result<(), QuicTlsError> {
        let mut c = Cursor::new(body);
        let legacy_version = c.u16()?;
        if legacy_version != TLS13_LEGACY_VERSION {
            return Err(QuicTlsError::alert(
                ALERT_ILLEGAL_PARAMETER,
                "ServerHello legacy_version is not 0x0303",
            ));
        }
        let random = c.bytes(32)?;
        if random == HRR_RANDOM {
            return Err(QuicTlsError::alert(
                ALERT_HANDSHAKE_FAILURE,
                "HelloRetryRequest is not supported",
            ));
        }
        let _session_id = c.vec_u8()?; // legacy_session_id_echo (empty on our QUIC CH)
        let suite = CipherSuite::from_u16(c.u16()?)?;
        if c.u8()? != 0 {
            return Err(QuicTlsError::alert(
                ALERT_ILLEGAL_PARAMETER,
                "ServerHello compression_method is not null",
            ));
        }

        let extensions = c.vec_u16()?;
        let mut e = Cursor::new(extensions);
        let mut tls13_selected = false;
        let mut key_share_group = None;
        let mut key_share = None;
        while e.remaining() > 0 {
            let ext_type = e.u16()?;
            let data = e.vec_u16()?;
            match ext_type {
                EXT_SUPPORTED_VERSIONS => {
                    if data.len() == 2
                        && u16::from_be_bytes([data[0], data[1]]) == TLS13_SELECTED_VERSION
                    {
                        tls13_selected = true;
                    }
                }
                EXT_KEY_SHARE => {
                    let mut ks = Cursor::new(data);
                    key_share_group = Some(ks.u16()?);
                    key_share = Some(ks.vec_u16()?.to_vec());
                }
                _ => {}
            }
        }
        if !tls13_selected {
            return Err(QuicTlsError::alert(
                ALERT_ILLEGAL_PARAMETER,
                "ServerHello did not select TLS 1.3",
            ));
        }
        let group = key_share_group.ok_or_else(|| {
            QuicTlsError::alert(ALERT_MISSING_EXTENSION, "ServerHello missing key_share")
        })?;
        let share = key_share.ok_or_else(|| {
            QuicTlsError::alert(
                ALERT_MISSING_EXTENSION,
                "ServerHello missing key_share data",
            )
        })?;

        self.suite = Some(suite);
        let shared_secret = self.compute_shared_secret(group, &share)?;
        // The transcript already includes this ServerHello (appended by
        // process_message before this handler), so the snapshot is over
        // ClientHello..ServerHello as the handshake-secret derivation requires.
        let transcript_hash = suite.digest(&self.transcript);

        let (schedule, keys) =
            KeySchedule::after_server_hello(suite, &shared_secret, &transcript_hash)?;
        self.schedule = Some(schedule);
        self.pending_handshake_keys = Some(keys);
        Ok(())
    }

    fn compute_shared_secret(
        &self,
        group: u16,
        share: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, QuicTlsError> {
        match group {
            GROUP_X25519 => {
                if share.len() != X25519_KEY_LEN {
                    return Err(QuicTlsError::alert(
                        ALERT_ILLEGAL_PARAMETER,
                        "invalid X25519 server key_share length",
                    ));
                }
                let mut server_public = [0_u8; X25519_KEY_LEN];
                server_public.copy_from_slice(share);
                let shared =
                    Zeroizing::new(x25519_shared_secret(&self.x25519.private, &server_public));
                reject_degenerate_x25519(&shared)?;
                Ok(Zeroizing::new(shared.to_vec()))
            }
            GROUP_X25519_MLKEM768 => {
                if share.len() != MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN {
                    return Err(QuicTlsError::alert(
                        ALERT_ILLEGAL_PARAMETER,
                        "invalid X25519MLKEM768 server key_share length",
                    ));
                }
                let (mlkem_ciphertext, server_x25519) = share.split_at(MLKEM768_CIPHERTEXT_LEN);
                let dk = DecapsulationKey::new(&ML_KEM_768, &self.mlkem_secret)
                    .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 decap key".into()))?;
                let mlkem_shared = dk
                    .decapsulate(Ciphertext::from(mlkem_ciphertext))
                    .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 decapsulation".into()))?;
                let mut server_public = [0_u8; X25519_KEY_LEN];
                server_public.copy_from_slice(server_x25519);
                let x25519_shared =
                    Zeroizing::new(x25519_shared_secret(&self.x25519.private, &server_public));
                reject_degenerate_x25519(&x25519_shared)?;
                // IETF X25519MLKEM768 combiner: ML-KEM shared secret first, then
                // the X25519 shared secret.
                let mut combined = Zeroizing::new(Vec::with_capacity(64));
                combined.extend_from_slice(mlkem_shared.as_ref());
                combined.extend_from_slice(x25519_shared.as_ref());
                Ok(combined)
            }
            _ => Err(QuicTlsError::alert(
                ALERT_ILLEGAL_PARAMETER,
                "unsupported server key_share group",
            )),
        }
    }

    fn handle_encrypted_extensions(&mut self, body: &[u8]) -> Result<(), QuicTlsError> {
        let mut c = Cursor::new(body);
        let extensions = c.vec_u16()?;
        let mut e = Cursor::new(extensions);
        while e.remaining() > 0 {
            let ext_type = e.u16()?;
            let data = e.vec_u16()?;
            match ext_type {
                EXT_ALPN => {
                    self.alpn = Some(parse_selected_alpn(data)?.to_vec());
                }
                EXT_QUIC_TRANSPORT_PARAMETERS => {
                    self.peer_transport_params = Some(data.to_vec());
                }
                _ => {}
            }
        }
        // ALPN is mandatory for QUIC: if we offered ALPN the server must select one.
        if !self.config.alpn_protocols.is_empty() && self.alpn.is_none() {
            return Err(QuicTlsError::alert(
                super::ALERT_NO_APPLICATION_PROTOCOL,
                "server selected no ALPN protocol",
            ));
        }
        if self.peer_transport_params.is_none() {
            return Err(QuicTlsError::alert(
                ALERT_MISSING_EXTENSION,
                "EncryptedExtensions missing quic_transport_parameters",
            ));
        }
        Ok(())
    }

    fn verify_cert_chain(&self) -> Result<(), QuicTlsError> {
        let leaf = self
            .server_certs
            .first()
            .ok_or_else(|| QuicTlsError::alert(ALERT_BAD_CERTIFICATE, "empty certificate chain"))?;
        let intermediates: Vec<&[u8]> = self
            .server_certs
            .iter()
            .skip(1)
            .map(|c| c.as_slice())
            .collect();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.config
            .verifier
            .verify_cert(leaf, &intermediates, &self.server_name, now)
            .map_err(|e| QuicTlsError::Certificate(e.to_string()))
    }

    fn handle_certificate_verify(&mut self, body: &[u8]) -> Result<(), QuicTlsError> {
        let suite = self.suite.expect("suite set at ServerHello");
        let leaf = self
            .server_certs
            .first()
            .ok_or_else(|| {
                QuicTlsError::alert(
                    ALERT_BAD_CERTIFICATE,
                    "CertificateVerify without certificate",
                )
            })?
            .clone();
        let mut c = Cursor::new(body);
        let scheme = c.u16()?;
        let signature = c.vec_u16()?;

        // Signed content: 64 spaces || "TLS 1.3, server CertificateVerify" || 0x00
        // || Transcript-Hash(ClientHello..Certificate). The transcript hash is
        // taken BEFORE the CertificateVerify message is added (RFC 8446 §4.4.3).
        let transcript_hash = suite.digest(&self.transcript);
        let mut signed = Vec::with_capacity(64 + 34 + transcript_hash.len());
        signed.extend_from_slice(&[0x20; 64]);
        signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed.push(0);
        signed.extend_from_slice(&transcript_hash);

        self.config
            .verifier
            .verify_signature(&signed, &leaf, scheme, signature)
            .map_err(|e| QuicTlsError::Certificate(e.to_string()))
    }

    fn handle_server_finished(&mut self, body: &[u8], message: &[u8]) -> Result<(), QuicTlsError> {
        let suite = self.suite.expect("suite set at ServerHello");
        let schedule = self.schedule.as_mut().expect("schedule set at ServerHello");

        // Server Finished MAC is over the transcript through CertificateVerify
        // (BEFORE the server Finished is added).
        let transcript_hash = suite.digest(&self.transcript);
        let expected = schedule.server_finished_verify_data(&transcript_hash)?;
        if !bool::from(body.ct_eq(&expected)) {
            return Err(QuicTlsError::alert(
                ALERT_DECRYPT_ERROR,
                "server Finished verify_data mismatch",
            ));
        }

        // Add the server Finished to the transcript, then derive 1-RTT + exporter
        // and the client Finished (both over ClientHello..server Finished).
        self.transcript.extend_from_slice(message);
        let th_sf = suite.digest(&self.transcript);
        let onertt = schedule.derive_application(&th_sf)?;
        let client_verify_data = schedule.client_finished_verify_data(&th_sf)?;

        let mut finished = Vec::with_capacity(4 + client_verify_data.len());
        finished.push(HANDSHAKE_FINISHED);
        let len = client_verify_data.len();
        finished.push((len >> 16) as u8);
        finished.push((len >> 8) as u8);
        finished.push(len as u8);
        finished.extend_from_slice(&client_verify_data);

        self.pending_client_finished = Some(finished);
        self.pending_1rtt_keys = Some(onertt);
        Ok(())
    }
}

/// Reject an all-zero X25519 shared secret in constant time.
///
/// `x25519-dalek` does not reject small-order peer public keys (RFC 7748 leaves
/// the all-zero-output check to the caller). On the REALITY-style QUIC leg the
/// server key_share is unauthenticated until Finished, so a peer could force the
/// X25519 half to zero; rejecting restores X25519's contributory guarantee (and
/// matches `crypto::session` / `crypto::pq`, which guard the same way).
fn reject_degenerate_x25519(secret: &[u8; X25519_KEY_LEN]) -> Result<(), QuicTlsError> {
    if bool::from(secret.ct_eq(&[0_u8; X25519_KEY_LEN])) {
        return Err(QuicTlsError::alert(
            ALERT_ILLEGAL_PARAMETER,
            "degenerate (all-zero) X25519 shared secret",
        ));
    }
    Ok(())
}

/// Parse the selected ALPN protocol from an ALPN extension body.
fn parse_selected_alpn(data: &[u8]) -> Result<&[u8], QuicTlsError> {
    let mut c = Cursor::new(data);
    let list = c.vec_u16()?;
    let mut l = Cursor::new(list);
    l.vec_u8()
}

/// Parse a TLS 1.3 Certificate message body into the DER chain.
fn parse_certificate_body(body: &[u8]) -> Result<Vec<Vec<u8>>, QuicTlsError> {
    let mut c = Cursor::new(body);
    let _request_context = c.vec_u8()?;
    let list = c.vec_u24()?;
    let mut l = Cursor::new(list);
    let mut certs = Vec::new();
    while l.remaining() > 0 {
        let cert = l.vec_u24()?;
        certs.push(cert.to_vec());
        let _extensions = l.vec_u16()?;
    }
    if certs.is_empty() {
        return Err(QuicTlsError::alert(
            ALERT_BAD_CERTIFICATE,
            "empty certificate chain",
        ));
    }
    Ok(certs)
}

/// Parse a CompressedCertificate (RFC 8879) body: decompress then parse as a
/// Certificate. Bounds both the declared and actual inflation to defend against a
/// malicious (pre-authentication) cover origin's zlib bomb.
fn parse_compressed_certificate_body(body: &[u8]) -> Result<Vec<Vec<u8>>, QuicTlsError> {
    let mut c = Cursor::new(body);
    let algorithm = c.u16()?;
    if algorithm != CERT_COMPRESSION_ZLIB {
        return Err(QuicTlsError::alert(
            ALERT_BAD_CERTIFICATE,
            "unsupported certificate compression algorithm",
        ));
    }
    let uncompressed_len = c.u24()? as usize;
    if uncompressed_len > MAX_DECOMPRESSED_CERT_CHAIN {
        return Err(QuicTlsError::alert(
            ALERT_BAD_CERTIFICATE,
            "compressed_certificate uncompressed_length exceeds maximum",
        ));
    }
    let compressed = c.vec_u24()?;
    let decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::with_capacity(uncompressed_len.min(MAX_DECOMPRESSED_CERT_CHAIN));
    let mut limited = decoder.take((MAX_DECOMPRESSED_CERT_CHAIN as u64) + 1);
    limited
        .read_to_end(&mut decompressed)
        .map_err(|_| QuicTlsError::alert(ALERT_BAD_CERTIFICATE, "zlib decompression failed"))?;
    if decompressed.len() > MAX_DECOMPRESSED_CERT_CHAIN {
        return Err(QuicTlsError::alert(
            ALERT_BAD_CERTIFICATE,
            "compressed_certificate inflates beyond maximum",
        ));
    }
    if decompressed.len() != uncompressed_len {
        return Err(QuicTlsError::alert(
            ALERT_BAD_CERTIFICATE,
            "compressed_certificate length mismatch",
        ));
    }
    parse_certificate_body(&decompressed)
}

/// Minimal big-endian TLS reader with bounds checks; every short read is a fatal
/// decode_error alert.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], QuicTlsError> {
        if self.remaining() < len {
            return Err(QuicTlsError::alert(
                ALERT_DECODE_ERROR,
                "handshake data truncated",
            ));
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.data[start..start + len])
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], QuicTlsError> {
        self.take(len)
    }

    fn u8(&mut self) -> Result<u8, QuicTlsError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, QuicTlsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<u32, QuicTlsError> {
        let b = self.take(3)?;
        Ok((u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]))
    }

    fn vec_u8(&mut self) -> Result<&'a [u8], QuicTlsError> {
        let len = self.u8()? as usize;
        self.take(len)
    }

    fn vec_u16(&mut self) -> Result<&'a [u8], QuicTlsError> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    fn vec_u24(&mut self) -> Result<&'a [u8], QuicTlsError> {
        let len = self.u24()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::quic::AcceptAnyServerCert;

    fn handshake() -> ClientHandshake {
        let config = Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ));
        ClientHandshake::new(config, QUIC_VERSION_V1, "example.com", vec![0x0f, 0x00]).unwrap()
    }

    /// Wrap a body as a handshake message (`type || u24 len || body`).
    fn msg(ty: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![
            ty,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        m.extend_from_slice(body);
        m
    }

    /// A ServerHello body; `random` lets the HRR sentinel be injected, and the
    /// extensions are appended raw (empty here unless the caller adds them).
    fn server_hello_body(random: [u8; 32], extensions: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&TLS13_LEGACY_VERSION.to_be_bytes());
        b.extend_from_slice(&random);
        b.push(0); // empty legacy_session_id_echo
        b.extend_from_slice(&0x1301_u16.to_be_bytes()); // cipher suite
        b.push(0); // null compression
        b.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        b.extend_from_slice(extensions);
        b
    }

    #[test]
    fn unexpected_message_before_server_hello_is_rejected() {
        let mut hs = handshake();
        // EncryptedExtensions (0x08) while expecting ServerHello.
        let err = hs
            .read_handshake(&msg(HANDSHAKE_ENCRYPTED_EXTENSIONS, &[0, 0]))
            .unwrap_err();
        assert_eq!(err.alert_description(), Some(ALERT_UNEXPECTED_MESSAGE));
    }

    #[test]
    fn hello_retry_request_is_cleanly_rejected() {
        let mut hs = handshake();
        let err = hs
            .read_handshake(&msg(
                HANDSHAKE_SERVER_HELLO,
                &server_hello_body(HRR_RANDOM, &[]),
            ))
            .unwrap_err();
        assert_eq!(err.alert_description(), Some(ALERT_HANDSHAKE_FAILURE));
    }

    #[test]
    fn oversized_handshake_message_is_rejected_before_buffering() {
        let mut hs = handshake();
        let big = (MAX_HANDSHAKE_MESSAGE + 1) as u32;
        let header = [
            HANDSHAKE_SERVER_HELLO,
            (big >> 16) as u8,
            (big >> 8) as u8,
            big as u8,
        ];
        let err = hs.read_handshake(&header).unwrap_err();
        assert_eq!(err.alert_description(), Some(ALERT_DECODE_ERROR));
    }

    #[test]
    fn server_hello_without_tls13_supported_versions_is_rejected() {
        let mut hs = handshake();
        // No supported_versions=0x0304 extension → not TLS 1.3.
        let err = hs
            .read_handshake(&msg(
                HANDSHAKE_SERVER_HELLO,
                &server_hello_body([0x22; 32], &[]),
            ))
            .unwrap_err();
        assert_eq!(err.alert_description(), Some(ALERT_ILLEGAL_PARAMETER));
    }

    #[test]
    fn partial_message_buffers_across_reads() {
        let mut hs = handshake();
        let m = msg(HANDSHAKE_SERVER_HELLO, &server_hello_body([0x33; 32], &[]));
        let (first, second) = m.split_at(10);
        // The incomplete prefix yields neither readiness nor an error.
        assert!(!hs.read_handshake(first).unwrap());
        // Completing the message then surfaces the (missing-TLS1.3) rejection,
        // proving the two halves were reassembled into one message.
        let err = hs.read_handshake(second).unwrap_err();
        assert_eq!(err.alert_description(), Some(ALERT_ILLEGAL_PARAMETER));
    }
}
