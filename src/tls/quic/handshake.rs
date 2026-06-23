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

use super::client_hello::{build_client_hello, ClientHelloParams, ResumptionParams};
use super::keys::{DirectionalKeys, KeyPair, Keys, PacketKey};
use super::schedule::{
    binder_finished_key, client_early_traffic_secret, early_secret_from_psk, initial_keys,
    KeySchedule,
};
use super::suite::CipherSuite;
use super::ticket::ClientTicket;
use super::{
    ClientConfig, QuicTlsError, Side, ALERT_BAD_CERTIFICATE, ALERT_DECODE_ERROR,
    ALERT_DECRYPT_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER, ALERT_MISSING_EXTENSION,
    ALERT_UNEXPECTED_MESSAGE, ALERT_UNSUPPORTED_EXTENSION, QUIC_VERSION_V1,
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
const EXT_EARLY_DATA: u16 = 0x002a;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;

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
    /// Install 0-RTT (early-data) write keys. Emitted right after the resumption
    /// ClientHello so the transport can send 0-RTT application data before the
    /// handshake completes. Only `keys.local` is meaningful on the client (0-RTT is
    /// client→server only); the server installs `keys.remote` to open it.
    ZeroRtt { keys: Keys },
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

    // 0-RTT resumption state (all inert for a cold-start handshake).
    /// The resumption PSK offered in `pre_shared_key`; `Some` only when resuming.
    /// Fed into the key schedule iff the server accepts the PSK (`psk_accepted`).
    resumption_psk: Option<Zeroizing<Vec<u8>>>,
    /// 0-RTT write keys, queued to emit as [`KeyChange::ZeroRtt`] after the CH.
    pending_0rtt_keys: Option<Keys>,
    /// The server echoed `pre_shared_key` in ServerHello — the PSK was accepted, so
    /// the handshake is a resumption (no Certificate / CertificateVerify follow).
    psk_accepted: bool,
    /// The server echoed `early_data` in EncryptedExtensions — 0-RTT was accepted.
    early_data_accepted: bool,
}

impl ClientHandshake {
    /// Build a fresh (cold-start) client handshake for `server_name`, carrying
    /// `transport_params` (the opaque QUIC 0x39 blob). See [`Self::new_resumption`]
    /// for the 0-RTT variant.
    pub fn new(
        config: Arc<ClientConfig>,
        version: u32,
        server_name: &str,
        transport_params: Vec<u8>,
    ) -> Result<Self, QuicTlsError> {
        Self::new_inner(config, version, server_name, transport_params, None, 0)
    }

    /// Build a 0-RTT resumption client handshake: it offers `ticket` via
    /// `pre_shared_key` + `early_data` and derives the 0-RTT write keys (emitted as
    /// [`KeyChange::ZeroRtt`] after the ClientHello). `now_ms` is the current Unix
    /// time in milliseconds, for `obfuscated_ticket_age`.
    #[allow(dead_code)] // wired into the client runtime in S7
    pub(crate) fn new_resumption(
        config: Arc<ClientConfig>,
        version: u32,
        server_name: &str,
        transport_params: Vec<u8>,
        ticket: &ClientTicket,
        now_ms: u64,
    ) -> Result<Self, QuicTlsError> {
        Self::new_inner(
            config,
            version,
            server_name,
            transport_params,
            Some(ticket),
            now_ms,
        )
    }

    fn new_inner(
        config: Arc<ClientConfig>,
        version: u32,
        server_name: &str,
        transport_params: Vec<u8>,
        ticket: Option<&ClientTicket>,
        now_ms: u64,
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

        let mut resumption_psk = None;
        let mut pending_0rtt_keys = None;
        let client_hello = if let Some(t) = ticket {
            // 0-RTT: derive the early secret + binder finished key, build the
            // resumption ClientHello (early_data + trailing pre_shared_key with a
            // valid binder), then derive the 0-RTT write keys from
            // client_early_traffic_secret over that exact ClientHello.
            let suite = CipherSuite::from_u16(t.suite)?;
            let early = early_secret_from_psk(suite, &t.psk);
            let fk = binder_finished_key(suite, &early)?;
            let ch = build_client_hello(&ClientHelloParams {
                server_name,
                alpn_protocols: &config.alpn_protocols,
                x25519_public: &x25519.public,
                mlkem768_public: &mlkem_public,
                transport_params: &transport_params,
                grease,
                random: &random,
                resumption: Some(ResumptionParams {
                    ticket: t.ticket.as_slice(),
                    obfuscated_ticket_age: t.obfuscated_ticket_age(now_ms),
                    binder_finished_key: fk.as_slice(),
                    suite,
                }),
            })?;
            let cet = client_early_traffic_secret(suite, &early, &suite.digest(&ch))?;
            pending_0rtt_keys = Some(Keys {
                local: DirectionalKeys::from_secret(suite, &cet)?,
                remote: DirectionalKeys::from_secret(suite, &cet)?,
            });
            resumption_psk = Some(Zeroizing::new(t.psk.to_vec()));
            ch
        } else {
            build_client_hello(&ClientHelloParams {
                server_name,
                alpn_protocols: &config.alpn_protocols,
                x25519_public: &x25519.public,
                mlkem768_public: &mlkem_public,
                transport_params: &transport_params,
                grease,
                random: &random,
                resumption: None,
            })?
        };

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
            resumption_psk,
            pending_0rtt_keys,
            psk_accepted: false,
            early_data_accepted: false,
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

    /// Whether the server accepted 0-RTT (echoed `early_data` in EncryptedExtensions).
    /// Meaningful only on a resumption handshake; always false for cold-start.
    #[allow(dead_code)] // wired into the transport in S6
    pub fn is_early_data_accepted(&self) -> bool {
        self.early_data_accepted
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
        if let Some(keys) = self.pending_0rtt_keys.take() {
            // 0-RTT write keys, emitted right after the resumption ClientHello so
            // the transport can send early data before the handshake completes.
            return Some(KeyChange::ZeroRtt { keys });
        }
        if let Some(keys) = self.pending_handshake_keys.take() {
            return Some(KeyChange::Handshake { keys });
        }
        if let Some(finished) = self.pending_client_finished.take() {
            out.extend_from_slice(&finished);
            // Keep the transcript through the client Finished so a later
            // `resumption_master_secret` matches the server (RFC 8446 §7.1).
            self.transcript.extend_from_slice(&finished);
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

    /// `resumption_master_secret` over the transcript through the client Finished
    /// (RFC 8446 §7.1). Available only after [`Self::write_handshake`] has emitted
    /// the client Finished (which appends it to the transcript). The per-ticket PSK
    /// the client stores is [`super::schedule::resumption_psk`] of this secret.
    #[allow(dead_code)] // wired in S4 (client ticket store)
    pub fn resumption_master_secret(&self) -> Result<Zeroizing<Vec<u8>>, QuicTlsError> {
        let suite = self
            .suite
            .ok_or_else(|| QuicTlsError::Crypto("resumption master before handshake".into()))?;
        let schedule = self
            .schedule
            .as_ref()
            .ok_or_else(|| QuicTlsError::Crypto("resumption master before schedule".into()))?;
        let transcript_hash = suite.digest(&self.transcript);
        schedule.resumption_master_secret(&transcript_hash)
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
                // A resumed handshake (PSK accepted) sends no Certificate /
                // CertificateVerify — the next message is the server Finished.
                self.read_state = if self.psk_accepted {
                    ReadState::Finished
                } else {
                    ReadState::Certificate
                };
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
            // Accepted limitation (tracked follow-up): HelloRetryRequest is not
            // handled — the client aborts instead of sending a second ClientHello.
            // The production QUIC peer is ParallaX's own server, which never sends
            // HRR (it accepts the offered X25519MLKEM768), and the TCP camouflage
            // path (safari26) takes the same posture. A future slice can add HRR
            // for full browser parity under active Initial-space injection.
            return Err(QuicTlsError::alert(
                ALERT_HANDSHAKE_FAILURE,
                "HelloRetryRequest is not supported",
            ));
        }
        // legacy_session_id_echo: our QUIC ClientHello sends an EMPTY session id,
        // so RFC 8446 §4.1.3 requires the echo to be empty too. A non-empty echo
        // is a lenient behavioural tell vs rustls/Safari; reject it.
        if !c.vec_u8()?.is_empty() {
            return Err(QuicTlsError::alert(
                ALERT_ILLEGAL_PARAMETER,
                "ServerHello legacy_session_id_echo is not empty",
            ));
        }
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
        let mut psk_selected = false;
        while e.remaining() > 0 {
            let ext_type = e.u16()?;
            let data = e.vec_u16()?;
            match ext_type {
                EXT_SUPPORTED_VERSIONS => {
                    if tls13_selected {
                        return Err(QuicTlsError::alert(
                            ALERT_ILLEGAL_PARAMETER,
                            "duplicate supported_versions in ServerHello",
                        ));
                    }
                    if data.len() == 2
                        && u16::from_be_bytes([data[0], data[1]]) == TLS13_SELECTED_VERSION
                    {
                        tls13_selected = true;
                    } else {
                        return Err(QuicTlsError::alert(
                            ALERT_ILLEGAL_PARAMETER,
                            "ServerHello supported_versions did not select TLS 1.3",
                        ));
                    }
                }
                EXT_KEY_SHARE => {
                    if key_share_group.is_some() {
                        return Err(QuicTlsError::alert(
                            ALERT_ILLEGAL_PARAMETER,
                            "duplicate key_share in ServerHello",
                        ));
                    }
                    let mut ks = Cursor::new(data);
                    key_share_group = Some(ks.u16()?);
                    key_share = Some(ks.vec_u16()?.to_vec());
                    if ks.remaining() != 0 {
                        return Err(QuicTlsError::alert(
                            ALERT_DECODE_ERROR,
                            "trailing bytes after ServerHello key_share",
                        ));
                    }
                }
                // RFC 8446 §4.2: a TLS 1.3 ServerHello carries only
                // supported_versions + key_share (plus pre_shared_key when the
                // client offered one — handled above). Reject anything else rather
                // than silently tolerating it — silent leniency is an active-probe
                // tell.
                EXT_PRE_SHARED_KEY => {
                    // The server selects one of the PSK identities we offered. We
                    // offer exactly one (index 0), so this is illegal unless we
                    // resumed, and the selected_identity must be 0.
                    if self.resumption_psk.is_none() {
                        return Err(QuicTlsError::alert(
                            ALERT_ILLEGAL_PARAMETER,
                            "ServerHello pre_shared_key we did not offer",
                        ));
                    }
                    if data.len() != 2 || u16::from_be_bytes([data[0], data[1]]) != 0 {
                        return Err(QuicTlsError::alert(
                            ALERT_ILLEGAL_PARAMETER,
                            "ServerHello selected_identity is not our offered PSK",
                        ));
                    }
                    psk_selected = true;
                }
                other => {
                    return Err(QuicTlsError::alert(
                        ALERT_UNSUPPORTED_EXTENSION,
                        format!("unexpected ServerHello extension {other:#06x}"),
                    ));
                }
            }
        }
        self.psk_accepted = psk_selected;
        if !tls13_selected {
            return Err(QuicTlsError::alert(
                ALERT_MISSING_EXTENSION,
                "ServerHello did not select TLS 1.3 (no supported_versions)",
            ));
        }
        // A real TLS stack rejects trailing bytes after the extensions block; silent
        // tolerance is an active-probe distinguisher (same posture as the unknown-
        // extension rejection above).
        if c.remaining() != 0 {
            return Err(QuicTlsError::alert(
                ALERT_DECODE_ERROR,
                "trailing bytes after ServerHello extensions",
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

        // On a resumed handshake (the server accepted our PSK) the key schedule
        // chains from the ticket PSK; otherwise it uses the cold-start all-zero PSK.
        let resumption_psk = self.resumption_psk.as_ref().map(|p| p.as_slice());
        let psk = if self.psk_accepted {
            let psk = resumption_psk.ok_or_else(|| {
                QuicTlsError::alert(
                    ALERT_ILLEGAL_PARAMETER,
                    "server selected pre_shared_key we did not offer",
                )
            })?;
            if psk.len() != suite.hash_len() {
                return Err(QuicTlsError::alert(
                    ALERT_ILLEGAL_PARAMETER,
                    "resumed suite hash does not match the ticket PSK",
                ));
            }
            Some(psk)
        } else {
            None
        };
        let (schedule, keys) =
            KeySchedule::after_server_hello(suite, psk, &shared_secret, &transcript_hash)?;
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
                // Accepted trade-off: a server selecting plain X25519 (dropping the
                // ML-KEM hybrid) is honoured for Safari-26 parity (the ClientHello
                // offers X25519 as a group). This is sound against an active MITM
                // (the QUIC leg's TLS auth is off by design; trust is the
                // exporter-bound token), but it silently forgoes post-quantum
                // harvest-now/decrypt-later protection. The production peer is
                // ParallaX's own server, which always selects X25519MLKEM768, so a
                // downgrade only occurs against a non-ParallaX origin.
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
                // Copy the decapsulated secret into Zeroizing immediately so the
                // combined IKM is scrubbed on drop regardless of the aws-lc-rs
                // SharedSecret's own drop behaviour.
                let mlkem_shared = Zeroizing::new(
                    dk.decapsulate(Ciphertext::from(mlkem_ciphertext))
                        .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 decapsulation".into()))?
                        .as_ref()
                        .to_vec(),
                );
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
                    if self.alpn.is_some() {
                        return Err(QuicTlsError::alert(
                            ALERT_ILLEGAL_PARAMETER,
                            "duplicate ALPN extension in EncryptedExtensions",
                        ));
                    }
                    let selected = parse_selected_alpn(data)?;
                    // RFC 7301 §3.2: the server MUST select a protocol the client
                    // offered. Reject an unoffered (or empty) selection rather than
                    // completing the handshake on a protocol we never advertised.
                    if !self
                        .config
                        .alpn_protocols
                        .iter()
                        .any(|offered| offered.as_slice() == selected)
                    {
                        return Err(QuicTlsError::alert(
                            ALERT_ILLEGAL_PARAMETER,
                            "server selected an ALPN protocol the client did not offer",
                        ));
                    }
                    self.alpn = Some(selected.to_vec());
                }
                EXT_QUIC_TRANSPORT_PARAMETERS => {
                    if self.peer_transport_params.is_some() {
                        return Err(QuicTlsError::alert(
                            ALERT_ILLEGAL_PARAMETER,
                            "duplicate quic_transport_parameters in EncryptedExtensions",
                        ));
                    }
                    self.peer_transport_params = Some(data.to_vec());
                }
                EXT_EARLY_DATA => {
                    // The server echoing `early_data` accepts 0-RTT (RFC 8446
                    // §4.2.10); its EncryptedExtensions body is empty.
                    if !data.is_empty() {
                        return Err(QuicTlsError::alert(
                            ALERT_DECODE_ERROR,
                            "EncryptedExtensions early_data must be empty",
                        ));
                    }
                    self.early_data_accepted = true;
                }
                _ => {}
            }
        }
        // Reject trailing bytes after the extensions block (active-probe distinguisher).
        if c.remaining() != 0 {
            return Err(QuicTlsError::alert(
                ALERT_DECODE_ERROR,
                "trailing bytes after EncryptedExtensions",
            ));
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
    if c.remaining() != 0 {
        return Err(QuicTlsError::alert(
            ALERT_DECODE_ERROR,
            "trailing bytes after ALPN protocol list",
        ));
    }
    let mut l = Cursor::new(list);
    let proto = l.vec_u8()?;
    // RFC 7301 §3.2: the server selects exactly one protocol.
    if l.remaining() != 0 {
        return Err(QuicTlsError::alert(
            ALERT_DECODE_ERROR,
            "ALPN list carried more than one protocol",
        ));
    }
    Ok(proto)
}

/// Parse a TLS 1.3 Certificate message body into the DER chain.
fn parse_certificate_body(body: &[u8]) -> Result<Vec<Vec<u8>>, QuicTlsError> {
    let mut c = Cursor::new(body);
    let _request_context = c.vec_u8()?;
    let list = c.vec_u24()?;
    if c.remaining() != 0 {
        return Err(QuicTlsError::alert(
            ALERT_DECODE_ERROR,
            "trailing bytes after the certificate list",
        ));
    }
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
        // No supported_versions=0x0304 extension → required extension missing.
        let err = hs
            .read_handshake(&msg(
                HANDSHAKE_SERVER_HELLO,
                &server_hello_body([0x22; 32], &[]),
            ))
            .unwrap_err();
        assert_eq!(err.alert_description(), Some(ALERT_MISSING_EXTENSION));
    }

    #[test]
    fn partial_message_buffers_across_reads() {
        let mut hs = handshake();
        let m = msg(HANDSHAKE_SERVER_HELLO, &server_hello_body([0x33; 32], &[]));
        let (first, second) = m.split_at(10);
        // The incomplete prefix yields neither readiness nor an error.
        assert!(!hs.read_handshake(first).unwrap());
        // Completing the message then surfaces the rejection (the test SH carries
        // no supported_versions), proving the two halves were reassembled.
        assert!(hs.read_handshake(second).is_err());
    }

    /// An ALPN extension body selecting a single `proto`.
    fn alpn_ext_body(proto: &[u8]) -> Vec<u8> {
        let mut list = vec![proto.len() as u8];
        list.extend_from_slice(proto);
        let mut out = (list.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&list);
        out
    }

    /// An EncryptedExtensions body from `(ext_type, ext_body)` pairs.
    fn encrypted_extensions(exts: &[(u16, &[u8])]) -> Vec<u8> {
        let mut ext = Vec::new();
        for (ty, body) in exts {
            ext.extend_from_slice(&ty.to_be_bytes());
            ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext.extend_from_slice(body);
        }
        let mut ee = (ext.len() as u16).to_be_bytes().to_vec();
        ee.extend_from_slice(&ext);
        ee
    }

    #[test]
    fn server_alpn_not_offered_is_rejected() {
        // The client offers only h3; a server selecting h2 must be rejected
        // (RFC 7301 §3.2) rather than completing on an unoffered protocol.
        let mut hs = handshake();
        hs.read_state = ReadState::EncryptedExtensions;
        let alpn = alpn_ext_body(b"h2");
        let ee = encrypted_extensions(&[(EXT_ALPN, alpn.as_slice())]);
        let err = hs
            .read_handshake(&msg(HANDSHAKE_ENCRYPTED_EXTENSIONS, &ee))
            .unwrap_err();
        assert_eq!(err.alert_description(), Some(ALERT_ILLEGAL_PARAMETER));
    }

    #[test]
    fn server_alpn_offered_is_accepted() {
        let mut hs = handshake();
        hs.read_state = ReadState::EncryptedExtensions;
        let alpn = alpn_ext_body(b"h3");
        let ee = encrypted_extensions(&[
            (EXT_ALPN, alpn.as_slice()),
            (EXT_QUIC_TRANSPORT_PARAMETERS, &[0x0f, 0x00][..]),
        ]);
        hs.read_handshake(&msg(HANDSHAKE_ENCRYPTED_EXTENSIONS, &ee))
            .unwrap();
        assert_eq!(hs.alpn_protocol(), Some(&b"h3"[..]));
    }

    #[test]
    fn duplicate_alpn_extension_is_rejected() {
        // A second ALPN extension is a malformed message a real stack rejects;
        // tolerating it is an active-probe distinguisher.
        let mut hs = handshake();
        hs.read_state = ReadState::EncryptedExtensions;
        let alpn = alpn_ext_body(b"h3");
        let ee = encrypted_extensions(&[(EXT_ALPN, alpn.as_slice()), (EXT_ALPN, alpn.as_slice())]);
        let err = hs
            .read_handshake(&msg(HANDSHAKE_ENCRYPTED_EXTENSIONS, &ee))
            .unwrap_err();
        assert_eq!(err.alert_description(), Some(ALERT_ILLEGAL_PARAMETER));
    }

    #[test]
    fn alpn_list_with_more_than_one_protocol_is_rejected() {
        // RFC 7301 §3.2: the server selects exactly one protocol.
        let mut list = Vec::new();
        for p in [b"h3".as_slice(), b"h2".as_slice()] {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        let err = parse_selected_alpn(&data).unwrap_err();
        assert_eq!(err.alert_description(), Some(ALERT_DECODE_ERROR));
    }
}
