//! Server-side QUIC TLS 1.3 handshake (RFC 9001 + RFC 8446), clean-room.
//!
//! The mirror of [`super::handshake::ClientHandshake`]: it ingests the client's
//! ClientHello, runs the X25519MLKEM768 hybrid key exchange, and (across later
//! slices) emits the ServerHello / EncryptedExtensions / Certificate /
//! CertificateVerify / Finished flight, reusing the shared key schedule
//! ([`super::schedule`]) and packet/header protection ([`super::keys`]). Trust is
//! REALITY-style — the server signs a CertificateVerify the client need not
//! validate — but the server Finished MAC and the RFC 5705 exporter are real and
//! MUST match the client byte-for-byte.
//!
//! The server engine is built incrementally; items are wired into the
//! `ServerHandshake` state machine as the slices land, so unused-until-wired
//! pieces are tolerated here.
#![allow(dead_code)]

use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::schedule::KeySchedule;
use super::suite::CipherSuite;
use super::{
    KeyChange, KeyPair, Keys, PacketKey, QuicTlsError, ALERT_DECODE_ERROR, ALERT_DECRYPT_ERROR,
    ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER, ALERT_MISSING_EXTENSION,
    ALERT_NO_APPLICATION_PROTOCOL, ALERT_UNEXPECTED_MESSAGE,
};
use crate::crypto::session::{x25519_shared_secret, X25519KeyPair};

/// X25519MLKEM768 wire sizes (the IETF hybrid): the client offers the ML-KEM-768
/// encapsulation key ‖ X25519 public; the server replies with the ML-KEM-768
/// ciphertext ‖ X25519 public.
const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const X25519_LEN: usize = 32;

/// The combined hybrid shared-secret length (ML-KEM 32 ‖ X25519 32).
const HYBRID_SHARED_LEN: usize = 64;

/// Server half of the X25519MLKEM768 key exchange.
///
/// `client_share` is the client's key_share entry for group 0x11ec (the ML-KEM-768
/// encapsulation key ‖ the X25519 public). Returns the server's key_share entry
/// (ML-KEM-768 ciphertext ‖ the server's X25519 public) and the combined shared
/// secret using the IETF combiner — ML-KEM secret first, then X25519 — exactly as
/// [`super::handshake`]'s client-side combiner, so both ends agree.
fn server_hybrid_kex(client_share: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), QuicTlsError> {
    if client_share.len() != MLKEM768_PUBLIC_KEY_LEN + X25519_LEN {
        return Err(QuicTlsError::alert(
            ALERT_ILLEGAL_PARAMETER,
            "invalid X25519MLKEM768 client key_share length",
        ));
    }
    let (client_mlkem_pub, client_x25519) = client_share.split_at(MLKEM768_PUBLIC_KEY_LEN);

    let ek = EncapsulationKey::new(&ML_KEM_768, client_mlkem_pub)
        .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 encapsulation key".into()))?;
    let (ciphertext, mlkem_ss) = ek
        .encapsulate()
        .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 encapsulation".into()))?;
    let mlkem_shared = Zeroizing::new(mlkem_ss.as_ref().to_vec());

    let server_x25519 = X25519KeyPair::generate();
    let mut client_pub = [0u8; X25519_LEN];
    client_pub.copy_from_slice(client_x25519);
    let x25519_shared = Zeroizing::new(x25519_shared_secret(&server_x25519.private, &client_pub));
    // Reject a degenerate (all-zero) X25519 shared secret from a low-order client
    // share, mirroring the client engine's guard.
    if bool::from(x25519_shared.ct_eq(&[0u8; X25519_LEN])) {
        return Err(QuicTlsError::alert(
            ALERT_ILLEGAL_PARAMETER,
            "degenerate X25519 client key_share",
        ));
    }

    let mut combined = Zeroizing::new(Vec::with_capacity(HYBRID_SHARED_LEN));
    combined.extend_from_slice(&mlkem_shared);
    combined.extend_from_slice(&x25519_shared[..]);

    let mut server_share = Vec::with_capacity(MLKEM768_CIPHERTEXT_LEN + X25519_LEN);
    server_share.extend_from_slice(ciphertext.as_ref());
    server_share.extend_from_slice(&server_x25519.public);

    Ok((server_share, combined))
}

// --- ClientHello ingest (RFC 8446 §4.1.2) --------------------------------------

/// TLS extension codepoints the server reads off the ClientHello.
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
/// Named-group codepoint for the X25519MLKEM768 hybrid (the only group the engine
/// completes; the GREASE entry and the standalone X25519 share are ignored).
const GROUP_X25519MLKEM768: u16 = 0x11ec;
/// The QUIC v1 Initial / pinned suite (RFC 9001).
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS 1.3 wire version (in `supported_versions`).
const TLS13_VERSION: u16 = 0x0304;

/// The fields the server needs from a parsed ClientHello.
struct ClientHelloSummary {
    /// Echoed verbatim into the ServerHello (empty for the QUIC client).
    legacy_session_id: Vec<u8>,
    /// The client's X25519MLKEM768 key_share (ML-KEM-768 encapsulation key ‖
    /// X25519 public).
    hybrid_key_share: Vec<u8>,
    /// The peer's raw `quic_transport_parameters` (0x39) blob, for the TP reader.
    transport_params: Vec<u8>,
    /// The ALPN protocols the client offered (ext 0x10), in offer order. The
    /// server selects the first local protocol that appears here (RFC 7301).
    offered_alpn: Vec<Vec<u8>>,
}

/// Parse a ClientHello body (the handshake-message payload, i.e. WITHOUT the
/// 4-byte handshake type+length header) far enough to drive the server handshake:
/// it must offer TLS 1.3 + `TLS_AES_128_GCM_SHA256`, an X25519MLKEM768 key_share,
/// and `quic_transport_parameters`.
fn parse_client_hello(body: &[u8]) -> Result<ClientHelloSummary, QuicTlsError> {
    let mut r = Reader::new(body);
    let _legacy_version = r.u16()?;
    r.take(32)?; // random
    let legacy_session_id = r.vec_u8()?.to_vec();
    let cipher_suites = r.vec_u16()?;
    if !cipher_suites
        .chunks_exact(2)
        .any(|c| u16::from_be_bytes([c[0], c[1]]) == TLS_AES_128_GCM_SHA256)
    {
        return Err(QuicTlsError::alert(
            ALERT_HANDSHAKE_FAILURE,
            "client did not offer TLS_AES_128_GCM_SHA256",
        ));
    }
    let _compression = r.vec_u8()?;

    let mut er = Reader::new(r.vec_u16()?);
    let mut hybrid_key_share = None;
    let mut transport_params = None;
    let mut offered_alpn: Vec<Vec<u8>> = Vec::new();
    let mut offers_tls13 = false;
    while er.remaining() > 0 {
        let ext_type = er.u16()?;
        let ext_data = er.vec_u16()?;
        match ext_type {
            EXT_KEY_SHARE => {
                let mut kr = Reader::new(ext_data);
                let mut sr = Reader::new(kr.vec_u16()?);
                while sr.remaining() > 0 {
                    let group = sr.u16()?;
                    let key_exchange = sr.vec_u16()?;
                    if group == GROUP_X25519MLKEM768 {
                        hybrid_key_share = Some(key_exchange.to_vec());
                    }
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                let mut vr = Reader::new(ext_data);
                if vr
                    .vec_u8()?
                    .chunks_exact(2)
                    .any(|c| u16::from_be_bytes([c[0], c[1]]) == TLS13_VERSION)
                {
                    offers_tls13 = true;
                }
            }
            EXT_QUIC_TRANSPORT_PARAMETERS => transport_params = Some(ext_data.to_vec()),
            EXT_ALPN => {
                // ALPN ProtocolNameList: a u16-length list of u8-length names.
                let mut ar = Reader::new(ext_data);
                let mut lr = Reader::new(ar.vec_u16()?);
                while lr.remaining() > 0 {
                    offered_alpn.push(lr.vec_u8()?.to_vec());
                }
            }
            _ => {}
        }
    }

    if !offers_tls13 {
        return Err(QuicTlsError::alert(
            ALERT_MISSING_EXTENSION,
            "client did not offer TLS 1.3",
        ));
    }
    Ok(ClientHelloSummary {
        legacy_session_id,
        hybrid_key_share: hybrid_key_share.ok_or_else(|| {
            QuicTlsError::alert(ALERT_MISSING_EXTENSION, "no X25519MLKEM768 key_share")
        })?,
        transport_params: transport_params.ok_or_else(|| {
            QuicTlsError::alert(ALERT_MISSING_EXTENSION, "no quic_transport_parameters")
        })?,
        offered_alpn,
    })
}

/// A minimal big-endian, length-prefix-aware reader over a TLS structure.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], QuicTlsError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| QuicTlsError::alert(ALERT_DECODE_ERROR, "length overflow"))?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| QuicTlsError::alert(ALERT_DECODE_ERROR, "truncated ClientHello"))?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, QuicTlsError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, QuicTlsError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    /// A `u8`-length-prefixed byte string.
    fn vec_u8(&mut self) -> Result<&'a [u8], QuicTlsError> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    /// A `u16`-length-prefixed byte string.
    fn vec_u16(&mut self) -> Result<&'a [u8], QuicTlsError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

// --- Server handshake flight (RFC 8446 §4) -------------------------------------

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HANDSHAKE_CERTIFICATE: u8 = 0x0b;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0f;
const HANDSHAKE_FINISHED: u8 = 0x14;
const EXT_ALPN: u16 = 0x0010;
const TLS13_LEGACY_VERSION: u16 = 0x0303;
/// `ecdsa_secp256r1_sha256` (RFC 8446 §4.2.3) — the CertificateVerify scheme.
const SIG_SCHEME_ECDSA_P256: u16 = 0x0403;
/// Largest handshake message the server will buffer (the client Finished is tiny).
const MAX_HANDSHAKE_MESSAGE: usize = 1 << 16;

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u24(out: &mut Vec<u8>, v: usize) {
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

fn put_vec_u8(out: &mut Vec<u8>, body: &[u8]) {
    out.push(body.len() as u8);
    out.extend_from_slice(body);
}

fn put_vec_u16(out: &mut Vec<u8>, body: &[u8]) {
    put_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

fn put_vec_u24(out: &mut Vec<u8>, body: &[u8]) {
    put_u24(out, body.len());
    out.extend_from_slice(body);
}

/// Wrap a handshake-message body in its `type(1) ‖ length(3)` header.
fn handshake_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(msg_type);
    put_u24(&mut m, body.len());
    m.extend_from_slice(body);
    m
}

/// ServerHello: pins TLS 1.3 + `TLS_AES_128_GCM_SHA256`, echoes the (empty)
/// session id, and carries supported_versions + the X25519MLKEM768 key_share.
fn build_server_hello(
    session_id_echo: &[u8],
    server_key_share: &[u8],
    random: &[u8; 32],
) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, TLS13_LEGACY_VERSION);
    body.extend_from_slice(random);
    put_vec_u8(&mut body, session_id_echo);
    put_u16(&mut body, TLS_AES_128_GCM_SHA256);
    body.push(0); // null compression

    let mut exts = Vec::new();
    put_u16(&mut exts, EXT_SUPPORTED_VERSIONS);
    put_vec_u16(&mut exts, &0x0304u16.to_be_bytes());
    let mut ks = Vec::new();
    put_u16(&mut ks, GROUP_X25519MLKEM768);
    put_vec_u16(&mut ks, server_key_share);
    put_u16(&mut exts, EXT_KEY_SHARE);
    put_vec_u16(&mut exts, &ks);
    put_vec_u16(&mut body, &exts);

    handshake_message(HANDSHAKE_SERVER_HELLO, &body)
}

/// EncryptedExtensions: the selected ALPN + the server's transport parameters.
fn build_encrypted_extensions(alpn: &[u8], transport_params: &[u8]) -> Vec<u8> {
    let mut exts = Vec::new();
    let mut alpn_list = Vec::new();
    put_vec_u8(&mut alpn_list, alpn);
    let mut alpn_ext = Vec::new();
    put_vec_u16(&mut alpn_ext, &alpn_list);
    put_u16(&mut exts, EXT_ALPN);
    put_vec_u16(&mut exts, &alpn_ext);
    put_u16(&mut exts, EXT_QUIC_TRANSPORT_PARAMETERS);
    put_vec_u16(&mut exts, transport_params);
    let mut body = Vec::new();
    put_vec_u16(&mut body, &exts);
    handshake_message(HANDSHAKE_ENCRYPTED_EXTENSIONS, &body)
}

/// Certificate: empty request context + the DER chain (each entry with empty
/// per-certificate extensions).
fn build_certificate(cert_chain: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    put_vec_u8(&mut body, &[]); // certificate_request_context
    let mut list = Vec::new();
    for cert in cert_chain {
        put_vec_u24(&mut list, cert);
        put_vec_u16(&mut list, &[]); // per-cert extensions
    }
    put_vec_u24(&mut body, &list);
    handshake_message(HANDSHAKE_CERTIFICATE, &body)
}

fn build_certificate_verify(scheme: u16, signature: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, scheme);
    put_vec_u16(&mut body, signature);
    handshake_message(HANDSHAKE_CERTIFICATE_VERIFY, &body)
}

/// The CertificateVerify signed content (RFC 8446 §4.4.3): 64 spaces, the context
/// string, a separator 0x00, then `Transcript-Hash(ClientHello..Certificate)`.
fn certificate_verify_content(transcript_hash: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(64 + 34 + transcript_hash.len());
    content.extend_from_slice(&[0x20; 64]);
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    content.push(0);
    content.extend_from_slice(transcript_hash);
    content
}

fn build_finished(verify_data: &[u8]) -> Vec<u8> {
    handshake_message(HANDSHAKE_FINISHED, verify_data)
}

/// Re-key a client-perspective [`Keys`] aggregate to the server's perspective:
/// the schedule always returns `local = client`, `remote = server`, so the server
/// swaps them (it seals with the server secret, opens with the client secret).
fn swap(keys: Keys) -> Keys {
    Keys {
        local: keys.remote,
        remote: keys.local,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerState {
    ExpectClientHello,
    ExpectClientFinished,
    Complete,
}

/// Clean-room server half of the QUIC TLS 1.3 handshake (the mirror of
/// [`super::handshake::ClientHandshake`]). It ingests the ClientHello, builds the
/// full server flight, derives the Handshake + 1-RTT keys via the shared
/// [`KeySchedule`], and verifies the client Finished.
pub struct ServerHandshake {
    alpn_protocols: Vec<Vec<u8>>,
    cert_chain: Vec<Vec<u8>>,
    signing_key: EcdsaKeyPair,
    transport_params: Vec<u8>,
    suite: CipherSuite,
    schedule: Option<KeySchedule>,
    transcript: Vec<u8>,
    state: ServerState,
    peer_transport_params: Option<Vec<u8>>,
    pending_server_hello: Option<Vec<u8>>,
    pending_handshake_keys: Option<Keys>,
    pending_handshake_flight: Option<Vec<u8>>,
    pending_1rtt_keys: Option<Keys>,
    expected_client_finished: Option<Vec<u8>>,
    handshake_complete: bool,
    inbound: Vec<u8>,
}

impl ServerHandshake {
    /// Build a server handshake with the cover certificate chain (DER), the
    /// ECDSA P-256 signing key (PKCS#8) that signs CertificateVerify, the ALPN
    /// list to select from, and the server's transport-parameters blob. The QUIC
    /// v1 Initial suite (`TLS_AES_128_GCM_SHA256`) is pinned.
    pub fn new(
        cert_chain: Vec<Vec<u8>>,
        signing_key_pkcs8: &[u8],
        alpn_protocols: Vec<Vec<u8>>,
        transport_params: Vec<u8>,
    ) -> Result<Self, QuicTlsError> {
        let signing_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, signing_key_pkcs8)
                .map_err(|_| QuicTlsError::Crypto("server ECDSA P-256 signing key".into()))?;
        Ok(Self {
            alpn_protocols,
            cert_chain,
            signing_key,
            transport_params,
            suite: CipherSuite::Aes128GcmSha256,
            schedule: None,
            transcript: Vec::new(),
            state: ServerState::ExpectClientHello,
            peer_transport_params: None,
            pending_server_hello: None,
            pending_handshake_keys: None,
            pending_handshake_flight: None,
            pending_1rtt_keys: None,
            expected_client_finished: None,
            handshake_complete: false,
            inbound: Vec::new(),
        })
    }

    pub fn is_handshaking(&self) -> bool {
        !self.handshake_complete
    }

    /// The next 1-RTT packet-key generation for a key update (RFC 9001 §6).
    pub fn next_1rtt_keys(&mut self) -> Option<KeyPair<PacketKey>> {
        self.schedule.as_mut()?.next_1rtt_packet_keys().ok()
    }

    /// The client's raw `quic_transport_parameters` blob, once the ClientHello has
    /// been ingested.
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.peer_transport_params.as_deref()
    }

    /// RFC 5705 exporter; available once the schedule reaches 1-RTT.
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

    /// Emit outgoing CRYPTO bytes; return a [`KeyChange`] when crossing into the
    /// next packet-number space. Steps: ServerHello (Initial) → Handshake keys →
    /// EncryptedExtensions/Certificate/CertificateVerify/Finished (Handshake) +
    /// 1-RTT keys.
    pub fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        if let Some(sh) = self.pending_server_hello.take() {
            out.extend_from_slice(&sh);
            return None;
        }
        if let Some(keys) = self.pending_handshake_keys.take() {
            return Some(KeyChange::Handshake { keys });
        }
        if let Some(flight) = self.pending_handshake_flight.take() {
            out.extend_from_slice(&flight);
            let keys = self
                .pending_1rtt_keys
                .take()
                .expect("1-RTT keys derived with the server flight");
            return Some(KeyChange::OneRtt { keys });
        }
        None
    }

    /// Feed reassembled CRYPTO bytes (the ClientHello, then the client Finished).
    /// Returns `Ok(true)` once handshake data (peer TPs / completion) is available.
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<bool, QuicTlsError> {
        self.inbound.extend_from_slice(data);
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
        }
        Ok(self.peer_transport_params.is_some() || self.handshake_complete)
    }

    fn process_message(&mut self, message: &[u8]) -> Result<(), QuicTlsError> {
        let msg_type = message[0];
        match (self.state, msg_type) {
            (ServerState::ExpectClientHello, HANDSHAKE_CLIENT_HELLO) => {
                self.process_client_hello(message)?;
                self.state = ServerState::ExpectClientFinished;
                Ok(())
            }
            (ServerState::ExpectClientFinished, HANDSHAKE_FINISHED) => {
                self.verify_client_finished(&message[4..])?;
                self.transcript.extend_from_slice(message);
                self.state = ServerState::Complete;
                self.handshake_complete = true;
                Ok(())
            }
            (state, ty) => Err(QuicTlsError::alert(
                ALERT_UNEXPECTED_MESSAGE,
                format!("unexpected handshake message {ty:#04x} in state {state:?}"),
            )),
        }
    }

    fn process_client_hello(&mut self, message: &[u8]) -> Result<(), QuicTlsError> {
        let summary = parse_client_hello(&message[4..])?;
        let (server_share, shared) = server_hybrid_kex(&summary.hybrid_key_share)?;
        self.peer_transport_params = Some(summary.transport_params);

        let mut random = [0u8; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| QuicTlsError::Crypto("server random".into()))?;

        // transcript: ClientHello, then ServerHello.
        self.transcript.extend_from_slice(message);
        let server_hello = build_server_hello(&summary.legacy_session_id, &server_share, &random);
        self.transcript.extend_from_slice(&server_hello);
        let hash_sh = self.suite.digest(&self.transcript);
        let (mut schedule, hs_keys) =
            KeySchedule::after_server_hello(self.suite, &shared, &hash_sh)?;

        // RFC 7301: select the first local ALPN protocol the client actually
        // offered; a peer that shares none gets no_application_protocol rather than
        // an unoffered protocol (which a compliant client would reject).
        let alpn = self
            .alpn_protocols
            .iter()
            .find(|p| summary.offered_alpn.iter().any(|o| o == *p))
            .cloned()
            .ok_or_else(|| {
                QuicTlsError::alert(ALERT_NO_APPLICATION_PROTOCOL, "no overlapping ALPN protocol")
            })?;
        let ee = build_encrypted_extensions(&alpn, &self.transport_params);
        self.transcript.extend_from_slice(&ee);
        let cert = build_certificate(&self.cert_chain);
        self.transcript.extend_from_slice(&cert);

        // CertificateVerify over Transcript-Hash(ClientHello..Certificate), signed
        // with the cover cert's ECDSA P-256 key (RFC 8446 §4.4.3). The REALITY
        // client (AcceptAnyServerCert) does not verify it, but a real verifier — or
        // the differential oracle — accepts the valid signature.
        let hash_cert = self.suite.digest(&self.transcript);
        let content = certificate_verify_content(&hash_cert);
        let signature = self
            .signing_key
            .sign(&SystemRandom::new(), &content)
            .map_err(|_| QuicTlsError::Crypto("CertificateVerify signing".into()))?;
        let cv = build_certificate_verify(SIG_SCHEME_ECDSA_P256, signature.as_ref());
        self.transcript.extend_from_slice(&cv);

        let hash_cv = self.suite.digest(&self.transcript);
        let server_verify = schedule.server_finished_verify_data(&hash_cv)?;
        let fin = build_finished(&server_verify);
        self.transcript.extend_from_slice(&fin);

        let hash_sf = self.suite.digest(&self.transcript);
        let onertt = schedule.derive_application(&hash_sf)?;
        self.expected_client_finished = Some(schedule.client_finished_verify_data(&hash_sf)?);

        let mut handshake_flight = ee;
        handshake_flight.extend_from_slice(&cert);
        handshake_flight.extend_from_slice(&cv);
        handshake_flight.extend_from_slice(&fin);

        self.schedule = Some(schedule);
        self.pending_server_hello = Some(server_hello);
        self.pending_handshake_keys = Some(swap(hs_keys));
        self.pending_handshake_flight = Some(handshake_flight);
        self.pending_1rtt_keys = Some(swap(onertt));
        Ok(())
    }

    fn verify_client_finished(&mut self, verify_data: &[u8]) -> Result<(), QuicTlsError> {
        let expected = self.expected_client_finished.as_ref().ok_or_else(|| {
            QuicTlsError::alert(ALERT_UNEXPECTED_MESSAGE, "Finished before flight")
        })?;
        if !bool::from(verify_data.ct_eq(expected)) {
            return Err(QuicTlsError::alert(
                ALERT_DECRYPT_ERROR,
                "client Finished verify_data mismatch",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::kem::{Ciphertext, DecapsulationKey};

    #[test]
    fn hybrid_kex_client_and_server_derive_the_same_secret() {
        // Client side: build the key_share the server ingests (ML-KEM pub ‖ X25519).
        let client_x = X25519KeyPair::generate();
        let dk = DecapsulationKey::generate(&ML_KEM_768).unwrap();
        let mut client_share = dk
            .encapsulation_key()
            .and_then(|ek| ek.key_bytes())
            .unwrap()
            .as_ref()
            .to_vec();
        assert_eq!(client_share.len(), MLKEM768_PUBLIC_KEY_LEN);
        client_share.extend_from_slice(&client_x.public);

        // Server encapsulates against the client's ML-KEM key and ECDHs.
        let (server_share, server_secret) = server_hybrid_kex(&client_share).unwrap();
        assert_eq!(server_share.len(), MLKEM768_CIPHERTEXT_LEN + X25519_LEN);
        assert_eq!(server_secret.len(), HYBRID_SHARED_LEN);

        // Client recombines from the server's key_share and must match.
        let (ct, server_x25519) = server_share.split_at(MLKEM768_CIPHERTEXT_LEN);
        let mlkem_shared = dk
            .decapsulate(Ciphertext::from(ct))
            .unwrap()
            .as_ref()
            .to_vec();
        let mut sx = [0u8; X25519_LEN];
        sx.copy_from_slice(server_x25519);
        let x_shared = x25519_shared_secret(&client_x.private, &sx);
        let mut client_secret = Vec::with_capacity(HYBRID_SHARED_LEN);
        client_secret.extend_from_slice(&mlkem_shared);
        client_secret.extend_from_slice(&x_shared);

        assert_eq!(
            &server_secret[..],
            &client_secret[..],
            "client and server derive the identical hybrid shared secret"
        );
    }

    #[test]
    fn rejects_wrong_length_client_share() {
        assert!(server_hybrid_kex(&[0u8; 100]).is_err());
    }

    #[test]
    fn parses_a_real_client_hello_and_ingests_its_key_share() {
        use crate::tls::quic::{
            AcceptAnyServerCert, ClientConfig, ClientHandshake, QUIC_VERSION_V1,
        };
        use std::sync::Arc;

        let config = Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ));
        let tp_blob = vec![0xde, 0xad, 0xbe, 0xef];
        let mut engine =
            ClientHandshake::new(config, QUIC_VERSION_V1, "example.com", tp_blob.clone()).unwrap();

        // Pull the real ClientHello handshake message and strip its 4-byte header.
        let mut msg = Vec::new();
        let _ = engine.write_handshake(&mut msg);
        assert_eq!(msg[0], 0x01, "handshake message is a ClientHello");
        let summary = parse_client_hello(&msg[4..]).unwrap();

        assert!(
            summary.legacy_session_id.is_empty(),
            "QUIC ClientHello carries an empty legacy_session_id"
        );
        assert_eq!(
            summary.hybrid_key_share.len(),
            MLKEM768_PUBLIC_KEY_LEN + X25519_LEN,
            "extracted the X25519MLKEM768 client share"
        );
        assert_eq!(summary.transport_params, tp_blob, "recovered the 0x39 blob");

        // The server can immediately ingest that share into the hybrid KEX.
        let (server_share, secret) = server_hybrid_kex(&summary.hybrid_key_share).unwrap();
        assert_eq!(server_share.len(), MLKEM768_CIPHERTEXT_LEN + X25519_LEN);
        assert_eq!(secret.len(), HYBRID_SHARED_LEN);
    }

    #[test]
    fn client_and_server_complete_a_tls_handshake_with_matching_exporter() {
        use crate::tls::quic::{
            AcceptAnyServerCert, ClientConfig, ClientHandshake, QUIC_VERSION_V1,
        };
        use std::sync::Arc;

        // A dummy cover certificate (the REALITY client accepts any) and the
        // server/client transport-parameter blobs (opaque to the TLS handshake).
        let cert_chain = vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]];
        let server_tp = vec![0x01, 0x02, 0x03, 0x04];
        let key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let mut server = ServerHandshake::new(
            cert_chain,
            key.as_ref(),
            vec![b"h3".to_vec()],
            server_tp.clone(),
        )
        .unwrap();

        let client_config = Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ));
        let mut client = ClientHandshake::new(
            client_config,
            QUIC_VERSION_V1,
            "example.com",
            vec![0xaa, 0xbb],
        )
        .unwrap();

        // Drain a handshake's write side into a byte buffer (the QUIC space routing
        // is irrelevant at the TLS-message level — the peer reads them in order).
        fn drain_client(h: &mut ClientHandshake) -> Vec<u8> {
            let mut all = Vec::new();
            loop {
                let mut b = Vec::new();
                let kc = h.write_handshake(&mut b);
                if b.is_empty() && kc.is_none() {
                    break;
                }
                all.extend_from_slice(&b);
            }
            all
        }
        fn drain_server(h: &mut ServerHandshake) -> Vec<u8> {
            let mut all = Vec::new();
            loop {
                let mut b = Vec::new();
                let kc = h.write_handshake(&mut b);
                if b.is_empty() && kc.is_none() {
                    break;
                }
                all.extend_from_slice(&b);
            }
            all
        }

        // 1. ClientHello -> server.
        let ch = drain_client(&mut client);
        server.read_handshake(&ch).unwrap();
        // 2. ServerHello..Finished -> client.
        let flight = drain_server(&mut server);
        client.read_handshake(&flight).unwrap();
        // 3. client Finished -> server.
        let client_fin = drain_client(&mut client);
        server.read_handshake(&client_fin).unwrap();

        assert!(!client.is_handshaking(), "client completed");
        assert!(!server.is_handshaking(), "server completed");

        // The RFC 5705 exporter must be byte-identical on both ends — it backs the
        // UDP auth token.
        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        client
            .export_keying_material(&mut ce, b"parallax tudp", b"ctx")
            .unwrap();
        server
            .export_keying_material(&mut se, b"parallax tudp", b"ctx")
            .unwrap();
        assert_eq!(
            ce, se,
            "client and server derive identical exporter material"
        );

        // The client negotiated our ALPN and saw our transport parameters.
        assert_eq!(client.alpn_protocol(), Some(b"h3".as_ref()));
        assert_eq!(
            client.peer_transport_parameters(),
            Some(server_tp.as_slice())
        );
        // ...and the server saw the client's.
        assert_eq!(
            server.peer_transport_parameters(),
            Some([0xaa, 0xbb].as_ref())
        );
    }
}
