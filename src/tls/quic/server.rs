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

use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::schedule::{
    binder_finished_key, client_early_traffic_secret, early_secret_from_psk, psk_binder,
    resumption_psk, KeySchedule,
};
use super::suite::CipherSuite;
use super::ticket::{
    encode_new_session_ticket, open_ticket, seal_ticket, NewSessionTicket, TicketState,
    QUIC_MAX_EARLY_DATA,
};
use super::{
    DirectionalKeys, KeyChange, KeyPair, Keys, PacketKey, QuicTlsError, ZeroRttGuard,
    ALERT_DECODE_ERROR, ALERT_DECRYPT_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER,
    ALERT_MISSING_EXTENSION, ALERT_NO_APPLICATION_PROTOCOL, ALERT_UNEXPECTED_MESSAGE,
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
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// Freshness window for the origin-splice auth marker (seconds): how old a marker
/// may be (also the retention an Initial-time replay cache needs). Generous enough
/// for client/server clock skew (so a real client is not mis-spliced), bounded
/// enough to limit a captured marker's capture-and-replay-later window.
///
/// Exported so the persistent marker-replay cache window in `handshake::server`
/// can statically assert it retains entries for at least this long (a static
/// `assert!` there fails the build if the two ever drift such that a still-fresh
/// marker could be evicted from the replay cache, reopening a replay gap).
pub(crate) const MARKER_WINDOW_SECS: u64 = 3600;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
/// `pre_shared_key` (RFC 8446 §4.2.11): offered last by a resuming client; echoed
/// in ServerHello (selected_identity) when the server accepts the PSK.
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
/// `early_data` (RFC 8446 §4.2.10): offered (empty) by a 0-RTT client; echoed
/// (empty) in EncryptedExtensions when the server accepts 0-RTT.
const EXT_EARLY_DATA: u16 = 0x002a;
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
    /// The `ClientHello.random` (carries the covert origin-splice auth marker).
    client_random: [u8; 32],
    /// The client's SNI host_name (server_name ext), bound by the auth marker.
    sni: Vec<u8>,
    /// The client's X25519MLKEM768 key_share (ML-KEM-768 encapsulation key ‖
    /// X25519 public).
    hybrid_key_share: Vec<u8>,
    /// The peer's raw `quic_transport_parameters` (0x39) blob, for the TP reader.
    transport_params: Vec<u8>,
    /// The ALPN protocols the client offered (ext 0x10), in offer order. The
    /// server selects the first local protocol that appears here (RFC 7301).
    offered_alpn: Vec<Vec<u8>>,
    /// The first `pre_shared_key` identity (the opaque ticket), if the client
    /// offered a PSK (0-RTT resumption).
    psk_identity: Option<Vec<u8>>,
    /// The first PSK binder, paired with `psk_identity`.
    psk_binder: Option<Vec<u8>>,
    /// The wire length of the binders list content (= the `binders<>` vector
    /// length), used to truncate the ClientHello for binder verification.
    psk_binders_wire_len: Option<usize>,
    /// Whether the client offered the `early_data` extension (0-RTT).
    offers_early_data: bool,
}

/// Parse a ClientHello body (the handshake-message payload, i.e. WITHOUT the
/// 4-byte handshake type+length header) far enough to drive the server handshake:
/// it must offer TLS 1.3 + `TLS_AES_128_GCM_SHA256`, an X25519MLKEM768 key_share,
/// and `quic_transport_parameters`.
fn parse_client_hello(body: &[u8]) -> Result<ClientHelloSummary, QuicTlsError> {
    let mut r = Reader::new(body);
    let _legacy_version = r.u16()?;
    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(r.take(32)?);
    let legacy_session_id = r.vec_u8()?.to_vec();
    let cipher_suites = r.vec_u16()?;
    // RFC 8446 §4.1.2: cipher_suites is a vector of 2-byte values, so an odd length
    // is malformed. chunks_exact(2) would silently drop the trailing odd byte; reject
    // it instead, matching the client-side parser's strictness (a lenient server is an
    // active-probe distinguisher from a real TLS stack).
    if cipher_suites.len() % 2 != 0 {
        return Err(QuicTlsError::alert(
            ALERT_DECODE_ERROR,
            "odd-length cipher_suites",
        ));
    }
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
    let mut sni: Vec<u8> = Vec::new();
    let mut transport_params = None;
    let mut offered_alpn: Vec<Vec<u8>> = Vec::new();
    let mut offers_tls13 = false;
    let mut psk_identity = None;
    let mut psk_binder = None;
    let mut psk_binders_wire_len = None;
    let mut offers_early_data = false;
    while er.remaining() > 0 {
        let ext_type = er.u16()?;
        let ext_data = er.vec_u16()?;
        match ext_type {
            EXT_SERVER_NAME => {
                // ServerNameList: u16 list_len, then [name_type(1) u16 name_len name].
                // Take the first host_name (type 0x00); the marker is bound to it.
                let mut nr = Reader::new(ext_data);
                let mut list = Reader::new(nr.vec_u16()?);
                while list.remaining() > 0 {
                    let name_type = list.u8()?;
                    let name = list.vec_u16()?;
                    if name_type == 0 {
                        sni = name.to_vec();
                        break;
                    }
                }
            }
            EXT_KEY_SHARE => {
                let mut kr = Reader::new(ext_data);
                let mut sr = Reader::new(kr.vec_u16()?);
                // The KeyShareClientHello is exactly the u16-length client_shares list;
                // reject trailing bytes after it (client-side parser strictness — a
                // real TLS stack does not leave garbage after the key_share vector).
                if kr.remaining() != 0 {
                    return Err(QuicTlsError::alert(
                        ALERT_DECODE_ERROR,
                        "trailing bytes after key_share client_shares",
                    ));
                }
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
            EXT_PRE_SHARED_KEY => {
                // OfferedPsks { identities<7..>, binders<33..> } (RFC 8446 §4.2.11.1).
                // ParallaX offers exactly one identity + one binder; take the first.
                let mut pr = Reader::new(ext_data);
                let identities = pr.vec_u16()?;
                let binders_blob = pr.vec_u16()?;
                let mut ir = Reader::new(identities);
                let id = ir.vec_u16()?; // PskIdentity.identity (the opaque ticket)
                ir.take(4)?; // obfuscated_ticket_age (unused server-side)
                psk_identity = Some(id.to_vec());
                let mut br = Reader::new(binders_blob);
                psk_binder = Some(br.vec_u8()?.to_vec()); // first PskBinderEntry
                psk_binders_wire_len = Some(binders_blob.len());
            }
            EXT_EARLY_DATA => offers_early_data = true,
            _ => {}
        }
    }
    // The extensions vector is the last field of the ClientHello body; reject any
    // trailing bytes after it (the client-side parser rejects the symmetric case as an
    // active-probe distinguisher — handshake.rs:710 — so the server must too).
    if r.remaining() != 0 {
        return Err(QuicTlsError::alert(
            ALERT_DECODE_ERROR,
            "trailing bytes after ClientHello extensions",
        ));
    }

    if !offers_tls13 {
        return Err(QuicTlsError::alert(
            ALERT_MISSING_EXTENSION,
            "client did not offer TLS 1.3",
        ));
    }
    Ok(ClientHelloSummary {
        legacy_session_id,
        client_random,
        sni,
        hybrid_key_share: hybrid_key_share.ok_or_else(|| {
            QuicTlsError::alert(ALERT_MISSING_EXTENSION, "no X25519MLKEM768 key_share")
        })?,
        transport_params: transport_params.ok_or_else(|| {
            QuicTlsError::alert(ALERT_MISSING_EXTENSION, "no quic_transport_parameters")
        })?,
        offered_alpn,
        psk_identity,
        psk_binder,
        psk_binders_wire_len,
        offers_early_data,
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
/// 0-RTT resumption-ticket lifetime: RFC 8446 §4.6.1's 7-day cap, matching the
/// Safari 26.4 NewSessionTicket baseline.
///
/// Exported so the 0-RTT anti-replay cache window in `handshake::server` can
/// statically assert it retains a ticket's replay record for at least the
/// ticket's whole lifetime (a static `assert!` there fails the build if the two
/// drift such that a still-valid ticket could be replayed after eviction).
pub(crate) const TICKET_LIFETIME_SECS: u32 = 604_800;

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
    psk_selected: bool,
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
    if psk_selected {
        // pre_shared_key in ServerHello carries selected_identity; we offered exactly
        // one identity, so the server selects index 0 (RFC 8446 §4.2.11).
        put_u16(&mut exts, EXT_PRE_SHARED_KEY);
        put_vec_u16(&mut exts, &0u16.to_be_bytes());
    }
    put_vec_u16(&mut body, &exts);

    handshake_message(HANDSHAKE_SERVER_HELLO, &body)
}

/// EncryptedExtensions: the selected ALPN + the server's transport parameters, plus
/// an (empty) `early_data` extension when the server accepts 0-RTT.
fn build_encrypted_extensions(alpn: &[u8], transport_params: &[u8], early_data: bool) -> Vec<u8> {
    let mut exts = Vec::new();
    let mut alpn_list = Vec::new();
    put_vec_u8(&mut alpn_list, alpn);
    let mut alpn_ext = Vec::new();
    put_vec_u16(&mut alpn_ext, &alpn_list);
    put_u16(&mut exts, EXT_ALPN);
    put_vec_u16(&mut exts, &alpn_ext);
    put_u16(&mut exts, EXT_QUIC_TRANSPORT_PARAMETERS);
    put_vec_u16(&mut exts, transport_params);
    if early_data {
        // Accept 0-RTT: echo an empty early_data extension (RFC 8446 §4.2.10).
        put_u16(&mut exts, EXT_EARLY_DATA);
        put_vec_u16(&mut exts, &[]);
    }
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
    /// STEK for sealing 0-RTT resumption tickets. `None` disables ticket issuance,
    /// so a cold-start-only server behaves exactly as before.
    stek: Option<Zeroizing<[u8; 32]>>,
    /// The ALPN selected from the ClientHello, retained for the resumption ticket.
    selected_alpn: Option<Vec<u8>>,
    /// Post-handshake (1-RTT) CRYPTO queued for emission (the NewSessionTicket).
    pending_post_handshake: Vec<u8>,
    /// 0-RTT (early-data) open keys, queued as [`KeyChange::ZeroRtt`] when the
    /// server accepts 0-RTT; the transport installs `remote` to decrypt early data.
    pending_0rtt_keys: Option<Keys>,
    /// Whether the server accepted 0-RTT (echoed `early_data` in EE).
    early_data_accepted: bool,
    /// Cross-connection single-use anti-replay guard for 0-RTT tickets (RFC 8446
    /// §8). `None` disables the check (e.g. cold-start-only servers / unit tests).
    replay_guard: Option<Arc<dyn ZeroRttGuard>>,
    /// Origin-splice auth-marker key: `(psk, server static X25519 private)`. When
    /// set, the ClientHello.random is verified as a covert marker
    /// ([`crate::crypto::quic_marker`]); the recovered marker (if any) is exposed via
    /// [`Self::marker_result`] for the endpoint's terminate-vs-splice fork. `None`
    /// leaves `marker_result` `None` (cold-start: the fork treats every flow as
    /// unauthenticated).
    marker_key: Option<crate::crypto::quic_marker::MarkerKey>,
    /// This connection's first-Initial Destination Connection ID, bound into the
    /// marker MAC (issue #74). A marker minted for one DCID fails to verify when
    /// replayed onto a different DCID / routing identity. Empty until set.
    marker_dcid: Vec<u8>,
    /// The marker recovered from this connection's ClientHello.random, if it carried
    /// a valid + fresh one. Set during ClientHello processing when `marker_key` is set.
    marker_result: Option<crate::crypto::quic_marker::Marker>,
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
        stek: Option<Zeroizing<[u8; 32]>>,
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
            stek,
            selected_alpn: None,
            pending_post_handshake: Vec::new(),
            pending_0rtt_keys: None,
            early_data_accepted: false,
            replay_guard: None,
            marker_key: None,
            marker_dcid: Vec::new(),
            marker_result: None,
        })
    }

    /// Install the cross-connection 0-RTT anti-replay guard. Must be set before the
    /// ClientHello is processed (the runtime sets it right after construction).
    pub(crate) fn set_zero_rtt_guard(&mut self, guard: Arc<dyn ZeroRttGuard>) {
        self.replay_guard = Some(guard);
    }

    /// Install the origin-splice auth-marker key `(psk, server static X25519
    /// private)`. Must be set before the ClientHello is processed; the server then
    /// verifies `ClientHello.random` as a covert marker and exposes the result via
    /// [`Self::marker_result`].
    pub(crate) fn set_marker_key(
        &mut self,
        psk: Zeroizing<Vec<u8>>,
        static_priv: Zeroizing<[u8; 32]>,
        bound_dcid: Vec<u8>,
    ) {
        self.marker_key = Some((psk, static_priv));
        self.marker_dcid = bound_dcid;
    }

    /// The marker recovered from this connection's ClientHello.random, if valid +
    /// fresh (only ever `Some` when [`Self::set_marker_key`] was set before the CH).
    pub(crate) fn marker_result(&self) -> Option<crate::crypto::quic_marker::Marker> {
        self.marker_result
    }

    /// Whether the ClientHello has been consumed, so [`Self::marker_result`] is final
    /// (a parsed CH that carried no valid marker) rather than merely "not parsed yet"
    /// (an incomplete first flight). The endpoint's buffer-decide-then-route marker
    /// fork waits for this before deciding terminate-vs-splice, since the Safari
    /// ClientHello spans two Initials.
    pub(crate) fn client_hello_processed(&self) -> bool {
        self.state != ServerState::ExpectClientHello
    }

    pub fn is_handshaking(&self) -> bool {
        !self.handshake_complete
    }

    /// The next 1-RTT packet-key generation for a key update (RFC 9001 §6).
    #[allow(dead_code)] // key-update keys: implemented + tested; the relay closes at the AEAD limit, not rotates
    pub fn next_1rtt_keys(&mut self) -> Option<KeyPair<PacketKey>> {
        // The schedule is side-agnostic (local = client, remote = server). The server
        // seals with the server key and opens with the client key, so swap — exactly
        // as `swap()` does for the handshake Keys (RFC 9001 §6 key update).
        let pair = self.schedule.as_mut()?.next_1rtt_packet_keys().ok()?;
        Some(KeyPair {
            local: pair.remote,
            remote: pair.local,
        })
    }

    /// The client's raw `quic_transport_parameters` blob, once the ClientHello has
    /// been ingested.
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.peer_transport_params.as_deref()
    }

    /// Whether the server accepted 0-RTT for this connection (echoed `early_data`).
    #[allow(dead_code)] // 0-RTT acceptance inspection; exercised by the server handshake tests
    pub fn is_early_data_accepted(&self) -> bool {
        self.early_data_accepted
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
        if let Some(keys) = self.pending_0rtt_keys.take() {
            // 0-RTT open keys, installed before the ServerHello so the transport can
            // decrypt early-data packets that arrived alongside the ClientHello.
            return Some(KeyChange::ZeroRtt { keys });
        }
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
        if !self.pending_post_handshake.is_empty() {
            // The NewSessionTicket rides 1-RTT CRYPTO, emitted after the OneRtt
            // KeyChange so the connection seals it with the application keys.
            out.append(&mut self.pending_post_handshake);
            return None;
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
                self.issue_session_ticket()?;
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

        // Origin-splice auth marker: when a marker key is set, verify the covert
        // marker in ClientHello.random; the endpoint's terminate-vs-splice fork
        // consults [`Self::marker_result`]. The client's ephemeral X25519 public is
        // the trailing 32 bytes of the X25519MLKEM768 key_share, and the ECDH mirrors
        // the client's (server static private x client ephemeral). Constant-work: a
        // full X25519 (zero share when the key_share is too short) + the marker open
        // always run, so a failed verify takes the same path as a success (no
        // terminate-vs-splice timing fork). `marker_dcid` (this Initial's DCID, set by
        // the endpoint before the CH is processed) is bound into the MAC so a marker
        // captured for one DCID fails to verify on another (issue #74).
        if let Some((psk, static_priv)) = &self.marker_key {
            let mut client_x25519 = [0u8; 32];
            let share = &summary.hybrid_key_share;
            if share.len() >= 32 {
                client_x25519.copy_from_slice(&share[share.len() - 32..]);
            }
            let ss = crate::crypto::session::x25519_shared_secret(static_priv, &client_x25519);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.marker_result = crate::crypto::quic_marker::open(
                psk,
                &ss,
                &summary.sni,
                &self.marker_dcid,
                &summary.client_random,
                now,
                MARKER_WINDOW_SECS,
            );
        }

        let (server_share, shared) = server_hybrid_kex(&summary.hybrid_key_share)?;

        // Decide 0-RTT resumption BEFORE consuming `summary`: validate the offered
        // PSK (ticket unseal + binder over the truncated ClientHello).
        let accepted_psk = self.try_accept_psk(&summary, message);
        self.peer_transport_params = Some(summary.transport_params.clone());

        let mut random = [0u8; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| QuicTlsError::Crypto("server random".into()))?;

        // transcript: ClientHello first.
        self.transcript.extend_from_slice(message);

        // Accepting 0-RTT: derive the early-data open keys (client_early_traffic_secret
        // over the full ClientHello) and queue them as a ZeroRtt KeyChange so the
        // transport can decrypt the client's early data.
        if let Some(psk) = accepted_psk.as_ref() {
            let early = early_secret_from_psk(self.suite, psk);
            let cet = client_early_traffic_secret(
                self.suite,
                &early,
                &self.suite.digest(&self.transcript),
            )?;
            self.pending_0rtt_keys = Some(Keys {
                local: DirectionalKeys::from_secret(self.suite, &cet)?,
                remote: DirectionalKeys::from_secret(self.suite, &cet)?,
            });
            self.early_data_accepted = true;
        }

        let server_hello = build_server_hello(
            &summary.legacy_session_id,
            &server_share,
            &random,
            accepted_psk.is_some(),
        );
        self.transcript.extend_from_slice(&server_hello);
        let hash_sh = self.suite.digest(&self.transcript);
        let (mut schedule, hs_keys) = KeySchedule::after_server_hello(
            self.suite,
            accepted_psk.as_ref().map(|p| p.as_slice()),
            &shared,
            &hash_sh,
        )?;

        // RFC 7301: select the first local ALPN protocol the client actually
        // offered; a peer that shares none gets no_application_protocol rather than
        // an unoffered protocol (which a compliant client would reject).
        let alpn = self
            .alpn_protocols
            .iter()
            .find(|p| summary.offered_alpn.iter().any(|o| o == *p))
            .cloned()
            .ok_or_else(|| {
                QuicTlsError::alert(
                    ALERT_NO_APPLICATION_PROTOCOL,
                    "no overlapping ALPN protocol",
                )
            })?;
        self.selected_alpn = Some(alpn.clone());
        let ee = build_encrypted_extensions(&alpn, &self.transport_params, accepted_psk.is_some());
        self.transcript.extend_from_slice(&ee);

        let mut handshake_flight = ee;
        // A resumed (PSK) handshake authenticates via the PSK: it sends NO
        // Certificate / CertificateVerify (RFC 8446 §2.2). A full handshake signs
        // both with the cover cert's ECDSA P-256 key (RFC 8446 §4.4.3); the REALITY
        // client (AcceptAnyServerCert) does not verify it, but a real verifier — or
        // the differential oracle — accepts the valid signature.
        if accepted_psk.is_none() {
            let cert = build_certificate(&self.cert_chain);
            self.transcript.extend_from_slice(&cert);
            let hash_cert = self.suite.digest(&self.transcript);
            let content = certificate_verify_content(&hash_cert);
            let signature = self
                .signing_key
                .sign(&SystemRandom::new(), &content)
                .map_err(|_| QuicTlsError::Crypto("CertificateVerify signing".into()))?;
            let cv = build_certificate_verify(SIG_SCHEME_ECDSA_P256, signature.as_ref());
            self.transcript.extend_from_slice(&cv);
            handshake_flight.extend_from_slice(&cert);
            handshake_flight.extend_from_slice(&cv);
        }

        // Server Finished MAC over the transcript through the last flight message
        // (CertificateVerify for a full handshake, EncryptedExtensions for a resumed).
        let hash_pre_finished = self.suite.digest(&self.transcript);
        let server_verify = schedule.server_finished_verify_data(&hash_pre_finished)?;
        let fin = build_finished(&server_verify);
        self.transcript.extend_from_slice(&fin);
        handshake_flight.extend_from_slice(&fin);

        let hash_sf = self.suite.digest(&self.transcript);
        let onertt = schedule.derive_application(&hash_sf)?;
        self.expected_client_finished = Some(schedule.client_finished_verify_data(&hash_sf)?);

        self.schedule = Some(schedule);
        self.pending_server_hello = Some(server_hello);
        self.pending_handshake_keys = Some(swap(hs_keys));
        self.pending_handshake_flight = Some(handshake_flight);
        self.pending_1rtt_keys = Some(swap(onertt));
        Ok(())
    }

    /// Validate a resuming client's `pre_shared_key` for 0-RTT: unseal the ticket
    /// under the STEK, check expiry + suite + ALPN, and verify the PSK binder over
    /// the ClientHello truncated before the binders (RFC 8446 §4.2.11.2). Returns the
    /// resumption PSK on success, or `None` to fall back to a full handshake (no
    /// STEK, no `early_data` offer, bad ticket, expired, or binder mismatch).
    fn try_accept_psk(
        &self,
        summary: &ClientHelloSummary,
        ch_message: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let stek = self.stek.as_ref()?;
        // ParallaX only resumes for 0-RTT (the Safari case): a PSK without
        // early_data falls back to a full handshake.
        if !summary.offers_early_data {
            return None;
        }
        let identity = summary.psk_identity.as_deref()?;
        let binder = summary.psk_binder.as_deref()?;
        let binders_wire_len = summary.psk_binders_wire_len?;

        let ticket = open_ticket(stek, identity)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if ticket.is_expired(now) {
            return None;
        }
        // The resumed suite must match the ticket's (binder + early keys use it).
        if ticket.suite != self.suite.to_u16() {
            return None;
        }
        // The client must still offer the ticket's ALPN.
        if !summary.offered_alpn.iter().any(|a| a == &ticket.alpn) {
            return None;
        }
        // Verify the binder over the ClientHello truncated before the binders list:
        // remove binders_len(2) + the binders content.
        let truncate_to = ch_message.len().checked_sub(2 + binders_wire_len)?;
        let truncated = &ch_message[..truncate_to];
        let early = early_secret_from_psk(self.suite, &ticket.psk);
        let fk = binder_finished_key(self.suite, &early).ok()?;
        let expected = psk_binder(self.suite, &fk, &self.suite.digest(truncated)).ok()?;
        if !bool::from(expected.ct_eq(binder)) {
            return None;
        }
        // Single-use anti-replay (RFC 8446 §8): consult the guard only AFTER the
        // binder verifies, so a bad-binder probe cannot burn a ticket. A replayed
        // (already-used) ticket is rejected here → the client falls back to 1-RTT.
        if let Some(guard) = self.replay_guard.as_ref() {
            if !guard.accept_ticket(identity, now) {
                return None;
            }
        }
        // `ticket.psk` is already `Zeroizing<Vec<u8>>`; move it out (TicketState has
        // no Drop, so the move is allowed) and the caller's copy scrubs on drop.
        Some(ticket.psk)
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

    /// Once the handshake completes, seal a single-use resumption ticket and queue
    /// the NewSessionTicket as post-handshake (1-RTT) CRYPTO. No-op when no STEK is
    /// configured (cold-start-only server). `transcript` already runs through the
    /// client Finished, so `resumption_master_secret` matches the client's.
    fn issue_session_ticket(&mut self) -> Result<(), QuicTlsError> {
        let Some(stek) = self.stek.as_ref() else {
            return Ok(());
        };
        let schedule = self
            .schedule
            .as_ref()
            .ok_or_else(|| QuicTlsError::Crypto("session ticket before schedule".into()))?;
        let transcript_hash = self.suite.digest(&self.transcript);
        let res_master = schedule.resumption_master_secret(&transcript_hash)?;
        // Empty ticket nonce: Safari 26.4's NewSessionTicket carries nonce len 0.
        let psk = resumption_psk(self.suite, &res_master, &[])?;
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut state = TicketState {
            suite: self.suite.to_u16(),
            alpn: self.selected_alpn.clone().unwrap_or_default(),
            psk: Zeroizing::new(psk.to_vec()),
            issued_at,
            lifetime_secs: TICKET_LIFETIME_SECS,
        };
        let sealed = seal_ticket(stek, &state)?;
        // The plaintext PSK copy held in `state` is no longer needed; scrub it.
        state.psk.zeroize();
        let mut age_add = [0_u8; 4];
        SystemRandom::new()
            .fill(&mut age_add)
            .map_err(|_| QuicTlsError::Crypto("ticket age_add".into()))?;
        let nst = NewSessionTicket {
            lifetime_secs: TICKET_LIFETIME_SECS,
            age_add: u32::from_be_bytes(age_add),
            nonce: Vec::new(),
            ticket: sealed,
            max_early_data: Some(QUIC_MAX_EARLY_DATA),
        };
        self.pending_post_handshake = encode_new_session_ticket(&nst)?;
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
            ClientHandshake::new(config, QUIC_VERSION_V1, "example.com", tp_blob.clone(), &[])
                .unwrap();

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

    /// Build a real QUIC ClientHello body (handshake message minus the 4-byte
    /// header), for malformed-input strictness tests below.
    fn real_client_hello_body() -> Vec<u8> {
        use crate::tls::quic::{
            AcceptAnyServerCert, ClientConfig, ClientHandshake, QUIC_VERSION_V1,
        };
        use std::sync::Arc;
        let config = Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ));
        let mut engine = ClientHandshake::new(
            config,
            QUIC_VERSION_V1,
            "example.com",
            vec![0xde, 0xad, 0xbe, 0xef],
            &[],
        )
        .unwrap();
        let mut msg = Vec::new();
        let _ = engine.write_handshake(&mut msg);
        msg[4..].to_vec()
    }

    #[test]
    fn parser_rejects_trailing_bytes_after_extensions() {
        // PAR-26: a real TLS stack does not leave bytes after the extensions vector;
        // the client-side parser rejects this, so the server must too (active-probe
        // distinguisher otherwise). The clean body parses; the same body with one
        // trailing byte is a decode error.
        let body = real_client_hello_body();
        assert!(parse_client_hello(&body).is_ok(), "clean body parses");
        let mut trailing = body.clone();
        trailing.push(0x00);
        let Err(err) = parse_client_hello(&trailing) else {
            panic!("trailing-byte ClientHello must be rejected");
        };
        assert_eq!(err.alert_description(), Some(ALERT_DECODE_ERROR));
    }

    #[test]
    fn parser_rejects_odd_length_cipher_suites() {
        // PAR-26: cipher_suites is a vector of 2-byte values; an odd length is
        // malformed and must be rejected rather than silently dropping the last byte
        // via chunks_exact(2). We locate the cipher_suites length field in a real
        // ClientHello and bump it by one (claiming an odd byte count), then add the
        // stray byte so the outer framing still parses up to the cipher_suites field.
        let body = real_client_hello_body();
        // Body layout: legacy_version(2) | random(32) | session_id(u8-len + bytes) |
        // cipher_suites(u16-len + bytes) | ...
        let sid_len = body[34] as usize;
        let cs_len_off = 2 + 32 + 1 + sid_len; // offset of the cipher_suites u16 length
        let cs_len = u16::from_be_bytes([body[cs_len_off], body[cs_len_off + 1]]) as usize;
        // Construct a malformed body: prefix up to and including the cipher_suites
        // bytes, but with the length field set to an ODD value (cs_len + 1) and one
        // extra byte appended to the cipher_suites region so `take` succeeds and the
        // odd-length check is what fires.
        let mut bad = body.clone();
        let odd = (cs_len + 1) as u16;
        bad[cs_len_off..cs_len_off + 2].copy_from_slice(&odd.to_be_bytes());
        bad.insert(cs_len_off + 2 + cs_len, 0x00); // the stray odd byte
        let Err(err) = parse_client_hello(&bad) else {
            panic!("odd-length cipher_suites must be rejected");
        };
        assert_eq!(err.alert_description(), Some(ALERT_DECODE_ERROR));
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
            None,
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
            &[],
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

    #[test]
    fn server_issues_resumption_ticket_both_ends_agree_on_psk() {
        use crate::tls::quic::schedule::resumption_psk;
        use crate::tls::quic::ticket::{
            decode_new_session_ticket, open_ticket, HANDSHAKE_NEW_SESSION_TICKET,
        };
        use crate::tls::quic::{
            AcceptAnyServerCert, ClientConfig, ClientHandshake, QUIC_VERSION_V1,
        };
        use std::sync::Arc;

        // Drain a handshake's write side, accumulating all CRYPTO bytes it emits.
        fn drain(mut write: impl FnMut(&mut Vec<u8>) -> Option<KeyChange>) -> Vec<u8> {
            let mut all = Vec::new();
            loop {
                let mut b = Vec::new();
                let kc = write(&mut b);
                if b.is_empty() && kc.is_none() {
                    break;
                }
                all.extend_from_slice(&b);
            }
            all
        }

        let cert_chain = vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]];
        let key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let stek = Zeroizing::new([0x5c_u8; 32]);
        let mut server = ServerHandshake::new(
            cert_chain,
            key.as_ref(),
            vec![b"h3".to_vec()],
            vec![0x01, 0x02, 0x03, 0x04],
            Some(stek.clone()),
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
            &[],
        )
        .unwrap();

        let ch = drain(|b| client.write_handshake(b));
        server.read_handshake(&ch).unwrap();
        let flight = drain(|b| server.write_handshake(b));
        client.read_handshake(&flight).unwrap();
        let client_fin = drain(|b| client.write_handshake(b));
        server.read_handshake(&client_fin).unwrap();
        assert!(!server.is_handshaking());
        assert!(!client.is_handshaking());

        // The server emits a NewSessionTicket as post-handshake (1-RTT) CRYPTO.
        let post = drain(|b| server.write_handshake(b));
        assert!(
            !post.is_empty(),
            "server emits a NewSessionTicket after completion"
        );
        assert_eq!(post[0], HANDSHAKE_NEW_SESSION_TICKET);
        let body_len = ((post[1] as usize) << 16) | ((post[2] as usize) << 8) | (post[3] as usize);
        let nst = decode_new_session_ticket(&post[4..4 + body_len]).unwrap();
        assert_eq!(nst.lifetime_secs, 604_800);
        assert!(nst.nonce.is_empty(), "Safari NST carries an empty nonce");
        assert_eq!(nst.max_early_data, Some(0xFFFF_FFFF));

        // Open the sealed ticket and confirm both ends derive the SAME resumption
        // PSK — the property the whole 0-RTT resumption rests on.
        let state = open_ticket(&stek, &nst.ticket).expect("ticket opens under the STEK");
        assert_eq!(state.suite, 0x1301);
        assert_eq!(state.alpn, b"h3");
        assert_eq!(state.lifetime_secs, 604_800);
        assert_eq!(state.psk.len(), 32);
        let client_res_master = client.resumption_master_secret().unwrap();
        let client_psk =
            resumption_psk(CipherSuite::Aes128GcmSha256, &client_res_master, &[]).unwrap();
        assert_eq!(
            &client_psk[..],
            &state.psk[..],
            "client and server derive the same resumption PSK"
        );
    }

    #[test]
    fn full_0rtt_resumption_round_trip() {
        use crate::tls::quic::keys::AEAD_TAG_LEN;
        use crate::tls::quic::schedule::resumption_psk;
        use crate::tls::quic::ticket::{decode_new_session_ticket, ClientTicket};
        use crate::tls::quic::{
            AcceptAnyServerCert, ClientConfig, ClientHandshake, QUIC_VERSION_V1,
        };
        use std::sync::Arc;

        // Drain a handshake's write side, accumulating CRYPTO bytes and capturing the
        // first ZeroRtt KeyChange's keys (0-RTT write keys on the client, open keys
        // on the server).
        fn drain(
            mut write: impl FnMut(&mut Vec<u8>) -> Option<KeyChange>,
        ) -> (Vec<u8>, Option<Keys>) {
            let mut all = Vec::new();
            let mut zerortt = None;
            loop {
                let mut b = Vec::new();
                let kc = write(&mut b);
                let kc_is_none = kc.is_none();
                if let Some(KeyChange::ZeroRtt { keys }) = kc {
                    zerortt = Some(keys);
                }
                if b.is_empty() && kc_is_none {
                    break;
                }
                all.extend_from_slice(&b);
            }
            (all, zerortt)
        }

        let cert_chain = vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]];
        let key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let stek = Zeroizing::new([0x5c_u8; 32]);
        let server_tp = vec![0x01, 0x02, 0x03, 0x04];
        let client_config = Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ));

        // --- 1. Cold-start handshake to obtain a NewSessionTicket. -------------
        let mut server = ServerHandshake::new(
            cert_chain.clone(),
            key.as_ref(),
            vec![b"h3".to_vec()],
            server_tp.clone(),
            Some(stek.clone()),
        )
        .unwrap();
        let mut client = ClientHandshake::new(
            client_config.clone(),
            QUIC_VERSION_V1,
            "example.com",
            vec![0xaa],
            &[],
        )
        .unwrap();
        let (ch, _) = drain(|b| client.write_handshake(b));
        server.read_handshake(&ch).unwrap();
        let (flight, _) = drain(|b| server.write_handshake(b));
        client.read_handshake(&flight).unwrap();
        let (client_fin, _) = drain(|b| client.write_handshake(b));
        server.read_handshake(&client_fin).unwrap();
        let (post, _) = drain(|b| server.write_handshake(b));
        let body_len = ((post[1] as usize) << 16) | ((post[2] as usize) << 8) | (post[3] as usize);
        let nst = decode_new_session_ticket(&post[4..4 + body_len]).unwrap();
        let client_res_master = client.resumption_master_secret().unwrap();
        let client_psk =
            resumption_psk(CipherSuite::Aes128GcmSha256, &client_res_master, &nst.nonce).unwrap();
        let ticket = ClientTicket {
            ticket: nst.ticket.clone(),
            psk: client_psk,
            suite: 0x1301,
            alpn: b"h3".to_vec(),
            peer_transport_params: server_tp.clone(),
            age_add: nst.age_add,
            lifetime_secs: nst.lifetime_secs,
            received_at_ms: 1_000_000,
        };

        // --- 2. 0-RTT resumption handshake using that ticket. -----------------
        let mut server2 = ServerHandshake::new(
            cert_chain,
            key.as_ref(),
            vec![b"h3".to_vec()],
            server_tp.clone(),
            Some(stek.clone()),
        )
        .unwrap();
        let mut client2 = ClientHandshake::new_resumption(
            client_config,
            QUIC_VERSION_V1,
            "example.com",
            vec![0xaa],
            &[],
            &ticket,
            1_005_000,
        )
        .unwrap();

        let (ch2, client_0rtt) = drain(|b| client2.write_handshake(b));
        assert!(
            client_0rtt.is_some(),
            "client emits 0-RTT write keys after the CH"
        );
        server2.read_handshake(&ch2).unwrap();
        let (flight2, server_0rtt) = drain(|b| server2.write_handshake(b));
        assert!(
            server_0rtt.is_some(),
            "server emits 0-RTT open keys (PSK accepted)"
        );
        client2.read_handshake(&flight2).unwrap();
        let (client_fin2, _) = drain(|b| client2.write_handshake(b));
        server2.read_handshake(&client_fin2).unwrap();

        assert!(
            !client2.is_handshaking(),
            "client completed the resumed handshake"
        );
        assert!(
            !server2.is_handshaking(),
            "server completed the resumed handshake"
        );
        assert!(
            client2.is_early_data_accepted(),
            "client saw early_data accepted"
        );
        assert!(server2.is_early_data_accepted(), "server accepted 0-RTT");

        // The 1-RTT exporter still agrees on the resumed handshake.
        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        client2
            .export_keying_material(&mut ce, b"parallax tudp", b"ctx")
            .unwrap();
        server2
            .export_keying_material(&mut se, b"parallax tudp", b"ctx")
            .unwrap();
        assert_eq!(ce, se, "resumed handshake exporters match");

        // The 0-RTT keys agree: the client seals early data with its write key and
        // the server opens it with its open key.
        let client_0rtt = client_0rtt.unwrap();
        let server_0rtt = server_0rtt.unwrap();
        let plaintext = b"the 0-RTT early data";
        let mut buf = plaintext.to_vec();
        buf.extend_from_slice(&[0u8; AEAD_TAG_LEN]);
        client_0rtt
            .local
            .packet
            .encrypt_in_place(0, b"0-rtt-header", &mut buf)
            .unwrap();
        let opened = server_0rtt
            .remote
            .packet
            .decrypt_in_place(0, b"0-rtt-header", &mut buf)
            .unwrap();
        assert_eq!(
            opened, plaintext,
            "server 0-RTT key opens the client's early data"
        );
    }

    /// Issue #74: the auth marker is cryptographically bound to the first-Initial
    /// DCID. A marker minted by a client for DCID-A verifies only against a server
    /// that bound the SAME DCID; binding a different DCID (a captured marker lifted
    /// onto another routing identity) yields no marker (the endpoint then splices it).
    #[test]
    fn marker_is_bound_to_the_initial_dcid() {
        use crate::tls::quic::{
            AcceptAnyServerCert, ClientConfig, ClientHandshake, QuicMarkerConfig, QUIC_VERSION_V1,
        };
        use std::sync::Arc;

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

        const DCID_A: &[u8] = &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        const DCID_B: &[u8] = &[0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00];

        let server_kp = X25519KeyPair::generate();
        let psk: Zeroizing<Vec<u8>> = Zeroizing::new(b"parallax-quic-marker-dcid-bind".to_vec());

        // A client that hides a marker in its ClientHello.random, sealed against DCID_A.
        let client_config = Arc::new(
            ClientConfig::new(Arc::new(AcceptAnyServerCert), vec![b"h3".to_vec()]).with_marker(
                QuicMarkerConfig {
                    psk: psk.clone(),
                    server_static_public: server_kp.public,
                },
            ),
        );
        let mut client = ClientHandshake::new(
            client_config,
            QUIC_VERSION_V1,
            "example.com",
            vec![0x01, 0x02, 0x03, 0x04],
            DCID_A,
        )
        .unwrap();
        let ch = drain_client(&mut client);

        let build_server = |bound_dcid: &[u8]| {
            let cert_chain = vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]];
            let key =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                    .unwrap();
            let mut server = ServerHandshake::new(
                cert_chain,
                key.as_ref(),
                vec![b"h3".to_vec()],
                vec![0x05, 0x06, 0x07, 0x08],
                None,
            )
            .unwrap();
            server.set_marker_key(
                psk.clone(),
                Zeroizing::new(server_kp.private),
                bound_dcid.to_vec(),
            );
            server.read_handshake(&ch).unwrap();
            server
        };

        // Matching DCID: the marker verifies (a real, correctly-routed ParallaX client).
        let server_match = build_server(DCID_A);
        assert!(
            server_match.marker_result().is_some(),
            "marker bound to DCID_A verifies against a server that bound DCID_A"
        );

        // Wrong DCID: the same ClientHello yields no marker, so the endpoint splices it.
        let server_wrong = build_server(DCID_B);
        assert!(
            server_wrong.marker_result().is_none(),
            "marker bound to DCID_A is rejected when verified against DCID_B (issue #74)"
        );
    }
}
