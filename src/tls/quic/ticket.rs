//! 0-RTT session tickets: the server-side STEK seal/open, the NewSessionTicket
//! wire codec (RFC 8446 §4.6.1 + RFC 9001 §4.6.1), and the client-retained
//! [`ClientTicket`].
//!
//! ParallaX's QUIC server is stateless across connections: a NewSessionTicket's
//! opaque `ticket` is an AEAD-sealed [`TicketState`] (the resumption PSK plus the
//! parameters needed to resume), sealed under a Session-Ticket Encryption Key
//! (STEK). The server validates a resumed (0-RTT) ClientHello with no session
//! database. The STEK is derived per-server from the host key, so a ticket sealed
//! by one server never opens on another — cross-server 0-RTT replay fails closed
//! at unseal (RFC 8446 §8.1, the user's "GFW replays elsewhere" concern). The
//! sealed ticket is padded to a fixed length inside Safari 26.4's observed
//! resumption-ticket range (157–160 B) so the wire `pre_shared_key` identity
//! length is browser-plausible, not a ParallaX constant.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

use super::QuicTlsError;

/// XChaCha20-Poly1305 nonce length.
const STEK_NONCE_LEN: usize = 24;
/// AEAD tag length.
const TAG_LEN: usize = 16;
/// Fixed sealed-ticket length on the wire, inside Safari 26.4's observed
/// resumption-ticket range (157–160 B), so the `pre_shared_key` identity length is
/// browser-plausible rather than a ParallaX tell.
pub(crate) const SEALED_TICKET_LEN: usize = 160;
/// Sealed plaintext length: total minus the nonce and AEAD tag (= 120).
const PLAINTEXT_LEN: usize = SEALED_TICKET_LEN - STEK_NONCE_LEN - TAG_LEN;
/// AAD binding the sealed blob to its purpose so a ticket cannot be confused with
/// any other STEK-sealed object.
const TICKET_AAD: &[u8] = b"ParallaX v1 QUIC 0-RTT ticket";
/// HKDF-SHA256 info for deriving the STEK from the host key.
const STEK_HKDF_INFO: &[u8] = b"parallax-quic-0rtt-stek-v1";
/// Ticket plaintext format version.
const TICKET_VERSION: u8 = 1;

/// NewSessionTicket handshake-message type (RFC 8446 §4.6.1).
pub(crate) const HANDSHAKE_NEW_SESSION_TICKET: u8 = 0x04;
/// `early_data` extension codepoint (RFC 8446 §4.2.10); in a NewSessionTicket its
/// body is the `max_early_data_size` (RFC 9001 §4.6.1 requires 0xFFFFFFFF for QUIC).
pub(crate) const EXT_EARLY_DATA: u16 = 0x002a;
/// The `max_early_data_size` a QUIC server MUST advertise (RFC 9001 §4.6.1); the
/// real early-data bound is the transport parameters remembered from the prior
/// connection, not this value.
pub(crate) const QUIC_MAX_EARLY_DATA: u32 = 0xFFFF_FFFF;

/// Derive the per-server STEK from the 32-byte host key (see
/// [`crate::secret_store`]). Distinct HKDF info keeps it independent of the
/// config-sealing KEKs.
pub(crate) fn derive_stek(host_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, host_key);
    let mut out = Zeroizing::new([0_u8; 32]);
    hkdf.expand(STEK_HKDF_INFO, out.as_mut_slice())
        .expect("HKDF-SHA256 expand of 32 bytes never fails");
    out
}

/// The resume-time state sealed inside an opaque ticket — everything the server
/// needs to validate a resumed ClientHello and accept 0-RTT. `Debug` redacts the
/// PSK so it never reaches a log.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TicketState {
    /// Negotiated cipher-suite codepoint (selects the hash for binder/early keys).
    pub suite: u16,
    /// Negotiated ALPN (e.g. `b"h3"`); the resumed ClientHello must still offer it.
    pub alpn: Vec<u8>,
    /// The resumption PSK (`resumption_psk`), hash-length (32 or 48 B). Wrapped in
    /// `Zeroizing` so the decrypted PSK is scrubbed when a `TicketState` is dropped —
    /// covering every `try_accept_psk` reject path (expired / suite / ALPN / binder /
    /// replay), where the state is dropped without an explicit scrub.
    pub psk: Zeroizing<Vec<u8>>,
    /// Unix seconds when the ticket was issued (freshness / expiry).
    pub issued_at: u64,
    /// Ticket lifetime in seconds (RFC 8446 §4.6.1 caps at 604800 = 7 d).
    pub lifetime_secs: u32,
}

impl fmt::Debug for TicketState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketState")
            .field("suite", &format_args!("{:#06x}", self.suite))
            .field("alpn", &self.alpn)
            .field("psk", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("lifetime_secs", &self.lifetime_secs)
            .finish()
    }
}

impl TicketState {
    /// Whether the ticket is past its lifetime at `now_unix` (seconds).
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.issued_at.saturating_add(u64::from(self.lifetime_secs))
    }
}

/// Seal a [`TicketState`] into the fixed-length opaque ticket carried on the wire.
pub(crate) fn seal_ticket(stek: &[u8; 32], state: &TicketState) -> Result<Vec<u8>, QuicTlsError> {
    let mut content = Zeroizing::new(Vec::with_capacity(PLAINTEXT_LEN));
    content.push(TICKET_VERSION);
    content.extend_from_slice(&state.suite.to_be_bytes());
    push_u8_vec(&mut content, &state.alpn)?;
    push_u8_vec(&mut content, &state.psk)?;
    content.extend_from_slice(&state.issued_at.to_be_bytes());
    content.extend_from_slice(&state.lifetime_secs.to_be_bytes());

    // plaintext = content_len(u16) || content || zero padding to PLAINTEXT_LEN.
    if content.len() + 2 > PLAINTEXT_LEN {
        return Err(QuicTlsError::Crypto(
            "0-RTT ticket state exceeds fixed length".into(),
        ));
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(PLAINTEXT_LEN));
    plaintext.extend_from_slice(&(content.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(&content);
    plaintext.resize(PLAINTEXT_LEN, 0);

    let mut nonce = [0_u8; STEK_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(stek));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: TICKET_AAD,
            },
        )
        .map_err(|_| QuicTlsError::Crypto("0-RTT ticket seal failed".into()))?;

    let mut sealed = Vec::with_capacity(SEALED_TICKET_LEN);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    debug_assert_eq!(sealed.len(), SEALED_TICKET_LEN);
    Ok(sealed)
}

/// Open an opaque ticket back to its [`TicketState`]. Returns `None` on any
/// failure (wrong STEK, tamper, wrong length, malformed) so the caller can fall
/// back to a full handshake instead of failing the connection.
pub(crate) fn open_ticket(stek: &[u8; 32], sealed: &[u8]) -> Option<TicketState> {
    if sealed.len() != SEALED_TICKET_LEN {
        return None;
    }
    let (nonce, ciphertext) = sealed.split_at(STEK_NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(stek));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: TICKET_AAD,
                },
            )
            .ok()?,
    );
    parse_ticket_state(&plaintext)
}

fn parse_ticket_state(plaintext: &[u8]) -> Option<TicketState> {
    let mut r = Reader::new(plaintext);
    let content_len = r.u16()? as usize;
    let content = r.take(content_len)?;
    let mut c = Reader::new(content);
    if c.u8()? != TICKET_VERSION {
        return None;
    }
    let suite = c.u16()?;
    let alpn = c.vec_u8()?.to_vec();
    let psk = Zeroizing::new(c.vec_u8()?.to_vec());
    let issued_at = c.u64()?;
    let lifetime_secs = c.u32()?;
    if c.remaining() != 0 {
        return None;
    }
    Some(TicketState {
        suite,
        alpn,
        psk,
        issued_at,
        lifetime_secs,
    })
}

/// A parsed NewSessionTicket (RFC 8446 §4.6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NewSessionTicket {
    pub lifetime_secs: u32,
    pub age_add: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    /// `max_early_data_size` from the `early_data` extension, if present.
    pub max_early_data: Option<u32>,
}

/// Encode a NewSessionTicket as a handshake message (`type 0x04 || u24 len || body`),
/// for the server to send on the 1-RTT CRYPTO stream.
pub(crate) fn encode_new_session_ticket(nst: &NewSessionTicket) -> Result<Vec<u8>, QuicTlsError> {
    let mut body = Vec::new();
    body.extend_from_slice(&nst.lifetime_secs.to_be_bytes());
    body.extend_from_slice(&nst.age_add.to_be_bytes());
    push_u8_vec(&mut body, &nst.nonce)?;
    push_u16_vec(&mut body, &nst.ticket)?;

    let mut exts = Vec::new();
    if let Some(max) = nst.max_early_data {
        exts.extend_from_slice(&EXT_EARLY_DATA.to_be_bytes());
        push_u16_vec(&mut exts, &max.to_be_bytes())?;
    }
    push_u16_vec(&mut body, &exts)?;

    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(HANDSHAKE_NEW_SESSION_TICKET);
    push_u24(&mut msg, body.len())?;
    msg.extend_from_slice(&body);
    Ok(msg)
}

/// Decode a NewSessionTicket message body (WITHOUT the 4-byte handshake header).
pub(crate) fn decode_new_session_ticket(body: &[u8]) -> Option<NewSessionTicket> {
    let mut r = Reader::new(body);
    let lifetime_secs = r.u32()?;
    let age_add = r.u32()?;
    let nonce = r.vec_u8()?.to_vec();
    let ticket = r.vec_u16()?.to_vec();
    let exts = r.vec_u16()?;
    if r.remaining() != 0 {
        return None;
    }
    let mut max_early_data = None;
    let mut er = Reader::new(exts);
    while er.remaining() > 0 {
        let ext_type = er.u16()?;
        let ext_body = er.vec_u16()?;
        if ext_type == EXT_EARLY_DATA {
            let mut br = Reader::new(ext_body);
            max_early_data = Some(br.u32()?);
            if br.remaining() != 0 {
                return None;
            }
        }
    }
    Some(NewSessionTicket {
        lifetime_secs,
        age_add,
        nonce,
        ticket,
        max_early_data,
    })
}

/// A ticket the client retains to drive a later 0-RTT resumption. Single-use: the
/// client offers it once, then drops it (S8 anti-replay relies on this). `Clone` is
/// derived so a replay scenario (an attacker resending a captured flight, or a test
/// presenting the same ticket twice) can be modelled; single-use is enforced by the
/// server's anti-replay guard, not by this type.
#[derive(Clone)]
pub struct ClientTicket {
    /// The opaque ticket bytes, sent back verbatim as the `pre_shared_key` identity.
    pub ticket: Vec<u8>,
    /// The resumption PSK the client derived (= the server's sealed PSK).
    pub psk: Zeroizing<Vec<u8>>,
    /// Negotiated cipher suite (selects the hash for binder/early keys).
    pub suite: u16,
    /// Negotiated ALPN, re-offered on resumption.
    pub alpn: Vec<u8>,
    /// The server's transport parameters from the original connection; these bound
    /// how much 0-RTT data the client may send (RFC 9001 §4.6.1 / §7.4.1).
    pub peer_transport_params: Vec<u8>,
    /// `ticket_age_add` from the NewSessionTicket, added into `obfuscated_ticket_age`.
    pub age_add: u32,
    /// Ticket lifetime in seconds.
    pub lifetime_secs: u32,
    /// Unix-millisecond time the client received the ticket (the ticket-age epoch).
    pub received_at_ms: u64,
}

impl fmt::Debug for ClientTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientTicket")
            .field("ticket_len", &self.ticket.len())
            .field("psk", &"<redacted>")
            .field("suite", &format_args!("{:#06x}", self.suite))
            .field("alpn", &self.alpn)
            .field("age_add", &self.age_add)
            .field("lifetime_secs", &self.lifetime_secs)
            .field("received_at_ms", &self.received_at_ms)
            .finish()
    }
}

impl ClientTicket {
    /// Whether the ticket is past its lifetime at `now_ms` (Unix milliseconds).
    pub fn is_expired(&self, now_ms: u64) -> bool {
        let age_secs = now_ms.saturating_sub(self.received_at_ms) / 1000;
        age_secs >= u64::from(self.lifetime_secs)
    }

    /// `obfuscated_ticket_age = (ticket_age_ms + ticket_age_add) mod 2^32`
    /// (RFC 8446 §4.2.11.1), where `ticket_age_ms = now_ms - received_at_ms`.
    pub fn obfuscated_ticket_age(&self, now_ms: u64) -> u32 {
        let age_ms = now_ms.saturating_sub(self.received_at_ms) as u32;
        age_ms.wrapping_add(self.age_add)
    }
}

// --- minimal big-endian helpers -----------------------------------------------

fn push_u8_vec(out: &mut Vec<u8>, body: &[u8]) -> Result<(), QuicTlsError> {
    let len = u8::try_from(body.len())
        .map_err(|_| QuicTlsError::Crypto("ticket u8 vector too long".into()))?;
    out.push(len);
    out.extend_from_slice(body);
    Ok(())
}

fn push_u16_vec(out: &mut Vec<u8>, body: &[u8]) -> Result<(), QuicTlsError> {
    let len = u16::try_from(body.len())
        .map_err(|_| QuicTlsError::Crypto("ticket u16 vector too long".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

fn push_u24(out: &mut Vec<u8>, len: usize) -> Result<(), QuicTlsError> {
    if len > 0x00ff_ffff {
        return Err(QuicTlsError::Crypto("ticket message too large".into()));
    }
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    Ok(())
}

/// Minimal big-endian reader returning `None` on any short read.
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
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        let mut a = [0_u8; 8];
        a.copy_from_slice(s);
        Some(u64::from_be_bytes(a))
    }
    fn vec_u8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec_u16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> TicketState {
        TicketState {
            suite: 0x1301,
            alpn: b"h3".to_vec(),
            psk: Zeroizing::new(vec![0x5a_u8; 32]),
            issued_at: 1_700_000_000,
            lifetime_secs: 604_800,
        }
    }

    #[test]
    fn seal_open_round_trips_and_is_fixed_length() {
        let stek = [0x11_u8; 32];
        let state = sample_state();
        let sealed = seal_ticket(&stek, &state).unwrap();
        assert_eq!(
            sealed.len(),
            SEALED_TICKET_LEN,
            "ticket is fixed wire length"
        );
        let opened = open_ticket(&stek, &sealed).unwrap();
        assert_eq!(opened, state);
    }

    #[test]
    fn seal_open_round_trips_sha384_psk() {
        let stek = [0x22_u8; 32];
        let state = TicketState {
            suite: 0x1302,
            alpn: b"h3".to_vec(),
            psk: Zeroizing::new(vec![0x77_u8; 48]),
            issued_at: 1_700_000_500,
            lifetime_secs: 7200,
        };
        let sealed = seal_ticket(&stek, &state).unwrap();
        assert_eq!(sealed.len(), SEALED_TICKET_LEN);
        assert_eq!(open_ticket(&stek, &sealed).unwrap(), state);
    }

    #[test]
    fn open_with_wrong_stek_fails_closed() {
        let sealed = seal_ticket(&[0x11_u8; 32], &sample_state()).unwrap();
        assert!(open_ticket(&[0x99_u8; 32], &sealed).is_none());
    }

    #[test]
    fn tampered_ticket_fails_closed() {
        let stek = [0x33_u8; 32];
        let mut sealed = seal_ticket(&stek, &sample_state()).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open_ticket(&stek, &sealed).is_none());
        // Wrong length is rejected too.
        assert!(open_ticket(&stek, &sealed[..sealed.len() - 1]).is_none());
    }

    #[test]
    fn cross_server_stek_does_not_open_ticket() {
        // Distinct host keys -> distinct STEKs -> a ticket sealed on server A must
        // not open on server B (cross-server 0-RTT replay fails closed).
        let stek_a = derive_stek(&[0x01_u8; 32]);
        let stek_b = derive_stek(&[0x02_u8; 32]);
        assert_ne!(&stek_a[..], &stek_b[..]);
        let sealed = seal_ticket(&stek_a, &sample_state()).unwrap();
        assert!(open_ticket(&stek_b, &sealed).is_none());
        assert_eq!(open_ticket(&stek_a, &sealed).unwrap(), sample_state());
    }

    #[test]
    fn new_session_ticket_round_trips_with_early_data() {
        let nst = NewSessionTicket {
            lifetime_secs: 604_800,
            age_add: 0xEF1C_2D44,
            nonce: Vec::new(),
            ticket: vec![0xab_u8; SEALED_TICKET_LEN],
            max_early_data: Some(QUIC_MAX_EARLY_DATA),
        };
        let msg = encode_new_session_ticket(&nst).unwrap();
        assert_eq!(msg[0], HANDSHAKE_NEW_SESSION_TICKET);
        let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        assert_eq!(body_len, msg.len() - 4);
        let decoded = decode_new_session_ticket(&msg[4..]).unwrap();
        assert_eq!(decoded, nst);
        assert_eq!(decoded.max_early_data, Some(0xFFFF_FFFF));
    }

    #[test]
    fn new_session_ticket_round_trips_without_early_data() {
        let nst = NewSessionTicket {
            lifetime_secs: 7200,
            age_add: 1,
            nonce: vec![0x01, 0x02],
            ticket: vec![0xcd_u8; 64],
            max_early_data: None,
        };
        let msg = encode_new_session_ticket(&nst).unwrap();
        assert_eq!(decode_new_session_ticket(&msg[4..]).unwrap(), nst);
    }

    #[test]
    fn ticket_expiry_and_obfuscated_age() {
        let t = ClientTicket {
            ticket: vec![0; SEALED_TICKET_LEN],
            psk: Zeroizing::new(vec![0x5a; 32]),
            suite: 0x1301,
            alpn: b"h3".to_vec(),
            peer_transport_params: vec![0x04, 0x04],
            age_add: 1000,
            lifetime_secs: 7,
            received_at_ms: 10_000,
        };
        // 6s after receipt: live; obfuscated age = 6000 + 1000.
        assert!(!t.is_expired(16_000));
        assert_eq!(t.obfuscated_ticket_age(16_000), 7000);
        // 7s after receipt: expired.
        assert!(t.is_expired(17_000));
        // age_add wraps mod 2^32.
        let t2 = ClientTicket {
            age_add: u32::MAX,
            ..t
        };
        assert_eq!(t2.obfuscated_ticket_age(10_001), 0); // (1 + 0xffffffff) mod 2^32
    }

    #[test]
    fn state_debug_redacts_psk() {
        let dbg = format!("{:?}", sample_state());
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("5a5a5a"));
    }
}
