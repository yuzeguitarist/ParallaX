//! QUIC Initial packet decryption + SNI extraction.
//!
//! Real-world deployments of the GFW (and the leaked Geedge TSG appliance) ship
//! a QUIC Initial decryption path: long-header Initial packets are sniffed at
//! the border, the per-packet Initial keys are derived from the destination
//! connection ID per RFC 9001 §5.2, the header is unprotected, the payload is
//! decrypted with AES-128-GCM, the Crypto frames are reassembled into a TLS
//! ClientHello, and the SNI is extracted exactly like in TCP/443 traffic. On
//! match the (client IP, server IP, server port) 3-tuple is dropped for ~180 s
//! - long enough to make further QUIC handshake retries fail.
//!
//! This module implements the same path. Test vectors taken from RFC 9001
//! Appendix A.2 are used to verify byte-level conformance.
//!
//! ### References
//! - RFC 9000 - QUIC Transport
//! - RFC 9001 - Using TLS to Secure QUIC (Initial key derivation §5.2, AEAD
//!   §5.3, Header Protection §5.4, test vectors Appendix A)
//! - gfw.report/blog/quic_sni/ - QUIC SNI blocking measurement

use std::time::{Duration, Instant};

use aes::Aes128;
use aes_gcm::{
    aead::{Aead, KeyInit as GcmKeyInit, Payload},
    Aes128Gcm, Nonce,
};
use cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit as _};
use hkdf::Hkdf;
use sha2::Sha256;

use super::sni_filter::parse_client_hello;

/// QUIC v1 Initial salt (RFC 9001 §5.2). 20 bytes.
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Older draft-29 Initial salt; the simulator only accepts v1, but the constant
/// is kept for cross-reference.
pub const INITIAL_SALT_DRAFT_29: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

pub const QUIC_VERSION_V1: u32 = 0x0000_0001;

#[derive(Debug, thiserror::Error)]
pub enum QuicInitialError {
    #[error("packet too short for QUIC long header")]
    Truncated,
    #[error("not a long-header packet")]
    NotLongHeader,
    #[error("not an Initial packet")]
    NotInitial,
    #[error("unsupported QUIC version {0:#010x}")]
    UnsupportedVersion(u32),
    #[error("malformed length field")]
    BadLength,
    #[error("HKDF expand failed")]
    Hkdf,
    #[error("AEAD authentication failed")]
    Aead,
    #[error("crypto frame contained malformed data")]
    BadCryptoFrame,
    #[error("could not reassemble a complete ClientHello from crypto frames")]
    IncompleteClientHello,
    #[error("ClientHello inside Initial parse failed: {0}")]
    ClientHello(#[from] super::sni_filter::ClientHelloParseError),
}

/// Layout of a parsed long-header QUIC Initial packet, with sub-slice offsets
/// preserved so the AAD bytes match exactly during AEAD verification.
#[derive(Debug, Clone)]
pub struct InitialHeader {
    pub first_byte: u8,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub length_field: u64,
    pub packet_number_offset: usize,
    /// Total header length once the packet number is unprotected (header bytes
    /// included in AAD).
    pub header_len_after_unprotection: usize,
    pub packet_number_full: u64,
    pub packet_number_length: usize,
    pub payload_offset: usize,
    pub payload_len: usize,
}

/// Derived Initial keys (client side; the GFW only decrypts client → server).
#[derive(Debug, Clone)]
pub struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

fn hkdf_expand_label(
    hk: &Hkdf<Sha256>,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), QuicInitialError> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    let full_label_len = 6 + label.len();
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hk.expand(&info, out).map_err(|_| QuicInitialError::Hkdf)
}

/// Re-derive the client Initial keys *without* the dummy `extract_prk` helper,
/// avoiding an unimplemented call. We compute HKDF-Extract manually using the
/// inner HMAC, then run HKDF-Expand-Label off that PRK.
pub fn derive_client_initial_keys_v2(dcid: &[u8]) -> Result<InitialKeys, QuicInitialError> {
    use hkdf::hmac::{Hmac, Mac};

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&INITIAL_SALT_V1)
        .map_err(|_| QuicInitialError::Hkdf)?;
    mac.update(dcid);
    let initial_secret_prk = mac.finalize().into_bytes();
    let initial_hk =
        Hkdf::<Sha256>::from_prk(&initial_secret_prk).map_err(|_| QuicInitialError::Hkdf)?;
    let mut client_secret = [0_u8; 32];
    hkdf_expand_label(&initial_hk, b"client in", b"", &mut client_secret)?;
    let client_hk = Hkdf::<Sha256>::from_prk(&client_secret).map_err(|_| QuicInitialError::Hkdf)?;
    let mut key = [0_u8; 16];
    let mut iv = [0_u8; 12];
    let mut hp = [0_u8; 16];
    hkdf_expand_label(&client_hk, b"quic key", b"", &mut key)?;
    hkdf_expand_label(&client_hk, b"quic iv", b"", &mut iv)?;
    hkdf_expand_label(&client_hk, b"quic hp", b"", &mut hp)?;
    Ok(InitialKeys { key, iv, hp })
}

// ---------------------- packet parsing ----------------------

/// Parse the protected long header through the Length field, returning the
/// offset of the packet number (still protected at this point).
pub fn parse_protected_long_header(bytes: &[u8]) -> Result<InitialHeader, QuicInitialError> {
    if bytes.len() < 7 {
        return Err(QuicInitialError::Truncated);
    }
    let first = bytes[0];
    if first & 0x80 == 0 {
        return Err(QuicInitialError::NotLongHeader);
    }
    if first & 0x40 == 0 {
        // Fixed bit must be 1 in RFC 9000.
        return Err(QuicInitialError::NotLongHeader);
    }
    let packet_type = (first >> 4) & 0x03;
    if packet_type != 0x00 {
        return Err(QuicInitialError::NotInitial);
    }
    let version = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    if version != QUIC_VERSION_V1 {
        return Err(QuicInitialError::UnsupportedVersion(version));
    }
    let mut cur = 5;
    let dcid_len = bytes.get(cur).copied().ok_or(QuicInitialError::Truncated)? as usize;
    cur += 1;
    if cur + dcid_len > bytes.len() {
        return Err(QuicInitialError::Truncated);
    }
    let dcid = bytes[cur..cur + dcid_len].to_vec();
    cur += dcid_len;
    let scid_len = bytes.get(cur).copied().ok_or(QuicInitialError::Truncated)? as usize;
    cur += 1;
    if cur + scid_len > bytes.len() {
        return Err(QuicInitialError::Truncated);
    }
    let scid = bytes[cur..cur + scid_len].to_vec();
    cur += scid_len;
    let (token_len, token_len_size) = read_varint(&bytes[cur..])?;
    cur += token_len_size;
    let token_len = token_len as usize;
    if cur + token_len > bytes.len() {
        return Err(QuicInitialError::Truncated);
    }
    let token = bytes[cur..cur + token_len].to_vec();
    cur += token_len;
    let (length_field, length_size) = read_varint(&bytes[cur..])?;
    cur += length_size;
    let packet_number_offset = cur;
    let payload_end = packet_number_offset + length_field as usize;
    if payload_end > bytes.len() {
        return Err(QuicInitialError::BadLength);
    }
    Ok(InitialHeader {
        first_byte: first,
        version,
        dcid,
        scid,
        token,
        length_field,
        packet_number_offset,
        header_len_after_unprotection: packet_number_offset, // will be patched after HP unmask
        packet_number_full: 0,
        packet_number_length: 0,
        payload_offset: 0,
        payload_len: 0,
    })
}

fn read_varint(bytes: &[u8]) -> Result<(u64, usize), QuicInitialError> {
    if bytes.is_empty() {
        return Err(QuicInitialError::Truncated);
    }
    let prefix = bytes[0] >> 6;
    let length = 1_usize << prefix;
    if bytes.len() < length {
        return Err(QuicInitialError::Truncated);
    }
    let mut value = u64::from(bytes[0] & 0x3f);
    for byte in &bytes[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

/// Encode a QUIC variable-length integer. Only used by the test-only Initial
/// constructor below.
fn encode_varint(value: u64) -> Vec<u8> {
    if value < (1 << 6) {
        vec![value as u8]
    } else if value < (1 << 14) {
        let v = (value as u16) | 0x4000;
        v.to_be_bytes().to_vec()
    } else if value < (1 << 30) {
        let v = (value as u32) | 0x8000_0000;
        v.to_be_bytes().to_vec()
    } else {
        let v = value | 0xc000_0000_0000_0000;
        v.to_be_bytes().to_vec()
    }
}

/// Apply header protection to recover the original first byte and packet number.
pub fn unprotect_header(
    packet: &mut [u8],
    header: &mut InitialHeader,
    keys: &InitialKeys,
) -> Result<(), QuicInitialError> {
    let sample_start = header.packet_number_offset + 4;
    let sample_end = sample_start + 16;
    if sample_end > packet.len() {
        return Err(QuicInitialError::Truncated);
    }
    let mut sample = [0_u8; 16];
    sample.copy_from_slice(&packet[sample_start..sample_end]);
    let mask = hp_mask(&keys.hp, &sample);

    // Unprotect first byte (low 4 bits for long headers).
    packet[0] ^= mask[0] & 0x0f;
    let pn_length = ((packet[0] & 0x03) as usize) + 1;
    // Unprotect packet number bytes.
    for i in 0..pn_length {
        packet[header.packet_number_offset + i] ^= mask[1 + i];
    }

    let mut pn_full: u64 = 0;
    for i in 0..pn_length {
        pn_full = (pn_full << 8) | u64::from(packet[header.packet_number_offset + i]);
    }
    header.first_byte = packet[0];
    header.packet_number_full = pn_full;
    header.packet_number_length = pn_length;
    header.payload_offset = header.packet_number_offset + pn_length;
    header.payload_len = (header.length_field as usize) - pn_length;
    header.header_len_after_unprotection = header.payload_offset;
    Ok(())
}

fn hp_mask(hp_key: &[u8; 16], sample: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = *GenericArray::from_slice(sample);
    cipher.encrypt_block(&mut block);
    let mut out = [0_u8; 16];
    out.copy_from_slice(block.as_slice());
    out
}

/// AEAD-decrypt the Initial packet payload, returning the plaintext frame bytes.
///
/// The AEAD nonce is constructed per RFC 9001 §5.3: right-pad `iv` to 12 bytes
/// then XOR the packet number (in BE, right-aligned with leading zeros).
pub fn decrypt_payload(
    packet: &[u8],
    header: &InitialHeader,
    keys: &InitialKeys,
) -> Result<Vec<u8>, QuicInitialError> {
    let mut nonce_bytes = keys.iv;
    let pn_be = header.packet_number_full.to_be_bytes();
    let pn_offset = nonce_bytes.len() - pn_be.len();
    for (i, b) in pn_be.iter().enumerate() {
        nonce_bytes[pn_offset + i] ^= b;
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| QuicInitialError::Aead)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = &packet[..header.payload_offset];
    let ct = &packet[header.payload_offset..header.payload_offset + header.payload_len];
    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| QuicInitialError::Aead)
}

// ---------------------- frame parsing ----------------------

#[derive(Debug, Clone, PartialEq)]
pub enum InitialFrame {
    Padding(usize),
    Ping,
    Ack {
        largest: u64,
        delay: u64,
        ranges: Vec<(u64, u64)>,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    ConnectionClose {
        error_code: u64,
        reason: Vec<u8>,
    },
}

pub fn parse_initial_frames(payload: &[u8]) -> Result<Vec<InitialFrame>, QuicInitialError> {
    let mut frames = Vec::new();
    let mut cur = 0_usize;
    while cur < payload.len() {
        let frame_type = payload[cur];
        cur += 1;
        match frame_type {
            0x00 => {
                // PADDING - read all consecutive zeros.
                let mut count = 1;
                while cur < payload.len() && payload[cur] == 0x00 {
                    cur += 1;
                    count += 1;
                }
                frames.push(InitialFrame::Padding(count));
            }
            0x01 => frames.push(InitialFrame::Ping),
            0x02 | 0x03 => {
                let (largest, n) = read_varint(&payload[cur..])?;
                cur += n;
                let (delay, n) = read_varint(&payload[cur..])?;
                cur += n;
                let (range_count, n) = read_varint(&payload[cur..])?;
                cur += n;
                let (first_range, n) = read_varint(&payload[cur..])?;
                cur += n;
                let mut ranges = Vec::with_capacity(range_count as usize + 1);
                let mut current_smallest = largest.saturating_sub(first_range);
                ranges.push((current_smallest, largest));
                let mut last_smallest = current_smallest;
                for _ in 0..range_count {
                    let (gap, n) = read_varint(&payload[cur..])?;
                    cur += n;
                    let (rl, n) = read_varint(&payload[cur..])?;
                    cur += n;
                    let largest_in_range = last_smallest.saturating_sub(gap + 2);
                    current_smallest = largest_in_range.saturating_sub(rl);
                    ranges.push((current_smallest, largest_in_range));
                    last_smallest = current_smallest;
                }
                if frame_type == 0x03 {
                    // ACK with ECN counts - skip them.
                    for _ in 0..3 {
                        let (_, n) = read_varint(&payload[cur..])?;
                        cur += n;
                    }
                }
                frames.push(InitialFrame::Ack {
                    largest,
                    delay,
                    ranges,
                });
            }
            0x06 => {
                let (offset, n) = read_varint(&payload[cur..])?;
                cur += n;
                let (length, n) = read_varint(&payload[cur..])?;
                cur += n;
                let length = length as usize;
                if cur + length > payload.len() {
                    return Err(QuicInitialError::BadCryptoFrame);
                }
                let data = payload[cur..cur + length].to_vec();
                cur += length;
                frames.push(InitialFrame::Crypto { offset, data });
            }
            0x1c | 0x1d => {
                let (error_code, n) = read_varint(&payload[cur..])?;
                cur += n;
                if frame_type == 0x1c {
                    // skip frame_type (varint) for transport close
                    let (_, n) = read_varint(&payload[cur..])?;
                    cur += n;
                }
                let (reason_len, n) = read_varint(&payload[cur..])?;
                cur += n;
                let reason_len = reason_len as usize;
                if cur + reason_len > payload.len() {
                    return Err(QuicInitialError::BadCryptoFrame);
                }
                let reason = payload[cur..cur + reason_len].to_vec();
                cur += reason_len;
                frames.push(InitialFrame::ConnectionClose { error_code, reason });
            }
            other => {
                // Anchor the unknown type into the error for easier debugging
                // in CI logs - just log and propagate.
                tracing_log_unknown(other);
                return Err(QuicInitialError::BadCryptoFrame);
            }
        }
    }
    Ok(frames)
}

fn tracing_log_unknown(frame_type: u8) {
    // No-op; kept as a hook so tests can compile without an actual tracing
    // dependency in the simulator. Real GFW logs the unknown frame type into
    // its DPI counters.
    let _ = frame_type;
}

/// Reassemble Crypto-frame payloads into a single contiguous byte stream.
pub fn reassemble_crypto_stream(frames: &[InitialFrame]) -> Vec<u8> {
    let mut chunks: Vec<(u64, &[u8])> = frames
        .iter()
        .filter_map(|f| match f {
            InitialFrame::Crypto { offset, data } => Some((*offset, data.as_slice())),
            _ => None,
        })
        .collect();
    chunks.sort_by_key(|(offset, _)| *offset);
    let mut out = Vec::new();
    let mut cur = 0_u64;
    for (offset, data) in chunks {
        if offset > cur {
            // Gap: pad with zeros - real GFW would buffer and retry; in this
            // simulator we surface the partial reassembly so callers can decide
            // whether to retry.
            let pad = (offset - cur) as usize;
            out.extend(std::iter::repeat(0).take(pad));
            cur = offset;
        }
        let end = offset + data.len() as u64;
        if end <= cur {
            // Old retransmit segment - drop.
            continue;
        }
        let drop_prefix = (cur - offset) as usize;
        out.extend_from_slice(&data[drop_prefix..]);
        cur = end;
    }
    out
}

// ---------------------- end-to-end ----------------------

/// Final verdict from the QUIC Initial detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicInitialVerdict {
    /// Initial decrypted, ClientHello reassembled, SNI extracted, no rule fired.
    AllowSni { sni: String, dcid: Vec<u8> },
    /// Initial decrypted and SNI matched a blocklist - the (sip, dip, port)
    /// 3-tuple should be dropped for 180 s.
    BlockSni {
        sni: String,
        matched_rule: String,
        dcid: Vec<u8>,
    },
    /// Initial decrypted but no SNI extension was present. The simulator's
    /// configurable policy decides whether to allow or escalate.
    NoSni { dcid: Vec<u8> },
    /// Anything that prevented decryption / parsing.
    Failed(String),
}

pub struct QuicInitialDetector {
    blocklist: super::super::data::sni_blocklist::SniBlocklist,
    drop_window: Duration,
    triples: std::cell::RefCell<Vec<(QuicTriple, Instant)>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuicTriple {
    pub client_ip: std::net::IpAddr,
    pub server_ip: std::net::IpAddr,
    pub server_port: u16,
}

impl Default for QuicInitialDetector {
    fn default() -> Self {
        Self {
            blocklist: super::super::data::sni_blocklist::SniBlocklist::default_circumvention(),
            drop_window: Duration::from_secs(180),
            triples: std::cell::RefCell::new(Vec::new()),
        }
    }
}

impl QuicInitialDetector {
    pub fn new(
        blocklist: super::super::data::sni_blocklist::SniBlocklist,
        drop_window: Duration,
    ) -> Self {
        Self {
            blocklist,
            drop_window,
            triples: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Run the full pipeline on a raw QUIC Initial packet captured from the
    /// wire. The returned verdict tells the caller whether to drop the 3-tuple.
    pub fn inspect(&self, packet: &[u8], triple: Option<QuicTriple>) -> QuicInitialVerdict {
        if let Some(triple) = &triple {
            if self.is_dropped(triple) {
                return QuicInitialVerdict::BlockSni {
                    sni: String::from("<residual-drop>"),
                    matched_rule: String::from("<residual-3tuple>"),
                    dcid: Vec::new(),
                };
            }
        }
        let mut packet = packet.to_vec();
        let mut header = match parse_protected_long_header(&packet) {
            Ok(h) => h,
            Err(e) => return QuicInitialVerdict::Failed(format!("{e}")),
        };
        let keys = match derive_client_initial_keys_v2(&header.dcid) {
            Ok(k) => k,
            Err(e) => return QuicInitialVerdict::Failed(format!("{e}")),
        };
        if let Err(e) = unprotect_header(&mut packet, &mut header, &keys) {
            return QuicInitialVerdict::Failed(format!("{e}"));
        }
        let payload = match decrypt_payload(&packet, &header, &keys) {
            Ok(p) => p,
            Err(e) => return QuicInitialVerdict::Failed(format!("{e}")),
        };
        let frames = match parse_initial_frames(&payload) {
            Ok(f) => f,
            Err(e) => return QuicInitialVerdict::Failed(format!("{e}")),
        };
        let crypto = reassemble_crypto_stream(&frames);
        let parsed_ch = match parse_tls_handshake_clienthello(&crypto) {
            Ok(rec) => rec,
            Err(e) => return QuicInitialVerdict::Failed(format!("{e}")),
        };
        let sni = match parsed_ch.sni {
            Some(s) => s,
            None => return QuicInitialVerdict::NoSni { dcid: header.dcid },
        };
        if let Some(rule) = self.blocklist.matched_rule(&sni) {
            if let Some(triple) = triple {
                self.triples.borrow_mut().push((triple, Instant::now()));
            }
            QuicInitialVerdict::BlockSni {
                sni,
                matched_rule: rule,
                dcid: header.dcid,
            }
        } else {
            QuicInitialVerdict::AllowSni {
                sni,
                dcid: header.dcid,
            }
        }
    }

    fn is_dropped(&self, triple: &QuicTriple) -> bool {
        let now = Instant::now();
        let mut triples = self.triples.borrow_mut();
        triples.retain(|(_, when)| now.duration_since(*when) <= self.drop_window);
        triples.iter().any(|(t, _)| t == triple)
    }

    pub fn drop_window(&self) -> Duration {
        self.drop_window
    }
}

/// Crypto stream parser: TLS ClientHello carried inside QUIC Initial does *not*
/// have the outer 5-byte TLS record header (the Crypto-frame payload is the
/// handshake message starting at type=0x01). We add a synthetic TLS record
/// header so we can reuse the standard ClientHello parser.
fn parse_tls_handshake_clienthello(
    crypto: &[u8],
) -> Result<super::sni_filter::ParsedClientHello, QuicInitialError> {
    if crypto.len() < 4 {
        return Err(QuicInitialError::IncompleteClientHello);
    }
    if crypto[0] != 0x01 {
        return Err(QuicInitialError::IncompleteClientHello);
    }
    let hs_len = (u32::from(crypto[1]) << 16) | (u32::from(crypto[2]) << 8) | u32::from(crypto[3]);
    let needed = 4 + hs_len as usize;
    if crypto.len() < needed {
        return Err(QuicInitialError::IncompleteClientHello);
    }
    let mut wrapped = Vec::with_capacity(5 + needed);
    wrapped.push(super::sni_filter::TLS_CONTENT_HANDSHAKE);
    wrapped.extend_from_slice(&[0x03, 0x03]);
    wrapped.extend_from_slice(&(needed as u16).to_be_bytes());
    wrapped.extend_from_slice(&crypto[..needed]);
    Ok(parse_client_hello(&wrapped)?)
}

// ---------------------- Test-only encryption helper ----------------------

/// Construct a QUIC v1 Initial packet that wraps a single Crypto frame holding
/// `handshake_bytes` (a TLS ClientHello handshake message starting at type=0x01,
/// NOT a TLS record). Pads to `total_len`. Returns the encrypted packet.
///
/// Available only via tests; this is the encryption inverse of the detector and
/// is what red-team scenarios use to feed the simulator. Real GFW deployments
/// do not need to encrypt - they only decrypt.
#[cfg(test)]
pub(crate) fn build_test_initial_packet(
    dcid: &[u8],
    scid: &[u8],
    handshake_bytes: &[u8],
    packet_number: u32,
    total_len: usize,
) -> Result<Vec<u8>, QuicInitialError> {
    use aes_gcm::aead::Aead as AeadEnc;

    let keys = derive_client_initial_keys_v2(dcid)?;

    // Construct unprotected header (without packet number length set yet).
    let mut header = Vec::new();
    let pn_len = 4_usize; // always 4 bytes for simplicity
    header.push(0xc0 | ((pn_len - 1) as u8));
    header.extend_from_slice(&QUIC_VERSION_V1.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(scid);
    header.extend_from_slice(&encode_varint(0)); // token_len = 0

    let mut frames = Vec::new();
    frames.push(0x06); // CRYPTO
    frames.extend_from_slice(&encode_varint(0)); // offset
    frames.extend_from_slice(&encode_varint(handshake_bytes.len() as u64));
    frames.extend_from_slice(handshake_bytes);

    let header_overhead = header.len();
    let varint_max_size = 2; // assume length fits in 2-byte varint (<=16383)
    let auth_tag = 16;
    let bare = header_overhead + varint_max_size + pn_len + frames.len() + auth_tag;
    let pad = total_len.saturating_sub(bare);
    let mut padded_payload = frames;
    padded_payload.extend(std::iter::repeat(0_u8).take(pad));
    let payload_plus_pn_plus_tag = padded_payload.len() + pn_len + auth_tag;
    if payload_plus_pn_plus_tag > 16383 {
        return Err(QuicInitialError::BadLength);
    }
    let mut varint_two = (payload_plus_pn_plus_tag as u16).to_be_bytes();
    varint_two[0] |= 0x40;
    header.extend_from_slice(&varint_two);
    header.extend_from_slice(&packet_number.to_be_bytes());
    let aad = header.clone();

    // Encrypt payload.
    let mut nonce_bytes = keys.iv;
    let off = nonce_bytes.len() - 8;
    // Promote pn to u64 BE for nonce XOR.
    let pn_full_be = (packet_number as u64).to_be_bytes();
    for (i, b) in pn_full_be.iter().enumerate() {
        nonce_bytes[off + i] ^= b;
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| QuicInitialError::Aead)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &padded_payload,
                aad: &aad,
            },
        )
        .map_err(|_| QuicInitialError::Aead)?;

    // Build the full packet (still unprotected).
    let mut packet = aad;
    packet.extend_from_slice(&ciphertext);

    // Apply header protection.
    let pn_offset = packet.len() - pn_len - ciphertext.len();
    let sample_start = pn_offset + 4;
    let mut sample = [0_u8; 16];
    sample.copy_from_slice(&packet[sample_start..sample_start + 16]);
    let mask = hp_mask(&keys.hp, &sample);
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gfw_sim::fixtures::synthetic_tls13_client_hello;

    #[test]
    fn varint_round_trip_within_each_class() {
        for value in [0_u64, 63, 64, 16383, 16384, 1 << 29, 1 << 30, (1 << 62) - 1] {
            let encoded = encode_varint(value);
            let (decoded, n) = read_varint(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(n, encoded.len());
        }
    }

    #[test]
    fn rfc9001_initial_keys_match_appendix_a() {
        // From RFC 9001 Appendix A.1:
        //   initial_secret = ebf8fa56f12931b9f1d63cfdb9a9b1d6
        //                    2acd00c8c8c75e2c66c80ad8e6ed3cf3
        //   client_initial_secret = c00cf151ca5be075ed0ebfb5c80323c4
        //                           2d6b7db67881289af4008f1f6c357aea
        //   key = 1f369613dd76d5467730efcbe3b1a22d
        //   iv  = fa044b2f42a3fd3b46fb255c
        //   hp  = 9f50449e04a0e810283a1e9933adedd2
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = derive_client_initial_keys_v2(&dcid).unwrap();
        let key_hex: String = keys.key.iter().map(|b| format!("{:02x}", b)).collect();
        let iv_hex: String = keys.iv.iter().map(|b| format!("{:02x}", b)).collect();
        let hp_hex: String = keys.hp.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(key_hex, "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(iv_hex, "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hp_hex, "9f50449e04a0e810283a1e9933adedd2");
    }

    fn build_parallax_initial_packet(sni: &str) -> (Vec<u8>, Vec<u8>) {
        let record = synthetic_tls13_client_hello(sni, 13);
        // Strip the 5-byte TLS record header to get the handshake message.
        let handshake = record[5..].to_vec();
        let dcid = b"01234567";
        let packet = build_test_initial_packet(dcid, b"abcd", &handshake, 0, 1200).unwrap();
        (packet, dcid.to_vec())
    }

    #[test]
    fn detector_extracts_sni_from_self_encrypted_initial() {
        let (packet, dcid) = build_parallax_initial_packet("cloudflare.com");
        let det = QuicInitialDetector::default();
        match det.inspect(&packet, None) {
            QuicInitialVerdict::AllowSni {
                sni,
                dcid: out_dcid,
            } => {
                assert_eq!(sni, "cloudflare.com");
                assert_eq!(out_dcid, dcid);
            }
            other => panic!("expected AllowSni, got {other:?}"),
        }
    }

    #[test]
    fn detector_blocks_known_circumvention_sni_inside_initial() {
        let (packet, _) = build_parallax_initial_packet("relay7.shadowsocks.io");
        let det = QuicInitialDetector::default();
        match det.inspect(&packet, None) {
            QuicInitialVerdict::BlockSni {
                sni, matched_rule, ..
            } => {
                assert_eq!(sni, "relay7.shadowsocks.io");
                assert_eq!(matched_rule, "*.shadowsocks.io");
            }
            other => panic!("expected BlockSni, got {other:?}"),
        }
    }

    #[test]
    fn invalid_long_header_returns_failed() {
        let det = QuicInitialDetector::default();
        match det.inspect(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], None) {
            QuicInitialVerdict::Failed(_) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
