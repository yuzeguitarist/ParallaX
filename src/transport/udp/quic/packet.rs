//! QUIC packet headers and packet-number coding (RFC 9000 §17), clean-room.
//!
//! Decoding is two-step, mirroring RFC 9001 §5.4.2: the long/short header is
//! parsed up to the packet-number field BEFORE header protection is removed (to
//! locate the HP sample), then the packet number is read AFTER the caller removes
//! protection. [`locate_pn_offset`] does the first step; [`Header::decode`] does
//! the second (it assumes the first byte + packet number are already unmasked).
//!
//! The bytes from the first byte through the packet number are the AEAD AAD
//! (RFC 9001 §5.3); both [`Header::encode`] and [`Header::decode`] report that
//! header length so the caller can feed it to the existing
//! [`crate::tls::quic::PacketKey`] / [`crate::tls::quic::HeaderProtectionKey`].
//!
//! Scope: only the packet types the relay sends/receives on the happy path are
//! decodable — Initial + Handshake (long) and 1-RTT (short). 0-RTT, Retry, and
//! Version Negotiation are rejected with [`DecodeError::UnsupportedPacketType`]
//! (the relay talks only to a controlled ParallaX peer that emits none of them).

use super::varint;

/// Maximum connection-id length in QUIC v1 (RFC 9000 §17.2).
pub const MAX_CID_LEN: usize = 20;

// First-byte bit fields (RFC 9000 §17.2 long header / §17.3 short header).
const LONG_HEADER_FORM: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const SPIN_BIT: u8 = 0x20;
const KEY_PHASE_BIT: u8 = 0x04;
const PN_LEN_MASK: u8 = 0x03;
const LONG_TYPE_MASK: u8 = 0x30;

/// Long-header packet type — the 2 bits below the form + fixed bits (RFC 9000
/// §17.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl LongType {
    fn from_first_byte(b: u8) -> Self {
        match b & LONG_TYPE_MASK {
            0x00 => LongType::Initial,
            0x10 => LongType::ZeroRtt,
            0x20 => LongType::Handshake,
            _ => LongType::Retry,
        }
    }

    fn type_bits(self) -> u8 {
        match self {
            LongType::Initial => 0x00,
            LongType::ZeroRtt => 0x10,
            LongType::Handshake => 0x20,
            LongType::Retry => 0x30,
        }
    }
}

/// Error decoding a packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Ran off the end of the buffer.
    Truncated,
    /// A connection id field announced a length above [`MAX_CID_LEN`].
    CidTooLong,
    /// The fixed bit (0x40) was clear. Safari does not negotiate the
    /// grease-QUIC-bit transport parameter, so a clear fixed bit is invalid here.
    MissingFixedBit,
    /// A long-header type the relay does not process at the transport layer
    /// (0-RTT, Retry, Version Negotiation). See module scope.
    UnsupportedPacketType,
}

/// A QUIC connection id (RFC 9000 §5.1): an inline buffer of up to
/// [`MAX_CID_LEN`] bytes. The Safari client's source CID is zero-length.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConnectionId {
    bytes: [u8; MAX_CID_LEN],
    len: u8,
}

impl ConnectionId {
    /// Build from a slice. Panics if longer than [`MAX_CID_LEN`] (a local bug;
    /// wire-sourced CIDs are length-checked in [`Header::decode`] and surface
    /// [`DecodeError::CidTooLong`] instead).
    pub fn new(slice: &[u8]) -> Self {
        assert!(
            slice.len() <= MAX_CID_LEN,
            "connection id exceeds {MAX_CID_LEN} bytes"
        );
        let mut bytes = [0u8; MAX_CID_LEN];
        bytes[..slice.len()].copy_from_slice(slice);
        Self {
            bytes,
            len: slice.len() as u8,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnectionId(")?;
        for b in self.as_slice() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Truncate `full_pn` to the fewest bytes that let the peer reconstruct it given
/// `largest_acked` (RFC 9000 §17.1 / Appendix A.2): the encoding must represent
/// MORE than twice the range between the two. Returns `(buf, len)` with `len` in
/// `1..=4`; the wire bytes are the low `len` bytes of `full_pn`, big-endian, in
/// `buf[..len]`.
pub fn encode_packet_number(full_pn: u64, largest_acked: Option<u64>) -> ([u8; 4], usize) {
    let num_unacked = match largest_acked {
        Some(largest) => full_pn.saturating_sub(largest),
        None => full_pn + 1,
    };
    // Smallest `len` whose range 2^(8*len) strictly exceeds twice `num_unacked`.
    let twice = u128::from(num_unacked) * 2;
    let len = if twice < (1 << 8) {
        1
    } else if twice < (1 << 16) {
        2
    } else if twice < (1 << 24) {
        3
    } else {
        4
    };
    let be = full_pn.to_be_bytes();
    let mut buf = [0u8; 4];
    buf[..len].copy_from_slice(&be[8 - len..]);
    (buf, len)
}

/// Reconstruct the full packet number from the `pn_len`-byte truncated value and
/// the largest packet number already processed in this space (RFC 9000 §17.1 /
/// Appendix A.3). `pn_len` is `1..=4`.
pub fn decode_packet_number(largest_pn: u64, truncated: u64, pn_len: usize) -> u64 {
    let pn_nbits = pn_len * 8;
    let expected = largest_pn.wrapping_add(1);
    let pn_win = 1u64 << pn_nbits; // pn_len 1..=4 ⇒ shift 8..=32, always in range
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let candidate = (expected & !pn_mask) | truncated;
    if candidate + pn_hwin <= expected && candidate < (1u64 << 62) - pn_win {
        candidate + pn_win
    } else if candidate > expected + pn_hwin && candidate >= pn_win {
        candidate - pn_win
    } else {
        candidate
    }
}

/// A decoded (or to-be-encoded) packet header with a plaintext packet number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// Initial or Handshake long header (RFC 9000 §17.2). `token` is empty for
    /// Handshake. `length` is the §17.2 Length field (packet number + protected
    /// payload + AEAD tag).
    Long {
        ty: LongType,
        version: u32,
        dcid: ConnectionId,
        scid: ConnectionId,
        token: Vec<u8>,
        length: u64,
        packet_number: u64,
        pn_len: usize,
    },
    /// 1-RTT short header (RFC 9000 §17.3). `dcid` is the destination's CID
    /// (zero-length when the destination is the Safari client).
    Short {
        spin: bool,
        key_phase: bool,
        dcid: ConnectionId,
        packet_number: u64,
        pn_len: usize,
    },
}

impl Header {
    /// Serialize the header (through the plaintext packet number) into `out`, and
    /// return the byte offset of the packet-number field (the HP `pn_offset`). The
    /// written bytes are the AEAD AAD.
    pub fn encode(&self, out: &mut Vec<u8>) -> usize {
        match self {
            Header::Long {
                ty,
                version,
                dcid,
                scid,
                token,
                length,
                packet_number,
                pn_len,
            } => {
                let first = LONG_HEADER_FORM | FIXED_BIT | ty.type_bits() | (*pn_len as u8 - 1);
                out.push(first);
                out.extend_from_slice(&version.to_be_bytes());
                out.push(dcid.len() as u8);
                out.extend_from_slice(dcid.as_slice());
                out.push(scid.len() as u8);
                out.extend_from_slice(scid.as_slice());
                if *ty == LongType::Initial {
                    varint::encode(token.len() as u64, out);
                    out.extend_from_slice(token);
                }
                varint::encode(*length, out);
                let pn_offset = out.len();
                let be = packet_number.to_be_bytes();
                out.extend_from_slice(&be[8 - pn_len..]);
                pn_offset
            }
            Header::Short {
                spin,
                key_phase,
                dcid,
                packet_number,
                pn_len,
            } => {
                let mut first = FIXED_BIT | (*pn_len as u8 - 1);
                if *spin {
                    first |= SPIN_BIT;
                }
                if *key_phase {
                    first |= KEY_PHASE_BIT;
                }
                out.push(first);
                out.extend_from_slice(dcid.as_slice());
                let pn_offset = out.len();
                let be = packet_number.to_be_bytes();
                out.extend_from_slice(&be[8 - pn_len..]);
                pn_offset
            }
        }
    }

    /// Decode a header whose first byte and packet number have ALREADY been
    /// unmasked (header protection removed). `local_cid_len` is the length of the
    /// destination CID this endpoint issues — needed for short headers, whose DCID
    /// has no on-wire length prefix (zero for the Safari client). Returns the
    /// header and the AAD length (offset of the first protected payload byte).
    pub fn decode(buf: &[u8], local_cid_len: usize) -> Result<(Header, usize), DecodeError> {
        let first = *buf.first().ok_or(DecodeError::Truncated)?;
        if first & FIXED_BIT == 0 {
            return Err(DecodeError::MissingFixedBit);
        }
        if first & LONG_HEADER_FORM != 0 {
            let ty = LongType::from_first_byte(first);
            if ty != LongType::Initial && ty != LongType::Handshake {
                return Err(DecodeError::UnsupportedPacketType);
            }
            let mut c = Cursor::new(buf);
            c.skip(1)?; // first byte
            let version = c.u32()?;
            let dcid = c.cid()?;
            let scid = c.cid()?;
            let token = if ty == LongType::Initial {
                let tlen = c.varint()? as usize;
                c.take(tlen)?.to_vec()
            } else {
                Vec::new()
            };
            let length = c.varint()?;
            let pn_offset = c.pos();
            let pn_len = ((first & PN_LEN_MASK) + 1) as usize;
            let packet_number = read_pn(buf, pn_offset, pn_len)?;
            Ok((
                Header::Long {
                    ty,
                    version,
                    dcid,
                    scid,
                    token,
                    length,
                    packet_number,
                    pn_len,
                },
                pn_offset + pn_len,
            ))
        } else {
            let pn_offset = 1 + local_cid_len;
            let dcid = ConnectionId::new(buf.get(1..pn_offset).ok_or(DecodeError::Truncated)?);
            let pn_len = ((first & PN_LEN_MASK) + 1) as usize;
            let packet_number = read_pn(buf, pn_offset, pn_len)?;
            Ok((
                Header::Short {
                    spin: first & SPIN_BIT != 0,
                    key_phase: first & KEY_PHASE_BIT != 0,
                    dcid,
                    packet_number,
                    pn_len,
                },
                pn_offset + pn_len,
            ))
        }
    }
}

/// Parse a header far enough to return the packet-number offset (the HP
/// `pn_offset`), WITHOUT reading the still-masked packet number. Long-header
/// structure (version, CIDs, token, length) is plaintext; the short-header DCID
/// length comes from `local_cid_len`.
pub fn locate_pn_offset(buf: &[u8], local_cid_len: usize) -> Result<usize, DecodeError> {
    let first = *buf.first().ok_or(DecodeError::Truncated)?;
    if first & FIXED_BIT == 0 {
        return Err(DecodeError::MissingFixedBit);
    }
    if first & LONG_HEADER_FORM == 0 {
        return Ok(1 + local_cid_len);
    }
    match LongType::from_first_byte(first) {
        LongType::Initial | LongType::Handshake => {}
        _ => return Err(DecodeError::UnsupportedPacketType),
    }
    let ty = LongType::from_first_byte(first);
    let mut c = Cursor::new(buf);
    c.skip(1)?;
    c.skip(4)?; // version
    let _dcid = c.cid()?;
    let _scid = c.cid()?;
    if ty == LongType::Initial {
        let tlen = c.varint()? as usize;
        c.skip(tlen)?;
    }
    let _length = c.varint()?;
    Ok(c.pos())
}

/// Read the big-endian `pn_len`-byte packet number at `pn_offset`.
fn read_pn(buf: &[u8], pn_offset: usize, pn_len: usize) -> Result<u64, DecodeError> {
    let bytes = buf
        .get(pn_offset..pn_offset + pn_len)
        .ok_or(DecodeError::Truncated)?;
    let mut pn = 0u64;
    for &b in bytes {
        pn = (pn << 8) | u64::from(b);
    }
    Ok(pn)
}

/// A minimal forward cursor over a header buffer.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn skip(&mut self, n: usize) -> Result<(), DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        self.pos += n;
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(DecodeError::Truncated)?;
        self.pos += n;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        let (v, n) = varint::decode(&self.buf[self.pos..]).ok_or(DecodeError::Truncated)?;
        self.pos += n;
        Ok(v)
    }

    /// Read a length-prefixed connection id (RFC 9000 §17.2 long header).
    fn cid(&mut self) -> Result<ConnectionId, DecodeError> {
        let len = *self.buf.get(self.pos).ok_or(DecodeError::Truncated)? as usize;
        if len > MAX_CID_LEN {
            return Err(DecodeError::CidTooLong);
        }
        self.pos += 1;
        Ok(ConnectionId::new(self.take(len)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_number_encoding_matches_rfc9000_appendix_a2() {
        // RFC 9000 A.2: largest_acked 0xa82f30ea, full 0xac5c02 needs ≥16 bits;
        // 0xac5c02 truncated to 2 bytes is 0x5c02.
        let (buf, len) = encode_packet_number(0xac5c02, Some(0xabe8bc));
        assert_eq!(len, 2);
        assert_eq!(&buf[..len], &[0x5c, 0x02]);
    }

    #[test]
    fn packet_number_decoding_matches_rfc9000_appendix_a3() {
        // RFC 9000 A.3: largest 0xa82f30ea, truncated 0x9b32 (16 bits) → 0xa82f9b32.
        assert_eq!(decode_packet_number(0xa82f30ea, 0x9b32, 2), 0xa82f9b32);
    }

    #[test]
    fn packet_number_round_trips_against_largest_acked() {
        let largest = 0xa82f30ea;
        for full in [0xa82f30eb, 0xa82f4000, 0xa82fb0ea, 0xa830_0000] {
            let (buf, len) = encode_packet_number(full, Some(largest));
            let mut truncated = 0u64;
            for &b in &buf[..len] {
                truncated = (truncated << 8) | u64::from(b);
            }
            assert_eq!(
                decode_packet_number(largest, truncated, len),
                full,
                "round-trip failed for {full:#x}"
            );
        }
    }

    #[test]
    fn first_packet_uses_one_byte() {
        // No prior ack, pn 0 ⇒ num_unacked 1 ⇒ 1 byte.
        let (_, len) = encode_packet_number(0, None);
        assert_eq!(len, 1);
    }

    #[test]
    fn connection_id_round_trips() {
        let cid = ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(cid.len(), 8);
        assert_eq!(cid.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(ConnectionId::new(&[]).is_empty());
    }

    #[test]
    fn initial_header_round_trips() {
        let hdr = Header::Long {
            ty: LongType::Initial,
            version: 1,
            dcid: ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]),
            scid: ConnectionId::new(&[]),
            token: vec![],
            length: 2 + 19 + 16,
            packet_number: 2,
            pn_len: 1,
        };
        let mut out = Vec::new();
        let pn_offset = hdr.encode(&mut out);
        assert_eq!(locate_pn_offset(&out, 0).unwrap(), pn_offset);
        let (decoded, aad_len) = Header::decode(&out, 0).unwrap();
        assert_eq!(decoded, hdr);
        assert_eq!(aad_len, out.len());
    }

    #[test]
    fn short_header_round_trips_with_known_dcid_len() {
        let hdr = Header::Short {
            spin: false,
            key_phase: true,
            dcid: ConnectionId::new(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]),
            packet_number: 0x1234,
            pn_len: 2,
        };
        let mut out = Vec::new();
        let pn_offset = hdr.encode(&mut out);
        assert_eq!(locate_pn_offset(&out, 8).unwrap(), pn_offset);
        let (decoded, _) = Header::decode(&out, 8).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn decode_rejects_unsupported_long_types_and_clear_fixed_bit() {
        // Retry (type bits 0x30) is not transport-processed.
        let retry = vec![LONG_HEADER_FORM | FIXED_BIT | 0x30, 0, 0, 0, 1, 0, 0];
        assert_eq!(
            Header::decode(&retry, 0),
            Err(DecodeError::UnsupportedPacketType)
        );
        // Clear fixed bit on an otherwise-short header.
        let no_fixed = vec![0x00, 0x00];
        assert_eq!(
            Header::decode(&no_fixed, 0),
            Err(DecodeError::MissingFixedBit)
        );
    }

    /// Full compose against the SHIPPING crypto: encode an Initial header, AEAD-seal
    /// the payload with the header as AAD, apply header protection, then reverse —
    /// locate the pn offset, remove HP, decode the header, and open the payload.
    /// Proves the new wire layer and the existing `keys.rs` AEAD/HP fit together.
    #[test]
    fn header_aead_and_hp_compose_round_trip() {
        use crate::tls::quic::{CipherSuite, DirectionalKeys};

        let keys =
            DirectionalKeys::from_secret(CipherSuite::Aes128GcmSha256, &[0x42u8; 32]).unwrap();
        let payload = b"the quick brown fox jumps over"; // 30 bytes > sample needs
        let pn = 7u64;
        let (_, pn_len) = encode_packet_number(pn, None);
        let length = (pn_len + payload.len() + keys.packet.tag_len()) as u64;
        let hdr = Header::Long {
            ty: LongType::Initial,
            version: 1,
            dcid: ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]),
            scid: ConnectionId::new(&[]),
            token: vec![],
            length,
            packet_number: pn,
            pn_len,
        };

        let mut packet = Vec::new();
        let pn_offset = hdr.encode(&mut packet);
        let aad = packet[..pn_offset + pn_len].to_vec();
        // Append payload + reserved tag, then seal in place.
        let body_start = packet.len();
        packet.extend_from_slice(payload);
        packet.extend_from_slice(&[0u8; 16]);
        keys.packet
            .encrypt_in_place(pn, &aad, &mut packet[body_start..])
            .unwrap();
        keys.header.encrypt_header(pn_offset, &mut packet).unwrap();

        // Receiver: locate pn, remove HP, decode header, open payload.
        let located = locate_pn_offset(&packet, 0).unwrap();
        assert_eq!(located, pn_offset);
        keys.header.decrypt_header(located, &mut packet).unwrap();
        let (decoded, aad_len) = Header::decode(&packet, 0).unwrap();
        assert_eq!(decoded, hdr);
        let aad2 = packet[..aad_len].to_vec();
        let pt = keys
            .packet
            .decrypt_in_place(pn, &aad2, &mut packet[aad_len..])
            .unwrap();
        assert_eq!(pt, payload);
    }
}
