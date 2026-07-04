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
//! Scope: only the packet types the relay sends/receives are decodable — Initial,
//! 0-RTT, and Handshake (long) plus 1-RTT (short). Retry and Version Negotiation
//! are rejected with [`DecodeError::UnsupportedPacketType`] (the relay talks only
//! to a controlled ParallaX peer that emits neither).

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
/// Reserved bits that MUST be zero once header protection is removed (RFC 9000
/// §17.2 long header / §17.3 short header).
const LONG_RESERVED_BITS: u8 = 0x0c;
const SHORT_RESERVED_BITS: u8 = 0x18;

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
    /// A reserved bit in the (already-unmasked) first byte was set. RFC 9000
    /// §17.2 (long, bits 0x0c) / §17.3 (short, bits 0x18) require them clear once
    /// header protection is removed; a set bit is a PROTOCOL_VIOLATION.
    ReservedBitsSet,
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
    // `candidate + pn_hwin` / `expected + pn_hwin` can overflow `u64` for a
    // near-`u64::MAX` operand (a debug-build panic; production packet numbers stay
    // < 2^62 so it is not reached on the live path, but this `pub` fn is called on
    // every received header before decryption and is exercised directly by fuzzing).
    // `saturating_add` is exact here: `pn_hwin <= 2^31`, so a saturated result is
    // strictly greater than any real `expected`/`candidate`, which preserves both
    // inequalities — and the branch that then adds/subtracts `pn_win` is already
    // gated by the `< 2^62 - pn_win` / `>= pn_win` bounds, so no result overflows.
    if candidate.saturating_add(pn_hwin) <= expected && candidate < (1u64 << 62) - pn_win {
        candidate + pn_win
    } else if candidate > expected.saturating_add(pn_hwin) && candidate >= pn_win {
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
    /// The (full, reconstructed) packet number this header carries.
    pub fn packet_number(&self) -> u64 {
        match self {
            Header::Long { packet_number, .. } | Header::Short { packet_number, .. } => {
                *packet_number
            }
        }
    }

    /// The on-wire packet-number length (1..=4).
    pub fn pn_len(&self) -> usize {
        match self {
            Header::Long { pn_len, .. } | Header::Short { pn_len, .. } => *pn_len,
        }
    }

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
    /// has no on-wire length prefix (zero for the Safari client). `largest_pn` is
    /// the largest packet number already processed in this packet-number space; it
    /// reconstructs the full packet number from its truncated wire form (RFC 9000
    /// §17.1 / Appendix A.3), so the returned `packet_number` is ALWAYS the full
    /// value (the same domain [`Header::encode`] is given), never the truncated
    /// bytes. Returns the header and the AAD length (offset of the first protected
    /// payload byte).
    pub fn decode(
        buf: &[u8],
        local_cid_len: usize,
        largest_pn: u64,
    ) -> Result<(Header, usize), DecodeError> {
        let first = *buf.first().ok_or(DecodeError::Truncated)?;
        if first & FIXED_BIT == 0 {
            return Err(DecodeError::MissingFixedBit);
        }
        if first & LONG_HEADER_FORM != 0 {
            let ty = LongType::from_first_byte(first);
            if !matches!(
                ty,
                LongType::Initial | LongType::ZeroRtt | LongType::Handshake
            ) {
                return Err(DecodeError::UnsupportedPacketType);
            }
            if first & LONG_RESERVED_BITS != 0 {
                return Err(DecodeError::ReservedBitsSet);
            }
            let mut c = Cursor::new(buf);
            c.skip(1)?; // first byte
            let version = c.u32()?;
            let dcid = c.cid()?;
            let scid = c.cid()?;
            let token = if ty == LongType::Initial {
                // try_from, not `as usize`: a >usize varint must fail closed, not
                // silently truncate on a 32-bit target (matches `long_packet_len`).
                let tlen = usize::try_from(c.varint()?).map_err(|_| DecodeError::Truncated)?;
                c.take(tlen)?.to_vec()
            } else {
                Vec::new()
            };
            let length = c.varint()?;
            let pn_offset = c.pos();
            let pn_len = ((first & PN_LEN_MASK) + 1) as usize;
            let packet_number =
                decode_packet_number(largest_pn, read_pn(buf, pn_offset, pn_len)?, pn_len);
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
            if first & SHORT_RESERVED_BITS != 0 {
                return Err(DecodeError::ReservedBitsSet);
            }
            let pn_offset = 1 + local_cid_len;
            let dcid = ConnectionId::new(buf.get(1..pn_offset).ok_or(DecodeError::Truncated)?);
            let pn_len = ((first & PN_LEN_MASK) + 1) as usize;
            let packet_number =
                decode_packet_number(largest_pn, read_pn(buf, pn_offset, pn_len)?, pn_len);
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
        LongType::Initial | LongType::ZeroRtt | LongType::Handshake => {}
        _ => return Err(DecodeError::UnsupportedPacketType),
    }
    let ty = LongType::from_first_byte(first);
    let mut c = Cursor::new(buf);
    c.skip(1)?;
    c.skip(4)?; // version
    let _dcid = c.cid()?;
    let _scid = c.cid()?;
    if ty == LongType::Initial {
        // try_from, not `as usize`: fail closed on a >usize varint rather than
        // silently truncate on a 32-bit target (matches `long_packet_len`).
        let tlen = usize::try_from(c.varint()?).map_err(|_| DecodeError::Truncated)?;
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

/// The packet-number spaces a received packet can map to. `ZeroRtt` shares the
/// `OneRtt` (Application Data) packet-number space (RFC 9000 §12.3) but is
/// protected with the 0-RTT keys, so it is classified separately for key
/// selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSpace {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
}

/// Classify a received datagram's first packet by space, from its (still
/// HP-masked) first byte — the long-header form + type bits are not header-
/// protected (RFC 9001 §5.4.2). Returns `None` for a clear fixed bit or an
/// unsupported long type (Retry / Version Negotiation).
pub fn first_packet_space(datagram: &[u8]) -> Option<PacketSpace> {
    let first = *datagram.first()?;
    if first & FIXED_BIT == 0 {
        return None;
    }
    if first & LONG_HEADER_FORM == 0 {
        return Some(PacketSpace::OneRtt);
    }
    match LongType::from_first_byte(first) {
        LongType::Initial => Some(PacketSpace::Initial),
        LongType::ZeroRtt => Some(PacketSpace::ZeroRtt),
        LongType::Handshake => Some(PacketSpace::Handshake),
        LongType::Retry => None,
    }
}

/// Peek the destination + source connection ids of a long-header packet WITHOUT
/// removing header protection (the CIDs are plaintext). The server uses this on
/// the client's first Initial to derive Initial keys from the chosen DCID and to
/// learn the client's SCID before it can decrypt anything.
pub fn peek_long_cids(datagram: &[u8]) -> Result<(ConnectionId, ConnectionId), DecodeError> {
    let first = *datagram.first().ok_or(DecodeError::Truncated)?;
    if first & LONG_HEADER_FORM == 0 {
        return Err(DecodeError::UnsupportedPacketType);
    }
    let mut c = Cursor::new(datagram);
    c.skip(1)?;
    c.skip(4)?; // version
    let dcid = c.cid()?;
    let scid = c.cid()?;
    Ok((dcid, scid))
}

/// The total on-wire size of the long-header packet at the start of `buf`, used
/// to find the next packet when several are coalesced into one datagram (RFC 9000
/// §12.2). It is the header length through the §17.2 Length field plus the Length
/// value (which covers the packet number + protected payload + AEAD tag). Reads
/// only plaintext header fields, so it is valid BEFORE header protection is
/// removed. Returns `None` for a short header (no Length field — a 1-RTT packet
/// runs to the end of the datagram and so is always the last coalesced packet),
/// for an unsupported long type, or for a truncated/clear-fixed-bit header.
pub fn long_packet_len(buf: &[u8]) -> Option<usize> {
    let first = *buf.first()?;
    if first & FIXED_BIT == 0 || first & LONG_HEADER_FORM == 0 {
        return None;
    }
    let ty = LongType::from_first_byte(first);
    if !matches!(
        ty,
        LongType::Initial | LongType::ZeroRtt | LongType::Handshake
    ) {
        return None;
    }
    let mut c = Cursor::new(buf);
    c.skip(1).ok()?; // first byte
    c.skip(4).ok()?; // version
    c.cid().ok()?; // dcid
    c.cid().ok()?; // scid
    if ty == LongType::Initial {
        let tlen = usize::try_from(c.varint().ok()?).ok()?;
        c.skip(tlen).ok()?;
    }
    let length = usize::try_from(c.varint().ok()?).ok()?;
    // Reject a Length that points past the datagram (a malformed long header must
    // not yield a coalescing boundary outside `buf`); `usize::try_from` also avoids
    // a silent `as usize` truncation on a 32-bit target.
    let total = c.pos().checked_add(length)?;
    (total <= buf.len()).then_some(total)
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
        // `n` is an attacker-controlled varint (e.g. the Initial token length),
        // so `self.pos + n` must use checked arithmetic: an unchecked add can
        // wrap past `usize::MAX`, slip under the `> buf.len()` guard, and leave
        // `self.pos` pointing past the buffer, panicking a later `varint()`
        // slice on a raw pre-decryption datagram.
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        if end > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        self.pos = end;
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        // See `skip`: `self.pos + n` on an attacker varint can overflow and make
        // `get` observe a wrapped (valid-looking) range, so compute the end with
        // checked arithmetic before slicing.
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        // Fail closed rather than index `&self.buf[self.pos..]`: if a prior read
        // ever advanced `self.pos` past the buffer, the direct slice would panic.
        let rest = self.buf.get(self.pos..).ok_or(DecodeError::Truncated)?;
        let (v, n) = varint::decode(rest).ok_or(DecodeError::Truncated)?;
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
        let (decoded, aad_len) = Header::decode(&out, 0, 0).unwrap();
        assert_eq!(decoded, hdr);
        assert_eq!(aad_len, out.len());
    }

    #[test]
    fn locate_pn_offset_rejects_overflowing_initial_token_length() {
        // A raw, pre-decryption Initial whose token-length varint is the maximum
        // 8-byte value (2^62-1). `Cursor::skip(tlen)` must fail closed with
        // `Truncated` — an unchecked `self.pos + tlen` would wrap `usize`, slip
        // under the length guard, and panic the following `varint()` slice.
        let mut pkt = vec![LONG_HEADER_FORM | FIXED_BIT]; // Initial, type bits 0x00
        pkt.extend_from_slice(&[0, 0, 0, 1]); // version
        pkt.push(0); // dcid len = 0
        pkt.push(0); // scid len = 0
        pkt.extend_from_slice(&[0xff; 8]); // token length varint = 2^62-1

        assert_eq!(locate_pn_offset(&pkt, 0), Err(DecodeError::Truncated));
        // `long_packet_len` shares the same cursor; it must also stay bounded.
        assert_eq!(long_packet_len(&pkt), None);
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
        let (decoded, _) = Header::decode(&out, 8, 0).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn decode_rejects_unsupported_long_types_and_clear_fixed_bit() {
        // Retry (type bits 0x30) is not transport-processed.
        let retry = vec![LONG_HEADER_FORM | FIXED_BIT | 0x30, 0, 0, 0, 1, 0, 0];
        assert_eq!(
            Header::decode(&retry, 0, 0),
            Err(DecodeError::UnsupportedPacketType)
        );
        // Clear fixed bit on an otherwise-short header.
        let no_fixed = vec![0x00, 0x00];
        assert_eq!(
            Header::decode(&no_fixed, 0, 0),
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
        let (decoded, aad_len) = Header::decode(&packet, 0, 0).unwrap();
        assert_eq!(decoded, hdr);
        let aad2 = packet[..aad_len].to_vec();
        let pt = keys
            .packet
            .decrypt_in_place(pn, &aad2, &mut packet[aad_len..])
            .unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn header_decode_reconstructs_full_packet_number() {
        // Full PN 0xa82f9b32 truncates to 2 wire bytes (0x9b32) against largest
        // 0xa82f30ea; decode MUST return the FULL value (RFC 9000 A.3), not the
        // truncated bytes — otherwise the AEAD nonce (iv XOR full pn) is wrong.
        let largest = 0xa82f30ea;
        let full_pn = 0xa82f9b32;
        let (_, pn_len) = encode_packet_number(full_pn, Some(largest));
        assert_eq!(pn_len, 2);
        let hdr = Header::Long {
            ty: LongType::Handshake,
            version: 1,
            dcid: ConnectionId::new(&[9, 9, 9, 9]),
            scid: ConnectionId::new(&[]),
            token: vec![],
            length: 0,
            packet_number: full_pn,
            pn_len,
        };
        let mut out = Vec::new();
        hdr.encode(&mut out);
        let (decoded, _) = Header::decode(&out, 0, largest).unwrap();
        assert_eq!(decoded, hdr);
        match decoded {
            Header::Long { packet_number, .. } => assert_eq!(packet_number, 0xa82f9b32),
            _ => panic!("expected long header"),
        }
    }

    #[test]
    fn long_packet_len_finds_the_coalesced_boundary() {
        // Two long-header packets concatenated into one datagram (RFC 9000 §12.2):
        // `long_packet_len` of the buffer MUST return exactly the first packet's
        // size, so the receiver lands on the start of the second.
        let mk = |ty, pn: u64, payload: usize| {
            let (_, pn_len) = encode_packet_number(pn, None);
            let length = (pn_len + payload + 16) as u64; // + AEAD tag
            let hdr = Header::Long {
                ty,
                version: 1,
                dcid: ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]),
                scid: ConnectionId::new(&[9, 9]),
                token: vec![],
                length,
                packet_number: pn,
                pn_len,
            };
            let mut out = Vec::new();
            let pn_offset = hdr.encode(&mut out);
            out.resize(pn_offset + length as usize, 0); // payload + tag bytes
            out
        };
        let first = mk(LongType::Initial, 0, 40);
        let second = mk(LongType::Handshake, 0, 25);
        let first_len = first.len();
        let mut datagram = first;
        datagram.extend_from_slice(&second);

        assert_eq!(
            long_packet_len(&datagram),
            Some(first_len),
            "boundary is exactly the first packet's on-wire size"
        );
        // The second packet is a long header too, but it is the last → its own
        // length still resolves (no trailing packet to find, but the value is the
        // packet size).
        assert_eq!(long_packet_len(&datagram[first_len..]), Some(second.len()));
        // A short header has no Length field → None (it is always last).
        let short = {
            let hdr = Header::Short {
                spin: false,
                key_phase: false,
                dcid: ConnectionId::new(&[]),
                packet_number: 1,
                pn_len: 1,
            };
            let mut out = Vec::new();
            hdr.encode(&mut out);
            out.extend_from_slice(&[0u8; 20]);
            out
        };
        assert_eq!(long_packet_len(&short), None);
    }

    #[test]
    fn decode_rejects_reserved_bits() {
        let hdr = Header::Long {
            ty: LongType::Initial,
            version: 1,
            dcid: ConnectionId::new(&[1, 2, 3, 4]),
            scid: ConnectionId::new(&[]),
            token: vec![],
            length: 17,
            packet_number: 0,
            pn_len: 1,
        };
        let mut out = Vec::new();
        hdr.encode(&mut out);
        out[0] |= 0x08; // set a long-header reserved bit (mask 0x0c)
        assert_eq!(
            Header::decode(&out, 0, 0),
            Err(DecodeError::ReservedBitsSet)
        );
    }

    #[test]
    fn decode_rejects_short_header_reserved_bits() {
        // The existing reserved-bits test only covers the LONG header (mask 0x0c);
        // the short-header path has its own guard (mask 0x18). Set a short reserved
        // bit and confirm it is rejected before the packet number is decoded.
        let hdr = Header::Short {
            spin: false,
            key_phase: false,
            dcid: ConnectionId::new(&[0xaa, 0xbb, 0xcc, 0xdd]),
            packet_number: 0,
            pn_len: 1,
        };
        let mut out = Vec::new();
        hdr.encode(&mut out);
        out[0] |= 0x10; // a short-header reserved bit (mask 0x18)
        assert_eq!(
            Header::decode(&out, 4, 0),
            Err(DecodeError::ReservedBitsSet)
        );
    }

    #[test]
    fn decode_rejects_long_header_cid_over_max_len() {
        // A long-header connection-id length byte above MAX_CID_LEN must be rejected
        // (bounds check on a wire-controlled length on an unauthenticated Initial),
        // not truncated silently or used to over-read.
        let mut pkt = vec![LONG_HEADER_FORM | FIXED_BIT]; // Initial, pn_len bits 0
        pkt.extend_from_slice(&1u32.to_be_bytes()); // version
        pkt.push((MAX_CID_LEN + 1) as u8); // DCID length: one over the cap
        pkt.extend_from_slice(&[0x00; MAX_CID_LEN + 1]); // the (too-long) DCID bytes
        assert_eq!(Header::decode(&pkt, 0, 0), Err(DecodeError::CidTooLong));
    }

    #[test]
    fn decode_packet_number_exercises_window_wraparound_branches() {
        // The plain branch (no window adjustment).
        assert_eq!(decode_packet_number(300, 0x05, 1), 261);
        // ADD branch: truncated value belongs to the NEXT window up.
        // largest 0x1ef -> expected 0x1f0; truncated 0x05 -> candidate 0x105 is
        // >half a window below expected, so a window is added -> 0x205.
        assert_eq!(decode_packet_number(0x1ef, 0x05, 1), 0x205);
        // SUB branch: truncated value belongs to the PREVIOUS window down.
        // largest 0x105 -> expected 0x106; truncated 0xfe -> candidate 0x1fe is
        // >half a window above expected, so a window is subtracted -> 0xfe.
        assert_eq!(decode_packet_number(0x105, 0xfe, 1), 0xfe);
    }

    #[test]
    fn decode_packet_number_does_not_overflow_near_u64_max() {
        // `decode_packet_number` runs on every received header BEFORE decryption,
        // so it must be total over its input domain. A `largest_pn` a hair below
        // `u64::MAX` (so `expected = largest_pn + 1` does NOT wrap to 0) drives
        // `expected`/`candidate` near `u64::MAX`, where the pre-fix
        // `candidate + pn_hwin` / `expected + pn_hwin` panicked in debug builds
        // ("attempt to add with overflow"). The saturating adds keep it total.
        // Sweep several such values and all four pn lengths.
        for pn_len in 1..=4usize {
            let pn_mask = (1u64 << (pn_len * 8)) - 1;
            for delta in 0..4u64 {
                let largest_pn = u64::MAX - delta;
                for truncated in [0u64, 1, pn_mask, pn_mask / 2] {
                    let got = decode_packet_number(largest_pn, truncated, pn_len);
                    // Near u64::MAX no window can be added (would overflow past the
                    // 2^62 bound) and the subtract branch's `candidate >= pn_win`
                    // with `candidate` a half-window above `expected` cannot hold, so
                    // the result is always the plain candidate.
                    let expected = largest_pn.wrapping_add(1);
                    let candidate = (expected & !pn_mask) | truncated;
                    assert_eq!(
                        got, candidate,
                        "pn_len {pn_len} delta {delta} truncated {truncated:#x}: \
                         near-u64::MAX decode must return the plain candidate"
                    );
                }
            }
        }
    }

    // The compose test proves the layer ROUND-TRIPS against itself; the three
    // tests below prove the AEAD/HP are not *self-consistently wrong* — i.e. a
    // mistake shared by encrypt and decrypt (constant nonce, unauthenticated
    // header, no-op header protection) that a plain round-trip would miss.

    #[test]
    fn aead_nonce_depends_on_packet_number() {
        use crate::tls::quic::{CipherSuite, DirectionalKeys};
        let keys =
            DirectionalKeys::from_secret(CipherSuite::Aes128GcmSha256, &[0x11u8; 32]).unwrap();
        let aad = b"quic-header";
        let mut at5 = b"the same plaintext payload".to_vec();
        at5.extend_from_slice(&[0u8; 16]);
        let mut at6 = at5.clone();
        keys.packet.encrypt_in_place(5, aad, &mut at5).unwrap();
        keys.packet.encrypt_in_place(6, aad, &mut at6).unwrap();
        assert_ne!(
            at5, at6,
            "AEAD output must depend on the packet number (nonce = iv XOR pn)"
        );
        // Opening pn=5's packet under pn=6 must fail the tag (the nonce is wrong).
        assert!(
            keys.packet.decrypt_in_place(6, aad, &mut at5).is_err(),
            "decrypting with the wrong packet number must fail"
        );
    }

    #[test]
    fn aead_authenticates_the_header_aad() {
        use crate::tls::quic::{CipherSuite, DirectionalKeys};
        let keys =
            DirectionalKeys::from_secret(CipherSuite::Aes128GcmSha256, &[0x33u8; 32]).unwrap();
        let mut sealed = b"payload".to_vec();
        sealed.extend_from_slice(&[0u8; 16]);
        keys.packet
            .encrypt_in_place(1, b"good-aad", &mut sealed)
            .unwrap();
        // A different AAD of the same length must fail to authenticate.
        let mut tampered = sealed.clone();
        assert!(
            keys.packet
                .decrypt_in_place(1, b"evil-aad", &mut tampered)
                .is_err(),
            "the header must be covered as AEAD AAD"
        );
    }

    #[test]
    fn header_protection_actually_masks_and_restores() {
        use crate::tls::quic::{CipherSuite, DirectionalKeys};
        let keys =
            DirectionalKeys::from_secret(CipherSuite::Aes128GcmSha256, &[0x55u8; 32]).unwrap();
        let hdr = Header::Long {
            ty: LongType::Initial,
            version: 1,
            dcid: ConnectionId::new(&[1, 2, 3, 4]),
            scid: ConnectionId::new(&[]),
            token: vec![],
            length: 1 + 16,
            packet_number: 0x41,
            pn_len: 1,
        };
        let mut pkt = Vec::new();
        let pn_offset = hdr.encode(&mut pkt);
        // The HP sample is 16 bytes at pn_offset+4; pad so it exists.
        pkt.extend_from_slice(&[0xab; 32]);
        let plain = pkt.clone();
        keys.header.encrypt_header(pn_offset, &mut pkt).unwrap();
        assert_ne!(
            pkt[..pn_offset + 1],
            plain[..pn_offset + 1],
            "header protection must mask the first byte and packet number"
        );
        keys.header.decrypt_header(pn_offset, &mut pkt).unwrap();
        assert_eq!(
            pkt, plain,
            "removing header protection must restore the bytes"
        );
    }

    #[test]
    fn zero_rtt_long_header_decodes_and_classifies() {
        // A 0-RTT long header (type 0x1) carries no token (like Handshake) and must
        // now decode + classify to the ZeroRtt space, not be rejected/dropped.
        let hdr = Header::Long {
            ty: LongType::ZeroRtt,
            version: 1,
            dcid: ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]),
            scid: ConnectionId::new(&[]),
            token: vec![],
            length: 1 + 16,
            packet_number: 3,
            pn_len: 1,
        };
        let mut pkt = Vec::new();
        let pn_offset = hdr.encode(&mut pkt);
        pkt.extend_from_slice(&[0u8; 32]); // room for the pn + a protected payload
                                           // Classification (from the unmasked first byte) maps to the ZeroRtt space.
        assert_eq!(first_packet_space(&pkt), Some(PacketSpace::ZeroRtt));
        // long_packet_len treats it like any long header (for coalescing).
        assert!(long_packet_len(&pkt).is_some());
        // Decode (header protection already removed) reconstructs the same header.
        let (decoded, aad_len) = Header::decode(&pkt, 0, 0).unwrap();
        assert_eq!(decoded, hdr);
        assert_eq!(aad_len, pn_offset + 1);
    }
}
