//! Connection packet I/O: seal an outgoing packet and open an incoming one
//! (RFC 9001 §5.3/§5.4 packet + header protection), clean-room.
//!
//! These tie the wire codec ([`super::packet`], [`super::frame`]) to the SHIPPING
//! AEAD / header-protection keys from the Phase-1 TLS engine
//! ([`crate::tls::quic::DirectionalKeys`]) — no crypto is re-implemented. The
//! connection state machine (built on top, in this module later) drives them per
//! packet-number space.
//!
//! Send: encode the header (plaintext PN), append the frame payload, AEAD-seal
//! with the header as AAD, then apply header protection. Receive: locate the PN
//! offset, remove header protection, decode the header, reconstruct the full
//! packet number from the space's largest seen PN (RFC 9000 Appendix A.3), and
//! AEAD-open the payload.

use super::frame::Frame;
use super::packet::{self, Header};
use crate::tls::quic::DirectionalKeys;

/// Error opening (decrypting/parsing) an incoming packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// Header parse failed or ran off the buffer.
    Decode(packet::DecodeError),
    /// The §17.2 Length field pointed past the datagram, or below the PN length.
    Malformed,
    /// AEAD open or header-protection removal failed (bad key / forged packet).
    Crypto,
}

impl From<packet::DecodeError> for OpenError {
    fn from(e: packet::DecodeError) -> Self {
        OpenError::Decode(e)
    }
}

/// Seal one packet into a datagram: encode `header` (its `length` is computed
/// here for long headers), append the encoded `frames`, AEAD-seal with the header
/// as AAD, then apply header protection. The header's `packet_number`/`pn_len`
/// must already be set (the caller picks `pn_len` via
/// [`packet::encode_packet_number`]). Returns the protected datagram.
pub fn seal_packet(keys: &DirectionalKeys, mut header: Header, frames: &[Frame]) -> Vec<u8> {
    let mut payload = Vec::new();
    for f in frames {
        f.encode(&mut payload);
    }
    let tag_len = keys.packet.tag_len();
    let pn = header.packet_number();
    let pn_len = header.pn_len();
    if let Header::Long { length, .. } = &mut header {
        *length = (pn_len + payload.len() + tag_len) as u64;
    }

    let mut pkt = Vec::with_capacity(pn_len + payload.len() + tag_len + 32);
    let pn_offset = header.encode(&mut pkt);
    // AEAD AAD = the header bytes through the (plaintext) packet number.
    let aad = pkt[..pn_offset + pn_len].to_vec();
    let body = pkt.len();
    pkt.extend_from_slice(&payload);
    pkt.resize(pkt.len() + tag_len, 0);
    keys.packet
        .encrypt_in_place(pn, &aad, &mut pkt[body..])
        .expect("packet buffer reserves the AEAD tag");
    keys.header
        .encrypt_header(pn_offset, &mut pkt)
        .expect("sealed packet is longer than the HP sample");
    pkt
}

/// Open one packet in place. `datagram` is decrypted in place: header protection
/// is removed, the header decoded, the full packet number reconstructed from
/// `largest_pn` (the largest PN already processed in this space, `None` before the
/// first), and the payload AEAD-opened. `local_cid_len` is the length of the CID
/// this endpoint issues (needed for short headers). Returns the decoded header
/// (with the full packet number) and the byte range of the decrypted frame
/// payload within `datagram`.
pub fn open_packet(
    keys: &DirectionalKeys,
    datagram: &mut [u8],
    local_cid_len: usize,
    largest_pn: Option<u64>,
) -> Result<(Header, std::ops::Range<usize>), OpenError> {
    let pn_offset = packet::locate_pn_offset(datagram, local_cid_len)?;
    keys.header
        .decrypt_header(pn_offset, datagram)
        .map_err(|_| OpenError::Crypto)?;
    let (mut header, aad_len) = Header::decode(datagram, local_cid_len)?;

    // Reconstruct the full packet number from the truncated wire value.
    let truncated = header.packet_number();
    let pn_len = header.pn_len();
    let full_pn = match largest_pn {
        Some(largest) => packet::decode_packet_number(largest, truncated, pn_len),
        None => truncated,
    };
    header.set_packet_number(full_pn);

    // The protected region: long headers carry an explicit Length; short headers
    // run to the end of the datagram.
    let body_end = match &header {
        Header::Long { length, .. } => {
            let body = (*length as usize)
                .checked_sub(pn_len)
                .ok_or(OpenError::Malformed)?;
            aad_len.checked_add(body).ok_or(OpenError::Malformed)?
        }
        Header::Short { .. } => datagram.len(),
    };
    if body_end > datagram.len() || body_end < aad_len {
        return Err(OpenError::Malformed);
    }

    let aad = datagram[..aad_len].to_vec();
    let pt = keys
        .packet
        .decrypt_in_place(full_pn, &aad, &mut datagram[aad_len..body_end])
        .map_err(|_| OpenError::Crypto)?;
    let pt_len = pt.len();
    Ok((header, aad_len..aad_len + pt_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::quic::CipherSuite;

    fn test_keys() -> DirectionalKeys {
        DirectionalKeys::from_secret(CipherSuite::Aes128GcmSha256, &[0x42u8; 32]).unwrap()
    }

    #[test]
    fn initial_packet_seal_open_round_trips() {
        let keys = test_keys();
        let frames = [
            Frame::Crypto {
                offset: 0,
                data: b"a fragment of the safari clienthello bytes",
            },
            Frame::Padding(8),
        ];
        let header = Header::Long {
            ty: packet::LongType::Initial,
            version: 1,
            dcid: packet::ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]),
            scid: packet::ConnectionId::new(&[]),
            token: vec![],
            length: 0, // computed by seal_packet
            packet_number: 0,
            pn_len: 1,
        };

        let mut datagram = seal_packet(&keys, header, &frames);
        let (decoded, range) = open_packet(&keys, &mut datagram, 0, None).unwrap();
        assert_eq!(decoded.packet_number(), 0);
        let frames_back: Vec<_> = super::super::frame::Iter::new(&datagram[range])
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(frames_back, frames);
    }

    #[test]
    fn short_packet_reconstructs_full_packet_number() {
        let keys = test_keys();
        // A 1-RTT packet at full PN 0x1_0005 sent with the peer's largest at 0x1_0000.
        let full_pn = 0x1_0005;
        let (_, pn_len) = packet::encode_packet_number(full_pn, Some(0x1_0000));
        let frames = [Frame::Stream {
            id: 0,
            offset: 0,
            fin: false,
            data: b"relay bytes over the bidi stream, long enough to sample",
        }];
        let header = Header::Short {
            spin: false,
            key_phase: false,
            dcid: packet::ConnectionId::new(&[]),
            packet_number: full_pn,
            pn_len,
        };
        let mut datagram = seal_packet(&keys, header, &frames);
        // Receiver knows the largest processed PN is 0x1_0000.
        let (decoded, range) = open_packet(&keys, &mut datagram, 0, Some(0x1_0000)).unwrap();
        assert_eq!(decoded.packet_number(), full_pn, "full PN reconstructed");
        let frames_back: Vec<_> = super::super::frame::Iter::new(&datagram[range])
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(frames_back, frames);
    }

    #[test]
    fn open_rejects_a_packet_under_the_wrong_key() {
        let keys = test_keys();
        let other =
            DirectionalKeys::from_secret(CipherSuite::Aes128GcmSha256, &[0x99u8; 32]).unwrap();
        let header = Header::Long {
            ty: packet::LongType::Handshake,
            version: 1,
            dcid: packet::ConnectionId::new(&[9, 9, 9, 9]),
            scid: packet::ConnectionId::new(&[]),
            token: vec![],
            length: 0,
            packet_number: 1,
            pn_len: 1,
        };
        let mut datagram = seal_packet(&keys, header, &[Frame::Ping, Frame::Padding(20)]);
        assert_eq!(
            open_packet(&other, &mut datagram, 0, None),
            Err(OpenError::Crypto)
        );
    }
}
