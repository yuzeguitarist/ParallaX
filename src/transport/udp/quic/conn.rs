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

use std::sync::Arc;

use super::frame::Frame;
use super::packet::{self, ConnectionId, Header, LongType};
use super::spaces::PacketNumberSpace;
use super::transport_params::TransportParameters;
use crate::tls::quic::{
    ClientConfig, ClientHandshake, DirectionalKeys, Keys, QuicTlsError, Side, QUIC_VERSION_V1,
};

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

/// RFC 9000 §14.1: a client MUST pad every datagram carrying an Initial packet to
/// at least 1200 bytes so the path can carry it before address validation.
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// A hand-rolled QUIC v1 client connection.
///
/// This slice covers the Initial flight only: it constructs the Phase-1 TLS engine,
/// pulls the Safari ClientHello into the Initial CRYPTO stream, and fragments it
/// across 1200-byte Initial datagrams via [`Connection::poll_transmit`]. The
/// receive path, Handshake/1-RTT spaces, timers, and streams land in later slices
/// (the `tls` handle and dcid/scid are retained for them).
pub struct Connection {
    version: u32,
    /// Destination CID (the server's; client-chosen random for the first Initial).
    dcid: ConnectionId,
    /// Our source CID (zero-length for the Safari client).
    scid: ConnectionId,
    tls: ClientHandshake,
    initial_keys: Keys,
    initial_send: PacketNumberSpace,
    /// The outgoing Initial-space CRYPTO byte stream (the ClientHello) and how much
    /// of it has been packetized so far.
    initial_crypto: Vec<u8>,
    initial_crypto_sent: usize,
}

impl Connection {
    /// Start a client connection to `server_name`. `dcid` is the client-chosen
    /// destination connection id for the first Initial (RFC 9001 §5.2 derives the
    /// Initial secrets from it); `scid` is our source CID (zero-length for Safari,
    /// echoed into the `initial_source_connection_id` transport parameter).
    pub fn new_client(
        config: Arc<ClientConfig>,
        server_name: &str,
        dcid: ConnectionId,
        scid: ConnectionId,
    ) -> Result<Self, QuicTlsError> {
        let tp = TransportParameters::safari_client(scid.as_slice());
        let mut tls = ClientHandshake::new(
            config,
            QUIC_VERSION_V1,
            server_name,
            tp.encode_safari_client(),
        )?;
        let initial_keys = tls.initial_keys(dcid.as_slice(), Side::Client);
        // Pull the ClientHello into the Initial CRYPTO stream (no key change yet).
        let mut initial_crypto = Vec::new();
        let _ = tls.write_handshake(&mut initial_crypto);
        Ok(Self {
            version: QUIC_VERSION_V1,
            dcid,
            scid,
            tls,
            initial_keys,
            initial_send: PacketNumberSpace::new(),
            initial_crypto,
            initial_crypto_sent: 0,
        })
    }

    /// Produce the next datagram to send, or `None` when the Initial flight is
    /// fully packetized. Each datagram carries one Initial packet whose CRYPTO
    /// frame holds the next slice of the ClientHello, padded to
    /// [`MIN_INITIAL_DATAGRAM`].
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        if self.initial_crypto_sent >= self.initial_crypto.len() {
            return None;
        }
        let tag_len = self.initial_keys.local.packet.tag_len();
        let offset = self.initial_crypto_sent as u64;
        let pn = self.initial_send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);

        // Encode the header with a 2-byte length placeholder (valid for ~1200) to
        // measure the packet-number offset, then size the CRYPTO chunk to the
        // remaining datagram budget.
        let header = Header::Long {
            ty: LongType::Initial,
            version: self.version,
            dcid: self.dcid,
            scid: self.scid,
            token: Vec::new(),
            length: MIN_INITIAL_DATAGRAM as u64,
            packet_number: pn,
            pn_len,
        };
        let mut probe = Vec::new();
        let pn_offset = header.encode(&mut probe);

        let crypto_hdr = 1 + super::varint::size(offset) + 2;
        let budget = MIN_INITIAL_DATAGRAM.saturating_sub(pn_offset + pn_len + tag_len + crypto_hdr);
        let remaining = self.initial_crypto.len() - self.initial_crypto_sent;
        let chunk_len = remaining.min(budget.max(1));
        let end = self.initial_crypto_sent + chunk_len;

        let datagram = {
            let crypto = Frame::Crypto {
                offset,
                data: &self.initial_crypto[self.initial_crypto_sent..end],
            };
            let mut payload = Vec::new();
            crypto.encode(&mut payload);
            let pad =
                MIN_INITIAL_DATAGRAM.saturating_sub(pn_offset + pn_len + payload.len() + tag_len);
            let frames = if pad > 0 {
                vec![crypto, Frame::Padding(pad)]
            } else {
                vec![crypto]
            };
            seal_packet(&self.initial_keys.local, header, &frames)
        };
        self.initial_crypto_sent = end;
        Some(datagram)
    }
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

    #[test]
    fn client_initial_flight_is_decryptable_and_carries_clienthello() {
        use crate::tls::quic::AcceptAnyServerCert;

        let config = Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ));
        let dcid = packet::ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        let mut conn =
            Connection::new_client(config, "example.com", dcid, packet::ConnectionId::new(&[]))
                .unwrap();

        let mut datagrams = Vec::new();
        while let Some(d) = conn.poll_transmit() {
            datagrams.push(d);
        }
        assert!(!datagrams.is_empty(), "client emits at least one Initial");
        for d in &datagrams {
            assert!(
                d.len() >= 1200,
                "every Initial datagram is padded to >=1200"
            );
        }
        // The Safari ClientHello is large (PQ key share) and MUST NOT fit one
        // datagram — that is the SNI-not-single-packet-extractable property.
        assert!(
            datagrams.len() >= 2,
            "the Safari ClientHello spans more than one Initial datagram"
        );

        // Reassemble the CRYPTO stream by opening each Initial (with our own Initial
        // keys — symmetric AEAD) and concatenating CRYPTO payloads in offset order.
        let mut crypto = Vec::new();
        let mut largest: Option<u64> = None;
        for d in &datagrams {
            let mut buf = d.clone();
            let (hdr, range) = open_packet(&conn.initial_keys.local, &mut buf, 0, largest).unwrap();
            largest = Some(hdr.packet_number());
            for f in super::super::frame::Iter::new(&buf[range]) {
                if let Frame::Crypto { offset, data } = f.unwrap() {
                    assert_eq!(offset as usize, crypto.len(), "contiguous CRYPTO offsets");
                    crypto.extend_from_slice(data);
                }
            }
        }
        // The reassembled stream is a TLS 1.3 ClientHello: type 0x01 then a 3-byte
        // length that frames the rest.
        assert_eq!(crypto[0], 0x01, "CRYPTO stream starts with ClientHello");
        let body_len = u32::from_be_bytes([0, crypto[1], crypto[2], crypto[3]]) as usize;
        assert_eq!(
            crypto.len(),
            4 + body_len,
            "ClientHello length frames the CRYPTO stream"
        );
    }
}
