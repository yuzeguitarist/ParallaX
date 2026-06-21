//! Connection packet I/O and the role-generic QUIC connection state machine
//! (RFC 9000 §10, RFC 9001 §5), clean-room.
//!
//! [`seal_packet`] / [`open_packet`] tie the wire codec ([`super::packet`],
//! [`super::frame`]) to the SHIPPING AEAD / header-protection keys from the
//! Phase-1 TLS engine ([`crate::tls::quic::DirectionalKeys`]) — no crypto is
//! re-implemented. [`Connection`] drives the handshake on top: it owns the three
//! packet-number spaces, pumps the [`TlsSession`] (client or server) for CRYPTO
//! bytes + key transitions, fragments them into packets, and processes incoming
//! datagrams (locate PN → remove HP → AEAD-open → dispatch frames → feed CRYPTO).
//!
//! This slice carries the handshake to completion (the in-memory loopback
//! milestone). Loss recovery / ACK timing (RFC 9002) and the 1-RTT data streams
//! land in later slices; a lossless loopback completes without them.

use std::sync::Arc;

use super::frame::{Frame, Iter};
use super::packet::{self, ConnectionId, Header, LongType, PacketSpace};
use super::spaces::{PacketNumberSpace, ReceivedPackets};
use super::transport_params::TransportParameters;
use crate::tls::quic::{
    initial_keys, ClientConfig, ClientHandshake, DirectionalKeys, KeyChange, KeyPair, Keys,
    PacketKey, QuicTlsError, ServerHandshake, Side, TlsSession, QUIC_VERSION_V1,
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
/// A conservative max UDP payload for non-Initial packets (one datagram holds the
/// whole Handshake flight in practice).
const MAX_DATAGRAM: usize = 1252;

const SPACE_INITIAL: usize = 0;
const SPACE_HANDSHAKE: usize = 1;
const SPACE_DATA: usize = 2;

fn space_index(space: PacketSpace) -> usize {
    match space {
        PacketSpace::Initial => SPACE_INITIAL,
        PacketSpace::Handshake => SPACE_HANDSHAKE,
        PacketSpace::OneRtt => SPACE_DATA,
    }
}

/// Per-packet-number-space state: protection keys (installed as the handshake
/// crosses spaces), the send allocator + received-PN set, and the in-/out-bound
/// CRYPTO byte streams.
#[derive(Default)]
struct Space {
    keys: Option<Keys>,
    send: PacketNumberSpace,
    recv: ReceivedPackets,
    /// Outgoing CRYPTO bytes and how much has been packetized.
    crypto_send: Vec<u8>,
    crypto_send_off: usize,
    /// Next in-order CRYPTO offset expected on receive, plus buffered future gaps.
    crypto_recv_off: u64,
    crypto_pending: Vec<(u64, Vec<u8>)>,
}

/// The relay's single bidirectional stream (client-initiated, id 0): the outgoing
/// byte buffer + how much has been packetized, and the in-order reassembled
/// inbound bytes. Flow control, FIN, and the general N-stream mux land with the
/// stream API in a later slice; the relay rides exactly this one bidi.
#[derive(Default)]
struct BidiStream {
    send: Vec<u8>,
    send_off: u64,
    recv: Vec<u8>,
    recv_off: u64,
    recv_pending: Vec<(u64, Vec<u8>)>,
}

/// The relay bidi stream id (client-initiated bidirectional stream 0, RFC 9000
/// §2.1). Both ends read and write it.
const RELAY_STREAM_ID: u64 = 0;

/// A hand-rolled QUIC v1 connection (client or server), carried to handshake
/// completion. Role-generic over a [`TlsSession`].
pub struct Connection {
    side: Side,
    version: u32,
    /// The DCID the Initial secrets are derived from (RFC 9001 §5.2) — fixed once
    /// known (the client's first-Initial choice).
    initial_dcid: ConnectionId,
    /// The peer connection id placed in outgoing headers; updated to the peer's
    /// advertised SCID once seen.
    dcid: ConnectionId,
    /// Our source connection id (zero-length for the Safari client).
    scid: ConnectionId,
    peer_cid_adopted: bool,
    tls: Box<dyn TlsSession>,
    spaces: [Space; 3],
    /// The space the next `write_handshake` bytes belong to (advances on KeyChange).
    write_level: usize,
    /// The relay's single bidirectional data stream (1-RTT).
    stream: BidiStream,
}

impl Connection {
    /// Start a client connection. `dcid` is the client-chosen destination
    /// connection id for the first Initial; `scid` is our (zero-length) source CID.
    pub fn new_client(
        config: Arc<ClientConfig>,
        server_name: &str,
        dcid: ConnectionId,
        scid: ConnectionId,
    ) -> Result<Self, QuicTlsError> {
        let tp = TransportParameters::safari_client(scid.as_slice());
        let tls = ClientHandshake::new(
            config,
            QUIC_VERSION_V1,
            server_name,
            tp.encode_safari_client(),
        )?;
        let mut spaces = [Space::default(), Space::default(), Space::default()];
        spaces[SPACE_INITIAL].keys = Some(initial_keys(dcid.as_slice(), Side::Client));
        let mut conn = Self {
            side: Side::Client,
            version: QUIC_VERSION_V1,
            initial_dcid: dcid,
            dcid,
            scid,
            peer_cid_adopted: false,
            tls: Box::new(tls),
            spaces,
            write_level: SPACE_INITIAL,
            stream: BidiStream::default(),
        };
        conn.pump_write(); // pull the ClientHello into the Initial CRYPTO stream
        Ok(conn)
    }

    /// Start a server connection. `scid` is the server's source CID; the Initial
    /// keys and the client's CID are learned from the first Initial datagram.
    pub fn new_server(
        cert_chain: Vec<Vec<u8>>,
        signing_key_pkcs8: &[u8],
        alpn_protocols: Vec<Vec<u8>>,
        transport_params: Vec<u8>,
        scid: ConnectionId,
    ) -> Result<Self, QuicTlsError> {
        let tls = ServerHandshake::new(
            cert_chain,
            signing_key_pkcs8,
            alpn_protocols,
            transport_params,
        )?;
        Ok(Self {
            side: Side::Server,
            version: QUIC_VERSION_V1,
            initial_dcid: ConnectionId::new(&[]),
            dcid: ConnectionId::new(&[]),
            scid,
            peer_cid_adopted: false,
            tls: Box::new(tls),
            spaces: [Space::default(), Space::default(), Space::default()],
            write_level: SPACE_INITIAL,
            stream: BidiStream::default(),
        })
    }

    pub fn is_handshaking(&self) -> bool {
        self.tls.is_handshaking()
    }

    /// RFC 5705 exporter (byte-identical on both ends; backs the auth token).
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), QuicTlsError> {
        self.tls.export_keying_material(out, label, context)
    }

    /// The peer's raw `quic_transport_parameters` blob, once the handshake has
    /// exchanged them (the relay parses it with [`TransportParameters::read`]).
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.tls.peer_transport_parameters()
    }

    /// The next 1-RTT packet-key generation for a key update (RFC 9001 §6). MUST
    /// be `Some` once the connection has 1-RTT keys (the Data-space-entry contract).
    pub fn next_1rtt_keys(&mut self) -> Option<KeyPair<PacketKey>> {
        self.tls.next_1rtt_keys()
    }

    /// Queue application bytes for the relay's bidi stream; they are packetized
    /// into 1-RTT STREAM frames once the handshake installs Data keys.
    pub fn send_stream(&mut self, data: &[u8]) {
        self.stream.send.extend_from_slice(data);
    }

    /// Take the bytes reassembled in order from the peer's STREAM frames.
    pub fn read_stream(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stream.recv)
    }

    /// Drain the TLS engine's outgoing CRYPTO into the right space and install the
    /// Handshake / 1-RTT keys as the engine hands them over.
    fn pump_write(&mut self) {
        loop {
            let mut buf = Vec::new();
            let kc = self.tls.write_handshake(&mut buf);
            if !buf.is_empty() {
                self.spaces[self.write_level]
                    .crypto_send
                    .extend_from_slice(&buf);
            }
            match kc {
                Some(KeyChange::Handshake { keys }) => {
                    self.spaces[SPACE_HANDSHAKE].keys = Some(keys);
                    self.write_level = SPACE_HANDSHAKE;
                }
                Some(KeyChange::OneRtt { keys }) => {
                    self.spaces[SPACE_DATA].keys = Some(keys);
                    self.write_level = SPACE_DATA;
                }
                None => {
                    if buf.is_empty() {
                        break;
                    }
                }
            }
        }
    }

    /// Produce the next datagram to send (one CRYPTO packet from the lowest space
    /// with pending handshake bytes and installed keys), or `None` when idle.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            let sp = &self.spaces[space];
            if sp.keys.is_some() && sp.crypto_send_off < sp.crypto_send.len() {
                return Some(self.build_crypto_packet(space));
            }
        }
        // 1-RTT relay data: once Data keys are installed, drain the bidi stream.
        if self.spaces[SPACE_DATA].keys.is_some()
            && (self.stream.send_off as usize) < self.stream.send.len()
        {
            return Some(self.build_stream_packet());
        }
        None
    }

    fn build_crypto_packet(&mut self, space: usize) -> Vec<u8> {
        let pn = self.spaces[space].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let offset = self.spaces[space].crypto_send_off as u64;
        let tag_len = self.spaces[space]
            .keys
            .as_ref()
            .unwrap()
            .local
            .packet
            .tag_len();

        let header = match space {
            SPACE_INITIAL | SPACE_HANDSHAKE => {
                let ty = if space == SPACE_INITIAL {
                    LongType::Initial
                } else {
                    LongType::Handshake
                };
                Header::Long {
                    ty,
                    version: self.version,
                    dcid: self.dcid,
                    scid: self.scid,
                    token: Vec::new(),
                    length: MIN_INITIAL_DATAGRAM as u64, // 2-byte-varint placeholder
                    packet_number: pn,
                    pn_len,
                }
            }
            _ => Header::Short {
                spin: false,
                key_phase: false,
                dcid: self.dcid,
                packet_number: pn,
                pn_len,
            },
        };
        let mut probe = Vec::new();
        let pn_offset = header.encode(&mut probe);

        let crypto_hdr = 1 + super::varint::size(offset) + 2;
        let cap = if space == SPACE_INITIAL {
            MIN_INITIAL_DATAGRAM
        } else {
            MAX_DATAGRAM
        };
        let budget = cap.saturating_sub(pn_offset + pn_len + tag_len + crypto_hdr);
        let remaining = self.spaces[space].crypto_send.len() - self.spaces[space].crypto_send_off;
        let chunk_len = remaining.min(budget.max(1));
        let end = self.spaces[space].crypto_send_off + chunk_len;

        let datagram = {
            let crypto = Frame::Crypto {
                offset,
                data: &self.spaces[space].crypto_send[self.spaces[space].crypto_send_off..end],
            };
            let mut payload = Vec::new();
            crypto.encode(&mut payload);
            let frames = if space == SPACE_INITIAL {
                let pad = MIN_INITIAL_DATAGRAM
                    .saturating_sub(pn_offset + pn_len + payload.len() + tag_len);
                if pad > 0 {
                    vec![crypto, Frame::Padding(pad)]
                } else {
                    vec![crypto]
                }
            } else {
                vec![crypto]
            };
            let keys = self.spaces[space].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, &frames)
        };
        self.spaces[space].crypto_send_off = end;
        datagram
    }

    /// Build one 1-RTT (short-header) packet carrying a STREAM frame with the next
    /// slice of the relay stream's outgoing bytes.
    fn build_stream_packet(&mut self) -> Vec<u8> {
        let pn = self.spaces[SPACE_DATA].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let offset = self.stream.send_off;
        let tag_len = self.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .unwrap()
            .local
            .packet
            .tag_len();

        let header = Header::Short {
            spin: false,
            key_phase: false,
            dcid: self.dcid,
            packet_number: pn,
            pn_len,
        };
        let mut probe = Vec::new();
        let pn_offset = header.encode(&mut probe);

        let frame_hdr = 1 + super::varint::size(RELAY_STREAM_ID) + super::varint::size(offset) + 2;
        let budget = MAX_DATAGRAM.saturating_sub(pn_offset + pn_len + tag_len + frame_hdr);
        let remaining = self.stream.send.len() - self.stream.send_off as usize;
        let chunk_len = remaining.min(budget.max(1));
        let end = self.stream.send_off as usize + chunk_len;

        let datagram = {
            let frame = Frame::Stream {
                id: RELAY_STREAM_ID,
                offset,
                fin: false,
                data: &self.stream.send[self.stream.send_off as usize..end],
            };
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, &[frame])
        };
        self.stream.send_off = end as u64;
        datagram
    }

    /// Process one received datagram: identify the space, (for the server's first
    /// Initial) derive Initial keys + learn CIDs, AEAD-open, dispatch the frames,
    /// then pump the TLS engine for the response and key transitions.
    pub fn handle_datagram(&mut self, datagram: &[u8]) -> Result<(), QuicTlsError> {
        let pspace = packet::first_packet_space(datagram)
            .ok_or_else(|| QuicTlsError::Crypto("unsupported packet type".into()))?;
        let space = space_index(pspace);

        // Server learns the client's chosen DCID (for Initial keys) + SCID, and
        // either endpoint adopts the peer's SCID as its outgoing DCID.
        if matches!(pspace, PacketSpace::Initial | PacketSpace::Handshake) {
            let (dcid, scid) = packet::peek_long_cids(datagram)
                .map_err(|_| QuicTlsError::Crypto("malformed long header".into()))?;
            if self.side == Side::Server && self.spaces[SPACE_INITIAL].keys.is_none() {
                self.initial_dcid = dcid;
                self.spaces[SPACE_INITIAL].keys = Some(initial_keys(dcid.as_slice(), Side::Server));
            }
            if !self.peer_cid_adopted {
                self.dcid = scid;
                self.peer_cid_adopted = true;
            }
        }

        let local_cid_len = self.scid.len();
        let largest = self.spaces[space].recv.largest();
        let mut buf = datagram.to_vec();
        let (header, range) = {
            let keys = self.spaces[space]
                .keys
                .as_ref()
                .ok_or_else(|| QuicTlsError::Crypto("no keys for packet space".into()))?;
            open_packet(&keys.remote, &mut buf, local_cid_len, largest)
                .map_err(|e| QuicTlsError::Crypto(format!("packet open failed: {e:?}")))?
        };

        // Drop a duplicate (replayed) packet without reprocessing it.
        if !self.spaces[space].recv.insert(header.packet_number()) {
            return Ok(());
        }

        // Copy the decrypted frames out so the TLS engine can be mutated while we
        // iterate.
        let payload = buf[range].to_vec();
        for frame in Iter::new(&payload) {
            let frame =
                frame.map_err(|e| QuicTlsError::Crypto(format!("frame decode failed: {e:?}")))?;
            // CRYPTO advances the handshake; STREAM carries 1-RTT relay data. ACK
            // timing / loss recovery land in B2; other frames are ignored here.
            match frame {
                Frame::Crypto { offset, data } => self.recv_crypto(space, offset, data)?,
                Frame::Stream {
                    id, offset, data, ..
                } if id == RELAY_STREAM_ID => self.recv_stream(offset, data),
                _ => {}
            }
        }
        self.pump_write();
        Ok(())
    }

    /// Reassemble an incoming CRYPTO fragment in order and feed the contiguous
    /// run to the TLS engine (which buffers partial handshake messages itself).
    fn recv_crypto(&mut self, space: usize, offset: u64, data: &[u8]) -> Result<(), QuicTlsError> {
        let mut to_feed: Vec<u8> = Vec::new();
        {
            let sp = &mut self.spaces[space];
            if offset > sp.crypto_recv_off {
                sp.crypto_pending.push((offset, data.to_vec()));
            } else {
                let skip = (sp.crypto_recv_off - offset) as usize;
                if skip < data.len() {
                    to_feed.extend_from_slice(&data[skip..]);
                    sp.crypto_recv_off += (data.len() - skip) as u64;
                }
                // Drain any buffered fragments that are now contiguous.
                while let Some(i) = sp.crypto_pending.iter().position(|(o, d)| {
                    *o <= sp.crypto_recv_off && *o + d.len() as u64 > sp.crypto_recv_off
                }) {
                    let (o, d) = sp.crypto_pending.remove(i);
                    let s = (sp.crypto_recv_off - o) as usize;
                    to_feed.extend_from_slice(&d[s..]);
                    sp.crypto_recv_off += (d.len() - s) as u64;
                }
            }
        }
        if !to_feed.is_empty() {
            self.tls.read_handshake(&to_feed)?;
        }
        Ok(())
    }

    /// Reassemble an incoming STREAM fragment in order into the relay stream's
    /// receive buffer (out-of-order fragments are buffered until contiguous).
    fn recv_stream(&mut self, offset: u64, data: &[u8]) {
        let s = &mut self.stream;
        if offset > s.recv_off {
            s.recv_pending.push((offset, data.to_vec()));
            return;
        }
        let skip = (s.recv_off - offset) as usize;
        if skip < data.len() {
            s.recv.extend_from_slice(&data[skip..]);
            s.recv_off += (data.len() - skip) as u64;
        }
        while let Some(i) = s
            .recv_pending
            .iter()
            .position(|(o, d)| *o <= s.recv_off && *o + d.len() as u64 > s.recv_off)
        {
            let (o, d) = s.recv_pending.remove(i);
            let sk = (s.recv_off - o) as usize;
            s.recv.extend_from_slice(&d[sk..]);
            s.recv_off += (d.len() - sk) as u64;
        }
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
            length: 0,
            packet_number: 0,
            pn_len: 1,
        };

        let mut datagram = seal_packet(&keys, header, &frames);
        let (decoded, range) = open_packet(&keys, &mut datagram, 0, None).unwrap();
        assert_eq!(decoded.packet_number(), 0);
        let frames_back: Vec<_> = Iter::new(&datagram[range])
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(frames_back, frames);
    }

    #[test]
    fn short_packet_reconstructs_full_packet_number() {
        let keys = test_keys();
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
        let (decoded, range) = open_packet(&keys, &mut datagram, 0, Some(0x1_0000)).unwrap();
        assert_eq!(decoded.packet_number(), full_pn, "full PN reconstructed");
        let frames_back: Vec<_> = Iter::new(&datagram[range])
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

    fn client_config() -> Arc<ClientConfig> {
        use crate::tls::quic::AcceptAnyServerCert;
        Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ))
    }

    /// A throwaway ECDSA P-256 PKCS#8 key for the server's CertificateVerify.
    fn server_key() -> Vec<u8> {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec()
    }

    #[test]
    fn client_initial_flight_is_decryptable_and_carries_clienthello() {
        let dcid = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        let mut conn =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();

        let mut datagrams = Vec::new();
        while let Some(d) = conn.poll_transmit() {
            datagrams.push(d);
        }
        assert!(
            datagrams.len() >= 2,
            "the Safari ClientHello spans >1 Initial"
        );
        for d in &datagrams {
            assert!(
                d.len() >= 1200,
                "every Initial datagram is padded to >=1200"
            );
        }

        let initial_keys = conn.spaces[SPACE_INITIAL].keys.as_ref().unwrap();
        let mut crypto = Vec::new();
        let mut largest: Option<u64> = None;
        for d in &datagrams {
            let mut buf = d.clone();
            let (hdr, range) = open_packet(&initial_keys.local, &mut buf, 0, largest).unwrap();
            largest = Some(hdr.packet_number());
            for f in Iter::new(&buf[range]) {
                if let Frame::Crypto { offset, data } = f.unwrap() {
                    assert_eq!(offset as usize, crypto.len(), "contiguous CRYPTO offsets");
                    crypto.extend_from_slice(data);
                }
            }
        }
        assert_eq!(crypto[0], 0x01, "CRYPTO stream starts with ClientHello");
    }

    #[test]
    fn client_and_server_complete_a_quic_handshake_over_loopback() {
        let dcid = ConnectionId::new(&[0xc0, 0xff, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        // A dummy cover cert (the REALITY client accepts any) + a server TP blob.
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            vec![0x01, 0x02, 0x03, 0x04],
            ConnectionId::new(&[0xab, 0xcd, 0xef, 0x01]),
        )
        .unwrap();

        // Ping-pong real QUIC datagrams until both sides go idle (lossless: no ACKs).
        drive(&mut client, &mut server);

        assert!(!client.is_handshaking(), "client handshake completed");
        assert!(!server.is_handshaking(), "server handshake completed");

        // The exporter (RFC 5705) is byte-identical on both ends.
        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        client
            .export_keying_material(&mut ce, b"parallax tudp", b"binding")
            .unwrap();
        server
            .export_keying_material(&mut se, b"parallax tudp", b"binding")
            .unwrap();
        assert_eq!(ce, se, "client and server agree on exporter material");
        assert_ne!(ce, [0u8; 32], "exporter produced real key material");

        // Transport parameters were exchanged both ways.
        assert_eq!(
            client.peer_transport_parameters(),
            Some([0x01, 0x02, 0x03, 0x04].as_ref()),
            "client received the server's transport parameters"
        );
        assert!(
            server
                .peer_transport_parameters()
                .is_some_and(|tp| !tp.is_empty()),
            "server received the client's (Safari) transport parameters"
        );
        // The next 1-RTT keys MUST be ready once the handshake completes.
        assert!(
            client.next_1rtt_keys().is_some(),
            "client 1-RTT key update ready"
        );
        assert!(
            server.next_1rtt_keys().is_some(),
            "server 1-RTT key update ready"
        );
    }

    /// Ping-pong datagrams between two connections until neither has anything more
    /// to send (handshake CRYPTO, then 1-RTT data).
    fn drive(a: &mut Connection, b: &mut Connection) {
        for _ in 0..16 {
            let mut moved = false;
            while let Some(dg) = a.poll_transmit() {
                b.handle_datagram(&dg).unwrap();
                moved = true;
            }
            while let Some(dg) = b.poll_transmit() {
                a.handle_datagram(&dg).unwrap();
                moved = true;
            }
            if !moved {
                break;
            }
        }
    }

    #[test]
    fn relay_data_round_trips_over_one_rtt() {
        let dcid = ConnectionId::new(&[0x0a; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            vec![0x01, 0x02, 0x03, 0x04],
            ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(
            !client.is_handshaking() && !server.is_handshaking(),
            "handshake done"
        );

        // Client -> server over the 1-RTT bidi stream.
        let request = b"GET / over the hand-rolled QUIC 1-RTT relay stream";
        client.send_stream(request);
        drive(&mut client, &mut server);
        assert_eq!(server.read_stream(), request, "server received the request");

        // Server -> client over the same bidi stream.
        let response = b"200 OK back over the hand-rolled bidi stream";
        server.send_stream(response);
        drive(&mut client, &mut server);
        assert_eq!(
            client.read_stream(),
            response,
            "client received the response"
        );
    }
}
