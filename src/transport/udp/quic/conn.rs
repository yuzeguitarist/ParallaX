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

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::congestion::{Controller, NewReno};
use super::frame::{Ack, Frame, Iter};
use super::packet::{self, ConnectionId, Header, LongType, PacketSpace};
use super::recovery::{RttEstimator, SentPacket, SentPackets};
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
    // `Header::decode` reconstructs the full packet number internally from
    // `largest_pn` (the largest PN already processed in this space; 0 before the
    // first packet, which makes the reconstruction a no-op for the small early
    // packet numbers — equivalent to taking the truncated value verbatim).
    let (header, aad_len) = Header::decode(datagram, local_cid_len, largest_pn.unwrap_or(0))?;
    let pn_len = header.pn_len();
    let full_pn = header.packet_number();

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

/// Cap on out-of-order CRYPTO bytes buffered per space. The handshake transcript
/// is small; since Initial keys derive from the public DCID, an unbounded buffer
/// is a memory-exhaustion DoS (anyone can mint Initials carrying CRYPTO frames at
/// ever-rising offsets that never become contiguous).
const MAX_CRYPTO_REASSEMBLY: usize = 64 * 1024;

/// RFC 9000 §18.2 default `ack_delay_exponent`. The peer scales its ACK `delay`
/// field by `2^exponent` microseconds; we decode with the default (neither we nor
/// the Safari client negotiate a different value).
const ACK_DELAY_EXPONENT: u32 = 3;

/// RFC 9002 §6.2.1 `max_ack_delay` added to the PTO. The relay does not negotiate
/// a different value; the QUIC default is 25 ms.
const MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// Cap on PTO exponential backoff (`2^pto_count`) so a long outage cannot overflow
/// the timer arithmetic; 2^8 = 256× the base PTO is far beyond any live path.
const MAX_PTO_BACKOFF: u32 = 8;

/// Keep-alive period: send a PING if the connection has been idle this long, to
/// stop the peer's idle timer from tearing down a held-open relay (matches the
/// `keep_alive_interval` the quinn carrier configured).
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

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

/// What an ack-eliciting sent packet carried that must be RESENT (in a new packet,
/// RFC 9002 §6.2.4) if the packet is declared lost. ACK/PADDING/PING carry nothing
/// retransmittable, so a pure-ACK packet stores an empty record (and is not even
/// tracked here — only ack-eliciting packets are).
#[derive(Default, Clone)]
struct SentContent {
    /// CRYPTO byte ranges `(offset, len)` in this space's outgoing CRYPTO stream.
    crypto: Vec<(u64, u64)>,
    /// Relay-stream byte ranges `(stream_id, offset, len, fin)`.
    stream: Vec<(u64, u64, u64, bool)>,
    /// This packet carried HANDSHAKE_DONE (RFC 9001 §4.1.2); resend it if lost.
    handshake_done: bool,
    /// This packet carried a connection MAX_DATA update; re-arm it if lost.
    max_data: bool,
    /// Stream ids whose MAX_STREAM_DATA this packet carried; re-arm them if lost.
    max_stream_data: Vec<u64>,
}

/// Per-packet-number-space state: protection keys (installed as the handshake
/// crosses spaces), the send allocator + received-PN set, and the in-/out-bound
/// CRYPTO byte streams.
#[derive(Default)]
struct Space {
    keys: Option<Keys>,
    send: PacketNumberSpace,
    recv: ReceivedPackets,
    /// Sent-packet bookkeeping for loss detection + RTT (RFC 9002 §6.1).
    sent: SentPackets,
    /// Per-packet-number retransmittable content, kept in lockstep with `sent`:
    /// removed when the packet is acked, drained into the retransmit queues when
    /// it is declared lost.
    sent_content: BTreeMap<u64, SentContent>,
    /// An ack-eliciting packet has been received and not yet acknowledged.
    ack_pending: bool,
    /// CRYPTO byte ranges to RESEND (lost packets) before any fresh CRYPTO.
    retransmit_crypto: Vec<(u64, u64)>,
    /// Earliest armed time-threshold loss deadline (RFC 9002 §6.1.2), if any.
    loss_time: Option<Instant>,
    /// Outgoing CRYPTO bytes and how much has been packetized.
    crypto_send: Vec<u8>,
    crypto_send_off: usize,
    /// Next in-order CRYPTO offset expected on receive, plus buffered future gaps.
    crypto_recv_off: u64,
    crypto_pending: Vec<(u64, Vec<u8>)>,
}

/// One QUIC stream's send + receive halves (RFC 9000 §2–3). A unidirectional
/// stream drives only the half its initiator owns; a bidirectional stream uses
/// both. The relay opens one client bidi (id 0) for data plus a few uni streams
/// for HTTP/3 control + QPACK. Connection- and stream-level flow control (RFC 9000
/// §4) bound how much each side may send and buffer.
#[derive(Default)]
struct Stream {
    // Send half (bytes this endpoint transmits on the stream).
    send: Vec<u8>,
    /// Next absolute offset to packetize from `send`.
    send_off: u64,
    /// Peer's MAX_STREAM_DATA limit: we MUST NOT send past this absolute offset.
    send_max: u64,
    /// Lost `(offset, len, fin)` ranges to resend before fresh bytes.
    retransmit: Vec<(u64, u64, bool)>,
    /// The app has requested FIN after all buffered bytes.
    fin: bool,
    /// The FIN bit has been packetized at the final offset.
    fin_sent: bool,
    // Receive half (bytes this endpoint receives on the stream).
    recv: Vec<u8>,
    recv_off: u64,
    recv_pending: Vec<(u64, Vec<u8>)>,
    /// Highest offset+len received (flow-control credit the peer has consumed).
    recv_high: u64,
    /// Bytes the app has read (drives the receive-window extension).
    recv_consumed: u64,
    /// Our advertised MAX_STREAM_DATA limit, and the last value we sent.
    recv_max: u64,
    recv_max_sent: u64,
    /// A grown receive window owes the peer a MAX_STREAM_DATA update.
    need_max_stream_data: bool,
    /// Final size once a FIN has been received (RFC 9000 §4.5).
    recv_fin: Option<u64>,
    /// A peer RESET_STREAM error code, if the receive half was reset.
    recv_reset: Option<u64>,
}

impl Stream {
    /// A fresh stream advertising the initial receive window. (Not `Default`: the
    /// receive windows start non-zero.)
    fn fresh() -> Self {
        Self {
            recv_max: STREAM_RECV_WINDOW,
            recv_max_sent: STREAM_RECV_WINDOW,
            ..Self::default()
        }
    }
}

/// The relay's data stream: client-initiated bidirectional stream 0 (RFC 9000
/// §2.1). The carrier opens it for the HTTP/3 request/response relay.
const RELAY_STREAM_ID: u64 = 0;

/// Initial per-stream receive window we advertise (MAX_STREAM_DATA); extended as
/// the app reads. Matches the Safari `initial_max_stream_data` value.
const STREAM_RECV_WINDOW: u64 = 2 * 1024 * 1024;

/// Initial connection-level receive window we advertise (MAX_DATA); extended as
/// the app reads across all streams. Matches the Safari `initial_max_data` value.
const CONN_RECV_WINDOW: u64 = 16 * 1024 * 1024;

/// Cap on concurrent peer-initiated streams of each kind (a memory-exhaustion DoS
/// guard, ≥ what our transport parameters advertise so it never wrongly rejects).
const MAX_PEER_STREAMS: usize = 64;

/// Stream-id bit 1 (RFC 9000 §2.1): set for unidirectional streams.
fn is_uni(id: u64) -> bool {
    id & 0x2 != 0
}

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
    /// Connection-wide RTT estimator (RFC 9002 §5 keeps one across all spaces).
    rtt: RttEstimator,
    /// Congestion controller behind the CC seam (NewReno scaffold; BBR later).
    cc: Box<dyn Controller>,
    /// PTO exponential-backoff exponent, reset to 0 whenever an ACK is received.
    pto_count: u32,
    /// Number of probe packets allowed to bypass the congestion window (RFC 9002
    /// §6.2.4): a PTO sets this so a retransmit goes out even when cwnd is full.
    probe_pending: u8,
    /// When the most recent ack-eliciting packet was sent (arms the PTO timer).
    last_ack_eliciting_sent: Option<Instant>,
    /// The server queues HANDSHAKE_DONE once its handshake completes; resent if lost.
    handshake_done_pending: bool,
    /// The handshake is confirmed (RFC 9001 §4.1.2): the server when it sends
    /// HANDSHAKE_DONE, the client when it receives it.
    handshake_confirmed: bool,
    /// When any packet was last sent (drives the keep-alive timer).
    last_send_time: Option<Instant>,
    /// A keep-alive (or PTO-fallback) PING is queued for the 1-RTT space.
    ping_pending: bool,
    /// The space the next `write_handshake` bytes belong to (advances on KeyChange).
    write_level: usize,
    /// All open streams, keyed by stream id (RFC 9000 §2.1).
    streams: BTreeMap<u64, Stream>,
    /// Next stream id this endpoint will allocate for an outgoing bidi / uni stream.
    next_bidi: u64,
    next_uni: u64,
    /// Peer-initiated streams newly observed, awaiting `accept_bi` / `accept_uni`.
    accept_bidi: VecDeque<u64>,
    accept_uni: VecDeque<u64>,
    /// Connection-level flow control (RFC 9000 §4.1). Send side: the peer's MAX_DATA
    /// limit and how much we have sent against it. Receive side: the limit we
    /// advertise, the last value sent, total received (enforcement), total consumed
    /// (extension), and whether a MAX_DATA update is queued.
    send_max_data: u64,
    send_data_total: u64,
    recv_max_data: u64,
    recv_max_data_sent: u64,
    recv_data_total: u64,
    recv_data_consumed: u64,
    /// A grown connection window owes the peer a MAX_DATA update.
    need_max_data: bool,
    /// Whether the peer's transport-parameter flow-control limits have been applied.
    peer_flow_applied: bool,
    /// The peer's initial MAX_STREAM_DATA limits, by stream kind (RFC 9000 §18.2),
    /// applied to each stream's `send_max` when first opened/seen.
    peer_msd_bidi_local: u64,
    peer_msd_bidi_remote: u64,
    peer_msd_uni: u64,
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
            rtt: RttEstimator::new(),
            cc: Box::new(NewReno::new()),
            pto_count: 0,
            probe_pending: 0,
            last_ack_eliciting_sent: None,
            handshake_done_pending: false,
            handshake_confirmed: false,
            last_send_time: None,
            ping_pending: false,
            write_level: SPACE_INITIAL,
            streams: BTreeMap::new(),
            // Client-initiated stream ids: bidi 0,4,8,…; uni 2,6,10,… (RFC 9000 §2.1).
            next_bidi: 0,
            next_uni: 2,
            accept_bidi: VecDeque::new(),
            accept_uni: VecDeque::new(),
            send_max_data: 0,
            send_data_total: 0,
            recv_max_data: CONN_RECV_WINDOW,
            recv_max_data_sent: CONN_RECV_WINDOW,
            recv_data_total: 0,
            recv_data_consumed: 0,
            need_max_data: false,
            peer_flow_applied: false,
            peer_msd_bidi_local: 0,
            peer_msd_bidi_remote: 0,
            peer_msd_uni: 0,
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
            rtt: RttEstimator::new(),
            cc: Box::new(NewReno::new()),
            pto_count: 0,
            probe_pending: 0,
            last_ack_eliciting_sent: None,
            handshake_done_pending: false,
            handshake_confirmed: false,
            last_send_time: None,
            ping_pending: false,
            write_level: SPACE_INITIAL,
            streams: BTreeMap::new(),
            // Server-initiated stream ids: bidi 1,5,9,…; uni 3,7,11,… (RFC 9000 §2.1).
            next_bidi: 1,
            next_uni: 3,
            accept_bidi: VecDeque::new(),
            accept_uni: VecDeque::new(),
            send_max_data: 0,
            send_data_total: 0,
            recv_max_data: CONN_RECV_WINDOW,
            recv_max_data_sent: CONN_RECV_WINDOW,
            recv_data_total: 0,
            recv_data_consumed: 0,
            need_max_data: false,
            peer_flow_applied: false,
            peer_msd_bidi_local: 0,
            peer_msd_bidi_remote: 0,
            peer_msd_uni: 0,
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

    /// Open a new outgoing bidirectional stream, returning its id (RFC 9000 §2.1).
    /// The relay's first call returns the data stream ([`RELAY_STREAM_ID`]).
    pub fn open_bi(&mut self) -> u64 {
        let id = self.next_bidi;
        self.next_bidi += 4;
        self.create_local_stream(id);
        id
    }

    /// Open a new outgoing unidirectional stream (HTTP/3 control / QPACK).
    pub fn open_uni(&mut self) -> u64 {
        let id = self.next_uni;
        self.next_uni += 4;
        self.create_local_stream(id);
        id
    }

    /// Insert a locally-opened stream with its initial windows + peer send limit.
    fn create_local_stream(&mut self, id: u64) {
        self.ensure_peer_flow();
        let send_max = self.peer_send_limit(id);
        let s = self.streams.entry(id).or_insert_with(Stream::fresh);
        s.send_max = s.send_max.max(send_max);
    }

    /// Take the id of the next peer-initiated bidirectional stream, if any.
    pub fn accept_bi(&mut self) -> Option<u64> {
        self.accept_bidi.pop_front()
    }

    /// Take the id of the next peer-initiated unidirectional stream, if any.
    pub fn accept_uni(&mut self) -> Option<u64> {
        self.accept_uni.pop_front()
    }

    /// Queue application bytes on stream `id`; they are packetized into 1-RTT STREAM
    /// frames once the handshake installs Data keys. Creates the stream if absent.
    pub fn send_stream(&mut self, id: u64, data: &[u8]) {
        self.create_local_stream(id);
        self.streams
            .get_mut(&id)
            .expect("just created")
            .send
            .extend_from_slice(data);
    }

    /// Mark stream `id` finished (a FIN is sent after all buffered bytes).
    pub fn finish_stream(&mut self, id: u64) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.fin = true;
        }
    }

    /// Take the bytes reassembled in order from stream `id`'s STREAM frames, and
    /// extend the receive windows (RFC 9000 §4.1): consuming data grows this
    /// stream's MAX_STREAM_DATA and the connection's MAX_DATA so the peer may send
    /// more (the updates are emitted by `poll_transmit`).
    pub fn read_stream(&mut self, id: u64) -> Vec<u8> {
        let Some(s) = self.streams.get_mut(&id) else {
            return Vec::new();
        };
        let data = std::mem::take(&mut s.recv);
        let n = data.len() as u64;
        s.recv_consumed += n;
        s.recv_max = s.recv_consumed + STREAM_RECV_WINDOW;
        // Advertise a bigger window once half of it has been consumed since the
        // last MAX_STREAM_DATA (avoids a frame per read).
        if s.recv_max - s.recv_max_sent >= STREAM_RECV_WINDOW / 2 {
            s.need_max_stream_data = true;
        }
        self.recv_data_consumed += n;
        self.recv_max_data = self.recv_data_consumed + CONN_RECV_WINDOW;
        if self.recv_max_data - self.recv_max_data_sent >= CONN_RECV_WINDOW / 2 {
            self.need_max_data = true;
        }
        data
    }

    /// Whether stream `id`'s receive half has delivered all bytes through a FIN
    /// (a clean end-of-stream, RFC 9000 §4.5).
    pub fn stream_recv_finished(&self, id: u64) -> bool {
        self.streams
            .get(&id)
            .is_some_and(|s| s.recv_fin.is_some_and(|fin| s.recv_off >= fin))
    }

    /// The RESET_STREAM error code if stream `id`'s receive half was reset by the
    /// peer (a mid-transfer truncation, surfaced to the relay as ConnectionReset).
    pub fn stream_reset(&self, id: u64) -> Option<u64> {
        self.streams.get(&id).and_then(|s| s.recv_reset)
    }

    /// Stream-id bit 0 (RFC 9000 §2.1): a stream is peer-initiated when its
    /// initiator bit differs from ours (client = 0, server = 1).
    fn is_peer_initiated(&self, id: u64) -> bool {
        let our_bit = if self.side == Side::Client { 0 } else { 1 };
        (id & 0x1) != our_bit
    }

    /// Parse the peer's transport parameters once (available after the handshake
    /// exchanges them) and apply their flow-control limits: the connection MAX_DATA
    /// and each open stream's initial MAX_STREAM_DATA send window (RFC 9000 §4.1).
    fn ensure_peer_flow(&mut self) {
        if self.peer_flow_applied {
            return;
        }
        let Some(blob) = self.tls.peer_transport_parameters() else {
            return;
        };
        let Ok(tp) = TransportParameters::read(blob) else {
            return;
        };
        self.send_max_data = tp.initial_max_data;
        self.peer_msd_bidi_local = tp.initial_max_stream_data_bidi_local;
        self.peer_msd_bidi_remote = tp.initial_max_stream_data_bidi_remote;
        self.peer_msd_uni = tp.initial_max_stream_data_uni;
        self.peer_flow_applied = true;
        // Raise the send window of streams already created before the TP arrived.
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        for id in ids {
            let limit = self.peer_send_limit(id);
            if let Some(s) = self.streams.get_mut(&id) {
                s.send_max = s.send_max.max(limit);
            }
        }
    }

    /// The peer's initial MAX_STREAM_DATA for a stream, by kind (RFC 9000 §18.2):
    /// a uni stream, a bidi stream we opened (the peer's "remote" limit), or a bidi
    /// stream the peer opened (its "local" limit). Zero until the peer TP arrives.
    fn peer_send_limit(&self, id: u64) -> u64 {
        if is_uni(id) {
            self.peer_msd_uni
        } else if self.is_peer_initiated(id) {
            self.peer_msd_bidi_local
        } else {
            self.peer_msd_bidi_remote
        }
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

    /// Produce the next datagram to send, or `None` when idle (or congestion-window
    /// limited). Priority: a pending ACK (lowest space first; never gated), then
    /// CRYPTO (retransmits before fresh bytes, lowest space first), then 1-RTT relay
    /// STREAM data. Fresh/retransmitted ack-eliciting data is gated on the
    /// congestion window unless a PTO probe is pending (RFC 9002 §6.2.4). One
    /// datagram per call; the driver loops until `None`.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Vec<u8>> {
        // Pure ACKs first so acknowledgements are not held behind data, and are
        // never blocked by the congestion window (they are not ack-eliciting).
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            if self.spaces[space].keys.is_some() && self.spaces[space].ack_pending {
                return Some(self.build_ack_packet(space, now));
            }
        }
        // Ack-eliciting data is gated on the congestion window, except a PTO probe
        // which is allowed to exceed it to guarantee forward progress.
        let probing = self.probe_pending > 0;
        let congestion_ok =
            probing || self.bytes_in_flight() + MAX_DATAGRAM as u64 <= self.cc.window();
        if congestion_ok {
            // CRYPTO (handshake) from the lowest space with retransmits or fresh bytes.
            for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
                let sp = &self.spaces[space];
                if sp.keys.is_some()
                    && (!sp.retransmit_crypto.is_empty()
                        || sp.crypto_send_off < sp.crypto_send.len())
                {
                    let dg = self.build_crypto_packet(space, now);
                    self.probe_pending = self.probe_pending.saturating_sub(1);
                    return Some(dg);
                }
            }
            // The server signals handshake confirmation (RFC 9001 §4.1.2) before
            // relay data; it is resent if the carrying packet is lost.
            if self.spaces[SPACE_DATA].keys.is_some() && self.handshake_done_pending {
                let dg = self.build_handshake_done_packet(now);
                self.probe_pending = self.probe_pending.saturating_sub(1);
                return Some(dg);
            }
            // Flow-control window updates (MAX_DATA / MAX_STREAM_DATA) so the peer
            // can keep sending as we consume; sent before fresh data.
            if self.spaces[SPACE_DATA].keys.is_some() && self.flow_update_pending() {
                let dg = self.build_flow_update_packet(now);
                self.probe_pending = self.probe_pending.saturating_sub(1);
                return Some(dg);
            }
            // 1-RTT relay data: once Data keys are installed, resend losses then
            // drain whichever stream has bytes (or a pending FIN) to send.
            if self.spaces[SPACE_DATA].keys.is_some() {
                if let Some(id) = self.next_stream_to_send() {
                    let dg = self.build_stream_packet(id, now);
                    self.probe_pending = self.probe_pending.saturating_sub(1);
                    return Some(dg);
                }
            }
            // A keep-alive or PTO-fallback PING, last so real data goes first.
            if self.spaces[SPACE_DATA].keys.is_some() && self.ping_pending {
                let dg = self.build_ping_packet(now);
                self.probe_pending = self.probe_pending.saturating_sub(1);
                return Some(dg);
            }
        }
        None
    }

    /// Total ack-eliciting bytes in flight across all packet-number spaces.
    fn bytes_in_flight(&self) -> u64 {
        self.spaces.iter().map(|s| s.sent.in_flight()).sum()
    }

    /// Whether any space has ack-eliciting packets in flight (arms the PTO timer).
    fn any_in_flight(&self) -> bool {
        self.spaces.iter().any(|s| s.sent.in_flight() > 0)
    }

    /// Current PTO duration with exponential backoff (RFC 9002 §6.2.1).
    fn pto_duration(&self) -> Duration {
        (self.rtt.pto_base() + MAX_ACK_DELAY) * 2u32.pow(self.pto_count.min(MAX_PTO_BACKOFF))
    }

    /// The earliest loss-detection / PTO deadline, for the async layer to arm a
    /// timer against (RFC 9002 §6.2). `None` when nothing is outstanding.
    pub fn next_timeout(&self) -> Option<Instant> {
        let mut deadline: Option<Instant> = None;
        let mut earliest = |t: Instant| deadline = Some(deadline.map_or(t, |d| d.min(t)));
        for sp in &self.spaces {
            if let Some(lt) = sp.loss_time {
                earliest(lt);
            }
        }
        if self.any_in_flight() {
            if let Some(last) = self.last_ack_eliciting_sent {
                earliest(last + self.pto_duration());
            }
        }
        // Keep-alive: once confirmed, schedule a PING after an idle interval.
        if self.handshake_confirmed {
            if let Some(last) = self.last_send_time {
                earliest(last + KEEP_ALIVE_INTERVAL);
            }
        }
        deadline
    }

    /// Drive time-based loss detection and PTO (RFC 9002 §6.2). The async layer
    /// calls this when [`Self::next_timeout`] elapses; `poll_transmit` then sends
    /// any retransmits / probes that were queued.
    pub fn handle_timeout(&mut self, now: Instant) {
        // Time-threshold losses first (RFC 9002 §6.1.2).
        let mut any_loss = false;
        let loss_delay = self.rtt.loss_delay();
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            let due = self.spaces[space].loss_time.is_some_and(|lt| lt <= now);
            if !due {
                continue;
            }
            let (lost, loss_time) = self.spaces[space].sent.detect_lost(loss_delay, now);
            self.spaces[space].loss_time = loss_time;
            for (pn, _) in lost {
                if let Some(content) = self.spaces[space].sent_content.remove(&pn) {
                    self.requeue(space, content);
                    any_loss = true;
                }
            }
        }
        if any_loss {
            self.cc.on_congestion_event();
        }

        // Otherwise, if the PTO has elapsed with packets in flight, probe.
        if !any_loss && self.any_in_flight() {
            let elapsed = self
                .last_ack_eliciting_sent
                .is_some_and(|last| now >= last + self.pto_duration());
            if elapsed {
                self.pto_count = (self.pto_count + 1).min(MAX_PTO_BACKOFF);
                self.queue_probe();
            }
        }

        // Keep-alive: if the connection has been idle past the interval, queue a
        // PING so the peer's idle timer does not tear down a held-open relay.
        if self.handshake_confirmed
            && self
                .last_send_time
                .is_some_and(|last| now >= last + KEEP_ALIVE_INTERVAL)
        {
            self.ping_pending = true;
        }
    }

    /// Queue a PTO probe: retransmit the oldest unacked ack-eliciting packet's data
    /// (lowest space first, so handshake progress is not blocked behind 1-RTT).
    fn queue_probe(&mut self) {
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            if self.spaces[space].sent.in_flight() == 0 {
                continue;
            }
            let oldest = self.spaces[space].sent_content.keys().next().copied();
            if let Some(pn) = oldest {
                let content = self.spaces[space].sent_content.remove(&pn).unwrap();
                // The probed packet leaves bytes-in-flight but is NOT a loss signal
                // (cwnd is unchanged); its data is resent in a fresh packet.
                self.spaces[space].sent.discard(pn);
                // A PING-only packet (e.g. a lost keep-alive) has nothing to resend;
                // probe with a fresh PING so the peer still ACKs.
                if content.crypto.is_empty() && content.stream.is_empty() && !content.handshake_done
                {
                    self.ping_pending = true;
                }
                self.requeue(space, content);
                self.probe_pending = self.probe_pending.saturating_add(1);
                return;
            }
        }
    }

    /// Push a lost/probed packet's CRYPTO + STREAM ranges onto the resend queues,
    /// and re-arm HANDSHAKE_DONE if the packet carried it.
    fn requeue(&mut self, space: usize, content: SentContent) {
        for range in content.crypto {
            self.spaces[space].retransmit_crypto.push(range);
        }
        for (id, offset, len, fin) in content.stream {
            if let Some(s) = self.streams.get_mut(&id) {
                s.retransmit.push((offset, len, fin));
            }
        }
        if content.handshake_done {
            self.handshake_done_pending = true;
        }
        // A lost window update must be re-sent or the peer stalls.
        if content.max_data {
            self.need_max_data = true;
        }
        for id in content.max_stream_data {
            if let Some(s) = self.streams.get_mut(&id) {
                s.need_max_stream_data = true;
            }
        }
    }

    /// The long/short header for an outgoing packet in `space`.
    fn make_header(&self, space: usize, pn: u64, pn_len: usize) -> Header {
        match space {
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
        }
    }

    /// Record an outgoing packet for loss detection. Only ack-eliciting packets
    /// keep retransmittable content (a pure-ACK packet has none).
    fn record_sent(
        &mut self,
        space: usize,
        pn: u64,
        size: usize,
        ack_eliciting: bool,
        content: SentContent,
        now: Instant,
    ) {
        self.spaces[space].sent.on_sent(
            pn,
            SentPacket {
                time_sent: now,
                size: size as u64,
                ack_eliciting,
            },
        );
        if ack_eliciting {
            self.spaces[space].sent_content.insert(pn, content);
            self.last_ack_eliciting_sent = Some(now);
        }
        self.last_send_time = Some(now);
    }

    /// Build a packet carrying only an ACK frame for `space` (non-ack-eliciting),
    /// clearing the space's pending-ACK flag.
    fn build_ack_packet(&mut self, space: usize, now: Instant) -> Vec<u8> {
        let pn = self.spaces[space].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let ack = self.spaces[space]
            .recv
            .to_ack(0)
            .expect("ack_pending is only set after receiving an ack-eliciting packet");
        let header = self.make_header(space, pn, pn_len);
        let datagram = {
            let keys = self.spaces[space].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, &[Frame::Ack(ack)])
        };
        self.spaces[space].ack_pending = false;
        self.record_sent(
            space,
            pn,
            datagram.len(),
            false,
            SentContent::default(),
            now,
        );
        datagram
    }

    /// Build a 1-RTT packet carrying HANDSHAKE_DONE (RFC 9001 §4.1.2). Ack-eliciting
    /// and tracked so it is resent if lost; clears the pending flag. PADDING brings
    /// the payload up to the 4 bytes header protection needs for its sample (RFC
    /// 9001 §5.4.2): a lone 1-byte HANDSHAKE_DONE would be too short to sample.
    fn build_handshake_done_packet(&mut self, now: Instant) -> Vec<u8> {
        let pn = self.spaces[SPACE_DATA].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(SPACE_DATA, pn, pn_len);
        let datagram = {
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            seal_packet(
                &keys.local,
                header,
                &[Frame::HandshakeDone, Frame::Padding(3)],
            )
        };
        self.handshake_done_pending = false;
        let content = SentContent {
            crypto: Vec::new(),
            stream: Vec::new(),
            handshake_done: true,
            ..Default::default()
        };
        self.record_sent(SPACE_DATA, pn, datagram.len(), true, content, now);
        datagram
    }

    /// Build a 1-RTT PING packet (keep-alive or PTO fallback). Ack-eliciting so it
    /// elicits an ACK; PADDING brings it up to the header-protection sample size. It
    /// carries no retransmittable content (a fresh PING is sent if a probe is lost).
    fn build_ping_packet(&mut self, now: Instant) -> Vec<u8> {
        let pn = self.spaces[SPACE_DATA].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(SPACE_DATA, pn, pn_len);
        let datagram = {
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, &[Frame::Ping, Frame::Padding(3)])
        };
        self.ping_pending = false;
        self.record_sent(
            SPACE_DATA,
            pn,
            datagram.len(),
            true,
            SentContent::default(),
            now,
        );
        datagram
    }

    /// Whether any receive window has grown enough to owe the peer a MAX_DATA or
    /// MAX_STREAM_DATA update.
    fn flow_update_pending(&self) -> bool {
        self.need_max_data || self.streams.values().any(|s| s.need_max_stream_data)
    }

    /// Build a 1-RTT packet carrying the pending MAX_DATA + MAX_STREAM_DATA window
    /// updates (RFC 9000 §19.9–19.10), recording them so they are re-armed if lost.
    fn build_flow_update_packet(&mut self, now: Instant) -> Vec<u8> {
        let pn = self.spaces[SPACE_DATA].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(SPACE_DATA, pn, pn_len);

        let mut frames: Vec<Frame> = Vec::new();
        let mut content = SentContent::default();
        if self.need_max_data {
            frames.push(Frame::MaxData(self.recv_max_data));
            content.max_data = true;
        }
        let grown: Vec<(u64, u64)> = self
            .streams
            .iter()
            .filter(|(_, s)| s.need_max_stream_data)
            .map(|(&id, s)| (id, s.recv_max))
            .collect();
        for &(id, max) in &grown {
            frames.push(Frame::MaxStreamData { id, max });
            content.max_stream_data.push(id);
        }
        // Pad to the header-protection sample size if the frames are tiny.
        let probe_len: usize = {
            let mut p = Vec::new();
            for f in &frames {
                f.encode(&mut p);
            }
            p.len()
        };
        if probe_len < 4 {
            frames.push(Frame::Padding(4 - probe_len));
        }

        let datagram = {
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, &frames)
        };

        // Mark the advertised values as sent and clear the owe-flags.
        if self.need_max_data {
            self.recv_max_data_sent = self.recv_max_data;
            self.need_max_data = false;
        }
        for (id, max) in grown {
            if let Some(s) = self.streams.get_mut(&id) {
                s.recv_max_sent = max;
                s.need_max_stream_data = false;
            }
        }
        self.record_sent(SPACE_DATA, pn, datagram.len(), true, content, now);
        datagram
    }

    fn build_crypto_packet(&mut self, space: usize, now: Instant) -> Vec<u8> {
        let pn = self.spaces[space].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let tag_len = self.spaces[space]
            .keys
            .as_ref()
            .unwrap()
            .local
            .packet
            .tag_len();
        let header = self.make_header(space, pn, pn_len);
        let mut probe = Vec::new();
        let pn_offset = header.encode(&mut probe);

        // A lost CRYPTO range is resent verbatim (it was already sized to fit a
        // packet); otherwise carve the next fresh chunk under the datagram budget.
        let (offset, end, is_retransmit) =
            if let Some(&(off, len)) = self.spaces[space].retransmit_crypto.first() {
                (off as usize, (off + len) as usize, true)
            } else {
                let off = self.spaces[space].crypto_send_off;
                let crypto_hdr = 1 + super::varint::size(off as u64) + 2;
                let cap = if space == SPACE_INITIAL {
                    MIN_INITIAL_DATAGRAM
                } else {
                    MAX_DATAGRAM
                };
                let budget = cap.saturating_sub(pn_offset + pn_len + tag_len + crypto_hdr);
                let remaining = self.spaces[space].crypto_send.len() - off;
                (off, off + remaining.min(budget.max(1)), false)
            };

        let datagram = {
            let crypto = Frame::Crypto {
                offset: offset as u64,
                data: &self.spaces[space].crypto_send[offset..end],
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

        let content = SentContent {
            crypto: vec![(offset as u64, (end - offset) as u64)],
            stream: Vec::new(),
            handshake_done: false,
            ..Default::default()
        };
        self.record_sent(space, pn, datagram.len(), true, content, now);
        if is_retransmit {
            self.spaces[space].retransmit_crypto.remove(0);
        } else {
            self.spaces[space].crypto_send_off = end;
        }
        datagram
    }

    /// The id of the next stream with something to send, in ascending id order:
    /// a resend (always allowed), a pending empty FIN, or fresh bytes that fit
    /// within both the connection and per-stream flow-control windows. `None` if
    /// every stream is idle or flow-control blocked.
    fn next_stream_to_send(&self) -> Option<u64> {
        let conn_window = self.send_max_data.saturating_sub(self.send_data_total);
        self.streams
            .iter()
            .find(|(_, s)| {
                if !s.retransmit.is_empty() {
                    return true;
                }
                let all_sent = (s.send_off as usize) == s.send.len();
                if s.fin && !s.fin_sent && all_sent {
                    return true; // an empty FIN consumes no flow-control credit
                }
                let fresh = (s.send_off as usize) < s.send.len();
                let stream_window = s.send_max.saturating_sub(s.send_off);
                fresh && stream_window > 0 && conn_window > 0
            })
            .map(|(&id, _)| id)
    }

    /// Build one 1-RTT (short-header) packet carrying a STREAM frame for stream
    /// `id` — either a resend of a lost range or the next fresh slice (with the FIN
    /// bit when the final byte is reached).
    fn build_stream_packet(&mut self, id: u64, now: Instant) -> Vec<u8> {
        let pn = self.spaces[SPACE_DATA].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let tag_len = self.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .unwrap()
            .local
            .packet
            .tag_len();
        let header = self.make_header(SPACE_DATA, pn, pn_len);
        let mut probe = Vec::new();
        let pn_offset = header.encode(&mut probe);

        let s = &self.streams[&id];
        let (offset, end, fin, is_retransmit) = if let Some(&(off, len, fin)) = s.retransmit.first()
        {
            (off, off + len, fin, true)
        } else {
            let offset = s.send_off;
            let frame_hdr = 1 + super::varint::size(id) + super::varint::size(offset) + 2;
            let budget = MAX_DATAGRAM.saturating_sub(pn_offset + pn_len + tag_len + frame_hdr);
            let remaining = s.send.len() - offset as usize;
            // Clamp the fresh chunk to both flow-control windows (RFC 9000 §4.1).
            let conn_window = self.send_max_data.saturating_sub(self.send_data_total);
            let fc_window = s.send_max.saturating_sub(offset).min(conn_window) as usize;
            let chunk = remaining.min(budget.max(1)).min(fc_window);
            let end = offset + chunk as u64;
            // Carry the FIN only once the final buffered byte is in this frame.
            let fin = s.fin && !s.fin_sent && end as usize == s.send.len();
            (offset, end, fin, false)
        };

        let datagram = {
            let frame = Frame::Stream {
                id,
                offset,
                fin,
                data: &self.streams[&id].send[offset as usize..end as usize],
            };
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, &[frame])
        };

        let content = SentContent {
            crypto: Vec::new(),
            stream: vec![(id, offset, end - offset, fin)],
            handshake_done: false,
            ..Default::default()
        };
        self.record_sent(SPACE_DATA, pn, datagram.len(), true, content, now);
        let s = self.streams.get_mut(&id).unwrap();
        if is_retransmit {
            s.retransmit.remove(0);
        } else {
            // Fresh bytes consume connection-level flow-control credit.
            self.send_data_total += end - s.send_off;
            s.send_off = end;
            if fin {
                s.fin_sent = true;
            }
        }
        datagram
    }

    /// Process one received datagram. A single UDP datagram MAY carry several
    /// coalesced QUIC packets (RFC 9000 §12.2; e.g. quinn sends Initial+Handshake
    /// together), so iterate over them: a long-header packet carries an explicit
    /// Length, so the next coalesced packet starts immediately after it; a
    /// short-header (1-RTT) packet has no Length and so is always the last in the
    /// datagram. The TLS engine is pumped after each packet ([`Self::process_packet`])
    /// so that, e.g., the Handshake keys learned from a coalesced Initial are
    /// installed before the Handshake packet that follows it in the same datagram.
    pub fn handle_datagram(&mut self, datagram: &[u8], now: Instant) -> Result<(), QuicTlsError> {
        let mut buf = datagram.to_vec();
        let mut pos = 0;
        while pos < buf.len() {
            // Boundary of the current packet, read from its plaintext long header
            // BEFORE `process_packet` decrypts in place. `None` ⇒ a short header
            // (or unparseable) which runs to the datagram end: process it, stop.
            let advance = packet::long_packet_len(&buf[pos..]);
            self.process_packet(&mut buf[pos..], now)?;
            match advance {
                Some(n) if n != 0 && pos.checked_add(n).is_some_and(|e| e <= buf.len()) => {
                    pos += n;
                }
                _ => break,
            }
        }
        Ok(())
    }

    /// Process ONE packet (already isolated from any coalesced trailer): for the
    /// server's first Initial, derive Initial keys + learn CIDs; AEAD-open; on
    /// success dispatch the frames and pump the TLS engine. An undecryptable packet
    /// is dropped (RFC 9001 §5.4.2 — `Ok(())`): a coalesced trailer, a replay, or a
    /// packet for keys not yet held must NOT fail the connection. Only a protocol
    /// error decoding a frame on an AUTHENTICATED packet propagates.
    fn process_packet(&mut self, pkt: &mut [u8], now: Instant) -> Result<(), QuicTlsError> {
        let pspace = match packet::first_packet_space(pkt) {
            Some(s) => s,
            None => return Ok(()), // unsupported type / clear fixed bit: drop
        };
        let space = space_index(pspace);

        // Peek the long-header CIDs but DO NOT latch any state from them yet: a
        // forged/unauthenticated datagram must not be able to corrupt CID routing
        // or pin Initial keys. (Initial keys derive from the public DCID, so an
        // off-path attacker could otherwise inject one spoofed Initial before the
        // genuine first packet and permanently break the connection.) Everything
        // derived from this datagram is committed only AFTER the packet AEAD-opens.
        let long_cids = if matches!(pspace, PacketSpace::Initial | PacketSpace::Handshake) {
            match packet::peek_long_cids(pkt) {
                Ok(c) => Some(c),
                Err(_) => return Ok(()), // malformed long header: drop
            }
        } else {
            None
        };

        // The server derives Initial keys from the peer's (public) DCID on demand;
        // keep them in a temporary until the packet opens, so a spoofed Initial
        // cannot replace already-derived keys or pin a bogus DCID.
        let pending_initial = if self.side == Side::Server
            && space == SPACE_INITIAL
            && self.spaces[SPACE_INITIAL].keys.is_none()
        {
            let dcid = long_cids.expect("Initial space implies a long header").0;
            Some((dcid, initial_keys(dcid.as_slice(), Side::Server)))
        } else {
            None
        };

        let local_cid_len = self.scid.len();
        let largest = self.spaces[space].recv.largest();
        let opened = {
            let keys = match &pending_initial {
                Some((_, k)) => &k.remote,
                None => match self.spaces[space].keys.as_ref() {
                    Some(k) => &k.remote,
                    None => return Ok(()), // no keys installed for this space yet: drop
                },
            };
            open_packet(keys, pkt, local_cid_len, largest)
        };
        let (header, range) = match opened {
            Ok(v) => v,
            Err(_) => return Ok(()), // undecryptable: drop, do NOT fail the connection
        };

        // The packet authenticated — only NOW is it safe to commit state derived
        // from this (now-trusted) datagram.
        if let Some((dcid, keys)) = pending_initial {
            self.initial_dcid = dcid;
            self.spaces[SPACE_INITIAL].keys = Some(keys);
        }
        if let Some((_, scid)) = long_cids {
            if !self.peer_cid_adopted {
                self.dcid = scid;
                self.peer_cid_adopted = true;
            }
        }

        // Drop a duplicate (replayed) packet without reprocessing it.
        if !self.spaces[space].recv.insert(header.packet_number()) {
            return Ok(());
        }

        // Copy the decrypted frames out so the TLS engine can be mutated while we
        // iterate.
        let payload = pkt[range].to_vec();
        // A packet is ack-eliciting (RFC 9002 §2) if it carries any frame other
        // than ACK / PADDING / CONNECTION_CLOSE — such a packet schedules an ACK.
        let mut ack_eliciting = false;
        for frame in Iter::new(&payload) {
            let frame =
                frame.map_err(|e| QuicTlsError::Crypto(format!("frame decode failed: {e:?}")))?;
            match frame {
                Frame::Crypto { offset, data } => {
                    ack_eliciting = true;
                    self.recv_crypto(space, offset, data)?;
                }
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } => {
                    ack_eliciting = true;
                    self.recv_stream(id, offset, fin, data)?;
                }
                Frame::ResetStream {
                    id,
                    error_code,
                    final_size,
                } => {
                    ack_eliciting = true;
                    self.recv_reset_stream(id, error_code, final_size)?;
                }
                Frame::StopSending { id, .. } => {
                    ack_eliciting = true;
                    // The peer will not read more of this stream: stop sending it.
                    // (A full RESET_STREAM emission lands with flow control.)
                    if let Some(s) = self.streams.get_mut(&id) {
                        s.send_off = s.send.len() as u64;
                        s.retransmit.clear();
                    }
                }
                Frame::MaxData(max) => {
                    // Raise the connection-level send limit (RFC 9000 §19.9).
                    self.send_max_data = self.send_max_data.max(max);
                }
                Frame::MaxStreamData { id, max } => {
                    // Raise a stream's send limit (RFC 9000 §19.10).
                    ack_eliciting = true;
                    if let Some(s) = self.streams.get_mut(&id) {
                        s.send_max = s.send_max.max(max);
                    }
                }
                Frame::Ack(ack) => self.recv_ack(space, &ack, now),
                Frame::HandshakeDone => {
                    ack_eliciting = true;
                    // RFC 9001 §4.1.2: the client treats HANDSHAKE_DONE as handshake
                    // confirmation. (Only a client should receive it.)
                    if self.side == Side::Client {
                        self.handshake_confirmed = true;
                    }
                }
                Frame::Padding(_) | Frame::Close(_) => {}
                // PING and every other relay-relevant frame are ack-eliciting but
                // carry no payload we act on here.
                _ => ack_eliciting = true,
            }
        }
        if ack_eliciting {
            self.spaces[space].ack_pending = true;
        }
        self.pump_write();
        self.maybe_queue_handshake_done();
        Ok(())
    }

    /// Once the server's handshake completes (it has verified the client's
    /// Finished), queue HANDSHAKE_DONE exactly once and mark the handshake confirmed
    /// (RFC 9001 §4.1.2).
    fn maybe_queue_handshake_done(&mut self) {
        if self.side == Side::Server
            && !self.handshake_confirmed
            && !self.tls.is_handshaking()
            && self.spaces[SPACE_DATA].keys.is_some()
        {
            self.handshake_done_pending = true;
            self.handshake_confirmed = true;
        }
    }

    /// Apply a received ACK frame (RFC 9002 §5–6.1): drop the acknowledged sent
    /// packets, fold one RTT sample (largest newly acked + an ack-eliciting packet),
    /// feed the congestion controller, then run loss detection and queue any lost
    /// CRYPTO/STREAM bytes for resend.
    fn recv_ack(&mut self, space: usize, ack: &Ack, now: Instant) {
        let newly = self.spaces[space].sent.on_ack(ack.largest, &ack.ranges);
        if newly.is_empty() {
            return;
        }
        // An ACK confirms forward progress, so reset the PTO backoff (RFC 9002 §6.2).
        self.pto_count = 0;
        // RTT sample: only when the largest acked is newly acked AND at least one
        // newly-acked packet was ack-eliciting (RFC 9002 §5.1).
        let mut largest_time = None;
        let mut any_ack_eliciting = false;
        let mut acked_bytes = 0u64;
        for (pn, sp) in &newly {
            self.spaces[space].sent_content.remove(pn);
            if sp.ack_eliciting {
                any_ack_eliciting = true;
                acked_bytes += sp.size;
            }
            if *pn == ack.largest {
                largest_time = Some(sp.time_sent);
            }
        }
        if let (Some(sent_at), true) = (largest_time, any_ack_eliciting) {
            // ACK delay applies only to the Application space (RFC 9002 §5.3); the
            // peer MUST send 0 for Initial/Handshake.
            let ack_delay = if space == SPACE_DATA {
                Duration::from_micros(ack.delay.saturating_mul(1 << ACK_DELAY_EXPONENT))
            } else {
                Duration::ZERO
            };
            self.rtt
                .update(ack_delay, now.saturating_duration_since(sent_at));
        }
        // Grow the congestion window on newly-acked ack-eliciting bytes. (Proper
        // app-limited suppression — RFC 9002 §7.8 — lands with BBR; NewReno
        // over-growing while app-limited is benign for the scaffold.)
        if acked_bytes > 0 {
            self.cc.on_ack(acked_bytes, false);
        }

        // Loss detection: re-queue the content of every packet declared lost and
        // signal the congestion controller once for the batch (RFC 9002 §7.3.2).
        let loss_delay = self.rtt.loss_delay();
        let (lost, loss_time) = self.spaces[space].sent.detect_lost(loss_delay, now);
        self.spaces[space].loss_time = loss_time;
        let mut any_lost = false;
        for (pn, _) in lost {
            if let Some(content) = self.spaces[space].sent_content.remove(&pn) {
                self.requeue(space, content);
                any_lost = true;
            }
        }
        if any_lost {
            self.cc.on_congestion_event();
        }
    }

    /// Reassemble an incoming CRYPTO fragment in order and feed the contiguous
    /// run to the TLS engine (which buffers partial handshake messages itself).
    fn recv_crypto(&mut self, space: usize, offset: u64, data: &[u8]) -> Result<(), QuicTlsError> {
        let mut to_feed: Vec<u8> = Vec::new();
        {
            let sp = &mut self.spaces[space];
            if offset > sp.crypto_recv_off {
                // Bound out-of-order CRYPTO buffering (see MAX_CRYPTO_REASSEMBLY):
                // reject offsets/volume beyond the window rather than buffer an
                // attacker's ever-rising, never-contiguous fragments.
                let buffered: usize = sp.crypto_pending.iter().map(|(_, d)| d.len()).sum();
                if offset.saturating_sub(sp.crypto_recv_off) > MAX_CRYPTO_REASSEMBLY as u64
                    || buffered + data.len() > MAX_CRYPTO_REASSEMBLY
                {
                    return Err(QuicTlsError::Crypto(
                        "CRYPTO reassembly window exceeded".into(),
                    ));
                }
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

    /// Reassemble an incoming STREAM fragment for stream `id` in order (out-of-order
    /// fragments buffered until contiguous). A previously-unseen peer-initiated
    /// stream is created and queued for `accept_*`. Enforces flow control (RFC 9000
    /// §4.1): a peer that exceeds the advertised stream or connection window is a
    /// FLOW_CONTROL_ERROR. `fin` records the final size (RFC 9000 §4.5).
    fn recv_stream(
        &mut self,
        id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<(), QuicTlsError> {
        self.ensure_stream(id)?;
        let end = offset + data.len() as u64;
        let s = self.streams.get_mut(&id).expect("just ensured");
        if end > s.recv_max {
            return Err(QuicTlsError::Crypto(
                "peer exceeded the stream receive window".into(),
            ));
        }
        let new_high = end.max(s.recv_high);
        let delta = new_high - s.recv_high;
        if self.recv_data_total + delta > self.recv_max_data {
            return Err(QuicTlsError::Crypto(
                "peer exceeded the connection receive window".into(),
            ));
        }
        s.recv_high = new_high;
        self.recv_data_total += delta;
        if fin {
            s.recv_fin = Some(end);
        }
        // In-order reassembly (the window above bounds out-of-order buffering).
        if offset > s.recv_off {
            s.recv_pending.push((offset, data.to_vec()));
            return Ok(());
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
        Ok(())
    }

    /// Record a peer RESET_STREAM (RFC 9000 §19.4): the receive half is truncated.
    /// The relay surfaces this as a ConnectionReset (a mid-transfer truncation),
    /// distinct from a clean FIN.
    fn recv_reset_stream(
        &mut self,
        id: u64,
        error_code: u64,
        _final_size: u64,
    ) -> Result<(), QuicTlsError> {
        self.ensure_stream(id)?;
        self.streams.get_mut(&id).expect("just ensured").recv_reset = Some(error_code);
        Ok(())
    }

    /// Create a stream on first sight, queuing a peer-initiated one for `accept_*`.
    /// Caps concurrent peer-initiated streams (a memory-exhaustion DoS guard,
    /// RFC 9000 §4.6 STREAM_LIMIT_ERROR), and seeds the send window from the peer's
    /// transport parameters.
    fn ensure_stream(&mut self, id: u64) -> Result<(), QuicTlsError> {
        if self.streams.contains_key(&id) {
            return Ok(());
        }
        let peer = self.is_peer_initiated(id);
        if peer {
            let kind_uni = is_uni(id);
            let count = self
                .streams
                .keys()
                .filter(|&&k| self.is_peer_initiated(k) && is_uni(k) == kind_uni)
                .count();
            if count >= MAX_PEER_STREAMS {
                return Err(QuicTlsError::Crypto(
                    "peer exceeded the stream limit".into(),
                ));
            }
        }
        let mut s = Stream::fresh();
        s.send_max = self.peer_send_limit(id);
        self.streams.insert(id, s);
        if peer {
            if is_uni(id) {
                self.accept_uni.push_back(id);
            } else {
                self.accept_bidi.push_back(id);
            }
        }
        Ok(())
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
        // A wrong key corrupts header-protection removal, so the packet is rejected
        // either at header decode (garbage reserved bits) or at the AEAD tag — both
        // are valid rejections; assert it is refused, not the specific variant.
        assert!(
            open_packet(&other, &mut datagram, 0, None).is_err(),
            "a packet sealed under a different key must be rejected"
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

    /// A valid server transport-parameters blob (16 MiB conn / 2 MiB stream
    /// windows) so flow control admits real data. (Reusing the Safari encoding is
    /// fine for the test — only the limits matter here, not the fingerprint.)
    fn server_tp() -> Vec<u8> {
        TransportParameters::safari_client(&[]).encode_safari_client()
    }

    #[test]
    fn client_initial_flight_is_decryptable_and_carries_clienthello() {
        let dcid = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        let mut conn =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();

        let mut datagrams = Vec::new();
        let now = Instant::now();
        while let Some(d) = conn.poll_transmit(now) {
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
            server_tp(),
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
            Some(server_tp().as_ref()),
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

    #[test]
    fn server_sends_handshake_done_and_both_sides_confirm() {
        let dcid = ConnectionId::new(&[0x44; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xde, 0xad, 0xbe, 0xef]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert!(
            server.handshake_confirmed,
            "server confirms when it sends HANDSHAKE_DONE"
        );
        assert!(
            client.handshake_confirmed,
            "client confirms on receiving HANDSHAKE_DONE"
        );
    }

    /// Ping-pong datagrams between two connections until neither has anything more
    /// to send (handshake CRYPTO + ACKs, then 1-RTT data). Lossless, so a single
    /// `now` suffices (no timers fire).
    fn drive(a: &mut Connection, b: &mut Connection) {
        let now = Instant::now();
        for _ in 0..16 {
            let mut moved = false;
            while let Some(dg) = a.poll_transmit(now) {
                b.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            while let Some(dg) = b.poll_transmit(now) {
                a.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            if !moved {
                break;
            }
        }
    }

    /// Like [`drive`] but COALESCES every datagram a side has pending into a single
    /// UDP datagram before delivering it (RFC 9000 §12.2). Exercises the receiver's
    /// coalesced-packet loop: the client's multi-Initial ClientHello arrives as one
    /// datagram, and the server's Initial+Handshake response arrives as one — so
    /// the Handshake keys learned from the coalesced Initial must be installed
    /// before the Handshake packet that immediately follows it.
    fn drive_coalesced(a: &mut Connection, b: &mut Connection) {
        let now = Instant::now();
        for _ in 0..16 {
            let mut moved = false;
            let mut from_a = Vec::new();
            while let Some(dg) = a.poll_transmit(now) {
                from_a.extend_from_slice(&dg);
                moved = true;
            }
            if !from_a.is_empty() {
                b.handle_datagram(&from_a, now).unwrap();
            }
            let mut from_b = Vec::new();
            while let Some(dg) = b.poll_transmit(now) {
                from_b.extend_from_slice(&dg);
                moved = true;
            }
            if !from_b.is_empty() {
                a.handle_datagram(&from_b, now).unwrap();
            }
            if !moved {
                break;
            }
        }
    }

    #[test]
    fn handshake_completes_across_coalesced_datagrams() {
        let dcid = ConnectionId::new(&[0x0c, 0x0a, 0x1e, 0x5c, 0xed, 0x00, 0x11, 0x22]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x99, 0x88, 0x77, 0x66]),
        )
        .unwrap();

        drive_coalesced(&mut client, &mut server);

        assert!(
            !client.is_handshaking() && !server.is_handshaking(),
            "handshake completes when packets arrive coalesced into single datagrams"
        );
        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        client
            .export_keying_material(&mut ce, b"parallax tudp", b"binding")
            .unwrap();
        server
            .export_keying_material(&mut se, b"parallax tudp", b"binding")
            .unwrap();
        assert_eq!(ce, se, "exporter agrees across coalesced delivery");

        // And 1-RTT relay data still round-trips through coalesced datagrams.
        client.send_stream(RELAY_STREAM_ID, b"coalesced request");
        drive_coalesced(&mut client, &mut server);
        assert_eq!(server.read_stream(RELAY_STREAM_ID), b"coalesced request");
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
            server_tp(),
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
        client.send_stream(RELAY_STREAM_ID, request);
        drive(&mut client, &mut server);
        assert_eq!(
            server.read_stream(RELAY_STREAM_ID),
            request,
            "server received the request"
        );

        // Server -> client over the same bidi stream.
        let response = b"200 OK back over the hand-rolled bidi stream";
        server.send_stream(RELAY_STREAM_ID, response);
        drive(&mut client, &mut server);
        assert_eq!(
            client.read_stream(RELAY_STREAM_ID),
            response,
            "client received the response"
        );
    }

    #[test]
    fn uni_and_bidi_streams_multiplex_with_fin() {
        let dcid = ConnectionId::new(&[0x70; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x07, 0x07, 0x07, 0x07]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // Client opens a uni stream (HTTP/3 control-style) with a FIN, plus the
        // bidi relay stream — exactly the shape the H3 layer drives.
        let ctrl = client.open_uni();
        assert_eq!(ctrl, 2, "first client uni stream id is 2");
        client.send_stream(ctrl, b"H3-SETTINGS");
        client.finish_stream(ctrl);
        let bidi = client.open_bi();
        assert_eq!(bidi, RELAY_STREAM_ID, "first client bidi stream id is 0");
        client.send_stream(bidi, b"request");
        drive(&mut client, &mut server);

        // The server surfaces both peer-initiated streams via accept_*.
        assert_eq!(server.accept_uni(), Some(ctrl), "uni stream accepted");
        assert_eq!(server.accept_bi(), Some(bidi), "bidi stream accepted");
        assert_eq!(server.read_stream(ctrl), b"H3-SETTINGS");
        assert!(
            server.stream_recv_finished(ctrl),
            "the uni stream's FIN was delivered"
        );
        assert_eq!(server.read_stream(bidi), b"request");
        assert!(
            !server.stream_recv_finished(bidi),
            "the bidi stream has no FIN yet"
        );

        // The server replies on the reverse direction of the bidi stream.
        server.send_stream(bidi, b"response");
        drive(&mut client, &mut server);
        assert_eq!(client.read_stream(bidi), b"response");
        // No spurious extra accepts.
        assert_eq!(server.accept_uni(), None);
        assert_eq!(client.accept_bi(), None);
    }

    #[test]
    fn large_transfer_exceeds_window_via_flow_control() {
        let now = Instant::now();
        let dcid = ConnectionId::new(&[0x5f; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x5f, 0x5f, 0x5f, 0x5f]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // A payload far larger than the 2 MiB per-stream window: it can only
        // complete if the server's reads extend the window (MAX_STREAM_DATA) and
        // the client respects + then exceeds the initial limit.
        let payload: Vec<u8> = (0..5_000_000u32).map(|i| (i % 251) as u8).collect();
        client.send_stream(RELAY_STREAM_ID, &payload);

        let mut received = Vec::new();
        for _ in 0..2000 {
            let mut moved = false;
            while let Some(dg) = client.poll_transmit(now) {
                server.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            // Reading drives the receive-window extension.
            received.extend_from_slice(&server.read_stream(RELAY_STREAM_ID));
            while let Some(dg) = server.poll_transmit(now) {
                client.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            if !moved && received.len() == payload.len() {
                break;
            }
        }
        assert_eq!(received.len(), payload.len(), "whole payload delivered");
        assert_eq!(
            received, payload,
            "bytes intact and in order across the window"
        );
    }

    #[test]
    fn lost_stream_packet_is_retransmitted_and_reassembled() {
        let mut now = Instant::now();
        let dcid = ConnectionId::new(&[0x10; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x12, 0x34, 0x56, 0x78]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // A payload spanning several 1-RTT packets.
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        client.send_stream(RELAY_STREAM_ID, &payload);

        // Collect the client's data packets, then deliver all but the SECOND —
        // simulating one mid-stream packet lost on the wire.
        let mut pkts = Vec::new();
        while let Some(dg) = client.poll_transmit(now) {
            pkts.push(dg);
        }
        assert!(
            pkts.len() >= 5,
            "payload should span several packets, got {}",
            pkts.len()
        );
        for (i, dg) in pkts.iter().enumerate() {
            if i == 1 {
                continue; // this packet is "lost"
            }
            server.handle_datagram(dg, now).unwrap();
        }

        // The server's gap-ACK drives the client's packet-threshold loss detection,
        // which resends the dropped range; pump until the hole is healed.
        for _ in 0..16 {
            now += Duration::from_millis(10);
            let mut moved = false;
            while let Some(dg) = server.poll_transmit(now) {
                client.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            while let Some(dg) = client.poll_transmit(now) {
                server.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            if !moved {
                break;
            }
        }

        assert_eq!(
            server.read_stream(RELAY_STREAM_ID),
            payload,
            "the dropped packet was retransmitted and the stream reassembled in order"
        );
    }

    #[test]
    fn tail_loss_is_recovered_by_pto_probe() {
        let mut now = Instant::now();
        let dcid = ConnectionId::new(&[0x20; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x21, 0x43, 0x65, 0x87]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        client.send_stream(RELAY_STREAM_ID, &payload);

        // Deliver every data packet EXCEPT the last — a tail loss, which has no
        // higher-numbered packet to trigger packet-threshold detection.
        let mut pkts = Vec::new();
        while let Some(dg) = client.poll_transmit(now) {
            pkts.push(dg);
        }
        assert!(pkts.len() >= 3, "payload spans several packets");
        for dg in &pkts[..pkts.len() - 1] {
            server.handle_datagram(dg, now).unwrap();
        }
        // The server ACKs what it has; the client cannot yet detect the tail loss.
        while let Some(dg) = server.poll_transmit(now) {
            client.handle_datagram(&dg, now).unwrap();
        }
        assert!(
            client.poll_transmit(now).is_none(),
            "tail loss is not ACK-detectable — only a PTO recovers it"
        );

        // After the PTO elapses, the probe resends the tail; pump to completion.
        now += Duration::from_millis(500);
        client.handle_timeout(now);
        for _ in 0..16 {
            now += Duration::from_millis(50);
            let mut moved = false;
            while let Some(dg) = client.poll_transmit(now) {
                server.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            while let Some(dg) = server.poll_transmit(now) {
                client.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            if !moved {
                break;
            }
        }

        assert_eq!(
            server.read_stream(RELAY_STREAM_ID),
            payload,
            "the tail packet was recovered by a PTO probe and the stream reassembled"
        );
    }

    #[test]
    fn congestion_window_limits_the_in_flight_burst() {
        let now = Instant::now();
        let dcid = ConnectionId::new(&[0x30; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x31, 0x41, 0x59, 0x26]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking());

        // Offer far more than one initial congestion window (12000 bytes) of data
        // without delivering any ACK: the client must stop sending at ~the window.
        client.send_stream(RELAY_STREAM_ID, &vec![0x5a; 256 * 1024]);
        let mut burst = 0usize;
        while let Some(dg) = client.poll_transmit(now) {
            burst += dg.len();
        }
        assert!(
            (12_000..=14_000).contains(&burst),
            "first burst is bounded by the initial congestion window, got {burst} bytes"
        );
    }

    #[test]
    fn keep_alive_ping_is_sent_after_idle_interval() {
        let dcid = ConnectionId::new(&[0x40; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xab, 0xba, 0xab, 0xba]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(
            client.handshake_confirmed,
            "handshake confirmed before idle"
        );

        // Capture a clock at/after the last send, then idle past the keep-alive
        // interval and fire the timer.
        let mut now = Instant::now();
        assert!(
            client.poll_transmit(now).is_none(),
            "connection is idle after the handshake"
        );
        now += KEEP_ALIVE_INTERVAL + Duration::from_secs(1);
        client.handle_timeout(now);
        let ping = client
            .poll_transmit(now)
            .expect("an idle, confirmed connection queues a keep-alive PING");

        // The PING is ack-eliciting: the server schedules an ACK on receipt.
        server.handle_datagram(&ping, now).unwrap();
        assert!(
            server.poll_transmit(now).is_some(),
            "the server ACKs the keep-alive PING — the connection stays live"
        );
    }
}
