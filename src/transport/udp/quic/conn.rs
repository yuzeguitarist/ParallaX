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

use std::collections::BTreeMap;
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
/// Cap on out-of-order STREAM bytes buffered for the relay — the advertised
/// per-stream receive window (full MAX_STREAM_DATA flow control lands in B2).
const MAX_STREAM_REASSEMBLY: usize = 2 * 1024 * 1024;

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
    /// Relay-stream byte ranges `(offset, len, fin)`.
    stream: Vec<(u64, u64, bool)>,
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

/// The relay's single bidirectional stream (client-initiated, id 0): the outgoing
/// byte buffer + how much has been packetized, and the in-order reassembled
/// inbound bytes. Flow control, FIN, and the general N-stream mux land with the
/// stream API in a later slice; the relay rides exactly this one bidi.
#[derive(Default)]
struct BidiStream {
    send: Vec<u8>,
    send_off: u64,
    /// Stream byte ranges `(offset, len, fin)` to RESEND before any fresh data.
    retransmit: Vec<(u64, u64, bool)>,
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
            rtt: RttEstimator::new(),
            cc: Box::new(NewReno::new()),
            pto_count: 0,
            probe_pending: 0,
            last_ack_eliciting_sent: None,
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
            rtt: RttEstimator::new(),
            cc: Box::new(NewReno::new()),
            pto_count: 0,
            probe_pending: 0,
            last_ack_eliciting_sent: None,
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
            // 1-RTT relay data: once Data keys are installed, resend losses then drain.
            if self.spaces[SPACE_DATA].keys.is_some()
                && (!self.stream.retransmit.is_empty()
                    || (self.stream.send_off as usize) < self.stream.send.len())
            {
                let dg = self.build_stream_packet(now);
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
                self.requeue(space, content);
                self.probe_pending = self.probe_pending.saturating_add(1);
                return;
            }
        }
    }

    /// Push a lost/probed packet's CRYPTO + STREAM ranges onto the resend queues.
    fn requeue(&mut self, space: usize, content: SentContent) {
        for range in content.crypto {
            self.spaces[space].retransmit_crypto.push(range);
        }
        for range in content.stream {
            self.stream.retransmit.push(range);
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
        };
        self.record_sent(space, pn, datagram.len(), true, content, now);
        if is_retransmit {
            self.spaces[space].retransmit_crypto.remove(0);
        } else {
            self.spaces[space].crypto_send_off = end;
        }
        datagram
    }

    /// Build one 1-RTT (short-header) packet carrying a STREAM frame — either a
    /// resend of a lost range or the next fresh slice of the relay stream.
    fn build_stream_packet(&mut self, now: Instant) -> Vec<u8> {
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

        let (offset, end, fin, is_retransmit) =
            if let Some(&(off, len, fin)) = self.stream.retransmit.first() {
                (off, off + len, fin, true)
            } else {
                let offset = self.stream.send_off;
                let frame_hdr =
                    1 + super::varint::size(RELAY_STREAM_ID) + super::varint::size(offset) + 2;
                let budget = MAX_DATAGRAM.saturating_sub(pn_offset + pn_len + tag_len + frame_hdr);
                let remaining = self.stream.send.len() - offset as usize;
                let chunk = remaining.min(budget.max(1));
                (offset, offset + chunk as u64, false, false)
            };

        let datagram = {
            let frame = Frame::Stream {
                id: RELAY_STREAM_ID,
                offset,
                fin,
                data: &self.stream.send[offset as usize..end as usize],
            };
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, &[frame])
        };

        let content = SentContent {
            crypto: Vec::new(),
            stream: vec![(offset, end - offset, fin)],
        };
        self.record_sent(SPACE_DATA, pn, datagram.len(), true, content, now);
        if is_retransmit {
            self.stream.retransmit.remove(0);
        } else {
            self.stream.send_off = end;
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
                    id, offset, data, ..
                } if id == RELAY_STREAM_ID => {
                    ack_eliciting = true;
                    self.recv_stream(offset, data)?;
                }
                Frame::Ack(ack) => self.recv_ack(space, &ack, now),
                Frame::Padding(_) | Frame::Close(_) => {}
                // PING, HANDSHAKE_DONE, and every other relay-relevant frame are
                // ack-eliciting but carry no payload we act on here.
                _ => ack_eliciting = true,
            }
        }
        if ack_eliciting {
            self.spaces[space].ack_pending = true;
        }
        self.pump_write();
        Ok(())
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

    /// Reassemble an incoming STREAM fragment in order into the relay stream's
    /// receive buffer (out-of-order fragments are buffered until contiguous, up to
    /// the advertised window — see [`MAX_STREAM_REASSEMBLY`]).
    fn recv_stream(&mut self, offset: u64, data: &[u8]) -> Result<(), QuicTlsError> {
        let s = &mut self.stream;
        if offset > s.recv_off {
            // Bound out-of-order STREAM buffering to the advertised window rather
            // than buffer unboundedly (full MAX_STREAM_DATA flow control is B2).
            let buffered: usize = s.recv_pending.iter().map(|(_, d)| d.len()).sum();
            if offset.saturating_sub(s.recv_off) > MAX_STREAM_REASSEMBLY as u64
                || buffered + data.len() > MAX_STREAM_REASSEMBLY
            {
                return Err(QuicTlsError::Crypto(
                    "STREAM reassembly window exceeded".into(),
                ));
            }
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
            vec![0x01, 0x02, 0x03, 0x04],
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
        client.send_stream(b"coalesced request");
        drive_coalesced(&mut client, &mut server);
        assert_eq!(server.read_stream(), b"coalesced request");
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
            vec![0x01, 0x02, 0x03, 0x04],
            ConnectionId::new(&[0x12, 0x34, 0x56, 0x78]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // A payload spanning several 1-RTT packets.
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        client.send_stream(&payload);

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
            server.read_stream(),
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
            vec![0x01, 0x02, 0x03, 0x04],
            ConnectionId::new(&[0x21, 0x43, 0x65, 0x87]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        client.send_stream(&payload);

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
            server.read_stream(),
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
            vec![0x01, 0x02, 0x03, 0x04],
            ConnectionId::new(&[0x31, 0x41, 0x59, 0x26]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking());

        // Offer far more than one initial congestion window (12000 bytes) of data
        // without delivering any ACK: the client must stop sending at ~the window.
        client.send_stream(&vec![0x5a; 256 * 1024]);
        let mut burst = 0usize;
        while let Some(dg) = client.poll_transmit(now) {
            burst += dg.len();
        }
        assert!(
            (12_000..=14_000).contains(&burst),
            "first burst is bounded by the initial congestion window, got {burst} bytes"
        );
    }
}
