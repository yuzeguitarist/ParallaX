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

use super::congestion::{AckInfo, Bbr, Controller};
use super::frame::{Ack, Frame, Iter};
use super::packet::{self, ConnectionId, Header, LongType, PacketSpace};
use super::recovery::{RttEstimator, SentPacket, SentPackets};
use super::spaces::{PacketNumberSpace, ReceivedPackets};
use super::transport_params::TransportParameters;
use crate::tls::quic::{
    initial_keys, ClientConfig, ClientHandshake, ClientTicket, DirectionalKeys, KeyChange, KeyPair,
    Keys, PacketKey, QuicTlsError, ServerHandshake, Side, TlsSession, ZeroRttGuard,
    QUIC_VERSION_V1,
};
use zeroize::Zeroizing;

/// Why a connection is no longer usable (RFC 9000 §10), reported by
/// [`Connection::close_reason`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// This endpoint closed with an application error code + reason.
    LocalApp(u64, Vec<u8>),
    /// The peer sent an application CONNECTION_CLOSE (0x1d).
    PeerApp(u64, Vec<u8>),
    /// The peer sent a transport CONNECTION_CLOSE (0x1c).
    PeerTransport(u64, Vec<u8>),
    /// The idle timeout fired (RFC 9000 §10.1).
    IdleTimeout,
}

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

/// Entry-count cap on out-of-order CRYPTO fragments (complements the byte cap
/// above): bounds the number of buffered `(offset, Vec)` tuples so a flood of tiny
/// fragments cannot exhaust per-entry overhead even within the byte budget.
const MAX_CRYPTO_PENDING_FRAGMENTS: usize = 256;

/// Cap on out-of-order STREAM bytes buffered per stream. Connection/stream flow
/// control bounds the high watermark (the furthest offset seen), but NOT the
/// reassembly buffer: duplicate or overlapping out-of-order fragments do not
/// advance the watermark yet still buffer bytes. This byte cap (mirroring the
/// per-stream receive window) plus the zero-length guard and entry-count cap below
/// bound that buffer (memory-exhaustion DoS otherwise).
const MAX_STREAM_REASSEMBLY: usize = 2 * 1024 * 1024;

/// Entry-count cap on out-of-order STREAM fragments per stream (complements the
/// byte cap): bounds buffered tuples against a tiny-fragment flood.
const MAX_STREAM_PENDING_FRAGMENTS: usize = 4096;

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

/// Keep-alive period bounds: send a PING once the connection has been idle for a
/// per-cycle random interval drawn uniformly from `[MIN, MAX]`, to stop the peer's
/// idle timer from tearing down a held-open relay.
///
/// A FIXED interval (the old constant 15.000s) is a passive distinguisher: an idle
/// connection emits a `[PING, PADDING]` packet at an exact, jitter-free period, so
/// the inter-arrival series has a single sharp autocorrelation spike — a textbook
/// "periodic handshake" tell, made worse because it sat at exactly IDLE_TIMEOUT/2.
/// Re-rolling the interval every cycle smears that spike across the band. The mean
/// (~15s) is preserved so liveness/throughput are unchanged, and MAX stays well
/// under [`IDLE_TIMEOUT`] so the PING always reaches the peer before its idle timer
/// fires, even on a high-RTT path.
const KEEP_ALIVE_MIN: Duration = Duration::from_secs(10);
const KEEP_ALIVE_MAX: Duration = Duration::from_secs(20);

/// Idle timeout (RFC 9000 §10.1): tear the connection down after this long with no
/// received packet. Larger than [`KEEP_ALIVE_MAX`] so a live peer's keep-alive PING
/// refreshes it with margin to spare.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Draw a fresh keep-alive interval uniformly from `[KEEP_ALIVE_MIN, KEEP_ALIVE_MAX]`.
/// Sourced from the system CSPRNG so the period is unpredictable to an observer (a
/// low-entropy PRNG would leave a recoverable schedule). The range is small (10s),
/// so modulo bias over a u64 draw is negligible.
fn random_keep_alive_interval() -> Duration {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0_u8; 8];
    // A failed RNG draw is not a reason to abort a live connection; fall back to the
    // midpoint, which is still a valid keep-alive interval (just not jittered).
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return (KEEP_ALIVE_MIN + KEEP_ALIVE_MAX) / 2;
    }
    let span_ms = (KEEP_ALIVE_MAX - KEEP_ALIVE_MIN).as_millis() as u64;
    let offset_ms = u64::from_le_bytes(bytes) % (span_ms + 1);
    KEEP_ALIVE_MIN + Duration::from_millis(offset_ms)
}

/// Transport error code APPLICATION_ERROR (RFC 9000 §20.1), used for a transport
/// CONNECTION_CLOSE (0x1c) emitted before 1-RTT keys exist in place of an
/// application close (0x1d), which is prohibited in Initial/Handshake (§10.2.3).
const APPLICATION_ERROR: u64 = 0x0c;

const SPACE_INITIAL: usize = 0;
const SPACE_HANDSHAKE: usize = 1;
const SPACE_DATA: usize = 2;

fn space_index(space: PacketSpace) -> usize {
    match space {
        PacketSpace::Initial => SPACE_INITIAL,
        PacketSpace::Handshake => SPACE_HANDSHAKE,
        // 0-RTT shares the Application Data packet-number space (RFC 9000 §12.3);
        // only its protection keys differ.
        PacketSpace::ZeroRtt | PacketSpace::OneRtt => SPACE_DATA,
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
    /// Stream ids whose RESET_STREAM this packet carried; re-arm them if lost.
    reset: Vec<u64>,
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
    /// When this space last sent an ack-eliciting packet (RFC 9002 §6.2.1
    /// GetPtoTimeAndSpace): the per-space PTO is armed from here.
    last_ack_eliciting: Option<Instant>,
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
    /// The app requested RESET_STREAM with this error code; stop sending data.
    reset: Option<u64>,
    /// The RESET_STREAM frame has been packetized.
    reset_sent: bool,
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
#[allow(dead_code)] // named relay-stream id; used by the conn tests and the doc link below
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
    /// Congestion controller behind the CC seam (clean-room BBRv1; the only
    /// wired controller).
    cc: Box<dyn Controller>,
    /// Connection-wide cumulative delivered (acknowledged) bytes — the BBR /
    /// delivery-rate "delivered" counter (draft-cheng-iccrg-delivery-rate-est).
    delivered: u64,
    /// PTO exponential-backoff exponent, reset to 0 whenever an ACK is received.
    pto_count: u32,
    /// Number of probe packets allowed to bypass the congestion window (RFC 9002
    /// §6.2.4): a PTO sets this so a retransmit goes out even when cwnd is full.
    probe_pending: u8,
    /// Count of 1-RTT (Data-space) packets sealed with the current key, to enforce
    /// the AEAD confidentiality limit (RFC 9001 §6.6). Without 1-RTT key update we
    /// force-close before exceeding it rather than overrun the AEAD safety margin.
    data_packets_sealed: u64,
    /// Count of 1-RTT (Data-space) packets that FAILED to AEAD-open, to enforce the
    /// AEAD integrity limit (RFC 9001 §6.6). Without 1-RTT key update we force-close
    /// once forged-packet attempts reach the AEAD's forgery margin, mirroring the
    /// confidentiality-limit handling. Initial/Handshake/0-RTT open failures are
    /// excluded (public/short-lived keys).
    data_packets_open_failed: u64,
    /// The server queues HANDSHAKE_DONE once its handshake completes; resent if lost.
    handshake_done_pending: bool,
    /// The handshake is confirmed (RFC 9001 §4.1.2): the server when it sends
    /// HANDSHAKE_DONE, the client when it receives it.
    handshake_confirmed: bool,
    /// When any packet was last sent (drives the keep-alive timer).
    last_send_time: Option<Instant>,
    /// The current keep-alive cycle's interval, drawn fresh from
    /// `[KEEP_ALIVE_MIN, KEEP_ALIVE_MAX]` and re-rolled each time a keep-alive PING
    /// is queued, so the idle-PING period carries no fixed-cadence fingerprint. Read
    /// identically by `next_timeout` (to arm the timer) and `handle_timeout` (to
    /// fire it), so the armed deadline and the fire condition never disagree.
    keepalive_interval: Duration,
    /// A keep-alive (or PTO-fallback) PING is queued for the 1-RTT space.
    ping_pending: bool,
    /// The space the next `write_handshake` bytes belong to (advances on KeyChange).
    write_level: usize,
    /// 0-RTT (early-data) keys, installed from [`KeyChange::ZeroRtt`]. The client
    /// seals early-data packets with `local`; the server opens them with `remote`.
    /// `None` outside a 0-RTT resumption. (Wired into the 0-RTT send/recv path in S6.)
    zero_rtt_keys: Option<Keys>,
    /// All open streams, keyed by stream id (RFC 9000 §2.1).
    streams: BTreeMap<u64, Stream>,
    /// Next stream id this endpoint will allocate for an outgoing bidi / uni stream.
    next_bidi: u64,
    next_uni: u64,
    /// Peer-initiated streams newly observed, awaiting `accept_bi` / `accept_uni`.
    accept_bidi: VecDeque<u64>,
    accept_uni: VecDeque<u64>,
    /// Why the connection closed, if it has (local close, peer close, or idle).
    closed: Option<CloseReason>,
    /// A pending application CONNECTION_CLOSE to transmit `(error_code, reason)`.
    app_close_pending: Option<(u64, Vec<u8>)>,
    /// The CONNECTION_CLOSE has been put on the wire.
    app_close_sent: bool,
    /// When the connection entered the closing/draining state (RFC 9000 §10.2),
    /// for the 3×PTO drain countdown after which it can be reaped.
    close_time: Option<Instant>,
    /// The drain period has elapsed; the endpoint may remove this connection.
    drained: bool,
    /// When a packet was last received (drives the idle timeout, RFC 9000 §10.1).
    last_recv_time: Option<Instant>,
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
    /// Start a cold-start client connection. `dcid` is the client-chosen
    /// destination connection id for the first Initial; `scid` is our (zero-length)
    /// source CID.
    pub fn new_client(
        config: Arc<ClientConfig>,
        server_name: &str,
        dcid: ConnectionId,
        scid: ConnectionId,
    ) -> Result<Self, QuicTlsError> {
        Self::new_client_inner(config, server_name, dcid, scid, None, 0)
    }

    /// Start a 0-RTT resumption client connection: offers `ticket` (PSK +
    /// early_data) and installs the 0-RTT keys so early data can be sent before the
    /// handshake completes. `now_ms` is the current Unix time in milliseconds (for
    /// `obfuscated_ticket_age`).
    pub fn new_client_resumption(
        config: Arc<ClientConfig>,
        server_name: &str,
        dcid: ConnectionId,
        scid: ConnectionId,
        ticket: &ClientTicket,
        now_ms: u64,
    ) -> Result<Self, QuicTlsError> {
        Self::new_client_inner(config, server_name, dcid, scid, Some(ticket), now_ms)
    }

    fn new_client_inner(
        config: Arc<ClientConfig>,
        server_name: &str,
        dcid: ConnectionId,
        scid: ConnectionId,
        ticket: Option<&ClientTicket>,
        now_ms: u64,
    ) -> Result<Self, QuicTlsError> {
        let tp = TransportParameters::safari_client(scid.as_slice());
        let tp_blob = tp.encode_safari_client();
        let tls = match ticket {
            Some(t) => ClientHandshake::new_resumption(
                config,
                QUIC_VERSION_V1,
                server_name,
                tp_blob,
                t,
                now_ms,
            )?,
            None => ClientHandshake::new(config, QUIC_VERSION_V1, server_name, tp_blob)?,
        };
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
            cc: Box::new(Bbr::new()),
            delivered: 0,
            pto_count: 0,
            probe_pending: 0,
            data_packets_sealed: 0,
            data_packets_open_failed: 0,
            handshake_done_pending: false,
            handshake_confirmed: false,
            last_send_time: None,
            keepalive_interval: random_keep_alive_interval(),
            ping_pending: false,
            write_level: SPACE_INITIAL,
            zero_rtt_keys: None,
            streams: BTreeMap::new(),
            // Client-initiated stream ids: bidi 0,4,8,…; uni 2,6,10,… (RFC 9000 §2.1).
            next_bidi: 0,
            next_uni: 2,
            accept_bidi: VecDeque::new(),
            accept_uni: VecDeque::new(),
            closed: None,
            app_close_pending: None,
            app_close_sent: false,
            close_time: None,
            drained: false,
            last_recv_time: None,
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
        // 0-RTT: seed flow control from the remembered transport parameters so
        // early data can be sent before the server's parameters arrive (RFC 9001
        // §7.4.1). ensure_peer_flow later overwrites with the server's actual TP.
        if let Some(t) = ticket {
            conn.apply_remembered_transport_params(&t.peer_transport_params);
        }
        conn.pump_write(); // pull the ClientHello (and install 0-RTT keys on resumption)
        Ok(conn)
    }

    /// Start a server connection. `scid` is the server's source CID; the Initial
    /// keys and the client's CID are learned from the first Initial datagram.
    #[allow(dead_code)] // cold-start (no-STEK) server ctor; prod uses new_server_with_stek, tests use this
    pub fn new_server(
        cert_chain: Vec<Vec<u8>>,
        signing_key_pkcs8: &[u8],
        alpn_protocols: Vec<Vec<u8>>,
        transport_params: Vec<u8>,
        scid: ConnectionId,
    ) -> Result<Self, QuicTlsError> {
        Self::new_server_with_stek(
            cert_chain,
            signing_key_pkcs8,
            alpn_protocols,
            transport_params,
            scid,
            None,
        )
    }

    /// Like [`Self::new_server`] but with a Session-Ticket Encryption Key (STEK) so
    /// the server issues + accepts 0-RTT resumption tickets (RFC 8446 §4.6.1).
    pub fn new_server_with_stek(
        cert_chain: Vec<Vec<u8>>,
        signing_key_pkcs8: &[u8],
        alpn_protocols: Vec<Vec<u8>>,
        transport_params: Vec<u8>,
        scid: ConnectionId,
        stek: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Self, QuicTlsError> {
        let tls = ServerHandshake::new(
            cert_chain,
            signing_key_pkcs8,
            alpn_protocols,
            transport_params,
            stek,
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
            cc: Box::new(Bbr::new()),
            delivered: 0,
            pto_count: 0,
            probe_pending: 0,
            data_packets_sealed: 0,
            data_packets_open_failed: 0,
            handshake_done_pending: false,
            handshake_confirmed: false,
            last_send_time: None,
            keepalive_interval: random_keep_alive_interval(),
            ping_pending: false,
            write_level: SPACE_INITIAL,
            zero_rtt_keys: None,
            streams: BTreeMap::new(),
            // Server-initiated stream ids: bidi 1,5,9,…; uni 3,7,11,… (RFC 9000 §2.1).
            next_bidi: 1,
            next_uni: 3,
            accept_bidi: VecDeque::new(),
            accept_uni: VecDeque::new(),
            closed: None,
            app_close_pending: None,
            app_close_sent: false,
            close_time: None,
            drained: false,
            last_recv_time: None,
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

    /// Take a resumption ticket received on this connection via a post-handshake
    /// NewSessionTicket (client only; the server returns `None`). `now_ms` stamps
    /// the ticket-age epoch.
    pub fn take_session_ticket(&mut self, now_ms: u64) -> Option<ClientTicket> {
        self.tls.take_session_ticket(now_ms)
    }

    /// Install the cross-connection 0-RTT anti-replay guard (server only). Set right
    /// after construction, before any datagram is processed.
    pub fn set_zero_rtt_replay_guard(&mut self, guard: Arc<dyn ZeroRttGuard>) {
        self.tls.set_zero_rtt_guard(guard);
    }

    /// Install the origin-splice auth-marker key (server only). Set right after
    /// construction, before the ClientHello is processed; the server then verifies
    /// `ClientHello.random` and exposes the result via [`Self::marker_result`].
    pub fn set_marker_key(
        &mut self,
        psk: zeroize::Zeroizing<Vec<u8>>,
        static_priv: zeroize::Zeroizing<[u8; 32]>,
    ) {
        self.tls.set_marker_key(psk, static_priv);
    }

    /// The origin-splice auth marker recovered from this connection's
    /// ClientHello.random, if valid + fresh (server only; `None` otherwise). The
    /// endpoint driver consults this for the terminate-vs-splice fork.
    pub fn marker_result(&self) -> Option<crate::crypto::quic_marker::Marker> {
        self.tls.marker_result()
    }

    /// Whether the ClientHello has been processed, so [`Self::marker_result`] is final
    /// (server only). The endpoint's buffer-decide-then-route marker fork waits for
    /// this before deciding, since the Safari ClientHello spans two Initials.
    pub fn client_hello_processed(&self) -> bool {
        self.tls.client_hello_processed()
    }

    /// Whether 0-RTT keys are installed on this connection. On a resuming CLIENT
    /// this is set at construction (it can send early data); on the SERVER it is set
    /// only after it ACCEPTED a resumed ticket's 0-RTT (and can decrypt early data),
    /// so the server side reports "did we accept 0-RTT for this connection". A
    /// replayed/rejected/cold connection leaves it `false` (fell back to 1-RTT).
    #[allow(dead_code)] // 0-RTT acceptance inspection; exercised by the resumption/replay tests
    pub fn zero_rtt_keys_installed(&self) -> bool {
        self.zero_rtt_keys.is_some()
    }

    /// Close the connection with an application error code + reason (RFC 9000
    /// §19.19): an APPLICATION_CLOSE is queued for transmission. Idempotent.
    pub fn close(&mut self, error_code: u64, reason: &[u8]) {
        if self.closed.is_some() {
            return;
        }
        self.closed = Some(CloseReason::LocalApp(error_code, reason.to_vec()));
        self.app_close_pending = Some((error_code, reason.to_vec()));
    }

    /// Why the connection closed, if it has (local close, peer close, or idle).
    pub fn close_reason(&self) -> Option<&CloseReason> {
        self.closed.as_ref()
    }

    /// Whether the connection has closed (locally, by the peer, or on idle).
    pub fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Whether the closing/draining period (RFC 9000 §10.2) has elapsed, so the
    /// endpoint can drop this connection from its routing table.
    pub fn is_drained(&self) -> bool {
        self.drained
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
    #[allow(dead_code)] // key-update keys: implemented + tested; the relay closes at the AEAD limit, not rotates
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

    /// Abruptly reset stream `id`'s send half with `error_code` (RFC 9000 §19.4):
    /// stop sending its data and emit RESET_STREAM.
    pub fn reset_stream(&mut self, id: u64, error_code: u64) {
        self.create_local_stream(id);
        if let Some(s) = self.streams.get_mut(&id) {
            if s.reset.is_none() {
                s.reset = Some(error_code);
            }
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

    /// Seed flow-control limits from a resumption ticket's remembered transport
    /// parameters (RFC 9001 §7.4.1) so a 0-RTT client can send early data before the
    /// server's parameters arrive. Leaves `peer_flow_applied` false so
    /// [`Self::ensure_peer_flow`] later re-applies the server's actual parameters.
    fn apply_remembered_transport_params(&mut self, blob: &[u8]) {
        let Ok(tp) = TransportParameters::read(blob) else {
            return;
        };
        self.send_max_data = tp.initial_max_data;
        self.peer_msd_bidi_local = tp.initial_max_stream_data_bidi_local;
        self.peer_msd_bidi_remote = tp.initial_max_stream_data_bidi_remote;
        self.peer_msd_uni = tp.initial_max_stream_data_uni;
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
                Some(KeyChange::ZeroRtt { keys }) => {
                    // 0-RTT write keys (client resumption). Stored for the 0-RTT
                    // send path; the CRYPTO write_level stays in its current space.
                    self.zero_rtt_keys = Some(keys);
                }
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

    /// Discard a packet-number space's keys and all associated state (RFC 9001 §4.9,
    /// RFC 9002 §6.4): the packets it held leave bytes_in_flight and its loss/PTO
    /// timers and ACK/CRYPTO buffers are cleared. Used at the Initial→Handshake and
    /// Handshake→1-RTT transitions so stale handshake packets cannot throttle the
    /// 1-RTT congestion window or trigger probes in a keyspace the peer can no longer
    /// decrypt — and so the public Initial keys stop AEAD-opening forged packets once
    /// the handshake has moved on.
    fn discard_space(&mut self, space: usize) {
        self.spaces[space] = Space::default();
    }

    /// Force a local close once the 1-RTT AEAD confidentiality limit is reached
    /// (RFC 9001 §6.6). The relay does not perform 1-RTT key update, so closing is
    /// the spec-permitted alternative to rotating the key before the limit. (A
    /// ChaCha20-Poly1305 key has an effectively unbounded limit, so this never
    /// fires for it; AES-GCM caps at 2^23 packets.)
    fn enforce_aead_confidentiality_limit(&mut self) {
        if self.closed.is_some() {
            return;
        }
        let limit = self.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .map(|k| k.local.packet.confidentiality_limit());
        if let Some(limit) = limit {
            if self.data_packets_sealed >= limit {
                self.close(0, b"AEAD confidentiality limit reached");
            }
        }
    }

    /// Enforce the AEAD integrity limit (RFC 9001 §6.6): once the number of 1-RTT
    /// packets that failed to AEAD-open reaches the cipher's integrity limit, the
    /// key's forgery-resistance margin is spent. With no 1-RTT key update the only
    /// spec-permitted action is to close — mirroring `enforce_aead_confidentiality_limit`
    /// (same close shape, same NO_ERROR code) so this adds no externally distinct
    /// behavior. The limit (2^36 for ChaCha20-Poly1305, 2^52 for AES-GCM) is never
    /// reached in normal operation.
    fn enforce_aead_integrity_limit(&mut self) {
        if self.closed.is_some() {
            return;
        }
        let limit = self.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .map(|k| k.remote.packet.integrity_limit());
        if let Some(limit) = limit {
            if self.data_packets_open_failed >= limit {
                self.close(0, b"AEAD integrity limit reached");
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
        // Enforce the AEAD confidentiality limit (RFC 9001 §6.6): with no 1-RTT key
        // update, once we have sealed the cipher's safe number of 1-RTT packets we
        // MUST stop using the key — force-close rather than overrun the AEAD margin.
        self.enforce_aead_confidentiality_limit();
        self.enforce_aead_integrity_limit();
        // Once closed (locally, by the peer, or on idle) the connection enters the
        // closing/draining state (RFC 9000 §10.2): it sends at most a single
        // CONNECTION_CLOSE (for a local close) and is otherwise silent — no ACKs,
        // data, probes, or keep-alives. This also starts the drain countdown.
        if self.closed.is_some() {
            if self.close_time.is_none() {
                self.close_time = Some(now);
            }
            if self.app_close_pending.is_some() && !self.app_close_sent {
                if let Some(dg) = self.build_close_packet(now) {
                    return Some(dg);
                }
            }
            return None;
        }
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
            // 0-RTT early data: before 1-RTT keys exist, a resuming client sends app
            // stream data under the 0-RTT keys (same Application Data PN space).
            if self.spaces[SPACE_DATA].keys.is_none() && self.zero_rtt_keys.is_some() {
                if let Some(id) = self.next_stream_to_send() {
                    let dg = self.build_zero_rtt_stream_packet(id, now);
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
            // RESET_STREAM for any stream the app aborted.
            if self.spaces[SPACE_DATA].keys.is_some() {
                if let Some(id) = self.next_stream_to_reset() {
                    let dg = self.build_reset_packet(id, now);
                    self.probe_pending = self.probe_pending.saturating_sub(1);
                    return Some(dg);
                }
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

    /// Current PTO duration with exponential backoff (RFC 9002 §6.2.1). `max_ack_delay`
    /// is added only for the Application (1-RTT) space; Initial/Handshake peers must
    /// ACK immediately, so adding it there arms handshake probes too late.
    fn pto_duration(&self, space: usize) -> Duration {
        let extra = if space == SPACE_DATA {
            MAX_ACK_DELAY
        } else {
            Duration::ZERO
        };
        (self.rtt.pto_base() + extra) * 2u32.pow(self.pto_count.min(MAX_PTO_BACKOFF))
    }

    /// How long to remain in the closing/draining state before the connection is
    /// considered drained and reapable (RFC 9000 §10.2: at least 3×PTO).
    fn drain_duration(&self) -> Duration {
        3 * (self.rtt.pto_base() + MAX_ACK_DELAY)
    }

    /// The earliest loss-detection / PTO deadline, for the async layer to arm a
    /// timer against (RFC 9002 §6.2). `None` when nothing is outstanding.
    pub fn next_timeout(&self) -> Option<Instant> {
        // Closing/draining (RFC 9000 §10.2): the only timer is the drain deadline,
        // after which the connection is reapable. No loss/PTO/keep-alive/idle timers.
        if self.closed.is_some() {
            if self.drained {
                return None;
            }
            return self.close_time.map(|t| t + self.drain_duration());
        }
        let mut deadline: Option<Instant> = None;
        let mut earliest = |t: Instant| deadline = Some(deadline.map_or(t, |d| d.min(t)));
        for sp in &self.spaces {
            if let Some(lt) = sp.loss_time {
                earliest(lt);
            }
        }
        // PTO per packet-number space (RFC 9002 §6.2.1 GetPtoTimeAndSpace): each
        // space's timer is armed from its own last ack-eliciting send; the earliest
        // across spaces is when handle_timeout must probe.
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            if self.spaces[space].sent.in_flight() > 0 {
                if let Some(last) = self.spaces[space].last_ack_eliciting {
                    earliest(last + self.pto_duration(space));
                }
            }
        }
        // Keep-alive: once confirmed, schedule a PING after this cycle's (jittered)
        // idle interval. handle_timeout fires on the SAME field, so arm and fire agree.
        if self.handshake_confirmed {
            if let Some(last) = self.last_send_time {
                earliest(last + self.keepalive_interval);
            }
        }
        // Idle timeout (RFC 9000 §10.1): tear down after no receipt for too long.
        if self.closed.is_none() {
            if let Some(last) = self.last_recv_time {
                earliest(last + IDLE_TIMEOUT);
            }
        }
        deadline
    }

    /// Drive time-based loss detection and PTO (RFC 9002 §6.2). The async layer
    /// calls this when [`Self::next_timeout`] elapses; `poll_transmit` then sends
    /// any retransmits / probes that were queued.
    pub fn handle_timeout(&mut self, now: Instant) {
        // Closing/draining (RFC 9000 §10.2): count down to drained, nothing else.
        if self.closed.is_some() {
            if self.close_time.is_none() {
                self.close_time = Some(now);
            }
            if self
                .close_time
                .is_some_and(|t| now >= t + self.drain_duration())
            {
                self.drained = true;
            }
            return;
        }
        // Idle timeout (RFC 9000 §10.1): close the connection if silent too long.
        if self.closed.is_none()
            && self
                .last_recv_time
                .is_some_and(|last| now >= last + IDLE_TIMEOUT)
        {
            self.closed = Some(CloseReason::IdleTimeout);
            self.close_time = Some(now);
            return;
        }
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
            self.cc.on_congestion_event(now);
        }

        // Otherwise, if any space's PTO has elapsed (per-space timer, RFC 9002
        // §6.2.1), probe. queue_probe picks the lowest space with packets in flight.
        if !any_loss {
            let elapsed = [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA]
                .iter()
                .any(|&space| {
                    self.spaces[space].sent.in_flight() > 0
                        && self.spaces[space]
                            .last_ack_eliciting
                            .is_some_and(|last| now >= last + self.pto_duration(space))
                });
            if elapsed {
                self.pto_count = (self.pto_count + 1).min(MAX_PTO_BACKOFF);
                self.queue_probe();
            }
        }

        // Keep-alive: if the connection has been idle past this cycle's interval,
        // queue a PING so the peer's idle timer does not tear down a held-open relay,
        // then re-roll the interval so the NEXT idle period uses a fresh random
        // period (no fixed cadence to autocorrelate). Sending the PING refreshes
        // last_send_time, so the new interval governs the next cycle.
        if self.handshake_confirmed
            && self
                .last_send_time
                .is_some_and(|last| now >= last + self.keepalive_interval)
        {
            self.ping_pending = true;
            self.keepalive_interval = random_keep_alive_interval();
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
        for id in content.reset {
            if let Some(s) = self.streams.get_mut(&id) {
                s.reset_sent = false;
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
                delivered: self.delivered,
            },
        );
        if ack_eliciting {
            self.spaces[space].sent_content.insert(pn, content);
            self.spaces[space].last_ack_eliciting = Some(now);
        }
        if space == SPACE_DATA {
            // Every 1-RTT packet is sealed with the Data key; count it toward the
            // AEAD confidentiality limit (RFC 9001 §6.6).
            self.data_packets_sealed = self.data_packets_sealed.saturating_add(1);
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

    /// Build a packet carrying the queued application CONNECTION_CLOSE (RFC 9000
    /// §19.19) in the highest space with keys. `None` if no keys exist yet.
    fn build_close_packet(&mut self, now: Instant) -> Option<Vec<u8>> {
        let (code, reason) = self.app_close_pending.clone()?;
        let space = [SPACE_DATA, SPACE_HANDSHAKE, SPACE_INITIAL]
            .into_iter()
            .find(|&s| self.spaces[s].keys.is_some())?;
        let pn = self.spaces[space].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(space, pn, pn_len);
        // An application CONNECTION_CLOSE (0x1d) is prohibited in Initial/Handshake
        // packets (RFC 9000 §12.5). If 1-RTT keys are not yet installed, close with
        // a transport CONNECTION_CLOSE (0x1c) carrying APPLICATION_ERROR and no
        // application-specific code/reason (RFC 9000 §10.2.3).
        let close = if space == SPACE_DATA {
            super::frame::Close {
                application: true,
                error_code: code,
                frame_type: 0,
                reason: &reason,
            }
        } else {
            super::frame::Close {
                application: false,
                error_code: APPLICATION_ERROR,
                frame_type: 0,
                reason: &[],
            }
        };
        let datagram = {
            let keys = self.spaces[space].keys.as_ref().unwrap();
            seal_packet(
                &keys.local,
                header,
                &[Frame::Close(close), Frame::Padding(3)],
            )
        };
        self.app_close_sent = true;
        // CONNECTION_CLOSE is not ack-eliciting (RFC 9002 §2).
        self.record_sent(
            space,
            pn,
            datagram.len(),
            false,
            SentContent::default(),
            now,
        );
        Some(datagram)
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
                if s.reset.is_some() {
                    return false; // a reset stream sends RESET_STREAM, not data
                }
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

    /// The id of the next stream that owes a RESET_STREAM, if any.
    fn next_stream_to_reset(&self) -> Option<u64> {
        self.streams
            .iter()
            .find(|(_, s)| s.reset.is_some() && !s.reset_sent)
            .map(|(&id, _)| id)
    }

    /// Build a 1-RTT packet carrying RESET_STREAM for `id` (RFC 9000 §19.4),
    /// recording it for loss re-arm.
    fn build_reset_packet(&mut self, id: u64, now: Instant) -> Vec<u8> {
        let pn = self.spaces[SPACE_DATA].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(SPACE_DATA, pn, pn_len);
        let s = &self.streams[&id];
        let error_code = s.reset.unwrap_or(0);
        let final_size = s.send_off;
        let datagram = {
            let frame = Frame::ResetStream {
                id,
                error_code,
                final_size,
            };
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, &[frame, Frame::Padding(3)])
        };
        if let Some(s) = self.streams.get_mut(&id) {
            s.reset_sent = true;
        }
        let content = SentContent {
            reset: vec![id],
            ..Default::default()
        };
        self.record_sent(SPACE_DATA, pn, datagram.len(), true, content, now);
        datagram
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

    /// The 0-RTT long header (RFC 9000 §17.2.3) for an outgoing early-data packet.
    fn make_zero_rtt_header(&self, pn: u64, pn_len: usize) -> Header {
        Header::Long {
            ty: LongType::ZeroRtt,
            version: self.version,
            dcid: self.dcid,
            scid: self.scid,
            token: Vec::new(),
            length: MIN_INITIAL_DATAGRAM as u64, // placeholder; seal_packet fixes it
            packet_number: pn,
            pn_len,
        }
    }

    /// Build a 0-RTT packet carrying STREAM data for `id`, sealed with the early-data
    /// keys (client resumption). Mirrors [`Self::build_stream_packet`] but uses the
    /// 0-RTT keys + a 0-RTT long header; the packet number comes from the shared
    /// Application Data space (RFC 9000 §12.3). A lost 0-RTT packet's bytes stay
    /// buffered in the stream and are retransmitted in 1-RTT.
    fn build_zero_rtt_stream_packet(&mut self, id: u64, now: Instant) -> Vec<u8> {
        let pn = self.spaces[SPACE_DATA].send.allocate();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let tag_len = self
            .zero_rtt_keys
            .as_ref()
            .expect("0-RTT keys present")
            .local
            .packet
            .tag_len();
        let header = self.make_zero_rtt_header(pn, pn_len);
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
            let conn_window = self.send_max_data.saturating_sub(self.send_data_total);
            let fc_window = s.send_max.saturating_sub(offset).min(conn_window) as usize;
            let chunk = remaining.min(budget.max(1)).min(fc_window);
            let end = offset + chunk as u64;
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
            let keys = self.zero_rtt_keys.as_ref().expect("0-RTT keys present");
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
        // NB: the idle timer (last_recv_time) is refreshed inside process_packet
        // only AFTER a packet AEAD-opens (RFC 9000 §10.1: "received and processed"),
        // so an off-path attacker cannot pin the connection open with garbage UDP.
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
            let keys = if pspace == PacketSpace::ZeroRtt {
                // 0-RTT opens with the early-data keys. If they are not installed
                // (PSK not accepted, or the ClientHello not yet processed) the packet
                // is dropped — the genuine client then falls back to 1-RTT.
                match self.zero_rtt_keys.as_ref() {
                    Some(k) => &k.remote,
                    None => return Ok(()),
                }
            } else if let Some((_, k)) = &pending_initial {
                &k.remote
            } else {
                match self.spaces[space].keys.as_ref() {
                    Some(k) => &k.remote,
                    None => return Ok(()), // no keys installed for this space yet: drop
                }
            };
            open_packet(keys, pkt, local_cid_len, largest)
        };
        let (header, range) = match opened {
            Ok(v) => v,
            Err(_) => {
                // RFC 9001 §6.6: count 1-RTT AEAD decryption failures toward the
                // integrity limit. Only the long-lived 1-RTT key matters (0-RTT has a
                // separate short-lived key; Initial/Handshake forgeries are expected —
                // public keys). enforce_aead_integrity_limit() (run from poll_transmit,
                // like the confidentiality check) force-closes once the count reaches
                // the cipher's forgery margin — unreachable in normal operation, and
                // the same close a conformant QUIC stack performs.
                if space == SPACE_DATA && pspace != PacketSpace::ZeroRtt {
                    self.data_packets_open_failed = self.data_packets_open_failed.saturating_add(1);
                    self.enforce_aead_integrity_limit();
                }
                return Ok(()); // undecryptable: drop, do NOT fail the connection
            }
        };

        // The packet authenticated — only NOW is it safe to commit state derived
        // from this (now-trusted) datagram.
        // Refresh the idle timer only here, after authentication (RFC 9000 §10.1):
        // a forged/garbage datagram that never AEAD-opens must not reset it.
        self.last_recv_time = Some(now);
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

        // Successfully processing a Handshake packet proves the peer holds Handshake
        // keys, hence received our Initial CRYPTO: discard Initial keys + state (RFC
        // 9001 §4.9.1). Safe for both roles — the server's §4.9.1 trigger exactly,
        // and for the client it implies the server acked our ClientHello.
        if space == SPACE_HANDSHAKE && self.spaces[SPACE_INITIAL].keys.is_some() {
            self.discard_space(SPACE_INITIAL);
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
            // RFC 9000 §12.4/§12.5: Initial and Handshake packets may carry only
            // PADDING, PING, ACK, CRYPTO, and a transport CONNECTION_CLOSE (0x1c).
            // Any other frame is a PROTOCOL_VIOLATION. This matters because Initial
            // keys are publicly derivable (RFC 9001 §5.2), so an on-path attacker
            // can forge an Initial that AEAD-opens; without this gate it could inject
            // STREAM / MAX_DATA / RESET_STREAM etc. straight into the connection's
            // data plane. The packet is dropped (Err) rather than acted on.
            if matches!(space, SPACE_INITIAL | SPACE_HANDSHAKE)
                && !matches!(
                    frame,
                    Frame::Padding(_) | Frame::Ping | Frame::Ack(_) | Frame::Crypto { .. }
                )
                && !matches!(frame, Frame::Close(ref c) if !c.application)
            {
                return Err(QuicTlsError::Protocol(
                    "frame type not permitted in Initial/Handshake space".into(),
                ));
            }
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
                    // MAX_DATA is ack-eliciting (RFC 9002 §2), so a lone MAX_DATA
                    // must still schedule an ACK or the peer would PTO-retransmit it.
                    ack_eliciting = true;
                    self.send_max_data = self.send_max_data.max(max);
                }
                Frame::MaxStreamData { id, max } => {
                    // Raise a stream's send limit (RFC 9000 §19.10).
                    ack_eliciting = true;
                    if let Some(s) = self.streams.get_mut(&id) {
                        s.send_max = s.send_max.max(max);
                    }
                }
                Frame::Ack(ack) => self.recv_ack(space, &ack, now)?,
                Frame::HandshakeDone => {
                    ack_eliciting = true;
                    // RFC 9001 §4.1.2: the client treats HANDSHAKE_DONE as handshake
                    // confirmation. (Only a client should receive it.) On confirmation
                    // discard Handshake keys + state (RFC 9001 §4.9.2 / RFC 9002 §6.4).
                    if self.side == Side::Client {
                        self.handshake_confirmed = true;
                        self.discard_space(SPACE_HANDSHAKE);
                    }
                }
                Frame::Padding(_) => {}
                Frame::Close(c) => {
                    // The peer is tearing the connection down (RFC 9000 §19.19):
                    // enter the draining state and start the drain countdown.
                    if self.closed.is_none() {
                        let reason = c.reason.to_vec();
                        self.closed = Some(if c.application {
                            CloseReason::PeerApp(c.error_code, reason)
                        } else {
                            CloseReason::PeerTransport(c.error_code, reason)
                        });
                        self.close_time = Some(now);
                    }
                }
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
            // The server confirms when it completes (it has the client's Finished):
            // discard Handshake keys + state (RFC 9001 §4.9.2 / RFC 9002 §6.4).
            self.discard_space(SPACE_HANDSHAKE);
        }
    }

    /// Apply a received ACK frame (RFC 9002 §5–6.1): drop the acknowledged sent
    /// packets, fold one RTT sample (largest newly acked + an ack-eliciting packet),
    /// feed the congestion controller, then run loss detection and queue any lost
    /// CRYPTO/STREAM bytes for resend.
    fn recv_ack(&mut self, space: usize, ack: &Ack, now: Instant) -> Result<(), QuicTlsError> {
        // RFC 9000 §13.1: a peer must never acknowledge a packet number we never
        // sent. Reject such an ACK (PROTOCOL_VIOLATION) before on_ack runs — it would
        // otherwise advance largest_acked past anything sent, and the next loss
        // detection would declare every in-flight packet lost (a spurious-retransmit
        // storm). Critically reachable in the Initial space, whose keys are public.
        if ack.largest >= self.spaces[space].send.peek() {
            return Err(QuicTlsError::Protocol(
                "ACK acknowledges a packet number that was never sent".into(),
            ));
        }
        let newly = self.spaces[space].sent.on_ack(ack.largest, &ack.ranges);
        if newly.is_empty() {
            return Ok(());
        }
        // An ACK confirms forward progress, so reset the PTO backoff (RFC 9002 §6.2).
        self.pto_count = 0;
        // RTT sample: only when the largest acked is newly acked AND at least one
        // newly-acked packet was ack-eliciting (RFC 9002 §5.1). Track the largest
        // newly-acked packet's send time + its delivered mark for the BBR rate.
        let mut largest_time = None;
        let mut largest_delivered = None;
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
                largest_delivered = Some(sp.delivered);
            }
        }
        if let (Some(sent_at), true) = (largest_time, any_ack_eliciting) {
            // ACK delay applies only to the Application space (RFC 9002 §5.3); the
            // peer MUST send 0 for Initial/Handshake. Clamp to max_ack_delay so a
            // peer cannot report a huge ack_delay to deflate our smoothed RTT (and
            // thus trigger premature PTO/loss). RFC 9002 §5.3.
            let ack_delay = if space == SPACE_DATA {
                Duration::from_micros(ack.delay.saturating_mul(1 << ACK_DELAY_EXPONENT))
                    .min(MAX_ACK_DELAY)
            } else {
                Duration::ZERO
            };
            self.rtt
                .update(ack_delay, now.saturating_duration_since(sent_at));
        }
        // Feed the congestion controller: grow on newly-acked bytes + (for BBR) a
        // delivery-rate sample = (delivered since the largest packet was sent) /
        // (its in-flight time). See draft-cheng-iccrg-delivery-rate-estimation.
        if acked_bytes > 0 {
            self.delivered += acked_bytes;
            let delivery_rate = match (largest_time, largest_delivered) {
                (Some(sent_at), Some(sent_delivered)) => {
                    let elapsed = now.saturating_duration_since(sent_at).as_secs_f64();
                    if elapsed > 0.0 {
                        ((self.delivered - sent_delivered) as f64 / elapsed) as u64
                    } else {
                        0
                    }
                }
                _ => 0,
            };
            let info = AckInfo {
                now,
                bytes_acked: acked_bytes,
                rtt: self.rtt.latest(),
                delivery_rate,
                in_flight: self.bytes_in_flight(),
                delivered: self.delivered,
                app_limited: false,
            };
            self.cc.on_ack(&info);
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
            self.cc.on_congestion_event(now);
        }
        Ok(())
    }

    /// Reassemble an incoming CRYPTO fragment in order and feed the contiguous
    /// run to the TLS engine (which buffers partial handshake messages itself).
    fn recv_crypto(&mut self, space: usize, offset: u64, data: &[u8]) -> Result<(), QuicTlsError> {
        // A zero-length CRYPTO fragment carries nothing to reassemble and never
        // advances crypto_recv_off; dropping it here stops empty future-offset
        // fragments from growing crypto_pending without counting against the byte
        // cap (memory-exhaustion DoS — Initial keys are public, RFC 9001 §5.2).
        if data.is_empty() {
            return Ok(());
        }
        let mut to_feed: Vec<u8> = Vec::new();
        {
            let sp = &mut self.spaces[space];
            if offset > sp.crypto_recv_off {
                // Bound out-of-order CRYPTO buffering (see MAX_CRYPTO_REASSEMBLY):
                // reject offsets/volume/entry-count beyond the window rather than
                // buffer an attacker's ever-rising, never-contiguous fragments.
                let buffered: usize = sp.crypto_pending.iter().map(|(_, d)| d.len()).sum();
                if offset.saturating_sub(sp.crypto_recv_off) > MAX_CRYPTO_REASSEMBLY as u64
                    || buffered + data.len() > MAX_CRYPTO_REASSEMBLY
                    || sp.crypto_pending.len() >= MAX_CRYPTO_PENDING_FRAGMENTS
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
                // Evict fragments now fully below the receive offset. The drain
                // loop above only matches fragments that STRADDLE recv_off; a
                // fragment that an overlapping in-order fill jumped entirely past
                // (`o + len <= recv_off`) matches neither it nor any other removal
                // path, so it would linger forever while still counting toward the
                // MAX_CRYPTO_REASSEMBLY budget. A peer could exploit that to wedge
                // the budget and stall the (off-path-injectable, Initial-space)
                // handshake; drop the already-consumed bytes instead.
                sp.crypto_pending
                    .retain(|(o, d)| *o + d.len() as u64 > sp.crypto_recv_off);
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
        // FINAL_SIZE validation (RFC 9000 §4.5): once a final size is known it is
        // immutable, no data may arrive beyond it, and a FIN must not retroactively
        // place the final size below data already received.
        if let Some(final_size) = s.recv_fin {
            if end > final_size || (fin && end != final_size) {
                return Err(QuicTlsError::Protocol(
                    "STREAM frame violates the stream's final size".into(),
                ));
            }
        }
        if fin && end < s.recv_high {
            return Err(QuicTlsError::Protocol(
                "FIN final size below data already received".into(),
            ));
        }
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
        // In-order reassembly. Flow control above bounds the high watermark, but
        // NOT this buffer: a zero-length fragment (e.g. a bare FIN, already recorded
        // above) carries nothing to reassemble, and duplicate/overlapping fragments
        // do not advance the watermark yet still buffer bytes. Drop empties and cap
        // both buffered bytes and entry count (memory-exhaustion DoS otherwise).
        if offset > s.recv_off {
            if !data.is_empty() {
                let buffered: usize = s.recv_pending.iter().map(|(_, d)| d.len()).sum();
                if buffered + data.len() > MAX_STREAM_REASSEMBLY
                    || s.recv_pending.len() >= MAX_STREAM_PENDING_FRAGMENTS
                {
                    return Err(QuicTlsError::Crypto(
                        "stream reassembly buffer exceeded".into(),
                    ));
                }
                s.recv_pending.push((offset, data.to_vec()));
            }
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
        // Evict fragments now fully below the receive offset (see recv_crypto):
        // the drain loop only removes fragments straddling recv_off, so one that an
        // overlapping in-order fill jumped entirely past would otherwise linger and
        // permanently consume the MAX_STREAM_REASSEMBLY budget.
        s.recv_pending
            .retain(|(o, d)| *o + d.len() as u64 > s.recv_off);
        Ok(())
    }

    /// Record a peer RESET_STREAM (RFC 9000 §19.4): the receive half is truncated.
    /// The relay surfaces this as a ConnectionReset (a mid-transfer truncation),
    /// distinct from a clean FIN.
    fn recv_reset_stream(
        &mut self,
        id: u64,
        error_code: u64,
        final_size: u64,
    ) -> Result<(), QuicTlsError> {
        self.ensure_stream(id)?;
        let s = self.streams.get_mut(&id).expect("just ensured");
        // RFC 9000 §4.5: the reset's final size must agree with any known final
        // size and must not be below data already received; the bytes up to it count
        // toward connection-level flow control (they are considered delivered).
        if s.recv_fin.is_some_and(|known| known != final_size) {
            return Err(QuicTlsError::Protocol(
                "RESET_STREAM final size conflicts with a known final size".into(),
            ));
        }
        if final_size < s.recv_high {
            return Err(QuicTlsError::Protocol(
                "RESET_STREAM final size below data already received".into(),
            ));
        }
        if final_size > s.recv_max {
            return Err(QuicTlsError::Crypto(
                "RESET_STREAM exceeded the stream receive window".into(),
            ));
        }
        let delta = final_size - s.recv_high;
        if self.recv_data_total + delta > self.recv_max_data {
            return Err(QuicTlsError::Crypto(
                "RESET_STREAM exceeded the connection receive window".into(),
            ));
        }
        s.recv_high = final_size;
        s.recv_fin = Some(final_size);
        s.recv_reset = Some(error_code);
        self.recv_data_total += delta;
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
        // ensure_stream runs only on the receive path (the peer referenced `id`).
        // A peer may open streams only in ITS OWN initiator space (RFC 9000 §3.2 /
        // §19.8); referencing an unopened stream in our space is a STREAM_STATE_ERROR
        // and would otherwise bypass the peer-stream cap below (the count filters on
        // is_peer_initiated, so an our-space id was never counted — unbounded creation).
        if !self.is_peer_initiated(id) {
            return Err(QuicTlsError::Protocol(
                "peer referenced an unopened locally-initiated stream".into(),
            ));
        }
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
        let mut s = Stream::fresh();
        s.send_max = self.peer_send_limit(id);
        self.streams.insert(id, s);
        if is_uni(id) {
            self.accept_uni.push_back(id);
        } else {
            self.accept_bidi.push_back(id);
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

    #[test]
    fn integrity_limit_forces_close_with_no_error_at_the_limit() {
        // RFC 9001 §6.6: once 1-RTT AEAD-open failures reach the cipher's integrity
        // limit, the connection must close. Verify the `>=` boundary and that the close
        // mirrors the confidentiality-limit close exactly (NO_ERROR / code 0), so it
        // introduces no externally distinct fingerprint.
        let mut conn = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x5a, 0x5a, 0x5a, 0x5a]),
        )
        .unwrap();
        // Install 1-RTT (Data-space) keys so the integrity limit is defined.
        conn.spaces[SPACE_DATA].keys = Some(Keys {
            local: test_keys(),
            remote: test_keys(),
        });
        let limit = conn.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .unwrap()
            .remote
            .packet
            .integrity_limit();

        // One below the limit: no close.
        conn.data_packets_open_failed = limit - 1;
        conn.enforce_aead_integrity_limit();
        assert!(
            !conn.is_closed(),
            "below the integrity limit must not close"
        );

        // At the limit: force-close with NO_ERROR (code 0), like the confidentiality close.
        conn.data_packets_open_failed = limit;
        conn.enforce_aead_integrity_limit();
        assert!(conn.is_closed(), "reaching the integrity limit must close");
        assert!(
            matches!(conn.close_reason(), Some(CloseReason::LocalApp(0, _))),
            "integrity-limit close must use NO_ERROR (code 0), matching the confidentiality close"
        );
    }

    fn client_config() -> Arc<ClientConfig> {
        use crate::tls::quic::AcceptAnyServerCert;
        Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ))
    }

    #[test]
    fn reassembly_evicts_fragments_consumed_by_a_later_overlapping_fill() {
        // Regression: an in-order fill that jumps the receive offset entirely past
        // earlier out-of-order fragments must evict them. The drain loop only
        // removes fragments straddling recv_off, so without the post-drain
        // `retain` these fully-consumed fragments would wedge the bounded
        // reassembly budget and stall further reassembly.
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x4d, 0x4d, 0x4d, 0x4d]),
        )
        .unwrap();

        // Stream 0 is client-initiated bidi (peer-initiated for the server). Two
        // out-of-order fragments buffered ahead of the receive offset (0).
        server.recv_stream(0, 100, false, &[0xAA; 10]).unwrap(); // 100..110
        server.recv_stream(0, 200, false, &[0xBB; 10]).unwrap(); // 200..210
        assert_eq!(server.streams[&0].recv_pending.len(), 2);

        // A single in-order fragment fills 0..250, jumping recv_off past both
        // buffered fragments without straddling either.
        server.recv_stream(0, 0, false, &vec![0xCC; 250]).unwrap();

        assert_eq!(server.streams[&0].recv_off, 250);
        assert!(
            server.streams[&0].recv_pending.is_empty(),
            "fully-consumed out-of-order fragments must be evicted, not wedged in the budget"
        );
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
    fn client_receives_a_session_ticket_from_a_stek_server() {
        let dcid = ConnectionId::new(&[0x5e; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let stek = Zeroizing::new([0x33u8; 32]);
        let mut server = Connection::new_server_with_stek(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x12, 0x34, 0x56, 0x78]),
            Some(stek),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // The server issued a NewSessionTicket post-handshake; the client parsed it
        // into a resumption ticket usable for a future 0-RTT connection.
        let ticket = client
            .take_session_ticket(1_000_000)
            .expect("client received a resumption ticket");
        assert_eq!(ticket.suite, 0x1301);
        assert_eq!(ticket.alpn, b"h3");
        assert_eq!(ticket.psk.len(), 32);
        assert!(!ticket.ticket.is_empty(), "opaque ticket present");
        assert!(
            !ticket.is_expired(1_000_000),
            "freshly issued ticket is live"
        );
        assert_eq!(ticket.received_at_ms, 1_000_000);
        // The ticket is single-use: a second take yields nothing.
        assert!(client.take_session_ticket(1_000_000).is_none());
    }

    #[test]
    fn zero_rtt_early_data_flows_to_the_server() {
        let stek = Zeroizing::new([0x44u8; 32]);
        let cover = || vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]];

        // 1. Cold-start handshake to obtain a resumption ticket.
        let mut client = Connection::new_client(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x01; 8]),
            ConnectionId::new(&[]),
        )
        .unwrap();
        let mut server = Connection::new_server_with_stek(
            cover(),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xaa, 0xbb, 0xcc, 0xdd]),
            Some(stek.clone()),
        )
        .unwrap();
        drive(&mut client, &mut server);
        let ticket = client
            .take_session_ticket(1_000_000)
            .expect("client received a resumption ticket");

        // 2. A resumption connection that writes early data BEFORE the handshake.
        let mut rclient = Connection::new_client_resumption(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x02; 8]),
            ConnectionId::new(&[]),
            &ticket,
            1_001_000,
        )
        .unwrap();
        let mut rserver = Connection::new_server_with_stek(
            cover(),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]),
            Some(stek),
        )
        .unwrap();
        let early = b"GET /?0rtt early data over the resumed 0-RTT stream";
        rclient.send_stream(RELAY_STREAM_ID, early);

        // 3. Deliver the client's first flight (Initial ClientHello + 0-RTT) to the
        // server. At least one datagram MUST be a 0-RTT packet (long type 0x1).
        let now = Instant::now();
        let mut saw_zero_rtt = false;
        while let Some(dg) = rclient.poll_transmit(now) {
            if dg[0] & 0x80 != 0 && dg[0] & 0x30 == 0x10 {
                saw_zero_rtt = true;
            }
            rserver.handle_datagram(&dg, now).unwrap();
        }
        assert!(
            saw_zero_rtt,
            "client emitted a 0-RTT (long type 0x1) packet"
        );

        // 4. The server decrypted the 0-RTT early data with its 0-RTT keys — before
        // its own handshake flight even completes.
        assert!(
            rserver.zero_rtt_keys.is_some(),
            "server accepted the PSK and installed 0-RTT keys"
        );
        assert!(
            rserver.is_handshaking(),
            "server has not yet completed 1-RTT"
        );
        assert_eq!(
            rserver.read_stream(RELAY_STREAM_ID),
            early,
            "server received the 0-RTT early data"
        );

        // 5. The resumed handshake still completes cleanly afterwards.
        drive(&mut rclient, &mut rserver);
        assert!(
            !rclient.is_handshaking() && !rserver.is_handshaking(),
            "resumed handshake completes"
        );
    }

    #[test]
    fn single_use_ticket_rejects_a_0rtt_replay() {
        use std::sync::Arc;

        // A single-use guard shared across connections: the first presentation of a
        // ticket is accepted, any replay of the same identity is rejected.
        struct OnceGuard {
            used: std::sync::Mutex<std::collections::HashSet<Vec<u8>>>,
        }
        impl ZeroRttGuard for OnceGuard {
            fn accept_ticket(&self, identity: &[u8], _now_unix: u64) -> bool {
                self.used.lock().unwrap().insert(identity.to_vec())
            }
        }
        let guard: Arc<dyn ZeroRttGuard> = Arc::new(OnceGuard {
            used: std::sync::Mutex::new(std::collections::HashSet::new()),
        });

        let stek = Zeroizing::new([0x55u8; 32]);
        let cover = || vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]];

        // Mint a ticket via a cold-start handshake.
        let mut client = Connection::new_client(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x01; 8]),
            ConnectionId::new(&[]),
        )
        .unwrap();
        let mut server = Connection::new_server_with_stek(
            cover(),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xa1, 0xa2, 0xa3, 0xa4]),
            Some(stek.clone()),
        )
        .unwrap();
        drive(&mut client, &mut server);
        let ticket = client
            .take_session_ticket(1_000_000)
            .expect("client received a resumption ticket");
        let early = b"early data carried in a replayed 0-RTT flight";
        let now = Instant::now();

        // Attempt 1: a fresh ticket -> 0-RTT accepted.
        let mut c1 = Connection::new_client_resumption(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x02; 8]),
            ConnectionId::new(&[]),
            &ticket,
            1_001_000,
        )
        .unwrap();
        let mut s1 = Connection::new_server_with_stek(
            cover(),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xb1, 0xb2, 0xb3, 0xb4]),
            Some(stek.clone()),
        )
        .unwrap();
        s1.set_zero_rtt_replay_guard(guard.clone());
        c1.send_stream(RELAY_STREAM_ID, early);
        while let Some(dg) = c1.poll_transmit(now) {
            s1.handle_datagram(&dg, now).unwrap();
        }
        assert!(s1.zero_rtt_keys.is_some(), "first use: 0-RTT accepted");
        assert_eq!(
            s1.read_stream(RELAY_STREAM_ID),
            early,
            "first use: early data delivered"
        );

        // Attempt 2: the SAME ticket replayed -> 0-RTT rejected by the guard.
        let mut c2 = Connection::new_client_resumption(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x03; 8]),
            ConnectionId::new(&[]),
            &ticket,
            1_002_000,
        )
        .unwrap();
        let mut s2 = Connection::new_server_with_stek(
            cover(),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xc1, 0xc2, 0xc3, 0xc4]),
            Some(stek),
        )
        .unwrap();
        s2.set_zero_rtt_replay_guard(guard);
        c2.send_stream(RELAY_STREAM_ID, early);
        while let Some(dg) = c2.poll_transmit(now) {
            s2.handle_datagram(&dg, now).unwrap();
        }
        assert!(
            s2.zero_rtt_keys.is_none(),
            "replay: the single-use guard rejected 0-RTT"
        );
        assert!(
            s2.read_stream(RELAY_STREAM_ID).is_empty(),
            "replay: no early data accepted via 0-RTT"
        );

        // The replayed connection still completes a normal 1-RTT handshake.
        drive(&mut c2, &mut s2);
        assert!(
            !c2.is_handshaking() && !s2.is_handshaking(),
            "replayed connection falls back to a full 1-RTT handshake"
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
        // Advance past the worst-case (max) jittered interval so the keep-alive
        // fires regardless of this connection's random draw.
        now += KEEP_ALIVE_MAX + Duration::from_secs(1);
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

    #[test]
    fn keep_alive_interval_is_jittered_within_bounds() {
        // Every draw must stay inside [MIN, MAX] (so the PING never trips the 30s
        // idle timeout and never fires absurdly early), and the value must vary
        // across draws (a fixed cadence is the fingerprint we are removing).
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let interval = random_keep_alive_interval();
            assert!(
                interval >= KEEP_ALIVE_MIN && interval <= KEEP_ALIVE_MAX,
                "interval {interval:?} out of [{KEEP_ALIVE_MIN:?}, {KEEP_ALIVE_MAX:?}]"
            );
            assert!(
                interval < IDLE_TIMEOUT,
                "keep-alive interval must stay under the idle timeout"
            );
            seen.insert(interval.as_millis());
        }
        assert!(
            seen.len() > 1,
            "keep-alive interval must be jittered, not a single fixed value"
        );
    }

    #[test]
    fn closed_connection_goes_quiet_drains_and_stops_peer() {
        let dcid = ConnectionId::new(&[0x5c; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x5e, 0x5e, 0x5e, 0x5e]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(client.handshake_confirmed && server.handshake_confirmed);

        let mut now = Instant::now();
        // Local application close: exactly one CONNECTION_CLOSE goes out, then silence
        // (no ACKs, data, or keep-alive PINGs — RFC 9000 §10.2.1 closing state).
        client.close(0x1234, b"bye");
        let close_dg = client
            .poll_transmit(now)
            .expect("a local close emits one CONNECTION_CLOSE");
        assert!(
            client.poll_transmit(now).is_none(),
            "a closed connection is silent after its CONNECTION_CLOSE"
        );
        // The only armed timer is the drain deadline — not a past/immediate one that
        // would spin the driver at 100% CPU.
        let drain_deadline = client.next_timeout().expect("drain deadline armed");
        assert!(
            drain_deadline > now,
            "drain deadline is in the future, not a spin"
        );

        // The peer enters draining on receipt and itself goes quiet (RFC 9000 §10.2.2).
        server.handle_datagram(&close_dg, now).unwrap();
        assert!(
            server.is_closed(),
            "server enters draining on peer CONNECTION_CLOSE"
        );
        assert!(
            matches!(server.close_reason(), Some(CloseReason::PeerApp(0x1234, _))),
            "server records the peer application close"
        );
        assert!(
            server.poll_transmit(now).is_none(),
            "a draining peer does not transmit"
        );

        // After the drain period the connection is reapable and arms no timer.
        now += Duration::from_secs(60);
        client.handle_timeout(now);
        assert!(client.is_drained(), "closed connection drains after 3xPTO");
        assert!(
            client.next_timeout().is_none(),
            "a drained connection arms no timer (endpoint can reap it)"
        );
    }

    #[test]
    fn prohibited_frame_in_initial_space_is_a_protocol_violation() {
        // Initial keys are publicly derivable (RFC 9001 §5.2), so an on-path attacker
        // can forge an Initial that AEAD-opens. A STREAM frame is prohibited in the
        // Initial space (RFC 9000 §12.5) and must be rejected, never reaching the
        // data plane.
        let dcid = ConnectionId::new(&[0x88; 8]);
        let client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let pn = 0u64;
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = client.make_header(SPACE_INITIAL, pn, pn_len);
        let forged = {
            let keys = client.spaces[SPACE_INITIAL].keys.as_ref().unwrap();
            seal_packet(
                &keys.local,
                header,
                &[
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: false,
                        data: &b"injected"[..],
                    },
                    Frame::Padding(1200),
                ],
            )
        };
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x12, 0x34, 0x56, 0x78]),
        )
        .unwrap();
        let now = Instant::now();
        let err = server
            .handle_datagram(&forged, now)
            .expect_err("a forged STREAM in the Initial space is a protocol violation");
        assert!(
            matches!(err, QuicTlsError::Protocol(_)),
            "expected PROTOCOL_VIOLATION, got {err:?}"
        );
    }

    #[test]
    fn close_before_handshake_uses_transport_connection_close() {
        // Closing before 1-RTT keys exist must emit a transport CONNECTION_CLOSE
        // (0x1c) with APPLICATION_ERROR, never an application close (0x1d), which is
        // prohibited in Initial/Handshake packets (RFC 9000 §10.2.3/§12.5).
        let dcid = ConnectionId::new(&[0x77; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let now = Instant::now();
        while client.poll_transmit(now).is_some() {} // drain the Initial flight
        client.close(0x99, b"nope");
        let dg = client
            .poll_transmit(now)
            .expect("a close packet is emitted");
        let keys = client.spaces[SPACE_INITIAL].keys.as_ref().unwrap();
        let mut buf = dg.clone();
        let (_hdr, range) = open_packet(&keys.local, &mut buf, 0, None).unwrap();
        let mut saw_transport_close = false;
        for f in Iter::new(&buf[range]) {
            if let Frame::Close(c) = f.unwrap() {
                assert!(
                    !c.application,
                    "must be a transport CONNECTION_CLOSE (0x1c) in the Initial space"
                );
                assert_eq!(c.error_code, APPLICATION_ERROR);
                saw_transport_close = true;
            }
        }
        assert!(
            saw_transport_close,
            "the close packet carries CONNECTION_CLOSE"
        );
    }

    #[test]
    fn empty_crypto_fragments_do_not_grow_the_reassembly_buffer() {
        // Zero-length CRYPTO at a future offset can never become contiguous and
        // contributes 0 to the byte cap; it must be dropped, not buffered.
        let dcid = ConnectionId::new(&[0x6a; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        for _ in 0..10_000 {
            client.recv_crypto(SPACE_INITIAL, 1, &[]).unwrap();
        }
        assert!(
            client.spaces[SPACE_INITIAL].crypto_pending.is_empty(),
            "empty CRYPTO fragments are not buffered (no unbounded growth)"
        );
    }

    #[test]
    fn duplicate_out_of_order_stream_fragments_are_bounded() {
        // Each duplicate of a future-offset fragment leaves the flow-control high
        // watermark unchanged (delta 0), so only the reassembly cap bounds the
        // buffer. Without it, recv_pending would grow without bound.
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x6b, 0x6b, 0x6b, 0x6b]),
        )
        .unwrap();
        let chunk = vec![0xAB; 1000];
        let mut accepted = 0usize;
        let mut rejected = false;
        for _ in 0..5000 {
            match server.recv_stream(0, 10_000, false, &chunk) {
                Ok(()) => accepted += 1,
                Err(_) => {
                    rejected = true;
                    break;
                }
            }
        }
        assert!(
            rejected,
            "duplicate out-of-order fragments are eventually rejected"
        );
        assert!(
            accepted <= MAX_STREAM_REASSEMBLY / chunk.len() + 1,
            "recv_pending is bounded by the byte cap (accepted {accepted})"
        );
    }

    #[test]
    fn peer_cannot_open_a_locally_initiated_stream() {
        // A client never opened stream 0 (client-initiated bidi); a peer STREAM frame
        // for it is a STREAM_STATE_ERROR and must not bypass the peer-stream cap.
        let dcid = ConnectionId::new(&[0x4a; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let err = client
            .recv_stream(0, 0, false, b"x")
            .expect_err("a peer may not open a locally-initiated stream");
        assert!(matches!(err, QuicTlsError::Protocol(_)), "got {err:?}");
    }

    #[test]
    fn final_size_violations_are_rejected() {
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x4b, 0x4b, 0x4b, 0x4b]),
        )
        .unwrap();
        // Stream 0 is client-initiated bidi (peer-initiated for the server).
        server.recv_stream(0, 0, true, b"hello").unwrap(); // final size = 5
        let err = server
            .recv_stream(0, 5, false, b"more")
            .expect_err("data past the final size is rejected");
        assert!(matches!(err, QuicTlsError::Protocol(_)), "got {err:?}");
        let err2 = server
            .recv_stream(0, 0, true, b"hi")
            .expect_err("a conflicting final size is rejected");
        assert!(matches!(err2, QuicTlsError::Protocol(_)), "got {err2:?}");
    }

    #[test]
    fn reset_stream_final_size_is_validated_and_flow_accounted() {
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x4c, 0x4c, 0x4c, 0x4c]),
        )
        .unwrap();
        server.recv_stream(0, 0, false, &[0u8; 200]).unwrap(); // recv_high = 200
        let err = server
            .recv_reset_stream(0, 7, 100)
            .expect_err("a reset below data already received is rejected");
        assert!(matches!(err, QuicTlsError::Protocol(_)), "got {err:?}");
        // A consistent reset (final size >= received) is accepted.
        server.recv_reset_stream(0, 7, 200).unwrap();
    }

    #[test]
    fn initial_and_handshake_keys_are_discarded_after_the_handshake() {
        let dcid = ConnectionId::new(&[0x39; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x39, 0x39, 0x39, 0x39]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(client.handshake_confirmed && server.handshake_confirmed);

        // Both Initial and Handshake keys (and their sent-packet state) are gone
        // (RFC 9001 §4.9 / RFC 9002 §6.4): no stale handshake packets in flight, and
        // the public Initial keys no longer AEAD-open forged packets.
        for c in [&client, &server] {
            assert!(
                c.spaces[SPACE_INITIAL].keys.is_none(),
                "Initial keys discarded"
            );
            assert!(
                c.spaces[SPACE_HANDSHAKE].keys.is_none(),
                "Handshake keys discarded"
            );
            assert_eq!(c.spaces[SPACE_INITIAL].sent.in_flight(), 0);
            assert_eq!(c.spaces[SPACE_HANDSHAKE].sent.in_flight(), 0);
        }

        // Relay data still flows after the keys are discarded.
        let msg = b"after the handshake, over 1-RTT";
        client.send_stream(RELAY_STREAM_ID, msg);
        drive(&mut client, &mut server);
        assert_eq!(server.read_stream(RELAY_STREAM_ID), msg);
    }

    #[test]
    fn ack_of_unsent_packet_is_rejected() {
        // The DATA space has sent nothing (peek() == 0); an ACK claiming packet 1000
        // is a protocol violation (RFC 9000 §13.1) and must be rejected before it can
        // poison largest_acked and trigger a spurious-loss retransmit storm.
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x13, 0x13, 0x13, 0x13]),
        )
        .unwrap();
        let ack = Ack {
            largest: 1000,
            delay: 0,
            ranges: vec![(1000, 1000)],
            ecn: None,
        };
        let err = server
            .recv_ack(SPACE_DATA, &ack, Instant::now())
            .expect_err("an ACK of a never-sent packet is rejected");
        assert!(matches!(err, QuicTlsError::Protocol(_)), "got {err:?}");
    }

    #[test]
    fn unauthenticated_datagram_does_not_reset_the_idle_timer() {
        // Garbage that never AEAD-opens must not refresh the idle timer (RFC 9000
        // §10.1), else an off-path attacker could pin a connection open forever.
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x14, 0x14, 0x14, 0x14]),
        )
        .unwrap();
        assert!(server.last_recv_time.is_none());
        let _ = server.handle_datagram(&[0xff; 1200], Instant::now());
        assert!(
            server.last_recv_time.is_none(),
            "a garbage datagram must not start/refresh the idle timer"
        );
    }

    #[test]
    fn server_key_update_keys_are_direction_consistent() {
        let dcid = ConnectionId::new(&[0x6c; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x6c, 0x6c, 0x6c, 0x6c]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // The next key-update generation must be direction-consistent: the server's
        // seal key must pair with the client's open key and vice versa. If the server
        // omitted the local/remote swap, one direction fails to decrypt.
        let ckp = client.next_1rtt_keys().expect("client 1-RTT update keys");
        let skp = server.next_1rtt_keys().expect("server 1-RTT update keys");
        let tag = ckp.local.tag_len();

        // client -> server: client seals (local), server opens (remote).
        let c2s = b"key-update probe client to server";
        let mut buf = c2s.to_vec();
        buf.resize(c2s.len() + tag, 0);
        ckp.local.encrypt_in_place(42, &[], &mut buf).unwrap();
        assert_eq!(
            skp.remote.decrypt_in_place(42, &[], &mut buf).unwrap(),
            c2s,
            "server opens a packet the client sealed with the updated keys"
        );

        // server -> client: server seals (local), client opens (remote).
        let s2c = b"key-update probe server to client";
        let mut buf2 = s2c.to_vec();
        buf2.resize(s2c.len() + tag, 0);
        skp.local.encrypt_in_place(7, &[], &mut buf2).unwrap();
        assert_eq!(
            ckp.remote.decrypt_in_place(7, &[], &mut buf2).unwrap(),
            s2c,
            "client opens a packet the server sealed with the updated keys"
        );
    }
}
