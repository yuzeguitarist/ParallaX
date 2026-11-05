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
use super::frame::{Ack, Dir, Frame, Iter};
use super::pacer::Pacer;
use super::packet::{self, ConnectionId, Header, LongType, PacketSpace};
use super::pmtud::Pmtud;
use super::recovery::{RttEstimator, SentPacket, SentPackets};
use super::spaces::{PacketNumberSpace, ReceivedPackets};
use super::transport_params::TransportParameters;
use crate::tls::quic::{
    initial_keys, ClientConfig, ClientHandshake, ClientTicket, DirectionalKeys,
    HeaderProtectionKey, KeyChange, KeyPair, Keys, PacketKey, QuicTlsError, ServerHandshake, Side,
    TlsSession, ZeroRttGuard, QUIC_VERSION_V1,
};
use zeroize::Zeroizing;

/// Why a connection is no longer usable (RFC 9000 §10), reported by
/// [`Connection::close_reason`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// This endpoint closed with an application error code + reason.
    LocalApp(u64, Vec<u8>),
    /// This endpoint closed with a transport error code, frame type, and reason.
    LocalTransport(u64, u64, Vec<u8>),
    /// The peer sent an application CONNECTION_CLOSE (0x1d).
    PeerApp(u64, Vec<u8>),
    /// The peer sent a transport CONNECTION_CLOSE (0x1c).
    PeerTransport(u64, u64, Vec<u8>),
    /// The idle timeout fired (RFC 9000 §10.1).
    IdleTimeout,
}

/// Admission for decoded frame codepoints, before that frame has any effect.
/// Keep the original packet level: 0-RTT shares a PN space with 1-RTT, but not
/// its permitted frames. RFC 9000 §§12.4–12.5 and verified erratum 7365.
fn frame_permitted(space: PacketSpace, side: Side, frame_type: u64) -> bool {
    if side == Side::Server && matches!(frame_type, 0x07 | 0x1e) {
        return false;
    }
    match space {
        PacketSpace::Initial | PacketSpace::Handshake => {
            matches!(frame_type, 0x00 | 0x01 | 0x02 | 0x03 | 0x06 | 0x1c)
        }
        PacketSpace::ZeroRtt => {
            !matches!(frame_type, 0x02 | 0x03 | 0x06 | 0x07 | 0x19 | 0x1b | 0x1e)
        }
        PacketSpace::OneRtt => true,
    }
}

/// Exhausting a protection key ends the connection without another encrypted
/// close packet. Preserve an existing close reason, but cancel even a close that
/// was queued before the budget was spent. Used by both transmit entry points.
fn close_on_exhausted_data_key(
    sealed: u64,
    limit: u64,
    closed: &mut Option<CloseReason>,
    close_pending: &mut Option<(u64, Option<u64>, Vec<u8>)>,
) {
    if sealed < limit {
        return;
    }
    if closed.is_none() {
        *closed = Some(CloseReason::LocalApp(
            0,
            b"AEAD confidentiality limit reached".to_vec(),
        ));
    }
    *close_pending = None;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadGeneration {
    Previous,
    Current,
    Next,
    Unavailable,
}

/// Non-secret key-update metadata. Packet numbers remain in the existing global
/// Application space; these frontiers only bind an authenticated PN to its key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct KeyPhaseState {
    tx: u64,
    rx: u64,
    tx_first: Option<u64>,
    tx_last: Option<u64>,
    tx_acked: bool,
    rx_min: Option<u64>,
    rx_max: Option<u64>,
    previous_max: Option<u64>,
    update_ack_pending: bool,
}

impl KeyPhaseState {
    fn select(&self, phase: bool, pn: u64) -> ReadGeneration {
        if phase == (self.rx & 1 != 0) {
            ReadGeneration::Current
        } else if self.rx_min.is_some_and(|min| pn < min) {
            ReadGeneration::Previous
        } else if self.rx_max.map_or(true, |max| pn > max) {
            ReadGeneration::Next
        } else {
            ReadGeneration::Unavailable
        }
    }

    fn valid_receive(&self, generation: ReadGeneration, pn: u64) -> bool {
        match generation {
            ReadGeneration::Current => self.previous_max.map_or(true, |max| pn > max),
            ReadGeneration::Previous => self.rx > 0 && self.rx_min.is_some_and(|min| pn < min),
            ReadGeneration::Next => {
                self.rx.checked_add(1).is_some()
                    && (!self.update_ack_pending || self.rx.checked_add(1) == Some(self.tx))
                    && self.rx_max.map_or(true, |max| pn > max)
            }
            ReadGeneration::Unavailable => false,
        }
    }

    /// Authentication, ordering and global dedup are independent prerequisites.
    fn commit_receive(
        &mut self,
        generation: ReadGeneration,
        pn: u64,
        authenticated: bool,
        fresh: bool,
    ) -> bool {
        if !authenticated || !fresh || !self.valid_receive(generation, pn) {
            return false;
        }
        match generation {
            ReadGeneration::Next => {
                self.rx = self.rx.checked_add(1).expect("validated generation");
                self.previous_max = self.rx_max;
                self.rx_min = Some(pn);
                self.rx_max = Some(pn);
                self.update_ack_pending = true;
            }
            ReadGeneration::Current => {
                self.rx_min = Some(self.rx_min.map_or(pn, |min| min.min(pn)));
                self.rx_max = Some(self.rx_max.map_or(pn, |max| max.max(pn)));
            }
            ReadGeneration::Previous => {
                self.previous_max = Some(self.previous_max.map_or(pn, |max| max.max(pn)));
            }
            ReadGeneration::Unavailable => unreachable!(),
        }
        true
    }

    fn active_successor(&self, confirmed: bool) -> Option<u64> {
        (confirmed && self.tx == self.rx && self.tx_acked)
            .then(|| self.tx.checked_add(1))
            .flatten()
    }

    fn confirm(&mut self, receive_generation: u64, low: u64, high: u64) -> bool {
        let covered = self
            .tx_first
            .zip(self.tx_last)
            .is_some_and(|(first, last)| low <= high && low <= last && high >= first);
        if receive_generation < self.tx || !covered {
            return false;
        }
        self.tx_acked = true;
        true
    }
}

/// Each direction consumes its own half once. An initiating sender may be one
/// generation ahead of its receiver until the peer responds.
struct NextPacketKeys {
    generation: u64,
    local: Option<PacketKey>,
    remote: Option<PacketKey>,
}

struct PreviousReadKey {
    key: PacketKey,
    retire_at: Instant,
}

/// Only fresh, authenticated ack-eliciting packets contribute to this count.
/// Two is also the immediate-feedback state; no ACK frame or key is retained.
fn ack_count_after_packet(count: u8, ack_eliciting: bool, immediate: bool) -> u8 {
    if !ack_eliciting {
        return count;
    }
    if immediate {
        2
    } else {
        count.saturating_add(1).min(2)
    }
}

fn ack_count_due(count: u8, expired: bool) -> bool {
    count >= 2 || (count != 0 && expired)
}

fn encoded_ack_delay(elapsed: Duration) -> u64 {
    ((elapsed.as_micros() >> ACK_DELAY_EXPONENT).min((1u128 << 62) - 1)) as u64
}

fn decoded_ack_delay(raw: u64, exponent: u32) -> Duration {
    // Both inputs are wire-validated: raw <= 2^62-1 and exponent <= 20.
    // The complete scaled value fits u128; its seconds fit u64.
    let micros = (raw as u128) << exponent;
    Duration::new(
        (micros / 1_000_000) as u64,
        ((micros % 1_000_000) * 1_000) as u32,
    )
}

fn ack_delay_for_recovery(
    raw: u64,
    exponent: u32,
    space: usize,
    confirmed: bool,
    peer_max: Duration,
) -> Duration {
    cap_decoded_peer_ack_delay(decoded_ack_delay(raw, exponent), space, confirmed, peer_max)
}

fn cap_decoded_peer_ack_delay(
    delay: Duration,
    space: usize,
    confirmed: bool,
    peer_max: Duration,
) -> Duration {
    if space != SPACE_DATA {
        return Duration::ZERO;
    }
    if confirmed {
        delay.min(peer_max)
    } else {
        delay
    }
}

fn pto_space_eligible(space: usize, confirmed: bool) -> bool {
    space != SPACE_DATA || confirmed
}

fn peer_ack_delay_for_pto(space: usize, confirmed: bool, peer_max: Duration) -> Duration {
    if space == SPACE_DATA && confirmed {
        peer_max
    } else {
        Duration::ZERO
    }
}

fn transport_error(error_code: u64, frame_type: u64, reason: impl Into<String>) -> QuicTlsError {
    QuicTlsError::Transport {
        error_code,
        frame_type,
        reason: reason.into(),
    }
}

/// Preserve the transport code while attaching the actual decoded wire type.
fn with_frame_type(error: QuicTlsError, frame_type: u64) -> QuicTlsError {
    match error {
        QuicTlsError::Transport {
            error_code, reason, ..
        } => transport_error(error_code, frame_type, reason),
        QuicTlsError::Protocol(reason) => transport_error(0x0a, frame_type, reason),
        QuicTlsError::Crypto(reason) => transport_error(0x01, frame_type, reason),
        other => other,
    }
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
    let opened = unprotect_packet_header(&keys.header, datagram, local_cid_len, largest_pn)?;
    let payload = open_packet_payload(&keys.packet, datagram, &opened)?;
    Ok((opened.header, payload))
}

struct UnprotectedHeader {
    header: Header,
    aad_len: usize,
    body_end: usize,
}

/// Remove HP once. A 1-RTT receiver can select one generation's AEAD key from
/// the unprotected phase/PN; neither is trusted before payload authentication.
fn unprotect_packet_header(
    key: &HeaderProtectionKey,
    datagram: &mut [u8],
    local_cid_len: usize,
    largest_pn: Option<u64>,
) -> Result<UnprotectedHeader, OpenError> {
    let pn_offset = packet::locate_pn_offset(datagram, local_cid_len)?;
    key.decrypt_header(pn_offset, datagram)
        .map_err(|_| OpenError::Crypto)?;
    // `Header::decode` reconstructs the full packet number internally from
    // `largest_pn` (the largest PN already processed in this space; 0 before the
    // first packet, which makes the reconstruction a no-op for the small early
    // packet numbers — equivalent to taking the truncated value verbatim).
    let (header, aad_len) = Header::decode(datagram, local_cid_len, largest_pn.unwrap_or(0))?;
    let pn_len = header.pn_len();

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

    Ok(UnprotectedHeader {
        header,
        aad_len,
        body_end,
    })
}

fn open_packet_payload(
    key: &PacketKey,
    datagram: &mut [u8],
    opened: &UnprotectedHeader,
) -> Result<std::ops::Range<usize>, OpenError> {
    let (aad, body) = datagram.split_at_mut(opened.aad_len);
    let pt = key
        .decrypt_in_place(
            opened.header.packet_number(),
            aad,
            &mut body[..opened.body_end - opened.aad_len],
        )
        .map_err(|_| OpenError::Crypto)?;
    let pt_len = pt.len();
    Ok(opened.aad_len..opened.aad_len + pt_len)
}

/// RFC 9000 §14.1: a client MUST pad every datagram carrying an Initial packet to
/// at least 1200 bytes so the path can carry it before address validation.
const MIN_INITIAL_DATAGRAM: usize = 1200;
/// A conservative max UDP payload for non-Initial packets (one datagram holds the
/// whole Handshake flight in practice).
const MAX_DATAGRAM: usize = 1252;
/// Safari's per-packet cap on client Initial CRYPTO bytes: its ClientHello is cut
/// 999 + rest, the first Initial padded out with PADDING (Safari 26.3 wire, every
/// connection, cold and 0-RTT, 2026-10-27). Initial keys are public, so an
/// observer sees this split.
const SAFARI_INITIAL_CRYPTO_CHUNK: usize = 999;

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

/// Cap on out-of-order STREAM bytes buffered across ALL streams, tied to the
/// connection receive window. The per-stream cap composes badly on its own:
/// duplicate/overlapping fragments below a stream's high watermark cost (almost)
/// no connection flow-control credit, so [`MAX_PEER_STREAMS`] of each kind ×
/// [`MAX_STREAM_REASSEMBLY`] (~256 MiB) could be buffered while
/// [`CONN_RECV_WINDOW`] (16 MiB) is never engaged. This aggregate budget
/// restores the connection-level bound the flow-control design assumes.
const MAX_CONN_REASSEMBLY: usize = CONN_RECV_WINDOW as usize;

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
///
/// If the CSPRNG draw fails (should never happen on a live host), the fallback must
/// still VARY the period: returning a fixed value (e.g. the midpoint) would re-create
/// exactly the constant-cadence autocorrelation tell this jitter exists to remove.
/// The fallback therefore walks a process-local counter across the span so successive
/// intervals still differ, with no wall-clock read (the sans-IO core stays
/// time-input-free). This trades unpredictability for liveness ONLY on the degraded
/// path where the CSPRNG is non-functional: the counter walk is itself a predictable
/// sequence (an active prober who knew the counter origin could extrapolate it), but it
/// still removes the fixed-cadence autocorrelation spike that is the primary passive
/// tell, and it is strictly better than the constant value it replaces. On a healthy
/// host this branch is unreachable.
fn random_keep_alive_interval() -> Duration {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let span_ms = (KEEP_ALIVE_MAX - KEEP_ALIVE_MIN).as_millis() as u64;
    let mut bytes = [0_u8; 8];
    let offset_ms = if SystemRandom::new().fill(&mut bytes).is_ok() {
        u64::from_le_bytes(bytes) % (span_ms + 1)
    } else {
        // Degraded fallback: a fixed value would be a fixed-cadence fingerprint, so
        // step a static counter through the span instead. Non-clock, non-constant.
        use std::sync::atomic::{AtomicU64, Ordering};
        static FALLBACK_STEP: AtomicU64 = AtomicU64::new(0);
        let step = FALLBACK_STEP.fetch_add(1, Ordering::Relaxed);
        fallback_keep_alive_offset_ms(step, span_ms)
    };
    KEEP_ALIVE_MIN + Duration::from_millis(offset_ms)
}

/// The CSPRNG-failure fallback offset (ms into the keep-alive span) for the `step`-th
/// call. Walking the counter across `[0, span_ms]` keeps successive intervals varying
/// (no fixed-cadence tell) without reading the clock. Pure, so it is unit-testable.
fn fallback_keep_alive_offset_ms(step: u64, span_ms: u64) -> u64 {
    step % (span_ms + 1)
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

/// The IP-layer ECN codepoint of a received datagram (RFC 3168 / RFC 9000 §13.4): the
/// low two bits of the IP TOS / IPv6 traffic-class byte. The connection counts these
/// per packet-number space and echoes the totals in ACK_ECN so the peer can validate
/// ECN end to end (RFC 9000 §13.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EcnCodepoint {
    /// Not ECN-Capable Transport (0b00): the default when the path/kernel strips ECN.
    #[default]
    NotEct,
    /// ECT(0) (0b10) — what ParallaX (and Safari) mark on egress.
    Ect0,
    /// ECT(1) (0b01).
    Ect1,
    /// Congestion Experienced (0b11): a router marked congestion on the path.
    Ce,
}

impl EcnCodepoint {
    /// Map the raw 2-bit ECN field to a codepoint (any out-of-range value ⇒ Not-ECT).
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b10 => EcnCodepoint::Ect0,
            0b01 => EcnCodepoint::Ect1,
            0b11 => EcnCodepoint::Ce,
            _ => EcnCodepoint::NotEct,
        }
    }
}

/// Per-packet-number-space tally of received ECN codepoints, echoed in ACK_ECN
/// (RFC 9000 §19.3.2). Only the Application space sees a meaningful CE stream in
/// practice, but the counts are kept per space for RFC correctness.
#[derive(Debug, Clone, Copy, Default)]
struct EcnCounts {
    ect0: u64,
    ect1: u64,
    ce: u64,
}

impl EcnCounts {
    /// Fold one received datagram's ECN codepoint into the running totals.
    fn record(&mut self, ecn: EcnCodepoint) {
        match ecn {
            EcnCodepoint::Ect0 => self.ect0 += 1,
            EcnCodepoint::Ect1 => self.ect1 += 1,
            EcnCodepoint::Ce => self.ce += 1,
            EcnCodepoint::NotEct => {}
        }
    }

    /// Whether any ECN codepoint has been seen (so a space that never received ECN
    /// sends a plain ACK, not ACK_ECN — matching a path that strips ECN).
    fn any(&self) -> bool {
        self.ect0 != 0 || self.ect1 != 0 || self.ce != 0
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
    /// Directions whose cumulative MAX_STREAMS grant must be re-armed if lost.
    max_streams: [bool; 2],
    /// Stream ids whose RESET_STREAM this packet carried; re-arm them if lost.
    reset: Vec<u64>,
}

/// Per-packet-number-space state: protection keys (installed as the handshake
/// crosses spaces), the send allocator + received-PN set, and the in-/out-bound
/// CRYPTO byte streams.
#[derive(Default)]
struct Space {
    keys: Option<Keys>,
    /// Discard is permanent: absent keys alone also describes an Initial space
    /// whose keys have not yet been derived on the server.
    discarded: bool,
    send: PacketNumberSpace,
    recv: ReceivedPackets,
    /// Sent-packet bookkeeping for loss detection + RTT (RFC 9002 §6.1).
    sent: SentPackets,
    /// Per-packet-number retransmittable content, kept in lockstep with `sent`:
    /// removed when the packet is acked, drained into the retransmit queues when
    /// it is declared lost.
    sent_content: BTreeMap<u64, SentContent>,
    /// Running tally of received ECN codepoints in this space, echoed in ACK_ECN
    /// (RFC 9000 §13.4.2) so the peer can validate ECN. Incremented after a packet in
    /// a received datagram AEAD-opens (an authenticated ECN mark).
    recv_ecn: EcnCounts,
    /// An ack-eliciting packet has been received and not yet acknowledged.
    ack_pending: bool,
    ack_eliciting_count: u8,
    ack_deadline: Option<Instant>,
    /// When the LARGEST-numbered packet covered by the current (not-yet-sent) ACK was
    /// received, for the `ack_delay` field (RFC 9000 §13.2.5: ack_delay is measured from
    /// the receipt of the largest ACKNOWLEDGED packet, NOT the first one in the batch —
    /// using the first would overreport the delay by the packets' inter-arrival gap and
    /// inflate the peer's RTT). The ACK's Largest Acknowledged is `recv.largest()`, which
    /// may be a NON-ack-eliciting packet (e.g. a pure ACK whose PN exceeds a later,
    /// reordered ack-eliciting packet), so this is updated whenever ANY newly-received
    /// packet becomes the new largest — NOT gated on ack-eliciting (gating it there left
    /// a stale, too-old stamp in that interleaving). Retained while ranges retain the largest PN. A real
    /// QUIC stack reports this; hard-coding 0 was a passive tell.
    largest_recv_time: Option<Instant>,
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
    /// Absolute stream offset of `send[0]`: the fully-acked prefix is compacted
    /// away (see [`Connection::compact_send_buffer`]), so an absolute offset `o`
    /// indexes `send` at `o - send_base`.
    send_base: u64,
    /// Next absolute offset to packetize from `send`.
    send_off: u64,
    /// Peer's MAX_STREAM_DATA limit: we MUST NOT send past this absolute offset.
    send_max: u64,
    /// Lost `(offset, len, fin)` ranges to resend before fresh bytes.
    retransmit: Vec<(u64, u64, bool)>,
    /// Start offsets of this stream's STREAM ranges currently tracked in the DATA
    /// space's `sent_content` (in flight, awaiting ACK), as a multiset
    /// `offset -> count`. Kept in lockstep with `sent_content` by
    /// [`Connection::index_sent_stream_ranges`] (packet recorded) /
    /// [`Connection::unindex_sent_stream_ranges`] (packet acked, declared lost, or
    /// consumed by a PTO probe), so [`Connection::compact_send_buffer`] reads the
    /// lowest live offset in O(log n) via `first_key_value` instead of rescanning
    /// every in-flight packet's ranges per acked stream — under a large cwnd
    /// (thousands of in-flight packets) across ~128 streams that rescan cost
    /// ~1e6 range visits per ACK. STREAM frames only ever ride 0-RTT/1-RTT
    /// packets (both the DATA packet-number space here), so `discard_space` on
    /// Initial/Handshake never bypasses the unindex step.
    sent_range_offsets: BTreeMap<u64, usize>,
    /// The app has requested FIN after all buffered bytes.
    fin: bool,
    /// The FIN bit has been packetized at the final offset.
    fin_sent: bool,
    fin_acked: bool,
    /// The app requested RESET_STREAM with this error code; stop sending data.
    reset: Option<u64>,
    /// The RESET_STREAM frame has been packetized.
    reset_sent: bool,
    reset_acked: bool,
    /// The stream is cancelled in both directions: STOP_SENDING (same code) rides
    /// in the RESET_STREAM packet. See [`Connection::cancel_stream`].
    stop_sending: bool,
    /// Streams whose data was queued (unsent) when this stream was cancelled. The
    /// cancellation waits until they are sent, so it never overtakes them.
    cancel_after: Vec<u64>,
    // Receive half (bytes this endpoint receives on the stream).
    recv: Vec<u8>,
    recv_off: u64,
    recv_pending: Vec<(u64, Vec<u8>)>,
    /// Highest offset+len received (flow-control credit the peer has consumed).
    recv_high: u64,
    /// Bytes the app has read (drives the receive-window extension).
    recv_consumed: u64,
    /// Bytes of this stream already released to the CONNECTION window
    /// (`recv_data_consumed`). Normally equal to `recv_consumed`, but a reset or an
    /// abandoned receive half also releases bytes the app will never read, so the
    /// two diverge. Tracked explicitly so every release site can credit exactly
    /// `target - recv_credited` and the invariant `recv_credited <= recv_high`
    /// — hence `recv_data_consumed <= recv_data_total` — holds by construction.
    recv_credited: u64,
    /// Our advertised MAX_STREAM_DATA limit, and the last value we sent.
    recv_max: u64,
    recv_max_sent: u64,
    /// A grown receive window owes the peer a MAX_STREAM_DATA update.
    need_max_stream_data: bool,
    /// Final size once a FIN has been received (RFC 9000 §4.5).
    recv_fin: Option<u64>,
    /// A peer RESET_STREAM error code, if the receive half was reset.
    recv_reset: Option<u64>,
    /// The application consumed the final bytes or dropped its receive half.
    recv_released: bool,
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

/// Cap on bytes a stream's send half may hold buffered (unsent + in flight +
/// awaiting compaction). The async write path stops accepting bytes once the
/// backlog reaches this (see [`Connection::stream_send_capacity`]) and resumes as
/// ACKs reclaim the buffer — without it an application writing faster than the
/// peer acknowledges would grow `Stream::send` without bound (memory-DoS,
/// finding #28). Sized to the per-stream receive window so a well-behaved peer
/// can keep a full window in flight.
pub(super) const STREAM_SEND_BUFFER: usize = 2 * 1024 * 1024;

/// Initial connection-level receive window we advertise (MAX_DATA); extended as
/// the app reads across all streams. Matches the Safari `initial_max_data` value.
const CONN_RECV_WINDOW: u64 = 16 * 1024 * 1024;

/// Cap on concurrent peer-initiated streams of each kind (a memory-exhaustion DoS
/// guard). Initial transport parameters retain the Safari profile; MAX_STREAMS
/// expands to this budget once 1-RTT keys are available and replenishes on retire.
const MAX_PEER_STREAMS: usize = 64;

/// Stream-id bit 1 (RFC 9000 §2.1): set for unidirectional streams.
fn is_uni(id: u64) -> bool {
    id & 0x2 != 0
}

/// Reassemble an in-order fragment and any buffered fragments it makes
/// contiguous, appending the recovered bytes to `sink` and advancing
/// `recv_off`. Shared by CRYPTO ([`Connection::recv_crypto`]) and STREAM
/// ([`Connection::recv_stream`]) reassembly, which differ only in their
/// `pending`/`recv_off`/`sink` storage.
///
/// Preconditions: `offset <= *recv_off` (the caller has already routed strictly
/// future fragments into `pending`). The function:
///   1. appends the non-duplicate tail of `(offset, data)`,
///   2. drains every buffered fragment that now straddles `recv_off`, then
///   3. evicts buffered fragments that fell fully below `recv_off` so they stop
///      counting against the reassembly budget (see the inline notes that this
///      replaced — a fragment an overlapping fill jumped entirely past matches
///      no removal path and would otherwise linger forever).
///
/// Returns the number of buffered bytes removed from `pending` (drained or
/// evicted), so the STREAM caller can settle the connection-wide reassembly
/// budget ([`MAX_CONN_REASSEMBLY`]); the CRYPTO caller has no aggregate budget
/// and ignores it.
fn drain_contiguous(
    pending: &mut Vec<(u64, Vec<u8>)>,
    recv_off: &mut u64,
    offset: u64,
    data: &[u8],
    sink: &mut Vec<u8>,
) -> usize {
    let mut freed = 0;
    let skip = (*recv_off - offset) as usize;
    if skip < data.len() {
        sink.extend_from_slice(&data[skip..]);
        *recv_off += (data.len() - skip) as u64;
    }
    while let Some(i) = pending
        .iter()
        .position(|(o, d)| *o <= *recv_off && *o + d.len() as u64 > *recv_off)
    {
        let (o, d) = pending.remove(i);
        let s = (*recv_off - o) as usize;
        sink.extend_from_slice(&d[s..]);
        *recv_off += (d.len() - s) as u64;
        freed += d.len();
    }
    pending.retain(|(o, d)| {
        let keep = *o + d.len() as u64 > *recv_off;
        if !keep {
            freed += d.len();
        }
        keep
    });
    freed
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
    /// Packet pacer: spreads ack-eliciting DATA packets at the controller's target
    /// rate instead of bursting a full window. Additive — only delays packets the
    /// cwnd already allows; bypassed before a model exists / below the min rate /
    /// while burst tokens remain.
    pacer: Pacer,
    /// Path MTU discovery (DPLPMTUD, RFC 8899). Drives the datagram size bulk DATA is
    /// built to: starts at the validated baseline and probes upward. `mtu_probe_pn`
    /// is the packet number of the in-flight probe (if any), so its ACK/loss routes
    /// to [`Pmtud`] — a probe loss validates a too-big size, NOT congestion (§14.4).
    pmtud: Pmtud,
    mtu_probe_pn: Option<u64>,
    /// The largest CE count the peer has reported in an ACK_ECN for the Application
    /// space (RFC 9000 §13.4.2). A reported increase means the path marked Congestion
    /// Experienced on our egress; the delta drives one congestion event. Monotonic per
    /// the RFC, so only growth is acted on.
    peer_ecn_ce: u64,
    /// Connection-wide cumulative delivered (acknowledged) bytes — the BBR /
    /// delivery-rate "delivered" counter (draft-cheng-iccrg-delivery-rate-est).
    delivered: u64,
    /// PTO exponential-backoff exponent, reset to 0 whenever an ACK is received.
    pto_count: u32,
    /// Number of probe packets allowed to bypass the congestion window (RFC 9002
    /// §6.2.4): a PTO sets this so a retransmit goes out even when cwnd is full.
    probe_pending: u8,
    /// Count of 1-RTT packets sealed with the current sending key (RFC 9001 §6.6).
    data_packets_sealed: u64,
    zero_rtt_packets_sealed: u64,
    key_phase: KeyPhaseState,
    next_packet_keys: Option<NextPacketKeys>,
    previous_read_key: Option<PreviousReadKey>,
    /// Respect the recommended three-PTO interval after confirming a key update.
    next_update_at: Option<Instant>,
    #[cfg(test)]
    key_update_soft_limit: Option<u64>,
    #[cfg(test)]
    sealed_packets: Vec<(Side, u64, u64)>,
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
    /// The current handshake's authenticated peer ACK parameters, never ticket state.
    peer_ack_delay_exponent: u32,
    peer_max_ack_delay: Duration,
    peer_ack_params_applied: bool,
    /// Current complete CH/EE parameters passed syntax/range validation. This
    /// never substitutes for the authenticated reparse or activates ACK policy.
    peer_transport_params_prevalidated: bool,
    /// A client saw a Handshake packet while it still owed an Initial ACK: it
    /// discards the Initial space right after sending that ACK instead of at once.
    discard_initial_after_ack: bool,
    /// The peer's address is validated (RFC 9000 §8.1). A client trusts the server
    /// address it dialed, so it starts `true`; a server starts `false` and flips
    /// when a packet from the peer opens under Handshake keys — proof the peer
    /// received our Initial flight at its claimed (unspoofable) address. While
    /// `false`, egress is capped at 3x `anti_amp_recv` in `poll_transmit`.
    peer_addr_validated: bool,
    /// Bytes received in datagrams from the peer while its address was unvalidated.
    /// Every datagram byte attributed to the connection counts, even bytes that
    /// fail to decrypt (RFC 9000 §8.1) — garbage still "pays" 1:3 for what it can
    /// reflect, which is exactly the amplification bound the limit accepts.
    anti_amp_recv: u64,
    /// Bytes sent to the peer while its address was unvalidated.
    anti_amp_sent: u64,
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
    /// Cumulative opened/allowed peer streams, indexed by bidi=0, uni=1. Opening
    /// an id implicitly opens all lower ids of its kind; missing ids below this
    /// frontier have retired and must never be recreated by late frames.
    peer_streams_opened: [u64; 2],
    recv_max_streams: [u64; 2],
    recv_max_streams_sent: [u64; 2],
    need_max_streams: [bool; 2],
    /// Cumulative stream credit granted by the peer, including MAX_STREAMS.
    send_max_streams: [u64; 2],
    /// Peer-initiated streams newly observed, awaiting `accept_bi` / `accept_uni`.
    accept_bidi: VecDeque<u64>,
    accept_uni: VecDeque<u64>,
    /// Why the connection closed, if it has (local close, peer close, or idle).
    closed: Option<CloseReason>,
    /// A pending CONNECTION_CLOSE `(error_code, transport frame type, reason)`.
    /// `None` for the frame type denotes an application close.
    close_pending: Option<(u64, Option<u64>, Vec<u8>)>,
    /// The CONNECTION_CLOSE has been put on the wire.
    close_sent: bool,
    /// When the connection entered the closing/draining state (RFC 9000 §10.2),
    /// for the 3×PTO drain countdown after which it can be reaped.
    close_time: Option<Instant>,
    /// The drain period has elapsed; the endpoint may remove this connection.
    drained: bool,
    /// When a packet was last received (drives the idle timeout, RFC 9000 §10.1).
    last_recv_time: Option<Instant>,
    /// When this connection was constructed: the cold-start backstop origin for the
    /// idle deadline while `last_recv_time` is still `None` (no packet has ever
    /// AEAD-opened). Without it such a connection arms NO idle timer at all — a
    /// server-side connection created for a spoofed/undecryptable Initial would
    /// return `next_timeout() == None` and sit in the endpoint's table forever
    /// (table-exhaustion DoS), and a client whose peer never replies would
    /// retransmit Initials indefinitely. `next_timeout` and `handle_timeout` both
    /// read `last_recv_time.unwrap_or(created_at)`, so the armed deadline and the
    /// fire condition never disagree.
    created_at: Instant,
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
    /// Out-of-order STREAM bytes currently buffered across all streams'
    /// `recv_pending` (bounded by [`MAX_CONN_REASSEMBLY`]): incremented on push,
    /// decremented as `drain_contiguous` drains/evicts fragments.
    recv_pending_total: usize,
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

    /// Construct a `Connection` with every role-independent field at its initial
    /// value. The client and server constructors supply only the fields that
    /// genuinely differ (`side`, the CIDs, the boxed TLS session, and the
    /// initial stream-id counters), so a newly added field is initialized in one
    /// place instead of two struct literals that could silently drift apart.
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        side: Side,
        tls: Box<dyn TlsSession>,
        initial_dcid: ConnectionId,
        dcid: ConnectionId,
        scid: ConnectionId,
        next_bidi: u64,
        next_uni: u64,
    ) -> Self {
        Self {
            side,
            version: QUIC_VERSION_V1,
            initial_dcid,
            dcid,
            scid,
            peer_cid_adopted: false,
            tls,
            spaces: [Space::default(), Space::default(), Space::default()],
            rtt: RttEstimator::new(),
            cc: Box::new(Bbr::new()),
            pacer: Pacer::new(),
            pmtud: Pmtud::new(),
            mtu_probe_pn: None,
            peer_ecn_ce: 0,
            delivered: 0,
            pto_count: 0,
            probe_pending: 0,
            data_packets_sealed: 0,
            zero_rtt_packets_sealed: 0,
            key_phase: KeyPhaseState::default(),
            next_packet_keys: None,
            previous_read_key: None,
            next_update_at: None,
            #[cfg(test)]
            key_update_soft_limit: None,
            #[cfg(test)]
            sealed_packets: Vec::new(),
            data_packets_open_failed: 0,
            handshake_done_pending: false,
            handshake_confirmed: false,
            peer_ack_delay_exponent: ACK_DELAY_EXPONENT,
            peer_max_ack_delay: MAX_ACK_DELAY,
            peer_ack_params_applied: false,
            peer_transport_params_prevalidated: false,
            discard_initial_after_ack: false,
            peer_addr_validated: side == Side::Client,
            anti_amp_recv: 0,
            anti_amp_sent: 0,
            last_send_time: None,
            keepalive_interval: random_keep_alive_interval(),
            ping_pending: false,
            write_level: SPACE_INITIAL,
            zero_rtt_keys: None,
            streams: BTreeMap::new(),
            next_bidi,
            next_uni,
            peer_streams_opened: [0; 2],
            recv_max_streams: [MAX_PEER_STREAMS as u64; 2],
            recv_max_streams_sent: [0; 2],
            need_max_streams: [true; 2],
            send_max_streams: [0; 2],
            accept_bidi: VecDeque::new(),
            accept_uni: VecDeque::new(),
            closed: None,
            close_pending: None,
            close_sent: false,
            close_time: None,
            drained: false,
            last_recv_time: None,
            created_at: Instant::now(),
            send_max_data: 0,
            send_data_total: 0,
            recv_max_data: CONN_RECV_WINDOW,
            recv_max_data_sent: CONN_RECV_WINDOW,
            recv_data_total: 0,
            recv_data_consumed: 0,
            recv_pending_total: 0,
            need_max_data: false,
            peer_flow_applied: false,
            peer_msd_bidi_local: 0,
            peer_msd_bidi_remote: 0,
            peer_msd_uni: 0,
        }
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
                dcid.as_slice(),
                t,
                now_ms,
            )?,
            None => ClientHandshake::new(
                config,
                QUIC_VERSION_V1,
                server_name,
                tp_blob,
                dcid.as_slice(),
            )?,
        };
        // Client-initiated stream ids: bidi 0,4,8,…; uni 2,6,10,… (RFC 9000 §2.1).
        let mut conn = Self::new_inner(Side::Client, Box::new(tls), dcid, dcid, scid, 0, 2);
        conn.recv_max_streams_sent = [tp.initial_max_streams_bidi, tp.initial_max_streams_uni];
        conn.spaces[SPACE_INITIAL].keys = Some(initial_keys(dcid.as_slice(), Side::Client));
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
        cert_chain: Arc<Vec<Vec<u8>>>,
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
        cert_chain: Arc<Vec<Vec<u8>>>,
        signing_key_pkcs8: &[u8],
        alpn_protocols: Vec<Vec<u8>>,
        transport_params: Vec<u8>,
        scid: ConnectionId,
        stek: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Self, QuicTlsError> {
        let limits = TransportParameters::read(&transport_params)
            .map(|tp| [tp.initial_max_streams_bidi, tp.initial_max_streams_uni])
            .unwrap_or([0; 2]);
        let tls = ServerHandshake::new(
            cert_chain,
            signing_key_pkcs8,
            alpn_protocols,
            transport_params,
            stek,
        )?;
        // Server-initiated stream ids: bidi 1,5,9,…; uni 3,7,11,… (RFC 9000 §2.1).
        // The initial/dcid CIDs are learned from the first Initial datagram.
        let mut conn = Self::new_inner(
            Side::Server,
            Box::new(tls),
            ConnectionId::new(&[]),
            ConnectionId::new(&[]),
            scid,
            1,
            3,
        );
        conn.recv_max_streams_sent = limits;
        Ok(conn)
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
        bound_dcid: Vec<u8>,
        authorized_sni: Vec<String>,
    ) {
        self.tls
            .set_marker_key(psk, static_priv, bound_dcid, authorized_sni);
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
        self.close_pending = Some((error_code, None, reason.to_vec()));
        self.clear_ack_schedules();
    }

    /// Close with a transport error, preserving its code and triggering frame.
    pub fn close_transport(&mut self, error_code: u64, frame_type: u64, reason: &[u8]) {
        if self.closed.is_some() {
            return;
        }
        self.closed = Some(CloseReason::LocalTransport(
            error_code,
            frame_type,
            reason.to_vec(),
        ));
        self.close_pending = Some((error_code, Some(frame_type), reason.to_vec()));
        self.clear_ack_schedules();
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

    /// The current congestion window in bytes (test inspection only): lets a test
    /// assert the in-flight burst is bounded by the live window rather than a fixed
    /// constant, since MTU discovery + BBR can grow both the window and the per-packet
    /// size during the handshake exchange.
    #[cfg(test)]
    pub(crate) fn cc_window(&self) -> u64 {
        self.cc.window()
    }

    /// The validated path MTU (test inspection only).
    #[cfg(test)]
    pub(crate) fn current_mtu(&self) -> usize {
        self.pmtud.current_mtu()
    }

    /// The largest CE count the peer has reported (test inspection only).
    #[cfg(test)]
    pub(crate) fn peer_ecn_ce(&self) -> u64 {
        self.peer_ecn_ce
    }

    /// The received CE count tallied in the Application space (test inspection only).
    #[cfg(test)]
    pub(crate) fn data_recv_ce(&self) -> u64 {
        self.spaces[SPACE_DATA].recv_ecn.ce
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

    /// Open a new outgoing bidirectional stream, returning its id (RFC 9000 §2.1).
    /// The relay's first call returns the data stream ([`RELAY_STREAM_ID`]).
    pub fn open_bi(&mut self) -> u64 {
        let id = self.next_bidi;
        self.create_local_stream(id);
        id
    }

    /// Open a new outgoing unidirectional stream (HTTP/3 control / QPACK).
    pub fn open_uni(&mut self) -> u64 {
        let id = self.next_uni;
        self.create_local_stream(id);
        id
    }

    /// Insert a locally-opened stream with its initial windows + peer send limit.
    fn create_local_stream(&mut self, id: u64) {
        if self.stream_retired(id) {
            return;
        }
        self.ensure_peer_flow();
        let send_max = self.peer_send_limit(id);
        let s = self.streams.entry(id).or_insert_with(Stream::fresh);
        s.send_max = s.send_max.max(send_max);
        if !self.is_peer_initiated(id) {
            let next = if is_uni(id) {
                &mut self.next_uni
            } else {
                &mut self.next_bidi
            };
            *next = (*next).max(id + 4);
        }
    }

    /// Take the id of the next peer-initiated bidirectional stream, if any. A stream
    /// the peer reset before sending a byte (a cancelled HTTP/3 request stream,
    /// which Safari opens and cancels ahead of its real request) carries nothing to
    /// serve, so it is skipped rather than handed to the application.
    pub fn accept_bi(&mut self) -> Option<u64> {
        while let Some(id) = self.accept_bidi.pop_front() {
            let cancelled_empty = self
                .streams
                .get(&id)
                .is_some_and(|s| s.recv_reset.is_some() && s.recv_high == 0);
            if !cancelled_empty {
                return Some(id);
            }
            self.discard_stream_recv(id);
        }
        None
    }

    /// Take the id of the next peer-initiated unidirectional stream, if any.
    pub fn accept_uni(&mut self) -> Option<u64> {
        self.accept_uni.pop_front()
    }

    /// Queue application bytes on stream `id`; they are packetized into 1-RTT STREAM
    /// frames once the handshake installs Data keys. Creates the stream if absent.
    pub fn send_stream(&mut self, id: u64, data: &[u8]) {
        self.create_local_stream(id);
        if let Some(s) = self.streams.get_mut(&id) {
            if !s.fin && s.reset.is_none() {
                s.send.extend_from_slice(data);
            }
        }
    }

    /// Remaining bytes stream `id` may buffer for sending before hitting the
    /// per-stream backlog cap (see [`STREAM_SEND_BUFFER`]). The async write path
    /// uses this for backpressure: at 0 it parks the writer until ACK progress
    /// reclaims buffer space, instead of buffering without bound (finding #28).
    pub fn stream_send_capacity(&self, id: u64) -> usize {
        let buffered = self.streams.get(&id).map_or(0, |s| s.send.len());
        STREAM_SEND_BUFFER.saturating_sub(buffered)
    }

    pub fn stream_send_finished(&self, id: u64) -> bool {
        self.stream_retired(id)
            || self
                .streams
                .get(&id)
                .is_some_and(|s| s.fin || s.reset.is_some())
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
                s.retransmit.clear();
            }
        }
    }

    /// Cancel stream `id` in both directions with `error_code`: one packet carries
    /// STOP_SENDING then RESET_STREAM (RFC 9000 §19.5 / §19.4), as Safari cancels an
    /// HTTP/3 request stream it opened but never used. The cancellation is sent
    /// only after every byte already queued on other streams (Safari: the H3
    /// control SETTINGS goes out first), since RESET_STREAM otherwise outranks
    /// stream data in [`Self::poll_transmit`].
    pub fn cancel_stream(&mut self, id: u64, error_code: u64) {
        self.reset_stream(id, error_code);
        let cancel_after: Vec<u64> = self
            .streams
            .keys()
            .copied()
            .filter(|&other| other != id && self.has_unsent_data(other))
            .collect();
        if let Some(s) = self.streams.get_mut(&id) {
            if !s.stop_sending {
                s.stop_sending = true;
                // A RESET_STREAM already packetized carried no STOP_SENDING: send
                // the combined pair again.
                s.reset_sent = false;
                s.reset_acked = false;
                s.cancel_after = cancel_after;
            }
        }
        self.discard_stream_recv(id);
    }

    /// Stream `id` has fresh bytes buffered that are not yet packetized.
    fn has_unsent_data(&self, id: u64) -> bool {
        self.streams
            .get(&id)
            .is_some_and(|s| s.reset.is_none() && s.send_off < s.send_base + s.send.len() as u64)
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
        s.recv_credited += n;
        s.recv_max = s.recv_consumed + STREAM_RECV_WINDOW;
        // Advertise a bigger window once half of it has been consumed since the
        // last MAX_STREAM_DATA (avoids a frame per read).
        if s.recv_max - s.recv_max_sent >= STREAM_RECV_WINDOW / 2 {
            s.need_max_stream_data = true;
        }
        if s.recv_reset.is_none() && s.recv_fin.is_some_and(|fin| s.recv_off >= fin) {
            s.recv_released = true;
        }
        self.credit_connection_window(n);
        self.retire_stream(id);
        data
    }

    /// Whether stream `id`'s receive half has delivered all bytes through a FIN
    /// (a clean end-of-stream, RFC 9000 §4.5).
    pub fn stream_recv_finished(&self, id: u64) -> bool {
        self.stream_retired(id)
            || self
                .streams
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

    /// Missing streams below their opened frontier are terminal, not new. This
    /// constant-size history prevents retransmitted frames resurrecting them.
    fn stream_retired(&self, id: u64) -> bool {
        if self.streams.contains_key(&id) {
            return false;
        }
        if self.is_peer_initiated(id) {
            id / 4 < self.peer_streams_opened[usize::from(is_uni(id))]
        } else {
            id < if is_uni(id) {
                self.next_uni
            } else {
                self.next_bidi
            }
        }
    }

    fn stream_can_send(&self, id: u64) -> bool {
        if self.is_peer_initiated(id) {
            !is_uni(id)
        } else {
            id / 4 < self.send_max_streams[usize::from(is_uni(id))]
        }
    }

    /// Release terminal state after send data/FIN or RESET is acknowledged and
    /// the application consumed or abandoned the receive half. No per-retired-
    /// stream tombstones are needed (RFC 9000 §4.5).
    fn retire_stream(&mut self, id: u64) {
        let peer = self.is_peer_initiated(id);
        let Some(s) = self.streams.get(&id) else {
            return;
        };
        let send_done = (is_uni(id) && peer) || s.reset_acked || s.fin_acked;
        let recv_done = (is_uni(id) && !peer)
            || (s.recv_released
                && s.recv_fin
                    .is_some_and(|fin| s.recv_reset.is_some() || s.recv_off >= fin));
        if !send_done || !recv_done || !s.sent_range_offsets.is_empty() || !s.retransmit.is_empty()
        {
            return;
        }
        self.streams.remove(&id);
        self.accept_bidi.retain(|&queued| queued != id);
        self.accept_uni.retain(|&queued| queued != id);
        if peer {
            let kind = usize::from(is_uni(id));
            self.recv_max_streams[kind] = (self.recv_max_streams[kind] + 1).min(1 << 60);
            self.need_max_streams[kind] = true;
        }
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
        self.send_max_streams = [tp.initial_max_streams_bidi, tp.initial_max_streams_uni];
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
        self.send_max_streams[0] = self.send_max_streams[0].max(tp.initial_max_streams_bidi);
        self.send_max_streams[1] = self.send_max_streams[1].max(tp.initial_max_streams_uni);
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

    /// Reject malformed complete CH/EE parameters before the next coalesced
    /// packet can publish early data. Missing input is not cached as validated;
    /// ACK policy remains at its defaults until the authenticated reparse below.
    fn prevalidate_peer_transport_params(&mut self) -> Result<(), QuicTlsError> {
        if self.peer_transport_params_prevalidated {
            return Ok(());
        }
        let Some(blob) = self.tls.peer_transport_parameters() else {
            return Ok(());
        };
        if let Err(error) = TransportParameters::read(blob) {
            // The endpoint may ignore a handshaking error. Make rejection
            // terminal before returning so later datagrams cannot publish data.
            self.close_transport(0x08, 0x06, b"invalid peer transport parameters");
            return Err(transport_error(
                0x08,
                0x06,
                format!("invalid peer transport parameters: {error:?}"),
            ));
        }
        self.peer_transport_params_prevalidated = true;
        Ok(())
    }

    /// ACK recovery settings come only from this completed, authenticated TLS
    /// handshake. Raw CH/EE parameters and remembered 0-RTT flow limits do not
    /// establish this boundary. Parse before committing any peer ACK state.
    fn apply_authenticated_peer_ack_params(&mut self) -> Result<(), QuicTlsError> {
        if self.peer_ack_params_applied || self.tls.is_handshaking() {
            return Ok(());
        }
        let blob = self.tls.peer_transport_parameters().ok_or_else(|| {
            QuicTlsError::alert(
                crate::tls::quic::ALERT_MISSING_EXTENSION,
                "missing authenticated peer transport parameters",
            )
        })?;
        let tp = TransportParameters::read(blob).map_err(|error| {
            transport_error(
                0x08,
                0x06,
                format!("invalid peer transport parameters: {error:?}"),
            )
        })?;
        self.peer_ack_delay_exponent = tp.ack_delay_exponent;
        self.peer_max_ack_delay = Duration::from_millis(tp.max_ack_delay_ms);
        self.peer_ack_params_applied = true;
        Ok(())
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
                    if self.side == Side::Client {
                        self.zero_rtt_keys = None;
                    }
                    if self.cache_next_packet_keys().is_err() {
                        self.retire_data_connection(b"key update derivation failed");
                        return;
                    }
                }
                None => {
                    if buf.is_empty() {
                        break;
                    }
                }
            }
        }
    }

    fn retire_data_connection(&mut self, reason: &[u8]) {
        if self.closed.is_none() {
            self.closed = Some(CloseReason::LocalApp(0, reason.to_vec()));
        }
        self.close_pending = None;
        self.clear_ack_schedules();
    }

    fn cache_next_packet_keys(&mut self) -> Result<(), QuicTlsError> {
        if self
            .next_packet_keys
            .as_ref()
            .is_some_and(|keys| keys.local.is_some() || keys.remote.is_some())
        {
            return Ok(());
        }
        let generation = self
            .key_phase
            .tx
            .max(self.key_phase.rx)
            .checked_add(1)
            .ok_or_else(|| QuicTlsError::Crypto("key generation exhausted".into()))?;
        let KeyPair { local, remote } = self.tls.next_1rtt_keys()?;
        self.next_packet_keys = Some(NextPacketKeys {
            generation,
            local: Some(local),
            remote: Some(remote),
        });
        Ok(())
    }

    fn install_send_key(&mut self, generation: u64) -> Result<(), QuicTlsError> {
        let next = self
            .next_packet_keys
            .as_mut()
            .filter(|next| next.generation == generation)
            .ok_or_else(|| QuicTlsError::Crypto("missing next sending generation".into()))?;
        let key = next
            .local
            .take()
            .ok_or_else(|| QuicTlsError::Crypto("sending generation already consumed".into()))?;
        self.spaces[SPACE_DATA].keys.as_mut().unwrap().local.packet = key;
        self.key_phase.tx = generation;
        self.key_phase.tx_first = None;
        self.key_phase.tx_last = None;
        self.key_phase.tx_acked = false;
        self.data_packets_sealed = 0;
        self.next_update_at = None;
        Ok(())
    }

    fn initiate_key_update(&mut self, now: Instant) -> Result<bool, QuicTlsError> {
        if self.closed.is_some() || self.next_update_at.is_some_and(|at| now < at) {
            return Ok(false);
        }
        let Some(generation) = self.key_phase.active_successor(self.handshake_confirmed) else {
            return Ok(false);
        };
        self.install_send_key(generation)?;
        Ok(true)
    }

    fn maybe_update_send_key(&mut self, now: Instant) {
        let Some(keys) = self.spaces[SPACE_DATA].keys.as_ref() else {
            return;
        };
        // Leave half the confidentiality budget for loss, ACKs, and the three-PTO
        // update interval. A peer that never confirms still hits the hard stop.
        let soft_limit = keys.local.packet.confidentiality_limit() / 2;
        #[cfg(test)]
        let soft_limit = self.key_update_soft_limit.unwrap_or(soft_limit);
        if self.data_packets_sealed < keys.local.packet.confidentiality_limit()
            && self.data_packets_sealed >= soft_limit
            && self.initiate_key_update(now).is_err()
        {
            self.retire_data_connection(b"key update derivation failed");
        }
    }

    fn retire_previous_read_key(&mut self, now: Instant) {
        if self
            .previous_read_key
            .as_ref()
            .is_some_and(|previous| now >= previous.retire_at)
        {
            self.previous_read_key = None;
        }
    }

    /// The fixed HP key is applied once, followed by exactly one selected AEAD
    /// attempt. Missing/retired candidates use the current key as a dummy; they
    /// are never admitted, even if that attempt happens to authenticate.
    fn open_data_packet(
        &self,
        pkt: &mut [u8],
        local_cid_len: usize,
        largest: Option<u64>,
        now: Instant,
    ) -> Result<(Header, std::ops::Range<usize>, ReadGeneration), OpenError> {
        let keys = self.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .ok_or(OpenError::Crypto)?;
        let opened = unprotect_packet_header(&keys.remote.header, pkt, local_cid_len, largest)?;
        let Header::Short { key_phase, .. } = &opened.header else {
            return Err(OpenError::Malformed);
        };
        let mut generation = self
            .key_phase
            .select(*key_phase, opened.header.packet_number());
        let selected = match generation {
            ReadGeneration::Current => Some(&keys.remote.packet),
            ReadGeneration::Previous => self
                .previous_read_key
                .as_ref()
                .filter(|previous| now < previous.retire_at)
                .map(|previous| &previous.key),
            ReadGeneration::Next => self
                .next_packet_keys
                .as_ref()
                .filter(|next| self.key_phase.rx.checked_add(1) == Some(next.generation))
                .and_then(|next| next.remote.as_ref()),
            ReadGeneration::Unavailable => None,
        };
        if selected.is_none() {
            generation = ReadGeneration::Unavailable;
        }
        let range = open_packet_payload(selected.unwrap_or(&keys.remote.packet), pkt, &opened)?;
        Ok((opened.header, range, generation))
    }

    fn commit_data_generation(
        &mut self,
        generation: ReadGeneration,
        pn: u64,
        now: Instant,
    ) -> Result<(), QuicTlsError> {
        assert!(self.key_phase.commit_receive(generation, pn, true, true));
        if generation == ReadGeneration::Next {
            let next = self.next_packet_keys.as_mut().unwrap();
            let read_key = next.remote.take().expect("authenticated cached next key");
            let keys = self.spaces[SPACE_DATA].keys.as_mut().unwrap();
            let old_key = std::mem::replace(&mut keys.remote.packet, read_key);
            self.previous_read_key = Some(PreviousReadKey {
                key: old_key,
                retire_at: now + self.drain_duration(),
            });
            // A locally initiated update already consumed this same local half.
            // Otherwise respond before any ACK can acknowledge the new phase.
            if self.key_phase.tx < self.key_phase.rx {
                if let Err(error) = self.install_send_key(self.key_phase.rx) {
                    self.retire_data_connection(b"key update installation failed");
                    return Err(error);
                }
            }
            if let Err(error) = self.cache_next_packet_keys() {
                self.retire_data_connection(b"key update derivation failed");
                return Err(error);
            }
        }
        Ok(())
    }

    /// Discard a packet-number space's keys and all associated state (RFC 9001 §4.9,
    /// RFC 9002 §6.4): the packets it held leave bytes_in_flight and its loss/PTO
    /// timers and ACK/CRYPTO buffers are cleared. Used at the Initial→Handshake and
    /// Handshake→1-RTT transitions so stale handshake packets cannot throttle the
    /// 1-RTT congestion window or trigger probes in a keyspace the peer can no longer
    /// decrypt — and so the public Initial keys stop AEAD-opening forged packets once
    /// the handshake has moved on.
    fn discard_space(&mut self, space: usize) {
        self.spaces[space] = Space {
            discarded: true,
            ..Space::default()
        };
    }

    fn clear_ack_schedules(&mut self) {
        for space in &mut self.spaces {
            space.ack_pending = false;
            space.ack_eliciting_count = 0;
            space.ack_deadline = None;
        }
    }

    fn schedule_ack(&mut self, space: usize, ack_eliciting: bool, immediate: bool, now: Instant) {
        if self.closed.is_some() {
            self.clear_ack_schedules();
            return;
        }
        if !ack_eliciting {
            return;
        }
        let sp = &mut self.spaces[space];
        sp.ack_pending = true;
        sp.ack_eliciting_count =
            ack_count_after_packet(sp.ack_eliciting_count, ack_eliciting, immediate);
        let deadline = if sp.ack_eliciting_count >= 2 {
            now
        } else {
            now + MAX_ACK_DELAY
        };
        sp.ack_deadline = Some(sp.ack_deadline.map_or(deadline, |old| old.min(deadline)));
    }

    fn ack_ready_for_space(&self, space: usize, now: Instant) -> bool {
        let sp = &self.spaces[space];
        sp.ack_pending
            && (space != SPACE_DATA
                || !self.handshake_confirmed
                || ack_count_due(
                    sp.ack_eliciting_count,
                    sp.ack_deadline.is_some_and(|deadline| now >= deadline),
                ))
    }

    /// Only arm a new ACK timer where poll_transmit can actually send it. The
    /// Initial client's existing ServerHello/Initial-ACK exception is unchanged.
    fn pending_data_ack_deadline(&self) -> Option<Instant> {
        let sp = &self.spaces[SPACE_DATA];
        if self.closed.is_some()
            || !sp.ack_pending
            || sp.keys.is_none()
            || sp.discarded
            || (!self.peer_addr_validated
                && self.anti_amp_sent.saturating_add(MAX_DATAGRAM as u64)
                    > self.anti_amp_recv.saturating_mul(3))
        {
            return None;
        }
        sp.ack_deadline
    }

    /// Force a local close once the 1-RTT AEAD confidentiality limit is reached
    /// (RFC 9001 §6.6). If an update was not possible before the hard stop, no
    /// encrypted CONNECTION_CLOSE can be sent after the budget is spent. (A
    /// ChaCha20-Poly1305 key has an effectively unbounded limit, so this never
    /// fires for it; AES-GCM caps at 2^23 packets.)
    fn enforce_aead_confidentiality_limit(&mut self) {
        if self.spaces[SPACE_DATA].keys.is_none() {
            if let Some(keys) = &self.zero_rtt_keys {
                close_on_exhausted_data_key(
                    self.zero_rtt_packets_sealed,
                    keys.local.packet.confidentiality_limit(),
                    &mut self.closed,
                    &mut self.close_pending,
                );
            }
        }
        let limit = self.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .map(|k| k.local.packet.confidentiality_limit());
        if let Some(limit) = limit {
            close_on_exhausted_data_key(
                self.data_packets_sealed,
                limit,
                &mut self.closed,
                &mut self.close_pending,
            );
        }
    }

    /// Enforce the AEAD integrity limit (RFC 9001 §6.6): once the number of 1-RTT
    /// packets that failed to AEAD-open reaches the cipher's integrity limit, the
    /// connection's forgery-resistance margin is spent, across all generations.
    /// Retire without further encrypted output. The limit is unreachable in
    /// normal operation (2^36 for ChaCha20-Poly1305, 2^52 for AES-GCM).
    fn enforce_aead_integrity_limit(&mut self) {
        let limit = self.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .map(|k| k.remote.packet.integrity_limit());
        if let Some(limit) = limit {
            if self.data_packets_open_failed >= limit {
                self.retire_data_connection(b"AEAD integrity limit reached");
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
        let dg = self.poll_transmit_inner(now)?;
        // Anti-amplification accounting (RFC 9000 §8.1): every byte sent before the
        // peer's address is validated draws down the 3x budget enforced in
        // `poll_transmit_inner`.
        if !self.peer_addr_validated {
            self.anti_amp_sent = self.anti_amp_sent.saturating_add(dg.len() as u64);
        }
        Some(dg)
    }

    fn poll_transmit_inner(&mut self, now: Instant) -> Option<Vec<u8>> {
        // Rotate while budget remains; closing never rotates just to send close.
        if self.closed.is_none() {
            self.maybe_update_send_key(now);
        }
        self.enforce_aead_confidentiality_limit();
        self.enforce_aead_integrity_limit();
        if self
            .spaces
            .iter()
            .any(|space| !space.discarded && !space.send.can_allocate())
        {
            self.retire_data_connection(b"packet-number space exhausted");
        }
        // Once closed (locally, by the peer, or on idle) the connection enters the
        // closing/draining state (RFC 9000 §10.2): it sends at most a single
        // CONNECTION_CLOSE (for a local close) and is otherwise silent — no ACKs,
        // data, probes, or keep-alives. This also starts the drain countdown.
        if self.closed.is_some() {
            self.clear_ack_schedules();
            if self.close_time.is_none() {
                self.close_time = Some(now);
            }
            if self.close_pending.is_some() && !self.close_sent {
                if let Some(dg) = self.build_close_packet(now) {
                    return Some(dg);
                }
            }
            return None;
        }
        // Anti-amplification (RFC 9000 §8.1): until the peer's address is validated
        // (a packet from it opens under Handshake keys), everything sent to it —
        // ACKs and CRYPTO alike — is capped at 3x the bytes received from it, so a
        // spoofed client Initial cannot reflect the multi-KB server handshake
        // flight at a victim. Reserving a full MAX_DATAGRAM keeps the cap strict
        // without building a packet that then could not be sent (building mutates
        // send state); the single small close packet above stays within the same
        // reserve. This cannot deadlock a genuine handshake: every client datagram
        // grows the budget by 3x its size (client Initials alone are >=1200 bytes
        // each, and PTO makes the client resend them), the driver re-polls on every
        // receive, and the client's first Handshake-level packet lifts the cap.
        if !self.peer_addr_validated
            && self.anti_amp_sent.saturating_add(MAX_DATAGRAM as u64)
                > self.anti_amp_recv.saturating_mul(3)
        {
            return None;
        }
        // Pure ACKs first so acknowledgements are not held behind data, and are
        // never blocked by the congestion window (they are not ack-eliciting).
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            if self.spaces[space].keys.is_some() && self.ack_ready_for_space(space, now) {
                // A client holds its Initial ACK until the ServerHello is complete
                // (Handshake keys installed), so a ServerHello split across several
                // Initial datagrams draws ONE padded ACK, as Safari sends — not one
                // per datagram. A lost tail Initial is resent by the server's PTO.
                if space == SPACE_INITIAL
                    && self.side == Side::Client
                    && self.spaces[SPACE_HANDSHAKE].keys.is_none()
                {
                    continue;
                }
                let ack = self.build_ack_packet(space, now);
                if space == SPACE_INITIAL && self.discard_initial_after_ack {
                    self.discard_initial_after_ack = false;
                    self.discard_space(SPACE_INITIAL);
                }
                return Some(ack);
            }
        }
        // Ack-eliciting data is gated on the congestion window, except a PTO probe
        // which is allowed to exceed it to guarantee forward progress.
        let probing = self.probe_pending > 0;
        let congestion_ok =
            probing || self.bytes_in_flight() + self.pmtud.current_mtu() as u64 <= self.cc.window();
        // Packet pacing gate (PAR-23): spread bulk DATA-stream packets at the
        // controller's target rate. A PTO probe bypasses pacing (forward progress);
        // so do pure ACKs, handshake CRYPTO, HANDSHAKE_DONE, flow-control updates,
        // RESET_STREAM, and keep-alive PINGs below — only the 1-RTT/0-RTT *stream
        // data* sends consult `pacing_ok`. Bypassed entirely before a model exists,
        // below the min rate, and while burst tokens remain (see `Pacer`).
        let pacing_ok = probing || self.pacer.can_send(now);
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
            if pacing_ok && self.spaces[SPACE_DATA].keys.is_none() && self.zero_rtt_keys.is_some() {
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
            // drain whichever stream has bytes (or a pending FIN) to send. Paced.
            if pacing_ok && self.spaces[SPACE_DATA].keys.is_some() {
                if let Some(id) = self.next_stream_to_send() {
                    let dg = self.build_stream_packet(id, now);
                    self.probe_pending = self.probe_pending.saturating_sub(1);
                    return Some(dg);
                }
            }
            // A DPLPMTUD path-MTU probe (RFC 8899): after real data has drained, if the
            // handshake is confirmed and no probe is in flight, emit one inflated
            // PING+PADDING packet at the next candidate size. Low priority (real data
            // first) and at most one outstanding, so it never displaces the transfer;
            // its ACK/loss drives the MTU search. Gated on `handshake_confirmed` so a
            // probe never races the handshake, and on no in-flight probe via
            // `mtu_probe_pn`.
            if self.spaces[SPACE_DATA].keys.is_some()
                && self.handshake_confirmed
                && self.mtu_probe_pn.is_none()
            {
                if let Some(size) = self.pmtud.next_probe_size() {
                    let dg = self.build_mtu_probe_packet(size, now);
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
    /// is the peer's value and is added only for confirmed Application data;
    /// Initial/Handshake peers must ACK immediately.
    fn pto_duration(&self, space: usize) -> Duration {
        let extra =
            peer_ack_delay_for_pto(space, self.handshake_confirmed, self.peer_max_ack_delay);
        (self.rtt.pto_base() + extra) * 2u32.pow(self.pto_count.min(MAX_PTO_BACKOFF))
    }

    /// How long to remain in the closing/draining state before the connection is
    /// considered drained and reapable (RFC 9000 §10.2: at least 3×PTO).
    fn drain_duration(&self) -> Duration {
        3 * (self.rtt.pto_base()
            + peer_ack_delay_for_pto(
                SPACE_DATA,
                self.handshake_confirmed,
                self.peer_max_ack_delay,
            ))
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
            let drain = self.close_time.map(|t| t + self.drain_duration());
            return match (drain, &self.previous_read_key) {
                (Some(drain), Some(previous)) => Some(drain.min(previous.retire_at)),
                (None, Some(previous)) => Some(previous.retire_at),
                (deadline, _) => deadline,
            };
        }
        let mut deadline: Option<Instant> = None;
        let mut earliest = |t: Instant| deadline = Some(deadline.map_or(t, |d| d.min(t)));
        if let Some(previous) = &self.previous_read_key {
            earliest(previous.retire_at);
        }
        if let Some(ack) = self.pending_data_ack_deadline() {
            earliest(ack);
        }
        for sp in &self.spaces {
            if let Some(lt) = sp.loss_time {
                earliest(lt);
            }
        }
        // PTO per packet-number space (RFC 9002 §6.2.1 GetPtoTimeAndSpace): each
        // space's timer is armed from its own last ack-eliciting send; the earliest
        // across spaces is when handle_timeout must probe.
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            if !pto_space_eligible(space, self.handshake_confirmed) {
                continue;
            }
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
        // Pacing deadline (PAR-23): if a paced DATA packet is being held back by the
        // pacer, wake the driver at the release time so it is sent then — otherwise a
        // deferred packet would wait for an unrelated timer (added latency). Only arm
        // it when there is actually data to send and the cwnd would allow it, so an
        // idle connection is not woken.
        if let Some(t) = self.pacer.next_send_time() {
            let has_data = self.spaces[SPACE_DATA].keys.is_some()
                && self.bytes_in_flight() + self.pmtud.current_mtu() as u64 <= self.cc.window()
                && self.next_stream_to_send().is_some();
            if has_data {
                earliest(t);
            }
        }
        // Idle timeout (RFC 9000 §10.1): tear down after no receipt for too long.
        // Falls back to `created_at` while no packet has ever AEAD-opened, so a
        // connection that never receives an openable packet (spoofed Initial on
        // the server, silent peer on the client) still arms a teardown deadline
        // instead of living forever with no timer.
        if self.closed.is_none() {
            let last = self.last_recv_time.unwrap_or(self.created_at);
            earliest(last + IDLE_TIMEOUT);
        }
        deadline
    }

    /// Drive time-based loss detection and PTO (RFC 9002 §6.2). The async layer
    /// calls this when [`Self::next_timeout`] elapses; `poll_transmit` then sends
    /// any retransmits / probes that were queued.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.retire_previous_read_key(now);
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
        // Reads the SAME `last_recv_time.unwrap_or(created_at)` origin as
        // `next_timeout`, so the cold-start backstop deadline armed there also
        // fires here even when no packet ever AEAD-opened.
        if self.closed.is_none()
            && now >= self.last_recv_time.unwrap_or(self.created_at) + IDLE_TIMEOUT
        {
            self.closed = Some(CloseReason::IdleTimeout);
            self.clear_ack_schedules();
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
            // Route probe loss to the MTU search + exclude it from congestion, exactly
            // as the ACK-driven path does (shared helper).
            any_loss |= self.process_lost_packets(space, lost, now);
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
                    pto_space_eligible(space, self.handshake_confirmed)
                        && self.spaces[space].sent.in_flight() > 0
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
            if !pto_space_eligible(space, self.handshake_confirmed)
                || self.spaces[space].sent.in_flight() == 0
            {
                continue;
            }
            let oldest = self.spaces[space].sent_content.keys().next().copied();
            if let Some(pn) = oldest {
                let content = self.spaces[space].sent_content.remove(&pn).unwrap();
                if space == SPACE_DATA {
                    self.unindex_sent_stream_ranges(&content);
                }
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
                if s.reset.is_none() {
                    s.retransmit.push((offset, len, fin));
                }
            }
            self.retire_stream(id);
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
                if !s.reset_acked {
                    s.reset_sent = false;
                }
            }
        }
        for (kind, sent) in content.max_streams.into_iter().enumerate() {
            self.need_max_streams[kind] |= sent;
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
                key_phase: self.key_phase.tx & 1 != 0,
                dcid: self.dcid,
                packet_number: pn,
                pn_len,
            },
        }
    }

    fn allocate_packet_number(&mut self, space: usize) -> u64 {
        let (sealed, limit) = if space == SPACE_DATA {
            if let Some(keys) = &self.spaces[SPACE_DATA].keys {
                (
                    self.data_packets_sealed,
                    keys.local.packet.confidentiality_limit(),
                )
            } else if let Some(keys) = &self.zero_rtt_keys {
                (
                    self.zero_rtt_packets_sealed,
                    keys.local.packet.confidentiality_limit(),
                )
            } else {
                (0, 0)
            }
        } else {
            (0, u64::MAX)
        };
        self.spaces[space]
            .send
            .allocate_protected(sealed, limit)
            .expect("transmit dispatcher admitted key budget and PN")
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
        // Advance the pacer ONLY for DATA-space packets that actually carry STREAM
        // data — the bulk flow `poll_transmit` gates on `pacing_ok`. Control packets
        // (PING, HANDSHAKE_DONE, MAX_DATA/MAX_STREAM_DATA, RESET_STREAM) bypass the
        // pacing gate, so they must not consume burst tokens or arm the deadline here,
        // or they would wrongly delay subsequent stream data. `sent.on_sent` above
        // already folded this packet in, so subtract its size to recover
        // bytes-in-flight BEFORE it — zero there means we left quiescence (burst
        // refill). DATA space only keeps the handshake unthrottled.
        if ack_eliciting && space == SPACE_DATA && !content.stream.is_empty() {
            let in_flight_before = self.bytes_in_flight().saturating_sub(size as u64);
            let rate = self.cc.pacing_rate();
            self.pacer.on_sent(now, size, rate, in_flight_before);
        }
        if ack_eliciting {
            // Mirror the packet's STREAM ranges into the per-stream in-flight
            // offset index (only DATA-space packets carry STREAM frames).
            if space == SPACE_DATA {
                self.index_sent_stream_ranges(&content);
            }
            self.spaces[space].sent_content.insert(pn, content);
            self.spaces[space].last_ack_eliciting = Some(now);
        }
        if space == SPACE_DATA {
            if self.spaces[SPACE_DATA].keys.is_some() {
                self.data_packets_sealed = self.data_packets_sealed.saturating_add(1);
                self.key_phase.tx_first.get_or_insert(pn);
                self.key_phase.tx_last = Some(pn);
                #[cfg(test)]
                self.sealed_packets.push((self.side, self.key_phase.tx, pn));
            } else {
                self.zero_rtt_packets_sealed = self.zero_rtt_packets_sealed.saturating_add(1);
            }
        }
        self.last_send_time = Some(now);
    }

    /// Build a packet carrying only an ACK frame for `space` (non-ack-eliciting),
    /// clearing the space's pending-ACK flag.
    fn build_ack_packet(&mut self, space: usize, now: Instant) -> Vec<u8> {
        let pn = self.allocate_packet_number(space);
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        // ack_delay (RFC 9000 §19.3): how long the ACK was held since the LARGEST
        // acknowledged packet was received (§13.2.5) and
        // encoded as the raw value (microseconds >> ack_delay_exponent). The peer
        // multiplies it back by 2^exponent. A real QUIC stack reports this; the old
        // hard-coded 0 is a passive distinguisher (an ACK that always claims zero
        // delay). The wire value reports actual elapsed time, including scheduling
        // delay; the local delayed-ACK timer is bounded separately at 25ms.
        // Only the Application (1-RTT) space reports a real ack_delay: Initial and
        // Handshake ACKs are sent immediately (the peer must not apply max_ack_delay
        // there, RFC 9000 §13.2.1 / §17.2.5), so they keep delay 0.
        let ack_delay_raw = if space == SPACE_DATA {
            self.spaces[space]
                .largest_recv_time
                .map(|recv| encoded_ack_delay(now.saturating_duration_since(recv)))
                .unwrap_or(0)
        } else {
            0
        };
        let mut ack = self.spaces[space]
            .recv
            .to_ack(ack_delay_raw)
            .expect("ack_pending is only set after receiving an ack-eliciting packet");
        // Echo the received ECN counts as ACK_ECN (RFC 9000 §13.4.2) so the peer can
        // validate its ECN marking. Only when this space has actually seen ECN — a
        // space on an ECN-stripping path sends a plain ACK, matching the path.
        let recv_ecn = self.spaces[space].recv_ecn;
        if recv_ecn.any() {
            ack.ecn = Some(super::frame::EcnCounts {
                ect0: recv_ecn.ect0,
                ect1: recv_ecn.ect1,
                ce: recv_ecn.ce,
            });
        }
        let header = self.make_header(space, pn, pn_len);
        let datagram = {
            let keys = self.spaces[space].keys.as_ref().unwrap();
            let ack = Frame::Ack(ack);
            // RFC 9000 §14.1: a client pads EVERY datagram carrying an Initial, an
            // ACK-only one included (Safari: ACK + PADDING to 1200).
            if space == SPACE_INITIAL && self.side == Side::Client {
                let mut probe = Vec::new();
                let pn_offset = header.encode(&mut probe);
                let mut payload = Vec::new();
                ack.encode(&mut payload);
                let pad = MIN_INITIAL_DATAGRAM.saturating_sub(
                    pn_offset + pn_len + payload.len() + keys.local.packet.tag_len(),
                );
                seal_packet(&keys.local, header, &[ack, Frame::Padding(pad)])
            } else {
                seal_packet(&keys.local, header, &[ack])
            }
        };
        self.spaces[space].ack_pending = false;
        self.spaces[space].ack_eliciting_count = 0;
        self.spaces[space].ack_deadline = None;
        if space == SPACE_DATA {
            self.key_phase.update_ack_pending = false;
        }
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

    /// Coalesce readable closes for the possible peer handshake states (§10.2.3).
    /// Before confirmation a server must cover both a peer awaiting ServerHello
    /// (Initial) and one awaiting Finished (Handshake). Data is optional then.
    fn build_close_packet(&mut self, now: Instant) -> Option<Vec<u8>> {
        self.enforce_aead_confidentiality_limit();
        self.enforce_aead_integrity_limit();
        let (code, frame_type, reason) = self.close_pending.clone()?;
        let available =
            |space: usize| !self.spaces[space].discarded && self.spaces[space].keys.is_some();
        let mut spaces = if !self.handshake_confirmed {
            let mut spaces = Vec::new();
            if self.side == Side::Server && available(SPACE_INITIAL) {
                spaces.push(SPACE_INITIAL);
            }
            if available(SPACE_HANDSHAKE) {
                spaces.push(SPACE_HANDSHAKE);
            }
            spaces
        } else {
            Vec::new()
        };
        let mandatory = spaces.len().max(1);
        if available(SPACE_DATA) {
            spaces.push(SPACE_DATA);
        } else if spaces.is_empty() && !self.handshake_confirmed && available(SPACE_INITIAL) {
            spaces.push(SPACE_INITIAL);
        }
        if spaces.is_empty() {
            return None;
        }
        // Preflight the entire batch before any PN advances or AEAD seals. A
        // lower-level close must not bypass an exhausted Application key.
        if spaces
            .iter()
            .any(|&space| !self.spaces[space].send.can_allocate())
        {
            self.close_pending = None;
            return None;
        }
        let mtu = self.pmtud.current_mtu();
        let batch_size = |spaces: &[usize], reason: &[u8]| {
            spaces.iter().try_fold(0usize, |total, &space| {
                total.checked_add(self.close_packet_size(space, code, frame_type, reason))
            })
        };
        let mut size = batch_size(&spaces, &reason)?;
        if size > mtu && spaces.len() > mandatory {
            spaces.truncate(mandatory);
            size = batch_size(&spaces, &reason)?;
        }
        // Optional Data is already removed. Shorten only the wire reason when
        // necessary to retain BOTH mandatory server levels; keep the local
        // CloseReason unchanged. The final sealer reads this same pending tuple.
        let shorten_reason = size > mtu
            && frame_type.is_some()
            && spaces.as_slice() == [SPACE_INITIAL, SPACE_HANDSHAKE];
        if shorten_reason {
            size = batch_size(&spaces, &[])?;
        }
        if size > mtu {
            self.close_pending = None;
            return None;
        }
        if !self.peer_addr_validated
            && self.anti_amp_sent.saturating_add(size as u64) > self.anti_amp_recv.saturating_mul(3)
        {
            return None;
        }
        if shorten_reason {
            self.close_pending.as_mut()?.2.clear();
        }
        let mut datagram = Vec::new();
        for space in spaces {
            datagram.extend(self.build_close_packet_in_space(space, now)?);
        }
        self.close_sent = true;
        Some(datagram)
    }

    fn close_frame(
        space: usize,
        code: u64,
        frame_type: Option<u64>,
        reason: &[u8],
    ) -> super::frame::Close<'_> {
        if let Some(frame_type) = frame_type {
            super::frame::Close {
                application: false,
                error_code: code,
                frame_type,
                reason,
            }
        } else if space == SPACE_DATA {
            super::frame::Close {
                application: true,
                error_code: code,
                frame_type: 0,
                reason,
            }
        } else {
            super::frame::Close {
                application: false,
                error_code: APPLICATION_ERROR,
                frame_type: 0,
                reason: &[],
            }
        }
    }

    fn close_packet_size(
        &self,
        space: usize,
        code: u64,
        frame_type: Option<u64>,
        reason: &[u8],
    ) -> usize {
        let pn = self.spaces[space].send.peek();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(space, pn, pn_len);
        let close = Self::close_frame(space, code, frame_type, reason);
        if close.reason.len() > self.pmtud.current_mtu() {
            return self.pmtud.current_mtu().saturating_add(1);
        }
        let mut encoded = Vec::new();
        header.encode(&mut encoded);
        Frame::Close(close).encode(&mut encoded);
        encoded
            .len()
            .checked_add(3)
            .and_then(|size| {
                size.checked_add(
                    self.spaces[space]
                        .keys
                        .as_ref()
                        .unwrap()
                        .local
                        .packet
                        .tag_len(),
                )
            })
            .unwrap_or(usize::MAX)
    }

    /// Seal a close at one explicit encryption level. The orchestrator preflights
    /// the whole batch; this entry point independently guards direct callers.
    fn build_close_packet_in_space(&mut self, space: usize, now: Instant) -> Option<Vec<u8>> {
        self.enforce_aead_confidentiality_limit();
        self.enforce_aead_integrity_limit();
        let (code, frame_type, reason) = self.close_pending.clone()?;
        if self.spaces[space].discarded
            || self.spaces[space].keys.is_none()
            || (self.handshake_confirmed && space != SPACE_DATA)
            || !self.spaces[space].send.can_allocate()
            || self.close_packet_size(space, code, frame_type, &reason) > self.pmtud.current_mtu()
        {
            self.close_pending = None;
            return None;
        }
        let pn = self.allocate_packet_number(space);
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(space, pn, pn_len);
        let close = Self::close_frame(space, code, frame_type, &reason);
        let datagram = {
            let keys = self.spaces[space].keys.as_ref().unwrap();
            seal_packet(
                &keys.local,
                header,
                &[Frame::Close(close), Frame::Padding(3)],
            )
        };
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

    /// Seal a 1-RTT (`SPACE_DATA`) packet from `frames` and record it for loss
    /// recovery. Centralizes the allocate-pn → encode-pn → make-header →
    /// seal_packet → record_sent sequence shared by the small control-frame
    /// builders. The caller owns any pending-flag clearing and content payload;
    /// the emitted bytes are identical to the inlined sequence it replaces.
    fn seal_data_packet(
        &mut self,
        frames: &[Frame],
        ack_eliciting: bool,
        content: SentContent,
        now: Instant,
    ) -> Vec<u8> {
        let pn = self.allocate_packet_number(SPACE_DATA);
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(SPACE_DATA, pn, pn_len);
        let datagram = {
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, frames)
        };
        self.record_sent(SPACE_DATA, pn, datagram.len(), ack_eliciting, content, now);
        datagram
    }

    /// Encode an authenticated peer input for endpoint-level UDP regressions.
    #[cfg(test)]
    pub(crate) fn test_data_packet(&mut self, frames: &[Frame]) -> Vec<u8> {
        self.seal_data_packet(frames, true, SentContent::default(), Instant::now())
    }

    /// Build a 1-RTT packet carrying HANDSHAKE_DONE (RFC 9001 §4.1.2). Ack-eliciting
    /// and tracked so it is resent if lost; clears the pending flag. PADDING brings
    /// the payload up to the 4 bytes header protection needs for its sample (RFC
    /// 9001 §5.4.2): a lone 1-byte HANDSHAKE_DONE would be too short to sample.
    fn build_handshake_done_packet(&mut self, now: Instant) -> Vec<u8> {
        self.handshake_done_pending = false;
        let content = SentContent {
            crypto: Vec::new(),
            stream: Vec::new(),
            handshake_done: true,
            ..Default::default()
        };
        self.seal_data_packet(
            &[Frame::HandshakeDone, Frame::Padding(3)],
            true,
            content,
            now,
        )
    }

    /// Build a 1-RTT PING packet (keep-alive or PTO fallback). Ack-eliciting so it
    /// elicits an ACK; PADDING brings it up to the header-protection sample size. It
    /// carries no retransmittable content (a fresh PING is sent if a probe is lost).
    fn build_ping_packet(&mut self, now: Instant) -> Vec<u8> {
        self.ping_pending = false;
        self.seal_data_packet(
            &[Frame::Ping, Frame::Padding(3)],
            true,
            SentContent::default(),
            now,
        )
    }

    /// Build a DPLPMTUD path-MTU probe (RFC 8899 §4.1 / RFC 9000 §14.4): an
    /// ack-eliciting 1-RTT packet (PING + PADDING) inflated so the datagram is exactly
    /// `probe_size` bytes. If it is acknowledged, the path carries `probe_size`; if it
    /// is lost, the size is too big — and that loss is NOT a congestion signal. The
    /// probe's packet number is recorded in `mtu_probe_pn` so [`Self::recv_ack`] / loss
    /// detection route its outcome to [`Pmtud`] instead of the normal data path.
    ///
    /// The probe carries NO retransmittable content: a fresh probe is issued by the
    /// state machine if this one is lost, so there is nothing to requeue.
    fn build_mtu_probe_packet(&mut self, probe_size: usize, now: Instant) -> Vec<u8> {
        let pn = self.allocate_packet_number(SPACE_DATA);
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(SPACE_DATA, pn, pn_len);
        let mut hdr_buf = Vec::new();
        let pn_offset = header.encode(&mut hdr_buf);
        let tag_len = self.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .unwrap()
            .local
            .packet
            .tag_len();
        // Target payload so the sealed datagram == probe_size:
        //   probe_size = pn_offset + pn_len + payload_len + tag_len
        // The payload is a 1-byte PING plus PADDING; clamp so the PADDING is >= the
        // header-protection sample minimum even for a tiny (defensively small) probe.
        let overhead = pn_offset + pn_len + tag_len;
        let payload_len = probe_size.saturating_sub(overhead).max(4);
        let pad = payload_len.saturating_sub(1); // minus the PING byte
        let frames = [Frame::Ping, Frame::Padding(pad)];
        let datagram = {
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            seal_packet(&keys.local, header, &frames)
        };
        // Record the probe (ack-eliciting, no retransmittable content) and remember its
        // PN so its ACK/loss drives the MTU search rather than the data path.
        self.record_sent(
            SPACE_DATA,
            pn,
            datagram.len(),
            true,
            SentContent::default(),
            now,
        );
        self.mtu_probe_pn = Some(pn);
        datagram
    }

    /// Whether receive windows or stream concurrency credit owe a peer update.
    fn flow_update_pending(&self) -> bool {
        self.need_max_data
            || self.need_max_streams.iter().any(|pending| *pending)
            || self.streams.values().any(|s| s.need_max_stream_data)
    }

    /// Build pending MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS updates, recording
    /// them so lost grants are re-armed (RFC 9000 §19.9–19.11).
    fn build_flow_update_packet(&mut self, now: Instant) -> Vec<u8> {
        let pn = self.allocate_packet_number(SPACE_DATA);
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(SPACE_DATA, pn, pn_len);

        let mut frames: Vec<Frame> = Vec::new();
        let mut content = SentContent::default();
        if self.need_max_data {
            frames.push(Frame::MaxData(self.recv_max_data));
            content.max_data = true;
        }
        for (kind, dir) in [Dir::Bidi, Dir::Uni].into_iter().enumerate() {
            if self.need_max_streams[kind] {
                frames.push(Frame::MaxStreams {
                    dir,
                    max: self.recv_max_streams[kind],
                });
                content.max_streams[kind] = true;
                self.recv_max_streams_sent[kind] = self.recv_max_streams[kind];
            }
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
        self.need_max_streams = [false; 2];
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
        let pn = self.allocate_packet_number(space);
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
                let mut budget = cap.saturating_sub(pn_offset + pn_len + tag_len + crypto_hdr);
                if space == SPACE_INITIAL && self.side == Side::Client {
                    budget = budget.min(SAFARI_INITIAL_CRYPTO_CHUNK);
                }
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
            .find(|(&id, s)| {
                if !self.stream_can_send(id) {
                    return false;
                }
                if s.reset.is_some() {
                    return false; // a reset stream sends RESET_STREAM, not data
                }
                if !s.retransmit.is_empty() {
                    return true;
                }
                let buffered_end = s.send_base + s.send.len() as u64;
                let all_sent = s.send_off == buffered_end;
                if s.fin && !s.fin_sent && all_sent {
                    return true; // an empty FIN consumes no flow-control credit
                }
                let fresh = s.send_off < buffered_end;
                let stream_window = s.send_max.saturating_sub(s.send_off);
                fresh && stream_window > 0 && conn_window > 0
            })
            .map(|(&id, _)| id)
    }

    /// The id of the next stream that owes a RESET_STREAM, if any.
    fn next_stream_to_reset(&self) -> Option<u64> {
        self.streams
            .iter()
            .find(|(&id, s)| {
                self.stream_can_send(id)
                    && s.reset.is_some()
                    && !s.reset_sent
                    && !s.cancel_after.iter().any(|&id| self.has_unsent_data(id))
            })
            .map(|(&id, _)| id)
    }

    /// Build a 1-RTT packet carrying RESET_STREAM for `id` (RFC 9000 §19.4),
    /// recording it for loss re-arm.
    fn build_reset_packet(&mut self, id: u64, now: Instant) -> Vec<u8> {
        let pn = self.allocate_packet_number(SPACE_DATA);
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(SPACE_DATA, pn, pn_len);
        let s = &self.streams[&id];
        let error_code = s.reset.unwrap_or(0);
        let final_size = s.send_off;
        let stop_sending = s.stop_sending;
        let datagram = {
            let frame = Frame::ResetStream {
                id,
                error_code,
                final_size,
            };
            let keys = self.spaces[SPACE_DATA].keys.as_ref().unwrap();
            if stop_sending {
                // A cancelled stream: STOP_SENDING then RESET_STREAM in one packet,
                // Safari's HTTP/3 request-cancel shape (frame types 0x05, 0x04).
                let stop = Frame::StopSending { id, error_code };
                seal_packet(&keys.local, header, &[stop, frame])
            } else {
                seal_packet(&keys.local, header, &[frame, Frame::Padding(3)])
            }
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
        let pn = self.allocate_packet_number(SPACE_DATA);
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
        let offset = s.retransmit.first().map_or(s.send_off, |range| range.0);
        let frame_hdr = 1 + super::varint::size(id) + super::varint::size(offset) + 2;
        // A lost range may have been sent before a PMTU blackhole reset, so size
        // retransmissions and fresh data against the current validated MTU.
        let budget = self
            .pmtud
            .current_mtu()
            .saturating_sub(pn_offset + pn_len + tag_len + frame_hdr);
        let (offset, end, fin, is_retransmit) = if let Some(&(off, len, fin)) = s.retransmit.first()
        {
            let chunk = len.min(budget.max(1) as u64);
            (off, off + chunk, fin && chunk == len, true)
        } else {
            let buffered_end = s.send_base + s.send.len() as u64;
            let remaining = (buffered_end - offset) as usize;
            // Clamp the fresh chunk to both flow-control windows (RFC 9000 §4.1).
            let conn_window = self.send_max_data.saturating_sub(self.send_data_total);
            let fc_window = s.send_max.saturating_sub(offset).min(conn_window) as usize;
            let chunk = remaining.min(budget.max(1)).min(fc_window);
            let end = offset + chunk as u64;
            // Carry the FIN only once the final buffered byte is in this frame.
            let fin = s.fin && !s.fin_sent && end == buffered_end;
            (offset, end, fin, false)
        };

        let datagram = {
            let s = &self.streams[&id];
            let frame = Frame::Stream {
                id,
                offset,
                fin,
                data: &s.send[(offset - s.send_base) as usize..(end - s.send_base) as usize],
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
            let (_, len, range_fin) = s.retransmit[0];
            let sent = end - offset;
            if sent == len {
                s.retransmit.remove(0);
            } else {
                s.retransmit[0] = (end, len - sent, range_fin);
            }
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
        let pn = self.allocate_packet_number(SPACE_DATA);
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
            // 0-RTT data uses the same validated path MTU; before any probe completes
            // (the usual case this early) current_mtu() is the BASE ceiling, unchanged.
            let budget = self
                .pmtud
                .current_mtu()
                .saturating_sub(pn_offset + pn_len + tag_len + frame_hdr);
            let buffered_end = s.send_base + s.send.len() as u64;
            let remaining = (buffered_end - offset) as usize;
            let conn_window = self.send_max_data.saturating_sub(self.send_data_total);
            let fc_window = s.send_max.saturating_sub(offset).min(conn_window) as usize;
            let chunk = remaining.min(budget.max(1)).min(fc_window);
            let end = offset + chunk as u64;
            let fin = s.fin && !s.fin_sent && end == buffered_end;
            (offset, end, fin, false)
        };

        let datagram = {
            let s = &self.streams[&id];
            let frame = Frame::Stream {
                id,
                offset,
                fin,
                data: &s.send[(offset - s.send_base) as usize..(end - s.send_base) as usize],
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
    #[allow(dead_code)] // ECN-less entry point: used throughout the conn/netsim tests + a public API
    pub fn handle_datagram(&mut self, datagram: &[u8], now: Instant) -> Result<(), QuicTlsError> {
        // Datagrams with no ECN information (tests, non-Linux recv path) are Not-ECT.
        self.handle_datagram_ecn(datagram, EcnCodepoint::NotEct, now)
    }

    /// Like [`Self::handle_datagram`] but carries the datagram's IP-layer ECN codepoint
    /// (RFC 9000 §13.4): after a packet in the datagram AEAD-opens, the codepoint is
    /// folded into the receiving space's ECN tally so the next ACK echoes it as ACK_ECN.
    pub fn handle_datagram_ecn(
        &mut self,
        datagram: &[u8],
        ecn: EcnCodepoint,
        now: Instant,
    ) -> Result<(), QuicTlsError> {
        // NB: the idle timer (last_recv_time) is refreshed inside process_packet
        // only AFTER a packet AEAD-opens (RFC 9000 §10.1: "received and processed"),
        // so an off-path attacker cannot pin the connection open with garbage UDP.
        //
        // Anti-amplification (RFC 9000 §8.1): while the peer's address is
        // unvalidated, every byte of every datagram attributed to the connection —
        // decryptable or not — grows the 3x send budget enforced in poll_transmit.
        if !self.peer_addr_validated {
            self.anti_amp_recv = self.anti_amp_recv.saturating_add(datagram.len() as u64);
        }
        let mut buf = datagram.to_vec();
        let mut pos = 0;
        while pos < buf.len() {
            // Boundary of the current packet, read from its plaintext long header
            // BEFORE `process_packet` decrypts in place. `None` ⇒ a short header
            // (or unparseable) which runs to the datagram end: process it, stop.
            let advance = packet::long_packet_len(&buf[pos..]);
            self.process_packet(&mut buf[pos..], ecn, now)?;
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
    fn process_packet(
        &mut self,
        pkt: &mut [u8],
        ecn: EcnCodepoint,
        now: Instant,
    ) -> Result<(), QuicTlsError> {
        let pspace = match packet::first_packet_space(pkt) {
            Some(s) => s,
            None => return Ok(()), // unsupported type / clear fixed bit: drop
        };
        // RFC 9001 §5.6: servers never send 0-RTT. Drop reflected client early
        // data before decryption or any packet-derived state can be committed.
        if self.side == Side::Client && pspace == PacketSpace::ZeroRtt {
            return Ok(());
        }
        if self.closed.is_some() {
            return Ok(());
        }
        // RFC 9001 section 5.7 applies to both roles, including close and ACK.
        // A coalesced earlier Handshake packet can complete TLS before this call.
        if pspace == PacketSpace::OneRtt && self.tls.is_handshaking() {
            return Ok(());
        }
        let space = space_index(pspace);
        if self.spaces[space].discarded {
            return Ok(());
        }

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
        let mut read_generation = None;
        let opened = if pspace == PacketSpace::OneRtt {
            self.open_data_packet(pkt, local_cid_len, largest, now).map(
                |(header, range, generation)| {
                    read_generation = Some(generation);
                    (header, range)
                },
            )
        } else {
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

        if let Some(generation) = read_generation {
            if !self
                .key_phase
                .valid_receive(generation, header.packet_number())
            {
                return Err(transport_error(
                    0x0e,
                    0,
                    "invalid key phase packet-number ordering",
                ));
            }
        }
        // Only a new authenticated packet may commit trusted state. This also
        // rejects evicted low-water PNs, not just explicitly retained replays.
        if !self.spaces[space].recv.insert(header.packet_number()) {
            return Ok(());
        }
        let receive_generation = if let Some(generation) = read_generation {
            self.commit_data_generation(generation, header.packet_number(), now)?;
            Some(if generation == ReadGeneration::Previous {
                self.key_phase.rx - 1
            } else {
                self.key_phase.rx
            })
        } else {
            None
        };
        let immediate_ack = pspace != PacketSpace::OneRtt
            || !self.handshake_confirmed
            || read_generation == Some(ReadGeneration::Next)
            || largest.is_some_and(|largest| header.packet_number() != largest + 1)
            || ecn == EcnCodepoint::Ce;
        // Refresh idle only after authentication AND deduplication (RFC 9000
        // §10.1), so a recorded valid packet cannot keep a silent peer alive.
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

        // Fold this authenticated, non-duplicate packet's ECN codepoint into the
        // space's tally (RFC 9000 §13.4): the next ACK echoes it as ACK_ECN so the peer
        // can validate ECN. Recorded only after authentication + dedup so a forged or
        // replayed datagram cannot inflate the counts.
        self.spaces[space].recv_ecn.record(ecn);

        // Successfully processing a Handshake packet proves the peer holds Handshake
        // keys, hence received our Initial CRYPTO: discard Initial keys + state (RFC
        // 9001 §4.9.1). Safe for both roles — the server's §4.9.1 trigger exactly,
        // and for the client it implies the server acked our ClientHello.
        //
        // A client still owing an Initial ACK sends it first (poll_transmit discards
        // right after): Safari ACKs the server's Initial flight even when its tail
        // arrives coalesced with Handshake packets. RFC 9001 §4.9.1 lets a client keep
        // Initial keys until it first sends a Handshake packet.
        if space == SPACE_HANDSHAKE && self.spaces[SPACE_INITIAL].keys.is_some() {
            if self.side == Side::Client && self.spaces[SPACE_INITIAL].ack_pending {
                self.discard_initial_after_ack = true;
            } else {
                self.discard_space(SPACE_INITIAL);
            }
        }
        // The same proof validates the peer's address (RFC 9000 §8.1: "receipt of
        // a packet protected with Handshake keys"): only an on-path peer at its
        // claimed address can hold Handshake keys, so the 3x anti-amplification
        // cap is lifted. (0-RTT does NOT validate — it opens in SPACE_DATA under
        // PSK-derived keys a replay could reuse from a spoofed address.)
        if space == SPACE_HANDSHAKE {
            self.peer_addr_validated = true;
        }

        // Copy the decrypted frames out so the TLS engine can be mutated while we
        // iterate.
        let payload = pkt[range].to_vec();
        // A packet is ack-eliciting (RFC 9002 §2) if it carries any frame other
        // than ACK / PADDING / CONNECTION_CLOSE — such a packet schedules an ACK.
        let mut ack_eliciting = false;
        // SECURITY INVARIANT: reaching the frame parser means this packet belongs to
        // a TERMINATED ParallaX<->ParallaX tunnel (we are a `Connection`), never a
        // spliced real-origin flow (those are forwarded verbatim as a `SpliceFlow`
        // and never decoded). This is what makes the parser's deliberate omissions
        // sound — unknown/GREASE/DATAGRAM frames as a hard decode error would be
        // fingerprints/interop breaks against a real
        // origin, but a ParallaX peer never sends them. See frame.rs's invariant note
        // before pointing this path at any non-ParallaX peer.
        let mut frames = Iter::new(&payload);
        while let Some(frame) = frames.next() {
            let frame_type = frames.last_frame_type();
            let frame = frame.map_err(|e| {
                transport_error(0x07, frame_type, format!("frame decode failed: {e:?}"))
            })?;
            // A driver may ignore a handshake processing error. Make rejection
            // terminal before returning; neither this frame nor later frames
            // (including in another datagram) may then mutate the connection.
            // Earlier legal frames and authenticated packet metadata stay committed.
            if !frame_permitted(pspace, self.side, frame_type) {
                self.close_transport(0x0a, frame_type, b"frame not permitted");
                return Err(transport_error(0x0a, frame_type, "frame not permitted"));
            }
            match frame {
                Frame::Crypto { offset, data } => {
                    ack_eliciting = true;
                    self.recv_crypto(space, offset, data)
                        .map_err(|error| with_frame_type(error, frame_type))?;
                }
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } => {
                    ack_eliciting = true;
                    self.recv_stream(id, offset, fin, data)
                        .map_err(|error| with_frame_type(error, frame_type))?;
                }
                Frame::ResetStream {
                    id,
                    error_code,
                    final_size,
                } => {
                    ack_eliciting = true;
                    self.recv_reset_stream(id, error_code, final_size)?;
                }
                Frame::StopSending { id, error_code } => {
                    ack_eliciting = true;
                    if is_uni(id) && self.is_peer_initiated(id) {
                        return Err(QuicTlsError::Transport {
                            error_code: 0x05,
                            frame_type: 0x05,
                            reason: "STOP_SENDING on a receive-only stream".into(),
                        });
                    }
                    if !self.stream_retired(id) {
                        if !self.is_peer_initiated(id) && !self.streams.contains_key(&id) {
                            return Err(QuicTlsError::Transport {
                                error_code: 0x05,
                                frame_type: 0x05,
                                reason: "STOP_SENDING on an unopened locally-initiated stream"
                                    .into(),
                            });
                        }
                        self.ensure_stream(id, frame_type)?;
                        self.reset_stream(id, error_code);
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
                Frame::MaxStreams { dir, max } => {
                    ack_eliciting = true;
                    if max > (1 << 60) {
                        return Err(QuicTlsError::Transport {
                            error_code: 0x07, // FRAME_ENCODING_ERROR, RFC 9000 §19.11.
                            frame_type: if dir == Dir::Uni { 0x13 } else { 0x12 },
                            reason: "MAX_STREAMS exceeds 2^60".into(),
                        });
                    }
                    let kind = usize::from(dir == Dir::Uni);
                    self.send_max_streams[kind] = self.send_max_streams[kind].max(max);
                }
                Frame::Ack(ack) => self
                    .recv_ack(space, &ack, receive_generation, now)
                    .map_err(|error| with_frame_type(error, frame_type))?,
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
                            CloseReason::PeerTransport(c.error_code, c.frame_type, reason)
                        });
                        self.close_time = Some(now);
                    }
                }
                // PING and every other relay-relevant frame are ack-eliciting but
                // carry no payload we act on here.
                _ => ack_eliciting = true,
            }
        }
        // Stamp the receive time of the packet bearing the LARGEST acknowledged packet
        // number (RFC 9000 §13.2.5: ack_delay is measured from when the largest-acked
        // packet was received, NOT the first one the pending ACK covers). `to_ack`
        // names `recv.largest()` as the ACK's largest, so the stamp must track whichever
        // packet IS the largest received — which can be a non-ack-eliciting one (e.g. a
        // pure ACK whose PN exceeds a later ack-eliciting packet's). Gating this on
        // `ack_eliciting` (as the prior code did) left a stale, too-old stamp in exactly
        // that interleaving, over-reporting the delay. `recv.insert` above already folded
        // this packet in, so it is the new largest iff its PN equals `recv.largest()`; a
        // reordered (smaller-PN) packet does not move the stamp.
        if self.spaces[space].recv.largest() == Some(header.packet_number()) {
            self.spaces[space].largest_recv_time = Some(now);
        }
        self.schedule_ack(space, ack_eliciting, immediate_ack, now);
        self.prevalidate_peer_transport_params()?;
        self.pump_write();
        self.apply_authenticated_peer_ack_params()?;
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
    fn recv_ack(
        &mut self,
        space: usize,
        ack: &Ack,
        receive_generation: Option<u64>,
        now: Instant,
    ) -> Result<(), QuicTlsError> {
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
        if let Some(generation) = receive_generation {
            let was_acked = self.key_phase.tx_acked;
            for &(low, high) in &ack.ranges {
                // Old-key ACKs cannot confirm a packet sent with newer keys.
                if generation < self.key_phase.tx
                    && self.key_phase.tx_first.is_some_and(|first| high >= first)
                {
                    return Err(transport_error(0x0e, 0, "old-key ACK for updated packet"));
                }
                self.key_phase.confirm(generation, low, high);
            }
            if !was_acked && self.key_phase.tx_acked && self.key_phase.tx > 0 {
                self.next_update_at = Some(now + self.drain_duration());
            }
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
        let mut probe_acked = false;
        // Streams with newly-acked bytes: their fully-acked send-buffer prefixes are
        // compacted below, once loss detection has requeued anything declared lost.
        let mut acked_streams: Vec<u64> = Vec::new();
        for (pn, sp) in &newly {
            if let Some(content) = self.spaces[space].sent_content.remove(pn) {
                if space == SPACE_DATA {
                    self.unindex_sent_stream_ranges(&content);
                }
                for &(id, _, _, _) in &content.stream {
                    if !acked_streams.contains(&id) {
                        acked_streams.push(id);
                    }
                }
                for &(id, _, _, fin) in &content.stream {
                    if fin {
                        if let Some(s) = self.streams.get_mut(&id) {
                            s.fin_acked = true;
                        }
                    }
                }
                for id in content.reset {
                    if let Some(s) = self.streams.get_mut(&id) {
                        s.reset_acked = true;
                    }
                    if !acked_streams.contains(&id) {
                        acked_streams.push(id);
                    }
                }
            }
            if sp.ack_eliciting {
                any_ack_eliciting = true;
                acked_bytes += sp.size;
            }
            if *pn == ack.largest {
                largest_time = Some(sp.time_sent);
                largest_delivered = Some(sp.delivered);
            }
            // A DPLPMTUD probe was acknowledged: the path carries that size. Note it
            // here and validate the size after the loop (the probe PN lives only in the
            // DATA space). A full-size data ack also clears the black-hole streak.
            if space == SPACE_DATA && self.mtu_probe_pn == Some(*pn) {
                probe_acked = true;
            }
        }
        if probe_acked {
            self.mtu_probe_pn = None;
            self.pmtud.on_probe_acked();
        } else if space == SPACE_DATA && !newly.is_empty() {
            // Any ordinary DATA ack at the current MTU proves the path still carries it.
            self.pmtud.on_full_size_acked();
        }
        if let (Some(sent_at), true) = (largest_time, any_ack_eliciting) {
            // The peer controls the incoming exponent/bound. Before confirmation
            // RFC 9002 §5.3 does not clamp to max_ack_delay; min_rtt still bounds
            // adjustment in RttEstimator. Our outgoing ACK contract stays 3/25ms.
            let ack_delay = ack_delay_for_recovery(
                ack.delay,
                self.peer_ack_delay_exponent,
                space,
                self.handshake_confirmed,
                self.peer_max_ack_delay,
            );
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
            // App-limited (draft-cheng-iccrg-delivery-rate-estimation): the sender ran
            // out of data rather than bandwidth. A sample taken while app-limited must
            // not raise BBR's bottleneck-bandwidth estimate, or an interactive/bursty
            // flow that briefly drains its send buffer would lock in an under-estimate
            // of the path and then under-send. Proxy it from current state: no stream
            // has bytes (or a FIN) queued AND we are below the congestion window (so the
            // gap is the app's, not the cwnd's). This was hard-coded `false`, which made
            // every quiet gap look like a true bandwidth ceiling.
            let app_limited =
                self.next_stream_to_send().is_none() && self.bytes_in_flight() < self.cc.window();
            let info = AckInfo {
                now,
                bytes_acked: acked_bytes,
                rtt: self.rtt.latest(),
                delivery_rate,
                in_flight: self.bytes_in_flight(),
                delivered: self.delivered,
                app_limited,
            };
            self.cc.on_ack(&info);
        }

        // Loss detection: re-queue the content of every packet declared lost and
        // signal the congestion controller once for the batch (RFC 9002 §7.3.2).
        let loss_delay = self.rtt.loss_delay();
        let (lost, loss_time) = self.spaces[space].sent.detect_lost(loss_delay, now);
        self.spaces[space].loss_time = loss_time;
        let any_lost = self.process_lost_packets(space, lost, now);
        if any_lost {
            self.cc.on_congestion_event(now);
        }

        // ECN reaction (RFC 9002 §7): a reported increase in the peer's CE count means
        // the path marked Congestion Experienced on our egress — a congestion signal
        // equivalent to loss. Only the Application space carries a meaningful ECN
        // stream, and the count is monotonic per the RFC, so act on growth only. (BBR's
        // on_congestion_event is intentionally a no-op — it does not collapse on loss or
        // CE — so this is RFC-correct signalling that today changes no behaviour; a
        // future loss-reactive controller behind the same seam would honour it.)
        if space == SPACE_DATA {
            if let Some(ecn) = ack.ecn {
                if ecn.ce > self.peer_ecn_ce {
                    self.peer_ecn_ce = ecn.ce;
                    self.cc.on_congestion_event(now);
                }
            }
        }

        // Reclaim fully-acked send-buffer prefixes (finding #28). Runs AFTER loss
        // detection so a lost range is already requeued in `retransmit` and still
        // counts as needed.
        for id in acked_streams {
            self.compact_send_buffer(id);
            self.retire_stream(id);
        }
        Ok(())
    }

    /// Fold a just-recorded DATA-space packet's STREAM ranges into each stream's
    /// in-flight offset index (see [`Stream::sent_range_offsets`]). Paired with
    /// [`Self::unindex_sent_stream_ranges`] at every site that removes the packet
    /// from `sent_content` (acked / declared lost / consumed by a PTO probe), so
    /// the index is an exact multiset mirror of the stream ranges held there.
    fn index_sent_stream_ranges(&mut self, content: &SentContent) {
        for &(id, off, _, _) in &content.stream {
            if let Some(s) = self.streams.get_mut(&id) {
                *s.sent_range_offsets.entry(off).or_insert(0) += 1;
            }
        }
    }

    /// Remove a DATA-space packet's STREAM ranges from the in-flight offset index
    /// as the packet leaves `sent_content`. Counterpart of
    /// [`Self::index_sent_stream_ranges`].
    fn unindex_sent_stream_ranges(&mut self, content: &SentContent) {
        for &(id, off, _, _) in &content.stream {
            if let Some(s) = self.streams.get_mut(&id) {
                if let Some(n) = s.sent_range_offsets.get_mut(&off) {
                    *n -= 1;
                    if *n == 0 {
                        s.sent_range_offsets.remove(&off);
                    }
                }
            }
        }
    }

    /// Drop the fully-acknowledged prefix of stream `id`'s send buffer so a
    /// long-lived stream does not retain every byte ever sent (memory-DoS,
    /// finding #28). Everything below the lowest offset still needed for
    /// (re)transmission — fresh bytes from `send_off`, queued lost ranges, and
    /// ranges in flight awaiting an ACK — has been acknowledged and can never be
    /// resent, so it is dropped and `send_base` advanced to keep absolute-offset
    /// indexing correct. Amortized O(1)/byte: compaction only runs once the dead
    /// prefix is at least as large as the live tail it would memmove. The lowest
    /// in-flight offset comes from the per-stream index
    /// ([`Stream::sent_range_offsets`], O(log n)) rather than rescanning every
    /// in-flight packet's ranges, which cost
    /// O(acked_streams × in_flight_packets) per ACK under a large cwnd.
    fn compact_send_buffer(&mut self, id: u64) {
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        let mut low = s.send_off;
        for &(off, _, _) in &s.retransmit {
            low = low.min(off);
        }
        if let Some((&off, _)) = s.sent_range_offsets.first_key_value() {
            low = low.min(off);
        }
        let reclaim = low.saturating_sub(s.send_base) as usize;
        if reclaim == 0 || reclaim < s.send.len() - reclaim {
            return;
        }
        s.send.drain(..reclaim);
        s.send_base = low;
    }

    /// Requeue the retransmittable content of declared-lost packets and report whether
    /// any loss should signal congestion. A DPLPMTUD probe loss is routed to the MTU
    /// state machine and EXCLUDED from the congestion signal (RFC 9000 §14.4: a lost
    /// PMTU probe is not a congestion event); a full-size DATA loss also feeds the
    /// black-hole detector. Shared by the ACK-driven and timeout-driven loss paths so
    /// both treat a probe loss identically.
    fn process_lost_packets(
        &mut self,
        space: usize,
        lost: Vec<(u64, SentPacket)>,
        _now: Instant,
    ) -> bool {
        let mut any_congestion_loss = false;
        for (pn, _) in lost {
            // A lost MTU probe: drive the search down, do NOT count it as congestion
            // and do NOT requeue (the probe carries no retransmittable content; a fresh
            // probe is issued by the state machine).
            if space == SPACE_DATA && self.mtu_probe_pn == Some(pn) {
                self.mtu_probe_pn = None;
                self.pmtud.on_probe_lost();
                // A probe carries no STREAM ranges, but unindex uniformly so the
                // offset index can never drift from sent_content.
                if let Some(content) = self.spaces[space].sent_content.remove(&pn) {
                    self.unindex_sent_stream_ranges(&content);
                }
                continue;
            }
            if let Some(content) = self.spaces[space].sent_content.remove(&pn) {
                if space == SPACE_DATA {
                    self.unindex_sent_stream_ranges(&content);
                }
                // A full-size DATA loss feeds the black-hole detector (sustained such
                // losses at a grown MTU reset the path to BASE so the transfer
                // self-heals). Ordinary loss below the threshold is ignored there.
                if space == SPACE_DATA {
                    self.pmtud.on_full_size_loss();
                }
                self.requeue(space, content);
                any_congestion_loss = true;
            }
        }
        any_congestion_loss
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
                    return Err(transport_error(
                        0x0d,
                        0x06,
                        "CRYPTO reassembly window exceeded",
                    ));
                }
                sp.crypto_pending.push((offset, data.to_vec()));
            } else {
                drain_contiguous(
                    &mut sp.crypto_pending,
                    &mut sp.crypto_recv_off,
                    offset,
                    data,
                    &mut to_feed,
                );
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
        // A locally initiated uni is send-only even after retirement. Validate
        // direction before ignoring closed streams or charging receive credit.
        if is_uni(id) && !self.is_peer_initiated(id) {
            return Err(QuicTlsError::Transport {
                error_code: 0x05,
                frame_type: 0x08,
                reason: "STREAM on a send-only stream".into(),
            });
        }
        if self.stream_retired(id) {
            return Ok(());
        }
        // `end` overflowing u64 is a frame encoding error, not arithmetic to wrap:
        // such an offset can never fall inside any receive window (debug builds
        // would panic, release builds would wrap to a small `end` and bypass the
        // window check below). Reject before touching connection state.
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| transport_error(0x07, 0x08, "STREAM frame offset overflows u64"))?;
        // Validate against the stream's current state (or a fresh stream's defaults
        // if this frame would open it) BEFORE `ensure_stream` inserts and accept-
        // queues the stream: a flow-control / final-size violation must not leave a
        // zombie stream behind (RFC 9000 §4.6 stream limit, §4.5 final size). A new
        // stream starts at recv_fin=None, recv_high=0, recv_max=STREAM_RECV_WINDOW.
        let (cur_fin, cur_high, cur_max) = self
            .streams
            .get(&id)
            .map(|s| (s.recv_fin, s.recv_high, s.recv_max))
            .unwrap_or((None, 0, STREAM_RECV_WINDOW));
        // FINAL_SIZE validation (RFC 9000 §4.5): once a final size is known it is
        // immutable, no data may arrive beyond it, and a FIN must not retroactively
        // place the final size below data already received.
        if let Some(final_size) = cur_fin {
            if end > final_size || (fin && end != final_size) {
                return Err(transport_error(
                    0x06,
                    0x08,
                    "STREAM frame violates the stream's final size",
                ));
            }
        }
        if fin && end < cur_high {
            return Err(transport_error(
                0x06,
                0x08,
                "FIN final size below data already received",
            ));
        }
        if end > cur_max {
            return Err(transport_error(
                0x03,
                0x08,
                "peer exceeded the stream receive window",
            ));
        }
        let new_high = end.max(cur_high);
        let delta = new_high - cur_high;
        // `checked_add` keeps the bound robust against u64 wrap (a release-mode
        // overflow would otherwise wrap to a small value and bypass the window);
        // treat overflow as a flow-control violation, like exceeding the window.
        match self.recv_data_total.checked_add(delta) {
            Some(total) if total <= self.recv_max_data => {}
            _ => {
                return Err(transport_error(
                    0x03,
                    0x08,
                    "peer exceeded the connection receive window",
                ));
            }
        }
        // All checks passed: now it is safe to create + accept-queue the stream.
        self.ensure_stream(id, 0x08)?;
        let s = self.streams.get_mut(&id).expect("just ensured");
        // A stream already in Reset Recvd had everything up to its final size
        // accounted as delivered when the reset was processed (RFC 9000 §4.5), so
        // reassembling a late retransmit would hand `read_stream` bytes to credit a
        // second time and inflate the connection window. The reset fixed the final
        // size, so `delta` is necessarily 0 here — there is nothing left to charge —
        // and RFC 9000 §3.2 lets the receiver discard data once the stream is reset.
        if s.recv_reset.is_some() {
            return Ok(());
        }
        s.recv_high = new_high;
        self.recv_data_total += delta;
        if fin {
            s.recv_fin = Some(end);
        }
        if s.recv_released {
            s.recv_credited += delta;
            if s.recv_fin.is_some_and(|fin| new_high >= fin) {
                s.recv_off = new_high;
            }
            self.credit_connection_window(delta);
            self.retire_stream(id);
            return Ok(());
        }
        // In-order reassembly. Flow control above bounds the high watermark, but
        // NOT this buffer: a zero-length fragment (e.g. a bare FIN, already recorded
        // above) carries nothing to reassemble, and duplicate/overlapping fragments
        // do not advance the watermark yet still buffer bytes. Drop empties and cap
        // buffered bytes (per stream AND connection-wide) and entry count
        // (memory-exhaustion DoS otherwise).
        if offset > s.recv_off {
            if !data.is_empty() {
                // A fragment fully covered by an already-buffered one reassembles
                // nothing new; drop it rather than buffer another copy. A retransmit
                // duplicate leaves the high watermark unchanged (delta == 0), so it
                // would otherwise consume reassembly budget at zero flow-control
                // cost. Partial overlaps still buffer (they may fill gaps).
                if s.recv_pending
                    .iter()
                    .any(|(o, d)| *o <= offset && *o + d.len() as u64 >= end)
                {
                    return Ok(());
                }
                let buffered: usize = s.recv_pending.iter().map(|(_, d)| d.len()).sum();
                if buffered + data.len() > MAX_STREAM_REASSEMBLY
                    || s.recv_pending.len() >= MAX_STREAM_PENDING_FRAGMENTS
                    || self.recv_pending_total + data.len() > MAX_CONN_REASSEMBLY
                {
                    return Err(transport_error(
                        0x01,
                        0x08,
                        "stream reassembly buffer exceeded",
                    ));
                }
                self.recv_pending_total += data.len();
                s.recv_pending.push((offset, data.to_vec()));
            }
            return Ok(());
        }
        let freed = drain_contiguous(
            &mut s.recv_pending,
            &mut s.recv_off,
            offset,
            data,
            &mut s.recv,
        );
        self.recv_pending_total -= freed;
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
        if is_uni(id) && !self.is_peer_initiated(id) {
            return Err(QuicTlsError::Transport {
                error_code: 0x05,
                frame_type: 0x04,
                reason: "RESET_STREAM on a send-only stream".into(),
            });
        }
        if self.stream_retired(id) {
            return Ok(());
        }
        // Validate against the stream's current state (or a fresh stream's defaults
        // if this RESET would open it) BEFORE `ensure_stream` inserts and accept-
        // queues the stream, so a flow-control / final-size violation leaves no
        // zombie stream behind. A new stream starts at recv_fin=None, recv_high=0,
        // recv_max=STREAM_RECV_WINDOW.
        let (cur_fin, cur_high, cur_max) = self
            .streams
            .get(&id)
            .map(|s| (s.recv_fin, s.recv_high, s.recv_max))
            .unwrap_or((None, 0, STREAM_RECV_WINDOW));
        // RFC 9000 §4.5: the reset's final size must agree with any known final
        // size and must not be below data already received; the bytes up to it count
        // toward connection-level flow control (they are considered delivered).
        if cur_fin.is_some_and(|known| known != final_size) {
            return Err(transport_error(
                0x06,
                0x04,
                "RESET_STREAM final size conflicts with a known final size",
            ));
        }
        if final_size < cur_high {
            return Err(transport_error(
                0x06,
                0x04,
                "RESET_STREAM final size below data already received",
            ));
        }
        if final_size > cur_max {
            return Err(transport_error(
                0x03,
                0x04,
                "RESET_STREAM exceeded the stream receive window",
            ));
        }
        let delta = final_size - cur_high;
        // See `recv_stream`: guard the connection-window check against u64 wrap.
        match self.recv_data_total.checked_add(delta) {
            Some(total) if total <= self.recv_max_data => {}
            _ => {
                return Err(transport_error(
                    0x03,
                    0x04,
                    "RESET_STREAM exceeded the connection receive window",
                ));
            }
        }
        // All checks passed: now it is safe to create + accept-queue the stream.
        self.ensure_stream(id, 0x04)?;
        let s = self.streams.get_mut(&id).expect("just ensured");
        s.recv_high = final_size;
        s.recv_fin = Some(final_size);
        // Only the FIRST reset may release flow control: a duplicate RESET_STREAM
        // carries delta == 0, so crediting again would inflate the window past what
        // the peer actually consumed.
        let first_reset = s.recv_reset.is_none();
        s.recv_reset = Some(error_code);
        // Bytes the application can still take: what is reassembled in order and
        // waiting (the reader drains that before the reset surfaces as
        // ConnectionReset). Everything else this stream charged to the connection
        // window — the gap the reset skipped, out-of-order fragments that can no
        // longer be reassembled, and the tail up to `final_size` — is now
        // undeliverable, so `read_stream` will never credit it.
        let still_readable = s.recv.len() as u64;
        let stranded_fragments: usize = s.recv_pending.iter().map(|(_, d)| d.len()).sum();
        if first_reset {
            // No further STREAM frames can arrive (the final size is fixed), so the
            // gaps in front of these fragments will never fill: they are dead weight
            // on the reassembly budget as well as on flow control.
            s.recv_pending = Vec::new();
        }
        // Credit up to `final_size - still_readable`, minus whatever this stream has
        // already released, so the release is exact and cannot double-count.
        let credit = final_size
            .saturating_sub(still_readable)
            .saturating_sub(s.recv_credited);
        if first_reset {
            s.recv_credited += credit;
        }
        self.recv_data_total += delta;
        if first_reset {
            self.recv_pending_total = self.recv_pending_total.saturating_sub(stranded_fragments);
            // RFC 9000 §4.5: the reset's bytes count as delivered for flow control.
            // Reclaiming them keeps MAX_DATA moving; without this a peer that resets
            // streams at their full final size permanently freezes the connection
            // window (recv_data_total climbs to the limit while recv_data_consumed
            // stays put) and the connection can never receive again.
            self.credit_connection_window(credit);
        }
        self.retire_stream(id);
        Ok(())
    }

    /// Release the connection-level flow-control credit for `bytes` and re-arm a
    /// MAX_DATA grant once half the window has been reclaimed. Shared by every
    /// release site (delivery, reset, abandonment) so they cannot drift.
    fn credit_connection_window(&mut self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.recv_data_consumed += bytes;
        self.recv_max_data = self.recv_data_consumed + CONN_RECV_WINDOW;
        if self.recv_max_data - self.recv_max_data_sent >= CONN_RECV_WINDOW / 2 {
            self.need_max_data = true;
        }
    }

    /// Abandon stream `id`'s receive half: nothing will ever read it again, so
    /// release the connection-level credit for everything it still holds and drop
    /// the buffers.
    ///
    /// Without this an abandoned stream ratchets the connection window shut exactly
    /// like an uncredited reset did: the server's mux drops the `recv` half of a
    /// bidi it rejects at the per-connection substream cap, and with no
    /// STOP_SENDING the peer may already have filled the full stream window. Eight
    /// such streams reach `CONN_RECV_WINDOW` with nothing consumed and the next
    /// STREAM frame fails the connection.
    pub fn discard_stream_recv(&mut self, id: u64) {
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        // Everything this stream charged to the window, less what it already
        // released. `recv_high` is its total charge, so this leaves the stream fully
        // credited and can never over-credit.
        let credit = s.recv_high.saturating_sub(s.recv_credited);
        s.recv_credited = s.recv_high;
        s.recv_released = true;
        s.recv = Vec::new();
        let stranded_fragments: usize = s.recv_pending.iter().map(|(_, d)| d.len()).sum();
        s.recv_pending = Vec::new();
        self.recv_pending_total = self.recv_pending_total.saturating_sub(stranded_fragments);
        self.credit_connection_window(credit);
        self.retire_stream(id);
    }

    /// Create a stream on first sight, queuing a peer-initiated one for `accept_*`.
    /// Caps concurrent peer-initiated streams (a memory-exhaustion DoS guard,
    /// RFC 9000 §4.6 STREAM_LIMIT_ERROR), and seeds the send window from the peer's
    /// transport parameters.
    fn ensure_stream(&mut self, id: u64, frame_type: u64) -> Result<(), QuicTlsError> {
        if self.streams.contains_key(&id) {
            return Ok(());
        }
        // ensure_stream runs only on the receive path (the peer referenced `id`).
        // A peer may open streams only in ITS OWN initiator space (RFC 9000 §3.2 /
        // §19.8); referencing an unopened stream in our space is a STREAM_STATE_ERROR
        // and would otherwise bypass the peer-stream cap below (the count filters on
        // is_peer_initiated, so an our-space id was never counted — unbounded creation).
        if !self.is_peer_initiated(id) {
            return Err(transport_error(
                0x05,
                frame_type,
                "peer referenced an unopened locally-initiated stream",
            ));
        }
        let kind_uni = is_uni(id);
        let kind = usize::from(kind_uni);
        let opened = id / 4 + 1;
        let live = self
            .streams
            .keys()
            .filter(|&&other| self.is_peer_initiated(other) && is_uni(other) == kind_uni)
            .count();
        if opened > self.recv_max_streams_sent[kind]
            || opened.saturating_sub(self.peer_streams_opened[kind])
                > MAX_PEER_STREAMS.saturating_sub(live) as u64
        {
            return Err(transport_error(
                0x04,
                frame_type,
                "peer exceeded the stream limit",
            ));
        }
        let bits = id & 3;
        for ordinal in self.peer_streams_opened[kind]..opened {
            let opened_id = ordinal * 4 + bits;
            let mut s = Stream::fresh();
            s.send_max = self.peer_send_limit(opened_id);
            self.streams.insert(opened_id, s);
            if kind_uni {
                self.accept_uni.push_back(opened_id);
            } else {
                self.accept_bidi.push_back(opened_id);
            }
        }
        self.peer_streams_opened[kind] = opened;
        Ok(())
    }
}

#[cfg(kani)]
mod packet_guard_proofs {
    use super::*;

    #[kani::proof]
    fn decoded_frame_admission_matrix() {
        let level: u8 = kani::any();
        let server: bool = kani::any();
        let frame_type: u8 = kani::any();
        kani::assume(level < 4 && frame_type <= 0x1e);
        let space = match level {
            0 => PacketSpace::Initial,
            1 => PacketSpace::Handshake,
            2 => PacketSpace::ZeroRtt,
            _ => PacketSpace::OneRtt,
        };
        let side = if server { Side::Server } else { Side::Client };
        // Independent finite table of decoded codepoints. Unknown frame errors
        // and client stateless 0-RTT rejection precede this shipping predicate.
        let allowed: u32 = match level {
            0 | 1 => 0x1000_004f,
            2 => 0x35ff_ff33,
            _ if server => 0x3fff_ff7f,
            _ => 0x7fff_ffff,
        };
        assert_eq!(
            frame_permitted(space, side, frame_type as u64),
            allowed & (1 << frame_type) != 0
        );
    }

    fn assert_peer_ack_decoding_for_exponent(exponent: u32) {
        let raw: u64 = kani::any();
        kani::assume(raw <= super::super::varint::MAX);
        let decoded = decoded_ack_delay(raw, exponent);
        let micros = (raw as u128) * (1u128 << exponent);
        assert_eq!(decoded.as_secs() as u128, micros / 1_000_000);
        assert_eq!(decoded.subsec_micros() as u128, micros % 1_000_000);
        assert_eq!(decoded.subsec_nanos() % 1_000, 0);
    }

    macro_rules! peer_ack_decoder_case {
        ($name:ident, $exponent:literal) => {
            #[kani::proof]
            #[kani::solver(z3)]
            fn $name() {
                assert_peer_ack_decoding_for_exponent($exponent);
            }
        };
    }

    // These independent proof cases exhaust the finite exponent domain. Every
    // case retains the complete 62-bit raw domain and the real decoder/checks.
    peer_ack_decoder_case!(peer_ack_decoding_exponent_00, 0);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_01, 1);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_02, 2);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_03, 3);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_04, 4);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_05, 5);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_06, 6);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_07, 7);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_08, 8);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_09, 9);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_10, 10);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_11, 11);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_12, 12);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_13, 13);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_14, 14);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_15, 15);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_16, 16);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_17, 17);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_18, 18);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_19, 19);
    peer_ack_decoder_case!(peer_ack_decoding_exponent_20, 20);

    #[kani::proof]
    fn peer_ack_recovery_caps_only_confirmed_data() {
        // Policy accepts any canonical Duration; decoding is a separate proof.
        let seconds: u64 = kani::any();
        let nanos: u32 = kani::any();
        let space: usize = kani::any();
        let confirmed: bool = kani::any();
        let max_ms: u16 = kani::any();
        kani::assume(nanos < 1_000_000_000);
        kani::assume(space <= SPACE_DATA && max_ms < (1 << 14));
        let peer_max = Duration::from_millis(max_ms as u64);
        let decoded = Duration::new(seconds, nanos);
        let actual = cap_decoded_peer_ack_delay(decoded, space, confirmed, peer_max);
        if space != SPACE_DATA {
            assert_eq!(actual, Duration::ZERO);
        } else if confirmed {
            assert_eq!(actual, decoded.min(peer_max));
        } else {
            assert_eq!(actual, decoded);
        }
    }

    #[kani::proof]
    fn peer_ack_pto_scope_requires_confirmation_only_for_data() {
        let space: usize = kani::any();
        let confirmed: bool = kani::any();
        let max_ms: u16 = kani::any();
        kani::assume(space <= SPACE_DATA && max_ms < (1 << 14));
        let peer_max = Duration::from_millis(max_ms as u64);
        assert_eq!(
            pto_space_eligible(space, confirmed),
            space != SPACE_DATA || confirmed
        );
        let extra = peer_ack_delay_for_pto(space, confirmed, peer_max);
        if space == SPACE_DATA && confirmed {
            assert_eq!(extra, peer_max);
        } else {
            assert_eq!(extra, Duration::ZERO);
        }
    }

    #[kani::proof]
    fn ack_count_accepts_first_second_and_immediate_packets_without_ack_of_ack() {
        let count: u8 = kani::any();
        kani::assume(count <= 2);
        let immediate: bool = kani::any();
        assert_eq!(ack_count_after_packet(count, false, immediate), count);
        assert!(ack_count_after_packet(count, true, immediate) <= 2);
        assert_eq!(ack_count_after_packet(0, true, false), 1);
        assert!(!ack_count_due(1, false));
        assert!(ack_count_due(1, true));
        assert!(ack_count_due(ack_count_after_packet(1, true, false), false));
        assert!(ack_count_due(ack_count_after_packet(0, true, true), false));
        assert!(!ack_count_due(0, true));
    }

    #[kani::proof]
    fn ack_delay_encoding_is_varint_bounded_and_does_not_clip_max_ack_delay() {
        let seconds: u64 = kani::any();
        let nanos: u32 = kani::any();
        kani::assume(nanos < 1_000_000_000);
        let elapsed = Duration::new(seconds, nanos);
        let encoded = encoded_ack_delay(elapsed);
        assert!(encoded < (1u64 << 62));
        assert_eq!(encoded_ack_delay(Duration::from_millis(40)), 5_000);
        assert_eq!(encoded_ack_delay(Duration::ZERO), 0);
    }

    fn arbitrary_phase() -> KeyPhaseState {
        KeyPhaseState {
            tx: kani::any(),
            rx: kani::any(),
            tx_first: kani::any(),
            tx_last: kani::any(),
            tx_acked: kani::any(),
            rx_min: kani::any(),
            rx_max: kani::any(),
            previous_max: kani::any(),
            update_ack_pending: kani::any(),
        }
    }

    #[kani::proof]
    fn key_phase_commit_requires_authenticated_fresh_ordered_packet() {
        let mut state = arbitrary_phase();
        let before = state;
        let pn: u64 = kani::any();
        let authenticated: bool = kani::any();
        let fresh: bool = kani::any();
        let kind: u8 = kani::any();
        let generation = match kind {
            0 => ReadGeneration::Previous,
            1 => ReadGeneration::Current,
            2 => ReadGeneration::Next,
            _ => ReadGeneration::Unavailable,
        };
        let valid = state.valid_receive(generation, pn);
        let committed = state.commit_receive(generation, pn, authenticated, fresh);
        assert_eq!(committed, authenticated && fresh && valid);
        if !committed {
            assert_eq!(state, before);
        } else {
            assert_eq!(state.tx, before.tx);
            assert_eq!(state.tx_acked, before.tx_acked);
            if generation == ReadGeneration::Next {
                assert!(before.rx < u64::MAX);
                assert_eq!(state.rx, before.rx + 1);
                assert_eq!(state.rx_min, Some(pn));
                assert_eq!(state.rx_max, Some(pn));
                assert!(state.update_ack_pending);
            } else {
                assert_eq!(state.rx, before.rx);
            }
        }
    }

    #[kani::proof]
    fn key_phase_expected_response_is_accepted_but_unsolicited_second_update_is_not() {
        let rx: u64 = kani::any();
        let frontier: u64 = kani::any();
        let pn: u64 = kani::any();
        kani::assume(rx < u64::MAX && frontier < pn);
        let mut state = KeyPhaseState {
            tx: rx + 1,
            rx,
            rx_min: Some(frontier),
            rx_max: Some(frontier),
            update_ack_pending: true,
            ..KeyPhaseState::default()
        };
        assert!(state.commit_receive(ReadGeneration::Next, pn, true, true));
        assert_eq!(state.rx, rx + 1);
        assert_eq!(state.tx, state.rx);
        assert_eq!(state.rx_min, Some(pn));
        assert!(state.update_ack_pending);
        let before = state;
        // No local initiation and no ACK of this peer generation: even a
        // correctly ordered, authenticated second update must remain rejected.
        if let Some(next_pn) = pn.checked_add(1) {
            assert!(!state.commit_receive(ReadGeneration::Next, next_pn, true, true));
            assert_eq!(state, before);
        }
    }

    #[kani::proof]
    fn key_phase_active_update_requires_confirmation_ack_and_checked_generation() {
        let state = arbitrary_phase();
        let confirmed: bool = kani::any();
        let next = state.active_successor(confirmed);
        if let Some(next) = next {
            assert!(confirmed && state.tx_acked && state.tx == state.rx);
            assert!(state.tx < u64::MAX);
            assert_eq!(next, state.tx + 1);
        } else {
            assert!(!confirmed || !state.tx_acked || state.tx != state.rx || state.tx == u64::MAX);
        }
    }

    #[kani::proof]
    fn key_phase_ack_must_cover_actual_current_generation_and_use_new_keys() {
        let mut state = arbitrary_phase();
        let before = state;
        let receive_generation: u64 = kani::any();
        let low: u64 = kani::any();
        let high: u64 = kani::any();
        let accepted = state.confirm(receive_generation, low, high);
        if accepted {
            assert!(receive_generation >= state.tx);
            assert!(low <= high);
            assert!(before.tx_first.is_some() && before.tx_last.is_some());
            assert!(low <= before.tx_last.unwrap() && high >= before.tx_first.unwrap());
            assert!(state.tx_acked);
        } else {
            assert_eq!(state, before);
        }
    }

    #[kani::proof]
    #[kani::unwind(40)] // Covers the fixed 34-byte exhaustion reason, with unwinding assertions.
    fn exhausted_key_cancels_protected_close_and_preserves_existing_reason() {
        let sealed: u64 = kani::any();
        let limit: u64 = kani::any();
        let code: u64 = kani::any();
        let frame_type: u64 = kani::any();
        let kind: u8 = kani::any();
        let mut closed = match kind {
            0 => None,
            1 => Some(CloseReason::LocalApp(code, Vec::new())),
            2 => Some(CloseReason::LocalTransport(code, frame_type, Vec::new())),
            3 => Some(CloseReason::PeerApp(code, Vec::new())),
            4 => Some(CloseReason::PeerTransport(code, frame_type, Vec::new())),
            _ => Some(CloseReason::IdleTimeout),
        };
        let mut pending = if kani::any() {
            Some((code, Some(frame_type), Vec::new()))
        } else {
            None
        };
        let closed_before = closed.clone();
        let pending_before = pending.clone();
        close_on_exhausted_data_key(sealed, limit, &mut closed, &mut pending);
        if sealed >= limit {
            assert!(closed.is_some());
            assert!(pending.is_none());
            if closed_before.is_some() {
                assert_eq!(closed, closed_before);
            }
        } else {
            assert_eq!(closed, closed_before);
            assert_eq!(pending, pending_before);
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

    fn assert_transport_error(error: QuicTlsError, expected: u64) {
        assert!(
            matches!(error, QuicTlsError::Transport { error_code, .. } if error_code == expected),
            "expected transport error {expected:#x}, got {error:?}"
        );
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
    fn selected_packet_key_opens_without_removing_header_protection_twice() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let keys = DirectionalKeys {
                packet: PacketKey::from_secret(suite, &vec![0x22; suite.hash_len()]).unwrap(),
                header: HeaderProtectionKey::from_secret(suite, &vec![0x11; suite.hash_len()])
                    .unwrap(),
            };
            let header = Header::Short {
                spin: false,
                key_phase: true,
                dcid: ConnectionId::new(&[]),
                packet_number: 17,
                pn_len: 1,
            };
            let frames = [Frame::Ping, Frame::Padding(20)];
            let mut packet = seal_packet(&keys, header, &frames);
            let opened = unprotect_packet_header(&keys.header, &mut packet, 0, None).unwrap();
            assert!(matches!(
                opened.header,
                Header::Short {
                    key_phase: true,
                    ..
                }
            ));
            let unprotected_header = packet[..opened.aad_len].to_vec();
            let range = open_packet_payload(&keys.packet, &mut packet, &opened).unwrap();
            assert_eq!(&packet[..opened.aad_len], &unprotected_header);
            assert_eq!(
                Iter::new(&packet[range])
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                frames
            );
        }
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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

    /// Server transport parameters with full test concurrency and receive windows.
    fn server_tp() -> Vec<u8> {
        let mut tp = TransportParameters::server(&[]);
        tp.initial_max_streams_bidi = MAX_PEER_STREAMS as u64;
        tp.initial_max_streams_uni = MAX_PEER_STREAMS as u64;
        tp.encode_server()
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
        let mut per_packet = Vec::new();
        let mut largest: Option<u64> = None;
        for d in &datagrams {
            let mut buf = d.clone();
            let (hdr, range) = open_packet(&initial_keys.local, &mut buf, 0, largest).unwrap();
            largest = Some(hdr.packet_number());
            for f in Iter::new(&buf[range]) {
                if let Frame::Crypto { offset, data } = f.unwrap() {
                    assert_eq!(offset as usize, crypto.len(), "contiguous CRYPTO offsets");
                    crypto.extend_from_slice(data);
                    per_packet.push(data.len());
                }
            }
        }
        assert_eq!(crypto[0], 0x01, "CRYPTO stream starts with ClientHello");
        // Safari cuts its ClientHello 999 + rest: every Initial but the last
        // carries exactly SAFARI_INITIAL_CRYPTO_CHUNK bytes.
        let (last, full) = per_packet.split_last().unwrap();
        assert!(
            full.iter().all(|&n| n == SAFARI_INITIAL_CRYPTO_CHUNK),
            "{per_packet:?}"
        );
        assert!(*last <= SAFARI_INITIAL_CRYPTO_CHUNK, "{per_packet:?}");
    }

    #[test]
    fn cancelled_empty_bidi_is_skipped_by_accept_and_the_request_rides_the_next() {
        let dcid = ConnectionId::new(&[0xc0, 0xff, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xab, 0xcd, 0xef, 0x01]),
        )
        .unwrap();
        drive(&mut client, &mut server);

        // Safari: cancel an unused request stream, then send the request on the next.
        let cancelled = client.open_bi();
        client.cancel_stream(cancelled, 0x10c);
        let request = client.open_bi();
        assert_eq!((cancelled, request), (0, 4));
        client.send_stream(request, b"request");
        drive(&mut client, &mut server);

        assert_eq!(server.stream_reset(cancelled), Some(0x10c));
        assert_eq!(
            server.accept_bi(),
            Some(request),
            "the cancelled stream is skipped"
        );
        assert_eq!(server.accept_bi(), None);
        assert_eq!(server.read_stream(request), b"request");
    }

    #[test]
    fn cancellation_waits_for_data_queued_before_it() {
        let dcid = ConnectionId::new(&[0xc0, 0xff, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xab, 0xcd, 0xef, 0x01]),
        )
        .unwrap();
        drive(&mut client, &mut server);

        // H3 control SETTINGS queued first, then the cancelled request stream.
        let control = client.open_uni();
        client.send_stream(control, b"control settings");
        let cancelled = client.open_bi();
        client.cancel_stream(cancelled, 0x10c);
        assert_eq!(client.next_stream_to_reset(), None, "control goes first");
        let now = Instant::now();
        client.poll_transmit(now).expect("control stream packet");
        assert_eq!(client.next_stream_to_reset(), Some(cancelled));
    }

    #[test]
    fn cancelling_an_already_reset_stream_resends_with_stop_sending() {
        let dcid = ConnectionId::new(&[0xc0, 0xff, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xab, 0xcd, 0xef, 0x01]),
        )
        .unwrap();
        drive(&mut client, &mut server);

        let id = client.open_bi();
        client.reset_stream(id, 0x10c);
        client.poll_transmit(Instant::now()).expect("RESET_STREAM");
        assert_eq!(client.next_stream_to_reset(), None);
        client.cancel_stream(id, 0x10c);
        assert_eq!(
            client.next_stream_to_reset(),
            Some(id),
            "re-armed with STOP_SENDING"
        );
    }

    #[test]
    fn coalesced_initial_and_handshake_still_draw_one_padded_initial_ack() {
        let dcid = ConnectionId::new(&[0xc0, 0xff, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xab, 0xcd, 0xef, 0x01]),
        )
        .unwrap();
        let now = Instant::now();
        while let Some(dg) = client.poll_transmit(now) {
            server.handle_datagram(&dg, now).unwrap();
        }
        // The server's whole first flight — Initial(s) then Handshake — in ONE
        // datagram: the Handshake packet arrives before the client could ACK.
        let mut flight = Vec::new();
        while let Some(dg) = server.poll_transmit(now) {
            flight.extend_from_slice(&dg);
        }
        client.handle_datagram(&flight, now).unwrap();

        let first = client.poll_transmit(now).expect("client reply");
        assert_eq!(first[0] & 0xb0, 0x80, "an Initial ACK leads the reply");
        assert!(first.len() >= MIN_INITIAL_DATAGRAM, "padded");
        assert!(
            client.spaces[SPACE_INITIAL].keys.is_none(),
            "Initial space discarded right after its ACK"
        );
    }

    #[test]
    fn client_acks_the_server_initial_flight_once_padded_to_1200() {
        let dcid = ConnectionId::new(&[0xc0, 0xff, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xab, 0xcd, 0xef, 0x01]),
        )
        .unwrap();
        let now = Instant::now();
        while let Some(dg) = client.poll_transmit(now) {
            server.handle_datagram(&dg, now).unwrap();
        }
        // Like the endpoint driver: deliver the server's flight one datagram at a
        // time, draining the client's output after each. The ServerHello spans
        // more than one Initial datagram, yet the client must ACK it exactly once.
        let mut server_flight = Vec::new();
        while let Some(dg) = server.poll_transmit(now) {
            server_flight.push(dg);
        }
        let mut client_initials = Vec::new();
        for dg in &server_flight {
            client.handle_datagram(dg, now).unwrap();
            while let Some(out) = client.poll_transmit(now) {
                if out[0] & 0xb0 == 0x80 {
                    client_initials.push(out);
                }
            }
        }
        assert_eq!(client_initials.len(), 1, "one Initial ACK for the flight");
        assert!(
            client_initials[0].len() >= MIN_INITIAL_DATAGRAM,
            "padded: {} bytes",
            client_initials[0].len()
        );
    }

    #[test]
    fn client_and_server_complete_a_quic_handshake_over_loopback() {
        let dcid = ConnectionId::new(&[0xc0, 0xff, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        // A dummy cover cert (the REALITY client accepts any) + a server TP blob.
        // Encoded once: the Safari encoding's id order is randomized per call.
        let server_tp = server_tp();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp.clone(),
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
            Some(server_tp.as_ref()),
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
            client
                .next_packet_keys
                .as_ref()
                .is_some_and(|next| next.local.is_some() && next.remote.is_some()),
            "client 1-RTT key update ready"
        );
        assert!(
            server
                .next_packet_keys
                .as_ref()
                .is_some_and(|next| next.local.is_some() && next.remote.is_some()),
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
    fn quic_guard_regression_zero_rtt_reflection_and_server_delivery() {
        let stek = Zeroizing::new([0x44u8; 32]);
        let cover = || Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]);

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
                assert_eq!(
                    rclient.data_packets_sealed, 0,
                    "early data has a separate key budget"
                );
                assert!(rclient.zero_rtt_packets_sealed > 0);
                let last_recv = rclient.last_recv_time;
                let received = rclient.spaces[SPACE_DATA].recv.to_ack(0);
                let largest = rclient.spaces[SPACE_DATA].recv.largest();
                let ack_pending = rclient.spaces[SPACE_DATA].ack_pending;
                let largest_time = rclient.spaces[SPACE_DATA].largest_recv_time;
                let ecn = rclient.spaces[SPACE_DATA].recv_ecn;
                // Reflect the actual emitted early-data ciphertext unchanged,
                // before delivering it to the intended server.
                rclient
                    .handle_datagram_ecn(&dg, EcnCodepoint::Ce, now + Duration::from_secs(1))
                    .unwrap();
                assert!(
                    rclient.read_stream(RELAY_STREAM_ID).is_empty(),
                    "a client must never read its own reflected 0-RTT bytes"
                );
                assert_eq!(rclient.last_recv_time, last_recv);
                assert_eq!(rclient.spaces[SPACE_DATA].recv.to_ack(0), received);
                assert_eq!(rclient.spaces[SPACE_DATA].recv.largest(), largest);
                assert_eq!(rclient.spaces[SPACE_DATA].ack_pending, ack_pending);
                assert_eq!(rclient.spaces[SPACE_DATA].largest_recv_time, largest_time);
                let after = rclient.spaces[SPACE_DATA].recv_ecn;
                assert_eq!(
                    (after.ect0, after.ect1, after.ce),
                    (ecn.ect0, ecn.ect1, ecn.ce)
                );
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
        let cover = || Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]);

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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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

    /// RFC 9000 §8.1 anti-amplification (findings #203/#216): before the client's
    /// address is validated, the server's egress — here inflated by a multi-KB
    /// certificate chain — is capped at 3x the bytes received, so a spoofed Initial
    /// cannot reflect the full handshake flight at a victim. The clipped flight is
    /// not a deadlock: the client's answering packets grow the budget and its first
    /// Handshake-level packet validates the address, after which the rest of the
    /// flight flows and the handshake completes.
    #[test]
    fn unvalidated_server_egress_is_capped_at_three_times_received() {
        let dcid = ConnectionId::new(&[0xa3; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0xab; 16 * 1024]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x3a, 0x3a, 0x3a, 0x3a]),
        )
        .unwrap();
        let now = Instant::now();

        // Deliver the full ClientHello flight, then drain the server WITHOUT letting
        // the client answer yet: everything it emits must fit within 3x what it
        // received. (The flight is still delivered so the exchange can resume below.)
        let mut received = 0usize;
        while let Some(dg) = client.poll_transmit(now) {
            received += dg.len();
            server.handle_datagram(&dg, now).unwrap();
        }
        let mut sent = 0usize;
        while let Some(dg) = server.poll_transmit(now) {
            sent += dg.len();
            client.handle_datagram(&dg, now).unwrap();
        }
        assert!(
            sent <= 3 * received,
            "unvalidated server egress ({sent} bytes) exceeds 3x the {received} received"
        );
        // The cap actually bit: part of the oversized flight is still unsent.
        let hs = &server.spaces[SPACE_HANDSHAKE];
        assert!(
            hs.crypto_send_off < hs.crypto_send.len(),
            "the oversized flight should have been clipped by the amplification cap"
        );
        assert!(!server.peer_addr_validated);

        // Let the exchange continue: the handshake still completes, and the cap is
        // lifted once the client's Handshake-level packets prove its address.
        drive(&mut client, &mut server);
        assert!(
            server.peer_addr_validated,
            "a Handshake-level packet from the client validates its address"
        );
        assert!(!client.is_handshaking() && !server.is_handshaking());
    }

    /// Ping-pong datagrams between two connections until neither has anything more
    /// to send (handshake CRYPTO + ACKs, then 1-RTT data). Lossless, so a single
    /// `now` suffices (no timers fire).
    fn drive(a: &mut Connection, b: &mut Connection) {
        drive_at(a, b, Instant::now());
    }

    fn drive_at(a: &mut Connection, b: &mut Connection, now: Instant) {
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

    /// Explicitly advance a caller-owned monotonic clock while ACK debt remains.
    /// A lack of output at a fixed instant is not treated as quiescence.
    fn drive_acked_at(a: &mut Connection, b: &mut Connection, now: &mut Instant) {
        for _ in 0..32 {
            drive_at(a, b, *now);
            let next = [a.pending_data_ack_deadline(), b.pending_data_ack_deadline()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next else {
                return;
            };
            *now = (*now).max(next);
            a.handle_timeout(*now);
            b.handle_timeout(*now);
        }
        panic!("ACK debt must settle in bounded timer steps");
    }

    fn connected_pair() -> (Connection, Connection) {
        let mut client = Connection::new_client(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x62; 8]),
            ConnectionId::new(&[]),
        )
        .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x63; 4]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(client.handshake_confirmed && server.handshake_confirmed);
        (client, server)
    }

    fn handshake_start(suite: CipherSuite) -> (Connection, Connection) {
        let client = Connection::new_client(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x71; 8]),
            ConnectionId::new(&[]),
        )
        .unwrap();
        let mut tls = ServerHandshake::new(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            None,
        )
        .unwrap();
        tls.set_test_suite(suite);
        let mut server = Connection::new_inner(
            Side::Server,
            Box::new(tls),
            ConnectionId::new(&[]),
            ConnectionId::new(&[]),
            ConnectionId::new(&[0x72; 4]),
            1,
            3,
        );
        server.recv_max_streams_sent = [MAX_PEER_STREAMS as u64; 2];
        (client, server)
    }

    fn handshake_start_with_transport_params(
        client_tp: Vec<u8>,
        server_tp: Vec<u8>,
    ) -> (Connection, Connection) {
        let dcid = ConnectionId::new(&[0x73; 8]);
        let tls = ClientHandshake::new(
            client_config(),
            QUIC_VERSION_V1,
            "example.com",
            client_tp,
            dcid.as_slice(),
        )
        .unwrap();
        let mut client = Connection::new_inner(
            Side::Client,
            Box::new(tls),
            dcid,
            dcid,
            ConnectionId::new(&[]),
            0,
            2,
        );
        client.spaces[SPACE_INITIAL].keys = Some(initial_keys(dcid.as_slice(), Side::Client));
        client.pump_write();
        let server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp,
            ConnectionId::new(&[0x74; 4]),
        )
        .unwrap();
        (client, server)
    }

    fn with_ack_transport_params(mut blob: Vec<u8>, exponent: u64, max_delay: u64) -> Vec<u8> {
        for (id, value) in [(0x0a, exponent), (0x0b, max_delay)] {
            super::super::varint::encode(id, &mut blob);
            super::super::varint::encode(super::super::varint::size(value) as u64, &mut blob);
            super::super::varint::encode(value, &mut blob);
        }
        blob
    }

    #[test]
    fn peer_ack_parameters_are_applied_by_both_authenticated_handshakes_without_streams() {
        let client_tp = with_ack_transport_params(
            TransportParameters::safari_client(&[]).encode_safari_client(),
            6,
            7,
        );
        let server_tp = with_ack_transport_params(server_tp(), 10, 100);
        let (mut client, mut server) = handshake_start_with_transport_params(client_tp, server_tp);
        drive(&mut client, &mut server);
        assert!(client.handshake_confirmed && server.handshake_confirmed);
        assert!(client.streams.is_empty() && server.streams.is_empty());
        assert_eq!(client.peer_ack_delay_exponent, 10);
        assert_eq!(client.peer_max_ack_delay, Duration::from_millis(100));
        assert_eq!(server.peer_ack_delay_exponent, 6);
        assert_eq!(server.peer_max_ack_delay, Duration::from_millis(7));
        assert!(client.peer_ack_params_applied && server.peer_ack_params_applied);
        for (connection, peer_max) in [(&client, 100), (&server, 7)] {
            for space in [SPACE_INITIAL, SPACE_HANDSHAKE] {
                assert_eq!(connection.pto_duration(space), connection.rtt.pto_base());
            }
            assert_eq!(
                connection.pto_duration(SPACE_DATA),
                connection.rtt.pto_base() + Duration::from_millis(peer_max)
            );
            assert_eq!(
                connection.drain_duration(),
                3 * connection.pto_duration(SPACE_DATA)
            );
        }
    }

    fn assert_encrypted_ack_rtt(
        sender: &mut Connection,
        peer: &mut Connection,
        now: Instant,
        raw_delay: u64,
        expected_delay: Duration,
    ) {
        sender.rtt = RttEstimator::new();
        sender.rtt.update(Duration::ZERO, Duration::from_millis(10));
        let mut expected = sender.rtt.clone();
        expected.update(expected_delay, Duration::from_millis(50));
        let pn = sender.spaces[SPACE_DATA].send.peek();
        let packet = sender.seal_data_packet(
            &[Frame::Ping, Frame::Padding(3)],
            true,
            SentContent::default(),
            now,
        );
        peer.handle_datagram(&packet, now + Duration::from_millis(5))
            .unwrap();
        let now = now + Duration::from_millis(50);
        let ack = peer.seal_data_packet(
            &[
                Frame::Ack(Ack {
                    largest: pn,
                    delay: raw_delay,
                    ranges: vec![(pn, pn)],
                    ecn: None,
                }),
                Frame::Padding(3),
            ],
            false,
            SentContent::default(),
            now,
        );
        sender.handle_datagram(&ack, now).unwrap();
        assert_eq!(sender.rtt.smoothed(), expected.smoothed());
        assert_eq!(sender.rtt.rttvar(), expected.rttvar());
    }

    #[test]
    fn peer_ack_parameters_decode_real_encrypted_acks_for_both_roles() {
        let client_tp = with_ack_transport_params(
            TransportParameters::safari_client(&[]).encode_safari_client(),
            6,
            7,
        );
        let server_tp = with_ack_transport_params(server_tp(), 10, 100);
        let (mut client, mut server) = handshake_start_with_transport_params(client_tp, server_tp);
        let mut now = Instant::now();
        drive_acked_at(&mut client, &mut server, &mut now);
        assert_encrypted_ack_rtt(
            &mut client,
            &mut server,
            now,
            20,
            Duration::from_micros(20_480),
        );
        now += Duration::from_millis(100);
        assert_encrypted_ack_rtt(&mut server, &mut client, now, 320, Duration::from_millis(7));
    }

    #[test]
    fn peer_max_ack_delay_caps_rtt_only_after_confirmation() {
        let client_tp = TransportParameters::safari_client(&[]).encode_safari_client();
        let server_tp = with_ack_transport_params(server_tp(), 3, 5);
        let (mut client, mut server) = handshake_start_with_transport_params(client_tp, server_tp);
        let mut now = Instant::now();
        while let Some(packet) = client.poll_transmit(now) {
            server.handle_datagram(&packet, now).unwrap();
        }
        while let Some(packet) = server.poll_transmit(now) {
            client.handle_datagram(&packet, now).unwrap();
        }
        while let Some(packet) = client.poll_transmit(now) {
            server.handle_datagram(&packet, now).unwrap();
        }
        assert!(server.handshake_confirmed && !client.handshake_confirmed);
        assert_eq!(client.peer_max_ack_delay, Duration::from_millis(5));
        assert_encrypted_ack_rtt(
            &mut client,
            &mut server,
            now,
            5_000,
            Duration::from_millis(40),
        );
        assert!(!client.handshake_confirmed);
        now += Duration::from_millis(100);
        drive_acked_at(&mut client, &mut server, &mut now);
        assert!(client.handshake_confirmed);
        assert_encrypted_ack_rtt(
            &mut client,
            &mut server,
            now,
            5_000,
            Duration::from_millis(5),
        );
    }

    #[test]
    fn invalid_peer_ack_parameters_fail_atomically_before_coalesced_one_rtt_data() {
        let client_base = TransportParameters::safari_client(&[]).encode_safari_client();
        let server_base = server_tp();
        let invalid_parameters = [
            with_ack_transport_params(Vec::new(), 21, 25),
            with_ack_transport_params(Vec::new(), 3, 1 << 14),
            vec![0x0a, 0x00],
            vec![0x0b, 0x02, 0x01, 0x01],
            vec![0x0a, 0x01, 0x03, 0x0a, 0x01, 0x03],
        ];
        for receiver_is_client in [false, true] {
            for invalid in &invalid_parameters {
                let mut client_tp = client_base.clone();
                let mut server_tp = server_base.clone();
                if receiver_is_client {
                    server_tp.extend(invalid);
                } else {
                    client_tp.extend(invalid);
                }
                let (mut client, mut server) =
                    handshake_start_with_transport_params(client_tp, server_tp);
                let now = Instant::now();
                let mut initial_error = None;
                while let Some(packet) = client.poll_transmit(now) {
                    if let Err(error) = server.handle_datagram(&packet, now) {
                        initial_error = Some(error);
                        break;
                    }
                }
                if !receiver_is_client {
                    // Invalid CH parameters now fail on the complete Initial
                    // CRYPTO input. Do not keep driving a rejected handshake
                    // merely to manufacture later authenticated STREAM keys.
                    assert_transport_error(initial_error.expect("invalid CH rejected early"), 0x08);
                    assert!(server.is_handshaking());
                    assert!(!server.peer_transport_params_prevalidated);
                    assert!(!server.peer_ack_params_applied);
                    assert_eq!(server.peer_ack_delay_exponent, ACK_DELAY_EXPONENT);
                    assert_eq!(server.peer_max_ack_delay, MAX_ACK_DELAY);
                    assert!(server.accept_uni().is_none());
                    assert!(server.read_stream(2).is_empty());
                    assert!(server.spaces[SPACE_DATA].recv.largest().is_none());
                    assert!(server.spaces[SPACE_INITIAL].keys.is_some());
                    assert!(server.spaces[SPACE_HANDSHAKE].keys.is_none());
                    assert!(server.spaces[SPACE_DATA].keys.is_none());
                    assert_invalid_parameter_close(
                        &mut client,
                        &mut server,
                        PacketSpace::Initial,
                        now,
                    );
                    continue;
                }
                assert!(initial_error.is_none());
                assert!(!server.peer_ack_params_applied);
                assert_eq!(server.peer_ack_delay_exponent, ACK_DELAY_EXPONENT);
                assert_eq!(server.peer_max_ack_delay, MAX_ACK_DELAY);
                let (sender, receiver, stream) = if receiver_is_client {
                    (&mut server, &mut client, 3)
                } else {
                    while let Some(packet) = server.poll_transmit(now) {
                        client.handle_datagram(&packet, now).unwrap();
                    }
                    (&mut client, &mut server, 2)
                };
                let mut flight = Vec::new();
                while let Some(packet) = sender.poll_transmit(now) {
                    // A short-header packet must be last in a valid coalesced
                    // datagram. Hold control-only 1-RTT output; append one STREAM
                    // packet after the complete long-header handshake flight.
                    if packet::first_packet_space(&packet) != Some(PacketSpace::OneRtt) {
                        flight.extend(packet);
                    }
                }
                let data = sender.seal_data_packet(
                    &[Frame::Stream {
                        id: stream,
                        offset: 0,
                        fin: false,
                        data: b"must not publish",
                    }],
                    true,
                    SentContent::default(),
                    now,
                );
                flight.extend(data);
                let result = receiver.handle_datagram(&flight, now);
                assert!(
                    matches!(
                        &result,
                        Err(QuicTlsError::Transport {
                            error_code: 0x08,
                            ..
                        })
                    ),
                    "client={receiver_is_client}, invalid={invalid:?}, result={result:?}"
                );
                // Complete invalid EE input may now fail before Finished is
                // consumed. Neither early validation nor authenticated adoption
                // is allowed to commit state on that failure.
                assert!(!receiver.peer_transport_params_prevalidated);
                assert!(!receiver.peer_ack_params_applied);
                assert_eq!(receiver.peer_ack_delay_exponent, ACK_DELAY_EXPONENT);
                assert_eq!(receiver.peer_max_ack_delay, MAX_ACK_DELAY);
                assert!(receiver.accept_uni().is_none());
                assert!(receiver.read_stream(stream).is_empty());
                assert!(receiver.spaces[SPACE_DATA].recv.largest().is_none());
                assert_invalid_parameter_close(sender, receiver, PacketSpace::Handshake, now);
            }
        }
    }

    #[test]
    fn remembered_ack_parameters_are_not_applied_before_the_new_authenticated_handshake() {
        let stek = Zeroizing::new([0x49; 32]);
        let cover = || Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]);
        let mut client = Connection::new_client(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x75; 8]),
            ConnectionId::new(&[]),
        )
        .unwrap();
        let mut server = Connection::new_server_with_stek(
            cover(),
            &server_key(),
            vec![b"h3".to_vec()],
            with_ack_transport_params(server_tp(), 10, 100),
            ConnectionId::new(&[0x76; 4]),
            Some(stek.clone()),
        )
        .unwrap();
        drive(&mut client, &mut server);
        let ticket = client.take_session_ticket(1_000_000).unwrap();
        assert_eq!(
            TransportParameters::read(&ticket.peer_transport_params)
                .unwrap()
                .ack_delay_exponent,
            10
        );
        let mut resumed = Connection::new_client_resumption(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x77; 8]),
            ConnectionId::new(&[]),
            &ticket,
            1_001_000,
        )
        .unwrap();
        assert!(!resumed.peer_ack_params_applied);
        assert_eq!(resumed.peer_ack_delay_exponent, 3);
        assert_eq!(resumed.peer_max_ack_delay, Duration::from_millis(25));
        assert!(
            resumed.send_max_data > 0,
            "remembered flow credit remains usable"
        );
        let mut peer = Connection::new_server_with_stek(
            cover(),
            &server_key(),
            vec![b"h3".to_vec()],
            with_ack_transport_params(server_tp(), 6, 7),
            ConnectionId::new(&[0x78; 4]),
            Some(stek),
        )
        .unwrap();
        resumed.send_stream(RELAY_STREAM_ID, b"permitted early data");
        let now = Instant::now();
        while let Some(packet) = resumed.poll_transmit(now) {
            peer.handle_datagram(&packet, now).unwrap();
        }
        assert!(peer.is_handshaking() && peer.zero_rtt_keys_installed());
        assert!(!peer.peer_ack_params_applied);
        assert_eq!(peer.read_stream(RELAY_STREAM_ID), b"permitted early data");
        drive_at(&mut resumed, &mut peer, now);
        assert!(resumed.peer_ack_params_applied);
        assert_eq!(resumed.peer_ack_delay_exponent, 6);
        assert_eq!(resumed.peer_max_ack_delay, Duration::from_millis(7));
    }

    fn ack_parameter_resumption_ticket() -> (ClientTicket, Zeroizing<[u8; 32]>) {
        let stek = Zeroizing::new([0x4a; 32]);
        let mut client = Connection::new_client(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x79; 8]),
            ConnectionId::new(&[]),
        )
        .unwrap();
        let mut server = Connection::new_server_with_stek(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            with_ack_transport_params(server_tp(), 10, 100),
            ConnectionId::new(&[0x7a; 4]),
            Some(stek.clone()),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());
        let ticket = client.take_session_ticket(1_000_000).unwrap();
        assert_eq!(ticket.alpn, b"h3");
        assert!(!ticket.ticket.is_empty());
        (ticket, stek)
    }

    const ACK_PARAMETER_EARLY_DATA: &[u8] = b"early STREAM under the new ClientHello";

    fn assert_invalid_parameter_close(
        peer: &mut Connection,
        rejected: &mut Connection,
        expected_space: PacketSpace,
        now: Instant,
    ) {
        let mut packet = rejected
            .poll_transmit(now)
            .expect("transport close is reachable");
        assert_eq!(packet::first_packet_space(&packet), Some(expected_space));
        assert_eq!(packet::long_packet_len(&packet), Some(packet.len()));
        let original = packet.clone();
        let space = space_index(expected_space);
        let (_, range) = open_packet(
            &peer.spaces[space]
                .keys
                .as_ref()
                .expect("peer can read close space")
                .remote,
            &mut packet,
            peer.scid.len(),
            peer.spaces[space].recv.largest(),
        )
        .unwrap();
        let frames: Vec<_> = Iter::new(&packet[range]).collect::<Result<_, _>>().unwrap();
        let mut close_count = 0;
        for frame in frames {
            match frame {
                Frame::Padding(_) => {}
                Frame::Close(close) => {
                    close_count += 1;
                    assert!(!close.application);
                    assert_eq!((close.error_code, close.frame_type), (0x08, 0x06));
                    assert_eq!(close.reason, b"invalid peer transport parameters");
                }
                frame => panic!("invalid CH/EE must not flush queued CRYPTO or STREAM: {frame:?}"),
            }
        }
        assert_eq!(close_count, 1);
        peer.handle_datagram(&original, now).unwrap();
        assert!(matches!(
            peer.close_reason(),
            Some(CloseReason::PeerTransport(0x08, 0x06, _))
        ));
        assert!(
            rejected.poll_transmit(now).is_none(),
            "only the terminal close is sent"
        );
    }

    fn resumption_first_flight_with_client_transport_params(
        ticket: &ClientTicket,
        stek: Zeroizing<[u8; 32]>,
        client_tp: Vec<u8>,
        dcid_byte: u8,
    ) -> (Connection, Connection, Vec<u8>) {
        let dcid = ConnectionId::new(&[dcid_byte; 8]);
        let scid = ConnectionId::new(&[]);
        let local_tp = TransportParameters::safari_client(scid.as_slice());
        // Rebuild the actual ClientHello with this raw TP vector. The real TLS
        // constructor recomputes its PSK binder and 0-RTT traffic keys over that
        // exact ClientHello; this never edits an already-authenticated flight.
        let tls = ClientHandshake::new_resumption(
            client_config(),
            QUIC_VERSION_V1,
            "example.com",
            client_tp,
            dcid.as_slice(),
            ticket,
            1_001_000,
        )
        .unwrap();
        // Mirror new_client_inner, changing only the raw ClientHello TP input.
        let mut client = Connection::new_inner(Side::Client, Box::new(tls), dcid, dcid, scid, 0, 2);
        client.recv_max_streams_sent = [
            local_tp.initial_max_streams_bidi,
            local_tp.initial_max_streams_uni,
        ];
        client.spaces[SPACE_INITIAL].keys = Some(initial_keys(dcid.as_slice(), Side::Client));
        client.apply_remembered_transport_params(&ticket.peer_transport_params);
        client.pump_write();
        assert!(client.is_handshaking() && client.zero_rtt_keys_installed());
        assert!(client.spaces[SPACE_DATA].keys.is_none());
        assert!(!client.peer_ack_params_applied);
        assert_eq!(client.peer_ack_delay_exponent, ACK_DELAY_EXPONENT);
        assert_eq!(client.peer_max_ack_delay, MAX_ACK_DELAY);
        client.send_stream(RELAY_STREAM_ID, ACK_PARAMETER_EARLY_DATA);
        let peer = Connection::new_server_with_stek(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            with_ack_transport_params(server_tp(), 10, 100),
            ConnectionId::new(&[dcid_byte; 4]),
            Some(stek),
        )
        .unwrap();
        let mut flight = Vec::new();
        let mut initial_count = 0;
        let mut early_count = 0;
        let now = Instant::now();
        while let Some(datagram) = client.poll_transmit(now) {
            match packet::first_packet_space(&datagram) {
                Some(PacketSpace::Initial) => {
                    assert_eq!(early_count, 0, "all Initial CRYPTO precedes 0-RTT");
                    initial_count += 1;
                }
                Some(PacketSpace::ZeroRtt) => early_count += 1,
                space => panic!("unexpected first-flight packet space: {space:?}"),
            }
            flight.extend(datagram);
        }
        assert!(initial_count > 0 && early_count > 0);
        assert!(
            client.is_handshaking(),
            "no server flight or Finished was exchanged"
        );
        (client, peer, flight)
    }

    #[test]
    fn invalid_new_client_ack_parameters_reject_resumption_before_coalesced_zero_rtt_stream() {
        let (ticket, stek) = ack_parameter_resumption_ticket();
        let base = TransportParameters::safari_client(&[]).encode_safari_client();
        let invalid = [
            ("exponent21", with_ack_transport_params(Vec::new(), 21, 25)),
            (
                "max_delay16384",
                with_ack_transport_params(Vec::new(), 3, 1 << 14),
            ),
            ("empty_exponent", vec![0x0a, 0x00]),
            ("trailing_max_delay", vec![0x0b, 0x02, 0x01, 0x01]),
            (
                "duplicate_exponent",
                vec![0x0a, 0x01, 0x03, 0x0a, 0x01, 0x03],
            ),
        ];
        let mut failures = Vec::new();
        for (index, (case, invalid_tp)) in invalid.into_iter().enumerate() {
            let mut client_tp = base.clone();
            client_tp.extend(invalid_tp);
            let (mut client, mut peer, flight) =
                resumption_first_flight_with_client_transport_params(
                    &ticket,
                    stek.clone(),
                    client_tp,
                    0x80 + index as u8,
                );
            // Deliver the actual Initial(s) and then 0-RTT in ONE datagram, so
            // packet ordering cannot hide validation behind another driver turn.
            let result = peer.handle_datagram(&flight, Instant::now());
            let published = peer.read_stream(RELAY_STREAM_ID);
            let accepted = peer.accept_bi();
            let rejected = matches!(
                &result,
                Err(QuicTlsError::Transport {
                    error_code: 0x08,
                    ..
                })
            );
            let default_ack = !peer.peer_ack_params_applied
                && !peer.peer_transport_params_prevalidated
                && peer.peer_ack_delay_exponent == ACK_DELAY_EXPONENT
                && peer.peer_max_ack_delay == MAX_ACK_DELAY;
            if !rejected || !published.is_empty() || accepted.is_some() || !default_ack {
                failures.push(format!(
                    "{case}: result={result:?}, published={published:?}, accepted={accepted:?}, \
                     ack_applied={}, exponent={}, max_delay={:?}",
                    peer.peer_ack_params_applied,
                    peer.peer_ack_delay_exponent,
                    peer.peer_max_ack_delay,
                ));
            }
            if rejected {
                assert!(peer.spaces[SPACE_INITIAL].keys.is_some());
                assert!(peer.spaces[SPACE_HANDSHAKE].keys.is_none());
                assert!(peer.spaces[SPACE_DATA].keys.is_none());
                assert!(!peer.zero_rtt_keys_installed());
                assert_invalid_parameter_close(
                    &mut client,
                    &mut peer,
                    PacketSpace::Initial,
                    Instant::now(),
                );
            }
        }
        // A valid ticket holder is already permitted to send early data. This
        // pins the chosen invalid-TP rejection boundary, not an auth-bypass or
        // a claim that the RFC requires all early bytes to await Finished.
        assert!(
            failures.is_empty(),
            "invalid resumption TP outcomes: {failures:#?}"
        );
    }

    fn frame_admission_resumption_pair(
        ticket: &ClientTicket,
        stek: Zeroizing<[u8; 32]>,
        now: Instant,
    ) -> (Connection, Connection) {
        let (client, mut server, flight) = resumption_first_flight_with_client_transport_params(
            ticket,
            stek,
            TransportParameters::safari_client(&[]).encode_safari_client(),
            0x91,
        );
        let mut remaining = flight.as_slice();
        while !remaining.is_empty() {
            let length = packet::long_packet_len(remaining).unwrap();
            let (packet, rest) = remaining.split_at(length);
            if packet::first_packet_space(packet) == Some(PacketSpace::Initial) {
                server.handle_datagram(packet, now).unwrap();
            }
            // Withhold the fixture's early STREAM. Each test seals fresh frames
            // with the actual resumed ClientHello's installed traffic keys.
            remaining = rest;
        }
        assert!(server.zero_rtt_keys_installed() && server.is_handshaking());
        assert!(server.peer_transport_params_prevalidated);
        assert!(server.spaces[SPACE_HANDSHAKE].keys.is_some());
        assert!(server.spaces[SPACE_DATA].keys.is_some());
        (client, server)
    }

    fn seal_early_frames(client: &mut Connection, frames: &[Frame], now: Instant) -> Vec<u8> {
        assert!(client.is_handshaking() && client.zero_rtt_keys_installed());
        let pn = client.allocate_packet_number(SPACE_DATA);
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = client.make_zero_rtt_header(pn, pn_len);
        let packet = seal_packet(
            &client.zero_rtt_keys.as_ref().unwrap().local,
            header,
            frames,
        );
        client.record_sent(
            SPACE_DATA,
            pn,
            packet.len(),
            true,
            SentContent::default(),
            now,
        );
        packet
    }

    #[test]
    fn frame_admission_rejects_forbidden_zero_rtt_before_effects_and_remains_terminal() {
        let (ticket, stek) = ack_parameter_resumption_ticket();
        let now = Instant::now();
        let mut failures = Vec::new();
        for frame_type in [0x02, 0x03, 0x06, 0x07, 0x19, 0x1b, 0x1e] {
            let (mut client, mut server) =
                frame_admission_resumption_pair(&ticket, stek.clone(), now);
            // ACK a genuinely emitted server Application packet, not an unsent
            // PN that the independent ACK-range guard would already reject.
            server.send_stream(1, b"actual server Application packet");
            let mut data_sent = false;
            while let Some(packet) = server.poll_transmit(now) {
                data_sent |= packet::first_packet_space(&packet) == Some(PacketSpace::OneRtt);
                // Never deliver the server flight: the client must retain its
                // actual 0-RTT keys and still be waiting for ServerHello.
            }
            assert!(data_sent);
            let sent_pn = server.spaces[SPACE_DATA].send.peek() - 1;
            let forbidden = match frame_type {
                0x02 | 0x03 => Frame::Ack(Ack {
                    largest: sent_pn,
                    delay: 0,
                    ranges: vec![(sent_pn, sent_pn)],
                    ecn: (frame_type == 0x03).then_some(super::super::frame::EcnCounts {
                        ect0: 0,
                        ect1: 0,
                        ce: 0,
                    }),
                }),
                0x06 => Frame::Crypto {
                    offset: 1,
                    data: b"future CRYPTO",
                },
                0x07 => Frame::NewToken { token: b"token" },
                0x19 => Frame::RetireConnectionId(0),
                0x1b => Frame::PathResponse(7),
                0x1e => Frame::HandshakeDone,
                _ => unreachable!(),
            };
            let marker = Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: b"must not publish",
            };
            let packet =
                seal_early_frames(&mut client, &[forbidden, marker, Frame::Padding(3)], now);
            let in_flight = server.spaces[SPACE_DATA].sent.in_flight();
            let result = server.handle_datagram(&packet, now);
            // Deliberately ignore the first error, as the handshake driver can.
            let next = seal_early_frames(
                &mut client,
                &[Frame::Stream {
                    id: 4,
                    offset: 0,
                    fin: false,
                    data: b"later datagram",
                }],
                now,
            );
            let followup = server.handle_datagram(&next, now);
            let first = server.read_stream(0);
            let later = server.read_stream(4);
            let pending = server.spaces[SPACE_DATA].crypto_pending.len();
            let rejected = matches!(&result, Err(QuicTlsError::Transport {
                error_code: 0x0a, frame_type: actual, ..
            }) if *actual == frame_type);
            if !rejected
                || followup.is_err()
                || !first.is_empty()
                || !later.is_empty()
                || pending != 0
                || server.spaces[SPACE_DATA].sent.in_flight() != in_flight
                || !matches!(server.close_reason(), Some(CloseReason::LocalTransport(0x0a, actual, _)) if *actual == frame_type)
            {
                failures.push(format!("type={frame_type:#x}, result={result:?}, followup={followup:?}, first={first:?}, later={later:?}, crypto_pending={pending}, sent_in_flight={in_flight}->{}, close={:?}", server.spaces[SPACE_DATA].sent.in_flight(), server.close_reason()));
            }
        }
        assert!(
            failures.is_empty(),
            "frame admission outcomes: {failures:#?}"
        );
    }

    #[test]
    fn frame_admission_server_rejects_client_only_one_rtt_frames() {
        let now = Instant::now();
        let mut failures = Vec::new();
        for (frame_type, frame) in [
            (0x07, Frame::NewToken { token: b"token" }),
            (0x1e, Frame::HandshakeDone),
        ] {
            let (mut client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
            let packet = client.test_data_packet(&[
                frame,
                Frame::Stream {
                    id: 0,
                    offset: 0,
                    fin: false,
                    data: b"must not publish",
                },
            ]);
            let result = server.handle_datagram(&packet, now);
            let followup = client.test_data_packet(&[Frame::Stream {
                id: 4,
                offset: 0,
                fin: false,
                data: b"later datagram",
            }]);
            server.handle_datagram(&followup, now).unwrap();
            let first = server.read_stream(0);
            let later = server.read_stream(4);
            if !matches!(&result, Err(QuicTlsError::Transport { error_code: 0x0a, frame_type: actual, .. }) if *actual == frame_type)
                || !first.is_empty()
                || !later.is_empty()
                || !matches!(server.close_reason(), Some(CloseReason::LocalTransport(0x0a, actual, _)) if *actual == frame_type)
            {
                failures.push(format!("type={frame_type:#x}, result={result:?}, first={first:?}, later={later:?}, close={:?}", server.close_reason()));
            }
        }
        assert!(failures.is_empty(), "wrong-role outcomes: {failures:#?}");
    }

    #[test]
    fn frame_admission_close_reaches_client_before_and_after_server_flight() {
        let (ticket, stek) = ack_parameter_resumption_ticket();
        let now = Instant::now();
        for received_server_flight in [false, true] {
            let (mut client, mut server) =
                frame_admission_resumption_pair(&ticket, stek.clone(), now);
            // Seal while genuine early keys exist, then optionally delay this
            // datagram until the client has read the server's handshake flight.
            let illegal = seal_early_frames(
                &mut client,
                &[
                    Frame::Crypto {
                        offset: 1,
                        data: b"future CRYPTO",
                    },
                    Frame::Padding(3),
                ],
                now,
            );
            if received_server_flight {
                while let Some(packet) = server.poll_transmit(now) {
                    client.handle_datagram(&packet, now).unwrap();
                }
                // Poll the client's Initial ACK/Finished, but withhold all of
                // them. This discards its Initial keys without confirming server.
                while client.poll_transmit(now).is_some() {}
                assert!(client.spaces[SPACE_INITIAL].discarded);
                assert!(client.spaces[SPACE_HANDSHAKE].keys.is_some());
            } else {
                assert!(client.is_handshaking());
                assert!(client.spaces[SPACE_HANDSHAKE].keys.is_none());
            }
            assert!(server.is_handshaking() && !server.handshake_confirmed);
            assert!(server.spaces[SPACE_INITIAL].keys.is_some());
            assert!(matches!(
                server.handle_datagram(&illegal, now),
                Err(QuicTlsError::Transport {
                    error_code: 0x0a,
                    frame_type: 0x06,
                    ..
                })
            ));
            let close = server.poll_transmit(now).expect("readable terminal close");
            assert!(close.len() <= server.pmtud.current_mtu());
            client.handle_datagram(&close, now).unwrap();
            assert!(
                matches!(
                    client.close_reason(),
                    Some(CloseReason::PeerTransport(0x0a, 0x06, _))
                ),
                "received_server_flight={received_server_flight}, close={:?}",
                client.close_reason()
            );
        }
    }

    #[test]
    fn frame_admission_preserves_legal_zero_rtt_frames() {
        let (ticket, stek) = ack_parameter_resumption_ticket();
        let now = Instant::now();
        let legal = [
            Frame::Padding(1),
            Frame::Ping,
            Frame::ResetStream {
                id: 4,
                error_code: 0,
                final_size: 0,
            },
            Frame::StopSending {
                id: 1,
                error_code: 0,
            },
            Frame::MaxData(1 << 20),
            Frame::MaxStreamData {
                id: 1,
                max: 1 << 20,
            },
            Frame::MaxStreams {
                dir: Dir::Bidi,
                max: 10,
            },
            Frame::MaxStreams {
                dir: Dir::Uni,
                max: 10,
            },
            Frame::DataBlocked(0),
            Frame::StreamDataBlocked { id: 0, limit: 0 },
            Frame::StreamsBlocked {
                dir: Dir::Bidi,
                limit: 0,
            },
            Frame::StreamsBlocked {
                dir: Dir::Uni,
                limit: 0,
            },
            Frame::NewConnectionId {
                seq: 1,
                retire_prior_to: 0,
                cid: b"new cid",
                reset_token: &[0; 16],
            },
            Frame::PathChallenge(7),
        ];
        for frame in legal {
            let (mut client, mut server) =
                frame_admission_resumption_pair(&ticket, stek.clone(), now);
            server.send_stream(1, b"opened local stream");
            let packet = seal_early_frames(
                &mut client,
                &[
                    frame.clone(),
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"legal early data",
                    },
                ],
                now,
            );
            server
                .handle_datagram(&packet, now)
                .unwrap_or_else(|error| panic!("{frame:?}: {error:?}"));
            assert_eq!(server.read_stream(0), b"legal early data", "{frame:?}");
            assert!(server.close_reason().is_none());
            assert!(server.is_handshaking());
        }
        for application in [false, true] {
            let (mut client, mut server) =
                frame_admission_resumption_pair(&ticket, stek.clone(), now);
            let packet = seal_early_frames(
                &mut client,
                &[
                    Frame::Close(super::super::frame::Close {
                        application,
                        error_code: 23,
                        frame_type: 0,
                        reason: b"legal close",
                    }),
                    Frame::Padding(3),
                ],
                now,
            );
            server.handle_datagram(&packet, now).unwrap();
            assert_eq!(
                server.close_reason(),
                Some(&if application {
                    CloseReason::PeerApp(23, b"legal close".to_vec())
                } else {
                    CloseReason::PeerTransport(23, 0, b"legal close".to_vec())
                })
            );
        }
    }

    #[test]
    fn frame_admission_server_close_preflights_all_candidates_and_preserves_mandatory_levels() {
        let (ticket, stek) = ack_parameter_resumption_ticket();
        let now = Instant::now();
        for failure in 0..5 {
            let (_, mut server) = frame_admission_resumption_pair(&ticket, stek.clone(), now);
            server.close_transport(0x0a, 0x06, b"local reason");
            match failure {
                0..=2 => server.spaces[failure].send = PacketNumberSpace::exhausted_for_test(),
                3 => {
                    server.data_packets_sealed = server.spaces[SPACE_DATA]
                        .keys
                        .as_ref()
                        .unwrap()
                        .local
                        .packet
                        .confidentiality_limit()
                }
                4 => {
                    server.anti_amp_recv = 0;
                    server.anti_amp_sent = 0;
                }
                _ => unreachable!(),
            }
            let before = std::array::from_fn::<_, 3, _>(|space| server.spaces[space].send.peek());
            let seals = server.sealed_packets.len();
            let local_reason = server.closed.clone();
            assert!(
                server.build_close_packet(now).is_none(),
                "failure={failure}"
            );
            assert_eq!(
                std::array::from_fn::<_, 3, _>(|space| server.spaces[space].send.peek()),
                before
            );
            assert_eq!(server.sealed_packets.len(), seals);
            assert_eq!(server.closed, local_reason);
        }
        for reason_len in [400, 900, 10_000] {
            let (client, mut server) = frame_admission_resumption_pair(&ticket, stek.clone(), now);
            let reason = vec![b'r'; reason_len];
            server.close_transport(0x0a, 0x06, &reason);
            let data_pn = server.spaces[SPACE_DATA].send.peek();
            let mut packet = server.build_close_packet(now).unwrap();
            assert!(packet.len() <= server.pmtud.current_mtu());
            let initial_len = packet::long_packet_len(&packet).unwrap();
            assert_eq!(
                packet::first_packet_space(&packet),
                Some(PacketSpace::Initial)
            );
            assert_eq!(
                packet::first_packet_space(&packet[initial_len..]),
                Some(PacketSpace::Handshake)
            );
            let handshake_len = packet::long_packet_len(&packet[initial_len..]).unwrap();
            assert_eq!(
                initial_len + handshake_len,
                packet.len(),
                "optional Data omitted first"
            );
            assert_eq!(server.spaces[SPACE_DATA].send.peek(), data_pn);
            let (_, body) = open_packet(
                &client.spaces[SPACE_INITIAL].keys.as_ref().unwrap().remote,
                &mut packet[..initial_len],
                client.scid.len(),
                None,
            )
            .unwrap();
            let Frame::Close(close) = Iter::new(&packet[body]).next().unwrap().unwrap() else {
                panic!("close")
            };
            assert_eq!(
                close.reason,
                if reason_len == 400 {
                    reason.as_slice()
                } else {
                    &[]
                }
            );
            assert_eq!(
                server.closed,
                Some(CloseReason::LocalTransport(0x0a, 0x06, reason))
            );
        }
        // A spent Data key must not be bypassed even when that optional packet
        // would have been removed from a large-reason batch for MTU.
        let (_, mut server) = frame_admission_resumption_pair(&ticket, stek, now);
        server.close_transport(0x0a, 0x06, &vec![1; 900]);
        server.data_packets_sealed = server.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .unwrap()
            .local
            .packet
            .confidentiality_limit();
        let before = std::array::from_fn::<_, 3, _>(|space| server.spaces[space].send.peek());
        assert!(server.build_close_packet(now).is_none());
        assert_eq!(
            std::array::from_fn::<_, 3, _>(|space| server.spaces[space].send.peek()),
            before
        );
    }

    #[test]
    fn legal_new_client_ack_parameters_allow_zero_rtt_without_committing_ack_before_finished() {
        let (ticket, stek) = ack_parameter_resumption_ticket();
        let client_tp = with_ack_transport_params(
            TransportParameters::safari_client(&[]).encode_safari_client(),
            6,
            7,
        );
        let (mut client, mut peer, flight) =
            resumption_first_flight_with_client_transport_params(&ticket, stek, client_tp, 0x85);
        let now = Instant::now();
        peer.handle_datagram(&flight, now).unwrap();
        assert!(peer.client_hello_processed());
        assert!(peer.is_handshaking() && peer.zero_rtt_keys_installed());
        assert!(peer.peer_transport_params_prevalidated);
        assert!(!peer.peer_ack_params_applied);
        assert_eq!(peer.peer_ack_delay_exponent, ACK_DELAY_EXPONENT);
        assert_eq!(peer.peer_max_ack_delay, MAX_ACK_DELAY);
        assert_eq!(peer.accept_bi(), Some(RELAY_STREAM_ID));
        assert_eq!(peer.read_stream(RELAY_STREAM_ID), ACK_PARAMETER_EARLY_DATA);
        drive_at(&mut client, &mut peer, now);
        assert!(!peer.is_handshaking());
        assert!(peer.peer_ack_params_applied);
        assert_eq!(peer.peer_ack_delay_exponent, 6);
        assert_eq!(peer.peer_max_ack_delay, Duration::from_millis(7));
    }

    #[test]
    fn invalid_new_client_ack_parameters_remain_terminal_when_driver_ignores_split_flight_errors() {
        let (ticket, stek) = ack_parameter_resumption_ticket();
        let client_tp = with_ack_transport_params(
            TransportParameters::safari_client(&[]).encode_safari_client(),
            21,
            25,
        );
        let (_, mut peer, flight) =
            resumption_first_flight_with_client_transport_params(&ticket, stek, client_tp, 0x87);
        let now = Instant::now();
        let mut remaining = flight.as_slice();
        let mut early_packets = Vec::new();
        let mut initial_errors = Vec::new();
        while !remaining.is_empty() {
            let len =
                packet::long_packet_len(remaining).expect("actual long-header packet boundary");
            let (packet, rest) = remaining.split_at(len);
            match packet::first_packet_space(packet) {
                Some(PacketSpace::Initial) => {
                    // Match the endpoint's driver behavior: record and ignore
                    // its initial processing error, then accept another datagram.
                    if let Err(error) = peer.handle_datagram(packet, now) {
                        assert!(matches!(
                            error,
                            QuicTlsError::Transport {
                                error_code: 0x08,
                                ..
                            }
                        ));
                        initial_errors.push(format!("{error:?}"));
                    }
                }
                Some(PacketSpace::ZeroRtt) => early_packets.push(packet),
                space => panic!("unexpected packet space in resumed first flight: {space:?}"),
            }
            remaining = rest;
        }
        assert!(
            !initial_errors.is_empty(),
            "invalid Initial input must actually return 0x08"
        );
        assert!(peer.client_hello_processed());
        assert!(!early_packets.is_empty());
        let mut followups_are_closed_drops = true;
        let early_results: Vec<_> = early_packets
            .into_iter()
            .map(|packet| {
                let result = peer.handle_datagram(packet, now + Duration::from_millis(1));
                followups_are_closed_drops &= result.is_ok();
                format!("{result:?}")
            })
            .collect();
        let published = peer.read_stream(RELAY_STREAM_ID);
        let accepted = peer.accept_bi();
        assert!(
            matches!(
                peer.close_reason(),
                Some(CloseReason::LocalTransport(0x08, 0x06, _))
            ) && followups_are_closed_drops
                && published.is_empty()
                && accepted.is_none()
                && !peer.peer_transport_params_prevalidated
                && !peer.peer_ack_params_applied
                && peer.peer_ack_delay_exponent == ACK_DELAY_EXPONENT
                && peer.peer_max_ack_delay == MAX_ACK_DELAY
                && peer.spaces[SPACE_DATA].recv.largest().is_none(),
            "ignored Initial errors={initial_errors:?}, followup0RTT={early_results:?}, \
             close={:?}, published={published:?}, accepted={accepted:?}, \
             prevalidated={}, ack_applied={}, exponent={}, max_delay={:?}",
            peer.close_reason(),
            peer.peer_transport_params_prevalidated,
            peer.peer_ack_params_applied,
            peer.peer_ack_delay_exponent,
            peer.peer_max_ack_delay,
        );
    }

    #[test]
    fn missing_peer_transport_parameters_do_not_cache_prevalidation_or_activate_ack_policy() {
        let mut client = Connection::new_client(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x86; 8]),
            ConnectionId::new(&[]),
        )
        .unwrap();
        assert!(client.tls.peer_transport_parameters().is_none());
        for _ in 0..2 {
            client.prevalidate_peer_transport_params().unwrap();
            assert!(!client.peer_transport_params_prevalidated);
            assert!(!client.peer_ack_params_applied);
            assert_eq!(client.peer_ack_delay_exponent, ACK_DELAY_EXPONENT);
            assert_eq!(client.peer_max_ack_delay, MAX_ACK_DELAY);
        }
    }

    #[test]
    fn preconfirmation_data_does_not_arm_or_fire_a_pto() {
        let now = Instant::now();
        let (mut client, _) = before_client_finished(CipherSuite::Aes128GcmSha256, now);
        assert!(!client.handshake_confirmed);
        client.seal_data_packet(
            &[Frame::Ping, Frame::Padding(3)],
            true,
            SentContent::default(),
            now,
        );
        let data_pto = now + client.pto_duration(SPACE_DATA);
        assert_ne!(client.next_timeout(), Some(data_pto));
        let in_flight = client.spaces[SPACE_DATA].sent.in_flight();
        client.handle_timeout(data_pto);
        assert_eq!(client.pto_count, 0);
        assert_eq!(client.probe_pending, 0);
        assert!(!client.ping_pending);
        client.queue_probe();
        assert_eq!(client.spaces[SPACE_DATA].sent.in_flight(), in_flight);
    }

    fn before_client_finished(suite: CipherSuite, now: Instant) -> (Connection, Connection) {
        let (mut client, mut server) = handshake_start(suite);
        while let Some(packet) = client.poll_transmit(now) {
            server.handle_datagram(&packet, now).unwrap();
        }
        while let Some(packet) = server.poll_transmit(now) {
            client.handle_datagram(&packet, now).unwrap();
        }
        assert!(!client.is_handshaking() && server.is_handshaking());
        assert!(server.spaces[SPACE_DATA].keys.is_some());
        (client, server)
    }

    fn key_phase_pair(suite: CipherSuite, now: Instant) -> (Connection, Connection) {
        let (mut client, mut server) = before_client_finished(suite, now);
        drive_at(&mut client, &mut server, now);
        assert!(client.handshake_confirmed && server.handshake_confirmed);
        // Two actual eliciting packets in each direction establish the current
        // generation's ACK precondition without bypassing delayed-ACK policy.
        for _ in 0..2 {
            let packet = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            server.handle_datagram(&packet, now).unwrap();
            let packet = server.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            client.handle_datagram(&packet, now).unwrap();
        }
        for _ in 0..16 {
            drive_at(&mut client, &mut server, now);
            if !client.spaces[SPACE_DATA].ack_pending && !server.spaces[SPACE_DATA].ack_pending {
                break;
            }
            if client.spaces[SPACE_DATA].ack_pending {
                let packet = server.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
                client.handle_datagram(&packet, now).unwrap();
            }
            if server.spaces[SPACE_DATA].ack_pending {
                let packet = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
                server.handle_datagram(&packet, now).unwrap();
            }
        }
        assert!(!client.spaces[SPACE_DATA].ack_pending && !server.spaces[SPACE_DATA].ack_pending);
        assert!(client.key_phase.tx_acked && server.key_phase.tx_acked);
        (client, server)
    }

    fn read_test_ack(receiver: &Connection, mut packet: Vec<u8>) -> Ack {
        let (_, range) = open_packet(
            &receiver.spaces[SPACE_DATA].keys.as_ref().unwrap().remote,
            &mut packet,
            receiver.scid.len(),
            receiver.spaces[SPACE_DATA].recv.largest(),
        )
        .unwrap();
        Iter::new(&packet[range])
            .find_map(|frame| match frame {
                Ok(Frame::Ack(ack)) => Some(ack),
                _ => None,
            })
            .expect("a real encrypted ACK")
    }

    #[test]
    fn delayed_ack_two_ordered_packets_share_one_ack() {
        let now = Instant::now();
        let (mut client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let first = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&first, now).unwrap();
        assert!(
            server.poll_transmit(now).is_none(),
            "one confirmed ordered packet waits for its bounded tail timer"
        );
        let second = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&second, now).unwrap();
        let ack = read_test_ack(
            &client,
            server
                .poll_transmit(now)
                .expect("second packet releases ACK"),
        );
        assert_eq!(ack.largest, client.spaces[SPACE_DATA].send.peek() - 1);
    }

    #[test]
    fn delayed_ack_preserves_largest_stamp_after_ack_and_reports_elapsed_over_25ms() {
        let now = Instant::now();
        let (client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let craft = |pn| {
            let (_, pn_len) = packet::encode_packet_number(pn, None);
            seal_packet(
                &client.spaces[SPACE_DATA].keys.as_ref().unwrap().local,
                client.make_header(SPACE_DATA, pn, pn_len),
                &[Frame::Ping, Frame::Padding(3)],
            )
        };
        server.handle_datagram(&craft(100), now).unwrap();
        let first = server.poll_transmit(now + MAX_ACK_DELAY).unwrap();
        assert_eq!(read_test_ack(&client, first).largest, 100);
        let later = now + Duration::from_millis(40);
        server.handle_datagram(&craft(50), later).unwrap();
        let ack = read_test_ack(&client, server.poll_transmit(later).unwrap());
        assert_eq!(ack.largest, 100);
        assert_eq!(
            ack.delay,
            40_000 >> ACK_DELAY_EXPONENT,
            "wire delay retains PN100's original receipt across ACKs, without a 25ms clamp"
        );
    }

    #[test]
    fn delayed_ack_frequency_tail_and_non_eliciting_packets() {
        let mut now = Instant::now();
        let (mut client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let mut acks = 0;
        for index in 1..=4 {
            let packet = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            server.handle_datagram(&packet, now).unwrap();
            if index % 2 == 0 {
                read_test_ack(
                    &client,
                    server.poll_transmit(now).expect("every second packet ACK"),
                );
                acks += 1;
                assert_eq!(server.spaces[SPACE_DATA].ack_eliciting_count, 0);
                assert!(server.spaces[SPACE_DATA].ack_deadline.is_none());
            } else {
                assert!(server.poll_transmit(now).is_none());
                assert_eq!(server.spaces[SPACE_DATA].ack_eliciting_count, 1);
            }
        }
        assert_eq!(acks, 2);
        let packet = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&packet, now).unwrap();
        let deadline = server.spaces[SPACE_DATA].ack_deadline.unwrap();
        assert_eq!(deadline, now + MAX_ACK_DELAY);
        let largest = server.spaces[SPACE_DATA].recv.largest().unwrap();
        now += Duration::from_millis(5);
        let acknowledged = server.spaces[SPACE_DATA].send.peek() - 1;
        let pure = client.test_data_packet(&[
            Frame::Ack(Ack {
                largest: acknowledged,
                delay: 0,
                ranges: vec![(acknowledged, acknowledged)],
                ecn: None,
            }),
            Frame::Padding(3),
        ]);
        server.handle_datagram(&pure, now).unwrap();
        assert_eq!(server.spaces[SPACE_DATA].ack_deadline, Some(deadline));
        assert_eq!(server.spaces[SPACE_DATA].ack_eliciting_count, 1);
        assert!(server.spaces[SPACE_DATA].recv.largest().unwrap() > largest);
        let pto = server.pto_count;
        assert!(server
            .poll_transmit(deadline - Duration::from_nanos(1))
            .is_none());
        server.handle_timeout(deadline);
        assert_eq!(server.pto_count, pto);
        assert!(!server.ping_pending);
        let ack = read_test_ack(&client, server.poll_transmit(deadline).unwrap());
        assert_eq!(ack.delay, 20_000 >> ACK_DELAY_EXPONENT);
        assert_eq!(ack.largest, client.spaces[SPACE_DATA].send.peek() - 1);
    }

    #[test]
    fn delayed_ack_new_generation_pure_ack_preserves_existing_deadline() {
        let now = Instant::now();
        let (mut client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let first = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&first, now).unwrap();
        let deadline = server.spaces[SPACE_DATA].ack_deadline;
        assert!(client.initiate_key_update(now).unwrap());
        let pure = client.test_data_packet(&[Frame::Padding(20)]);
        server
            .handle_datagram(&pure, now + Duration::from_millis(5))
            .unwrap();
        assert_eq!(server.key_phase.rx, 1);
        assert_eq!(server.spaces[SPACE_DATA].ack_eliciting_count, 1);
        assert_eq!(server.spaces[SPACE_DATA].ack_deadline, deadline);
        assert!(server
            .poll_transmit(now + Duration::from_millis(5))
            .is_none());
        let ack = server.poll_transmit(deadline.unwrap()).unwrap();
        client.handle_datagram(&ack, deadline.unwrap()).unwrap();
        assert!(
            !client.spaces[SPACE_DATA].ack_pending,
            "new-generation pure ACK cannot start ACK-of-ACK"
        );
        assert!(client.spaces[SPACE_DATA].ack_deadline.is_none());
    }

    #[test]
    fn delayed_ack_bad_tag_replay_gap_and_ce() {
        let now = Instant::now();
        let (mut client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let packet = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&packet, now).unwrap();
        let deadline = server.spaces[SPACE_DATA].ack_deadline;
        let stamp = server.last_recv_time;
        let ce = server.spaces[SPACE_DATA].recv_ecn.ce;
        let mut bad = packet.clone();
        *bad.last_mut().unwrap() ^= 0x40;
        for input in [&packet, &bad] {
            server
                .handle_datagram_ecn(input, EcnCodepoint::Ce, now + Duration::from_millis(1))
                .unwrap();
            assert_eq!(server.spaces[SPACE_DATA].ack_deadline, deadline);
            assert_eq!(server.spaces[SPACE_DATA].ack_eliciting_count, 1);
            assert_eq!(server.last_recv_time, stamp);
            assert_eq!(server.spaces[SPACE_DATA].recv_ecn.ce, ce);
        }
        client.spaces[SPACE_DATA].send.allocate();
        let gap = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&gap, now).unwrap();
        read_test_ack(
            &client,
            server.poll_transmit(now).expect("gap immediate ACK"),
        );
        let ce_packet = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server
            .handle_datagram_ecn(&ce_packet, EcnCodepoint::Ce, now)
            .unwrap();
        let ack = read_test_ack(
            &client,
            server.poll_transmit(now).expect("new CE immediate ACK"),
        );
        assert_eq!(ack.ecn.unwrap().ce, ce + 1);
    }

    #[test]
    fn delayed_ack_timer_sendability_and_no_pto_side_effects() {
        let now = Instant::now();
        let (mut client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let packet = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&packet, now).unwrap();
        let deadline = server.spaces[SPACE_DATA].ack_deadline.unwrap();
        assert_eq!(server.next_timeout(), Some(deadline));
        let keys = server.spaces[SPACE_DATA].keys.take();
        assert!(
            server.next_timeout().unwrap() > deadline,
            "unavailable keys cannot cause expired ACK spin"
        );
        server.spaces[SPACE_DATA].keys = keys;
        server.peer_addr_validated = false;
        server.anti_amp_recv = 0;
        server.anti_amp_sent = 0;
        assert!(
            server.next_timeout().unwrap() > deadline,
            "blocked amplification budget cannot spin"
        );
        assert!(server.poll_transmit(deadline).is_none());
        server.peer_addr_validated = true;
        server.spaces[SPACE_DATA].loss_time = Some(now + Duration::from_millis(3));
        assert_eq!(server.next_timeout(), Some(now + Duration::from_millis(3)));
        server.spaces[SPACE_DATA].loss_time = None;
        server.keepalive_interval = Duration::from_millis(4);
        assert_eq!(server.next_timeout(), Some(now + Duration::from_millis(4)));
        server.keepalive_interval = KEEP_ALIVE_MAX;
        let id = server.open_bi();
        server.send_stream(id, b"paced data");
        for _ in 0..10 {
            server.pacer.on_sent(now, 10_000, 1_000_000, 1);
        }
        assert_eq!(server.next_timeout(), server.pacer.next_send_time());
        assert!(server.next_timeout().unwrap() < deadline);
        // At the ACK deadline even a later pacing deadline cannot block feedback.
        server.pacer.on_sent(deadline, 10_000, 1_000_000, 1);
        server.last_recv_time = Some(now - IDLE_TIMEOUT + Duration::from_millis(5));
        assert_eq!(server.next_timeout(), Some(now + Duration::from_millis(5)));
        server.last_recv_time = Some(now);
        let pto = server.pto_count;
        let pn = server.spaces[SPACE_DATA].send.peek();
        server.handle_timeout(deadline);
        assert_eq!(server.pto_count, pto);
        assert!(!server.ping_pending);
        read_test_ack(&client, server.poll_transmit(deadline).unwrap());
        assert_eq!(server.spaces[SPACE_DATA].send.peek(), pn + 1);
        assert_eq!(
            server.data_packets_sealed,
            server
                .sealed_packets
                .iter()
                .filter(|(_, generation, _)| *generation == server.key_phase.tx)
                .count() as u64
        );
        let packet = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&packet, deadline).unwrap();
        server.close(0, b"clear ACK debt");
        assert!(server.spaces[SPACE_DATA].ack_deadline.is_none());
        assert!(!server.spaces[SPACE_DATA].ack_pending);
        client.spaces[SPACE_HANDSHAKE].ack_deadline = Some(deadline);
        client.spaces[SPACE_HANDSHAKE].ack_eliciting_count = 1;
        client.discard_space(SPACE_HANDSHAKE);
        assert!(client.spaces[SPACE_HANDSHAKE].ack_deadline.is_none());
    }

    #[test]
    fn key_phase_pre_finished_ciphertexts_cannot_decrypt_or_commit() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            for kind in 0..3 {
                let now = Instant::now();
                let (mut client, mut server) = before_client_finished(suite, now);
                let state = server.key_phase;
                let idle = server.last_recv_time;
                let received = server.spaces[SPACE_DATA].recv.to_ack(0);
                let ecn = server.spaces[SPACE_DATA].recv_ecn;
                let failures = server.data_packets_open_failed;
                if kind == 2 {
                    client.install_send_key(1).unwrap(); // malicious premature phase
                }
                let frames = match kind {
                    0 => vec![Frame::Stream {
                        id: RELAY_STREAM_ID,
                        offset: 0,
                        fin: false,
                        data: b"premature application data",
                    }],
                    1 => vec![Frame::Close(super::super::frame::Close {
                        application: true,
                        error_code: 77,
                        frame_type: 0,
                        reason: b"premature close",
                    })],
                    _ => vec![Frame::Ping, Frame::Padding(3)],
                };
                let packet = client.test_data_packet(&frames);
                server
                    .handle_datagram_ecn(&packet, EcnCodepoint::Ce, now + Duration::from_secs(1))
                    .unwrap();
                assert!(server.is_handshaking());
                assert!(server.close_reason().is_none());
                assert!(server.streams.is_empty());
                assert_eq!(server.key_phase, state);
                assert_eq!(server.last_recv_time, idle);
                assert_eq!(server.spaces[SPACE_DATA].recv.to_ack(0), received);
                let after = server.spaces[SPACE_DATA].recv_ecn;
                assert_eq!(
                    (after.ect0, after.ect1, after.ce),
                    (ecn.ect0, ecn.ect1, ecn.ce)
                );
                assert_eq!(server.data_packets_open_failed, failures);
                assert!(server.previous_read_key.is_none());
                let next = server.next_packet_keys.as_ref().unwrap();
                assert!(next.local.is_some() && next.remote.is_some());
            }
            // A legal earlier CF in the same datagram completes TLS before the
            // following 1-RTT packet is authenticated and delivered.
            let now = Instant::now();
            let (mut client, mut server) = before_client_finished(suite, now);
            client.send_stream(RELAY_STREAM_ID, b"after client Finished");
            let mut datagram = Vec::new();
            let mut application = None;
            while let Some(packet) = client.poll_transmit(now) {
                if packet::first_packet_space(&packet) != Some(PacketSpace::OneRtt) {
                    datagram.extend(packet);
                } else {
                    let mut inspect = packet.clone();
                    let (_, range) = open_packet(
                        &server.spaces[SPACE_DATA].keys.as_ref().unwrap().remote,
                        &mut inspect,
                        server.scid.len(),
                        server.spaces[SPACE_DATA].recv.largest(),
                    )
                    .unwrap();
                    if Iter::new(&inspect[range])
                        .any(|frame| matches!(frame, Ok(Frame::Stream { .. })))
                    {
                        application = Some(packet);
                    }
                }
            }
            // A short-header packet has no Length and must be last. Other short
            // control packets are lost rather than placed before the CF packet.
            datagram.extend(application.expect("one final STREAM packet"));
            server.handle_datagram(&datagram, now).unwrap();
            assert!(!server.is_handshaking());
            assert_eq!(
                server.read_stream(RELAY_STREAM_ID),
                b"after client Finished"
            );

            // The client also rejects early ciphertext before server Finished,
            // including before its provider has made application read keys ready.
            let (mut client, mut server) = handshake_start(suite);
            while let Some(packet) = client.poll_transmit(now) {
                server.handle_datagram(&packet, now).unwrap();
            }
            while let Some(packet) = server.poll_transmit(now) {
                if packet::first_packet_space(&packet) == Some(PacketSpace::Handshake) {
                    break; // withhold the server's Finished flight
                }
                client.handle_datagram(&packet, now).unwrap();
            }
            assert!(client.is_handshaking());
            let state = client.key_phase;
            let idle = client.last_recv_time;
            let failures = client.data_packets_open_failed;
            let packet = server.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            client.handle_datagram(&packet, now).unwrap();
            assert_eq!(client.key_phase, state);
            assert_eq!(client.last_recv_time, idle);
            assert_eq!(client.data_packets_open_failed, failures);
            assert_eq!(client.spaces[SPACE_DATA].recv.largest(), None);
        }
    }

    #[test]
    fn key_phase_handshake_close_batch_is_bounded_and_preflighted() {
        let now = Instant::now();
        for application in [false, true] {
            let (mut client, server) = before_client_finished(CipherSuite::Aes128GcmSha256, now);
            if application {
                client.close(79, b"application reason");
            } else {
                client.close_transport(0x07, 0x12, b"transport reason");
            }
            let mut batch = client.poll_transmit(now).unwrap();
            assert!(batch.len() <= client.pmtud.current_mtu());
            let length = packet::long_packet_len(&batch).expect("Handshake close first");
            let (_, body) = open_packet(
                &server.spaces[SPACE_HANDSHAKE].keys.as_ref().unwrap().remote,
                &mut batch[..length],
                server.scid.len(),
                server.spaces[SPACE_HANDSHAKE].recv.largest(),
            )
            .unwrap();
            let lower = Iter::new(&batch[body]).next().unwrap().unwrap();
            let Frame::Close(lower) = lower else {
                panic!("expected lower-level close")
            };
            assert!(!lower.application);
            assert_eq!(
                lower.error_code,
                if application { APPLICATION_ERROR } else { 0x07 }
            );
            assert_eq!(lower.frame_type, if application { 0 } else { 0x12 });
            assert_eq!(
                lower.reason,
                if application {
                    b"".as_slice()
                } else {
                    b"transport reason".as_slice()
                }
            );
            let (_, body) = open_packet(
                &server.spaces[SPACE_DATA].keys.as_ref().unwrap().remote,
                &mut batch[length..],
                server.scid.len(),
                server.spaces[SPACE_DATA].recv.largest(),
            )
            .unwrap();
            let Frame::Close(upper) = Iter::new(&batch[length + body.start..length + body.end])
                .next()
                .unwrap()
                .unwrap()
            else {
                panic!("expected 1-RTT close")
            };
            assert_eq!(upper.application, application);
            assert_eq!(upper.error_code, if application { 79 } else { 0x07 });
            assert_eq!(upper.frame_type, if application { 0 } else { 0x12 });
        }
        for failure in 0..4 {
            let (mut client, _) = before_client_finished(CipherSuite::Aes128GcmSha256, now);
            client.close_transport(0x07, 0x12, &vec![1; if failure == 3 { 10_000 } else { 20 }]);
            let reason = client.closed.clone();
            if failure == 0 {
                client.data_packets_sealed = client.spaces[SPACE_DATA]
                    .keys
                    .as_ref()
                    .unwrap()
                    .local
                    .packet
                    .confidentiality_limit();
            } else if failure == 1 {
                client.spaces[SPACE_DATA].send = PacketNumberSpace::exhausted_for_test();
            } else if failure == 2 {
                client.spaces[SPACE_HANDSHAKE].send = PacketNumberSpace::exhausted_for_test();
            }
            let before = [
                client.spaces[SPACE_HANDSHAKE].send.peek(),
                client.spaces[SPACE_DATA].send.peek(),
            ];
            let seals = client.sealed_packets.len();
            assert!(client.build_close_packet(now).is_none());
            assert_eq!(
                [
                    client.spaces[SPACE_HANDSHAKE].send.peek(),
                    client.spaces[SPACE_DATA].send.peek()
                ],
                before
            );
            assert_eq!(client.sealed_packets.len(), seals);
            assert_eq!(client.closed, reason);
        }
        let (mut client, _) = before_client_finished(CipherSuite::Aes128GcmSha256, now);
        client.close_transport(0x07, 0x12, &vec![1; 900]);
        let data_pn = client.spaces[SPACE_DATA].send.peek();
        let batch = client.build_close_packet(now).unwrap();
        assert!(batch.len() <= client.pmtud.current_mtu());
        assert_eq!(
            packet::long_packet_len(&batch),
            Some(batch.len()),
            "oversize pair falls back to one intact Handshake packet"
        );
        assert_eq!(client.spaces[SPACE_DATA].send.peek(), data_pn);
        let (mut client, _) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        assert!(client.spaces[SPACE_HANDSHAKE].keys.is_none());
        client.close(1, b"confirmed close");
        let batch = client.build_close_packet(now).unwrap();
        assert_eq!(
            packet::first_packet_space(&batch),
            Some(PacketSpace::OneRtt)
        );
        assert!(client
            .build_close_packet_in_space(SPACE_HANDSHAKE, now)
            .is_none());
    }

    fn assert_seal_numbers(conn: &Connection) {
        let mut seen = std::collections::BTreeSet::new();
        for &(direction, generation, pn) in &conn.sealed_packets {
            assert_eq!(direction, conn.side);
            assert!(
                seen.insert((u8::from(direction == Side::Server), generation, pn)),
                "key/IV and PN reused"
            );
        }
        for pair in conn.sealed_packets.windows(2) {
            assert!(pair[0].2 < pair[1].2, "global PN must not reset");
            assert!(pair[0].1 <= pair[1].1, "sending generation never goes back");
        }
    }

    #[test]
    fn key_phase_one_way_successive_responses_are_accepted() {
        let mut rejected = 0;
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let now = Instant::now();
            let (mut client, mut server) = key_phase_pair(suite, now);
            assert!(server.initiate_key_update(now).unwrap());
            let first = server.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            client.handle_datagram(&first, now).unwrap();
            let first_ack = client
                .poll_transmit(now)
                .expect("first-generation response ACK");
            server.handle_datagram(&first_ack, now).unwrap();
            assert_eq!((server.key_phase.tx, server.key_phase.rx), (1, 1));
            assert!(server.key_phase.tx_acked);
            assert!(server.key_phase.update_ack_pending);
            let second_time = server.next_update_at.unwrap() + Duration::from_millis(1);
            assert!(server.initiate_key_update(second_time).unwrap());
            assert_eq!((server.key_phase.tx, server.key_phase.rx), (2, 1));
            let second = server.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            client.handle_datagram(&second, second_time).unwrap();
            let second_ack = client
                .poll_transmit(second_time)
                .expect("second-generation response ACK");
            if server.handle_datagram(&second_ack, second_time).is_err() {
                rejected += 1;
            }
        }
        assert_eq!(
            rejected, 0,
            "legitimate responses to locally initiated updates must be accepted"
        );
    }

    #[test]
    fn key_phase_one_way_updates_with_pure_ack_loss_in_both_roles() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            for initiates_server in [false, true] {
                for lose_ack in [false, true] {
                    let now = Instant::now();
                    let (mut client, mut server) = key_phase_pair(suite, now);
                    let (sender, responder) = if initiates_server {
                        (&mut server, &mut client)
                    } else {
                        (&mut client, &mut server)
                    };
                    let mut time = now;
                    for generation in 1..=3 {
                        assert!(sender.initiate_key_update(time).unwrap());
                        let packet = sender.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
                        responder.handle_datagram(&packet, time).unwrap();
                        let mut ack = responder.poll_transmit(time).expect("pure ACK response");
                        if lose_ack {
                            assert!(!sender
                                .initiate_key_update(time + Duration::from_secs(1))
                                .unwrap());
                            let retry = sender.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
                            responder.handle_datagram(&retry, time).unwrap();
                            time = responder.pending_data_ack_deadline().unwrap();
                            responder.handle_timeout(time);
                            ack = responder
                                .poll_transmit(time)
                                .expect("replacement pure ACK at bounded tail deadline");
                        }
                        sender.handle_datagram(&ack, time).unwrap();
                        assert_eq!(
                            (sender.key_phase.tx, sender.key_phase.rx),
                            (generation, generation)
                        );
                        assert!(sender.key_phase.tx_acked);
                        assert!(
                            sender.key_phase.update_ack_pending,
                            "pure ACK does not elicit an ACK"
                        );
                        let state = sender.key_phase;
                        sender.handle_datagram(&ack, time).unwrap();
                        assert_eq!(sender.key_phase, state);
                        time = sender.next_update_at.unwrap() + Duration::from_millis(1);
                    }
                    assert_seal_numbers(sender);
                    assert_seal_numbers(responder);
                }
            }
        }
    }

    #[test]
    fn key_phase_real_connections_automatically_rotate_twice_in_both_directions() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            for initiator in 0..3 {
                let now = Instant::now();
                let (mut client, mut server) = key_phase_pair(suite, now);
                if initiator != 1 {
                    client.key_update_soft_limit = Some(1);
                }
                if initiator != 0 {
                    server.key_update_soft_limit = Some(1);
                }
                for generation in 1..=2 {
                    let mut time = now + Duration::from_secs(2 * generation);
                    client.ping_pending = true;
                    server.ping_pending = true;
                    // Simultaneously consume the local halves before delivering
                    // either packet; responding must not advance a second time.
                    if initiator == 2 {
                        let c = client.poll_transmit(time).unwrap();
                        let s = server.poll_transmit(time).unwrap();
                        assert_eq!(
                            (client.key_phase.tx, client.key_phase.rx),
                            (generation, generation - 1)
                        );
                        server.handle_datagram(&c, time).unwrap();
                        client.handle_datagram(&s, time).unwrap();
                    }
                    drive_acked_at(&mut client, &mut server, &mut time);
                    // A responder might otherwise send only a non-eliciting ACK
                    // in its new generation, which cannot itself be confirmed.
                    client.ping_pending = true;
                    server.ping_pending = true;
                    drive_acked_at(&mut client, &mut server, &mut time);
                    for conn in [&client, &server] {
                        assert_eq!(
                            (conn.key_phase.tx, conn.key_phase.rx),
                            (generation, generation)
                        );
                        assert!(conn.key_phase.tx_acked);
                        let next = conn.next_packet_keys.as_ref().unwrap();
                        assert_eq!(next.generation, generation + 1);
                        assert!(next.local.is_some() && next.remote.is_some());
                        assert!(!conn.is_closed());
                        assert_seal_numbers(conn);
                    }
                }
                client.send_stream(RELAY_STREAM_ID, b"payload after two phase flips");
                let mut end = now + Duration::from_secs(5);
                drive_acked_at(&mut client, &mut server, &mut end);
                assert_eq!(
                    server.read_stream(RELAY_STREAM_ID),
                    b"payload after two phase flips"
                );
            }
        }
    }

    #[test]
    fn key_phase_loss_reordering_replay_and_fixed_retirement() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let now = Instant::now();
            let (mut client, mut server) = key_phase_pair(suite, now);
            let replay = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            server.handle_datagram(&replay, now).unwrap();
            let reordered = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            let too_late = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            assert!(client.initiate_key_update(now).unwrap());
            let lost_first = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            let next = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            server.handle_datagram(&next, now).unwrap();
            let deadline = server.previous_read_key.as_ref().unwrap().retire_at;
            assert!(server.next_timeout().unwrap() <= deadline);
            let _lost_ack = server.poll_transmit(now).unwrap();
            assert!(
                !client.initiate_key_update(deadline).unwrap(),
                "lost ACK cannot unlock update"
            );
            server
                .handle_datagram(&reordered, now + Duration::from_millis(1))
                .unwrap();
            let state = server.key_phase;
            let last_recv = server.last_recv_time;
            let received = server.spaces[SPACE_DATA].recv.to_ack(0);
            let ecn = server.spaces[SPACE_DATA].recv_ecn;
            for packet in [&replay, &reordered] {
                server
                    .handle_datagram_ecn(packet, EcnCodepoint::Ce, now + Duration::from_millis(2))
                    .unwrap();
                assert_eq!(server.key_phase, state);
                assert_eq!(server.last_recv_time, last_recv);
                assert_eq!(server.spaces[SPACE_DATA].recv.to_ack(0), received);
                let after = server.spaces[SPACE_DATA].recv_ecn;
                assert_eq!(
                    (after.ect0, after.ect1, after.ce),
                    (ecn.ect0, ecn.ect1, ecn.ce)
                );
                assert_eq!(
                    server.previous_read_key.as_ref().unwrap().retire_at,
                    deadline
                );
            }
            // Re-delivery of the lost first new-phase packet also authenticates
            // with the current key, despite having a smaller PN than the first seen.
            server
                .handle_datagram(&lost_first, now + Duration::from_millis(3))
                .unwrap();
            let ack = server
                .poll_transmit(now + Duration::from_millis(3))
                .unwrap();
            client
                .handle_datagram(&ack, now + Duration::from_millis(3))
                .unwrap();
            assert!(client.key_phase.tx_acked);
            let client_state = client.key_phase;
            let client_idle = client.last_recv_time;
            client
                .handle_datagram(&ack, now + Duration::from_millis(4))
                .unwrap();
            assert_eq!(
                client.key_phase, client_state,
                "duplicate ACK changes no phase state"
            );
            assert_eq!(client.last_recv_time, client_idle);
            assert!(!client
                .initiate_key_update(now + Duration::from_millis(4))
                .unwrap());
            server.handle_timeout(deadline);
            assert!(server.previous_read_key.is_none());
            let state = server.key_phase;
            let last_recv = server.last_recv_time;
            let failures = server.data_packets_open_failed;
            server.handle_datagram(&too_late, deadline).unwrap();
            assert_eq!(server.key_phase, state);
            assert_eq!(server.last_recv_time, last_recv);
            assert_eq!(server.data_packets_open_failed, failures + 1);
            let next_update = client.next_update_at.unwrap();
            assert!(client.initiate_key_update(next_update).unwrap());
            let second = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
            server.handle_datagram(&second, next_update).unwrap();
            assert_eq!((server.key_phase.rx, server.key_phase.tx), (2, 2));
            assert_eq!(
                server.data_packets_open_failed,
                failures + 1,
                "integrity count survives rotation"
            );
            assert_seal_numbers(&client);
            assert_seal_numbers(&server);
        }
    }

    #[test]
    fn key_phase_lost_stream_retransmits_under_current_key_and_fresh_pn() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let now = Instant::now();
            let (mut client, mut server) = key_phase_pair(suite, now);
            let payload = b"lost under generation zero, retransmitted under generation one";
            client.send_stream(RELAY_STREAM_ID, payload);
            let old_pn = client.spaces[SPACE_DATA].send.peek();
            let _lost_stream = client.poll_transmit(now).unwrap();
            assert_eq!(
                client.sealed_packets.last(),
                Some(&(Side::Client, 0, old_pn))
            );
            assert!(client.initiate_key_update(now).unwrap());
            client.ping_pending = true;
            drive_at(&mut client, &mut server, now);
            let mut received = server.read_stream(RELAY_STREAM_ID);
            for _ in 0..8 {
                if received.len() == payload.len() {
                    break;
                }
                let time = client.next_timeout().unwrap();
                client.handle_timeout(time);
                drive_at(&mut client, &mut server, time);
                received.extend(server.read_stream(RELAY_STREAM_ID));
            }
            assert_eq!(received, payload);
            assert_eq!((client.key_phase.tx, server.key_phase.rx), (1, 1));
            assert!(client
                .sealed_packets
                .iter()
                .any(|&(side, generation, pn)| side == Side::Client
                    && generation == 1
                    && pn > old_pn));
            assert_seal_numbers(&client);
        }
    }

    #[test]
    fn key_phase_forged_headers_and_tags_cannot_commit_any_receive_state() {
        let now = Instant::now();
        let (mut client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let valid = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        let state = server.key_phase;
        let received = server.spaces[SPACE_DATA].recv.to_ack(0);
        let idle = server.last_recv_time;
        let cids = (server.initial_dcid, server.dcid, server.peer_cid_adopted);
        let ecn = server.spaces[SPACE_DATA].recv_ecn;
        let next = server.next_packet_keys.as_ref().unwrap().generation;
        for kind in 0..3 {
            let mut forged = valid.clone();
            match kind {
                0 => forged[0] ^= 0x04,                     // protected phase bit
                1 => *forged.last_mut().unwrap() ^= 0x80,   // AEAD tag
                _ => forged[1 + server.scid.len()] ^= 0x01, // protected PN
            }
            let failures = server.data_packets_open_failed;
            server
                .handle_datagram_ecn(&forged, EcnCodepoint::Ce, now + Duration::from_secs(1))
                .unwrap();
            assert_eq!(server.key_phase, state);
            assert_eq!(server.spaces[SPACE_DATA].recv.to_ack(0), received);
            assert_eq!(server.last_recv_time, idle);
            assert_eq!(
                (server.initial_dcid, server.dcid, server.peer_cid_adopted),
                cids
            );
            let after = server.spaces[SPACE_DATA].recv_ecn;
            assert_eq!(
                (after.ect0, after.ect1, after.ce),
                (ecn.ect0, ecn.ect1, ecn.ce)
            );
            let cached = server.next_packet_keys.as_ref().unwrap();
            assert_eq!(cached.generation, next);
            assert!(cached.local.is_some() && cached.remote.is_some());
            assert!(server.previous_read_key.is_none());
            assert_eq!(server.data_packets_open_failed, failures + 1);
        }
        server.handle_datagram(&valid, now).unwrap();
        assert_eq!(server.key_phase.rx, 0);
        assert!(client.initiate_key_update(now).unwrap());
        let valid_next = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&valid_next, now).unwrap();
        assert_eq!((server.key_phase.rx, server.key_phase.tx), (1, 1));
    }

    #[test]
    fn key_phase_authenticated_invalid_frontier_and_old_key_ack_are_rejected() {
        let now = Instant::now();
        let (mut client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let gap = client.spaces[SPACE_DATA].send.allocate();
        let old = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&old, now).unwrap();
        assert!(!server.spaces[SPACE_DATA].recv.contains(gap));
        assert!(client.initiate_key_update(now).unwrap());
        let new = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        server.handle_datagram(&new, now).unwrap();
        let state = server.key_phase;
        let received = server.spaces[SPACE_DATA].recv.to_ack(0);
        let (_, pn_len) = packet::encode_packet_number(gap, None);
        let invalid = seal_packet(
            &client.spaces[SPACE_DATA].keys.as_ref().unwrap().local,
            client.make_header(SPACE_DATA, gap, pn_len),
            &[Frame::Ping, Frame::Padding(3)],
        );
        assert!(matches!(
            server.handle_datagram(&invalid, now),
            Err(QuicTlsError::Transport {
                error_code: 0x0e,
                ..
            })
        ));
        assert_eq!(server.key_phase, state);
        assert_eq!(server.spaces[SPACE_DATA].recv.to_ack(0), received);

        let (mut client, mut server) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let pn = client.spaces[SPACE_DATA].send.peek();
        let old_ack = server.test_data_packet(&[
            Frame::Ack(Ack {
                largest: pn,
                delay: 0,
                ranges: vec![(pn, pn)],
                ecn: None,
            }),
            Frame::Padding(3),
        ]);
        assert!(client.initiate_key_update(now).unwrap());
        let _new = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
        assert!(matches!(
            client.handle_datagram(&old_ack, now),
            Err(QuicTlsError::Transport {
                error_code: 0x0e,
                ..
            })
        ));
        assert!(!client.key_phase.tx_acked);
        assert!(!client
            .initiate_key_update(now + Duration::from_secs(2))
            .unwrap());
    }

    #[test]
    fn key_phase_unconfirmed_or_unacknowledged_updates_and_exhaustion_fail_closed() {
        let now = Instant::now();
        let (mut client, _) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        client.handshake_confirmed = false;
        assert!(!client.initiate_key_update(now).unwrap());
        client.handshake_confirmed = true;
        client.key_phase.tx_acked = false;
        assert!(!client.initiate_key_update(now).unwrap());
        client.key_phase.tx_acked = true;
        client.data_packets_sealed = client.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .unwrap()
            .local
            .packet
            .confidentiality_limit();
        client.close(27, b"keep original reason");
        let reason = client.closed.clone();
        let pn = client.spaces[SPACE_DATA].send.peek();
        let sealed = client.sealed_packets.len();
        assert!(client.poll_transmit(now).is_none());
        assert!(client.build_close_packet(now).is_none());
        assert_eq!(client.closed, reason);
        assert_eq!(
            client.key_phase.tx, 0,
            "closing cannot rotate to buy a close"
        );
        assert_eq!(client.spaces[SPACE_DATA].send.peek(), pn);
        assert_eq!(client.sealed_packets.len(), sealed);

        let (mut client, _) = key_phase_pair(CipherSuite::Aes128GcmSha256, now);
        let pn = client.spaces[SPACE_DATA].send.peek();
        client.next_packet_keys = None; // simulate derivation/ownership failure
        client.key_update_soft_limit = Some(1);
        client.ping_pending = true;
        assert!(client.poll_transmit(now).is_none());
        assert!(client.is_closed());
        assert_eq!(client.spaces[SPACE_DATA].send.peek(), pn);
        assert_eq!(client.key_phase.tx, 0);
    }

    #[test]
    fn quic_guard_regression_replays_do_not_commit_receive_state() {
        for evict in [false, true] {
            let (mut client, mut server) = connected_pair();
            let t0 = Instant::now() + Duration::from_secs(1);
            let first_pn = client.spaces[SPACE_DATA].send.peek();
            let datagram = client.test_data_packet(&[Frame::Stream {
                id: RELAY_STREAM_ID,
                offset: 0,
                fin: false,
                data: b"authenticated bytes that must only arrive once",
            }]);
            // A forgery of this PN must not reserve it or refresh idle: the
            // subsequent authentic packet with that same PN must still work.
            let mut forged = datagram.clone();
            *forged.last_mut().unwrap() ^= 1;
            let before_forgery = server.spaces[SPACE_DATA].recv.to_ack(0);
            let idle_before = server.last_recv_time;
            server
                .handle_datagram_ecn(&forged, EcnCodepoint::Ce, t0)
                .unwrap();
            assert_eq!(server.spaces[SPACE_DATA].recv.to_ack(0), before_forgery);
            assert_eq!(server.last_recv_time, idle_before);
            server
                .handle_datagram_ecn(&datagram, EcnCodepoint::Ect0, t0)
                .unwrap();
            assert_eq!(
                server.read_stream(RELAY_STREAM_ID),
                b"authenticated bytes that must only arrive once"
            );
            if evict {
                // Forty gapped authenticated packets evict the first PN from
                // the 32-range ACK set, while keeping PN reconstruction unambiguous.
                for _ in 0..40 {
                    client.spaces[SPACE_DATA].send.allocate();
                    let packet = client.test_data_packet(&[Frame::Ping, Frame::Padding(3)]);
                    server
                        .handle_datagram_ecn(&packet, EcnCodepoint::Ect0, t0)
                        .unwrap();
                }
                assert!(server.spaces[SPACE_DATA].recv.contains(first_pn));
                assert!(
                    !server.spaces[SPACE_DATA]
                        .recv
                        .to_ack(0)
                        .unwrap()
                        .ranges
                        .iter()
                        .any(|&(lo, hi)| lo <= first_pn && first_pn <= hi),
                    "PN really evicted"
                );
            }
            // Demonstrate that the replay still authenticates, including after
            // eviction: this is a deduplication check, not an AEAD-failure test.
            let mut replay_check = datagram.clone();
            let (header, _) = open_packet(
                &server.spaces[SPACE_DATA].keys.as_ref().unwrap().remote,
                &mut replay_check,
                server.scid.len(),
                server.spaces[SPACE_DATA].recv.largest(),
            )
            .unwrap();
            assert_eq!(header.packet_number(), first_pn);
            let received = server.spaces[SPACE_DATA].recv.to_ack(0);
            let ack_pending = server.spaces[SPACE_DATA].ack_pending;
            let ack_schedule = (
                server.spaces[SPACE_DATA].ack_eliciting_count,
                server.spaces[SPACE_DATA].ack_deadline,
            );
            let largest_time = server.spaces[SPACE_DATA].largest_recv_time;
            let ecn = server.spaces[SPACE_DATA].recv_ecn;
            let cids = (server.initial_dcid, server.dcid, server.peer_cid_adopted);
            server
                .handle_datagram_ecn(&datagram, EcnCodepoint::Ce, t0 + IDLE_TIMEOUT / 2)
                .unwrap();
            assert_eq!(server.last_recv_time, Some(t0), "replay cannot extend idle");
            assert_eq!(server.spaces[SPACE_DATA].recv.to_ack(0), received);
            assert_eq!(server.spaces[SPACE_DATA].ack_pending, ack_pending);
            assert_eq!(
                (
                    server.spaces[SPACE_DATA].ack_eliciting_count,
                    server.spaces[SPACE_DATA].ack_deadline
                ),
                ack_schedule
            );
            assert_eq!(server.spaces[SPACE_DATA].largest_recv_time, largest_time);
            let after = server.spaces[SPACE_DATA].recv_ecn;
            assert_eq!(
                (after.ect0, after.ect1, after.ce),
                (ecn.ect0, ecn.ect1, ecn.ce)
            );
            assert_eq!(
                (server.initial_dcid, server.dcid, server.peer_cid_adopted),
                cids
            );
            assert!(server.read_stream(RELAY_STREAM_ID).is_empty());
            server.handle_timeout(t0 + IDLE_TIMEOUT);
            assert_eq!(server.close_reason(), Some(&CloseReason::IdleTimeout));
        }
    }

    #[test]
    fn quic_guard_regression_confidentiality_budget_includes_close() {
        for at_limit in [false, true] {
            for mode in 0..4 {
                let mut conn = Connection::new_server(
                    Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
                    &server_key(),
                    vec![b"h3".to_vec()],
                    server_tp(),
                    ConnectionId::new(&[0x64; 4]),
                )
                .unwrap();
                conn.spaces[SPACE_DATA].keys = Some(Keys {
                    local: test_keys(),
                    remote: test_keys(),
                });
                conn.peer_addr_validated = true;
                let limit = conn.spaces[SPACE_DATA]
                    .keys
                    .as_ref()
                    .unwrap()
                    .local
                    .packet
                    .confidentiality_limit();
                assert_eq!(limit, 1 << 23, "real AES-GCM budget");
                if mode == 0 {
                    conn.ping_pending = true;
                } else if mode == 2 {
                    conn.close_transport(0x1, 0, b"pending transport close");
                } else {
                    conn.close(0x42, b"pending application close");
                }
                conn.data_packets_sealed = limit - u64::from(!at_limit);
                let pn_before = conn.spaces[SPACE_DATA].send.peek();
                let sealed_before = conn.data_packets_sealed;
                let now = Instant::now();
                let first = if mode == 3 {
                    conn.build_close_packet(now)
                } else {
                    conn.poll_transmit(now)
                };
                assert_eq!(
                    first.is_some(),
                    !at_limit,
                    "mode={mode}, at_limit={at_limit}"
                );
                if let Some(mut packet) = first {
                    open_packet(&test_keys(), &mut packet, conn.dcid.len(), None)
                        .expect("last permitted packet is genuinely AEAD protected");
                }
                for _ in 0..3 {
                    assert!(
                        conn.poll_transmit(now).is_none(),
                        "no protected packet after exhaustion: q={}",
                        conn.data_packets_sealed
                    );
                    assert!(
                        conn.build_close_packet(now).is_none(),
                        "close builder enforces its own budget"
                    );
                }
                assert_eq!(conn.data_packets_sealed, limit);
                assert!(conn.data_packets_sealed >= sealed_before);
                assert_eq!(
                    conn.spaces[SPACE_DATA].send.peek(),
                    pn_before + u64::from(!at_limit)
                );
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
                // A short header has no Length field and must end the datagram.
                if dg[0] & 0x80 == 0 {
                    b.handle_datagram(&from_a, now).unwrap();
                    from_a.clear();
                }
            }
            if !from_a.is_empty() {
                b.handle_datagram(&from_a, now).unwrap();
            }
            let mut from_b = Vec::new();
            while let Some(dg) = b.poll_transmit(now) {
                from_b.extend_from_slice(&dg);
                moved = true;
                if dg[0] & 0x80 == 0 {
                    a.handle_datagram(&from_b, now).unwrap();
                    from_b.clear();
                }
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
    fn acked_send_buffer_prefix_is_reclaimed() {
        // Finding #28: once a prefix of the send buffer is fully acknowledged it can
        // never be resent, so it must be compacted away — a long-lived stream must
        // not retain every byte ever sent.
        let now = Instant::now();
        let dcid = ConnectionId::new(&[0x28; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x28, 0x28, 0x28, 0x28]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        let payload: Vec<u8> = (0..256_000u32).map(|i| (i % 251) as u8).collect();
        client.send_stream(RELAY_STREAM_ID, &payload);
        assert_eq!(
            client.stream_send_capacity(RELAY_STREAM_ID),
            STREAM_SEND_BUFFER - payload.len(),
            "buffered-but-unacked bytes consume send capacity"
        );

        let mut received = Vec::new();
        for _ in 0..2000 {
            let mut moved = false;
            while let Some(dg) = client.poll_transmit(now) {
                server.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            received.extend_from_slice(&server.read_stream(RELAY_STREAM_ID));
            while let Some(dg) = server.poll_transmit(now) {
                client.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            if !moved && received.len() == payload.len() {
                break;
            }
        }
        assert_eq!(received, payload, "whole payload delivered in order");

        let s = &client.streams[&RELAY_STREAM_ID];
        assert!(
            s.send.is_empty(),
            "fully-acked send buffer compacted away (still holds {} bytes)",
            s.send.len()
        );
        assert_eq!(
            s.send_base, s.send_off,
            "send_base advanced to the acked frontier"
        );
        assert_eq!(
            client.stream_send_capacity(RELAY_STREAM_ID),
            STREAM_SEND_BUFFER,
            "acks restore the full send capacity"
        );
    }

    /// The old `compact_send_buffer` implementation's source of truth: a full
    /// rescan of every in-flight DATA packet's STREAM ranges. The per-stream
    /// index ([`Stream::sent_range_offsets`]) that replaced it must be an exact
    /// multiset mirror of this scan at all times — mirror equality implies the
    /// "lowest live offset" (the only in-flight input `compact_send_buffer`
    /// reads) is identical, and therefore every reclaim decision is identical.
    fn scan_sent_range_offsets(c: &Connection) -> BTreeMap<u64, BTreeMap<u64, usize>> {
        let mut scan: BTreeMap<u64, BTreeMap<u64, usize>> = BTreeMap::new();
        for content in c.spaces[SPACE_DATA].sent_content.values() {
            for &(sid, off, _, _) in &content.stream {
                *scan.entry(sid).or_default().entry(off).or_insert(0) += 1;
            }
        }
        scan
    }

    fn assert_index_mirrors_scan(c: &Connection, side: &str, step: usize) {
        let scan = scan_sent_range_offsets(c);
        for (&id, s) in &c.streams {
            let expected = scan.get(&id).cloned().unwrap_or_default();
            assert_eq!(
                s.sent_range_offsets, expected,
                "{side} step {step} stream {id}: offset index diverged from the sent_content scan"
            );
        }
        // Streams retire only after their in-flight ranges have drained, so the
        // loop above must still cover every stream referenced by sent_content.
        for id in scan.keys() {
            assert!(
                c.streams.contains_key(id),
                "{side} step {step}: sent_content references unknown stream {id}"
            );
        }
    }

    #[test]
    fn compact_send_buffer_index_matches_a_full_sent_content_scan() {
        // Randomized equivalence proof for the compact_send_buffer index: drive a
        // real client/server pair through a lossy, PTO-probing, retransmitting
        // transfer over several streams and, after EVERY event that can touch
        // sent_content, assert the per-stream offset index is an exact multiset
        // mirror of the full scan the old implementation performed. Then drain
        // losslessly and assert every stream's bytes arrived intact — reclaim
        // never dropped bytes that were still needed.
        let mut client = Connection::new_client(
            client_config(),
            "example.com",
            ConnectionId::new(&[0x1d; 8]),
            ConnectionId::new(&[]),
        )
        .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x1d, 0xec, 0x0d, 0xed]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // Deterministic xorshift64 PRNG: reproducible "random" sizes/loss.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut rng = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };

        let ids: Vec<u64> = (0..4).map(|_| client.open_bi()).collect();
        let mut sent: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut recvd: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for &id in &ids {
            sent.insert(id, Vec::new());
            recvd.insert(id, Vec::new());
        }
        let mut now = Instant::now();

        for step in 0..400 {
            // Queue a random chunk on a random stream (bytes from the PRNG so a
            // mis-reclaimed retransmit is detected as corruption, not just length).
            let id = ids[rng(ids.len() as u64) as usize];
            let chunk: Vec<u8> = (0..64 + rng(1500)).map(|_| rng(256) as u8).collect();
            client.send_stream(id, &chunk);
            sent.entry(id).or_default().extend_from_slice(&chunk);

            // Client transmits; ~25% of datagrams are dropped on the floor so
            // packet-threshold loss, time-threshold loss, and retransmits all run.
            while let Some(dg) = client.poll_transmit(now) {
                assert_index_mirrors_scan(&client, "client", step);
                if rng(4) != 0 {
                    server.handle_datagram(&dg, now).unwrap();
                }
            }
            // Server responds (ACKs, flow updates); ~10% of those are dropped so
            // the client also PTO-probes DATA packets (queue_probe's unindex path).
            while let Some(dg) = server.poll_transmit(now) {
                assert_index_mirrors_scan(&server, "server", step);
                if rng(10) != 0 {
                    client.handle_datagram(&dg, now).unwrap();
                }
            }
            assert_index_mirrors_scan(&client, "client-post-acks", step);

            // Advance time and fire due timers (loss detection, PTO, keep-alive).
            now += Duration::from_millis(20 + rng(180));
            if client.next_timeout().is_some_and(|t| t <= now) {
                client.handle_timeout(now);
                assert_index_mirrors_scan(&client, "client-post-timeout", step);
            }
            if server.next_timeout().is_some_and(|t| t <= now) {
                server.handle_timeout(now);
            }
            // Drain the server's app reads so flow-control windows keep extending.
            for &id in &ids {
                let got = server.read_stream(id);
                recvd.entry(id).or_default().extend_from_slice(&got);
            }
        }

        // Lossless drain: force retransmits via timers until everything arrives.
        for _ in 0..10_000 {
            let mut moved = false;
            while let Some(dg) = client.poll_transmit(now) {
                server.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            while let Some(dg) = server.poll_transmit(now) {
                client.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            assert_index_mirrors_scan(&client, "client-drain", usize::MAX);
            for &id in &ids {
                let got = server.read_stream(id);
                recvd.entry(id).or_default().extend_from_slice(&got);
            }
            if recvd == sent {
                break;
            }
            if !moved {
                let t = client
                    .next_timeout()
                    .expect("undelivered data keeps a timer armed");
                now = now.max(t);
                client.handle_timeout(now);
                if server.next_timeout().is_some_and(|st| st <= now) {
                    server.handle_timeout(now);
                }
            }
        }
        for &id in &ids {
            assert_eq!(
                recvd.get(&id),
                sent.get(&id),
                "stream {id}: delivered bytes must match what was sent (reclaim \
                 must never drop bytes still needed for retransmission)"
            );
        }
    }

    /// Timing harness for [`Connection::compact_send_buffer`] under a large
    /// in-flight set (big cwnd, many streams). NOT a pass/fail perf gate — it
    /// only prints per-call cost, so it cannot flake in CI. Run it manually in
    /// release mode:
    ///
    /// ```text
    /// cargo test --locked --lib --release bench_compact_send_buffer -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "timing harness; run manually in --release with --nocapture"]
    fn bench_compact_send_buffer() {
        const STREAMS: u64 = 128;
        const PACKETS: u64 = 4096; // in-flight DATA packets: a few-MB cwnd of 1200B packets
        const RANGE_LEN: u64 = 1200;
        const ITERS: u32 = 100; // repeats of "compact every stream once" (one ACK batch)

        let mut client = Connection::new_client(
            client_config(),
            "example.com",
            ConnectionId::new(&[0xbe; 8]),
            ConnectionId::new(&[]),
        )
        .unwrap();
        let now = Instant::now();
        let ids: Vec<u64> = (0..STREAMS).map(|_| client.open_bi()).collect();
        // Record the in-flight set through the REAL send-path bookkeeping
        // (`record_sent`), one STREAM range per packet round-robin across the
        // streams — the shape a bulk transfer produces.
        for k in 0..PACKETS {
            let id = ids[(k % STREAMS) as usize];
            let off = (k / STREAMS) * RANGE_LEN;
            let content = SentContent {
                stream: vec![(id, off, RANGE_LEN, false)],
                ..SentContent::default()
            };
            let pn = client.spaces[SPACE_DATA].send.allocate();
            client.record_sent(SPACE_DATA, pn, RANGE_LEN as usize, true, content, now);
        }
        // Give each stream a send buffer + packetize frontier consistent with the
        // recorded ranges. Offset 0 is still in flight on every stream, so there
        // is nothing to reclaim: each call does its full "lowest live offset"
        // lookup and early-outs — the steady-state hot path (and the worst case
        // for the old full rescan of sent_content).
        let per_stream = PACKETS / STREAMS;
        for &id in &ids {
            let s = client.streams.get_mut(&id).unwrap();
            s.send = vec![0xa5; (per_stream * RANGE_LEN) as usize];
            s.send_off = per_stream * RANGE_LEN;
        }

        let t = Instant::now();
        for _ in 0..ITERS {
            for &id in &ids {
                client.compact_send_buffer(id);
            }
        }
        let elapsed = t.elapsed();
        let calls = ITERS * STREAMS as u32;
        eprintln!(
            "compact_send_buffer: {STREAMS} streams, {PACKETS} in-flight packets: \
             {calls} calls in {elapsed:?} ({:?}/call)",
            elapsed / calls
        );
        // Sanity: nothing was reclaimed (offset 0 is still live everywhere).
        for &id in &ids {
            assert_eq!(client.streams[&id].send_base, 0, "nothing to reclaim yet");
        }
    }

    #[test]
    fn path_mtu_discovery_grows_the_datagram_over_a_clean_path() {
        // DPLPMTUD must climb above the conservative BASE on a path that carries larger
        // datagrams (the loss-free in-process loopback), and the bulk payload must stay
        // byte-intact while the datagram size grows under it.
        let now = Instant::now();
        let dcid = ConnectionId::new(&[0x6d; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x6d, 0x6d, 0x6d, 0x6d]),
        )
        .unwrap();
        // A fresh connection (before the handshake confirms + probes start) is at BASE.
        assert_eq!(
            client.current_mtu(),
            super::super::pmtud::BASE_MTU,
            "MTU starts at BASE before the handshake confirms"
        );
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        let payload: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
        client.send_stream(RELAY_STREAM_ID, &payload);

        let mut received = Vec::new();
        for _ in 0..4000 {
            let mut moved = false;
            while let Some(dg) = client.poll_transmit(now) {
                server.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            received.extend_from_slice(&server.read_stream(RELAY_STREAM_ID));
            while let Some(dg) = server.poll_transmit(now) {
                client.handle_datagram(&dg, now).unwrap();
                moved = true;
            }
            if !moved && received.len() == payload.len() {
                break;
            }
        }
        assert_eq!(
            received, payload,
            "payload intact while the MTU grew under it"
        );
        assert!(
            client.current_mtu() > super::super::pmtud::BASE_MTU,
            "MTU discovery raised the datagram above BASE on a clean path (got {})",
            client.current_mtu()
        );
        assert!(
            client.current_mtu() <= super::super::pmtud::MAX_MTU,
            "MTU never exceeds the search ceiling"
        );
    }

    #[test]
    fn lost_stream_ranges_shrink_after_a_path_mtu_blackhole() {
        let mut now = Instant::now();
        let dcid = ConnectionId::new(&[0x6e; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x6e; 4]),
        )
        .unwrap();
        drive_acked_at(&mut client, &mut server, &mut now);

        // Validate a large MTU, then model a route that only carries BASE-sized
        // datagrams. Bypass pacing to isolate packetization and loss recovery.
        while client.pmtud.next_probe_size().is_some() {
            client.pmtud.on_probe_acked();
        }
        let base = super::super::pmtud::BASE_MTU;
        assert!(client.current_mtu() > base);
        let payload: Vec<u8> = (0..5500u32).map(|i| (i % 251) as u8).collect();
        client.send_stream(RELAY_STREAM_ID, &payload);
        client.finish_stream(RELAY_STREAM_ID);
        let mut dropped = 0;
        while client.next_stream_to_send().is_some() {
            let dg = client.build_stream_packet(RELAY_STREAM_ID, now);
            assert!(dg.len() > base, "the smaller path drops each old packet");
            dropped += 1;
        }
        assert_eq!(dropped, 4);
        let charged = client.send_data_total;
        client.send_max_data = charged;
        client.streams.get_mut(&RELAY_STREAM_ID).unwrap().send_max = payload.len() as u64;

        // A small PING traverses the new path; its ACK and the subsequent loss
        // timer declare all four oversized STREAM packets lost and reset PMTU.
        now += Duration::from_millis(10);
        let ping = client.build_ping_packet(now);
        assert!(ping.len() <= base);
        server.handle_datagram(&ping, now).unwrap();
        let ack = server.build_ack_packet(SPACE_DATA, now);
        client.handle_datagram(&ack, now).unwrap();
        now += Duration::from_secs(1);
        client.handle_timeout(now);
        assert_eq!(client.current_mtu(), base, "blackhole reset reached BASE");
        assert_eq!(client.streams[&RELAY_STREAM_ID].retransmit.len(), dropped);
        assert_index_mirrors_scan(&client, "client", 0);

        let mut offset = 0;
        let mut retransmitted = 0;
        while client.next_stream_to_send().is_some() {
            let dg = client.build_stream_packet(RELAY_STREAM_ID, now);
            assert!(dg.len() <= base, "retransmission fits the smaller path");
            let content = client.spaces[SPACE_DATA]
                .sent_content
                .last_key_value()
                .unwrap()
                .1;
            let &(id, off, len, fin) = content.stream.first().unwrap();
            assert_eq!((id, off), (RELAY_STREAM_ID, offset));
            offset += len;
            assert_eq!(fin, offset == payload.len() as u64);
            assert_eq!(client.send_data_total, charged, "resends consume no credit");
            server.handle_datagram(&dg, now).unwrap();
            let ack = server.build_ack_packet(SPACE_DATA, now);
            client.handle_datagram(&ack, now).unwrap();
            retransmitted += 1;
            assert_index_mirrors_scan(&client, "client", retransmitted);
        }
        assert!(retransmitted > dropped, "lost ranges were split");
        assert_eq!(offset, payload.len() as u64);
        assert!(
            server.stream_recv_finished(RELAY_STREAM_ID),
            "FIN recovered"
        );
        assert_eq!(server.read_stream(RELAY_STREAM_ID), payload);
        assert!(client.streams[&RELAY_STREAM_ID].send.is_empty());
        assert!(client.streams[&RELAY_STREAM_ID].fin_acked);
    }

    #[test]
    fn ecn_ce_is_tallied_echoed_in_ack_ecn_and_signals_congestion() {
        // End-to-end ECN (RFC 9000 §13.4): a CE-marked datagram delivered to the server
        // must be tallied, echoed in the server's ACK as ACK_ECN, and — when that ACK
        // reaches the client — recorded as a peer CE increase (the congestion signal).
        let now = Instant::now();
        let dcid = ConnectionId::new(&[0xce; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xce, 0xce, 0xce, 0xce]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // The client sends some stream data; deliver each 1-RTT datagram to the server
        // marked CE (as if a router on the path set Congestion Experienced).
        client.send_stream(RELAY_STREAM_ID, b"ecn-marked relay bytes");
        while let Some(dg) = client.poll_transmit(now) {
            server
                .handle_datagram_ecn(&dg, EcnCodepoint::Ce, now)
                .unwrap();
        }
        assert!(
            server.data_recv_ce() > 0,
            "server tallied the CE-marked datagrams"
        );

        // The server's ACK must now carry ACK_ECN; deliver the server's packets to the
        // client and assert the client recorded the peer's CE increase.
        let mut saw_ack_ecn = false;
        while let Some(dg) = server.poll_transmit(now) {
            // Peek: at least one server datagram should decode to an ACK with ecn set.
            // (We assert indirectly via the client's peer_ecn_ce below, but also sanity
            // check the wire here by re-parsing is overkill — rely on the client state.)
            client.handle_datagram(&dg, now).unwrap();
            saw_ack_ecn = true;
        }
        assert!(saw_ack_ecn, "server emitted packets carrying its ACK");
        assert!(
            client.peer_ecn_ce() > 0,
            "client recorded the peer's reported CE count (ACK_ECN echoed end to end)"
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x21, 0x43, 0x65, 0x87]),
        )
        .unwrap();
        drive_acked_at(&mut client, &mut server, &mut now);
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
        let mut now = Instant::now();
        let dcid = ConnectionId::new(&[0x30; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x31, 0x41, 0x59, 0x26]),
        )
        .unwrap();
        drive_acked_at(&mut client, &mut server, &mut now);
        assert!(!client.is_handshaking());

        // Offer far more than one initial congestion window (12000 bytes) of data
        // without delivering any ACK: the client must stop sending at ~the window.
        client.send_stream(RELAY_STREAM_ID, &vec![0x5a; 256 * 1024]);
        let mut burst = 0usize;
        while let Some(dg) = client.poll_transmit(now) {
            burst += dg.len();
        }
        // The burst is bounded by the live congestion window: the send gate stops once
        // bytes-in-flight + one datagram would exceed it, so the burst can reach at most
        // window + one MTU. Read the window (and MTU) live rather than hard-coding the
        // initial 12000, because the handshake exchange — including DPLPMTUD probes that
        // get acknowledged on the in-process loopback — can grow both the window and the
        // per-packet size before this burst.
        let window = client.cc_window() as usize;
        let mtu = client.current_mtu();
        assert!(
            burst >= window.saturating_sub(mtu) && burst <= window + mtu,
            "first burst ({burst}) is bounded by the congestion window ({window} ± one MTU {mtu})"
        );
    }

    #[test]
    fn keep_alive_ping_is_sent_after_idle_interval() {
        let dcid = ConnectionId::new(&[0x40; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
    fn one_rtt_ack_encodes_the_real_nonzero_ack_delay() {
        // PAR-22: a 1-RTT ACK must carry the real time the ACK was held since the
        // packet it acknowledges, not a hard-coded 0. The server receives an
        // ack-eliciting PING, holds the ACK 8ms, then sends it; we decrypt that ACK
        // with the client's keys and read the delay field off the wire. 8ms encodes as
        // 8000us >> ack_delay_exponent(3) = 1000; the old hard-coded behavior would
        // decode to 0.
        let dcid = ConnectionId::new(&[0x41; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xcd, 0xdc, 0xcd, 0xdc]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        assert!(client.handshake_confirmed && server.handshake_confirmed);

        // Client emits a 1-RTT keep-alive PING.
        let t0 = Instant::now();
        client.last_send_time = Some(t0);
        client.keepalive_interval = Duration::from_secs(1);
        let mut t = t0 + Duration::from_secs(2);
        client.handle_timeout(t);
        let ping = client
            .poll_transmit(t)
            .expect("client queues a 1-RTT keep-alive PING");

        // Server receives the PING, holds the ACK 8ms, then sends it.
        server.handle_datagram(&ping, t).unwrap();
        t += Duration::from_millis(8);
        let mut ack = server
            .poll_transmit(t)
            .expect("server emits the (held) ACK of the PING");

        // Decrypt the server's 1-RTT ACK with the client's receive keys and read the
        // delay field. raw 1000 << exponent(3) = 8000us = 8ms. Use the client's real
        // local CID length and largest-received PN so packet-number reconstruction
        // matches handle_datagram.
        let local_cid_len = client.scid.len();
        let largest = client.spaces[SPACE_DATA].recv.largest();
        let keys = client.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .expect("client has 1-RTT keys");
        let (_hdr, range) =
            open_packet(&keys.remote, &mut ack, local_cid_len, largest).expect("ACK opens");
        let delay = Iter::new(&ack[range])
            .filter_map(|f| match f {
                Ok(Frame::Ack(a)) => Some(a.delay),
                _ => None,
            })
            .next()
            .expect("the server packet carries an ACK frame");
        assert_eq!(
            delay, 1000,
            "ack_delay must encode the 8ms hold (8000us >> 3 = 1000), not 0"
        );
    }

    #[test]
    fn ack_delay_is_measured_from_the_largest_even_when_it_is_not_ack_eliciting() {
        // Regression: ack_delay must be measured from the receipt of the LARGEST
        // acknowledged packet (RFC 9000 §13.2.5), which may be a NON-ack-eliciting
        // packet (e.g. a pure ACK / padding-only) whose PN exceeds a later, reordered
        // ack-eliciting packet's. The prior code gated the stamp on `ack_eliciting`, so
        // in this interleaving the stamp was never set for the largest packet and the
        // emitted ACK reported delay 0 (or a stale, too-old value). Here a padding-only
        // PN=100 arrives first, then a reordered PING PN=50 triggers the ACK 20ms later;
        // the ACK must report ~20ms (measured from PN=100's receipt), not 0.
        let dcid = ConnectionId::new(&[0x4a; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0xac, 0xeb, 0xac, 0xeb]),
        )
        .unwrap();
        let mut t0 = Instant::now();
        drive_acked_at(&mut client, &mut server, &mut t0);
        assert!(client.handshake_confirmed && server.handshake_confirmed);

        // Craft two 1-RTT packets with the CLIENT's local 1-RTT keys (the server opens
        // them with the client's keys as its remote), choosing the packet numbers so the
        // non-ack-eliciting one is the larger. seal_packet needs the client's routing
        // header (self.dcid -> the server) and the chosen PN.
        let craft = |conn: &Connection, pn: u64, frames: &[Frame]| -> Vec<u8> {
            let (_, pn_len) = packet::encode_packet_number(pn, None);
            let header = conn.make_header(SPACE_DATA, pn, pn_len);
            let keys = conn.spaces[SPACE_DATA]
                .keys
                .as_ref()
                .expect("client has 1-RTT keys");
            seal_packet(&keys.local, header, frames)
        };
        // PN=100: a padding-only (NON-ack-eliciting) packet — the new largest.
        let larger_non_eliciting = craft(&client, 100, &[Frame::Padding(20)]);
        // PN=50: a reordered ack-eliciting PING that triggers the ACK.
        let smaller_eliciting = craft(&client, 50, &[Frame::Ping, Frame::Padding(3)]);

        // Largest (PN=100) received first; it owes no ACK by itself but sets the stamp.
        server.handle_datagram(&larger_non_eliciting, t0).unwrap();
        assert!(
            !server.spaces[SPACE_DATA].ack_pending,
            "a padding-only packet is not ack-eliciting (no ACK owed yet)"
        );
        // 20ms later the reordered PING arrives and triggers the held ACK.
        let t1 = t0 + Duration::from_millis(20);
        server.handle_datagram(&smaller_eliciting, t1).unwrap();
        let mut ack = server
            .poll_transmit(t1)
            .expect("server emits the ACK triggered by the PING");

        // Decrypt the ACK with the client's receive keys and read the delay. The largest
        // acked is PN=100 (received at t0); the ACK is sent at t1, so the delay is 20ms.
        // 20ms = 20000us >> ack_delay_exponent(3) = 2500. The buggy (gated-stamp) code
        // would have reported 0.
        let local_cid_len = client.scid.len();
        let largest = client.spaces[SPACE_DATA].recv.largest();
        let keys = client.spaces[SPACE_DATA]
            .keys
            .as_ref()
            .expect("client has 1-RTT keys");
        let (_hdr, range) =
            open_packet(&keys.remote, &mut ack, local_cid_len, largest).expect("ACK opens");
        let delay = Iter::new(&ack[range])
            .filter_map(|f| match f {
                Ok(Frame::Ack(a)) => Some(a.delay),
                _ => None,
            })
            .next()
            .expect("the server packet carries an ACK frame");
        assert_eq!(
            delay, 2500,
            "ack_delay must be measured from the largest packet's receipt (20ms => 2500), not 0"
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
    fn keep_alive_fallback_varies_and_stays_in_bounds() {
        // CSPRNG-failure fallback: it must NOT collapse to a single fixed value (which
        // would re-create the constant-cadence tell jitter exists to remove), and every
        // offset must stay within the span so the resulting interval is still in
        // [MIN, MAX] (and thus under IDLE_TIMEOUT). Walking the counter across the span
        // yields a varying, in-bounds sequence with no clock read.
        let span_ms = (KEEP_ALIVE_MAX - KEEP_ALIVE_MIN).as_millis() as u64;
        let mut seen = std::collections::BTreeSet::new();
        for step in 0..(span_ms * 3) {
            let offset = fallback_keep_alive_offset_ms(step, span_ms);
            assert!(
                offset <= span_ms,
                "fallback offset {offset} exceeds the span"
            );
            let interval = KEEP_ALIVE_MIN + Duration::from_millis(offset);
            assert!(
                interval >= KEEP_ALIVE_MIN && interval <= KEEP_ALIVE_MAX,
                "fallback interval {interval:?} out of bounds"
            );
            seen.insert(offset);
        }
        assert!(
            seen.len() > 1,
            "the fallback must vary across cycles, not be a single fixed value"
        );
    }

    #[test]
    fn closed_connection_goes_quiet_drains_and_stops_peer() {
        let dcid = ConnectionId::new(&[0x5c; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
        assert_transport_error(err, 0x0a);
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
    fn reset_stream_reclaims_connection_flow_control_credit() {
        // RFC 9000 §4.5: a RESET_STREAM's bytes count as delivered for connection
        // flow control. Charging the reset tail to recv_data_total without ever
        // crediting recv_data_consumed froze MAX_DATA for good: a peer that opens a
        // stream, sends one byte and resets at the full stream window strands 2 MiB
        // each time, so ~8 resets pin recv_data_total at the 16 MiB CONN_RECV_WINDOW
        // with recv_data_consumed still 0 and the connection can never receive again.
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x6d, 0x6d, 0x6d, 0x6d]),
        )
        .unwrap();

        // MAX_PEER_STREAMS × STREAM_RECV_WINDOW (128 MiB) is many times the 16 MiB
        // connection window, so every one of these succeeds only if each reset
        // releases the credit it consumed.
        for n in 0..MAX_PEER_STREAMS as u64 {
            let id = n * 4; // client-initiated bidi == peer-initiated for the server
            server.recv_stream(id, 0, false, &[0xAB]).unwrap();
            server
                .recv_reset_stream(id, 0, STREAM_RECV_WINDOW)
                .unwrap_or_else(|e| {
                    panic!("reset #{n} must not exhaust the connection window: {e:?}")
                });
        }
        assert!(
            server.need_max_data,
            "reclaimed credit must re-arm a MAX_DATA grant"
        );
        assert!(
            server.recv_data_consumed <= server.recv_data_total,
            "credit reclaimed ({}) must never exceed what was charged ({})",
            server.recv_data_consumed,
            server.recv_data_total,
        );
        assert_eq!(
            server.recv_pending_total, 0,
            "a reset stream's unreassemblable fragments must release the budget"
        );

        // A duplicate RESET_STREAM carries delta == 0 and must not credit again,
        // which would inflate the window past what the peer actually consumed.
        let consumed = server.recv_data_consumed;
        server.recv_reset_stream(0, 0, STREAM_RECV_WINDOW).unwrap();
        assert_eq!(
            server.recv_data_consumed, consumed,
            "a duplicate RESET_STREAM must not credit the same bytes twice"
        );

        // Bytes already reassembled in order stay readable (the reader drains them
        // before the reset surfaces), and are credited exactly once, by the read.
        assert_eq!(server.read_stream(0), vec![0xAB]);
        assert_eq!(
            server.recv_data_consumed,
            consumed + 1,
            "the still-deliverable byte is credited by the read, not by the reset"
        );

        // A late retransmit on a reset stream must not be reassembled: its bytes
        // were already counted as delivered by the reset, and `delta` is 0 at this
        // point, so delivering them would credit the window a second time for bytes
        // that were never charged to it.
        let after_read = server.recv_data_consumed;
        server.recv_stream(0, 0, false, &[0xAB; 64]).unwrap();
        assert!(
            server.read_stream(0).is_empty(),
            "a reset stream must not deliver post-reset data"
        );
        assert_eq!(
            server.recv_data_consumed, after_read,
            "post-reset data must not credit the connection window again"
        );
        assert!(
            server.recv_data_consumed <= server.recv_data_total,
            "credit ({}) must never exceed what was charged ({})",
            server.recv_data_consumed,
            server.recv_data_total,
        );
    }

    #[test]
    fn duplicate_out_of_order_stream_fragments_are_bounded() {
        // Each duplicate of a future-offset fragment leaves the flow-control high
        // watermark unchanged (delta 0), so flow control never bounds it. It is
        // fully covered by the already-buffered copy, so it must be dropped:
        // buffering every copy would grow recv_pending at zero flow-control cost.
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x6b, 0x6b, 0x6b, 0x6b]),
        )
        .unwrap();
        let chunk = vec![0xAB; 1000];
        for _ in 0..5000 {
            server.recv_stream(0, 10_000, false, &chunk).unwrap();
        }
        assert_eq!(
            server.streams[&0].recv_pending.len(),
            1,
            "duplicate out-of-order fragments are dropped, not buffered"
        );
        assert_eq!(server.recv_pending_total, chunk.len());
        // The retained copy still reassembles once the gap is filled.
        server
            .recv_stream(0, 0, false, &vec![0xCC; 10_000])
            .unwrap();
        assert_eq!(server.streams[&0].recv_off, 11_000);
        assert!(server.streams[&0].recv_pending.is_empty());
        assert_eq!(
            server.recv_pending_total, 0,
            "drained fragments release the connection-wide budget"
        );
    }

    #[test]
    fn out_of_order_reassembly_is_bounded_connection_wide() {
        // Overlapping future-offset fragments cost only their 1-byte watermark
        // delta in connection flow-control credit yet buffer their full length,
        // so the per-stream cap alone would let MAX_PEER_STREAMS × 2 MiB (≈128 MiB
        // per kind) accumulate while CONN_RECV_WINDOW is never engaged. The
        // aggregate budget must reject buffering past MAX_CONN_REASSEMBLY.
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x6c, 0x6c, 0x6c, 0x6c]),
        )
        .unwrap();
        let chunk = vec![0xCD; 256 * 1024];
        let mut rejected = false;
        'streams: for n in 0..MAX_PEER_STREAMS as u64 {
            let id = n * 4; // client-initiated bidi (peer-initiated for the server)
            for i in 0..8u64 {
                // Each fragment extends the previous by one byte, so it is not a
                // full duplicate (it is buffered) but costs only delta == 1 after
                // the first (which charges its full length).
                if let Err(error) = server.recv_stream(id, i + 1, false, &chunk) {
                    assert_transport_error(error, 0x01);
                    rejected = true;
                    break 'streams;
                }
            }
        }
        assert!(
            rejected,
            "aggregate out-of-order buffering is eventually rejected"
        );
        assert!(
            server.recv_pending_total <= MAX_CONN_REASSEMBLY,
            "buffering never exceeds the connection-wide budget ({})",
            server.recv_pending_total
        );
        let buffered: usize = server
            .streams
            .values()
            .flat_map(|s| s.recv_pending.iter().map(|(_, d)| d.len()))
            .sum();
        assert_eq!(
            buffered, server.recv_pending_total,
            "the budget accounting matches the bytes actually buffered"
        );
    }

    #[test]
    fn sequential_finished_streams_replenish_credit_and_release_state() {
        let dcid = ConnectionId::new(&[0x71; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            TransportParameters::server(&[]).encode_server(),
            ConnectionId::new(&[0x72; 8]),
        )
        .unwrap();
        let mut now = Instant::now();
        drive_acked_at(&mut client, &mut server, &mut now);
        for _ in 0..(MAX_PEER_STREAMS * 3) {
            now += Duration::from_millis(10);
            let id = client.open_bi();
            client.send_stream(id, b"request");
            client.finish_stream(id);
            drive_acked_at(&mut client, &mut server, &mut now);
            assert_eq!(server.accept_bi(), Some(id));
            assert_eq!(server.read_stream(id), b"request");
            server.send_stream(id, b"response");
            server.finish_stream(id);
            drive_acked_at(&mut client, &mut server, &mut now);
            assert_eq!(client.read_stream(id), b"response");
            assert!(client.stream_recv_finished(id));
            drive_acked_at(&mut client, &mut server, &mut now);
            assert!(
                client.streams.is_empty(),
                "client retained finished stream {id}"
            );
            assert!(
                server.streams.is_empty(),
                "server retained finished stream {id}"
            );
        }
        assert!(!client.is_closed() && !server.is_closed());
        assert!(client.send_max_streams[0] > MAX_PEER_STREAMS as u64);
        let received = server.recv_data_total;
        let consumed = server.recv_data_consumed;
        // Fresh packets may retransmit an old STREAM or RESET after retirement.
        // Neither the stream nor its flow-control charge may be resurrected.
        server.recv_stream(0, 0, true, b"request").unwrap();
        server.recv_reset_stream(0, 9, 7).unwrap();
        client.send_stream(0, b"late write");
        client.reset_stream(0, 9);
        assert!(client.streams.is_empty() && server.streams.is_empty());
        assert_eq!(
            (server.recv_data_total, server.recv_data_consumed),
            (received, consumed)
        );
        assert!(server.accept_bidi.is_empty());
        // STOP_SENDING must elicit RESET_STREAM even for a newly opened empty
        // request; otherwise cancelled streams can never finish both halves.
        for _ in 0..MAX_PEER_STREAMS * 2 {
            now += Duration::from_millis(10);
            let id = client.open_bi();
            client.cancel_stream(id, 0x10c);
            drive_acked_at(&mut client, &mut server, &mut now);
            assert_eq!(server.accept_bi(), None);
            drive_acked_at(&mut client, &mut server, &mut now);
            assert!(client.streams.is_empty() && server.streams.is_empty());
        }
    }

    #[test]
    fn implicit_stream_opening_and_advertised_credit_are_bounded() {
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            TransportParameters::server(&[]).encode_server(),
            ConnectionId::new(&[0x73; 8]),
        )
        .unwrap();
        // The initial server transport parameters grant only two bidis. Merely
        // intending to send a larger MAX_STREAMS is not permission to use it.
        assert!(server.recv_stream(8, 0, false, b"").is_err());
        assert!(server.streams.is_empty());
        server.recv_max_streams_sent[0] = MAX_PEER_STREAMS as u64;
        let last = (MAX_PEER_STREAMS as u64 - 1) * 4;
        server.recv_stream(last, 0, false, b"").unwrap();
        assert_eq!(server.streams.len(), MAX_PEER_STREAMS);
        assert_eq!(server.accept_bidi.len(), MAX_PEER_STREAMS);
        assert!(server.recv_stream(last + 4, 0, false, b"").is_err());
        assert!(server.recv_stream((1 << 60) * 4, 0, false, b"").is_err());
        assert_eq!(server.streams.len(), MAX_PEER_STREAMS);
        assert_eq!(server.peer_streams_opened[0], MAX_PEER_STREAMS as u64);
    }

    #[test]
    fn finished_uni_retains_fin_until_ack_and_ignores_fresh_packet_retransmit() {
        let dcid = ConnectionId::new(&[0x74; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x75; 8]),
        )
        .unwrap();
        let mut now = Instant::now();
        drive_acked_at(&mut client, &mut server, &mut now);
        let id = client.open_uni();
        client.send_stream(id, b"control");
        client.finish_stream(id);
        let first = client.build_stream_packet(id, now);
        server.handle_datagram(&first, now).unwrap();
        assert_eq!(server.accept_uni(), Some(id));
        assert_eq!(server.read_stream(id), b"control");
        assert!(!server.streams.contains_key(&id));
        assert!(
            client.streams.contains_key(&id),
            "FIN has not been acknowledged"
        );
        // A PTO replaces the unacknowledged FIN packet. The receiver has already
        // retired the stream, but must acknowledge its retransmission in a new PN.
        client.queue_probe();
        assert_eq!(client.next_stream_to_send(), Some(id));
        let retry = client.build_stream_packet(id, now);
        server.handle_datagram(&retry, now).unwrap();
        assert!(!server.streams.contains_key(&id));
        assert!(server.accept_uni().is_none());
        drive_acked_at(&mut client, &mut server, &mut now);
        assert!(!client.streams.contains_key(&id));
        assert_eq!(server.recv_data_total, 7);
        assert_eq!(server.recv_data_consumed, 7);
        // A lost grant must re-arm even if a newer grant has since been queued.
        let mut lost = SentContent::default();
        lost.max_streams[1] = true;
        server.need_max_streams = [false; 2];
        server.requeue(SPACE_DATA, lost);
        assert!(server.need_max_streams[1]);
    }

    #[test]
    fn send_only_uni_rejects_receive_frames_before_and_after_retirement() {
        let dcid = ConnectionId::new(&[0x76; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x77; 8]),
        )
        .unwrap();
        drive(&mut client, &mut server);
        let id = client.open_uni();
        for retired in [false, true] {
            if retired {
                client.finish_stream(id);
                drive(&mut client, &mut server);
                assert!(client.stream_retired(id), "FIN must be acknowledged");
            }
            let before = (
                client.recv_data_total,
                client.recv_data_consumed,
                client.recv_pending_total,
                client.recv_max_data,
                client.need_max_data,
                client.streams.len(),
            );
            let stream_err = client
                .recv_stream(id, 1, false, b"x")
                .expect_err("STREAM on a send-only uni must be rejected");
            assert!(matches!(
                stream_err,
                QuicTlsError::Transport {
                    error_code: 0x05,
                    frame_type: 0x08,
                    ..
                }
            ));
            let reset_err = client
                .recv_reset_stream(id, 7, 2)
                .expect_err("RESET_STREAM on a send-only uni must be rejected");
            assert!(matches!(
                reset_err,
                QuicTlsError::Transport {
                    error_code: 0x05,
                    frame_type: 0x04,
                    ..
                }
            ));
            assert_eq!(
                (
                    client.recv_data_total,
                    client.recv_data_consumed,
                    client.recv_pending_total,
                    client.recv_max_data,
                    client.need_max_data,
                    client.streams.len(),
                ),
                before,
                "invalid receive frames must not change accounting (retired={retired})"
            );
            if let Some(s) = client.streams.get(&id) {
                assert_eq!(
                    (s.recv_high, s.recv_off, s.recv_consumed, s.recv_credited),
                    (0, 0, 0, 0)
                );
                assert!(s.recv_fin.is_none() && s.recv_reset.is_none());
                assert!(s.recv.is_empty() && s.recv_pending.is_empty());
            }
        }
    }

    #[test]
    fn receive_direction_guard_allows_peer_uni_and_both_bidi_directions() {
        let dcid = ConnectionId::new(&[0x78; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        client.recv_max_streams_sent = [MAX_PEER_STREAMS as u64; 2];
        let local_bidi = client.open_bi();
        for (id, data) in [
            (local_bidi, b"local bidi".as_slice()),
            (1, b"peer bidi"),
            (3, b"peer uni"),
        ] {
            client.recv_stream(id, 0, true, data).unwrap();
            assert_eq!(client.read_stream(id), data);
        }
        // RESET_STREAM is valid on the same three receive-capable kinds, too.
        for id in [local_bidi, 1, 7] {
            let final_size = client.streams.get(&id).map_or(0, |s| s.recv_high);
            client.recv_reset_stream(id, 9, final_size).unwrap();
            assert_eq!(client.stream_reset(id), Some(9));
        }
        assert_eq!(client.recv_pending_total, 0);
        assert_eq!(client.recv_data_total, client.recv_data_consumed);
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
        assert_transport_error(err, 0x05);
    }

    #[test]
    fn final_size_violations_are_rejected() {
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
        assert_transport_error(err, 0x06);
        let err2 = server
            .recv_stream(0, 0, true, b"hi")
            .expect_err("a conflicting final size is rejected");
        assert_transport_error(err2, 0x06);
    }

    #[test]
    fn reset_stream_final_size_is_validated_and_flow_accounted() {
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
        assert_transport_error(err, 0x06);
        // A consistent reset (final size >= received) is accepted.
        server.recv_reset_stream(0, 7, 200).unwrap();
    }

    #[test]
    fn flow_control_violation_opening_a_stream_leaves_no_zombie() {
        // A STREAM frame that would OPEN a fresh peer stream but violates flow
        // control must be rejected WITHOUT inserting or accept-queuing the stream
        // (RFC 9000 §4.1: a flow-control violation is connection-fatal, not a quiet
        // half-open). Otherwise a peer cycling fresh stream ids could pile zombie
        // streams up to the per-peer limit.
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x5a, 0x5a, 0x5a, 0x5a]),
        )
        .unwrap();
        // end = STREAM_RECV_WINDOW + 2 exceeds a fresh stream's receive window.
        let err = server
            .recv_stream(0, STREAM_RECV_WINDOW + 1, false, b"x")
            .expect_err("exceeding a fresh stream's window is rejected");
        assert_transport_error(err, 0x03);
        assert!(
            !server.streams.contains_key(&0),
            "a rejected opening STREAM must not leave the stream inserted"
        );
        assert!(
            server.accept_bidi.is_empty(),
            "a rejected opening STREAM must not enqueue an acceptable stream"
        );
    }

    #[test]
    fn stream_offset_overflow_is_rejected_without_opening() {
        // offset + len overflowing u64 is a frame encoding error (the offset can
        // never fall inside any window). It must be rejected before any state
        // mutation — and must not panic (debug) or wrap past the window (release).
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x5b, 0x5b, 0x5b, 0x5b]),
        )
        .unwrap();
        let err = server
            .recv_stream(0, u64::MAX, false, b"xx")
            .expect_err("an offset that overflows u64 is rejected");
        assert_transport_error(err, 0x07);
        assert!(
            !server.streams.contains_key(&0),
            "an overflowing STREAM must not leave the stream inserted"
        );
    }

    #[test]
    fn initial_and_handshake_keys_are_discarded_after_the_handshake() {
        let dcid = ConnectionId::new(&[0x39; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
    fn late_initial_cannot_reopen_discarded_keys_or_refresh_idle_time() {
        let dcid = ConnectionId::new(&[0x3a; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x3a; 4]),
        )
        .unwrap();
        let now = Instant::now();
        let initial = client.poll_transmit(now).expect("first Initial");
        server.handle_datagram(&initial, now).unwrap();
        drive(&mut client, &mut server);
        assert!(server.handshake_confirmed);
        assert!(server.spaces[SPACE_INITIAL].keys.is_none());
        let last_recv = server.last_recv_time;

        // Delayed/replayed handshake traffic cannot restore a discarded space,
        // including its public keys, packet-number set, or idle activity.
        server
            .handle_datagram(&initial, now + Duration::from_secs(1))
            .unwrap();
        assert!(server.spaces[SPACE_INITIAL].keys.is_none());
        assert_eq!(server.spaces[SPACE_INITIAL].recv.largest(), None);
        assert_eq!(server.last_recv_time, last_recv);
        assert!(!server.is_closed());

        client.send_stream(RELAY_STREAM_ID, b"still established");
        drive(&mut client, &mut server);
        assert_eq!(server.read_stream(RELAY_STREAM_ID), b"still established");
    }

    #[test]
    fn ack_of_unsent_packet_is_rejected() {
        // The DATA space has sent nothing (peek() == 0); an ACK claiming packet 1000
        // is a protocol violation (RFC 9000 §13.1) and must be rejected before it can
        // poison largest_acked and trigger a spurious-loss retransmit storm.
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
            .recv_ack(SPACE_DATA, &ack, Some(0), Instant::now())
            .expect_err("an ACK of a never-sent packet is rejected");
        assert!(matches!(err, QuicTlsError::Protocol(_)), "got {err:?}");
    }

    #[test]
    fn unauthenticated_datagram_does_not_reset_the_idle_timer() {
        // Garbage that never AEAD-opens must not refresh the idle timer (RFC 9000
        // §10.1), else an off-path attacker could pin a connection open forever.
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
    fn never_opening_server_connection_hits_the_cold_start_backstop() {
        // DoS backstop: a server connection created for a spoofed/undecryptable
        // Initial never AEAD-opens a packet, so `last_recv_time` stays `None`.
        // Without the `created_at` fallback it would arm NO timer at all
        // (`next_timeout() == None`) and sit in the endpoint's table forever.
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x0d, 0x05, 0x0d, 0x05]),
        )
        .unwrap();
        let t0 = server.created_at;
        assert_eq!(
            server.next_timeout(),
            Some(t0 + IDLE_TIMEOUT),
            "a connection that never opened a packet still arms the idle backstop"
        );
        // Garbage that never AEAD-opens must not refresh the backstop either.
        let _ = server.handle_datagram(&[0xff; 1200], t0 + Duration::from_secs(1));
        assert_eq!(
            server.next_timeout(),
            Some(t0 + IDLE_TIMEOUT),
            "an un-openable datagram must not push the backstop deadline out"
        );
        // Just before the deadline: still open.
        server.handle_timeout(t0 + IDLE_TIMEOUT - Duration::from_millis(1));
        assert!(!server.is_closed(), "backstop must not fire early");
        // At the deadline: torn down as an idle timeout.
        server.handle_timeout(t0 + IDLE_TIMEOUT);
        assert!(
            matches!(server.close_reason(), Some(CloseReason::IdleTimeout)),
            "cold-start zombie closes as an idle timeout, got {:?}",
            server.close_reason()
        );
        // And after the drain period it is reapable by the endpoint.
        let drain = server
            .next_timeout()
            .expect("a closing connection arms its drain deadline");
        server.handle_timeout(drain);
        assert!(
            server.is_drained(),
            "the endpoint can reap the never-opening connection"
        );
    }

    #[test]
    fn client_with_silent_peer_times_out_instead_of_probing_forever() {
        // A client whose peer NEVER replies keeps `last_recv_time == None`; before
        // the backstop its only timers were PTOs, so it would retransmit Initials
        // forever. Drive it exactly as the endpoint does (handle_timeout at each
        // armed deadline, then poll_transmit) and prove it closes by the backstop.
        let dcid = ConnectionId::new(&[0x51, 0x1e, 0x47, 0x0e, 0x51, 0x1e, 0x47, 0x0e]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let t0 = client.created_at;
        let mut now = t0;
        while client.poll_transmit(now).is_some() {}
        let mut fired = 0u32;
        while !client.is_closed() {
            let deadline = client
                .next_timeout()
                .expect("an unanswered client always has a timer armed");
            assert!(
                deadline <= t0 + IDLE_TIMEOUT,
                "no timer may be armed past the cold-start backstop"
            );
            now = deadline;
            client.handle_timeout(now);
            while client.poll_transmit(now).is_some() {}
            fired += 1;
            assert!(fired < 1000, "must converge to a close, not probe forever");
        }
        assert!(
            matches!(client.close_reason(), Some(CloseReason::IdleTimeout)),
            "silent-peer client closes as an idle timeout, got {:?}",
            client.close_reason()
        );
        assert_eq!(
            now,
            t0 + IDLE_TIMEOUT,
            "teardown happens exactly at the backstop deadline"
        );
    }

    #[test]
    fn established_connection_idle_deadline_tracks_receipt_not_creation() {
        // The backstop must be inert once a packet has AEAD-opened: the idle
        // deadline follows `last_recv_time`, not `created_at`. Handshake at
        // t0+10s, so the receipt-based deadline (t0+40s) is 10s later than the
        // creation-based one (t0+30s) — the connection must survive the latter.
        let dcid = ConnectionId::new(&[0x1d, 0x1e, 0x0f, 0x0f, 0x1d, 0x1e, 0x0f, 0x0f]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x1d, 0x1e, 0x0f, 0x0f]),
        )
        .unwrap();
        let t0 = client.created_at;
        // Lossless in-process pump (like `drive`) but at t0+10s, so last_recv_time
        // lands well after created_at.
        let hs = t0 + Duration::from_secs(10);
        for _ in 0..16 {
            let mut moved = false;
            while let Some(dg) = client.poll_transmit(hs) {
                server.handle_datagram(&dg, hs).unwrap();
                moved = true;
            }
            while let Some(dg) = server.poll_transmit(hs) {
                client.handle_datagram(&dg, hs).unwrap();
                moved = true;
            }
            if !moved {
                break;
            }
        }
        assert!(!client.is_handshaking(), "handshake completed");
        assert_eq!(client.last_recv_time, Some(hs));
        // Past created_at + IDLE_TIMEOUT but before last_recv + IDLE_TIMEOUT:
        // must stay open (the backstop yields to the real receipt time).
        client.handle_timeout(t0 + IDLE_TIMEOUT + Duration::from_secs(1));
        assert!(
            !client.is_closed(),
            "a connection that has received packets must not close on the creation-based backstop"
        );
        // The receipt-based deadline still fires as before.
        client.handle_timeout(hs + IDLE_TIMEOUT);
        assert!(
            matches!(client.close_reason(), Some(CloseReason::IdleTimeout)),
            "the ordinary idle timeout is unaffected, got {:?}",
            client.close_reason()
        );
    }

    /// Issue #75: a datagram at / above / well past the inbound recv cap must fail
    /// safe — no panic, no unbounded allocation, no state created. The kernel
    /// truncates anything larger than the recv buffer to the cap before it reaches
    /// `handle_datagram`; either way an un-openable slice AEAD-fails and is dropped.
    /// Here we exercise `handle_datagram` directly at sizes straddling the 2048
    /// default (and well beyond it) to prove the parse/decrypt path is bounds-safe.
    #[test]
    fn oversized_and_boundary_datagrams_fail_safe() {
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x75, 0x75, 0x75, 0x75]),
        )
        .unwrap();
        // Sizes around the 2048 default cap, plus far beyond it. A long-header byte
        // (0xc0) makes the parser attempt the long-header path; the rest is garbage,
        // so it cannot AEAD-open and must be dropped without panic.
        for &len in &[1199_usize, 1200, 1500, 2047, 2048, 2049, 4096, 8192, 65535] {
            let mut dg = vec![0xff; len];
            dg[0] = 0xc0; // long-header form bit + fixed bit
            let before = server.last_recv_time;
            // Must not panic and must report a clean drop (Ok) — never an error that
            // would tear the connection down on attacker-chosen junk.
            assert!(
                server.handle_datagram(&dg, Instant::now()).is_ok(),
                "a {len}-byte un-openable datagram is dropped cleanly"
            );
            assert_eq!(
                server.last_recv_time, before,
                "an un-openable {len}-byte datagram must not refresh the idle timer"
            );
        }
        // No connection / stream state was created by any of the junk datagrams.
        assert!(
            server.is_handshaking(),
            "no handshake progressed on garbage"
        );
        assert!(
            server.streams.is_empty(),
            "no stream state allocated from oversized garbage"
        );
    }

    #[test]
    fn server_key_update_keys_are_direction_consistent() {
        let dcid = ConnectionId::new(&[0x6c; 8]);
        let mut client =
            Connection::new_client(client_config(), "example.com", dcid, ConnectionId::new(&[]))
                .unwrap();
        let mut server = Connection::new_server(
            Arc::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]),
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
        let ckp = client
            .next_packet_keys
            .as_ref()
            .expect("client 1-RTT update keys");
        let skp = server
            .next_packet_keys
            .as_ref()
            .expect("server 1-RTT update keys");
        let tag = ckp.local.as_ref().unwrap().tag_len();

        // client -> server: client seals (local), server opens (remote).
        let c2s = b"key-update probe client to server";
        let mut buf = c2s.to_vec();
        buf.resize(c2s.len() + tag, 0);
        ckp.local
            .as_ref()
            .unwrap()
            .encrypt_in_place(42, &[], &mut buf)
            .unwrap();
        assert_eq!(
            skp.remote
                .as_ref()
                .unwrap()
                .decrypt_in_place(42, &[], &mut buf)
                .unwrap(),
            c2s,
            "server opens a packet the client sealed with the updated keys"
        );

        // server -> client: server seals (local), client opens (remote).
        let s2c = b"key-update probe server to client";
        let mut buf2 = s2c.to_vec();
        buf2.resize(s2c.len() + tag, 0);
        skp.local
            .as_ref()
            .unwrap()
            .encrypt_in_place(7, &[], &mut buf2)
            .unwrap();
        assert_eq!(
            ckp.remote
                .as_ref()
                .unwrap()
                .decrypt_in_place(7, &[], &mut buf2)
                .unwrap(),
            s2c,
            "client opens a packet the server sealed with the updated keys"
        );
    }
}
