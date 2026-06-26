use std::sync::{Arc, Mutex};

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::session::CipherSuite;

const CONNECT_MAGIC: &[u8; 4] = b"PX1C";
const PQ_REKEY_MAGIC: &[u8; 4] = b"PX1Q";
const SERVER_KEY_EXCHANGE_MAGIC: &[u8; 4] = b"PX1K";
const SERVER_IDENTITY_MAGIC: &[u8; 4] = b"PX1S";
const SERVER_IDENTITY_CHUNK_MAGIC: &[u8; 4] = b"PX1I";
/// Generic framed-chunk carrier for variable-length splitting of the PQ
/// handshake records (PX1Q rekey, PX1K key exchange) across several data
/// records, so neither side emits a single fixed-size first record. The inner
/// payload keeps its own PX1Q/PX1K magic, which disambiguates the message type
/// after reassembly.
const FRAMED_CHUNK_MAGIC: &[u8; 4] = b"PX1F";
const SPEED_TEST_MAGIC: &[u8; 4] = b"PX1T";
const SPEED_WARMUP_DOWNLOAD_DONE_MAGIC: &[u8; 4] = b"PX1W";
const SPEED_WARMUP_UPLOAD_DONE_MAGIC: &[u8; 4] = b"PX1V";
const SPEED_DOWNLOAD_DONE_MAGIC: &[u8; 4] = b"PX1D";
const SPEED_UPLOAD_DONE_MAGIC: &[u8; 4] = b"PX1U";
const MUX_FRAME_MAGIC: &[u8; 4] = b"PX1M";
const MAX_HOST_LEN: usize = 255;
const CONNECT_FIXED_LEN: usize = 4 + 2 + 2 + 4;
const MUX_FRAME_FIXED_LEN: usize = 4 + 4 + 1 + 4;

/// Per-record wire overhead a sealed data record adds on top of its plaintext:
/// the 2-byte self-describing pad-length trailer + the AEAD tag. So a CONNECT
/// record's on-wire TLS `length` field = plaintext + this. Used to translate a
/// target wire size into an `extra_pad` plaintext-suffix length.
const DATA_RECORD_WIRE_OVERHEAD: usize = 2 + 16;

/// Quantized wire-size bands the CONNECT record is padded up to (C3). The raw
/// CONNECT record length is `CONNECT_FIXED_LEN + host_len + initial_payload_len`
/// plus overhead, which directly leaks the target host length and the captured
/// 0-RTT payload size — a small, variable, self-custom control record unlike any
/// browser request. We snap the record to ONE randomly chosen band so the
/// observable size carries no host_len signal, is never a tiny control packet,
/// and is never a single fixed peak. The bands sit in the same sub-2 KiB
/// browser-request magnitude as the measured Safari first-request burst
/// (SETTINGS+WINDOW_UPDATE+HEADERS ~368 B and follow-on requests), WITHOUT
/// pinning to Safari's exact 368 — a fixed Safari value would itself become a
/// cluster signature once ParallaX is being hunted. Reusing the measured-Safari
/// provenance of `PQ_FLIGHT_RECORD_TARGETS`, spread across the realistic CONNECT
/// range so the random choice dominates the size.
const CONNECT_RECORD_SIZE_BANDS: [usize; 8] = [286, 469, 569, 735, 911, 1180, 1353, 1600];

/// Per-chunk plaintext size bounds for [`FramedChunk::encode_all_shaped`]
/// splitting of the PQ handshake records. A fresh size in this range is drawn
/// for every chunk (with a sub-min final remainder merged into the previous
/// chunk), so the wire shows a variable-length, browser-plausible burst with no
/// equal-length record run and no fixed per-session regime — instead of the
/// former fixed ~1631/1632 single record.
pub const PQ_HANDSHAKE_CHUNK_MIN_PLAINTEXT: usize = 256;
pub const PQ_HANDSHAKE_CHUNK_MAX_PLAINTEXT: usize = 1024;

/// Browser-modeled record-size targets for the PQ handshake flight (PAR-35 star2),
/// drawn from the real Safari-26 H2 data-plane capture (see the
/// `safari26-tcp-dataplane-packetization` notes): a small webpage response after a
/// GET is a handful of records whose sizes cluster in the sub-1.5 KiB band, not a
/// uniform `[256,1024]` blob. Shaping the PQ/identity chunks toward THIS one
/// coherent distribution — used identically for the up (PX1Q) and down (PX1K, PX1S)
/// sides — makes the post-handshake burst fall inside the page-load distribution the
/// outer camouflage GET already justifies, instead of reading as a second, heavier
/// PQ key exchange. The values are the measured Safari small/medium H2 record sizes
/// (a subset of `traffic::OBSERVED_PACKET_TARGETS`, the same provenance), kept here
/// so the protocol layer carries no dependency on the traffic module.
const PQ_FLIGHT_RECORD_TARGETS: [usize; 12] =
    [144, 191, 286, 339, 469, 519, 569, 713, 735, 911, 1180, 1353];

/// Lower bound on a shaped PQ record so the flight never emits a tiny tell record,
/// and so the record COUNT stays bounded (a ~4.6 KiB identity proof must not shatter
/// into many sub-100-byte records — that would be a latency/throughput regression on
/// the establishment path, the disqualifier called out in the PAR-21/PAR-28 triage).
const PQ_FLIGHT_RECORD_MIN: usize = 144;

/// Per-session aggregate pad bounds (plaintext bytes appended as a final shaped
/// record) so the TOTAL on-wire size of the PQ flight VARIES across sessions, killing
/// the constant-aggregate cross-session correlation (PAR-28 Low-1). A variable —
/// never constant — pad length keeps the pad itself browser-plausible rather than a
/// new fixed-overhead tell. Bounded to a few hundred bytes: enough to decorrelate the
/// aggregate, small enough to be free on the one-time establishment flight (it never
/// touches the steady-state relay path).
const PQ_FLIGHT_AGGREGATE_PAD_MIN: usize = 64;
const PQ_FLIGHT_AGGREGATE_PAD_MAX: usize = 512;

/// Wire-frame header bytes a [`FramedChunk`] / [`ServerIdentityChunk`] prepends to
/// each chunk's payload: `magic(4) | total_len(4) | offset(4) | len(4)`. The sealed
/// record plaintext for a shaped chunk is therefore `this + chunk_payload_len`, so
/// the per-chunk size cap must leave room for it under the record limit.
const PQ_CHUNK_FRAME_HEADER_LEN: usize = 16;

/// The largest shaped-chunk PAYLOAD size that always seals within the TLS record
/// limit, given the codec's `max_plaintext_len` (`max_sealed_plaintext`: the sealed
/// plaintext budget that already reserves room for the codec's `max_padding`). A
/// shaped chunk seals `PQ_CHUNK_FRAME_HEADER_LEN + size` plaintext bytes; the LAST
/// record additionally carries up to `PQ_FLIGHT_AGGREGATE_PAD_MAX` aggregate-pad
/// bytes. Reserving both keeps EVERY shaped record (any of which may end up last)
/// within the limit even under a heavy-but-valid `max_padding` profile — mirroring the
/// relay path, which chunks at `max_plaintext_len`. Clamped to `>= PQ_FLIGHT_RECORD_MIN`
/// so the tiling invariants (no tiny tell record, bounded count) always hold; for any
/// config the runtime accepts (`max_plaintext_len >= MIN_USABLE_PLAINTEXT_LEN`, 1024)
/// the cap stays well above the floor.
pub fn pq_flight_max_chunk_size(max_sealed_plaintext: usize) -> usize {
    max_sealed_plaintext
        .saturating_sub(PQ_CHUNK_FRAME_HEADER_LEN + PQ_FLIGHT_AGGREGATE_PAD_MAX)
        .max(PQ_FLIGHT_RECORD_MIN)
}
/// Hard cap on a reassembled PQ handshake frame (rekey / key exchange). Both
/// real frames are ~1608/1609 bytes (40/41-byte header + ML-KEM-1024 1568); this
/// bounds a malicious peer's reassembly buffer well above the legitimate maximum
/// while still rejecting absurd totals. The strict length checks in
/// `PqRekeyRequest` / `ServerKeyExchange` decode then reject anything not exactly
/// the right size.
pub(crate) const MAX_PQ_HANDSHAKE_FRAME: usize = 4096;

// UDP fast-plane (TUDP) control commands, carried over the TCP control plane
// alongside the other PX1* commands. Fixed-length wire formats.
const UDP_OFFER_MAGIC: &[u8; 4] = b"PX1O";
const UDP_PROBE_ACK_MAGIC: &[u8; 4] = b"PX1P";
const UDP_REQUEST_MAGIC: &[u8; 4] = b"PX1G";
const UDP_DECLINE_MAGIC: &[u8; 4] = b"PX1N";
const UDP_OFFER_ID_LEN: usize = 16;
const UDP_OFFER_LEN: usize = 4 + UDP_OFFER_ID_LEN + 2 + 8 + 1 + 1 + 1;
const UDP_PROBE_ACK_LEN: usize = 4 + UDP_OFFER_ID_LEN + 1 + 4;
const UDP_REQUEST_LEN: usize = 4 + 1;
const UDP_DECLINE_LEN: usize = 4 + 1;

/// Version byte for the client-initiated UDP negotiation (see [`UdpRequest`]).
pub const UDP_NEGOTIATION_VERSION: u8 = 1;
/// Decline reason codes carried in a [`UdpDecline`] (raw codes for forward-compat).
pub const UDP_DECLINE_DISABLED: u8 = 0;
pub const UDP_DECLINE_UNSUPPORTED: u8 = 1;

/// Congestion-control selector codes carried in a [`UdpOffer`] (kept as raw codes
/// so unknown future controllers round-trip; the runtime maps them to its config).
pub const UDP_CC_BBR: u8 = 0;
pub const UDP_CC_BRUTAL: u8 = 1;
/// FEC profile codes carried in a [`UdpOffer`].
pub const UDP_FEC_OFF: u8 = 0;
pub const UDP_FEC_ADAPTIVE: u8 = 1;
pub const UDP_FEC_RS: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    pub initial_payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectRequestRef<'a> {
    pub host: &'a str,
    pub port: u16,
    pub initial_payload: &'a [u8],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectRequestError {
    #[error("connect request is truncated")]
    Truncated,
    #[error("connect request magic mismatch")]
    BadMagic,
    #[error("connect request host is empty")]
    EmptyHost,
    #[error("connect request host is too long")]
    HostTooLong,
    #[error("connect request host is not valid UTF-8")]
    InvalidHost,
    #[error("connect request port must not be zero")]
    ZeroPort,
    #[error("connect request initial payload length is invalid")]
    InvalidPayloadLength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqRekeyRequest {
    pub client_x25519_public: [u8; 32],
    pub client_mlkem_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqRekeyRequestRef<'a> {
    pub client_x25519_public: [u8; 32],
    pub client_mlkem_public_key: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKeyExchange {
    pub server_x25519_public: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerKeyExchangeRef<'a> {
    pub server_x25519_public: [u8; 32],
    pub mlkem_ciphertext: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentityProof {
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentityChunk {
    pub total_len: u32,
    pub offset: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerIdentityChunkRef<'a> {
    pub total_len: u32,
    pub offset: u32,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeedTestRequest {
    pub warmup_bytes: u64,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub sample_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeedTestAckKind {
    WarmupDownloadDone,
    WarmupUploadDone,
    DownloadDone,
    UploadDone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeedTestAck {
    pub kind: SpeedTestAckKind,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxFrameKind {
    Open,
    Data,
    Fin,
    Reset,
    Cover,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxFrame {
    pub stream_id: u32,
    pub kind: MuxFrameKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxFrameRef<'a> {
    pub stream_id: u32,
    pub kind: MuxFrameKind,
    pub payload: &'a [u8],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PqRekeyError {
    #[error("PQ rekey request is truncated")]
    Truncated,
    #[error("PQ rekey request magic mismatch")]
    BadMagic,
    #[error("PQ rekey ML-KEM public key is empty")]
    EmptyPublicKey,
    #[error("PQ rekey ML-KEM public key length is invalid")]
    InvalidPublicKeyLength,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ServerKeyExchangeError {
    #[error("server key exchange is truncated")]
    Truncated,
    #[error("server key exchange magic mismatch")]
    BadMagic,
    #[error("server key exchange ML-KEM ciphertext is empty")]
    EmptyCiphertext,
    #[error("server key exchange ML-KEM ciphertext length is invalid")]
    InvalidCiphertextLength,
    #[error("server key exchange carries an unknown cipher suite tag")]
    InvalidCipherSuite,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ServerIdentityProofError {
    #[error("server identity proof is truncated")]
    Truncated,
    #[error("server identity proof magic mismatch")]
    BadMagic,
    #[error("server identity proof signature is empty")]
    EmptySignature,
    #[error("server identity proof signature length is invalid")]
    InvalidSignatureLength,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ServerIdentityChunkError {
    #[error("server identity chunk is truncated")]
    Truncated,
    #[error("server identity chunk magic mismatch")]
    BadMagic,
    #[error("server identity chunk payload is empty")]
    EmptyChunk,
    #[error("server identity chunk length is invalid")]
    InvalidChunkLength,
    #[error("server identity chunk offset is invalid")]
    InvalidOffset,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SpeedTestRequestError {
    #[error("speed test request is truncated")]
    Truncated,
    #[error("speed test request magic mismatch")]
    BadMagic,
    #[error("speed test request byte count must not be zero")]
    ZeroBytes,
    #[error("speed test request sample count must not be zero")]
    ZeroSamples,
    #[error("speed test request length is invalid")]
    InvalidLength,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SpeedTestAckError {
    #[error("speed test ack is truncated")]
    Truncated,
    #[error("speed test ack magic mismatch")]
    BadMagic,
    #[error("speed test ack length is invalid")]
    InvalidLength,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MuxFrameError {
    #[error("mux frame is truncated")]
    Truncated,
    #[error("mux frame magic mismatch")]
    BadMagic,
    #[error("mux frame kind is invalid")]
    InvalidKind,
    #[error("mux frame stream id is invalid")]
    InvalidStreamId,
    #[error("mux frame payload is too long")]
    PayloadTooLong,
    #[error("mux frame payload length is invalid")]
    InvalidPayloadLength,
}

impl ConnectRequest {
    pub fn max_initial_payload_len(host: &str, max_encoded_len: usize) -> usize {
        max_encoded_len.saturating_sub(CONNECT_FIXED_LEN + host.len())
    }

    pub fn encoded_len(&self) -> usize {
        CONNECT_FIXED_LEN + self.host.len() + self.initial_payload.len()
    }

    /// Extra plaintext-suffix padding (C3) to snap this CONNECT record's on-wire
    /// size onto one randomly chosen [`CONNECT_RECORD_SIZE_BANDS`] band, so the
    /// observable record length leaks neither the target host length nor the
    /// captured 0-RTT payload size.
    ///
    /// A band is chosen UNIFORMLY AT RANDOM among those large enough to hold this
    /// record, then the pad fills the gap. Choosing among all fitting bands (not
    /// "the next band up") is what severs the size→payload correlation: for the
    /// common case (raw size below the smallest band) the result is one of the
    /// full band set regardless of host_len, so two different targets produce the
    /// same size distribution. `max_extra_pad` caps the pad so the padded record
    /// still fits one outer TLS record; if even the natural size already exceeds
    /// the largest band (only reachable with a near-maximal captured 0-RTT
    /// payload) no band fits and we add no extra pad — a rare tail, and that
    /// record's size is dominated by the large payload, not by host_len.
    pub fn shaping_extra_pad<R>(&self, max_extra_pad: usize, rng: &mut R) -> usize
    where
        R: rand::Rng + ?Sized,
    {
        let raw_wire = self.encoded_len() + DATA_RECORD_WIRE_OVERHEAD;
        let mut fitting = CONNECT_RECORD_SIZE_BANDS
            .iter()
            .copied()
            .filter(|&band| band >= raw_wire && band - raw_wire <= max_extra_pad)
            .peekable();
        if fitting.peek().is_none() {
            return 0;
        }
        let candidates: Vec<usize> = fitting.collect();
        let band = candidates[rng.gen_range(0..candidates.len())];
        band - raw_wire
    }

    pub fn target(&self) -> String {
        connect_target(&self.host, self.port)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ConnectRequestError> {
        let host = self.host.as_bytes();
        if host.is_empty() {
            return Err(ConnectRequestError::EmptyHost);
        }
        if host.len() > MAX_HOST_LEN {
            return Err(ConnectRequestError::HostTooLong);
        }
        if self.port == 0 {
            return Err(ConnectRequestError::ZeroPort);
        }

        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(CONNECT_MAGIC);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&(self.initial_payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.initial_payload);
        crate::process_hardening::exclude_from_core_dump("connect_request.encoded", &out);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConnectRequestError> {
        let request = Self::decode_ref(input)?;
        Ok(Self {
            host: request.host.to_owned(),
            port: request.port,
            initial_payload: request.initial_payload.to_vec(),
        })
    }

    pub fn decode_ref(input: &[u8]) -> Result<ConnectRequestRef<'_>, ConnectRequestError> {
        if input.len() < 4 {
            return Err(ConnectRequestError::Truncated);
        }
        if &input[..4] != CONNECT_MAGIC {
            return Err(ConnectRequestError::BadMagic);
        }

        let mut cursor = Cursor::new(input, 4);
        let host_len = cursor.u16()? as usize;
        if host_len == 0 {
            return Err(ConnectRequestError::EmptyHost);
        }
        if host_len > MAX_HOST_LEN {
            return Err(ConnectRequestError::HostTooLong);
        }
        let host = cursor.bytes(host_len)?;
        let host = std::str::from_utf8(host).map_err(|_| ConnectRequestError::InvalidHost)?;

        let port = cursor.u16()?;
        if port == 0 {
            return Err(ConnectRequestError::ZeroPort);
        }

        let payload_len = cursor.u32()? as usize;
        if cursor.remaining() != payload_len {
            return Err(ConnectRequestError::InvalidPayloadLength);
        }
        let initial_payload = cursor.bytes(payload_len)?;

        let request = ConnectRequestRef {
            host,
            port,
            initial_payload,
        };
        request.protect_plaintext_memory();
        Ok(request)
    }

    pub fn protect_plaintext_memory(&self) {
        crate::process_hardening::exclude_from_core_dump(
            "connect_request.host",
            self.host.as_bytes(),
        );
        crate::process_hardening::exclude_from_core_dump(
            "connect_request.initial_payload",
            &self.initial_payload,
        );
    }
}

impl ConnectRequestRef<'_> {
    pub fn target(&self) -> String {
        connect_target(self.host, self.port)
    }

    pub fn protect_plaintext_memory(&self) {
        crate::process_hardening::exclude_from_core_dump(
            "connect_request.host",
            self.host.as_bytes(),
        );
        crate::process_hardening::exclude_from_core_dump(
            "connect_request.initial_payload",
            self.initial_payload,
        );
    }
}

/// Whether a CONNECT record's on-wire TLS payload length is one of the C3
/// shaping bands. Diagnostic/test helper so the shaping invariant can be checked
/// from other modules without exposing the band table.
pub fn connect_record_size_is_shaped(wire_payload_len: usize) -> bool {
    CONNECT_RECORD_SIZE_BANDS.contains(&wire_payload_len)
}

fn connect_target(host: &str, port: u16) -> String {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

impl PqRekeyRequest {
    pub fn encode(&self) -> Result<Vec<u8>, PqRekeyError> {
        Self::encode_borrowed(&self.client_x25519_public, &self.client_mlkem_public_key)
    }

    pub(crate) fn encode_borrowed(
        client_x25519_public: &[u8; 32],
        client_mlkem_public_key: &[u8],
    ) -> Result<Vec<u8>, PqRekeyError> {
        if client_mlkem_public_key.is_empty() {
            return Err(PqRekeyError::EmptyPublicKey);
        }
        let mut out = Vec::with_capacity(40 + client_mlkem_public_key.len());
        out.extend_from_slice(PQ_REKEY_MAGIC);
        out.extend_from_slice(client_x25519_public);
        out.extend_from_slice(&(client_mlkem_public_key.len() as u32).to_be_bytes());
        out.extend_from_slice(client_mlkem_public_key);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PqRekeyError> {
        let request = Self::decode_ref(input)?;
        Ok(Self {
            client_x25519_public: request.client_x25519_public,
            client_mlkem_public_key: request.client_mlkem_public_key.to_vec(),
        })
    }

    pub fn decode_ref(input: &[u8]) -> Result<PqRekeyRequestRef<'_>, PqRekeyError> {
        if input.len() < 4 {
            return Err(PqRekeyError::Truncated);
        }
        if &input[..4] != PQ_REKEY_MAGIC {
            return Err(PqRekeyError::BadMagic);
        }
        if input.len() < 40 {
            return Err(PqRekeyError::Truncated);
        }
        let mut client_x25519_public = [0_u8; 32];
        client_x25519_public.copy_from_slice(&input[4..36]);
        let len = u32::from_be_bytes([input[36], input[37], input[38], input[39]]) as usize;
        if len == 0 {
            return Err(PqRekeyError::EmptyPublicKey);
        }
        if input.len() != 40 + len {
            return Err(PqRekeyError::InvalidPublicKeyLength);
        }
        Ok(PqRekeyRequestRef {
            client_x25519_public,
            client_mlkem_public_key: &input[40..],
        })
    }
}

impl ServerKeyExchange {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ServerKeyExchangeError> {
        if self.mlkem_ciphertext.is_empty() {
            return Err(ServerKeyExchangeError::EmptyCiphertext);
        }
        let mut out = Vec::with_capacity(40 + self.mlkem_ciphertext.len());
        out.extend_from_slice(SERVER_KEY_EXCHANGE_MAGIC);
        out.extend_from_slice(&self.server_x25519_public);
        out.extend_from_slice(&(self.mlkem_ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.mlkem_ciphertext);
        Ok(out)
    }

    /// Like [`Self::encode`] but appends the one-byte negotiated cipher-suite
    /// tag. The server uses this; the client reads it with
    /// [`Self::decode_ref_with_suite`].
    pub fn encode_with_suite(&self, suite: CipherSuite) -> Result<Vec<u8>, ServerKeyExchangeError> {
        let mut out = self.encode()?;
        out.push(suite.to_wire());
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ServerKeyExchangeError> {
        let exchange = Self::decode_ref(input)?;
        Ok(Self {
            server_x25519_public: exchange.server_x25519_public,
            mlkem_ciphertext: exchange.mlkem_ciphertext.to_vec(),
        })
    }

    pub fn decode_ref(input: &[u8]) -> Result<ServerKeyExchangeRef<'_>, ServerKeyExchangeError> {
        Self::decode_ref_with_suite(input).map(|(exchange, _suite)| exchange)
    }

    /// Canonical parser. Requires the `41 + ct_len` layout: the 40-byte header
    /// (magic + server x25519 public + ct_len) followed by the ciphertext and a
    /// trailing one-byte cipher-suite tag. The ciphertext slice is bounded to
    /// exactly `ct_len`, so the trailing tag never bleeds into it.
    pub fn decode_ref_with_suite(
        input: &[u8],
    ) -> Result<(ServerKeyExchangeRef<'_>, CipherSuite), ServerKeyExchangeError> {
        if input.len() < 4 {
            return Err(ServerKeyExchangeError::Truncated);
        }
        if &input[..4] != SERVER_KEY_EXCHANGE_MAGIC {
            return Err(ServerKeyExchangeError::BadMagic);
        }
        if input.len() < 40 {
            return Err(ServerKeyExchangeError::Truncated);
        }
        let mut server_x25519_public = [0_u8; 32];
        server_x25519_public.copy_from_slice(&input[4..36]);
        let len = u32::from_be_bytes([input[36], input[37], input[38], input[39]]) as usize;
        if len == 0 {
            return Err(ServerKeyExchangeError::EmptyCiphertext);
        }
        // Reject an impossible length before the `41 + len` arithmetic so it
        // cannot wrap usize on a hypothetical 32-bit target (ParallaX ships
        // 64-bit only; belt-and-suspenders, redundant with the exact-length
        // check below on 64-bit but free).
        if len > input.len() {
            return Err(ServerKeyExchangeError::InvalidCiphertextLength);
        }
        if input.len() != 41 + len {
            return Err(ServerKeyExchangeError::InvalidCiphertextLength);
        }
        let suite = CipherSuite::from_wire(input[40 + len])
            .ok_or(ServerKeyExchangeError::InvalidCipherSuite)?;
        Ok((
            ServerKeyExchangeRef {
                server_x25519_public,
                mlkem_ciphertext: &input[40..40 + len],
            },
            suite,
        ))
    }
}

impl ServerIdentityProof {
    pub fn encode(&self) -> Result<Vec<u8>, ServerIdentityProofError> {
        if self.signature.is_empty() {
            return Err(ServerIdentityProofError::EmptySignature);
        }
        let mut out = Vec::with_capacity(8 + self.signature.len());
        out.extend_from_slice(SERVER_IDENTITY_MAGIC);
        out.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ServerIdentityProofError> {
        Ok(Self {
            signature: Self::signature(input)?.to_vec(),
        })
    }

    pub fn signature(input: &[u8]) -> Result<&[u8], ServerIdentityProofError> {
        if input.len() < 4 {
            return Err(ServerIdentityProofError::Truncated);
        }
        if &input[..4] != SERVER_IDENTITY_MAGIC {
            return Err(ServerIdentityProofError::BadMagic);
        }
        if input.len() < 8 {
            return Err(ServerIdentityProofError::Truncated);
        }
        let len = u32::from_be_bytes([input[4], input[5], input[6], input[7]]) as usize;
        if len == 0 {
            return Err(ServerIdentityProofError::EmptySignature);
        }
        if input.len() != 8 + len {
            return Err(ServerIdentityProofError::InvalidSignatureLength);
        }
        Ok(&input[8..])
    }
}

impl ServerIdentityChunk {
    pub fn encode(&self) -> Result<Vec<u8>, ServerIdentityChunkError> {
        Self::encode_borrowed(self.total_len, self.offset, &self.bytes)
    }

    fn encode_borrowed(
        total_len: u32,
        offset: u32,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ServerIdentityChunkError> {
        if bytes.is_empty() {
            return Err(ServerIdentityChunkError::EmptyChunk);
        }
        let end = offset
            .checked_add(bytes.len() as u32)
            .ok_or(ServerIdentityChunkError::InvalidOffset)?;
        if total_len == 0 || end > total_len {
            return Err(ServerIdentityChunkError::InvalidOffset);
        }

        let mut out = Vec::with_capacity(16 + bytes.len());
        out.extend_from_slice(SERVER_IDENTITY_CHUNK_MAGIC);
        out.extend_from_slice(&total_len.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ServerIdentityChunkError> {
        let chunk = Self::decode_ref(input)?;
        Ok(Self {
            total_len: chunk.total_len,
            offset: chunk.offset,
            bytes: chunk.bytes.to_vec(),
        })
    }

    pub fn decode_ref(
        input: &[u8],
    ) -> Result<ServerIdentityChunkRef<'_>, ServerIdentityChunkError> {
        if input.len() < 4 {
            return Err(ServerIdentityChunkError::Truncated);
        }
        if &input[..4] != SERVER_IDENTITY_CHUNK_MAGIC {
            return Err(ServerIdentityChunkError::BadMagic);
        }
        if input.len() < 16 {
            return Err(ServerIdentityChunkError::Truncated);
        }
        let total_len = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
        let offset = u32::from_be_bytes([input[8], input[9], input[10], input[11]]);
        let len = u32::from_be_bytes([input[12], input[13], input[14], input[15]]) as usize;
        if len == 0 {
            return Err(ServerIdentityChunkError::EmptyChunk);
        }
        if input.len() != 16 + len {
            return Err(ServerIdentityChunkError::InvalidChunkLength);
        }
        let end = offset
            .checked_add(len as u32)
            .ok_or(ServerIdentityChunkError::InvalidOffset)?;
        if total_len == 0 || end > total_len {
            return Err(ServerIdentityChunkError::InvalidOffset);
        }
        Ok(ServerIdentityChunkRef {
            total_len,
            offset,
            bytes: &input[16..],
        })
    }

    pub fn encode_all(
        payload: &[u8],
        max_chunk_len: usize,
    ) -> Result<Vec<Vec<u8>>, ServerIdentityChunkError> {
        if payload.is_empty() || max_chunk_len == 0 || payload.len() > u32::MAX as usize {
            return Err(ServerIdentityChunkError::InvalidChunkLength);
        }
        let total_len = payload.len() as u32;
        let mut chunks = Vec::with_capacity(payload.len().div_ceil(max_chunk_len));
        for (idx, bytes) in payload.chunks(max_chunk_len).enumerate() {
            chunks.push(Self::encode_borrowed(
                total_len,
                (idx * max_chunk_len) as u32,
                bytes,
            )?);
        }
        Ok(chunks)
    }

    /// Split the identity proof into records sized from the SAME browser-modeled
    /// distribution as the PQ key-exchange chunks (PAR-35), so the server->client
    /// PX1K + PX1S burst shares one coherent H2-page-like record-size regime instead
    /// of a visible `[256,1024]`-then-`[960,1320]` regime switch a passive observer
    /// could segment on. Sizes tile the payload exactly and the count stays bounded
    /// (each record `>= PQ_FLIGHT_RECORD_MIN`); the client reassembler is offset-based
    /// and size-agnostic, so it recovers the proof regardless of how it was chunked.
    ///
    /// `max_record_size` caps each chunk's payload so the sealed record fits the TLS
    /// record limit under the codec's `max_padding` (see
    /// [`FramedChunk::encode_all_browser_shaped`]); pass
    /// [`pq_flight_max_chunk_size`]`(codec.max_plaintext_len())`.
    pub fn encode_all_browser_shaped<R: rand::Rng + ?Sized>(
        payload: &[u8],
        max_record_size: usize,
        rng: &mut R,
    ) -> Result<Vec<Vec<u8>>, ServerIdentityChunkError> {
        if payload.is_empty() || payload.len() > u32::MAX as usize {
            return Err(ServerIdentityChunkError::InvalidChunkLength);
        }
        let total_len = payload.len() as u32;
        let mut chunks = Vec::new();
        let mut offset = 0_usize;
        for size in browser_shaped_sizes(payload.len(), max_record_size, rng) {
            let end = offset + size;
            chunks.push(Self::encode_borrowed(
                total_len,
                offset as u32,
                &payload[offset..end],
            )?);
            offset = end;
        }
        debug_assert_eq!(offset, payload.len());
        Ok(chunks)
    }
}

/// One chunk of a [`FramedChunk`]-carried payload. Wire layout mirrors
/// [`ServerIdentityChunk`]: `magic(4) | total_len(4) | offset(4) | len(4) | bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedChunk {
    pub total_len: u32,
    pub offset: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramedChunkRef<'a> {
    pub total_len: u32,
    pub offset: u32,
    pub bytes: &'a [u8],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FramedChunkError {
    #[error("framed chunk is truncated")]
    Truncated,
    #[error("framed chunk magic mismatch")]
    BadMagic,
    #[error("framed chunk is empty")]
    EmptyChunk,
    #[error("framed chunk length is invalid")]
    InvalidChunkLength,
    #[error("framed chunk offset is invalid")]
    InvalidOffset,
    #[error("framed payload exceeds the maximum permitted size")]
    TooLarge,
    #[error("framed chunk total length is inconsistent across chunks")]
    InconsistentTotal,
    #[error("framed chunk arrived out of order")]
    OutOfOrder,
}

impl FramedChunk {
    fn encode_borrowed(
        total_len: u32,
        offset: u32,
        bytes: &[u8],
    ) -> Result<Vec<u8>, FramedChunkError> {
        if bytes.is_empty() {
            return Err(FramedChunkError::EmptyChunk);
        }
        let end = offset
            .checked_add(bytes.len() as u32)
            .ok_or(FramedChunkError::InvalidOffset)?;
        if total_len == 0 || end > total_len {
            return Err(FramedChunkError::InvalidOffset);
        }
        let mut out = Vec::with_capacity(16 + bytes.len());
        out.extend_from_slice(FRAMED_CHUNK_MAGIC);
        out.extend_from_slice(&total_len.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        Ok(out)
    }

    pub fn decode_ref(input: &[u8]) -> Result<FramedChunkRef<'_>, FramedChunkError> {
        if input.len() < 4 {
            return Err(FramedChunkError::Truncated);
        }
        if &input[..4] != FRAMED_CHUNK_MAGIC {
            return Err(FramedChunkError::BadMagic);
        }
        if input.len() < 16 {
            return Err(FramedChunkError::Truncated);
        }
        let total_len = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
        let offset = u32::from_be_bytes([input[8], input[9], input[10], input[11]]);
        let len = u32::from_be_bytes([input[12], input[13], input[14], input[15]]) as usize;
        if len == 0 {
            return Err(FramedChunkError::EmptyChunk);
        }
        // checked_add so a crafted `len` near u32::MAX cannot overflow `16 + len`
        // on 32-bit targets (matches the offset arithmetic below).
        let expected = 16usize
            .checked_add(len)
            .ok_or(FramedChunkError::InvalidChunkLength)?;
        if input.len() != expected {
            return Err(FramedChunkError::InvalidChunkLength);
        }
        let end = offset
            .checked_add(len as u32)
            .ok_or(FramedChunkError::InvalidOffset)?;
        if total_len == 0 || end > total_len {
            return Err(FramedChunkError::InvalidOffset);
        }
        Ok(FramedChunkRef {
            total_len,
            offset,
            bytes: &input[16..],
        })
    }

    /// Split `payload` into a sequence of chunk records, each carrying at most
    /// `chunk_len` plaintext bytes. The caller picks `chunk_len` per session
    /// (e.g. `rng.gen_range(PQ_HANDSHAKE_CHUNK_MIN_PLAINTEXT..=MAX)`), so the
    /// emitted record sizes vary across connections. Mirrors
    /// [`ServerIdentityChunk::encode_all`].
    pub fn encode_all(payload: &[u8], chunk_len: usize) -> Result<Vec<Vec<u8>>, FramedChunkError> {
        if payload.is_empty() || chunk_len == 0 || payload.len() > u32::MAX as usize {
            return Err(FramedChunkError::InvalidChunkLength);
        }
        let total_len = payload.len() as u32;
        let mut chunks = Vec::with_capacity(payload.len().div_ceil(chunk_len));
        for (idx, bytes) in payload.chunks(chunk_len).enumerate() {
            chunks.push(Self::encode_borrowed(
                total_len,
                (idx * chunk_len) as u32,
                bytes,
            )?);
        }
        Ok(chunks)
    }

    /// Like [`Self::encode_all`] but draws a FRESH random plaintext size in
    /// `[min_chunk, max_chunk]` for every chunk, constraining each draw so the
    /// remainder is always 0 or >= `min_chunk`. Every chunk therefore stays within
    /// `[min_chunk, max_chunk]` (no sub-min tail, no collapse of a just-over-max
    /// payload into one record), removing the residual low-entropy shape a single
    /// per-session `chunk_len` would leave: no byte-identical record run, no fixed
    /// per-session regime, no tiny tell record (PAR-21 review). Sizes tile the
    /// payload exactly; the reassembler is size-agnostic, so the two ends need not
    /// agree on sizes.
    pub fn encode_all_shaped<R: rand::Rng + ?Sized>(
        payload: &[u8],
        rng: &mut R,
        min_chunk: usize,
        max_chunk: usize,
    ) -> Result<Vec<Vec<u8>>, FramedChunkError> {
        if payload.is_empty()
            || min_chunk == 0
            || max_chunk < min_chunk
            || payload.len() > u32::MAX as usize
        {
            return Err(FramedChunkError::InvalidChunkLength);
        }
        let total_len = payload.len() as u32;
        // Pick per-chunk sizes that tile the payload, constraining each draw so the
        // remainder is always either 0 or >= min_chunk. This keeps every chunk
        // within [min_chunk, max_chunk] -- no sub-min tail to merge, no collapse of
        // a just-over-max payload into one record, no over-max merge -- while still
        // varying every chunk size.
        let mut sizes: Vec<usize> = Vec::new();
        let mut consumed = 0_usize;
        while consumed < payload.len() {
            let remaining = payload.len() - consumed;
            if remaining <= max_chunk {
                // Final chunk. Reached either via constrained draws (so remaining
                // >= min_chunk) or directly when the whole payload is <= max_chunk
                // (a lone chunk, < min_chunk only when the payload itself is that
                // small -- not the case for PQ handshake records).
                sizes.push(remaining);
                break;
            }
            // remaining > max_chunk: draw a size that leaves a >= min_chunk tail.
            let hi = max_chunk.min(remaining - min_chunk);
            let take = if hi >= min_chunk {
                rng.gen_range(min_chunk..=hi)
            } else {
                // Only reachable for pathological bounds (max_chunk < 2*min_chunk)
                // where no split can keep the tail >= min_chunk; emit one max chunk.
                max_chunk
            };
            sizes.push(take);
            consumed += take;
        }
        let mut chunks = Vec::with_capacity(sizes.len());
        let mut offset = 0_usize;
        for size in sizes {
            let end = offset + size;
            chunks.push(Self::encode_borrowed(
                total_len,
                offset as u32,
                &payload[offset..end],
            )?);
            offset = end;
        }
        debug_assert_eq!(offset, payload.len());
        Ok(chunks)
    }

    /// Split `payload` into records whose sizes are drawn from the browser-modeled
    /// [`PQ_FLIGHT_RECORD_TARGETS`] distribution (PAR-35 star2), instead of the uniform
    /// `[256,1024]` of [`Self::encode_all_shaped`]. Used for BOTH the PQ key-exchange
    /// (PX1Q/PX1K) and the identity proof (PX1S), so the whole post-handshake burst
    /// shares ONE coherent record-size regime that matches a real Safari H2 page
    /// response — no intra-flight regime discontinuity to segment on, and no
    /// constant-shaped PQ blob to recognize.
    ///
    /// Like `encode_all_shaped` the sizes tile the payload exactly and every chunk
    /// stays `>= PQ_FLIGHT_RECORD_MIN` (no tiny tell record); the reassembler is
    /// size-agnostic so the two ends need not agree on sizes. The record COUNT is
    /// bounded by construction (each chunk carries at least `PQ_FLIGHT_RECORD_MIN`
    /// bytes), so a large identity proof never shatters into many tiny records — the
    /// latency/throughput disqualifier from the PAR-21/PAR-28 triage. Aggregate
    /// (flight-level) decorrelation padding is applied separately at the seal layer
    /// via the per-record padding suffix, so it stays fully decode-transparent and
    /// this splitter remains a pure function of `(payload, max_record_size, rng)`.
    ///
    /// `max_record_size` caps each shaped chunk's payload so the sealed record
    /// (`PQ_CHUNK_FRAME_HEADER_LEN + chunk` plaintext, plus the aggregate pad on the
    /// last record) always fits the TLS record limit under the codec's `max_padding`;
    /// callers pass [`pq_flight_max_chunk_size`]`(codec.max_plaintext_len())`. Under the
    /// default / light-padding profile the cap is far above the target distribution, so
    /// the on-wire shape is unchanged.
    pub fn encode_all_browser_shaped<R: rand::Rng + ?Sized>(
        payload: &[u8],
        max_record_size: usize,
        rng: &mut R,
    ) -> Result<Vec<Vec<u8>>, FramedChunkError> {
        if payload.is_empty() || payload.len() > u32::MAX as usize {
            return Err(FramedChunkError::InvalidChunkLength);
        }
        let total_len = payload.len() as u32;
        let mut chunks = Vec::new();
        let mut offset = 0_usize;
        for size in browser_shaped_sizes(payload.len(), max_record_size, rng) {
            let end = offset + size;
            chunks.push(Self::encode_borrowed(
                total_len,
                offset as u32,
                &payload[offset..end],
            )?);
            offset = end;
        }
        debug_assert_eq!(offset, payload.len());
        Ok(chunks)
    }

    /// Per-session aggregate pad length (plaintext bytes) for the PQ flight, drawn
    /// uniformly from `[PQ_FLIGHT_AGGREGATE_PAD_MIN, PQ_FLIGHT_AGGREGATE_PAD_MAX]`, so
    /// the flight's TOTAL on-wire size varies across sessions (decorrelation, PAR-28
    /// Low-1). Applied by the seal layer as extra per-record padding-suffix bytes,
    /// which the receiver strips transparently — so the wire frame and the reassembler
    /// are unchanged. A variable (never constant) length keeps the pad itself
    /// browser-plausible rather than a new fixed-overhead tell.
    pub fn aggregate_pad_len<R: rand::Rng + ?Sized>(rng: &mut R) -> usize {
        rng.gen_range(PQ_FLIGHT_AGGREGATE_PAD_MIN..=PQ_FLIGHT_AGGREGATE_PAD_MAX)
    }
}

/// Tile a payload of `payload_len` bytes into record sizes drawn from the
/// browser-modeled [`PQ_FLIGHT_RECORD_TARGETS`] distribution, shared by the PQ
/// key-exchange chunks ([`FramedChunk::encode_all_browser_shaped`]) and the identity
/// proof chunks ([`ServerIdentityChunk::encode_all_browser_shaped`]) so the whole PQ
/// flight uses ONE coherent regime (PAR-35). The sizes tile the payload exactly, and
/// every record carries `>= PQ_FLIGHT_RECORD_MIN` bytes except possibly a lone tiny
/// payload (not the case for any PQ/identity frame) — so the record COUNT stays
/// bounded (no shatter-into-many-records latency regression) and there is no tiny
/// tell record.
fn browser_shaped_sizes<R: rand::Rng + ?Sized>(
    payload_len: usize,
    max_record_size: usize,
    rng: &mut R,
) -> Vec<usize> {
    let target_max = *PQ_FLIGHT_RECORD_TARGETS
        .iter()
        .max()
        .expect("PQ_FLIGHT_RECORD_TARGETS is non-empty");
    // Cap the largest emitted record at the codec's safe ceiling so every shaped
    // record (each of which may end up the padded last one) seals within the TLS
    // record limit even under a heavy `max_padding` profile. `max_record_size` is
    // >= PQ_FLIGHT_RECORD_MIN (the caller clamps via `pq_flight_max_chunk_size`), so
    // the tiling/`>= MIN`-tail invariants below are unaffected.
    let max_target = target_max.min(max_record_size.max(PQ_FLIGHT_RECORD_MIN));
    let mut sizes = Vec::new();
    let mut consumed = 0_usize;
    while consumed < payload_len {
        let remaining = payload_len - consumed;
        if remaining <= max_target {
            // Final record carries the whole remainder.
            sizes.push(remaining);
            break;
        }
        // remaining > max_target: pick a target that leaves a >= MIN tail.
        let hi = max_target.min(remaining - PQ_FLIGHT_RECORD_MIN);
        let take = pick_target_size(rng, hi);
        sizes.push(take);
        consumed += take;
    }
    sizes
}

/// Draw a record size from [`PQ_FLIGHT_RECORD_TARGETS`] that is `<= hi` (so the
/// constrained tail invariant holds). Falls back to `hi` clamped up to
/// `PQ_FLIGHT_RECORD_MIN` when no target fits — only reachable when `hi` is below the
/// smallest target, i.e. the penultimate record of a short tail.
fn pick_target_size<R: rand::Rng + ?Sized>(rng: &mut R, hi: usize) -> usize {
    let choices: Vec<usize> = PQ_FLIGHT_RECORD_TARGETS
        .iter()
        .copied()
        .filter(|&t| t <= hi)
        .collect();
    if choices.is_empty() {
        return hi.max(PQ_FLIGHT_RECORD_MIN);
    }
    choices[rng.gen_range(0..choices.len())]
}

/// Stateful reassembler for a [`FramedChunk`] sequence. Mirrors the in-order,
/// total-length-bounded accumulation that `read_server_identity_payload` already
/// uses for the identity proof: every chunk must agree on `total_len`, chunks
/// must arrive in offset order, and `total_len` must not exceed `cap` (a
/// memory-DoS bound). [`Self::push`] returns `Some(payload)` once the whole
/// frame is assembled, `None` while more chunks are needed.
#[derive(Debug, Default)]
pub struct FramedReassembler {
    expected_total: Option<usize>,
    assembled: Vec<u8>,
}

impl FramedReassembler {
    pub fn push(&mut self, chunk: &[u8], cap: usize) -> Result<Option<Vec<u8>>, FramedChunkError> {
        let chunk = FramedChunk::decode_ref(chunk)?;
        let total_len = chunk.total_len as usize;
        if total_len == 0 || total_len > cap {
            return Err(FramedChunkError::TooLarge);
        }
        match self.expected_total {
            Some(expected) if expected != total_len => {
                return Err(FramedChunkError::InconsistentTotal);
            }
            None => {
                self.expected_total = Some(total_len);
                self.assembled.reserve(total_len);
            }
            _ => {}
        }
        if chunk.offset as usize != self.assembled.len() {
            return Err(FramedChunkError::OutOfOrder);
        }
        self.assembled.extend_from_slice(chunk.bytes);
        if self.assembled.len() == total_len {
            // Clear the expected-total latch as well as taking the buffer, so the
            // reassembler carries no stale state if reused for a fresh frame.
            self.expected_total = None;
            return Ok(Some(std::mem::take(&mut self.assembled)));
        }
        // Defensive backstop: unreachable given decode_ref guarantees
        // offset + len <= total_len and offset == assembled.len() above, but kept
        // so a future invariant change fails closed rather than over-reading.
        if self.assembled.len() > total_len {
            return Err(FramedChunkError::OutOfOrder);
        }
        Ok(None)
    }
}

impl SpeedTestRequest {
    pub fn has_magic(input: &[u8]) -> bool {
        input.len() >= 4 && &input[..4] == SPEED_TEST_MAGIC
    }

    pub fn encode(&self) -> Result<Vec<u8>, SpeedTestRequestError> {
        if self.warmup_bytes == 0 || self.download_bytes == 0 || self.upload_bytes == 0 {
            return Err(SpeedTestRequestError::ZeroBytes);
        }
        if self.sample_count == 0 {
            return Err(SpeedTestRequestError::ZeroSamples);
        }
        let mut out = Vec::with_capacity(30);
        out.extend_from_slice(SPEED_TEST_MAGIC);
        out.extend_from_slice(&self.warmup_bytes.to_be_bytes());
        out.extend_from_slice(&self.download_bytes.to_be_bytes());
        out.extend_from_slice(&self.upload_bytes.to_be_bytes());
        out.extend_from_slice(&self.sample_count.to_be_bytes());
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SpeedTestRequestError> {
        if input.len() < 4 {
            return Err(SpeedTestRequestError::Truncated);
        }
        if &input[..4] != SPEED_TEST_MAGIC {
            return Err(SpeedTestRequestError::BadMagic);
        }
        if input.len() < 30 {
            return Err(SpeedTestRequestError::Truncated);
        }
        if input.len() != 30 {
            return Err(SpeedTestRequestError::InvalidLength);
        }
        let warmup_bytes = u64::from_be_bytes([
            input[4], input[5], input[6], input[7], input[8], input[9], input[10], input[11],
        ]);
        let download_bytes = u64::from_be_bytes([
            input[12], input[13], input[14], input[15], input[16], input[17], input[18], input[19],
        ]);
        let upload_bytes = u64::from_be_bytes([
            input[20], input[21], input[22], input[23], input[24], input[25], input[26], input[27],
        ]);
        let sample_count = u16::from_be_bytes([input[28], input[29]]);
        if warmup_bytes == 0 || download_bytes == 0 || upload_bytes == 0 {
            return Err(SpeedTestRequestError::ZeroBytes);
        }
        if sample_count == 0 {
            return Err(SpeedTestRequestError::ZeroSamples);
        }
        Ok(Self {
            warmup_bytes,
            download_bytes,
            upload_bytes,
            sample_count,
        })
    }
}

impl SpeedTestAck {
    pub fn warmup_download_done(bytes: u64) -> Self {
        Self {
            kind: SpeedTestAckKind::WarmupDownloadDone,
            bytes,
        }
    }

    pub fn warmup_upload_done(bytes: u64) -> Self {
        Self {
            kind: SpeedTestAckKind::WarmupUploadDone,
            bytes,
        }
    }

    pub fn download_done(bytes: u64) -> Self {
        Self {
            kind: SpeedTestAckKind::DownloadDone,
            bytes,
        }
    }

    pub fn upload_done(bytes: u64) -> Self {
        Self {
            kind: SpeedTestAckKind::UploadDone,
            bytes,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(match self.kind {
            SpeedTestAckKind::WarmupDownloadDone => SPEED_WARMUP_DOWNLOAD_DONE_MAGIC,
            SpeedTestAckKind::WarmupUploadDone => SPEED_WARMUP_UPLOAD_DONE_MAGIC,
            SpeedTestAckKind::DownloadDone => SPEED_DOWNLOAD_DONE_MAGIC,
            SpeedTestAckKind::UploadDone => SPEED_UPLOAD_DONE_MAGIC,
        });
        out.extend_from_slice(&self.bytes.to_be_bytes());
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, SpeedTestAckError> {
        if input.len() < 4 {
            return Err(SpeedTestAckError::Truncated);
        }
        let kind = match &input[..4] {
            magic if magic == SPEED_WARMUP_DOWNLOAD_DONE_MAGIC => {
                SpeedTestAckKind::WarmupDownloadDone
            }
            magic if magic == SPEED_WARMUP_UPLOAD_DONE_MAGIC => SpeedTestAckKind::WarmupUploadDone,
            magic if magic == SPEED_DOWNLOAD_DONE_MAGIC => SpeedTestAckKind::DownloadDone,
            magic if magic == SPEED_UPLOAD_DONE_MAGIC => SpeedTestAckKind::UploadDone,
            _ => return Err(SpeedTestAckError::BadMagic),
        };
        if input.len() < 12 {
            return Err(SpeedTestAckError::Truncated);
        }
        if input.len() != 12 {
            return Err(SpeedTestAckError::InvalidLength);
        }
        let bytes = u64::from_be_bytes([
            input[4], input[5], input[6], input[7], input[8], input[9], input[10], input[11],
        ]);
        Ok(Self { kind, bytes })
    }
}

impl MuxFrameKind {
    fn to_wire(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Data => 2,
            Self::Fin => 3,
            Self::Reset => 4,
            Self::Cover => 5,
        }
    }

    fn from_wire(value: u8) -> Result<Self, MuxFrameError> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::Data),
            3 => Ok(Self::Fin),
            4 => Ok(Self::Reset),
            5 => Ok(Self::Cover),
            _ => Err(MuxFrameError::InvalidKind),
        }
    }
}

impl MuxFrame {
    pub fn has_magic(input: &[u8]) -> bool {
        input.len() >= 4 && &input[..4] == MUX_FRAME_MAGIC
    }

    pub fn max_payload_len(max_encoded_len: usize) -> usize {
        max_encoded_len.saturating_sub(MUX_FRAME_FIXED_LEN)
    }

    pub fn max_open_initial_payload_len(host: &str, max_encoded_len: usize) -> usize {
        ConnectRequest::max_initial_payload_len(host, Self::max_payload_len(max_encoded_len))
    }

    pub fn encode(&self) -> Result<Vec<u8>, MuxFrameError> {
        Self::encode_borrowed(self.stream_id, self.kind, &self.payload)
    }

    pub fn encoded_len(payload_len: usize) -> Result<usize, MuxFrameError> {
        // Enforce the u32 wire limit BEFORE any caller uses this to size an
        // allocation (e.g. `encode_borrowed`'s `Vec::with_capacity`). Checking
        // only usize overflow here would let a payload in (u32::MAX, usize::MAX]
        // trigger a multi-gigabyte reservation before the limit is checked.
        if payload_len > u32::MAX as usize {
            return Err(MuxFrameError::PayloadTooLong);
        }
        MUX_FRAME_FIXED_LEN
            .checked_add(payload_len)
            .ok_or(MuxFrameError::PayloadTooLong)
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), MuxFrameError> {
        Self::encode_borrowed_into(self.stream_id, self.kind, &self.payload, out)
    }

    pub fn encode_borrowed(
        stream_id: u32,
        kind: MuxFrameKind,
        payload: &[u8],
    ) -> Result<Vec<u8>, MuxFrameError> {
        let mut out = Vec::with_capacity(Self::encoded_len(payload.len())?);
        Self::encode_borrowed_into(stream_id, kind, payload, &mut out)?;
        Ok(out)
    }

    pub fn encode_borrowed_into(
        stream_id: u32,
        kind: MuxFrameKind,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), MuxFrameError> {
        validate_mux_stream(kind, stream_id)?;
        if payload.len() > u32::MAX as usize {
            return Err(MuxFrameError::PayloadTooLong);
        }

        out.extend_from_slice(MUX_FRAME_MAGIC);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.push(kind.to_wire());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        crate::process_hardening::exclude_transient_from_core_dump(
            "mux_frame.payload",
            out.as_slice(),
        );
        Ok(())
    }

    pub fn decode(input: &[u8]) -> Result<Self, MuxFrameError> {
        let frame = Self::decode_ref(input)?;
        Ok(Self {
            stream_id: frame.stream_id,
            kind: frame.kind,
            payload: frame.payload.to_vec(),
        })
    }

    pub fn decode_ref(input: &[u8]) -> Result<MuxFrameRef<'_>, MuxFrameError> {
        let (frame, used) = Self::decode_ref_prefix(input)?;
        if input.len() != used {
            return Err(MuxFrameError::InvalidPayloadLength);
        }
        Ok(frame)
    }

    pub fn decode_prefix(input: &[u8]) -> Result<(Self, usize), MuxFrameError> {
        let (frame, used) = Self::decode_ref_prefix(input)?;
        Ok((
            Self {
                stream_id: frame.stream_id,
                kind: frame.kind,
                payload: frame.payload.to_vec(),
            },
            used,
        ))
    }

    pub fn decode_ref_prefix(input: &[u8]) -> Result<(MuxFrameRef<'_>, usize), MuxFrameError> {
        if input.len() < 4 {
            return Err(MuxFrameError::Truncated);
        }
        if &input[..4] != MUX_FRAME_MAGIC {
            return Err(MuxFrameError::BadMagic);
        }
        if input.len() < MUX_FRAME_FIXED_LEN {
            return Err(MuxFrameError::Truncated);
        }

        let stream_id = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
        let kind = MuxFrameKind::from_wire(input[8])?;
        validate_mux_stream(kind, stream_id)?;
        let len = u32::from_be_bytes([input[9], input[10], input[11], input[12]]) as usize;
        let used = Self::encoded_len(len)?;
        if input.len() < used {
            return Err(MuxFrameError::InvalidPayloadLength);
        }
        Ok((
            MuxFrameRef {
                stream_id,
                kind,
                payload: &input[MUX_FRAME_FIXED_LEN..used],
            },
            used,
        ))
    }

    pub fn decode_all(input: &[u8]) -> Result<Vec<Self>, MuxFrameError> {
        let mut frames = Vec::new();
        let mut rest = input;
        while !rest.is_empty() {
            let (frame, used) = Self::decode_prefix(rest)?;
            frames.push(frame);
            rest = &rest[used..];
        }
        Ok(frames)
    }
}

fn validate_mux_stream(kind: MuxFrameKind, stream_id: u32) -> Result<(), MuxFrameError> {
    match kind {
        MuxFrameKind::Cover if stream_id == 0 => Ok(()),
        MuxFrameKind::Open | MuxFrameKind::Data | MuxFrameKind::Fin | MuxFrameKind::Reset
            if stream_id != 0 =>
        {
            Ok(())
        }
        _ => Err(MuxFrameError::InvalidStreamId),
    }
}

/// Default retention cap for a [`MuxPayloadPool`] freelist.
///
/// Steady-state relays keep only a handful of recycled buffers alive at once
/// (one producer hands a buffer back as the writer drains it), so a small cap
/// is plenty while bounding idle memory well below the in-flight channel depth.
pub const MUX_PAYLOAD_POOL_DEFAULT_MAX: usize = 64;

/// Recycles `MuxFrame` `Data` payload buffers between the relay's per-stream
/// producer tasks and the single fan-in writer task.
///
/// The relay hot path reads a TCP chunk, wraps it in a [`MuxFrame`], ships it
/// across an mpsc channel to the writer, and the writer copies the payload into
/// the seal buffer before dropping the frame. Without recycling that is one
/// heap allocation and one free per chunk on both the client upload and server
/// download paths. The pool turns that churn into a bounded freelist guarded by
/// a briefly-held mutex (no `.await` is ever held across the lock).
#[derive(Clone)]
pub struct MuxPayloadPool {
    free: Arc<Mutex<Vec<Vec<u8>>>>,
    buffer_capacity: usize,
    max_buffers: usize,
}

impl MuxPayloadPool {
    pub fn new(buffer_capacity: usize, max_buffers: usize) -> Self {
        Self {
            free: Arc::new(Mutex::new(Vec::new())),
            buffer_capacity: buffer_capacity.max(1),
            max_buffers: max_buffers.max(1),
        }
    }

    /// Builds a pool whose buffers hold one max-sized mux `Data` payload.
    pub fn with_capacity(buffer_capacity: usize) -> Self {
        Self::new(buffer_capacity, MUX_PAYLOAD_POOL_DEFAULT_MAX)
    }

    /// Returns an empty buffer, reusing a recycled allocation when available.
    pub fn take(&self) -> Vec<u8> {
        if let Ok(mut free) = self.free.lock() {
            if let Some(buf) = free.pop() {
                return buf;
            }
        }
        Vec::with_capacity(self.buffer_capacity)
    }

    /// Returns a buffer pre-filled with `chunk`, reusing a recycled allocation.
    pub fn take_filled(&self, chunk: &[u8]) -> Vec<u8> {
        let mut buf = self.take();
        buf.extend_from_slice(chunk);
        buf
    }

    /// Returns a buffer for reuse. Buffers smaller than one full payload slot,
    /// or those that would exceed the retention cap, are dropped instead of
    /// being hoarded so the freelist never grows without bound.
    pub fn put(&self, mut buf: Vec<u8>) {
        if buf.capacity() < self.buffer_capacity {
            return;
        }
        buf.clear();
        if let Ok(mut free) = self.free.lock() {
            if free.len() < self.max_buffers {
                free.push(buf);
            }
        }
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8], pos: usize) -> Self {
        Self { input, pos }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ConnectRequestError> {
        if self.remaining() < len {
            return Err(ConnectRequestError::Truncated);
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.input[start..start + len])
    }

    fn u16(&mut self) -> Result<u16, ConnectRequestError> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, ConnectRequestError> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// `PX1O` UDP offer: the server tells the client how to reach and configure the
/// UDP fast plane. Sent over the TCP control plane after the handshake. The
/// `offer_id` doubles as the RFC 5705 exporter-binding context (see
/// `transport::udp::auth`) and as a replay handle for the offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpOffer {
    pub offer_id: [u8; UDP_OFFER_ID_LEN],
    /// Server UDP fast-plane port; the client reuses the TCP server IP.
    pub udp_port: u16,
    pub port_hop_seed: u64,
    /// Congestion-control code (see `UDP_CC_*`).
    pub cc: u8,
    /// FEC profile code (see `UDP_FEC_*`).
    pub fec_profile: u8,
    pub ignore_client_bandwidth: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpOfferError {
    #[error("UDP offer is truncated")]
    Truncated,
    #[error("UDP offer magic mismatch")]
    BadMagic,
    #[error("UDP offer has an invalid length")]
    InvalidLength,
    #[error("UDP offer udp_port must not be zero")]
    ZeroPort,
}

impl UdpOffer {
    pub fn encode(&self) -> Result<Vec<u8>, UdpOfferError> {
        if self.udp_port == 0 {
            return Err(UdpOfferError::ZeroPort);
        }
        let mut out = Vec::with_capacity(UDP_OFFER_LEN);
        out.extend_from_slice(UDP_OFFER_MAGIC);
        out.extend_from_slice(&self.offer_id);
        out.extend_from_slice(&self.udp_port.to_be_bytes());
        out.extend_from_slice(&self.port_hop_seed.to_be_bytes());
        out.push(self.cc);
        out.push(self.fec_profile);
        out.push(u8::from(self.ignore_client_bandwidth));
        Ok(out)
    }

    pub fn has_magic(input: &[u8]) -> bool {
        input.len() >= 4 && &input[..4] == UDP_OFFER_MAGIC
    }

    pub fn decode(input: &[u8]) -> Result<Self, UdpOfferError> {
        if input.len() < 4 {
            return Err(UdpOfferError::Truncated);
        }
        if &input[..4] != UDP_OFFER_MAGIC {
            return Err(UdpOfferError::BadMagic);
        }
        if input.len() < UDP_OFFER_LEN {
            return Err(UdpOfferError::Truncated);
        }
        if input.len() != UDP_OFFER_LEN {
            return Err(UdpOfferError::InvalidLength);
        }
        let mut offer_id = [0_u8; UDP_OFFER_ID_LEN];
        offer_id.copy_from_slice(&input[4..4 + UDP_OFFER_ID_LEN]);
        let mut pos = 4 + UDP_OFFER_ID_LEN;
        let udp_port = u16::from_be_bytes([input[pos], input[pos + 1]]);
        pos += 2;
        let port_hop_seed = u64::from_be_bytes([
            input[pos],
            input[pos + 1],
            input[pos + 2],
            input[pos + 3],
            input[pos + 4],
            input[pos + 5],
            input[pos + 6],
            input[pos + 7],
        ]);
        pos += 8;
        let cc = input[pos];
        let fec_profile = input[pos + 1];
        let ignore_client_bandwidth = input[pos + 2] != 0;
        if udp_port == 0 {
            return Err(UdpOfferError::ZeroPort);
        }
        Ok(Self {
            offer_id,
            udp_port,
            port_hop_seed,
            cc,
            fec_profile,
            ignore_client_bandwidth,
        })
    }
}

/// Outcome the client reports for a UDP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpProbeStatus {
    /// A verified application-level round-trip succeeded over the UDP leg.
    Verified,
    /// The UDP leg was unreachable / black-holed (timeout, no response).
    Unreachable,
    /// The probe failed for another reason.
    Failed,
}

impl UdpProbeStatus {
    fn to_byte(self) -> u8 {
        match self {
            Self::Verified => 0,
            Self::Unreachable => 1,
            Self::Failed => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, UdpProbeAckError> {
        match byte {
            0 => Ok(Self::Verified),
            1 => Ok(Self::Unreachable),
            2 => Ok(Self::Failed),
            other => Err(UdpProbeAckError::InvalidStatus(other)),
        }
    }
}

/// `PX1P` UDP probe ack: the client reports the probe outcome over the TCP
/// control plane, echoing the `offer_id` it responds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpProbeAck {
    pub offer_id: [u8; UDP_OFFER_ID_LEN],
    pub status: UdpProbeStatus,
    pub rtt_micros: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpProbeAckError {
    #[error("UDP probe ack is truncated")]
    Truncated,
    #[error("UDP probe ack magic mismatch")]
    BadMagic,
    #[error("UDP probe ack has an invalid length")]
    InvalidLength,
    #[error("UDP probe ack has an invalid status byte: {0}")]
    InvalidStatus(u8),
}

impl UdpProbeAck {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(UDP_PROBE_ACK_LEN);
        out.extend_from_slice(UDP_PROBE_ACK_MAGIC);
        out.extend_from_slice(&self.offer_id);
        out.push(self.status.to_byte());
        out.extend_from_slice(&self.rtt_micros.to_be_bytes());
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, UdpProbeAckError> {
        if input.len() < 4 {
            return Err(UdpProbeAckError::Truncated);
        }
        if &input[..4] != UDP_PROBE_ACK_MAGIC {
            return Err(UdpProbeAckError::BadMagic);
        }
        if input.len() < UDP_PROBE_ACK_LEN {
            return Err(UdpProbeAckError::Truncated);
        }
        if input.len() != UDP_PROBE_ACK_LEN {
            return Err(UdpProbeAckError::InvalidLength);
        }
        let mut offer_id = [0_u8; UDP_OFFER_ID_LEN];
        offer_id.copy_from_slice(&input[4..4 + UDP_OFFER_ID_LEN]);
        let pos = 4 + UDP_OFFER_ID_LEN;
        let status = UdpProbeStatus::from_byte(input[pos])?;
        let rtt_micros = u32::from_be_bytes([
            input[pos + 1],
            input[pos + 2],
            input[pos + 3],
            input[pos + 4],
        ]);
        Ok(Self {
            offer_id,
            status,
            rtt_micros,
        })
    }
}

/// `PX1G` UDP request: the client opens the client-initiated, fail-soft UDP
/// negotiation. The server replies with [`UdpOffer`] (if it offers the UDP fast
/// plane) or [`UdpDecline`]; the server never sends an offer unsolicited, so a
/// peer with UDP disabled never desyncs the control stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpRequest {
    pub version: u8,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpRequestError {
    #[error("UDP request is truncated")]
    Truncated,
    #[error("UDP request magic mismatch")]
    BadMagic,
    #[error("UDP request has an invalid length")]
    InvalidLength,
}

impl UdpRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(UDP_REQUEST_LEN);
        out.extend_from_slice(UDP_REQUEST_MAGIC);
        out.push(self.version);
        out
    }

    pub fn has_magic(input: &[u8]) -> bool {
        input.len() >= 4 && &input[..4] == UDP_REQUEST_MAGIC
    }

    pub fn decode(input: &[u8]) -> Result<Self, UdpRequestError> {
        if input.len() < 4 {
            return Err(UdpRequestError::Truncated);
        }
        if &input[..4] != UDP_REQUEST_MAGIC {
            return Err(UdpRequestError::BadMagic);
        }
        if input.len() < UDP_REQUEST_LEN {
            return Err(UdpRequestError::Truncated);
        }
        if input.len() != UDP_REQUEST_LEN {
            return Err(UdpRequestError::InvalidLength);
        }
        Ok(Self { version: input[4] })
    }
}

/// `PX1N` UDP decline: the server's fail-soft response to a [`UdpRequest`] when
/// it will not offer the UDP fast plane. The client then proceeds on TCP only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDecline {
    pub reason: u8,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpDeclineError {
    #[error("UDP decline is truncated")]
    Truncated,
    #[error("UDP decline magic mismatch")]
    BadMagic,
    #[error("UDP decline has an invalid length")]
    InvalidLength,
}

impl UdpDecline {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(UDP_DECLINE_LEN);
        out.extend_from_slice(UDP_DECLINE_MAGIC);
        out.push(self.reason);
        out
    }

    pub fn has_magic(input: &[u8]) -> bool {
        input.len() >= 4 && &input[..4] == UDP_DECLINE_MAGIC
    }

    pub fn decode(input: &[u8]) -> Result<Self, UdpDeclineError> {
        if input.len() < 4 {
            return Err(UdpDeclineError::Truncated);
        }
        if &input[..4] != UDP_DECLINE_MAGIC {
            return Err(UdpDeclineError::BadMagic);
        }
        if input.len() < UDP_DECLINE_LEN {
            return Err(UdpDeclineError::Truncated);
        }
        if input.len() != UDP_DECLINE_LEN {
            return Err(UdpDeclineError::InvalidLength);
        }
        Ok(Self { reason: input[4] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framed_chunk_round_trips_through_reassembler() {
        let payload: Vec<u8> = (0..1608u32).map(|i| (i % 251) as u8).collect();
        for chunk_len in [256usize, 512, 1024, 1608, 2000] {
            let chunks = FramedChunk::encode_all(&payload, chunk_len).unwrap();
            let mut reassembler = FramedReassembler::default();
            let mut assembled = None;
            for chunk in &chunks {
                if let Some(done) = reassembler.push(chunk, MAX_PQ_HANDSHAKE_FRAME).unwrap() {
                    assembled = Some(done);
                }
            }
            assert_eq!(assembled.unwrap(), payload, "chunk_len={chunk_len}");
        }
    }

    #[test]
    fn framed_chunk_count_varies_and_never_carries_whole_payload() {
        // The anti-single-point property: a smaller chunk size yields more
        // records, and no single chunk carries the entire payload (the former
        // fixed ~1631/1632 first-record tell).
        let payload = vec![0x5A_u8; 1608];
        let few = FramedChunk::encode_all(&payload, 1024).unwrap();
        let many = FramedChunk::encode_all(&payload, 256).unwrap();
        assert!(few.len() >= 2);
        assert!(many.len() > few.len());
        for chunk in many.iter().chain(few.iter()) {
            let decoded = FramedChunk::decode_ref(chunk).unwrap();
            assert!(decoded.bytes.len() < payload.len());
            assert_eq!(decoded.total_len as usize, payload.len());
        }
    }

    #[test]
    fn framed_reassembler_rejects_total_over_cap() {
        let oversized =
            FramedChunk::encode_borrowed(MAX_PQ_HANDSHAKE_FRAME as u32 + 1, 0, &[0_u8; 8]).unwrap();
        let mut reassembler = FramedReassembler::default();
        assert!(matches!(
            reassembler.push(&oversized, MAX_PQ_HANDSHAKE_FRAME),
            Err(FramedChunkError::TooLarge)
        ));
    }

    #[test]
    fn framed_reassembler_rejects_out_of_order_chunk() {
        let payload = vec![7_u8; 300];
        let chunks = FramedChunk::encode_all(&payload, 100).unwrap();
        let mut reassembler = FramedReassembler::default();
        assert!(reassembler
            .push(&chunks[0], MAX_PQ_HANDSHAKE_FRAME)
            .unwrap()
            .is_none());
        // Skipping chunk[1] (offset 100) and pushing chunk[2] (offset 200) must
        // be rejected, not silently accepted into the wrong position.
        assert!(matches!(
            reassembler.push(&chunks[2], MAX_PQ_HANDSHAKE_FRAME),
            Err(FramedChunkError::OutOfOrder)
        ));
    }

    #[test]
    fn framed_chunk_decode_rejects_bad_magic() {
        assert!(matches!(
            FramedChunk::decode_ref(b"PX1X"),
            Err(FramedChunkError::BadMagic)
        ));
    }

    #[test]
    fn framed_chunk_encode_all_shaped_round_trips_varies_and_has_no_tiny_tail() {
        use rand::{rngs::StdRng, SeedableRng};
        let payload: Vec<u8> = (0..1608_u32).map(|i| (i % 251) as u8).collect();
        let mut sizes_seen = std::collections::BTreeSet::new();
        for seed in 0..40_u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let chunks = FramedChunk::encode_all_shaped(&payload, &mut rng, 256, 1024).unwrap();
            assert!(
                chunks.len() >= 2,
                "payload > max must split into >= 2 chunks"
            );
            let mut reassembler = FramedReassembler::default();
            let mut assembled = None;
            for chunk in &chunks {
                let decoded = FramedChunk::decode_ref(chunk).unwrap();
                // Constrained draw: every record stays within [min, max] -- no
                // sub-min tail and never over-max -- and never carries the frame.
                assert!(
                    (256..=1024).contains(&decoded.bytes.len()),
                    "chunk out of [min,max]: {}",
                    decoded.bytes.len()
                );
                sizes_seen.insert(decoded.bytes.len());
                if let Some(done) = reassembler.push(chunk, MAX_PQ_HANDSHAKE_FRAME).unwrap() {
                    assembled = Some(done);
                }
            }
            assert_eq!(assembled.unwrap(), payload, "seed={seed}");
        }
        assert!(
            sizes_seen.len() >= 8,
            "per-chunk sizing must vary record sizes, got {}",
            sizes_seen.len()
        );
    }

    #[test]
    fn framed_chunk_encode_all_shaped_boundary_cases() {
        use rand::{rngs::StdRng, SeedableRng};
        // The constrained draw must hold at the boundaries regardless of the RNG:
        // a payload just over max_chunk never collapses into one record (the draw
        // always leaves a >= min_chunk tail), and a payload <= max_chunk is a lone
        // chunk. Checked across seeds so a lucky draw cannot dodge the invariant.
        for seed in 0..64_u64 {
            let mut rng = StdRng::seed_from_u64(seed);

            // max_chunk + 1: must be exactly 2 chunks, both within [min, max].
            let just_over = vec![1_u8; 1025];
            let chunks = FramedChunk::encode_all_shaped(&just_over, &mut rng, 256, 1024).unwrap();
            assert_eq!(
                chunks.len(),
                2,
                "max+1 payload must split into 2 chunks, seed={seed}"
            );
            for chunk in &chunks {
                let len = FramedChunk::decode_ref(chunk).unwrap().bytes.len();
                assert!(
                    (256..=1024).contains(&len),
                    "boundary chunk out of range: {len}"
                );
            }

            // <= max_chunk: a single chunk carrying the whole payload.
            let small = vec![2_u8; 1024];
            let one = FramedChunk::encode_all_shaped(&small, &mut rng, 256, 1024).unwrap();
            assert_eq!(one.len(), 1);
            assert_eq!(FramedChunk::decode_ref(&one[0]).unwrap().bytes.len(), 1024);
        }
    }

    #[test]
    fn framed_reassembly_is_size_agnostic() {
        // The whole PAR-21 binding argument rests on reassembly recovering the
        // exact same plaintext regardless of how the sender chunked it, so the
        // two ends never need to agree on chunk sizes.
        use rand::{rngs::StdRng, SeedableRng};
        let payload: Vec<u8> = (0..1609_u32).map(|i| (i % 97) as u8).collect();
        let fixed = FramedChunk::encode_all(&payload, 300).unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let shaped = FramedChunk::encode_all_shaped(&payload, &mut rng, 256, 1024).unwrap();
        let reassemble = |chunks: &[Vec<u8>]| {
            let mut r = FramedReassembler::default();
            let mut out = None;
            for c in chunks {
                if let Some(p) = r.push(c, MAX_PQ_HANDSHAKE_FRAME).unwrap() {
                    out = Some(p);
                }
            }
            out.unwrap()
        };
        assert_eq!(reassemble(&fixed), payload);
        assert_eq!(reassemble(&shaped), payload);
    }

    #[test]
    fn browser_shaped_round_trips_and_sizes_track_the_target_distribution() {
        // PAR-35: the browser shaper must (a) reassemble exactly, (b) draw record
        // sizes from PQ_FLIGHT_RECORD_TARGETS (every non-final record is a target
        // value), and (c) keep every record >= PQ_FLIGHT_RECORD_MIN (no tiny tell).
        use rand::{rngs::StdRng, SeedableRng};
        // ML-KEM-1024 PX1Q/PX1K (~1.6 KB) and the ML-DSA-87 identity proof (~4.6 KB).
        for payload_len in [1608_usize, 1609, 4635, 6243] {
            let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
            let mut sizes_seen = std::collections::BTreeSet::new();
            for seed in 0..40_u64 {
                let mut rng = StdRng::seed_from_u64(seed);
                // usize::MAX => no codec cap; the shaper uses the full target range.
                let chunks =
                    FramedChunk::encode_all_browser_shaped(&payload, usize::MAX, &mut rng).unwrap();
                let max_target = *PQ_FLIGHT_RECORD_TARGETS.iter().max().unwrap();
                let mut reassembler = FramedReassembler::default();
                let mut assembled = None;
                for (idx, chunk) in chunks.iter().enumerate() {
                    let decoded = FramedChunk::decode_ref(chunk).unwrap();
                    let len = decoded.bytes.len();
                    assert!(len >= PQ_FLIGHT_RECORD_MIN, "tiny tell record: {len}");
                    assert!(len <= max_target, "record over max target: {len}");
                    // Every non-final record is exactly one of the browser targets.
                    if idx + 1 < chunks.len() {
                        assert!(
                            PQ_FLIGHT_RECORD_TARGETS.contains(&len),
                            "non-final record {len} not a browser target"
                        );
                    }
                    sizes_seen.insert(len);
                    if let Some(done) = reassembler.push(chunk, MAX_PQ_HANDSHAKE_FRAME * 2).unwrap()
                    {
                        assembled = Some(done);
                    }
                }
                assert_eq!(assembled.unwrap(), payload, "seed={seed}");
            }
            assert!(
                sizes_seen.len() >= 4,
                "browser shaper must vary record sizes; got {}",
                sizes_seen.len()
            );
        }
    }

    #[test]
    fn browser_shaped_record_count_is_bounded_no_shatter() {
        // The disqualifier from the PAR-21/PAR-28 triage: a large identity proof must
        // NOT shatter into many sub-record fragments (latency regression). With every
        // record >= PQ_FLIGHT_RECORD_MIN, the count is bounded by ceil(len / MIN).
        use rand::{rngs::StdRng, SeedableRng};
        let payload = vec![0x5A_u8; 4635]; // ML-DSA-87-sized identity proof
        for seed in 0..32_u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let chunks =
                FramedChunk::encode_all_browser_shaped(&payload, usize::MAX, &mut rng).unwrap();
            let bound = payload.len().div_ceil(PQ_FLIGHT_RECORD_MIN);
            assert!(
                chunks.len() <= bound,
                "record count {} exceeds bound {bound} (shatter regression)",
                chunks.len()
            );
        }
    }

    #[test]
    fn aggregate_pad_len_varies_within_bounds() {
        // PAR-28 Low-1 decorrelation: the per-session aggregate pad must vary across
        // sessions (kills the constant-aggregate correlation) and stay in [MIN, MAX]
        // (a variable, never-constant, sub-record pad — not a new fixed tell).
        use rand::{rngs::StdRng, SeedableRng};
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..256_u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let pad = FramedChunk::aggregate_pad_len(&mut rng);
            assert!(
                (PQ_FLIGHT_AGGREGATE_PAD_MIN..=PQ_FLIGHT_AGGREGATE_PAD_MAX).contains(&pad),
                "pad {pad} out of bounds"
            );
            seen.insert(pad);
        }
        assert!(seen.len() > 1, "aggregate pad must vary across sessions");
    }

    #[test]
    fn identity_browser_shaped_round_trips_and_is_size_agnostic() {
        // The identity proof uses the SAME browser distribution; its offset-based
        // reassembly must recover the proof regardless of how it was chunked.
        use rand::{rngs::StdRng, SeedableRng};
        let payload: Vec<u8> = (0..4635_u32).map(|i| (i % 97) as u8).collect();
        for seed in 0..24_u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let chunks =
                ServerIdentityChunk::encode_all_browser_shaped(&payload, usize::MAX, &mut rng)
                    .unwrap();
            assert!(chunks.len() >= 2, "identity proof must fragment");
            let mut assembled = Vec::new();
            for chunk in &chunks {
                let c = ServerIdentityChunk::decode_ref(chunk).unwrap();
                assert_eq!(c.offset as usize, assembled.len(), "in-order tiling");
                assert!(
                    c.bytes.len() >= PQ_FLIGHT_RECORD_MIN,
                    "no tiny identity record"
                );
                assembled.extend_from_slice(c.bytes);
            }
            assert_eq!(assembled, payload, "seed={seed}");
        }
    }

    #[test]
    fn framed_reassembler_rejects_inconsistent_total() {
        let a = FramedChunk::encode_borrowed(1000, 0, &[1_u8; 100]).unwrap();
        let b = FramedChunk::encode_borrowed(2000, 100, &[2_u8; 100]).unwrap();
        let mut reassembler = FramedReassembler::default();
        assert!(reassembler
            .push(&a, MAX_PQ_HANDSHAKE_FRAME)
            .unwrap()
            .is_none());
        assert!(matches!(
            reassembler.push(&b, MAX_PQ_HANDSHAKE_FRAME),
            Err(FramedChunkError::InconsistentTotal)
        ));
    }

    #[test]
    fn framed_chunk_decode_ref_rejects_malformed() {
        fn framed(total: u32, offset: u32, len: u32, trailing: usize) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(b"PX1F");
            v.extend_from_slice(&total.to_be_bytes());
            v.extend_from_slice(&offset.to_be_bytes());
            v.extend_from_slice(&len.to_be_bytes());
            v.extend_from_slice(&vec![0_u8; trailing]);
            v
        }
        assert!(matches!(
            FramedChunk::decode_ref(&[0_u8; 2]),
            Err(FramedChunkError::Truncated)
        ));
        assert!(matches!(
            FramedChunk::decode_ref(b"PX1F"),
            Err(FramedChunkError::Truncated)
        ));
        assert!(matches!(
            FramedChunk::decode_ref(&framed(512, 0, 0, 0)),
            Err(FramedChunkError::EmptyChunk)
        ));
        assert!(matches!(
            FramedChunk::decode_ref(&framed(512, 0, 10, 5)),
            Err(FramedChunkError::InvalidChunkLength)
        ));
        assert!(matches!(
            FramedChunk::decode_ref(&framed(100, 95, 10, 10)),
            Err(FramedChunkError::InvalidOffset)
        ));
    }

    #[test]
    fn framed_reassembler_accepts_cap_boundary() {
        let payload = vec![3_u8; MAX_PQ_HANDSHAKE_FRAME];
        let chunks = FramedChunk::encode_all(&payload, 1000).unwrap();
        let mut reassembler = FramedReassembler::default();
        let mut assembled = None;
        for chunk in &chunks {
            if let Some(done) = reassembler.push(chunk, MAX_PQ_HANDSHAKE_FRAME).unwrap() {
                assembled = Some(done);
            }
        }
        assert_eq!(assembled.unwrap().len(), MAX_PQ_HANDSHAKE_FRAME);
    }

    #[test]
    fn framed_reassembler_is_reusable_after_completion() {
        // After a frame completes, the reassembler must carry no stale
        // expected-total state, so a second frame of a different total length
        // reassembles cleanly on the same instance.
        let mut reassembler = FramedReassembler::default();
        let first = vec![1_u8; 700];
        let second = vec![2_u8; 300];
        let reassemble = |reassembler: &mut FramedReassembler, payload: &[u8]| {
            let mut out = None;
            for chunk in FramedChunk::encode_all(payload, 256).unwrap() {
                if let Some(done) = reassembler.push(&chunk, MAX_PQ_HANDSHAKE_FRAME).unwrap() {
                    out = Some(done);
                }
            }
            out.unwrap()
        };
        assert_eq!(reassemble(&mut reassembler, &first), first);
        assert_eq!(reassemble(&mut reassembler, &second), second);
    }

    #[test]
    fn connect_request_round_trip() {
        let request = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        };

        let encoded = request.encode().unwrap();
        assert_eq!(ConnectRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn encoded_len_matches_the_actual_encoded_byte_count() {
        // encoded_len() is computed from CONNECT_FIXED_LEN (4 magic + 2 host-len +
        // 2 port + 4 payload-len = 12) + host + payload, and encode() writes exactly
        // those literal bytes. They MUST agree, or encode()'s Vec::with_capacity is
        // wrong and max_initial_payload_len mis-budgets. Pins CONNECT_FIXED_LEN: any
        // arithmetic mutation of its `4 + 2 + 2 + 4` sum makes encoded_len() diverge
        // from the real encoded length.
        for (host, payload_len) in [
            ("a.io", 0usize),
            ("example.com", 17),
            (&"h".repeat(120), 300),
        ] {
            let request = ConnectRequest {
                host: host.to_owned(),
                port: 443,
                initial_payload: vec![0x41; payload_len],
            };
            let encoded = request.encode().unwrap();
            assert_eq!(
                encoded.len(),
                request.encoded_len(),
                "encoded_len() must equal the real encoded byte count (host={host:?})"
            );
            // And the fixed framing really is 12 bytes beyond host+payload.
            assert_eq!(encoded.len(), 12 + host.len() + payload_len);
        }
    }

    #[test]
    fn pq_flight_max_chunk_size_reserves_header_plus_aggregate_pad() {
        // The cap subtracts (PQ_CHUNK_FRAME_HEADER_LEN + PQ_FLIGHT_AGGREGATE_PAD_MAX)
        // = 16 + 512 = 528 from the sealed-plaintext budget so every shaped record
        // (any of which may be the last, carrying the aggregate pad) stays within the
        // record limit. Assert the exact value: a `+` -> `*` on the reservation would
        // subtract 16*512 = 8192 instead, badly under-sizing the chunk.
        let budget = 10_000usize;
        assert_eq!(
            pq_flight_max_chunk_size(budget),
            budget - (PQ_CHUNK_FRAME_HEADER_LEN + PQ_FLIGHT_AGGREGATE_PAD_MAX)
        );
        assert_eq!(pq_flight_max_chunk_size(10_000), 10_000 - 528);
        // Below the reservation the saturating_sub floors to PQ_FLIGHT_RECORD_MIN.
        assert_eq!(pq_flight_max_chunk_size(100), PQ_FLIGHT_RECORD_MIN);
    }

    #[test]
    fn shaping_extra_pad_respects_a_tight_max_extra_pad() {
        // The fitting filter requires `band - raw_wire <= max_extra_pad`. With a
        // small request and a TIGHT cap, only the bands within reach of that cap may
        // be chosen, and the returned pad must never exceed it. This pins the
        // subtraction: `-` -> `+` shrinks the reachable set to just the smallest
        // band, and `-` -> `/` makes (almost) every band "fit" — both change the
        // reachable band set away from the exact expected pair below.
        use rand::{rngs::StdRng, SeedableRng};
        use std::collections::BTreeSet;

        let request = ConnectRequest {
            host: "example.com".to_owned(), // encoded_len 23 -> raw_wire 41
            port: 443,
            initial_payload: Vec::new(),
        };
        let raw_wire = request.encoded_len() + DATA_RECORD_WIRE_OVERHEAD;
        let max_extra_pad = 500usize;

        // Correct fitting set: bands with band >= raw_wire and band - raw_wire <= 500.
        // raw_wire = 41 -> {286, 469} (569-41=528 > 500 is excluded).
        let expected: BTreeSet<usize> = CONNECT_RECORD_SIZE_BANDS
            .iter()
            .copied()
            .filter(|&b| b >= raw_wire && b - raw_wire <= max_extra_pad)
            .collect();
        assert_eq!(
            expected,
            BTreeSet::from([286usize, 469usize]),
            "fixture sanity: tight cap should admit exactly these two bands"
        );

        let mut reached = BTreeSet::new();
        for seed in 0..512u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let pad = request.shaping_extra_pad(max_extra_pad, &mut rng);
            assert!(
                pad <= max_extra_pad,
                "pad {pad} must not exceed the cap {max_extra_pad}"
            );
            let wire = raw_wire + pad;
            assert!(
                CONNECT_RECORD_SIZE_BANDS.contains(&wire),
                "padded wire {wire} must still land on a band"
            );
            reached.insert(wire);
        }
        assert_eq!(
            reached, expected,
            "with a tight cap the reachable band set must be exactly the fitting bands"
        );
    }

    #[test]
    fn decode_ref_accepts_host_of_exactly_max_len_and_rejects_one_over() {
        // decode_ref's host bound is `host_len > MAX_HOST_LEN`: a 255-byte host is
        // valid and must decode; 256 must be HostTooLong. Pins the `>` boundary on
        // the DECODE path (a `> -> >=` would reject the legal 255-byte host).
        let at_limit = ConnectRequest {
            host: "a".repeat(MAX_HOST_LEN),
            port: 443,
            initial_payload: Vec::new(),
        };
        let encoded = at_limit.encode().unwrap();
        assert_eq!(
            ConnectRequest::decode(&encoded).unwrap().host.len(),
            MAX_HOST_LEN
        );

        // Hand-craft a record claiming a 256-byte host (one over the limit): magic +
        // host_len=256 + 256 host bytes + port + payload_len=0. decode_ref must reject
        // it as HostTooLong before reading the host.
        let mut over = Vec::new();
        over.extend_from_slice(CONNECT_MAGIC);
        over.extend_from_slice(&((MAX_HOST_LEN as u16) + 1).to_be_bytes());
        over.extend_from_slice(&vec![b'a'; MAX_HOST_LEN + 1]);
        over.extend_from_slice(&443u16.to_be_bytes());
        over.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            ConnectRequest::decode(&over),
            Err(ConnectRequestError::HostTooLong)
        ));
    }

    #[test]
    fn connect_record_size_is_shaped_rejects_non_band_sizes() {
        // The helper must answer truthfully per band membership, not constant-true.
        // Pin a clearly off-band size to false (kills `-> true`) and a real band to
        // true.
        assert!(!connect_record_size_is_shaped(0));
        assert!(!connect_record_size_is_shaped(1));
        assert!(!connect_record_size_is_shaped(
            CONNECT_RECORD_SIZE_BANDS[0] - 1
        ));
        assert!(connect_record_size_is_shaped(CONNECT_RECORD_SIZE_BANDS[0]));
        assert!(connect_record_size_is_shaped(
            CONNECT_RECORD_SIZE_BANDS[CONNECT_RECORD_SIZE_BANDS.len() - 1]
        ));
    }

    #[test]
    fn pq_rekey_request_decode_length_boundary() {
        // decode_ref has a `input.len() < 40` truncation guard before parsing the
        // fixed header. An input of EXACTLY 40 bytes (valid magic) must pass that
        // guard and fail LATER (not as a length-40 Truncated), while 39 bytes must be
        // Truncated. This distinguishes `< 40` from `<= 40` / `== 40`.
        let mut at = Vec::new();
        at.extend_from_slice(PQ_REKEY_MAGIC);
        at.resize(40, 0); // 40 bytes: passes `< 40`, then len==0 -> EmptyPublicKey
        assert!(matches!(
            PqRekeyRequest::decode_ref(&at),
            Err(PqRekeyError::EmptyPublicKey)
        ));
        let mut short = Vec::new();
        short.extend_from_slice(PQ_REKEY_MAGIC);
        short.resize(39, 0);
        assert!(matches!(
            PqRekeyRequest::decode_ref(&short),
            Err(PqRekeyError::Truncated)
        ));
    }

    #[test]
    fn server_key_exchange_decode_length_boundary() {
        // `input.len() < 40` guard: a 40-byte input must pass it (and fail later as a
        // length error, not Truncated), 39 must be Truncated.
        let mut at = Vec::new();
        at.extend_from_slice(SERVER_KEY_EXCHANGE_MAGIC);
        at.resize(40, 0); // len field == 0 -> EmptyCiphertext, NOT Truncated
        assert!(matches!(
            ServerKeyExchange::decode_ref_with_suite(&at),
            Err(ServerKeyExchangeError::EmptyCiphertext)
        ));
        let mut short = Vec::new();
        short.extend_from_slice(SERVER_KEY_EXCHANGE_MAGIC);
        short.resize(39, 0);
        assert!(matches!(
            ServerKeyExchange::decode_ref_with_suite(&short),
            Err(ServerKeyExchangeError::Truncated)
        ));
    }

    #[test]
    fn server_identity_proof_signature_length_boundary() {
        // `input.len() < 8` guard: 8 bytes passes it (len==0 -> EmptySignature), 7 is
        // Truncated.
        let mut at = Vec::new();
        at.extend_from_slice(SERVER_IDENTITY_MAGIC);
        at.resize(8, 0);
        assert!(matches!(
            ServerIdentityProof::signature(&at),
            Err(ServerIdentityProofError::EmptySignature)
        ));
        let mut short = Vec::new();
        short.extend_from_slice(SERVER_IDENTITY_MAGIC);
        short.resize(7, 0);
        assert!(matches!(
            ServerIdentityProof::signature(&short),
            Err(ServerIdentityProofError::Truncated)
        ));
    }

    #[test]
    fn server_identity_chunk_decode_length_boundary() {
        // `input.len() < 16` guard: 16 bytes passes it (then fails on the body
        // length fields), 15 is Truncated.
        let mut at = Vec::new();
        at.extend_from_slice(SERVER_IDENTITY_CHUNK_MAGIC);
        at.resize(16, 0);
        assert!(
            !matches!(
                ServerIdentityChunk::decode_ref(&at),
                Err(ServerIdentityChunkError::Truncated)
            ),
            "a 16-byte input must pass the `< 16` guard (fail later, not as Truncated)"
        );
        let mut short = Vec::new();
        short.extend_from_slice(SERVER_IDENTITY_CHUNK_MAGIC);
        short.resize(15, 0);
        assert!(matches!(
            ServerIdentityChunk::decode_ref(&short),
            Err(ServerIdentityChunkError::Truncated)
        ));
    }

    #[test]
    fn encode_accepts_host_of_exactly_max_len_and_rejects_one_over() {
        // The length guard is `host.len() > MAX_HOST_LEN` (255): a host of EXACTLY
        // 255 bytes is valid and must encode; 256 must be rejected. Pins the `>`
        // boundary so a `>` -> `>=` mutation (which would reject the legal 255-byte
        // host) is caught.
        let at_limit = "a".repeat(MAX_HOST_LEN);
        let req = ConnectRequest {
            host: at_limit,
            port: 443,
            initial_payload: Vec::new(),
        };
        assert!(
            req.encode().is_ok(),
            "a host of exactly MAX_HOST_LEN must encode"
        );

        let over = "a".repeat(MAX_HOST_LEN + 1);
        let req_over = ConnectRequest {
            host: over,
            port: 443,
            initial_payload: Vec::new(),
        };
        assert!(matches!(
            req_over.encode(),
            Err(ConnectRequestError::HostTooLong)
        ));
    }

    #[test]
    fn shaping_extra_pad_lands_on_a_band() {
        // The padded wire size (raw plaintext + overhead + extra_pad) must equal
        // one of the configured bands, for many seeds and several request sizes.
        use rand::{rngs::StdRng, SeedableRng};
        for payload_len in [0_usize, 17, 300, 700] {
            let request = ConnectRequest {
                host: "example.com".to_owned(),
                port: 443,
                initial_payload: vec![0x41; payload_len],
            };
            let raw_wire = request.encoded_len() + DATA_RECORD_WIRE_OVERHEAD;
            for seed in 0..64 {
                let mut rng = StdRng::seed_from_u64(seed);
                let pad = request.shaping_extra_pad(16_000, &mut rng);
                let wire = raw_wire + pad;
                assert!(
                    CONNECT_RECORD_SIZE_BANDS.contains(&wire),
                    "wire {wire} (raw {raw_wire} + pad {pad}) not on a band"
                );
            }
        }
    }

    #[test]
    fn shaping_extra_pad_decorrelates_from_host_len() {
        // Two requests with very different host lengths but small payloads must be
        // able to reach the SAME set of band sizes — so the observable record size
        // carries no host-length signal. Sweep all seeds and collect the band each
        // can land on; the achievable band sets must be identical.
        use rand::{rngs::StdRng, SeedableRng};
        use std::collections::BTreeSet;

        let bands_for = |host: &str| -> BTreeSet<usize> {
            let request = ConnectRequest {
                host: host.to_owned(),
                port: 443,
                initial_payload: Vec::new(),
            };
            let raw_wire = request.encoded_len() + DATA_RECORD_WIRE_OVERHEAD;
            (0..512)
                .map(|seed| {
                    let mut rng = StdRng::seed_from_u64(seed);
                    raw_wire + request.shaping_extra_pad(16_000, &mut rng)
                })
                .collect()
        };

        let short = bands_for("a.io");
        let long = bands_for(&"x".repeat(200));
        // Both short and long hosts are below the smallest band, so every band is
        // reachable for both — identical sets, zero host_len leak.
        assert_eq!(short, long);
        assert_eq!(short, CONNECT_RECORD_SIZE_BANDS.iter().copied().collect());
    }

    #[test]
    fn connect_request_decode_ref_borrows_payload() {
        let request = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        };

        let encoded = request.encode().unwrap();
        let decoded = ConnectRequest::decode_ref(&encoded).unwrap();

        assert_eq!(decoded.host, request.host);
        assert_eq!(decoded.port, request.port);
        assert_eq!(decoded.initial_payload, request.initial_payload);
        assert_eq!(decoded.target(), "example.com:443");
    }

    #[test]
    fn connect_request_target_brackets_ipv6_literals() {
        let request = ConnectRequest {
            host: "::1".to_owned(),
            port: 443,
            initial_payload: Vec::new(),
        };

        assert_eq!(request.target(), "[::1]:443");
    }

    #[test]
    fn connect_request_initial_payload_budget_accounts_for_host() {
        assert_eq!(
            ConnectRequest::max_initial_payload_len("example.com", 64),
            64 - CONNECT_FIXED_LEN - "example.com".len()
        );
        assert_eq!(ConnectRequest::max_initial_payload_len("example.com", 4), 0);
    }

    #[test]
    fn rejects_bad_magic() {
        assert_eq!(
            ConnectRequest::decode(b"BAD!").unwrap_err(),
            ConnectRequestError::BadMagic
        );
    }

    #[test]
    fn mux_encoded_len_rejects_payload_over_u32_before_allocating() {
        // The u32 wire-limit check must live in encoded_len so callers that size
        // an allocation from it (encode_borrowed's Vec::with_capacity) reject an
        // oversized payload instead of attempting a multi-gigabyte reservation.
        let over = (u32::MAX as usize) + 1;
        assert_eq!(
            MuxFrame::encoded_len(over).unwrap_err(),
            MuxFrameError::PayloadTooLong
        );
        // A payload at the limit still computes a length.
        assert!(MuxFrame::encoded_len(u32::MAX as usize).is_ok());
    }

    #[test]
    fn connect_request_rejects_invalid_fields() {
        assert_eq!(
            ConnectRequest {
                host: String::new(),
                port: 443,
                initial_payload: Vec::new(),
            }
            .encode()
            .unwrap_err(),
            ConnectRequestError::EmptyHost
        );
        assert_eq!(
            ConnectRequest {
                host: "example.com".to_owned(),
                port: 0,
                initial_payload: Vec::new(),
            }
            .encode()
            .unwrap_err(),
            ConnectRequestError::ZeroPort
        );
        assert_eq!(
            ConnectRequest {
                host: "x".repeat(MAX_HOST_LEN + 1),
                port: 443,
                initial_payload: Vec::new(),
            }
            .encode()
            .unwrap_err(),
            ConnectRequestError::HostTooLong
        );

        let mut invalid_host = Vec::new();
        invalid_host.extend_from_slice(CONNECT_MAGIC);
        invalid_host.extend_from_slice(&1_u16.to_be_bytes());
        invalid_host.push(0xff);
        invalid_host.extend_from_slice(&443_u16.to_be_bytes());
        invalid_host.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            ConnectRequest::decode(&invalid_host).unwrap_err(),
            ConnectRequestError::InvalidHost
        );

        let mut invalid_payload_len = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: b"hello".to_vec(),
        }
        .encode()
        .unwrap();
        let payload_len_offset = 4 + 2 + "example.com".len() + 2;
        invalid_payload_len[payload_len_offset..payload_len_offset + 4]
            .copy_from_slice(&6_u32.to_be_bytes());
        assert_eq!(
            ConnectRequest::decode(&invalid_payload_len).unwrap_err(),
            ConnectRequestError::InvalidPayloadLength
        );
    }

    #[test]
    fn pq_rekey_round_trip() {
        let request = PqRekeyRequest {
            client_x25519_public: [9_u8; 32],
            client_mlkem_public_key: vec![1, 2, 3],
        };
        let encoded = request.encode().unwrap();
        assert_eq!(PqRekeyRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn pq_rekey_decode_ref_borrows_public_key() {
        let request = PqRekeyRequest {
            client_x25519_public: [9_u8; 32],
            client_mlkem_public_key: vec![1, 2, 3],
        };

        let encoded = request.encode().unwrap();
        let decoded = PqRekeyRequest::decode_ref(&encoded).unwrap();

        assert_eq!(decoded.client_x25519_public, request.client_x25519_public);
        assert_eq!(
            decoded.client_mlkem_public_key,
            request.client_mlkem_public_key
        );
    }

    #[test]
    fn pq_rekey_borrowed_encode_matches_owned_request() {
        let request = PqRekeyRequest {
            client_x25519_public: [9_u8; 32],
            client_mlkem_public_key: vec![1, 2, 3],
        };

        assert_eq!(
            PqRekeyRequest::encode_borrowed(
                &request.client_x25519_public,
                &request.client_mlkem_public_key
            )
            .unwrap(),
            request.encode().unwrap()
        );
    }

    #[test]
    fn server_key_exchange_round_trip() {
        let exchange = ServerKeyExchange {
            server_x25519_public: [7_u8; 32],
            mlkem_ciphertext: vec![1, 2, 3],
        };
        let encoded = exchange
            .encode_with_suite(CipherSuite::ChaCha20Poly1305)
            .unwrap();
        assert_eq!(ServerKeyExchange::decode(&encoded).unwrap(), exchange);
    }

    #[test]
    fn server_key_exchange_decode_ref_borrows_ciphertext() {
        let exchange = ServerKeyExchange {
            server_x25519_public: [7_u8; 32],
            mlkem_ciphertext: vec![1, 2, 3],
        };

        let encoded = exchange
            .encode_with_suite(CipherSuite::ChaCha20Poly1305)
            .unwrap();
        let decoded = ServerKeyExchange::decode_ref(&encoded).unwrap();

        assert_eq!(decoded.server_x25519_public, exchange.server_x25519_public);
        assert_eq!(decoded.mlkem_ciphertext, exchange.mlkem_ciphertext);
    }

    #[test]
    fn server_key_exchange_decode_ref_with_suite_round_trips_and_rejects_bad_tags() {
        let exchange = ServerKeyExchange {
            server_x25519_public: [9_u8; 32],
            mlkem_ciphertext: vec![10, 11, 12, 13],
        };

        // Each negotiated suite round-trips: the one-byte tag maps back to the
        // SAME suite (guards against a refactor mapping the tag to the wrong one).
        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let encoded = exchange.encode_with_suite(suite).unwrap();
            let (decoded, got) = ServerKeyExchange::decode_ref_with_suite(&encoded).unwrap();
            assert_eq!(
                got, suite,
                "tag must decode to the suite it was encoded with"
            );
            assert_eq!(decoded.mlkem_ciphertext, exchange.mlkem_ciphertext);
            assert_eq!(decoded.server_x25519_public, exchange.server_x25519_public);
        }

        // A bare untagged 40+len record (the removed legacy layout) no longer
        // decodes: encode() omits the suite tag, so the canonical parser rejects
        // it. Locks in that legacy untagged records are gone.
        let untagged = exchange.encode().unwrap();
        assert!(matches!(
            ServerKeyExchange::decode_ref_with_suite(&untagged),
            Err(ServerKeyExchangeError::InvalidCiphertextLength)
        ));

        // An out-of-range suite tag (41+len shape, unknown byte) is rejected, not
        // silently mapped onto a valid suite.
        let mut bad_tag = exchange.encode().unwrap();
        bad_tag.push(0xff);
        assert!(matches!(
            ServerKeyExchange::decode_ref_with_suite(&bad_tag),
            Err(ServerKeyExchangeError::InvalidCipherSuite)
        ));

        // Trailing garbage beyond the tag (42+len) is neither legacy nor tagged.
        let mut wrong_len = exchange.encode().unwrap();
        wrong_len.push(CipherSuite::Aes256Gcm.to_wire());
        wrong_len.push(0x00);
        assert!(matches!(
            ServerKeyExchange::decode_ref_with_suite(&wrong_len),
            Err(ServerKeyExchangeError::InvalidCiphertextLength)
        ));
    }

    #[test]
    fn server_identity_proof_round_trip() {
        let proof = ServerIdentityProof {
            signature: vec![4, 5, 6],
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(
            ServerIdentityProof::signature(&encoded).unwrap(),
            proof.signature
        );
        assert_eq!(ServerIdentityProof::decode(&encoded).unwrap(), proof);
    }

    #[test]
    fn server_identity_chunks_round_trip() {
        let payload = (0..2000).map(|v| (v % 251) as u8).collect::<Vec<_>>();
        let encoded = ServerIdentityChunk::encode_all(&payload, 700).unwrap();
        assert_eq!(encoded.len(), 3);

        let mut assembled = Vec::new();
        for chunk in encoded {
            let chunk_ref = ServerIdentityChunk::decode_ref(&chunk).unwrap();
            let chunk = ServerIdentityChunk::decode(&chunk).unwrap();
            assert_eq!(chunk_ref.bytes, chunk.bytes);
            assert_eq!(chunk.offset as usize, assembled.len());
            assembled.extend_from_slice(&chunk.bytes);
        }

        assert_eq!(assembled, payload);
    }

    #[test]
    fn speed_test_request_round_trip() {
        let request = SpeedTestRequest {
            warmup_bytes: 1024 * 1024,
            download_bytes: 16 * 1024 * 1024,
            upload_bytes: 8 * 1024 * 1024,
            sample_count: 3,
        };

        let encoded = request.encode().unwrap();
        assert_eq!(SpeedTestRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn speed_test_request_has_magic_is_exact() {
        // has_magic = len >= 4 && [..4] == MAGIC. Pin all three terms: a valid
        // prefix is true; too-short is false; a 4-byte wrong magic is false. Kills
        // `-> true`/`-> false`, `>= -> <`, `&& -> ||`, `== -> !=`.
        let mut good = SPEED_TEST_MAGIC.to_vec();
        good.extend_from_slice(&[0_u8; 26]);
        assert!(SpeedTestRequest::has_magic(&good));
        assert!(!SpeedTestRequest::has_magic(&SPEED_TEST_MAGIC[..3]));
        assert!(!SpeedTestRequest::has_magic(b"ZZZZ"));
        assert!(!SpeedTestRequest::has_magic(b""));
    }

    #[test]
    fn speed_test_request_decode_length_boundary() {
        // decode guards: `< 4` then `< 30` then `!= 30`. A valid 30-byte request
        // decodes; 29 bytes (valid magic) is Truncated; a 31-byte input is
        // InvalidLength. Pins `< 30` vs `<= 30`/`== 30` and the `!= 30` exact check.
        let valid = SpeedTestRequest {
            warmup_bytes: 1,
            download_bytes: 1,
            upload_bytes: 1,
            sample_count: 1,
        }
        .encode()
        .unwrap();
        assert_eq!(valid.len(), 30);
        assert!(SpeedTestRequest::decode(&valid).is_ok());

        let mut short = SPEED_TEST_MAGIC.to_vec();
        short.resize(29, 0);
        assert!(matches!(
            SpeedTestRequest::decode(&short),
            Err(SpeedTestRequestError::Truncated)
        ));

        let mut long = valid.clone();
        long.push(0);
        assert!(matches!(
            SpeedTestRequest::decode(&long),
            Err(SpeedTestRequestError::InvalidLength)
        ));
    }

    #[test]
    fn speed_test_ack_decode_length_boundary_and_every_magic() {
        // Each ack kind's magic must be recognized (pins the per-magic match guards,
        // e.g. SPEED_UPLOAD_DONE_MAGIC), and the `< 12` length guard: a 12-byte ack
        // decodes, 11 (valid magic) is Truncated.
        for ack in [
            SpeedTestAck::warmup_download_done(1),
            SpeedTestAck::warmup_upload_done(2),
            SpeedTestAck::download_done(3),
            SpeedTestAck::upload_done(4),
        ] {
            let encoded = ack.encode();
            assert_eq!(encoded.len(), 12);
            assert_eq!(SpeedTestAck::decode(&encoded).unwrap(), ack);
            assert!(matches!(
                SpeedTestAck::decode(&encoded[..11]),
                Err(SpeedTestAckError::Truncated)
            ));
        }
    }

    #[test]
    fn mux_frame_kind_from_wire_round_trips_every_variant() {
        // from_wire must map each wire byte back to its kind; deleting an arm (e.g.
        // Reset=4 or Cover=5) would turn that byte into InvalidKind. Round-trip every
        // variant through to_wire/from_wire and confirm an unknown byte is rejected.
        for kind in [
            MuxFrameKind::Open,
            MuxFrameKind::Data,
            MuxFrameKind::Fin,
            MuxFrameKind::Reset,
            MuxFrameKind::Cover,
        ] {
            assert_eq!(MuxFrameKind::from_wire(kind.to_wire()).unwrap(), kind);
        }
        assert!(matches!(
            MuxFrameKind::from_wire(0),
            Err(MuxFrameError::InvalidKind)
        ));
        assert!(matches!(
            MuxFrameKind::from_wire(6),
            Err(MuxFrameError::InvalidKind)
        ));
    }

    #[test]
    fn mux_frame_has_magic_and_payload_sizing_are_exact() {
        // has_magic: valid prefix true, short/wrong false (kills the same family as
        // SpeedTestRequest::has_magic).
        let mut good = MUX_FRAME_MAGIC.to_vec();
        good.extend_from_slice(&[0_u8; 9]);
        assert!(MuxFrame::has_magic(&good));
        assert!(!MuxFrame::has_magic(&MUX_FRAME_MAGIC[..3]));
        assert!(!MuxFrame::has_magic(b"ZZZZ"));

        // max_payload_len = max_encoded_len - MUX_FRAME_FIXED_LEN (13). Pin the exact
        // subtraction (kills `-> 0` / `-> 1`).
        assert_eq!(MuxFrame::max_payload_len(1000), 1000 - 13);
        assert_eq!(MuxFrame::max_payload_len(13), 0);
        assert_eq!(
            MuxFrame::max_payload_len(0),
            0,
            "saturating, never underflows"
        );

        // max_open_initial_payload_len subtracts the CONNECT fixed framing + host on
        // top of the mux payload budget; pin it against the explicit composition.
        let host = "example.com";
        let expected = ConnectRequest::max_initial_payload_len(host, 1000 - 13);
        assert_eq!(MuxFrame::max_open_initial_payload_len(host, 1000), expected);
        assert!(expected > 1, "fixture sanity: budget far exceeds 1");
    }

    #[test]
    fn validate_mux_stream_enforces_cover_zero_and_others_nonzero() {
        // Control-plane invariant: a Cover frame MUST carry stream_id 0, every other
        // kind MUST carry a non-zero stream_id. Pins the `stream_id == 0` guard (kills
        // `== 0 with false`, which would make Cover always invalid) and the `!= 0`
        // guard for the data-bearing kinds.
        assert!(MuxFrame::encode_borrowed(0, MuxFrameKind::Cover, &[]).is_ok());
        assert!(matches!(
            MuxFrame::encode_borrowed(1, MuxFrameKind::Cover, &[]),
            Err(MuxFrameError::InvalidStreamId)
        ));
        for kind in [
            MuxFrameKind::Open,
            MuxFrameKind::Data,
            MuxFrameKind::Fin,
            MuxFrameKind::Reset,
        ] {
            assert!(
                MuxFrame::encode_borrowed(7, kind, &[]).is_ok(),
                "{kind:?} with a non-zero stream id must be valid"
            );
            assert!(
                matches!(
                    MuxFrame::encode_borrowed(0, kind, &[]),
                    Err(MuxFrameError::InvalidStreamId)
                ),
                "{kind:?} with stream id 0 must be rejected"
            );
        }
    }

    #[test]
    fn udp_offer_and_decline_has_magic_are_exact() {
        // Same has_magic shape as SpeedTestRequest/MuxFrame: len >= 4 && prefix ==
        // MAGIC. Pin each so `-> true`/`-> false`, `>= -> <`, `&& -> ||`, `== -> !=`
        // are caught for both UdpOffer and UdpDecline.
        let mut offer = UDP_OFFER_MAGIC.to_vec();
        offer.extend_from_slice(&[0_u8; 8]);
        assert!(UdpOffer::has_magic(&offer));
        assert!(!UdpOffer::has_magic(&UDP_OFFER_MAGIC[..3]));
        assert!(!UdpOffer::has_magic(UDP_DECLINE_MAGIC)); // wrong 4-byte magic

        let mut decline = UDP_DECLINE_MAGIC.to_vec();
        decline.push(0);
        assert!(UdpDecline::has_magic(&decline));
        assert!(!UdpDecline::has_magic(&UDP_DECLINE_MAGIC[..3]));
        assert!(!UdpDecline::has_magic(UDP_OFFER_MAGIC));
    }

    #[test]
    fn mux_frame_decode_ref_prefix_length_boundary() {
        // decode_ref_prefix's `< 4` and `< MUX_FRAME_FIXED_LEN (13)` guards: a full
        // header (13 bytes, zero payload) decodes; 12 bytes (valid magic) is
        // Truncated. Pins the `< 13` guard vs `== 13`.
        let header = MuxFrame::encode_borrowed(0, MuxFrameKind::Cover, &[]).unwrap();
        assert_eq!(header.len(), 13);
        assert!(MuxFrame::decode_ref_prefix(&header).is_ok());
        assert!(matches!(
            MuxFrame::decode_ref_prefix(&header[..12]),
            Err(MuxFrameError::Truncated)
        ));
    }

    #[test]
    fn speed_test_ack_round_trip() {
        let warmup_download = SpeedTestAck::warmup_download_done(111);
        let warmup_upload = SpeedTestAck::warmup_upload_done(222);
        let download = SpeedTestAck::download_done(123);
        let upload = SpeedTestAck::upload_done(456);

        assert_eq!(
            SpeedTestAck::decode(&warmup_download.encode()).unwrap(),
            warmup_download
        );
        assert_eq!(
            SpeedTestAck::decode(&warmup_upload.encode()).unwrap(),
            warmup_upload
        );
        assert_eq!(SpeedTestAck::decode(&download.encode()).unwrap(), download);
        assert_eq!(SpeedTestAck::decode(&upload.encode()).unwrap(), upload);
    }

    #[test]
    fn mux_frame_round_trip() {
        let connect = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        }
        .encode()
        .unwrap();
        let encoded = MuxFrame::encode_borrowed(7, MuxFrameKind::Open, &connect).unwrap();

        let borrowed = MuxFrame::decode_ref(&encoded).unwrap();
        assert_eq!(borrowed.stream_id, 7);
        assert_eq!(borrowed.kind, MuxFrameKind::Open);
        assert_eq!(
            ConnectRequest::decode_ref(borrowed.payload).unwrap().host,
            "example.com"
        );
        assert_eq!(MuxFrame::decode(&encoded).unwrap().payload, connect);
    }

    #[test]
    fn mux_frame_prefix_decode_supports_batched_records() {
        let first = MuxFrame {
            stream_id: 1,
            kind: MuxFrameKind::Data,
            payload: b"one".to_vec(),
        };
        let second = MuxFrame {
            stream_id: 3,
            kind: MuxFrameKind::Fin,
            payload: Vec::new(),
        };
        let mut encoded = Vec::new();
        first.encode_into(&mut encoded).unwrap();
        second.encode_into(&mut encoded).unwrap();

        let (borrowed, used) = MuxFrame::decode_ref_prefix(&encoded).unwrap();
        assert_eq!(borrowed.stream_id, 1);
        assert_eq!(borrowed.payload, b"one");
        assert_eq!(used, first.encode().unwrap().len());
        assert_eq!(
            MuxFrame::decode(&encoded).unwrap_err(),
            MuxFrameError::InvalidPayloadLength
        );

        let decoded = MuxFrame::decode_all(&encoded).unwrap();
        assert_eq!(decoded, vec![first, second]);
    }

    #[test]
    fn mux_frame_rejects_bad_stream_ids_and_lengths() {
        assert_eq!(
            MuxFrame::encode_borrowed(0, MuxFrameKind::Data, b"x").unwrap_err(),
            MuxFrameError::InvalidStreamId
        );
        assert_eq!(
            MuxFrame::encode_borrowed(1, MuxFrameKind::Cover, b"").unwrap_err(),
            MuxFrameError::InvalidStreamId
        );

        let mut encoded = MuxFrame::encode_borrowed(1, MuxFrameKind::Fin, b"").unwrap();
        encoded.push(0);
        assert_eq!(
            MuxFrame::decode_ref(&encoded).unwrap_err(),
            MuxFrameError::InvalidPayloadLength
        );
    }

    #[test]
    fn speed_test_request_rejects_zero_values() {
        assert_eq!(
            SpeedTestRequest {
                warmup_bytes: 0,
                download_bytes: 1,
                upload_bytes: 1,
                sample_count: 1,
            }
            .encode()
            .unwrap_err(),
            SpeedTestRequestError::ZeroBytes
        );
        assert_eq!(
            SpeedTestRequest {
                warmup_bytes: 1,
                download_bytes: 1,
                upload_bytes: 1,
                sample_count: 0,
            }
            .encode()
            .unwrap_err(),
            SpeedTestRequestError::ZeroSamples
        );
    }

    #[test]
    fn rejects_malformed_length_prefixed_commands() {
        assert_eq!(
            PqRekeyRequest {
                client_x25519_public: [9_u8; 32],
                client_mlkem_public_key: Vec::new(),
            }
            .encode()
            .unwrap_err(),
            PqRekeyError::EmptyPublicKey
        );
        let mut pq = Vec::new();
        pq.extend_from_slice(PQ_REKEY_MAGIC);
        pq.extend_from_slice(&[9_u8; 32]);
        pq.extend_from_slice(&3_u32.to_be_bytes());
        pq.extend_from_slice(&[1, 2]);
        assert_eq!(
            PqRekeyRequest::decode(&pq).unwrap_err(),
            PqRekeyError::InvalidPublicKeyLength
        );

        assert_eq!(
            ServerKeyExchange {
                server_x25519_public: [7_u8; 32],
                mlkem_ciphertext: Vec::new(),
            }
            .encode()
            .unwrap_err(),
            ServerKeyExchangeError::EmptyCiphertext
        );
        let mut exchange = Vec::new();
        exchange.extend_from_slice(SERVER_KEY_EXCHANGE_MAGIC);
        exchange.extend_from_slice(&[7_u8; 32]);
        exchange.extend_from_slice(&3_u32.to_be_bytes());
        exchange.extend_from_slice(&[1, 2]);
        assert_eq!(
            ServerKeyExchange::decode(&exchange).unwrap_err(),
            ServerKeyExchangeError::InvalidCiphertextLength
        );

        assert_eq!(
            ServerIdentityProof {
                signature: Vec::new(),
            }
            .encode()
            .unwrap_err(),
            ServerIdentityProofError::EmptySignature
        );
        let mut proof = Vec::new();
        proof.extend_from_slice(SERVER_IDENTITY_MAGIC);
        proof.extend_from_slice(&3_u32.to_be_bytes());
        proof.extend_from_slice(&[1, 2]);
        assert_eq!(
            ServerIdentityProof::decode(&proof).unwrap_err(),
            ServerIdentityProofError::InvalidSignatureLength
        );
    }

    #[test]
    fn mux_payload_pool_recycles_buffer_allocations() {
        let pool = MuxPayloadPool::new(16 * 1024, 4);
        let first = pool.take_filled(b"hello");
        assert_eq!(first.as_slice(), b"hello");
        let ptr = first.as_ptr();
        let cap = first.capacity();
        pool.put(first);

        let reused = pool.take();
        assert!(reused.is_empty());
        assert_eq!(reused.as_ptr(), ptr, "freed buffer should be handed back");
        assert_eq!(reused.capacity(), cap);
    }

    #[test]
    fn mux_payload_pool_drops_undersized_and_overflow_buffers() {
        let pool = MuxPayloadPool::new(16 * 1024, 1);

        // Undersized buffers are never retained.
        pool.put(Vec::with_capacity(8));
        let fresh = pool.take();
        assert!(fresh.capacity() >= 16 * 1024);

        // The freelist respects its retention cap.
        pool.put(Vec::with_capacity(16 * 1024));
        pool.put(Vec::with_capacity(16 * 1024));
        let _first = pool.take();
        let second = pool.take();
        assert!(second.is_empty());
    }

    #[test]
    fn server_identity_chunks_reject_invalid_ranges() {
        assert_eq!(
            ServerIdentityChunk::encode_all(&[], 700).unwrap_err(),
            ServerIdentityChunkError::InvalidChunkLength
        );
        assert_eq!(
            ServerIdentityChunk::encode_all(b"payload", 0).unwrap_err(),
            ServerIdentityChunkError::InvalidChunkLength
        );
        assert_eq!(
            ServerIdentityChunk {
                total_len: 3,
                offset: 2,
                bytes: vec![1, 2],
            }
            .encode()
            .unwrap_err(),
            ServerIdentityChunkError::InvalidOffset
        );

        let mut chunk = Vec::new();
        chunk.extend_from_slice(SERVER_IDENTITY_CHUNK_MAGIC);
        chunk.extend_from_slice(&3_u32.to_be_bytes());
        chunk.extend_from_slice(&2_u32.to_be_bytes());
        chunk.extend_from_slice(&2_u32.to_be_bytes());
        chunk.extend_from_slice(&[1, 2]);
        assert_eq!(
            ServerIdentityChunk::decode(&chunk).unwrap_err(),
            ServerIdentityChunkError::InvalidOffset
        );
    }

    #[test]
    fn udp_offer_round_trips() {
        for ignore in [false, true] {
            let offer = UdpOffer {
                offer_id: [0xAB; UDP_OFFER_ID_LEN],
                udp_port: 8443,
                port_hop_seed: 0x0123_4567_89AB_CDEF,
                cc: UDP_CC_BRUTAL,
                fec_profile: UDP_FEC_RS,
                ignore_client_bandwidth: ignore,
            };
            let encoded = offer.encode().unwrap();
            assert_eq!(encoded.len(), UDP_OFFER_LEN);
            assert_eq!(&encoded[..4], UDP_OFFER_MAGIC);
            assert_eq!(UdpOffer::decode(&encoded).unwrap(), offer);
        }
    }

    #[test]
    fn udp_offer_rejects_zero_port() {
        let offer = UdpOffer {
            offer_id: [0; UDP_OFFER_ID_LEN],
            udp_port: 0,
            port_hop_seed: 0,
            cc: UDP_CC_BBR,
            fec_profile: UDP_FEC_OFF,
            ignore_client_bandwidth: false,
        };
        assert_eq!(offer.encode().unwrap_err(), UdpOfferError::ZeroPort);
    }

    #[test]
    fn udp_offer_rejects_bad_magic_length_and_zero_port() {
        let offer = UdpOffer {
            offer_id: [1; UDP_OFFER_ID_LEN],
            udp_port: 443,
            port_hop_seed: 7,
            cc: UDP_CC_BBR,
            fec_profile: UDP_FEC_ADAPTIVE,
            ignore_client_bandwidth: false,
        };
        let encoded = offer.encode().unwrap();

        // Too short / empty -> Truncated.
        assert_eq!(
            UdpOffer::decode(&encoded[..encoded.len() - 1]).unwrap_err(),
            UdpOfferError::Truncated
        );
        assert_eq!(UdpOffer::decode(&[]).unwrap_err(), UdpOfferError::Truncated);

        // Trailing garbage / too long -> InvalidLength.
        let mut too_long = encoded.clone();
        too_long.push(0);
        assert_eq!(
            UdpOffer::decode(&too_long).unwrap_err(),
            UdpOfferError::InvalidLength
        );

        // Bad magic.
        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            UdpOffer::decode(&bad_magic).unwrap_err(),
            UdpOfferError::BadMagic
        );

        // Decode-side zero-port (port lives at offset 4 + offer_id).
        let mut zero_port = encoded.clone();
        zero_port[4 + UDP_OFFER_ID_LEN] = 0;
        zero_port[4 + UDP_OFFER_ID_LEN + 1] = 0;
        assert_eq!(
            UdpOffer::decode(&zero_port).unwrap_err(),
            UdpOfferError::ZeroPort
        );
    }

    #[test]
    fn udp_probe_ack_round_trips_each_status() {
        for status in [
            UdpProbeStatus::Verified,
            UdpProbeStatus::Unreachable,
            UdpProbeStatus::Failed,
        ] {
            let ack = UdpProbeAck {
                offer_id: [0x5A; UDP_OFFER_ID_LEN],
                status,
                rtt_micros: 12_345,
            };
            let encoded = ack.encode();
            assert_eq!(encoded.len(), UDP_PROBE_ACK_LEN);
            assert_eq!(&encoded[..4], UDP_PROBE_ACK_MAGIC);
            assert_eq!(UdpProbeAck::decode(&encoded).unwrap(), ack);
        }
    }

    #[test]
    fn udp_probe_ack_rejects_invalid_status_magic_and_truncation() {
        let ack = UdpProbeAck {
            offer_id: [9; UDP_OFFER_ID_LEN],
            status: UdpProbeStatus::Verified,
            rtt_micros: 0,
        };
        let mut bad_status = ack.encode();
        bad_status[4 + UDP_OFFER_ID_LEN] = 9;
        assert_eq!(
            UdpProbeAck::decode(&bad_status).unwrap_err(),
            UdpProbeAckError::InvalidStatus(9)
        );
        let mut bad_magic = ack.encode();
        bad_magic[0] = b'X';
        assert_eq!(
            UdpProbeAck::decode(&bad_magic).unwrap_err(),
            UdpProbeAckError::BadMagic
        );
        assert_eq!(
            UdpProbeAck::decode(&ack.encode()[..5]).unwrap_err(),
            UdpProbeAckError::Truncated
        );
        let mut too_long = ack.encode();
        too_long.push(0);
        assert_eq!(
            UdpProbeAck::decode(&too_long).unwrap_err(),
            UdpProbeAckError::InvalidLength
        );
    }

    #[test]
    fn udp_request_round_trips_and_rejects_malformed() {
        let request = UdpRequest {
            version: UDP_NEGOTIATION_VERSION,
        };
        let encoded = request.encode();
        assert_eq!(encoded.len(), UDP_REQUEST_LEN);
        assert_eq!(&encoded[..4], UDP_REQUEST_MAGIC);
        assert!(UdpRequest::has_magic(&encoded));
        assert!(!UdpRequest::has_magic(MUX_FRAME_MAGIC));
        assert_eq!(UdpRequest::decode(&encoded).unwrap(), request);

        assert_eq!(
            UdpRequest::decode(&encoded[..4]).unwrap_err(),
            UdpRequestError::Truncated
        );
        let mut too_long = encoded.clone();
        too_long.push(0);
        assert_eq!(
            UdpRequest::decode(&too_long).unwrap_err(),
            UdpRequestError::InvalidLength
        );
        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            UdpRequest::decode(&bad_magic).unwrap_err(),
            UdpRequestError::BadMagic
        );
    }

    #[test]
    fn udp_decline_round_trips_and_rejects_malformed() {
        for reason in [UDP_DECLINE_DISABLED, UDP_DECLINE_UNSUPPORTED] {
            let decline = UdpDecline { reason };
            let encoded = decline.encode();
            assert_eq!(encoded.len(), UDP_DECLINE_LEN);
            assert_eq!(&encoded[..4], UDP_DECLINE_MAGIC);
            assert!(UdpDecline::has_magic(&encoded));
            assert_eq!(UdpDecline::decode(&encoded).unwrap(), decline);
        }

        let encoded = UdpDecline {
            reason: UDP_DECLINE_DISABLED,
        }
        .encode();
        assert_eq!(
            UdpDecline::decode(&encoded[..4]).unwrap_err(),
            UdpDeclineError::Truncated
        );
        let mut too_long = encoded.clone();
        too_long.push(0);
        assert_eq!(
            UdpDecline::decode(&too_long).unwrap_err(),
            UdpDeclineError::InvalidLength
        );
        let mut bad_magic = encoded;
        bad_magic[0] = b'X';
        assert_eq!(
            UdpDecline::decode(&bad_magic).unwrap_err(),
            UdpDeclineError::BadMagic
        );
    }
}
