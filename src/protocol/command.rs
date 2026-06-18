use std::sync::{Arc, Mutex};

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::session::CipherSuite;

const CONNECT_MAGIC: &[u8; 4] = b"PX1C";
const PQ_REKEY_MAGIC: &[u8; 4] = b"PX1Q";
const SERVER_KEY_EXCHANGE_MAGIC: &[u8; 4] = b"PX1K";
const SERVER_IDENTITY_MAGIC: &[u8; 4] = b"PX1S";
const SERVER_IDENTITY_CHUNK_MAGIC: &[u8; 4] = b"PX1I";
const SPEED_TEST_MAGIC: &[u8; 4] = b"PX1T";
const SPEED_WARMUP_DOWNLOAD_DONE_MAGIC: &[u8; 4] = b"PX1W";
const SPEED_WARMUP_UPLOAD_DONE_MAGIC: &[u8; 4] = b"PX1V";
const SPEED_DOWNLOAD_DONE_MAGIC: &[u8; 4] = b"PX1D";
const SPEED_UPLOAD_DONE_MAGIC: &[u8; 4] = b"PX1U";
const MUX_FRAME_MAGIC: &[u8; 4] = b"PX1M";
const MAX_HOST_LEN: usize = 255;
const CONNECT_FIXED_LEN: usize = 4 + 2 + 2 + 4;
const MUX_FRAME_FIXED_LEN: usize = 4 + 4 + 1 + 4;

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
    pub fn encode(&self) -> Result<Vec<u8>, ServerKeyExchangeError> {
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
    /// [`Self::decode_ref_with_suite`]. Legacy records (no tag) decode as
    /// ChaCha20-Poly1305, so the two layouts are wire-compatible.
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

    /// Canonical parser. Accepts both the legacy `40 + ct_len` layout (no suite
    /// tag -> ChaCha20-Poly1305 default) and the `41 + ct_len` layout with a
    /// trailing cipher-suite tag. The ciphertext slice is bounded to exactly
    /// `ct_len`, so a trailing tag never bleeds into it.
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
        // Reject an impossible length before the `40 + len` / `41 + len`
        // arithmetic so it cannot wrap usize on a hypothetical 32-bit target
        // (ParallaX ships 64-bit only; belt-and-suspenders, redundant with the
        // exact-length checks below on 64-bit but free).
        if len > input.len() {
            return Err(ServerKeyExchangeError::InvalidCiphertextLength);
        }
        let suite = if input.len() == 40 + len {
            CipherSuite::ChaCha20Poly1305
        } else if input.len() == 41 + len {
            CipherSuite::from_wire(input[40 + len])
                .ok_or(ServerKeyExchangeError::InvalidCipherSuite)?
        } else {
            return Err(ServerKeyExchangeError::InvalidCiphertextLength);
        };
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
        let encoded = exchange.encode().unwrap();
        assert_eq!(ServerKeyExchange::decode(&encoded).unwrap(), exchange);
    }

    #[test]
    fn server_key_exchange_decode_ref_borrows_ciphertext() {
        let exchange = ServerKeyExchange {
            server_x25519_public: [7_u8; 32],
            mlkem_ciphertext: vec![1, 2, 3],
        };

        let encoded = exchange.encode().unwrap();
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

        // A legacy record (no tag) decodes as ChaCha20-Poly1305 (wire-compat).
        let legacy = exchange.encode().unwrap();
        let (_, legacy_suite) = ServerKeyExchange::decode_ref_with_suite(&legacy).unwrap();
        assert_eq!(legacy_suite, CipherSuite::ChaCha20Poly1305);

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
