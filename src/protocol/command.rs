use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
const MAX_HOST_LEN: usize = 255;
const CONNECT_FIXED_LEN: usize = 4 + 2 + 2 + 4;

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

    pub fn decode(input: &[u8]) -> Result<Self, ServerKeyExchangeError> {
        let exchange = Self::decode_ref(input)?;
        Ok(Self {
            server_x25519_public: exchange.server_x25519_public,
            mlkem_ciphertext: exchange.mlkem_ciphertext.to_vec(),
        })
    }

    pub fn decode_ref(input: &[u8]) -> Result<ServerKeyExchangeRef<'_>, ServerKeyExchangeError> {
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
        if input.len() != 40 + len {
            return Err(ServerKeyExchangeError::InvalidCiphertextLength);
        }
        Ok(ServerKeyExchangeRef {
            server_x25519_public,
            mlkem_ciphertext: &input[40..],
        })
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
}
