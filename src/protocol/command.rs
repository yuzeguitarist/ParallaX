use thiserror::Error;

const CONNECT_MAGIC: &[u8; 4] = b"PX1C";
const PQ_REKEY_MAGIC: &[u8; 4] = b"PX1Q";
const SERVER_KEY_EXCHANGE_MAGIC: &[u8; 4] = b"PX1K";
const SERVER_IDENTITY_MAGIC: &[u8; 4] = b"PX1S";
const SERVER_IDENTITY_CHUNK_MAGIC: &[u8; 4] = b"PX1I";
const MAX_HOST_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    pub initial_payload: Vec<u8>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKeyExchange {
    pub server_x25519_public: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
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

impl ConnectRequest {
    pub fn target(&self) -> String {
        match self.host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(_)) => format!("[{}]:{}", self.host, self.port),
            _ => format!("{}:{}", self.host, self.port),
        }
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

        let mut out = Vec::with_capacity(12 + host.len() + self.initial_payload.len());
        out.extend_from_slice(CONNECT_MAGIC);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&(self.initial_payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.initial_payload);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConnectRequestError> {
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
        let host = std::str::from_utf8(host)
            .map_err(|_| ConnectRequestError::InvalidHost)?
            .to_owned();

        let port = cursor.u16()?;
        if port == 0 {
            return Err(ConnectRequestError::ZeroPort);
        }

        let payload_len = cursor.u32()? as usize;
        if cursor.remaining() != payload_len {
            return Err(ConnectRequestError::InvalidPayloadLength);
        }
        let initial_payload = cursor.bytes(payload_len)?.to_vec();

        Ok(Self {
            host,
            port,
            initial_payload,
        })
    }
}

impl PqRekeyRequest {
    pub fn encode(&self) -> Result<Vec<u8>, PqRekeyError> {
        if self.client_mlkem_public_key.is_empty() {
            return Err(PqRekeyError::EmptyPublicKey);
        }
        let mut out = Vec::with_capacity(40 + self.client_mlkem_public_key.len());
        out.extend_from_slice(PQ_REKEY_MAGIC);
        out.extend_from_slice(&self.client_x25519_public);
        out.extend_from_slice(&(self.client_mlkem_public_key.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.client_mlkem_public_key);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PqRekeyError> {
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
        Ok(Self {
            client_x25519_public,
            client_mlkem_public_key: input[40..].to_vec(),
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
        Ok(Self {
            server_x25519_public,
            mlkem_ciphertext: input[40..].to_vec(),
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
        Ok(Self {
            signature: input[8..].to_vec(),
        })
    }
}

impl ServerIdentityChunk {
    pub fn encode(&self) -> Result<Vec<u8>, ServerIdentityChunkError> {
        if self.bytes.is_empty() {
            return Err(ServerIdentityChunkError::EmptyChunk);
        }
        let end = self
            .offset
            .checked_add(self.bytes.len() as u32)
            .ok_or(ServerIdentityChunkError::InvalidOffset)?;
        if self.total_len == 0 || end > self.total_len {
            return Err(ServerIdentityChunkError::InvalidOffset);
        }

        let mut out = Vec::with_capacity(16 + self.bytes.len());
        out.extend_from_slice(SERVER_IDENTITY_CHUNK_MAGIC);
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&(self.bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.bytes);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ServerIdentityChunkError> {
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
        Ok(Self {
            total_len,
            offset,
            bytes: input[16..].to_vec(),
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
        let mut chunks = Vec::new();
        for (idx, bytes) in payload.chunks(max_chunk_len).enumerate() {
            chunks.push(
                Self {
                    total_len,
                    offset: (idx * max_chunk_len) as u32,
                    bytes: bytes.to_vec(),
                }
                .encode()?,
            );
        }
        Ok(chunks)
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
    fn connect_request_target_brackets_ipv6_literals() {
        let request = ConnectRequest {
            host: "::1".to_owned(),
            port: 443,
            initial_payload: Vec::new(),
        };

        assert_eq!(request.target(), "[::1]:443");
    }

    #[test]
    fn rejects_bad_magic() {
        assert_eq!(
            ConnectRequest::decode(b"BAD!").unwrap_err(),
            ConnectRequestError::BadMagic
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
    fn server_key_exchange_round_trip() {
        let exchange = ServerKeyExchange {
            server_x25519_public: [7_u8; 32],
            mlkem_ciphertext: vec![1, 2, 3],
        };
        let encoded = exchange.encode().unwrap();
        assert_eq!(ServerKeyExchange::decode(&encoded).unwrap(), exchange);
    }

    #[test]
    fn server_identity_proof_round_trip() {
        let proof = ServerIdentityProof {
            signature: vec![4, 5, 6],
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(ServerIdentityProof::decode(&encoded).unwrap(), proof);
    }

    #[test]
    fn server_identity_chunks_round_trip() {
        let payload = (0..2000).map(|v| (v % 251) as u8).collect::<Vec<_>>();
        let encoded = ServerIdentityChunk::encode_all(&payload, 700).unwrap();
        assert_eq!(encoded.len(), 3);

        let mut assembled = Vec::new();
        for chunk in encoded {
            let chunk = ServerIdentityChunk::decode(&chunk).unwrap();
            assert_eq!(chunk.offset as usize, assembled.len());
            assembled.extend_from_slice(&chunk.bytes);
        }

        assert_eq!(assembled, payload);
    }
}
