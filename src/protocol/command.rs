use thiserror::Error;

const CONNECT_MAGIC: &[u8; 4] = b"PX1C";
const PQ_REKEY_MAGIC: &[u8; 4] = b"PX1Q";
const SERVER_IDENTITY_MAGIC: &[u8; 4] = b"PX1S";
const MAX_HOST_LEN: usize = 255;
const CONNECT_FIXED_LEN: usize = 4 + 2 + 2 + 4;

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
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentityProof {
    pub signature: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PqRekeyError {
    #[error("PQ rekey request is truncated")]
    Truncated,
    #[error("PQ rekey request magic mismatch")]
    BadMagic,
    #[error("PQ rekey ciphertext is empty")]
    EmptyCiphertext,
    #[error("PQ rekey ciphertext length is invalid")]
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

impl ConnectRequest {
    pub fn max_initial_payload_len(host: &str, max_encoded_len: usize) -> usize {
        max_encoded_len.saturating_sub(CONNECT_FIXED_LEN + host.len())
    }

    pub fn encoded_len(&self) -> usize {
        CONNECT_FIXED_LEN + self.host.len() + self.initial_payload.len()
    }

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

        let mut out = Vec::with_capacity(self.encoded_len());
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
        if self.ciphertext.is_empty() {
            return Err(PqRekeyError::EmptyCiphertext);
        }
        let mut out = Vec::with_capacity(8 + self.ciphertext.len());
        out.extend_from_slice(PQ_REKEY_MAGIC);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PqRekeyError> {
        if input.len() < 4 {
            return Err(PqRekeyError::Truncated);
        }
        if &input[..4] != PQ_REKEY_MAGIC {
            return Err(PqRekeyError::BadMagic);
        }
        if input.len() < 8 {
            return Err(PqRekeyError::Truncated);
        }
        let len = u32::from_be_bytes([input[4], input[5], input[6], input[7]]) as usize;
        if len == 0 {
            return Err(PqRekeyError::EmptyCiphertext);
        }
        if input.len() != 8 + len {
            return Err(PqRekeyError::InvalidCiphertextLength);
        }
        Ok(Self {
            ciphertext: input[8..].to_vec(),
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
    fn pq_rekey_round_trip() {
        let request = PqRekeyRequest {
            ciphertext: vec![1, 2, 3],
        };
        let encoded = request.encode().unwrap();
        assert_eq!(PqRekeyRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn server_identity_proof_round_trip() {
        let proof = ServerIdentityProof {
            signature: vec![4, 5, 6],
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(ServerIdentityProof::decode(&encoded).unwrap(), proof);
    }
}
