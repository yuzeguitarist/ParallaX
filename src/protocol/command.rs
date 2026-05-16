use thiserror::Error;

const CONNECT_MAGIC: &[u8; 4] = b"PX1C";
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

impl ConnectRequest {
    pub fn target(&self) -> String {
        format!("{}:{}", self.host, self.port)
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
    fn rejects_bad_magic() {
        assert_eq!(
            ConnectRequest::decode(b"BAD!").unwrap_err(),
            ConnectRequestError::BadMagic
        );
    }
}
