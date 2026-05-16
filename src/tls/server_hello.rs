use std::ops::Range;

use thiserror::Error;

use super::record::{parse_header, TLS_CONTENT_HANDSHAKE, TLS_HEADER_LEN};

const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const TLS13_VERSION: u16 = 0x0304;
const RANDOM_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub record_len: usize,
    pub random: [u8; RANDOM_LEN],
    pub session_id_range: Range<usize>,
    pub tls13_selected: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ServerHelloError {
    #[error("TLS record parse failed: {0}")]
    Record(#[from] super::record::TlsRecordError),
    #[error("record is not a TLS handshake record")]
    NotHandshakeRecord,
    #[error("record is not a ServerHello")]
    NotServerHello,
    #[error("ServerHello is truncated")]
    Truncated,
    #[error("ServerHello length is invalid")]
    InvalidLength,
}

pub fn parse_server_hello(record: &[u8]) -> Result<ServerHello, ServerHelloError> {
    let header = parse_header(record)?;
    if record.len() < header.total_len {
        return Err(ServerHelloError::Truncated);
    }
    if header.content_type != TLS_CONTENT_HANDSHAKE {
        return Err(ServerHelloError::NotHandshakeRecord);
    }

    let mut cursor = Cursor::new(record, TLS_HEADER_LEN, header.total_len);
    if cursor.u8()? != HANDSHAKE_SERVER_HELLO {
        return Err(ServerHelloError::NotServerHello);
    }

    let body_len = cursor.u24()? as usize;
    let body_start = cursor.pos;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or(ServerHelloError::InvalidLength)?;
    if body_end > header.total_len {
        return Err(ServerHelloError::InvalidLength);
    }
    cursor.set_end(body_end);

    cursor.skip(2)?; // legacy_version
    let random_slice = cursor.bytes(RANDOM_LEN)?;
    let mut random = [0_u8; RANDOM_LEN];
    random.copy_from_slice(random_slice);

    let session_len = cursor.u8()? as usize;
    let session_start = cursor.pos;
    cursor.skip(session_len)?;
    let session_id_range = session_start..session_start + session_len;
    cursor.skip(2)?; // cipher_suite
    cursor.skip(1)?; // compression_method

    let mut tls13_selected = false;
    if cursor.remaining() > 0 {
        let ext_len = cursor.u16()? as usize;
        let ext_end = cursor
            .pos
            .checked_add(ext_len)
            .ok_or(ServerHelloError::InvalidLength)?;
        if ext_end > body_end {
            return Err(ServerHelloError::InvalidLength);
        }
        cursor.set_end(ext_end);

        while cursor.remaining() > 0 {
            let ext_type = cursor.u16()?;
            let ext_data = cursor.bytes_vec_u16()?;
            if ext_type == EXT_SUPPORTED_VERSIONS {
                tls13_selected = parse_supported_versions(ext_data)?;
            }
        }
    }

    Ok(ServerHello {
        record_len: header.total_len,
        random,
        session_id_range,
        tls13_selected,
    })
}

fn parse_supported_versions(data: &[u8]) -> Result<bool, ServerHelloError> {
    if data.len() != 2 {
        return Err(ServerHelloError::InvalidLength);
    }
    Ok(u16::from_be_bytes([data[0], data[1]]) == TLS13_VERSION)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], pos: usize, end: usize) -> Self {
        Self { data, pos, end }
    }

    fn set_end(&mut self, end: usize) {
        self.end = end;
    }

    fn remaining(&self) -> usize {
        self.end.saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8, ServerHelloError> {
        if self.remaining() < 1 {
            return Err(ServerHelloError::Truncated);
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ServerHelloError> {
        if self.remaining() < 2 {
            return Err(ServerHelloError::Truncated);
        }
        let value = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    fn u24(&mut self) -> Result<u32, ServerHelloError> {
        if self.remaining() < 3 {
            return Err(ServerHelloError::Truncated);
        }
        let value = ((self.data[self.pos] as u32) << 16)
            | ((self.data[self.pos + 1] as u32) << 8)
            | self.data[self.pos + 2] as u32;
        self.pos += 3;
        Ok(value)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ServerHelloError> {
        if self.remaining() < len {
            return Err(ServerHelloError::Truncated);
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.data[start..start + len])
    }

    fn bytes_vec_u16(&mut self) -> Result<&'a [u8], ServerHelloError> {
        let len = self.u16()? as usize;
        self.bytes(len)
    }

    fn skip(&mut self, len: usize) -> Result<(), ServerHelloError> {
        self.bytes(len).map(|_| ())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn parses_server_hello_fixture() {
        let record = server_hello_fixture();
        let parsed = parse_server_hello(&record).unwrap();

        assert_eq!(parsed.random, [0x44; 32]);
        assert_eq!(parsed.session_id_range.len(), 32);
        assert!(parsed.tls13_selected);
    }

    pub fn server_hello_fixture() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x44; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0x55; 32]); // echoed session id
        body.extend_from_slice(&[0x13, 0x01]); // cipher_suite
        body.push(0); // compression_method

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        extensions.extend_from_slice(&2_u16.to_be_bytes());
        extensions.extend_from_slice(&TLS13_VERSION.to_be_bytes());
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_SERVER_HELLO);
        push_u24(&mut handshake, body.len() as u32);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_CONTENT_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn push_u24(out: &mut Vec<u8>, value: u32) {
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
    }
}
