use std::{ops::Range, str};

use thiserror::Error;

use super::record::{parse_header, TLS_CONTENT_HANDSHAKE, TLS_HEADER_LEN};

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const TLS13_VERSION: u16 = 0x0304;
const NAMED_GROUP_X25519: u16 = 0x001d;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub record_len: usize,
    pub client_random: [u8; 32],
    pub session_id_range: Range<usize>,
    pub sni: Option<String>,
    pub tls13_supported: bool,
    pub x25519_key_share: Option<[u8; 32]>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClientHelloError {
    #[error("TLS record parse failed: {0}")]
    Record(#[from] super::record::TlsRecordError),
    #[error("record is not a TLS handshake record")]
    NotHandshakeRecord,
    #[error("record is not a ClientHello")]
    NotClientHello,
    #[error("ClientHello is truncated")]
    Truncated,
    #[error("ClientHello length is invalid")]
    InvalidLength,
    #[error("SNI is not valid UTF-8")]
    InvalidSni,
}

pub fn parse_client_hello(record: &[u8]) -> Result<ClientHello, ClientHelloError> {
    let header = parse_header(record)?;
    if record.len() < header.total_len {
        return Err(ClientHelloError::Truncated);
    }
    if header.content_type != TLS_CONTENT_HANDSHAKE {
        return Err(ClientHelloError::NotHandshakeRecord);
    }

    let mut cursor = Cursor::new(record, TLS_HEADER_LEN, header.total_len);
    let handshake_type = cursor.u8()?;
    if handshake_type != HANDSHAKE_CLIENT_HELLO {
        return Err(ClientHelloError::NotClientHello);
    }

    let body_len = cursor.u24()? as usize;
    let body_start = cursor.pos;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or(ClientHelloError::InvalidLength)?;
    if body_end > header.total_len {
        return Err(ClientHelloError::InvalidLength);
    }

    cursor.set_end(body_end);
    cursor.skip(2)?; // legacy_version
    let mut client_random = [0_u8; 32];
    client_random.copy_from_slice(cursor.bytes(32)?);
    let session_len = cursor.u8()? as usize;
    let session_start = cursor.pos;
    cursor.skip(session_len)?;
    let session_id_range = session_start..session_start + session_len;
    cursor.skip_vec_u16()?; // cipher_suites
    cursor.skip_vec_u8()?; // compression_methods

    let mut sni = None;
    let mut tls13_supported = false;
    let mut x25519_key_share = None;

    if cursor.remaining() == 0 {
        return Ok(ClientHello {
            record_len: header.total_len,
            client_random,
            session_id_range,
            sni,
            tls13_supported,
            x25519_key_share,
        });
    }

    let ext_len = cursor.u16()? as usize;
    let ext_end = cursor
        .pos
        .checked_add(ext_len)
        .ok_or(ClientHelloError::InvalidLength)?;
    if ext_end > body_end {
        return Err(ClientHelloError::InvalidLength);
    }
    cursor.set_end(ext_end);

    while cursor.remaining() > 0 {
        let ext_type = cursor.u16()?;
        let data = cursor.bytes_vec_u16()?;
        match ext_type {
            EXT_SERVER_NAME => sni = parse_sni(data)?,
            EXT_SUPPORTED_VERSIONS => tls13_supported = parse_supported_versions(data)?,
            EXT_KEY_SHARE => x25519_key_share = parse_key_share(data)?,
            _ => {}
        }
    }

    Ok(ClientHello {
        record_len: header.total_len,
        client_random,
        session_id_range,
        sni,
        tls13_supported,
        x25519_key_share,
    })
}

fn parse_sni(data: &[u8]) -> Result<Option<String>, ClientHelloError> {
    let mut c = Cursor::new(data, 0, data.len());
    let list_len = c.u16()? as usize;
    let list_end = c
        .pos
        .checked_add(list_len)
        .ok_or(ClientHelloError::InvalidLength)?;
    if list_end > data.len() {
        return Err(ClientHelloError::InvalidLength);
    }
    c.set_end(list_end);

    while c.remaining() > 0 {
        let name_type = c.u8()?;
        let name = c.bytes_vec_u16()?;
        if name_type == 0 {
            let host = str::from_utf8(name).map_err(|_| ClientHelloError::InvalidSni)?;
            return Ok(Some(host.to_owned()));
        }
    }

    Ok(None)
}

fn parse_supported_versions(data: &[u8]) -> Result<bool, ClientHelloError> {
    let mut c = Cursor::new(data, 0, data.len());
    let len = c.u8()? as usize;
    if len % 2 != 0 || len > c.remaining() {
        return Err(ClientHelloError::InvalidLength);
    }
    let end = c.pos + len;
    while c.pos < end {
        if c.u16()? == TLS13_VERSION {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_key_share(data: &[u8]) -> Result<Option<[u8; 32]>, ClientHelloError> {
    let mut c = Cursor::new(data, 0, data.len());
    let len = c.u16()? as usize;
    let end = c
        .pos
        .checked_add(len)
        .ok_or(ClientHelloError::InvalidLength)?;
    if end > data.len() {
        return Err(ClientHelloError::InvalidLength);
    }
    c.set_end(end);

    while c.remaining() > 0 {
        let group = c.u16()?;
        let key = c.bytes_vec_u16()?;
        if group == NAMED_GROUP_X25519 && key.len() == 32 {
            let mut out = [0_u8; 32];
            out.copy_from_slice(key);
            return Ok(Some(out));
        }
    }

    Ok(None)
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

    fn u8(&mut self) -> Result<u8, ClientHelloError> {
        if self.remaining() < 1 {
            return Err(ClientHelloError::Truncated);
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ClientHelloError> {
        if self.remaining() < 2 {
            return Err(ClientHelloError::Truncated);
        }
        let value = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    fn u24(&mut self) -> Result<u32, ClientHelloError> {
        if self.remaining() < 3 {
            return Err(ClientHelloError::Truncated);
        }
        let value = ((self.data[self.pos] as u32) << 16)
            | ((self.data[self.pos + 1] as u32) << 8)
            | self.data[self.pos + 2] as u32;
        self.pos += 3;
        Ok(value)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ClientHelloError> {
        if self.remaining() < len {
            return Err(ClientHelloError::Truncated);
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.data[start..start + len])
    }

    fn bytes_vec_u16(&mut self) -> Result<&'a [u8], ClientHelloError> {
        let len = self.u16()? as usize;
        self.bytes(len)
    }

    fn skip(&mut self, len: usize) -> Result<(), ClientHelloError> {
        self.bytes(len).map(|_| ())
    }

    fn skip_vec_u8(&mut self) -> Result<(), ClientHelloError> {
        let len = self.u8()? as usize;
        self.skip(len)
    }

    fn skip_vec_u16(&mut self) -> Result<(), ClientHelloError> {
        let len = self.u16()? as usize;
        self.skip(len)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn parses_client_hello_fixture() {
        let record = client_hello_fixture("example.com");
        let parsed = parse_client_hello(&record).unwrap();

        assert_eq!(parsed.sni.as_deref(), Some("example.com"));
        assert_eq!(parsed.client_random, [0x22; 32]);
        assert_eq!(parsed.session_id_range.len(), 32);
        assert!(parsed.tls13_supported);
        assert!(parsed.x25519_key_share.is_some());
    }

    pub fn client_hello_fixture(sni: &str) -> Vec<u8> {
        client_hello_fixture_with_key_share(sni, &[0x22; 32])
    }

    pub fn client_hello_fixture_with_key_share(sni: &str, key_share_bytes: &[u8; 32]) -> Vec<u8> {
        client_hello_fixture_with_random_and_key_share(sni, key_share_bytes, key_share_bytes)
    }

    pub fn client_hello_fixture_with_random_and_key_share(
        sni: &str,
        client_random: &[u8; 32],
        key_share_bytes: &[u8; 32],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(client_random); // ParallaX v2 public key carrier
        body.push(32);
        body.extend_from_slice(&[0_u8; 32]); // ParallaX signed SessionID placeholder
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();
        let host = sni.as_bytes();
        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
        sni_data.push(0);
        sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(host);
        extension(&mut extensions, EXT_SERVER_NAME, &sni_data);

        extension(&mut extensions, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);

        let mut key_share_data = Vec::new();
        let mut share = Vec::new();
        share.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
        share.extend_from_slice(&32_u16.to_be_bytes());
        share.extend_from_slice(key_share_bytes);
        key_share_data.extend_from_slice(&(share.len() as u16).to_be_bytes());
        key_share_data.extend_from_slice(&share);
        extension(&mut extensions, EXT_KEY_SHARE, &key_share_data);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        push_u24(&mut handshake, body.len() as u32);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_CONTENT_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
        out.extend_from_slice(&ext_type.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    /// A TLS 1.3 ClientHello fixture with NO key_share extension, so the server's
    /// inbound decision takes the no-X25519-key_share branch (M-2 shape B). Used to
    /// assert the rejection path's DH count is input-independent.
    pub fn client_hello_fixture_no_key_share(sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x22; 32]); // client_random
        body.push(32);
        body.extend_from_slice(&[0_u8; 32]); // SessionID placeholder
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();
        let host = sni.as_bytes();
        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
        sni_data.push(0);
        sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(host);
        extension(&mut extensions, EXT_SERVER_NAME, &sni_data);
        extension(&mut extensions, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
        // Deliberately NO key_share extension.

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        push_u24(&mut handshake, body.len() as u32);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_CONTENT_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
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
