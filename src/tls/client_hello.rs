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

    // --- Negative-path coverage for the inbound-boundary sub-parsers. ---
    //
    // `parse_client_hello` is reached from the server's inbound decision on the
    // attacker's first TLS record (`handshake/server.rs`), so every error branch
    // below is a security boundary. The happy-path fixtures above proved parsing
    // works; these pin the fail-closed behaviour so a future refactor cannot
    // silently turn a reject into an accept (or a panic).

    /// Assemble a ClientHello record around a caller-supplied extensions block,
    /// reusing the same body/handshake/record framing as the happy-path fixtures so
    /// a test can splice a crafted extension without re-deriving the offsets.
    fn record_with_extensions(exts: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x22; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0_u8; 32]); // 32-byte SessionID
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(1);
        body.push(0); // compression: null
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(exts);

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

    #[test]
    fn rejects_truncated_record() {
        // A record whose declared length exceeds the bytes actually present must be
        // Truncated, not read past the buffer.
        let full = client_hello_fixture("example.com");
        let cut = &full[..full.len() - 4];
        assert_eq!(
            parse_client_hello(cut),
            Err(ClientHelloError::Truncated),
            "a record shorter than its declared length must reject as Truncated"
        );
    }

    #[test]
    fn rejects_non_client_hello_handshake() {
        // Same framing, but the handshake type byte is ServerHello (0x02), not
        // ClientHello (0x01).
        let mut record = client_hello_fixture("example.com");
        record[TLS_HEADER_LEN] = 0x02;
        assert_eq!(
            parse_client_hello(&record),
            Err(ClientHelloError::NotClientHello)
        );
    }

    #[test]
    fn rejects_odd_length_supported_versions() {
        // supported_versions carries a 1-byte list length that MUST be even (each
        // version is 2 bytes). An odd length is InvalidLength (RFC 8446 §4.2.1).
        let mut exts = Vec::new();
        // list length = 3 (odd), followed by one full version + one stray byte.
        extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[3, 0x03, 0x04, 0x00]);
        let record = record_with_extensions(&exts);
        assert_eq!(
            parse_client_hello(&record),
            Err(ClientHelloError::InvalidLength)
        );
    }

    #[test]
    fn rejects_supported_versions_length_past_extension() {
        // The list length claims more bytes than the extension body holds.
        let mut exts = Vec::new();
        extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[8, 0x03, 0x04]);
        let record = record_with_extensions(&exts);
        assert_eq!(
            parse_client_hello(&record),
            Err(ClientHelloError::InvalidLength)
        );
    }

    #[test]
    fn rejects_non_utf8_sni() {
        // A host_name of type 0 whose bytes are not valid UTF-8 is InvalidSni.
        let host = [0xff, 0xfe, 0xfd];
        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
        sni_data.push(0); // name_type = host_name
        sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(&host);
        let mut exts = Vec::new();
        extension(&mut exts, EXT_SERVER_NAME, &sni_data);
        let record = record_with_extensions(&exts);
        assert_eq!(
            parse_client_hello(&record),
            Err(ClientHelloError::InvalidSni)
        );
    }

    #[test]
    fn rejects_sni_list_length_past_extension() {
        // The server_name_list length overruns the extension body.
        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&64_u16.to_be_bytes()); // claims 64 bytes
        sni_data.push(0);
        sni_data.extend_from_slice(&3_u16.to_be_bytes());
        sni_data.extend_from_slice(b"abc");
        let mut exts = Vec::new();
        extension(&mut exts, EXT_SERVER_NAME, &sni_data);
        let record = record_with_extensions(&exts);
        assert_eq!(
            parse_client_hello(&record),
            Err(ClientHelloError::InvalidLength)
        );
    }

    #[test]
    fn key_share_with_wrong_length_x25519_yields_no_share() {
        // A key_share entry tagged x25519 but only 31 bytes long must be skipped
        // (the `key.len() == 32` filter), leaving x25519_key_share == None rather
        // than copying an under-length key.
        let mut share = Vec::new();
        share.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
        share.extend_from_slice(&31_u16.to_be_bytes());
        share.extend_from_slice(&[0xaa; 31]);
        let mut key_share_data = Vec::new();
        key_share_data.extend_from_slice(&(share.len() as u16).to_be_bytes());
        key_share_data.extend_from_slice(&share);
        let mut exts = Vec::new();
        // supported_versions first so tls13 is still detected, then the bad share.
        extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
        extension(&mut exts, EXT_KEY_SHARE, &key_share_data);
        let record = record_with_extensions(&exts);
        let parsed = parse_client_hello(&record).unwrap();
        assert!(parsed.tls13_supported);
        assert_eq!(
            parsed.x25519_key_share, None,
            "a 31-byte x25519 share must be skipped, not accepted"
        );
    }

    #[test]
    fn rejects_extensions_length_past_body() {
        // The 2-byte extensions-length overruns the ClientHello body. Build a valid
        // record then bump the extensions-length field past the body end so
        // `ext_end > body_end`.
        let mut exts = Vec::new();
        extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
        let mut record = record_with_extensions(&exts);
        // The extensions-length is the 2 bytes immediately preceding the extensions
        // payload (which is the tail of the record).
        let ext_len_pos = record.len() - exts.len() - 2;
        record[ext_len_pos..ext_len_pos + 2].copy_from_slice(&0xffff_u16.to_be_bytes());
        assert_eq!(
            parse_client_hello(&record),
            Err(ClientHelloError::InvalidLength)
        );
    }

    #[test]
    fn key_share_no_sni_fixture_has_key_share_and_no_sni() {
        // Ground truth for the M-2 recover==None reject shape: key_share present,
        // session_id is 32 bytes, but SNI absent -> recover must take the missing-
        // SNI early-None gate.
        let record = client_hello_fixture_with_key_share_no_sni(&[0x66; 32]);
        let parsed = parse_client_hello(&record).unwrap();
        assert_eq!(parsed.sni, None, "fixture must omit SNI");
        assert_eq!(parsed.session_id_range.len(), 32);
        assert!(
            parsed.x25519_key_share.is_some(),
            "fixture must carry an x25519 key_share"
        );
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
        build_client_hello_fixture(client_random, Some(sni), Some(key_share_bytes))
    }

    /// Shared assembler for the ClientHello fixtures: a TLS 1.3 ClientHello with
    /// `client_random` as the random carrier, a 32-byte zero SessionID, the single
    /// TLS_AES_128_GCM_SHA256 suite, and extensions in wire order: SNI (when
    /// `sni` is Some), supported_versions, key_share (when `key_share` is Some).
    /// The two `Option`s let the same builder emit every shape the M-2 reject-path
    /// tests need (with/without SNI, with/without key_share) without duplicating
    /// the body/extension/record-framing logic across fixtures.
    fn build_client_hello_fixture(
        client_random: &[u8; 32],
        sni: Option<&str>,
        key_share: Option<&[u8; 32]>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(client_random);
        body.push(32);
        body.extend_from_slice(&[0_u8; 32]); // 32-byte SessionID placeholder
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();
        if let Some(host) = sni.map(str::as_bytes) {
            let mut sni_data = Vec::new();
            sni_data.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
            sni_data.push(0);
            sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
            sni_data.extend_from_slice(host);
            extension(&mut extensions, EXT_SERVER_NAME, &sni_data);
        }
        extension(&mut extensions, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
        if let Some(key_share_bytes) = key_share {
            let mut key_share_data = Vec::new();
            let mut share = Vec::new();
            share.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
            share.extend_from_slice(&32_u16.to_be_bytes());
            share.extend_from_slice(key_share_bytes);
            key_share_data.extend_from_slice(&(share.len() as u16).to_be_bytes());
            key_share_data.extend_from_slice(&share);
            extension(&mut extensions, EXT_KEY_SHARE, &key_share_data);
        }

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
        build_client_hello_fixture(&[0x22; 32], Some(sni), None)
    }

    /// A TLS 1.3 ClientHello fixture WITH an x25519 key_share but NO SNI
    /// extension. The 32-byte session_id placeholder is present, so the only
    /// early-None gate in `recover_stateful_auth_material_from_parsed` that fires
    /// is the missing-SNI one (`parsed.sni == None`). This drives the server's
    /// inbound decision down the "key_share present + recover==None" reject shape
    /// (M-2 shape: ballast DH on the v4 auth slot), which a key_share-present
    /// fixture WITH an SNI cannot reach (that one recovers `Some`).
    pub fn client_hello_fixture_with_key_share_no_sni(key_share_bytes: &[u8; 32]) -> Vec<u8> {
        build_client_hello_fixture(key_share_bytes, None, Some(key_share_bytes))
    }

    fn push_u24(out: &mut Vec<u8>, value: u32) {
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
    }
}
