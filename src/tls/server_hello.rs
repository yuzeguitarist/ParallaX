use std::ops::Range;

use thiserror::Error;

use super::record::{parse_header, TLS_CONTENT_HANDSHAKE, TLS_HEADER_LEN};

const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const TLS13_VERSION: u16 = 0x0304;
const RANDOM_LEN: usize = 32;
// Match the existing bounded middlebox-compatibility budget (also used by rustls).
pub(crate) const MAX_CHANGE_CIPHER_SPEC_RECORDS: usize = 2;
// Handshake header, fixed fields, maximum session ID and u16 extension vector.
const MAX_SERVER_HELLO_MESSAGE: usize = 4 + 2 + 32 + 1 + 32 + 2 + 1 + 2 + u16::MAX as usize;
const MAX_SERVER_HELLO_RECORDS: usize = 256;

/// RFC 8446 §4.1.3 SHA-256("HelloRetryRequest") sentinel placed in
/// `ServerHello.random` to encode a TLS 1.3 `HelloRetryRequest`.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; RANDOM_LEN] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Bytes consumed on the wire, including all fragment record headers.
    pub record_len: usize,
    pub random: [u8; RANDOM_LEN],
    /// Offset in the logical record (one header followed by the reassembled
    /// handshake). For fragmented input this is not a range into raw wire bytes.
    pub session_id_range: Range<usize>,
    pub tls13_selected: bool,
}

impl ServerHello {
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }
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
    #[error("origin sent a second HelloRetryRequest")]
    UnexpectedHelloRetryRequest,
    #[error("client retry flight after HelloRetryRequest is invalid")]
    RetryClientHelloInvalid,
}

pub(crate) fn is_compat_change_cipher_spec(record: &[u8]) -> bool {
    super::record::parse_exact(record).is_ok_and(|(header, payload)| {
        header.content_type == 0x14 && header.total_len == record.len() && payload == [1]
    })
}

pub fn parse_server_hello(record: &[u8]) -> Result<ServerHello, ServerHelloError> {
    let header = parse_header(record)?;
    if record.len() < header.total_len {
        return Err(ServerHelloError::Truncated);
    }
    if header.content_type != TLS_CONTENT_HANDSHAKE {
        return Err(ServerHelloError::NotHandshakeRecord);
    }

    parse_server_hello_payload(&record[TLS_HEADER_LEN..header.total_len], header.total_len)
}

/// Retain record boundaries for the ParallaX transcript while reassembling the
/// handshake bytes used by TLS. Limits apply across the entire ServerHello.
#[derive(Default)]
pub(crate) struct ServerHelloReassembly {
    records: Vec<u8>,
    payload: Vec<u8>,
    record_count: usize,
}

impl ServerHelloReassembly {
    pub(crate) fn started(&self) -> bool {
        self.record_count != 0
    }

    pub(crate) fn push_record(&mut self, record: &[u8]) -> Result<bool, ServerHelloError> {
        let header = parse_header(record)?;
        if record.len() != header.total_len {
            return Err(ServerHelloError::Truncated);
        }
        if header.content_type != TLS_CONTENT_HANDSHAKE {
            return Err(ServerHelloError::NotHandshakeRecord);
        }
        if self.record_count >= MAX_SERVER_HELLO_RECORDS
            || self.payload.len() + header.payload_len > MAX_SERVER_HELLO_MESSAGE
        {
            return Err(ServerHelloError::InvalidLength);
        }
        self.record_count += 1;
        self.records.extend_from_slice(record);
        self.payload.extend_from_slice(&record[TLS_HEADER_LEN..]);
        if self
            .payload
            .first()
            .is_some_and(|kind| *kind != HANDSHAKE_SERVER_HELLO)
        {
            return Err(ServerHelloError::NotServerHello);
        }
        if self.payload.len() >= 4 {
            let message_len = 4
                + ((usize::from(self.payload[1]) << 16)
                    | (usize::from(self.payload[2]) << 8)
                    | usize::from(self.payload[3]));
            if message_len > MAX_SERVER_HELLO_MESSAGE || self.payload.len() > message_len {
                return Err(ServerHelloError::InvalidLength);
            }
            if self.payload.len() == message_len {
                return Ok(true);
            }
        }
        if self.record_count == MAX_SERVER_HELLO_RECORDS {
            return Err(ServerHelloError::InvalidLength);
        }
        Ok(false)
    }

    pub(crate) fn into_records(self) -> Vec<u8> {
        self.records
    }
}

fn reassemble_server_hello(records: &[u8]) -> Result<ServerHelloReassembly, ServerHelloError> {
    let mut reassembly = ServerHelloReassembly::default();
    let mut remaining = records;
    while !remaining.is_empty() {
        let header = parse_header(remaining)?;
        let record = remaining
            .get(..header.total_len)
            .ok_or(ServerHelloError::Truncated)?;
        let complete = reassembly.push_record(record)?;
        remaining = &remaining[header.total_len..];
        if complete {
            return if remaining.is_empty() {
                Ok(reassembly)
            } else {
                Err(ServerHelloError::InvalidLength)
            };
        }
    }
    Err(ServerHelloError::Truncated)
}

pub(crate) fn server_hello_payload(records: &[u8]) -> Result<Vec<u8>, ServerHelloError> {
    Ok(reassemble_server_hello(records)?.payload)
}

pub(crate) fn parse_server_hello_records(records: &[u8]) -> Result<ServerHello, ServerHelloError> {
    let reassembly = reassemble_server_hello(records)?;
    parse_server_hello_payload(&reassembly.payload, records.len())
}

fn parse_server_hello_payload(
    payload: &[u8],
    record_len: usize,
) -> Result<ServerHello, ServerHelloError> {
    let mut cursor = Cursor::new(payload, 0, payload.len());
    if cursor.u8()? != HANDSHAKE_SERVER_HELLO {
        return Err(ServerHelloError::NotServerHello);
    }

    let body_len = cursor.u24()? as usize;
    let body_start = cursor.pos;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or(ServerHelloError::InvalidLength)?;
    if body_end > payload.len() {
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
    let session_id_range =
        TLS_HEADER_LEN + session_start..TLS_HEADER_LEN + session_start + session_len;
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
        record_len,
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

    pub fn fragment_handshake_record(record: &[u8], cuts: &[usize]) -> Vec<u8> {
        let payload = &record[TLS_HEADER_LEN..];
        let mut wire = Vec::new();
        let mut start = 0;
        for end in cuts.iter().copied().chain(std::iter::once(payload.len())) {
            assert!(start <= end && end <= payload.len());
            wire.extend_from_slice(&record[..3]);
            wire.extend_from_slice(&((end - start) as u16).to_be_bytes());
            wire.extend_from_slice(&payload[start..end]);
            start = end;
        }
        wire
    }

    #[test]
    fn parses_server_hello_fixture() {
        let record = server_hello_fixture();
        let parsed = parse_server_hello(&record).unwrap();

        assert_eq!(parsed.random, [0x44; 32]);
        assert_eq!(parsed.session_id_range.len(), 32);
        assert!(parsed.tls13_selected);
    }

    #[test]
    fn reassembles_server_hello_at_every_record_split() {
        let record = server_hello_fixture();
        let expected = parse_server_hello(&record).unwrap();
        assert_eq!(parse_server_hello_records(&record).unwrap(), expected);
        for split in 1..record.len() - TLS_HEADER_LEN {
            let wire = fragment_handshake_record(&record, &[split]);
            let parsed = parse_server_hello_records(&wire).unwrap();
            assert_eq!(parsed.record_len, wire.len());
            assert_eq!(parsed.random, expected.random);
            assert_eq!(parsed.session_id_range, expected.session_id_range);
            assert!(parsed.tls13_selected);
            assert_eq!(
                server_hello_payload(&wire).unwrap(),
                &record[TLS_HEADER_LEN..]
            );
        }
    }

    #[test]
    fn reassembles_maximum_server_hello_extension_vector() {
        let record = server_hello_fixture();
        // Replace the fixture's u16 extensions length + six-byte version
        // extension with a full u16 vector containing version and unknown data.
        let mut message = record[TLS_HEADER_LEN..record.len() - 8].to_vec();
        message.extend_from_slice(&u16::MAX.to_be_bytes());
        message.extend_from_slice(&[0, 43, 0, 2, 3, 4]);
        message.extend_from_slice(&[0xbe, 0xef]);
        message.extend_from_slice(&(u16::MAX - 10).to_be_bytes());
        message.extend(std::iter::repeat(0).take(usize::from(u16::MAX - 10)));
        assert_eq!(message.len(), MAX_SERVER_HELLO_MESSAGE);
        let body_len = message.len() - 4;
        message[1..4].copy_from_slice(&[
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ]);
        let mut logical = record[..TLS_HEADER_LEN].to_vec();
        logical.extend_from_slice(&message);
        let wire = fragment_handshake_record(&logical, &[16_384, 32_768, 49_152, 65_536]);
        assert!(parse_server_hello_records(&wire).unwrap().tls13_selected);
        assert_eq!(server_hello_payload(&wire).unwrap(), message);
    }

    #[test]
    fn server_hello_reassembly_rejects_oversize_truncation_and_interleaving() {
        let record = server_hello_fixture();
        let mut truncated = fragment_handshake_record(&record, &[3]);
        truncated.pop();
        assert_eq!(
            server_hello_payload(&truncated),
            Err(ServerHelloError::Truncated)
        );
        let body_len = MAX_SERVER_HELLO_MESSAGE - 4 + 1;
        let oversized = [
            TLS_CONTENT_HANDSHAKE,
            3,
            3,
            0,
            4,
            HANDSHAKE_SERVER_HELLO,
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ];
        assert_eq!(
            server_hello_payload(&oversized),
            Err(ServerHelloError::InvalidLength)
        );
        let fragmented = fragment_handshake_record(&record, &[3]);
        for content_type in [0x14, 0x15, 0x17] {
            let mut interleaved = fragmented[..TLS_HEADER_LEN + 3].to_vec();
            interleaved.extend_from_slice(&[content_type, 3, 3, 0, 1, 1]);
            interleaved.extend_from_slice(&fragmented[TLS_HEADER_LEN + 3..]);
            assert_eq!(
                server_hello_payload(&interleaved),
                Err(ServerHelloError::NotHandshakeRecord)
            );
        }
        let mut trailing = record.clone();
        trailing.push(0);
        trailing[3..5].copy_from_slice(&((record.len() + 1 - TLS_HEADER_LEN) as u16).to_be_bytes());
        assert_eq!(
            server_hello_payload(&trailing),
            Err(ServerHelloError::InvalidLength)
        );
    }

    #[test]
    fn server_hello_reassembly_bounds_empty_records_without_another_read() {
        let empty = [TLS_CONTENT_HANDSHAKE, 3, 3, 0, 0];
        let mut wire = empty.repeat(MAX_SERVER_HELLO_RECORDS - 1);
        wire.extend_from_slice(&server_hello_fixture());
        assert!(
            parse_server_hello_records(&wire).is_ok(),
            "completion at the record limit is legal"
        );
        let wire = empty.repeat(MAX_SERVER_HELLO_RECORDS);
        assert_eq!(
            server_hello_payload(&wire),
            Err(ServerHelloError::InvalidLength)
        );
    }

    #[test]
    fn rejects_record_truncated_below_declared_length() {
        // Declared record length exceeds the bytes actually present -> Truncated,
        // before any body field is interpreted.
        let mut record = server_hello_fixture();
        record.pop();
        assert_eq!(
            parse_server_hello(&record),
            Err(ServerHelloError::Truncated)
        );
    }

    #[test]
    fn rejects_non_handshake_content_type() {
        let mut record = server_hello_fixture();
        record[0] ^= 0xff; // corrupt the content type away from handshake
        assert_eq!(
            parse_server_hello(&record),
            Err(ServerHelloError::NotHandshakeRecord)
        );
    }

    #[test]
    fn rejects_handshake_that_is_not_a_server_hello() {
        let mut record = server_hello_fixture();
        record[TLS_HEADER_LEN] = HANDSHAKE_SERVER_HELLO ^ 0x01; // e.g. a different handshake type
        assert_eq!(
            parse_server_hello(&record),
            Err(ServerHelloError::NotServerHello)
        );
    }

    #[test]
    fn rejects_handshake_body_longer_than_record() {
        // Inflate the 24-bit handshake body length past the record's own length so
        // `body_end > header.total_len`.
        let mut record = server_hello_fixture();
        let body_len_hi = TLS_HEADER_LEN + 1; // first of the u24 body-length bytes
        record[body_len_hi] = 0xff;
        assert_eq!(
            parse_server_hello(&record),
            Err(ServerHelloError::InvalidLength)
        );
    }

    #[test]
    fn rejects_supported_versions_extension_of_wrong_length() {
        // A supported_versions body must be exactly 2 bytes; a 3-byte body is
        // rejected as InvalidLength (guards `parse_supported_versions`).
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x44; 32]); // random
        body.push(0); // empty session id
        body.extend_from_slice(&[0x13, 0x01]); // cipher_suite
        body.push(0); // compression_method

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        extensions.extend_from_slice(&3_u16.to_be_bytes()); // WRONG: 3-byte value
        extensions.extend_from_slice(&[0x03, 0x04, 0x00]);
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

        assert_eq!(
            parse_server_hello(&record),
            Err(ServerHelloError::InvalidLength)
        );
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
