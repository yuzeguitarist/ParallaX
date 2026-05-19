use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const TLS_HEADER_LEN: usize = 5;
pub const TLS_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
pub const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
pub const TLS_CONTENT_APPLICATION_DATA: u8 = 0x17;
pub const TLS_CONTENT_ALERT: u8 = 0x15;
pub const MAX_TLS_RECORD_PAYLOAD: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsRecordHeader {
    pub content_type: u8,
    pub legacy_version: [u8; 2],
    pub payload_len: usize,
    pub total_len: usize,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TlsRecordError {
    #[error("TLS record header is incomplete")]
    IncompleteHeader,
    #[error("TLS record payload is incomplete")]
    IncompletePayload,
    #[error("TLS record payload exceeds limit: {0}")]
    PayloadTooLarge(usize),
}

pub fn parse_header(buf: &[u8]) -> Result<TlsRecordHeader, TlsRecordError> {
    if buf.len() < TLS_HEADER_LEN {
        return Err(TlsRecordError::IncompleteHeader);
    }

    let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if payload_len > MAX_TLS_RECORD_PAYLOAD + 256 {
        return Err(TlsRecordError::PayloadTooLarge(payload_len));
    }

    Ok(TlsRecordHeader {
        content_type: buf[0],
        legacy_version: [buf[1], buf[2]],
        payload_len,
        total_len: TLS_HEADER_LEN + payload_len,
    })
}

pub fn parse_exact(buf: &[u8]) -> Result<(TlsRecordHeader, &[u8]), TlsRecordError> {
    let header = parse_header(buf)?;
    if buf.len() < header.total_len {
        return Err(TlsRecordError::IncompletePayload);
    }
    Ok((header, &buf[TLS_HEADER_LEN..header.total_len]))
}

pub fn wrap_application_data(payload: &[u8]) -> Result<Vec<u8>, TlsRecordError> {
    if payload.len() > MAX_TLS_RECORD_PAYLOAD {
        return Err(TlsRecordError::PayloadTooLarge(payload.len()));
    }

    let mut out = Vec::with_capacity(TLS_HEADER_LEN + payload.len());
    out.push(TLS_CONTENT_APPLICATION_DATA);
    out.extend_from_slice(&TLS_LEGACY_VERSION);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn alert_bad_record_mac() -> Vec<u8> {
    vec![TLS_CONTENT_ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 0x14]
}

pub fn change_cipher_spec() -> Vec<u8> {
    vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
}

pub async fn read_record<R>(reader: &mut R) -> Result<Vec<u8>, std::io::Error>
where
    R: AsyncRead + Unpin,
{
    TlsRecordReader::new(reader).read_record().await
}

pub struct TlsRecordReader<R> {
    reader: R,
    header: [u8; TLS_HEADER_LEN],
    header_pos: usize,
    record: Vec<u8>,
    payload_len: Option<usize>,
    payload_pos: usize,
}

impl<R> TlsRecordReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            header: [0_u8; TLS_HEADER_LEN],
            header_pos: 0,
            record: Vec::new(),
            payload_len: None,
            payload_pos: 0,
        }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R> TlsRecordReader<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn read_record(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let mut record = Vec::new();
        self.read_record_into(&mut record).await?;
        Ok(record)
    }

    pub async fn read_record_into(&mut self, out: &mut Vec<u8>) -> Result<(), std::io::Error> {
        while self.header_pos < TLS_HEADER_LEN {
            let n = self
                .reader
                .read(&mut self.header[self.header_pos..])
                .await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "TLS record header ended early",
                ));
            }
            self.header_pos += n;
        }

        if self.payload_len.is_none() {
            let parsed = parse_header(&self.header).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid TLS record header: {err}"),
                )
            })?;
            self.record.clear();
            self.record.extend_from_slice(&self.header);
            self.record
                .reserve(parsed.total_len.saturating_sub(self.record.len()));
            self.payload_len = Some(parsed.payload_len);
            self.payload_pos = 0;
        }

        let payload_len = self.payload_len.expect("payload length is initialized");
        while self.payload_pos < payload_len {
            let remaining = payload_len - self.payload_pos;
            let n = (&mut self.reader)
                .take(remaining as u64)
                .read_buf(&mut self.record)
                .await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "TLS record payload ended early",
                ));
            }
            self.payload_pos += n;
        }

        self.header = [0_u8; TLS_HEADER_LEN];
        self.header_pos = 0;
        self.payload_len = None;
        self.payload_pos = 0;
        out.clear();
        std::mem::swap(out, &mut self.record);
        Ok(())
    }
}

pub fn log_record_read(cid: u64, direction: &'static str, task_name: &'static str, record: &[u8]) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    if let Ok(header) = parse_header(record) {
        tracing::debug!(
            cid,
            direction,
            task_name,
            tls_content_type = header.content_type,
            outer_tls_payload_len = header.payload_len,
            "outer TLS record read"
        );
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[test]
    fn wraps_application_data() {
        let record = wrap_application_data(b"abc").unwrap();
        assert_eq!(&record[..5], &[0x17, 0x03, 0x03, 0x00, 0x03]);
        assert_eq!(&record[5..], b"abc");
    }

    #[test]
    fn parses_header() {
        let record = wrap_application_data(b"abc").unwrap();
        let header = parse_header(&record).unwrap();
        assert_eq!(header.payload_len, 3);
        assert_eq!(header.total_len, 8);
    }

    #[test]
    fn emits_tls13_compat_change_cipher_spec() {
        assert_eq!(change_cipher_spec(), [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }

    #[tokio::test]
    async fn record_reader_can_reuse_caller_buffer() {
        let first = wrap_application_data(b"abc").unwrap();
        let second = wrap_application_data(b"defgh").unwrap();
        let (mut writer, reader) = tokio::io::duplex(64);
        tokio::spawn(async move {
            writer.write_all(&first).await.unwrap();
            writer.write_all(&second).await.unwrap();
        });
        let mut reader = TlsRecordReader::new(reader);
        let mut out = Vec::with_capacity(64);

        reader.read_record_into(&mut out).await.unwrap();
        assert_eq!(&out[TLS_HEADER_LEN..], b"abc");
        out.clear();
        out.extend_from_slice(b"stale");

        reader.read_record_into(&mut out).await.unwrap();
        assert_eq!(&out[TLS_HEADER_LEN..], b"defgh");
    }
}
