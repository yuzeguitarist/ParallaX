use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::mpsc,
    task::JoinHandle,
};

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
    let mut header = [0_u8; TLS_HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let parsed = parse_header(&header).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid TLS record header: {err}"),
        )
    })?;
    let payload_len = parsed.payload_len;

    let mut record = Vec::with_capacity(TLS_HEADER_LEN + payload_len);
    record.extend_from_slice(&header);
    record.resize(TLS_HEADER_LEN + payload_len, 0);
    reader.read_exact(&mut record[TLS_HEADER_LEN..]).await?;
    Ok(record)
}

pub type RecordReadResult = Result<Vec<u8>, std::io::Error>;

pub struct RecordReader {
    records: mpsc::Receiver<RecordReadResult>,
    task: JoinHandle<()>,
}

impl RecordReader {
    pub async fn recv(&mut self) -> Option<RecordReadResult> {
        self.records.recv().await
    }
}

impl Drop for RecordReader {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn spawn_record_reader<R>(
    mut reader: R,
    cid: u64,
    direction: &'static str,
    task_name: &'static str,
) -> RecordReader
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (tx, records) = mpsc::channel(32);
    let task = tokio::spawn(async move {
        loop {
            let result = read_record(&mut reader).await;
            match result {
                Ok(record) => {
                    if let Ok(header) = parse_header(&record) {
                        tracing::debug!(
                            cid,
                            direction,
                            task_name,
                            tls_content_type = header.content_type,
                            outer_tls_payload_len = header.payload_len,
                            "outer TLS record read"
                        );
                    }
                    if tx.send(Ok(record)).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    let _ = tx.send(Err(err)).await;
                    break;
                }
            }
        }
    });
    RecordReader { records, task }
}

#[cfg(test)]
mod tests {
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
}
