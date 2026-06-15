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

/// Read-side buffer capacity for long-lived data-phase record readers.
pub const BUFFERED_READ_CAPACITY: usize = 64 * 1024;

/// A [`TlsRecordReader`] that amortizes socket reads through an internal
/// buffer. Only safe for readers that own the read half for the rest of the
/// connection: buffered bytes are lost if the underlying stream is reused
/// for raw reads afterwards.
pub type BufferedTlsRecordReader<R> = TlsRecordReader<tokio::io::BufReader<R>>;

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

    /// Mutable access to the underlying reader, for a caller that must interleave
    /// a raw write on the same stream between record reads while holding this
    /// long-lived reader. Bytes already buffered in the reader are preserved.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

impl<R> BufferedTlsRecordReader<R>
where
    R: AsyncRead + Unpin,
{
    pub fn buffered(reader: R) -> Self {
        Self::new(tokio::io::BufReader::with_capacity(
            BUFFERED_READ_CAPACITY,
            reader,
        ))
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

    /// True iff the reader has consumed zero bytes of a new record (no partial
    /// header or payload buffered). A full record swap resets state to exactly
    /// this with no await in between, so when a `read_record_into` future is
    /// cancelled (e.g. by a timeout) this distinguishes a clean boundary — the
    /// stream cursor is safe to hand off — from a half-read record that would
    /// desync any subsequent reader.
    pub fn at_record_boundary(&self) -> bool {
        self.header_pos == 0 && self.payload_len.is_none()
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

    /// Attempts to read the next complete record using only data that is
    /// already available (buffered or immediately readable), without waiting.
    /// Returns `None` when the read would block before a full record is
    /// buffered; any partially consumed header/payload bytes remain in the
    /// reader's state, so a subsequent [`Self::read_record_into`] (or another
    /// call to this method) resumes exactly where this one left off.
    pub async fn try_read_record_into(&mut self, out: &mut Vec<u8>) -> Option<std::io::Result<()>> {
        use std::{
            future::{poll_fn, Future},
            pin::pin,
            task::Poll,
        };
        let mut read = pin!(self.read_record_into(out));
        poll_fn(move |cx| {
            Poll::Ready(match read.as_mut().poll(cx) {
                Poll::Ready(result) => Some(result),
                Poll::Pending => None,
            })
        })
        .await
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

    #[test]
    fn parse_header_rejects_short_input() {
        assert!(matches!(
            parse_header(&[]),
            Err(TlsRecordError::IncompleteHeader)
        ));
        assert!(matches!(
            parse_header(&[0x17, 0x03, 0x03, 0x00]),
            Err(TlsRecordError::IncompleteHeader)
        ));
    }

    #[test]
    fn parse_header_rejects_oversized_payload() {
        let mut header = [0_u8; TLS_HEADER_LEN];
        header[0] = TLS_CONTENT_APPLICATION_DATA;
        header[1] = TLS_LEGACY_VERSION[0];
        header[2] = TLS_LEGACY_VERSION[1];
        let oversized = (MAX_TLS_RECORD_PAYLOAD + 257) as u16;
        header[3..5].copy_from_slice(&oversized.to_be_bytes());

        assert!(matches!(
            parse_header(&header),
            Err(TlsRecordError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn parse_exact_requires_complete_payload() {
        let record = wrap_application_data(b"abcdef").unwrap();
        let (_, payload) = parse_exact(&record).unwrap();
        assert_eq!(payload, b"abcdef");

        // truncate the last byte: header reports 6 bytes, only 5 follow.
        let truncated = &record[..record.len() - 1];
        assert!(matches!(
            parse_exact(truncated),
            Err(TlsRecordError::IncompletePayload)
        ));
    }

    #[test]
    fn wrap_application_data_rejects_oversized_payload() {
        let too_large = vec![0_u8; MAX_TLS_RECORD_PAYLOAD + 1];
        assert!(matches!(
            wrap_application_data(&too_large),
            Err(TlsRecordError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn alert_bad_record_mac_emits_fixed_alert() {
        let alert = alert_bad_record_mac();
        assert_eq!(alert.len(), 7);
        assert_eq!(alert[0], TLS_CONTENT_ALERT);
        assert_eq!(&alert[1..3], &TLS_LEGACY_VERSION);
        assert_eq!(&alert[3..5], &(2_u16).to_be_bytes());
        // AlertLevel::fatal(2), AlertDescription::bad_record_mac(20)
        assert_eq!(alert[5], 0x02);
        assert_eq!(alert[6], 0x14);
    }

    #[tokio::test]
    async fn record_reader_into_inner_returns_underlying_reader() {
        let record = wrap_application_data(b"abc").unwrap();
        let (mut writer, reader) = tokio::io::duplex(32);
        tokio::spawn(async move {
            writer.write_all(&record).await.unwrap();
        });
        let mut reader = TlsRecordReader::new(reader);
        let _ = reader.read_record().await.unwrap();
        let _inner = reader.into_inner();
    }

    #[tokio::test]
    async fn record_reader_reports_eof_during_header() {
        let (mut writer, reader) = tokio::io::duplex(16);
        tokio::spawn(async move {
            writer.write_all(&[0x17, 0x03]).await.unwrap();
            drop(writer);
        });
        let mut reader = TlsRecordReader::new(reader);
        let err = reader.read_record().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn record_reader_reports_eof_during_payload() {
        let (mut writer, reader) = tokio::io::duplex(16);
        tokio::spawn(async move {
            // Announce 4 bytes of payload but only deliver 2 before closing.
            writer
                .write_all(&[0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02])
                .await
                .unwrap();
            drop(writer);
        });
        let mut reader = TlsRecordReader::new(reader);
        let err = reader.read_record().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn record_reader_reports_invalid_header_payload_length() {
        let (mut writer, reader) = tokio::io::duplex(16);
        tokio::spawn(async move {
            let mut header = [0_u8; TLS_HEADER_LEN];
            header[0] = TLS_CONTENT_APPLICATION_DATA;
            header[1] = TLS_LEGACY_VERSION[0];
            header[2] = TLS_LEGACY_VERSION[1];
            let oversized = (MAX_TLS_RECORD_PAYLOAD + 1024) as u16;
            header[3..5].copy_from_slice(&oversized.to_be_bytes());
            writer.write_all(&header).await.unwrap();
        });
        let mut reader = TlsRecordReader::new(reader);
        let err = reader.read_record().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
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

    #[tokio::test]
    async fn record_reader_handles_fragmented_payload_reads() {
        let record = wrap_application_data(b"fragmented payload").unwrap();
        let split = TLS_HEADER_LEN + 4;
        let (mut writer, reader) = tokio::io::duplex(64);
        tokio::spawn(async move {
            writer.write_all(&record[..split]).await.unwrap();
            writer.write_all(&record[split..]).await.unwrap();
        });
        let mut reader = TlsRecordReader::new(reader);
        let mut out = Vec::new();

        reader.read_record_into(&mut out).await.unwrap();

        assert_eq!(&out[TLS_HEADER_LEN..], b"fragmented payload");
    }

    #[tokio::test]
    async fn buffered_record_reader_matches_unbuffered_across_fragmented_stream() {
        let payloads: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            vec![0x42; 700],
            Vec::new(),
            vec![0x07; MAX_TLS_RECORD_PAYLOAD],
            b"tail".to_vec(),
        ];
        let mut stream = Vec::new();
        for payload in &payloads {
            stream.extend_from_slice(&wrap_application_data(payload).unwrap());
        }

        for chunk_len in [1_usize, 3, 5, 64, 1024, stream.len()] {
            let stream = stream.clone();
            let (mut writer, reader) = tokio::io::duplex(256);
            tokio::spawn(async move {
                for chunk in stream.chunks(chunk_len) {
                    writer.write_all(chunk).await.unwrap();
                }
            });
            let mut reader = TlsRecordReader::buffered(reader);
            let mut out = Vec::new();
            for payload in &payloads {
                reader.read_record_into(&mut out).await.unwrap();
                assert_eq!(&out[TLS_HEADER_LEN..], payload.as_slice());
            }
        }
    }

    #[tokio::test]
    async fn try_read_record_preserves_partial_state_across_would_block() {
        let record = wrap_application_data(b"hello world").unwrap();
        let second = wrap_application_data(b"second").unwrap();
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut reader = TlsRecordReader::buffered(reader);
        let mut out = Vec::new();

        // Nothing available: must report would-block, not error or hang.
        assert!(reader.try_read_record_into(&mut out).await.is_none());

        // A partial record (header + part of the payload) is consumed into the
        // reader's state but no record is produced.
        writer
            .write_all(&record[..TLS_HEADER_LEN + 4])
            .await
            .unwrap();
        assert!(reader.try_read_record_into(&mut out).await.is_none());
        assert!(out.is_empty());

        // The blocking read resumes from the partial state and the record
        // comes out intact.
        writer
            .write_all(&record[TLS_HEADER_LEN + 4..])
            .await
            .unwrap();
        writer.write_all(&second).await.unwrap();
        reader.read_record_into(&mut out).await.unwrap();
        assert_eq!(out, record);

        // A complete buffered record is returned without waiting.
        match reader.try_read_record_into(&mut out).await {
            Some(Ok(())) => assert_eq!(out, second),
            other => panic!("expected buffered record, got {other:?}"),
        }

        // EOF surfaces through the non-blocking path as an error, not a hang.
        drop(writer);
        match reader.try_read_record_into(&mut out).await {
            Some(Err(err)) => assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof),
            other => panic!("expected EOF error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn buffered_record_reader_reports_eof_after_last_record() {
        let record = wrap_application_data(b"only").unwrap();
        let (mut writer, reader) = tokio::io::duplex(64);
        tokio::spawn(async move {
            writer.write_all(&record).await.unwrap();
            drop(writer);
        });
        let mut reader = TlsRecordReader::buffered(reader);
        let mut out = Vec::new();

        reader.read_record_into(&mut out).await.unwrap();
        assert_eq!(&out[TLS_HEADER_LEN..], b"only");

        let err = reader.read_record_into(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn timeout_mid_record_preserves_buffered_bytes_on_reused_reader() {
        use std::time::Duration;
        // Regression for the cancel-safety bug: a timeout firing mid-record must
        // NOT discard the bytes already pulled off the socket when the SAME reader
        // is reused (the old throwaway-reader-per-call path lost them, desyncing
        // the reused data-phase stream).
        let first = wrap_application_data(b"hello world").unwrap();
        let second = wrap_application_data(b"second").unwrap();
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut record_reader = TlsRecordReader::new(reader);
        let mut out = Vec::new();

        // Deliver only the header + a few payload bytes, then let a read consume
        // them and block for the rest until the timeout fires.
        writer.write_all(&first[..8]).await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            record_reader.read_record_into(&mut out),
        )
        .await
        .is_err());
        assert!(
            !record_reader.at_record_boundary(),
            "a timeout that consumed a partial record must report mid-record",
        );

        // Deliver the rest of the first record plus a full second record. The SAME
        // reader resumes from its buffered state and yields the first record
        // byte-for-byte — proving the pre-timeout bytes were preserved.
        writer.write_all(&first[8..]).await.unwrap();
        writer.write_all(&second).await.unwrap();
        record_reader.read_record_into(&mut out).await.unwrap();
        assert_eq!(
            out, first,
            "buffered bytes from before the timeout were lost"
        );
        assert!(record_reader.at_record_boundary());

        // The stream is not desynced: the second record reads back intact.
        record_reader.read_record_into(&mut out).await.unwrap();
        assert_eq!(out, second);
    }

    #[tokio::test]
    async fn timeout_at_boundary_reports_clean_boundary() {
        use std::time::Duration;
        // A fresh reader with nothing on the wire: a timeout leaves it exactly at
        // a record boundary (the benign "no/slow record arrived" drain case), so
        // the caller can safely stop without desyncing the stream.
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut record_reader = TlsRecordReader::new(reader);
        let mut out = Vec::new();
        assert!(record_reader.at_record_boundary());
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            record_reader.read_record_into(&mut out),
        )
        .await
        .is_err());
        assert!(record_reader.at_record_boundary());

        // And it still reads a subsequent record cleanly.
        let rec = wrap_application_data(b"abc").unwrap();
        writer.write_all(&rec).await.unwrap();
        record_reader.read_record_into(&mut out).await.unwrap();
        assert_eq!(out, rec);
    }
}
