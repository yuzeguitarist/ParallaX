//! Transport-agnostic record legs. A `Leg` carries TLS-record-framed AEAD
//! records; the relay/mux loops read and write records through these traits and
//! never see whether the underlying transport is TCP or (later) a UDP/QUIC leg.

use std::{future::Future, io};

use tokio::{io::AsyncWriteExt, net::tcp::OwnedWriteHalf};

use crate::tls::record::{BufferedTlsRecordReader, TlsRecordReader};

/// A source of in-order AEAD records. Semantics MUST match
/// `BufferedTlsRecordReader::read_record_into` (it APPENDS one record's bytes
/// to `buf`; callers clear() between reads as they already do today).
pub(crate) trait LegReader: Send {
    fn read_record_into(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Reads the next complete record using only data that is already available
    /// (buffered or immediately readable), without waiting. Returns `None` when
    /// a full record is not yet available; any partial reader state is
    /// preserved so a subsequent read resumes exactly where this left off.
    /// Semantics MUST match `BufferedTlsRecordReader::try_read_record_into`.
    ///
    /// The mux reader loops use this to opportunistically drain an
    /// already-arrived burst so the batch can be opened across the crypto pool.
    fn try_read_record_into(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> impl Future<Output = Option<io::Result<()>>> + Send;
}

/// A sink for sealed record bytes (one or more concatenated TLS records in one
/// call). The TCP leg writes them to the byte stream; a future UDP leg frames
/// them into datagrams.
pub(crate) trait LegWriter: Send {
    fn write_records(&mut self, bytes: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

/// TCP record-reader leg: delegates 1:1 to the existing buffered TLS record
/// reader over the connection's owned read half.
pub(crate) struct TcpLegReader<R>(pub BufferedTlsRecordReader<R>);

impl<R> LegReader for TcpLegReader<R>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    async fn read_record_into(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        self.0.read_record_into(buf).await
    }

    async fn try_read_record_into(&mut self, buf: &mut Vec<u8>) -> Option<io::Result<()>> {
        self.0.try_read_record_into(buf).await
    }
}

impl<R> TcpLegReader<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    /// Wraps a raw read half in a buffered record reader, mirroring the
    /// `TlsRecordReader::buffered` wrap the loops used to perform internally.
    pub(crate) fn buffered(reader: R) -> Self {
        Self(TlsRecordReader::buffered(reader))
    }
}

/// TCP record-writer leg: writes sealed record bytes straight to the
/// connection's owned write half (`write_all` folds in any flush for TCP).
pub(crate) struct TcpLegWriter(pub OwnedWriteHalf);

impl LegWriter for TcpLegWriter {
    async fn write_records(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.write_all(bytes).await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}
