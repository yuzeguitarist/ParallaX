//! Transport-agnostic record legs. A `Leg` carries TLS-record-framed AEAD
//! records; the relay/mux loops read and write records through these traits and
//! never see whether the underlying transport is TCP or (later) a UDP/QUIC leg.

use std::{future::Future, io};

use tokio::{io::AsyncWriteExt, net::tcp::OwnedWriteHalf};

use crate::tls::record::{BufferedTlsRecordReader, TlsRecordReader};

/// A source of in-order AEAD records. Each read yields exactly one record.
pub(crate) trait LegReader: Send {
    /// Reads exactly one record, REPLACING the contents of `buf`: the
    /// implementation clears `buf` and then fills it with the record's bytes, so
    /// callers may reuse the same buffer across reads without clearing it
    /// themselves (the mux batch-drain loops rely on this — they reuse one
    /// scratch buffer per read). Semantics MUST match
    /// `BufferedTlsRecordReader::read_record_into` (clear + swap). A future
    /// non-TCP `LegReader` MUST also replace, not append, or the batch-drain
    /// loops would accumulate stale bytes and desync the record stream.
    fn read_record_into(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Reads the next complete record using only data that is already available
    /// (buffered or immediately readable), without waiting. On success it
    /// REPLACES `buf` exactly like [`Self::read_record_into`]. Returns `None`
    /// when a full record is not yet available; any partial reader state is
    /// preserved so a subsequent read resumes exactly where this left off.
    /// Semantics MUST match `BufferedTlsRecordReader::try_read_record_into`.
    ///
    /// The mux reader loops use this to opportunistically drain an
    /// already-arrived burst so the batch can be opened across the crypto pool.
    fn try_read_record_into(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> impl Future<Output = Option<io::Result<()>>> + Send;

    /// Whether a read error marks a clean end-of-leg under THIS transport's
    /// teardown convention. TCP (the default): a peer FIN (`UnexpectedEof`), a
    /// RST (`ConnectionReset`, the proxy's own graceful-close convention — see
    /// `transport::tcp`), or a `BrokenPipe` are all treated as a clean close.
    /// The QUIC leg OVERRIDES this: on a `quinn::RecvStream` a clean stream
    /// finish surfaces as `UnexpectedEof`, whereas `ConnectionReset` means the
    /// peer sent `RESET_STREAM` — a mid-transfer TRUNCATION of the relay that
    /// MUST surface as an error, never be swallowed as a clean half-close.
    fn is_clean_close(&self, err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
        )
    }
}

/// A sink for sealed record bytes (one or more concatenated TLS records in one
/// call). The TCP leg writes them to the byte stream; a future UDP leg frames
/// them into datagrams.
pub(crate) trait LegWriter: Send {
    fn write_records(&mut self, bytes: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    /// Writes `bytes` (one or more concatenated sealed records) whose FIRST record
    /// has sequence `base_seq`; the records that follow are `base_seq + 1, + 2, …`
    /// in order. The default IGNORES `base_seq` and forwards to
    /// [`Self::write_records`]: a byte-stream carrier (TCP, QUIC reliable stream) is
    /// implicitly ordered, so it needs no per-record sequence. The datagram carrier
    /// OVERRIDES this to envelope each record with its seq for reorder + FEC, where
    /// order is not implicit. Relay write sites call this (not `write_records`) so
    /// the datagram carrier can be dropped in without touching them.
    fn write_records_seq(
        &mut self,
        _base_seq: u64,
        bytes: &[u8],
    ) -> impl Future<Output = io::Result<()>> + Send {
        self.write_records(bytes)
    }

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

/// QUIC-stream record-reader leg over a reliable bidi `quinn::RecvStream`.
///
/// A quinn reliable bidi stream carries the record byte-stream exactly like TCP,
/// so reads delegate 1:1 to the inner [`TcpLegReader`] (which is already generic
/// over any `R: AsyncRead + Unpin + Send`, and `quinn::RecvStream` is one in
/// quinn 0.11). It is a NEWTYPE rather than a bare type alias because the QUIC
/// leg must OVERRIDE [`LegReader::is_clean_close`]: quinn maps a peer
/// `RESET_STREAM` to `io::ErrorKind::ConnectionReset`, which on a reliable relay
/// stream is a mid-transfer truncation that must surface as an error — unlike a
/// TCP RST, which is conventionally a clean half-close. `read_record_into` /
/// `try_read_record_into` keep their exact `BufferedTlsRecordReader` semantics.
pub(crate) struct QuicStreamLegReader(TcpLegReader<quinn::RecvStream>);

impl QuicStreamLegReader {
    /// Wraps a `quinn::RecvStream` in a buffered record reader, mirroring
    /// [`TcpLegReader::buffered`].
    pub(crate) fn buffered(reader: quinn::RecvStream) -> Self {
        Self(TcpLegReader::buffered(reader))
    }
}

impl LegReader for QuicStreamLegReader {
    async fn read_record_into(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        self.0.read_record_into(buf).await
    }

    async fn try_read_record_into(&mut self, buf: &mut Vec<u8>) -> Option<io::Result<()>> {
        self.0.try_read_record_into(buf).await
    }

    /// A QUIC clean finish surfaces as `UnexpectedEof`; `ConnectionReset`
    /// (`RESET_STREAM`) is a truncated relay and is therefore NOT a clean close.
    fn is_clean_close(&self, err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
        )
    }
}

/// Test-only counter of record bytes written through [`QuicStreamLegWriter`].
/// Lets the relay e2e tests prove application data actually traversed the QUIC
/// stream (rather than silently falling back to TCP). Not compiled in release.
#[cfg(test)]
pub(crate) static QUIC_LEG_BYTES_WRITTEN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// QUIC-stream record-writer leg: writes sealed record bytes straight to a
/// reliable bidi `quinn::SendStream`. A thin 1:1 wrapper mirroring
/// [`TcpLegWriter`]: `quinn::SendStream` implements `tokio::io::AsyncWrite`, so
/// `AsyncWriteExt::write_all`/`shutdown` already yield `io::Result` (the
/// `AsyncWrite` impl converts quinn's `WriteError` to `io::Error` internally),
/// and `shutdown` issues the stream's QUIC finish via `poll_shutdown`.
pub(crate) struct QuicStreamLegWriter(pub quinn::SendStream);

impl LegWriter for QuicStreamLegWriter {
    async fn write_records(&mut self, bytes: &[u8]) -> io::Result<()> {
        // `quinn::SendStream` has an inherent `write_all(&mut self, &[u8]) ->
        // Result<(), quinn::WriteError>` that shadows `AsyncWriteExt::write_all`,
        // so call the trait method explicitly to get the `io::Result` (the
        // `AsyncWrite` impl converts `WriteError` -> `io::Error` internally),
        // mirroring `TcpLegWriter` exactly.
        AsyncWriteExt::write_all(&mut self.0, bytes).await?;
        #[cfg(test)]
        QUIC_LEG_BYTES_WRITTEN.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        // `poll_shutdown` issues the QUIC stream finish.
        AsyncWriteExt::shutdown(&mut self.0).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        crypto::session::{AeadCodec, KEY_LEN, NONCE_LEN},
        protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD},
        traffic::PaddingProfile,
        transport::udp::test_support::loopback_pair,
    };

    use super::*;

    fn data_codec() -> DataRecordCodec {
        // Matched key+nonce_base on both seal and open sides; zero padding keeps
        // the wire bytes deterministic. CLIENT_TO_SERVER_AAD because we test the
        // opener (client) -> acceptor (server) direction.
        let key = [0x11_u8; KEY_LEN];
        let nonce = [0x22_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD)
    }

    /// Proves the QUIC reliable bidi stream is a drop-in record carrier for the
    /// Leg seam: real sealed `DataRecordCodec` records round-trip byte-exact
    /// through `QuicStreamLegWriter` -> `QuicStreamLegReader`, and the mux
    /// batch-drain contract (`try_read_record_into`) holds over a
    /// `quinn::RecvStream` — it yields complete records in order when buffered
    /// and `None` (not a partial/garbage record) when nothing is yet available.
    #[tokio::test]
    async fn quic_stream_leg_round_trips_sealed_records_and_batch_drains() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        // The reader signals the opener once it has fully drained the stream, so
        // the opener can keep `client_conn` alive until then: dropping the last
        // Connection handle closes the QUIC connection (application close), which
        // would tear the stream down before the reader sees the clean finish.
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        // quinn opens a bidi stream lazily: the acceptor only observes it once
        // the opener writes, so open + first write + accept must run together.
        let opener = tokio::spawn(async move {
            let (send, _recv) = client_conn.open_bi().await.expect("open_bi");
            let mut writer = QuicStreamLegWriter(send);

            let mut seal = data_codec();
            let mut rng = StdRng::seed_from_u64(0x5EA1);

            // Phase 1: several multi-KB records, sealed and concatenated, then
            // written in one call (mirrors how the mux flushes a batch).
            let payloads_phase1: Vec<Vec<u8>> = vec![
                vec![0xA1_u8; 1500],
                vec![0xB2_u8; 4096],
                b"short-control-frame".to_vec(),
                vec![0xC3_u8; 3000],
            ];
            let mut batch = Vec::new();
            for payload in &payloads_phase1 {
                batch.extend_from_slice(&seal.seal(payload, &mut rng).unwrap());
            }
            writer.write_records(&batch).await.unwrap();

            // Hand control back so the reader can fully drain phase 1 and then
            // observe a genuine would-block (empty stream) before phase 2.
            tokio::time::sleep(Duration::from_millis(150)).await;

            // Phase 2: a back-to-back burst written in one go, for the
            // try_read_record_into drain assertion on the reader side.
            let payloads_phase2: Vec<Vec<u8>> = vec![
                b"burst-0".to_vec(),
                vec![0xD4_u8; 200],
                b"burst-2".to_vec(),
                vec![0xE5_u8; 512],
                b"burst-4".to_vec(),
            ];
            let mut burst = Vec::new();
            for payload in &payloads_phase2 {
                burst.extend_from_slice(&seal.seal(payload, &mut rng).unwrap());
            }
            writer.write_records(&burst).await.unwrap();
            // Finish the stream so the reader sees a clean end after the burst.
            writer.shutdown().await.unwrap();

            // Keep `client_conn` (and the stream) alive until the reader is done.
            let _ = done_rx.await;
            (payloads_phase1, payloads_phase2)
        });

        let (server_send, server_recv) = server_conn.accept_bi().await.expect("accept_bi");
        // Keep the acceptor's send half alive for the stream's lifetime.
        let _server_send = server_send;
        let mut reader = QuicStreamLegReader::buffered(server_recv);
        let mut open = data_codec();
        let mut buf = Vec::new();

        // Phase 1: blocking reads recover each record byte-exact (REPLACE
        // semantics: we reuse `buf` without clearing it ourselves).
        let payloads_phase1 = vec![
            vec![0xA1_u8; 1500],
            vec![0xB2_u8; 4096],
            b"short-control-frame".to_vec(),
            vec![0xC3_u8; 3000],
        ];
        for expected in &payloads_phase1 {
            reader.read_record_into(&mut buf).await.unwrap();
            let plaintext = open.open(&buf).unwrap();
            assert_eq!(&plaintext, expected, "phase-1 record must round-trip");
        }

        // Phase 1 is fully drained. With nothing buffered and nothing yet on the
        // wire, try_read_record_into MUST report would-block (None) — not block,
        // not a partial/garbage record.
        assert!(
            reader.try_read_record_into(&mut buf).await.is_none(),
            "try_read_record_into over a quinn RecvStream must return None when no record is ready",
        );

        // Wait for the phase-2 burst to arrive, then opportunistically drain it
        // with the non-blocking path. The mux uses exactly this loop to batch an
        // already-arrived burst across the crypto pool.
        let phase2_expected: Vec<Vec<u8>> = vec![
            b"burst-0".to_vec(),
            vec![0xD4_u8; 200],
            b"burst-2".to_vec(),
            vec![0xE5_u8; 512],
            b"burst-4".to_vec(),
        ];
        let mut drained: Vec<Vec<u8>> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while drained.len() < phase2_expected.len() {
            match reader.try_read_record_into(&mut buf).await {
                Some(result) => {
                    result.expect("try_read_record_into record");
                    drained.push(open.open(&buf).unwrap());
                }
                None => {
                    // Nothing buffered yet (the burst is still in flight): yield
                    // briefly and retry. A correct None must never desync the
                    // reader — the next try resumes cleanly.
                    if tokio::time::Instant::now() >= deadline {
                        panic!("phase-2 burst did not arrive within deadline");
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        }
        assert_eq!(
            drained, phase2_expected,
            "try_read_record_into must yield complete phase-2 records in order",
        );

        // After the burst is drained and the writer has finished the stream, the
        // try-path eventually surfaces the clean EOF (Some(Err(UnexpectedEof)))
        // rather than a partial record or a hang.
        let eof = loop {
            match reader.try_read_record_into(&mut buf).await {
                Some(result) => break result,
                None => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        };
        let err = eof.expect_err("clean stream finish must surface as an error, not a record");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        // Reader is done; release the opener so it may drop `client_conn`.
        let _ = done_tx.send(());
        let (writer_phase1, writer_phase2) = opener.await.expect("opener task");
        assert_eq!(writer_phase1, payloads_phase1);
        assert_eq!(writer_phase2, phase2_expected);
    }

    /// M-9/M-10: a QUIC `RESET_STREAM` (which quinn surfaces as
    /// `io::ErrorKind::ConnectionReset`) is a mid-transfer TRUNCATION and MUST
    /// surface as an error that `LegReader::is_clean_close` rejects — never be
    /// swallowed as a clean EOF. The TCP leg keeps its conventional
    /// RST-as-clean-half-close behavior (probe-resistance), proving the override
    /// is QUIC-scoped; a clean QUIC finish (`UnexpectedEof`) stays clean too.
    #[tokio::test]
    async fn quic_leg_reset_stream_is_truncation_not_clean_close() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        // Gate the reset on the reader having consumed the one good record, so the
        // record is delivered before the abort (deterministic, no data race).
        let (proceed_tx, proceed_rx) = tokio::sync::oneshot::channel::<()>();
        let opener = tokio::spawn(async move {
            let (send, _recv) = client_conn.open_bi().await.expect("open_bi");
            let mut writer = QuicStreamLegWriter(send);
            let mut seal = data_codec();
            let mut rng = StdRng::seed_from_u64(0x4E5E7);
            let good = seal.seal(b"first-and-only-record", &mut rng).unwrap();
            writer.write_records(&good).await.unwrap();
            let _ = proceed_rx.await;
            // Abort mid-transfer with RESET_STREAM instead of a clean finish.
            writer
                .0
                .reset(quinn::VarInt::from_u32(0))
                .expect("reset stream");
            // Keep the connection (not just the stream) alive so the reader
            // observes a stream RESET, not a connection close.
            tokio::time::sleep(Duration::from_millis(200)).await;
            client_conn
        });

        let (server_send, server_recv) = server_conn.accept_bi().await.expect("accept_bi");
        let _server_send = server_send;
        let mut reader = QuicStreamLegReader::buffered(server_recv);
        let mut open = data_codec();
        let mut buf = Vec::new();

        // The one good record arrives intact.
        reader
            .read_record_into(&mut buf)
            .await
            .expect("first record");
        assert_eq!(open.open(&buf).unwrap(), b"first-and-only-record");

        // Now let the opener RESET_STREAM, and observe the truncation.
        let _ = proceed_tx.send(());
        let err = reader
            .read_record_into(&mut buf)
            .await
            .expect_err("RESET_STREAM must surface as an error, not a clean EOF");
        assert_eq!(
            err.kind(),
            io::ErrorKind::ConnectionReset,
            "quinn maps RESET_STREAM to ConnectionReset",
        );
        assert!(
            !reader.is_clean_close(&err),
            "the QUIC leg must NOT treat a RESET_STREAM as a clean close (would silently truncate)",
        );
        // No over-correction: a genuine clean finish stays clean on the QUIC leg.
        assert!(reader.is_clean_close(&io::Error::from(io::ErrorKind::UnexpectedEof)));

        // The TCP leg is unchanged: a RST is still a conventional clean half-close.
        let tcp = TcpLegReader::buffered(tokio::io::duplex(64).0);
        assert!(
            tcp.is_clean_close(&io::Error::from(io::ErrorKind::ConnectionReset)),
            "TCP leg must keep treating ConnectionReset as a clean half-close",
        );

        let _ = opener.await;
    }
}
