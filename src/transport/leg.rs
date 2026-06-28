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
    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

/// Flush a sealed record batch while reading the next source burst concurrently
/// (read-ahead pipelining), but surface a write error IMMEDIATELY — cancelling
/// the still-pending read — so a failed peer write is never masked behind a
/// blocked source read. This preserves the serial path's "a write error returns
/// before the next read is consumed" ordering while keeping the read overlapped:
///
/// - Write completes first (Ok): await the read to completion and return its
///   byte count. A `read` is cancellation-safe and we did not poll it to
///   completion, but we do NOT drop it here — we keep awaiting it, so no bytes
///   are lost on the happy path.
/// - Write errors first: return the error WITHOUT awaiting the read. Dropping the
///   pending `read` future is safe (tokio's `AsyncReadExt::read` consumes no bytes
///   unless it returns `Ok(n)`), and the relay is being torn down anyway, so the
///   unread bytes are irrelevant.
/// - Read completes first: stash its result, then await the write; a subsequent
///   write error still short-circuits (returned before the stashed read count).
///
/// `read` is the caller's `source.read(&mut spare_buf)` future; on success this
/// returns the number of bytes it read into that buffer.
pub(crate) async fn write_batch_with_read_ahead<W, Fut>(
    writer: &mut W,
    sealed: &[u8],
    read: Fut,
) -> io::Result<usize>
where
    W: LegWriter,
    Fut: Future<Output = io::Result<usize>>,
{
    let write = writer.write_records(sealed);
    tokio::pin!(write);
    tokio::pin!(read);

    tokio::select! {
        // Bias the write so an already-ready write result (including an error)
        // wins over a simultaneously-ready read, matching the serial ordering.
        biased;
        write_res = &mut write => {
            // Write finished first. Surface an error immediately, cancelling the
            // still-pending read by dropping it as we return.
            write_res?;
            // Write succeeded: now await the read to completion (no bytes lost).
            read.await
        }
        read_res = &mut read => {
            // Read finished first. Still await the write so its error (if any)
            // short-circuits ahead of the read's success, exactly as the serial
            // path surfaces a write error before acting on the next read.
            let n = read_res?;
            write.await?;
            Ok(n)
        }
    }
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

/// Test-only counter of record bytes written through the QUIC relay leg
/// ([`H3DataFrameLegWriter`]). Lets the relay e2e tests prove application data
/// actually traversed the QUIC stream (rather than silently falling back to TCP).
/// Not compiled in release.
#[cfg(test)]
pub(crate) static QUIC_LEG_BYTES_WRITTEN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------------------
// HTTP/3 DATA-frame relay legs.
//
// On the H3 request bidi the relay record byte-stream is carried inside HTTP/3
// DATA frames (RFC 9114 §7.2.1): the writer wraps each `write_records` batch in
// one `DATA = varint(0x00) varint(len) bytes` frame, and the reader strips DATA
// frame headers to recover the original record byte-stream before the TLS-record
// splitter runs on it. Records may span DATA frames and a DATA frame may contain
// partial records — exactly the H3 body model — because the de-framer presents a
// continuous byte stream regardless of frame boundaries. The REPLACE read
// semantics and the RESET-as-truncation close semantics are preserved: the
// de-framer propagates the inner stream's `io::Error` kind unchanged (a peer
// `RESET_STREAM` stays `ConnectionReset`, a clean finish stays `UnexpectedEof`),
// so the leg's clean-close override still distinguishes them.
// ---------------------------------------------------------------------------

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::fingerprint::http3::{read_stream_type, FRAME_TYPE_DATA};

/// Max H3 DATA frame payload the de-framer will accept, mirroring the codec's
/// [`crate::fingerprint::http3::MAX_PAYLOAD_LEN`] bound so a hostile peer cannot
/// announce an unbounded DATA frame.
const MAX_H3_DATA_FRAME_LEN: u64 = 1 << 20;

/// An `AsyncRead` that de-frames HTTP/3 DATA frames from an inner reader, yielding
/// only the concatenated DATA-frame payload bytes. Frame headers (`DATA` type +
/// length varints) are consumed and discarded; a non-DATA frame on this stream is
/// a protocol error (the relay bidi carries only DATA after the probe HEADERS).
pub(crate) struct H3DataFrameReader<R> {
    inner: R,
    /// Bytes left in the current DATA frame's payload; 0 means "read a header next".
    remaining: u64,
    /// Partial frame-header bytes accumulated while parsing `type` + `length`.
    header: Vec<u8>,
}

impl<R> H3DataFrameReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            remaining: 0,
            header: Vec::with_capacity(9),
        }
    }
}

impl<R> AsyncRead for H3DataFrameReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Parse frame headers (one DATA frame at a time) until we are positioned
        // inside a payload, then copy payload bytes into `buf`.
        while this.remaining == 0 {
            // Try to parse `type` + `length` from the bytes accumulated so far.
            if let Some((frame_type, type_len)) = read_stream_type(&this.header) {
                if let Some((len, _len_len)) = read_stream_type(&this.header[type_len..]) {
                    if frame_type != FRAME_TYPE_DATA {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("non-DATA H3 frame on relay bidi (type {frame_type:#x})"),
                        )));
                    }
                    if len > MAX_H3_DATA_FRAME_LEN {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("H3 DATA frame length {len} exceeds bound"),
                        )));
                    }
                    this.header.clear();
                    this.remaining = len;
                    // A zero-length DATA frame carries no payload; loop to read the
                    // next header rather than returning Ok with 0 bytes (which a
                    // reader would misread as EOF).
                    //
                    // A hostile peer streaming endless 2-byte zero-length DATA
                    // frames spins this loop without yielding payload, but it is
                    // bounded: each iteration consumes 2 inner bytes, so progress is
                    // capped by QUIC stream flow control (the peer cannot send
                    // unbounded bytes without our reads granting credit), and a
                    // payload-starved relay is torn down by the relay idle watchdog.
                    // So this is a no-payload-progress, not an unbounded-memory or
                    // unbounded-CPU, condition; left as-is to keep the de-framer
                    // behaviour byte-faithful.
                    if this.remaining == 0 {
                        continue;
                    }
                    break;
                }
            }
            // Need more header bytes: read exactly one more into a 1-byte scratch.
            let mut byte = [0u8; 1];
            let mut one = ReadBuf::new(&mut byte);
            match Pin::new(&mut this.inner).poll_read(cx, &mut one) {
                Poll::Ready(Ok(())) => {
                    if one.filled().is_empty() {
                        // Clean EOF. At a frame boundary (no partial header) this is
                        // a clean finish; mid-header it is a truncated header. Either
                        // way surface EOF as the inner reader would (UnexpectedEof
                        // via read_exact upstack) — return Ok with 0 filled so the
                        // record reader sees EOF.
                        return Poll::Ready(Ok(()));
                    }
                    this.header.push(byte[0]);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Inside a DATA payload: copy up to min(buf capacity, remaining).
        let want = std::cmp::min(buf.remaining() as u64, this.remaining);
        if want == 0 {
            return Poll::Ready(Ok(()));
        }
        // Limit the inner read to `want` so we never read past this frame's payload,
        // following tokio's `io::Take` pattern to propagate the fill to `buf`.
        let mut limited = buf.take(want as usize);
        match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let n = limited.filled().len();
                // SAFETY: the inner reader initialized and filled `n` bytes in
                // `limited`, which aliases `buf`'s spare capacity (tokio Take pattern).
                unsafe {
                    buf.assume_init(n);
                }
                buf.advance(n);
                this.remaining -= n as u64;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// QUIC-stream record-reader leg that de-frames HTTP/3 DATA frames before the
/// TLS-record split. A NEWTYPE over `TcpLegReader<H3DataFrameReader<..>>`: it
/// keeps the exact `BufferedTlsRecordReader` record semantics but the underlying
/// byte source is an [`H3DataFrameReader`] over the bidi `quinn::RecvStream`, and
/// it OVERRIDES [`LegReader::is_clean_close`] for QUIC (RESET = truncation).
pub(crate) struct H3DataFrameLegReader(
    TcpLegReader<H3DataFrameReader<crate::transport::udp::quic::endpoint::RecvStream>>,
);

impl H3DataFrameLegReader {
    /// Wrap a relay-bidi QUIC `RecvStream` in a DATA-frame de-framer + buffered
    /// record reader.
    pub(crate) fn buffered(reader: crate::transport::udp::quic::endpoint::RecvStream) -> Self {
        Self(TcpLegReader::buffered(H3DataFrameReader::new(reader)))
    }
}

impl LegReader for H3DataFrameLegReader {
    async fn read_record_into(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        self.0.read_record_into(buf).await
    }

    async fn try_read_record_into(&mut self, buf: &mut Vec<u8>) -> Option<io::Result<()>> {
        self.0.try_read_record_into(buf).await
    }

    /// QUIC clean-close override: a clean finish is `UnexpectedEof`;
    /// `ConnectionReset` (`RESET_STREAM`) is a truncated relay and is NOT a clean
    /// close. The de-framer propagates the inner error kind, so this classification
    /// is unchanged by the DATA framing.
    fn is_clean_close(&self, err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
        )
    }
}

/// QUIC-stream record-writer leg that frames each record batch as one HTTP/3 DATA
/// frame: it prepends a `DATA` frame header to every `write_records` batch (RFC
/// 9114 §7.2.1) before writing to the reliable bidi QUIC `SendStream`.
/// `shutdown` finishes the stream (no trailing frame).
pub(crate) struct H3DataFrameLegWriter(pub crate::transport::udp::quic::endpoint::SendStream);

impl LegWriter for H3DataFrameLegWriter {
    async fn write_records(&mut self, bytes: &[u8]) -> io::Result<()> {
        // Wrap this batch in a single DATA frame: varint(0x00) varint(len) bytes.
        let framed = crate::fingerprint::http3::encode_frame(FRAME_TYPE_DATA, bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        AsyncWriteExt::write_all(&mut self.0, &framed).await?;
        #[cfg(test)]
        QUIC_LEG_BYTES_WRITTEN.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
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

    /// Proves the H3 DATA-frame relay leg is a drop-in record carrier for the
    /// Leg seam: real sealed `DataRecordCodec` records round-trip byte-exact
    /// through `H3DataFrameLegWriter` -> `H3DataFrameLegReader`, and the mux
    /// batch-drain contract (`try_read_record_into`) holds over a DATA-framed
    /// `quinn::RecvStream` — it yields complete records in order when buffered
    /// and `None` (not a partial/garbage record) when nothing is yet available.
    #[tokio::test]
    async fn h3_leg_round_trips_sealed_records_and_batch_drains() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        // The reader signals the opener once it has fully drained the stream, so
        // the opener can keep `client_conn` alive until then: dropping the last
        // Connection handle closes the QUIC connection (application close), which
        // would tear the stream down before the reader sees the clean finish.
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        // quinn opens a bidi stream lazily: the acceptor only observes it once
        // the opener writes, so open + first write + accept must run together.
        let opener = tokio::spawn(async move {
            let (send, _recv) = client_conn.open_bi();
            let mut writer = H3DataFrameLegWriter(send);

            let mut seal = data_codec();
            let mut rng = StdRng::seed_from_u64(0x5EA1);

            // Phase 1: several multi-KB records, sealed and concatenated, then
            // written in one call (mirrors how the mux flushes a batch -> one DATA
            // frame holding multiple records).
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
        let mut reader = H3DataFrameLegReader::buffered(server_recv);
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
            "try_read_record_into over a DATA-framed RecvStream must return None when no record is ready",
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

    /// H3 DATA-frame relay leg: real sealed `DataRecordCodec` records must
    /// round-trip BYTE-EXACT through `H3DataFrameLegWriter` -> `H3DataFrameLegReader`
    /// when each writer batch is wrapped in its own DATA frame. Exercises the
    /// record/frame misalignment the design requires the de-framer to absorb:
    /// several records concatenated into ONE DATA frame, and records split across
    /// SEPARATE DATA frames, all recovered in order.
    #[tokio::test]
    async fn h3_data_frame_leg_round_trips_records_across_frame_boundaries() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let opener = tokio::spawn(async move {
            let (send, _recv) = client_conn.open_bi();
            let mut writer = H3DataFrameLegWriter(send);
            let mut seal = data_codec();
            let mut rng = StdRng::seed_from_u64(0xD474);

            let payloads: Vec<Vec<u8>> = vec![
                vec![0xA1; 1500],
                vec![0xB2; 4096],
                b"short-control-frame".to_vec(),
                vec![0xC3; 9000],
                b"tail".to_vec(),
            ];

            // Batch 1: three records concatenated into ONE DATA frame.
            let mut batch = Vec::new();
            for p in &payloads[..3] {
                batch.extend_from_slice(&seal.seal(p, &mut rng).unwrap());
            }
            writer.write_records(&batch).await.unwrap();

            // Batch 2 + 3: one record each, in their own DATA frames.
            for p in &payloads[3..] {
                let one = seal.seal(p, &mut rng).unwrap();
                writer.write_records(&one).await.unwrap();
            }
            writer.shutdown().await.unwrap();
            let _ = done_rx.await;
            payloads
        });

        let (server_send, server_recv) = server_conn.accept_bi().await.expect("accept_bi");
        let _server_send = server_send;
        let mut reader = H3DataFrameLegReader::buffered(server_recv);
        let mut open = data_codec();
        let mut buf = Vec::new();

        let expected: Vec<Vec<u8>> = vec![
            vec![0xA1; 1500],
            vec![0xB2; 4096],
            b"short-control-frame".to_vec(),
            vec![0xC3; 9000],
            b"tail".to_vec(),
        ];
        for want in &expected {
            reader.read_record_into(&mut buf).await.unwrap();
            assert_eq!(&open.open(&buf).unwrap(), want, "record must round-trip");
        }
        // After all records, the clean stream finish must surface as UnexpectedEof
        // (a clean close), NOT a partial record.
        let err = reader
            .read_record_into(&mut buf)
            .await
            .expect_err("clean finish surfaces as an error, not a record");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(reader.is_clean_close(&err));

        let _ = done_tx.send(());
        let payloads = opener.await.expect("opener task");
        assert_eq!(payloads, expected);
    }

    /// A `RESET_STREAM` mid-transfer must surface through the DATA-frame de-framer
    /// as `ConnectionReset` (a truncation), and `H3DataFrameLegReader::is_clean_close`
    /// must reject it — the DATA framing does not mask the truncation semantics.
    #[tokio::test]
    async fn h3_data_frame_leg_reset_is_truncation_not_clean_close() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;
        let (proceed_tx, proceed_rx) = tokio::sync::oneshot::channel::<()>();

        let opener = tokio::spawn(async move {
            let (send, _recv) = client_conn.open_bi();
            let mut writer = H3DataFrameLegWriter(send);
            let mut seal = data_codec();
            let mut rng = StdRng::seed_from_u64(0x4E5E7);
            let good = seal.seal(b"first-and-only-record", &mut rng).unwrap();
            writer.write_records(&good).await.unwrap();
            let _ = proceed_rx.await;
            writer
                .0
                .reset(crate::transport::udp::quic::endpoint::VarInt::from_u32(0));
            tokio::time::sleep(Duration::from_millis(200)).await;
            client_conn
        });

        let (server_send, server_recv) = server_conn.accept_bi().await.expect("accept_bi");
        let _server_send = server_send;
        let mut reader = H3DataFrameLegReader::buffered(server_recv);
        let mut open = data_codec();
        let mut buf = Vec::new();

        reader
            .read_record_into(&mut buf)
            .await
            .expect("first record");
        assert_eq!(open.open(&buf).unwrap(), b"first-and-only-record");

        let _ = proceed_tx.send(());
        let err = reader
            .read_record_into(&mut buf)
            .await
            .expect_err("RESET_STREAM must surface as an error");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert!(
            !reader.is_clean_close(&err),
            "the H3 DATA-frame leg must NOT treat a RESET_STREAM as a clean close",
        );
        // No over-correction: a genuine clean finish stays clean on the H3 leg.
        assert!(reader.is_clean_close(&io::Error::from(io::ErrorKind::UnexpectedEof)));

        // The TCP leg is unchanged: a RST is still a conventional clean half-close,
        // proving the QUIC truncation override is transport-scoped (probe-resistance).
        let tcp = TcpLegReader::buffered(tokio::io::duplex(64).0);
        assert!(
            tcp.is_clean_close(&io::Error::from(io::ErrorKind::ConnectionReset)),
            "TCP leg must keep treating ConnectionReset as a clean half-close",
        );

        let _ = opener.await;
    }

    /// A `LegWriter` whose `write_records` resolves to a caller-chosen result
    /// without touching any socket — lets the read-ahead helper tests drive the
    /// write/read race deterministically.
    struct MockWriter {
        write_result: io::Result<()>,
        written: Vec<u8>,
    }

    impl LegWriter for MockWriter {
        async fn write_records(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.written.extend_from_slice(bytes);
            // Clone the stored result (io::Error is not Clone, so map by kind).
            match &self.write_result {
                Ok(()) => Ok(()),
                Err(err) => Err(io::Error::new(err.kind(), err.to_string())),
            }
        }
        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The read-ahead helper MUST surface a write error immediately, even when the
    /// concurrent read never resolves — proving a failed peer write is not masked
    /// behind a blocked source read (the read future is cancelled on the error).
    #[tokio::test]
    async fn write_batch_read_ahead_surfaces_write_error_despite_blocked_read() {
        let mut writer = MockWriter {
            write_result: Err(io::Error::new(io::ErrorKind::BrokenPipe, "peer reset")),
            written: Vec::new(),
        };
        // A read that never completes: if the helper waited on it, this test would
        // hang and the timeout would fire.
        let never_read = std::future::pending::<io::Result<usize>>();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            write_batch_with_read_ahead(&mut writer, b"sealed-records", never_read),
        )
        .await
        .expect("write error must return promptly, not wait on the blocked read");

        let err = result.expect_err("a write error must propagate");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// Happy path: the batch is written and the helper returns the read-ahead's
    /// byte count.
    #[tokio::test]
    async fn write_batch_read_ahead_returns_read_count_on_success() {
        let mut writer = MockWriter {
            write_result: Ok(()),
            written: Vec::new(),
        };
        let read = async { Ok::<usize, io::Error>(4096) };
        let n = write_batch_with_read_ahead(&mut writer, b"payload", read)
            .await
            .expect("happy path must succeed");
        assert_eq!(n, 4096, "must return the read-ahead byte count");
        assert_eq!(writer.written, b"payload", "the batch must be written");
    }

    /// Read-completes-first path: a subsequent write error still short-circuits and
    /// is returned ahead of the (already-known) read count.
    #[tokio::test]
    async fn write_batch_read_ahead_read_first_then_write_error_propagates() {
        let mut writer = MockWriter {
            // The write resolves immediately, but with an error.
            write_result: Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset")),
            written: Vec::new(),
        };
        // A read that resolves immediately, so the read arm can win the race.
        let read = std::future::ready(Ok::<usize, io::Error>(10));
        let err = write_batch_with_read_ahead(&mut writer, b"x", read)
            .await
            .expect_err("a write error must propagate even when the read won the race");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }
}
