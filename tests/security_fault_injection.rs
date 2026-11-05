//! Deterministic faults at the actual record-reader and batch-decrypt boundaries.
//! No sockets, timing sleeps, cfg(test) production substitutes, or public targets.
//! A Pending read is observed once, its future is cancelled, and the same reader
//! resumes. Every byte cut is exercised, including all five TLS-header bytes.

use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use parallax::crypto::parallel::CryptoPool;
use parallax::crypto::session::{AeadCodec, CipherSuite};
use parallax::protocol::command::{FramedChunkError, FramedReassembler};
use parallax::protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD, SERVER_TO_CLIENT_AAD};
use parallax::tls::record::TlsRecordReader;
use parallax::traffic::PaddingProfile;
use rand::{rngs::StdRng, SeedableRng};
use tokio::io::{AsyncRead, ReadBuf};

#[derive(Clone, Copy)]
enum Fault {
    Pending,
    Eof,
    Error(io::ErrorKind),
}

struct FaultReader {
    bytes: Vec<u8>,
    position: usize,
    cut: usize,
    fault: Fault,
    released: Arc<AtomicBool>,
    injections: Arc<AtomicUsize>,
}

impl AsyncRead for FaultReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let end = if self.released.load(Ordering::SeqCst) {
            self.bytes.len()
        } else {
            self.cut
        };
        if self.position == end && !self.released.load(Ordering::SeqCst) {
            self.injections.fetch_add(1, Ordering::SeqCst);
            return match self.fault {
                // The test explicitly drops this pending future and starts a new
                // one after release, so no wake or real timer is needed.
                Fault::Pending => Poll::Pending,
                Fault::Eof => Poll::Ready(Ok(())),
                Fault::Error(kind) => Poll::Ready(Err(io::Error::new(kind, "injected"))),
            };
        }
        let n = (end - self.position).min(buf.remaining()).min(7);
        buf.put_slice(&self.bytes[self.position..self.position + n]);
        self.position += n;
        Poll::Ready(Ok(()))
    }
}

fn record(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x17, 3, 3];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn fault_reader(
    bytes: Vec<u8>,
    cut: usize,
    fault: Fault,
) -> (FaultReader, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let released = Arc::new(AtomicBool::new(false));
    let injections = Arc::new(AtomicUsize::new(0));
    (
        FaultReader {
            bytes,
            position: 0,
            cut,
            fault,
            released: Arc::clone(&released),
            injections: Arc::clone(&injections),
        },
        released,
        injections,
    )
}

async fn cancel_and_resume<R: AsyncRead + Unpin>(
    mut reader: TlsRecordReader<R>,
    cut: usize,
    released: Arc<AtomicBool>,
    injections: Arc<AtomicUsize>,
    first: &[u8],
    second: &[u8],
) {
    let sentinel = b"caller buffer is unchanged until a complete record".to_vec();
    let mut out = sentinel.clone();
    let mut pending = Box::pin(reader.read_record_into(&mut out));
    let observed = poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx))).await;
    assert!(
        observed.is_pending(),
        "cut={cut}: fault did not suspend the read"
    );
    drop(pending);
    assert_eq!(injections.load(Ordering::SeqCst), 1, "cut={cut}");
    assert_eq!(out, sentinel, "cut={cut}: incomplete record escaped");
    assert_eq!(reader.at_record_boundary(), cut == 0, "cut={cut}");

    released.store(true, Ordering::SeqCst);
    reader.read_record_into(&mut out).await.unwrap();
    assert_eq!(
        out, first,
        "cut={cut}: cancellation lost or duplicated bytes"
    );
    assert!(reader.at_record_boundary());
    reader.read_record_into(&mut out).await.unwrap();
    assert_eq!(out, second, "cut={cut}: next record was over-read");
    assert!(reader.at_record_boundary());
    assert_eq!(injections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn every_record_byte_cut_survives_cancellation_buffered_and_unbuffered() {
    let first = record(&(0..64).collect::<Vec<u8>>());
    let second = record(b"next-record");
    let wire = [first.as_slice(), second.as_slice()].concat();
    for cut in 0..first.len() {
        let (source, released, injections) = fault_reader(wire.clone(), cut, Fault::Pending);
        cancel_and_resume(
            TlsRecordReader::new(source),
            cut,
            released,
            injections,
            &first,
            &second,
        )
        .await;
        let (source, released, injections) = fault_reader(wire.clone(), cut, Fault::Pending);
        cancel_and_resume(
            TlsRecordReader::buffered(source),
            cut,
            released,
            injections,
            &first,
            &second,
        )
        .await;
    }
}

#[tokio::test]
async fn every_record_byte_cut_propagates_eof_and_transport_errors() {
    let wire = record(&(0..64).collect::<Vec<u8>>());
    for cut in 0..wire.len() {
        for (fault, expected) in [
            (Fault::Eof, io::ErrorKind::UnexpectedEof),
            (
                Fault::Error(io::ErrorKind::ConnectionReset),
                io::ErrorKind::ConnectionReset,
            ),
            (
                Fault::Error(io::ErrorKind::TimedOut),
                io::ErrorKind::TimedOut,
            ),
            (
                Fault::Error(io::ErrorKind::Interrupted),
                io::ErrorKind::Interrupted,
            ),
        ] {
            let (source, _, injections) = fault_reader(wire.clone(), cut, fault);
            let mut reader = TlsRecordReader::new(source);
            let mut out = b"sentinel".to_vec();
            let err = reader.read_record_into(&mut out).await.unwrap_err();
            assert_eq!(err.kind(), expected, "cut={cut}");
            assert_eq!(out, b"sentinel", "cut={cut}: incomplete record escaped");
            assert_eq!(injections.load(Ordering::SeqCst), 1, "cut={cut}");
        }
    }
}

fn chunk(total: u32, offset: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = b"PX1F".to_vec();
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

#[test]
fn reassembly_rejects_sequence_and_resource_faults_without_false_completion() {
    let first = chunk(6, 0, b"abc");
    for (bad, expected) in [
        (first.clone(), FramedChunkError::OutOfOrder),
        (chunk(6, 4, b"ef"), FramedChunkError::OutOfOrder),
        (chunk(7, 3, b"def"), FramedChunkError::InconsistentTotal),
        (chunk(6, u32::MAX, b"x"), FramedChunkError::InvalidOffset),
        (chunk(6, 3, b""), FramedChunkError::EmptyChunk),
    ] {
        let mut state = FramedReassembler::default();
        assert!(state.push(&first, 4096).unwrap().is_none());
        assert_eq!(state.push(&bad, 4096).unwrap_err(), expected);
    }
    let mut state = FramedReassembler::default();
    assert_eq!(
        state.push(&chunk(4097, 0, b"a"), 4096),
        Err(FramedChunkError::TooLarge)
    );
    assert_eq!(
        state.push(&chunk(6, 3, b"def"), 4096),
        Err(FramedChunkError::OutOfOrder)
    );
    let mut state = FramedReassembler::default();
    assert!(state.push(&first, 6).unwrap().is_none());
    assert_eq!(
        state.push(&chunk(6, 3, b"def"), 6).unwrap(),
        Some(b"abcdef".to_vec())
    );
    assert_eq!(
        state.push(&chunk(1, 0, b"z"), 1).unwrap(),
        Some(b"z".to_vec())
    );
}

fn codec(suite: CipherSuite, aad: &'static [u8]) -> DataRecordCodec {
    DataRecordCodec::new(
        AeadCodec::new_with_suite(suite, [0x31; 32], [0x49; 12]),
        PaddingProfile::new(0, 0).unwrap(),
        aad,
    )
}

#[test]
fn a_failed_batch_commits_no_output_invalidates_serial_input_and_poison_is_sticky() {
    let pool = CryptoPool::new(3);
    for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        for aad in [CLIENT_TO_SERVER_AAD, SERVER_TO_CLIENT_AAD] {
            let mut sealer = codec(suite, aad);
            let mut rng = StdRng::seed_from_u64(0xFA017);
            let first = sealer.seal(b"valid-prefix", &mut rng).unwrap();
            let second = sealer.seal(b"valid-suffix", &mut rng).unwrap();
            let mut tag = second.clone();
            *tag.last_mut().unwrap() ^= 1;
            let mut wrong_type = second.clone();
            wrong_type[0] = 0x16;
            // A correctly authenticated record with an impossible padding trailer
            // exercises the post-AEAD failure path, not just tag rejection.
            let mut raw = AeadCodec::new_with_suite(suite, [0x31; 32], [0x49; 12]);
            raw.seal(b"unused-sequence-zero", aad).unwrap();
            let bad_padding = record(&raw.seal(&[1, 0xff, 0xff], aad).unwrap());
            let faults = [
                ("tag", tag),
                ("type", wrong_type),
                ("truncated", second[..second.len() - 1].to_vec()),
                ("duplicate", first.clone()),
                ("padding", bad_padding),
            ];
            for (label, bad_second) in faults {
                let batch = [first.as_slice(), bad_second.as_slice()].concat();
                let sentinel = b"already committed output".to_vec();
                let mut serial = codec(suite, aad);
                let mut input = batch.clone();
                let mut out = sentinel.clone();
                assert!(
                    serial.open_concat_records(&mut input, &mut out).is_err(),
                    "{label}"
                );
                assert_eq!(out, sentinel, "{label}: serial batch committed a prefix");
                assert!(
                    input.iter().all(|&b| b == 0),
                    "{label}: serial input retained plaintext"
                );
                assert!(
                    serial.seal(b"must refuse after error", &mut rng).is_err(),
                    "{label}"
                );
                assert!(serial.open(&second).is_err(), "{label}");
                let mut refused_input = first.clone();
                assert!(serial
                    .open_concat_records(&mut refused_input, &mut out)
                    .is_err());
                assert!(refused_input.iter().all(|&b| b == 0));
                assert_eq!(out, sentinel);

                let mut parallel = codec(suite, aad);
                let mut out = sentinel.clone();
                assert!(
                    parallel
                        .open_concat_records_parallel(&pool, &batch, &mut out)
                        .is_err(),
                    "{label}"
                );
                assert_eq!(out, sentinel, "{label}: parallel batch committed a prefix");
                assert!(
                    parallel.seal(b"must refuse after error", &mut rng).is_err(),
                    "{label}"
                );
                assert!(parallel.open(&first).is_err(), "{label}");
            }
        }
    }
}
