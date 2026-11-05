//! Authenticated TCP-record capture support for the loopback E2E test.
//!
//! A transparent TCP forwarder observes the actual TLS-framed bytes in both
//! directions, including the camouflage handshake and the encrypted PQ/data
//! exchange. Records are reassembled across arbitrary socket-read boundaries;
//! their timestamps are when the forwarder observed the complete record.
//!
//! This is a userspace stream tap, not packet capture: the extra TCP hop changes
//! packetization, and loopback timing includes host scheduling. It supplies real
//! direction/interleave/timing samples for harness validation, not evidence of
//! indistinguishability on an external network. No payload or key is exported.

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use parallax::tls::record::{self, TLS_CONTENT_APPLICATION_DATA, TLS_HEADER_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::trace::{Dir, Record, Trace};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedRecord {
    pub content_type: u8,
    pub len: u32,
    pub dir: Dir,
    pub t_micros: u64,
}

pub struct Capture {
    pub records: Vec<CapturedRecord>,
}

impl Capture {
    pub fn application_data(&self) -> Trace {
        Trace::new(
            self.records
                .iter()
                .filter(|r| r.content_type == TLS_CONTENT_APPLICATION_DATA)
                .map(|r| Record {
                    len: r.len,
                    dir: r.dir,
                    t_micros: r.t_micros,
                })
                .collect(),
        )
    }

    /// Opt-in metadata artifact. TLS 1.3 encrypted handshake records also use
    /// outer type 23, so this deliberately makes no plaintext-phase claim.
    pub fn write_tsv(&self, path: impl AsRef<Path>) -> io::Result<()> {
        use std::fmt::Write as _;
        let mut text = String::from(
            "# parallax-tcp-record-capture-v1\n\
             # vantage=loopback-userspace-forwarder; time=record-completion; payload=omitted\n\
             t_micros\tdirection\tcontent_type\trecord_length\n",
        );
        for r in &self.records {
            let dir = match r.dir {
                Dir::C2S => "c2s",
                Dir::S2C => "s2c",
            };
            writeln!(text, "{}\t{dir}\t{}\t{}", r.t_micros, r.content_type, r.len)
                .expect("write capture metadata to String");
        }
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(text.as_bytes())
    }
}

#[derive(Default)]
struct Reassembler {
    pending: Vec<u8>,
}

impl Reassembler {
    fn feed(&mut self, bytes: &[u8], dir: Dir, t_micros: u64) -> io::Result<Vec<CapturedRecord>> {
        self.pending.extend_from_slice(bytes);
        let mut records = Vec::new();
        let mut consumed = 0;
        while self.pending.len() - consumed >= TLS_HEADER_LEN {
            let header = record::parse_header(&self.pending[consumed..])
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            if !(20..=23).contains(&header.content_type) || header.legacy_version[0] != 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-TLS capture bytes",
                ));
            }
            if self.pending.len() - consumed < header.total_len {
                break;
            }
            records.push(CapturedRecord {
                content_type: header.content_type,
                len: header.payload_len as u32,
                dir,
                t_micros,
            });
            consumed += header.total_len;
        }
        self.pending.drain(..consumed);
        Ok(records)
    }

    fn finish(&self) -> io::Result<()> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "capture ended inside TLS record",
            ))
        }
    }
}

pub struct RecordingForwarder {
    pub front_addr: std::net::SocketAddr,
    records: Arc<Mutex<Vec<CapturedRecord>>>,
    task: JoinHandle<io::Result<()>>,
}

impl RecordingForwarder {
    pub async fn spawn(server_addr: std::net::SocketAddr, listen_port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, listen_port)).await?;
        let front_addr = listener.local_addr()?;
        let records = Arc::new(Mutex::new(Vec::new()));
        let log = records.clone();
        let task = tokio::spawn(async move {
            let (front, _) = listener.accept().await?;
            let back = TcpStream::connect(server_addr).await?;
            front.set_nodelay(true)?;
            back.set_nodelay(true)?;
            let (front_read, front_write) = front.into_split();
            let (back_read, back_write) = back.into_split();
            let started = Instant::now();
            tokio::try_join!(
                forward(front_read, back_write, Dir::C2S, started, log.clone()),
                forward(back_read, front_write, Dir::S2C, started, log),
            )?;
            Ok(())
        });
        Ok(Self {
            front_addr,
            records,
            task,
        })
    }

    pub async fn finish(mut self) -> io::Result<Capture> {
        (&mut self.task).await.map_err(io::Error::other)??;
        let mut records = self.records.lock().unwrap().clone();
        records.sort_by_key(|r| r.t_micros);
        if let Some(first) = records.first() {
            let start = first.t_micros;
            for r in &mut records {
                r.t_micros -= start;
            }
        }
        Ok(Capture { records })
    }
}

impl Drop for RecordingForwarder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    dir: Dir,
    started: Instant,
    records: Arc<Mutex<Vec<CapturedRecord>>>,
) -> io::Result<()> {
    let mut buf = vec![0; 64 * 1024];
    let mut reassembler = Reassembler::default();
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            reassembler.finish()?;
            return writer.shutdown().await;
        }
        let observed = reassembler.feed(&buf[..n], dir, started.elapsed().as_micros() as u64)?;
        records.lock().unwrap().extend(observed);
        writer.write_all(&buf[..n]).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_records_keep_completion_times_and_coalesced_boundaries() {
        let first = [23, 3, 3, 0, 3, 10, 11, 12];
        let second = [22, 3, 3, 0, 1, 13];
        let mut reassembler = Reassembler::default();
        assert!(reassembler
            .feed(&first[..2], Dir::C2S, 10)
            .unwrap()
            .is_empty());
        assert!(reassembler
            .feed(&first[2..7], Dir::C2S, 20)
            .unwrap()
            .is_empty());
        let mut remaining = first[7..].to_vec();
        remaining.extend_from_slice(&second);
        let records = reassembler.feed(&remaining, Dir::C2S, 37).unwrap();
        assert_eq!(
            records,
            vec![
                CapturedRecord {
                    content_type: 23,
                    len: 3,
                    dir: Dir::C2S,
                    t_micros: 37
                },
                CapturedRecord {
                    content_type: 22,
                    len: 1,
                    dir: Dir::C2S,
                    t_micros: 37
                },
            ]
        );
        reassembler.finish().unwrap();
    }

    #[test]
    fn truncated_and_invalid_records_fail_instead_of_silently_disappearing() {
        let mut truncated = Reassembler::default();
        truncated.feed(&[23, 3, 3, 0, 2, 1], Dir::S2C, 9).unwrap();
        assert_eq!(
            truncated.finish().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let mut invalid = Reassembler::default();
        assert_eq!(
            invalid
                .feed(&[23, 3, 3, 255, 255], Dir::S2C, 9)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
