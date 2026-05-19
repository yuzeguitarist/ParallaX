use std::{fmt::Write as _, io, time::Duration};

use rand::rngs::OsRng;
use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpStream, time::Instant};

use crate::{
    client::runtime::{self, ClientRuntimeError},
    config::{decode_base64_bytes, decode_key32, decode_psk, Config, ConfigError, Mode},
    handshake::client::{ClientDataSession, ClientHandshakeError},
    protocol::command::{
        SpeedTestAck, SpeedTestAckError, SpeedTestAckKind, SpeedTestRequest, SpeedTestRequestError,
    },
    protocol::data::relay_read_buffer_len,
    tls::record::TlsRecordReader,
};

const DEFAULT_DOWNLOAD_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_UPLOAD_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum SpeedError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("speed requires mode = \"client\"")]
    WrongMode,
    #[error("speed requires [client] config")]
    MissingClient,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("client runtime error: {0}")]
    ClientRuntime(#[from] ClientRuntimeError),
    #[error("client handshake error: {0}")]
    ClientHandshake(#[from] ClientHandshakeError),
    #[error("speed test request error: {0}")]
    SpeedTestRequest(#[from] SpeedTestRequestError),
    #[error("speed test ack error: {0}")]
    SpeedTestAck(#[from] SpeedTestAckError),
    #[error("unexpected speed test ack: expected {expected:?}, got {actual:?}")]
    UnexpectedAck {
        expected: SpeedTestAckKind,
        actual: SpeedTestAckKind,
    },
    #[error("speed test byte count mismatch: expected {expected}, got {actual}")]
    ByteCountMismatch { expected: u64, actual: u64 },
    #[error("speed test stream sent more bytes than requested")]
    TooManyBytes,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpeedMeasurement {
    pub bytes: u64,
    pub elapsed: Duration,
}

impl SpeedMeasurement {
    fn megabits_per_second(self) -> f64 {
        let seconds = self.elapsed.as_secs_f64();
        if seconds == 0.0 {
            0.0
        } else {
            self.bytes as f64 * 8.0 / seconds / 1_000_000.0
        }
    }

    fn mebibytes(self) -> f64 {
        self.bytes as f64 / 1024.0 / 1024.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpeedReport {
    pub download: SpeedMeasurement,
    pub upload: SpeedMeasurement,
}

impl SpeedReport {
    pub fn to_text(self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "ParallaX speed test complete");
        let _ = writeln!(
            out,
            "download: {:.2} MiB in {:.3}s ({:.2} Mbps)",
            self.download.mebibytes(),
            self.download.elapsed.as_secs_f64(),
            self.download.megabits_per_second()
        );
        let _ = writeln!(
            out,
            "upload:   {:.2} MiB in {:.3}s ({:.2} Mbps)",
            self.upload.mebibytes(),
            self.upload.elapsed.as_secs_f64(),
            self.upload.megabits_per_second()
        );
        out
    }
}

pub async fn run(config: Config) -> Result<SpeedReport, SpeedError> {
    if config.mode != Mode::Client {
        return Err(SpeedError::WrongMode);
    }
    let client = config.client.clone().ok_or(SpeedError::MissingClient)?;
    let psk = decode_psk(&config.crypto.psk)?;
    crate::process_hardening::protect_secret_bytes("runtime.crypto.psk", psk.as_slice());
    let server_public = decode_key32("client.server_public_key", &client.server_public_key)?;
    let server_identity_public = decode_base64_bytes(
        "client.server_identity_public_key",
        &client.server_identity_public_key,
    )?;

    let (mut server, mut data_session) = runtime::establish_authenticated_data_session(
        &client,
        config.traffic,
        psk.as_slice(),
        &server_public,
        &server_identity_public,
    )
    .await?;

    let request = SpeedTestRequest {
        download_bytes: DEFAULT_DOWNLOAD_BYTES,
        upload_bytes: DEFAULT_UPLOAD_BYTES,
    };
    let request_record = data_session.seal_payload(&request.encode()?, &mut OsRng)?;
    server.write_all(&request_record).await?;

    let download = read_download(&mut server, &mut data_session, request.download_bytes).await?;
    let upload = write_upload(&mut server, &mut data_session, request.upload_bytes).await?;

    Ok(SpeedReport { download, upload })
}

async fn read_download(
    server: &mut TcpStream,
    data_session: &mut ClientDataSession,
    expected_bytes: u64,
) -> Result<SpeedMeasurement, SpeedError> {
    let start = Instant::now();
    let mut received = 0_u64;
    let mut records = TlsRecordReader::new(server);
    let mut record = Vec::new();

    while received < expected_bytes {
        records.read_record_into(&mut record).await?;
        data_session.open_server_record_in_place(&mut record)?;
        if record.is_empty() {
            continue;
        }
        let len = record.len() as u64;
        if received + len > expected_bytes {
            return Err(SpeedError::TooManyBytes);
        }
        received += len;
    }
    let elapsed = start.elapsed();

    let ack = read_ack_from_records(
        &mut records,
        data_session,
        SpeedTestAckKind::DownloadDone,
        expected_bytes,
    )
    .await?;
    if ack.bytes != received {
        return Err(SpeedError::ByteCountMismatch {
            expected: received,
            actual: ack.bytes,
        });
    }

    Ok(SpeedMeasurement {
        bytes: received,
        elapsed,
    })
}

async fn write_upload(
    server: &mut TcpStream,
    data_session: &mut ClientDataSession,
    expected_bytes: u64,
) -> Result<SpeedMeasurement, SpeedError> {
    let chunk_len = data_session.max_payload_chunk_len();
    if chunk_len == 0 {
        return Err(SpeedError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "speed upload chunk size is zero",
        )));
    }
    let batch_len = relay_read_buffer_len(chunk_len);
    let payload = vec![0x5A; batch_len];
    let mut rng = OsRng;
    let mut sealed = Vec::with_capacity(batch_len);
    let mut records = Vec::new();
    let mut remaining = expected_bytes;
    let start = Instant::now();

    while remaining > 0 {
        let len = remaining.min(payload.len() as u64) as usize;
        sealed.clear();
        data_session.seal_payload_chunks_into_reusing(
            &payload[..len],
            &mut rng,
            &mut sealed,
            &mut records,
        )?;
        server.write_all(&sealed).await?;
        remaining -= len as u64;
    }
    server.flush().await?;

    let mut ack_reader = TlsRecordReader::new(server);
    let ack = read_ack_from_records(
        &mut ack_reader,
        data_session,
        SpeedTestAckKind::UploadDone,
        expected_bytes,
    )
    .await?;
    let elapsed = start.elapsed();
    if ack.bytes != expected_bytes {
        return Err(SpeedError::ByteCountMismatch {
            expected: expected_bytes,
            actual: ack.bytes,
        });
    }

    Ok(SpeedMeasurement {
        bytes: expected_bytes,
        elapsed,
    })
}

async fn read_ack_from_records<R>(
    records: &mut TlsRecordReader<R>,
    data_session: &mut ClientDataSession,
    expected_kind: SpeedTestAckKind,
    expected_bytes: u64,
) -> Result<SpeedTestAck, SpeedError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut record = Vec::new();
    loop {
        records.read_record_into(&mut record).await?;
        data_session.open_server_record_in_place(&mut record)?;
        if record.is_empty() {
            continue;
        }
        let ack = SpeedTestAck::decode(&record)?;
        if ack.kind != expected_kind {
            return Err(SpeedError::UnexpectedAck {
                expected: expected_kind,
                actual: ack.kind,
            });
        }
        if ack.bytes != expected_bytes {
            return Err(SpeedError::ByteCountMismatch {
                expected: expected_bytes,
                actual: ack.bytes,
            });
        }
        return Ok(ack);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speed_report_formats_rates() {
        let report = SpeedReport {
            download: SpeedMeasurement {
                bytes: 1_000_000,
                elapsed: Duration::from_secs(1),
            },
            upload: SpeedMeasurement {
                bytes: 2_000_000,
                elapsed: Duration::from_secs(2),
            },
        };

        let text = report.to_text();
        assert!(text.contains("ParallaX speed test complete"));
        assert!(text.contains("download:"));
        assert!(text.contains("upload:"));
    }
}
