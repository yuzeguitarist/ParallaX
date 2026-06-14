use std::{
    fmt::Write as _,
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::rngs::OsRng;
use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpStream, time::Instant};

use crate::{
    client::runtime::{self, ClientRuntimeError},
    config::{
        decode_base64_bytes, decode_key32, decode_psk, Config, ConfigError, Mode, TrafficConfig,
    },
    handshake::client::{ClientDataSession, ClientHandshakeError},
    protocol::command::{
        SpeedTestAck, SpeedTestAckError, SpeedTestAckKind, SpeedTestRequest, SpeedTestRequestError,
    },
    protocol::data::relay_read_buffer_len,
    runtime_guard::client_config_fingerprint,
    tls::record::TlsRecordReader,
    PROTOCOL_NAME, PROTOCOL_VERSION,
};

const REPORT_SCHEMA: &str = "parallax.speed.evidence.v1";
const DEFAULT_WARMUP_BYTES: u64 = 1024 * 1024;
const DEFAULT_SAMPLE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_SAMPLE_COUNT: u16 = 3;

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
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeedPlan {
    pub warmup_bytes: u64,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub sample_count: u16,
}

impl Default for SpeedPlan {
    fn default() -> Self {
        Self {
            warmup_bytes: DEFAULT_WARMUP_BYTES,
            download_bytes: DEFAULT_SAMPLE_BYTES,
            upload_bytes: DEFAULT_SAMPLE_BYTES,
            sample_count: DEFAULT_SAMPLE_COUNT,
        }
    }
}

impl SpeedPlan {
    fn request(self) -> SpeedTestRequest {
        SpeedTestRequest {
            warmup_bytes: self.warmup_bytes,
            download_bytes: self.download_bytes,
            upload_bytes: self.upload_bytes,
            sample_count: self.sample_count,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficEvidence {
    pub min_padding: u16,
    pub max_padding: u16,
    pub min_delay_ms: u16,
    pub max_delay_ms: u16,
    pub cover_min_interval_ms: u16,
    pub cover_max_interval_ms: u16,
    pub max_concurrent_streams: u8,
}

impl From<TrafficConfig> for TrafficEvidence {
    fn from(value: TrafficConfig) -> Self {
        Self {
            min_padding: value.min_padding,
            max_padding: value.max_padding,
            min_delay_ms: value.min_delay_ms,
            max_delay_ms: value.max_delay_ms,
            cover_min_interval_ms: value.cover_min_interval_ms,
            cover_max_interval_ms: value.cover_max_interval_ms,
            max_concurrent_streams: value.max_concurrent_streams,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PhaseMeasurement {
    pub bytes: u64,
    pub elapsed: Duration,
}

impl PhaseMeasurement {
    fn megabits_per_second(self) -> f64 {
        mbps(self.bytes, self.elapsed)
    }

    fn mebibytes(self) -> f64 {
        mebibytes(self.bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpeedSample {
    pub index: u16,
    pub measurement: PhaseMeasurement,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DirectionSummary {
    pub sample_count: usize,
    pub total_bytes: u64,
    pub median_mbps: f64,
    pub mean_mbps: f64,
    pub min_mbps: f64,
    pub max_mbps: f64,
    pub stddev_mbps: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DirectionReport {
    pub samples: Vec<SpeedSample>,
    pub summary: DirectionSummary,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpeedReport {
    pub schema: &'static str,
    pub generated_unix_ms: u128,
    pub protocol_name: &'static str,
    pub protocol_version: u8,
    pub binary_version: &'static str,
    pub config_fingerprint: String,
    pub server_addr: String,
    pub sni: String,
    pub traffic: TrafficEvidence,
    pub max_payload_chunk_len: usize,
    pub plan: SpeedPlan,
    pub handshake: PhaseMeasurement,
    pub warmup_download: PhaseMeasurement,
    pub warmup_upload: PhaseMeasurement,
    pub download: DirectionReport,
    pub upload: DirectionReport,
}

impl SpeedReport {
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "ParallaX speed evidence report");
        let _ = writeln!(out, "schema: {}", self.schema);
        let _ = writeln!(out, "generated_unix_ms: {}", self.generated_unix_ms);
        let _ = writeln!(
            out,
            "binary: {} {} / protocol {}",
            self.protocol_name, self.binary_version, self.protocol_version
        );
        let _ = writeln!(out, "server_addr: {}", self.server_addr);
        let _ = writeln!(out, "sni: {}", self.sni);
        let _ = writeln!(out, "config_fingerprint: {}", self.config_fingerprint);
        let _ = writeln!(
            out,
            "traffic: padding={}..{} delay_ms={}..{} cover_ms={}..{} streams={}",
            self.traffic.min_padding,
            self.traffic.max_padding,
            self.traffic.min_delay_ms,
            self.traffic.max_delay_ms,
            self.traffic.cover_min_interval_ms,
            self.traffic.cover_max_interval_ms,
            self.traffic.max_concurrent_streams
        );
        let _ = writeln!(
            out,
            "plan: warmup={:.2} MiB samples={} download_sample={:.2} MiB upload_sample={:.2} MiB chunk={} B",
            mebibytes(self.plan.warmup_bytes),
            self.plan.sample_count,
            mebibytes(self.plan.download_bytes),
            mebibytes(self.plan.upload_bytes),
            self.max_payload_chunk_len
        );
        let _ = writeln!(out, "handshake_ms: {:.3}", millis(self.handshake.elapsed));
        write_phase(&mut out, "warmup_download", self.warmup_download);
        write_phase(&mut out, "warmup_upload", self.warmup_upload);
        write_direction(&mut out, "download", &self.download);
        write_direction(&mut out, "upload", &self.upload);
        out
    }

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "{{");
        write_json_str(&mut out, 1, "schema", self.schema, true);
        write_json_u128(
            &mut out,
            1,
            "generated_unix_ms",
            self.generated_unix_ms,
            true,
        );
        write_json_str(&mut out, 1, "protocol_name", self.protocol_name, true);
        write_json_u64(
            &mut out,
            1,
            "protocol_version",
            u64::from(self.protocol_version),
            true,
        );
        write_json_str(&mut out, 1, "binary_version", self.binary_version, true);
        write_json_str(
            &mut out,
            1,
            "config_fingerprint",
            &self.config_fingerprint,
            true,
        );
        write_json_str(&mut out, 1, "server_addr", &self.server_addr, true);
        write_json_str(&mut out, 1, "sni", &self.sni, true);
        write_json_traffic(&mut out, 1, "traffic", self.traffic, true);
        write_json_u64(
            &mut out,
            1,
            "max_payload_chunk_len",
            self.max_payload_chunk_len as u64,
            true,
        );
        write_json_plan(&mut out, 1, "plan", self.plan, true);
        write_json_phase(&mut out, 1, "handshake", self.handshake, true);
        write_json_phase(&mut out, 1, "warmup_download", self.warmup_download, true);
        write_json_phase(&mut out, 1, "warmup_upload", self.warmup_upload, true);
        write_json_direction(&mut out, 1, "download", &self.download, true);
        write_json_direction(&mut out, 1, "upload", &self.upload, false);
        let _ = writeln!(out, "}}");
        out
    }
}

pub async fn run(config: Config) -> Result<SpeedReport, SpeedError> {
    run_with_plan(config, SpeedPlan::default()).await
}

async fn run_with_plan(config: Config, plan: SpeedPlan) -> Result<SpeedReport, SpeedError> {
    if config.mode != Mode::Client {
        return Err(SpeedError::WrongMode);
    }
    // Mirror `client` run(): the UDP-negotiation parameters live on `config.udp`
    // and are threaded into the data-session seam so `parallax speed` exercises
    // the UDP fast plane identically when enabled.
    let client = config.client.clone().ok_or(SpeedError::MissingClient)?;
    let psk = decode_psk(&config.crypto.psk)?;
    crate::process_hardening::protect_secret_bytes("runtime.crypto.psk", psk.as_slice());
    let server_public = decode_key32("client.server_public_key", &client.server_public_key)?;
    let server_identity_public = decode_base64_bytes(
        "client.server_identity_public_key",
        &client.server_identity_public_key,
    )?;

    let generated_unix_ms = unix_millis()?;
    let handshake_start = Instant::now();
    let (mut server, mut data_session) = runtime::establish_authenticated_data_session(
        &client,
        config.traffic,
        &config.udp,
        psk.as_slice(),
        &server_public,
        &server_identity_public,
    )
    .await?;
    let handshake = PhaseMeasurement {
        bytes: 0,
        elapsed: handshake_start.elapsed(),
    };
    let max_payload_chunk_len = data_session.max_payload_chunk_len();

    let request = plan.request();
    let request_record = data_session.seal_payload(&request.encode()?, &mut OsRng)?;
    server.write_all(&request_record).await?;

    let warmup_download = {
        let mut records = TlsRecordReader::new(&mut server);
        read_download_phase(
            &mut records,
            &mut data_session,
            SpeedTestAckKind::WarmupDownloadDone,
            request.warmup_bytes,
        )
        .await?
    };
    let warmup_upload = write_upload_phase(
        &mut server,
        &mut data_session,
        SpeedTestAckKind::WarmupUploadDone,
        request.warmup_bytes,
    )
    .await?;

    let mut download_samples = Vec::with_capacity(request.sample_count as usize);
    {
        let mut records = TlsRecordReader::new(&mut server);
        for index in 1..=request.sample_count {
            download_samples.push(SpeedSample {
                index,
                measurement: read_download_phase(
                    &mut records,
                    &mut data_session,
                    SpeedTestAckKind::DownloadDone,
                    request.download_bytes,
                )
                .await?,
            });
        }
    }

    let mut upload_samples = Vec::with_capacity(request.sample_count as usize);
    for index in 1..=request.sample_count {
        upload_samples.push(SpeedSample {
            index,
            measurement: write_upload_phase(
                &mut server,
                &mut data_session,
                SpeedTestAckKind::UploadDone,
                request.upload_bytes,
            )
            .await?,
        });
    }

    Ok(SpeedReport {
        schema: REPORT_SCHEMA,
        generated_unix_ms,
        protocol_name: PROTOCOL_NAME,
        protocol_version: PROTOCOL_VERSION,
        binary_version: env!("CARGO_PKG_VERSION"),
        config_fingerprint: client_config_fingerprint(&client),
        server_addr: client.server_addr,
        sni: client.sni,
        traffic: TrafficEvidence::from(config.traffic),
        max_payload_chunk_len,
        plan,
        handshake,
        warmup_download,
        warmup_upload,
        download: DirectionReport::new(download_samples),
        upload: DirectionReport::new(upload_samples),
    })
}

impl DirectionReport {
    fn new(samples: Vec<SpeedSample>) -> Self {
        Self {
            summary: DirectionSummary::from_samples(&samples),
            samples,
        }
    }
}

impl DirectionSummary {
    fn from_samples(samples: &[SpeedSample]) -> Self {
        let sample_count = samples.len();
        let total_bytes = samples.iter().map(|sample| sample.measurement.bytes).sum();
        let mut rates = samples
            .iter()
            .map(|sample| sample.measurement.megabits_per_second())
            .collect::<Vec<_>>();
        rates.sort_by(f64::total_cmp);
        let median_mbps = median(&rates);
        let mean_mbps = mean(&rates);
        let stddev_mbps = stddev(&rates, mean_mbps);
        let min_mbps = rates.first().copied().unwrap_or(0.0);
        let max_mbps = rates.last().copied().unwrap_or(0.0);
        Self {
            sample_count,
            total_bytes,
            median_mbps,
            mean_mbps,
            min_mbps,
            max_mbps,
            stddev_mbps,
        }
    }
}

async fn read_download_phase<R>(
    records: &mut TlsRecordReader<R>,
    data_session: &mut ClientDataSession,
    expected_ack: SpeedTestAckKind,
    expected_bytes: u64,
) -> Result<PhaseMeasurement, SpeedError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let start = Instant::now();
    let mut received = 0_u64;
    let mut record = Vec::new();

    while received < expected_bytes {
        records.read_record_into(&mut record).await?;
        let payload = data_session.open_server_record_in_place_payload_range(&mut record)?;
        if payload.is_empty() {
            continue;
        }
        let len = payload.len() as u64;
        if received + len > expected_bytes {
            return Err(SpeedError::TooManyBytes);
        }
        received += len;
    }
    let elapsed = start.elapsed();

    let ack = read_ack_from_records(records, data_session, expected_ack, expected_bytes).await?;
    if ack.bytes != received {
        return Err(SpeedError::ByteCountMismatch {
            expected: received,
            actual: ack.bytes,
        });
    }

    Ok(PhaseMeasurement {
        bytes: received,
        elapsed,
    })
}

async fn write_upload_phase(
    server: &mut TcpStream,
    data_session: &mut ClientDataSession,
    expected_ack: SpeedTestAckKind,
    expected_bytes: u64,
) -> Result<PhaseMeasurement, SpeedError> {
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
    let mut sealed = Vec::with_capacity(batch_len + 256);
    let mut remaining = expected_bytes;
    let start = Instant::now();

    while remaining > 0 {
        let len = remaining.min(payload.len() as u64) as usize;
        sealed.clear();
        data_session.seal_payload_chunks_into_untracked(&payload[..len], &mut rng, &mut sealed)?;
        server.write_all(&sealed).await?;
        remaining -= len as u64;
    }
    server.flush().await?;

    let mut ack_reader = TlsRecordReader::new(server);
    let ack =
        read_ack_from_records(&mut ack_reader, data_session, expected_ack, expected_bytes).await?;
    let elapsed = start.elapsed();
    if ack.bytes != expected_bytes {
        return Err(SpeedError::ByteCountMismatch {
            expected: expected_bytes,
            actual: ack.bytes,
        });
    }

    Ok(PhaseMeasurement {
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
        let payload = data_session.open_server_record_in_place_payload_range(&mut record)?;
        if payload.is_empty() {
            continue;
        }
        let ack = SpeedTestAck::decode(&record[payload])?;
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

fn write_phase(out: &mut String, label: &str, phase: PhaseMeasurement) {
    let _ = writeln!(
        out,
        "{label}: {:.2} MiB in {:.3}s ({:.2} Mbps)",
        phase.mebibytes(),
        phase.elapsed.as_secs_f64(),
        phase.megabits_per_second()
    );
}

fn write_direction(out: &mut String, label: &str, report: &DirectionReport) {
    let _ = writeln!(out, "{label}_samples:");
    for sample in &report.samples {
        let _ = writeln!(
            out,
            "  #{:02}: {:.2} MiB in {:.3}s ({:.2} Mbps)",
            sample.index,
            sample.measurement.mebibytes(),
            sample.measurement.elapsed.as_secs_f64(),
            sample.measurement.megabits_per_second()
        );
    }
    let _ = writeln!(
        out,
        "{label}_summary: samples={} total={:.2} MiB median={:.2} Mbps mean={:.2} Mbps min={:.2} Mbps max={:.2} Mbps stddev={:.2} Mbps",
        report.summary.sample_count,
        mebibytes(report.summary.total_bytes),
        report.summary.median_mbps,
        report.summary.mean_mbps,
        report.summary.min_mbps,
        report.summary.max_mbps,
        report.summary.stddev_mbps
    );
}

fn median(sorted: &[f64]) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn stddev(values: &[f64], mean: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt()
}

fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds == 0.0 {
        0.0
    } else {
        bytes as f64 * 8.0 / seconds / 1_000_000.0
    }
}

fn mebibytes(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn unix_millis() -> Result<u128, SpeedError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SpeedError::Clock)?
        .as_millis())
}

fn write_json_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_json_key(out: &mut String, indent: usize, key: &str) {
    write_json_indent(out, indent);
    let _ = write!(out, "\"{}\": ", json_escape(key));
}

fn write_json_str(out: &mut String, indent: usize, key: &str, value: &str, comma: bool) {
    write_json_key(out, indent, key);
    let _ = write!(out, "\"{}\"", json_escape(value));
    write_json_comma_newline(out, comma);
}

fn write_json_u64(out: &mut String, indent: usize, key: &str, value: u64, comma: bool) {
    write_json_key(out, indent, key);
    let _ = write!(out, "{value}");
    write_json_comma_newline(out, comma);
}

fn write_json_u128(out: &mut String, indent: usize, key: &str, value: u128, comma: bool) {
    write_json_key(out, indent, key);
    let _ = write!(out, "{value}");
    write_json_comma_newline(out, comma);
}

fn write_json_f64(out: &mut String, indent: usize, key: &str, value: f64, comma: bool) {
    write_json_key(out, indent, key);
    let _ = write!(out, "{value:.6}");
    write_json_comma_newline(out, comma);
}

fn write_json_comma_newline(out: &mut String, comma: bool) {
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_json_traffic(
    out: &mut String,
    indent: usize,
    key: &str,
    traffic: TrafficEvidence,
    comma: bool,
) {
    write_json_key(out, indent, key);
    let _ = writeln!(out, "{{");
    write_json_u64(
        out,
        indent + 1,
        "min_padding",
        u64::from(traffic.min_padding),
        true,
    );
    write_json_u64(
        out,
        indent + 1,
        "max_padding",
        u64::from(traffic.max_padding),
        true,
    );
    write_json_u64(
        out,
        indent + 1,
        "min_delay_ms",
        u64::from(traffic.min_delay_ms),
        true,
    );
    write_json_u64(
        out,
        indent + 1,
        "max_delay_ms",
        u64::from(traffic.max_delay_ms),
        true,
    );
    write_json_u64(
        out,
        indent + 1,
        "cover_min_interval_ms",
        u64::from(traffic.cover_min_interval_ms),
        true,
    );
    write_json_u64(
        out,
        indent + 1,
        "cover_max_interval_ms",
        u64::from(traffic.cover_max_interval_ms),
        true,
    );
    write_json_u64(
        out,
        indent + 1,
        "max_concurrent_streams",
        u64::from(traffic.max_concurrent_streams),
        false,
    );
    write_json_indent(out, indent);
    out.push('}');
    write_json_comma_newline(out, comma);
}

fn write_json_plan(out: &mut String, indent: usize, key: &str, plan: SpeedPlan, comma: bool) {
    write_json_key(out, indent, key);
    let _ = writeln!(out, "{{");
    write_json_u64(out, indent + 1, "warmup_bytes", plan.warmup_bytes, true);
    write_json_u64(out, indent + 1, "download_bytes", plan.download_bytes, true);
    write_json_u64(out, indent + 1, "upload_bytes", plan.upload_bytes, true);
    write_json_u64(
        out,
        indent + 1,
        "sample_count",
        u64::from(plan.sample_count),
        false,
    );
    write_json_indent(out, indent);
    out.push('}');
    write_json_comma_newline(out, comma);
}

fn write_json_phase(
    out: &mut String,
    indent: usize,
    key: &str,
    phase: PhaseMeasurement,
    comma: bool,
) {
    write_json_key(out, indent, key);
    let _ = writeln!(out, "{{");
    write_json_u64(out, indent + 1, "bytes", phase.bytes, true);
    write_json_f64(out, indent + 1, "elapsed_ms", millis(phase.elapsed), true);
    write_json_f64(
        out,
        indent + 1,
        "throughput_mbps",
        phase.megabits_per_second(),
        false,
    );
    write_json_indent(out, indent);
    out.push('}');
    write_json_comma_newline(out, comma);
}

fn write_json_direction(
    out: &mut String,
    indent: usize,
    key: &str,
    report: &DirectionReport,
    comma: bool,
) {
    write_json_key(out, indent, key);
    let _ = writeln!(out, "{{");
    write_json_key(out, indent + 1, "samples");
    let _ = writeln!(out, "[");
    for (idx, sample) in report.samples.iter().enumerate() {
        write_json_indent(out, indent + 2);
        let _ = writeln!(out, "{{");
        write_json_u64(out, indent + 3, "index", u64::from(sample.index), true);
        write_json_u64(out, indent + 3, "bytes", sample.measurement.bytes, true);
        write_json_f64(
            out,
            indent + 3,
            "elapsed_ms",
            millis(sample.measurement.elapsed),
            true,
        );
        write_json_f64(
            out,
            indent + 3,
            "throughput_mbps",
            sample.measurement.megabits_per_second(),
            false,
        );
        write_json_indent(out, indent + 2);
        out.push('}');
        write_json_comma_newline(out, idx + 1 < report.samples.len());
    }
    write_json_indent(out, indent + 1);
    out.push(']');
    write_json_comma_newline(out, true);
    write_json_summary(out, indent + 1, "summary", &report.summary, false);
    write_json_indent(out, indent);
    out.push('}');
    write_json_comma_newline(out, comma);
}

fn write_json_summary(
    out: &mut String,
    indent: usize,
    key: &str,
    summary: &DirectionSummary,
    comma: bool,
) {
    write_json_key(out, indent, key);
    let _ = writeln!(out, "{{");
    write_json_u64(
        out,
        indent + 1,
        "sample_count",
        summary.sample_count as u64,
        true,
    );
    write_json_u64(out, indent + 1, "total_bytes", summary.total_bytes, true);
    write_json_f64(out, indent + 1, "median_mbps", summary.median_mbps, true);
    write_json_f64(out, indent + 1, "mean_mbps", summary.mean_mbps, true);
    write_json_f64(out, indent + 1, "min_mbps", summary.min_mbps, true);
    write_json_f64(out, indent + 1, "max_mbps", summary.max_mbps, true);
    write_json_f64(out, indent + 1, "stddev_mbps", summary.stddev_mbps, false);
    write_json_indent(out, indent);
    out.push('}');
    write_json_comma_newline(out, comma);
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, CryptoConfig, ServerConfig, TrafficConfig, UdpConfig};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use pqcrypto_mldsa::mldsa87;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    fn measurement(bytes: u64, millis: u64) -> PhaseMeasurement {
        PhaseMeasurement {
            bytes,
            elapsed: Duration::from_millis(millis),
        }
    }

    fn sample(index: u16, bytes: u64, millis: u64) -> SpeedSample {
        SpeedSample {
            index,
            measurement: measurement(bytes, millis),
        }
    }

    fn report() -> SpeedReport {
        let samples = vec![
            sample(1, 1_000_000, 100),
            sample(2, 1_000_000, 200),
            sample(3, 1_000_000, 400),
        ];
        SpeedReport {
            schema: REPORT_SCHEMA,
            generated_unix_ms: 1_762_000_000_000,
            protocol_name: PROTOCOL_NAME,
            protocol_version: PROTOCOL_VERSION,
            binary_version: env!("CARGO_PKG_VERSION"),
            config_fingerprint: "abc123".to_owned(),
            server_addr: "203.0.113.10:443".to_owned(),
            sni: "example.com".to_owned(),
            traffic: TrafficEvidence {
                min_padding: 0,
                max_padding: 0,
                min_delay_ms: 0,
                max_delay_ms: 0,
                cover_min_interval_ms: 0,
                cover_max_interval_ms: 0,
                max_concurrent_streams: 1,
            },
            max_payload_chunk_len: 16_366,
            plan: SpeedPlan::default(),
            handshake: measurement(0, 50),
            warmup_download: measurement(1024 * 1024, 100),
            warmup_upload: measurement(1024 * 1024, 120),
            download: DirectionReport::new(samples.clone()),
            upload: DirectionReport::new(samples),
        }
    }

    #[test]
    fn direction_summary_uses_all_samples() {
        let report = DirectionReport::new(vec![
            sample(1, 1_000_000, 100),
            sample(2, 1_000_000, 200),
            sample(3, 1_000_000, 400),
        ]);

        assert_eq!(report.summary.sample_count, 3);
        assert_eq!(report.summary.total_bytes, 3_000_000);
        assert!((report.summary.median_mbps - 40.0).abs() < f64::EPSILON);
        assert!((report.summary.min_mbps - 20.0).abs() < f64::EPSILON);
        assert!((report.summary.max_mbps - 80.0).abs() < f64::EPSILON);
        assert!(report.summary.stddev_mbps > 0.0);
    }

    #[test]
    fn speed_report_formats_evidence_text() {
        let text = report().to_text();

        assert!(text.contains("ParallaX speed evidence report"));
        assert!(text.contains("schema: parallax.speed.evidence.v1"));
        assert!(text.contains("config_fingerprint: abc123"));
        assert!(text.contains("download_summary: samples=3"));
        assert!(text.contains("upload_summary: samples=3"));
    }

    #[test]
    fn speed_report_formats_evidence_json() {
        let json = report().to_json();

        assert!(json.contains("\"schema\": \"parallax.speed.evidence.v1\""));
        assert!(json.contains("\"generated_unix_ms\": 1762000000000"));
        assert!(json.contains("\"config_fingerprint\": \"abc123\""));
        assert!(json.contains("\"median_mbps\": 40.000000"));
        assert!(json.contains("\"max_payload_chunk_len\": 16366"));
    }

    #[test]
    fn json_escape_handles_control_characters() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn megabits_per_second_handles_zero_elapsed() {
        let m = PhaseMeasurement {
            bytes: 1_000_000,
            elapsed: Duration::ZERO,
        };
        assert_eq!(m.megabits_per_second(), 0.0);
    }

    #[test]
    fn megabits_per_second_matches_formula() {
        let m = PhaseMeasurement {
            bytes: 1_250_000, // 10 Mbps over one second
            elapsed: Duration::from_secs(1),
        };
        assert!((m.megabits_per_second() - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn mebibytes_matches_formula() {
        let m = PhaseMeasurement {
            bytes: 2 * 1024 * 1024,
            elapsed: Duration::from_secs(1),
        };
        assert!((m.mebibytes() - 2.0).abs() < f64::EPSILON);
    }

    fn server_only_config() -> Config {
        Config {
            mode: Mode::Server,
            crypto: CryptoConfig {
                psk: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            },
            traffic: TrafficConfig::default(),
            udp: UdpConfig::default(),
            client: None,
            server: Some(ServerConfig {
                listen: "127.0.0.1:8443".parse::<SocketAddr>().unwrap(),
                fallback_addr: "fallback.example:443".to_owned(),
                data_target: None,
                private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                pq_secret_key: String::new(),
                identity_secret_key: STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]),
                replay_cache_path: PathBuf::from("/tmp/parallax-speed-test-replay.cache"),
                replay_cache_capacity: crate::config::DEFAULT_REPLAY_CACHE_CAPACITY,
                authorized_sni: vec!["example.com".to_owned()],
                strict_tls13: true,
            }),
        }
    }

    fn client_only_config() -> Config {
        Config {
            mode: Mode::Client,
            crypto: CryptoConfig {
                psk: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            },
            traffic: TrafficConfig::default(),
            udp: UdpConfig::default(),
            client: None,
            server: None,
        }
    }

    #[tokio::test]
    async fn run_rejects_server_mode() {
        let cfg = server_only_config();
        let err = run(cfg).await.unwrap_err();
        assert!(matches!(err, SpeedError::WrongMode));
    }

    #[tokio::test]
    async fn run_rejects_missing_client_section() {
        let cfg = client_only_config();
        let err = run(cfg).await.unwrap_err();
        assert!(matches!(err, SpeedError::MissingClient));
    }

    #[tokio::test]
    async fn run_propagates_invalid_psk() {
        let mut cfg = client_only_config();
        cfg.crypto.psk = "AA==".to_owned();
        cfg.client = Some(ClientConfig {
            listen: "127.0.0.1:1080".parse().unwrap(),
            server_addr: "example.com:443".to_owned(),
            sni: "example.com".to_owned(),
            server_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            server_pq_public_key: String::new(),
            server_identity_public_key: STANDARD.encode(vec![0_u8; mldsa87::public_key_bytes()]),
        });
        let err = run(cfg).await.unwrap_err();
        assert!(matches!(err, SpeedError::Config(ConfigError::WeakPsk)));
    }

    #[test]
    fn speed_error_messages_are_human_readable() {
        let err = SpeedError::UnexpectedAck {
            expected: SpeedTestAckKind::DownloadDone,
            actual: SpeedTestAckKind::UploadDone,
        };
        let text = err.to_string();
        assert!(text.contains("unexpected speed test ack"));
        assert!(text.contains("DownloadDone"));
        assert!(text.contains("UploadDone"));

        let mismatch = SpeedError::ByteCountMismatch {
            expected: 10,
            actual: 5,
        };
        assert!(mismatch
            .to_string()
            .contains("byte count mismatch: expected 10, got 5"));
        assert_eq!(
            SpeedError::TooManyBytes.to_string(),
            "speed test stream sent more bytes than requested"
        );
    }

    #[test]
    fn speed_upload_uses_relay_sized_batches() {
        let chunk_len = crate::protocol::data::max_plaintext_len(
            crate::config::TrafficConfig::default().max_padding,
        );
        let batch_len = relay_read_buffer_len(chunk_len);

        assert!(batch_len > chunk_len);
        assert_eq!(batch_len, crate::protocol::data::RELAY_READ_BUFFER_TARGET);
    }
}
