//! `trafficgen`: application traffic scenario generator for the ParallaX lab.
//!
//! It drives representative application traffic (bulk download/upload,
//! interactive request/response, streaming video, VoIP-style call frames, and
//! parallel web-object bursts) through a ParallaX client's local SOCKS5 port to
//! a local HTTP origin sitting behind the ParallaX server:
//!   trafficgen -> (SOCKS5) -> plx client -> GFW box -> plx server -> origin
//!
//! For each run it speaks minimal HTTP/1.1 over the tunnel, measures
//! throughput / latency, writes a single `ScenarioOutcome` as pretty JSON, and
//! prints a one-line human summary to stderr. It never panics on I/O errors:
//! any failure (including a hang, caught by a per-scenario timeout) becomes a
//! failed `ScenarioOutcome` with a non-zero exit code.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use rand::Rng;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use gfw_lab::report::ScenarioOutcome;
use gfw_lab::scenario::{Scenario, ScenarioKind};
use gfw_lab::stats::Summary;

/// Overall wall-clock guard for any single scenario. A hang trips this and is
/// reported as a failure rather than blocking CI forever.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(120);

/// I/O chunk size for bulk transfers.
const CHUNK: usize = 64 * 1024;

/// Upload / echo payload fill byte.
const FILL: u8 = 0x5A;

#[derive(Parser)]
#[command(
    name = "trafficgen",
    about = "Drive traffic scenarios through a ParallaX client SOCKS5 port and measure them"
)]
struct Cli {
    /// The ParallaX client's SOCKS5 listener.
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: SocketAddr,
    /// SOCKS5 CONNECT target host (cosmetic; the server uses a fixed data_target).
    #[arg(long, default_value = "origin.internal")]
    connect_host: String,
    /// SOCKS5 CONNECT target port.
    #[arg(long, default_value_t = 80)]
    connect_port: u16,
    /// Scenario name (download/upload/bidirectional/serial/parallel/single-stream/video/call/web/
    /// large-upload/video-hd/web-heavy/chat/burst/api-poll/mixed/download-ramp).
    #[arg(long)]
    scenario: String,
    /// Label copied into the report's `link_profile`.
    #[arg(long, default_value = "unknown")]
    link_name: String,
    /// Where to write the JSON `ScenarioOutcome`.
    #[arg(long, default_value = "trafficgen-report.json")]
    report: String,

    // Optional overrides; when absent the per-scenario defaults are used.
    #[arg(long)]
    bytes: Option<u64>,
    #[arg(long)]
    concurrency: Option<usize>,
    #[arg(long)]
    iterations: Option<usize>,
    #[arg(long)]
    frame_bytes: Option<usize>,
    #[arg(long)]
    interval_ms: Option<u64>,
    #[arg(long)]
    video_kbps: Option<u32>,
    /// Per-scenario wall-clock timeout in seconds (default 120). Hostile links
    /// (high loss/latency) need a larger budget for bulk transfers.
    #[arg(long)]
    timeout_secs: Option<u64>,
}

/// Connection coordinates for a single SOCKS5-tunnelled HTTP conversation.
#[derive(Clone)]
struct Target {
    socks: SocketAddr,
    host: String,
    port: u16,
}

/// Measurements gathered by a scenario; mapped into a `ScenarioOutcome`.
#[derive(Default)]
struct Measurement {
    download_mbps: Option<f64>,
    upload_mbps: Option<f64>,
    rtt_ms: Option<Summary>,
    bytes_transferred: Option<u64>,
    detail: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let kind = match ScenarioKind::parse(&cli.scenario) {
        Some(k) => k,
        None => {
            let outcome = failed(
                cli.scenario.clone(),
                cli.link_name.clone(),
                format!("unknown scenario '{}'", cli.scenario),
            );
            finish(&cli.report, outcome);
        }
    };

    let scenario = build_scenario(kind, &cli);

    let timeout = cli
        .timeout_secs
        .map(Duration::from_secs)
        .unwrap_or(SCENARIO_TIMEOUT);
    let outcome = match tokio::time::timeout(timeout, run_scenario(&cli, &scenario)).await {
        Ok(Ok(m)) => ScenarioOutcome {
            scenario: kind.as_str().to_string(),
            link_profile: cli.link_name.clone(),
            ok: true,
            detail: m.detail,
            download_mbps: m.download_mbps,
            upload_mbps: m.upload_mbps,
            rtt_ms: m.rtt_ms,
            bytes_transferred: m.bytes_transferred,
        },
        Ok(Err(e)) => failed(
            kind.as_str().to_string(),
            cli.link_name.clone(),
            format!("{e:#}"),
        ),
        Err(_) => failed(
            kind.as_str().to_string(),
            cli.link_name.clone(),
            format!("timed out after {}s", timeout.as_secs()),
        ),
    };

    finish(&cli.report, outcome);
}

/// Apply CLI overrides on top of the per-scenario defaults.
fn build_scenario(kind: ScenarioKind, cli: &Cli) -> Scenario {
    let mut s = Scenario::default_for(kind);
    if let Some(v) = cli.bytes {
        s.bytes = v;
    }
    if let Some(v) = cli.concurrency {
        s.concurrency = v;
    }
    if let Some(v) = cli.iterations {
        s.iterations = v;
    }
    if let Some(v) = cli.frame_bytes {
        s.frame_bytes = v;
    }
    if let Some(v) = cli.interval_ms {
        s.interval_ms = v;
    }
    if let Some(v) = cli.video_kbps {
        s.video_kbps = v;
    }
    s
}

async fn run_scenario(cli: &Cli, s: &Scenario) -> Result<Measurement> {
    let target = Target {
        socks: cli.socks,
        host: cli.connect_host.clone(),
        port: cli.connect_port,
    };
    match s.kind {
        ScenarioKind::Download | ScenarioKind::SingleStream => {
            run_single_download(&target, s.bytes).await
        }
        ScenarioKind::Upload | ScenarioKind::LargeUpload => {
            run_single_upload(&target, s.bytes).await
        }
        ScenarioKind::Bidirectional => run_bidir(&target, s.bytes).await,
        ScenarioKind::Serial => run_serial(&target, s).await,
        ScenarioKind::Parallel | ScenarioKind::Web | ScenarioKind::WebHeavy => {
            run_parallel(&target, s.bytes, s.concurrency).await
        }
        ScenarioKind::Video | ScenarioKind::VideoHd => run_video(&target, s).await,
        ScenarioKind::Call => run_call(&target, s).await,
        ScenarioKind::Chat => run_chat(&target, s).await,
        ScenarioKind::Burst => run_burst(&target, s).await,
        ScenarioKind::ApiPoll => run_api_poll(&target, s).await,
        ScenarioKind::Mixed => run_mixed(&target, s).await,
        ScenarioKind::DownloadRamp => run_download_ramp(&target).await,
    }
}

// --------------------------------------------------------------------------
// Scenario implementations
// --------------------------------------------------------------------------

/// Bulk download (also serves single-stream, which only differs in size).
async fn run_single_download(t: &Target, bytes: u64) -> Result<Measurement> {
    let start = Instant::now();
    let got = download_once(t, bytes, 0).await?;
    let secs = start.elapsed().as_secs_f64();
    Ok(Measurement {
        download_mbps: Some(throughput_mbps(got, secs)),
        bytes_transferred: Some(got),
        detail: format!("downloaded {got} B in {secs:.3}s"),
        ..Default::default()
    })
}

async fn run_single_upload(t: &Target, bytes: u64) -> Result<Measurement> {
    let start = Instant::now();
    let sent = upload_once(t, bytes).await?;
    let secs = start.elapsed().as_secs_f64();
    Ok(Measurement {
        upload_mbps: Some(throughput_mbps(sent, secs)),
        bytes_transferred: Some(sent),
        detail: format!("uploaded {sent} B in {secs:.3}s"),
        ..Default::default()
    })
}

/// Concurrent download + upload on two separate tunnels; both throughputs are
/// computed over the shared wall-clock window they ran in.
async fn run_bidir(t: &Target, bytes: u64) -> Result<Measurement> {
    let start = Instant::now();
    let (dl, ul) = tokio::join!(download_once(t, bytes, 0), upload_once(t, bytes));
    let secs = start.elapsed().as_secs_f64();
    let down = dl?;
    let up = ul?;
    Ok(Measurement {
        download_mbps: Some(throughput_mbps(down, secs)),
        upload_mbps: Some(throughput_mbps(up, secs)),
        bytes_transferred: Some(down + up),
        detail: format!("bidir down {down} B / up {up} B in {secs:.3}s"),
        ..Default::default()
    })
}

/// Sequential request/response on one reused (keep-alive) tunnel, recording the
/// RTT of every exchange.
async fn run_serial(t: &Target, s: &Scenario) -> Result<Measurement> {
    let mut conn = HttpConn::connect(t).await?;
    let use_download = s.bytes > 0;
    let resp_size: u64 = if use_download { s.bytes } else { 4 };
    let mut rtts = Vec::with_capacity(s.iterations);
    let mut total = 0u64;

    for _ in 0..s.iterations {
        let t0 = Instant::now();
        if use_download {
            conn.write_all(download_req(&t.host, s.bytes, 0).as_bytes())
                .await?;
            conn.flush().await?;
            let head = conn.read_head().await?;
            if head.code != 200 {
                bail!("serial: unexpected status {}", head.code);
            }
            let cl = head
                .content_length
                .context("serial: missing Content-Length")?;
            if cl != s.bytes {
                bail!("serial: Content-Length {cl} != requested {}", s.bytes);
            }
            let got = conn.drain_exact(cl).await?;
            if got != cl {
                bail!("serial: short read {got} of {cl}");
            }
            total += got;
        } else {
            conn.write_all(ping_req(&t.host).as_bytes()).await?;
            conn.flush().await?;
            let head = conn.read_head().await?;
            if head.code != 200 {
                bail!("serial: unexpected status {}", head.code);
            }
            let cl = head
                .content_length
                .context("serial: missing Content-Length")?;
            let got = conn.drain_exact(cl).await?;
            if got != cl {
                bail!("serial: short read {got} of {cl}");
            }
            total += got;
        }
        rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
    }

    let expected = s.iterations as u64 * resp_size;
    if total != expected {
        bail!("serial: transferred {total} of expected {expected}");
    }
    let summary = Summary::of(&rtts);
    Ok(Measurement {
        rtt_ms: Some(summary.clone()),
        bytes_transferred: Some(total),
        detail: format!(
            "serial {} iters, median rtt {:.2}ms (min {:.2} / max {:.2})",
            s.iterations, summary.median, summary.min, summary.max
        ),
        ..Default::default()
    })
}

/// `concurrency` parallel download tunnels; aggregate throughput over the wall
/// clock during which they all ran. Also used for the web-page burst shape.
async fn run_parallel(t: &Target, bytes: u64, concurrency: usize) -> Result<Measurement> {
    let concurrency = concurrency.max(1);
    let start = Instant::now();
    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let t = t.clone();
        handles.push(tokio::spawn(
            async move { download_once(&t, bytes, 0).await },
        ));
    }
    let mut total = 0u64;
    for h in handles {
        let got = h.await.context("parallel: task join failed")??;
        total += got;
    }
    let secs = start.elapsed().as_secs_f64();
    let expected = bytes * concurrency as u64;
    if total != expected {
        bail!("parallel: transferred {total} of expected {expected}");
    }
    Ok(Measurement {
        download_mbps: Some(throughput_mbps(total, secs)),
        bytes_transferred: Some(total),
        detail: format!("{concurrency} streams x {bytes} B = {total} B in {secs:.3}s"),
        ..Default::default()
    })
}

/// Streaming-video shape: one paced download. Inter-chunk arrival gaps (ms) are
/// recorded as an RTT summary (a jitter proxy); throughput is over the whole
/// transfer.
async fn run_video(t: &Target, s: &Scenario) -> Result<Measurement> {
    // Total bytes for ~6s of play-out at the target bitrate, unless an explicit
    // --bytes override was supplied.
    let total_bytes = if s.bytes > 0 {
        s.bytes
    } else {
        (s.video_kbps as u64 * 1000 / 8) * 6
    };
    if total_bytes == 0 {
        bail!("video: computed zero bytes (set --video-kbps or --bytes)");
    }

    let mut conn = HttpConn::connect(t).await?;
    let start = Instant::now();
    conn.write_all(download_req(&t.host, total_bytes, s.video_kbps).as_bytes())
        .await?;
    conn.flush().await?;
    let head = conn.read_head().await?;
    if head.code != 200 {
        bail!("video: unexpected status {}", head.code);
    }
    let cl = head
        .content_length
        .context("video: missing Content-Length")?;
    if cl != total_bytes {
        bail!("video: Content-Length {cl} != requested {total_bytes}");
    }
    let (got, gaps) = conn.read_body_gaps(cl).await?;
    let secs = start.elapsed().as_secs_f64();
    if got != cl {
        bail!("video: short read {got} of {cl}");
    }
    let jitter = Summary::of(&gaps);
    Ok(Measurement {
        download_mbps: Some(throughput_mbps(got, secs)),
        rtt_ms: Some(jitter.clone()),
        bytes_transferred: Some(got),
        detail: format!(
            "video {got} B in {secs:.3}s @ {}kbps, chunk-gap median {:.2}ms",
            s.video_kbps, jitter.median
        ),
        ..Default::default()
    })
}

/// VoIP-style call: fixed-cadence small echo frames on one keep-alive tunnel;
/// per-frame round-trip time is recorded.
async fn run_call(t: &Target, s: &Scenario) -> Result<Measurement> {
    if s.frame_bytes == 0 {
        bail!("call: frame_bytes must be > 0");
    }
    let mut conn = HttpConn::connect(t).await?;
    let interval = Duration::from_millis(s.interval_ms);
    let frame = s.frame_bytes as u64;
    let mut rtts = Vec::with_capacity(s.iterations);
    let start = Instant::now();

    for i in 0..s.iterations {
        // Keep a steady send cadence relative to the first frame.
        let due = start + interval * i as u32;
        let now = Instant::now();
        if due > now {
            tokio::time::sleep(due - now).await;
        }

        let t0 = Instant::now();
        conn.write_all(
            format!(
                "POST /echo HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
                t.host, frame
            )
            .as_bytes(),
        )
        .await?;
        conn.write_fill(frame, FILL).await?;
        conn.flush().await?;

        let head = conn.read_head().await?;
        if head.code != 200 {
            bail!("call: unexpected status {}", head.code);
        }
        let cl = head
            .content_length
            .context("call: missing Content-Length")?;
        if cl != frame {
            bail!("call: echo Content-Length {cl} != frame {frame}");
        }
        let got = conn.drain_exact(cl).await?;
        if got != cl {
            bail!("call: short echo {got} of {cl}");
        }
        rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
    }

    let bytes = s.iterations as u64 * frame * 2;
    let summary = Summary::of(&rtts);
    Ok(Measurement {
        rtt_ms: Some(summary.clone()),
        bytes_transferred: Some(bytes),
        detail: format!(
            "call {} frames x {} B @ {}ms, median rtt {:.2}ms",
            s.iterations, s.frame_bytes, s.interval_ms, summary.median
        ),
        ..Default::default()
    })
}

/// Messaging shape: small echo frames on one keep-alive tunnel with a
/// randomized idle gap between sends (uniform in [interval_ms/4 ..
/// interval_ms*3]); per-message round-trip time is recorded.
async fn run_chat(t: &Target, s: &Scenario) -> Result<Measurement> {
    if s.frame_bytes == 0 {
        bail!("chat: frame_bytes must be > 0");
    }
    let mut conn = HttpConn::connect(t).await?;
    let frame = s.frame_bytes as u64;
    let mut rtts = Vec::with_capacity(s.iterations);

    for i in 0..s.iterations {
        // Sporadic, human-like pause before every message after the first.
        if i > 0 {
            let gap_ms = rand::thread_rng().gen_range(s.interval_ms / 4..=s.interval_ms * 3);
            tokio::time::sleep(Duration::from_millis(gap_ms)).await;
        }

        let t0 = Instant::now();
        conn.write_all(
            format!(
                "POST /echo HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
                t.host, frame
            )
            .as_bytes(),
        )
        .await?;
        conn.write_fill(frame, FILL).await?;
        conn.flush().await?;

        let head = conn.read_head().await?;
        if head.code != 200 {
            bail!("chat: unexpected status {}", head.code);
        }
        let cl = head
            .content_length
            .context("chat: missing Content-Length")?;
        if cl != frame {
            bail!("chat: echo Content-Length {cl} != frame {frame}");
        }
        let got = conn.drain_exact(cl).await?;
        if got != cl {
            bail!("chat: short echo {got} of {cl}");
        }
        rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
    }

    let bytes = s.iterations as u64 * frame * 2;
    let summary = Summary::of(&rtts);
    Ok(Measurement {
        rtt_ms: Some(summary.clone()),
        bytes_transferred: Some(bytes),
        detail: format!(
            "chat {} msgs x {} B, gaps [{}..{}]ms, median rtt {:.2}ms",
            s.iterations,
            s.frame_bytes,
            s.interval_ms / 4,
            s.interval_ms * 3,
            summary.median
        ),
        ..Default::default()
    })
}

/// On/off browsing shape: `iterations` cycles of one download then an idle
/// gap, all on one keep-alive tunnel. Throughput is over the ACTIVE transfer
/// time only (idle sleeps excluded).
async fn run_burst(t: &Target, s: &Scenario) -> Result<Measurement> {
    if s.bytes == 0 {
        bail!("burst: bytes must be > 0");
    }
    let mut conn = HttpConn::connect(t).await?;
    let mut active = Duration::ZERO;
    let mut total = 0u64;

    for i in 0..s.iterations {
        let t0 = Instant::now();
        conn.write_all(download_req(&t.host, s.bytes, 0).as_bytes())
            .await?;
        conn.flush().await?;
        let head = conn.read_head().await?;
        if head.code != 200 {
            bail!("burst: unexpected status {}", head.code);
        }
        let cl = head
            .content_length
            .context("burst: missing Content-Length")?;
        if cl != s.bytes {
            bail!("burst: Content-Length {cl} != requested {}", s.bytes);
        }
        let got = conn.drain_exact(cl).await?;
        if got != cl {
            bail!("burst: short read {got} of {cl}");
        }
        active += t0.elapsed();
        total += got;
        // Idle gap between bursts (skipped after the last one).
        if i + 1 < s.iterations {
            tokio::time::sleep(Duration::from_millis(s.interval_ms)).await;
        }
    }

    let expected = s.iterations as u64 * s.bytes;
    if total != expected {
        bail!("burst: transferred {total} of expected {expected}");
    }
    let secs = active.as_secs_f64();
    Ok(Measurement {
        download_mbps: Some(throughput_mbps(total, secs)),
        bytes_transferred: Some(total),
        detail: format!(
            "burst {} cycles x {} B = {total} B, active {secs:.3}s, idle {}ms/cycle",
            s.iterations, s.bytes, s.interval_ms
        ),
        ..Default::default()
    })
}

/// API-polling shape: small `GET /ping` requests at a fixed cadence on one
/// keep-alive tunnel; per-request round-trip time is recorded.
async fn run_api_poll(t: &Target, s: &Scenario) -> Result<Measurement> {
    let mut conn = HttpConn::connect(t).await?;
    let interval = Duration::from_millis(s.interval_ms);
    let mut rtts = Vec::with_capacity(s.iterations);
    let mut total = 0u64;
    let start = Instant::now();

    for i in 0..s.iterations {
        // Keep a fixed polling cadence relative to the first request.
        let due = start + interval * i as u32;
        let now = Instant::now();
        if due > now {
            tokio::time::sleep(due - now).await;
        }

        let t0 = Instant::now();
        conn.write_all(ping_req(&t.host).as_bytes()).await?;
        conn.flush().await?;
        let head = conn.read_head().await?;
        if head.code != 200 {
            bail!("api-poll: unexpected status {}", head.code);
        }
        let cl = head
            .content_length
            .context("api-poll: missing Content-Length")?;
        let got = conn.drain_exact(cl).await?;
        if got != cl {
            bail!("api-poll: short read {got} of {cl}");
        }
        total += got;
        rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
    }

    // `/ping` replies with the 4-byte body "pong".
    let expected = s.iterations as u64 * 4;
    if total != expected {
        bail!("api-poll: transferred {total} of expected {expected}");
    }
    let summary = Summary::of(&rtts);
    Ok(Measurement {
        rtt_ms: Some(summary.clone()),
        bytes_transferred: Some(total),
        detail: format!(
            "api-poll {} reqs @ {}ms, median rtt {:.2}ms",
            s.iterations, s.interval_ms, summary.median
        ),
        ..Default::default()
    })
}

/// Multitask shape: a paced video downlink and a VoIP-style call run
/// concurrently on separate tunnels. Throughput comes from the video leg and
/// the RTT summary from the call leg; ok requires both legs to succeed.
async fn run_mixed(t: &Target, s: &Scenario) -> Result<Measurement> {
    let video = Scenario {
        kind: ScenarioKind::Video,
        bytes: s.bytes,
        concurrency: 1,
        iterations: 1,
        frame_bytes: 0,
        interval_ms: 0,
        video_kbps: s.video_kbps,
    };
    let call = Scenario {
        kind: ScenarioKind::Call,
        bytes: 0,
        concurrency: 1,
        iterations: s.iterations,
        frame_bytes: s.frame_bytes,
        interval_ms: s.interval_ms,
        video_kbps: 0,
    };

    let (v, c) = tokio::join!(run_video(t, &video), run_call(t, &call));
    let v = v.context("mixed: video leg failed")?;
    let c = c.context("mixed: call leg failed")?;

    let bytes = v.bytes_transferred.unwrap_or(0) + c.bytes_transferred.unwrap_or(0);
    Ok(Measurement {
        download_mbps: v.download_mbps,
        rtt_ms: c.rtt_ms,
        bytes_transferred: Some(bytes),
        detail: format!("mixed: video [{}] + call [{}]", v.detail, c.detail),
        ..Default::default()
    })
}

/// Object sizes for the download-ramp scenario: 64 KiB, 256 KiB, 1 MiB, 4 MiB.
const RAMP_SIZES: [u64; 4] = [64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024];

/// Ramp shape: sequential downloads of increasing size on one keep-alive
/// tunnel; aggregate throughput is over the total transfer time.
async fn run_download_ramp(t: &Target) -> Result<Measurement> {
    let mut conn = HttpConn::connect(t).await?;
    let start = Instant::now();
    let mut total = 0u64;

    for bytes in RAMP_SIZES {
        conn.write_all(download_req(&t.host, bytes, 0).as_bytes())
            .await?;
        conn.flush().await?;
        let head = conn.read_head().await?;
        if head.code != 200 {
            bail!("download-ramp: unexpected status {}", head.code);
        }
        let cl = head
            .content_length
            .context("download-ramp: missing Content-Length")?;
        if cl != bytes {
            bail!("download-ramp: Content-Length {cl} != requested {bytes}");
        }
        let got = conn.drain_exact(cl).await?;
        if got != cl {
            bail!("download-ramp: short read {got} of {bytes}");
        }
        total += got;
    }

    let secs = start.elapsed().as_secs_f64();
    let expected: u64 = RAMP_SIZES.iter().sum();
    if total != expected {
        bail!("download-ramp: transferred {total} of expected {expected}");
    }
    Ok(Measurement {
        download_mbps: Some(throughput_mbps(total, secs)),
        bytes_transferred: Some(total),
        detail: format!("ramp {RAMP_SIZES:?} = {total} B in {secs:.3}s"),
        ..Default::default()
    })
}

// --------------------------------------------------------------------------
// One-shot transfer primitives (each opens its own tunnel)
// --------------------------------------------------------------------------

/// Open a tunnel, request `bytes` from `/download`, and read exactly that many
/// body bytes. Returns the number of bytes actually read (verified == `bytes`).
async fn download_once(t: &Target, bytes: u64, rate_kbps: u32) -> Result<u64> {
    let mut conn = HttpConn::connect(t).await?;
    conn.write_all(download_req(&t.host, bytes, rate_kbps).as_bytes())
        .await?;
    conn.flush().await?;
    let head = conn.read_head().await?;
    if head.code != 200 {
        bail!("download: unexpected status {}", head.code);
    }
    let cl = head
        .content_length
        .context("download: missing Content-Length")?;
    if cl != bytes {
        bail!("download: Content-Length {cl} != requested {bytes}");
    }
    let got = conn.drain_exact(cl).await?;
    if got != bytes {
        bail!("download: short read {got} of {bytes}");
    }
    Ok(got)
}

/// Open a tunnel and POST `bytes` to `/upload`; drain the JSON acknowledgement.
async fn upload_once(t: &Target, bytes: u64) -> Result<u64> {
    let mut conn = HttpConn::connect(t).await?;
    conn.write_all(
        format!(
            "POST /upload HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
            t.host, bytes
        )
        .as_bytes(),
    )
    .await?;
    conn.write_fill(bytes, FILL).await?;
    conn.flush().await?;
    let head = conn.read_head().await?;
    if head.code != 200 {
        bail!("upload: unexpected status {}", head.code);
    }
    let cl = head.content_length.unwrap_or(0);
    conn.drain_exact(cl).await?;
    Ok(bytes)
}

// --------------------------------------------------------------------------
// HTTP request builders
// --------------------------------------------------------------------------

fn download_req(host: &str, bytes: u64, rate_kbps: u32) -> String {
    format!("GET /download?bytes={bytes}&rate_kbps={rate_kbps} HTTP/1.1\r\nHost: {host}\r\n\r\n")
}

fn ping_req(host: &str) -> String {
    format!("GET /ping HTTP/1.1\r\nHost: {host}\r\n\r\n")
}

// --------------------------------------------------------------------------
// Minimal HTTP/1.1 connection over a SOCKS5-tunnelled stream
// --------------------------------------------------------------------------

/// Parsed HTTP response head.
struct HttpHead {
    code: u16,
    content_length: Option<u64>,
}

/// A keep-alive-capable HTTP/1.1 connection. The `BufReader` lets us read the
/// status line and headers line-by-line and then read the body exactly, while
/// still writing requests directly to the underlying socket.
struct HttpConn {
    inner: BufReader<TcpStream>,
}

impl HttpConn {
    async fn connect(t: &Target) -> Result<Self> {
        let raw = socks_connect(t.socks, &t.host, t.port).await?;
        Ok(Self {
            inner: BufReader::new(raw),
        })
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.inner.write_all(buf).await?;
        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await?;
        Ok(())
    }

    /// Write `n` bytes of `fill` as a request/echo body.
    async fn write_fill(&mut self, n: u64, fill: u8) -> Result<()> {
        let chunk = vec![fill; CHUNK];
        let mut remaining = n;
        while remaining > 0 {
            let w = remaining.min(chunk.len() as u64) as usize;
            self.inner.write_all(&chunk[..w]).await?;
            remaining -= w as u64;
        }
        Ok(())
    }

    /// Read the status line and headers up to the blank CRLF line, returning the
    /// status code and any `Content-Length`.
    async fn read_head(&mut self) -> Result<HttpHead> {
        let mut line = Vec::new();
        let n = self.inner.read_until(b'\n', &mut line).await?;
        if n == 0 {
            bail!("connection closed before response");
        }
        let status = String::from_utf8_lossy(&line);
        let code: u16 = status
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .with_context(|| format!("malformed status line: {:?}", status.trim_end()))?;

        let mut content_length: Option<u64> = None;
        loop {
            line.clear();
            let n = self.inner.read_until(b'\n', &mut line).await?;
            if n == 0 {
                bail!("connection closed during headers");
            }
            if line.iter().all(|&b| b == b'\r' || b == b'\n') {
                break;
            }
            if let Some(idx) = line.iter().position(|&b| b == b':') {
                if line[..idx].eq_ignore_ascii_case(b"content-length") {
                    let val = String::from_utf8_lossy(&line[idx + 1..]);
                    content_length = val.trim().parse().ok();
                }
            }
        }
        Ok(HttpHead {
            code,
            content_length,
        })
    }

    /// Read and discard exactly `n` body bytes, returning how many were read
    /// (short of `n` only if the peer closed early).
    async fn drain_exact(&mut self, n: u64) -> Result<u64> {
        let mut buf = vec![0u8; CHUNK];
        let mut remaining = n;
        let mut total = 0u64;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let m = self.inner.read(&mut buf[..want]).await?;
            if m == 0 {
                break;
            }
            remaining -= m as u64;
            total += m as u64;
        }
        Ok(total)
    }

    /// Read exactly `n` body bytes, recording the inter-chunk arrival gaps (ms)
    /// as a jitter proxy. Returns `(bytes_read, gaps)`.
    async fn read_body_gaps(&mut self, n: u64) -> Result<(u64, Vec<f64>)> {
        let mut buf = vec![0u8; CHUNK];
        let mut remaining = n;
        let mut total = 0u64;
        let mut gaps = Vec::new();
        let mut last: Option<Instant> = None;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let m = self.inner.read(&mut buf[..want]).await?;
            if m == 0 {
                break;
            }
            let now = Instant::now();
            if let Some(prev) = last {
                gaps.push((now - prev).as_secs_f64() * 1000.0);
            }
            last = Some(now);
            remaining -= m as u64;
            total += m as u64;
        }
        Ok((total, gaps))
    }
}

// --------------------------------------------------------------------------
// SOCKS5 (RFC 1928, no auth) client
// --------------------------------------------------------------------------

/// Establish a SOCKS5 CONNECT tunnel via `socks` to `host:port` and return the
/// resulting raw stream (a transparent tunnel to the origin). The reply's
/// bound-address is consumed exactly so no origin bytes are lost.
async fn socks_connect(socks: SocketAddr, host: &str, port: u16) -> Result<TcpStream> {
    let mut s = TcpStream::connect(socks)
        .await
        .with_context(|| format!("connect SOCKS5 {socks}"))?;
    s.set_nodelay(true).ok();

    // Greeting: VER=5, one method, NO-AUTH(0x00).
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel != [0x05, 0x00] {
        bail!("SOCKS5 method negotiation failed: {sel:?}");
    }

    // CONNECT with DOMAINNAME atyp.
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        bail!("SOCKS5 host name too long: {} bytes", host_bytes.len());
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    // Reply: VER, REP, RSV, ATYP, then a bound address we must consume.
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("SOCKS5 bad reply version {}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("SOCKS5 CONNECT rejected, rep={}", head[1]);
    }
    match head[3] {
        0x01 => {
            let mut addr = [0u8; 4 + 2];
            s.read_exact(&mut addr).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut addr = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut addr).await?;
        }
        0x04 => {
            let mut addr = [0u8; 16 + 2];
            s.read_exact(&mut addr).await?;
        }
        other => bail!("SOCKS5 unknown reply atyp {other}"),
    }
    Ok(s)
}

// --------------------------------------------------------------------------
// Helpers + reporting
// --------------------------------------------------------------------------

/// Megabits per second for `bytes` transferred over `secs`.
fn throughput_mbps(bytes: u64, secs: f64) -> f64 {
    if secs > 0.0 {
        bytes as f64 * 8.0 / 1e6 / secs
    } else {
        0.0
    }
}

fn failed(scenario: String, link_profile: String, detail: String) -> ScenarioOutcome {
    ScenarioOutcome {
        scenario,
        link_profile,
        ok: false,
        detail,
        download_mbps: None,
        upload_mbps: None,
        rtt_ms: None,
        bytes_transferred: None,
    }
}

/// Write the report, print a one-line summary to stderr, and exit (0 on ok).
fn finish(report_path: &str, outcome: ScenarioOutcome) -> ! {
    let down = outcome
        .download_mbps
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "-".to_string());
    let up = outcome
        .upload_mbps
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "-".to_string());
    let rtt = outcome
        .rtt_ms
        .as_ref()
        .map(|s| format!("{:.2}", s.median))
        .unwrap_or_else(|| "-".to_string());
    let bytes = outcome
        .bytes_transferred
        .map(|b| b.to_string())
        .unwrap_or_else(|| "-".to_string());
    eprintln!(
        "trafficgen[{}/{}] ok={} down={down}Mbps up={up}Mbps rtt_med={rtt}ms bytes={bytes} :: {}",
        outcome.scenario, outcome.link_profile, outcome.ok, outcome.detail
    );

    let mut code = if outcome.ok { 0 } else { 1 };
    match serde_json::to_string_pretty(&outcome) {
        Ok(json) => {
            if let Err(e) = std::fs::write(report_path, json) {
                eprintln!("trafficgen: failed to write report {report_path}: {e}");
                code = 1;
            }
        }
        Err(e) => {
            eprintln!("trafficgen: failed to serialize report: {e}");
            code = 1;
        }
    }
    std::process::exit(code);
}
