//! `plx netmatrix` — a reproducible controlled-network regression harness.
//!
//! It measures the REAL end-to-end data path (`speed::run`) across a fixed
//! matrix of network impairments, so a perf change can be checked against a
//! deterministic RTT × bandwidth sweep instead of only a raw-CPU benchmark.
//!
//! How it works without a second machine: between the speed-test client and the
//! configured server it interposes a loopback **shaper** — a transparent TCP
//! relay that adds one-way latency (a delay line, so throughput is not capped by
//! the delay) and an optional token-bucket bandwidth cap. The client's
//! `server_addr` is pointed at the shaper; the shaper forwards to the real
//! server, so the camouflage handshake, auth, PQ rekey and AEAD relay are all
//! exercised unchanged. The same configured server `plx speed` uses is required
//! (a real VPS, or a local `plx serve` against a reachable fallback origin).
//!
//! Honest limitation: a userspace TCP-stream shaper cannot emulate packet LOSS
//! or reordering (dropping stream bytes would corrupt TLS). Loss/reorder cells
//! need the Linux netns + `tc qdisc netem` arm, which is a separate slice; this
//! `--emulated` shaper covers latency and bandwidth, which are reproducible on
//! any one machine including macOS dev.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};

use crate::config::{Config, Mode};
use crate::speed::{self, SpeedReport};

/// One network-impairment profile applied symmetrically to both directions.
#[derive(Debug, Clone, Copy)]
struct Impairment {
    label: &'static str,
    /// Emulated round-trip time. Half is added one-way in each direction.
    rtt_ms: u64,
    /// Per-direction bandwidth cap in megabits/s, or `None` for unbounded.
    bandwidth_mbit: Option<u64>,
}

/// Fixed, reproducible matrix. Kept small so a full run stays minutes, not
/// hours: a clean-link RTT ladder, two bandwidth-constrained high-RTT rows, and
/// one named "real" China<->Germany-shaped profile.
const MATRIX: &[Impairment] = &[
    Impairment {
        label: "clean-0ms",
        rtt_ms: 0,
        bandwidth_mbit: None,
    },
    Impairment {
        label: "rtt-20ms",
        rtt_ms: 20,
        bandwidth_mbit: None,
    },
    Impairment {
        label: "rtt-80ms",
        rtt_ms: 80,
        bandwidth_mbit: None,
    },
    Impairment {
        label: "rtt-160ms",
        rtt_ms: 160,
        bandwidth_mbit: None,
    },
    Impairment {
        label: "rtt-160ms-bw-50",
        rtt_ms: 160,
        bandwidth_mbit: Some(50),
    },
    Impairment {
        label: "rtt-160ms-bw-20",
        rtt_ms: 160,
        bandwidth_mbit: Some(20),
    },
    Impairment {
        label: "rtt-320ms-bw-20",
        rtt_ms: 320,
        bandwidth_mbit: Some(20),
    },
    Impairment {
        label: "real-180ms-bw-60",
        rtt_ms: 180,
        bandwidth_mbit: Some(60),
    },
];

/// Token bucket pacing one direction to `bytes_per_sec`. `None` == unbounded.
struct TokenBucket {
    bytes_per_sec: Option<f64>,
    next: Instant,
}

impl TokenBucket {
    fn new(bandwidth_mbit: Option<u64>) -> Self {
        Self {
            // 1 Mbit/s = 1_000_000 bits/s = 125_000 bytes/s.
            bytes_per_sec: bandwidth_mbit.map(|m| m as f64 * 125_000.0),
            next: Instant::now(),
        }
    }

    /// Blocks until `n` bytes may be sent without exceeding the rate.
    async fn consume(&mut self, n: usize) {
        let Some(bps) = self.bytes_per_sec else {
            return;
        };
        let now = Instant::now();
        if self.next > now {
            sleep_until(self.next).await;
        }
        let base = self.next.max(now);
        self.next = base + Duration::from_secs_f64(n as f64 / bps);
    }
}

/// Relay one direction with an added-latency delay line + bandwidth cap. The
/// delay line (a bounded channel carrying per-chunk deliver-at timestamps)
/// decouples latency from throughput: reads keep flowing while chunks wait out
/// their delay, so a high RTT does not throttle goodput the way an inline
/// per-chunk `sleep` would.
async fn shape_direction<R, W>(mut reader: R, mut writer: W, imp: Impairment)
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let half_rtt = Duration::from_millis(imp.rtt_ms / 2);
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(1024);

    let read_task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 32 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let deliver_at = Instant::now() + half_rtt;
                    if tx.send((deliver_at, buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut bucket = TokenBucket::new(imp.bandwidth_mbit);
    while let Some((deliver_at, chunk)) = rx.recv().await {
        sleep_until(deliver_at).await;
        bucket.consume(chunk.len()).await;
        if writer.write_all(&chunk).await.is_err() {
            break;
        }
    }
    let _ = writer.flush().await;
    let _ = writer.shutdown().await;
    read_task.abort();
}

/// Binds a loopback shaper that forwards to `upstream`, applying `imp` to both
/// directions. Returns its local address and the accept-loop handle (abort it to
/// stop the shaper). `upstream` is the real server address (`host:port`).
async fn spawn_shaper(
    upstream: String,
    imp: Impairment,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((downstream, _)) = listener.accept().await else {
                return;
            };
            let upstream = upstream.clone();
            tokio::spawn(async move {
                let Ok(up) = TcpStream::connect(&upstream).await else {
                    return;
                };
                let _ = downstream.set_nodelay(true);
                let _ = up.set_nodelay(true);
                let (dr, dw) = downstream.into_split();
                let (ur, uw) = up.into_split();
                // client -> server and server -> client, each shaped.
                let to_server = tokio::spawn(shape_direction(dr, uw, imp));
                let to_client = tokio::spawn(shape_direction(ur, dw, imp));
                let _ = to_server.await;
                let _ = to_client.await;
            });
        }
    });
    Ok((addr, handle))
}

/// One matrix cell's result.
struct NetCell {
    imp: Impairment,
    outcome: Result<SpeedReport, String>,
}

/// Runs the full matrix against the configured server and prints a report.
pub async fn run(config: Config, json: bool) -> anyhow::Result<()> {
    if config.mode != Mode::Client {
        anyhow::bail!("netmatrix requires a client-mode config");
    }
    let upstream = config
        .client
        .as_ref()
        .map(|c| c.server_addr.clone())
        .ok_or_else(|| anyhow::anyhow!("netmatrix requires a [client] section"))?;

    let mut cells = Vec::with_capacity(MATRIX.len());
    for imp in MATRIX {
        let (shaper_addr, shaper) = spawn_shaper(upstream.clone(), *imp).await?;

        // Point the speed client at the shaper; everything else (keys, sni,
        // traffic, udp) is unchanged so the measured path is identical to prod.
        let mut cell_config = config.clone();
        if let Some(client) = cell_config.client.as_mut() {
            client.server_addr = shaper_addr.to_string();
        }

        let outcome = speed::run(cell_config).await.map_err(|e| e.to_string());
        shaper.abort();
        cells.push(NetCell { imp: *imp, outcome });
    }

    let rendered = if json {
        render_json(&upstream, &cells)
    } else {
        render_text(&upstream, &cells)
    };
    print!("{rendered}");
    Ok(())
}

fn render_text(upstream: &str, cells: &[NetCell]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "ParallaX netmatrix report (emulated shaper)");
    let _ = writeln!(out, "upstream server: {upstream}");
    let _ = writeln!(
        out,
        "{:<18} {:>9} {:>12} {:>14} {:>14}",
        "profile", "rtt_ms", "bw_mbit", "down_mbps", "up_mbps"
    );
    for cell in cells {
        let bw = cell
            .imp
            .bandwidth_mbit
            .map(|m| m.to_string())
            .unwrap_or_else(|| "inf".to_string());
        match &cell.outcome {
            Ok(report) => {
                let _ = writeln!(
                    out,
                    "{:<18} {:>9} {:>12} {:>14.2} {:>14.2}",
                    cell.imp.label,
                    cell.imp.rtt_ms,
                    bw,
                    report.download.summary.median_mbps,
                    report.upload.summary.median_mbps,
                );
            }
            Err(err) => {
                let _ = writeln!(
                    out,
                    "{:<18} {:>9} {:>12}  ERROR: {}",
                    cell.imp.label, cell.imp.rtt_ms, bw, err
                );
            }
        }
    }
    out
}

fn render_json(upstream: &str, cells: &[NetCell]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"schema\": \"parallax.netmatrix.v1\",");
    let _ = writeln!(out, "  \"upstream\": \"{}\",", json_escape(upstream));
    let _ = writeln!(out, "  \"cells\": [");
    for (i, cell) in cells.iter().enumerate() {
        let comma = if i + 1 < cells.len() { "," } else { "" };
        let bw = cell
            .imp
            .bandwidth_mbit
            .map(|m| m.to_string())
            .unwrap_or_else(|| "null".to_string());
        match &cell.outcome {
            Ok(report) => {
                let _ = writeln!(out, "    {{");
                let _ = writeln!(out, "      \"profile\": \"{}\",", cell.imp.label);
                let _ = writeln!(out, "      \"rtt_ms\": {},", cell.imp.rtt_ms);
                let _ = writeln!(out, "      \"bandwidth_mbit\": {bw},");
                let _ = writeln!(
                    out,
                    "      \"handshake_ms\": {:.3},",
                    report.handshake.elapsed.as_secs_f64() * 1000.0
                );
                let _ = writeln!(
                    out,
                    "      \"download_median_mbps\": {:.4},",
                    report.download.summary.median_mbps
                );
                let _ = writeln!(
                    out,
                    "      \"upload_median_mbps\": {:.4}",
                    report.upload.summary.median_mbps
                );
                let _ = writeln!(out, "    }}{comma}");
            }
            Err(err) => {
                let _ = writeln!(out, "    {{");
                let _ = writeln!(out, "      \"profile\": \"{}\",", cell.imp.label);
                let _ = writeln!(out, "      \"rtt_ms\": {},", cell.imp.rtt_ms);
                let _ = writeln!(out, "      \"bandwidth_mbit\": {bw},");
                let _ = writeln!(out, "      \"error\": \"{}\"", json_escape(err));
                let _ = writeln!(out, "    }}{comma}");
            }
        }
    }
    let _ = writeln!(out, "  ]");
    let _ = writeln!(out, "}}");
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// An echo upstream lets us measure what the shaper does to a transfer.
    async fn spawn_echo() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0_u8; 64 * 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn shaper_forwards_bytes_intact() {
        let (echo_addr, _echo) = spawn_echo().await;
        let imp = Impairment {
            label: "t",
            rtt_ms: 0,
            bandwidth_mbit: None,
        };
        let (shaper_addr, shaper) = spawn_shaper(echo_addr.to_string(), imp).await.unwrap();

        let mut c = TcpStream::connect(shaper_addr).await.unwrap();
        let payload = vec![0xab_u8; 48 * 1024];
        c.write_all(&payload).await.unwrap();
        let mut got = vec![0_u8; payload.len()];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "shaper must forward bytes byte-for-byte");
        shaper.abort();
    }

    #[tokio::test]
    async fn shaper_adds_round_trip_latency() {
        let (echo_addr, _echo) = spawn_echo().await;
        let imp = Impairment {
            label: "t",
            rtt_ms: 200,
            bandwidth_mbit: None,
        };
        let (shaper_addr, shaper) = spawn_shaper(echo_addr.to_string(), imp).await.unwrap();

        let mut c = TcpStream::connect(shaper_addr).await.unwrap();
        let start = std::time::Instant::now();
        c.write_all(b"ping").await.unwrap();
        let mut got = [0_u8; 4];
        c.read_exact(&mut got).await.unwrap();
        let elapsed = start.elapsed();
        // 200ms RTT split as 100ms each way -> ~200ms round trip through echo.
        assert!(
            elapsed >= Duration::from_millis(150),
            "expected ~200ms added RTT, saw {elapsed:?}"
        );
        shaper.abort();
    }

    #[tokio::test]
    async fn token_bucket_paces_throughput() {
        // 10 Mbit/s = 1_250_000 bytes/s, so a 125_000-byte chunk is 0.1s of
        // budget. The bucket lets the first chunk through free and paces the
        // rest, so 6 chunks incur ~5 x 0.1s = ~0.5s of real pacing (a transfer
        // of hundreds of chunks converges to the target rate).
        let mut bucket = TokenBucket::new(Some(10));
        let start = std::time::Instant::now();
        for _ in 0..6 {
            bucket.consume(125_000).await;
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(400) && elapsed <= Duration::from_millis(900),
            "10 Mbit/s should pace 6x125KB to ~0.5s, saw {elapsed:?}"
        );
    }
}
