//! `gfw-box`: a man-in-the-middle "censor" that sits between the ParallaX
//! client and server. It transparently relays the wire traffic while (a)
//! applying a configurable link-quality profile in userspace and (b) passively
//! analysing every flow for proxy/obfuscation distinguishers. A separate
//! `probe` subcommand actively probes the ParallaX server the way a censor
//! would, and compares its behaviour to a reference TLS origin.
//!
//! This is a CI/test tool, not a production component.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use gfw_lab::analyze::{analyze_flow, FlowObservation};
use gfw_lab::link::LinkProfile;
use gfw_lab::report::{ActiveProbeReport, ActiveProbeResult, FlowFeatures, GfwBoxReport};

#[derive(Parser)]
#[command(
    name = "gfw-box",
    about = "MITM link-impairment + traffic-analysis censor for the ParallaX lab"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Relay + impair + passively analyse client<->server traffic.
    Relay(RelayArgs),
    /// Actively probe the ParallaX server and compare to a reference origin.
    Probe(ProbeArgs),
}

#[derive(Parser)]
struct RelayArgs {
    /// Address the ParallaX client should dial (the censor's TCP ingress).
    #[arg(long, default_value = "127.0.0.1:9443")]
    listen: SocketAddr,
    /// Real ParallaX server TCP address to forward to.
    #[arg(long, default_value = "127.0.0.1:8443")]
    upstream: SocketAddr,
    /// Also relay the QUIC/UDP fast plane on this UDP ingress (optional).
    #[arg(long)]
    udp_listen: Option<SocketAddr>,
    /// Real ParallaX server UDP address to forward to (required with --udp-listen).
    #[arg(long)]
    udp_upstream: Option<SocketAddr>,
    /// Named link profile (perfect, broadband, mobile_4g, mobile_3g,
    /// transpacific, lossy, satellite).
    #[arg(long, default_value = "perfect")]
    profile: String,
    /// Where to write the JSON analysis report on shutdown.
    #[arg(long, default_value = "gfw-box-report.json")]
    report: String,
    /// Optional auto-stop after N seconds (0 = run until SIGINT/SIGTERM).
    #[arg(long, default_value_t = 0)]
    duration_secs: u64,
}

#[derive(Parser)]
struct ProbeArgs {
    /// ParallaX server address to probe.
    #[arg(long, default_value = "127.0.0.1:8443")]
    server: SocketAddr,
    /// Reference TLS origin (host:port) the server camouflages as, for A/B.
    #[arg(long, default_value = "www.cloudflare.com:443")]
    reference: String,
    /// SNI to present in TLS probes.
    #[arg(long, default_value = "www.cloudflare.com")]
    sni: String,
    /// Where to write the JSON probe report.
    #[arg(long, default_value = "gfw-probe-report.json")]
    report: String,
}

/// Per-flow accumulator shared by the two relay directions.
///
/// A snapshot of every accumulator (open or closed) is analysed at report time,
/// because ParallaX uses long-lived multiplexed connections that typically stay
/// open for the whole measurement window — and a real middle-box classifies a
/// flow from what it has seen so far, without waiting for it to close.
#[derive(Default)]
struct FlowAcc {
    flow_id: u64,
    client_addr: String,
    start: Option<Instant>,
    bytes_c2s: u64,
    bytes_s2c: u64,
    seg_sizes: Vec<f64>,
    segments_c2s: usize,
    segments_s2c: usize,
    c2s_gaps_ms: Vec<f64>,
    last_c2s: Option<Instant>,
    first_flight: Vec<u8>,
}

/// Shared registry of all flow accumulators seen this window.
type FlowRegistry = Arc<Mutex<Vec<Arc<Mutex<FlowAcc>>>>>;

const FIRST_FLIGHT_CAP: usize = 2048;

#[derive(Default)]
struct UdpCounters {
    forwarded: AtomicU64,
    dropped: AtomicU64,
    reordered: AtomicU64,
    duplicated: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Relay(args) => run_relay(args).await,
        Command::Probe(args) => run_probe(args).await,
    }
}

async fn run_relay(args: RelayArgs) -> Result<()> {
    let profile = LinkProfile::preset(&args.profile)
        .with_context(|| format!("unknown link profile: {}", args.profile))?;
    eprintln!(
        "gfw-box relay: listen={} upstream={} profile={} (latency={}ms jitter={}ms bw={}kbps loss={}%)",
        args.listen, args.upstream, profile.name, profile.latency_ms, profile.jitter_ms,
        profile.bandwidth_kbps, profile.loss_pct
    );

    let flows: FlowRegistry = Arc::new(Mutex::new(Vec::new()));
    let udp = Arc::new(UdpCounters::default());

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind TCP {}", args.listen))?;

    if let (Some(ul), Some(uu)) = (args.udp_listen, args.udp_upstream) {
        let profile = profile.clone();
        let udp = Arc::clone(&udp);
        tokio::spawn(async move {
            if let Err(e) = run_udp_relay(ul, uu, profile, udp).await {
                eprintln!("gfw-box udp relay ended: {e:#}");
            }
        });
    }

    let flow_id = Arc::new(AtomicU64::new(0));
    let accept_loop = {
        let flows = Arc::clone(&flows);
        let profile = profile.clone();
        let flow_id = Arc::clone(&flow_id);
        async move {
            loop {
                let (client, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("gfw-box accept error: {e}");
                        continue;
                    }
                };
                let id = flow_id.fetch_add(1, Ordering::Relaxed);
                let flows = Arc::clone(&flows);
                let profile = profile.clone();
                let upstream = args.upstream;
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(id, client, peer, upstream, profile, flows).await {
                        eprintln!("gfw-box flow {id} ended: {e}");
                    }
                });
            }
        }
    };

    // Run until SIGINT/SIGTERM or the optional duration elapses.
    if args.duration_secs > 0 {
        tokio::select! {
            _ = accept_loop => {}
            _ = tokio::time::sleep(Duration::from_secs(args.duration_secs)) => {}
            _ = shutdown_signal() => {}
        }
    } else {
        tokio::select! {
            _ = accept_loop => {}
            _ = shutdown_signal() => {}
        }
    }

    // Give in-flight flows a moment to finalize, then analyze + report.
    tokio::time::sleep(Duration::from_millis(400)).await;
    write_report(&args.report, &profile, &flows, &udp)?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = ctrl_c.await;
                return;
            }
        };
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

async fn handle_conn(
    flow_id: u64,
    client: TcpStream,
    peer: SocketAddr,
    upstream: SocketAddr,
    profile: LinkProfile,
    flows: FlowRegistry,
) -> Result<()> {
    let server = TcpStream::connect(upstream)
        .await
        .with_context(|| format!("connect upstream {upstream}"))?;
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);

    let (cr, cw) = client.into_split();
    let (sr, sw) = server.into_split();

    let acc = Arc::new(Mutex::new(FlowAcc {
        flow_id,
        client_addr: peer.to_string(),
        start: Some(Instant::now()),
        ..Default::default()
    }));
    // Register the accumulator immediately so an open, long-lived flow is still
    // analysed when the report is written at shutdown.
    flows.lock().unwrap().push(Arc::clone(&acc));

    // client -> server (this is the direction the censor fingerprints first)
    let c2s = spawn_direction(cr, sw, profile.clone(), Arc::clone(&acc), Direction::C2S);
    // server -> client
    let s2c = spawn_direction(sr, cw, profile.clone(), Arc::clone(&acc), Direction::S2C);

    let _ = c2s.await;
    let _ = s2c.await;
    Ok(())
}

/// Take a consistent snapshot of a (possibly still-open) accumulator.
fn snapshot(acc: &Arc<Mutex<FlowAcc>>) -> FlowObservation {
    let g = acc.lock().unwrap();
    let duration_ms = g
        .start
        .map(|s| s.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    FlowObservation {
        flow_id: g.flow_id,
        client_addr: g.client_addr.clone(),
        duration_ms,
        bytes_c2s: g.bytes_c2s,
        bytes_s2c: g.bytes_s2c,
        seg_sizes: g.seg_sizes.clone(),
        segments_c2s: g.segments_c2s,
        segments_s2c: g.segments_s2c,
        c2s_gaps_ms: g.c2s_gaps_ms.clone(),
        first_flight: g.first_flight.clone(),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Direction {
    C2S,
    S2C,
}

/// Spawn a one-directional relay with a decoupled delay line: the reader never
/// blocks on latency, it only enqueues; the writer applies per-chunk latency
/// (with jitter) and a token-bucket bandwidth cap. This models a link far more
/// faithfully than sleeping inline before each read.
fn spawn_direction<R, W>(
    mut reader: R,
    mut writer: W,
    profile: LinkProfile,
    acc: Arc<Mutex<FlowAcc>>,
    dir: Direction,
) -> tokio::task::JoinHandle<()>
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, Instant)>(1024);

    // Writer half: honour latency + bandwidth, preserve order.
    let bw_bps = profile.bandwidth_kbps as u64 * 1000;
    let writer_task = tokio::spawn(async move {
        let mut next_free = Instant::now();
        while let Some((buf, enqueued)) = rx.recv().await {
            let delay_ms = {
                let mut rng = rand::thread_rng();
                profile.sample_delay_ms(&mut rng)
            };
            let deliver_at = enqueued + Duration::from_millis(delay_ms as u64);
            let now = Instant::now();
            if deliver_at > now {
                tokio::time::sleep(deliver_at - now).await;
            }
            if bw_bps > 0 {
                // Token-bucket pacing: time to serialise these bytes.
                let serialise = Duration::from_secs_f64((buf.len() as f64 * 8.0) / bw_bps as f64);
                let now = Instant::now();
                let start = next_free.max(now);
                if start > now {
                    tokio::time::sleep(start - now).await;
                }
                next_free = start + serialise;
            }
            if writer.write_all(&buf).await.is_err() {
                break;
            }
        }
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
    });

    // Reader half: record features + enqueue.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let chunk = &buf[..n];
            {
                let mut a = acc.lock().unwrap();
                a.seg_sizes.push(n as f64);
                match dir {
                    Direction::C2S => {
                        a.bytes_c2s += n as u64;
                        a.segments_c2s += 1;
                        let now = Instant::now();
                        if let Some(prev) = a.last_c2s {
                            a.c2s_gaps_ms
                                .push(now.duration_since(prev).as_secs_f64() * 1000.0);
                        }
                        a.last_c2s = Some(now);
                        if a.first_flight.len() < FIRST_FLIGHT_CAP {
                            let take = (FIRST_FLIGHT_CAP - a.first_flight.len()).min(n);
                            a.first_flight.extend_from_slice(&chunk[..take]);
                        }
                    }
                    Direction::S2C => {
                        a.bytes_s2c += n as u64;
                        a.segments_s2c += 1;
                    }
                }
            }
            if tx.send((chunk.to_vec(), Instant::now())).await.is_err() {
                break;
            }
        }
        // Dropping tx closes the channel; the writer drains then shuts down.
        drop(tx);
        writer_task.await.ok();
    })
}

/// Symmetric-NAT UDP relay: one ingress socket, one dedicated upstream socket
/// per client 4-tuple. This is what makes the QUIC fast plane's *concurrent*
/// connections work — each client source port gets its own upstream socket, so
/// server replies are demultiplexed back to the right client (a single-client
/// relay would cross-deliver once more than one QUIC flow exists).
async fn run_udp_relay(
    listen: SocketAddr,
    upstream: SocketAddr,
    profile: LinkProfile,
    counters: Arc<UdpCounters>,
) -> Result<()> {
    let ingress = Arc::new(UdpSocket::bind(listen).await.context("bind udp")?);
    eprintln!("gfw-box udp relay (multi-client): listen={listen} upstream={upstream}");
    // client_addr -> upstream socket dedicated to that client.
    let table: Arc<Mutex<std::collections::HashMap<SocketAddr, Arc<UdpSocket>>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    let mut buf = vec![0u8; 65535];
    loop {
        let (n, client) = match ingress.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("udp ingress recv error: {e}");
                continue;
            }
        };
        let datagram = buf[..n].to_vec();

        // Get-or-create the dedicated upstream socket for this client.
        let up = {
            let existing = table.lock().unwrap().get(&client).cloned();
            match existing {
                Some(s) => s,
                None => {
                    let s = match UdpSocket::bind(("127.0.0.1", 0)).await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            eprintln!("udp upstream bind error: {e}");
                            continue;
                        }
                    };
                    if let Err(e) = s.connect(upstream).await {
                        eprintln!("udp upstream connect error: {e}");
                        continue;
                    }
                    table.lock().unwrap().insert(client, Arc::clone(&s));
                    // Spawn the return-path pump: upstream -> (impair) -> client.
                    spawn_udp_return_pump(
                        Arc::clone(&ingress),
                        Arc::clone(&s),
                        client,
                        profile.clone(),
                        Arc::clone(&counters),
                    );
                    s
                }
            }
        };

        forward_datagram_impaired(
            UdpDest::Upstream(up),
            datagram,
            &profile,
            Arc::clone(&counters),
        );
    }
}

/// Where an impaired datagram should be sent.
enum UdpDest {
    /// Send to the connected upstream socket.
    Upstream(Arc<UdpSocket>),
    /// Send back to a specific client via the ingress socket.
    Client(Arc<UdpSocket>, SocketAddr),
}

/// Apply loss/dup/reorder/latency then deliver the datagram (spawns tasks for
/// delayed / duplicated copies so ordering can genuinely change).
fn forward_datagram_impaired(
    dest: UdpDest,
    datagram: Vec<u8>,
    profile: &LinkProfile,
    counters: Arc<UdpCounters>,
) {
    let (drop, dup, extra_reorder_ms, delay_ms) = {
        let mut rng = rand::thread_rng();
        let drop = rng.gen_bool((profile.loss_pct / 100.0).clamp(0.0, 1.0));
        let dup = rng.gen_bool((profile.dup_pct / 100.0).clamp(0.0, 1.0));
        let reorder = rng.gen_bool((profile.reorder_pct / 100.0).clamp(0.0, 1.0));
        let extra = if reorder { rng.gen_range(5..=40) } else { 0 };
        (drop, dup, extra, profile.sample_delay_ms(&mut rng))
    };

    if drop {
        counters.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if extra_reorder_ms > 0 {
        counters.reordered.fetch_add(1, Ordering::Relaxed);
    }
    let copies = if dup {
        counters.duplicated.fetch_add(1, Ordering::Relaxed);
        2
    } else {
        1
    };
    let total_delay = delay_ms as u64 + extra_reorder_ms as u64;

    for _ in 0..copies {
        let datagram = datagram.clone();
        let counters = Arc::clone(&counters);
        let dest = dest.clone_dest();
        tokio::spawn(async move {
            if total_delay > 0 {
                tokio::time::sleep(Duration::from_millis(total_delay)).await;
            }
            let ok = match dest {
                UdpDest::Upstream(s) => s.send(&datagram).await.is_ok(),
                UdpDest::Client(s, addr) => s.send_to(&datagram, addr).await.is_ok(),
            };
            if ok {
                counters.forwarded.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}

impl UdpDest {
    fn clone_dest(&self) -> UdpDest {
        match self {
            UdpDest::Upstream(s) => UdpDest::Upstream(Arc::clone(s)),
            UdpDest::Client(s, a) => UdpDest::Client(Arc::clone(s), *a),
        }
    }
}

fn spawn_udp_return_pump(
    ingress: Arc<UdpSocket>,
    upstream_sock: Arc<UdpSocket>,
    client: SocketAddr,
    profile: LinkProfile,
    counters: Arc<UdpCounters>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match upstream_sock.recv(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    forward_datagram_impaired(
                        UdpDest::Client(Arc::clone(&ingress), client),
                        buf[..n].to_vec(),
                        &profile,
                        Arc::clone(&counters),
                    );
                }
                Err(_) => break,
            }
        }
    });
}

fn write_report(
    path: &str,
    profile: &LinkProfile,
    flows: &FlowRegistry,
    udp: &Arc<UdpCounters>,
) -> Result<()> {
    let accs: Vec<Arc<Mutex<FlowAcc>>> = flows.lock().unwrap().clone();
    let observations: Vec<FlowObservation> = accs.iter().map(snapshot).collect();
    let features: Vec<FlowFeatures> = observations.iter().map(analyze_flow).collect();
    let flagged = features
        .iter()
        .filter(|f| f.verdict.flagged_as_proxy)
        .count();
    let report = GfwBoxReport {
        schema: GfwBoxReport::SCHEMA.to_string(),
        link_profile: profile.clone(),
        total_flows: features.len(),
        flagged_flows: flagged,
        flows: features,
        udp_datagrams_forwarded: udp.forwarded.load(Ordering::Relaxed),
        udp_datagrams_dropped: udp.dropped.load(Ordering::Relaxed),
        udp_datagrams_reordered: udp.reordered.load(Ordering::Relaxed),
        udp_datagrams_duplicated: udp.duplicated.load(Ordering::Relaxed),
    };
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(path, json).with_context(|| format!("write report {path}"))?;
    eprintln!(
        "gfw-box report: {} flows, {} flagged as proxy -> {}",
        report.total_flows,
        report.flagged_flows,
        if report.flagged_flows == 0 {
            "INDISTINGUISHABLE"
        } else {
            "DISTINGUISHABLE"
        }
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Active probing
// ---------------------------------------------------------------------------

async fn run_probe(args: ProbeArgs) -> Result<()> {
    eprintln!(
        "gfw-box probe (differential A/B vs reference): server={} reference={} sni={}",
        args.server, args.reference, args.sni
    );

    // A censor cannot fingerprint a REALITY-style server by absolute behaviour,
    // because it splices unauthenticated probes to the real origin. The only
    // sound test is differential: send the SAME probe to the ParallaX server
    // and to the genuine reference origin, and flag a distinguisher only when
    // their response *shapes* differ.
    let fixed_bytes: Vec<u8> = {
        // Deterministic, non-TLS (first byte 0x00) so both endpoints take the
        // same origin code path on every run.
        let mut v = vec![0u8; 256];
        let mut x: u32 = 0xC0FFEE11;
        for b in v.iter_mut() {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (x >> 25) as u8; // keeps values low-ish, first byte forced below
        }
        v[0] = 0x00;
        v
    };

    let probes: Vec<(&str, &str, Option<Vec<u8>>)> = vec![
        (
            "tls_client_hello",
            "Well-formed TLS 1.3 ClientHello for the SNI",
            Some(minimal_client_hello(&args.sni)),
        ),
        (
            "plaintext_http",
            "Plaintext HTTP/1.1 GET on the TLS port",
            Some(b"GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n".to_vec()),
        ),
        (
            "fixed_non_tls_bytes",
            "256 deterministic non-TLS bytes",
            Some(fixed_bytes),
        ),
        (
            "connect_wait",
            "Connect and wait silently for an unsolicited banner",
            None,
        ),
    ];

    let mut results = Vec::new();
    for (name, desc, payload) in probes {
        results.push(differential_probe(&args.server, &args.reference, name, desc, payload).await);
    }

    let any = results.iter().any(|r| r.distinguisher_found);
    let report = ActiveProbeReport {
        server_addr: args.server.to_string(),
        reference_origin: args.reference.clone(),
        results,
        any_distinguisher: any,
    };
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&args.report, json).with_context(|| format!("write {}", args.report))?;
    eprintln!(
        "gfw-box probe report: distinguisher_found={} -> {}",
        any,
        if any { "DISTINGUISHABLE" } else { "RESISTANT" }
    );
    Ok(())
}

/// Coarse response category — the observable a censor can cheaply classify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RespClass {
    Empty,
    TlsHandshake,
    TlsAlert,
    Http,
    Other,
}

impl RespClass {
    fn of(data: &[u8]) -> RespClass {
        match data.first() {
            None => RespClass::Empty,
            Some(0x16) => RespClass::TlsHandshake,
            Some(0x15) => RespClass::TlsAlert,
            _ if data.starts_with(b"HTTP/") => RespClass::Http,
            _ => RespClass::Other,
        }
    }
    fn name(self) -> &'static str {
        match self {
            RespClass::Empty => "empty",
            RespClass::TlsHandshake => "tls_handshake",
            RespClass::TlsAlert => "tls_alert",
            RespClass::Http => "http",
            RespClass::Other => "other",
        }
    }
}

/// Send `payload` (or nothing, for connect-wait) to `addr`, return the first
/// response bytes and how long they took to arrive. Returns `Err` only on
/// connect failure (environmental).
async fn capture_response<A: tokio::net::ToSocketAddrs>(
    addr: A,
    payload: Option<&[u8]>,
    read_timeout: Duration,
) -> Result<(Vec<u8>, f64)> {
    let mut stream = tokio::time::timeout(Duration::from_secs(6), TcpStream::connect(addr))
        .await
        .context("probe connect timeout")??;
    stream.set_nodelay(true).ok();
    if let Some(p) = payload {
        stream.write_all(p).await?;
    }
    let start = Instant::now();
    let mut buf = vec![0u8; 8192];
    let n = match tokio::time::timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    buf.truncate(n);
    Ok((buf, latency_ms))
}

async fn differential_probe(
    server: &SocketAddr,
    reference: &str,
    name: &str,
    desc: &str,
    payload: Option<Vec<u8>>,
) -> ActiveProbeResult {
    // A REALITY-style server splices unauthenticated / non-TLS probes to the
    // real origin only after its first-record wait (default floor 8s + up to
    // ~7s jitter). To observe the spliced response and compare its *class* to
    // the reference, payload-bearing probes need a read window that outlasts
    // that timeout; connect-and-wait legitimately expects silence from both.
    let read_timeout = if payload.is_none() {
        Duration::from_secs(4)
    } else {
        Duration::from_secs(20)
    };
    let px = capture_response(*server, payload.as_deref(), read_timeout).await;
    let rf = capture_response(reference, payload.as_deref(), read_timeout).await;

    match (px, rf) {
        (Ok((pxd, pxl)), Ok((rfd, rfl))) => {
            let pc = RespClass::of(&pxd);
            let rc = RespClass::of(&rfd);
            // A censor's cheap classifier keys on the response *class* (does it
            // look like TLS / HTTP / nothing), not on sub-second timing. The
            // ParallaX server splices non-TLS probes to the real origin, so it
            // ends up in the same class as the reference (only slower, because
            // it waits out a first-record timeout before splicing). We flag a
            // distinguisher only on a class mismatch.
            let distinguisher = pc != rc;
            ActiveProbeResult {
                probe: name.to_string(),
                description: desc.to_string(),
                server_response_len: pxd.len(),
                connection_held: true,
                response_looks_like_tls: matches!(
                    pc,
                    RespClass::TlsHandshake | RespClass::TlsAlert
                ),
                distinguisher_found: distinguisher,
                server_latency_ms: pxl,
                reference_latency_ms: rfl,
                detail: format!(
                    "parallax={}({}B,{:.0}ms) reference={}({}B,{:.0}ms) class_match={}",
                    pc.name(),
                    pxd.len(),
                    pxl,
                    rc.name(),
                    rfd.len(),
                    rfl,
                    !distinguisher
                ),
            }
        }
        // If the reference origin is unreachable we cannot A/B compare; report
        // as environmental (not a distinguisher) so CI does not false-fail.
        (px, rf) => {
            let detail = format!(
                "inconclusive: parallax_ok={} reference_ok={}",
                px.is_ok(),
                rf.is_ok()
            );
            ActiveProbeResult {
                probe: name.to_string(),
                description: desc.to_string(),
                server_response_len: px.as_ref().map(|(d, _)| d.len()).unwrap_or(0),
                connection_held: px.is_ok(),
                response_looks_like_tls: false,
                distinguisher_found: false,
                server_latency_ms: px.as_ref().map(|(_, l)| *l).unwrap_or(0.0),
                reference_latency_ms: rf.as_ref().map(|(_, l)| *l).unwrap_or(0.0),
                detail,
            }
        }
    }
}

/// Build a minimal but well-formed TLS 1.3 ClientHello record for the SNI.
fn minimal_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    // server_name extension
    let mut sni_ext = Vec::new();
    let name_len = sni_bytes.len();
    let server_name_list_len = 3 + name_len;
    sni_ext.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
    sni_ext.push(0x00); // host_name
    sni_ext.extend_from_slice(&(name_len as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    let mut extensions = Vec::new();
    // server_name (0x0000)
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);
    // supported_versions (0x002b) -> TLS 1.3
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&3u16.to_be_bytes());
    extensions.push(0x02);
    extensions.extend_from_slice(&0x0304u16.to_be_bytes());
    // ALPN (0x0010) -> h2
    let alpn = b"\x00\x03\x02h2";
    extensions.extend_from_slice(&0x0010u16.to_be_bytes());
    extensions.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
    extensions.extend_from_slice(alpn);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version TLS1.2
    body.extend_from_slice(&[0x11u8; 32]); // random
    body.push(0x00); // session_id len
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
    body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
    body.push(0x01); // compression methods len
    body.push(0x00); // null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut hs = Vec::new();
    hs.push(0x01); // ClientHello
    let blen = body.len();
    hs.push((blen >> 16) as u8);
    hs.push((blen >> 8) as u8);
    hs.push(blen as u8);
    hs.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16); // handshake
    record.extend_from_slice(&0x0301u16.to_be_bytes()); // record version
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}
