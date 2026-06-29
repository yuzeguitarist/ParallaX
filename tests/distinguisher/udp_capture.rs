//! Live ParallaX QUIC capture at the UDP-datagram layer — the censor's vantage
//! point — normalised to a [`Trace`].
//!
//! HOW (and why this layer): a censor observing a QUIC flow sees UDP datagrams,
//! not application-layer stream reads. Tapping at the stream API would measure
//! the wrong thing (it misses QUIC's own packetisation, ACK datagrams, and
//! coalescing). So we drive a real production QUIC session over loopback through
//! a transparent recording forwarder sitting between client and server:
//!
//! ```text
//!   client ──UDP──▶ RecordingForwarder ──UDP──▶ server
//!          ◀──UDP──                    ◀──UDP──
//! ```
//!
//! The forwarder logs every datagram's `(len, direction, time)` exactly as it
//! crosses the wire — true censor-visible packets, with **zero production-code
//! changes** (it is an ordinary UDP relay, the same shape as `quic/splice.rs`).
//!
//! SCOPE / HONESTY: datagram **length** and **direction** are wire-faithful and
//! compared directly. Inter-arrival **time** is recorded but is NOT gated on —
//! loopback wall-clock IAT is host-scheduling noise, not censor-faithful in
//! absolute terms (see the battery's tier docs). We never let timing drive a
//! verdict.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use parallax::transport::udp::endpoint::{bind_client_endpoint_accept_any, bind_server_endpoint};

use super::trace::{Dir, Record, Trace};

/// Max UDP payload we relay in one datagram (generous ceiling above path MTU).
const RELAY_BUF: usize = 64 * 1024;

/// Shared, time-ordered log of every datagram the forwarder relayed.
type Log = Arc<Mutex<Vec<Record>>>;

/// A transparent UDP relay that records each datagram crossing it.
///
/// Binds one socket facing the client (its address is what the client connects
/// to) and forwards client→server and server→client datagrams verbatim, logging
/// `(len, dir, t)` for each. C2S = client→server (uplink, the imitated side).
struct RecordingForwarder {
    /// Address the client should connect to.
    front_addr: SocketAddr,
    log: Log,
    task: tokio::task::JoinHandle<()>,
}

impl RecordingForwarder {
    /// Spawn a forwarder in front of `server_addr`. The relay learns the client's
    /// address from its first datagram (the client uses a fixed local port for
    /// the connection), then shuttles datagrams both ways.
    async fn spawn(server_addr: SocketAddr) -> std::io::Result<Self> {
        let front = UdpSocket::bind("127.0.0.1:0").await?;
        let front_addr = front.local_addr()?;
        // Socket the forwarder uses to talk to the real server.
        let back = UdpSocket::bind("127.0.0.1:0").await?;
        back.connect(server_addr).await?;

        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let log_task = log.clone();
        let started = Instant::now();

        let task = tokio::spawn(async move {
            // Separate buffers per direction so both select! arms can hold a
            // mutable borrow concurrently.
            let mut up_buf = vec![0u8; RELAY_BUF];
            let mut down_buf = vec![0u8; RELAY_BUF];
            let mut client_addr: Option<SocketAddr> = None;
            loop {
                tokio::select! {
                    // Client → forwarder → server (uplink, C2S).
                    r = front.recv_from(&mut up_buf) => {
                        let (n, from) = match r { Ok(v) => v, Err(_) => break };
                        client_addr = Some(from);
                        record(&log_task, n, Dir::C2S, started);
                        if back.send(&up_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    // Server → forwarder → client (downlink, S2C).
                    r = back.recv(&mut down_buf) => {
                        let n = match r { Ok(v) => v, Err(_) => break };
                        record(&log_task, n, Dir::S2C, started);
                        if let Some(c) = client_addr {
                            if front.send_to(&down_buf[..n], c).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(RecordingForwarder {
            front_addr,
            log,
            task,
        })
    }

    /// Stop the relay and return the recorded datagram trace.
    fn finish(self) -> Trace {
        self.task.abort();
        let recs = self.log.lock().unwrap().clone();
        Trace::new(recs)
    }
}

fn record(log: &Log, len: usize, dir: Dir, started: Instant) {
    let t_micros = started.elapsed().as_micros() as u64;
    log.lock().unwrap().push(Record {
        len: len as u32,
        dir,
        t_micros,
    });
}

/// Drive a real ParallaX QUIC session over loopback through the recording
/// forwarder, transferring `uplink_bytes` up and `downlink_bytes` back on a
/// bidirectional stream, and return the captured UDP-datagram [`Trace`].
///
/// This is heavyweight (binds real endpoints, runs a real handshake + transfer),
/// so it is only invoked from `#[ignore]` tiers.
pub async fn capture_parallax_quic_trace(
    uplink_bytes: usize,
    downlink_bytes: usize,
) -> Result<Trace, String> {
    let server = bind_server_endpoint("127.0.0.1:0".parse().unwrap(), "localhost")
        .await
        .map_err(|e| format!("bind server: {e}"))?;
    let server_addr = server
        .local_addr()
        .map_err(|e| format!("server addr: {e}"))?;

    let forwarder = RecordingForwarder::spawn(server_addr)
        .await
        .map_err(|e| format!("spawn forwarder: {e}"))?;
    let front_addr = forwarder.front_addr;

    // Server side: accept one connection, accept its bidi stream, drain the
    // uplink, then send the downlink payload back.
    let server_task = tokio::spawn(async move {
        let conn = match server.accept().await {
            Some(c) => c,
            None => return Err("server accept returned None".to_string()),
        };
        let (mut send, mut recv) = match conn.accept_bi().await {
            Some(s) => s,
            None => return Err("server accept_bi returned None".to_string()),
        };
        let mut sink = Vec::new();
        recv.read_to_end(&mut sink)
            .await
            .map_err(|e| format!("server read: {e}"))?;
        let reply = vec![0xa5u8; downlink_bytes];
        send.write_all(&reply)
            .await
            .map_err(|e| format!("server write: {e}"))?;
        send.finish();
        // Hold the connection briefly so queued datagrams flush before drop.
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok::<usize, String>(sink.len())
    });

    let client = bind_client_endpoint_accept_any("127.0.0.1:0".parse().unwrap())
        .await
        .map_err(|e| format!("bind client: {e}"))?;

    // Connect to the FORWARDER, not the server, so all datagrams cross the tap.
    let conn = client
        .connect(front_addr, "localhost")
        .await
        .map_err(|e| format!("client connect: {e}"))?;
    let (mut send, mut recv) = conn.open_bi();

    let payload = vec![0x5au8; uplink_bytes];
    send.write_all(&payload)
        .await
        .map_err(|e| format!("client write: {e}"))?;
    send.finish();
    let mut got = Vec::new();
    recv.read_to_end(&mut got)
        .await
        .map_err(|e| format!("client read: {e}"))?;

    // Let the last datagrams (ACKs, stream FIN) cross the forwarder.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Propagate server-side stream errors and confirm the transfer completed in
    // full: a truncated handshake/transfer would otherwise yield a misleading
    // Tier 5 trace. We require the bytes actually transferred to match what was
    // requested in both directions.
    let server_recv = server_task
        .await
        .map_err(|e| format!("server task join: {e}"))?
        .map_err(|e| format!("server task: {e}"))?;
    if server_recv != uplink_bytes {
        return Err(format!(
            "uplink truncated: server received {server_recv} of {uplink_bytes} bytes"
        ));
    }
    if got.len() != downlink_bytes {
        return Err(format!(
            "downlink truncated: client received {} of {downlink_bytes} bytes",
            got.len()
        ));
    }

    let trace = forwarder.finish();
    if trace.is_empty() {
        return Err("forwarder captured no datagrams".into());
    }
    Ok(trace)
}

/// One request/response exchange in an interactive capture: the client sends
/// `request_bytes`, the server replies with `response_bytes`.
#[derive(Debug, Clone, Copy)]
pub struct Exchange {
    pub request_bytes: usize,
    pub response_bytes: usize,
}

/// Drive a real ParallaX QUIC session that performs a *sequence* of
/// request/response exchanges over one bidirectional stream, and return the
/// captured UDP-datagram [`Trace`].
///
/// WHY this exists: the bulk [`capture_parallax_quic_trace`] streams one large
/// payload each way, which produces a single uplink burst followed by a single
/// downlink burst — nothing like a browser. Real Safari QUIC interleaves many
/// small request/response turns (`UUU DDD UUU DD …`). This driver reproduces
/// that shape by ping-ponging `exchanges` over the stream, so the captured
/// direction-run distribution can be compared to Safari's on equal terms.
///
/// Each turn uses `read_exact` for an exact byte count (not `read_to_end`, which
/// would block until close), so the stream stays open across turns. Heavyweight;
/// invoked only from `#[ignore]` tiers.
pub async fn capture_parallax_quic_interactive(exchanges: &[Exchange]) -> Result<Trace, String> {
    let server = bind_server_endpoint("127.0.0.1:0".parse().unwrap(), "localhost")
        .await
        .map_err(|e| format!("bind server: {e}"))?;
    let server_addr = server
        .local_addr()
        .map_err(|e| format!("server addr: {e}"))?;

    let forwarder = RecordingForwarder::spawn(server_addr)
        .await
        .map_err(|e| format!("spawn forwarder: {e}"))?;
    let front_addr = forwarder.front_addr;

    // The server mirrors each turn: read the agreed request size, write the
    // agreed response size. It learns the per-turn sizes from the same schedule
    // the client follows (passed by value into the task).
    let schedule: Vec<Exchange> = exchanges.to_vec();
    let server_task = tokio::spawn(async move {
        let conn = match server.accept().await {
            Some(c) => c,
            None => return Err("server accept returned None".to_string()),
        };
        let (mut send, mut recv) = match conn.accept_bi().await {
            Some(s) => s,
            None => return Err("server accept_bi returned None".to_string()),
        };
        for (i, ex) in schedule.iter().enumerate() {
            let mut req = vec![0u8; ex.request_bytes];
            recv.read_exact(&mut req)
                .await
                .map_err(|e| format!("server read turn {i}: {e}"))?;
            let resp = vec![0xa5u8; ex.response_bytes];
            send.write_all(&resp)
                .await
                .map_err(|e| format!("server write turn {i}: {e}"))?;
        }
        send.finish();
        // Hold briefly so the last datagrams flush before drop.
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok::<(), String>(())
    });

    let client = bind_client_endpoint_accept_any("127.0.0.1:0".parse().unwrap())
        .await
        .map_err(|e| format!("bind client: {e}"))?;
    let conn = client
        .connect(front_addr, "localhost")
        .await
        .map_err(|e| format!("client connect: {e}"))?;
    let (mut send, mut recv) = conn.open_bi();

    for (i, ex) in exchanges.iter().enumerate() {
        let req = vec![0x5au8; ex.request_bytes];
        send.write_all(&req)
            .await
            .map_err(|e| format!("client write turn {i}: {e}"))?;
        let mut resp = vec![0u8; ex.response_bytes];
        recv.read_exact(&mut resp)
            .await
            .map_err(|e| format!("client read turn {i}: {e}"))?;
    }
    send.finish();

    // Let trailing datagrams (ACKs, FIN) cross the forwarder.
    tokio::time::sleep(Duration::from_millis(200)).await;
    server_task
        .await
        .map_err(|e| format!("server task join: {e}"))?
        .map_err(|e| format!("server task: {e}"))?;

    let trace = forwarder.finish();
    if trace.is_empty() {
        return Err("forwarder captured no datagrams".into());
    }
    Ok(trace)
}
