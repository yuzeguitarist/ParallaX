use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use zeroize::Zeroizing;

use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{
        lookup_host,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{mpsc, oneshot, Mutex, Notify, Semaphore, TryAcquireError},
    time::{sleep, timeout, Instant},
};

use crate::{
    client::initial_payload,
    client::socks::{self, SocksError},
    config::{
        decode_base64_bytes, decode_key32, decode_psk, ClientConfig, Config, ConfigError, Mode,
        TrafficConfig, UdpConfig,
    },
    crypto::{auth::AuthError, identity, parallel, pq},
    handshake::client::{self, ClientDataSession, ClientHandshakeError, PendingPqRekey},
    protocol::command::{
        ConnectRequest, ConnectRequestError, FramedReassembler, MuxFrame, MuxFrameError,
        MuxFrameKind, MuxFrameRef, MuxPayloadPool, ServerIdentityChunk, ServerIdentityProof,
        ServerKeyExchange, MAX_PQ_HANDSHAKE_FRAME,
    },
    protocol::data::{
        max_plaintext_len, relay_read_buffer_len, should_parallelize_aead, DataRecordCodec,
        DataRecordError, SealedRecord, QUIC_RELAY_DONE_MARKER, RELAY_IDLE_CLOSE_CODE,
    },
    tls::{
        record::{log_record_read, TlsRecordError, TlsRecordReader},
        safari26::{Safari26TlsCamouflage, Safari26TlsError},
    },
    traffic::CoverTrafficProfile,
    transport::{
        leg::{
            H3DataFrameLegReader, H3DataFrameLegWriter, LegReader, LegWriter, TcpLegReader,
            TcpLegWriter,
        },
        tcp::{
            connect_tuned_tcp_addr, drain_ready_tcp_read, is_fd_exhaustion_error,
            relay_connection_limit, tune_tcp_stream,
        },
    },
};

const MAX_SERVER_IDENTITY_PAYLOAD: usize = 16 * 1024;
/// How many undecryptable (camouflage) records the client skips before the
/// server's ParallaX key-exchange record. Bound to the shared
/// [`crate::handshake::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS`] so it always
/// covers the server's pre-PQ fallback forward cap; a smaller value (this was 16
/// vs the server's 64) caused intermittent ~33-75% handshake failures on high-RTT
/// links where the camouflage origin's response body leaks into this skip window.
const MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE: usize =
    crate::handshake::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS;
/// Hard deadline for the whole post-connect authenticated establishment
/// (camouflage TLS handshake + PQ rekey + identity verify). Mirrors the server's
/// HANDSHAKE_TIMEOUT so a stalling/impersonating upstream cannot pin an
/// establishing task (and its permit/fds) indefinitely.
const CLIENT_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(15);
/// Idle backstop for an established client relay/mux session: if neither
/// direction moves real bytes for this long, tear the session down so a silent
/// (e.g. MITM-held) upstream cannot pin a global connection slot and both fds.
const CLIENT_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Bound on the local SOCKS5 negotiation. A loopback client that opens the
/// socket then stalls (or trickles bytes one at a time) would otherwise park the
/// connection task forever, holding a connection slot — and on the non-mux path
/// a speculative upstream session. An independent flat 10s bound on the loopback
/// SOCKS side (not the GFW-facing server first-record wait, which is jittered).
const SOCKS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const WARM_SESSION_POOL_TARGET: usize = 4;
const MUX_FRAME_CHANNEL_PER_STREAM: usize = 8;
const MUX_FRAME_BATCH_LIMIT: usize = 64;
/// Cap on the ciphertext bytes batched per mux read before opening, bounding
/// scratch memory while leaving enough records for the crypto pool to fan out.
const MUX_OPEN_BATCH_BYTES: usize = 1024 * 1024;
/// How often the mux warm-keeper re-checks the shared tunnel's health.
const MUX_WARM_KEEPER_INTERVAL: Duration = Duration::from_secs(5);
/// The warm-keeper proactively rebuilds a DEAD shared mux tunnel only if a real
/// local connection was served within this window. So an actively-used client
/// always finds a warm tunnel (resilient to a mid-session RST/blackhole), while a
/// genuinely idle client lets the tunnel idle out and does NOT re-handshake on a
/// 24/7 timer — matching a browser that reconnects on use and idles otherwise
/// (keeping the warm pool from becoming an always-on behavioral tell).
const MUX_WARM_KEEPER_ACTIVE_WINDOW: Duration = Duration::from_secs(90);
/// After this many consecutive FAILED proactive rebuilds the keeper goes dormant
/// until fresh local activity, so a persistently blocked/blackholed server is not
/// hammered on a fixed cadence — a clock-locked retry burst to a dead endpoint is
/// itself a behavioral tell / active-probe confirmation. Real browsers back off a
/// dead origin; so does this.
const MUX_WARM_KEEPER_MAX_REBUILD_FAILURES: u32 = 4;
/// Cap on the exponential backoff between failed proactive rebuild attempts.
const MUX_WARM_KEEPER_MAX_BACKOFF: Duration = Duration::from_secs(60);

static NEXT_CLIENT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum ClientRuntimeError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("client mode requires [client] config")]
    MissingClient,
    #[error("parallax client requires mode = \"client\"")]
    WrongMode,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("SOCKS error: {0}")]
    Socks(#[from] SocksError),
    #[error("connect request error: {0}")]
    ConnectRequest(#[from] ConnectRequestError),
    #[error("Safari 26 TLS camouflage error: {0}")]
    Safari26Tls(#[from] Safari26TlsError),
    #[error("ClientHello auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("client handshake error: {0}")]
    Handshake(#[from] ClientHandshakeError),
    #[error("server identity chunk sequence is invalid")]
    InvalidServerIdentityChunks,
    #[error("server identity proof is too large")]
    ServerIdentityTooLarge,
    #[error("TLS record error: {0}")]
    TlsRecord(#[from] TlsRecordError),
    #[error("mux frame error: {0}")]
    MuxFrame(#[from] MuxFrameError),
    #[error("blocking crypto task failed: {0}")]
    BlockingTask(#[from] tokio::task::JoinError),
}

type ClientSession = (TcpStream, ClientDataSession, Option<RetainedClientQuic>);
type ClientSessionTask = tokio::task::JoinHandle<Result<ClientSession, ClientRuntimeError>>;

pub async fn run(config: Config) -> Result<(), ClientRuntimeError> {
    if config.mode != Mode::Client {
        return Err(ClientRuntimeError::WrongMode);
    }
    // Client UDP-negotiation parameters, read at the data-session seam to decide
    // whether to open a PX1G UdpRequest and how long to probe. Threaded as a
    // cheap-to-clone Arc, mirroring how `traffic` flows into the pools.
    let udp = Arc::new(config.udp.clone());
    if udp.enabled {
        tracing::info!(
            probe_timeout_ms = udp.probe_timeout_ms,
            "UDP fast plane ENABLED (experimental): QUIC reliable-stream carrier for \
             the single-Connect relay; requires matched binaries on both ends"
        );
        let reserved = udp.reserved_knobs_in_use();
        if !reserved.is_empty() {
            tracing::warn!(
                reserved = ?reserved,
                "udp config sets RESERVED knobs that this version does not yet honor (no-op)"
            );
        }
    }

    // Process-wide socket-buffer sizing (wire-invisible kernel tuning), installed
    // before any relay socket is created. First call wins (run() is one-per-process).
    crate::transport::tcp::configure_socket_buffers(
        config.transport.tcp_send_buffer_bytes,
        config.transport.tcp_recv_buffer_bytes,
    );

    let client = config
        .client
        .clone()
        .ok_or(ClientRuntimeError::MissingClient)?;
    let psk = decode_psk(config.crypto.psk.as_b64())?;
    crate::process_hardening::protect_secret_bytes("runtime.crypto.psk", psk.as_slice());
    let psk = Arc::new(psk);
    let server_public = decode_key32("client.server_public_key", &client.server_public_key)?;
    let server_identity_public = Arc::<[u8]>::from(
        decode_base64_bytes(
            "client.server_identity_public_key",
            &client.server_identity_public_key,
        )?
        .into_boxed_slice(),
    );
    let listener = TcpListener::bind(client.listen).await?;
    let server_addr = ServerAddrResolver::new(&client.server_addr).await?;
    let client = Arc::new(client);
    // Process-shared UDP fast-plane circuit breaker. Created once and threaded
    // alongside `udp` so a black-holed UDP path is probed at most once per
    // `UDP_BLACKHOLE_TTL` instead of on every connection.
    let udp_reachability = Arc::new(UdpReachability::new(UDP_BLACKHOLE_TTL));
    let warm_sessions = if config.traffic.max_concurrent_streams == 1 {
        let warm_sessions = WarmSessionPool::new(
            Arc::clone(&client),
            server_addr.clone(),
            config.traffic,
            Arc::clone(&udp),
            Arc::clone(&udp_reachability),
            Arc::clone(&psk),
            server_public,
            Arc::clone(&server_identity_public),
        );
        // Pre-warm only when udp is off. With udp on the pool's warm target is 0
        // (no parked idle retained QUIC), so single-connect sessions are
        // established on demand "cold"; pre-warming would be a no-op anyway, so we
        // skip it explicitly.
        if !udp.enabled {
            warm_sessions.ensure_started().await;
        }
        Some(warm_sessions)
    } else {
        None
    };
    let mux_sessions = if config.traffic.max_concurrent_streams > 1 {
        let mux_sessions = ClientMuxPool::new(
            Arc::clone(&client),
            server_addr.clone(),
            config.traffic,
            Arc::clone(&udp),
            Arc::clone(&udp_reachability),
            Arc::clone(&psk),
            server_public,
            Arc::clone(&server_identity_public),
        );
        mux_sessions.ensure_started();
        Some(mux_sessions)
    } else {
        None
    };
    let connection_limit = relay_connection_limit(udp.enabled)?;
    let connection_slots = Arc::new(Semaphore::new(connection_limit));
    tracing::info!(
        connection_limit,
        "ParallaX client SOCKS5 listening on {}",
        client.listen
    );

    loop {
        let (local, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) if is_fd_exhaustion_error(&err) => {
                tracing::error!(
                    error = %err,
                    "accept() ran out of file descriptors; backing off 100ms"
                );
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        let connection_permit = match Arc::clone(&connection_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                tracing::warn!(
                    %peer,
                    connection_limit,
                    "client connection limit reached; closing accepted socket"
                );
                drop(local);
                continue;
            }
            Err(TryAcquireError::Closed) => {
                return Err(io::Error::other("client connection limiter was closed").into());
            }
        };
        let cid = NEXT_CLIENT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let client = Arc::clone(&client);
        let psk = Arc::clone(&psk);
        let server_identity_public = Arc::clone(&server_identity_public);
        let traffic = config.traffic;
        let udp = Arc::clone(&udp);
        let reachability = Arc::clone(&udp_reachability);
        let server_addr = server_addr.clone();
        let warm_sessions = warm_sessions.clone();
        let mux_sessions = mux_sessions.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Some(mux_sessions) = mux_sessions {
                if let Err(err) =
                    handle_local_mux_connection_with_cid(local, mux_sessions, cid).await
                {
                    tracing::debug!(cid, %peer, error = %err, "client mux connection closed");
                }
                return;
            }
            let context = ClientConnectionContext {
                config: client.as_ref(),
                server_addr,
                traffic,
                udp: udp.as_ref(),
                reachability,
                psk: psk.as_ref().as_slice(),
                server_public: &server_public,
                server_identity_public,
                warm_sessions,
            };
            if let Err(err) = handle_local_connection_with_cid(local, context, cid).await {
                tracing::debug!(cid, %peer, error = %err, "client connection closed");
            }
        });
    }
}

pub async fn handle_local_connection(
    local: TcpStream,
    config: &ClientConfig,
    traffic: TrafficConfig,
    udp: &UdpConfig,
    psk: &[u8],
    server_public: &[u8; 32],
    server_identity_public: &[u8],
) -> Result<(), ClientRuntimeError> {
    let cid = NEXT_CLIENT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let server_addr = ServerAddrResolver::new(&config.server_addr).await?;
    let server_identity_public =
        Arc::<[u8]>::from(server_identity_public.to_vec().into_boxed_slice());
    let context = ClientConnectionContext {
        config,
        server_addr,
        traffic,
        udp,
        reachability: Arc::new(UdpReachability::new(UDP_BLACKHOLE_TTL)),
        psk,
        server_public,
        server_identity_public,
        warm_sessions: None,
    };
    handle_local_connection_with_cid(local, context, cid).await
}

/// Time the UDP fast-plane circuit breaker suppresses negotiation after a probe
/// reports the path unusable. On a network that black-holes UDP (the common
/// censored case the fast plane targets), re-probing every connection would add
/// `probe_timeout_ms` of dead latency to each one — a regression below the
/// TCP-only floor on exactly the networks this feature exists for. After a
/// blocked probe the breaker skips negotiation for this window, then allows one
/// half-open retry.
const UDP_BLACKHOLE_TTL: Duration = Duration::from_secs(30);

/// Client-side circuit breaker for the UDP fast plane (process-shared, one per
/// runtime). It removes the probe from the connection critical path once UDP is
/// known-unusable: while tripped, the client skips PX1G negotiation entirely, so
/// the session is byte-identical to a TCP-only one (the server only ever reacts
/// to PX1G being present, so suppressing it cannot desync). A Verified probe
/// clears it; after [`UDP_BLACKHOLE_TTL`] it permits one more attempt.
pub(crate) struct UdpReachability {
    ttl: Duration,
    /// `None` = not tripped; `Some(t)` = last marked unusable at `t`.
    blocked_since: std::sync::Mutex<Option<std::time::Instant>>,
}

impl UdpReachability {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            blocked_since: std::sync::Mutex::new(None),
        }
    }

    /// Whether this connection should attempt UDP negotiation — and, at the
    /// half-open boundary, CLAIM the single trial probe. This mutates state: when
    /// a tripped breaker's TTL has expired, the first caller re-stamps
    /// `blocked_since` to now and returns `true`, so concurrent callers in the
    /// same window see it as still tripped and skip. That keeps the trial to one
    /// connection per TTL instead of a thundering herd of re-probes. If that
    /// claiming connection dies without recording an outcome, the next TTL lets
    /// another connection reclaim (self-healing); a Verified outcome clears the
    /// breaker via `record_usable`, a failure re-trips it via `record_unusable`.
    fn should_attempt_at(&self, now: std::time::Instant) -> bool {
        let mut guard = self.blocked_since.lock().expect("reachability mutex");
        match *guard {
            // Usable (or never tripped): every connection negotiates so they all
            // use the fast plane while it works — no claim, no state change.
            None => true,
            Some(t) => {
                if now.saturating_duration_since(t) >= self.ttl {
                    *guard = Some(now);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Whether to attempt UDP negotiation on a new connection (see
    /// [`Self::should_attempt_at`] — this claims the half-open trial slot).
    pub(crate) fn should_attempt(&self) -> bool {
        self.should_attempt_at(std::time::Instant::now())
    }

    /// Record that the UDP path is unusable (probe Unreachable or Failed): trip
    /// the breaker so subsequent connections skip negotiation for the TTL.
    pub(crate) fn record_unusable(&self) {
        *self.blocked_since.lock().expect("reachability mutex") = Some(std::time::Instant::now());
    }

    /// Record that the UDP path works (probe Verified): clear the breaker.
    pub(crate) fn record_usable(&self) {
        *self.blocked_since.lock().expect("reachability mutex") = None;
    }
}

struct ClientConnectionContext<'a> {
    config: &'a ClientConfig,
    server_addr: ServerAddrResolver,
    traffic: TrafficConfig,
    udp: &'a UdpConfig,
    reachability: Arc<UdpReachability>,
    psk: &'a [u8],
    server_public: &'a [u8; 32],
    server_identity_public: Arc<[u8]>,
    warm_sessions: Option<WarmSessionPool>,
}

#[derive(Clone)]
struct WarmSessionPool {
    inner: Arc<Mutex<VecDeque<ClientSessionTask>>>,
    config: Arc<ClientConfig>,
    server_addr: ServerAddrResolver,
    traffic: TrafficConfig,
    udp: Arc<UdpConfig>,
    reachability: Arc<UdpReachability>,
    psk: Arc<Zeroizing<Vec<u8>>>,
    server_public: [u8; 32],
    server_identity_public: Arc<[u8]>,
    /// Number of pre-established idle sessions the pool keeps warm. This is
    /// `WARM_SESSION_POOL_TARGET` by default, but 0 when `udp.enabled`: a warm
    /// single-connect session retains a live QUIC connection (15s keep-alive
    /// PINGs) and parks a matching server task blocked on the first-command read
    /// holding its QUIC conn -- an idle footprint (resource + fingerprint) before
    /// any traffic. With udp on we therefore establish single-connect sessions on
    /// demand "cold" (no parked idle QUIC), trading away the warm-pool latency
    /// benefit. With udp off this stays `WARM_SESSION_POOL_TARGET` and the pool is
    /// byte-identical to before.
    warm_target: usize,
}

impl WarmSessionPool {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: Arc<ClientConfig>,
        server_addr: ServerAddrResolver,
        traffic: TrafficConfig,
        udp: Arc<UdpConfig>,
        reachability: Arc<UdpReachability>,
        psk: Arc<Zeroizing<Vec<u8>>>,
        server_public: [u8; 32],
        server_identity_public: Arc<[u8]>,
    ) -> Self {
        // With udp on, single-connect sessions are established on demand "cold"
        // (target 0) so the pool never parks idle retained QUIC connections; with
        // udp off the pool keeps `WARM_SESSION_POOL_TARGET` warm sessions exactly
        // as before.
        let warm_target = if udp.enabled {
            0
        } else {
            WARM_SESSION_POOL_TARGET
        };
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            config,
            server_addr,
            traffic,
            udp,
            reachability,
            psk,
            server_public,
            server_identity_public,
            warm_target,
        }
    }

    async fn ensure_started(&self) {
        let mut warm = self.inner.lock().await;
        self.fill_locked(&mut warm);
    }

    async fn take_or_start(&self) -> ClientSessionTask {
        let mut warm = self.inner.lock().await;
        let session = match warm.pop_front() {
            // A parked warm session may have died (RST / NAT blackhole) or its
            // handshake may have failed while idle; validate it and transparently
            // re-dial once if it is not a live, successful session.
            Some(parked) => self.spawn_validated(parked),
            None => self.spawn_session(),
        };
        self.fill_locked(&mut warm);
        session
    }

    fn fill_locked(&self, warm: &mut VecDeque<ClientSessionTask>) {
        while warm.len() < self.warm_target {
            warm.push_back(self.spawn_session());
        }
    }

    fn spawn_session(&self) -> ClientSessionTask {
        // The warm-session pool retains up to `self.warm_target` idle sessions,
        // each of which (on the udp-on retain path) would hold a live QUIC
        // connection alive (keep-alive footprint / idle resource cost). That is
        // why `warm_target` is 0 when `udp.enabled`: udp-on single-connect
        // sessions are established on demand "cold" so no idle retained QUIC is
        // parked. With udp off the target stays `WARM_SESSION_POOL_TARGET` (4) and
        // the pre-warm behavior is unchanged.
        let config = Arc::clone(&self.config);
        let server_addr = self.server_addr.clone();
        let traffic = self.traffic;
        let udp = Arc::clone(&self.udp);
        let reachability = Arc::clone(&self.reachability);
        let psk = Arc::clone(&self.psk);
        let server_public = self.server_public;
        let server_identity_public = Arc::clone(&self.server_identity_public);
        tokio::spawn(async move {
            establish_authenticated_data_session_with_resolver(
                &server_addr,
                &config,
                traffic,
                &udp,
                &reachability,
                psk.as_ref().as_slice(),
                &server_public,
                server_identity_public,
            )
            .await
        })
    }

    /// Wraps a parked warm-session handle so the handle the caller awaits ALWAYS
    /// resolves to a validated, live session or a genuinely-fresh dial. Fixes a
    /// stale-cached handshake error (poison/abort -> re-dial) and a dead parked
    /// socket (RST/blackhole -> re-dial) without changing the call site.
    fn spawn_validated(&self, parked: ClientSessionTask) -> ClientSessionTask {
        let config = Arc::clone(&self.config);
        let server_addr = self.server_addr.clone();
        let traffic = self.traffic;
        let udp = Arc::clone(&self.udp);
        let reachability = Arc::clone(&self.reachability);
        let psk = Arc::clone(&self.psk);
        let server_public = self.server_public;
        let server_identity_public = Arc::clone(&self.server_identity_public);
        tokio::spawn(async move {
            // Propagate cancellation to the inner establishment task: if THIS
            // wrapper is aborted (e.g. the caller's session_abort fires), abort the
            // parked handshake too. A bare JoinHandle drop only DETACHES the inner
            // task, leaving the full handshake running uncancelled.
            let _abort_inner = AbortOnDrop(parked.abort_handle());
            match parked.await {
                Ok(Ok(session)) if warm_session_is_live(&session.0) => Ok(session),
                // Poisoned handshake error, aborted/panicked task, or a dead parked
                // socket: dial a genuinely fresh session instead of returning stale.
                _ => {
                    establish_authenticated_data_session_with_resolver(
                        &server_addr,
                        &config,
                        traffic,
                        &udp,
                        &reachability,
                        psk.as_ref().as_slice(),
                        &server_public,
                        server_identity_public,
                    )
                    .await
                }
            }
        })
    }
}

/// Aborts a tokio task when dropped, so cancelling a wrapper task propagates the
/// cancellation to the task it is awaiting instead of detaching it.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Non-destructively probes whether a parked warm TCP session is still alive via
/// a 1-byte `MSG_PEEK`: a healthy idle session has no pending pre-Connect bytes,
/// so this never consumes real data. `> 0` => live (bytes peeked); `0` => dead
/// (clean EOF); `< 0` with `EWOULDBLOCK`/`EAGAIN` => live (idle, the normal warm
/// case); any other errno (e.g. `ECONNRESET`) => dead.
#[cfg(unix)]
fn warm_session_is_live(stream: &TcpStream) -> bool {
    use rustix::io::Errno;
    use rustix::net::{recv, RecvFlags};

    let mut byte = [0_u8; 1];
    // Non-destructive (peek) + non-blocking probe on the borrowed fd. The second
    // tuple field is recv()'s return: > 0 => live, 0 => clean EOF (dead);
    // EWOULDBLOCK/EAGAIN => live (idle warm socket, the normal case).
    match recv(stream, &mut byte, RecvFlags::PEEK | RecvFlags::DONTWAIT) {
        Ok((_, peeked)) => peeked > 0,
        Err(err) => err == Errno::WOULDBLOCK || err == Errno::AGAIN,
    }
}

#[cfg(not(unix))]
fn warm_session_is_live(_stream: &TcpStream) -> bool {
    true
}

/// State of the shared mux session, used to single-flight establishment WITHOUT
/// holding the pool mutex across the (up to 15s) network handshake. `Building`
/// carries a `Notify` the in-flight builder fires on completion (success or
/// failure) so every concurrently-waiting connection shares the one attempt
/// instead of serializing a fresh 15s handshake each behind the lock.
enum MuxState {
    /// No session and nobody building one.
    Idle,
    /// A build is in flight; waiters park on this `Notify`.
    Building(Arc<Notify>),
    /// A live (or possibly now-stale) session; reusability is re-checked.
    Ready(ClientMuxHandle),
}

#[derive(Clone)]
struct ClientMuxPool {
    inner: Arc<Mutex<MuxState>>,
    /// Monotonic ms of the last real connection served by `handle()`. The warm-
    /// keeper consults it to refill a dead tunnel only during active-use windows
    /// (so an idle client never re-handshakes on a 24/7 timer).
    last_activity: Arc<AtomicU64>,
    config: Arc<ClientConfig>,
    server_addr: ServerAddrResolver,
    traffic: TrafficConfig,
    udp: Arc<UdpConfig>,
    reachability: Arc<UdpReachability>,
    psk: Arc<Zeroizing<Vec<u8>>>,
    server_public: [u8; 32],
    server_identity_public: Arc<[u8]>,
}

#[derive(Clone)]
struct ClientMuxHandle {
    frame_tx: mpsc::Sender<MuxFrame>,
    register_tx: mpsc::Sender<ClientStreamControl>,
    next_stream_id: Arc<AtomicU32>,
    stream_slots: Arc<Semaphore>,
    chunk_size: usize,
    payload_pool: MuxPayloadPool,
}

impl ClientMuxHandle {
    /// A cached mux session may be reused only if BOTH of its background tasks
    /// are still alive. `frame_tx`'s receiver (`frame_rx`) is owned by the WRITER
    /// task; `register_tx`'s receiver (`register_rx`) is owned by the READER task.
    /// Either task can exit independently (most importantly, the reader returns
    /// `Ok` on a clean server->client half-close FIN while a cover-disabled writer
    /// keeps blocking on `frame_rx.recv()`), so both channels must be checked —
    /// otherwise a half-dead session is handed out and every new local connection
    /// fails at `register_tx.send`.
    fn is_reusable(&self) -> bool {
        !self.frame_tx.is_closed() && !self.register_tx.is_closed()
    }
}

/// Hands a freshly opened stream's local write half to the single mux reader
/// loop, which owns every download half and writes decrypted payloads inline
/// (mirroring the server's upload path). `outcome_tx` lets the reader report
/// stream completion back to the per-connection task that holds the slot
/// permit, so the download direction no longer needs a per-stream task.
struct ClientStreamRegistration {
    stream_id: u32,
    local_write: OwnedWriteHalf,
    outcome_tx: oneshot::Sender<DownloadOutcome>,
}

/// Control messages a per-connection task sends to the single mux reader loop.
enum ClientStreamControl {
    /// Hand a newly opened stream's download half to the reader.
    Register(ClientStreamRegistration),
    /// Drop a stream's download half because its per-connection task has exited.
    /// Sent after the per-connection `try_join!` returns so the reader-owned
    /// `OwnedWriteHalf` cannot leak when the stream ends without a server
    /// `Fin`/`Reset` (e.g. the local upload half errored). Idempotent: a no-op if
    /// the reader already removed the stream on a server `Fin`/`Reset`.
    Deregister(u32),
}

#[derive(Clone, Copy)]
enum DownloadOutcome {
    Fin,
    Reset,
}

impl ClientMuxPool {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: Arc<ClientConfig>,
        server_addr: ServerAddrResolver,
        traffic: TrafficConfig,
        udp: Arc<UdpConfig>,
        reachability: Arc<UdpReachability>,
        psk: Arc<Zeroizing<Vec<u8>>>,
        server_public: [u8; 32],
        server_identity_public: Arc<[u8]>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MuxState::Idle)),
            last_activity: Arc::new(AtomicU64::new(0)),
            config,
            server_addr,
            traffic,
            udp,
            reachability,
            psk,
            server_public,
            server_identity_public,
        }
    }

    /// Records activity (so the warm-keeper keeps a tunnel ready during active
    /// use), then returns a reusable mux session, building one if needed.
    async fn handle(&self) -> Result<ClientMuxHandle, ClientRuntimeError> {
        self.last_activity
            .store(relay_now_millis(), Ordering::Relaxed);
        self.get_or_build().await
    }

    async fn get_or_build(&self) -> Result<ClientMuxHandle, ClientRuntimeError> {
        loop {
            let mut state = self.inner.lock().await;
            // Decide an action without awaiting under the lock. The match yields an
            // OWNED value so its borrow of `state` ends before we touch the guard.
            let waiting_notify: Option<Arc<Notify>> = match &*state {
                // A cached session is only reusable if BOTH of its tasks are alive
                // (see ClientMuxHandle::is_reusable). The reader can exit
                // independently of the writer — e.g. on a clean server->client
                // half-close FIN the reader returns Ok while the cover-disabled
                // writer blocks forever on frame_rx.recv(). Probing only the writer
                // would keep handing out a half-dead handle whose register_tx is
                // closed, and every new local connection would fail at
                // register_tx.send. A stale Ready falls through to a rebuild.
                MuxState::Ready(handle) if handle.is_reusable() => {
                    return Ok(handle.clone());
                }
                MuxState::Building(notify) => Some(notify.clone()),
                // Idle, or a stale (non-reusable) Ready: we become the builder.
                _ => None,
            };

            match waiting_notify {
                Some(notify) => {
                    // Another connection is establishing the session. Register for
                    // its completion wakeup BEFORE dropping the lock (lost-wakeup
                    // safety: a notify_waiters() racing our unlock is not missed),
                    // then wait off-lock and re-check.
                    let notified = notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    drop(state);
                    notified.await;
                    continue;
                }
                None => {
                    // Sole builder: publish Building, release the lock, and run the
                    // (up to CLIENT_ESTABLISH_TIMEOUT) handshake OFF-LOCK so a slow
                    // or stalling server cannot block every other local connection
                    // behind this mutex — the M-7 fix. Concurrent callers share
                    // this single attempt instead of serializing a fresh handshake.
                    let notify = Arc::new(Notify::new());
                    *state = MuxState::Building(Arc::clone(&notify));
                    drop(state);

                    // Run establishment in a detached task and await its handle, so a
                    // PANIC inside start_session() surfaces as Err(JoinError) and is
                    // handled on the normal path below (reset Building->Idle + notify)
                    // instead of unwinding past the reset and stranding every waiter
                    // on a Notify that never fires. This restores the panic self-heal
                    // the pre-single-flight lock-holding code had, WITHOUT a
                    // try_lock-in-Drop guard (which could miss the reset under lock
                    // contention). handle() callers run it in detached spawns, so the
                    // future itself is never cancelled mid-await.
                    let pool = self.clone();
                    let result = match tokio::spawn(async move { pool.start_session().await }).await
                    {
                        Ok(r) => r,
                        Err(join_err) => {
                            tracing::warn!(
                                error = %join_err,
                                "client mux establishment task failed (panic); resetting"
                            );
                            Err(ClientRuntimeError::Io(io::Error::other(
                                "client mux establishment task panicked",
                            )))
                        }
                    };
                    let mut state = self.inner.lock().await;
                    let outcome = match result {
                        Ok(handle) => {
                            *state = MuxState::Ready(handle.clone());
                            Ok(handle)
                        }
                        Err(err) => {
                            // Reset so a waiter re-loops and one becomes the next
                            // builder (preserves the original retry-on-failure).
                            *state = MuxState::Idle;
                            Err(err)
                        }
                    };
                    drop(state);
                    notify.notify_waiters();
                    return outcome;
                }
            }
        }
    }

    fn ensure_started(&self) {
        let pool = self.clone();
        tokio::spawn(async move {
            // Initial warm at startup.
            if let Err(err) = pool.get_or_build().await {
                tracing::debug!(error = %err, "client mux warm session startup failed");
            }
            // Warm-keeper: during active-use windows, proactively rebuild a dead
            // shared tunnel so the next local connection finds it warm (resilience
            // to a mid-session RST/blackhole). Outside the active window, let it
            // idle out — no 24/7 re-handshake churn. Uses get_or_build (not handle)
            // so the keeper never bumps last_activity and thus never perpetuates
            // itself past genuine idle.
            //
            // The 5s poll emits NO packets (a local lock check); only a rebuild
            // ATTEMPT touches the network. So FAILED rebuilds (server blocked /
            // blackholed) use exponential backoff + jitter and a hard attempt cap,
            // after which the keeper goes dormant until fresh local activity — a
            // clock-locked retry burst to a dead endpoint is itself a covert tell.
            let mut failures: u32 = 0;
            let mut next_rebuild_at: u64 = 0;
            // last_activity value at which we gave up; stay dormant until it advances.
            let mut dormant_after: Option<u64> = None;
            loop {
                sleep(MUX_WARM_KEEPER_INTERVAL).await;
                let alive = {
                    let state = pool.inner.lock().await;
                    matches!(&*state, MuxState::Ready(handle) if handle.is_reusable())
                };
                if alive {
                    failures = 0;
                    next_rebuild_at = 0;
                    dormant_after = None;
                    continue;
                }
                let act = pool.last_activity.load(Ordering::Relaxed);
                let now = relay_now_millis();
                if now.saturating_sub(act) > MUX_WARM_KEEPER_ACTIVE_WINDOW.as_millis() as u64 {
                    // Idled out cleanly (not an establishment failure): don't rebuild.
                    failures = 0;
                    next_rebuild_at = 0;
                    dormant_after = None;
                    continue;
                }
                // Dead + recently active. If we already gave up after repeated
                // failures, stay dormant until a NEW local connection arrives
                // (last_activity advances past the point we gave up).
                if let Some(gave_up_at) = dormant_after {
                    if act <= gave_up_at {
                        continue;
                    }
                    dormant_after = None;
                    failures = 0;
                    next_rebuild_at = 0;
                }
                // Respect the exponential backoff between failed attempts.
                if now < next_rebuild_at {
                    continue;
                }
                match pool.get_or_build().await {
                    Ok(_) => {
                        failures = 0;
                        next_rebuild_at = 0;
                    }
                    Err(err) => {
                        failures += 1;
                        let base_ms = MUX_WARM_KEEPER_INTERVAL.as_millis() as u64;
                        let backoff_ms = base_ms
                            .saturating_mul(1u64 << failures.min(4))
                            .min(MUX_WARM_KEEPER_MAX_BACKOFF.as_millis() as u64);
                        // +/-25% jitter (low bits of the ms clock; jitter only needs
                        // to decorrelate retry timing, not be cryptographic) so the
                        // attempts are not a fixed metronome.
                        let spread = (backoff_ms / 2).max(1);
                        let wait =
                            backoff_ms.saturating_sub(spread / 2) + relay_now_millis() % spread;
                        next_rebuild_at = relay_now_millis().saturating_add(wait);
                        if failures >= MUX_WARM_KEEPER_MAX_REBUILD_FAILURES {
                            dormant_after = Some(act);
                        }
                        tracing::debug!(
                            error = %err,
                            failures,
                            "client mux warm refill failed; backing off"
                        );
                    }
                }
            }
        });
    }

    async fn start_session(&self) -> Result<ClientMuxHandle, ClientRuntimeError> {
        let (server, data_session, retained_quic) =
            establish_authenticated_data_session_with_resolver(
                &self.server_addr,
                self.config.as_ref(),
                self.traffic,
                &self.udp,
                &self.reachability,
                self.psk.as_ref().as_slice(),
                &self.server_public,
                Arc::clone(&self.server_identity_public),
            )
            .await?;
        // Mux stays on TCP in this slice: close any retained QUIC connection.
        if let Some(retained) = retained_quic {
            retained.close();
        }
        let (server_read, server_write) = server.into_split();
        let (seal_to_server, open_from_server) = data_session.into_data_codecs();
        let stream_limit = self.traffic.max_concurrent_streams as usize;
        let channel_capacity = stream_limit
            .saturating_mul(MUX_FRAME_CHANNEL_PER_STREAM)
            .max(1);
        let (frame_tx, frame_rx) = mpsc::channel(channel_capacity);
        let (register_tx, register_rx) = mpsc::channel(stream_limit.max(1));
        let session_cid = NEXT_CLIENT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let chunk_size = max_plaintext_len(self.traffic.max_padding);
        let payload_pool = MuxPayloadPool::with_capacity(MuxFrame::max_payload_len(chunk_size));
        tokio::spawn(async move {
            if let Err(err) = client_mux_reader_loop(
                TcpLegReader::buffered(server_read),
                open_from_server,
                register_rx,
                session_cid,
                CLIENT_RELAY_IDLE_TIMEOUT,
            )
            .await
            {
                tracing::debug!(cid = session_cid, error = %err, "client mux reader stopped");
            }
        });
        let cover = CoverTrafficProfile::from_config(self.traffic);
        let writer_pool = payload_pool.clone();
        tokio::spawn(async move {
            if let Err(err) = client_mux_writer_loop(
                TcpLegWriter(server_write),
                seal_to_server,
                frame_rx,
                cover,
                session_cid,
                writer_pool,
            )
            .await
            {
                tracing::debug!(cid = session_cid, error = %err, "client mux writer stopped");
            }
        });

        Ok(ClientMuxHandle {
            frame_tx,
            register_tx,
            next_stream_id: Arc::new(AtomicU32::new(1)),
            stream_slots: Arc::new(Semaphore::new(stream_limit)),
            chunk_size,
            payload_pool,
        })
    }
}

async fn handle_local_mux_connection_with_cid(
    mut local: TcpStream,
    mux_pool: ClientMuxPool,
    cid: u64,
) -> Result<(), ClientRuntimeError> {
    tune_tcp_stream(&local)?;
    tracing::debug!(
        cid,
        task_name = "client-mux-connection",
        "accepted SOCKS connection for mux session"
    );

    let request =
        match tokio::time::timeout(SOCKS_ACCEPT_TIMEOUT, socks::accept_connect(&mut local)).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "SOCKS handshake timed out").into(),
                );
            }
        };
    let mux = mux_pool.handle().await?;
    let _stream_permit = Arc::clone(&mux.stream_slots)
        .acquire_owned()
        .await
        .map_err(|_| io::Error::other("client mux stream limiter was closed"))?;
    let stream_id = next_mux_stream_id(&mux.next_stream_id);
    let initial_payload_cap = MuxFrame::max_open_initial_payload_len(&request.host, mux.chunk_size);
    let initial_payload = initial_payload::read_initial_payload(&mut local, initial_payload_cap)
        .await
        .map_err(ClientRuntimeError::Io)?;
    let connect_request = ConnectRequest {
        host: request.host,
        port: request.port,
        initial_payload,
    };
    let connect_payload = connect_request.encode()?;
    let open_frame = MuxFrame {
        stream_id,
        kind: MuxFrameKind::Open,
        payload: connect_payload,
    };

    let (local_read, local_write) = local.into_split();
    let (outcome_tx, outcome_rx) = oneshot::channel();
    // Register the download half with the reader before announcing the stream,
    // so an immediate server response can never race ahead of the write half.
    if mux
        .register_tx
        .send(ClientStreamControl::Register(ClientStreamRegistration {
            stream_id,
            local_write,
            outcome_tx,
        }))
        .await
        .is_err()
    {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "client mux reader is gone").into());
    }
    if let Err(err) = mux.frame_tx.send(open_frame).await {
        // Register succeeded but the Open frame never reached the server:
        // deregister the just-registered stream so the reader drops its cached
        // write half + outcome_tx instead of leaking them (no Fin/Reset will ever
        // arrive for a stream the server never saw).
        let _ = mux
            .register_tx
            .send(ClientStreamControl::Deregister(stream_id))
            .await;
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()).into());
    }

    let upload = client_mux_upload_loop(
        local_read,
        mux.frame_tx.clone(),
        stream_id,
        mux.chunk_size,
        cid,
        mux.payload_pool.clone(),
    );
    let download = client_mux_await_download(outcome_rx, cid);
    // Wait for BOTH halves. A clean server Fin (DownloadOutcome::Fin -> Ok)
    // resolves the download future but must NOT cancel the upload: the local app
    // may still be sending (TCP half-close), and the server deliberately keeps
    // its client->target write half open on Fin. try_join! keeps draining the
    // upload until local EOF (which sends the upstream Fin), and short-circuits
    // only on a Reset/error (DownloadOutcome::Reset -> Err), which the teardown
    // below turns into an upstream Reset. Cancelling the upload here would
    // silently drop in-flight client->server bytes and break half-close.
    let result = tokio::try_join!(upload, download).map(|_| ());

    // Tear the stream down on both ends so it cannot leak when it ended without a
    // server Fin/Reset (e.g. the local upload half errored before a clean Fin).
    // On an abnormal end, reset the server side so its target socket is released;
    // always deregister so the reader drops the local write half. Both are
    // idempotent no-ops if the stream was already removed via a server Fin/Reset.
    if result.is_err() {
        let _ = mux
            .frame_tx
            .send(MuxFrame {
                stream_id,
                kind: MuxFrameKind::Reset,
                payload: Vec::new(),
            })
            .await;
    }
    let _ = mux
        .register_tx
        .send(ClientStreamControl::Deregister(stream_id))
        .await;
    result
}

fn next_mux_stream_id(next: &AtomicU32) -> u32 {
    next.fetch_add(2, Ordering::Relaxed) | 1
}

async fn handle_local_connection_with_cid(
    mut local: TcpStream,
    context: ClientConnectionContext<'_>,
    cid: u64,
) -> Result<(), ClientRuntimeError> {
    let ClientConnectionContext {
        config,
        server_addr,
        traffic,
        udp,
        reachability,
        psk,
        server_public,
        server_identity_public,
        warm_sessions,
    } = context;
    tune_tcp_stream(&local)?;
    tracing::debug!(
        cid,
        task_name = "client-connection",
        "accepted SOCKS connection"
    );
    // Browser SOCKS clients normally send CONNECT immediately after opening the
    // local TCP socket, so pre-establish the upstream ParallaX session while the
    // local SOCKS request is still arriving.
    let server_session_task = if let Some(warm_sessions) = &warm_sessions {
        warm_sessions.take_or_start().await
    } else {
        let speculative_config = config.clone();
        let speculative_server_addr = server_addr.clone();
        let speculative_udp = udp.clone();
        let speculative_reachability = Arc::clone(&reachability);
        // Wrap the speculative-path PSK copy in Zeroizing so it is wiped when the
        // spawned task's Arc drops, matching the canonical PSK and the warm/mux
        // pools (which keep Arc<Zeroizing<Vec<u8>>>); a bare Arc<[u8]> would leave
        // a plaintext PSK copy un-wiped on this single-connect path.
        let speculative_psk = Arc::new(Zeroizing::new(psk.to_vec()));
        let speculative_server_public = *server_public;
        let speculative_server_identity_public = server_identity_public.clone();
        tokio::spawn(async move {
            establish_authenticated_data_session_with_resolver(
                &speculative_server_addr,
                &speculative_config,
                traffic,
                &speculative_udp,
                &speculative_reachability,
                speculative_psk.as_slice(),
                &speculative_server_public,
                speculative_server_identity_public,
            )
            .await
        })
    };
    // Abort handle for the speculative/warm session task: if the local SOCKS
    // request errors out below, we must ABORT the spawned task (not just drop its
    // JoinHandle, which detaches it and lets it run a full handshake + QUIC connect
    // to completion, transiently holding a retained QUIC connection when udp is on).
    let session_abort = server_session_task.abort_handle();
    let request =
        match tokio::time::timeout(SOCKS_ACCEPT_TIMEOUT, socks::accept_connect(&mut local)).await {
            Ok(Ok(request)) => request,
            Ok(Err(err)) => {
                server_session_task.abort();
                return Err(err.into());
            }
            Err(_elapsed) => {
                server_session_task.abort();
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "SOCKS handshake timed out").into(),
                );
            }
        };
    let chunk_size = max_plaintext_len(traffic.max_padding);
    let initial_payload_cap = ConnectRequest::max_initial_payload_len(&request.host, chunk_size);
    // Keep the zero-RTT-style initial payload capture, but hide its small wait
    // behind the remote TCP/TLS setup instead of putting it on the critical path.
    let initial_payload_fut = async {
        initial_payload::read_initial_payload(&mut local, initial_payload_cap)
            .await
            .map_err(ClientRuntimeError::Io)
    };
    let server_session_fut = async {
        server_session_task
            .await
            .map_err(ClientRuntimeError::BlockingTask)?
    };
    let (initial_payload, (mut server, mut data_session, retained_quic)) =
        match tokio::try_join!(initial_payload_fut, server_session_fut) {
            Ok(joined) => joined,
            Err(err) => {
                // The upstream session task lives inside `server_session_fut`. If
                // `try_join!` short-circuited on the initial-payload read error,
                // dropping that future does NOT abort the task (Tokio detaches a
                // dropped JoinHandle), so the speculative authenticated upstream
                // session would keep running -- completing a full handshake + QUIC
                // connect and transiently holding a server connection slot and a
                // retained QUIC connection (when udp is on). Abort it explicitly so
                // a stalled/failed local SOCKS exchange cannot orphan it.
                session_abort.abort();
                return Err(err);
            }
        };
    let connect_request = ConnectRequest {
        host: request.host,
        port: request.port,
        initial_payload,
    };
    let connect_plaintext_len = connect_request.encoded_len();
    let connect_record = data_session.build_connect_record(connect_request, &mut OsRng)?;
    log_outer_write(
        cid,
        "client->server",
        "client-handshake",
        connect_plaintext_len,
        &connect_record,
    );
    server.write_all(&connect_record).await?;

    let (local_read, local_write) = local.into_split();
    let (server_read, server_write) = server.into_split();
    ClientRelay {
        local_read,
        local_write,
        server_read,
        server_write,
        data_session,
        chunk_size,
        cover: CoverTrafficProfile::from_config(traffic),
        retained_quic,
        cid,
    }
    .run()
    .await
}

pub(crate) async fn establish_authenticated_data_session(
    config: &ClientConfig,
    traffic: TrafficConfig,
    udp: &UdpConfig,
    psk: &[u8],
    server_public: &[u8; 32],
    server_identity_public: &[u8],
) -> Result<(TcpStream, ClientDataSession), ClientRuntimeError> {
    let server_addr = ServerAddrResolver::new(&config.server_addr).await?;
    let server_identity_public =
        Arc::<[u8]>::from(server_identity_public.to_vec().into_boxed_slice());
    // One-shot seam (speed test): a fresh breaker just means this single
    // establishment probes normally, exactly as before this slice.
    let reachability = UdpReachability::new(UDP_BLACKHOLE_TTL);
    let (server, data_session, retained_quic) = establish_authenticated_data_session_with_resolver(
        &server_addr,
        config,
        traffic,
        udp,
        &reachability,
        psk,
        server_public,
        server_identity_public,
    )
    .await?;
    // This public seam feeds the speed-test path, which stays on TCP in this
    // slice: close any retained QUIC connection rather than leaving it idle.
    if let Some(retained) = retained_quic {
        retained.close();
    }
    Ok((server, data_session))
}

/// A QUIC fast-plane connection the client has retained for the data relay after
/// a Verified probe, together with the client `Endpoint` that owns it and the
/// HTTP/3 stream set established during the probe. ALL of these must stay alive
/// for the relay's whole duration: dropping the last `Connection` handle
/// application-closes the connection, dropping the `Endpoint` stops driving its
/// I/O, and the control/encoder streams must stay open per RFC 9114 §6.2.1. The
/// request bidi (`relay_send`/`relay_recv`) carried the probe round-trip and now
/// continues to carry the relay (DATA-framed). Carried through the session seam to
/// `ClientRelay`.
struct RetainedClientQuic {
    endpoint: crate::transport::udp::quic::endpoint::Endpoint,
    conn: crate::transport::udp::quic::endpoint::Connection,
    /// HTTP/3 control + encoder uni streams, held open for the connection's life.
    h3_control: crate::transport::udp::h3::H3ControlStreams,
    /// The request bidi's send/recv halves. The probe round-trip already ran on
    /// this stream (HEADERS + DATA); the relay continues on the SAME stream.
    relay_send: crate::transport::udp::quic::endpoint::SendStream,
    relay_recv: crate::transport::udp::quic::endpoint::RecvStream,
}

impl RetainedClientQuic {
    /// Promptly application-closes the retained connection (and its endpoint) when
    /// a non-single-Connect path (Mux/SpeedTest) keeps the relay on TCP, so no
    /// idle fast-plane connection lingers. A bare drop also closes it; this just
    /// makes the CONNECTION_CLOSE immediate.
    fn close(self) {
        self.conn.close(0u32.into(), b"tcp-path");
        self.endpoint.close(0u32.into(), b"tcp-path");
    }
}

/// Outcome of the client UDP probe: the classification plus, on `Verified`, the
/// retained connection + endpoint + H3 streams to carry the relay.
struct ClientProbeResult {
    outcome: crate::transport::udp::probe::ProbeOutcome,
    /// `Some` only when `outcome` is `Verified`: the live QUIC connection + H3
    /// stream set kept alive for the data relay. `None` otherwise (everything is
    /// dropped, staying on TCP).
    retained: Option<RetainedClientQuic>,
}

/// Current Unix time in milliseconds, for `obfuscated_ticket_age` and the ticket
/// age epoch. A pre-1970 clock (impossible in practice) clamps to 0.
fn current_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Process-wide single-slot cache of the most recent QUIC resumption ticket for the
/// configured server. The client runtime is one-per-process with a single server,
/// so one slot suffices (mirroring the server's process-wide 0-RTT state). Each
/// 0-RTT connect CONSUMES the stored ticket (single-use); a successful session
/// deposits a fresh one for the next.
fn client_quic_ticket_slot() -> &'static std::sync::Mutex<Option<crate::tls::quic::ClientTicket>> {
    static SLOT: std::sync::OnceLock<std::sync::Mutex<Option<crate::tls::quic::ClientTicket>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::Mutex::new(None))
}

/// Probe the offered UDP fast plane over a fresh QUIC connection to the server's
/// IP and the offered port. Never errors — failures map to Unreachable/Failed so
/// the caller can always report a PX1P and keep the control stream aligned. On a
/// Verified probe the connection, its endpoint, and the established HTTP/3 stream
/// set are RETAINED (returned to the caller) so the data relay continues on the
/// SAME request bidi; on any other outcome they are dropped here.
///
/// The probe rides an HTTP/3 request bidi (RFC 9114): after opening the control
/// stream (SETTINGS), the client opens the request bidi and writes HEADERS + a
/// DATA frame carrying the probe request, reads the server's HEADERS + DATA(probe
/// response), then opens the QPACK encoder stream — matching Safari's control ->
/// request -> encoder stream order. The exporter-bound auth is unchanged; only the
/// carrier is H3 framing.
///
/// `sni` is the camouflage front domain (the client's REALITY SNI), used as both
/// the QUIC ClientHello server name AND the request's `:authority`; it is never
/// the literal "localhost", which would be a zero-false-positive censorship
/// signature on the wire.
async fn run_client_udp_probe(
    server: &TcpStream,
    offer: &crate::protocol::command::UdpOffer,
    psk: &[u8],
    server_public: &[u8; 32],
    sni: &str,
    probe_timeout: std::time::Duration,
) -> ClientProbeResult {
    use crate::transport::udp::probe::ProbeOutcome;
    let failed = || ClientProbeResult {
        outcome: ProbeOutcome::Failed,
        retained: None,
    };
    let unreachable = || ClientProbeResult {
        outcome: ProbeOutcome::Unreachable,
        retained: None,
    };
    let Ok(peer) = server.peer_addr() else {
        return failed();
    };
    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(endpoint) = crate::transport::udp::endpoint::bind_client_endpoint_accept_any(
        bind.parse().expect("valid wildcard bind address"),
    )
    .await
    else {
        return failed();
    };
    // Emit the covert auth marker in ClientHello.random so the server's stable-:443
    // carrier marker-terminates us (every unmarked Initial it splices to the real
    // origin). The marker binds the shared PSK to an ECDH with the server's static
    // X25519 key; an unauthenticated prober cannot forge it. Overrides the
    // accept-any default config installed by the bind helper.
    endpoint.set_default_client_config(std::sync::Arc::new(
        crate::tls::quic::ClientConfig::new(
            std::sync::Arc::new(crate::tls::quic::AcceptAnyServerCert),
            vec![crate::transport::udp::UDP_ALPN.to_vec()],
        )
        .with_marker(crate::tls::quic::QuicMarkerConfig {
            psk: zeroize::Zeroizing::new(psk.to_vec()),
            server_static_public: *server_public,
        }),
    ));
    let udp_addr = std::net::SocketAddr::new(peer.ip(), offer.udp_port);
    // 0-RTT resumption when a ticket from a prior session is cached: the connect
    // returns BEFORE the handshake completes, so the H3 control SETTINGS and the
    // probe request are sent as 0-RTT early data; we then await the handshake and
    // verify the response under the 1-RTT exporter token. Only the non-sensitive
    // probe request (a random challenge) rides 0-RTT — the relay payload waits for
    // the verified (commit-late) 1-RTT path. The cached ticket is CONSUMED on use
    // (single-use). With no ticket, a normal cold 1-RTT handshake + probe runs,
    // byte-identical to before.
    let stored_ticket = client_quic_ticket_slot().lock().unwrap().take();
    let (conn, control_send, relay_send, relay_recv, outcome) = if let Some(ticket) = stored_ticket
    {
        let conn = match tokio::time::timeout(
            probe_timeout,
            endpoint.connect_resumption_0rtt_with_dcid(
                udp_addr,
                sni,
                ticket,
                current_unix_millis(),
                crate::transport::udp::quic::packet::ConnectionId::new(&offer.offer_id),
            ),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            _ => return unreachable(),
        };
        // Control SETTINGS as 0-RTT early data (same stream order as cold start).
        let control_send = match tokio::time::timeout(
            probe_timeout,
            crate::transport::udp::h3::open_h3_control_stream(&conn),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return unreachable(),
        };
        let (mut relay_send, mut relay_recv) = conn.open_bi();
        // Probe request (HEADERS + DATA) as 0-RTT early data — no exporter token is
        // needed to SEND it (the token only gates response verification).
        let nonce = match crate::transport::udp::probe::probe_client_send_request_early(
            &mut relay_send,
            sni,
        )
        .await
        {
            Ok(nonce) => nonce,
            Err(_) => return unreachable(),
        };
        // Await the 1-RTT handshake, then verify under the exporter token. If the
        // server rejected 0-RTT, the early data was retransmitted under 1-RTT by loss
        // recovery, so the server still has the request.
        match tokio::time::timeout(probe_timeout, conn.wait_established()).await {
            Ok(Ok(())) => {}
            _ => return unreachable(),
        }
        let outcome = crate::transport::udp::probe::probe_client_read_and_verify(
            &conn,
            &mut relay_recv,
            &nonce,
            psk,
            &offer.offer_id,
            probe_timeout,
        )
        .await
        .unwrap_or(ProbeOutcome::Failed);
        (conn, control_send, relay_send, relay_recv, outcome)
    } else {
        let conn = match tokio::time::timeout(
            probe_timeout,
            endpoint.connect_with_dcid(
                udp_addr,
                sni,
                crate::transport::udp::quic::packet::ConnectionId::new(&offer.offer_id),
            ),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            _ => return unreachable(),
        };

        // H3 stream order: control (SETTINGS) -> request bidi (probe) -> encoder.
        // Timeout-bounded like the other post-connect H3 steps (open_bi/encoder
        // open/SETTINGS read below): the client accepts any server cert during the
        // probe handshake (AcceptAnyServerCert), so an on-path peer that completes the
        // unauthenticated QUIC handshake but advertises `initial_max_streams_uni=0`
        // and never sends MAX_STREAMS would otherwise stall this `open_uni` forever —
        // the probe would never return, never write PX1P, never fall back to TCP. On
        // timeout/error treat as Unreachable (stay on TCP).
        let control_send = match tokio::time::timeout(
            probe_timeout,
            crate::transport::udp::h3::open_h3_control_stream(&conn),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return unreachable(),
        };
        // The hand-rolled `open_bi` is synchronous and infallible (it allocates the
        // stream id locally; flow-control is enforced when bytes are transmitted), so
        // it neither awaits nor returns a Result.
        let (mut relay_send, mut relay_recv) = conn.open_bi();
        let outcome = crate::transport::udp::probe::probe_client_over_bidi(
            &conn,
            &mut relay_send,
            &mut relay_recv,
            sni,
            psk,
            &offer.offer_id,
            probe_timeout,
        )
        .await
        .unwrap_or(ProbeOutcome::Failed);
        (conn, control_send, relay_send, relay_recv, outcome)
    };

    match outcome {
        ProbeOutcome::Verified { .. } => {
            // Probe Verified: open the QPACK encoder stream (last in Safari's
            // stream order), then retain everything for the relay on the SAME bidi.
            // Timeout-bounded like the other post-connect H3 steps: a non-
            // cooperative peer that grants bidi/control credit but withholds uni
            // credit (`initial_max_streams_uni`) could otherwise stall `open_uni`
            // here indefinitely. On timeout/error treat as Unreachable (stay on TCP).
            let encoder_send = match tokio::time::timeout(
                probe_timeout,
                crate::transport::udp::h3::open_h3_encoder_stream(&conn),
            )
            .await
            {
                Ok(Ok(s)) => s,
                // The connection died right after a Verified probe (or the peer
                // withheld uni credit past the deadline); treat as Unreachable so
                // the client stays on TCP rather than reporting a Verified path it
                // can no longer use.
                _ => return unreachable(),
            };
            // Read + verify the server's H3 SETTINGS off its control stream (the
            // server opened its control stream before serving the bidi probe, so it
            // is already in flight; no deadlock). A peer that does not advertise
            // Safari-26's SETTINGS is a protocol divergence -> stay on TCP.
            //
            // LOCKSTEP: this requires the server's SETTINGS to be Safari-26-SHAPED
            // — the two QPACK params exact, the GREASE setting per-connection random
            // so only its reserved form is checked (see `is_safari26_settings`). The
            // server sends those same Safari-26 SETTINGS, and keeps that shape: the
            // server's stable carrier already splices every unauthenticated Initial to
            // the real origin, so this SETTINGS exchange happens only between our own
            // client and server (a prober sees the TRUE origin's SETTINGS via the
            // splice). Both sides just have to agree on the Safari-26 shape — they do.
            match tokio::time::timeout(
                probe_timeout,
                crate::transport::udp::h3::read_peer_h3_settings(&conn),
            )
            .await
            {
                Ok(Ok(settings)) if crate::fingerprint::http3::is_safari26_settings(&settings) => {}
                _ => return unreachable(),
            }
            // Deposit a fresh single-use resumption ticket for the next session's
            // 0-RTT (the prior ticket, if any, was consumed at connect). The server
            // issues its NewSessionTicket post-handshake; if it has not arrived yet
            // this is `None` and the next session simply starts cold.
            if let Some(fresh) = conn.take_session_ticket(current_unix_millis()) {
                *client_quic_ticket_slot().lock().unwrap() = Some(fresh);
            }
            ClientProbeResult {
                outcome,
                retained: Some(RetainedClientQuic {
                    endpoint,
                    conn,
                    h3_control: crate::transport::udp::h3::H3ControlStreams::new(
                        control_send,
                        encoder_send,
                    ),
                    relay_send,
                    relay_recv,
                }),
            }
        }
        // Drop conn + endpoint + streams (function-local) -> connection closes,
        // stay on TCP.
        _ => ClientProbeResult {
            outcome,
            retained: None,
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn establish_authenticated_data_session_with_resolver(
    server_addr: &ServerAddrResolver,
    config: &ClientConfig,
    traffic: TrafficConfig,
    udp: &UdpConfig,
    reachability: &UdpReachability,
    psk: &[u8],
    server_public: &[u8; 32],
    server_identity_public: Arc<[u8]>,
) -> Result<(TcpStream, ClientDataSession, Option<RetainedClientQuic>), ClientRuntimeError> {
    // Bound the entire post-connect establishment (camouflage TLS .complete(),
    // PQ-rekey read, server-identity read/verify, AND the fail-soft UDP
    // negotiation). Without a deadline an unresponsive or impersonating upstream —
    // which any on-path adversary in front of the single configured server can be —
    // that completes the cheap TCP+camouflage handshake then stalls would hang this
    // task forever while it holds a global connection permit (relay path) or leaks
    // an eagerly pre-established warm/mux session, letting the adversary exhaust
    // client resources without authenticating. The server already bounds its
    // symmetric handshake reads with HANDSHAKE_TIMEOUT; this is the client mirror.
    // The UDP negotiation lives inside the inner fn so its record exchange + probe
    // are covered by the same deadline.
    match timeout(
        CLIENT_ESTABLISH_TIMEOUT,
        establish_authenticated_data_session_inner(
            server_addr,
            config,
            traffic,
            udp,
            reachability,
            psk,
            server_public,
            server_identity_public,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(ClientRuntimeError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "ParallaX server did not complete the authenticated establishment in time",
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
async fn establish_authenticated_data_session_inner(
    server_addr: &ServerAddrResolver,
    config: &ClientConfig,
    traffic: TrafficConfig,
    udp: &UdpConfig,
    reachability: &UdpReachability,
    psk: &[u8],
    server_public: &[u8; 32],
    server_identity_public: Arc<[u8]>,
) -> Result<(TcpStream, ClientDataSession, Option<RetainedClientQuic>), ClientRuntimeError> {
    let (mut server, mut data_session) =
        connect_and_establish_data_session(server_addr, config, traffic, psk, server_public)
            .await?;
    let (pq_record, pending_rekey) = data_session.build_pq_rekey_record(&mut OsRng)?;
    server.write_all(&pq_record).await?;
    apply_server_key_exchange_after_residuals(&mut server, &mut data_session, &pending_rekey, psk)
        .await?;
    let identity_payload = read_server_identity_payload(&mut server, &mut data_session).await?;
    verify_server_identity_payload_blocking(
        &data_session,
        identity_payload,
        server_identity_public,
        server_public,
    )
    .await?;

    // The QUIC connection retained for the data relay, set only when the probe is
    // Verified. `None` keeps the relay on TCP, byte-identical to before this slice.
    let mut retained_quic: Option<RetainedClientQuic> = None;

    // Client-initiated, fail-soft UDP negotiation. Gated on the threaded
    // udp.enabled flag AND the reachability circuit breaker: once a probe has
    // found UDP unusable (black-holed, declined, or malformed), the breaker
    // suppresses this whole block for UDP_BLACKHOLE_TTL so we neither pay the
    // probe_timeout stall on every connection nor emit the PX1G/PX1N pair that
    // would otherwise tell on a UDP-blocked or UDP-declining path. Suppressed, the
    // session is byte-identical to a TCP-only one (the server only ever reacts to
    // PX1G being present), so this cannot desync. When the breaker DOES allow a
    // run, it occupies record #1 in each AEAD direction before the first
    // Connect/Mux command, with no reordering risk; an error here fails the
    // connection (the record stream would be desynced), which is correct.
    if udp.enabled && reachability.should_attempt() {
        use crate::protocol::command::{
            UdpDecline, UdpOffer, UdpProbeAck, UdpProbeStatus, UdpRequest, UDP_NEGOTIATION_VERSION,
        };
        use crate::transport::udp::probe::ProbeOutcome;

        let request = UdpRequest {
            version: UDP_NEGOTIATION_VERSION,
        }
        .encode();
        let request_record = data_session.seal_payload(&request, &mut OsRng)?;
        server.write_all(&request_record).await?;

        let mut response = Vec::new();
        {
            let mut reader = crate::tls::record::TlsRecordReader::new(&mut server);
            reader.read_record_into(&mut response).await?;
        }
        data_session.open_server_record_in_place(&mut response)?;

        if UdpOffer::has_magic(&response) {
            // The server offered the UDP fast plane: probe it, then ALWAYS report
            // the outcome with PX1P (the server always reads it) so the control
            // stream stays aligned regardless of the probe result.
            let (offer_id, probe) = match UdpOffer::decode(&response) {
                Ok(offer) => {
                    let probe_timeout =
                        std::time::Duration::from_millis(u64::from(udp.probe_timeout_ms.max(1)));
                    let probe = run_client_udp_probe(
                        &server,
                        &offer,
                        psk,
                        server_public,
                        &config.sni,
                        probe_timeout,
                    )
                    .await;
                    (offer.offer_id, probe)
                }
                Err(err) => {
                    tracing::debug!(error = %err, "udp offer decode failed");
                    (
                        [0_u8; 16],
                        ClientProbeResult {
                            outcome: ProbeOutcome::Failed,
                            retained: None,
                        },
                    )
                }
            };
            let ClientProbeResult { outcome, retained } = probe;
            let status = match outcome {
                ProbeOutcome::Verified { .. } => UdpProbeStatus::Verified,
                ProbeOutcome::Unreachable => UdpProbeStatus::Unreachable,
                ProbeOutcome::Failed => UdpProbeStatus::Failed,
            };
            let rtt_micros = match outcome {
                ProbeOutcome::Verified { rtt } => rtt.as_micros().min(u128::from(u32::MAX)) as u32,
                _ => 0,
            };
            tracing::info!(?status, "UDP fast-plane probe outcome");
            // Drive the circuit breaker: a Verified path clears it; any unusable
            // outcome trips it so subsequent connections skip negotiation for the
            // TTL (removing the probe stall + the negotiation tell).
            match outcome {
                ProbeOutcome::Verified { .. } => reachability.record_usable(),
                ProbeOutcome::Unreachable | ProbeOutcome::Failed => reachability.record_unusable(),
            }
            let ack = UdpProbeAck {
                offer_id,
                status,
                rtt_micros,
            }
            .encode();
            let ack_record = data_session.seal_payload(&ack, &mut OsRng)?;
            server.write_all(&ack_record).await?;
            // Retain the connection (Verified only) for the data relay. The server
            // retains on the SAME signal (the PX1P status just sent), so both ends
            // agree on whether the relay will use the QUIC stream.
            retained_quic = retained;
        } else if UdpDecline::has_magic(&response) {
            // The server declines UDP (config asymmetry): trip the breaker so we
            // stop emitting the PX1G/PX1N pair on every connection to a server that
            // will keep declining.
            reachability.record_unusable();
            tracing::info!("UDP fast plane declined by server; continuing on TCP");
        } else {
            reachability.record_unusable();
            tracing::info!("UDP negotiation: unrecognized response; continuing on TCP");
        }
    }

    Ok((server, data_session, retained_quic))
}

#[derive(Clone)]
struct ServerAddrResolver {
    original: Arc<str>,
    cached: Arc<Mutex<SocketAddr>>,
    literal: bool,
}

impl ServerAddrResolver {
    async fn new(server_addr: &str) -> Result<Self, ClientRuntimeError> {
        let parsed = server_addr.parse::<SocketAddr>().ok();
        let initial = match parsed {
            Some(addr) => addr,
            None => resolve_client_server_addr(server_addr).await?,
        };
        Ok(Self {
            original: Arc::<str>::from(server_addr),
            cached: Arc::new(Mutex::new(initial)),
            literal: parsed.is_some(),
        })
    }

    async fn connect(&self) -> Result<TcpStream, ClientRuntimeError> {
        let cached = *self.cached.lock().await;
        match connect_tuned_tcp_addr(cached).await {
            Ok(stream) => Ok(stream),
            Err(err) if self.literal => Err(err.into()),
            Err(first_err) => {
                let refreshed = resolve_client_server_addr(self.original.as_ref()).await?;
                *self.cached.lock().await = refreshed;
                if refreshed == cached {
                    return Err(first_err.into());
                }
                Ok(connect_tuned_tcp_addr(refreshed).await?)
            }
        }
    }
}

async fn resolve_client_server_addr(server_addr: &str) -> Result<SocketAddr, ClientRuntimeError> {
    if let Ok(addr) = server_addr.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let mut addrs = lookup_host(server_addr).await?;
    addrs.next().ok_or_else(|| {
        ClientRuntimeError::Io(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("client.server_addr did not resolve: {server_addr}"),
        ))
    })
}

/// Reads the server's PQ key-exchange (PX1K), tolerating residual camouflage
/// records the fallback origin may have raced ahead, and reassembling the
/// key-exchange across its FramedChunk records (PAR-21). `pub(crate)` so the
/// server-side loopback test harness can drive the real client receive path.
pub(crate) async fn apply_server_key_exchange_after_residuals<R>(
    server: &mut R,
    data_session: &mut ClientDataSession,
    pending_rekey: &PendingPqRekey,
    psk: &[u8],
) -> Result<(), ClientRuntimeError>
where
    R: AsyncRead + Unpin,
{
    let mut server_records = TlsRecordReader::new(server);
    let mut record = Vec::new();
    let mut skipped = 0;
    // The server now splits PX1K across several FramedChunk records (PAR-21);
    // accumulate them here. Residual camouflage records (the fallback origin's
    // H2 response racing ahead) fail to open and are skipped up to the budget,
    // exactly as before; the PX1K chunks arrive contiguously once they start.
    let mut reassembler = FramedReassembler::default();
    loop {
        server_records.read_record_into(&mut record).await?;
        match apply_server_key_exchange_record_blocking(
            data_session,
            &mut record,
            pending_rekey,
            psk,
            &mut reassembler,
        )
        .await
        {
            Ok(true) => {
                if skipped > 0 {
                    tracing::warn!(
                        skipped,
                        budget = MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE,
                        "accepted server key exchange after skipping residual camouflage records"
                    );
                }
                return Ok(());
            }
            Ok(false) => {
                // Accepted one PX1K chunk; keep reading until the frame completes.
                continue;
            }
            Err(ClientRuntimeError::Handshake(err)) if is_residual_camouflage_record(&err) => {
                if skipped < MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE {
                    skipped += 1;
                    // Loud-on-purpose: hitting this path at all means the
                    // camouflage host is racing ahead of the ParallaX server's
                    // key-exchange record. We still tolerate it up to the
                    // budget, but operators need to see it without bumping the
                    // global log level to trace.
                    tracing::warn!(
                        skipped,
                        budget = MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE,
                        record_len = record.len(),
                        "skipping residual camouflage TLS record before ParallaX key exchange"
                    );
                } else {
                    // Fast-fail: do NOT silently keep reading. Surface this as
                    // a hard error with the exact diagnostic an operator needs
                    // (skipped count, last record length, underlying cause) so
                    // a future "灵异事件" never has to be reverse-engineered
                    // from a blank log.
                    tracing::error!(
                        skipped,
                        budget = MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE,
                        record_len = record.len(),
                        error = %err,
                        "exceeded residual camouflage record budget before ParallaX key exchange; \
                         fallback host likely answered the H2 camouflage GET ahead of the \
                         ParallaX server's key-exchange record"
                    );
                    return Err(ClientRuntimeError::Handshake(err));
                }
            }
            Err(err) => return Err(err),
        }
    }
}

async fn apply_server_key_exchange_record_blocking(
    data_session: &mut ClientDataSession,
    record: &mut Vec<u8>,
    pending_rekey: &PendingPqRekey,
    psk: &[u8],
    reassembler: &mut FramedReassembler,
) -> Result<bool, ClientRuntimeError> {
    // Opening fails on a residual camouflage record; the caller treats that as
    // skippable. A ParallaX record opens to a PX1K FramedChunk, which we
    // accumulate until the whole key-exchange frame is recovered (Ok(false) =>
    // need more chunks), then decode and apply the rekey once (Ok(true)).
    let chunk_range = data_session.open_server_record_in_place_payload_range(record)?;
    let exchange_payload = match reassembler
        .push(&record[chunk_range], MAX_PQ_HANDSHAKE_FRAME)
        .map_err(ClientHandshakeError::from)?
    {
        Some(payload) => payload,
        None => return Ok(false),
    };
    let (exchange, cipher_suite) = ServerKeyExchange::decode_ref_with_suite(&exchange_payload)
        .map_err(ClientHandshakeError::from)?;
    let pq_identity_binding = pending_rekey.identity_binding(&exchange_payload);
    let x25519_shared =
        zeroize::Zeroizing::new(pending_rekey.x25519_shared_secret(&exchange.server_x25519_public));
    let mlkem_ciphertext = exchange.mlkem_ciphertext.to_vec();
    let secret_key = zeroize::Zeroizing::new(pending_rekey.mlkem_secret_key().to_vec());
    let pq_shared = zeroize::Zeroizing::new(
        tokio::task::spawn_blocking(move || {
            pq::decapsulate(&mlkem_ciphertext, secret_key.as_slice())
                .map_err(ClientHandshakeError::from)
        })
        .await??,
    );
    data_session.apply_pq_rekey_shared_with_identity_binding(
        cipher_suite,
        &x25519_shared,
        &pq_shared,
        psk,
        pq_identity_binding,
    )?;
    Ok(true)
}

async fn verify_server_identity_payload_blocking(
    data_session: &ClientDataSession,
    payload: Vec<u8>,
    server_identity_public_key: Arc<[u8]>,
    server_x25519_public_key: &[u8; 32],
) -> Result<(), ClientRuntimeError> {
    let transcript_hash = data_session.transcript_hash();
    let server_x25519_public_key = *server_x25519_public_key;
    let pq_identity_binding = data_session.pq_identity_binding()?;
    let epoch = data_session.epoch();
    tokio::task::spawn_blocking(move || {
        let signature =
            ServerIdentityProof::signature(&payload).map_err(ClientHandshakeError::from)?;
        identity::verify_server_identity(
            server_identity_public_key.as_ref(),
            signature,
            &transcript_hash,
            &server_x25519_public_key,
            &pq_identity_binding,
            epoch,
        )
        .map_err(ClientHandshakeError::from)
    })
    .await??;
    Ok(())
}

fn is_residual_camouflage_record(err: &ClientHandshakeError) -> bool {
    matches!(
        err,
        ClientHandshakeError::DataRecord(
            DataRecordError::Aead(_) | DataRecordError::NotApplicationData
        )
    )
}

async fn read_server_identity_payload(
    server: &mut TcpStream,
    data_session: &mut ClientDataSession,
) -> Result<Vec<u8>, ClientRuntimeError> {
    let mut expected_total = None;
    let mut assembled = Vec::new();
    let mut server_records = TlsRecordReader::new(server);
    let mut record = Vec::new();

    loop {
        server_records.read_record_into(&mut record).await?;
        data_session.open_server_record_in_place(&mut record)?;
        let chunk = ServerIdentityChunk::decode_ref(&record).map_err(ClientHandshakeError::from)?;
        let total_len = chunk.total_len as usize;
        if total_len == 0 || total_len > MAX_SERVER_IDENTITY_PAYLOAD {
            return Err(ClientRuntimeError::ServerIdentityTooLarge);
        }
        match expected_total {
            Some(expected) if expected != total_len => {
                return Err(ClientRuntimeError::InvalidServerIdentityChunks);
            }
            None => {
                expected_total = Some(total_len);
                assembled.reserve(total_len);
            }
            _ => {}
        }
        if chunk.offset as usize != assembled.len() {
            return Err(ClientRuntimeError::InvalidServerIdentityChunks);
        }
        assembled.extend_from_slice(chunk.bytes);
        if assembled.len() == total_len {
            return Ok(assembled);
        }
        if assembled.len() > total_len {
            return Err(ClientRuntimeError::InvalidServerIdentityChunks);
        }
    }
}

async fn establish_data_session(
    server: &mut TcpStream,
    config: &ClientConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    server_public: &[u8; 32],
) -> Result<ClientDataSession, ClientRuntimeError> {
    let completed = Safari26TlsCamouflage
        .start(config.sni.clone(), psk, server_public)?
        .complete(server)
        .await?;
    let session_keys = client::derive_session_keys_from_shared(
        psk,
        completed.x25519_shared_secret(),
        &completed.client_hello,
        &completed.server_hello_record,
    )?;
    Ok(ClientDataSession::new(session_keys, traffic)?)
}

async fn connect_and_establish_data_session(
    server_addr: &ServerAddrResolver,
    config: &ClientConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    server_public: &[u8; 32],
) -> Result<(TcpStream, ClientDataSession), ClientRuntimeError> {
    let mut server = server_addr.connect().await?;
    tune_tcp_stream(&server)?;
    let data_session =
        establish_data_session(&mut server, config, traffic, psk, server_public).await?;
    Ok((server, data_session))
}

struct ClientRelay {
    local_read: OwnedReadHalf,
    local_write: OwnedWriteHalf,
    server_read: OwnedReadHalf,
    server_write: OwnedWriteHalf,
    data_session: ClientDataSession,
    chunk_size: usize,
    cover: CoverTrafficProfile,
    /// Retained QUIC fast-plane endpoint + connection when the probe was Verified.
    /// `Some` => carry the relay over a reliable bidi stream (the client is the
    /// bidi opener); `None` => the relay stays on the TCP record legs exactly as
    /// before this slice.
    retained_quic: Option<RetainedClientQuic>,
    cid: u64,
}

/// Generous backstop on the teardown DONE read. The read is PRIMARILY bounded on
/// connection liveness (`conn.closed()`), but the 15s keep-alive masks the ~60s
/// idle timeout for a peer that is alive-but-stuck (e.g. a target that responds
/// then stops reading the request body, blocking the server's upload drain
/// forever). Without a backstop the completed side would park in the DONE
/// handshake indefinitely, pinning the QUIC connection + endpoint + TCP control
/// connection. This bound resets such a stuck teardown; it is deliberately large
/// so a legitimately slow-but-progressing drain is not cut.
const QUIC_RELAY_DONE_BACKSTOP: Duration = Duration::from_secs(120);

/// Brief grace, applied AFTER the teardown DONE `select!` takes its
/// `conn.closed()` arm, for the reliable TCP DONE to arrive. The peer sends its
/// DONE over the TCP control stream and THEN closes the QUIC connection, so the
/// CONNECTION_CLOSE can reorder ahead of the already-sent TCP DONE bytes and trip
/// the biased select's `conn.closed()` arm even on a fully-successful relay. No
/// data is lost (the app already has everything); without this grace the relay
/// would spuriously error. Small: the DONE was sent before the peer closed, so it
/// is at most one TCP delivery away.
const QUIC_RELAY_DONE_GRACE: Duration = Duration::from_secs(2);

impl ClientRelay {
    async fn run(self) -> Result<(), ClientRuntimeError> {
        let ClientRelay {
            local_read,
            local_write,
            server_read,
            server_write,
            data_session,
            chunk_size,
            cover,
            retained_quic,
            cid,
        } = self;
        let local_buf = vec![0_u8; relay_read_buffer_len(chunk_size)];
        let (seal_to_server, open_from_server) = data_session.into_data_codecs();

        // Shared idle backstop for the relay (main's DoS hardening). Without it a
        // server that goes silent (e.g. an on-path adversary holding the single
        // configured server connection) keeps this relay's global connection permit
        // and both fds pinned forever; after enough such sessions the client
        // silently stops accepting new local SOCKS connections. Only real payload
        // bytes in either direction reset the clock; cover records do not. The
        // watchdog wraps BOTH relay paths (QUIC fast plane and TCP).
        let activity: ClientRelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));

        // QUIC fast-plane path: the probe was Verified on BOTH ends, so the client
        // (the bidi opener) opens a reliable bidi stream and carries both relay
        // directions over it. Direction mapping: open_bi gives (send = client->
        // server, recv = server->client), so client_upload (local->server) writes
        // the SendStream and client_download (server->client) reads the RecvStream.
        if let Some(retained) = retained_quic {
            let RetainedClientQuic {
                endpoint,
                conn,
                h3_control,
                relay_send,
                relay_recv,
            } = retained;
            // Hold the endpoint + connection + H3 control streams alive for the
            // relay's whole duration. The control/encoder uni streams must stay
            // open per RFC 9114 §6.2.1; `_endpoint` must not drop early.
            let _endpoint = endpoint;
            let _h3_control = h3_control;
            // Keep the TCP control halves alive too so the outer TCP connection
            // stays open for the relay's duration (the server likewise holds its
            // TCP halves). They carry no relay DATA, but they DO carry the
            // teardown DONE handshake: the TCP control stream is reliable and
            // independent of the QUIC connection close, so it can coordinate a
            // safe, truncation-free teardown after the QUIC relay finishes.
            // `server_read` is consumed by the DONE handshake; `server_write`
            // needs `mut` to write our DONE marker.
            let mut server_write = server_write;

            // The HTTP/3 control set and the request bidi were established during
            // the probe (control -> request[HEADERS+DATA probe] -> encoder), and
            // the probe round-trip already woke the server's `accept_bi`. The relay
            // continues on the SAME request bidi, now carrying DATA-framed sealed
            // records — no rendezvous trigger record is needed (the probe HEADERS
            // already triggered the stream). The relay leg wraps each record batch
            // in an H3 DATA frame and the reader strips DATA headers.
            let server_write_leg = H3DataFrameLegWriter(relay_send);
            let upload = client_upload_loop(
                local_read,
                server_write_leg,
                seal_to_server,
                local_buf,
                cover,
                activity.clone(),
                cid,
            );
            // The download loop shuts the local write half down on the server's
            // clean EOF (the app sees its response EOF immediately, decoupled from
            // the upload direction -- read-until-close apps depend on this).
            let download = client_download_loop(
                H3DataFrameLegReader::buffered(relay_recv),
                local_write,
                open_from_server,
                activity.clone(),
                cid,
            );
            // Application-level DONE handshake over the reliable TCP control stream.
            // quinn 0.11.9's Connection::close ABANDONS undelivered stream data, so
            // closing the QUIC connection right after our own try_join could
            // silently truncate an upload tail the server is still draining into a
            // slow target. After both directions finish, each side seals a DONE on
            // its send codec, writes it over TCP, then reads the peer's DONE (bounded
            // on connection liveness via select against conn.closed(), so a slow-but-
            // alive drain is never cut short) before closing the QUIC connection. The
            // local app already saw its clean response EOF the instant the download
            // direction finished, so a DONE failure -- rare, a genuine connection
            // loss after the download completed while the upload was still draining --
            // surfaces as Err here but the app has already moved on (documented
            // residual, ~TCP-equivalent: a mid-relay network failure).
            //
            // The relay is also bounded by the shared idle backstop: if neither
            // direction moves a real payload byte for CLIENT_RELAY_IDLE_TIMEOUT, the
            // watchdog fires, we close the QUIC connection, and return Ok WITHOUT the
            // DONE handshake (a forced teardown of a genuinely-idle relay). A live-
            // but-slow drain keeps bumping `activity`, so the backstop never cuts it.
            let relay = async { tokio::try_join!(upload, download) };
            let relay_outcome = tokio::select! {
                joined = relay => Some(joined),
                _ = client_relay_idle_watchdog(activity, CLIENT_RELAY_IDLE_TIMEOUT) => {
                    tracing::debug!(
                        cid,
                        "client QUIC fast-plane relay idle backstop reached; tearing down"
                    );
                    None
                }
            };
            match relay_outcome {
                None => {
                    conn.close(RELAY_IDLE_CLOSE_CODE.into(), b"relay-idle");
                    Ok(())
                }
                Some(Ok((mut seal_to_server, mut open_from_server))) => {
                    let result = client_exchange_quic_done(
                        &conn,
                        &mut server_write,
                        server_read,
                        &mut seal_to_server,
                        &mut open_from_server,
                        cid,
                    )
                    .await;
                    conn.close(0u32.into(), b"relay-done");
                    result
                }
                Some(Err(err)) => {
                    // If the server's idle watchdog fired first, the relay error
                    // here is a benign mutual idle teardown — recognize it and
                    // return Ok instead of a spurious error, so an operator may
                    // tighten the server idle floor without the client reporting a
                    // failure. The close is an idempotent no-op (peer already closed).
                    if is_peer_idle_close(&conn) {
                        conn.close(RELAY_IDLE_CLOSE_CODE.into(), b"relay-idle");
                        return Ok(());
                    }
                    conn.close(0u32.into(), b"relay-error");
                    Err(err)
                }
            }
        } else {
            // No retained QUIC connection: TCP record legs, byte-identical to
            // before this slice. The download loop shuts the local write half down
            // on the server's clean EOF (immediate, decoupled from the upload
            // direction -- so read-until-close apps get their response EOF and can
            // close); the per-direction codecs are discarded (no DONE handshake on
            // the TCP path -- TCP delivers reliably and FIN/EOF is a clean,
            // fully-delivered close). The relay is bounded by the same idle backstop
            // as the server's DataRelay.
            let upload = client_upload_loop(
                local_read,
                TcpLegWriter(server_write),
                seal_to_server,
                local_buf,
                cover,
                activity.clone(),
                cid,
            );
            let download = client_download_loop(
                TcpLegReader::buffered(server_read),
                local_write,
                open_from_server,
                activity.clone(),
                cid,
            );
            tokio::select! {
                result = async {
                    tokio::try_join!(upload, download)
                        .map(|(_seal_to_server, _open_from_server)| ())
                } => result,
                _ = client_relay_idle_watchdog(activity, CLIENT_RELAY_IDLE_TIMEOUT) => {
                    tracing::debug!(cid, "client relay idle backstop reached; tearing down");
                    Ok(())
                }
            }
        }
    }
}

/// Monotonic milliseconds since a process-local epoch, backing the lock-free
/// client relay activity clock. Coarse (ms) granularity is ample for the idle
/// backstop (timeouts are whole seconds) and lets the clock live in one atomic.
fn relay_now_millis() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Shared last-activity clock for a client relay, reset on every real payload
/// byte moved in either direction (cover records excluded). Lock-free: both relay
/// directions and the watchdog touch it with a single relaxed atomic, so the hot
/// path never contends on a mutex.
type ClientRelayActivity = Arc<AtomicU64>;

fn bump_client_relay_activity(activity: &ClientRelayActivity) {
    activity.store(relay_now_millis(), Ordering::Relaxed);
}

async fn client_relay_idle_watchdog(activity: ClientRelayActivity, idle_timeout: Duration) {
    let timeout_ms = idle_timeout.as_millis() as u64;
    loop {
        let elapsed_ms = relay_now_millis().saturating_sub(activity.load(Ordering::Relaxed));
        if elapsed_ms >= timeout_ms {
            return;
        }
        sleep(idle_timeout.saturating_sub(Duration::from_millis(elapsed_ms))).await;
    }
}

/// Performs the client side of the QUIC fast-plane teardown DONE handshake over
/// the held TCP control stream halves, using the SAME per-direction session
/// codecs the relay used so the sequence numbers continue uninterrupted. It
/// seals and writes our DONE, then reads, opens, and verifies the server's DONE.
/// The DONE read is bounded on CONNECTION LIVENESS (`conn.closed()`), not a wall
/// clock, so a slow-but-alive server draining a large upload tail is never
/// truncated. Returns Ok only when both DONEs are exchanged; the caller closes
/// the QUIC connection afterward (on Ok) or eagerly (on Err).
async fn client_exchange_quic_done(
    conn: &crate::transport::udp::quic::endpoint::Connection,
    server_write: &mut OwnedWriteHalf,
    server_read: OwnedReadHalf,
    seal_to_server: &mut DataRecordCodec,
    open_from_server: &mut DataRecordCodec,
    cid: u64,
) -> Result<(), ClientRuntimeError> {
    // Seal our DONE on the client->server (send) codec -- its next sequence
    // number -- and write it over the reliable TCP control stream.
    let done = seal_to_server
        .seal(QUIC_RELAY_DONE_MARKER, &mut OsRng)
        .map_err(ClientHandshakeError::from)?;
    // Bound the DONE write+flush with the same backstop as the DONE read below: a
    // peer that stops reading the reliable TCP control stream during teardown must
    // not pin the slot/fds forever.
    match tokio::time::timeout(QUIC_RELAY_DONE_BACKSTOP, async {
        server_write
            .write_all(&done)
            .await
            .map_err(ClientRuntimeError::Io)?;
        server_write.flush().await.map_err(ClientRuntimeError::Io)?;
        Ok::<(), ClientRuntimeError>(())
    })
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            tracing::warn!(cid, "QUIC fast-plane teardown DONE write backstop elapsed");
            return Err(ClientRuntimeError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "QUIC fast-plane teardown DONE write backstop elapsed",
            )));
        }
    }

    // Read exactly ONE record (the server's DONE) over the TCP control stream.
    // The read is bounded on CONNECTION LIVENESS, not a wall clock: we `select!`
    // it against `conn.closed()`. While the server is alive (actively draining our
    // upload tail + the 15s keep-alive PINGs keeping the QUIC connection up),
    // `conn.closed()` pends and this read blocks for as long as the server
    // legitimately needs -- a multi-minute drain is fine, with no fixed cap to
    // truncate a slow-but-alive peer. If the server genuinely vanishes, the QUIC
    // connection idle-times-out (~60s, configured) and `conn.closed()` resolves,
    // yielding a clean Err. EOF on the TCP read is likewise NOT a clean close: we
    // require the server's explicit DONE record.
    let mut reader = TlsRecordReader::new(server_read);
    let mut record = Vec::new();
    // PRIMARY bound: connection liveness (`conn.closed()`), so a slow-but-alive
    // drain is never cut. BACKSTOP: a generous wall-clock timeout, because the 15s
    // keep-alive masks the idle timeout for an alive-but-stuck peer -- without it a
    // completed side would park here forever pinning the connection.
    //
    // The inner select yields a SENTINEL rather than concluding: `Ok(true)` means
    // the DONE record was read into `record`; `Ok(false)` means `conn.closed()`
    // fired first. The grace read runs AFTER the select returns (so the `reader`/
    // `record` borrows the select held are released -- no double-mutable borrow)
    // to absorb a teardown reorder: the peer sends its DONE over the reliable TCP
    // control stream and THEN closes the QUIC connection, so the CONNECTION_CLOSE
    // can reorder ahead of the already-sent TCP DONE bytes and trip the
    // `conn.closed()` arm even on a fully-successful relay. No data is lost (the
    // app already has everything); the grace just lets the in-flight DONE land
    // before we conclude failure.
    let read_done = async {
        tokio::select! {
            // `biased`: poll the DONE read FIRST so an already-arrived peer DONE
            // (sent over TCP before the peer closes QUIC) wins over a concurrently-
            // ready `conn.closed()`; otherwise a fully successful relay could be
            // reported as a failure.
            biased;
            res = reader.read_record_into(&mut record) => res.map(|()| true).map_err(ClientRuntimeError::Io),
            _ = crate::transport::udp::endpoint::conn_closed(conn) => Ok(false),
        }
    };
    let done_read = match tokio::time::timeout(QUIC_RELAY_DONE_BACKSTOP, read_done).await {
        Ok(res) => res?,
        Err(_) => {
            tracing::warn!(cid, "QUIC fast-plane teardown DONE backstop elapsed");
            return Err(ClientRuntimeError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "QUIC fast-plane teardown DONE backstop elapsed",
            )));
        }
    };
    if !done_read {
        // `conn.closed()` won the select. The peer's TCP DONE was sent BEFORE it
        // closed the QUIC connection, so give it a brief grace to arrive over the
        // reliable control stream before concluding failure. This read runs after
        // the select returned, so the `reader`/`record` borrows are free.
        match tokio::time::timeout(QUIC_RELAY_DONE_GRACE, reader.read_record_into(&mut record))
            .await
        {
            Ok(Ok(())) => {}
            _ => {
                return Err(ClientRuntimeError::Io(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "QUIC connection closed before peer DONE",
                )));
            }
        }
    }
    let plaintext = open_from_server
        .open_in_place_payload_range(&mut record)
        .map_err(|err| ClientRuntimeError::Handshake(err.into()))?;
    if &record[plaintext] != QUIC_RELAY_DONE_MARKER {
        tracing::warn!(cid, "QUIC fast-plane teardown DONE marker mismatch");
        return Err(ClientRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "QUIC fast-plane teardown DONE marker mismatch",
        )));
    }
    Ok(())
}

/// Drains the local app -> server direction. Returns the owned `seal_to_server`
/// codec on a clean finish so the QUIC fast-plane teardown can seal the local
/// DONE marker on the SAME send-direction codec (sequence continues
/// uninterrupted). TCP-path callers discard the returned codec.
async fn client_upload_loop<W>(
    mut local_read: OwnedReadHalf,
    mut server_write: W,
    mut seal_to_server: DataRecordCodec,
    mut local_buf: Vec<u8>,
    cover: CoverTrafficProfile,
    activity: ClientRelayActivity,
    cid: u64,
) -> Result<DataRecordCodec, ClientRuntimeError>
where
    W: LegWriter,
{
    let mut seal_scratch = RelaySealScratch::with_payload_capacity(local_buf.len());
    let mut rng = StdRng::from_entropy();
    if !cover.is_enabled() {
        loop {
            let n = local_read.read(&mut local_buf).await?;
            if n == 0 {
                let _ = server_write.shutdown().await;
                return Ok(seal_to_server);
            }
            bump_client_relay_activity(&activity);
            let n = drain_ready_tcp_read(&local_read, &mut local_buf, n)?;
            write_client_data_records_chunked(
                &mut server_write,
                &mut seal_to_server,
                &local_buf[..n],
                &mut rng,
                &mut seal_scratch,
                RelayWriteLog::new(cid, "client->server", "client-upload-writer"),
            )
            .await?;
        }
    }

    let mut cover_sleep = Box::pin(sleep(cover.sample_interval(&mut rng)));

    loop {
        tokio::select! {
            _ = &mut cover_sleep, if cover.is_enabled() => {
                write_client_data_records_chunked(
                    &mut server_write,
                    &mut seal_to_server,
                    &[],
                    &mut rng,
                    &mut seal_scratch,
                    RelayWriteLog::new(cid, "client->server", "client-cover-writer"),
                )
                .await?;
                cover_sleep.as_mut().reset(Instant::now() + cover.sample_interval(&mut rng));
            }
            read = local_read.read(&mut local_buf) => {
                let n = read?;
                if n == 0 {
                    let _ = server_write.shutdown().await;
                    return Ok(seal_to_server);
                }
                bump_client_relay_activity(&activity);
                let n = drain_ready_tcp_read(&local_read, &mut local_buf, n)?;
                write_client_data_records_chunked(
                    &mut server_write,
                    &mut seal_to_server,
                    &local_buf[..n],
                    &mut rng,
                    &mut seal_scratch,
                    RelayWriteLog::new(cid, "client->server", "client-upload-writer"),
                )
                .await?;
            }
        }
    }
}

/// Drains the server -> local app direction. On a clean finish it shuts down the
/// local write half (so the app sees its response EOF IMMEDIATELY, decoupled from
/// the upload direction -- read-until-close apps depend on this) and returns the
/// owned `open_from_server` codec (so the QUIC fast-plane teardown can open the
/// peer's DONE marker on the SAME receive-direction codec, sequence
/// uninterrupted). On a mid-download ERROR it returns Err and drops the write half
/// into a graceful FIN -- a mid-download failure breaks the app connection.
async fn client_download_loop<R>(
    mut server_records: R,
    mut local_write: OwnedWriteHalf,
    mut open_from_server: DataRecordCodec,
    activity: ClientRelayActivity,
    cid: u64,
) -> Result<DataRecordCodec, ClientRuntimeError>
where
    R: LegReader,
{
    let mut server_record = Vec::new();
    // Scratch reused across iterations for the opportunistic batch-open path
    // (mirrors the mux reader): one extra-record staging buffer, one concatenated
    // record buffer, and one concatenated plaintext buffer.
    let mut extra_record = Vec::new();
    let mut batch_records = Vec::new();
    let mut batch_plaintext = Vec::new();
    let mut deferred_read_error: Option<io::Error> = None;

    loop {
        match deferred_read_error.take() {
            Some(err) if server_records.is_clean_close(&err) => {
                let _ = local_write.shutdown().await;
                return Ok(open_from_server);
            }
            Some(err) => return Err(ClientRuntimeError::Io(err)),
            None => match server_records.read_record_into(&mut server_record).await {
                Ok(()) => {}
                Err(err) if server_records.is_clean_close(&err) => {
                    let _ = local_write.shutdown().await;
                    return Ok(open_from_server);
                }
                Err(err) => return Err(ClientRuntimeError::Io(err)),
            },
        }
        log_record_read(cid, "server->client", "client-outer-reader", &server_record);

        // Opportunistically grab any records already buffered so a bulk burst is
        // opened across the crypto pool instead of pinning every open on this
        // task. A would-block (`None`) ends the drain with partial reader state
        // intact; a read error is deferred and surfaced on the next iteration,
        // after the records that did arrive have been relayed. The on-wire and
        // app-visible bytes are identical to opening each record in order — only
        // the CPU placement of the AEAD changes.
        let mut record_count = 1_usize;
        batch_records.clear();
        let mut batch_bytes = server_record.len();
        while batch_bytes < MUX_OPEN_BATCH_BYTES {
            match server_records.try_read_record_into(&mut extra_record).await {
                None => break,
                Some(Ok(())) => {
                    log_record_read(cid, "server->client", "client-outer-reader", &extra_record);
                    if record_count == 1 {
                        batch_records.extend_from_slice(&server_record);
                    }
                    batch_records.extend_from_slice(&extra_record);
                    batch_bytes += extra_record.len();
                    record_count += 1;
                }
                Some(Err(err)) => {
                    deferred_read_error = Some(err);
                    break;
                }
            }
        }

        if record_count == 1 {
            match open_from_server.open_in_place_payload_range(&mut server_record) {
                Ok(plaintext) => {
                    if !plaintext.is_empty() {
                        bump_client_relay_activity(&activity);
                        local_write.write_all(&server_record[plaintext]).await?;
                    }
                }
                Err(err) => {
                    return Err(ClientRuntimeError::Handshake(err.into()));
                }
            }
        } else {
            batch_plaintext.clear();
            let payload_bytes =
                batch_records.len() - record_count * crate::tls::record::TLS_HEADER_LEN;
            let opened = if should_parallelize_aead(record_count, payload_bytes) {
                open_from_server.open_concat_records_parallel(
                    parallel::global(),
                    &batch_records,
                    &mut batch_plaintext,
                )
            } else {
                open_from_server.open_concat_records(&mut batch_records, &mut batch_plaintext)
            };
            opened.map_err(|err| ClientRuntimeError::Handshake(err.into()))?;
            if !batch_plaintext.is_empty() {
                bump_client_relay_activity(&activity);
                local_write.write_all(&batch_plaintext).await?;
            }
        }
    }
}

async fn client_mux_upload_loop(
    mut local_read: OwnedReadHalf,
    frame_tx: mpsc::Sender<MuxFrame>,
    stream_id: u32,
    chunk_size: usize,
    cid: u64,
    payload_pool: MuxPayloadPool,
) -> Result<(), ClientRuntimeError> {
    let mut local_buf = vec![0_u8; relay_read_buffer_len(MuxFrame::max_payload_len(chunk_size))];
    let max_payload_len = MuxFrame::max_payload_len(chunk_size);
    if max_payload_len == 0 {
        return Err(ClientRuntimeError::TlsRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0),
        ));
    }

    loop {
        let n = local_read.read(&mut local_buf).await?;
        if n == 0 {
            send_mux_frame(&frame_tx, stream_id, MuxFrameKind::Fin, Vec::new()).await?;
            return Ok(());
        }
        let n = drain_ready_tcp_read(&local_read, &mut local_buf, n)?;
        for chunk in local_buf[..n].chunks(max_payload_len) {
            send_mux_frame(
                &frame_tx,
                stream_id,
                MuxFrameKind::Data,
                payload_pool.take_filled(chunk),
            )
            .await?;
        }
        tracing::trace!(
            cid,
            stream_id,
            bytes = n,
            "queued client mux upload payload"
        );
    }
}

/// A mux stream's local socket write half, owned by the reader loop, plus a
/// one-shot used to report the download direction's completion back to the
/// per-connection task that holds the stream's slot permit.
struct ClientDownloadStream {
    write: OwnedWriteHalf,
    outcome_tx: oneshot::Sender<DownloadOutcome>,
}

/// Resolves once the reader loop reports the download direction is done: a
/// server `Fin` (or the reader exiting) ends cleanly; a `Reset` surfaces as a
/// connection-reset error, matching the previous per-stream download task.
async fn client_mux_await_download(
    outcome_rx: oneshot::Receiver<DownloadOutcome>,
    cid: u64,
) -> Result<(), ClientRuntimeError> {
    match outcome_rx.await {
        Ok(DownloadOutcome::Fin) | Err(_) => Ok(()),
        Ok(DownloadOutcome::Reset) => Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("server reset mux stream for cid {cid}"),
        )
        .into()),
    }
}

/// Applies a control message to the reader-owned download-stream map. Register
/// inserts the stream's write half; Deregister removes and FIN-closes it. Keeping
/// this in one place ensures both the select arm and the opportunistic drain
/// handle deregistration identically.
async fn apply_client_stream_control(
    local_writes: &mut HashMap<u32, ClientDownloadStream>,
    control: ClientStreamControl,
) {
    match control {
        ClientStreamControl::Register(reg) => {
            local_writes.insert(
                reg.stream_id,
                ClientDownloadStream {
                    write: reg.local_write,
                    outcome_tx: reg.outcome_tx,
                },
            );
        }
        ClientStreamControl::Deregister(stream_id) => {
            if let Some(mut stream) = local_writes.remove(&stream_id) {
                let _ = stream.write.shutdown().await;
            }
        }
    }
}

async fn client_mux_reader_loop<R>(
    mut server_records: R,
    mut open_from_server: DataRecordCodec,
    mut register_rx: mpsc::Receiver<ClientStreamControl>,
    cid: u64,
    idle: Duration,
) -> Result<(), ClientRuntimeError>
where
    R: LegReader,
{
    let mut server_record = Vec::new();
    let mut extra_record = Vec::new();
    let mut batch_records = Vec::new();
    let mut batch_plaintext = Vec::new();
    let mut deferred_read_error: Option<io::Error> = None;
    let mut local_writes: HashMap<u32, ClientDownloadStream> = HashMap::new();
    let mut register_open = true;

    loop {
        let read_result = if let Some(err) = deferred_read_error.take() {
            Err(err)
        } else {
            tokio::select! {
                biased;
                registration = register_rx.recv(), if register_open => {
                    match registration {
                        Some(control) => {
                            apply_client_stream_control(&mut local_writes, control).await;
                        }
                        None => register_open = false,
                    }
                    continue;
                }
                // Idle backstop (H-2): without it, a server that goes silent parks
                // this SHARED per-session reader on the read forever, pinning the
                // connection permit, every per-connection task (each waiting on its
                // outcome_rx) with its stream permit and local fd — until the client
                // stops accepting new SOCKS connections. A real record resets the
                // clock implicitly (the read returns and the loop re-arms). Mirrors
                // the server's per-session mux backstop; the register arm stays
                // outside the timeout (it is liveness, not relay activity).
                result = timeout(
                    idle,
                    server_records.read_record_into(&mut server_record),
                ) => match result {
                    Ok(inner) => inner,
                    Err(_) => {
                        tracing::debug!(cid, "client mux idle backstop reached; tearing down session");
                        shutdown_client_download_streams(&mut local_writes, DownloadOutcome::Fin)
                            .await;
                        return Ok(());
                    }
                },
            }
        };
        match read_result {
            Ok(()) => {}
            Err(err) if server_records.is_clean_close(&err) => {
                shutdown_client_download_streams(&mut local_writes, DownloadOutcome::Fin).await;
                return Ok(());
            }
            Err(err) => {
                shutdown_client_download_streams(&mut local_writes, DownloadOutcome::Reset).await;
                return Err(ClientRuntimeError::Io(err));
            }
        }
        log_record_read(
            cid,
            "server->client",
            "client-mux-outer-reader",
            &server_record,
        );

        // Opportunistically grab any records that are already buffered so a
        // bulk burst can be opened across the crypto pool instead of pinning
        // every open on this task. A would-block leaves partial reader state
        // intact; a read error is surfaced on the next iteration, after the
        // records that did arrive have been relayed.
        let mut record_count = 1_usize;
        batch_records.clear();
        let mut batch_bytes = server_record.len();
        while batch_bytes < MUX_OPEN_BATCH_BYTES {
            match server_records.try_read_record_into(&mut extra_record).await {
                None => break,
                Some(Ok(())) => {
                    log_record_read(
                        cid,
                        "server->client",
                        "client-mux-outer-reader",
                        &extra_record,
                    );
                    if record_count == 1 {
                        batch_records.extend_from_slice(&server_record);
                    }
                    batch_records.extend_from_slice(&extra_record);
                    batch_bytes += extra_record.len();
                    record_count += 1;
                }
                Some(Err(err)) => {
                    deferred_read_error = Some(err);
                    break;
                }
            }
        }

        // Absorb any control messages queued alongside these records so a
        // stream's write half is always present before its first Data, and a
        // deregister from an exited per-connection task is applied promptly.
        while let Ok(control) = register_rx.try_recv() {
            apply_client_stream_control(&mut local_writes, control).await;
        }

        // Open + dispatch the batch. Any AEAD-open, decode, or dispatch error
        // here (e.g. an on-path byte-flip surfacing as DataRecordError::Aead, or a
        // codec desync) must signal each in-flight stream a Reset, exactly like the
        // hard read-error arm above — otherwise dropping `local_writes` drops every
        // outcome_tx, which client_mux_await_download maps to Ok(()) and delivers a
        // truncated download to the local app as a clean, complete response.
        let processed: Result<(), ClientRuntimeError> = async {
            let frames_payload: &[u8] = if record_count == 1 {
                let payload = open_from_server
                    .open_in_place_payload_range(&mut server_record)
                    .map_err(ClientHandshakeError::from)?;
                &server_record[payload]
            } else {
                // Frames never span records (the sender keeps records
                // frame-aligned), so decoding the concatenated plaintext is
                // equivalent to decoding each record's plaintext in order.
                batch_plaintext.clear();
                let payload_bytes =
                    batch_records.len() - record_count * crate::tls::record::TLS_HEADER_LEN;
                if should_parallelize_aead(record_count, payload_bytes) {
                    open_from_server
                        .open_concat_records_parallel(
                            parallel::global(),
                            &batch_records,
                            &mut batch_plaintext,
                        )
                        .map_err(ClientHandshakeError::from)?;
                } else {
                    open_from_server
                        .open_concat_records(&mut batch_records, &mut batch_plaintext)
                        .map_err(ClientHandshakeError::from)?;
                }
                batch_plaintext.as_slice()
            };
            let mut frames = frames_payload;
            while !frames.is_empty() {
                let (frame, used) = MuxFrame::decode_ref_prefix(frames)?;
                dispatch_client_mux_frame(&mut local_writes, frame, cid).await?;
                frames = &frames[used..];
            }
            Ok::<(), ClientRuntimeError>(())
        }
        .await;
        if let Err(err) = processed {
            shutdown_client_download_streams(&mut local_writes, DownloadOutcome::Reset).await;
            return Err(err);
        }
    }
}

/// Writes a decrypted download frame straight to its local socket. The payload
/// borrows the already-decrypted record buffer, so the relay hot path no longer
/// allocates or hops through a per-stream channel. A failing local write tears
/// down only that stream and keeps relaying the others.
async fn dispatch_client_mux_frame(
    local_writes: &mut HashMap<u32, ClientDownloadStream>,
    frame: MuxFrameRef<'_>,
    cid: u64,
) -> Result<(), ClientRuntimeError> {
    match frame.kind {
        MuxFrameKind::Data => {
            let write_failed = match local_writes.get_mut(&frame.stream_id) {
                Some(stream) if !frame.payload.is_empty() => {
                    stream.write.write_all(frame.payload).await.is_err()
                }
                _ => false,
            };
            if write_failed {
                if let Some(stream) = local_writes.remove(&frame.stream_id) {
                    tracing::debug!(
                        cid,
                        stream_id = frame.stream_id,
                        "client mux local write failed; dropping stream"
                    );
                    let _ = stream.outcome_tx.send(DownloadOutcome::Reset);
                }
            }
        }
        MuxFrameKind::Fin => {
            if let Some(mut stream) = local_writes.remove(&frame.stream_id) {
                let _ = stream.write.shutdown().await;
                let _ = stream.outcome_tx.send(DownloadOutcome::Fin);
            }
        }
        MuxFrameKind::Reset => {
            if let Some(mut stream) = local_writes.remove(&frame.stream_id) {
                let _ = stream.write.shutdown().await;
                let _ = stream.outcome_tx.send(DownloadOutcome::Reset);
            }
        }
        MuxFrameKind::Cover => {}
        MuxFrameKind::Open => {
            // The server never legitimately opens a stream toward the client
            // (the client is the mux initiator). Treat an unexpected Open as a
            // single-stream anomaly: reset that stream id if we know it and
            // otherwise ignore it. Crucially, do NOT propagate an error out of
            // the shared reader loop — doing so would tear down every concurrent
            // stream and (because the writer keeps the frame channel open) leave
            // the whole client mux session permanently poisoned until restart.
            tracing::debug!(
                cid,
                stream_id = frame.stream_id,
                "ignoring unexpected server-originated mux Open frame"
            );
            if let Some(mut stream) = local_writes.remove(&frame.stream_id) {
                let _ = stream.write.shutdown().await;
                let _ = stream.outcome_tx.send(DownloadOutcome::Reset);
            }
        }
    }
    Ok(())
}

/// Closes every download half when the session ends, signaling each waiting
/// per-connection task the REASON explicitly: a clean close sends Fin (graceful
/// EOF) while a hard session error sends Reset, so the local app sees a
/// connection error instead of a truncated response delivered as success. (The
/// old behavior relied on dropping the sender, which always mapped to a clean Fin.)
async fn shutdown_client_download_streams(
    local_writes: &mut HashMap<u32, ClientDownloadStream>,
    outcome: DownloadOutcome,
) {
    for (_, mut stream) in local_writes.drain() {
        let _ = stream.write.shutdown().await;
        let _ = stream.outcome_tx.send(outcome);
    }
}

async fn client_mux_writer_loop<W>(
    mut server_write: W,
    mut seal_to_server: DataRecordCodec,
    mut frame_rx: mpsc::Receiver<MuxFrame>,
    cover: CoverTrafficProfile,
    cid: u64,
    payload_pool: MuxPayloadPool,
) -> Result<(), ClientRuntimeError>
where
    W: LegWriter,
{
    let mut seal_scratch =
        RelaySealScratch::with_payload_capacity(seal_to_server.max_plaintext_len());
    let mut rng = StdRng::from_entropy();
    if !cover.is_enabled() {
        loop {
            let Some(frame) = frame_rx.recv().await else {
                let _ = server_write.shutdown().await;
                return Ok(());
            };
            write_client_mux_frames_batched(
                &mut server_write,
                &mut seal_to_server,
                frame,
                ClientMuxBatchState {
                    frame_rx: &mut frame_rx,
                },
                &mut rng,
                &mut seal_scratch,
                RelayWriteLog::new(cid, "client->server", "client-mux-writer"),
                &payload_pool,
            )
            .await?;
        }
    }

    let mut cover_sleep = Box::pin(sleep(cover.sample_interval(&mut rng)));

    loop {
        tokio::select! {
            _ = &mut cover_sleep, if cover.is_enabled() => {
                write_client_mux_frame(
                    &mut server_write,
                    &mut seal_to_server,
                    MuxFrame { stream_id: 0, kind: MuxFrameKind::Cover, payload: Vec::new() },
                    &mut rng,
                    &mut seal_scratch,
                    cid,
                    "client-mux-cover-writer",
                )
                .await?;
                cover_sleep.as_mut().reset(Instant::now() + cover.sample_interval(&mut rng));
            }
            frame = frame_rx.recv() => {
                let Some(frame) = frame else {
                    let _ = server_write.shutdown().await;
                    return Ok(());
                };
                write_client_mux_frames_batched(
                    &mut server_write,
                    &mut seal_to_server,
                    frame,
                    ClientMuxBatchState {
                        frame_rx: &mut frame_rx,
                    },
                    &mut rng,
                    &mut seal_scratch,
                    RelayWriteLog::new(cid, "client->server", "client-mux-writer"),
                    &payload_pool,
                )
                .await?;
            }
        }
    }
}

async fn write_client_mux_frame<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    frame: MuxFrame,
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    cid: u64,
    task_name: &'static str,
) -> Result<(), ClientRuntimeError>
where
    W: LegWriter,
    R: rand::Rng + rand::RngCore + rand::CryptoRng + ?Sized,
{
    let frame_payload = frame.encode()?;
    write_client_data_records_chunked(
        writer,
        codec,
        &frame_payload,
        rng,
        scratch,
        RelayWriteLog::new(cid, "client->server", task_name),
    )
    .await
}

struct ClientMuxBatchState<'a> {
    frame_rx: &'a mut mpsc::Receiver<MuxFrame>,
}

/// Encodes the first frame plus any immediately available frames into
/// frame-aligned plaintext records (one record per `max_plaintext_len`
/// window), then seals the whole batch — inline for small batches, fanned out
/// across the shared crypto pool for bulk — and writes the records in order
/// with a single socket write.
#[allow(clippy::too_many_arguments)]
async fn write_client_mux_frames_batched<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    first_frame: MuxFrame,
    batch: ClientMuxBatchState<'_>,
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    log: RelayWriteLog,
    payload_pool: &MuxPayloadPool,
) -> Result<(), ClientRuntimeError>
where
    W: LegWriter,
    R: rand::Rng + rand::RngCore + rand::CryptoRng + ?Sized,
{
    let max_plaintext_len = codec.max_plaintext_len();
    if max_plaintext_len == 0 {
        return Err(ClientRuntimeError::TlsRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0),
        ));
    }

    // Phase A: drain frames into frame-aligned plaintext records, tracking
    // each record's length so the record boundaries are fixed before sealing.
    scratch.plaintext_buf.clear();
    scratch.record_lens.clear();
    let mut record_plaintext_len = encode_client_mux_frame(
        &mut scratch.plaintext_buf,
        first_frame,
        max_plaintext_len,
        payload_pool,
    )?;

    let mut drained = 0;
    while drained < MUX_FRAME_BATCH_LIMIT {
        let frame = match batch.frame_rx.try_recv() {
            Ok(frame) => frame,
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        };
        let frame_len = MuxFrame::encoded_len(frame.payload.len())?;
        if record_plaintext_len + frame_len > max_plaintext_len {
            scratch.record_lens.push(record_plaintext_len);
            record_plaintext_len = 0;
        }
        record_plaintext_len += encode_client_mux_frame(
            &mut scratch.plaintext_buf,
            frame,
            max_plaintext_len,
            payload_pool,
        )?;
        drained += 1;
    }
    scratch.record_lens.push(record_plaintext_len);

    // Phase B: seal every record with unchanged boundaries and sequence
    // order; only the bulk path pays the crypto-pool dispatch cost.
    scratch.records_buf.clear();
    if should_parallelize_aead(scratch.record_lens.len(), scratch.plaintext_buf.len()) {
        codec
            .seal_records_into_parallel(
                parallel::global(),
                &scratch.plaintext_buf,
                &scratch.record_lens,
                rng,
                &mut scratch.records_buf,
            )
            .map_err(ClientHandshakeError::from)?;
    } else {
        codec
            .seal_records_into(
                &scratch.plaintext_buf,
                &scratch.record_lens,
                rng,
                &mut scratch.records_buf,
            )
            .map_err(ClientHandshakeError::from)?;
    }
    log_outer_write_batch(log, &scratch.record_lens, &scratch.records_buf);
    writer.write_records(scratch.records_buf.as_slice()).await?;
    scratch.records_buf.clear();
    Ok(())
}

/// Debug-logs each sealed record of a batch, mirroring the per-record
/// [`log_outer_write`] calls the serial writer used to make.
fn log_outer_write_batch(log: RelayWriteLog, record_lens: &[usize], records_buf: &[u8]) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let mut offset = 0;
    for &plaintext_len in record_lens {
        let Ok(header) = crate::tls::record::parse_header(&records_buf[offset..]) else {
            return;
        };
        log_outer_write(
            log.cid,
            log.direction,
            log.task_name,
            plaintext_len,
            &records_buf[offset..offset + header.total_len],
        );
        offset += header.total_len;
    }
}

fn encode_client_mux_frame(
    out: &mut Vec<u8>,
    frame: MuxFrame,
    max_plaintext_len: usize,
    payload_pool: &MuxPayloadPool,
) -> Result<usize, ClientRuntimeError> {
    let frame_len = MuxFrame::encoded_len(frame.payload.len())?;
    if frame_len > max_plaintext_len {
        return Err(ClientRuntimeError::TlsRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(frame_len),
        ));
    }
    frame.encode_into(out)?;
    payload_pool.put(frame.payload);
    Ok(frame_len)
}

async fn send_mux_frame(
    frame_tx: &mpsc::Sender<MuxFrame>,
    stream_id: u32,
    kind: MuxFrameKind,
    payload: Vec<u8>,
) -> Result<(), ClientRuntimeError> {
    frame_tx
        .send(MuxFrame {
            stream_id,
            kind,
            payload,
        })
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()).into())
}

async fn write_client_data_records_chunked<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    payload: &[u8],
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    log: RelayWriteLog,
) -> Result<(), ClientRuntimeError>
where
    W: LegWriter,
    R: rand::Rng + rand::RngCore + rand::CryptoRng + ?Sized,
{
    let max_chunk_len = codec.max_plaintext_len();
    if max_chunk_len == 0 {
        return Err(ClientRuntimeError::TlsRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(payload.len()),
        ));
    }
    scratch.records_buf.clear();
    let debug_records = tracing::enabled!(tracing::Level::DEBUG);
    if debug_records {
        codec
            .seal_chunks_into_reusing(payload, rng, &mut scratch.records_buf, &mut scratch.records)
            .map_err(ClientHandshakeError::from)?;
        for record in scratch.records.iter() {
            log_outer_write(
                log.cid,
                log.direction,
                log.task_name,
                record.plaintext_len,
                &scratch.records_buf[record.range.clone()],
            );
        }
    } else {
        codec
            .seal_chunks_into_untracked(payload, rng, &mut scratch.records_buf)
            .map_err(ClientHandshakeError::from)?;
    }
    writer.write_records(scratch.records_buf.as_slice()).await?;
    Ok(())
}

struct RelaySealScratch {
    records_buf: Vec<u8>,
    records: Vec<SealedRecord>,
    /// Frame-aligned record plaintext accumulated before sealing, so the seal
    /// can be fanned out across the crypto pool without changing record
    /// boundaries.
    plaintext_buf: Vec<u8>,
    record_lens: Vec<usize>,
}

impl RelaySealScratch {
    fn with_payload_capacity(capacity: usize) -> Self {
        Self {
            records_buf: Vec::with_capacity(capacity + crate::tls::record::TLS_HEADER_LEN),
            records: Vec::new(),
            plaintext_buf: Vec::with_capacity(capacity),
            record_lens: Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
struct RelayWriteLog {
    cid: u64,
    direction: &'static str,
    task_name: &'static str,
}

impl RelayWriteLog {
    fn new(cid: u64, direction: &'static str, task_name: &'static str) -> Self {
        Self {
            cid,
            direction,
            task_name,
        }
    }
}

fn log_outer_write(
    cid: u64,
    direction: &'static str,
    task_name: &'static str,
    plaintext_len: usize,
    record: &[u8],
) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    if let Ok(header) = crate::tls::record::parse_header(record) {
        tracing::debug!(
            cid,
            direction,
            task_name,
            plaintext_len,
            sealed_len = header.payload_len,
            outer_tls_payload_len = header.payload_len,
            tls_content_type = header.content_type,
            "outer TLS record write"
        );
    }
}

/// True iff the QUIC connection was closed by the peer with the agreed
/// [`RELAY_IDLE_CLOSE_CODE`] (the server's idle watchdog fired first). Lets the
/// client treat that as a benign mutual idle teardown (Ok) instead of a relay
/// error, so a tightened server idle floor does not surface as client failures.
fn is_peer_idle_close(conn: &crate::transport::udp::quic::endpoint::Connection) -> bool {
    crate::protocol::data::is_relay_idle_close_reason(conn.close_reason().as_ref())
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, sync::Arc};

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::{
        io::{duplex, AsyncReadExt, AsyncWriteExt},
        time::{timeout, Duration},
    };

    use super::*;

    // --- Track A1: lock-free relay activity clock — watchdog semantics ---
    // Below the `mod tests` boundary, so the no-timeout static ratchet is
    // unaffected. Locks the preserved idle-backstop semantics for the client.

    #[tokio::test]
    async fn client_relay_idle_watchdog_fires_after_idle_timeout() {
        let activity: ClientRelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let fired = timeout(
            Duration::from_secs(2),
            client_relay_idle_watchdog(activity, Duration::from_millis(20)),
        )
        .await;
        assert!(fired.is_ok(), "watchdog must fire once the relay is idle");
    }

    #[tokio::test]
    async fn client_relay_idle_watchdog_pending_before_idle_timeout() {
        let activity: ClientRelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let fired = timeout(
            Duration::from_millis(50),
            client_relay_idle_watchdog(activity, Duration::from_secs(30)),
        )
        .await;
        assert!(
            fired.is_err(),
            "watchdog must not fire before the idle timeout"
        );
    }

    #[tokio::test]
    async fn bump_client_relay_activity_defers_watchdog() {
        let activity: ClientRelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let bumped = activity.clone();
        let bumper = tokio::spawn(async move {
            for _ in 0..10 {
                sleep(Duration::from_millis(15)).await;
                bump_client_relay_activity(&bumped);
            }
        });
        let fired = timeout(
            Duration::from_millis(100),
            client_relay_idle_watchdog(activity, Duration::from_millis(60)),
        )
        .await;
        assert!(
            fired.is_err(),
            "ongoing activity must defer the idle watchdog"
        );
        bumper.await.unwrap();
    }

    use crate::{
        config::ServerConfig,
        crypto::{
            identity, pq,
            session::{derive_client_keys, expand_epoch_keys, X25519KeyPair},
        },
        handshake::{client::data_codecs, server},
        protocol::command::{PqRekeyRequest, ServerKeyExchange},
        tls::record,
    };

    const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

    /// A syntactically valid TLS ApplicationData record whose ciphertext is not a
    /// ParallaX record, so the client's `open_*` fails with an AEAD error — exactly
    /// what a forwarded camouflage-origin record looks like in the residual-skip
    /// loop before the ParallaX key exchange.
    fn camouflage_record(seed: u8) -> Vec<u8> {
        let payload = vec![seed; 40];
        let len = payload.len() as u16;
        let mut rec = vec![0x17, 0x03, 0x03, (len >> 8) as u8, (len & 0xff) as u8];
        rec.extend_from_slice(&payload);
        rec
    }

    // Test helper: reassemble a PQ handshake frame (PX1Q/PX1K) from a buffer of
    // concatenated sealed FramedChunk records, mirroring production (PAR-21).
    fn open_framed_payload(codec: &mut DataRecordCodec, buf: &[u8]) -> Vec<u8> {
        let mut reassembler = FramedReassembler::default();
        let mut offset = 0;
        while offset < buf.len() {
            let payload_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
            let end = offset + crate::tls::record::TLS_HEADER_LEN + payload_len;
            let chunk = codec.open(&buf[offset..end]).unwrap();
            if let Some(payload) = reassembler.push(&chunk, MAX_PQ_HANDSHAKE_FRAME).unwrap() {
                assert_eq!(
                    end,
                    buf.len(),
                    "framed payload completed before consuming all sealed records"
                );
                return payload;
            }
            offset = end;
        }
        panic!("framed payload did not complete");
    }

    // Test helper: seal a PQ handshake payload the way production does — split
    // into several FramedChunk records (small chunk size to exercise reassembly).
    fn seal_framed<R: rand::Rng + rand::RngCore + ?Sized>(
        codec: &mut DataRecordCodec,
        payload: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in crate::protocol::command::FramedChunk::encode_all(payload, 400).unwrap() {
            codec.seal_into(&chunk, rng, &mut out).unwrap();
        }
        out
    }

    /// Regression for the high-RTT handshake-failure bug (client budget 16 vs
    /// server forward limit 64): the client must skip as many camouflage records as
    /// the server may forward before the key-exchange
    /// (`MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS`) and still accept the key
    /// exchange. With the old budget this aborted with an AEAD/"residual budget"
    /// error on the 17th camouflage record.
    #[tokio::test]
    async fn residual_skip_tolerates_full_server_forward_limit() {
        use rand::{rngs::StdRng, SeedableRng};

        use crate::{
            config::TrafficConfig,
            crypto::session::{derive_client_keys, CipherSuite},
            handshake::client::ClientDataSession,
        };

        let client = X25519KeyPair::generate();
        let server_static = X25519KeyPair::generate();
        let transcript = [7_u8; 32];
        let keys =
            derive_client_keys(PSK, &client.private, &server_static.public, &transcript).unwrap();
        let traffic = TrafficConfig::default();
        let mut session = ClientDataSession::new(keys.clone(), traffic).unwrap();
        let mut rng = StdRng::seed_from_u64(42);

        // Client builds its PQ rekey record; reconstruct the matching server
        // key-exchange the same way an authenticated server would (mirrors the
        // `pq_rekey_changes_client_session_keys` roundtrip in handshake::client).
        let (pq_record, pending) = session.build_pq_rekey_record(&mut rng).unwrap();
        let (mut server_open, _) = data_codecs(&keys, traffic).unwrap();
        let request =
            PqRekeyRequest::decode(&open_framed_payload(&mut server_open, &pq_record)).unwrap();
        let server_eph = X25519KeyPair::generate();
        let encapsulation = pq::encapsulate(&request.client_mlkem_public_key).unwrap();
        let (_, mut server_seal) = data_codecs(&keys, traffic).unwrap();
        let kx_record = seal_framed(
            &mut server_seal,
            &ServerKeyExchange {
                server_x25519_public: server_eph.public,
                mlkem_ciphertext: encapsulation.ciphertext,
            }
            .encode_with_suite(CipherSuite::ChaCha20Poly1305)
            .unwrap(),
            &mut rng,
        );

        // Prepend exactly the maximum number of camouflage records the server may
        // forward, then the real key-exchange as the next record.
        let mut stream = Vec::new();
        for i in 0..crate::handshake::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS {
            stream.extend_from_slice(&camouflage_record(i as u8));
        }
        stream.extend_from_slice(&kx_record);

        let mut cursor: &[u8] = &stream;
        apply_server_key_exchange_after_residuals(&mut cursor, &mut session, &pending, PSK)
            .await
            .expect(
                "client must skip all forwarded camouflage records and accept the key exchange",
            );
    }

    /// The client's residual-skip budget must always be at least the server's
    /// pre-PQ fallback forward limit, or high-RTT handshakes intermittently abort
    /// (the 16-vs-64 bug). Both are bound to the shared constant, so this holds by
    /// construction; the test guards against a future divergence.
    #[test]
    fn residual_budget_covers_server_forward_limit() {
        const {
            assert!(
                MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE
                    >= crate::handshake::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS,
                "client residual-skip budget must cover the server's pre-PQ fallback forward limit"
            );
        }
    }

    /// The UDP circuit breaker: starts closed, trips on an unusable outcome and
    /// suppresses negotiation until the TTL elapses, then lets exactly ONE
    /// connection claim the half-open trial (concurrent callers in that window
    /// still skip); a usable outcome clears it. Driven via the `_at` time seam so
    /// the TTL boundary is deterministic without sleeping.
    #[test]
    fn udp_reachability_circuit_breaker_trips_and_half_opens() {
        let ttl = Duration::from_secs(30);
        let breaker = UdpReachability::new(ttl);
        let t0 = std::time::Instant::now();

        // Closed initially: every connection may attempt UDP (no claim, repeatable).
        assert!(breaker.should_attempt_at(t0));
        assert!(breaker.should_attempt_at(t0));

        // Trip it (probe found UDP unusable): suppressed for the whole TTL window.
        breaker.record_unusable();
        let tripped_at = std::time::Instant::now();
        assert!(!breaker.should_attempt_at(tripped_at));
        assert!(!breaker.should_attempt_at(tripped_at + ttl - Duration::from_millis(1)));

        // Half-open: the FIRST caller at/after the TTL claims the single trial...
        let claim_at = tripped_at + ttl;
        assert!(breaker.should_attempt_at(claim_at));
        // ...and concurrent callers in the same window now see it as re-stamped
        // (still tripped) and skip — no thundering-herd re-probe.
        assert!(!breaker.should_attempt_at(claim_at));
        assert!(!breaker.should_attempt_at(claim_at + ttl - Duration::from_millis(1)));

        // If the trial connection died without recording, the next TTL (measured
        // from the claim) lets another connection reclaim — self-healing.
        assert!(breaker.should_attempt_at(claim_at + ttl));

        // A Verified outcome clears it immediately: back to attempting freely.
        breaker.record_usable();
        assert!(breaker.should_attempt_at(std::time::Instant::now()));
    }

    /// Serializes the QUIC fast-plane e2e tests that share the process-global
    /// `RETAINED_QUIC_CONN_FOR_TEST` hook and the `QUIC_LEG_BYTES_WRITTEN`
    /// counter, so a parallel `--ignored` run cannot have one test grab/close the
    /// other's retained connection. Other tests still run concurrently. A tokio
    /// async mutex so the guard may be held across the tests' `.await` points.
    static QUIC_E2E_SERIAL: Mutex<()> = Mutex::const_new(());

    /// Acquires the QUIC e2e serial lock for the duration of a test.
    async fn quic_e2e_guard() -> tokio::sync::MutexGuard<'static, ()> {
        QUIC_E2E_SERIAL.lock().await
    }

    fn dummy_mux_handle() -> (
        ClientMuxHandle,
        mpsc::Receiver<MuxFrame>,
        mpsc::Receiver<ClientStreamControl>,
    ) {
        let (frame_tx, frame_rx) = mpsc::channel(4);
        let (register_tx, register_rx) = mpsc::channel(4);
        let handle = ClientMuxHandle {
            frame_tx,
            register_tx,
            next_stream_id: Arc::new(AtomicU32::new(1)),
            stream_slots: Arc::new(Semaphore::new(4)),
            chunk_size: 1024,
            payload_pool: MuxPayloadPool::with_capacity(1024),
        };
        (handle, frame_rx, register_rx)
    }

    #[test]
    fn mux_handle_reusable_only_while_both_tasks_alive() {
        // Both background tasks alive -> reusable.
        let (handle, frame_rx, register_rx) = dummy_mux_handle();
        assert!(handle.is_reusable());

        // Reader dead (its register_rx dropped) but writer alive: must NOT be
        // reused. This is the clean server->client half-close FIN case that
        // previously wedged the pool when only frame_tx was probed.
        drop(register_rx);
        assert!(
            !handle.is_reusable(),
            "a handle whose reader task has exited must not be reused"
        );
        drop(frame_rx);

        // Writer dead (frame_rx dropped) is likewise not reusable.
        let (handle, frame_rx, register_rx) = dummy_mux_handle();
        drop(frame_rx);
        assert!(!handle.is_reusable());
        drop(register_rx);
    }

    /// M-7: ClientMuxPool::handle() must NOT hold the pool mutex across the (up to
    /// CLIENT_ESTABLISH_TIMEOUT) network establishment, otherwise one stalling
    /// server blocks every new local connection behind the lock. A stalling TCP
    /// listener (accepts, never completes the camouflage handshake) keeps a
    /// builder parked in start_session(); the pool mutex must remain acquirable
    /// and show the in-flight `Building` state.
    #[tokio::test]
    async fn mux_handle_does_not_hold_lock_across_establishment() {
        // Accept connections but never speak: the client's wait for the origin
        // ServerHello stalls until the establish timeout (far longer than this test).
        let stalling = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stall_addr = stalling.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = stalling.accept().await {
                held.push(stream); // keep the connection open, send nothing
            }
        });

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_config = Arc::new(ClientConfig {
            listen: local.local_addr().unwrap(),
            server_addr: stall_addr.to_string(),
            sni: "example.com".to_owned(),
            server_public_key: STANDARD.encode(server_keys.public),
            server_identity_public_key: STANDARD.encode(&server_identity_keys.public),
        });
        let server_addr = ServerAddrResolver::new(&client_config.server_addr)
            .await
            .unwrap();
        let pool = ClientMuxPool::new(
            Arc::clone(&client_config),
            server_addr,
            TrafficConfig::default(),
            Arc::new(UdpConfig::default()),
            Arc::new(UdpReachability::new(UDP_BLACKHOLE_TTL)),
            Arc::new(zeroize::Zeroizing::new(PSK.to_vec())),
            server_keys.public,
            Arc::from(server_identity_keys.public.clone().into_boxed_slice()),
        );

        // Kick off a builder; it parks in start_session() OFF-LOCK.
        let builder_pool = pool.clone();
        let builder = tokio::spawn(async move { builder_pool.handle().await });

        // Let it publish Building and enter the stalled handshake.
        tokio::time::sleep(Duration::from_millis(250)).await;

        // The pool mutex MUST be free (not held across establishment) and the
        // state MUST be the in-flight Building — the M-7 guarantee.
        {
            let state = pool
                .inner
                .try_lock()
                .expect("pool mutex must not be held across establishment");
            assert!(
                matches!(*state, MuxState::Building(_)),
                "state must be Building while the single in-flight session establishes",
            );
        }

        // End the test without waiting the full establish timeout.
        builder.abort();
    }

    /// A LegReader that connected then went permanently silent: reads never
    /// resolve. Models the H-2 threat (a server that completes establishment then
    /// stops sending).
    struct SilentLegReader;
    impl LegReader for SilentLegReader {
        async fn read_record_into(&mut self, _buf: &mut Vec<u8>) -> io::Result<()> {
            std::future::pending().await
        }
        async fn try_read_record_into(&mut self, _buf: &mut Vec<u8>) -> Option<io::Result<()>> {
            None
        }
    }

    /// H-2: the SHARED per-session mux reader must tear down on an idle backstop, so
    /// a silent server cannot pin the connection permit and every parked
    /// per-connection task (each holding a stream permit + local fd) forever.
    #[tokio::test]
    async fn client_mux_reader_idle_backstop_tears_down_silent_session() {
        let (register_tx, register_rx) = mpsc::channel::<ClientStreamControl>(4);

        // A real OwnedWriteHalf for the registered download stream.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (_server_side, _) = listener.accept().await.unwrap();
        let (_local_read, local_write) = connect.await.unwrap().into_split();

        let (outcome_tx, outcome_rx) = oneshot::channel::<DownloadOutcome>();
        register_tx
            .send(ClientStreamControl::Register(ClientStreamRegistration {
                stream_id: 1,
                local_write,
                outcome_tx,
            }))
            .await
            .unwrap();
        // Drop the sender so the register arm closes after delivering the buffered
        // registration; only the (silent) read arm then remains.
        drop(register_tx);

        let session_keys = derive_client_keys(
            &[0x5a_u8; 32],
            &X25519KeyPair::generate().private,
            &X25519KeyPair::generate().public,
            &[7_u8; 32],
        )
        .unwrap();
        let (open_from_server, _seal) =
            data_codecs(&session_keys, TrafficConfig::default()).unwrap();

        // A short injected idle so the per-session backstop fires in real time.
        // Without the H-2 timeout the reader parks on the silent read forever, so
        // the outer wall budget elapses — the fail-before signal.
        let loop_result = tokio::time::timeout(
            Duration::from_secs(5),
            client_mux_reader_loop(
                SilentLegReader,
                open_from_server,
                register_rx,
                1,
                Duration::from_millis(80),
            ),
        )
        .await
        .expect("mux reader must return within the wall budget once the backstop fires");
        assert!(
            matches!(loop_result, Ok(())),
            "mux reader must return Ok after the idle backstop, got {loop_result:?}",
        );

        // The parked per-connection download is released: the backstop teardown
        // dropped the stream's outcome_tx, so await_download resolves Ok.
        assert!(matches!(
            client_mux_await_download(outcome_rx, 1).await,
            Ok(())
        ));
    }

    const CAMOUFLAGE_CERT_DER_B64: &str = concat!(
        "MIIC9jCCAd6gAwIBAgIJAPNzR81y9p7pMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4X",
        "DTI2MDUxNjEyNDA0NloXDTI2MDUxNzEyNDA0NlowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3",
        "DQEBAQUAA4IBDwAwggEKAoIBAQCnjSfVPv1Xy5razuOYABOSvGvlddr0MMVWQCSmjE47PMQEzvETytmburNZEdqQ",
        "BzSjDVxTExxd8eIHFTp8ylkztsxma5yJftQo81uqxZEnwT00tJRaazg10OYTf0ZrH6PMNC2izwJML0GkYz7s6OMF",
        "qImMCG3v00PIAYknlDrlKoDjdmANco8V5FNrbQYp2kqIcFyXrbgYurcMIKCE9Wu8L2W0oKhW6DNyRVoBGTn5zN1w",
        "jXLBO+6TJsBj4thI4tM0mUcLc+YohOfoGVq7na/wgCESoK1B+m8PdrXIEuZ7gZ0x3ZqdZ7jxL23sTmkfm+AeNdp+",
        "XshxAS77l3dcrAV9AgMBAAGjRzBFMBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAkGA1UdEwQCMAAwCwYDVR0PBAQD",
        "AgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4IBAQA8KHWHoA4otNmYh9q+X8cZnYx9y0LU",
        "NfdbHLR8ebnk/9T+/WP5CgIGWvn3+L2ulEvuSMhDC23C20SnX0h815JfMBY/PiAbLKGp3UXrgIq1dWc8t40HQBGR",
        "uBKi2fc743Sup5kPQgNAqev+8kKs4WFDXaWBpdwqI55PADVPOX66h0WiObB7crp5YTEVEe37G6UsxX40HUAAZJXt",
        "CI9eqPLISNuuNOAjJEMDMjdRH7ZjcMyrqQSweuKLAwdvUam8UJQsUNe7rM2II6GlgPS/mKZx1Nihn70GIo0yu0Bs",
        "xc9cpSHbggzQarE3g8WRp+jI9GpWXXdjno7cyim5KEQVMZcz",
    );
    const CAMOUFLAGE_KEY_DER_B64: &str = concat!(
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCnjSfVPv1Xy5razuOYABOSvGvlddr0MMVWQCSm",
        "jE47PMQEzvETytmburNZEdqQBzSjDVxTExxd8eIHFTp8ylkztsxma5yJftQo81uqxZEnwT00tJRaazg10OYTf0Zr",
        "H6PMNC2izwJML0GkYz7s6OMFqImMCG3v00PIAYknlDrlKoDjdmANco8V5FNrbQYp2kqIcFyXrbgYurcMIKCE9Wu8",
        "L2W0oKhW6DNyRVoBGTn5zN1wjXLBO+6TJsBj4thI4tM0mUcLc+YohOfoGVq7na/wgCESoK1B+m8PdrXIEuZ7gZ0x",
        "3ZqdZ7jxL23sTmkfm+AeNdp+XshxAS77l3dcrAV9AgMBAAECggEAcsH8cVMWRAbBBnLDcX1D6rHBGMVy9ONelaeT",
        "MrtQbcQ94ak3dz3tc3sZkbznvNQimjbxcDjbqgCctgs1JvmUxRXDw7aa3ZWPjIi51SpCND9nQ20XWyKqujldDCeV",
        "PJPMJXXrd+JfCX0ocYZEOBF+RIbdxpqTabqCZz+eCAy/les95pv5YkkAjxEJkzhEfFTJtJRVIjIUBL/Gg8KwG4qs",
        "5nESoD1oiNGr8tgnbsS2KNXdozIsM1awitqNJ7drpDpEpkwDUoQGAqzuvyDiN2pPqsyg1UwZWH8kuA9RyXIAOWQo",
        "R9rIX/rUsYB5F4tKg6Tdy0n9Jb9ytTINYaletNjuIQKBgQDSEzvmO4Zan1Bz+0Eb4NWfnU1yyGKb7bBFBvcuigXP",
        "W/+as1yET2Zkc4qQBudye7DUgr+zXj0s+ZeXvv+HeGggD3Blnq5bl+gPkiPSeGd24QkfO38MF2RTpW5SoUT6Z9vT",
        "iaHjIgkwZIgQf3dfSPV/MskRVemqxB5o+Phd4NRzpQKBgQDMLhkoYeRurmFQ3iuWCLOaHWAwtA28j3ymknsHyP6E",
        "OkiHBVl3YWTpZ1ZcDGMJznHdkSrj4mNsnnDM71iFM0srgKKp07T4bumowOhmyeg/hYIblFGSoZS/nTl8tAusNzXt",
        "RJeVLa9GjkFjXihiC3E+t3J2s9ij2eE8bAM0tatC+QKBgCsAQuea0aKlL8u955L0T+YPRfYz7HNskQNgLKK7H/tV",
        "IpohEtQGiLgRKpDWyPOXPBgT93eY177oDE7EivvI+s9tOZ2jgJ9BFgBx8qE3gj5ETCC3hgcMlr3EhDOnzT3Qmp/P",
        "cXLT2butKGjwHphDj/UMiTniMyWAZZUpOXXF+tb9AoGAEKvG5BQyGZNlYLvzJRnqyC+T1gYthPLWQ6d8IiOYHGXB",
        "3DxklKnAGoqUc4mTYI6Zn3Sl4ttuMMUzApicSqvofFHRdjpR8WLk8yFlGFdt/hnBiMzwaB+HTKnisrrkpRgQ8CGE",
        "muqTABjHX/ylIXQ7t9o0n1qJ2r8Ec/GBxYD7zckCgYBZzU7u9Ujq8XL+Ok6T2Zqgf3O8H3VBlKPjeYpfH6mqBRdj",
        "+773IfoifCs19Y31OL8Sb28N98XnutTlHo6xs4li0zE2KDN1O3i00K7S0dO3250Fr1QSm86CML8fSDuS1BcuMHH+",
        "RNkQkMb9Q49K23t6B1s0xnIFfBarwbusw9onAw==",
    );

    #[tokio::test]
    async fn key_exchange_reader_skips_residual_camouflage_records() {
        let client_keys = X25519KeyPair::generate();
        let server_keys = X25519KeyPair::generate();
        let transcript_hash = [4_u8; 32];
        let session_keys = derive_client_keys(
            &[0x5a_u8; 32],
            &client_keys.private,
            &server_keys.public,
            &transcript_hash,
        )
        .unwrap();
        let traffic = TrafficConfig::default();
        let mut data_session = ClientDataSession::new(session_keys.clone(), traffic).unwrap();
        let mut rng = StdRng::seed_from_u64(90);

        let (pq_record, pending_rekey) = data_session.build_pq_rekey_record(&mut rng).unwrap();
        let (mut server_open, mut server_seal) = data_codecs(&session_keys, traffic).unwrap();
        let pq_request =
            PqRekeyRequest::decode(&open_framed_payload(&mut server_open, &pq_record)).unwrap();
        let server_ephemeral = X25519KeyPair::generate();
        let x25519_ephemeral_shared = crate::crypto::session::x25519_shared_secret(
            &server_ephemeral.private,
            &pq_request.client_x25519_public,
        );
        let pq_encapsulation = pq::encapsulate(&pq_request.client_mlkem_public_key).unwrap();
        let key_exchange_record = seal_framed(
            &mut server_seal,
            &ServerKeyExchange {
                server_x25519_public: server_ephemeral.public,
                mlkem_ciphertext: pq_encapsulation.ciphertext,
            }
            .encode_with_suite(crate::crypto::session::CipherSuite::ChaCha20Poly1305)
            .unwrap(),
            &mut rng,
        );

        let residual = record::wrap_application_data(b"residual camouflage TLS data").unwrap();
        let (mut client_side, mut server_side) = duplex(32 * 1024);
        server_side.write_all(&residual).await.unwrap();
        server_side.write_all(&key_exchange_record).await.unwrap();

        apply_server_key_exchange_after_residuals(
            &mut client_side,
            &mut data_session,
            &pending_rekey,
            PSK,
        )
        .await
        .unwrap();

        let chain_secret = pq::hybrid_sandwich_rekey(
            &session_keys.chain_secret,
            &x25519_ephemeral_shared,
            &pq_encapsulation.shared_secret,
            PSK,
        )
        .unwrap();
        let next_keys = expand_epoch_keys(
            chain_secret,
            session_keys.epoch + 1,
            session_keys.transcript_hash,
            x25519_ephemeral_shared,
        )
        .unwrap();
        server_seal.rekey(next_keys.server_key, next_keys.server_nonce);
        let post_rekey_record = server_seal.seal(b"ok", &mut rng).unwrap();

        assert_eq!(
            data_session.open_server_record(&post_rekey_record).unwrap(),
            b"ok"
        );
    }

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn socks_client_reaches_target_through_parallax_server_with_large_payloads() {
        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_echo_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server(server_config).await;
        let (local_addr, client_task) =
            spawn_local_client(parallax_addr, &server_keys, &server_identity_keys).await;

        let app = connect_socks_target(local_addr, target_addr).await;
        assert_large_payload_round_trips(app).await;

        wait_for_task("client", client_task).await;
        wait_for_task("server", server_task).await;
        wait_for_task("target", target_task).await;
        wait_for_task("fallback", fallback_task).await;
    }

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn socks_client_receives_response_after_local_write_half_close() {
        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_eof_response_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server(server_config).await;
        let (local_addr, client_task) =
            spawn_local_client(parallax_addr, &server_keys, &server_identity_keys).await;

        let mut app = connect_socks_target(local_addr, target_addr).await;
        app.write_all(b"request-before-half-close").await.unwrap();
        app.shutdown().await.unwrap();

        let mut response = Vec::new();
        timeout(Duration::from_secs(5), app.read_to_end(&mut response))
            .await
            .unwrap_or_else(|_| panic!("half-close response timed out"))
            .unwrap();
        assert_eq!(response, b"response-after-half-close");

        wait_for_task("client", client_task).await;
        wait_for_task("server", server_task).await;
        wait_for_task("target", target_task).await;
        wait_for_task("fallback", fallback_task).await;
    }

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn socks_relay_succeeds_with_client_udp_negotiation_enabled() {
        // Turn on client-initiated UDP negotiation for this test's client only;
        // the server stays default (declines with PX1N). The relay must still
        // succeed, proving the PX1G/PX1N control-plane exchange keeps the AEAD
        // record stream in sync (record #1 each direction) before the real
        // command. Each test carries its own config, so no serial lock is needed.
        let client_udp = UdpConfig {
            enabled: true,
            ..UdpConfig::default()
        };

        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_eof_response_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server(server_config).await;
        let (local_addr, client_task) = spawn_local_client_with_udp(
            parallax_addr,
            &server_keys,
            &server_identity_keys,
            client_udp,
        )
        .await;

        let mut app = connect_socks_target(local_addr, target_addr).await;
        app.write_all(b"request-before-half-close").await.unwrap();
        app.shutdown().await.unwrap();

        let mut response = Vec::new();
        timeout(Duration::from_secs(5), app.read_to_end(&mut response))
            .await
            .unwrap_or_else(|_| panic!("relay response timed out with UDP negotiation enabled"))
            .unwrap();
        assert_eq!(response, b"response-after-half-close");

        wait_for_task("client", client_task).await;
        wait_for_task("server", server_task).await;
        wait_for_task("target", target_task).await;
        wait_for_task("fallback", fallback_task).await;
    }

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn socks_relay_succeeds_with_full_udp_negotiation() {
        // Both sides enabled: the server offers the UDP fast plane (PX1O), the
        // client probes it over QUIC and reports PX1P; the SOCKS relay must still
        // complete, proving the full offer/probe/ack exchange keeps the control
        // stream aligned end to end. This path makes the server RETAIN a QUIC
        // connection (publishing the shared test hook), so it serializes against
        // the other QUIC fast-plane e2e tests.
        let _serial = quic_e2e_guard().await;
        let enabled_udp = UdpConfig {
            enabled: true,
            ..UdpConfig::default()
        };

        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_eof_response_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server_with_traffic_and_udp(
            server_config,
            TrafficConfig::default(),
            enabled_udp.clone(),
        )
        .await;
        let (local_addr, client_task) = spawn_local_client_with_udp(
            parallax_addr,
            &server_keys,
            &server_identity_keys,
            enabled_udp,
        )
        .await;

        let mut app = connect_socks_target(local_addr, target_addr).await;
        app.write_all(b"request-before-half-close").await.unwrap();
        app.shutdown().await.unwrap();

        let mut response = Vec::new();
        timeout(Duration::from_secs(10), app.read_to_end(&mut response))
            .await
            .unwrap_or_else(|_| panic!("relay response timed out with full UDP negotiation"))
            .unwrap();
        assert_eq!(response, b"response-after-half-close");

        wait_for_task("client", client_task).await;
        wait_for_task("server", server_task).await;
        wait_for_task("target", target_task).await;
        wait_for_task("fallback", fallback_task).await;
    }

    /// Full UDP negotiation, single-connect: push a multi-record (>64 KiB)
    /// request and response through the SOCKS relay and assert both round-trip
    /// BYTE-EXACT over the QUIC fast-plane stream. The `QUIC_LEG_BYTES_WRITTEN`
    /// instrument confirms application data actually traversed the QUIC stream
    /// (it would stay flat if the relay had silently fallen back to TCP).
    #[tokio::test]
    #[ignore = "requires loopback UDP+TCP sockets"]
    async fn socks_relay_round_trips_large_payload_over_quic_stream() {
        use crate::transport::leg::QUIC_LEG_BYTES_WRITTEN;
        use std::sync::atomic::Ordering;

        // Serialize against the other QUIC fast-plane e2e test (shared globals).
        let _serial = quic_e2e_guard().await;

        let enabled_udp = UdpConfig {
            enabled: true,
            ..UdpConfig::default()
        };

        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_echo_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server_with_traffic_and_udp(
            server_config,
            TrafficConfig::default(),
            enabled_udp.clone(),
        )
        .await;
        let (local_addr, client_task) = spawn_local_client_with_udp(
            parallax_addr,
            &server_keys,
            &server_identity_keys,
            enabled_udp,
        )
        .await;

        let before = QUIC_LEG_BYTES_WRITTEN.load(Ordering::Relaxed);
        let app = connect_socks_target(local_addr, target_addr).await;
        // Drives several payload sizes, the largest 5 MiB -> many records.
        assert_large_payload_round_trips(app).await;
        let after = QUIC_LEG_BYTES_WRITTEN.load(Ordering::Relaxed);
        assert!(
            after > before,
            "expected relay bytes to traverse the QUIC stream (before={before}, after={after})"
        );

        wait_for_task("client", client_task).await;
        wait_for_task("server", server_task).await;
        wait_for_task("target", target_task).await;
        wait_for_task("fallback", fallback_task).await;
    }

    /// Full UDP negotiation, single-connect: after the QUIC relay is carrying a
    /// large in-flight transfer, kill the server's retained QUIC connection. The
    /// proxied SOCKS connection must end with an ERROR / short read (a clean
    /// reset), never hang and never report a corrupt "success" with the full
    /// payload. This is the accepted failure mode for this slice, and it also
    /// proves the data path is genuinely on QUIC (killing it breaks the transfer).
    #[tokio::test]
    #[ignore = "requires loopback UDP+TCP sockets"]
    async fn quic_relay_reset_mid_transfer_ends_proxied_connection_cleanly() {
        // Serialize against the other QUIC fast-plane e2e test (shared globals).
        let _serial = quic_e2e_guard().await;

        let enabled_udp = UdpConfig {
            enabled: true,
            ..UdpConfig::default()
        };

        // A large response so the transfer is still in flight when we reset.
        const RESPONSE_LEN: usize = 8 * 1024 * 1024;

        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_slow_large_response_target(RESPONSE_LEN).await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        // Reset the test hook so we observe THIS connection's retained conn.
        *server::retained_quic_conn_for_test()
            .lock()
            .expect("retained quic test hook poisoned") = None;

        let (parallax_addr, server_task) = spawn_parallax_server_with_traffic_and_udp_allow_err(
            server_config,
            TrafficConfig::default(),
            enabled_udp.clone(),
        )
        .await;
        let (local_addr, client_task) = spawn_local_client_with_udp_allow_err(
            parallax_addr,
            &server_keys,
            &server_identity_keys,
            enabled_udp,
        )
        .await;

        let mut app = connect_socks_target(local_addr, target_addr).await;
        app.write_all(b"start").await.unwrap();

        // Read a prefix to confirm the relay is flowing, then kill the QUIC
        // connection mid-transfer.
        let mut prefix = vec![0_u8; 64 * 1024];
        timeout(Duration::from_secs(10), app.read_exact(&mut prefix))
            .await
            .expect("prefix read timed out")
            .expect("prefix read failed");

        // Grab and close the server's retained QUIC fast-plane endpoint in flight
        // (closing the endpoint closes its single relay connection).
        let endpoint = {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(endpoint) = server::retained_quic_conn_for_test()
                    .lock()
                    .expect("retained quic test hook poisoned")
                    .clone()
                {
                    break endpoint;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "server never retained a QUIC connection"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        endpoint.close(0u32.into(), b"test-mid-relay-reset");

        // The proxied connection must terminate (error or short read), NOT hang
        // and NOT deliver the full payload.
        let mut rest = Vec::new();
        let read_result = timeout(Duration::from_secs(10), app.read_to_end(&mut rest)).await;
        match read_result {
            Err(_) => panic!("proxied connection hung after QUIC reset"),
            Ok(Ok(_)) => {
                let total = prefix.len() + rest.len();
                assert!(
                    total < RESPONSE_LEN,
                    "QUIC reset must not deliver the full payload (got {total} of {RESPONSE_LEN})"
                );
            }
            Ok(Err(_)) => { /* a hard read error is the cleanest expected outcome */ }
        }

        // The relay tasks must terminate (they return Err on the broken stream);
        // tolerate either outcome but require they do not hang.
        let _ = timeout(Duration::from_secs(10), client_task)
            .await
            .expect("client task hung after QUIC reset");
        let _ = timeout(Duration::from_secs(10), server_task)
            .await
            .expect("server task hung after QUIC reset");
        target_task.abort();
        fallback_task.abort();
    }

    /// ASYMMETRIC UPLOAD (the critical data-integrity repro). Full UDP
    /// negotiation, single-connect. The local app uploads a large (>=2 MiB,
    /// multi-record) body to a target that READS SLOWLY (throttled), while the
    /// target's response is empty (it half-closes its write side immediately) so
    /// the server->client direction finishes fast. The local app half-closes its
    /// write side after sending. The TARGET must receive ALL upload bytes
    /// byte-exact, and the proxied connection must complete successfully.
    ///
    /// On the pre-fix code the client closed the QUIC connection the instant its
    /// own `try_join` returned Ok (upload FIN sent + small download drained),
    /// while the server was still draining the upload tail into the slow target.
    /// quinn's close ABANDONS that undelivered stream data, truncating the upload
    /// yet returning a (silent) success to the local app. The DONE handshake
    /// keeps the QUIC connection alive until the server has fully drained every
    /// uploaded byte to the target and acknowledged with its own DONE, so the
    /// upload cannot be truncated.
    #[tokio::test]
    #[ignore = "requires loopback UDP+TCP sockets"]
    async fn quic_relay_asymmetric_slow_upload_is_not_truncated() {
        use crate::transport::leg::QUIC_LEG_BYTES_WRITTEN;
        use std::sync::atomic::Ordering;

        // Serialize against the other QUIC fast-plane e2e tests (shared globals).
        let _serial = quic_e2e_guard().await;

        let enabled_udp = UdpConfig {
            enabled: true,
            ..UdpConfig::default()
        };

        // A multi-record upload, large enough that the tail is still mid-drain in
        // the slow target when the client's directions finish.
        const UPLOAD_LEN: usize = 4 * 1024 * 1024;

        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task, received_rx) = spawn_slow_reader_target(UPLOAD_LEN).await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server_with_traffic_and_udp(
            server_config,
            TrafficConfig::default(),
            enabled_udp.clone(),
        )
        .await;
        let (local_addr, client_task) = spawn_local_client_with_udp(
            parallax_addr,
            &server_keys,
            &server_identity_keys,
            enabled_udp,
        )
        .await;

        let before = QUIC_LEG_BYTES_WRITTEN.load(Ordering::Relaxed);
        let app = connect_socks_target(local_addr, target_addr).await;
        let (mut app_read, mut app_write) = app.into_split();

        let payload = (0..UPLOAD_LEN)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();
        let upload_payload = payload.clone();
        let writer = tokio::spawn(async move {
            app_write.write_all(&upload_payload).await.unwrap();
            // Half-close the write side: the local app is done sending. This is
            // what makes the client's upload direction finish promptly while the
            // slow target is still draining the bytes.
            app_write.shutdown().await.unwrap();
        });

        // The target half-closed its write side immediately, so the local app
        // sees a prompt clean EOF with no response bytes.
        let mut response = Vec::new();
        timeout(Duration::from_secs(30), app_read.read_to_end(&mut response))
            .await
            .expect("download EOF timed out")
            .expect("download read failed");
        assert!(
            response.is_empty(),
            "target sent no response; got {} bytes",
            response.len()
        );
        writer.await.unwrap();

        // The relay must have run over the QUIC fast plane, not silently fallen
        // back to TCP: the upload bytes traverse the client's QUIC stream leg, so
        // the instrument must have advanced. A silent TCP fallback leaves it flat.
        let after = QUIC_LEG_BYTES_WRITTEN.load(Ordering::Relaxed);
        assert!(
            after > before,
            "expected relay bytes to traverse the QUIC stream (before={before}, after={after})"
        );

        // The proxied connection must have completed successfully on BOTH ends.
        // The relay tasks legitimately run for several seconds here (the target
        // drains slowly and the DONE handshake only completes once it has), so use
        // a generous join window rather than the default 5s.
        wait_for_task_within("client", client_task, Duration::from_secs(30)).await;
        wait_for_task_within("server", server_task, Duration::from_secs(30)).await;

        // And the target must have received EVERY uploaded byte, byte-exact.
        let received = timeout(Duration::from_secs(30), received_rx)
            .await
            .expect("target receive report timed out")
            .expect("target receive report dropped");
        assert_eq!(
            received.len(),
            UPLOAD_LEN,
            "target must receive the full upload (no truncation)"
        );
        assert_eq!(
            received, payload,
            "uploaded bytes must round-trip byte-exact"
        );

        wait_for_task_within("target", target_task, Duration::from_secs(30)).await;
        fallback_task.abort();
    }

    /// ASYMMETRIC DOWNLOAD (slow local-app drain). Full UDP negotiation,
    /// single-connect. The target sends a multi-record response fast and then
    /// closes, while the LOCAL app reads SLOWLY (throttled) so draining the
    /// response to it takes well over the old fixed 5s server grace. The local app
    /// must receive ALL response bytes byte-exact, and the proxied connection must
    /// complete successfully.
    ///
    /// This is the counterpart to the upload repro and the regression guard for
    /// removing the server's fixed 5s `QUIC_RELAY_DRAIN_GRACE` cap: a healthy
    /// download whose client takes >5s to drain to a slow local app must NOT be
    /// time-capped. The DONE handshake keeps the QUIC connection alive (the server
    /// blocks reading the client's DONE over the TCP control stream) until the
    /// client has drained every downloaded byte and acknowledged with its own
    /// DONE -- so wall-clock drain time no longer bounds correctness.
    ///
    /// Note: unlike the upload direction, this exact scenario does not *fail* on
    /// the pre-fix code on loopback -- empirically quinn 0.11 lets the application
    /// drain a FINISHED, fully-buffered RecvStream even after the peer's connection
    /// close, and a slow client whose RecvStream buffer fills instead
    /// backpressures the server so its `try_join` never completes early and the 5s
    /// grace never fires. The download truncation the fix removes is real in
    /// principle (quinn's close abandons undelivered stream data) but is not
    /// deterministically loopback-reproducible; this test therefore asserts the
    /// fixed behavior is correct and that the cap removal does not regress slow
    /// downloads. The deterministic pre-fix repro is the upload test above.
    #[tokio::test]
    #[ignore = "requires loopback UDP+TCP sockets"]
    async fn quic_relay_asymmetric_slow_download_is_not_truncated() {
        use crate::transport::leg::QUIC_LEG_BYTES_WRITTEN;
        use std::sync::atomic::Ordering;

        // Serialize against the other QUIC fast-plane e2e tests (shared globals).
        let _serial = quic_e2e_guard().await;

        let enabled_udp = UdpConfig {
            enabled: true,
            ..UdpConfig::default()
        };

        // Under quinn's default ~1.25 MB per-stream receive window so the server
        // sends the whole response without backpressure and the slow local-app
        // drain (>5s) is what would have tripped the old fixed 5s server grace.
        // Multi-record (64+ records of 16 KiB).
        const DOWNLOAD_LEN: usize = 1024 * 1024;

        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_fast_large_response_target(DOWNLOAD_LEN).await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server_with_traffic_and_udp(
            server_config,
            TrafficConfig::default(),
            enabled_udp.clone(),
        )
        .await;
        let (local_addr, client_task) = spawn_local_client_with_udp(
            parallax_addr,
            &server_keys,
            &server_identity_keys,
            enabled_udp,
        )
        .await;

        let before = QUIC_LEG_BYTES_WRITTEN.load(Ordering::Relaxed);
        let app = connect_socks_target(local_addr, target_addr).await;
        let (mut app_read, mut app_write) = app.into_split();

        // Small request, then half-close: the upload direction finishes promptly.
        app_write.write_all(b"start").await.unwrap();
        app_write.shutdown().await.unwrap();

        // Drain the response SLOWLY: small chunks with a sleep between them so
        // total drain time exceeds the old 5s grace by a wide margin.
        let expected = (0..DOWNLOAD_LEN)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();
        let mut response = Vec::with_capacity(DOWNLOAD_LEN);
        let mut chunk = vec![0_u8; 8 * 1024];
        loop {
            let n = timeout(Duration::from_secs(30), app_read.read(&mut chunk))
                .await
                .expect("slow download read timed out")
                .expect("slow download read failed");
            if n == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..n]);
            // ~128 chunks * 50ms ~= 6.4s drain, comfortably beyond the old 5s cap.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            response.len(),
            DOWNLOAD_LEN,
            "local app must receive the full download (no 5s-cap truncation)"
        );
        assert_eq!(
            response, expected,
            "downloaded bytes must round-trip byte-exact"
        );

        // The relay must have run over the QUIC fast plane, not silently fallen
        // back to TCP: even this small upload (the request + the rendezvous
        // trigger record) traverses the client's QUIC stream leg, so the
        // instrument must have advanced. A silent TCP fallback leaves it flat.
        let after = QUIC_LEG_BYTES_WRITTEN.load(Ordering::Relaxed);
        assert!(
            after > before,
            "expected relay bytes to traverse the QUIC stream (before={before}, after={after})"
        );

        // The relay tasks legitimately run for several seconds here (the local app
        // drains slowly and the DONE handshake only completes once it has), so use
        // a generous join window rather than the default 5s.
        wait_for_task_within("client", client_task, Duration::from_secs(30)).await;
        wait_for_task_within("server", server_task, Duration::from_secs(30)).await;
        wait_for_task_within("target", target_task, Duration::from_secs(30)).await;
        fallback_task.abort();
    }

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn mux_client_reaches_two_targets_over_one_authenticated_session() {
        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_multi_echo_target(2).await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let mux_traffic = TrafficConfig {
            max_concurrent_streams: 2,
            ..TrafficConfig::default()
        };
        let (parallax_addr, server_task) =
            spawn_parallax_server_with_traffic(server_config, mux_traffic).await;
        let (local_addr, client_task) =
            spawn_mux_local_client(parallax_addr, &server_keys, &server_identity_keys, 2).await;

        let app_one = connect_socks_target(local_addr, target_addr).await;
        let app_two = connect_socks_target(local_addr, target_addr).await;
        let first = assert_payload_round_trip(app_one, b"mux-stream-one".to_vec());
        let second = assert_payload_round_trip(app_two, b"mux-stream-two".to_vec());
        let ((), ()) = tokio::join!(first, second);

        wait_for_task("client", client_task).await;
        wait_for_task("server", server_task).await;
        wait_for_task("target", target_task).await;
        wait_for_task("fallback", fallback_task).await;
    }

    /// Regression cover for the mux data path: one stream carrying many small,
    /// consecutive payloads must deliver every byte in order in both directions,
    /// and a half-close FIN must never overtake queued DATA. This drives the
    /// batched mux writers/readers and the AEAD record batching end to end, so a
    /// reorder, drop, duplication, or premature FIN shows up as a byte mismatch
    /// or a timeout. The byte pattern is position-encoded so any such defect is
    /// detectable rather than masked by repeated bytes.
    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn mux_single_stream_small_consecutive_payloads_preserve_order_and_fin() {
        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_echo_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        // Force the mux data path; the reported regression only appears with
        // max_concurrent_streams > 1 (max_concurrent_streams == 1 is non-mux).
        let mux_traffic = TrafficConfig {
            max_concurrent_streams: 4,
            ..TrafficConfig::default()
        };
        let (parallax_addr, server_task) =
            spawn_parallax_server_with_traffic(server_config, mux_traffic).await;
        let (local_addr, client_task) =
            spawn_mux_local_client(parallax_addr, &server_keys, &server_identity_keys, 1).await;

        let app = connect_socks_target(local_addr, target_addr).await;
        let (mut app_read, mut app_write) = app.into_split();

        const CHUNKS: usize = 4096;
        const CHUNK_LEN: usize = 13;
        let mut expected = Vec::with_capacity(CHUNKS * CHUNK_LEN);
        for i in 0..CHUNKS {
            for b in 0..CHUNK_LEN {
                expected.push((i.wrapping_mul(31).wrapping_add(b.wrapping_mul(7)) % 251) as u8);
            }
        }
        let total = expected.len();

        let writer_expected = expected.clone();
        let writer = async move {
            for chunk in writer_expected.chunks(CHUNK_LEN) {
                app_write.write_all(chunk).await.unwrap();
            }
            // Half-close the upload: the FIN must land after every queued DATA
            // frame so the echo target still sees and echoes all bytes.
            app_write.shutdown().await.unwrap();
        };
        let reader = async move {
            let mut got = vec![0_u8; total];
            app_read.read_exact(&mut got).await.unwrap();
            // Every echoed byte arrived; the stream must now cleanly reach EOF.
            let mut tail = [0_u8; 1];
            let extra = app_read.read(&mut tail).await.unwrap();
            (got, extra)
        };

        let (_, (got, extra)) = timeout(Duration::from_secs(20), async {
            tokio::join!(writer, reader)
        })
        .await
        .expect("mux small-payload round trip timed out");

        assert_eq!(
            extra, 0,
            "stream must EOF only after all echoed bytes (FIN overtook queued DATA)"
        );
        assert_eq!(
            got, expected,
            "echoed bytes must match byte-for-byte and in order"
        );

        wait_for_task("client", client_task).await;
        wait_for_task("server", server_task).await;
        wait_for_task("target", target_task).await;
        wait_for_task("fallback", fallback_task).await;
    }

    /// Regression cover for global mux ordering: with several streams active at
    /// once, each stream must receive its own bytes in order with no cross-stream
    /// mixing, even though the batched writer interleaves frames from every
    /// stream into shared sealed records. Each stream uses a distinct payload
    /// pattern so any cross-stream contamination is caught.
    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn mux_concurrent_streams_keep_per_stream_payload_order() {
        const STREAMS: usize = 4;
        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_multi_echo_target(STREAMS).await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let mux_traffic = TrafficConfig {
            max_concurrent_streams: STREAMS as u8,
            ..TrafficConfig::default()
        };
        let (parallax_addr, server_task) =
            spawn_parallax_server_with_traffic(server_config, mux_traffic).await;
        let (local_addr, client_task) =
            spawn_mux_local_client(parallax_addr, &server_keys, &server_identity_keys, STREAMS)
                .await;

        let mut apps = Vec::with_capacity(STREAMS);
        for _ in 0..STREAMS {
            apps.push(connect_socks_target(local_addr, target_addr).await);
        }
        let mut tasks = Vec::with_capacity(STREAMS);
        for (idx, app) in apps.into_iter().enumerate() {
            let payload: Vec<u8> = (0..8192)
                .map(|b| (idx as u8).wrapping_mul(101).wrapping_add((b % 251) as u8))
                .collect();
            tasks.push(tokio::spawn(assert_payload_round_trip(app, payload)));
        }
        for task in tasks {
            timeout(Duration::from_secs(20), task)
                .await
                .expect("mux concurrent stream round trip timed out")
                .unwrap();
        }

        wait_for_task("client", client_task).await;
        wait_for_task("server", server_task).await;
        wait_for_task("target", target_task).await;
        wait_for_task("fallback", fallback_task).await;
    }

    /// Tunables for one loopback mux benchmark run.
    struct MuxBenchParams {
        streams: usize,
        latency_round_trips: usize,
        latency_payload: usize,
        warmup_bytes_per_stream: u64,
        measure_bytes_per_stream: u64,
    }

    struct LatencyStats {
        samples: usize,
        min: Duration,
        median: Duration,
        p99: Duration,
    }

    struct MuxBenchResult {
        streams: usize,
        measure_bytes_per_stream: u64,
        elapsed: Duration,
        latency: Option<LatencyStats>,
    }

    impl MuxBenchResult {
        /// Bytes moved in one direction (echo doubles total work) per second.
        fn per_direction_mib_s(&self) -> f64 {
            let total = (self.measure_bytes_per_stream * self.streams as u64) as f64;
            (total / (1024.0 * 1024.0)) / self.elapsed.as_secs_f64()
        }

        fn report(&self, label: &str) {
            println!("---- mux loopback benchmark: {label} ----");
            println!("  streams                : {}", self.streams);
            if let Some(latency) = &self.latency {
                println!(
                    "  ping-pong RTT (n={})  : min={:?} median={:?} p99={:?}",
                    latency.samples, latency.min, latency.median, latency.p99
                );
            }
            println!(
                "  payload per stream     : {:.1} MiB",
                self.measure_bytes_per_stream as f64 / (1024.0 * 1024.0)
            );
            println!("  full-duplex elapsed    : {:?}", self.elapsed);
            println!(
                "  throughput/direction   : {:.1} MiB/s ({:.2} Gbps)",
                self.per_direction_mib_s(),
                self.per_direction_mib_s() * 8.0 / 1024.0
            );
        }
    }

    /// Sequentially ping-pongs `round_trips` small payloads through one stream
    /// and reports min/median/p99 RTT after a short warmup.
    async fn measure_mux_latency(
        app: &mut TcpStream,
        round_trips: usize,
        payload: usize,
    ) -> LatencyStats {
        let out = vec![0x5A_u8; payload];
        let mut back = vec![0_u8; payload];
        for _ in 0..16 {
            app.write_all(&out).await.unwrap();
            app.read_exact(&mut back).await.unwrap();
        }
        let mut samples = Vec::with_capacity(round_trips);
        for _ in 0..round_trips {
            let start = Instant::now();
            app.write_all(&out).await.unwrap();
            app.read_exact(&mut back).await.unwrap();
            samples.push(start.elapsed());
        }
        samples.sort_unstable();
        LatencyStats {
            samples: samples.len(),
            min: samples[0],
            median: samples[samples.len() / 2],
            p99: samples[(samples.len() * 99 / 100).min(samples.len() - 1)],
        }
    }

    /// Drives `bytes` of full-duplex echo traffic over one already-open stream,
    /// reading and writing concurrently on the same task. Echo guarantees every
    /// byte written returns, so reading exactly `bytes` drains the direction.
    async fn full_duplex_pump(r: &mut OwnedReadHalf, w: &mut OwnedWriteHalf, bytes: u64) {
        let write_fut = async {
            let chunk = vec![0xAB_u8; 64 * 1024];
            let mut remaining = bytes;
            while remaining > 0 {
                let n = remaining.min(chunk.len() as u64) as usize;
                w.write_all(&chunk[..n]).await.unwrap();
                remaining -= n as u64;
            }
            w.flush().await.unwrap();
        };
        let read_fut = async {
            let mut buf = vec![0_u8; 64 * 1024];
            let mut remaining = bytes;
            while remaining > 0 {
                let n = r.read(&mut buf).await.unwrap();
                assert!(n > 0, "unexpected EOF during throughput pump");
                remaining = remaining.saturating_sub(n as u64);
            }
        };
        tokio::join!(write_fut, read_fut);
    }

    async fn run_mux_loopback_benchmark(params: MuxBenchParams) -> MuxBenchResult {
        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_multi_echo_target(params.streams).await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = crate::crypto::identity::keypair();
        let replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let mux_traffic = TrafficConfig {
            max_concurrent_streams: params.streams as u8,
            ..TrafficConfig::default()
        };
        let (parallax_addr, server_task) =
            spawn_parallax_server_with_traffic(server_config, mux_traffic).await;
        let (local_addr, client_task) = spawn_mux_local_client(
            parallax_addr,
            &server_keys,
            &server_identity_keys,
            params.streams,
        )
        .await;

        let mut apps = Vec::with_capacity(params.streams);
        for _ in 0..params.streams {
            apps.push(connect_socks_target(local_addr, target_addr).await);
        }

        let latency = if params.latency_round_trips > 0 {
            Some(
                measure_mux_latency(
                    &mut apps[0],
                    params.latency_round_trips,
                    params.latency_payload,
                )
                .await,
            )
        } else {
            None
        };

        let barrier = Arc::new(tokio::sync::Barrier::new(params.streams + 1));
        let mut pump_handles = Vec::with_capacity(params.streams);
        for app in apps {
            let (mut r, mut w) = app.into_split();
            let barrier = Arc::clone(&barrier);
            let warmup = params.warmup_bytes_per_stream;
            let measure = params.measure_bytes_per_stream;
            pump_handles.push(tokio::spawn(async move {
                full_duplex_pump(&mut r, &mut w, warmup).await;
                barrier.wait().await;
                full_duplex_pump(&mut r, &mut w, measure).await;
                let _ = w.shutdown().await;
            }));
        }
        barrier.wait().await;
        let start = Instant::now();
        for handle in pump_handles {
            handle.await.unwrap();
        }
        let elapsed = start.elapsed();

        wait_for_task("client", client_task).await;
        wait_for_task("server", server_task).await;
        wait_for_task("target", target_task).await;
        wait_for_task("fallback", fallback_task).await;

        MuxBenchResult {
            streams: params.streams,
            measure_bytes_per_stream: params.measure_bytes_per_stream,
            elapsed,
            latency,
        }
    }

    /// Loopback latency (ping-pong RTT) and steady-state throughput benchmark
    /// for the mux data path. Ignored by default: it needs loopback sockets and
    /// prints timing evidence rather than asserting fixed numbers. Run with:
    ///   cargo test --lib -- --ignored --nocapture mux_loopback_benchmark
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "loopback latency/throughput benchmark; run with --ignored --nocapture"]
    async fn mux_loopback_benchmark() {
        let single = run_mux_loopback_benchmark(MuxBenchParams {
            streams: 1,
            latency_round_trips: 200,
            latency_payload: 64,
            warmup_bytes_per_stream: 4 * 1024 * 1024,
            measure_bytes_per_stream: 64 * 1024 * 1024,
        })
        .await;
        single.report("single-stream");

        let concurrent = run_mux_loopback_benchmark(MuxBenchParams {
            streams: 8,
            latency_round_trips: 0,
            latency_payload: 0,
            warmup_bytes_per_stream: 1024 * 1024,
            measure_bytes_per_stream: 8 * 1024 * 1024,
        })
        .await;
        concurrent.report("8-stream-concurrent");
    }

    async fn spawn_camouflage_fallback() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            run_camouflage_tls_server(stream).await;
        });
        (addr, task)
    }

    async fn spawn_multi_echo_target(count: usize) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut tasks = Vec::with_capacity(count);
            for _ in 0..count {
                let (mut stream, _) = listener.accept().await.unwrap();
                tasks.push(tokio::spawn(async move {
                    let mut buf = vec![0_u8; 64 * 1024];
                    loop {
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        stream.write_all(&buf[..n]).await.unwrap();
                    }
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        });
        (addr, task)
    }

    async fn spawn_echo_target() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 64 * 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
            }
        });
        (addr, task)
    }

    async fn spawn_eof_response_target() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request-before-half-close");
            stream
                .write_all(b"response-after-half-close")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        (addr, task)
    }

    /// A target that, after reading a small request, streams a large response in
    /// chunks with small pauses so the transfer is still in flight when a test
    /// kills the QUIC connection mid-relay. Best-effort writes (the relay may be
    /// reset mid-stream), so errors are swallowed rather than asserted.
    async fn spawn_slow_large_response_target(
        total_len: usize,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 5];
            if stream.read_exact(&mut request).await.is_err() {
                return;
            }
            let chunk = vec![0xC7_u8; 64 * 1024];
            let mut written = 0;
            while written < total_len {
                let len = chunk.len().min(total_len - written);
                if stream.write_all(&chunk[..len]).await.is_err() {
                    return;
                }
                written += len;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        (addr, task)
    }

    /// A target that half-closes its WRITE side immediately (so the proxied
    /// server->client direction finishes promptly) and then READS its upload
    /// SLOWLY in small chunks with a pause between reads, accumulating every
    /// byte. The full received body is reported back over the returned oneshot
    /// once the upload reaches a clean EOF. Used by the asymmetric-upload
    /// truncation repro: the slow reads keep the upload tail mid-drain when the
    /// client's own directions finish, so a premature QUIC close would truncate
    /// it. `expected_len` only sizes the receive buffer; the target reads until
    /// EOF and reports whatever it actually received.
    async fn spawn_slow_reader_target(
        expected_len: usize,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<()>,
        oneshot::Receiver<Vec<u8>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (received_tx, received_rx) = oneshot::channel::<Vec<u8>>();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut read_half, mut write_half) = stream.split();
            // Half-close the response direction up front so the proxied
            // server->client direction reaches EOF quickly.
            write_half.shutdown().await.unwrap();

            let mut received = Vec::with_capacity(expected_len);
            let mut chunk = vec![0_u8; 16 * 1024];
            loop {
                let n = read_half.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n]);
                // Throttle: keep the upload tail in flight while the client's
                // directions finish. ~256 chunks * 25ms across 4 MiB.
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let _ = received_tx.send(received);
        });
        (addr, task, received_rx)
    }

    /// A target that reads the small request, then sends a large deterministic
    /// response (the `(idx % 251)` pattern) as fast as it can and closes. Used by
    /// the asymmetric-download truncation repro, where the LOCAL app reads the
    /// response slowly: a premature server-side connection drop would truncate
    /// the in-flight download.
    async fn spawn_fast_large_response_target(
        total_len: usize,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"start");
            let response = (0..total_len)
                .map(|idx| (idx % 251) as u8)
                .collect::<Vec<_>>();
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        (addr, task)
    }

    fn large_payload_server_config(
        fallback_addr: SocketAddr,
        target_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_identity_keys: &identity::MlDsaKeyPair,
        replay_cache_path: std::path::PathBuf,
    ) -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: fallback_addr.to_string(),
            data_target: Some(target_addr.to_string()),
            private_key: STANDARD.encode(server_keys.private).into(),
            identity_secret_key: STANDARD.encode(&server_identity_keys.secret).into(),
            replay_cache_path,
            replay_cache_capacity: crate::config::DEFAULT_REPLAY_CACHE_CAPACITY,
            authorized_sni: vec![String::from("example.com")],
            strict_tls13: true,
            max_concurrent_per_source_v4: 256,
            max_concurrent_per_source_v6: 256,
            source_ipv6_prefix_len: 64,
            first_record_wait_floor_ms: 8_000,
            first_record_wait_jitter_ms: 7_000,
            fallback_idle_floor_ms: 600_000,
            fallback_idle_jitter_ms: 0,
            tcp_congestion: None,
        }
    }

    async fn spawn_parallax_server(
        server_config: ServerConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        spawn_parallax_server_with_traffic(server_config, TrafficConfig::default()).await
    }

    async fn spawn_parallax_server_with_traffic(
        server_config: ServerConfig,
        traffic: TrafficConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        spawn_parallax_server_with_traffic_and_udp(server_config, traffic, UdpConfig::default())
            .await
    }

    async fn spawn_parallax_server_with_traffic_and_udp(
        server_config: ServerConfig,
        traffic: TrafficConfig,
        udp: UdpConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        // run() builds the stable carrier at startup; these tests call
        // handle_connection directly, so inject it here when the fast plane is on.
        if udp.enabled {
            if let Ok(carrier) = server::build_quic_carrier_for_test(&server_config, PSK).await {
                server::set_quic_carrier_for_test(Some(carrier));
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server::handle_connection(stream, &server_config, traffic, &udp, PSK)
                .await
                .unwrap();
        });
        (addr, task)
    }

    /// Like [`spawn_parallax_server_with_traffic_and_udp`] but tolerates a relay
    /// error (used by the mid-relay reset test, where killing the QUIC connection
    /// makes the relay return Err -- the expected clean-reset outcome).
    async fn spawn_parallax_server_with_traffic_and_udp_allow_err(
        server_config: ServerConfig,
        traffic: TrafficConfig,
        udp: UdpConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        if udp.enabled {
            if let Ok(carrier) = server::build_quic_carrier_for_test(&server_config, PSK).await {
                server::set_quic_carrier_for_test(Some(carrier));
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = server::handle_connection(stream, &server_config, traffic, &udp, PSK).await;
        });
        (addr, task)
    }

    async fn spawn_mux_local_client(
        parallax_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_identity_keys: &identity::MlDsaKeyPair,
        stream_count: usize,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_config = Arc::new(ClientConfig {
            listen: addr,
            server_addr: parallax_addr.to_string(),
            sni: "example.com".to_owned(),
            server_public_key: STANDARD.encode(server_keys.public),
            server_identity_public_key: STANDARD.encode(&server_identity_keys.public),
        });
        let traffic = TrafficConfig {
            max_concurrent_streams: stream_count as u8,
            ..TrafficConfig::default()
        };
        let server_addr = ServerAddrResolver::new(&client_config.server_addr)
            .await
            .unwrap();
        let mux_pool = ClientMuxPool::new(
            Arc::clone(&client_config),
            server_addr,
            traffic,
            Arc::new(UdpConfig::default()),
            Arc::new(UdpReachability::new(UDP_BLACKHOLE_TTL)),
            Arc::new(zeroize::Zeroizing::new(PSK.to_vec())),
            server_keys.public,
            Arc::from(server_identity_keys.public.clone().into_boxed_slice()),
        );
        let task = tokio::spawn(async move {
            let mut tasks = Vec::with_capacity(stream_count);
            for _ in 0..stream_count {
                let (stream, _) = listener.accept().await.unwrap();
                let mux_pool = mux_pool.clone();
                let cid = NEXT_CLIENT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
                tasks.push(tokio::spawn(async move {
                    handle_local_mux_connection_with_cid(stream, mux_pool, cid)
                        .await
                        .unwrap();
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        });
        (addr, task)
    }

    async fn spawn_local_client(
        parallax_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_identity_keys: &identity::MlDsaKeyPair,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        spawn_local_client_with_udp(
            parallax_addr,
            server_keys,
            server_identity_keys,
            UdpConfig::default(),
        )
        .await
    }

    async fn spawn_local_client_with_udp(
        parallax_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_identity_keys: &identity::MlDsaKeyPair,
        udp: UdpConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_config = ClientConfig {
            listen: addr,
            server_addr: parallax_addr.to_string(),
            sni: "example.com".to_owned(),
            server_public_key: STANDARD.encode(server_keys.public),
            server_identity_public_key: STANDARD.encode(&server_identity_keys.public),
        };
        let server_public_key = server_keys.public;
        let server_identity_public_key = server_identity_keys.public.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_local_connection(
                stream,
                &client_config,
                TrafficConfig::default(),
                &udp,
                PSK,
                &server_public_key,
                &server_identity_public_key,
            )
            .await
            .unwrap();
        });
        (addr, task)
    }

    /// Like [`spawn_local_client_with_udp`] but tolerates a relay error (used by
    /// the mid-relay reset test).
    async fn spawn_local_client_with_udp_allow_err(
        parallax_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_identity_keys: &identity::MlDsaKeyPair,
        udp: UdpConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_config = ClientConfig {
            listen: addr,
            server_addr: parallax_addr.to_string(),
            sni: "example.com".to_owned(),
            server_public_key: STANDARD.encode(server_keys.public),
            server_identity_public_key: STANDARD.encode(&server_identity_keys.public),
        };
        let server_public_key = server_keys.public;
        let server_identity_public_key = server_identity_keys.public.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_local_connection(
                stream,
                &client_config,
                TrafficConfig::default(),
                &udp,
                PSK,
                &server_public_key,
                &server_identity_public_key,
            )
            .await;
        });
        (addr, task)
    }

    async fn connect_socks_target(local_addr: SocketAddr, target_addr: SocketAddr) -> TcpStream {
        let mut app = TcpStream::connect(local_addr).await.unwrap();
        app.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        app.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        app.write_all(&[
            5,
            1,
            0,
            1,
            127,
            0,
            0,
            1,
            (target_addr.port() >> 8) as u8,
            (target_addr.port() & 0xff) as u8,
        ])
        .await
        .unwrap();
        let mut socks_reply = [0_u8; 10];
        app.read_exact(&mut socks_reply).await.unwrap();
        assert_eq!(socks_reply[0..2], [5, 0]);
        app
    }

    async fn assert_large_payload_round_trips(app: TcpStream) {
        let (mut app_read, mut app_write) = app.into_split();
        for len in [32 * 1024, 64 * 1024, 256 * 1024, 5 * 1024 * 1024] {
            let payload = (0..len).map(|idx| (idx % 251) as u8).collect::<Vec<_>>();
            let mut response = vec![0_u8; len];
            for (sent, expected) in response
                .chunks_mut(64 * 1024)
                .zip(payload.chunks(64 * 1024))
            {
                let (write_result, read_result) = timeout(Duration::from_secs(20), async {
                    tokio::join!(app_write.write_all(expected), app_read.read_exact(sent))
                })
                .await
                .unwrap_or_else(|_| panic!("payload round trip timed out for {len} bytes"));
                write_result.unwrap();
                read_result.unwrap();
            }
            assert_eq!(response, payload);
        }

        drop(app_read);
        drop(app_write);
    }

    async fn assert_payload_round_trip(mut app: TcpStream, payload: Vec<u8>) {
        app.write_all(&payload).await.unwrap();
        let mut response = vec![0_u8; payload.len()];
        timeout(Duration::from_secs(10), app.read_exact(&mut response))
            .await
            .unwrap_or_else(|_| panic!("mux payload round trip timed out"))
            .unwrap();
        assert_eq!(response, payload);
        app.shutdown().await.unwrap();
    }

    async fn wait_for_task(name: &str, task: tokio::task::JoinHandle<()>) {
        timeout(Duration::from_secs(5), task)
            .await
            .unwrap_or_else(|_| panic!("{name} task timed out"))
            .unwrap();
    }

    /// Like [`wait_for_task`] but with a caller-chosen timeout, for the slow
    /// asymmetric e2e tests whose relay tasks legitimately run for several seconds
    /// (throttled drains) and must not be bounded by the default 5s join window.
    async fn wait_for_task_within(name: &str, task: tokio::task::JoinHandle<()>, within: Duration) {
        timeout(within, task)
            .await
            .unwrap_or_else(|_| panic!("{name} task timed out"))
            .unwrap();
    }

    async fn run_camouflage_tls_server(mut stream: TcpStream) {
        let mut server =
            rustls::ServerConnection::new(rustls_server_config()).expect("rustls server config");
        let mut buf = [0_u8; 4096];

        while server.is_handshaking() {
            flush_rustls_server(&mut server, &mut stream).await;
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            let mut cursor = Cursor::new(&buf[..n]);
            server.read_tls(&mut cursor).unwrap();
            server.process_new_packets().unwrap();
        }

        flush_rustls_server(&mut server, &mut stream).await;
        let mut one = [0_u8; 1];
        let _ = timeout(Duration::from_millis(500), stream.read(&mut one)).await;
    }

    async fn flush_rustls_server(server: &mut rustls::ServerConnection, stream: &mut TcpStream) {
        while server.wants_write() {
            let mut out = Vec::new();
            server.write_tls(&mut out).unwrap();
            if out.is_empty() {
                break;
            }
            stream.write_all(&out).await.unwrap();
        }
    }

    fn rustls_server_config() -> Arc<rustls::ServerConfig> {
        let cert_der = CertificateDer::from(STANDARD.decode(CAMOUFLAGE_CERT_DER_B64).unwrap());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            STANDARD.decode(CAMOUFLAGE_KEY_DER_B64).unwrap(),
        ));
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("aws_lc_rs provider supports rustls default protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap(),
        )
    }

    /// Drives the REAL `run_client_udp_probe` (the production client probe function,
    /// including its process-wide ticket cache and the resumption branch) over
    /// loopback against a real 0-RTT server: the FIRST call is cold (the cache is
    /// empty) and deposits a ticket; the SECOND call picks that ticket up and resumes
    /// with 0-RTT, which the server ACCEPTS. This is the most faithful reproduction
    /// of the runtime 0-RTT path short of the full TCP/SOCKS control wrapper (which
    /// is orthogonal to 0-RTT). No other test calls `run_client_udp_probe`, so the
    /// process-wide ticket slot is exercised in isolation here.
    #[tokio::test]
    async fn run_client_udp_probe_resumes_with_0rtt_on_the_second_session() {
        use crate::crypto::replay::ReplayCache;
        use crate::protocol::command::UdpOffer;
        use crate::tls::quic::derive_stek;
        use crate::transport::udp::endpoint::bind_server_endpoint_0rtt;
        use crate::transport::udp::h3::{open_h3_control_stream, open_h3_encoder_stream};
        use crate::transport::udp::probe::{serve_probe_over_bidi, ProbeOutcome};
        use crate::transport::udp::quic::endpoint::Endpoint;
        use crate::transport::udp::zero_rtt::ReplayCacheGuard;

        const PSK: &[u8] = b"run-client-udp-probe-0rtt-test-ps";
        // The ephemeral test server sets no marker key, so it ignores the client's
        // marker (cold-start terminates everyone); any server_public works here.
        const SERVER_PUBLIC: [u8; 32] = [0x55; 32];
        let sni = "localhost";
        let timeout = Duration::from_secs(5);

        // Real 0-RTT server endpoint (production builder).
        let guard = Arc::new(ReplayCacheGuard::new(
            ReplayCache::new(64).with_window_secs(604_800),
        ));
        let server = bind_server_endpoint_0rtt(
            "127.0.0.1:0".parse().unwrap(),
            sni,
            derive_stek(&[0x71; 32]),
            guard,
        )
        .await
        .unwrap();
        let udp_port = server.local_addr().unwrap().port();
        let offer = UdpOffer {
            offer_id: [0x42; 16],
            udp_port,
            port_hop_seed: 0,
            cc: 0,
            fec_profile: 0,
            ignore_client_bandwidth: false,
        };

        // A throwaway loopback TCP connection so `run_client_udp_probe` can read the
        // server IP (127.0.0.1) off `peer_addr()`; it reuses `offer.udp_port`. The
        // listener accepts in a loop so both sessions' connects succeed.
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let _tcp_accept = tokio::spawn(async move { while tcp_listener.accept().await.is_ok() {} });

        // Server mirror of `accept_probed_quic_from_peer`: accept, open the control
        // stream (Safari-26 SETTINGS the client verifies), serve one bidi probe, open
        // the encoder. Returns whether it accepted 0-RTT plus the held streams (kept
        // alive by `join!` until the client finishes reading).
        async fn serve_one(server: &Endpoint, psk: &[u8], offer_id: &[u8]) -> (bool, impl Send) {
            let conn = server.accept().await.expect("server accepts");
            let control = open_h3_control_stream(&conn).await.expect("server control");
            let (mut send, mut recv) = conn.accept_bi().await.expect("server accept_bi");
            serve_probe_over_bidi(&conn, &mut send, &mut recv, psk, offer_id)
                .await
                .expect("server serve_probe_over_bidi");
            let encoder = open_h3_encoder_stream(&conn).await.ok();
            let accepted = conn.zero_rtt_keys_installed();
            (accepted, (conn, send, recv, control, encoder))
        }

        // Session 1: cold (empty cache) -> Verified, deposits a ticket.
        let tcp1 = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
        let ((accepted1, held1), probe1) = tokio::join!(
            serve_one(&server, PSK, &offer.offer_id),
            run_client_udp_probe(&tcp1, &offer, PSK, &SERVER_PUBLIC, sni, timeout),
        );
        assert!(
            matches!(probe1.outcome, ProbeOutcome::Verified { .. }),
            "cold probe must Verify, got {:?}",
            probe1.outcome
        );
        assert!(
            !accepted1,
            "cold session offers no ticket, so the server must NOT accept 0-RTT"
        );
        // Close both ends of session 1 before session 2 (fresh connections).
        drop(held1);
        drop(probe1);

        // Session 2: the cached ticket drives a 0-RTT resumption the server ACCEPTS.
        let tcp2 = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
        let ((accepted2, held2), probe2) = tokio::join!(
            serve_one(&server, PSK, &offer.offer_id),
            run_client_udp_probe(&tcp2, &offer, PSK, &SERVER_PUBLIC, sni, timeout),
        );
        assert!(
            matches!(probe2.outcome, ProbeOutcome::Verified { .. }),
            "resumed probe must Verify, got {:?}",
            probe2.outcome
        );
        assert!(
            accepted2,
            "second session must resume via the cached ticket and the server ACCEPTS 0-RTT"
        );
        drop(held2);
        drop(probe2);
    }
}
