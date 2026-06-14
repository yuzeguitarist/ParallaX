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
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        lookup_host,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{mpsc, oneshot, Mutex, Semaphore, TryAcquireError},
    time::{sleep, Instant},
};

use crate::{
    client::initial_payload,
    client::socks::{self, SocksError, SocksRequest},
    config::{
        decode_base64_bytes, decode_key32, decode_psk, ClientConfig, Config, ConfigError, Mode,
        TrafficConfig,
    },
    crypto::{auth::AuthError, identity, parallel, pq},
    handshake::client::{self, ClientDataSession, ClientHandshakeError, PendingPqRekey},
    protocol::command::{
        ConnectRequest, ConnectRequestError, MuxFrame, MuxFrameError, MuxFrameKind, MuxFrameRef,
        MuxPayloadPool, ServerIdentityChunk, ServerIdentityProof, ServerKeyExchange,
    },
    protocol::data::{
        max_plaintext_len, relay_read_buffer_len, should_parallelize_aead, DataRecordCodec,
        DataRecordError, SealedRecord,
    },
    tls::{
        record::{log_record_read, TlsRecordError, TlsRecordReader},
        safari26::{Safari26TlsCamouflage, Safari26TlsError},
    },
    traffic::CoverTrafficProfile,
    transport::tcp::{
        connect_tuned_tcp_addr, drain_ready_tcp_read, is_fd_exhaustion_error,
        relay_connection_limit, tune_tcp_stream,
    },
};

const MAX_SERVER_IDENTITY_PAYLOAD: usize = 16 * 1024;
const MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE: usize = 16;
const WARM_SESSION_POOL_TARGET: usize = 4;
const MUX_FRAME_CHANNEL_PER_STREAM: usize = 8;
const MUX_FRAME_BATCH_LIMIT: usize = 64;
/// Cap on the ciphertext bytes batched per mux read before opening, bounding
/// scratch memory while leaving enough records for the crypto pool to fan out.
const MUX_OPEN_BATCH_BYTES: usize = 1024 * 1024;

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

type ClientSession = (TcpStream, ClientDataSession);
type ClientSessionTask = tokio::task::JoinHandle<Result<ClientSession, ClientRuntimeError>>;

static CLIENT_UDP_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Process-wide client UDP probe budget (ms): the Happy-Eyeballs window for the
/// QUIC connect and the probe round-trip. Set once at startup; defaults to the
/// config default so paths that don't call `run()` (tests) still get a sane
/// bound.
static CLIENT_UDP_PROBE_TIMEOUT_MS: std::sync::atomic::AtomicU16 =
    std::sync::atomic::AtomicU16::new(300);

/// Stores the process-wide client UDP-negotiation runtime parameters, read at
/// the data-session seam. Called by both `run()` and the `speed` subcommand so
/// the two client entry points negotiate the UDP fast plane identically.
pub(crate) fn configure_udp_runtime(udp: &crate::config::UdpConfig) {
    CLIENT_UDP_ENABLED.store(udp.enabled, std::sync::atomic::Ordering::Relaxed);
    CLIENT_UDP_PROBE_TIMEOUT_MS.store(udp.probe_timeout_ms, std::sync::atomic::Ordering::Relaxed);
}

pub async fn run(config: Config) -> Result<(), ClientRuntimeError> {
    if config.mode != Mode::Client {
        return Err(ClientRuntimeError::WrongMode);
    }
    // Process-wide client UDP-negotiation parameters, read at the data-session
    // seam to decide whether to open a PX1G UdpRequest and how long to probe.
    // Set once at startup.
    configure_udp_runtime(&config.udp);

    let client = config
        .client
        .clone()
        .ok_or(ClientRuntimeError::MissingClient)?;
    let psk = decode_psk(&config.crypto.psk)?;
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
    let warm_sessions = if config.traffic.max_concurrent_streams == 1 {
        let warm_sessions = WarmSessionPool::new(
            Arc::clone(&client),
            server_addr.clone(),
            config.traffic,
            Arc::clone(&psk),
            server_public,
            Arc::clone(&server_identity_public),
        );
        warm_sessions.ensure_started().await;
        Some(warm_sessions)
    } else {
        None
    };
    let mux_sessions = if config.traffic.max_concurrent_streams > 1 {
        let mux_sessions = ClientMuxPool::new(
            Arc::clone(&client),
            server_addr.clone(),
            config.traffic,
            Arc::clone(&psk),
            server_public,
            Arc::clone(&server_identity_public),
        );
        mux_sessions.ensure_started();
        Some(mux_sessions)
    } else {
        None
    };
    let connection_limit = relay_connection_limit()?;
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
        psk,
        server_public,
        server_identity_public,
        warm_sessions: None,
    };
    handle_local_connection_with_cid(local, context, cid).await
}

struct ClientConnectionContext<'a> {
    config: &'a ClientConfig,
    server_addr: ServerAddrResolver,
    traffic: TrafficConfig,
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
    psk: Arc<Zeroizing<Vec<u8>>>,
    server_public: [u8; 32],
    server_identity_public: Arc<[u8]>,
}

impl WarmSessionPool {
    fn new(
        config: Arc<ClientConfig>,
        server_addr: ServerAddrResolver,
        traffic: TrafficConfig,
        psk: Arc<Zeroizing<Vec<u8>>>,
        server_public: [u8; 32],
        server_identity_public: Arc<[u8]>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            config,
            server_addr,
            traffic,
            psk,
            server_public,
            server_identity_public,
        }
    }

    async fn ensure_started(&self) {
        let mut warm = self.inner.lock().await;
        self.fill_locked(&mut warm);
    }

    async fn take_or_start(&self) -> ClientSessionTask {
        let mut warm = self.inner.lock().await;
        let session = warm.pop_front().unwrap_or_else(|| self.spawn_session());
        self.fill_locked(&mut warm);
        session
    }

    fn fill_locked(&self, warm: &mut VecDeque<ClientSessionTask>) {
        while warm.len() < WARM_SESSION_POOL_TARGET {
            warm.push_back(self.spawn_session());
        }
    }

    fn spawn_session(&self) -> ClientSessionTask {
        let config = Arc::clone(&self.config);
        let server_addr = self.server_addr.clone();
        let traffic = self.traffic;
        let psk = Arc::clone(&self.psk);
        let server_public = self.server_public;
        let server_identity_public = Arc::clone(&self.server_identity_public);
        tokio::spawn(async move {
            establish_authenticated_data_session_with_resolver(
                &server_addr,
                &config,
                traffic,
                psk.as_ref().as_slice(),
                &server_public,
                server_identity_public,
            )
            .await
        })
    }
}

#[derive(Clone)]
struct ClientMuxPool {
    inner: Arc<Mutex<Option<ClientMuxHandle>>>,
    config: Arc<ClientConfig>,
    server_addr: ServerAddrResolver,
    traffic: TrafficConfig,
    psk: Arc<Zeroizing<Vec<u8>>>,
    server_public: [u8; 32],
    server_identity_public: Arc<[u8]>,
}

#[derive(Clone)]
struct ClientMuxHandle {
    frame_tx: mpsc::Sender<MuxFrame>,
    register_tx: mpsc::Sender<ClientStreamRegistration>,
    next_stream_id: Arc<AtomicU32>,
    stream_slots: Arc<Semaphore>,
    chunk_size: usize,
    payload_pool: MuxPayloadPool,
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

enum DownloadOutcome {
    Fin,
    Reset,
}

impl ClientMuxPool {
    fn new(
        config: Arc<ClientConfig>,
        server_addr: ServerAddrResolver,
        traffic: TrafficConfig,
        psk: Arc<Zeroizing<Vec<u8>>>,
        server_public: [u8; 32],
        server_identity_public: Arc<[u8]>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            config,
            server_addr,
            traffic,
            psk,
            server_public,
            server_identity_public,
        }
    }

    async fn handle(&self) -> Result<ClientMuxHandle, ClientRuntimeError> {
        let mut mux = self.inner.lock().await;
        if let Some(handle) = mux.as_ref() {
            if !handle.frame_tx.is_closed() {
                return Ok(handle.clone());
            }
        }

        let handle = self.start_session().await?;
        *mux = Some(handle.clone());
        Ok(handle)
    }

    fn ensure_started(&self) {
        let mux_pool = self.clone();
        tokio::spawn(async move {
            if let Err(err) = mux_pool.handle().await {
                tracing::debug!(error = %err, "client mux warm session startup failed");
            }
        });
    }

    async fn start_session(&self) -> Result<ClientMuxHandle, ClientRuntimeError> {
        let (server, data_session) = establish_authenticated_data_session_with_resolver(
            &self.server_addr,
            self.config.as_ref(),
            self.traffic,
            self.psk.as_ref().as_slice(),
            &self.server_public,
            Arc::clone(&self.server_identity_public),
        )
        .await?;
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
            if let Err(err) =
                client_mux_reader_loop(server_read, open_from_server, register_rx, session_cid)
                    .await
            {
                tracing::debug!(cid = session_cid, error = %err, "client mux reader stopped");
            }
        });
        let cover = CoverTrafficProfile::from_config(self.traffic);
        let writer_pool = payload_pool.clone();
        tokio::spawn(async move {
            if let Err(err) = client_mux_writer_loop(
                server_write,
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

    let request = socks::accept_connect(&mut local).await?;
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
        .send(ClientStreamRegistration {
            stream_id,
            local_write,
            outcome_tx,
        })
        .await
        .is_err()
    {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "client mux reader is gone").into());
    }
    if let Err(err) = mux.frame_tx.send(open_frame).await {
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
    tokio::try_join!(upload, download).map(|_| ())
}

fn next_mux_stream_id(next: &AtomicU32) -> u32 {
    loop {
        let id = next.fetch_add(2, Ordering::Relaxed) | 1;
        if id != 0 {
            return id;
        }
    }
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
        let speculative_psk = Arc::<[u8]>::from(psk.to_vec().into_boxed_slice());
        let speculative_server_public = *server_public;
        let speculative_server_identity_public = server_identity_public.clone();
        tokio::spawn(async move {
            establish_authenticated_data_session_with_resolver(
                &speculative_server_addr,
                &speculative_config,
                traffic,
                speculative_psk.as_ref(),
                &speculative_server_public,
                speculative_server_identity_public,
            )
            .await
        })
    };
    let request = match socks::accept_connect(&mut local).await {
        Ok(request) => request,
        Err(err) => {
            server_session_task.abort();
            return Err(err.into());
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
    let (initial_payload, (mut server, mut data_session)) =
        tokio::try_join!(initial_payload_fut, server_session_fut)?;
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
        cid,
    }
    .run()
    .await
}

pub(crate) async fn establish_authenticated_data_session(
    config: &ClientConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    server_public: &[u8; 32],
    server_identity_public: &[u8],
) -> Result<(TcpStream, ClientDataSession), ClientRuntimeError> {
    let server_addr = ServerAddrResolver::new(&config.server_addr).await?;
    let server_identity_public =
        Arc::<[u8]>::from(server_identity_public.to_vec().into_boxed_slice());
    establish_authenticated_data_session_with_resolver(
        &server_addr,
        config,
        traffic,
        psk,
        server_public,
        server_identity_public,
    )
    .await
}

/// Probe the offered UDP fast plane over a fresh QUIC connection to the server's
/// IP and the offered port. Never errors — failures map to Unreachable/Failed so
/// the caller can always report a PX1P and keep the control stream aligned.
///
/// `sni` is the camouflage front domain (the client's REALITY SNI), used as the
/// QUIC ClientHello server name; it is never the literal "localhost", which would
/// be a zero-false-positive censorship signature on the wire.
async fn run_client_udp_probe(
    server: &TcpStream,
    offer: &crate::protocol::command::UdpOffer,
    psk: &[u8],
    sni: &str,
    probe_timeout: std::time::Duration,
) -> crate::transport::udp::probe::ProbeOutcome {
    use crate::transport::udp::probe::ProbeOutcome;
    let Ok(peer) = server.peer_addr() else {
        return ProbeOutcome::Failed;
    };
    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(endpoint) = crate::transport::udp::endpoint::bind_client_endpoint_accept_any(
        bind.parse().expect("valid wildcard bind address"),
    ) else {
        return ProbeOutcome::Failed;
    };
    let udp_addr = std::net::SocketAddr::new(peer.ip(), offer.udp_port);
    let Ok(connecting) = endpoint.connect(udp_addr, sni) else {
        return ProbeOutcome::Failed;
    };
    let conn = match tokio::time::timeout(probe_timeout, connecting).await {
        Ok(Ok(conn)) => conn,
        _ => return ProbeOutcome::Unreachable,
    };
    crate::transport::udp::probe::probe_client(&conn, psk, &offer.offer_id, probe_timeout)
        .await
        .unwrap_or(ProbeOutcome::Failed)
}

async fn establish_authenticated_data_session_with_resolver(
    server_addr: &ServerAddrResolver,
    config: &ClientConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    server_public: &[u8; 32],
    server_identity_public: Arc<[u8]>,
) -> Result<(TcpStream, ClientDataSession), ClientRuntimeError> {
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

    // Client-initiated, fail-soft UDP negotiation. Gated on the process-wide
    // udp.enabled flag. The client offers to use the UDP fast plane; the server
    // replies PX1N (decline) until the UDP datapath is wired. This runs strictly
    // before the first Connect/Mux command, so it occupies record #1 in each AEAD
    // direction with no reordering risk. An error here fails the connection (the
    // record stream would be desynced), which is the correct outcome.
    if CLIENT_UDP_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
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
            let (offer_id, outcome) = match UdpOffer::decode(&response) {
                Ok(offer) => {
                    let probe_timeout = std::time::Duration::from_millis(u64::from(
                        CLIENT_UDP_PROBE_TIMEOUT_MS
                            .load(std::sync::atomic::Ordering::Relaxed)
                            .max(1),
                    ));
                    let outcome =
                        run_client_udp_probe(&server, &offer, psk, &config.sni, probe_timeout)
                            .await;
                    (offer.offer_id, outcome)
                }
                Err(err) => {
                    tracing::debug!(error = %err, "udp offer decode failed");
                    ([0_u8; 16], ProbeOutcome::Failed)
                }
            };
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
            let ack = UdpProbeAck {
                offer_id,
                status,
                rtt_micros,
            }
            .encode();
            let ack_record = data_session.seal_payload(&ack, &mut OsRng)?;
            server.write_all(&ack_record).await?;
        } else if UdpDecline::has_magic(&response) {
            tracing::info!("UDP fast plane declined by server; continuing on TCP");
        } else {
            tracing::info!("UDP negotiation: unrecognized response; continuing on TCP");
        }
    }

    Ok((server, data_session))
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

async fn apply_server_key_exchange_after_residuals<R>(
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
    loop {
        server_records.read_record_into(&mut record).await?;
        match apply_server_key_exchange_record_blocking(
            data_session,
            &mut record,
            pending_rekey,
            psk,
        )
        .await
        {
            Ok(()) => {
                if skipped > 0 {
                    tracing::warn!(
                        skipped,
                        budget = MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE,
                        "accepted server key exchange after skipping residual camouflage records"
                    );
                }
                return Ok(());
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
) -> Result<(), ClientRuntimeError> {
    let exchange_payload_range = data_session.open_server_record_in_place_payload_range(record)?;
    let exchange_payload = &record[exchange_payload_range];
    let exchange =
        ServerKeyExchange::decode_ref(exchange_payload).map_err(ClientHandshakeError::from)?;
    let pq_identity_binding = pending_rekey.identity_binding(exchange_payload);
    let x25519_shared = pending_rekey.x25519_shared_secret(&exchange.server_x25519_public);
    let mlkem_ciphertext = exchange.mlkem_ciphertext.to_vec();
    let secret_key = zeroize::Zeroizing::new(pending_rekey.mlkem_secret_key().to_vec());
    let pq_shared = tokio::task::spawn_blocking(move || {
        pq::decapsulate(&mlkem_ciphertext, secret_key.as_slice())
            .map_err(ClientHandshakeError::from)
    })
    .await??;
    data_session.apply_pq_rekey_shared_with_identity_binding(
        &x25519_shared,
        &pq_shared,
        psk,
        pq_identity_binding,
    )?;
    Ok(())
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
    cid: u64,
}

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
            cid,
        } = self;
        let local_buf = vec![0_u8; relay_read_buffer_len(chunk_size)];
        let (seal_to_server, open_from_server) = data_session.into_data_codecs();
        let upload = client_upload_loop(
            local_read,
            server_write,
            seal_to_server,
            local_buf,
            cover,
            cid,
        );
        let download = client_download_loop(server_read, local_write, open_from_server, cid);

        let ((), ()) = tokio::try_join!(upload, download)?;
        Ok(())
    }
}

async fn client_upload_loop(
    mut local_read: OwnedReadHalf,
    mut server_write: OwnedWriteHalf,
    mut seal_to_server: DataRecordCodec,
    mut local_buf: Vec<u8>,
    cover: CoverTrafficProfile,
    cid: u64,
) -> Result<(), ClientRuntimeError> {
    let mut seal_scratch = RelaySealScratch::with_payload_capacity(local_buf.len());
    let mut rng = StdRng::from_entropy();
    if !cover.is_enabled() {
        loop {
            let n = local_read.read(&mut local_buf).await?;
            if n == 0 {
                let _ = server_write.shutdown().await;
                return Ok(());
            }
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
                    return Ok(());
                }
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

async fn client_download_loop(
    server_read: OwnedReadHalf,
    mut local_write: OwnedWriteHalf,
    mut open_from_server: DataRecordCodec,
    cid: u64,
) -> Result<(), ClientRuntimeError> {
    let mut server_records = TlsRecordReader::buffered(server_read);
    let mut server_record = Vec::new();

    loop {
        match server_records.read_record_into(&mut server_record).await {
            Ok(()) => {}
            Err(err) if is_clean_close(&err) => {
                let _ = local_write.shutdown().await;
                return Ok(());
            }
            Err(err) => return Err(ClientRuntimeError::Io(err)),
        };
        log_record_read(cid, "server->client", "client-outer-reader", &server_record);

        match open_from_server.open_in_place_payload_range(&mut server_record) {
            Ok(plaintext) => {
                if !plaintext.is_empty() {
                    local_write.write_all(&server_record[plaintext]).await?;
                }
            }
            Err(err) => {
                return Err(ClientRuntimeError::Handshake(err.into()));
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

async fn client_mux_reader_loop(
    server_read: OwnedReadHalf,
    mut open_from_server: DataRecordCodec,
    mut register_rx: mpsc::Receiver<ClientStreamRegistration>,
    cid: u64,
) -> Result<(), ClientRuntimeError> {
    let mut server_records = TlsRecordReader::buffered(server_read);
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
                        Some(reg) => {
                            local_writes.insert(
                                reg.stream_id,
                                ClientDownloadStream { write: reg.local_write, outcome_tx: reg.outcome_tx },
                            );
                        }
                        None => register_open = false,
                    }
                    continue;
                }
                result = server_records.read_record_into(&mut server_record) => result,
            }
        };
        match read_result {
            Ok(()) => {}
            Err(err) if is_clean_close(&err) => {
                shutdown_client_download_streams(&mut local_writes).await;
                return Ok(());
            }
            Err(err) => {
                shutdown_client_download_streams(&mut local_writes).await;
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
        while batch_records.len() + server_record.len() < MUX_OPEN_BATCH_BYTES {
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
                    record_count += 1;
                }
                Some(Err(err)) => {
                    deferred_read_error = Some(err);
                    break;
                }
            }
        }

        // Absorb any registrations queued alongside these records so a
        // stream's write half is always present before its first Data.
        while let Ok(reg) = register_rx.try_recv() {
            local_writes.insert(
                reg.stream_id,
                ClientDownloadStream {
                    write: reg.local_write,
                    outcome_tx: reg.outcome_tx,
                },
            );
        }

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
            return Err(MuxFrameError::InvalidKind.into());
        }
    }
    Ok(())
}

/// Closes every download half when the session ends. Dropping each one-shot
/// sender signals the waiting per-connection task that the download finished.
async fn shutdown_client_download_streams(local_writes: &mut HashMap<u32, ClientDownloadStream>) {
    for (_, mut stream) in local_writes.drain() {
        let _ = stream.write.shutdown().await;
    }
}

async fn client_mux_writer_loop(
    mut server_write: OwnedWriteHalf,
    mut seal_to_server: DataRecordCodec,
    mut frame_rx: mpsc::Receiver<MuxFrame>,
    cover: CoverTrafficProfile,
    cid: u64,
    payload_pool: MuxPayloadPool,
) -> Result<(), ClientRuntimeError> {
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
    W: AsyncWrite + Unpin,
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
    W: AsyncWrite + Unpin,
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
    writer.write_all(scratch.records_buf.as_slice()).await?;
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
    W: AsyncWrite + Unpin,
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
    writer.write_all(scratch.records_buf.as_slice()).await?;
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

fn is_clean_close(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    )
}

#[allow(dead_code)]
fn _request_target(request: &SocksRequest) -> String {
    request.target()
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

    /// Serializes the tests that mutate the process-wide UDP-negotiation flags
    /// (CLIENT_UDP_ENABLED / SERVER_UDP_ENABLED). Under a parallel `--ignored`
    /// run these globals would otherwise leak across tests — e.g. the
    /// full-negotiation test's SERVER_UDP_ENABLED=true bleeding into the
    /// decline-path test and silently changing the path it claims to exercise.
    static UDP_NEGOTIATION_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
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
        let session_keys =
            derive_client_keys(&client_keys.private, &server_keys.public, &transcript_hash)
                .unwrap();
        let traffic = TrafficConfig::default();
        let mut data_session = ClientDataSession::new(session_keys.clone(), traffic).unwrap();
        let mut rng = StdRng::seed_from_u64(90);

        let (pq_record, pending_rekey) = data_session.build_pq_rekey_record(&mut rng).unwrap();
        let (mut server_open, mut server_seal) = data_codecs(&session_keys, traffic).unwrap();
        let pq_request = PqRekeyRequest::decode(&server_open.open(&pq_record).unwrap()).unwrap();
        let server_ephemeral = X25519KeyPair::generate();
        let x25519_ephemeral_shared = crate::crypto::session::x25519_shared_secret(
            &server_ephemeral.private,
            &pq_request.client_x25519_public,
        );
        let pq_encapsulation = pq::encapsulate(&pq_request.client_mlkem_public_key).unwrap();
        let key_exchange_record = server_seal
            .seal(
                &ServerKeyExchange {
                    server_x25519_public: server_ephemeral.public,
                    mlkem_ciphertext: pq_encapsulation.ciphertext,
                }
                .encode()
                .unwrap(),
                &mut rng,
            )
            .unwrap();

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
        let server_pq_keys = pq::keypair();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server(server_config).await;
        let (local_addr, client_task) = spawn_local_client(
            parallax_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
        )
        .await;

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
        let server_pq_keys = pq::keypair();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server(server_config).await;
        let (local_addr, client_task) = spawn_local_client(
            parallax_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
        )
        .await;

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
        // Hold the serial lock for the whole test so a concurrent --ignored run
        // cannot leak the other test's SERVER_UDP_ENABLED into this one.
        let _serial = UDP_NEGOTIATION_TEST_LOCK.lock().await;
        // Turn on client-initiated UDP negotiation process-wide for this test;
        // the server replies PX1N (decline). The relay must still succeed,
        // proving the PX1G/PX1N control-plane exchange keeps the AEAD record
        // stream in sync (record #1 each direction) before the real command.
        struct UdpFlagGuard;
        impl Drop for UdpFlagGuard {
            fn drop(&mut self) {
                CLIENT_UDP_ENABLED.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
        CLIENT_UDP_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
        let _udp_guard = UdpFlagGuard;

        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_eof_response_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_pq_keys = pq::keypair();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server(server_config).await;
        let (local_addr, client_task) = spawn_local_client(
            parallax_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
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
        // Hold the serial lock for the whole test so a concurrent --ignored run
        // cannot leak this test's SERVER_UDP_ENABLED into the decline-path test.
        let _serial = UDP_NEGOTIATION_TEST_LOCK.lock().await;
        // Both sides enabled: the server offers the UDP fast plane (PX1O), the
        // client probes it over QUIC and reports PX1P; the SOCKS relay must still
        // complete, proving the full offer/probe/ack exchange keeps the control
        // stream aligned end to end.
        struct UdpFlagGuard;
        impl Drop for UdpFlagGuard {
            fn drop(&mut self) {
                CLIENT_UDP_ENABLED.store(false, std::sync::atomic::Ordering::Relaxed);
                crate::handshake::server::SERVER_UDP_ENABLED
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
        CLIENT_UDP_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
        crate::handshake::server::SERVER_UDP_ENABLED
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _udp_guard = UdpFlagGuard;

        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_eof_response_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_pq_keys = pq::keypair();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let (parallax_addr, server_task) = spawn_parallax_server(server_config).await;
        let (local_addr, client_task) = spawn_local_client(
            parallax_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
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

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn mux_client_reaches_two_targets_over_one_authenticated_session() {
        let (fallback_addr, fallback_task) = spawn_camouflage_fallback().await;
        let (target_addr, target_task) = spawn_multi_echo_target(2).await;

        let server_keys = X25519KeyPair::generate();
        let server_pq_keys = pq::keypair();
        let server_identity_keys = crate::crypto::identity::keypair();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        let mux_traffic = TrafficConfig {
            max_concurrent_streams: 2,
            ..TrafficConfig::default()
        };
        let (parallax_addr, server_task) =
            spawn_parallax_server_with_traffic(server_config, mux_traffic).await;
        let (local_addr, client_task) = spawn_mux_local_client(
            parallax_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
            2,
        )
        .await;

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
        let server_pq_keys = pq::keypair();
        let server_identity_keys = crate::crypto::identity::keypair();
        let replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = large_payload_server_config(
            fallback_addr,
            target_addr,
            &server_keys,
            &server_pq_keys,
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
            &server_pq_keys,
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

    fn large_payload_server_config(
        fallback_addr: SocketAddr,
        target_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_pq_keys: &pq::MlKemKeyPair,
        server_identity_keys: &identity::MlDsaKeyPair,
        replay_cache_path: std::path::PathBuf,
    ) -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: fallback_addr.to_string(),
            data_target: Some(target_addr.to_string()),
            private_key: STANDARD.encode(server_keys.private),
            pq_secret_key: STANDARD.encode(&server_pq_keys.secret),
            identity_secret_key: STANDARD.encode(&server_identity_keys.secret),
            replay_cache_path,
            replay_cache_capacity: crate::config::DEFAULT_REPLAY_CACHE_CAPACITY,
            authorized_sni: vec![String::from("example.com")],
            strict_tls13: true,
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server::handle_connection(stream, &server_config, traffic, PSK)
                .await
                .unwrap();
        });
        (addr, task)
    }

    async fn spawn_mux_local_client(
        parallax_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_pq_keys: &pq::MlKemKeyPair,
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
            server_pq_public_key: STANDARD.encode(&server_pq_keys.public),
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
        server_pq_keys: &pq::MlKemKeyPair,
        server_identity_keys: &identity::MlDsaKeyPair,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_config = ClientConfig {
            listen: addr,
            server_addr: parallax_addr.to_string(),
            sni: "example.com".to_owned(),
            server_public_key: STANDARD.encode(server_keys.public),
            server_pq_public_key: STANDARD.encode(&server_pq_keys.public),
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
                PSK,
                &server_public_key,
                &server_identity_public_key,
            )
            .await
            .unwrap();
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
}
