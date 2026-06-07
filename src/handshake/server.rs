use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        lookup_host,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{mpsc, Semaphore, TryAcquireError},
    time::{sleep, timeout, timeout_at, Instant},
};
use zeroize::Zeroize;

use super::transcript::transcript_hash;

use crate::{
    config::{
        decode_base64_secret, decode_key32_secret, decode_psk, Config, ConfigError, Mode,
        ServerConfig, TrafficConfig,
    },
    crypto::{
        auth::{
            derive_server_auth_key_from_shared, recover_stateful_auth_material_from_parsed,
            verify_client_hello_auth_with_parsed,
            verify_masked_stateful_client_hello_auth_with_parsed_material, AuthError, ClientAuth,
        },
        identity::{self, IdentityError},
        pq::{self, PqError},
        replay::{current_unix_timestamp, ReplayCache, ReplayCacheError, ReplayEntry},
        session::{
            derive_server_keys_from_shared, expand_epoch_keys, x25519_public_from_private,
            x25519_shared_secret, AeadCodec, SessionError, SessionKeys, X25519KeyPair,
        },
    },
    protocol::{
        command::{
            ConnectRequest, ConnectRequestError, MuxFrame, MuxFrameError, MuxFrameKind,
            MuxFrameRef, PqRekeyError, PqRekeyRequest, ServerIdentityChunk,
            ServerIdentityChunkError, ServerIdentityProof, ServerIdentityProofError,
            ServerKeyExchange, ServerKeyExchangeError, SpeedTestAck, SpeedTestRequest,
            SpeedTestRequestError,
        },
        data::{
            max_plaintext_len, relay_read_buffer_len, DataRecordCodec, DataRecordError,
            SealedRecord, CLIENT_TO_SERVER_AAD, SERVER_TO_CLIENT_AAD,
        },
    },
    tls::{
        client_hello::parse_client_hello,
        record::{log_record_read, parse_header, read_record, TlsRecordReader, TLS_HEADER_LEN},
        server_hello::{parse_server_hello, ServerHello, ServerHelloError},
    },
    traffic::{CoverTrafficProfile, PaddingProfile, TimingProfile, TrafficError},
    transport::tcp::{
        connect_tuned_tcp_any, connect_tuned_tcp_host, drain_ready_tcp_read,
        is_fd_exhaustion_error, relay_connection_limit, tune_tcp_stream,
    },
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const FALLBACK_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const SERVER_IDENTITY_CHUNK_MIN_PLAINTEXT: usize = 960;
const SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT: usize = 1320;
const SERVER_IDENTITY_CHUNK_MIN_DELAY: Duration = Duration::from_millis(45);
const CLIENT_RESIDUAL_CAMOUFLAGE_RECORD_BUDGET: usize = 16;
const PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT: usize = CLIENT_RESIDUAL_CAMOUFLAGE_RECORD_BUDGET / 2;
const SERVER_MUX_FRAME_CHANNEL: usize = 1024;
const SERVER_MUX_FRAME_BATCH_LIMIT: usize = 32;

static NEXT_SERVER_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum HandshakeServerError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("server mode requires [server] config")]
    MissingServer,
    #[error("parallax server requires mode = \"server\"")]
    WrongMode,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("ClientHello authentication failed: {0}")]
    Auth(#[from] AuthError),
    #[error("ServerHello parse failed: {0}")]
    ServerHello(#[from] ServerHelloError),
    #[error("handshake timed out")]
    Timeout,
    #[error("outbound TCP connect timed out")]
    OutboundConnectTimeout,
    #[error("fallback ServerHello did not negotiate TLS 1.3")]
    Tls13Required,
    #[error("session key derivation failed: {0}")]
    Session(#[from] SessionError),
    #[error("data record error: {0}")]
    DataRecord(#[from] DataRecordError),
    #[error("traffic shaping error: {0}")]
    Traffic(#[from] TrafficError),
    #[error("connect request error: {0}")]
    ConnectRequest(#[from] ConnectRequestError),
    #[error("speed test request error: {0}")]
    SpeedTestRequest(#[from] SpeedTestRequestError),
    #[error("mux frame error: {0}")]
    MuxFrame(#[from] MuxFrameError),
    #[error("PQ rekey command error: {0}")]
    PqRekey(#[from] PqRekeyError),
    #[error("server key exchange command error: {0}")]
    ServerKeyExchange(#[from] ServerKeyExchangeError),
    #[error("PQ crypto error: {0}")]
    Pq(#[from] PqError),
    #[error("server identity proof command error: {0}")]
    ServerIdentityProof(#[from] ServerIdentityProofError),
    #[error("server identity chunk command error: {0}")]
    ServerIdentityChunk(#[from] ServerIdentityChunkError),
    #[error("server identity signing failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("replay cache error: {0}")]
    ReplayCache(#[from] ReplayCacheError),
    #[error("missing encrypted connect request and no fixed server.data_target configured")]
    MissingConnectTarget,
    #[error("client-selected outbound target is denied by server egress policy: {0}")]
    OutboundTargetDenied(String),
    #[error("blocking crypto task failed: {0}")]
    BlockingTask(#[from] tokio::task::JoinError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundDecision {
    Authenticated(AuthenticatedHello),
    Fallback(FallbackReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedHello {
    pub sni: String,
    /// ParallaX ephemeral X25519 public key carried in ClientHello.random.
    pub x25519_key_share: [u8; 32],
    pub timestamp: u64,
    pub nonce: [u8; 8],
    pub transcript_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackReason {
    AuthFailed,
    Replay,
    MissingSni,
    UnauthorizedSni(String),
}

#[derive(Debug)]
pub struct ForwardedServerHello {
    pub raw_record: Vec<u8>,
    pub parsed: ServerHello,
}

#[derive(Debug)]
pub struct AuthenticatedHandshake {
    pub client: TcpStream,
    pub fallback: TcpStream,
    pub client_hello: AuthenticatedHello,
    pub server_hello: ServerHello,
    pub session_keys: SessionKeys,
    pub server_public_key: [u8; 32],
}

struct AuthenticatedInbound {
    hello: AuthenticatedHello,
    x25519_shared_secret: [u8; 32],
}

struct PendingReplayEntry {
    cache: Arc<Mutex<ReplayCache>>,
    entry: ReplayEntry,
}

enum ConnectionDecision {
    Authenticated(AuthenticatedInbound),
    Fallback(FallbackReason),
}

#[derive(Debug, PartialEq, Eq)]
enum FirstClientRead {
    Record(Vec<u8>),
    FallbackPrefix(Vec<u8>),
}

pub async fn run(config: Config) -> Result<(), HandshakeServerError> {
    if config.mode != Mode::Server {
        return Err(HandshakeServerError::WrongMode);
    }

    let server = config
        .server
        .clone()
        .ok_or(HandshakeServerError::MissingServer)?;
    let server = Arc::new(server);
    let traffic = config.traffic;
    let psk = decode_psk(&config.crypto.psk)?;
    crate::process_hardening::protect_secret_bytes("runtime.crypto.psk", psk.as_slice());
    let psk = Arc::new(psk);
    let replay_cache = Arc::new(Mutex::new(ReplayCache::load_or_create_authenticated(
        &server.replay_cache_path,
        8192,
        &psk,
    )?));
    let secrets = ServerRuntimeSecrets::decode(&server)?;
    let listener = TcpListener::bind(server.listen).await?;
    let connection_limit = relay_connection_limit()?;
    let connection_slots = Arc::new(Semaphore::new(connection_limit));
    tracing::info!(
        connection_limit,
        "ParallaX server listening on {}",
        server.listen
    );

    loop {
        let (client, peer) = match listener.accept().await {
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
                    "server connection limit reached; closing accepted socket"
                );
                drop(client);
                continue;
            }
            Err(TryAcquireError::Closed) => {
                return Err(io::Error::other("server connection limiter was closed").into());
            }
        };
        let cid = NEXT_SERVER_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let server = Arc::clone(&server);
        let connection_traffic = traffic;
        let psk = Arc::clone(&psk);
        let replay_cache = Arc::clone(&replay_cache);
        let secrets = secrets.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(err) = handle_connection_with_replay(
                client,
                &server,
                connection_traffic,
                &psk,
                replay_cache,
                &secrets,
                cid,
            )
            .await
            {
                tracing::debug!(cid, %peer, error = %err, "connection closed");
            }
        });
    }
}

pub async fn handle_connection(
    client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    psk: &[u8],
) -> Result<(), HandshakeServerError> {
    let cid = NEXT_SERVER_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let secrets = ServerRuntimeSecrets::decode(config)?;
    handle_connection_inner(client, config, traffic, psk, None, &secrets, cid).await
}

async fn handle_connection_with_replay(
    client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    replay_cache: Arc<Mutex<ReplayCache>>,
    secrets: &ServerRuntimeSecrets,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    handle_connection_inner(
        client,
        config,
        traffic,
        psk,
        Some(replay_cache),
        secrets,
        cid,
    )
    .await
}

async fn handle_connection_inner(
    mut client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    replay_cache: Option<Arc<Mutex<ReplayCache>>>,
    secrets: &ServerRuntimeSecrets,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    tune_tcp_stream(&client)?;
    tracing::info!(
        cid,
        task_name = "server-connection",
        "accepted outer connection"
    );
    let server_private = secrets.private_key();
    let server_public_key = secrets.server_public_key();
    let first_record = match read_first_client_record(&mut client).await? {
        FirstClientRead::Record(record) => record,
        FirstClientRead::FallbackPrefix(prefix) => {
            tracing::info!(
                cid,
                prefix_len = prefix.len(),
                "falling back to camouflage origin before a complete ClientHello"
            );
            relay_fallback(client, &config.fallback_addr, prefix).await?;
            return Ok(());
        }
    };
    match decide_connection_inbound(&first_record, psk, &config.authorized_sni, server_private)? {
        ConnectionDecision::Fallback(reason) => {
            tracing::info!(cid, ?reason, "falling back to camouflage origin");
            relay_fallback(client, &config.fallback_addr, first_record).await?;
        }
        ConnectionDecision::Authenticated(authenticated) => {
            let AuthenticatedInbound {
                hello: client_hello,
                x25519_shared_secret,
            } = authenticated;
            let pending_replay = replay_cache.map(|cache| PendingReplayEntry {
                cache,
                entry: ReplayEntry {
                    timestamp: client_hello.timestamp,
                    nonce: client_hello.nonce,
                    transcript_fingerprint: client_hello.transcript_fingerprint,
                },
            });
            let handshake = accept_authenticated(
                client,
                config,
                server_public_key,
                x25519_shared_secret,
                first_record,
                client_hello,
            )
            .await?;
            tracing::info!(
                cid,
                sni = %handshake.client_hello.sni,
                tls13 = handshake.server_hello.tls13_selected,
                "authenticated ParallaX handshake accepted"
            );
            run_authenticated_data_mode(
                handshake,
                config.data_target.as_deref(),
                secrets.identity_secret_key(),
                psk,
                traffic,
                pending_replay,
                cid,
            )
            .await?;
        }
    }

    Ok(())
}

#[derive(Clone)]
struct ServerRuntimeSecrets {
    private_key: Arc<zeroize::Zeroizing<[u8; 32]>>,
    server_public_key: [u8; 32],
    identity_secret_key: Arc<zeroize::Zeroizing<Vec<u8>>>,
}

impl ServerRuntimeSecrets {
    fn decode(config: &ServerConfig) -> Result<Self, ConfigError> {
        let private_key = decode_key32_secret("server.private_key", &config.private_key)?;
        crate::process_hardening::protect_secret_bytes("runtime.server.private_key", &*private_key);
        let server_public_key = x25519_public_from_private(&private_key);
        let identity_secret_key =
            decode_base64_secret("server.identity_secret_key", &config.identity_secret_key)?;
        crate::process_hardening::protect_secret_bytes(
            "runtime.server.identity_secret_key",
            identity_secret_key.as_slice(),
        );
        Ok(Self {
            private_key: Arc::new(private_key),
            server_public_key,
            identity_secret_key: Arc::new(identity_secret_key),
        })
    }

    fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    fn server_public_key(&self) -> [u8; 32] {
        self.server_public_key
    }

    fn identity_secret_key(&self) -> Arc<zeroize::Zeroizing<Vec<u8>>> {
        Arc::clone(&self.identity_secret_key)
    }
}

fn client_hello_fingerprint(first_record: &[u8]) -> [u8; 32] {
    Sha256::digest(first_record).into()
}

pub fn decide_inbound(
    first_client_record: &[u8],
    psk: &[u8],
    authorized_sni: &[String],
    server_private: &[u8; 32],
) -> Result<InboundDecision, HandshakeServerError> {
    match decide_connection_inbound(first_client_record, psk, authorized_sni, server_private)? {
        ConnectionDecision::Authenticated(authenticated) => {
            Ok(InboundDecision::Authenticated(authenticated.hello))
        }
        ConnectionDecision::Fallback(reason) => Ok(InboundDecision::Fallback(reason)),
    }
}

fn decide_connection_inbound(
    first_client_record: &[u8],
    psk: &[u8],
    authorized_sni: &[String],
    server_private: &[u8; 32],
) -> Result<ConnectionDecision, HandshakeServerError> {
    let parsed = match parse_client_hello(first_client_record) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed)),
    };
    if !parsed.tls13_supported {
        return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed));
    }
    if let Some(material) =
        recover_stateful_auth_material_from_parsed(first_client_record, psk, &parsed)?
    {
        let x25519_key_share = material.x25519_public;
        let x25519_shared_secret = x25519_shared_secret(server_private, &x25519_key_share);
        let auth_key = derive_server_auth_key_from_shared(psk, &x25519_shared_secret)?;
        let auth = match verify_masked_stateful_client_hello_auth_with_parsed_material(
            first_client_record,
            &auth_key,
            &material,
            &parsed,
        ) {
            Ok(auth) => auth,
            Err(err @ (AuthError::EmptyPsk | AuthError::Hkdf)) => return Err(err.into()),
            Err(_) => return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed)),
        };
        if auth.authenticated {
            return authenticated_decision(
                first_client_record,
                auth,
                authorized_sni,
                x25519_key_share,
                x25519_shared_secret,
            );
        }
    }

    let x25519_key_share = parsed.client_random;
    let x25519_shared_secret = x25519_shared_secret(server_private, &x25519_key_share);
    let auth_key = derive_server_auth_key_from_shared(psk, &x25519_shared_secret)?;
    let auth =
        match verify_client_hello_auth_with_parsed(first_client_record, &auth_key, None, parsed) {
            Ok(auth) => auth,
            Err(err @ (AuthError::EmptyPsk | AuthError::Hkdf)) => return Err(err.into()),
            Err(_) => return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed)),
        };
    if !auth.authenticated {
        return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed));
    }
    authenticated_decision(
        first_client_record,
        auth,
        authorized_sni,
        x25519_key_share,
        x25519_shared_secret,
    )
}

fn authenticated_decision(
    first_client_record: &[u8],
    auth: ClientAuth,
    authorized_sni: &[String],
    x25519_key_share: [u8; 32],
    x25519_shared_secret: [u8; 32],
) -> Result<ConnectionDecision, HandshakeServerError> {
    let timestamp = match auth.timestamp {
        Some(timestamp) => timestamp,
        None => return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed)),
    };
    let nonce = match auth.nonce {
        Some(nonce) => nonce,
        None => return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed)),
    };

    let sni = match auth.sni {
        Some(sni) => sni,
        None => return Ok(ConnectionDecision::Fallback(FallbackReason::MissingSni)),
    };

    if !is_authorized_sni(&sni, authorized_sni) {
        return Ok(ConnectionDecision::Fallback(
            FallbackReason::UnauthorizedSni(sni),
        ));
    }

    Ok(ConnectionDecision::Authenticated(AuthenticatedInbound {
        hello: AuthenticatedHello {
            sni,
            x25519_key_share,
            timestamp,
            nonce,
            transcript_fingerprint: client_hello_fingerprint(first_client_record),
        },
        x25519_shared_secret,
    }))
}

pub async fn accept_authenticated(
    mut client: TcpStream,
    config: &ServerConfig,
    server_public_key: [u8; 32],
    x25519_shared_secret: [u8; 32],
    first_client_record: Vec<u8>,
    client_hello: AuthenticatedHello,
) -> Result<AuthenticatedHandshake, HandshakeServerError> {
    let mut fallback = connect_tcp_with_timeout(&config.fallback_addr).await?;
    tune_tcp_stream(&fallback)?;
    fallback.write_all(&first_client_record).await?;

    let forwarded = read_forwarded_server_hello(&mut fallback).await?;
    if config.strict_tls13 && !forwarded.parsed.tls13_selected {
        client.write_all(&forwarded.raw_record).await?;
        return Err(HandshakeServerError::Tls13Required);
    }
    client.write_all(&forwarded.raw_record).await?;

    let context = transcript_hash(&first_client_record, &forwarded.raw_record);
    let session_keys = derive_server_keys_from_shared(&x25519_shared_secret, &context)?;
    session_keys.protect_secret_memory();

    Ok(AuthenticatedHandshake {
        client,
        fallback,
        client_hello,
        server_hello: forwarded.parsed,
        session_keys,
        server_public_key,
    })
}

pub async fn relay_fallback(
    client: TcpStream,
    fallback_addr: &str,
    first_client_record: Vec<u8>,
) -> Result<(), HandshakeServerError> {
    let mut fallback = connect_tcp_with_timeout(fallback_addr).await?;
    tune_tcp_stream(&fallback)?;
    fallback.write_all(&first_client_record).await?;
    relay_fallback_with_idle_timeout(client, fallback, FALLBACK_IDLE_TIMEOUT).await
}

async fn relay_fallback_with_idle_timeout(
    client: TcpStream,
    fallback: TcpStream,
    idle_timeout: Duration,
) -> Result<(), HandshakeServerError> {
    #[cfg(target_os = "linux")]
    {
        if crate::transport::tcp::kernel_splice_available() {
            tracing::debug!("using Linux splice(2) kernel relay for fallback TCP tunnel");
            return crate::transport::tcp::relay_kernel_splice_bidirectional_with_idle_timeout(
                client,
                fallback,
                idle_timeout,
            )
            .await
            .map_err(HandshakeServerError::Io);
        }
    }

    let (mut client_read, mut client_write) = client.into_split();
    let (mut fallback_read, mut fallback_write) = fallback.into_split();
    let fallback_buffer_len = relay_read_buffer_len(max_plaintext_len(0));
    let mut client_buf = vec![0_u8; fallback_buffer_len];
    let mut fallback_buf = vec![0_u8; fallback_buffer_len];
    let idle_sleep = sleep(idle_timeout);
    tokio::pin!(idle_sleep);
    let mut client_closed = false;
    let mut fallback_closed = false;

    loop {
        if client_closed && fallback_closed {
            break;
        }

        tokio::select! {
            _ = &mut idle_sleep => {
                break;
            }
            read = client_read.read(&mut client_buf), if !client_closed => {
                let n = read?;
                if n == 0 {
                    client_closed = true;
                    fallback_write.shutdown().await?;
                } else {
                    fallback_write.write_all(&client_buf[..n]).await?;
                    idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
            read = fallback_read.read(&mut fallback_buf), if !fallback_closed => {
                let n = read?;
                if n == 0 {
                    fallback_closed = true;
                    client_write.shutdown().await?;
                } else {
                    client_write.write_all(&fallback_buf[..n]).await?;
                    idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
        }
    }

    Ok(())
}

async fn read_forwarded_server_hello(
    fallback: &mut TcpStream,
) -> Result<ForwardedServerHello, HandshakeServerError> {
    let raw_record = read_first_record(fallback).await?;
    let parsed = parse_server_hello(&raw_record)?;
    Ok(ForwardedServerHello { raw_record, parsed })
}

async fn read_first_record(stream: &mut TcpStream) -> Result<Vec<u8>, HandshakeServerError> {
    timeout(HANDSHAKE_TIMEOUT, read_record(stream))
        .await
        .map_err(|_| HandshakeServerError::Timeout)?
        .map_err(HandshakeServerError::Io)
}

async fn read_first_client_record(
    stream: &mut TcpStream,
) -> Result<FirstClientRead, HandshakeServerError> {
    read_first_client_record_with_timeout(stream, HANDSHAKE_TIMEOUT).await
}

async fn read_first_client_record_with_timeout<R>(
    stream: &mut R,
    read_timeout: Duration,
) -> Result<FirstClientRead, HandshakeServerError>
where
    R: AsyncRead + Unpin,
{
    let deadline = Instant::now() + read_timeout;
    let mut header = [0_u8; TLS_HEADER_LEN];
    let mut header_pos = 0;
    while header_pos < TLS_HEADER_LEN {
        let read = read_before_deadline(stream, &mut header[header_pos..], deadline).await;
        match read {
            Ok(Some(0)) if header_pos == 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS record header ended early",
                )
                .into());
            }
            Ok(Some(0)) => {
                return Ok(FirstClientRead::FallbackPrefix(
                    header[..header_pos].to_vec(),
                ));
            }
            Ok(Some(n)) => header_pos += n,
            Ok(None) => {
                return Ok(FirstClientRead::FallbackPrefix(
                    header[..header_pos].to_vec(),
                ));
            }
            Err(err) => return Err(err.into()),
        }
    }

    let parsed = match parse_header(&header) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(FirstClientRead::FallbackPrefix(header.to_vec())),
    };

    let mut record = vec![0_u8; parsed.total_len];
    record[..TLS_HEADER_LEN].copy_from_slice(&header);
    let mut record_pos = TLS_HEADER_LEN;
    while record_pos < parsed.total_len {
        let read = read_before_deadline(stream, &mut record[record_pos..], deadline).await;
        match read {
            Ok(Some(0)) => {
                return Ok(FirstClientRead::FallbackPrefix(
                    record[..record_pos].to_vec(),
                ))
            }
            Ok(Some(n)) => record_pos += n,
            Ok(None) => {
                return Ok(FirstClientRead::FallbackPrefix(
                    record[..record_pos].to_vec(),
                ))
            }
            Err(err) => return Err(err.into()),
        }
    }

    Ok(FirstClientRead::Record(record))
}

async fn read_before_deadline<R>(
    stream: &mut R,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<Option<usize>, io::Error>
where
    R: AsyncRead + Unpin,
{
    match timeout_at(deadline, stream.read(buf)).await {
        Ok(read) => read.map(Some),
        Err(_) => Ok(None),
    }
}

async fn connect_tcp_with_timeout(addr: &str) -> Result<TcpStream, HandshakeServerError> {
    connect_future_with_timeout(connect_tuned_tcp_host(addr), HANDSHAKE_TIMEOUT).await
}

async fn connect_future_with_timeout<F>(
    connect: F,
    connect_timeout: Duration,
) -> Result<TcpStream, HandshakeServerError>
where
    F: Future<Output = io::Result<TcpStream>>,
{
    timeout(connect_timeout, connect)
        .await
        .map_err(|_| HandshakeServerError::OutboundConnectTimeout)?
        .map_err(HandshakeServerError::Io)
}

async fn run_authenticated_data_mode(
    handshake: AuthenticatedHandshake,
    fixed_data_target: Option<&str>,
    identity_secret_key: Arc<zeroize::Zeroizing<Vec<u8>>>,
    sandwich_secret: &[u8],
    traffic: TrafficConfig,
    mut pending_replay: Option<PendingReplayEntry>,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    handshake.session_keys.protect_secret_memory();
    let padding = PaddingProfile::from_config(traffic)?;
    let timing = TimingProfile::from_config(traffic);
    let cover = CoverTrafficProfile::from_config(traffic);
    let mut client_open = DataRecordCodec::new(
        AeadCodec::new(
            handshake.session_keys.client_key,
            handshake.session_keys.client_nonce,
        ),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let mut server_seal = DataRecordCodec::new(
        AeadCodec::new(
            handshake.session_keys.server_key,
            handshake.session_keys.server_nonce,
        ),
        padding,
        SERVER_TO_CLIENT_AAD,
    );
    client_open.protect_secret_memory();
    server_seal.protect_secret_memory();

    let (client_read, mut client_write) = handshake.client.into_split();
    let (fallback_read, mut fallback_write) = handshake.fallback.into_split();
    let mut client_records = TlsRecordReader::new(client_read);
    let mut fallback_records = TlsRecordReader::new(fallback_read);
    let mut client_record = Vec::new();
    let mut fallback_record = Vec::new();
    let mut client_camouflage_records_before_pq = 0usize;
    let mut client_camouflage_bytes_before_pq = 0usize;
    let mut fallback_records_before_pq = 0usize;
    let mut fallback_bytes_before_pq = 0usize;

    tracing::info!(
        cid,
        sni = %handshake.client_hello.sni,
        "authenticated pre-data mode started; waiting for client PQ rekey"
    );

    loop {
        tokio::select! {
            read = client_records.read_record_into(&mut client_record) => {
                match read {
                    Ok(()) => {}
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };
                log_record_read(
                    cid,
                    "client->server",
                    "server-predata-client-reader",
                    &client_record,
                );

                match client_open.open(&client_record) {
                    Ok(first_payload) => {
                        let pq_rekey = PqRekeyRequest::decode_ref(first_payload.as_slice())?;
                        let client_x25519_public = pq_rekey.client_x25519_public;
                        let client_mlkem_public_key = pq_rekey.client_mlkem_public_key.to_vec();
                        if !commit_pending_replay_entry(&mut pending_replay).await? {
                            tracing::warn!(cid, "closing on replayed ClientHello after data proof");
                            return Ok(());
                        }
                        let server_ephemeral = X25519KeyPair::generate();
                        crate::process_hardening::protect_secret_bytes(
                            "pq_rekey.server_x25519_private",
                            &server_ephemeral.private,
                        );
                        let x25519_ephemeral_shared = x25519_shared_secret(
                            &server_ephemeral.private,
                            &client_x25519_public,
                        );
                        let pq_encapsulation =
                            encapsulate_mlkem_blocking(client_mlkem_public_key).await?;
                        let key_exchange_payload = ServerKeyExchange {
                            server_x25519_public: server_ephemeral.public,
                            mlkem_ciphertext: pq_encapsulation.ciphertext,
                        }
                        .encode()?;
                        let pq_identity_binding =
                            identity::pq_rekey_binding(first_payload.as_slice(), &key_exchange_payload);
                        crate::process_hardening::protect_secret_bytes(
                            "pq_rekey.mlkem_shared_secret",
                            &pq_encapsulation.shared_secret,
                        );
                        let mut rng = StdRng::from_entropy();
                        let key_exchange_record =
                            server_seal.seal(&key_exchange_payload, &mut rng)?;
                        log_outer_write(
                            cid,
                            "server->client",
                            "server-key-exchange-writer",
                            key_exchange_payload.len(),
                            &key_exchange_record,
                        );
                        client_write.write_all(&key_exchange_record).await?;
                        tracing::info!(
                            cid,
                            client_camouflage_records_before_pq,
                            client_camouflage_bytes_before_pq,
                            fallback_records_before_pq,
                            fallback_bytes_before_pq,
                            key_exchange_record_len = key_exchange_record.len(),
                            "server key exchange record written"
                        );
                        let rekeyed_keys = apply_server_pq_rekey(
                            &mut client_open,
                            &mut server_seal,
                            &handshake.session_keys,
                            &x25519_ephemeral_shared,
                            &pq_encapsulation.shared_secret,
                            sandwich_secret,
                        )?;
                        rekeyed_keys.protect_secret_memory();
                        let identity_signature = sign_server_identity_blocking(
                            identity_secret_key,
                            rekeyed_keys.transcript_hash,
                            handshake.server_public_key,
                            pq_identity_binding,
                            rekeyed_keys.epoch,
                        )
                        .await?;
                        let identity_payload = ServerIdentityProof {
                            signature: identity_signature,
                        }
                        .encode()?;
                        let identity_chunk_plaintext =
                            server_identity_chunk_plaintext_len(&mut rng);
                        let identity_chunks =
                            ServerIdentityChunk::encode_all(&identity_payload, identity_chunk_plaintext)?;
                        write_server_identity_chunks(
                            &mut client_write,
                            &mut server_seal,
                            identity_chunks,
                            &mut rng,
                            timing,
                            cid,
                        )
                        .await?;

                        drop(fallback_write);
                        client_records.read_record_into(&mut client_record).await?;
                        log_record_read(
                            cid,
                            "client->server",
                            "server-connect-reader",
                            &client_record,
                        );
                        let first_payload_range =
                            client_open.open_in_place_payload_range(&mut client_record)?;
                        let first_payload = &mut client_record[first_payload_range];
                        tracing::info!(
                            cid,
                            client_camouflage_records_before_pq,
                            fallback_records_before_pq,
                            "ParallaX data mode switch confirmed"
                        );

                        if SpeedTestRequest::has_magic(first_payload) {
                            let request = SpeedTestRequest::decode(first_payload)?;
                            return run_authenticated_speed_test_mode(
                                client_records,
                                client_write,
                                client_open,
                                server_seal,
                                request,
                                max_plaintext_len(traffic.max_padding),
                                cid,
                            )
                            .await;
                        }

                        if MuxFrame::has_magic(first_payload) {
                            let first_frames = MuxFrame::decode_all(first_payload)?;
                            return run_authenticated_mux_data_mode(
                                client_records,
                                client_write,
                                client_open,
                                server_seal,
                                first_frames,
                                ServerMuxContext {
                                    fixed_data_target,
                                    timing,
                                    cover,
                                    chunk_size: max_plaintext_len(traffic.max_padding),
                                    cid,
                                },
                            )
                            .await;
                        }

                        let (target_addr, initial_payload) =
                            resolve_connect_target(first_payload, fixed_data_target)?;
                        let mut target =
                            connect_outbound_target(&target_addr, fixed_data_target.is_some())
                                .await?;
                        tune_tcp_stream(&target)?;
                        if !initial_payload.is_empty() {
                            target.write_all(initial_payload).await?;
                            initial_payload.zeroize();
                        }
                        let (target_read, target_write) = target.into_split();
                        return DataRelay {
                            client_records,
                            client_write,
                            target_read,
                            target_write,
                            client_open,
                            server_seal,
                            timing,
                            cover,
                            chunk_size: max_plaintext_len(traffic.max_padding),
                            cid,
                        }
                        .run()
                        .await;
                    }
                    Err(DataRecordError::Aead(_)) | Err(DataRecordError::NotApplicationData) => {
                        client_camouflage_records_before_pq += 1;
                        client_camouflage_bytes_before_pq += client_record.len();
                        if client_camouflage_records_before_pq == 1
                            || client_camouflage_records_before_pq == 8
                        {
                            tracing::info!(
                                cid,
                                client_camouflage_records_before_pq,
                                client_camouflage_bytes_before_pq,
                                record_len = client_record.len(),
                                "forwarding client camouflage record before ParallaX PQ rekey"
                            );
                        }
                        fallback_write.write_all(&client_record).await?;
                    }
                    Err(err) => return Err(HandshakeServerError::DataRecord(err)),
                }
            }
            read = fallback_records.read_record_into(&mut fallback_record),
                if fallback_records_before_pq < PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT => {
                match read {
                    Ok(()) => {}
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };
                log_record_read(
                    cid,
                    "fallback->server",
                    "server-predata-fallback-reader",
                    &fallback_record,
                );
                fallback_records_before_pq += 1;
                fallback_bytes_before_pq += fallback_record.len();
                if let Ok(header) = crate::tls::record::parse_header(&fallback_record) {
                    if fallback_records_before_pq == 1 {
                        tracing::info!(
                            cid,
                            direction = "fallback->client",
                            task_name = "server-camouflage-writer",
                            fallback_records_before_pq,
                            fallback_bytes_before_pq,
                            outer_tls_payload_len = header.payload_len,
                            tls_content_type = header.content_type,
                            "forwarding fallback camouflage record before ParallaX PQ rekey"
                        );
                    } else if fallback_records_before_pq == PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT {
                        tracing::warn!(
                            cid,
                            direction = "fallback->client",
                            task_name = "server-camouflage-writer",
                            fallback_records_before_pq,
                            fallback_bytes_before_pq,
                            outer_tls_payload_len = header.payload_len,
                            tls_content_type = header.content_type,
                            client_residual_budget = CLIENT_RESIDUAL_CAMOUFLAGE_RECORD_BUDGET,
                            pre_pq_forward_limit = PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT,
                            "pre-PQ fallback camouflage forward limit reached; pausing fallback \
                             reads until ParallaX PQ rekey"
                        );
                    }
                } else if fallback_records_before_pq == PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT {
                    tracing::warn!(
                        cid,
                        fallback_records_before_pq,
                        fallback_bytes_before_pq,
                        record_len = fallback_record.len(),
                        client_residual_budget = CLIENT_RESIDUAL_CAMOUFLAGE_RECORD_BUDGET,
                        pre_pq_forward_limit = PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT,
                        "pre-PQ fallback camouflage forward limit reached with unparsed TLS \
                         record; pausing fallback reads until ParallaX PQ rekey"
                    );
                }
                client_write.write_all(&fallback_record).await?;
            }
        }
    }
}

fn resolve_connect_target<'a>(
    first_payload: &'a mut [u8],
    fixed_data_target: Option<&str>,
) -> Result<(String, &'a mut [u8]), HandshakeServerError> {
    crate::process_hardening::exclude_from_core_dump(
        "connect_request.first_payload",
        first_payload,
    );
    match ConnectRequest::decode_ref(first_payload) {
        Ok(request) => {
            request.protect_plaintext_memory();
            let payload_len = request.initial_payload.len();
            let target = fixed_data_target
                .map(str::to_owned)
                .unwrap_or_else(|| request.target());
            let start = first_payload.len().saturating_sub(payload_len);
            let initial_payload = &mut first_payload[start..];
            crate::process_hardening::exclude_from_core_dump(
                "connect_request.initial_payload",
                initial_payload,
            );
            Ok((target, initial_payload))
        }
        Err(ConnectRequestError::BadMagic | ConnectRequestError::Truncated) => {
            let target = fixed_data_target.ok_or(HandshakeServerError::MissingConnectTarget)?;
            crate::process_hardening::exclude_from_core_dump(
                "connect_request.fixed_target_payload",
                first_payload,
            );
            Ok((target.to_owned(), first_payload))
        }
        Err(err) => Err(HandshakeServerError::ConnectRequest(err)),
    }
}

async fn connect_outbound_target(
    target_addr: &str,
    allow_private: bool,
) -> Result<TcpStream, HandshakeServerError> {
    if allow_private {
        return connect_tcp_with_timeout(target_addr).await;
    }

    let addrs = resolve_public_target_addrs(target_addr).await?;
    connect_future_with_timeout(connect_tuned_tcp_any(addrs.as_slice()), HANDSHAKE_TIMEOUT).await
}

async fn resolve_public_target_addrs(
    target_addr: &str,
) -> Result<Vec<SocketAddr>, HandshakeServerError> {
    let addrs: Vec<SocketAddr> = lookup_host(target_addr).await?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("client-selected target did not resolve: {target_addr}"),
        )
        .into());
    }
    validate_public_target_addrs(target_addr, &addrs)?;
    Ok(addrs)
}

fn validate_public_target_addrs(
    target_addr: &str,
    addrs: &[SocketAddr],
) -> Result<(), HandshakeServerError> {
    for addr in addrs {
        if is_denied_outbound_ip(addr.ip()) {
            return Err(HandshakeServerError::OutboundTargetDenied(format!(
                "{target_addr} resolved to {}",
                addr.ip()
            )));
        }
    }
    Ok(())
}

fn is_denied_outbound_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_denied_outbound_ipv4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_denied_outbound_ipv4(mapped);
            }
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || is_ipv6_unique_local(ip)
                || is_ipv6_unicast_link_local(ip)
                || is_ipv6_documentation(ip)
                || is_ipv6_teredo(ip)
                || is_ipv6_6to4(ip)
        }
    }
}

fn is_denied_outbound_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn is_ipv6_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn is_ipv6_teredo(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0
}

fn is_ipv6_6to4(ip: Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2002
}

async fn encapsulate_mlkem_blocking(
    client_mlkem_public_key: Vec<u8>,
) -> Result<pq::MlKemEncapsulation, HandshakeServerError> {
    Ok(tokio::task::spawn_blocking(move || pq::encapsulate(&client_mlkem_public_key)).await??)
}

async fn sign_server_identity_blocking(
    identity_secret_key: Arc<zeroize::Zeroizing<Vec<u8>>>,
    transcript_hash: [u8; 32],
    server_public_key: [u8; 32],
    pq_rekey_binding: [u8; 32],
    epoch: u64,
) -> Result<Vec<u8>, HandshakeServerError> {
    Ok(tokio::task::spawn_blocking(move || {
        identity::sign_server_identity(
            identity_secret_key.as_slice(),
            &transcript_hash,
            &server_public_key,
            &pq_rekey_binding,
            epoch,
        )
    })
    .await??)
}

async fn insert_replay_entry_blocking(
    replay_cache: Arc<Mutex<ReplayCache>>,
    entry: ReplayEntry,
) -> Result<bool, HandshakeServerError> {
    Ok(tokio::task::spawn_blocking(move || {
        let now = current_unix_timestamp()?;
        replay_cache
            .lock()
            .expect("replay cache poisoned")
            .insert_new(entry, now)
    })
    .await??)
}

async fn commit_pending_replay_entry(
    pending_replay: &mut Option<PendingReplayEntry>,
) -> Result<bool, HandshakeServerError> {
    let Some(pending) = pending_replay.take() else {
        return Ok(true);
    };
    insert_replay_entry_blocking(pending.cache, pending.entry).await
}

fn apply_server_pq_rekey(
    client_open: &mut DataRecordCodec,
    server_seal: &mut DataRecordCodec,
    keys: &SessionKeys,
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
    sandwich_secret: &[u8],
) -> Result<SessionKeys, HandshakeServerError> {
    let chain_secret = pq::hybrid_sandwich_rekey(
        &keys.chain_secret,
        x25519_shared_secret,
        pq_shared_secret,
        sandwich_secret,
    )?;
    let next_keys = expand_epoch_keys(
        chain_secret,
        keys.epoch + 1,
        keys.transcript_hash,
        *x25519_shared_secret,
    )?;
    next_keys.protect_secret_memory();
    client_open.rekey(next_keys.client_key, next_keys.client_nonce);
    server_seal.rekey(next_keys.server_key, next_keys.server_nonce);
    Ok(next_keys)
}

fn server_identity_chunk_delay<R>(timing: TimingProfile, rng: &mut R) -> Duration
where
    R: Rng + ?Sized,
{
    if timing.is_enabled() {
        SERVER_IDENTITY_CHUNK_MIN_DELAY + timing.sample_delay(rng)
    } else {
        Duration::ZERO
    }
}

fn server_identity_chunk_plaintext_len<R>(rng: &mut R) -> usize
where
    R: Rng + ?Sized,
{
    rng.gen_range(SERVER_IDENTITY_CHUNK_MIN_PLAINTEXT..=SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT)
}

async fn write_server_identity_chunks<W, R>(
    client_write: &mut W,
    server_seal: &mut DataRecordCodec,
    identity_chunks: Vec<Vec<u8>>,
    rng: &mut R,
    timing: TimingProfile,
    cid: u64,
) -> Result<(), HandshakeServerError>
where
    W: AsyncWrite + Unpin,
    R: Rng + rand::RngCore + ?Sized,
{
    if timing.is_enabled() {
        let identity_chunk_count = identity_chunks.len();
        for (idx, chunk) in identity_chunks.into_iter().enumerate() {
            let identity_record = server_seal.seal(&chunk, rng)?;
            log_outer_write(
                cid,
                "server->client",
                "server-identity-writer",
                chunk.len(),
                &identity_record,
            );
            client_write.write_all(&identity_record).await?;
            if idx + 1 < identity_chunk_count {
                let delay = server_identity_chunk_delay(timing, rng);
                if !delay.is_zero() {
                    sleep(delay).await;
                }
            }
        }
        return Ok(());
    }

    let capacity = identity_chunks
        .iter()
        .map(|chunk| server_seal.max_sealed_len(chunk.len()))
        .sum();
    let mut identity_records = Vec::with_capacity(capacity);
    for chunk in identity_chunks {
        let range = server_seal.seal_into(&chunk, rng, &mut identity_records)?;
        log_outer_write(
            cid,
            "server->client",
            "server-identity-writer",
            chunk.len(),
            &identity_records[range],
        );
    }
    client_write.write_all(&identity_records).await?;
    Ok(())
}

struct DataRelay {
    client_records: TlsRecordReader<OwnedReadHalf>,
    client_write: OwnedWriteHalf,
    target_read: OwnedReadHalf,
    target_write: OwnedWriteHalf,
    client_open: DataRecordCodec,
    server_seal: DataRecordCodec,
    timing: TimingProfile,
    cover: CoverTrafficProfile,
    chunk_size: usize,
    cid: u64,
}

#[derive(Clone, Copy)]
struct ServerMuxContext<'a> {
    fixed_data_target: Option<&'a str>,
    timing: TimingProfile,
    cover: CoverTrafficProfile,
    chunk_size: usize,
    cid: u64,
}

impl DataRelay {
    async fn run(self) -> Result<(), HandshakeServerError> {
        let DataRelay {
            client_records,
            client_write,
            target_read,
            target_write,
            client_open,
            server_seal,
            timing,
            cover,
            chunk_size,
            cid,
        } = self;
        let target_buf = vec![0_u8; relay_read_buffer_len(chunk_size)];
        let upload = server_upload_loop(client_records, target_write, client_open, cid);
        let download = server_download_loop(
            target_read,
            client_write,
            server_seal,
            target_buf,
            timing,
            cover,
            cid,
        );

        let ((), ()) = tokio::try_join!(upload, download)?;
        Ok(())
    }
}

async fn run_authenticated_mux_data_mode(
    client_records: TlsRecordReader<OwnedReadHalf>,
    client_write: OwnedWriteHalf,
    client_open: DataRecordCodec,
    server_seal: DataRecordCodec,
    first_frames: Vec<MuxFrame>,
    context: ServerMuxContext<'_>,
) -> Result<(), HandshakeServerError> {
    tracing::info!(cid = context.cid, "ParallaX mux data mode started");
    let (frame_tx, frame_rx) = mpsc::channel(SERVER_MUX_FRAME_CHANNEL);
    let reader =
        server_mux_client_reader_loop(client_records, client_open, frame_tx, first_frames, context);
    let writer = server_mux_writer_loop(
        client_write,
        server_seal,
        frame_rx,
        context.cover,
        context.cid,
    );
    let ((), ()) = tokio::try_join!(reader, writer)?;
    Ok(())
}

async fn server_mux_client_reader_loop(
    mut client_records: TlsRecordReader<OwnedReadHalf>,
    mut client_open: DataRecordCodec,
    frame_tx: mpsc::Sender<MuxFrame>,
    first_frames: Vec<MuxFrame>,
    context: ServerMuxContext<'_>,
) -> Result<(), HandshakeServerError> {
    let mut target_writes = HashMap::<u32, OwnedWriteHalf>::new();
    for frame in first_frames {
        process_server_mux_frame(
            MuxFrameRef {
                stream_id: frame.stream_id,
                kind: frame.kind,
                payload: &frame.payload,
            },
            &mut target_writes,
            &frame_tx,
            context,
        )
        .await?;
    }

    let mut client_record = Vec::new();
    loop {
        match client_records.read_record_into(&mut client_record).await {
            Ok(()) => {}
            Err(err) if is_clean_close(&err) => {
                for (_, mut target_write) in target_writes {
                    let _ = target_write.shutdown().await;
                }
                return Ok(());
            }
            Err(err) => return Err(HandshakeServerError::Io(err)),
        };
        log_record_read(
            context.cid,
            "client->server",
            "server-mux-client-reader",
            &client_record,
        );
        let payload = client_open.open_in_place_payload_range(&mut client_record)?;
        let mut frames = &client_record[payload];
        while !frames.is_empty() {
            let (frame, used) = MuxFrame::decode_ref_prefix(frames)?;
            process_server_mux_frame(frame, &mut target_writes, &frame_tx, context).await?;
            frames = &frames[used..];
        }
    }
}

async fn process_server_mux_frame(
    frame: MuxFrameRef<'_>,
    target_writes: &mut HashMap<u32, OwnedWriteHalf>,
    frame_tx: &mpsc::Sender<MuxFrame>,
    context: ServerMuxContext<'_>,
) -> Result<(), HandshakeServerError> {
    match frame.kind {
        MuxFrameKind::Open => {
            if target_writes.contains_key(&frame.stream_id) {
                send_server_mux_frame(frame_tx, frame.stream_id, MuxFrameKind::Reset, Vec::new())
                    .await?;
                return Ok(());
            }
            let mut payload = frame.payload.to_vec();
            let (target_addr, initial_payload) = {
                let (target_addr, initial_payload) =
                    resolve_connect_target(payload.as_mut_slice(), context.fixed_data_target)?;
                (target_addr, initial_payload.to_vec())
            };
            let mut target =
                connect_outbound_target(&target_addr, context.fixed_data_target.is_some()).await?;
            tune_tcp_stream(&target)?;
            if !initial_payload.is_empty() {
                target.write_all(&initial_payload).await?;
                let mut initial_payload = initial_payload;
                initial_payload.zeroize();
            }
            let (target_read, target_write) = target.into_split();
            target_writes.insert(frame.stream_id, target_write);
            let stream_id = frame.stream_id;
            let target_frame_tx = frame_tx.clone();
            tokio::spawn(async move {
                if let Err(err) = server_mux_target_reader_loop(
                    target_read,
                    target_frame_tx,
                    stream_id,
                    context.timing,
                    context.chunk_size,
                    context.cid,
                )
                .await
                {
                    tracing::debug!(
                        cid = context.cid,
                        stream_id,
                        error = %err,
                        "server mux target reader stopped"
                    );
                }
            });
        }
        MuxFrameKind::Data => {
            if let Some(target_write) = target_writes.get_mut(&frame.stream_id) {
                if !frame.payload.is_empty() {
                    target_write.write_all(&frame.payload).await?;
                }
            }
        }
        MuxFrameKind::Fin => {
            if let Some(mut target_write) = target_writes.remove(&frame.stream_id) {
                let _ = target_write.shutdown().await;
            }
        }
        MuxFrameKind::Reset => {
            if let Some(mut target_write) = target_writes.remove(&frame.stream_id) {
                let _ = target_write.shutdown().await;
            }
        }
        MuxFrameKind::Cover => {}
    }
    Ok(())
}

async fn server_mux_target_reader_loop(
    mut target_read: OwnedReadHalf,
    frame_tx: mpsc::Sender<MuxFrame>,
    stream_id: u32,
    timing: TimingProfile,
    chunk_size: usize,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    let max_payload_len = MuxFrame::max_payload_len(chunk_size);
    if max_payload_len == 0 {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0).into(),
        ));
    }
    let mut target_buf = vec![0_u8; relay_read_buffer_len(max_payload_len)];
    let mut rng = StdRng::from_entropy();

    loop {
        let n = target_read.read(&mut target_buf).await?;
        if n == 0 {
            send_server_mux_frame(&frame_tx, stream_id, MuxFrameKind::Fin, Vec::new()).await?;
            return Ok(());
        }
        let n = drain_ready_tcp_read(&target_read, &mut target_buf, n)?;
        let delay = timing.sample_delay(&mut rng);
        if !delay.is_zero() {
            sleep(delay).await;
        }
        for chunk in target_buf[..n].chunks(max_payload_len) {
            send_server_mux_frame(&frame_tx, stream_id, MuxFrameKind::Data, chunk.to_vec()).await?;
        }
        tracing::trace!(
            cid,
            stream_id,
            bytes = n,
            "queued server mux download payload"
        );
    }
}

async fn server_mux_writer_loop(
    mut client_write: OwnedWriteHalf,
    mut server_seal: DataRecordCodec,
    mut frame_rx: mpsc::Receiver<MuxFrame>,
    cover: CoverTrafficProfile,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    let mut seal_scratch = RelaySealScratch::with_payload_capacity(server_seal.max_plaintext_len());
    let mut mux_payload_buf = Vec::with_capacity(server_seal.max_plaintext_len());
    let mut rng = StdRng::from_entropy();
    let mut cover_sleep = Box::pin(sleep(cover.sample_interval(&mut rng)));

    loop {
        tokio::select! {
            _ = &mut cover_sleep, if cover.is_enabled() => {
                write_server_mux_frame(
                    &mut client_write,
                    &mut server_seal,
                    MuxFrame { stream_id: 0, kind: MuxFrameKind::Cover, payload: Vec::new() },
                    &mut rng,
                    &mut seal_scratch,
                    cid,
                    "server-mux-cover-writer",
                )
                .await?;
                cover_sleep.as_mut().reset(Instant::now() + cover.sample_interval(&mut rng));
            }
            frame = frame_rx.recv() => {
                let Some(frame) = frame else {
                    let _ = client_write.shutdown().await;
                    return Ok(());
                };
                write_server_mux_frames_batched(
                    &mut client_write,
                    &mut server_seal,
                    frame,
                    ServerMuxBatchState {
                        frame_rx: &mut frame_rx,
                        payload_buf: &mut mux_payload_buf,
                    },
                    &mut rng,
                    &mut seal_scratch,
                    RelayWriteLog::new(cid, "server->client", "server-mux-writer"),
                )
                .await?;
            }
        }
    }
}

async fn write_server_mux_frame<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    frame: MuxFrame,
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    cid: u64,
    task_name: &'static str,
) -> Result<(), HandshakeServerError>
where
    W: AsyncWrite + Unpin,
    R: Rng + rand::RngCore + ?Sized,
{
    let frame_payload = frame.encode()?;
    write_server_data_records_chunked(
        writer,
        codec,
        &frame_payload,
        rng,
        scratch,
        RelayWriteLog::new(cid, "server->client", task_name),
    )
    .await
}

struct ServerMuxBatchState<'a> {
    frame_rx: &'a mut mpsc::Receiver<MuxFrame>,
    payload_buf: &'a mut Vec<u8>,
}

async fn write_server_mux_frames_batched<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    first_frame: MuxFrame,
    batch: ServerMuxBatchState<'_>,
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    log: RelayWriteLog,
) -> Result<(), HandshakeServerError>
where
    W: AsyncWrite + Unpin,
    R: Rng + rand::RngCore + ?Sized,
{
    let max_plaintext_len = codec.max_plaintext_len();
    if max_plaintext_len == 0 {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0).into(),
        ));
    }

    batch.payload_buf.clear();
    append_server_mux_frame(batch.payload_buf, first_frame, max_plaintext_len)?;
    let mut drained = 0;
    while drained < SERVER_MUX_FRAME_BATCH_LIMIT {
        let frame = match batch.frame_rx.try_recv() {
            Ok(frame) => frame,
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        };
        let frame_len = MuxFrame::encoded_len(frame.payload.len())?;
        if !batch.payload_buf.is_empty() && batch.payload_buf.len() + frame_len > max_plaintext_len
        {
            write_server_data_records_chunked(
                writer,
                codec,
                batch.payload_buf.as_slice(),
                rng,
                scratch,
                log,
            )
            .await?;
            batch.payload_buf.clear();
        }
        append_server_mux_frame(batch.payload_buf, frame, max_plaintext_len)?;
        drained += 1;
    }

    if !batch.payload_buf.is_empty() {
        write_server_data_records_chunked(
            writer,
            codec,
            batch.payload_buf.as_slice(),
            rng,
            scratch,
            log,
        )
        .await?;
    }
    Ok(())
}

fn append_server_mux_frame(
    mux_payload_buf: &mut Vec<u8>,
    frame: MuxFrame,
    max_plaintext_len: usize,
) -> Result<(), HandshakeServerError> {
    let frame_len = MuxFrame::encoded_len(frame.payload.len())?;
    if frame_len > max_plaintext_len {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(frame_len).into(),
        ));
    }
    frame.encode_into(mux_payload_buf)?;
    Ok(())
}

async fn send_server_mux_frame(
    frame_tx: &mpsc::Sender<MuxFrame>,
    stream_id: u32,
    kind: MuxFrameKind,
    payload: Vec<u8>,
) -> Result<(), HandshakeServerError> {
    frame_tx
        .send(MuxFrame {
            stream_id,
            kind,
            payload,
        })
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()).into())
}

async fn run_authenticated_speed_test_mode(
    mut client_records: TlsRecordReader<OwnedReadHalf>,
    mut client_write: OwnedWriteHalf,
    mut client_open: DataRecordCodec,
    mut server_seal: DataRecordCodec,
    request: SpeedTestRequest,
    chunk_size: usize,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    tracing::info!(
        cid,
        warmup_bytes = request.warmup_bytes,
        download_bytes = request.download_bytes,
        upload_bytes = request.upload_bytes,
        sample_count = request.sample_count,
        "ParallaX speed test mode started"
    );
    if chunk_size == 0 {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0).into(),
        ));
    }

    let mut rng = StdRng::from_entropy();
    let mut scratch = RelaySealScratch::with_payload_capacity(chunk_size);
    let batch_len = relay_read_buffer_len(chunk_size);
    let payload = vec![0xA5; batch_len];
    let mut io = SpeedServerIo {
        client_records: &mut client_records,
        client_write: &mut client_write,
        client_open: &mut client_open,
        server_seal: &mut server_seal,
        rng: &mut rng,
        scratch: &mut scratch,
        cid,
    };

    write_speed_download_phase(
        &mut io,
        &payload,
        request.warmup_bytes,
        SpeedTestAck::warmup_download_done(request.warmup_bytes),
    )
    .await?;
    read_speed_upload_phase(
        &mut io,
        request.warmup_bytes,
        SpeedTestAck::warmup_upload_done(request.warmup_bytes),
    )
    .await?;

    for _ in 0..request.sample_count {
        write_speed_download_phase(
            &mut io,
            &payload,
            request.download_bytes,
            SpeedTestAck::download_done(request.download_bytes),
        )
        .await?;
    }
    for _ in 0..request.sample_count {
        read_speed_upload_phase(
            &mut io,
            request.upload_bytes,
            SpeedTestAck::upload_done(request.upload_bytes),
        )
        .await?;
    }

    tracing::info!(cid, "ParallaX speed test mode finished");
    Ok(())
}

struct SpeedServerIo<'a, R: ?Sized> {
    client_records: &'a mut TlsRecordReader<OwnedReadHalf>,
    client_write: &'a mut OwnedWriteHalf,
    client_open: &'a mut DataRecordCodec,
    server_seal: &'a mut DataRecordCodec,
    rng: &'a mut R,
    scratch: &'a mut RelaySealScratch,
    cid: u64,
}

async fn write_speed_download_phase<R>(
    io: &mut SpeedServerIo<'_, R>,
    payload: &[u8],
    bytes: u64,
    ack: SpeedTestAck,
) -> Result<(), HandshakeServerError>
where
    R: Rng + rand::RngCore + ?Sized,
{
    let mut remaining = bytes;
    while remaining > 0 {
        let len = remaining.min(payload.len() as u64) as usize;
        write_server_data_records_chunked(
            io.client_write,
            io.server_seal,
            &payload[..len],
            io.rng,
            io.scratch,
            RelayWriteLog::new(io.cid, "server->client", "server-speed-download-writer"),
        )
        .await?;
        remaining -= len as u64;
    }
    let ack = ack.encode();
    write_server_data_records_chunked(
        io.client_write,
        io.server_seal,
        &ack,
        io.rng,
        io.scratch,
        RelayWriteLog::new(io.cid, "server->client", "server-speed-download-done"),
    )
    .await
}

async fn read_speed_upload_phase<R>(
    io: &mut SpeedServerIo<'_, R>,
    bytes: u64,
    ack: SpeedTestAck,
) -> Result<(), HandshakeServerError>
where
    R: Rng + rand::RngCore + ?Sized,
{
    let mut uploaded = 0_u64;
    let mut client_record = Vec::new();
    while uploaded < bytes {
        match io.client_records.read_record_into(&mut client_record).await {
            Ok(()) => {}
            Err(err) if is_clean_close(&err) => return Ok(()),
            Err(err) => return Err(HandshakeServerError::Io(err)),
        };
        log_record_read(
            io.cid,
            "client->server",
            "server-speed-upload-reader",
            &client_record,
        );
        let plaintext = io
            .client_open
            .open_in_place_payload_range(&mut client_record)?;
        let len = plaintext.len() as u64;
        if len == 0 {
            continue;
        }
        if uploaded + len > bytes {
            return Err(HandshakeServerError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "speed upload sent more bytes than requested",
            )));
        }
        uploaded += len;
    }

    let ack = ack.encode();
    write_server_data_records_chunked(
        io.client_write,
        io.server_seal,
        &ack,
        io.rng,
        io.scratch,
        RelayWriteLog::new(io.cid, "server->client", "server-speed-upload-done"),
    )
    .await
}

async fn server_upload_loop(
    mut client_records: TlsRecordReader<OwnedReadHalf>,
    mut target_write: OwnedWriteHalf,
    mut client_open: DataRecordCodec,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    let mut client_record = Vec::new();

    loop {
        match client_records.read_record_into(&mut client_record).await {
            Ok(()) => {}
            Err(err) if is_clean_close(&err) => {
                let _ = target_write.shutdown().await;
                return Ok(());
            }
            Err(err) => return Err(HandshakeServerError::Io(err)),
        };
        log_record_read(
            cid,
            "client->server",
            "server-data-client-reader",
            &client_record,
        );
        match client_open.open_in_place_payload_range(&mut client_record) {
            Ok(plaintext) => {
                if !plaintext.is_empty() {
                    target_write.write_all(&client_record[plaintext]).await?;
                }
            }
            Err(err) => {
                return Err(HandshakeServerError::DataRecord(err));
            }
        }
    }
}

async fn server_download_loop(
    mut target_read: OwnedReadHalf,
    mut client_write: OwnedWriteHalf,
    mut server_seal: DataRecordCodec,
    mut target_buf: Vec<u8>,
    timing: TimingProfile,
    cover: CoverTrafficProfile,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    let mut seal_scratch = RelaySealScratch::with_payload_capacity(target_buf.len());
    let mut rng = StdRng::from_entropy();
    let mut cover_sleep = Box::pin(sleep(cover.sample_interval(&mut rng)));

    loop {
        tokio::select! {
            _ = &mut cover_sleep, if cover.is_enabled() => {
                write_server_data_records_chunked(
                    &mut client_write,
                    &mut server_seal,
                    &[],
                    &mut rng,
                    &mut seal_scratch,
                    RelayWriteLog::new(cid, "server->client", "server-cover-writer"),
                )
                .await?;
                cover_sleep.as_mut().reset(
                    Instant::now() + cover.sample_interval(&mut rng),
                );
            }
            read = target_read.read(&mut target_buf) => {
                let n = read?;
                if n == 0 {
                    let _ = client_write.shutdown().await;
                    return Ok(());
                }
                let n = drain_ready_tcp_read(&target_read, &mut target_buf, n)?;

                let delay = timing.sample_delay(&mut rng);
                if !delay.is_zero() {
                    sleep(delay).await;
                }

                write_server_data_records_chunked(
                    &mut client_write,
                    &mut server_seal,
                    &target_buf[..n],
                    &mut rng,
                    &mut seal_scratch,
                    RelayWriteLog::new(cid, "server->client", "server-download-writer"),
                )
                .await?;
            }
        }
    }
}

async fn write_server_data_records_chunked<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    payload: &[u8],
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    log: RelayWriteLog,
) -> Result<(), HandshakeServerError>
where
    W: AsyncWrite + Unpin,
    R: rand::Rng + rand::RngCore + ?Sized,
{
    let max_chunk_len = codec.max_plaintext_len();
    if max_chunk_len == 0 {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(payload.len()).into(),
        ));
    }
    scratch.records_buf.clear();
    let debug_records = tracing::enabled!(tracing::Level::DEBUG);
    if debug_records {
        codec.seal_chunks_into_reusing(
            payload,
            rng,
            &mut scratch.records_buf,
            &mut scratch.records,
        )?;
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
        codec.seal_chunks_into_untracked(payload, rng, &mut scratch.records_buf)?;
    }
    writer.write_all(scratch.records_buf.as_slice()).await?;
    Ok(())
}

struct RelaySealScratch {
    records_buf: Vec<u8>,
    records: Vec<SealedRecord>,
}

impl RelaySealScratch {
    fn with_payload_capacity(capacity: usize) -> Self {
        Self {
            records_buf: Vec::with_capacity(capacity + crate::tls::record::TLS_HEADER_LEN),
            records: Vec::new(),
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

fn is_authorized_sni(sni: &str, authorized_sni: &[String]) -> bool {
    authorized_sni
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(sni))
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use rand::{rngs::StdRng, SeedableRng};
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use super::*;
    use crate::{
        crypto::{
            auth::{
                build_auth_tail_at, build_masked_stateful_auth_session_id,
                build_masked_stateful_client_random, derive_client_auth_key,
                sign_client_hello_session_id,
            },
            pq,
            session::X25519KeyPair,
        },
        handshake::client::ClientDataSession,
        protocol::command::{ConnectRequest, ConnectRequestError},
        tls::{
            client_hello::tests::{
                client_hello_fixture_with_key_share, client_hello_fixture_with_random_and_key_share,
            },
            server_hello::{parse_server_hello, tests::server_hello_fixture},
        },
    };

    const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn outbound_connect_timeout_maps_to_server_timeout_error() {
        let err = connect_future_with_timeout(
            std::future::pending::<io::Result<TcpStream>>(),
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, HandshakeServerError::OutboundConnectTimeout));
    }

    #[tokio::test]
    async fn first_client_record_timeout_enters_fallback_without_close() {
        let (_client, mut server_side) = tokio::io::duplex(8);

        let read =
            read_first_client_record_with_timeout(&mut server_side, Duration::from_millis(1))
                .await
                .unwrap();

        assert_eq!(read, FirstClientRead::FallbackPrefix(Vec::new()));
    }

    #[tokio::test]
    async fn first_client_record_invalid_header_preserves_probe_prefix() {
        let (mut client, mut server_side) = tokio::io::duplex(8);
        client
            .write_all(&[0x16, 0x03, 0x03, 0xff, 0xff])
            .await
            .unwrap();

        let read =
            read_first_client_record_with_timeout(&mut server_side, Duration::from_millis(50))
                .await
                .unwrap();

        assert_eq!(
            read,
            FirstClientRead::FallbackPrefix(vec![0x16, 0x03, 0x03, 0xff, 0xff])
        );
    }

    #[tokio::test]
    async fn first_client_record_timeout_is_total_not_per_read() {
        let (mut client, mut server_side) = tokio::io::duplex(8);
        client.write_all(&[0x16]).await.unwrap();
        tokio::spawn(async move {
            sleep(Duration::from_millis(30)).await;
            let _ = client.write_all(&[0x03]).await;
            sleep(Duration::from_millis(30)).await;
            let _ = client.write_all(&[0x03]).await;
        });

        let started = Instant::now();
        let read =
            read_first_client_record_with_timeout(&mut server_side, Duration::from_millis(50))
                .await
                .unwrap();

        let FirstClientRead::FallbackPrefix(prefix) = read else {
            panic!("slow first record should fall back");
        };
        assert!(!prefix.is_empty());
        assert!(prefix.len() < TLS_HEADER_LEN);
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn pending_replay_entry_commits_once_after_data_proof() {
        let cache = Arc::new(Mutex::new(ReplayCache::new(8)));
        let entry = ReplayEntry {
            timestamp: current_unix_timestamp().unwrap(),
            nonce: [7; 8],
            transcript_fingerprint: [8; 32],
        };
        let mut first = Some(PendingReplayEntry {
            cache: Arc::clone(&cache),
            entry: entry.clone(),
        });
        let mut replayed = Some(PendingReplayEntry {
            cache: Arc::clone(&cache),
            entry,
        });

        assert!(commit_pending_replay_entry(&mut first).await.unwrap());
        assert!(first.is_none());
        assert!(!commit_pending_replay_entry(&mut replayed).await.unwrap());
        assert!(replayed.is_none());
    }

    #[test]
    fn identity_chunk_delay_is_zero_for_speed_first_traffic() {
        let timing = TimingProfile::from_config(TrafficConfig::default());
        let mut rng = StdRng::seed_from_u64(101);

        assert_eq!(
            server_identity_chunk_delay(timing, &mut rng),
            Duration::ZERO
        );
    }

    #[test]
    fn identity_chunk_delay_keeps_camouflage_floor_when_timing_enabled() {
        let timing = TimingProfile::from_config(TrafficConfig {
            min_delay_ms: 1,
            max_delay_ms: 1,
            ..TrafficConfig::default()
        });
        let mut rng = StdRng::seed_from_u64(102);

        assert_eq!(
            server_identity_chunk_delay(timing, &mut rng),
            SERVER_IDENTITY_CHUNK_MIN_DELAY + Duration::from_millis(1)
        );
    }

    #[test]
    fn identity_chunk_plaintext_len_jitters_without_timing_delay() {
        let mut rng = StdRng::seed_from_u64(104);
        let mut saw_different = false;
        let first = server_identity_chunk_plaintext_len(&mut rng);

        for _ in 0..64 {
            let len = server_identity_chunk_plaintext_len(&mut rng);
            assert!(
                (SERVER_IDENTITY_CHUNK_MIN_PLAINTEXT..=SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT)
                    .contains(&len)
            );
            saw_different |= len != first;
        }

        assert!(saw_different);
    }

    #[tokio::test]
    async fn speed_first_identity_writer_batches_chunks_into_one_write() {
        let traffic = TrafficConfig::default();
        let padding = PaddingProfile::from_config(traffic).unwrap();
        let timing = TimingProfile::from_config(traffic);
        let mut server_seal = DataRecordCodec::new(
            AeadCodec::new([3_u8; 32], [4_u8; 24]),
            padding,
            SERVER_TO_CLIENT_AAD,
        );
        let mut client_open = DataRecordCodec::new(
            AeadCodec::new([3_u8; 32], [4_u8; 24]),
            padding,
            SERVER_TO_CLIENT_AAD,
        );
        let payload = vec![0x42_u8; SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT * 2 + 1];
        let chunks =
            ServerIdentityChunk::encode_all(&payload, SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT).unwrap();
        let expected_chunks = chunks.clone();
        let mut rng = StdRng::seed_from_u64(103);
        let mut writer = CountingWriter::default();

        write_server_identity_chunks(&mut writer, &mut server_seal, chunks, &mut rng, timing, 7)
            .await
            .unwrap();

        assert_eq!(writer.writes, 1);
        let mut opened_chunks = Vec::new();
        let mut offset = 0;
        while offset < writer.bytes.len() {
            let header = crate::tls::record::parse_header(&writer.bytes[offset..]).unwrap();
            let end = offset + header.total_len;
            opened_chunks.push(client_open.open(&writer.bytes[offset..end]).unwrap());
            offset = end;
        }
        assert_eq!(opened_chunks, expected_chunks);
    }

    #[derive(Default)]
    struct CountingWriter {
        writes: usize,
        bytes: Vec<u8>,
    }

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn decides_authenticated_inbound() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let mut record = client_hello_fixture_with_key_share("example.com", &client.public);
        let mut rng = StdRng::seed_from_u64(1);
        sign_client_hello_session_id(&mut record, &auth_key, &mut rng).unwrap();

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        match decision {
            InboundDecision::Authenticated(hello) => {
                assert_eq!(hello.sni, "example.com");
                assert_eq!(hello.x25519_key_share, client.public);
            }
            other => panic!("unexpected decision: {other:?}"),
        }

        let decision = decide_connection_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();
        match decision {
            ConnectionDecision::Authenticated(authenticated) => {
                assert_eq!(
                    authenticated.x25519_shared_secret,
                    x25519_shared_secret(&server.private, &client.public)
                );
            }
            ConnectionDecision::Fallback(reason) => panic!("unexpected fallback: {reason:?}"),
        }
    }

    #[test]
    fn decides_masked_stateful_inbound() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let mut record = client_hello_fixture_with_random_and_key_share(
            "example.com",
            &client.public,
            &[0x44_u8; 32],
        );
        let parsed = parse_client_hello(&record).unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        let tail = build_auth_tail_at(1_700_000_001, &mut rng);
        let encoded_random =
            build_masked_stateful_client_random(PSK, "example.com", &client.public, &tail).unwrap();
        let session_id = build_masked_stateful_auth_session_id(
            PSK,
            &auth_key,
            "example.com",
            &client.public,
            &encoded_random,
            &tail,
        )
        .unwrap();
        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        record[random_offset..random_offset + 32].copy_from_slice(&encoded_random);
        record[parsed.session_id_range].copy_from_slice(&session_id);

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        match decision {
            InboundDecision::Authenticated(hello) => {
                assert_eq!(hello.sni, "example.com");
                assert_eq!(hello.x25519_key_share, client.public);
                assert_eq!(hello.timestamp, 1_700_000_001);
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn masked_stateful_without_tls13_support_falls_back() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let mut record = client_hello_fixture_with_random_and_key_share(
            "example.com",
            &client.public,
            &[0x44_u8; 32],
        );
        let parsed = parse_client_hello(&record).unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        let tail = build_auth_tail_at(1_700_000_001, &mut rng);
        let encoded_random =
            build_masked_stateful_client_random(PSK, "example.com", &client.public, &tail).unwrap();
        let session_id = build_masked_stateful_auth_session_id(
            PSK,
            &auth_key,
            "example.com",
            &client.public,
            &encoded_random,
            &tail,
        )
        .unwrap();
        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        record[random_offset..random_offset + 32].copy_from_slice(&encoded_random);
        record[parsed.session_id_range].copy_from_slice(&session_id);
        replace_tls13_supported_version_with_tls12(&mut record);

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::AuthFailed)
        );
    }

    #[test]
    fn falls_back_on_bad_auth() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let mut record = client_hello_fixture_with_key_share("example.com", &client.public);
        let mut rng = StdRng::seed_from_u64(1);
        sign_client_hello_session_id(&mut record, b"wrong-auth-key", &mut rng).unwrap();

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::AuthFailed)
        );
    }

    #[test]
    fn falls_back_on_unauthorized_sni() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let mut record = client_hello_fixture_with_key_share("example.com", &client.public);
        let mut rng = StdRng::seed_from_u64(1);
        sign_client_hello_session_id(&mut record, &auth_key, &mut rng).unwrap();

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("allowed.com")],
            &server.private,
        )
        .unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::UnauthorizedSni(String::from("example.com")))
        );
    }

    #[test]
    fn authorized_sni_matching_is_case_insensitive() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let mut record = client_hello_fixture_with_key_share("Example.COM", &client.public);
        let mut rng = StdRng::seed_from_u64(2);
        sign_client_hello_session_id(&mut record, &auth_key, &mut rng).unwrap();

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        match decision {
            InboundDecision::Authenticated(hello) => {
                assert_eq!(hello.sni, "Example.COM");
                assert_eq!(hello.x25519_key_share, client.public);
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn malformed_probe_falls_back_instead_of_closing() {
        let server = X25519KeyPair::generate();
        let decision = decide_inbound(
            b"not a TLS ClientHello",
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::AuthFailed)
        );
    }

    #[test]
    fn resolve_connect_target_decodes_explicit_request() {
        let request = ConnectRequest {
            host: "2001:db8::1".to_owned(),
            port: 443,
            initial_payload: b"hello".to_vec(),
        };

        let mut encoded = request.encode().unwrap();
        let (target, initial_payload) = resolve_connect_target(&mut encoded, None).unwrap();

        assert_eq!(target, "[2001:db8::1]:443");
        assert_eq!(initial_payload, b"hello");
    }

    #[test]
    fn resolve_connect_target_honors_fixed_target_for_connect_request() {
        let request = ConnectRequest {
            host: "2001:db8::1".to_owned(),
            port: 443,
            initial_payload: b"hello".to_vec(),
        };

        let mut encoded = request.encode().unwrap();
        let (target, initial_payload) =
            resolve_connect_target(&mut encoded, Some("target.example:443")).unwrap();

        assert_eq!(target, "target.example:443");
        assert_eq!(initial_payload, b"hello");
    }

    #[test]
    fn resolve_connect_target_uses_fixed_target_for_raw_payload() {
        let mut raw = *b"GET / HTTP/1.1\r\n\r\n";
        let (target, initial_payload) =
            resolve_connect_target(&mut raw, Some("target.example:443")).unwrap();

        assert_eq!(target, "target.example:443");
        assert_eq!(initial_payload, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn resolve_connect_target_requires_fixed_target_for_raw_payload() {
        let mut raw = *b"raw";
        assert!(matches!(
            resolve_connect_target(&mut raw, None).unwrap_err(),
            HandshakeServerError::MissingConnectTarget
        ));
    }

    #[test]
    fn resolve_connect_target_rejects_malformed_connect_request() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"PX1C");
        encoded.extend_from_slice(&0_u16.to_be_bytes());

        assert!(matches!(
            resolve_connect_target(&mut encoded, Some("target.example:443")).unwrap_err(),
            HandshakeServerError::ConnectRequest(ConnectRequestError::EmptyHost)
        ));
    }

    #[test]
    fn client_selected_egress_policy_denies_private_addresses() {
        let denied = [
            "127.0.0.1:80",
            "0.1.2.3:80",
            "10.0.0.1:80",
            "172.16.0.1:80",
            "192.168.0.1:80",
            "192.0.2.1:80",
            "198.18.0.1:80",
            "198.51.100.1:80",
            "203.0.113.1:80",
            "240.0.0.1:80",
            "169.254.169.254:80",
            "100.64.0.1:80",
            "[::1]:80",
            "[fc00::1]:80",
            "[fd00::1]:80",
            "[fe80::1]:80",
            "[febf::1]:80",
            "[2001:db8::1]:80",
            "[2001::1]:80",
            "[2002:c000:0201::1]:80",
        ];

        for target in denied {
            let addr: SocketAddr = target.parse().unwrap();
            assert!(
                validate_public_target_addrs(target, &[addr]).is_err(),
                "{target} should be denied"
            );
        }
    }

    #[test]
    fn client_selected_egress_policy_allows_public_addresses() {
        let allowed = [
            "93.184.216.34:443",
            "[2606:2800:220:1:248:1893:25c8:1946]:443",
        ];

        for target in allowed {
            let addr: SocketAddr = target.parse().unwrap();
            validate_public_target_addrs(target, &[addr]).unwrap();
        }
    }

    #[test]
    fn client_selected_egress_policy_rejects_any_denied_dns_result() {
        let addrs = [
            "93.184.216.34:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];

        assert!(matches!(
            validate_public_target_addrs("example.test:443", &addrs).unwrap_err(),
            HandshakeServerError::OutboundTargetDenied(_)
        ));
    }

    #[tokio::test]
    async fn fallback_relay_forwards_client_records_after_origin_flight() {
        let first_client_record = client_hello_fixture_with_key_share("example.com", &[0x22; 32]);
        let second_client_record = crate::tls::record::wrap_application_data(b"client-finished")
            .expect("test client record fits");
        let first_origin_record = crate::tls::record::wrap_application_data(b"server-flight")
            .expect("test origin record fits");
        let second_origin_record = crate::tls::record::wrap_application_data(b"origin-reply")
            .expect("test origin reply fits");

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let expected_first = first_client_record.clone();
        let expected_second = second_client_record.clone();
        let origin_first = first_origin_record.clone();
        let origin_second = second_origin_record.clone();
        let origin_task = tokio::spawn(async move {
            let (mut origin, _) = origin_listener.accept().await.unwrap();
            let relayed_first = read_record(&mut origin).await.unwrap();
            assert_eq!(relayed_first, expected_first);
            origin.write_all(&origin_first).await.unwrap();

            let relayed_second = read_record(&mut origin).await.unwrap();
            assert_eq!(relayed_second, expected_second);
            origin.write_all(&origin_second).await.unwrap();
        });

        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (server_side, _) = parallax_listener.accept().await.unwrap();
            relay_fallback(server_side, &origin_addr.to_string(), first_client_record)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let relayed_origin_first = read_record(&mut client).await.unwrap();
        assert_eq!(relayed_origin_first, first_origin_record);
        client.write_all(&second_client_record).await.unwrap();
        let relayed_origin_second = read_record(&mut client).await.unwrap();
        assert_eq!(relayed_origin_second, second_origin_record);
        drop(client);

        origin_task.await.unwrap();
        relay_task.await.unwrap();
    }

    #[tokio::test]
    async fn fallback_relay_idle_timeout_closes_empty_probe() {
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut origin, _) = origin_listener.accept().await.unwrap();
            let mut one = [0_u8; 1];
            origin.read(&mut one).await.unwrap()
        });

        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (server_side, _) = parallax_listener.accept().await.unwrap();
            let fallback = TcpStream::connect(origin_addr).await.unwrap();
            relay_fallback_with_idle_timeout(server_side, fallback, Duration::from_millis(30))
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let mut one = [0_u8; 1];
        let client_read = timeout(Duration::from_millis(500), client.read(&mut one))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(client_read, 0);
        assert_eq!(origin_task.await.unwrap(), 0);
        relay_task.await.unwrap();
    }

    #[tokio::test]
    async fn strict_tls13_rejection_relays_origin_server_hello_first() {
        let tls12_server_hello = server_hello_fixture_with_tls12_selected();
        let fallback_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback_listener.local_addr().unwrap();
        let expected_first_client_record =
            client_hello_fixture_with_key_share("example.com", &[0x22; 32]);
        let origin_record = tls12_server_hello.clone();
        let fallback_task = tokio::spawn(async move {
            let (mut origin, _) = fallback_listener.accept().await.unwrap();
            let relayed_first = read_record(&mut origin).await.unwrap();
            assert_eq!(relayed_first, expected_first_client_record);
            origin.write_all(&origin_record).await.unwrap();
        });

        let server_keys = X25519KeyPair::generate();
        let server_pq_keys = pq::keypair();
        let server_identity_keys = identity::keypair();
        let replay_cache_dir = tempfile::tempdir().unwrap();
        let config = authenticated_server_config(
            fallback_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
            replay_cache_dir.path().join("parallax-replay.cache"),
        );
        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let first_client_record = client_hello_fixture_with_key_share("example.com", &[0x22; 32]);
        let accepted = tokio::spawn(async move {
            let (server_side, _) = parallax_listener.accept().await.unwrap();
            accept_authenticated(
                server_side,
                &config,
                server_keys.public,
                [0_u8; 32],
                first_client_record,
                AuthenticatedHello {
                    sni: String::from("example.com"),
                    x25519_key_share: [0x22; 32],
                    timestamp: 1_700_000_001,
                    nonce: [7; 8],
                    transcript_fingerprint: [8; 32],
                },
            )
            .await
        });

        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let relayed = read_record(&mut client).await.unwrap();
        assert_eq!(relayed, tls12_server_hello);

        let err = accepted.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeServerError::Tls13Required));
        fallback_task.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn authenticated_connection_switches_to_data_mode() {
        let (fallback_addr, fallback_task) = spawn_server_hello_fallback().await;
        let (target_addr, target_task) = spawn_ping_pong_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_pq_keys = pq::keypair();
        let server_identity_keys = identity::keypair();
        let client_keys = X25519KeyPair::generate();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let traffic = TrafficConfig::default();
        let mut config = authenticated_server_config(
            fallback_addr,
            &server_keys,
            &server_pq_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        config.data_target = Some(target_addr.to_string());
        let (parallax_addr, server_task) = spawn_authenticated_server(config, traffic).await;
        let (mut client, mut data_session, mut rng) = open_authenticated_data_session(
            parallax_addr,
            &server_keys,
            &server_identity_keys.public,
            &client_keys,
            traffic,
        )
        .await;

        send_ping_connect(&mut client, &mut data_session, &mut rng, target_addr).await;

        drop(client);
        server_task.await.unwrap();
        target_task.await.unwrap();
        fallback_task.await.unwrap();
    }

    async fn spawn_server_hello_fallback() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _client_hello = read_record(&mut stream).await.unwrap();
            stream.write_all(&server_hello_fixture()).await.unwrap();

            let mut one = [0_u8; 1];
            let _ = timeout(Duration::from_millis(500), stream.read(&mut one)).await;
        });
        (addr, task)
    }

    async fn spawn_ping_pong_target() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut initial = [0_u8; 4];
            stream.read_exact(&mut initial).await.unwrap();
            assert_eq!(&initial, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        (addr, task)
    }

    fn authenticated_server_config(
        fallback_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_pq_keys: &pq::MlKemKeyPair,
        server_identity_keys: &identity::MlDsaKeyPair,
        replay_cache_path: std::path::PathBuf,
    ) -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: fallback_addr.to_string(),
            data_target: None,
            private_key: STANDARD.encode(server_keys.private),
            pq_secret_key: STANDARD.encode(&server_pq_keys.secret),
            identity_secret_key: STANDARD.encode(&server_identity_keys.secret),
            replay_cache_path,
            authorized_sni: vec![String::from("example.com")],
            strict_tls13: true,
        }
    }

    async fn spawn_authenticated_server(
        config: ServerConfig,
        traffic: TrafficConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, &config, traffic, PSK)
                .await
                .unwrap();
        });
        (addr, task)
    }

    async fn open_authenticated_data_session(
        parallax_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_identity_public_key: &[u8],
        client_keys: &X25519KeyPair,
        traffic: TrafficConfig,
    ) -> (TcpStream, ClientDataSession, StdRng) {
        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let mut client_hello =
            client_hello_fixture_with_key_share("example.com", &client_keys.public);
        let mut rng = StdRng::seed_from_u64(20);
        let auth_key =
            derive_client_auth_key(PSK, &client_keys.private, &server_keys.public).unwrap();
        sign_client_hello_session_id(&mut client_hello, &auth_key, &mut rng).unwrap();
        client.write_all(&client_hello).await.unwrap();

        let server_hello_record = read_record(&mut client).await.unwrap();
        let _server_hello = parse_server_hello(&server_hello_record).unwrap();
        let session_keys = crate::handshake::client::derive_session_keys(
            &client_keys.private,
            &server_keys.public,
            &client_hello,
            &server_hello_record,
        )
        .unwrap();
        let mut data_session = ClientDataSession::new(session_keys, traffic).unwrap();
        let (pq_record, pending_rekey) = data_session.build_pq_rekey_record(&mut rng).unwrap();
        client.write_all(&pq_record).await.unwrap();
        let key_exchange_record = read_record(&mut client).await.unwrap();
        data_session
            .apply_server_key_exchange_record(&key_exchange_record, &pending_rekey, PSK)
            .unwrap();
        let mut identity_payload = Vec::new();
        loop {
            let identity_record = read_record(&mut client).await.unwrap();
            let chunk = data_session
                .open_server_identity_chunk(&identity_record)
                .unwrap();
            assert_eq!(chunk.offset as usize, identity_payload.len());
            identity_payload.extend_from_slice(&chunk.bytes);
            if identity_payload.len() == chunk.total_len as usize {
                break;
            }
        }
        data_session
            .verify_server_identity_payload(
                &identity_payload,
                server_identity_public_key,
                &server_keys.public,
            )
            .unwrap();

        (client, data_session, rng)
    }

    fn replace_tls13_supported_version_with_tls12(record: &mut [u8]) {
        let needle = [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        let offset = record
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("ClientHello fixture carries supported_versions TLS 1.3");
        record[offset + needle.len() - 1] = 0x03;
        assert!(!parse_client_hello(record).unwrap().tls13_supported);
    }

    fn server_hello_fixture_with_tls12_selected() -> Vec<u8> {
        let mut record = server_hello_fixture();
        let needle = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        let offset = record
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("ServerHello fixture carries supported_versions TLS 1.3");
        record[offset + needle.len() - 1] = 0x03;
        assert!(!parse_server_hello(&record).unwrap().tls13_selected);
        record
    }

    async fn send_ping_connect(
        client: &mut TcpStream,
        data_session: &mut ClientDataSession,
        rng: &mut StdRng,
        target_addr: SocketAddr,
    ) {
        let connect = ConnectRequest {
            host: target_addr.ip().to_string(),
            port: target_addr.port(),
            initial_payload: b"ping".to_vec(),
        };
        let connect_record = data_session.build_connect_record(connect, rng).unwrap();
        client.write_all(&connect_record).await.unwrap();

        let response_record = read_record(client).await.unwrap();
        let response = data_session.open_server_record(&response_record).unwrap();
        assert_eq!(response, b"pong");
    }
}
