use std::{
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{Semaphore, TryAcquireError},
    time::{sleep, timeout, Instant},
};

use super::transcript::transcript_hash;

use crate::{
    config::{
        decode_base64_secret, decode_key32_secret, decode_psk, Config, ConfigError, Mode,
        ServerConfig, TrafficConfig,
    },
    crypto::{
        auth::{
            derive_server_auth_key, recover_stateful_auth_material, verify_client_hello_auth,
            verify_client_hello_auth_with_material, AuthError, ClientAuth,
        },
        identity::{self, IdentityError},
        pq::{self, PqError},
        replay::{current_unix_timestamp, ReplayCache, ReplayCacheError, ReplayEntry},
        session::{
            derive_server_keys, expand_epoch_keys, x25519_public_from_private,
            x25519_shared_secret, AeadCodec, SessionError, SessionKeys, X25519KeyPair,
        },
    },
    protocol::{
        command::{
            ConnectRequest, ConnectRequestError, PqRekeyError, PqRekeyRequest, ServerIdentityChunk,
            ServerIdentityChunkError, ServerIdentityProof, ServerIdentityProofError,
            ServerKeyExchange, ServerKeyExchangeError,
        },
        data::{
            max_plaintext_len, relay_read_buffer_len, DataRecordCodec, DataRecordError,
            SealedRecord, CLIENT_TO_SERVER_AAD, SERVER_TO_CLIENT_AAD,
        },
    },
    tls::{
        client_hello::parse_client_hello,
        record::{log_record_read, read_record, TlsRecordReader},
        server_hello::{parse_server_hello, ServerHello, ServerHelloError},
    },
    traffic::{CoverTrafficProfile, PaddingProfile, TimingProfile, TrafficError},
    transport::tcp::{
        drain_ready_tcp_read, is_fd_exhaustion_error, relay_connection_limit, tune_tcp_stream,
    },
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const SERVER_IDENTITY_CHUNK_PLAINTEXT: usize = 1180;
const SERVER_IDENTITY_CHUNK_MIN_DELAY: Duration = Duration::from_millis(45);

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

pub async fn run(config: Config) -> Result<(), HandshakeServerError> {
    if config.mode != Mode::Server {
        return Err(HandshakeServerError::WrongMode);
    }

    let server = config
        .server
        .clone()
        .ok_or(HandshakeServerError::MissingServer)?;
    let traffic = config.traffic;
    let psk = Arc::new(decode_psk(&config.crypto.psk)?);
    let replay_cache = Arc::new(Mutex::new(ReplayCache::load_or_create_authenticated(
        &server.replay_cache_path,
        8192,
        &psk,
    )?));
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
        let server = server.clone();
        let connection_traffic = traffic;
        let psk = Arc::clone(&psk);
        let replay_cache = Arc::clone(&replay_cache);
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(err) = handle_connection_with_replay(
                client,
                &server,
                connection_traffic,
                &psk,
                replay_cache,
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
    handle_connection_inner(client, config, traffic, psk, None, cid).await
}

async fn handle_connection_with_replay(
    client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    replay_cache: Arc<Mutex<ReplayCache>>,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    handle_connection_inner(client, config, traffic, psk, Some(replay_cache), cid).await
}

async fn handle_connection_inner(
    mut client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    replay_cache: Option<Arc<Mutex<ReplayCache>>>,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    tune_tcp_stream(&client)?;
    tracing::debug!(
        cid,
        task_name = "server-connection",
        "accepted outer connection"
    );
    let server_private = decode_key32_secret("server.private_key", &config.private_key)?;
    let first_record = read_first_record(&mut client).await?;
    match decide_inbound(&first_record, psk, &config.authorized_sni, &server_private)? {
        InboundDecision::Fallback(reason) => {
            tracing::debug!(?reason, "falling back to authenticated SNI target");
            relay_fallback(client, &config.fallback_addr, first_record).await?;
        }
        InboundDecision::Authenticated(client_hello) => {
            if let Some(replay_cache) = replay_cache {
                if !replay_cache
                    .lock()
                    .expect("replay cache poisoned")
                    .insert_new(
                        ReplayEntry {
                            timestamp: client_hello.timestamp,
                            nonce: client_hello.nonce,
                            transcript_fingerprint: client_hello.transcript_fingerprint,
                        },
                        current_unix_timestamp()?,
                    )?
                {
                    tracing::debug!("falling back on replayed ClientHello");
                    relay_fallback(client, &config.fallback_addr, first_record).await?;
                    return Ok(());
                }
            }
            let handshake =
                accept_authenticated(client, config, &server_private, first_record, client_hello)
                    .await?;
            tracing::debug!(
                cid,
                sni = %handshake.client_hello.sni,
                tls13 = handshake.server_hello.tls13_selected,
                "authenticated ParallaX handshake accepted"
            );
            let identity_secret =
                decode_base64_secret("server.identity_secret_key", &config.identity_secret_key)?;
            run_authenticated_data_mode(
                handshake,
                config.data_target.as_deref(),
                &identity_secret,
                psk,
                traffic,
                cid,
            )
            .await?;
        }
    }

    Ok(())
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
    let parsed = match parse_client_hello(first_client_record) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(InboundDecision::Fallback(FallbackReason::AuthFailed)),
    };
    if let Some(material) = recover_stateful_auth_material(first_client_record, psk)? {
        let x25519_key_share = material.x25519_public;
        let auth_key = derive_server_auth_key(psk, server_private, &x25519_key_share)?;
        let auth = match verify_client_hello_auth_with_material(
            first_client_record,
            &auth_key,
            Some(material),
        ) {
            Ok(auth) => auth,
            Err(err @ (AuthError::EmptyPsk | AuthError::Hkdf)) => return Err(err.into()),
            Err(_) => return Ok(InboundDecision::Fallback(FallbackReason::AuthFailed)),
        };
        if auth.authenticated {
            return authenticated_decision(
                first_client_record,
                auth,
                authorized_sni,
                x25519_key_share,
            );
        }
    }

    let x25519_key_share = parsed.client_random;
    let auth_key = derive_server_auth_key(psk, server_private, &x25519_key_share)?;
    let auth = match verify_client_hello_auth(first_client_record, &auth_key) {
        Ok(auth) => auth,
        Err(err @ (AuthError::EmptyPsk | AuthError::Hkdf)) => return Err(err.into()),
        Err(_) => return Ok(InboundDecision::Fallback(FallbackReason::AuthFailed)),
    };
    if !auth.authenticated {
        return Ok(InboundDecision::Fallback(FallbackReason::AuthFailed));
    }
    authenticated_decision(first_client_record, auth, authorized_sni, x25519_key_share)
}

fn authenticated_decision(
    first_client_record: &[u8],
    auth: ClientAuth,
    authorized_sni: &[String],
    x25519_key_share: [u8; 32],
) -> Result<InboundDecision, HandshakeServerError> {
    let timestamp = match auth.timestamp {
        Some(timestamp) => timestamp,
        None => return Ok(InboundDecision::Fallback(FallbackReason::AuthFailed)),
    };
    let nonce = match auth.nonce {
        Some(nonce) => nonce,
        None => return Ok(InboundDecision::Fallback(FallbackReason::AuthFailed)),
    };

    let sni = match auth.sni {
        Some(sni) => sni,
        None => return Ok(InboundDecision::Fallback(FallbackReason::MissingSni)),
    };

    if !is_authorized_sni(&sni, authorized_sni) {
        return Ok(InboundDecision::Fallback(FallbackReason::UnauthorizedSni(
            sni,
        )));
    }

    Ok(InboundDecision::Authenticated(AuthenticatedHello {
        sni,
        x25519_key_share,
        timestamp,
        nonce,
        transcript_fingerprint: client_hello_fingerprint(first_client_record),
    }))
}

pub async fn accept_authenticated(
    mut client: TcpStream,
    config: &ServerConfig,
    server_private: &[u8; 32],
    first_client_record: Vec<u8>,
    client_hello: AuthenticatedHello,
) -> Result<AuthenticatedHandshake, HandshakeServerError> {
    let mut fallback = TcpStream::connect(&config.fallback_addr).await?;
    tune_tcp_stream(&fallback)?;
    fallback.write_all(&first_client_record).await?;

    let forwarded = read_forwarded_server_hello(&mut fallback).await?;
    if config.strict_tls13 && !forwarded.parsed.tls13_selected {
        return Err(HandshakeServerError::Tls13Required);
    }
    client.write_all(&forwarded.raw_record).await?;

    let context = transcript_hash(&first_client_record, &forwarded.raw_record);
    let session_keys =
        derive_server_keys(server_private, &client_hello.x25519_key_share, &context)?;

    Ok(AuthenticatedHandshake {
        client,
        fallback,
        client_hello,
        server_hello: forwarded.parsed,
        session_keys,
        server_public_key: x25519_public_from_private(server_private),
    })
}

pub async fn relay_fallback(
    mut client: TcpStream,
    fallback_addr: &str,
    first_client_record: Vec<u8>,
) -> Result<(), HandshakeServerError> {
    let mut fallback = TcpStream::connect(fallback_addr).await?;
    tune_tcp_stream(&fallback)?;
    fallback.write_all(&first_client_record).await?;
    copy_bidirectional(&mut client, &mut fallback).await?;
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

async fn run_authenticated_data_mode(
    handshake: AuthenticatedHandshake,
    fixed_data_target: Option<&str>,
    identity_secret_key: &[u8],
    sandwich_secret: &[u8],
    traffic: TrafficConfig,
    cid: u64,
) -> Result<(), HandshakeServerError> {
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

    let (client_read, mut client_write) = handshake.client.into_split();
    let (fallback_read, mut fallback_write) = handshake.fallback.into_split();
    let mut client_records = TlsRecordReader::new(client_read);
    let mut fallback_records = TlsRecordReader::new(fallback_read);

    loop {
        tokio::select! {
            record = client_records.read_record() => {
                let record = match record {
                    Ok(record) => record,
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };
                log_record_read(cid, "client->server", "server-predata-client-reader", &record);

                match client_open.open(&record) {
                    Ok(first_payload) => {
                        let pq_rekey = PqRekeyRequest::decode(&first_payload)?;
                        let server_ephemeral = X25519KeyPair::generate();
                        let x25519_ephemeral_shared = x25519_shared_secret(
                            &server_ephemeral.private,
                            &pq_rekey.client_x25519_public,
                        );
                        let pq_encapsulation =
                            encapsulate_mlkem_blocking(pq_rekey.client_mlkem_public_key).await?;
                        let key_exchange_payload = ServerKeyExchange {
                            server_x25519_public: server_ephemeral.public,
                            mlkem_ciphertext: pq_encapsulation.ciphertext,
                        }
                        .encode()?;
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
                        let rekeyed_keys = apply_server_pq_rekey(
                            &mut client_open,
                            &mut server_seal,
                            &handshake.session_keys,
                            &x25519_ephemeral_shared,
                            &pq_encapsulation.shared_secret,
                            sandwich_secret,
                        )?;
                        let identity_signature = sign_server_identity_blocking(
                            identity_secret_key,
                            rekeyed_keys.transcript_hash,
                            handshake.server_public_key,
                            rekeyed_keys.epoch,
                        )
                        .await?;
                        let identity_payload = ServerIdentityProof {
                            signature: identity_signature,
                        }
                        .encode()?;
                        let identity_chunks = ServerIdentityChunk::encode_all(
                            &identity_payload,
                            SERVER_IDENTITY_CHUNK_PLAINTEXT,
                        )?;
                        let identity_chunk_count = identity_chunks.len();
                        for (idx, chunk) in identity_chunks.into_iter().enumerate() {
                            let identity_record = server_seal.seal(&chunk, &mut rng)?;
                            log_outer_write(
                                cid,
                                "server->client",
                                "server-identity-writer",
                                chunk.len(),
                                &identity_record,
                            );
                            client_write.write_all(&identity_record).await?;
                            if idx + 1 < identity_chunk_count {
                                sleep(
                                    SERVER_IDENTITY_CHUNK_MIN_DELAY
                                        + timing.sample_delay(&mut rng),
                                )
                                .await;
                            }
                        }

                        drop(fallback_write);
                        let record = client_records.read_record().await?;
                        log_record_read(cid, "client->server", "server-connect-reader", &record);
                        let first_payload = client_open.open_owned(record)?;
                        tracing::debug!(cid, "ParallaX data mode switch confirmed");

                        let (target_addr, initial_payload) =
                            resolve_connect_target(first_payload, fixed_data_target)?;
                        let mut target = TcpStream::connect(target_addr).await?;
                        tune_tcp_stream(&target)?;
                        if !initial_payload.is_empty() {
                            target.write_all(&initial_payload).await?;
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
                        fallback_write.write_all(&record).await?;
                    }
                    Err(err) => return Err(HandshakeServerError::DataRecord(err)),
                }
            }
            record = fallback_records.read_record() => {
                let record = match record {
                    Ok(record) => record,
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };
                log_record_read(cid, "fallback->server", "server-predata-fallback-reader", &record);
                if tracing::enabled!(tracing::Level::DEBUG) {
                    if let Ok(header) = crate::tls::record::parse_header(&record) {
                        tracing::debug!(
                            cid,
                            direction = "fallback->client",
                            task_name = "server-camouflage-writer",
                            outer_tls_payload_len = header.payload_len,
                            tls_content_type = header.content_type,
                            "camouflage TLS record write"
                        );
                    }
                }
                client_write.write_all(&record).await?;
            }
        }
    }
}

fn resolve_connect_target(
    first_payload: Vec<u8>,
    fixed_data_target: Option<&str>,
) -> Result<(String, Vec<u8>), HandshakeServerError> {
    match ConnectRequest::decode(&first_payload) {
        Ok(request) => Ok((request.target(), request.initial_payload)),
        Err(ConnectRequestError::BadMagic) => {
            let target = fixed_data_target.ok_or(HandshakeServerError::MissingConnectTarget)?;
            Ok((target.to_owned(), first_payload))
        }
        Err(err) => Err(HandshakeServerError::ConnectRequest(err)),
    }
}

async fn encapsulate_mlkem_blocking(
    client_mlkem_public_key: Vec<u8>,
) -> Result<pq::MlKemEncapsulation, HandshakeServerError> {
    Ok(tokio::task::spawn_blocking(move || pq::encapsulate(&client_mlkem_public_key)).await??)
}

async fn sign_server_identity_blocking(
    identity_secret_key: &[u8],
    transcript_hash: [u8; 32],
    server_public_key: [u8; 32],
    epoch: u64,
) -> Result<Vec<u8>, HandshakeServerError> {
    let identity_secret_key = zeroize::Zeroizing::new(identity_secret_key.to_vec());
    Ok(tokio::task::spawn_blocking(move || {
        identity::sign_server_identity(
            identity_secret_key.as_slice(),
            &transcript_hash,
            &server_public_key,
            epoch,
        )
    })
    .await??)
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
    client_open.rekey(next_keys.client_key, next_keys.client_nonce);
    server_seal.rekey(next_keys.server_key, next_keys.server_nonce);
    Ok(next_keys)
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

impl DataRelay {
    async fn run(self) -> Result<(), HandshakeServerError> {
        let DataRelay {
            mut client_records,
            mut client_write,
            mut target_read,
            mut target_write,
            mut client_open,
            mut server_seal,
            timing,
            cover,
            chunk_size,
            cid,
        } = self;
        let mut client_record = Vec::new();
        let upload = async move {
            loop {
                match client_records.read_record_into(&mut client_record).await {
                    Ok(()) => {}
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };
                log_record_read(
                    cid,
                    "client->server",
                    "server-data-client-reader",
                    &client_record,
                );
                client_open.open_in_place(&mut client_record)?;
                if !client_record.is_empty() {
                    target_write.write_all(&client_record).await?;
                }
            }
        };

        let mut target_buf = vec![0_u8; relay_read_buffer_len(chunk_size)];
        let mut seal_scratch = RelaySealScratch::with_payload_capacity(target_buf.len());
        let mut rng = StdRng::from_entropy();
        let mut cover_sleep = Box::pin(sleep(cover.sample_interval(&mut rng)));
        let download = async move {
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
                            return Ok(());
                        }

                        let delay = timing.sample_delay(&mut rng);
                        if !delay.is_zero() {
                            sleep(delay).await;
                        }
                        let n = drain_ready_tcp_read(&target_read, &mut target_buf, n)?;

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
        };

        tokio::select! {
            result = upload => result,
            result = download => result,
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
    codec.seal_chunks_into_reusing(payload, rng, &mut scratch.records_buf, &mut scratch.records)?;

    if tracing::enabled!(tracing::Level::DEBUG) {
        for record in scratch.records.iter() {
            log_outer_write(
                log.cid,
                log.direction,
                log.task_name,
                record.plaintext_len,
                &scratch.records_buf[record.range.clone()],
            );
        }
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
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use rand::{rngs::StdRng, SeedableRng};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        crypto::{
            auth::{derive_client_auth_key, sign_client_hello_session_id},
            pq,
            session::X25519KeyPair,
        },
        handshake::client::ClientDataSession,
        protocol::command::ConnectRequest,
        tls::{
            client_hello::tests::client_hello_fixture_with_key_share,
            server_hello::{parse_server_hello, tests::server_hello_fixture},
        },
    };

    const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

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

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn authenticated_connection_switches_to_data_mode() {
        let fallback_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback_listener.local_addr().unwrap();
        let fallback_task = tokio::spawn(async move {
            let (mut stream, _) = fallback_listener.accept().await.unwrap();
            let _client_hello = read_record(&mut stream).await.unwrap();
            stream.write_all(&server_hello_fixture()).await.unwrap();

            let mut one = [0_u8; 1];
            let _ = timeout(Duration::from_millis(500), stream.read(&mut one)).await;
        });

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut initial = [0_u8; 4];
            stream.read_exact(&mut initial).await.unwrap();
            assert_eq!(&initial, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let server_keys = X25519KeyPair::generate();
        let server_pq_keys = pq::keypair();
        let server_identity_keys = identity::keypair();
        let client_keys = X25519KeyPair::generate();
        let traffic = TrafficConfig::default();
        let config = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: fallback_addr.to_string(),
            data_target: None,
            private_key: STANDARD.encode(server_keys.private),
            pq_secret_key: STANDARD.encode(&server_pq_keys.secret),
            identity_secret_key: STANDARD.encode(&server_identity_keys.secret),
            replay_cache_path: "parallax-replay.cache".into(),
            authorized_sni: vec![String::from("example.com")],
            strict_tls13: true,
        };

        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = parallax_listener.accept().await.unwrap();
            handle_connection(stream, &config, traffic, PSK)
                .await
                .unwrap();
        });

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
                &server_identity_keys.public,
                &server_keys.public,
            )
            .unwrap();
        let connect = ConnectRequest {
            host: target_addr.ip().to_string(),
            port: target_addr.port(),
            initial_payload: b"ping".to_vec(),
        };
        let connect_record = data_session
            .build_connect_record(connect, &mut rng)
            .unwrap();
        client.write_all(&connect_record).await.unwrap();

        let response_record = read_record(&mut client).await.unwrap();
        let response = data_session.open_server_record(&response_record).unwrap();
        assert_eq!(response, b"pong");

        drop(client);
        server_task.await.unwrap();
        target_task.await.unwrap();
        fallback_task.await.unwrap();
    }
}
