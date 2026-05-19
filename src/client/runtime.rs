use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

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
    sync::{Mutex, Semaphore, TryAcquireError},
    time::{sleep, Instant},
};

use crate::{
    client::initial_payload,
    client::socks::{self, SocksError, SocksRequest},
    config::{
        decode_base64_bytes, decode_key32, decode_psk, ClientConfig, Config, ConfigError, Mode,
        TrafficConfig,
    },
    crypto::{auth::AuthError, identity, pq},
    handshake::client::{self, ClientDataSession, ClientHandshakeError, PendingPqRekey},
    protocol::command::{ConnectRequest, ServerIdentityChunk, ServerIdentityProof},
    protocol::data::{
        max_plaintext_len, relay_read_buffer_len, DataRecordCodec, DataRecordError, SealedRecord,
    },
    tls::{
        record::{log_record_read, read_record, TlsRecordError, TlsRecordReader},
        safari26::{Safari26TlsCamouflage, Safari26TlsError},
    },
    traffic::CoverTrafficProfile,
    transport::tcp::{
        drain_ready_tcp_read, is_fd_exhaustion_error, relay_connection_limit, tune_tcp_stream,
    },
};

const MAX_SERVER_IDENTITY_PAYLOAD: usize = 16 * 1024;
const MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE: usize = 16;

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
    #[error("blocking crypto task failed: {0}")]
    BlockingTask(#[from] tokio::task::JoinError),
}

pub async fn run(config: Config) -> Result<(), ClientRuntimeError> {
    if config.mode != Mode::Client {
        return Err(ClientRuntimeError::WrongMode);
    }

    let client = config
        .client
        .clone()
        .ok_or(ClientRuntimeError::MissingClient)?;
    let psk = decode_psk(&config.crypto.psk)?;
    crate::process_hardening::protect_secret_bytes("runtime.crypto.psk", psk.as_slice());
    let psk = Arc::new(psk);
    let server_public = decode_key32("client.server_public_key", &client.server_public_key)?;
    let server_identity_public = Arc::new(decode_base64_bytes(
        "client.server_identity_public_key",
        &client.server_identity_public_key,
    )?);
    let listener = TcpListener::bind(client.listen).await?;
    let server_addr = ServerAddrResolver::new(&client.server_addr).await?;
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
        let client = client.clone();
        let psk = Arc::clone(&psk);
        let server_identity_public = Arc::clone(&server_identity_public);
        let traffic = config.traffic;
        let server_addr = server_addr.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let context = ClientConnectionContext {
                config: &client,
                server_addr,
                traffic,
                psk: psk.as_ref().as_slice(),
                server_public: &server_public,
                server_identity_public: &server_identity_public,
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
    let context = ClientConnectionContext {
        config,
        server_addr,
        traffic,
        psk,
        server_public,
        server_identity_public,
    };
    handle_local_connection_with_cid(local, context, cid).await
}

struct ClientConnectionContext<'a> {
    config: &'a ClientConfig,
    server_addr: ServerAddrResolver,
    traffic: TrafficConfig,
    psk: &'a [u8],
    server_public: &'a [u8; 32],
    server_identity_public: &'a [u8],
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
    } = context;
    tune_tcp_stream(&local)?;
    tracing::debug!(
        cid,
        task_name = "client-connection",
        "accepted SOCKS connection"
    );
    let request = socks::accept_connect(&mut local).await?;
    let chunk_size = max_plaintext_len(traffic.max_padding);
    let initial_payload_cap = ConnectRequest::max_initial_payload_len(&request.host, chunk_size);
    // Keep the zero-RTT-style initial payload capture, but hide its small wait
    // behind the remote TCP/TLS setup instead of putting it on the critical path.
    let initial_payload_fut = async {
        initial_payload::read_initial_payload(&mut local, initial_payload_cap)
            .await
            .map_err(ClientRuntimeError::Io)
    };
    let server_session_fut =
        connect_and_establish_data_session(&server_addr, config, traffic, psk, server_public);
    let (initial_payload, (mut server, mut data_session)) =
        tokio::try_join!(initial_payload_fut, server_session_fut)?;
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
        match TcpStream::connect(cached).await {
            Ok(stream) => Ok(stream),
            Err(err) if self.literal => Err(err.into()),
            Err(first_err) => {
                let refreshed = resolve_client_server_addr(self.original.as_ref()).await?;
                *self.cached.lock().await = refreshed;
                if refreshed == cached {
                    return Err(first_err.into());
                }
                Ok(TcpStream::connect(refreshed).await?)
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
    let mut skipped = 0;
    loop {
        let record = read_record(server).await?;
        match apply_server_key_exchange_record_blocking(data_session, &record, pending_rekey, psk)
            .await
        {
            Ok(()) => return Ok(()),
            Err(ClientRuntimeError::Handshake(err)) if is_residual_camouflage_record(&err) => {
                if skipped < MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE {
                    skipped += 1;
                    // Loud-on-purpose: hitting this path at all means the
                    // camouflage host is racing ahead of the ParallaX server's
                    // key-exchange record. We still tolerate it up to the
                    // budget, but operators need to see it without bumping the
                    // global log level to trace.
                    tracing::debug!(
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
    record: &[u8],
    pending_rekey: &PendingPqRekey,
    psk: &[u8],
) -> Result<(), ClientRuntimeError> {
    let exchange = data_session.open_server_key_exchange_record(record)?;
    let x25519_shared = pending_rekey.x25519_shared_secret(&exchange.server_x25519_public);
    let ciphertext = exchange.mlkem_ciphertext;
    let secret_key = zeroize::Zeroizing::new(pending_rekey.mlkem_secret_key().to_vec());
    let pq_shared =
        tokio::task::spawn_blocking(move || pq::decapsulate(&ciphertext, secret_key.as_slice()))
            .await?
            .map_err(ClientHandshakeError::from)?;
    data_session.apply_pq_rekey_shared(&x25519_shared, &pq_shared, psk)?;
    Ok(())
}

async fn verify_server_identity_payload_blocking(
    data_session: &ClientDataSession,
    payload: Vec<u8>,
    server_identity_public_key: &[u8],
    server_x25519_public_key: &[u8; 32],
) -> Result<(), ClientRuntimeError> {
    let public_key = server_identity_public_key.to_vec();
    let transcript_hash = data_session.transcript_hash();
    let server_x25519_public_key = *server_x25519_public_key;
    let epoch = data_session.epoch();
    tokio::task::spawn_blocking(move || {
        let signature =
            ServerIdentityProof::signature(&payload).map_err(ClientHandshakeError::from)?;
        identity::verify_server_identity(
            &public_key,
            signature,
            &transcript_hash,
            &server_x25519_public_key,
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

        tokio::select! {
            result = upload => result,
            result = download => result,
        }
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
    let mut server_records = TlsRecordReader::new(server_read);
    let mut server_record = Vec::new();

    loop {
        match server_records.read_record_into(&mut server_record).await {
            Ok(()) => {}
            Err(err) if is_clean_close(&err) => return Ok(()),
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
            pq,
            session::{derive_client_keys, expand_epoch_keys, X25519KeyPair},
        },
        handshake::{client::data_codecs, server},
        protocol::command::{PqRekeyRequest, ServerKeyExchange},
        tls::record,
    };

    const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";
    const CAMOUFLAGE_CERT_DER_B64: &str = "MIIC9jCCAd6gAwIBAgIJAPNzR81y9p7pMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTI2MDUxNjEyNDA0NloXDTI2MDUxNzEyNDA0NlowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnjSfVPv1Xy5razuOYABOSvGvlddr0MMVWQCSmjE47PMQEzvETytmburNZEdqQBzSjDVxTExxd8eIHFTp8ylkztsxma5yJftQo81uqxZEnwT00tJRaazg10OYTf0ZrH6PMNC2izwJML0GkYz7s6OMFqImMCG3v00PIAYknlDrlKoDjdmANco8V5FNrbQYp2kqIcFyXrbgYurcMIKCE9Wu8L2W0oKhW6DNyRVoBGTn5zN1wjXLBO+6TJsBj4thI4tM0mUcLc+YohOfoGVq7na/wgCESoK1B+m8PdrXIEuZ7gZ0x3ZqdZ7jxL23sTmkfm+AeNdp+XshxAS77l3dcrAV9AgMBAAGjRzBFMBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4IBAQA8KHWHoA4otNmYh9q+X8cZnYx9y0LUNfdbHLR8ebnk/9T+/WP5CgIGWvn3+L2ulEvuSMhDC23C20SnX0h815JfMBY/PiAbLKGp3UXrgIq1dWc8t40HQBGRuBKi2fc743Sup5kPQgNAqev+8kKs4WFDXaWBpdwqI55PADVPOX66h0WiObB7crp5YTEVEe37G6UsxX40HUAAZJXtCI9eqPLISNuuNOAjJEMDMjdRH7ZjcMyrqQSweuKLAwdvUam8UJQsUNe7rM2II6GlgPS/mKZx1Nihn70GIo0yu0Bsxc9cpSHbggzQarE3g8WRp+jI9GpWXXdjno7cyim5KEQVMZcz";
    const CAMOUFLAGE_KEY_DER_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCnjSfVPv1Xy5razuOYABOSvGvlddr0MMVWQCSmjE47PMQEzvETytmburNZEdqQBzSjDVxTExxd8eIHFTp8ylkztsxma5yJftQo81uqxZEnwT00tJRaazg10OYTf0ZrH6PMNC2izwJML0GkYz7s6OMFqImMCG3v00PIAYknlDrlKoDjdmANco8V5FNrbQYp2kqIcFyXrbgYurcMIKCE9Wu8L2W0oKhW6DNyRVoBGTn5zN1wjXLBO+6TJsBj4thI4tM0mUcLc+YohOfoGVq7na/wgCESoK1B+m8PdrXIEuZ7gZ0x3ZqdZ7jxL23sTmkfm+AeNdp+XshxAS77l3dcrAV9AgMBAAECggEAcsH8cVMWRAbBBnLDcX1D6rHBGMVy9ONelaeTMrtQbcQ94ak3dz3tc3sZkbznvNQimjbxcDjbqgCctgs1JvmUxRXDw7aa3ZWPjIi51SpCND9nQ20XWyKqujldDCeVPJPMJXXrd+JfCX0ocYZEOBF+RIbdxpqTabqCZz+eCAy/les95pv5YkkAjxEJkzhEfFTJtJRVIjIUBL/Gg8KwG4qs5nESoD1oiNGr8tgnbsS2KNXdozIsM1awitqNJ7drpDpEpkwDUoQGAqzuvyDiN2pPqsyg1UwZWH8kuA9RyXIAOWQoR9rIX/rUsYB5F4tKg6Tdy0n9Jb9ytTINYaletNjuIQKBgQDSEzvmO4Zan1Bz+0Eb4NWfnU1yyGKb7bBFBvcuigXPW/+as1yET2Zkc4qQBudye7DUgr+zXj0s+ZeXvv+HeGggD3Blnq5bl+gPkiPSeGd24QkfO38MF2RTpW5SoUT6Z9vTiaHjIgkwZIgQf3dfSPV/MskRVemqxB5o+Phd4NRzpQKBgQDMLhkoYeRurmFQ3iuWCLOaHWAwtA28j3ymknsHyP6EOkiHBVl3YWTpZ1ZcDGMJznHdkSrj4mNsnnDM71iFM0srgKKp07T4bumowOhmyeg/hYIblFGSoZS/nTl8tAusNzXtRJeVLa9GjkFjXihiC3E+t3J2s9ij2eE8bAM0tatC+QKBgCsAQuea0aKlL8u955L0T+YPRfYz7HNskQNgLKK7H/tVIpohEtQGiLgRKpDWyPOXPBgT93eY177oDE7EivvI+s9tOZ2jgJ9BFgBx8qE3gj5ETCC3hgcMlr3EhDOnzT3Qmp/PcXLT2butKGjwHphDj/UMiTniMyWAZZUpOXXF+tb9AoGAEKvG5BQyGZNlYLvzJRnqyC+T1gYthPLWQ6d8IiOYHGXB3DxklKnAGoqUc4mTYI6Zn3Sl4ttuMMUzApicSqvofFHRdjpR8WLk8yFlGFdt/hnBiMzwaB+HTKnisrrkpRgQ8CGEmuqTABjHX/ylIXQ7t9o0n1qJ2r8Ec/GBxYD7zckCgYBZzU7u9Ujq8XL+Ok6T2Zqgf3O8H3VBlKPjeYpfH6mqBRdj+773IfoifCs19Y31OL8Sb28N98XnutTlHo6xs4li0zE2KDN1O3i00K7S0dO3250Fr1QSm86CML8fSDuS1BcuMHH+RNkQkMb9Q49K23t6B1s0xnIFfBarwbusw9onAw==";

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
        let fallback_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback_listener.local_addr().unwrap();
        let fallback_task = tokio::spawn(async move {
            let (stream, _) = fallback_listener.accept().await.unwrap();
            run_camouflage_tls_server(stream).await;
        });

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 64 * 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
            }
        });

        let server_keys = X25519KeyPair::generate();
        let server_pq_keys = pq::keypair();
        let server_identity_keys = crate::crypto::identity::keypair();
        let replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = replay_cache_dir.path().join("parallax-replay.cache");
        let server_config = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: fallback_addr.to_string(),
            data_target: None,
            private_key: STANDARD.encode(server_keys.private),
            pq_secret_key: STANDARD.encode(&server_pq_keys.secret),
            identity_secret_key: STANDARD.encode(&server_identity_keys.secret),
            replay_cache_path,
            authorized_sni: vec![String::from("example.com")],
            strict_tls13: true,
        };
        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = parallax_listener.accept().await.unwrap();
            server::handle_connection(stream, &server_config, TrafficConfig::default(), PSK)
                .await
                .unwrap();
        });

        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let client_config = ClientConfig {
            listen: local_addr,
            server_addr: parallax_addr.to_string(),
            sni: "example.com".to_owned(),
            server_public_key: STANDARD.encode(server_keys.public),
            server_pq_public_key: STANDARD.encode(&server_pq_keys.public),
            server_identity_public_key: STANDARD.encode(&server_identity_keys.public),
        };
        let client_task = tokio::spawn(async move {
            let (stream, _) = local_listener.accept().await.unwrap();
            handle_local_connection(
                stream,
                &client_config,
                TrafficConfig::default(),
                PSK,
                &server_keys.public,
                &server_identity_keys.public,
            )
            .await
            .unwrap();
        });

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
        timeout(Duration::from_secs(5), client_task)
            .await
            .expect("client task timed out")
            .unwrap();
        timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server task timed out")
            .unwrap();
        timeout(Duration::from_secs(5), target_task)
            .await
            .expect("target task timed out")
            .unwrap();
        timeout(Duration::from_secs(5), fallback_task)
            .await
            .expect("fallback task timed out")
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
