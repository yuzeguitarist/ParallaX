use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use quinn::{congestion, crypto::rustls::QuicClientConfig, Endpoint, VarInt};
use rand::{rngs::OsRng, RngCore};
use rcgen::generate_simple_self_signed;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    io::{copy, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::{
    client::initial_payload,
    client::socks,
    config::{
        decode_base64_bytes, decode_base64_secret, decode_key32, decode_key32_secret, decode_psk,
        ClientConfig, Config, ConfigError, Mode, ServerConfig,
    },
    crypto::{
        identity::{self, IdentityError},
        replay::{ReplayCache, ReplayCacheError, ReplayEntry},
        session::x25519_public_from_private,
    },
    protocol::command::{
        ConnectRequest, ConnectRequestError, ServerIdentityProof, ServerIdentityProofError,
    },
    transport::tcp::tune_tcp_stream,
};
use zeroize::Zeroizing;

const QUIC_ALPN: &[u8] = b"h3";
const QUIC_AUTH_MAGIC: &[u8; 4] = b"PX1U";
const QUIC_STREAM_OPEN_PREAMBLE: &[u8; 4] = b"PX1O";
const QUIC_AUTH_LABEL: &[u8] = b"ParallaX v1 QUIC stream auth";
const QUIC_AUTH_EXPORTER_LABEL: &[u8] = b"ParallaX v1 QUIC TLS exporter auth binding";
const QUIC_AUTH_KEY_LABEL: &[u8] = b"ParallaX v2 QUIC stream auth key";
const QUIC_AUTH_CONTEXT_LABEL: &[u8] = b"ParallaX v2 QUIC auth context";
const QUIC_STREAM_AUTH_CONTEXT_PAYLOAD: &[u8] = b"";
const QUIC_SERVER_IDENTITY_EXPORTER_LABEL: &[u8] = b"ParallaX v1 QUIC TLS exporter server identity";
const QUIC_SERVER_IDENTITY_CONTEXT: &[u8] = b"ParallaX v1 QUIC server identity context";
const QUIC_AUTH_NONCE_LEN: usize = 16;
const QUIC_AUTH_TAG_LEN: usize = 32;
const QUIC_AUTH_WINDOW_SECS: u64 = 90;
const MAX_AUTH_FRAME_LEN: usize = 512;
const MAX_SERVER_IDENTITY_FRAME_LEN: usize = 8192;
const MAX_CONNECT_FRAME_LEN: usize = 4096;
const QUIC_FLOW_WINDOW: u32 = 16 * 1024 * 1024;
const QUIC_BRUTAL_LIKE_INITIAL_WINDOW_PACKETS: u64 = 96;
const QUIC_KEEP_ALIVE_SECS: u64 = 15;
const QUIC_AUTH_TIMEOUT: Duration = Duration::from_secs(8);

type HmacSha256 = Hmac<Sha256>;
type SharedPsk = Arc<Zeroizing<Vec<u8>>>;

#[derive(Debug, Error)]
pub enum QuicRuntimeError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("client mode requires [client] config")]
    MissingClient,
    #[error("server mode requires [server] config")]
    MissingServer,
    #[error("QUIC client requires mode = \"client\"")]
    WrongClientMode,
    #[error("QUIC server requires mode = \"server\"")]
    WrongServerMode,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("SOCKS error: {0}")]
    Socks(#[from] socks::SocksError),
    #[error("QUIC connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC write error: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("QUIC stream already closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("QUIC read error: {0}")]
    Read(#[from] quinn::ReadError),
    #[error("QUIC read exact error: {0}")]
    ReadExact(#[from] quinn::ReadExactError),
    #[error("connect request error: {0}")]
    ConnectRequest(#[from] ConnectRequestError),
    #[error("QUIC server address did not resolve: {0}")]
    UnresolvedServer(String),
    #[error("server.authorized_sni must contain at least one SNI for QUIC")]
    MissingSni,
    #[error("TLS config error: {0}")]
    TlsConfig(String),
    #[error("connect frame is too large")]
    ConnectFrameTooLarge,
    #[error("connect frame length is invalid")]
    InvalidConnectFrameLength,
    #[error("QUIC auth frame is too large")]
    AuthFrameTooLarge,
    #[error("QUIC auth key derivation failed")]
    AuthKey,
    #[error("QUIC TLS exporter failed")]
    AuthExporter,
    #[error("QUIC auth frame is truncated")]
    AuthFrameTruncated,
    #[error("QUIC auth magic mismatch")]
    AuthBadMagic,
    #[error("QUIC stream open preamble mismatch")]
    StreamOpenPreambleMismatch,
    #[error("QUIC auth SNI is not allowed: {0}")]
    AuthSniNotAllowed(String),
    #[error("QUIC auth tag mismatch")]
    AuthTagMismatch,
    #[error("QUIC auth timestamp is outside the allowed window")]
    AuthStale,
    #[error("QUIC auth timed out")]
    AuthTimeout,
    #[error("QUIC auth replay detected")]
    AuthReplay,
    #[error("QUIC replay cache error: {0}")]
    ReplayCache(#[from] ReplayCacheError),
    #[error("QUIC server identity proof command error: {0}")]
    ServerIdentityProof(#[from] ServerIdentityProofError),
    #[error("QUIC server identity verification failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("QUIC server identity frame is too large")]
    ServerIdentityFrameTooLarge,
    #[error("QUIC server identity frame length is invalid")]
    InvalidServerIdentityFrameLength,
    #[error("system clock is before UNIX epoch")]
    AuthClock,
    #[error("blocking runtime task failed: {0}")]
    BlockingTask(#[from] tokio::task::JoinError),
}

pub async fn run_server(config: Config) -> Result<(), QuicRuntimeError> {
    if config.mode != Mode::Server {
        return Err(QuicRuntimeError::WrongServerMode);
    }
    let psk = Arc::new(decode_psk(&config.crypto.psk)?);
    let server = config.server.ok_or(QuicRuntimeError::MissingServer)?;
    let replay_cache = Arc::new(Mutex::new(ReplayCache::load_or_create_authenticated(
        &server.replay_cache_path,
        8192,
        psk.as_ref().as_slice(),
    )?));
    let endpoint = Endpoint::server(server_config(&server)?, server.listen)?;
    tracing::info!("ParallaX QUIC server listening on udp://{}", server.listen);

    while let Some(incoming) = endpoint.accept().await {
        let server = server.clone();
        let psk = Arc::clone(&psk);
        let replay_cache = Arc::clone(&replay_cache);
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = handle_connection(connection, server, psk, replay_cache).await
                    {
                        tracing::debug!(error = %err, "QUIC connection closed");
                    }
                }
                Err(err) => tracing::debug!(error = %err, "QUIC handshake failed"),
            }
        });
    }

    Ok(())
}

pub async fn run_client(config: Config) -> Result<(), QuicRuntimeError> {
    if config.mode != Mode::Client {
        return Err(QuicRuntimeError::WrongClientMode);
    }
    let psk = Arc::new(decode_psk(&config.crypto.psk)?);
    let client = config.client.ok_or(QuicRuntimeError::MissingClient)?;
    let server_addr = resolve_addr(&client.server_addr)?;
    let mut endpoint = Endpoint::client(bind_any_addr(server_addr))?;
    endpoint.set_default_client_config(client_config()?);
    let listener = TcpListener::bind(client.listen).await?;
    tracing::info!(
        "ParallaX QUIC client SOCKS5 listening on {} -> udp://{}",
        client.listen,
        server_addr
    );

    loop {
        let (local, peer) = listener.accept().await?;
        let endpoint = endpoint.clone();
        let client = client.clone();
        let psk = Arc::clone(&psk);
        tokio::spawn(async move {
            if let Err(err) =
                handle_local_connection(local, endpoint, server_addr, client, psk).await
            {
                tracing::debug!(%peer, error = %err, "QUIC client stream closed");
            }
        });
    }
}

async fn handle_connection(
    connection: quinn::Connection,
    server: ServerConfig,
    psk: SharedPsk,
    replay_cache: Arc<Mutex<ReplayCache>>,
) -> Result<(), QuicRuntimeError> {
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => return Ok(()),
            Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        let connection = connection.clone();
        let server = server.clone();
        let psk = Arc::clone(&psk);
        let replay_cache = Arc::clone(&replay_cache);
        tokio::spawn(async move {
            if let Err(err) = handle_stream(send, recv, connection, server, psk, replay_cache).await
            {
                tracing::debug!(error = %err, "QUIC stream closed");
            }
        });
    }
}

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    connection: quinn::Connection,
    server: ServerConfig,
    psk: SharedPsk,
    replay_cache: Arc<Mutex<ReplayCache>>,
) -> Result<(), QuicRuntimeError> {
    timeout(QUIC_AUTH_TIMEOUT, read_stream_open_preamble(&mut recv))
        .await
        .map_err(|_| QuicRuntimeError::AuthTimeout)??;
    let auth_frame = timeout(QUIC_AUTH_TIMEOUT, read_auth_frame(&mut recv))
        .await
        .map_err(|_| QuicRuntimeError::AuthTimeout)??;
    let (replay_entry, replay_now) = verify_auth_frame(
        &auth_frame,
        &connection,
        &psk,
        QUIC_STREAM_AUTH_CONTEXT_PAYLOAD,
        &server.authorized_sni,
    )?;
    insert_quic_replay_entry_blocking(replay_cache, replay_entry, replay_now).await?;
    write_server_identity_frame(&mut send, &connection, &server).await?;
    let connect_payload = timeout(
        QUIC_AUTH_TIMEOUT,
        read_len_prefixed(&mut recv, MAX_CONNECT_FRAME_LEN),
    )
    .await
    .map_err(|_| QuicRuntimeError::AuthTimeout)??;
    let request = ConnectRequest::decode(&connect_payload)?;
    let target_addr = server
        .data_target
        .clone()
        .unwrap_or_else(|| request.target());
    let mut target = TcpStream::connect(&target_addr).await?;
    tune_tcp_stream(&target)?;
    if !request.initial_payload.is_empty() {
        target.write_all(&request.initial_payload).await?;
    }

    let (mut target_read, mut target_write) = target.into_split();
    let upload = async {
        copy(&mut recv, &mut target_write)
            .await
            .map_err(QuicRuntimeError::Io)?;
        target_write
            .shutdown()
            .await
            .map_err(QuicRuntimeError::Io)?;
        Ok::<(), QuicRuntimeError>(())
    };
    let download = async {
        copy(&mut target_read, &mut send).await?;
        send.finish()?;
        Ok::<(), QuicRuntimeError>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn handle_local_connection(
    mut local: TcpStream,
    endpoint: Endpoint,
    server_addr: SocketAddr,
    client: ClientConfig,
    psk: SharedPsk,
) -> Result<(), QuicRuntimeError> {
    tune_tcp_stream(&local)?;
    let request = socks::accept_connect(&mut local).await?;
    let initial_payload_cap =
        ConnectRequest::max_initial_payload_len(&request.host, MAX_CONNECT_FRAME_LEN);
    let initial_payload =
        initial_payload::read_initial_payload(&mut local, initial_payload_cap).await?;
    let connection = connect_with_0rtt(&endpoint, server_addr, &client.sni).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_stream_open_preamble(&mut send).await?;
    write_quic_auth_frame(&mut send, &connection, &psk, &client.sni).await?;
    let connect = ConnectRequest {
        host: request.host,
        port: request.port,
        initial_payload,
    };
    read_and_verify_server_identity_frame(&mut recv, &connection, &client).await?;
    write_connect_request(&mut send, &connect).await?;

    let (mut local_read, mut local_write) = local.into_split();
    let upload = async {
        copy(&mut local_read, &mut send).await?;
        send.finish()?;
        Ok::<(), QuicRuntimeError>(())
    };
    let download = async {
        copy(&mut recv, &mut local_write)
            .await
            .map_err(QuicRuntimeError::Io)?;
        local_write.shutdown().await.map_err(QuicRuntimeError::Io)?;
        Ok::<(), QuicRuntimeError>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn connect_with_0rtt(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    sni: &str,
) -> Result<quinn::Connection, QuicRuntimeError> {
    let connecting = endpoint.connect(server_addr, sni)?;
    match connecting.into_0rtt() {
        Ok((connection, accepted)) => {
            tokio::spawn(async move {
                let accepted = accepted.await;
                tracing::debug!(accepted, "QUIC 0-RTT resumption result");
            });
            Ok(connection)
        }
        Err(connecting) => Ok(connecting.await?),
    }
}

async fn write_quic_auth_frame(
    send: &mut quinn::SendStream,
    connection: &quinn::Connection,
    psk: &[u8],
    sni: &str,
) -> Result<(), QuicRuntimeError> {
    let auth_key = derive_quic_auth_key(connection, psk, sni, QUIC_STREAM_AUTH_CONTEXT_PAYLOAD)?;
    let auth = build_auth_frame(&auth_key, sni, QUIC_STREAM_AUTH_CONTEXT_PAYLOAD)?;
    write_len_prefixed(send, &auth, MAX_AUTH_FRAME_LEN).await?;
    Ok(())
}

async fn write_connect_request(
    send: &mut quinn::SendStream,
    request: &ConnectRequest,
) -> Result<(), QuicRuntimeError> {
    let connect_payload = request.encode()?;
    if connect_payload.len() > MAX_CONNECT_FRAME_LEN {
        return Err(QuicRuntimeError::ConnectFrameTooLarge);
    }
    write_len_prefixed(send, &connect_payload, MAX_CONNECT_FRAME_LEN).await?;
    Ok(())
}

async fn read_auth_frame(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, QuicRuntimeError> {
    read_len_prefixed(recv, MAX_AUTH_FRAME_LEN).await
}

async fn write_server_identity_frame(
    send: &mut quinn::SendStream,
    connection: &quinn::Connection,
    server: &ServerConfig,
) -> Result<(), QuicRuntimeError> {
    let context = quic_server_identity_context(connection)?;
    let frame = build_server_identity_frame(server, &context)?;
    write_identity_len_prefixed(send, &frame).await
}

async fn write_stream_open_preamble(send: &mut quinn::SendStream) -> Result<(), QuicRuntimeError> {
    send.write_all(QUIC_STREAM_OPEN_PREAMBLE).await?;
    Ok(())
}

async fn read_stream_open_preamble(recv: &mut quinn::RecvStream) -> Result<(), QuicRuntimeError> {
    let mut preamble = [0_u8; QUIC_STREAM_OPEN_PREAMBLE.len()];
    recv.read_exact(&mut preamble).await?;
    if &preamble != QUIC_STREAM_OPEN_PREAMBLE {
        return Err(QuicRuntimeError::StreamOpenPreambleMismatch);
    }
    Ok(())
}

async fn read_and_verify_server_identity_frame(
    recv: &mut quinn::RecvStream,
    connection: &quinn::Connection,
    client: &ClientConfig,
) -> Result<(), QuicRuntimeError> {
    let frame = timeout(QUIC_AUTH_TIMEOUT, read_identity_len_prefixed(recv))
        .await
        .map_err(|_| QuicRuntimeError::AuthTimeout)??;
    let context = quic_server_identity_context(connection)?;
    verify_server_identity_frame(&frame, client, &context)
}

fn build_server_identity_frame(
    server: &ServerConfig,
    context: &[u8; 32],
) -> Result<Vec<u8>, QuicRuntimeError> {
    let server_private = decode_key32_secret("server.private_key", &server.private_key)?;
    let server_public = x25519_public_from_private(&server_private);
    let identity_secret =
        decode_base64_secret("server.identity_secret_key", &server.identity_secret_key)?;
    let signature =
        identity::sign_server_identity(identity_secret.as_slice(), context, &server_public, 0)?;
    Ok(ServerIdentityProof { signature }.encode()?)
}

fn verify_server_identity_frame(
    frame: &[u8],
    client: &ClientConfig,
    context: &[u8; 32],
) -> Result<(), QuicRuntimeError> {
    let proof = ServerIdentityProof::decode(frame)?;
    let server_identity_public = decode_base64_bytes(
        "client.server_identity_public_key",
        &client.server_identity_public_key,
    )?;
    let server_public = decode_key32("client.server_public_key", &client.server_public_key)?;
    identity::verify_server_identity(
        &server_identity_public,
        &proof.signature,
        context,
        &server_public,
        0,
    )?;
    Ok(())
}

async fn write_identity_len_prefixed(
    send: &mut quinn::SendStream,
    payload: &[u8],
) -> Result<(), QuicRuntimeError> {
    if payload.is_empty()
        || payload.len() > MAX_SERVER_IDENTITY_FRAME_LEN
        || payload.len() > u16::MAX as usize
    {
        return Err(QuicRuntimeError::ServerIdentityFrameTooLarge);
    }
    send.write_all(&(payload.len() as u16).to_be_bytes())
        .await?;
    send.write_all(payload).await?;
    Ok(())
}

async fn read_identity_len_prefixed(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<u8>, QuicRuntimeError> {
    let mut len = [0_u8; 2];
    recv.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_SERVER_IDENTITY_FRAME_LEN {
        return Err(QuicRuntimeError::InvalidServerIdentityFrameLength);
    }
    let mut payload = vec![0_u8; len];
    recv.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_len_prefixed(
    send: &mut quinn::SendStream,
    payload: &[u8],
    max_len: usize,
) -> Result<(), QuicRuntimeError> {
    if payload.is_empty() || payload.len() > max_len || payload.len() > u16::MAX as usize {
        return Err(QuicRuntimeError::InvalidConnectFrameLength);
    }
    send.write_all(&(payload.len() as u16).to_be_bytes())
        .await?;
    send.write_all(payload).await?;
    Ok(())
}

async fn read_len_prefixed(
    recv: &mut quinn::RecvStream,
    max_len: usize,
) -> Result<Vec<u8>, QuicRuntimeError> {
    let mut len = [0_u8; 2];
    recv.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 || len > max_len {
        return Err(QuicRuntimeError::InvalidConnectFrameLength);
    }
    let mut payload = vec![0_u8; len];
    recv.read_exact(&mut payload).await?;
    Ok(payload)
}

fn build_auth_frame(
    auth_key: &[u8; 32],
    sni: &str,
    connect_payload: &[u8],
) -> Result<Vec<u8>, QuicRuntimeError> {
    let unix_time = unix_time_secs()?;
    let mut nonce = [0_u8; QUIC_AUTH_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let tag = quic_auth_tag(auth_key, unix_time, &nonce, sni, connect_payload);

    let sni_bytes = sni.as_bytes();
    if sni_bytes.is_empty()
        || sni_bytes.len() > u16::MAX as usize
        || 4 + 8 + QUIC_AUTH_NONCE_LEN + 2 + sni_bytes.len() + QUIC_AUTH_TAG_LEN
            > MAX_AUTH_FRAME_LEN
    {
        return Err(QuicRuntimeError::AuthFrameTooLarge);
    }

    let mut out =
        Vec::with_capacity(4 + 8 + QUIC_AUTH_NONCE_LEN + 2 + sni_bytes.len() + QUIC_AUTH_TAG_LEN);
    out.extend_from_slice(QUIC_AUTH_MAGIC);
    out.extend_from_slice(&unix_time.to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(sni_bytes);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn verify_auth_frame(
    auth_frame: &[u8],
    connection: &quinn::Connection,
    psk: &[u8],
    connect_payload: &[u8],
    authorized_sni: &[String],
) -> Result<(ReplayEntry, u64), QuicRuntimeError> {
    let parsed = parse_auth_frame(auth_frame)?;
    let auth_key = derive_quic_auth_key(connection, psk, &parsed.sni, connect_payload)?;
    verified_auth_replay_entry(auth_frame, &auth_key, connect_payload, authorized_sni)
}

#[cfg(test)]
fn verify_auth_frame_with_key(
    auth_frame: &[u8],
    auth_key: &[u8; 32],
    connect_payload: &[u8],
    authorized_sni: &[String],
    replay_cache: &Mutex<ReplayCache>,
) -> Result<(), QuicRuntimeError> {
    let (replay_entry, now) =
        verified_auth_replay_entry(auth_frame, auth_key, connect_payload, authorized_sni)?;
    if !replay_cache
        .lock()
        .expect("QUIC replay cache poisoned")
        .insert_new(replay_entry, now)?
    {
        return Err(QuicRuntimeError::AuthReplay);
    }

    Ok(())
}

fn verified_auth_replay_entry(
    auth_frame: &[u8],
    auth_key: &[u8; 32],
    connect_payload: &[u8],
    authorized_sni: &[String],
) -> Result<(ReplayEntry, u64), QuicRuntimeError> {
    let parsed = parse_auth_frame(auth_frame)?;
    if !authorized_sni
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&parsed.sni))
    {
        return Err(QuicRuntimeError::AuthSniNotAllowed(parsed.sni));
    }

    let now = unix_time_secs()?;
    let age = now.abs_diff(parsed.unix_time);
    if age > QUIC_AUTH_WINDOW_SECS {
        return Err(QuicRuntimeError::AuthStale);
    }

    let expected = quic_auth_tag(
        auth_key,
        parsed.unix_time,
        &parsed.nonce,
        &parsed.sni,
        connect_payload,
    );
    if !bool::from(expected.ct_eq(&parsed.tag)) {
        return Err(QuicRuntimeError::AuthTagMismatch);
    }

    let fingerprint: [u8; 32] = Sha256::digest(auth_frame).into();
    let mut replay_nonce = [0_u8; 8];
    replay_nonce.copy_from_slice(&parsed.nonce[..8]);
    let replay_entry = ReplayEntry {
        timestamp: parsed.unix_time,
        nonce: replay_nonce,
        transcript_fingerprint: fingerprint,
    };
    Ok((replay_entry, now))
}

async fn insert_quic_replay_entry_blocking(
    replay_cache: Arc<Mutex<ReplayCache>>,
    replay_entry: ReplayEntry,
    now: u64,
) -> Result<(), QuicRuntimeError> {
    if tokio::task::spawn_blocking(move || {
        replay_cache
            .lock()
            .expect("QUIC replay cache poisoned")
            .insert_new(replay_entry, now)
    })
    .await??
    {
        Ok(())
    } else {
        Err(QuicRuntimeError::AuthReplay)
    }
}

fn derive_quic_auth_key(
    connection: &quinn::Connection,
    psk: &[u8],
    sni: &str,
    connect_payload: &[u8],
) -> Result<[u8; 32], QuicRuntimeError> {
    if psk.is_empty() {
        return Err(QuicRuntimeError::AuthKey);
    }
    let context = quic_auth_exporter_context(sni, connect_payload);
    let mut exporter = [0_u8; 32];
    connection
        .export_keying_material(&mut exporter, QUIC_AUTH_EXPORTER_LABEL, &context)
        .map_err(|_| QuicRuntimeError::AuthExporter)?;
    let hk = Hkdf::<Sha256>::new(Some(psk), &exporter);
    let mut out = [0_u8; 32];
    hk.expand(QUIC_AUTH_KEY_LABEL, &mut out)
        .map_err(|_| QuicRuntimeError::AuthKey)?;
    Ok(out)
}

fn quic_server_identity_context(
    connection: &quinn::Connection,
) -> Result<[u8; 32], QuicRuntimeError> {
    let mut exporter = [0_u8; 32];
    connection
        .export_keying_material(
            &mut exporter,
            QUIC_SERVER_IDENTITY_EXPORTER_LABEL,
            QUIC_SERVER_IDENTITY_CONTEXT,
        )
        .map_err(|_| QuicRuntimeError::AuthExporter)?;
    Ok(Sha256::digest(exporter).into())
}

fn quic_auth_exporter_context(sni: &str, connect_payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(QUIC_AUTH_CONTEXT_LABEL);
    hash.update((sni.len() as u16).to_be_bytes());
    hash.update(sni.as_bytes());
    hash.update((connect_payload.len() as u32).to_be_bytes());
    hash.update(connect_payload);
    hash.finalize().into()
}

fn parse_auth_frame(input: &[u8]) -> Result<ParsedQuicAuth, QuicRuntimeError> {
    let min_len = 4 + 8 + QUIC_AUTH_NONCE_LEN + 2 + QUIC_AUTH_TAG_LEN;
    if input.len() < min_len {
        return Err(QuicRuntimeError::AuthFrameTruncated);
    }
    if &input[..4] != QUIC_AUTH_MAGIC {
        return Err(QuicRuntimeError::AuthBadMagic);
    }

    let unix_time = u64::from_be_bytes(input[4..12].try_into().expect("fixed timestamp length"));
    let mut nonce = [0_u8; QUIC_AUTH_NONCE_LEN];
    nonce.copy_from_slice(&input[12..12 + QUIC_AUTH_NONCE_LEN]);
    let sni_len_offset = 12 + QUIC_AUTH_NONCE_LEN;
    let sni_len = u16::from_be_bytes([input[sni_len_offset], input[sni_len_offset + 1]]) as usize;
    let sni_start = sni_len_offset + 2;
    let sni_end = sni_start
        .checked_add(sni_len)
        .ok_or(QuicRuntimeError::AuthFrameTruncated)?;
    let tag_end = sni_end
        .checked_add(QUIC_AUTH_TAG_LEN)
        .ok_or(QuicRuntimeError::AuthFrameTruncated)?;
    if tag_end != input.len() {
        return Err(QuicRuntimeError::AuthFrameTruncated);
    }

    let sni = std::str::from_utf8(&input[sni_start..sni_end])
        .map_err(|_| QuicRuntimeError::AuthFrameTruncated)?
        .to_owned();
    let mut tag = [0_u8; QUIC_AUTH_TAG_LEN];
    tag.copy_from_slice(&input[sni_end..tag_end]);

    Ok(ParsedQuicAuth {
        unix_time,
        nonce,
        sni,
        tag,
    })
}

fn quic_auth_tag(
    auth_key: &[u8; 32],
    unix_time: u64,
    nonce: &[u8; QUIC_AUTH_NONCE_LEN],
    sni: &str,
    connect_payload: &[u8],
) -> [u8; QUIC_AUTH_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(QUIC_AUTH_LABEL);
    mac.update(&unix_time.to_be_bytes());
    mac.update(nonce);
    mac.update(&(sni.len() as u16).to_be_bytes());
    mac.update(sni.as_bytes());
    mac.update(&(connect_payload.len() as u32).to_be_bytes());
    mac.update(connect_payload);
    mac.finalize().into_bytes().into()
}

fn unix_time_secs() -> Result<u64, QuicRuntimeError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| QuicRuntimeError::AuthClock)?
        .as_secs())
}

struct ParsedQuicAuth {
    unix_time: u64,
    nonce: [u8; QUIC_AUTH_NONCE_LEN],
    sni: String,
    tag: [u8; QUIC_AUTH_TAG_LEN],
}

fn server_config(server: &ServerConfig) -> Result<quinn::ServerConfig, QuicRuntimeError> {
    let sni = server
        .authorized_sni
        .first()
        .ok_or(QuicRuntimeError::MissingSni)?;
    let certified = generate_simple_self_signed(vec![sni.clone()])
        .map_err(|err| QuicRuntimeError::TlsConfig(err.to_string()))?;
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));

    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|err| QuicRuntimeError::TlsConfig(err.to_string()))?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .map_err(|err| QuicRuntimeError::TlsConfig(err.to_string()))?;
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    tls.max_early_data_size = u32::MAX;

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls))
        .map_err(|err| QuicRuntimeError::TlsConfig(err.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport = Arc::new(tuned_transport_config());
    Ok(config)
}

fn client_config() -> Result<quinn::ClientConfig, QuicRuntimeError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|err| QuicRuntimeError::TlsConfig(err.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptQuicServerCert))
    .with_no_client_auth();
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    tls.enable_early_data = true;

    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|err| QuicRuntimeError::TlsConfig(err.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(tuned_transport_config()));
    Ok(config)
}

fn tuned_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    let mut bbr = congestion::BbrConfig::default();
    bbr.initial_window(QUIC_BRUTAL_LIKE_INITIAL_WINDOW_PACKETS * 1200);
    transport.congestion_controller_factory(Arc::new(bbr));
    transport.max_concurrent_bidi_streams(1_u8.into());
    transport.send_window(QUIC_FLOW_WINDOW as u64);
    transport.receive_window(VarInt::from_u32(QUIC_FLOW_WINDOW));
    transport.stream_receive_window(VarInt::from_u32(QUIC_FLOW_WINDOW));
    transport.keep_alive_interval(Some(Duration::from_secs(QUIC_KEEP_ALIVE_SECS)));
    transport
}

fn resolve_addr(server_addr: &str) -> Result<SocketAddr, QuicRuntimeError> {
    server_addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| QuicRuntimeError::UnresolvedServer(server_addr.to_owned()))
}

fn bind_any_addr(server_addr: SocketAddr) -> SocketAddr {
    if server_addr.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
    } else {
        "[::]:0".parse().expect("valid IPv6 wildcard")
    }
}

#[derive(Debug)]
struct AcceptQuicServerCert;

impl ServerCertVerifier for AcceptQuicServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::crypto::{identity, session::X25519KeyPair};

    const KEY32: [u8; 32] = [7_u8; 32];

    #[test]
    fn resolves_bind_addr_family() {
        assert_eq!(
            bind_any_addr("127.0.0.1:443".parse().unwrap()),
            "0.0.0.0:0".parse().unwrap()
        );
        assert_eq!(
            bind_any_addr("[::1]:443".parse().unwrap()),
            "[::]:0".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn connect_request_frame_round_trip() {
        let auth_key = [3_u8; 32];
        let request = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: Vec::new(),
        };
        let encoded = request.encode().unwrap();
        let auth = build_auth_frame(&auth_key, "example.com", &encoded).unwrap();
        let replay = Mutex::new(ReplayCache::new(8));

        assert!(encoded.len() <= MAX_CONNECT_FRAME_LEN);
        verify_auth_frame_with_key(
            &auth,
            &auth_key,
            &encoded,
            &[String::from("example.com")],
            &replay,
        )
        .unwrap();
        assert_eq!(ConnectRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn quic_auth_binds_connect_payload() {
        let auth_key = [4_u8; 32];
        let good = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: Vec::new(),
        }
        .encode()
        .unwrap();
        let bad = ConnectRequest {
            host: "blocked.example".to_owned(),
            port: 443,
            initial_payload: Vec::new(),
        }
        .encode()
        .unwrap();
        let auth = build_auth_frame(&auth_key, "example.com", &good).unwrap();
        let replay = Mutex::new(ReplayCache::new(8));

        assert!(matches!(
            verify_auth_frame_with_key(
                &auth,
                &auth_key,
                &bad,
                &[String::from("example.com")],
                &replay,
            ),
            Err(QuicRuntimeError::AuthTagMismatch)
        ));
    }

    #[test]
    fn quic_server_identity_frame_verifies_configured_identity() {
        let server_x25519 = X25519KeyPair::generate();
        let server_identity = identity::keypair();
        let context = [9_u8; 32];
        let server = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: "example.com:443".to_owned(),
            data_target: None,
            private_key: STANDARD.encode(server_x25519.private),
            pq_secret_key: STANDARD.encode(KEY32),
            identity_secret_key: STANDARD.encode(&server_identity.secret),
            replay_cache_path: "parallax-test.cache".into(),
            authorized_sni: vec!["example.com".to_owned()],
            strict_tls13: true,
        };
        let client = ClientConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            server_addr: "127.0.0.1:443".to_owned(),
            sni: "example.com".to_owned(),
            server_public_key: STANDARD.encode(server_x25519.public),
            server_pq_public_key: String::new(),
            server_identity_public_key: STANDARD.encode(&server_identity.public),
            tls_profile: crate::tls::client_hello_builder::BrowserProfile::Safari17,
        };

        let frame = build_server_identity_frame(&server, &context).unwrap();

        verify_server_identity_frame(&frame, &client, &context).unwrap();
    }

    #[test]
    fn quic_server_identity_frame_rejects_wrong_identity() {
        let server_x25519 = X25519KeyPair::generate();
        let server_identity = identity::keypair();
        let wrong_identity = identity::keypair();
        let context = [9_u8; 32];
        let server = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: "example.com:443".to_owned(),
            data_target: None,
            private_key: STANDARD.encode(server_x25519.private),
            pq_secret_key: STANDARD.encode(KEY32),
            identity_secret_key: STANDARD.encode(&server_identity.secret),
            replay_cache_path: "parallax-test.cache".into(),
            authorized_sni: vec!["example.com".to_owned()],
            strict_tls13: true,
        };
        let client = ClientConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            server_addr: "127.0.0.1:443".to_owned(),
            sni: "example.com".to_owned(),
            server_public_key: STANDARD.encode(server_x25519.public),
            server_pq_public_key: String::new(),
            server_identity_public_key: STANDARD.encode(&wrong_identity.public),
            tls_profile: crate::tls::client_hello_builder::BrowserProfile::Safari17,
        };

        let frame = build_server_identity_frame(&server, &context).unwrap();

        assert!(matches!(
            verify_server_identity_frame(&frame, &client, &context),
            Err(QuicRuntimeError::Identity(_))
        ));
    }

    #[tokio::test]
    #[ignore = "requires UDP loopback sockets"]
    async fn quic_server_identity_waits_for_authenticated_stream() {
        let server_identity = identity::keypair();
        let server = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: "example.com:443".to_owned(),
            data_target: None,
            private_key: STANDARD.encode(KEY32),
            pq_secret_key: STANDARD.encode(KEY32),
            identity_secret_key: STANDARD.encode(&server_identity.secret),
            replay_cache_path: "parallax-test.cache".into(),
            authorized_sni: vec!["example.com".to_owned()],
            strict_tls13: true,
        };
        let endpoint = Endpoint::server(server_config(&server).unwrap(), server.listen).unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let err = handle_stream(
                send,
                recv,
                connection,
                server,
                Arc::new(Zeroizing::new(b"0123456789abcdef0123456789abcdef".to_vec())),
                Arc::new(Mutex::new(ReplayCache::new(8))),
            )
            .await
            .expect_err("unauthenticated stream must not complete");
            assert!(matches!(
                err,
                QuicRuntimeError::ReadExact(_)
                    | QuicRuntimeError::Read(_)
                    | QuicRuntimeError::Connection(_)
                    | QuicRuntimeError::AuthTimeout
            ));
        });

        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config().unwrap());
        let connection = client_endpoint
            .connect(server_addr, "example.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_stream_open_preamble(&mut send).await.unwrap();

        assert!(
            timeout(
                Duration::from_millis(200),
                read_identity_len_prefixed(&mut recv)
            )
            .await
            .is_err(),
            "server identity must not be sent before a valid QUIC auth frame"
        );

        send.finish().unwrap();
        drop(recv);
        server_task.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires UDP and TCP loopback sockets"]
    async fn quic_stream_reaches_tcp_target() {
        let server_identity = identity::keypair();
        let server_public_key = crate::crypto::session::x25519_public_from_private(&KEY32);
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let server = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: "example.com:443".to_owned(),
            data_target: None,
            private_key: STANDARD.encode(KEY32),
            pq_secret_key: STANDARD.encode(KEY32),
            identity_secret_key: STANDARD.encode(&server_identity.secret),
            replay_cache_path: "parallax-test.cache".into(),
            authorized_sni: vec!["example.com".to_owned()],
            strict_tls13: true,
        };
        let endpoint = Endpoint::server(server_config(&server).unwrap(), server.listen).unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            handle_stream(
                send,
                recv,
                connection,
                server,
                Arc::new(Zeroizing::new(b"0123456789abcdef0123456789abcdef".to_vec())),
                Arc::new(Mutex::new(ReplayCache::new(8))),
            )
            .await
            .unwrap();
        });

        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config().unwrap());
        let connection = client_endpoint
            .connect(server_addr, "example.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_stream_open_preamble(&mut send).await.unwrap();
        write_quic_auth_frame(
            &mut send,
            &connection,
            b"0123456789abcdef0123456789abcdef",
            "example.com",
        )
        .await
        .unwrap();
        read_and_verify_server_identity_frame(
            &mut recv,
            &connection,
            &ClientConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                server_addr: server_addr.to_string(),
                sni: "example.com".to_owned(),
                server_public_key: STANDARD.encode(server_public_key),
                server_pq_public_key: String::new(),
                server_identity_public_key: STANDARD.encode(&server_identity.public),
                tls_profile: crate::tls::client_hello_builder::BrowserProfile::Safari17,
            },
        )
        .await
        .unwrap();
        write_connect_request(
            &mut send,
            &ConnectRequest {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
                initial_payload: b"ping".to_vec(),
            },
        )
        .await
        .unwrap();

        let mut response = [0_u8; 4];
        recv.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        drop(send);
        drop(recv);
        server_task.await.unwrap();
        target_task.await.unwrap();
    }
}
