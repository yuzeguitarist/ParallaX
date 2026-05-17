use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    time::{sleep, timeout, Instant},
};

use super::transcript::transcript_hash;

use crate::{
    config::{decode_key32, decode_psk, Config, ConfigError, Mode, ServerConfig, TrafficConfig},
    crypto::{
        auth::{derive_server_auth_key, verify_client_hello_auth, AuthError},
        identity::{self, IdentityError},
        pq::{self, PqError},
        replay::{current_unix_timestamp, ReplayCache, ReplayCacheError, ReplayEntry},
        session::{
            derive_server_keys, expand_epoch_keys, x25519_public_from_private, AeadCodec,
            SessionError, SessionKeys,
        },
    },
    protocol::{
        command::{
            ConnectRequest, ConnectRequestError, PqRekeyError, PqRekeyRequest, ServerIdentityProof,
            ServerIdentityProofError,
        },
        data::{
            max_plaintext_len, DataRecordCodec, DataRecordError, CLIENT_TO_SERVER_AAD,
            SERVER_TO_CLIENT_AAD,
        },
    },
    tls::{
        client_hello::parse_client_hello,
        record::{alert_bad_record_mac, read_record},
        server_hello::{parse_server_hello, ServerHello, ServerHelloError},
    },
    traffic::{CoverTrafficProfile, PaddingProfile, TimingProfile, TrafficError},
    transport::tcp::tune_tcp_stream,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

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
    #[error("PQ crypto error: {0}")]
    Pq(#[from] PqError),
    #[error("server identity proof command error: {0}")]
    ServerIdentityProof(#[from] ServerIdentityProofError),
    #[error("server identity signing failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("replay cache error: {0}")]
    ReplayCache(#[from] ReplayCacheError),
    #[error("missing encrypted connect request and no fixed server.data_target configured")]
    MissingConnectTarget,
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
    let psk = Arc::new(decode_psk(&config.crypto.psk)?.to_vec());
    let replay_cache = Arc::new(Mutex::new(ReplayCache::load_or_create(
        &server.replay_cache_path,
        8192,
    )?));
    let listener = TcpListener::bind(server.listen).await?;
    tracing::info!("ParallaX server listening on {}", server.listen);

    loop {
        let (client, peer) = listener.accept().await?;
        let server = server.clone();
        let connection_traffic = traffic;
        let psk = Arc::clone(&psk);
        let replay_cache = Arc::clone(&replay_cache);
        tokio::spawn(async move {
            if let Err(err) = handle_connection_with_replay(
                client,
                &server,
                connection_traffic,
                &psk,
                replay_cache,
            )
            .await
            {
                tracing::debug!(%peer, error = %err, "connection closed");
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
    handle_connection_inner(client, config, traffic, psk, None).await
}

async fn handle_connection_with_replay(
    client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    replay_cache: Arc<Mutex<ReplayCache>>,
) -> Result<(), HandshakeServerError> {
    handle_connection_inner(client, config, traffic, psk, Some(replay_cache)).await
}

async fn handle_connection_inner(
    mut client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    replay_cache: Option<Arc<Mutex<ReplayCache>>>,
) -> Result<(), HandshakeServerError> {
    tune_tcp_stream(&client)?;
    let server_private = decode_key32("server.private_key", &config.private_key)?;
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
                sni = %handshake.client_hello.sni,
                tls13 = handshake.server_hello.tls13_selected,
                "authenticated ParallaX handshake accepted"
            );
            let pq_secret =
                crate::config::decode_base64_bytes("server.pq_secret_key", &config.pq_secret_key)?;
            let identity_secret = crate::config::decode_base64_bytes(
                "server.identity_secret_key",
                &config.identity_secret_key,
            )?;
            run_authenticated_data_mode(
                handshake,
                config.data_target.as_deref(),
                &pq_secret,
                &identity_secret,
                psk,
                traffic,
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
    pq_secret_key: &[u8],
    identity_secret_key: &[u8],
    sandwich_secret: &[u8],
    traffic: TrafficConfig,
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

    let (mut client_read, mut client_write) = handshake.client.into_split();
    let (mut fallback_read, mut fallback_write) = handshake.fallback.into_split();

    loop {
        tokio::select! {
            record = read_record(&mut client_read) => {
                let record = match record {
                    Ok(record) => record,
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };

                match client_open.open(&record) {
                    Ok(first_payload) => {
                        let pq_rekey = PqRekeyRequest::decode(&first_payload)?;
                        let pq_shared_secret =
                            pq::decapsulate(&pq_rekey.ciphertext, pq_secret_key)?;
                        let rekeyed_keys = apply_server_pq_rekey(
                            &mut client_open,
                            &mut server_seal,
                            &handshake.session_keys,
                            &pq_shared_secret,
                            sandwich_secret,
                        )?;
                        let mut rng = StdRng::from_entropy();
                        let identity_signature = identity::sign_server_identity(
                            identity_secret_key,
                            &rekeyed_keys.transcript_hash,
                            &handshake.server_public_key,
                            rekeyed_keys.epoch,
                        )?;
                        let identity_payload = ServerIdentityProof {
                            signature: identity_signature,
                        }
                        .encode()?;
                        let identity_record = server_seal.seal(&identity_payload, &mut rng)?;
                        client_write.write_all(&identity_record).await?;

                        let record = read_record(&mut client_read).await?;
                        let first_payload = client_open.open(&record)?;
                        drop(fallback_read);
                        drop(fallback_write);
                        tracing::debug!("ParallaX data mode switch confirmed");

                        let (target_addr, initial_payload) =
                            resolve_connect_target(first_payload, fixed_data_target)?;
                        let mut target = TcpStream::connect(target_addr).await?;
                        tune_tcp_stream(&target)?;
                        if !initial_payload.is_empty() {
                            target.write_all(&initial_payload).await?;
                        }
                        let (target_read, target_write) = target.into_split();
                        return DataRelay {
                            client_read,
                            client_write,
                            target_read,
                            target_write,
                            client_open,
                            server_seal,
                            timing,
                            cover,
                            chunk_size: max_plaintext_len(traffic.max_padding),
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
            record = read_record(&mut fallback_read) => {
                let record = match record {
                    Ok(record) => record,
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };
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

fn apply_server_pq_rekey(
    client_open: &mut DataRecordCodec,
    server_seal: &mut DataRecordCodec,
    keys: &SessionKeys,
    shared_secret: &[u8; 32],
    sandwich_secret: &[u8],
) -> Result<SessionKeys, HandshakeServerError> {
    let chain_secret = pq::hybrid_sandwich_rekey(
        &keys.chain_secret,
        &keys.x25519_shared_secret,
        shared_secret,
        sandwich_secret,
    )?;
    let next_keys = expand_epoch_keys(
        chain_secret,
        keys.epoch + 1,
        keys.transcript_hash,
        keys.x25519_shared_secret,
    )?;
    client_open.rekey(next_keys.client_key, next_keys.client_nonce);
    server_seal.rekey(next_keys.server_key, next_keys.server_nonce);
    Ok(next_keys)
}

struct DataRelay {
    client_read: OwnedReadHalf,
    client_write: OwnedWriteHalf,
    target_read: OwnedReadHalf,
    target_write: OwnedWriteHalf,
    client_open: DataRecordCodec,
    server_seal: DataRecordCodec,
    timing: TimingProfile,
    cover: CoverTrafficProfile,
    chunk_size: usize,
}

impl DataRelay {
    async fn run(mut self) -> Result<(), HandshakeServerError> {
        let mut target_buf = vec![0_u8; self.chunk_size];
        let mut rng = StdRng::from_entropy();
        let mut cover_sleep = Box::pin(sleep(self.cover.sample_interval(&mut rng)));

        loop {
            tokio::select! {
                _ = &mut cover_sleep, if self.cover.is_enabled() => {
                    let record = self.server_seal.seal(&[], &mut rng)?;
                    self.client_write.write_all(&record).await?;
                    cover_sleep.as_mut().reset(
                        Instant::now() + self.cover.sample_interval(&mut rng),
                    );
                }
                record = read_record(&mut self.client_read) => {
                    let record = match record {
                        Ok(record) => record,
                        Err(err) if is_clean_close(&err) => return Ok(()),
                        Err(err) => return Err(HandshakeServerError::Io(err)),
                    };
                    match self.client_open.open(&record) {
                        Ok(payload) => {
                            if !payload.is_empty() {
                                self.target_write.write_all(&payload).await?;
                            }
                        }
                        Err(err) => {
                            let _ = self.client_write.write_all(&alert_bad_record_mac()).await;
                            return Err(HandshakeServerError::DataRecord(err));
                        }
                    }
                }
                read = self.target_read.read(&mut target_buf) => {
                    let n = read?;
                    if n == 0 {
                        return Ok(());
                    }

                    let delay = self.timing.sample_delay(&mut rng);
                    if !delay.is_zero() {
                        sleep(delay).await;
                    }

                    let record = self.server_seal.seal(&target_buf[..n], &mut rng)?;
                    self.client_write.write_all(&record).await?;
                }
            }
        }
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
        let pq_record = data_session
            .build_pq_rekey_record(&server_pq_keys.public, PSK, &mut rng)
            .unwrap();
        client.write_all(&pq_record).await.unwrap();
        let identity_record = read_record(&mut client).await.unwrap();
        data_session
            .verify_server_identity_record(
                &identity_record,
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
