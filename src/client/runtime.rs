use std::{io, sync::Arc};

use rand::rngs::OsRng;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
};

use crate::{
    client::socks::{self, SocksError, SocksRequest},
    config::{decode_key32, decode_psk, ClientConfig, Config, ConfigError, Mode, TrafficConfig},
    crypto::{
        auth::{derive_client_auth_key, AuthError},
        session::X25519KeyPair,
    },
    handshake::client::{self, ClientDataSession, ClientHandshakeError},
    protocol::command::ConnectRequest,
    tls::{
        client_hello_builder::{ClientHelloBuildError, ClientHelloTemplate},
        record::{change_cipher_spec, read_record, TlsRecordError},
        server_hello::{parse_server_hello, ServerHelloError},
    },
};

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
    #[error("ClientHello build error: {0}")]
    ClientHelloBuild(#[from] ClientHelloBuildError),
    #[error("ClientHello auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("ServerHello parse failed: {0}")]
    ServerHello(#[from] ServerHelloError),
    #[error("server did not negotiate TLS 1.3")]
    Tls13Required,
    #[error("client handshake error: {0}")]
    Handshake(#[from] ClientHandshakeError),
    #[error("TLS record error: {0}")]
    TlsRecord(#[from] TlsRecordError),
}

pub async fn run(config: Config) -> Result<(), ClientRuntimeError> {
    if config.mode != Mode::Client {
        return Err(ClientRuntimeError::WrongMode);
    }

    let client = config
        .client
        .clone()
        .ok_or(ClientRuntimeError::MissingClient)?;
    let psk = Arc::new(decode_psk(&config.crypto.psk)?.to_vec());
    let server_public = decode_key32("client.server_public_key", &client.server_public_key)?;
    let listener = TcpListener::bind(client.listen).await?;
    tracing::info!("ParallaX client SOCKS5 listening on {}", client.listen);

    loop {
        let (local, peer) = listener.accept().await?;
        let client = client.clone();
        let psk = Arc::clone(&psk);
        let traffic = config.traffic;
        tokio::spawn(async move {
            if let Err(err) =
                handle_local_connection(local, &client, traffic, &psk, &server_public).await
            {
                tracing::debug!(%peer, error = %err, "client connection closed");
            }
        });
    }
}

pub async fn handle_local_connection(
    mut local: TcpStream,
    config: &ClientConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    server_public: &[u8; 32],
) -> Result<(), ClientRuntimeError> {
    local.set_nodelay(true)?;
    let request = socks::accept_connect(&mut local).await?;
    let mut server = TcpStream::connect(&config.server_addr).await?;
    server.set_nodelay(true)?;

    let mut data_session =
        establish_data_session(&mut server, config, traffic, psk, server_public).await?;
    let connect_record = data_session.build_connect_record(
        ConnectRequest {
            host: request.host,
            port: request.port,
            initial_payload: Vec::new(),
        },
        &mut OsRng,
    )?;
    server.write_all(&change_cipher_spec()).await?;
    server.write_all(&connect_record).await?;

    let (local_read, local_write) = local.into_split();
    let (server_read, server_write) = server.into_split();
    relay(
        local_read,
        local_write,
        server_read,
        server_write,
        data_session,
    )
    .await
}

async fn establish_data_session(
    server: &mut TcpStream,
    config: &ClientConfig,
    traffic: TrafficConfig,
    psk: &[u8],
    server_public: &[u8; 32],
) -> Result<ClientDataSession, ClientRuntimeError> {
    let client_keys = X25519KeyPair::generate();
    let auth_key = derive_client_auth_key(psk, &client_keys.private, server_public)?;
    let client_hello = ClientHelloTemplate {
        sni: config.sni.clone(),
        x25519_public_key: client_keys.public,
    }
    .build_signed(&auth_key, &mut OsRng)?;

    server.write_all(&client_hello).await?;
    let server_hello_record = read_record(server).await?;
    let server_hello = parse_server_hello(&server_hello_record)?;
    if !server_hello.tls13_selected {
        return Err(ClientRuntimeError::Tls13Required);
    }

    let session_keys = client::derive_session_keys(
        &client_keys.private,
        server_public,
        &client_hello,
        &server_hello.random,
    )?;
    Ok(ClientDataSession::new(session_keys, traffic)?)
}

async fn relay(
    mut local_read: OwnedReadHalf,
    mut local_write: OwnedWriteHalf,
    mut server_read: OwnedReadHalf,
    mut server_write: OwnedWriteHalf,
    mut data_session: ClientDataSession,
) -> Result<(), ClientRuntimeError> {
    let mut local_buf = vec![0_u8; 16 * 1024];
    let mut server_data_started = false;

    loop {
        tokio::select! {
            read = local_read.read(&mut local_buf) => {
                let n = read?;
                if n == 0 {
                    return Ok(());
                }
                let record = data_session.seal_payload(&local_buf[..n], &mut OsRng)?;
                server_write.write_all(&record).await?;
            }
            record = read_record(&mut server_read) => {
                let record = match record {
                    Ok(record) => record,
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(ClientRuntimeError::Io(err)),
                };

                match data_session.open_server_record(&record) {
                    Ok(payload) => {
                        server_data_started = true;
                        if !payload.is_empty() {
                            local_write.write_all(&payload).await?;
                        }
                    }
                    Err(err) if !server_data_started => {
                        tracing::trace!(error = %err, "ignoring residual camouflage TLS record");
                    }
                    Err(err) => return Err(ClientRuntimeError::Handshake(err)),
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

#[allow(dead_code)]
fn _request_target(request: &SocksRequest) -> String {
    request.target()
}
