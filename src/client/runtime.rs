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
    protocol::data::max_plaintext_len,
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
        max_plaintext_len(traffic.max_padding),
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
    chunk_size: usize,
) -> Result<(), ClientRuntimeError> {
    let mut local_buf = vec![0_u8; chunk_size];
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

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::{timeout, Duration},
    };

    use super::*;
    use crate::{
        config::ServerConfig,
        crypto::session::X25519KeyPair,
        handshake::server,
        tls::{record::read_record, server_hello::tests::server_hello_fixture},
    };

    const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn socks_client_reaches_target_through_parallax_server() {
        let fallback_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback_listener.local_addr().unwrap();
        let fallback_task = tokio::spawn(async move {
            let (mut stream, _) = fallback_listener.accept().await.unwrap();
            let _client_hello = read_record(&mut stream).await.unwrap();
            stream.write_all(&server_hello_fixture()).await.unwrap();
            let _ccs = timeout(Duration::from_secs(1), read_record(&mut stream))
                .await
                .unwrap()
                .unwrap();
        });

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let server_keys = X25519KeyPair::generate();
        let server_config = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: fallback_addr.to_string(),
            data_target: None,
            private_key: STANDARD.encode(server_keys.private),
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
        };
        let client_task = tokio::spawn(async move {
            let (stream, _) = local_listener.accept().await.unwrap();
            handle_local_connection(
                stream,
                &client_config,
                TrafficConfig::default(),
                PSK,
                &server_keys.public,
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

        app.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        app.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        drop(app);
        client_task.await.unwrap();
        server_task.await.unwrap();
        target_task.await.unwrap();
        fallback_task.await.unwrap();
    }
}
