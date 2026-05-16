use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
use rcgen::generate_simple_self_signed;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use thiserror::Error;
use tokio::{
    io::{copy, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    client::socks,
    config::{ClientConfig, Config, ConfigError, Mode, ServerConfig},
    protocol::command::{ConnectRequest, ConnectRequestError},
};

const QUIC_ALPN: &[u8] = b"h3";
const MAX_CONNECT_FRAME_LEN: usize = 4096;

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
}

pub async fn run_server(config: Config) -> Result<(), QuicRuntimeError> {
    if config.mode != Mode::Server {
        return Err(QuicRuntimeError::WrongServerMode);
    }
    let server = config.server.ok_or(QuicRuntimeError::MissingServer)?;
    let endpoint = Endpoint::server(server_config(&server)?, server.listen)?;
    tracing::info!("ParallaX QUIC server listening on udp://{}", server.listen);

    while let Some(incoming) = endpoint.accept().await {
        let server = server.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = handle_connection(connection, server).await {
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
        tokio::spawn(async move {
            if let Err(err) = handle_local_connection(local, endpoint, server_addr, client).await {
                tracing::debug!(%peer, error = %err, "QUIC client stream closed");
            }
        });
    }
}

async fn handle_connection(
    connection: quinn::Connection,
    server: ServerConfig,
) -> Result<(), QuicRuntimeError> {
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => return Ok(()),
            Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_stream(send, recv, server).await {
                tracing::debug!(error = %err, "QUIC stream closed");
            }
        });
    }
}

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    server: ServerConfig,
) -> Result<(), QuicRuntimeError> {
    let request = read_connect_request(&mut recv).await?;
    let target_addr = server
        .data_target
        .clone()
        .unwrap_or_else(|| request.target());
    let mut target = TcpStream::connect(&target_addr).await?;
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
) -> Result<(), QuicRuntimeError> {
    local.set_nodelay(true)?;
    let request = socks::accept_connect(&mut local).await?;
    let connection = endpoint.connect(server_addr, &client.sni)?.await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    let connect = ConnectRequest {
        host: request.host,
        port: request.port,
        initial_payload: Vec::new(),
    };
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

async fn write_connect_request(
    send: &mut quinn::SendStream,
    request: &ConnectRequest,
) -> Result<(), QuicRuntimeError> {
    let encoded = request.encode()?;
    if encoded.len() > MAX_CONNECT_FRAME_LEN {
        return Err(QuicRuntimeError::ConnectFrameTooLarge);
    }
    send.write_all(&(encoded.len() as u16).to_be_bytes())
        .await?;
    send.write_all(&encoded).await?;
    Ok(())
}

async fn read_connect_request(
    recv: &mut quinn::RecvStream,
) -> Result<ConnectRequest, QuicRuntimeError> {
    let mut len = [0_u8; 2];
    recv.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_CONNECT_FRAME_LEN {
        return Err(QuicRuntimeError::InvalidConnectFrameLength);
    }
    let mut encoded = vec![0_u8; len];
    recv.read_exact(&mut encoded).await?;
    Ok(ConnectRequest::decode(&encoded)?)
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

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|err| QuicRuntimeError::TlsConfig(err.to_string()))?;
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls))
        .map_err(|err| QuicRuntimeError::TlsConfig(err.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1_u8.into());
    config.transport = Arc::new(transport);
    Ok(config)
}

fn client_config() -> Result<quinn::ClientConfig, QuicRuntimeError> {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptQuicServerCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    tls.enable_early_data = true;

    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|err| QuicRuntimeError::TlsConfig(err.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1_u8.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
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
        let request = ConnectRequest {
            host: "example.com".to_owned(),
            port: 443,
            initial_payload: Vec::new(),
        };
        let encoded = request.encode().unwrap();
        assert!(encoded.len() <= MAX_CONNECT_FRAME_LEN);
        assert_eq!(ConnectRequest::decode(&encoded).unwrap(), request);
    }

    #[tokio::test]
    #[ignore = "requires UDP and TCP loopback sockets"]
    async fn quic_stream_reaches_tcp_target() {
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
            identity_secret_key: STANDARD.encode(KEY32),
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
            handle_stream(send, recv, server).await.unwrap();
        });

        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config().unwrap());
        let connection = client_endpoint
            .connect(server_addr, "example.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
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
