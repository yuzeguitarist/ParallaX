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
    config::{
        decode_base64_bytes, decode_key32, decode_psk, ClientConfig, Config, ConfigError, Mode,
        TrafficConfig,
    },
    crypto::auth::AuthError,
    handshake::client::{self, ClientDataSession, ClientHandshakeError},
    protocol::command::ConnectRequest,
    protocol::data::max_plaintext_len,
    tls::{
        backend::TlsBackendError,
        record::{alert_bad_record_mac, read_record, TlsRecordError},
        stateful::StatefulRustlsCamouflageBackend,
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
    #[error("TLS camouflage backend error: {0}")]
    TlsBackend(#[from] TlsBackendError),
    #[error("ClientHello auth error: {0}")]
    Auth(#[from] AuthError),
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
    let server_pq_public = Arc::new(decode_base64_bytes(
        "client.server_pq_public_key",
        &client.server_pq_public_key,
    )?);
    let server_identity_public = Arc::new(decode_base64_bytes(
        "client.server_identity_public_key",
        &client.server_identity_public_key,
    )?);
    let listener = TcpListener::bind(client.listen).await?;
    tracing::info!("ParallaX client SOCKS5 listening on {}", client.listen);

    loop {
        let (local, peer) = listener.accept().await?;
        let client = client.clone();
        let psk = Arc::clone(&psk);
        let server_pq_public = Arc::clone(&server_pq_public);
        let server_identity_public = Arc::clone(&server_identity_public);
        let traffic = config.traffic;
        tokio::spawn(async move {
            if let Err(err) = handle_local_connection(
                local,
                &client,
                traffic,
                &psk,
                &server_public,
                &server_pq_public,
                &server_identity_public,
            )
            .await
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
    server_pq_public: &[u8],
    server_identity_public: &[u8],
) -> Result<(), ClientRuntimeError> {
    local.set_nodelay(true)?;
    let request = socks::accept_connect(&mut local).await?;
    let mut server = TcpStream::connect(&config.server_addr).await?;
    server.set_nodelay(true)?;

    let mut data_session =
        establish_data_session(&mut server, config, traffic, psk, server_public).await?;
    let pq_record = data_session.build_pq_rekey_record(server_pq_public, &mut OsRng)?;
    server.write_all(&pq_record).await?;
    let identity_record = read_record(&mut server).await?;
    data_session.verify_server_identity_record(
        &identity_record,
        server_identity_public,
        server_public,
    )?;
    let connect_record = data_session.build_connect_record(
        ConnectRequest {
            host: request.host,
            port: request.port,
            initial_payload: Vec::new(),
        },
        &mut OsRng,
    )?;
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
    let completed = StatefulRustlsCamouflageBackend
        .start(config.sni.clone(), psk, server_public, config.tls_profile)?
        .complete(server)
        .await?;
    let session_keys = client::derive_session_keys(
        &completed.client_x25519.private,
        server_public,
        &completed.client_hello,
        &completed.server_hello_record,
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
                    Err(err) => {
                        let _ = server_write.write_all(&alert_bad_record_mac()).await;
                        return Err(ClientRuntimeError::Handshake(err));
                    }
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
    use std::{io::Cursor, sync::Arc};

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::{timeout, Duration},
    };

    use super::*;
    use crate::{
        config::ServerConfig,
        crypto::{pq, session::X25519KeyPair},
        handshake::server,
    };

    const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";
    const CAMOUFLAGE_CERT_DER_B64: &str = "MIIC9jCCAd6gAwIBAgIJAPNzR81y9p7pMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTI2MDUxNjEyNDA0NloXDTI2MDUxNzEyNDA0NlowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnjSfVPv1Xy5razuOYABOSvGvlddr0MMVWQCSmjE47PMQEzvETytmburNZEdqQBzSjDVxTExxd8eIHFTp8ylkztsxma5yJftQo81uqxZEnwT00tJRaazg10OYTf0ZrH6PMNC2izwJML0GkYz7s6OMFqImMCG3v00PIAYknlDrlKoDjdmANco8V5FNrbQYp2kqIcFyXrbgYurcMIKCE9Wu8L2W0oKhW6DNyRVoBGTn5zN1wjXLBO+6TJsBj4thI4tM0mUcLc+YohOfoGVq7na/wgCESoK1B+m8PdrXIEuZ7gZ0x3ZqdZ7jxL23sTmkfm+AeNdp+XshxAS77l3dcrAV9AgMBAAGjRzBFMBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4IBAQA8KHWHoA4otNmYh9q+X8cZnYx9y0LUNfdbHLR8ebnk/9T+/WP5CgIGWvn3+L2ulEvuSMhDC23C20SnX0h815JfMBY/PiAbLKGp3UXrgIq1dWc8t40HQBGRuBKi2fc743Sup5kPQgNAqev+8kKs4WFDXaWBpdwqI55PADVPOX66h0WiObB7crp5YTEVEe37G6UsxX40HUAAZJXtCI9eqPLISNuuNOAjJEMDMjdRH7ZjcMyrqQSweuKLAwdvUam8UJQsUNe7rM2II6GlgPS/mKZx1Nihn70GIo0yu0Bsxc9cpSHbggzQarE3g8WRp+jI9GpWXXdjno7cyim5KEQVMZcz";
    const CAMOUFLAGE_KEY_DER_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCnjSfVPv1Xy5razuOYABOSvGvlddr0MMVWQCSmjE47PMQEzvETytmburNZEdqQBzSjDVxTExxd8eIHFTp8ylkztsxma5yJftQo81uqxZEnwT00tJRaazg10OYTf0ZrH6PMNC2izwJML0GkYz7s6OMFqImMCG3v00PIAYknlDrlKoDjdmANco8V5FNrbQYp2kqIcFyXrbgYurcMIKCE9Wu8L2W0oKhW6DNyRVoBGTn5zN1wjXLBO+6TJsBj4thI4tM0mUcLc+YohOfoGVq7na/wgCESoK1B+m8PdrXIEuZ7gZ0x3ZqdZ7jxL23sTmkfm+AeNdp+XshxAS77l3dcrAV9AgMBAAECggEAcsH8cVMWRAbBBnLDcX1D6rHBGMVy9ONelaeTMrtQbcQ94ak3dz3tc3sZkbznvNQimjbxcDjbqgCctgs1JvmUxRXDw7aa3ZWPjIi51SpCND9nQ20XWyKqujldDCeVPJPMJXXrd+JfCX0ocYZEOBF+RIbdxpqTabqCZz+eCAy/les95pv5YkkAjxEJkzhEfFTJtJRVIjIUBL/Gg8KwG4qs5nESoD1oiNGr8tgnbsS2KNXdozIsM1awitqNJ7drpDpEpkwDUoQGAqzuvyDiN2pPqsyg1UwZWH8kuA9RyXIAOWQoR9rIX/rUsYB5F4tKg6Tdy0n9Jb9ytTINYaletNjuIQKBgQDSEzvmO4Zan1Bz+0Eb4NWfnU1yyGKb7bBFBvcuigXPW/+as1yET2Zkc4qQBudye7DUgr+zXj0s+ZeXvv+HeGggD3Blnq5bl+gPkiPSeGd24QkfO38MF2RTpW5SoUT6Z9vTiaHjIgkwZIgQf3dfSPV/MskRVemqxB5o+Phd4NRzpQKBgQDMLhkoYeRurmFQ3iuWCLOaHWAwtA28j3ymknsHyP6EOkiHBVl3YWTpZ1ZcDGMJznHdkSrj4mNsnnDM71iFM0srgKKp07T4bumowOhmyeg/hYIblFGSoZS/nTl8tAusNzXtRJeVLa9GjkFjXihiC3E+t3J2s9ij2eE8bAM0tatC+QKBgCsAQuea0aKlL8u955L0T+YPRfYz7HNskQNgLKK7H/tVIpohEtQGiLgRKpDWyPOXPBgT93eY177oDE7EivvI+s9tOZ2jgJ9BFgBx8qE3gj5ETCC3hgcMlr3EhDOnzT3Qmp/PcXLT2butKGjwHphDj/UMiTniMyWAZZUpOXXF+tb9AoGAEKvG5BQyGZNlYLvzJRnqyC+T1gYthPLWQ6d8IiOYHGXB3DxklKnAGoqUc4mTYI6Zn3Sl4ttuMMUzApicSqvofFHRdjpR8WLk8yFlGFdt/hnBiMzwaB+HTKnisrrkpRgQ8CGEmuqTABjHX/ylIXQ7t9o0n1qJ2r8Ec/GBxYD7zckCgYBZzU7u9Ujq8XL+Ok6T2Zqgf3O8H3VBlKPjeYpfH6mqBRdj+773IfoifCs19Y31OL8Sb28N98XnutTlHo6xs4li0zE2KDN1O3i00K7S0dO3250Fr1QSm86CML8fSDuS1BcuMHH+RNkQkMb9Q49K23t6B1s0xnIFfBarwbusw9onAw==";

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn socks_client_reaches_target_through_parallax_server() {
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
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let server_keys = X25519KeyPair::generate();
        let server_pq_keys = pq::keypair();
        let server_identity_keys = crate::crypto::identity::keypair();
        let server_config = ServerConfig {
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
            tls_profile: crate::tls::client_hello_builder::BrowserProfile::Safari17,
        };
        let client_task = tokio::spawn(async move {
            let (stream, _) = local_listener.accept().await.unwrap();
            handle_local_connection(
                stream,
                &client_config,
                TrafficConfig::default(),
                PSK,
                &server_keys.public,
                &server_pq_keys.public,
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
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap(),
        )
    }
}
