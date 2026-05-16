use std::{io, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::{
    config::{decode_psk, Config, ConfigError, Mode, ServerConfig},
    crypto::auth::{verify_client_hello_auth, AuthError},
    tls::{
        record::read_record,
        server_hello::{parse_server_hello, ServerHello, ServerHelloError},
    },
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundDecision {
    Authenticated(AuthenticatedHello),
    Fallback(FallbackReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedHello {
    pub sni: String,
    pub x25519_key_share: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackReason {
    AuthFailed,
    MissingSni,
    UnauthorizedSni(String),
    MissingX25519KeyShare,
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
}

pub async fn run(config: Config) -> Result<(), HandshakeServerError> {
    if config.mode != Mode::Server {
        return Err(HandshakeServerError::WrongMode);
    }

    let server = config
        .server
        .clone()
        .ok_or(HandshakeServerError::MissingServer)?;
    let psk = Arc::new(decode_psk(&config.crypto.psk)?.to_vec());
    let listener = TcpListener::bind(server.listen).await?;
    tracing::info!("ParallaX server listening on {}", server.listen);

    loop {
        let (client, peer) = listener.accept().await?;
        let server = server.clone();
        let psk = Arc::clone(&psk);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(client, &server, &psk).await {
                tracing::debug!(%peer, error = %err, "connection closed");
            }
        });
    }
}

pub async fn handle_connection(
    mut client: TcpStream,
    config: &ServerConfig,
    psk: &[u8],
) -> Result<(), HandshakeServerError> {
    let first_record = read_first_record(&mut client).await?;
    match decide_inbound(&first_record, psk, &config.authorized_sni)? {
        InboundDecision::Fallback(reason) => {
            tracing::debug!(?reason, "falling back to authenticated SNI target");
            relay_fallback(client, &config.fallback_addr, first_record).await?;
        }
        InboundDecision::Authenticated(client_hello) => {
            let handshake =
                accept_authenticated(client, config, first_record, client_hello).await?;
            tracing::debug!(
                sni = %handshake.client_hello.sni,
                tls13 = handshake.server_hello.tls13_selected,
                "authenticated ParallaX handshake accepted"
            );
            relay_authenticated_handshake_site(handshake).await?;
        }
    }

    Ok(())
}

pub fn decide_inbound(
    first_client_record: &[u8],
    psk: &[u8],
    authorized_sni: &[String],
) -> Result<InboundDecision, HandshakeServerError> {
    let auth = verify_client_hello_auth(first_client_record, psk)?;
    if !auth.authenticated {
        return Ok(InboundDecision::Fallback(FallbackReason::AuthFailed));
    }

    let sni = match auth.sni {
        Some(sni) => sni,
        None => return Ok(InboundDecision::Fallback(FallbackReason::MissingSni)),
    };

    if !is_authorized_sni(&sni, authorized_sni) {
        return Ok(InboundDecision::Fallback(FallbackReason::UnauthorizedSni(
            sni,
        )));
    }

    let x25519_key_share = match auth.x25519_key_share {
        Some(key) => key,
        None => {
            return Ok(InboundDecision::Fallback(
                FallbackReason::MissingX25519KeyShare,
            ));
        }
    };

    Ok(InboundDecision::Authenticated(AuthenticatedHello {
        sni,
        x25519_key_share,
    }))
}

pub async fn accept_authenticated(
    mut client: TcpStream,
    config: &ServerConfig,
    first_client_record: Vec<u8>,
    client_hello: AuthenticatedHello,
) -> Result<AuthenticatedHandshake, HandshakeServerError> {
    let mut fallback = TcpStream::connect(&config.fallback_addr).await?;
    fallback.write_all(&first_client_record).await?;

    let forwarded = read_forwarded_server_hello(&mut fallback).await?;
    if config.strict_tls13 && !forwarded.parsed.tls13_selected {
        return Err(HandshakeServerError::Tls13Required);
    }
    client.write_all(&forwarded.raw_record).await?;

    Ok(AuthenticatedHandshake {
        client,
        fallback,
        client_hello,
        server_hello: forwarded.parsed,
    })
}

pub async fn relay_fallback(
    mut client: TcpStream,
    fallback_addr: &str,
    first_client_record: Vec<u8>,
) -> Result<(), HandshakeServerError> {
    let mut fallback = TcpStream::connect(fallback_addr).await?;
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

async fn relay_authenticated_handshake_site(
    mut handshake: AuthenticatedHandshake,
) -> Result<(), HandshakeServerError> {
    copy_bidirectional(&mut handshake.client, &mut handshake.fallback).await?;
    Ok(())
}

fn is_authorized_sni(sni: &str, authorized_sni: &[String]) -> bool {
    authorized_sni
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(sni))
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{
        crypto::auth::sign_client_hello_session_id, tls::client_hello::tests::client_hello_fixture,
    };

    const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn decides_authenticated_inbound() {
        let mut record = client_hello_fixture("example.com");
        let mut rng = StdRng::seed_from_u64(1);
        sign_client_hello_session_id(&mut record, PSK, &mut rng).unwrap();

        let decision = decide_inbound(&record, PSK, &[String::from("example.com")]).unwrap();

        match decision {
            InboundDecision::Authenticated(hello) => {
                assert_eq!(hello.sni, "example.com");
                assert_eq!(hello.x25519_key_share, [0x22; 32]);
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn falls_back_on_bad_auth() {
        let mut record = client_hello_fixture("example.com");
        let mut rng = StdRng::seed_from_u64(1);
        sign_client_hello_session_id(&mut record, PSK, &mut rng).unwrap();

        let decision = decide_inbound(
            &record,
            b"wrong-wrong-wrong-wrong-wrong-32",
            &[String::from("example.com")],
        )
        .unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::AuthFailed)
        );
    }

    #[test]
    fn falls_back_on_unauthorized_sni() {
        let mut record = client_hello_fixture("example.com");
        let mut rng = StdRng::seed_from_u64(1);
        sign_client_hello_session_id(&mut record, PSK, &mut rng).unwrap();

        let decision = decide_inbound(&record, PSK, &[String::from("allowed.com")]).unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::UnauthorizedSni(String::from("example.com")))
        );
    }
}
