use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    pub host: String,
    pub port: u16,
}

impl SocksRequest {
    pub fn target(&self) -> String {
        match self.host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(_)) => format!("[{}]:{}", self.host, self.port),
            _ => format!("{}:{}", self.host, self.port),
        }
    }
}

#[derive(Debug, Error)]
pub enum SocksError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported SOCKS version: {0}")]
    UnsupportedVersion(u8),
    #[error("SOCKS client offered no authentication methods")]
    NoMethods,
    #[error("SOCKS no-auth method was not offered")]
    NoAuthMethodMissing,
    #[error("unsupported SOCKS command: {0}")]
    UnsupportedCommand(u8),
    #[error("unsupported SOCKS address type: {0}")]
    UnsupportedAddressType(u8),
    #[error("SOCKS domain name is empty")]
    EmptyDomain,
    #[error("SOCKS target port must not be zero")]
    ZeroPort,
}

pub async fn accept_connect<S>(stream: &mut S) -> Result<SocksRequest, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_no_auth(stream).await?;
    let request = read_connect_request(stream).await?;
    send_success(stream).await?;
    Ok(request)
}

async fn negotiate_no_auth<S>(stream: &mut S) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != 5 {
        return Err(SocksError::UnsupportedVersion(version));
    }

    let method_count = stream.read_u8().await?;
    if method_count == 0 {
        return Err(SocksError::NoMethods);
    }

    let mut methods = vec![0_u8; method_count as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        return Err(SocksError::NoAuthMethodMissing);
    }

    stream.write_all(&[5, 0]).await?;
    Ok(())
}

async fn read_connect_request<S>(stream: &mut S) -> Result<SocksRequest, SocksError>
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;
    if version != 5 {
        return Err(SocksError::UnsupportedVersion(version));
    }

    let command = stream.read_u8().await?;
    if command != 1 {
        return Err(SocksError::UnsupportedCommand(command));
    }

    let _reserved = stream.read_u8().await?;
    let address_type = stream.read_u8().await?;
    let host = match address_type {
        1 => {
            let raw = stream.read_u32().await?;
            Ipv4Addr::from(raw).to_string()
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                return Err(SocksError::EmptyDomain);
            }
            let mut domain = vec![0_u8; len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).into_owned()
        }
        4 => {
            let raw = stream.read_u128().await?;
            Ipv6Addr::from(raw).to_string()
        }
        other => return Err(SocksError::UnsupportedAddressType(other)),
    };

    let port = stream.read_u16().await?;
    if port == 0 {
        return Err(SocksError::ZeroPort);
    }

    Ok(SocksRequest { host, port })
}

async fn send_success<S>(stream: &mut S) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn accepts_domain_connect() {
        let (mut client, mut server) = duplex(128);
        let task = tokio::spawn(async move { accept_connect(&mut server).await.unwrap() });

        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        client
            .write_all(&[
                5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                1, 187,
            ])
            .await
            .unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0..2], [5, 0]);

        let request = task.await.unwrap();
        assert_eq!(
            request,
            SocksRequest {
                host: "example.com".to_owned(),
                port: 443
            }
        );
    }

    #[test]
    fn target_brackets_ipv6_literals() {
        let request = SocksRequest {
            host: "::1".to_owned(),
            port: 443,
        };

        assert_eq!(request.target(), "[::1]:443");
    }
}
