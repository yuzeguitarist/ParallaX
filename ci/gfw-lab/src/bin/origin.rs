//! `origin`: a minimal hand-rolled HTTP/1.1 origin server used as the
//! data-plane target behind a ParallaX proxy in end-to-end tests.
//!
//! Routes:
//! - `GET /download?bytes=N&rate_kbps=R` — N bytes of `0x5A`, optionally paced
//!   to approximately R kilobits/sec (simulates video-stream downlink pacing).
//! - `POST /upload` — reads and discards the Content-Length body, replies
//!   `{"received":N}`.
//! - `POST /echo` — echoes the request body back (VoIP round-trip timing).
//! - `GET /ping` — replies `pong`.
//!
//! This is a CI/test tool, not a production component.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

const CHUNK_SIZE: usize = 16 * 1024;
const MAX_HEADERS: usize = 256;
const DEFAULT_DOWNLOAD_BYTES: u64 = 1_048_576;

#[derive(Parser)]
#[command(
    name = "origin",
    about = "Minimal HTTP/1.1 test origin for the ParallaX lab"
)]
struct Cli {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let listener = TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("failed to bind {}", cli.listen))?;
    let addr = listener.local_addr().context("local_addr")?;
    eprintln!("origin listening on {addr}");

    loop {
        let (stream, _) = listener.accept().await.context("accept")?;
        tokio::spawn(async move {
            // Parse failures and broken pipes just end this connection.
            let _ = handle_conn(stream).await;
        });
    }
}

/// The parts of a request we care about.
struct Request {
    method: String,
    path: String,
    content_length: Option<u64>,
    connection: Option<String>,
    http_1_0: bool,
}

async fn handle_conn(stream: TcpStream) -> Result<()> {
    let mut stream = BufReader::new(stream);
    loop {
        let req = match read_request(&mut stream).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // clean close between requests
            Err(err) => {
                send_bad_request(&mut stream).await?;
                return Err(err);
            }
        };

        let keep_alive = match req.connection.as_deref() {
            Some("close") => false,
            Some(v) if v.contains("keep-alive") => true,
            _ => !req.http_1_0,
        };

        let (route, query) = req.path.split_once('?').unwrap_or((req.path.as_str(), ""));

        match (req.method.as_str(), route) {
            ("GET", "/download") => match download_params(query) {
                Ok((bytes, rate_kbps)) => {
                    send_download(&mut stream, bytes, rate_kbps, keep_alive).await?;
                }
                Err(err) => {
                    send_bad_request(&mut stream).await?;
                    return Err(err);
                }
            },
            ("POST", "/upload") => match req.content_length {
                Some(len) => {
                    discard_body(&mut stream, len).await?;
                    let body = format!("{{\"received\":{len}}}");
                    send_response(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        body.as_bytes(),
                        keep_alive,
                    )
                    .await?;
                }
                None => {
                    send_bad_request(&mut stream).await?;
                    bail!("POST /upload without Content-Length");
                }
            },
            ("POST", "/echo") => match req.content_length {
                Some(len) => send_echo(&mut stream, len, keep_alive).await?,
                None => {
                    send_bad_request(&mut stream).await?;
                    bail!("POST /echo without Content-Length");
                }
            },
            ("GET", "/ping") => {
                send_response(&mut stream, "200 OK", "text/plain", b"pong", keep_alive).await?;
            }
            _ => {
                // Drain any body so the connection stays usable for keep-alive.
                if let Some(len) = req.content_length {
                    discard_body(&mut stream, len).await?;
                }
                send_response(
                    &mut stream,
                    "404 Not Found",
                    "text/plain",
                    b"not found\n",
                    keep_alive,
                )
                .await?;
            }
        }

        if !keep_alive {
            return Ok(());
        }
    }
}

/// Read one request head (request line + headers). Returns `Ok(None)` on a
/// clean EOF before any bytes of the next request; `Err` on malformed input.
async fn read_request(stream: &mut BufReader<TcpStream>) -> Result<Option<Request>> {
    let mut line = String::new();
    let n = stream
        .read_line(&mut line)
        .await
        .context("read request line")?;
    if n == 0 {
        return Ok(None);
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.split_whitespace();
    let (method, path) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(p), Some(v)) if v.starts_with("HTTP/") => (m.to_string(), p.to_string()),
        _ => bail!("malformed request line: {trimmed:?}"),
    };
    let http_1_0 = trimmed.ends_with("HTTP/1.0");

    let mut content_length = None;
    let mut connection = None;
    for _ in 0..MAX_HEADERS {
        let mut hline = String::new();
        let n = stream.read_line(&mut hline).await.context("read header")?;
        if n == 0 {
            bail!("eof in headers");
        }
        let header = hline.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            return Ok(Some(Request {
                method,
                path,
                content_length,
                connection,
                http_1_0,
            }));
        }
        let (name, value) = header
            .split_once(':')
            .with_context(|| format!("malformed header: {header:?}"))?;
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                content_length = Some(value.parse::<u64>().context("bad Content-Length")?);
            }
            "connection" => connection = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    bail!("too many headers");
}

/// Parse `bytes` and `rate_kbps` from a `/download` query string.
fn download_params(query: &str) -> Result<(u64, u64)> {
    let mut bytes = DEFAULT_DOWNLOAD_BYTES;
    let mut rate_kbps = 0u64;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "bytes" => bytes = value.parse().context("bad bytes param")?,
            "rate_kbps" => rate_kbps = value.parse().context("bad rate_kbps param")?,
            _ => {}
        }
    }
    Ok((bytes, rate_kbps))
}

async fn send_download(
    stream: &mut BufReader<TcpStream>,
    bytes: u64,
    rate_kbps: u64,
    keep_alive: bool,
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {bytes}\r\nConnection: {}\r\n\r\n",
        connection_value(keep_alive)
    );
    stream.write_all(head.as_bytes()).await?;

    let chunk = [0x5Au8; CHUNK_SIZE];
    // 1 kbit/s = 125 bytes/s.
    let bytes_per_sec = rate_kbps * 125;
    let mut remaining = bytes;
    while remaining > 0 {
        let n = remaining.min(CHUNK_SIZE as u64) as usize;
        stream.write_all(&chunk[..n]).await?;
        remaining -= n as u64;
        if bytes_per_sec > 0 && remaining > 0 {
            sleep(Duration::from_secs_f64(n as f64 / bytes_per_sec as f64)).await;
        }
    }
    stream.flush().await?;
    Ok(())
}

/// Stream `len` request-body bytes straight back to the client.
async fn send_echo(stream: &mut BufReader<TcpStream>, len: u64, keep_alive: bool) -> Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {len}\r\nConnection: {}\r\n\r\n",
        connection_value(keep_alive)
    );
    stream.write_all(head.as_bytes()).await?;

    let mut buf = [0u8; CHUNK_SIZE];
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(CHUNK_SIZE as u64) as usize;
        let n = stream.read(&mut buf[..want]).await.context("read body")?;
        if n == 0 {
            bail!("eof in request body");
        }
        stream.write_all(&buf[..n]).await?;
        remaining -= n as u64;
    }
    stream.flush().await?;
    Ok(())
}

/// Read and discard exactly `len` request-body bytes.
async fn discard_body(stream: &mut BufReader<TcpStream>, len: u64) -> Result<()> {
    let mut buf = [0u8; CHUNK_SIZE];
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(CHUNK_SIZE as u64) as usize;
        let n = stream.read(&mut buf[..want]).await.context("read body")?;
        if n == 0 {
            bail!("eof in request body");
        }
        remaining -= n as u64;
    }
    Ok(())
}

async fn send_response(
    stream: &mut BufReader<TcpStream>,
    status: &str,
    content_type: &str,
    body: &[u8],
    keep_alive: bool,
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        body.len(),
        connection_value(keep_alive)
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_bad_request(stream: &mut BufReader<TcpStream>) -> Result<()> {
    send_response(
        stream,
        "400 Bad Request",
        "text/plain",
        b"bad request\n",
        false,
    )
    .await
}

fn connection_value(keep_alive: bool) -> &'static str {
    if keep_alive {
        "keep-alive"
    } else {
        "close"
    }
}
