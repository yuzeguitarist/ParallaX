use std::{
    fmt,
    io::{Cursor, Read},
    sync::Arc,
    time::Duration,
};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, ProtocolVersion, SignatureScheme,
};
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{timeout, Instant},
};

use crate::{
    config::{Config, Mode},
    tls::record::read_record,
};

const DEFAULT_PORT: u16 = 443;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const POST_HANDSHAKE_DRAIN_LIMIT: usize = 3;
const POST_HANDSHAKE_DRAIN_TIMEOUT: Duration = Duration::from_millis(220);

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("target cannot be empty; example: plx probe example.com")]
    EmptyTarget,
    #[error("only TLS/HTTPS targets are supported (use example.com or https://example.com)")]
    UnsupportedScheme,
    #[error("port must be 1-65535: {0}")]
    InvalidPort(String),
    #[error("no fallback/SNI in config to probe; run: plx probe example.com")]
    MissingConfigTarget,
    #[error("invalid TLS server name (SNI): {0}")]
    InvalidServerName(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    Good,
    Usable,
    Bad,
}

#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub target: ProbeTarget,
    pub sni: String,
    pub tcp_latency: Option<Duration>,
    pub handshake_latency: Option<Duration>,
    pub tls13: bool,
    pub alpn: Option<String>,
    pub post_handshake_records: usize,
    pub score: u8,
    pub verdict: ProbeVerdict,
    pub notes: Vec<String>,
}

impl ProbeTarget {
    pub fn parse(input: &str) -> Result<Self, ProbeError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ProbeError::EmptyTarget);
        }

        let without_scheme = if let Some(rest) = trimmed.strip_prefix("https://") {
            rest
        } else if trimmed.starts_with("http://") {
            return Err(ProbeError::UnsupportedScheme);
        } else {
            trimmed
        };

        let authority = without_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .trim();
        if authority.is_empty() {
            return Err(ProbeError::EmptyTarget);
        }

        let (host, port) = split_host_port(authority)?;
        if host.is_empty() {
            return Err(ProbeError::EmptyTarget);
        }

        Ok(Self { host, port })
    }

    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl fmt::Display for ProbeVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Good => f.write_str("Recommended"),
            Self::Usable => f.write_str("Usable"),
            Self::Bad => f.write_str("Not recommended"),
        }
    }
}

impl ProbeReport {
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("ParallaX probe: {}\n", self.target.authority()));
        out.push_str(&format!("SNI: {}\n\n", self.sni));

        match self.tcp_latency {
            Some(latency) => out.push_str(&format!(
                "  TCP connect      PASS  {}ms\n",
                latency.as_millis()
            )),
            None => out.push_str("  TCP connect      FAIL\n"),
        }
        out.push_str(&format!(
            "  TLS 1.3       {}\n",
            if self.tls13 { "PASS" } else { "FAIL" }
        ));
        match self.handshake_latency {
            Some(latency) => out.push_str(&format!(
                "  TLS handshake    PASS  {}ms\n",
                latency.as_millis()
            )),
            None => out.push_str("  TLS handshake    FAIL\n"),
        }
        out.push_str(&format!(
            "  ALPN             {}\n",
            self.alpn.as_deref().unwrap_or("(none negotiated)")
        ));
        out.push_str(&format!(
            "  Tickets/post-handshake {} record(s)\n",
            self.post_handshake_records
        ));
        out.push_str(&format!(
            "  Score             {}/100 ({})\n\n",
            self.score, self.verdict
        ));

        if !self.notes.is_empty() {
            out.push_str("Notes:\n");
            for note in &self.notes {
                out.push_str("  - ");
                out.push_str(note);
                out.push('\n');
            }
        }

        out
    }
}

pub fn target_from_config(config: &Config) -> Result<(ProbeTarget, String), ProbeError> {
    match config.mode {
        Mode::Server => {
            let server = config
                .server
                .as_ref()
                .ok_or(ProbeError::MissingConfigTarget)?;
            let target = ProbeTarget::parse(&server.fallback_addr)?;
            let sni = server
                .authorized_sni
                .first()
                .cloned()
                .unwrap_or_else(|| target.host.clone());
            Ok((target, sni))
        }
        Mode::Client => {
            let client = config
                .client
                .as_ref()
                .ok_or(ProbeError::MissingConfigTarget)?;
            let target = ProbeTarget::parse(&client.sni)?;
            Ok((target, client.sni.clone()))
        }
    }
}

pub async fn probe(target: ProbeTarget, sni: String) -> Result<ProbeReport, ProbeError> {
    probe_with_timeout(target, sni, DEFAULT_TIMEOUT).await
}

async fn probe_with_timeout(
    target: ProbeTarget,
    sni: String,
    deadline: Duration,
) -> Result<ProbeReport, ProbeError> {
    let started = Instant::now();
    let connect = timeout(deadline, TcpStream::connect(target.authority())).await;
    let mut notes = Vec::new();

    let Ok(Ok(mut stream)) = connect else {
        notes.push(
            "TCP connect failed — check hostname, port, routing, DNS, and the server firewall."
                .to_owned(),
        );
        return Ok(report(target, sni, ProbeSignals::default(), notes));
    };

    let tcp_latency = started.elapsed();
    let _ = stream.set_nodelay(true);

    let tls = match complete_tls_probe(&mut stream, &sni, deadline).await {
        Ok(tls) => tls,
        Err(reason) => {
            notes.push(reason);
            return Ok(report(
                target,
                sni,
                ProbeSignals {
                    tcp_latency: Some(tcp_latency),
                    ..ProbeSignals::default()
                },
                notes,
            ));
        }
    };

    if tls.tls13 {
        notes.push(
            "Target completed a TLS 1.3 handshake — reasonable camouflage fallback candidate."
                .to_owned(),
        );
    } else {
        notes.push(
            "ParallaX currently requires TLS 1.3; this target is not recommended.".to_owned(),
        );
    }
    if matches!(tls.alpn.as_deref(), Some("h2")) {
        notes.push(
            "Target negotiated HTTP/2 (ALPN h2): better browser-like camouflage.".to_owned(),
        );
    }
    if tls.post_handshake_records == 0 {
        notes.push(
            "No post-handshake records observed; acceptable but revisit ticket/session resumption in production.".to_owned(),
        );
    }

    Ok(report(
        target,
        sni,
        ProbeSignals {
            tcp_latency: Some(tcp_latency),
            handshake_latency: Some(tls.handshake_latency),
            tls13: tls.tls13,
            alpn: tls.alpn,
            post_handshake_records: tls.post_handshake_records,
        },
        notes,
    ))
}

#[derive(Debug, Default)]
struct ProbeSignals {
    tcp_latency: Option<Duration>,
    handshake_latency: Option<Duration>,
    tls13: bool,
    alpn: Option<String>,
    post_handshake_records: usize,
}

fn report(
    target: ProbeTarget,
    sni: String,
    signals: ProbeSignals,
    notes: Vec<String>,
) -> ProbeReport {
    let mut score = 0_u8;
    if let Some(latency) = signals.tcp_latency {
        score += 25;
        if latency <= Duration::from_millis(250) {
            score += 10;
        } else if latency <= Duration::from_secs(1) {
            score += 5;
        }
    }
    if signals.tls13 {
        score += 35;
    }
    if let Some(alpn) = &signals.alpn {
        score += if alpn == "h2" { 20 } else { 10 };
    }
    if signals.post_handshake_records > 0 {
        score += 10;
    }

    let verdict = if score >= 80 {
        ProbeVerdict::Good
    } else if score >= 50 {
        ProbeVerdict::Usable
    } else {
        ProbeVerdict::Bad
    };

    ProbeReport {
        target,
        sni,
        tcp_latency: signals.tcp_latency,
        handshake_latency: signals.handshake_latency,
        tls13: signals.tls13,
        alpn: signals.alpn,
        post_handshake_records: signals.post_handshake_records,
        score,
        verdict,
        notes,
    }
}

#[derive(Debug)]
struct TlsProbeResult {
    handshake_latency: Duration,
    tls13: bool,
    alpn: Option<String>,
    post_handshake_records: usize,
}

async fn complete_tls_probe(
    stream: &mut TcpStream,
    sni: &str,
    deadline: Duration,
) -> Result<TlsProbeResult, String> {
    let config = probe_client_config();
    let server_name = ServerName::try_from(sni.to_owned())
        .map_err(|_| ProbeError::InvalidServerName(sni.to_owned()).to_string())?;
    let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| format!("TLS client init failed: {err}"))?;

    let started = Instant::now();
    while connection.is_handshaking() {
        flush_tls(&mut connection, stream, deadline).await?;
        if connection.is_handshaking() {
            let record = read_tls_record(stream, deadline).await?;
            feed_tls_record(&mut connection, &record)?;
        }
    }
    flush_tls(&mut connection, stream, deadline).await?;

    let post_handshake_records =
        drain_post_handshake_records(&mut connection, stream, POST_HANDSHAKE_DRAIN_LIMIT).await?;
    let tls13 = connection.protocol_version() == Some(ProtocolVersion::TLSv1_3);
    let alpn = connection
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).to_string());

    Ok(TlsProbeResult {
        handshake_latency: started.elapsed(),
        tls13,
        alpn,
        post_handshake_records,
    })
}

fn probe_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("aws_lc_rs provider supports rustls default protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(ProbeServerCertVerifier))
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.enable_early_data = false;
    config
}

async fn flush_tls(
    connection: &mut rustls::ClientConnection,
    stream: &mut TcpStream,
    deadline: Duration,
) -> Result<(), String> {
    while connection.wants_write() {
        let mut out = Vec::new();
        let written = connection
            .write_tls(&mut out)
            .map_err(|err| format!("TLS write_tls failed: {err}"))?;
        if written == 0 || out.is_empty() {
            break;
        }
        timeout(deadline, stream.write_all(&out))
            .await
            .map_err(|_| "timed out writing TLS buffers; target may be unstable.".to_owned())?
            .map_err(|err| format!("TCP write after TLS framing failed: {err}"))?;
    }
    Ok(())
}

async fn read_tls_record(stream: &mut TcpStream, deadline: Duration) -> Result<Vec<u8>, String> {
    timeout(deadline, read_record(stream))
        .await
        .map_err(|_| "timed out waiting for TLS ciphertext; try a more stable upstream.".to_owned())?
        .map_err(|err| format!("TLS record read failed: {err}"))
}

fn feed_tls_record(connection: &mut rustls::ClientConnection, record: &[u8]) -> Result<(), String> {
    let mut cursor = Cursor::new(record);
    connection
        .read_tls(&mut cursor)
        .map_err(|err| format!("TLS read_tls failed: {err}"))?;
    connection
        .process_new_packets()
        .map_err(|err| format!("TLS handshake failed: {err}"))?;

    let mut plaintext = Vec::new();
    match connection.reader().read_to_end(&mut plaintext) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(err) => return Err(format!("TLS plaintext read failed: {err}")),
    }
    Ok(())
}

async fn drain_post_handshake_records(
    connection: &mut rustls::ClientConnection,
    stream: &mut TcpStream,
    limit: usize,
) -> Result<usize, String> {
    let mut observed = 0;
    for _ in 0..limit {
        let record = match timeout(POST_HANDSHAKE_DRAIN_TIMEOUT, read_record(stream)).await {
            Ok(Ok(record)) => record,
            Ok(Err(_)) | Err(_) => break,
        };
        feed_tls_record(connection, &record)?;
        observed += 1;
        flush_tls(connection, stream, POST_HANDSHAKE_DRAIN_TIMEOUT).await?;
    }
    Ok(observed)
}

#[derive(Debug)]
struct ProbeServerCertVerifier;

impl ServerCertVerifier for ProbeServerCertVerifier {
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
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn split_host_port(authority: &str) -> Result<(String, u16), ProbeError> {
    if let Some(host) = authority.strip_prefix('[') {
        let Some((host, rest)) = host.split_once(']') else {
            return Ok((authority.to_owned(), DEFAULT_PORT));
        };
        let port = match rest.strip_prefix(':') {
            Some(raw) if !raw.is_empty() => parse_port(raw)?,
            _ => DEFAULT_PORT,
        };
        return Ok((host.to_owned(), port));
    }

    if authority.matches(':').count() == 1 {
        let (host, raw_port) = authority.rsplit_once(':').expect("count checked");
        if raw_port.chars().all(|ch| ch.is_ascii_digit()) {
            return Ok((host.to_owned(), parse_port(raw_port)?));
        }
    }

    Ok((authority.to_owned(), DEFAULT_PORT))
}

fn parse_port(raw: &str) -> Result<u16, ProbeError> {
    raw.parse::<u16>()
        .map_err(|_| ProbeError::InvalidPort(raw.to_owned()))
        .and_then(|port| {
            if port == 0 {
                Err(ProbeError::InvalidPort(raw.to_owned()))
            } else {
                Ok(port)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_probe_targets() {
        assert_eq!(
            ProbeTarget::parse("example.com").unwrap(),
            ProbeTarget {
                host: "example.com".to_owned(),
                port: 443
            }
        );
        assert_eq!(
            ProbeTarget::parse("https://example.com:8443/path").unwrap(),
            ProbeTarget {
                host: "example.com".to_owned(),
                port: 8443
            }
        );
    }

    #[test]
    fn rejects_http_scheme() {
        assert!(matches!(
            ProbeTarget::parse("http://example.com"),
            Err(ProbeError::UnsupportedScheme)
        ));
    }

    #[test]
    fn scores_tls13_low_latency_as_good() {
        let report = report(
            ProbeTarget {
                host: "example.com".to_owned(),
                port: 443,
            },
            "example.com".to_owned(),
            ProbeSignals {
                tcp_latency: Some(Duration::from_millis(30)),
                handshake_latency: Some(Duration::from_millis(55)),
                tls13: true,
                alpn: Some("h2".to_owned()),
                post_handshake_records: 1,
            },
            Vec::new(),
        );

        assert_eq!(report.score, 100);
        assert_eq!(report.verdict, ProbeVerdict::Good);
    }
}
