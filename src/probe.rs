use std::{fmt, time::Duration};

use rand::rngs::OsRng;
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{timeout, Instant},
};

use crate::{
    config::{Config, Mode},
    crypto::session::X25519KeyPair,
    tls::{
        client_hello_builder::{BrowserProfile, ClientHelloBuildError, ClientHelloTemplate},
        record::read_record,
        server_hello::parse_server_hello,
    },
};

const DEFAULT_PORT: u16 = 443;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("目标不能为空。用法示例：plx probe example.com")]
    EmptyTarget,
    #[error("只支持 TLS/HTTPS 目标，请使用 example.com 或 https://example.com")]
    UnsupportedScheme,
    #[error("端口必须是 1-65535：{0}")]
    InvalidPort(String),
    #[error("配置里没有可检测的 fallback/SNI；请直接运行：plx probe example.com")]
    MissingConfigTarget,
    #[error("ClientHello build error: {0}")]
    ClientHello(#[from] ClientHelloBuildError),
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
    pub tls13: bool,
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
            Self::Good => f.write_str("推荐"),
            Self::Usable => f.write_str("可用"),
            Self::Bad => f.write_str("不建议"),
        }
    }
}

impl ProbeReport {
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("ParallaX 目标检测：{}\n", self.target.authority()));
        out.push_str(&format!("SNI：{}\n\n", self.sni));

        match self.tcp_latency {
            Some(latency) => out.push_str(&format!(
                "  TCP 连接      PASS  {}ms\n",
                latency.as_millis()
            )),
            None => out.push_str("  TCP 连接      FAIL\n"),
        }
        out.push_str(&format!(
            "  TLS 1.3       {}\n",
            if self.tls13 { "PASS" } else { "FAIL" }
        ));
        out.push_str(&format!(
            "  综合评分      {}/100 ({})\n\n",
            self.score, self.verdict
        ));

        if !self.notes.is_empty() {
            out.push_str("说明：\n");
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
        notes.push("TCP 无法连接。请确认域名、端口、网络和服务器防火墙。".to_owned());
        return Ok(report(target, sni, None, false, notes));
    };

    let tcp_latency = started.elapsed();
    let _ = stream.set_nodelay(true);

    let client_keys = X25519KeyPair::generate();
    let hello = ClientHelloTemplate {
        sni: sni.clone(),
        x25519_public_key: client_keys.public,
        profile: BrowserProfile::Safari17,
    }
    .build_unsigned(&mut OsRng)?;

    if timeout(deadline, stream.write_all(&hello)).await.is_err() {
        notes.push("ClientHello 发送超时。目标站可能不适合作为 camouflage dest。".to_owned());
        return Ok(report(target, sni, Some(tcp_latency), false, notes));
    }

    let tls13 = match timeout(deadline, read_record(&mut stream)).await {
        Ok(Ok(record)) => match parse_server_hello(&record) {
            Ok(server_hello) => server_hello.tls13_selected,
            Err(_) => {
                notes.push(
                    "目标没有返回标准 ServerHello；可能是非 TLS 服务或中间设备拦截。".to_owned(),
                );
                false
            }
        },
        _ => {
            notes.push("等待 ServerHello 超时。建议换一个更稳定的目标站。".to_owned());
            false
        }
    };

    if tls13 {
        notes.push("目标可完成 TLS 1.3 ServerHello，可作为候选 camouflage dest。".to_owned());
    } else {
        notes.push("ParallaX 当前要求 TLS 1.3；该目标不建议使用。".to_owned());
    }

    Ok(report(target, sni, Some(tcp_latency), tls13, notes))
}

fn report(
    target: ProbeTarget,
    sni: String,
    tcp_latency: Option<Duration>,
    tls13: bool,
    notes: Vec<String>,
) -> ProbeReport {
    let mut score = 0_u8;
    if let Some(latency) = tcp_latency {
        score += 40;
        if latency <= Duration::from_millis(250) {
            score += 20;
        } else if latency <= Duration::from_secs(1) {
            score += 10;
        }
    }
    if tls13 {
        score += 40;
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
        tcp_latency,
        tls13,
        score,
        verdict,
        notes,
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
            Some(Duration::from_millis(30)),
            true,
            Vec::new(),
        );

        assert_eq!(report.score, 100);
        assert_eq!(report.verdict, ProbeVerdict::Good);
    }
}
