use std::{fmt, time::Duration};

use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use tokio::{
    net::TcpStream,
    time::{timeout, Instant},
};
use zeroize::Zeroizing;

use crate::{
    config::{Config, Mode},
    crypto::session::X25519KeyPair,
    tls::safari26::{Safari26TlsCamouflage, Safari26TlsError},
    transport::tcp::connect_tuned_tcp_host,
};

const DEFAULT_PORT: u16 = 443;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

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
        match self.host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(_)) => format!("[{}]:{}", self.host, self.port),
            _ => format!("{}:{}", self.host, self.port),
        }
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
            // Use the parsed host (scheme/port/path stripped) as the TLS SNI,
            // matching the Server arm. A `client.sni` of `host:port` would
            // otherwise be handed verbatim to ServerName::try_from and rejected as
            // invalid, producing a false TLS-FAIL verdict for a reachable host.
            let sni = target.host.clone();
            Ok((target, sni))
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
    let connect = timeout(deadline, connect_tuned_tcp_host(&target.authority())).await;
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
        notes
            .push("Target negotiated HTTP/2 (ALPN h2): better browser-like camouflage.".to_owned());
    }
    if tls.post_handshake_records == 0 {
        notes.push(
            "No post-handshake records observed; acceptable but revisit ticket/session \
             resumption in production."
                .to_owned(),
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
    let server = X25519KeyPair::generate();
    // Use a fresh RANDOM per-probe PSK (and a throwaway server key), never a
    // hard-coded constant. As of v4 the ClientHello carrier masks are keyed by
    // HKDF(psk, X25519(server_static, tls_ephemeral)), so they no longer leak the
    // PSK to a passive observer; but the probe still uses a random PSK so its
    // ClientHello carries no fixed, binary-derivable structure a censor could
    // match against to flag the host as ParallaX. The benign TLS origin we probe
    // ignores these auth fields, so a random key does not affect what we measure.
    let mut probe_psk = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(probe_psk.as_mut_slice());
    let session = Safari26TlsCamouflage
        .start(sni.to_owned(), probe_psk.as_slice(), &server.public)
        .map_err(|err| match err {
            // Surface the dedicated, actionable SNI message instead of an opaque
            // generic string (makes the otherwise-dead ProbeError variant reachable).
            Safari26TlsError::InvalidServerName(name) => {
                ProbeError::InvalidServerName(name).to_string()
            }
            other => format!("Safari TLS client init failed: {other}"),
        })?;
    let started = Instant::now();
    let completed = timeout(deadline, session.complete(stream))
        .await
        .map_err(|_| "timed out completing Safari TLS handshake.".to_owned())?
        .map_err(|err| format!("Safari TLS handshake failed: {err}"))?;
    let alpn = completed
        .negotiated_alpn
        .as_deref()
        .map(|protocol| String::from_utf8_lossy(protocol).to_string());

    Ok(TlsProbeResult {
        handshake_latency: started.elapsed(),
        tls13: true,
        alpn,
        post_handshake_records: completed.post_handshake_records,
    })
}

fn split_host_port(authority: &str) -> Result<(String, u16), ProbeError> {
    if let Some(host) = authority.strip_prefix('[') {
        let Some((host, rest)) = host.split_once(']') else {
            return Err(ProbeError::InvalidPort(authority.to_owned()));
        };
        let port = match rest.strip_prefix(':') {
            Some(raw) if !raw.is_empty() => parse_port(raw)?,
            Some(raw) => return Err(ProbeError::InvalidPort(raw.to_owned())),
            None if rest.is_empty() => DEFAULT_PORT,
            None => return Err(ProbeError::InvalidPort(rest.to_owned())),
        };
        return Ok((host.to_owned(), port));
    }

    if authority.matches(':').count() == 1 {
        let (host, raw_port) = authority.rsplit_once(':').expect("count checked");
        return Ok((host.to_owned(), parse_port(raw_port)?));
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
    fn authority_brackets_ipv6_literals() {
        let target = ProbeTarget::parse("[::1]:8443").unwrap();

        assert_eq!(target.authority(), "[::1]:8443");
    }

    #[test]
    fn rejects_http_scheme() {
        assert!(matches!(
            ProbeTarget::parse("http://example.com"),
            Err(ProbeError::UnsupportedScheme)
        ));
    }

    #[test]
    fn rejects_malformed_authority_ports() {
        assert!(matches!(
            ProbeTarget::parse("example.com:abc"),
            Err(ProbeError::InvalidPort(_))
        ));
        assert!(matches!(
            ProbeTarget::parse("example.com:"),
            Err(ProbeError::InvalidPort(_))
        ));
        assert!(matches!(
            ProbeTarget::parse("[::1]garbage"),
            Err(ProbeError::InvalidPort(_))
        ));
        assert!(matches!(
            ProbeTarget::parse("[::1]:"),
            Err(ProbeError::InvalidPort(_))
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

    use crate::config::{ClientConfig, CryptoConfig, Mode, ServerConfig, TrafficConfig, UdpConfig};
    use crate::crypto::pq;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use pqcrypto_mldsa::mldsa87;
    use std::path::PathBuf;

    #[test]
    fn empty_targets_are_rejected() {
        assert!(matches!(
            ProbeTarget::parse(""),
            Err(ProbeError::EmptyTarget)
        ));
        assert!(matches!(
            ProbeTarget::parse("   "),
            Err(ProbeError::EmptyTarget)
        ));
        assert!(matches!(
            ProbeTarget::parse("https://"),
            Err(ProbeError::EmptyTarget)
        ));
        assert!(matches!(
            ProbeTarget::parse("/just/a/path"),
            Err(ProbeError::EmptyTarget)
        ));
    }

    #[test]
    fn trims_query_and_fragment_suffix() {
        let target = ProbeTarget::parse("example.com:8443?q=1#frag").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8443);
    }

    #[test]
    fn rejects_zero_port_via_parse() {
        assert!(matches!(
            ProbeTarget::parse("example.com:0"),
            Err(ProbeError::InvalidPort(_))
        ));
        assert!(matches!(
            ProbeTarget::parse("[::1]:0"),
            Err(ProbeError::InvalidPort(_))
        ));
    }

    #[test]
    fn ipv6_literal_with_no_port_defaults_to_443() {
        let target = ProbeTarget::parse("[::1]").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, DEFAULT_PORT);
    }

    #[test]
    fn authority_uses_plain_host_for_non_ipv6() {
        let target = ProbeTarget::parse("example.com:8443").unwrap();
        assert_eq!(target.authority(), "example.com:8443");

        let v4 = ProbeTarget::parse("127.0.0.1:9000").unwrap();
        assert_eq!(v4.authority(), "127.0.0.1:9000");
    }

    #[test]
    fn verdict_display_strings_are_stable() {
        assert_eq!(format!("{}", ProbeVerdict::Good), "Recommended");
        assert_eq!(format!("{}", ProbeVerdict::Usable), "Usable");
        assert_eq!(format!("{}", ProbeVerdict::Bad), "Not recommended");
    }

    fn synthetic_report(signals: ProbeSignals, notes: Vec<String>) -> ProbeReport {
        report(
            ProbeTarget {
                host: "example.com".to_owned(),
                port: 443,
            },
            "example.com".to_owned(),
            signals,
            notes,
        )
    }

    #[test]
    fn score_thresholds_map_to_verdicts() {
        let bad = synthetic_report(ProbeSignals::default(), Vec::new());
        assert_eq!(bad.score, 0);
        assert_eq!(bad.verdict, ProbeVerdict::Bad);

        let usable = synthetic_report(
            ProbeSignals {
                tcp_latency: Some(Duration::from_millis(30)),
                tls13: true,
                ..ProbeSignals::default()
            },
            Vec::new(),
        );
        assert_eq!(usable.score, 70);
        assert_eq!(usable.verdict, ProbeVerdict::Usable);

        let h11 = synthetic_report(
            ProbeSignals {
                tcp_latency: Some(Duration::from_millis(30)),
                handshake_latency: Some(Duration::from_millis(40)),
                tls13: true,
                alpn: Some("http/1.1".to_owned()),
                post_handshake_records: 0,
            },
            Vec::new(),
        );
        assert_eq!(h11.score, 80);
        assert_eq!(h11.verdict, ProbeVerdict::Good);
    }

    #[test]
    fn score_buckets_tcp_latency() {
        let fast = synthetic_report(
            ProbeSignals {
                tcp_latency: Some(Duration::from_millis(250)),
                ..ProbeSignals::default()
            },
            Vec::new(),
        );
        assert_eq!(fast.score, 35);

        let mid = synthetic_report(
            ProbeSignals {
                tcp_latency: Some(Duration::from_millis(700)),
                ..ProbeSignals::default()
            },
            Vec::new(),
        );
        assert_eq!(mid.score, 30);

        let slow = synthetic_report(
            ProbeSignals {
                tcp_latency: Some(Duration::from_secs(3)),
                ..ProbeSignals::default()
            },
            Vec::new(),
        );
        assert_eq!(slow.score, 25);
    }

    #[test]
    fn summary_lists_failures_and_notes() {
        let mut report = synthetic_report(ProbeSignals::default(), Vec::new());
        report.notes.push("first note".to_owned());
        report.notes.push("second note".to_owned());

        let summary = report.summary();
        assert!(summary.contains("ParallaX probe: example.com:443"));
        assert!(summary.contains("SNI: example.com"));
        assert!(summary.contains("TCP connect      FAIL"));
        assert!(summary.contains("TLS 1.3       FAIL"));
        assert!(summary.contains("TLS handshake    FAIL"));
        assert!(summary.contains("ALPN             (none negotiated)"));
        assert!(summary.contains("Tickets/post-handshake 0 record(s)"));
        assert!(summary.contains("Score             0/100 (Not recommended)"));
        assert!(summary.contains("Notes:\n  - first note\n  - second note\n"));
    }

    #[test]
    fn summary_includes_alpn_when_negotiated() {
        let report = synthetic_report(
            ProbeSignals {
                tcp_latency: Some(Duration::from_millis(7)),
                handshake_latency: Some(Duration::from_millis(11)),
                tls13: true,
                alpn: Some("h2".to_owned()),
                post_handshake_records: 2,
            },
            Vec::new(),
        );
        let summary = report.summary();

        assert!(summary.contains("TCP connect      PASS  7ms"));
        assert!(summary.contains("TLS 1.3       PASS"));
        assert!(summary.contains("TLS handshake    PASS  11ms"));
        assert!(summary.contains("ALPN             h2"));
        assert!(summary.contains("Tickets/post-handshake 2 record(s)"));
        assert!(!summary.contains("Notes:"));
    }

    fn client_config() -> Config {
        let server_pq_public_key = STANDARD.encode(vec![0_u8; pq::public_key_bytes()]);
        let server_identity_public_key = STANDARD.encode(vec![0_u8; mldsa87::public_key_bytes()]);
        Config {
            mode: Mode::Client,
            crypto: CryptoConfig {
                psk: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            },
            traffic: TrafficConfig::default(),
            udp: UdpConfig::default(),
            client: Some(ClientConfig {
                listen: "127.0.0.1:1080".parse().unwrap(),
                server_addr: "example.com:443".to_owned(),
                sni: "camouflage.example:443".to_owned(),
                server_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                server_pq_public_key,
                server_identity_public_key,
            }),
            server: None,
        }
    }

    fn server_config_with_sni(authorized_sni: Vec<String>) -> Config {
        Config {
            mode: Mode::Server,
            crypto: CryptoConfig {
                psk: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            },
            traffic: TrafficConfig::default(),
            udp: UdpConfig::default(),
            client: None,
            server: Some(ServerConfig {
                listen: "127.0.0.1:8443".parse().unwrap(),
                fallback_addr: "fallback.example:443".to_owned(),
                data_target: None,
                private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                pq_secret_key: String::new(),
                identity_secret_key: STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]),
                replay_cache_path: PathBuf::from("/tmp/parallax-test-replay.cache"),
                replay_cache_capacity: crate::config::DEFAULT_REPLAY_CACHE_CAPACITY,
                authorized_sni,
                strict_tls13: true,
                max_concurrent_per_source_v4: 256,
                max_concurrent_per_source_v6: 256,
                source_ipv6_prefix_len: 64,
                first_record_wait_floor_ms: 8_000,
                first_record_wait_jitter_ms: 7_000,
                fallback_idle_floor_ms: 600_000,
                fallback_idle_jitter_ms: 0,
                tcp_congestion: None,
            }),
        }
    }

    #[test]
    fn target_from_config_uses_client_sni() {
        let cfg = client_config();
        let (target, sni) = target_from_config(&cfg).unwrap();
        assert_eq!(target.host, "camouflage.example");
        assert_eq!(target.port, 443);
        // The SNI is the parsed bare host, never the raw host:port (which rustls
        // would reject as an invalid ServerName, yielding a false TLS-FAIL).
        assert_eq!(sni, "camouflage.example");
    }

    #[test]
    fn target_from_config_for_server_uses_fallback_and_first_sni() {
        let cfg = server_config_with_sni(vec![
            "primary.example".to_owned(),
            "secondary.example".to_owned(),
        ]);
        let (target, sni) = target_from_config(&cfg).unwrap();
        assert_eq!(target.host, "fallback.example");
        assert_eq!(target.port, 443);
        assert_eq!(sni, "primary.example");
    }

    #[test]
    fn target_from_config_for_server_falls_back_to_target_host_when_no_sni() {
        let cfg = server_config_with_sni(Vec::new());
        let (target, sni) = target_from_config(&cfg).unwrap();
        assert_eq!(target.host, "fallback.example");
        assert_eq!(sni, "fallback.example");
    }

    #[test]
    fn target_from_config_requires_section() {
        let mut cfg = client_config();
        cfg.client = None;
        assert!(matches!(
            target_from_config(&cfg).unwrap_err(),
            ProbeError::MissingConfigTarget
        ));

        let mut cfg = server_config_with_sni(vec!["example.com".to_owned()]);
        cfg.server = None;
        assert!(matches!(
            target_from_config(&cfg).unwrap_err(),
            ProbeError::MissingConfigTarget
        ));
    }

    #[tokio::test]
    async fn probe_marks_unreachable_targets_as_bad() {
        // Bind a TCP port and immediately drop it to ensure the OS owns the
        // address but refuses connections. This keeps the test deterministic
        // without relying on outbound network.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let target = ProbeTarget {
            host: addr.ip().to_string(),
            port: addr.port(),
        };
        let report =
            probe_with_timeout(target, "example.com".to_owned(), Duration::from_millis(150))
                .await
                .unwrap();

        assert_eq!(report.tcp_latency, None);
        assert_eq!(report.handshake_latency, None);
        assert!(!report.tls13);
        assert_eq!(report.verdict, ProbeVerdict::Bad);
        assert!(report
            .notes
            .iter()
            .any(|note| note.contains("TCP connect failed")));
    }
}
