use std::{
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use pqcrypto_mldsa::mldsa87;
use pqcrypto_mlkem::mlkem1024;
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

pub(crate) const DEFAULT_REPLAY_CACHE_PATH: &str = "/var/lib/parallax/parallax-replay.cache";
pub(crate) const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 8192;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("missing [client] section for client mode")]
    MissingClient,
    #[error("missing [server] section for server mode")]
    MissingServer,
    #[error("invalid socket address in {field}: {value}")]
    InvalidSocket { field: &'static str, value: String },
    #[error("invalid base64 in {field}: {source}")]
    InvalidBase64 {
        field: &'static str,
        source: base64::DecodeError,
    },
    #[error("{field} must decode to exactly 32 bytes")]
    InvalidKeyLen { field: &'static str },
    #[error("{field} must be valid base64")]
    InvalidBytes { field: &'static str },
    #[error("{field} must decode to exactly {expected} bytes, got {actual}")]
    InvalidBytesLen {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("crypto.psk must decode to at least 32 bytes")]
    WeakPsk,
    #[error("traffic.max_padding must be >= traffic.min_padding")]
    InvalidPaddingRange,
    #[error("traffic.max_padding leaves no room for encrypted payload")]
    ExcessivePadding,
    #[error("traffic.max_delay_ms must be >= traffic.min_delay_ms")]
    InvalidDelayRange,
    #[error("traffic.cover_max_interval_ms must be >= traffic.cover_min_interval_ms")]
    InvalidCoverIntervalRange,
    #[error("traffic.max_concurrent_streams must be at least 1")]
    InvalidMaxConcurrentStreams,
    #[error(
        "client.listen must bind to a loopback address because SOCKS5 has no authentication: {0}"
    )]
    UnsafeClientListen(SocketAddr),
    #[error("server.authorized_sni must not be empty")]
    EmptyAuthorizedSni,
    #[error("server.replay_cache_capacity must be at least 1")]
    InvalidReplayCacheCapacity,
    #[error("server.max_concurrent_per_source_v4/v6 must be at least 1")]
    InvalidSourceConcurrencyLimit,
    #[error("server.source_ipv6_prefix_len must be between 1 and 128")]
    InvalidSourceIpv6Prefix,
    #[error("server timeout floors must be at least 250ms")]
    InvalidTimeoutFloor,
    #[error("server.fallback_idle_floor_ms must be at least 5000ms (it resets on every byte; a tiny value closes active relays)")]
    InvalidIdleBackstop,
    #[error("server.tcp_congestion must be a short alphanumeric algorithm name (e.g. \"bbr\")")]
    InvalidCongestionControl,
    #[cfg(unix)]
    #[error(
        "config file permissions are insecure for {path:?}: mode {mode:o}, owner uid {uid}, \
         current uid {euid}; expected owner=current user and no group/world permission bits"
    )]
    InsecureConfigPermissions {
        path: PathBuf,
        mode: u32,
        uid: u32,
        euid: u32,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub mode: Mode,
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub traffic: TrafficConfig,
    pub client: Option<ClientConfig>,
    pub server: Option<ServerConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Client,
    Server,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client => f.write_str("client"),
            Self::Server => f.write_str("server"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    /// Base64-encoded pre-shared secret. Require at least 32 bytes after decode.
    pub psk: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server_addr: String,
    pub sni: String,
    pub server_public_key: String,
    #[serde(default)]
    pub server_pq_public_key: String,
    pub server_identity_public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub fallback_addr: String,
    #[serde(default)]
    pub data_target: Option<String>,
    pub private_key: String,
    #[serde(default)]
    pub pq_secret_key: String,
    pub identity_secret_key: String,
    #[serde(default = "default_replay_cache_path")]
    pub replay_cache_path: PathBuf,
    #[serde(default = "default_replay_cache_capacity")]
    pub replay_cache_capacity: usize,
    #[serde(default)]
    pub authorized_sni: Vec<String>,
    #[serde(default = "default_true")]
    pub strict_tls13: bool,
    /// Max concurrent connections from one IPv4 /32 source. A concurrency cap,
    /// not a rate limit; defaults high so legitimate shared/CGNAT addresses are
    /// not throttled (the global limit is the real backstop).
    #[serde(default = "default_max_concurrent_per_source")]
    pub max_concurrent_per_source_v4: u32,
    /// Max concurrent connections from one IPv6 prefix (see
    /// `source_ipv6_prefix_len`). Independent of the v4 cap because a prefix
    /// aggregates many more endpoints (carrier NAT64/464XLAT, /64-per-VM).
    #[serde(default = "default_max_concurrent_per_source")]
    pub max_concurrent_per_source_v6: u32,
    /// IPv6 prefix length used to group sources for the per-source cap.
    #[serde(default = "default_source_ipv6_prefix_len")]
    pub source_ipv6_prefix_len: u8,
    /// Floor (ms) for the client-facing first-record wait. Default 8000.
    #[serde(default = "default_first_record_wait_floor_ms")]
    pub first_record_wait_floor_ms: u64,
    /// Upward jitter (ms) added to the first-record wait floor. Default 7000.
    #[serde(default = "default_first_record_wait_jitter_ms")]
    pub first_record_wait_jitter_ms: u64,
    /// Floor (ms) for the camouflage relay idle backstop. A resource backstop,
    /// not a behavioral policy. NOTE: the idle timer RESETS on every byte in
    /// either direction, so this is a per-gap cap, not a total-session cap -- it
    /// only fires on a connection that goes fully silent. Keep it well above any
    /// plausible inter-packet gap of a real relay (min enforced 5000ms) so
    /// ParallaX does not originate closes on active-but-bursty connections.
    /// Default 600000 (10 min).
    #[serde(default = "default_fallback_idle_floor_ms")]
    pub fallback_idle_floor_ms: u64,
    /// Upward jitter (ms) on the idle backstop. Default 0 and discouraged: a
    /// uniform idle-close band is itself a synthetic signature no real origin
    /// produces (the floor, not the ceiling, is what a prober converges to).
    #[serde(default = "default_fallback_idle_jitter_ms")]
    pub fallback_idle_jitter_ms: u64,
    /// Optional TCP congestion-control algorithm to request on relay sockets, to
    /// match the camouflage origin's CDN (e.g. "bbr", "cubic"). Linux only; a
    /// no-op on other platforms. `None` keeps the built-in default. The kernel
    /// must have the algorithm available or the request is logged and ignored
    /// (verified via getsockopt read-back).
    #[serde(default)]
    pub tcp_congestion: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct TrafficConfig {
    #[serde(default)]
    pub min_padding: u16,
    #[serde(default = "default_max_padding")]
    pub max_padding: u16,
    #[serde(default)]
    pub min_delay_ms: u16,
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u16,
    #[serde(default = "default_cover_min_interval_ms")]
    pub cover_min_interval_ms: u16,
    #[serde(default = "default_cover_max_interval_ms")]
    pub cover_max_interval_ms: u16,
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u8,
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self {
            min_padding: 0,
            max_padding: default_max_padding(),
            min_delay_ms: 0,
            max_delay_ms: default_max_delay_ms(),
            cover_min_interval_ms: default_cover_min_interval_ms(),
            cover_max_interval_ms: default_cover_max_interval_ms(),
            max_concurrent_streams: default_max_concurrent_streams(),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = Zeroizing::new(fs::read_to_string(path)?);
        let mut cfg = toml::from_str::<Self>(raw.as_str())?;
        cfg.resolve_paths_relative_to(path);
        cfg.validate()?;
        cfg.validate_file_permissions(path)?;
        Ok(cfg)
    }

    pub fn protect_secret_memory(&self) {
        crate::process_hardening::protect_secret_bytes(
            "config.crypto.psk",
            self.crypto.psk.as_bytes(),
        );
        if let Some(server) = &self.server {
            crate::process_hardening::protect_secret_bytes(
                "config.server.private_key",
                server.private_key.as_bytes(),
            );
            if !server.pq_secret_key.is_empty() {
                crate::process_hardening::protect_secret_bytes(
                    "config.server.pq_secret_key",
                    server.pq_secret_key.as_bytes(),
                );
            }
            crate::process_hardening::protect_secret_bytes(
                "config.server.identity_secret_key",
                server.identity_secret_key.as_bytes(),
            );
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        decode_psk(&self.crypto.psk)?;
        self.traffic.validate()?;

        match self.mode {
            Mode::Client => {
                let client = self.client.as_ref().ok_or(ConfigError::MissingClient)?;
                if !client.listen.ip().is_loopback() {
                    return Err(ConfigError::UnsafeClientListen(client.listen));
                }
                require_host_port("client.server_addr", &client.server_addr)?;
                require_non_empty("client.sni", &client.sni)?;
                decode_key32("client.server_public_key", &client.server_public_key)?;
                if !client.server_pq_public_key.is_empty() {
                    decode_base64_bytes_exact(
                        "client.server_pq_public_key",
                        &client.server_pq_public_key,
                        mlkem1024::public_key_bytes(),
                    )?;
                }
                decode_base64_bytes_exact(
                    "client.server_identity_public_key",
                    &client.server_identity_public_key,
                    mldsa87::public_key_bytes(),
                )?;
            }
            Mode::Server => {
                let server = self.server.as_ref().ok_or(ConfigError::MissingServer)?;
                require_host_port("server.fallback_addr", &server.fallback_addr)?;
                if let Some(data_target) = &server.data_target {
                    require_host_port("server.data_target", data_target)?;
                }
                decode_key32_secret("server.private_key", &server.private_key)?;
                if !server.pq_secret_key.is_empty() {
                    decode_base64_secret_exact(
                        "server.pq_secret_key",
                        &server.pq_secret_key,
                        mlkem1024::secret_key_bytes(),
                    )?;
                }
                decode_base64_secret_exact(
                    "server.identity_secret_key",
                    &server.identity_secret_key,
                    mldsa87::secret_key_bytes(),
                )?;
                if server.authorized_sni.is_empty() {
                    return Err(ConfigError::EmptyAuthorizedSni);
                }
                for sni in &server.authorized_sni {
                    require_non_empty("server.authorized_sni", sni)?;
                }
                if server.replay_cache_capacity == 0 {
                    return Err(ConfigError::InvalidReplayCacheCapacity);
                }
                if server.max_concurrent_per_source_v4 == 0
                    || server.max_concurrent_per_source_v6 == 0
                {
                    return Err(ConfigError::InvalidSourceConcurrencyLimit);
                }
                if server.source_ipv6_prefix_len == 0 || server.source_ipv6_prefix_len > 128 {
                    return Err(ConfigError::InvalidSourceIpv6Prefix);
                }
                // The first-record wait is a one-shot give-up; 250ms is a safe
                // lower bound. The idle backstop resets on every byte, so a tiny
                // value would close active-but-bursty relays on any short gap --
                // ParallaX originating the close is exactly the tell we avoid --
                // hence a much higher minimum.
                if server.first_record_wait_floor_ms < 250 {
                    return Err(ConfigError::InvalidTimeoutFloor);
                }
                if server.fallback_idle_floor_ms < 5_000 {
                    return Err(ConfigError::InvalidIdleBackstop);
                }
                if let Some(algorithm) = &server.tcp_congestion {
                    let valid = !algorithm.is_empty()
                        && algorithm.len() <= 15
                        && algorithm
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
                    if !valid {
                        return Err(ConfigError::InvalidCongestionControl);
                    }
                }
            }
        }

        Ok(())
    }

    fn resolve_paths_relative_to(&mut self, config_path: &Path) {
        let Some(server) = self.server.as_mut() else {
            return;
        };
        if server.replay_cache_path.is_absolute() {
            return;
        }

        let config_dir = config_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        server.replay_cache_path = config_dir.join(&server.replay_cache_path);
    }

    fn validate_file_permissions(&self, path: &Path) -> Result<(), ConfigError> {
        validate_secret_config_file_permissions(path)
    }
}

#[cfg(unix)]
fn validate_secret_config_file_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)?;
    let mode = metadata.mode() & 0o777;
    let uid = metadata.uid();
    let euid = unsafe { libc::geteuid() };
    if mode & 0o077 != 0 || uid != euid {
        return Err(ConfigError::InsecureConfigPermissions {
            path: path.to_path_buf(),
            mode,
            uid,
            euid,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_config_file_permissions(_path: &Path) -> Result<(), ConfigError> {
    Ok(())
}

impl TrafficConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_padding < self.min_padding {
            return Err(ConfigError::InvalidPaddingRange);
        }
        if crate::protocol::data::max_plaintext_len(self.max_padding) == 0 {
            return Err(ConfigError::ExcessivePadding);
        }
        if self.max_delay_ms < self.min_delay_ms {
            return Err(ConfigError::InvalidDelayRange);
        }
        if self.cover_max_interval_ms < self.cover_min_interval_ms {
            return Err(ConfigError::InvalidCoverIntervalRange);
        }
        if self.max_concurrent_streams == 0 {
            return Err(ConfigError::InvalidMaxConcurrentStreams);
        }
        Ok(())
    }
}

pub fn decode_psk(value: &str) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|source| ConfigError::InvalidBase64 {
            field: "crypto.psk",
            source,
        })?;
    if decoded.len() < 32 {
        return Err(ConfigError::WeakPsk);
    }
    Ok(Zeroizing::new(decoded))
}

pub fn decode_key32(field: &'static str, value: &str) -> Result<[u8; 32], ConfigError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|source| ConfigError::InvalidBase64 { field, source })?;
    decoded
        .try_into()
        .map_err(|_| ConfigError::InvalidKeyLen { field })
}

pub fn decode_key32_secret(
    field: &'static str,
    value: &str,
) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|source| ConfigError::InvalidBase64 { field, source })?,
    );
    if decoded.len() != 32 {
        return Err(ConfigError::InvalidKeyLen { field });
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&decoded);
    Ok(Zeroizing::new(out))
}

pub fn decode_base64_bytes(field: &'static str, value: &str) -> Result<Vec<u8>, ConfigError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ConfigError::InvalidBytes { field })?;
    if decoded.is_empty() {
        return Err(ConfigError::InvalidBytes { field });
    }
    Ok(decoded)
}

pub fn decode_base64_secret(
    field: &'static str,
    value: &str,
) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ConfigError::InvalidBytes { field })?;
    if decoded.is_empty() {
        return Err(ConfigError::InvalidBytes { field });
    }
    Ok(Zeroizing::new(decoded))
}

pub fn decode_base64_bytes_exact(
    field: &'static str,
    value: &str,
    expected: usize,
) -> Result<Vec<u8>, ConfigError> {
    let decoded = decode_base64_bytes(field, value)?;
    if decoded.len() != expected {
        return Err(ConfigError::InvalidBytesLen {
            field,
            expected,
            actual: decoded.len(),
        });
    }
    Ok(decoded)
}

pub fn decode_base64_secret_exact(
    field: &'static str,
    value: &str,
    expected: usize,
) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    let decoded = decode_base64_secret(field, value)?;
    if decoded.len() != expected {
        return Err(ConfigError::InvalidBytesLen {
            field,
            expected,
            actual: decoded.len(),
        });
    }
    Ok(decoded)
}

fn require_host_port(field: &'static str, value: &str) -> Result<(), ConfigError> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(ConfigError::InvalidSocket {
            field,
            value: value.to_owned(),
        });
    };
    if host.trim().is_empty() || !matches!(port.parse::<u16>(), Ok(port) if port != 0) {
        return Err(ConfigError::InvalidSocket {
            field,
            value: value.to_owned(),
        });
    }
    let bracketed = host.starts_with('[') || host.ends_with(']');
    if bracketed && !(host.starts_with('[') && host.ends_with(']') && host.len() > 2) {
        return Err(ConfigError::InvalidSocket {
            field,
            value: value.to_owned(),
        });
    }
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return Err(ConfigError::InvalidSocket {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        Err(ConfigError::InvalidSocket {
            field,
            value: value.to_owned(),
        })
    } else {
        Ok(())
    }
}

const fn default_true() -> bool {
    true
}

const fn default_max_padding() -> u16 {
    0
}

const fn default_max_delay_ms() -> u16 {
    0
}

const fn default_cover_min_interval_ms() -> u16 {
    0
}

const fn default_cover_max_interval_ms() -> u16 {
    0
}

const fn default_max_concurrent_streams() -> u8 {
    4
}

fn default_replay_cache_path() -> PathBuf {
    PathBuf::from(DEFAULT_REPLAY_CACHE_PATH)
}

const fn default_replay_cache_capacity() -> usize {
    DEFAULT_REPLAY_CACHE_CAPACITY
}

const fn default_max_concurrent_per_source() -> u32 {
    256
}

const fn default_source_ipv6_prefix_len() -> u8 {
    64
}

const fn default_first_record_wait_floor_ms() -> u64 {
    8_000
}

const fn default_first_record_wait_jitter_ms() -> u64 {
    7_000
}

const fn default_fallback_idle_floor_ms() -> u64 {
    600_000
}

const fn default_fallback_idle_jitter_ms() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn validates_client_config() {
        let server_pq_public_key = STANDARD.encode(vec![0_u8; mlkem1024::public_key_bytes()]);
        let server_identity_public_key = STANDARD.encode(vec![0_u8; mldsa87::public_key_bytes()]);
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{KEY}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_pq_public_key = "{server_pq_public_key}"
server_identity_public_key = "{server_identity_public_key}"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn validates_configs_without_legacy_static_pq_keys() {
        let identity_public_key = STANDARD.encode(vec![0_u8; mldsa87::public_key_bytes()]);
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let client_raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{KEY}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{identity_public_key}"
"#
        );
        toml::from_str::<Config>(&client_raw)
            .unwrap()
            .validate()
            .unwrap();

        let server_raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
"#
        );
        toml::from_str::<Config>(&server_raw)
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn traffic_defaults_are_speed_first() {
        let traffic = TrafficConfig::default();

        assert_eq!(traffic.min_padding, 0);
        assert_eq!(traffic.max_padding, 0);
        assert_eq!(traffic.min_delay_ms, 0);
        assert_eq!(traffic.max_delay_ms, 0);
        assert_eq!(traffic.cover_min_interval_ms, 0);
        assert_eq!(traffic.cover_max_interval_ms, 0);
        assert_eq!(traffic.max_concurrent_streams, 4);
    }

    #[test]
    fn rejects_non_loopback_client_listener() {
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{KEY}"

[client]
listen = "0.0.0.0:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_pq_public_key = "{KEY}"
server_identity_public_key = "{KEY}"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();

        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::UnsafeClientListen(_)
        ));
    }

    #[test]
    fn rejects_weak_psk() {
        let err = decode_psk("AA==").unwrap_err();
        assert!(matches!(err, ConfigError::WeakPsk));
    }

    #[test]
    fn rejects_bad_padding_range() {
        let traffic = TrafficConfig {
            min_padding: 10,
            max_padding: 1,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            traffic.validate().unwrap_err(),
            ConfigError::InvalidPaddingRange
        ));
    }

    #[test]
    fn rejects_padding_that_leaves_no_payload_room() {
        let traffic = TrafficConfig {
            max_padding: u16::MAX,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            traffic.validate().unwrap_err(),
            ConfigError::ExcessivePadding
        ));
    }

    #[test]
    fn accepts_multiplexing_stream_count() {
        let traffic = TrafficConfig {
            max_concurrent_streams: 2,
            ..TrafficConfig::default()
        };
        traffic.validate().unwrap();
    }

    #[test]
    fn rejects_zero_multiplexing_stream_count() {
        let traffic = TrafficConfig {
            max_concurrent_streams: 0,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            traffic.validate().unwrap_err(),
            ConfigError::InvalidMaxConcurrentStreams
        ));
    }

    #[test]
    fn rejects_bad_cover_interval_range() {
        let traffic = TrafficConfig {
            cover_min_interval_ms: 100,
            cover_max_interval_ms: 10,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            traffic.validate().unwrap_err(),
            ConfigError::InvalidCoverIntervalRange
        ));
    }

    #[cfg(unix)]
    #[test]
    fn server_config_load_enforces_secret_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
"#
        );
        fs::write(&path, raw).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::InsecureConfigPermissions { .. })
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        Config::load(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn client_config_load_enforces_secret_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.toml");
        let server_pq_public_key = STANDARD.encode(vec![0_u8; mlkem1024::public_key_bytes()]);
        let server_identity_public_key = STANDARD.encode(vec![0_u8; mldsa87::public_key_bytes()]);
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{KEY}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_pq_public_key = "{server_pq_public_key}"
server_identity_public_key = "{server_identity_public_key}"
"#
        );
        fs::write(&path, raw).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::InsecureConfigPermissions { .. })
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        Config::load(&path).unwrap();
    }

    #[test]
    fn server_replay_cache_default_uses_writable_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
"#
        );
        fs::write(&path, raw).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let cfg = Config::load(&path).unwrap();
        let server = cfg.server.unwrap();

        assert_eq!(
            server.replay_cache_path,
            PathBuf::from(DEFAULT_REPLAY_CACHE_PATH)
        );
    }

    #[test]
    fn rejects_malformed_host_port() {
        let err = require_host_port("client.server_addr", "example.com:").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidSocket { .. }));

        let err = require_host_port("client.server_addr", ":443").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidSocket { .. }));

        let err = require_host_port("client.server_addr", "::1:443").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidSocket { .. }));

        let err = require_host_port("client.server_addr", "example.com:0").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidSocket { .. }));

        require_host_port("client.server_addr", "[::1]:443").unwrap();
        require_host_port("client.server_addr", "example.com:443").unwrap();
    }

    #[test]
    fn rejects_wrong_pq_key_length_during_validation() {
        let err = decode_base64_bytes_exact(
            "client.server_pq_public_key",
            KEY,
            mlkem1024::public_key_bytes(),
        )
        .unwrap_err();
        match err {
            ConfigError::InvalidBytesLen {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "client.server_pq_public_key");
                assert_eq!(expected, mlkem1024::public_key_bytes());
                assert_eq!(actual, 32);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn mode_display_is_serde_consistent() {
        assert_eq!(Mode::Client.to_string(), "client");
        assert_eq!(Mode::Server.to_string(), "server");
    }

    #[test]
    fn decode_key32_rejects_invalid_base64_and_wrong_length() {
        let err = decode_key32("client.server_public_key", "***not-base64***").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidBase64 {
                field: "client.server_public_key",
                ..
            }
        ));

        // Two valid base64 bytes -> length mismatch.
        let err = decode_key32("client.server_public_key", "AAA=").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidKeyLen {
                field: "client.server_public_key"
            }
        ));
    }

    #[test]
    fn decode_key32_secret_rejects_invalid_base64_and_wrong_length() {
        let err = decode_key32_secret("server.private_key", "***not-base64***").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidBase64 {
                field: "server.private_key",
                ..
            }
        ));
        let err = decode_key32_secret("server.private_key", "AAA=").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidKeyLen {
                field: "server.private_key"
            }
        ));

        let key = decode_key32_secret("server.private_key", KEY).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn decode_base64_bytes_rejects_invalid_base64_and_empty_value() {
        let err = decode_base64_bytes("crypto.psk", "***").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidBytes {
                field: "crypto.psk"
            }
        ));
        let err = decode_base64_bytes("crypto.psk", "").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidBytes {
                field: "crypto.psk"
            }
        ));
    }

    #[test]
    fn decode_base64_secret_rejects_invalid_base64_and_empty_value() {
        let err = decode_base64_secret("server.identity_secret_key", "***").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidBytes {
                field: "server.identity_secret_key"
            }
        ));
        let err = decode_base64_secret("server.identity_secret_key", "").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidBytes {
                field: "server.identity_secret_key"
            }
        ));
    }

    #[test]
    fn require_non_empty_rejects_whitespace_only() {
        assert!(matches!(
            require_non_empty("client.sni", "   ").unwrap_err(),
            ConfigError::InvalidSocket { .. }
        ));
        assert!(require_non_empty("client.sni", "example.com").is_ok());
    }

    #[test]
    fn rejects_bad_delay_range() {
        let traffic = TrafficConfig {
            min_delay_ms: 50,
            max_delay_ms: 1,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            traffic.validate().unwrap_err(),
            ConfigError::InvalidDelayRange
        ));
    }

    #[test]
    fn server_replay_cache_path_is_resolved_relative_to_config() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("conf");
        fs::create_dir(&nested).unwrap();
        let path = nested.join("server.toml");
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
replay_cache_path = "state/replay.cache"
authorized_sni = ["example.com"]
"#
        );
        fs::write(&path, raw).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let cfg = Config::load(&path).unwrap();
        let server = cfg.server.unwrap();
        assert_eq!(server.replay_cache_path, nested.join("state/replay.cache"));
    }

    #[test]
    fn server_validate_rejects_empty_authorized_sni_entry() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["  "]
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::InvalidSocket { .. }
        ));
    }

    #[test]
    fn server_replay_cache_capacity_defaults_when_omitted() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.server.unwrap().replay_cache_capacity,
            DEFAULT_REPLAY_CACHE_CAPACITY
        );
    }

    #[test]
    fn server_timeout_fields_default_when_omitted() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
        let server = cfg.server.unwrap();
        assert_eq!(server.first_record_wait_floor_ms, 8_000);
        assert_eq!(server.first_record_wait_jitter_ms, 7_000);
        assert_eq!(server.fallback_idle_floor_ms, 600_000);
        assert_eq!(server.fallback_idle_jitter_ms, 0);
        assert!(server.tcp_congestion.is_none());
    }

    #[test]
    fn server_validate_rejects_sub_minimum_timeout_floor() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
first_record_wait_floor_ms = 100
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::InvalidTimeoutFloor
        ));
    }

    #[test]
    fn server_validate_rejects_tiny_idle_backstop() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
fallback_idle_floor_ms = 1000
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::InvalidIdleBackstop
        ));
    }

    #[test]
    fn server_validate_rejects_bogus_tcp_congestion() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        for bogus in ["\"\"", "\"bbr xtls\"", "\"a;b\""] {
            let raw = format!(
                r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
tcp_congestion = {bogus}
"#
            );
            let cfg = toml::from_str::<Config>(&raw).unwrap();
            assert!(
                matches!(
                    cfg.validate().unwrap_err(),
                    ConfigError::InvalidCongestionControl
                ),
                "expected rejection for tcp_congestion = {bogus}"
            );
        }
    }

    #[test]
    fn server_validate_accepts_plausible_tcp_congestion() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
tcp_congestion = "cubic"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.server.unwrap().tcp_congestion.as_deref(), Some("cubic"));
    }

    #[test]
    fn server_replay_cache_capacity_parses_override() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
replay_cache_capacity = 65536
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.server.unwrap().replay_cache_capacity, 65536);
    }

    #[test]
    fn server_validate_rejects_zero_replay_cache_capacity() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
replay_cache_capacity = 0
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::InvalidReplayCacheCapacity
        ));
    }

    #[test]
    fn server_validate_rejects_bad_data_target() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa87::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
data_target = "not-a-host-port"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::InvalidSocket { .. }
        ));
    }

    #[test]
    fn missing_server_section_in_server_mode_is_rejected() {
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{KEY}"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::MissingServer
        ));
    }

    #[test]
    fn missing_client_section_in_client_mode_is_rejected() {
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{KEY}"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::MissingClient
        ));
    }

    #[test]
    fn config_load_propagates_toml_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        fs::write(&path, "this is = not valid = toml").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(Config::load(&path), Err(ConfigError::Toml(_))));
    }

    #[test]
    fn config_load_propagates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.toml");
        assert!(matches!(Config::load(&missing), Err(ConfigError::Read(_))));
    }
}
