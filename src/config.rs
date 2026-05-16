use std::{
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::tls::client_hello_builder::BrowserProfile;

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
    #[error("traffic.max_concurrent_streams must be 1 until multiplexing has fingerprint-safe scheduling")]
    UnsupportedMultiplexing,
    #[error("server.authorized_sni must not be empty")]
    EmptyAuthorizedSni,
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
    pub server_pq_public_key: String,
    pub server_identity_public_key: String,
    #[serde(default)]
    pub tls_profile: BrowserProfile,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub fallback_addr: String,
    #[serde(default)]
    pub data_target: Option<String>,
    pub private_key: String,
    pub pq_secret_key: String,
    pub identity_secret_key: String,
    #[serde(default = "default_replay_cache_path")]
    pub replay_cache_path: PathBuf,
    #[serde(default)]
    pub authorized_sni: Vec<String>,
    #[serde(default = "default_true")]
    pub strict_tls13: bool,
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
        let raw = fs::read_to_string(path)?;
        let cfg = toml::from_str::<Self>(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        decode_psk(&self.crypto.psk)?;
        self.traffic.validate()?;

        match self.mode {
            Mode::Client => {
                let client = self.client.as_ref().ok_or(ConfigError::MissingClient)?;
                require_host_port("client.server_addr", &client.server_addr)?;
                require_non_empty("client.sni", &client.sni)?;
                decode_key32("client.server_public_key", &client.server_public_key)?;
                decode_base64_bytes("client.server_pq_public_key", &client.server_pq_public_key)?;
                decode_base64_bytes(
                    "client.server_identity_public_key",
                    &client.server_identity_public_key,
                )?;
            }
            Mode::Server => {
                let server = self.server.as_ref().ok_or(ConfigError::MissingServer)?;
                require_host_port("server.fallback_addr", &server.fallback_addr)?;
                if let Some(data_target) = &server.data_target {
                    require_host_port("server.data_target", data_target)?;
                }
                decode_key32("server.private_key", &server.private_key)?;
                decode_base64_bytes("server.pq_secret_key", &server.pq_secret_key)?;
                decode_base64_bytes("server.identity_secret_key", &server.identity_secret_key)?;
                if server.authorized_sni.is_empty() {
                    return Err(ConfigError::EmptyAuthorizedSni);
                }
                for sni in &server.authorized_sni {
                    require_non_empty("server.authorized_sni", sni)?;
                }
            }
        }

        Ok(())
    }
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
        if self.max_concurrent_streams != 1 {
            return Err(ConfigError::UnsupportedMultiplexing);
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

pub fn decode_base64_bytes(field: &'static str, value: &str) -> Result<Vec<u8>, ConfigError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ConfigError::InvalidBytes { field })?;
    if decoded.is_empty() {
        return Err(ConfigError::InvalidBytes { field });
    }
    Ok(decoded)
}

fn require_host_port(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.rsplit_once(':').is_some() {
        Ok(())
    } else {
        Err(ConfigError::InvalidSocket {
            field,
            value: value.to_owned(),
        })
    }
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
    128
}

const fn default_max_delay_ms() -> u16 {
    12
}

const fn default_cover_min_interval_ms() -> u16 {
    15_000
}

const fn default_cover_max_interval_ms() -> u16 {
    45_000
}

const fn default_max_concurrent_streams() -> u8 {
    1
}

fn default_replay_cache_path() -> PathBuf {
    PathBuf::from("parallax-replay.cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn validates_client_config() {
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
server_pq_public_key = "{KEY}"
server_identity_public_key = "{KEY}"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
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
    fn rejects_multiplexing_until_safe() {
        let traffic = TrafficConfig {
            max_concurrent_streams: 2,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            traffic.validate().unwrap_err(),
            ConfigError::UnsupportedMultiplexing
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
}
