use std::{
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use crate::crypto::mldsa;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{de, Deserialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub(crate) const DEFAULT_REPLAY_CACHE_PATH: &str = "/var/lib/parallax/parallax-replay.cache";
/// Default authenticated-replay-cache capacity. Sized against the freshness
/// window: entries are retained for `replay_freshness_window_secs()` (= the
/// pre-PQ deadline + skew, ~720s with the default `fallback_idle_floor_ms`), so
/// the cache fills at roughly `capacity / window` sustained handshakes/sec before
/// it fail-CLOSES with `CacheFull` (sheds new handshakes — never a replay hole).
/// 49152 / 720s ≈ 68 conn/s of headroom; this scales with the window so widening
/// the pre-PQ deadline did not silently lower the throughput cliff. A busy shared
/// bridge above that rate (or one that raises `fallback_idle_floor_ms` further)
/// should raise `replay_cache_capacity` proportionally.
pub(crate) const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 49152;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse TOML at line {line}, column {column} (content redacted)")]
    Toml { line: usize, column: usize },
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
    #[error("{field}: a secret reference must set exactly one of `file`, `env`, or `sealed`")]
    SecretReference { field: &'static str },
    #[error("{field}: failed to read the referenced secret (missing file/env, bad permissions, or unknown entry)")]
    SecretRead { field: &'static str },
    #[error("{field}: failed to open the sealed secret (wrong host key, tampered bundle, or missing entry)")]
    SecretSeal { field: &'static str },
    #[error("{field}: cannot open the sealed secret because the host keyfile is missing or has insecure permissions; set $PARALLAX_HOST_KEY_FILE (or place the keyfile at /var/lib/parallax/host.key) to the host key used by `plx seal`")]
    SecretHostKey { field: &'static str },
    #[error(
        "crypto.psk appears to have low entropy; a server refuses to start with a \
         guessable PSK. Generate a CSPRNG key with `plx init` or \
         `openssl rand -base64 32`"
    )]
    LowEntropyPsk,
    #[error("traffic.max_padding must be >= traffic.min_padding")]
    InvalidPaddingRange,
    #[error("traffic.max_padding leaves too little room for encrypted payload")]
    ExcessivePadding,
    #[error("traffic.max_delay_ms must be >= traffic.min_delay_ms")]
    InvalidDelayRange,
    #[error("traffic.cover_max_interval_ms must be >= traffic.cover_min_interval_ms")]
    InvalidCoverIntervalRange,
    #[error(
        "traffic cover traffic requires a non-degenerate padding range \
         (max_padding > min_padding) so cover records vary in size; otherwise \
         every cover record is an identical-length beacon"
    )]
    CoverRequiresVariablePadding,
    #[error("traffic.cover_min_interval_ms must be at least {min_ms} ms when cover traffic is enabled (cover_max_interval_ms > 0); near-zero intervals hot-spin the cover loop and emit a high-rate, fingerprintable beacon")]
    CoverIntervalTooSmall { min_ms: u16 },
    #[error("traffic.max_concurrent_streams must be at least 1")]
    InvalidMaxConcurrentStreams,
    #[error("udp.probe_timeout_ms must be at least 1")]
    InvalidUdpProbeTimeout,
    #[error(
        "udp.cc = \"brutal\" requires udp.brutal_up_mbps and udp.brutal_down_mbps > 0 \
         unless udp.ignore_client_bandwidth is set"
    )]
    UdpBrutalMissingBandwidth,
    #[error("udp.max_udp_payload_bytes must be at least {MIN_UDP_PAYLOAD_BYTES} (the RFC 9000 §14.1 Initial minimum)")]
    UdpMaxPayloadTooSmall,
    #[error("udp.max_udp_payload_bytes must be at most {MAX_UDP_PAYLOAD_BYTES} (the maximum UDP datagram payload)")]
    UdpMaxPayloadTooLarge,
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
    #[error("server.first_record_wait_floor_ms must not exceed 300000ms (it is a short give-up backstop for the first client record, not the idle cap)")]
    InvalidTimeoutCeiling,
    #[error("server.fallback_idle_floor_ms must be at least 5000ms (it resets on every byte; a tiny value closes active relays)")]
    InvalidIdleBackstop,
    #[error("server timeout jitter must not exceed 300000ms")]
    InvalidTimeoutJitter,
    #[error("server.tcp_congestion must be a short algorithm name (letters, digits, '_' or '-'), e.g. \"bbr\"")]
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

impl ConfigError {
    /// True when secret resolution failed *because the source is unavailable* on
    /// this host (missing/insecure host key, or a missing sidecar file / env var /
    /// bundle entry) — as opposed to a malformed reference. `plx check` treats
    /// these as "cannot decrypt here" and degrades to a structure-only check.
    fn is_secret_unavailable(&self) -> bool {
        matches!(
            self,
            ConfigError::SecretHostKey { .. }
                | ConfigError::SecretRead { .. }
                | ConfigError::SecretSeal { .. }
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub traffic: TrafficConfig,
    #[serde(default)]
    pub udp: UdpConfig,
    #[serde(default)]
    pub transport: TransportConfig,
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
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    /// Pre-shared secret (≥32 bytes after base64 decode). May be inline base64 or
    /// an indirect [`SecretSource`] reference (`file`/`env`/`sealed`).
    ///
    /// The PSK is one of the two secrets the auth scheme and the initial session
    /// key derivation rest on, so it MUST be CSPRNG-generated (`plx init` or
    /// `openssl rand -base64 32`). A low-entropy / guessable PSK is rejected at
    /// startup on a server in any build profile (`ConfigError::LowEntropyPsk`);
    /// client mode only warns.
    pub psk: SecretSource,
}

/// Where a long-lived secret's bytes come from. Deserializes from **either** an
/// inline base64 string (back-compat, discouraged — makes the config a bearer
/// credential) **or** an indirection table:
///
/// ```toml
/// psk = "base64=="                                   # inline
/// psk = { file = "parallax.secrets.toml#psk" }       # 0600 sidecar file
/// psk = { env = "PARALLAX_PSK" }                      # environment / systemd cred
/// psk = { sealed = "parallax.secrets.enc#psk" }      # machine-bound encrypted
/// ```
///
/// `Config::load` resolves every source to its base64 text once, up front, so the
/// rest of the runtime keeps consuming the same bytes regardless of where they
/// came from. After resolution the variant is [`SecretSource::Resolved`].
#[derive(Clone)]
pub enum SecretSource {
    /// Literal base64 written straight into the config.
    Inline(String),
    /// An unresolved indirection (`file`/`env`/`sealed`); resolved at load time.
    Reference(SecretRef),
    /// The resolved base64 text plus whether it originated inline (for warnings).
    Resolved(ResolvedSecret),
}

/// Resolved secret text and provenance. The base64 lives in `Zeroizing` so it is
/// scrubbed on drop.
#[derive(Clone)]
pub struct ResolvedSecret {
    b64: Zeroizing<String>,
    was_inline: bool,
}

/// Indirection table for a secret: exactly one of the fields must be set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    env: Option<String>,
    #[serde(default)]
    sealed: Option<String>,
}

impl fmt::Debug for SecretSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render secret bytes through Debug — only the shape.
        match self {
            Self::Inline(_) => f.write_str("Inline(<redacted>)"),
            Self::Resolved(r) => f
                .debug_struct("Resolved")
                .field("was_inline", &r.was_inline)
                .finish_non_exhaustive(),
            Self::Reference(r) => f.debug_tuple("Reference").field(r).finish(),
        }
    }
}

impl From<String> for SecretSource {
    fn from(value: String) -> Self {
        Self::Inline(value)
    }
}

impl From<&str> for SecretSource {
    fn from(value: &str) -> Self {
        Self::Inline(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for SecretSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct SecretVisitor;

        impl<'de> de::Visitor<'de> for SecretVisitor {
            type Value = SecretSource;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a base64 string or a { file | env | sealed } table")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SecretSource::Inline(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SecretSource::Inline(v))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let reference = SecretRef::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(SecretSource::Reference(reference))
            }
        }

        deserializer.deserialize_any(SecretVisitor)
    }
}

impl SecretSource {
    /// The resolved base64 secret text. Inline/Resolved variants return their
    /// bytes; an unresolved `Reference` returns `""` (it is always resolved
    /// before any consumer reads it — see `Config::load`).
    pub fn as_b64(&self) -> &str {
        match self {
            Self::Inline(s) => s,
            Self::Resolved(r) => &r.b64,
            Self::Reference(_) => "",
        }
    }

    /// Whether this secret is (or was) stored inline in the config file, i.e. the
    /// config file itself carries the secret. Drives the `plx check` warning.
    pub fn is_inline_secret(&self) -> bool {
        match self {
            Self::Inline(_) => true,
            Self::Resolved(r) => r.was_inline,
            Self::Reference(_) => false,
        }
    }

    /// If this secret is an unresolved `{ file = "<path>#<frag>" }` reference, the
    /// sidecar path part (without the `#fragment`). `plx seal` uses this to delete
    /// the plaintext sidecar after sealing its secret. Only meaningful before
    /// resolution (a [`SecretSource::Resolved`] no longer remembers its origin).
    pub(crate) fn file_reference_path(&self) -> Option<&str> {
        match self {
            Self::Reference(r) => r
                .file
                .as_deref()
                .map(|spec| crate::secret_store::split_fragment(spec).0),
            _ => None,
        }
    }

    /// Resolve any indirection in place, reading `file`/`env`/`sealed` sources.
    /// `base` is the config directory used to resolve relative reference paths.
    fn resolve_in_place(&mut self, field: &'static str, base: &Path) -> Result<(), ConfigError> {
        let resolved = match self {
            Self::Resolved(_) => return Ok(()),
            Self::Inline(s) => ResolvedSecret {
                // Move the inline string out rather than cloning it, so we don't
                // leave a second, non-zeroized heap copy of the secret behind.
                b64: Zeroizing::new(std::mem::take(s)),
                was_inline: true,
            },
            Self::Reference(reference) => ResolvedSecret {
                b64: reference.resolve(field, base)?,
                was_inline: false,
            },
        };
        *self = Self::Resolved(resolved);
        Ok(())
    }
}

/// One long-lived secret field of a [`Config`], with every name a secret-handling
/// site needs. This is the single authoritative description of a secret: the
/// resolution, inline-detection, memory-protection, and `plx seal` paths all
/// enumerate secrets through [`Config::secret_sources`] so a newly added secret
/// cannot silently skip sealing or scrubbing.
pub(crate) struct SecretFieldRef<'a> {
    /// Dotted config path (`crypto.psk`): resolution-error field, inline warning.
    pub dotted: &'static str,
    /// Bare TOML key (`psk`): the sealed-bundle entry key / reference `#fragment`
    /// and the assignment the config rewriter targets.
    pub seal_key: &'static str,
    /// Static label for `protect_secret_bytes` (`config.crypto.psk`).
    pub mem_label: &'static str,
    pub source: &'a SecretSource,
}

impl SecretRef {
    fn resolve(&self, field: &'static str, base: &Path) -> Result<Zeroizing<String>, ConfigError> {
        match (
            self.file.as_deref(),
            self.env.as_deref(),
            self.sealed.as_deref(),
        ) {
            (Some(spec), None, None) => resolve_file_secret(base, spec, field),
            (None, Some(name), None) => resolve_env_secret(name, field),
            (None, None, Some(spec)) => {
                crate::secret_store::open_sealed_reference(base, spec, None).map_err(|err| {
                    tracing::debug!(%field, error = %err, "failed to open sealed secret");
                    match err {
                        // A missing/locked host keyfile is the common misconfig
                        // (e.g. `plx seal --host-key <custom>` not mirrored in the
                        // runtime env); surface that distinctly from a real
                        // decrypt failure so the operator looks in the right place.
                        crate::secret_store::SealError::HostKeyMissing { .. }
                        | crate::secret_store::SealError::HostKeyPermissions { .. } => {
                            ConfigError::SecretHostKey { field }
                        }
                        _ => ConfigError::SecretSeal { field },
                    }
                })
            }
            _ => Err(ConfigError::SecretReference { field }),
        }
    }
}

/// Read a base64 secret from a 0600 sidecar file. The spec may carry a
/// `#<key>` fragment selecting one entry from a TOML key/value file; without a
/// fragment the whole (trimmed) file content is the secret.
fn resolve_file_secret(
    base: &Path,
    spec: &str,
    field: &'static str,
) -> Result<Zeroizing<String>, ConfigError> {
    let (path_part, fragment) = crate::secret_store::split_fragment(spec);
    let path = crate::secret_store::resolve_path(base, path_part);
    let text = read_secret_config_file(&path).map_err(|_| ConfigError::SecretRead { field })?;
    match fragment {
        None => Ok(Zeroizing::new(text.trim().to_owned())),
        Some(key) => {
            let table: toml::Table =
                toml::from_str(text.as_str()).map_err(|_| ConfigError::SecretRead { field })?;
            let value = table
                .get(key)
                .and_then(toml::Value::as_str)
                .ok_or(ConfigError::SecretRead { field })?;
            Ok(Zeroizing::new(value.to_owned()))
        }
    }
}

fn resolve_env_secret(name: &str, field: &'static str) -> Result<Zeroizing<String>, ConfigError> {
    // Hold the raw env value in Zeroizing so the (untrimmed) copy is scrubbed on
    // drop rather than left in the heap after we copy the trimmed text out.
    let value = Zeroizing::new(std::env::var(name).map_err(|_| ConfigError::SecretRead { field })?);
    Ok(Zeroizing::new(value.trim().to_owned()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server_addr: String,
    pub sni: String,
    pub server_public_key: String,
    pub server_identity_public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub fallback_addr: String,
    #[serde(default)]
    pub data_target: Option<String>,
    pub private_key: SecretSource,
    pub identity_secret_key: SecretSource,
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
    /// Upward jitter (ms) on the idle backstop: the all-silent connection close
    /// is spread uniformly into [floor, floor+jitter] per connection. Default
    /// 60000 (60s) to break the fixed ~600s close tell -- a round, fixed close
    /// is a synthetic signature no real origin produces (see
    /// FALLBACK_IDLE_TIMEOUT_JITTER in handshake/server.rs).
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
#[serde(deny_unknown_fields)]
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

/// Transport-layer tuning shared by client and server (the `[transport]` config
/// section). Kernel/relay tuning that does not change any handshake/record bytes.
/// `tcp_send_buffer_bytes` is fully wire-invisible; `tcp_recv_buffer_bytes` is NOT
/// (it affects the advertised TCP window) and is applied only post-connect so the
/// camouflage SYN stays Safari-identical — see its field doc. All fields default
/// off (kernel autotuning = full Safari parity).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    /// Explicit SO_SNDBUF for relay sockets, in bytes. `None`/`0` keeps kernel
    /// autotuning (the safe default). Setting it DISABLES send-buffer autotuning
    /// for the socket and is clamped by the OS maximum (`net.core.wmem_max` on
    /// Linux, `kern.ipc.maxsockbuf` on macOS), so only raise it once that maximum
    /// has been raised — otherwise the kernel may clamp BELOW what autotuning would
    /// have reached (a logged warning surfaces such a clamp). Sized to the path
    /// bandwidth-delay product, this lifts the client→server upload window on
    /// high-RTT links where autotuning under-provisions it.
    #[serde(default)]
    pub tcp_send_buffer_bytes: Option<u32>,
    /// Explicit SO_RCVBUF for relay sockets, in bytes. `None`/`0` keeps kernel
    /// autotuning. Same clamp/maximum caveat as `tcp_send_buffer_bytes`
    /// (`net.core.rmem_max` / `kern.ipc.maxsockbuf`). On the server this is the
    /// upload SINK window; sizing it to the BDP helps asymmetric (slow-upload)
    /// high-RTT links. COVERTNESS: unlike the send buffer, an explicit recv buffer
    /// affects the advertised TCP window, so it is applied ONLY post-connect/accept
    /// (never on the camouflage SYN) and a fixed value flattens the window curve vs
    /// Safari's autotuning — prefer it on the server data-sink side; leave it `None`
    /// on the client to keep full browser parity.
    #[serde(default)]
    pub tcp_recv_buffer_bytes: Option<u32>,
}

/// User-space congestion controller for the UDP fast plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UdpCongestionControl {
    /// BBRv3-style controller: blends in with ordinary traffic; the safe default.
    #[default]
    Bbr,
    /// Hysteria-style brute-force rate controller; opt-in only (detectable, unfair).
    Brutal,
}

/// Forward-error-correction profile for the unreliable datagram fast path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UdpFecProfile {
    /// No FEC.
    Off,
    /// Sliding-window FEC, gated on measured loss x RTT.
    #[default]
    Adaptive,
    /// Reed-Solomon block codes for a bulk / high-loss profile.
    Rs,
}

/// UDP fast-plane configuration. **Experimental, disabled by default**: with
/// `enabled = false` the runtime behaves exactly like today's TCP-only transport
/// (byte-identical). All knobs have safe defaults so an operator never has to
/// choose TCP vs UDP.
///
/// LIVE knobs in this version (QUIC reliable-stream fast plane for the
/// single-Connect relay path): `enabled`, `probe_timeout_ms`,
/// `max_udp_payload_bytes`, and the wire-invisible carrier-socket buffer knobs
/// `send_buffer_bytes` / `recv_buffer_bytes`. Enabling requires matched binaries
/// on both ends.
///
/// RESERVED knobs (parsed + validated for forward-compatibility but NOT
/// honored): `cc` / `brutal_*` / `ignore_client_bandwidth` (congestion control —
/// Phase 3, deferred), `fec_profile` (FEC — Phase 3, deferred), `port_hop` /
/// `masque_front` / `ech` (camouflage — dropped, not planned; kept as inert
/// no-ops only so existing configs still parse). Setting one today is a no-op;
/// the runtime logs a warning at startup so it is not mistaken for active.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpConfig {
    /// LIVE. Turn the experimental UDP/QUIC fast plane on (default off).
    #[serde(default)]
    pub enabled: bool,
    /// RESERVED (congestion control, Phase 3) — not yet honored.
    #[serde(default)]
    pub cc: UdpCongestionControl,
    /// RESERVED. Declared uplink bandwidth (Mbps) for Brutal; 0 means unset.
    #[serde(default)]
    pub brutal_up_mbps: u32,
    /// RESERVED. Declared downlink bandwidth (Mbps) for Brutal; 0 means unset.
    #[serde(default)]
    pub brutal_down_mbps: u32,
    /// RESERVED. Let the server override the client-declared Brutal bandwidth.
    #[serde(default)]
    pub ignore_client_bandwidth: bool,
    /// RESERVED (forward error correction, Phase 3) — not yet honored.
    #[serde(default)]
    pub fec_profile: UdpFecProfile,
    /// LIVE. Happy-Eyeballs UDP probe timeout before committing to TCP-only.
    #[serde(default = "default_udp_probe_timeout_ms")]
    pub probe_timeout_ms: u16,
    /// LIVE. Maximum UDP payload the QUIC carrier reads in one datagram (the inbound
    /// receive-buffer ceiling and the origin-splice relay buffer). `None`/unset keeps
    /// the conservative default (2048, ~1.6x the largest datagram ParallaX emits).
    /// Oversized datagrams are truncated-and-dropped (truncation fails AEAD); this
    /// caps per-datagram memory. Must be `>=` the RFC 9000 §14.1 Initial minimum
    /// (1200) so a legal Initial is always receivable. See issue #75.
    #[serde(default)]
    pub max_udp_payload_bytes: Option<u32>,
    /// LIVE. Explicit SO_SNDBUF for the UDP carrier socket, in bytes. `None`/`0`
    /// keeps kernel autotuning (the safe default; byte-identical to today). Setting
    /// it DISABLES send-buffer autotuning for the socket and is clamped by the OS
    /// maximum (`net.core.wmem_max` on Linux, `kern.ipc.maxsockbuf` on macOS), so
    /// only raise it once that maximum has been raised — otherwise the kernel may
    /// clamp BELOW what autotuning would have reached (a logged warning surfaces
    /// such a clamp). Sized to the path bandwidth-delay product, this lifts the
    /// upload window on high-RTT links where autotuning under-provisions it.
    /// COVERTNESS: unlike TCP, a UDP socket has no advertised receive window or
    /// window scale, so SO_SNDBUF/SO_RCVBUF are entirely wire-invisible here.
    #[serde(default)]
    pub send_buffer_bytes: Option<u32>,
    /// LIVE. Explicit SO_RCVBUF for the UDP carrier socket, in bytes. `None`/`0`
    /// keeps kernel autotuning. Same clamp/maximum caveat as `send_buffer_bytes`
    /// (`net.core.rmem_max` / `kern.ipc.maxsockbuf`). A larger kernel recv buffer
    /// lets the single-threaded driver absorb inbound bursts without socket-layer
    /// drops while it is busy; it is independent of `max_udp_payload_bytes` (the
    /// per-datagram read ceiling). Wire-invisible (see `send_buffer_bytes`).
    #[serde(default)]
    pub recv_buffer_bytes: Option<u32>,
    /// RESERVED (UDP port hopping — dropped Phase 2 camouflage, not planned).
    /// Inert no-op kept only so existing configs still parse.
    #[serde(default)]
    pub port_hop: bool,
    /// RESERVED (dropped Phase 2 camouflage, not planned). SNI/host to front the
    /// masquerading HTTP/3 face on; `None` keeps the TCP `sni`. Inert no-op.
    #[serde(default)]
    pub masque_front: Option<String>,
    /// RESERVED (Encrypted ClientHello — dropped Phase 2 camouflage, not planned).
    /// Inert no-op kept only so existing configs still parse.
    #[serde(default)]
    pub ech: bool,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cc: UdpCongestionControl::Bbr,
            brutal_up_mbps: 0,
            brutal_down_mbps: 0,
            ignore_client_bandwidth: false,
            fec_profile: UdpFecProfile::Adaptive,
            probe_timeout_ms: default_udp_probe_timeout_ms(),
            max_udp_payload_bytes: None,
            send_buffer_bytes: None,
            recv_buffer_bytes: None,
            port_hop: false,
            masque_front: None,
            ech: false,
        }
    }
}

/// Default maximum UDP payload read per datagram (the inbound recv ceiling), when
/// `udp.max_udp_payload_bytes` is unset. A generous ceiling above the path MTU and
/// ~1.6x the largest datagram ParallaX itself emits; oversized inbound datagrams are
/// truncated, which fails AEAD and is dropped. See issue #75.
pub const DEFAULT_MAX_UDP_PAYLOAD_BYTES: u32 = 2048;

/// Lower bound for `udp.max_udp_payload_bytes`: the RFC 9000 §14.1 minimum Initial
/// datagram size. A cap below this could not receive a legal client Initial.
pub const MIN_UDP_PAYLOAD_BYTES: u32 = 1200;

/// Upper bound for `udp.max_udp_payload_bytes`: the largest a single UDP datagram
/// payload can be (65535 - 8-byte UDP header). The recv buffer is sized from this
/// value, so a ceiling bounds the per-endpoint allocation — an operator typo cannot
/// request a multi-GB buffer.
pub const MAX_UDP_PAYLOAD_BYTES: u32 = 65_527;

impl UdpConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        // RESERVED/LIVE knobs only take effect when the plane is on; with
        // `enabled = false` the runtime is byte-identical to TCP-only (see struct
        // docs) and the startup reserved-knob warning is likewise gated on
        // `enabled`, so skip validation entirely when off — a pre-staged but inert
        // knob must not block startup.
        if !self.enabled {
            return Ok(());
        }
        if self.probe_timeout_ms == 0 {
            return Err(ConfigError::InvalidUdpProbeTimeout);
        }
        if let Some(cap) = self.max_udp_payload_bytes {
            if cap < MIN_UDP_PAYLOAD_BYTES {
                return Err(ConfigError::UdpMaxPayloadTooSmall);
            }
            if cap > MAX_UDP_PAYLOAD_BYTES {
                return Err(ConfigError::UdpMaxPayloadTooLarge);
            }
        }
        if self.cc == UdpCongestionControl::Brutal
            && !self.ignore_client_bandwidth
            && (self.brutal_up_mbps == 0 || self.brutal_down_mbps == 0)
        {
            return Err(ConfigError::UdpBrutalMissingBandwidth);
        }
        if let Some(front) = &self.masque_front {
            require_non_empty("udp.masque_front", front)?;
        }
        Ok(())
    }

    /// The effective maximum UDP payload read per datagram (the inbound recv-buffer
    /// ceiling), resolving `max_udp_payload_bytes` to its default when unset. Always
    /// `>= MIN_UDP_PAYLOAD_BYTES` (enforced by [`Self::validate`]).
    pub fn effective_max_udp_payload(&self) -> usize {
        self.max_udp_payload_bytes
            .unwrap_or(DEFAULT_MAX_UDP_PAYLOAD_BYTES) as usize
    }

    /// Names of RESERVED knobs (see the struct docs) that an operator has set away
    /// from their default but which this version does NOT yet honor. The runtime
    /// logs these at startup so a no-op setting is not mistaken for an active one.
    pub fn reserved_knobs_in_use(&self) -> Vec<&'static str> {
        let d = Self::default();
        let mut set = Vec::new();
        if self.cc != d.cc {
            set.push("cc");
        }
        if self.brutal_up_mbps != d.brutal_up_mbps || self.brutal_down_mbps != d.brutal_down_mbps {
            set.push("brutal_up_mbps/brutal_down_mbps");
        }
        if self.ignore_client_bandwidth != d.ignore_client_bandwidth {
            set.push("ignore_client_bandwidth");
        }
        if self.fec_profile != d.fec_profile {
            set.push("fec_profile");
        }
        if self.port_hop != d.port_hop {
            set.push("port_hop");
        }
        if self.masque_front != d.masque_front {
            set.push("masque_front");
        }
        if self.ech != d.ech {
            set.push("ech");
        }
        set
    }
}

/// Convert a TOML parse error into a sanitized `ConfigError` exposing ONLY the
/// line/column — never the offending source content. We must not let
/// `toml::de::Error`'s `Display` (which renders the source line via toml_edit),
/// its retained raw-document copy, OR its `message()` reach stderr/logs: config
/// lines carry long-lived secrets (`crypto.psk`, `server.private_key`,
/// `identity_secret_key`), and `message()` is NOT value-free —
/// a type-mismatch (e.g. a secret string pasted onto a numeric field) yields
/// `invalid type: string "<the secret>", expected usize`. So we drop the message
/// entirely and report only the position; the operator finds the typo by line.
fn toml_error(raw: &str, err: toml::de::Error) -> ConfigError {
    let off = err.span().map(|s| s.start).unwrap_or(0).min(raw.len());
    let line = raw[..off].bytes().filter(|&b| b == b'\n').count() + 1;
    let line_start = raw[..off].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let column = off - line_start + 1;
    ConfigError::Toml { line, column }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        // Read the secret config through a single opened fd whose permissions are
        // verified on the fd itself (fstat), before parsing. This closes the
        // symlink / TOCTOU window that exists when a path-based permission check
        // and a separate path-based read can resolve to different inodes.
        let raw = read_secret_config_file(path)?;
        let mut cfg =
            toml::from_str::<Self>(raw.as_str()).map_err(|e| toml_error(raw.as_str(), e))?;
        cfg.resolve_paths_relative_to(path);
        cfg.resolve_secrets(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load + validate as thoroughly as the host allows, for `plx check`. Always
    /// enforces file permissions (the hardened reader), TOML structure, and every
    /// non-secret field. If the secrets resolve (host key / sidecar / env present),
    /// it also validates the secret bytes — identical to [`Config::load`]. If they
    /// cannot resolve *because the source is unavailable* (missing host key,
    /// sidecar, or env var), it degrades to structure-only and reports that via the
    /// returned flag instead of failing, so a sealed config is still checkable on a
    /// machine without the key. A malformed config or a present-but-wrong secret
    /// still fails. Returns `(config, secrets_validated)`.
    pub fn load_for_check(path: impl AsRef<Path>) -> Result<(Self, bool), ConfigError> {
        let path = path.as_ref();
        let raw = read_secret_config_file(path)?;
        let mut cfg =
            toml::from_str::<Self>(raw.as_str()).map_err(|e| toml_error(raw.as_str(), e))?;
        cfg.resolve_paths_relative_to(path);
        match cfg.resolve_secrets(path) {
            Ok(()) => {
                cfg.validate()?;
                Ok((cfg, true))
            }
            Err(err) if err.is_secret_unavailable() => {
                cfg.validate_structure()?;
                Ok((cfg, false))
            }
            Err(err) => Err(err),
        }
    }

    pub fn protect_secret_memory(&self) {
        for field in self.secret_sources() {
            crate::process_hardening::protect_secret_bytes(
                field.mem_label,
                field.source.as_b64().as_bytes(),
            );
        }
    }

    /// The authoritative set of long-lived secret fields (see [`SecretFieldRef`]).
    /// Every secret-handling site enumerates secrets through this one method.
    ///
    /// NOTE: Rust's borrow model can't express a single iterator yielding both
    /// shared and `&mut` views, so [`Config::secret_sources_mut`] mirrors this
    /// list for in-place resolution. The two MUST stay in sync — add new secrets
    /// to both (a test asserts they have equal length).
    pub(crate) fn secret_sources(&self) -> Vec<SecretFieldRef<'_>> {
        let mut fields = vec![SecretFieldRef {
            dotted: "crypto.psk",
            seal_key: "psk",
            mem_label: "config.crypto.psk",
            source: &self.crypto.psk,
        }];
        if let Some(server) = &self.server {
            fields.push(SecretFieldRef {
                dotted: "server.private_key",
                seal_key: "private_key",
                mem_label: "config.server.private_key",
                source: &server.private_key,
            });
            fields.push(SecretFieldRef {
                dotted: "server.identity_secret_key",
                seal_key: "identity_secret_key",
                mem_label: "config.server.identity_secret_key",
                source: &server.identity_secret_key,
            });
        }
        fields
    }

    /// Mutable view of the same authoritative secret set, for in-place
    /// resolution. MUST stay in sync with [`Config::secret_sources`] (see the
    /// note there); a test asserts the two yield the same number of fields.
    fn secret_sources_mut(&mut self) -> Vec<(&'static str, &mut SecretSource)> {
        let mut fields: Vec<(&'static str, &mut SecretSource)> =
            vec![("crypto.psk", &mut self.crypto.psk)];
        if let Some(server) = self.server.as_mut() {
            fields.push(("server.private_key", &mut server.private_key));
            fields.push((
                "server.identity_secret_key",
                &mut server.identity_secret_key,
            ));
        }
        fields
    }

    /// Names of the secret fields whose bytes are stored inline in the config
    /// file (so the file itself is a bearer credential). Empty once every secret
    /// is referenced or sealed. Used by `plx check` to warn operators.
    pub fn inline_secret_fields(&self) -> Vec<&'static str> {
        self.secret_sources()
            .into_iter()
            .filter(|field| field.source.is_inline_secret())
            .map(|field| field.dotted)
            .collect()
    }

    /// Server-mode outbound targets (`fallback_addr`, and `data_target` when set)
    /// whose host is an internal/special IP literal (loopback, private, link-local
    /// incl. the cloud metadata endpoint, or unspecified). Reuses the same
    /// classification as the load-time warning ([`outbound_literal_internal_ip`]),
    /// but returns the findings so `plx check` can surface them on stdout — the
    /// load-time `tracing::warn!` is swallowed unless `RUST_LOG` selects `warn`, so
    /// an operator running `plx check` would otherwise never see this footgun.
    ///
    /// Empty for a client-mode config or when every literal target is public.
    /// Hostnames are intentionally not resolved (an offline `plx check` must not
    /// perform blocking DNS), matching the load-time warning.
    pub fn internal_outbound_targets(&self) -> Vec<(&'static str, std::net::IpAddr)> {
        let mut out = Vec::new();
        if let Some(server) = &self.server {
            if let Some(ip) = outbound_literal_internal_ip(&server.fallback_addr) {
                out.push(("server.fallback_addr", ip));
            }
            if let Some(data_target) = &server.data_target {
                if let Some(ip) = outbound_literal_internal_ip(data_target) {
                    out.push(("server.data_target", ip));
                }
            }
        }
        out
    }

    /// Path parts of plaintext sidecars referenced via `{ file = "..." }` (the
    /// `#fragment` stripped), deduplicated. `plx seal` removes these after sealing
    /// so the directory stops being a bearer credential. Only meaningful on a
    /// freshly parsed (unresolved) config.
    pub(crate) fn referenced_secret_files(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut add = |path: Option<&str>| {
            if let Some(path) = path {
                if !out.iter().any(|existing| existing == path) {
                    out.push(path.to_owned());
                }
            }
        };
        add(self.crypto.psk.file_reference_path());
        if let Some(server) = &self.server {
            add(server.private_key.file_reference_path());
            add(server.identity_secret_key.file_reference_path());
        }
        out
    }
    /// Resolve every secret field's `file`/`env`/`sealed` indirection to its
    /// value, in place, relative to the config file's directory.
    fn resolve_secrets(&mut self, config_path: &Path) -> Result<(), ConfigError> {
        let base = config_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        for (field, source) in self.secret_sources_mut() {
            source.resolve_in_place(field, base)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_structure()?;
        self.validate_secret_bytes()
    }

    /// Validate everything that does NOT require the resolved secret bytes:
    /// traffic/udp parameters, addresses, public keys, and mode invariants.
    /// `plx check` runs only this layer when the host key/sidecar is unavailable,
    /// so a sealed config can still be structurally validated on a machine that
    /// lacks the key.
    pub fn validate_structure(&self) -> Result<(), ConfigError> {
        self.traffic.validate()?;
        self.udp.validate()?;

        match self.mode {
            Mode::Client => {
                let client = self.client.as_ref().ok_or(ConfigError::MissingClient)?;
                if !client.listen.ip().is_loopback() {
                    return Err(ConfigError::UnsafeClientListen(client.listen));
                }
                require_host_port("client.server_addr", &client.server_addr)?;
                require_non_empty("client.sni", &client.sni)?;
                decode_key32("client.server_public_key", &client.server_public_key)?;
                decode_base64_bytes_exact(
                    "client.server_identity_public_key",
                    &client.server_identity_public_key,
                    mldsa::public_key_bytes(),
                )?;
            }
            Mode::Server => {
                let server = self.server.as_ref().ok_or(ConfigError::MissingServer)?;
                require_host_port("server.fallback_addr", &server.fallback_addr)?;
                warn_if_outbound_literal_is_internal("server.fallback_addr", &server.fallback_addr);
                if let Some(data_target) = &server.data_target {
                    require_host_port("server.data_target", data_target)?;
                    warn_if_outbound_literal_is_internal("server.data_target", data_target);
                }
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
                // Cap the floor too: it is a short one-shot give-up for the first
                // client record, not the idle backstop. 300000ms matches the jitter
                // cap below, so floor + jitter stays within the deliberate 600s
                // idle window and a fat-fingered value cannot pin a slot/fd for
                // hours per silent connection.
                if server.first_record_wait_floor_ms > 300_000 {
                    return Err(ConfigError::InvalidTimeoutCeiling);
                }
                if server.fallback_idle_floor_ms < 5_000 {
                    return Err(ConfigError::InvalidIdleBackstop);
                }
                // Cap jitter so a fat-fingered value cannot extend a relay's
                // fd-hold unboundedly (or, on the idle path, paint a very wide
                // synthetic close band).
                if server.first_record_wait_jitter_ms > 300_000
                    || server.fallback_idle_jitter_ms > 300_000
                {
                    return Err(ConfigError::InvalidTimeoutJitter);
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

    /// Validate the resolved secret bytes (PSK + server key lengths). Requires the
    /// secrets to have been resolved (see [`Config::resolve_secrets`]); on an
    /// unresolved `Reference` the bytes are empty and this fails.
    fn validate_secret_bytes(&self) -> Result<(), ConfigError> {
        let psk = decode_psk(self.crypto.psk.as_b64())?;
        // The PSK is one of the two secrets the whole auth scheme rests on (it
        // salts the carrier-mask and auth-key HKDFs, the initial session key, and
        // keys replay/AEAD derivation). A low-entropy / human-chosen PSK is
        // guessable, so a server must refuse to start; client mode only warns. The
        // policy is keyed on the mode alone, NOT the build profile, so `plx check`
        // gives the same verdict regardless of how the binary was compiled and the
        // strict reject path is exercised by the default `cargo test`.
        check_psk_strength(&psk, matches!(self.mode, Mode::Server))?;
        if let Mode::Server = self.mode {
            if let Some(server) = self.server.as_ref() {
                decode_key32_secret("server.private_key", server.private_key.as_b64())?;
                decode_base64_secret_exact(
                    "server.identity_secret_key",
                    server.identity_secret_key.as_b64(),
                    mldsa::secret_key_bytes(),
                )?;
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
}

#[cfg(unix)]
pub(crate) fn read_secret_config_file(path: &Path) -> Result<Zeroizing<String>, ConfigError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    // O_NOFOLLOW: refuse to open the config if its final path component is a
    // symlink (a classic way to aim a privileged reader at another file). It
    // guards only the last component, but together with the fd-based permission
    // check below it removes the path-vs-read race.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    // fstat the OPEN fd, not the path, so the inode whose permissions we approve
    // is exactly the inode we then read — no TOCTOU between check and read.
    let metadata = file.metadata()?;
    let mode = metadata.mode() & 0o777;
    let uid = metadata.uid();
    let euid = rustix::process::geteuid().as_raw();
    if mode & 0o077 != 0 || uid != euid {
        return Err(ConfigError::InsecureConfigPermissions {
            path: path.to_path_buf(),
            mode,
            uid,
            euid,
        });
    }

    let mut raw = String::new();
    file.read_to_string(&mut raw)?;
    Ok(Zeroizing::new(raw))
}

#[cfg(not(unix))]
pub(crate) fn read_secret_config_file(path: &Path) -> Result<Zeroizing<String>, ConfigError> {
    Ok(Zeroizing::new(fs::read_to_string(path)?))
}

impl TrafficConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_padding < self.min_padding {
            return Err(ConfigError::InvalidPaddingRange);
        }
        if crate::protocol::data::max_plaintext_len(self.max_padding)
            < crate::protocol::data::MIN_USABLE_PLAINTEXT_LEN
        {
            return Err(ConfigError::ExcessivePadding);
        }
        if self.max_delay_ms < self.min_delay_ms {
            return Err(ConfigError::InvalidDelayRange);
        }
        if self.cover_max_interval_ms < self.cover_min_interval_ms {
            return Err(ConfigError::InvalidCoverIntervalRange);
        }
        // Floor the cover interval when cover is enabled. `sample_interval` draws
        // `gen_range(min..=max)` ms and the loop re-arms a timer for that long, so
        // a near-zero `cover_min_interval_ms` (e.g. 0) makes the cover loop spin at
        // thousands of empty records/s — a CPU hog and a trivially fingerprintable
        // high-rate beacon. 50ms caps the worst case at ~20 records/s, far below
        // any realistic cover cadence. Bound the floor (`min`); the range check
        // above then forces `max >= min >= 50` too. A fixed universal floor, no new
        // knob.
        const MIN_COVER_INTERVAL_MS: u16 = 50;
        if self.cover_max_interval_ms > 0 && self.cover_min_interval_ms < MIN_COVER_INTERVAL_MS {
            return Err(ConfigError::CoverIntervalTooSmall {
                min_ms: MIN_COVER_INTERVAL_MS,
            });
        }
        // If cover traffic is enabled it seals empty payloads whose record size
        // is driven entirely by the padding sampler. With a degenerate padding
        // range (max_padding == min_padding, e.g. padding disabled) every cover
        // record is an identical-length record emitted at quasi-periodic
        // intervals — a constant-size beacon a censor can fingerprint, which is
        // worse than sending no cover at all. Require variable padding so cover
        // record sizes are randomized.
        if self.cover_max_interval_ms > 0 && self.max_padding <= self.min_padding {
            return Err(ConfigError::CoverRequiresVariablePadding);
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

/// Heuristic, conservative low-entropy check for a decoded PSK. A CSPRNG-derived
/// 32-byte key spans ~30 distinct byte values, so requiring at least 16 distinct
/// values flags only obviously weak keys (repeated characters, short passphrases)
/// with no false positives for random keys.
fn psk_looks_low_entropy(decoded: &[u8]) -> bool {
    const MIN_DISTINCT_BYTES: usize = 16;
    let mut seen = [false; 256];
    let mut distinct = 0_usize;
    for &b in decoded {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    distinct < MIN_DISTINCT_BYTES
}

/// Enforces PSK strength. In `strict` mode (a server) a low-entropy PSK is a hard
/// error; otherwise (client mode) it is a warning. Strictness is keyed on the mode
/// alone, never on the build profile, so the verdict is reproducible. The minimum
/// length (>= 32 bytes) is already enforced by [`decode_psk`] before this runs —
/// this only gates entropy.
fn check_psk_strength(psk: &[u8], strict: bool) -> Result<(), ConfigError> {
    if !psk_looks_low_entropy(psk) {
        return Ok(());
    }
    if strict {
        return Err(ConfigError::LowEntropyPsk);
    }
    tracing::warn!(
        "crypto.psk appears to have low entropy; use a CSPRNG-generated 32-byte key \
         (e.g. `plx init` / `openssl rand -base64 32`). This is a hard error on a \
         server."
    );
    Ok(())
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

/// Classifies an `host:port` outbound literal as internal/special, returning the
/// offending IP, or `None` when the host is not an IP literal (a hostname, left to
/// runtime resolution) or is a normal public address. Split out from the warning so
/// the classification is unit-testable. Covers loopback, private, link-local (which
/// includes the cloud metadata endpoint 169.254.169.254), and unspecified.
fn outbound_literal_internal_ip(value: &str) -> Option<std::net::IpAddr> {
    let (host, _port) = value.rsplit_once(':')?;
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let ip = host.parse::<std::net::IpAddr>().ok()?;
    let internal = match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xffc0) == 0xfe80 // unicast link-local
                || (ip.segments()[0] & 0xfe00) == 0xfc00 // unique-local
        }
    };
    internal.then_some(ip)
}

/// Warn (never fail) when an operator-configured outbound target is an internal IP
/// literal (C-1). Unlike a client-selected forward target (screened and hard-denied
/// at runtime by `is_denied_outbound_ip`), `fallback_addr` / `data_target` are
/// operator-chosen and a client can never influence them, so this is not a remotely
/// reachable SSRF — it is a consistency / footgun guard. It stays a WARNING, not a
/// hard error, because a private/LAN value can be a deliberate, valid deployment (a
/// co-located camouflage origin or an internal `data_target`); failing the load
/// would break those. Hostnames are left to runtime resolution (resolving them here
/// would need blocking DNS in config validation and break an offline `plx check`).
fn warn_if_outbound_literal_is_internal(field: &str, value: &str) {
    if let Some(ip) = outbound_literal_internal_ip(value) {
        tracing::warn!(
            %field,
            %ip,
            "configured outbound target is an internal/special IP literal (loopback, \
             private, link-local incl. the cloud metadata endpoint, or unspecified); \
             ensure this is intentional — for the camouflage origin this should \
             normally be a public address"
        );
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

const fn default_udp_probe_timeout_ms() -> u16 {
    // Floor for the UDP-probe budget. The effective budget is RTT-aware
    // (`udp_probe_budget` = max(this, 6 × observed control-plane RTT), PAR-11), so on
    // a fast path it stays near this value and on a high-RTT path it grows with the
    // path. The floor is set above a single transcontinental RTT (~300ms) with margin,
    // so even before the RTT sample is applied the probe is not starved mid-handshake.
    1000
}

fn default_replay_cache_path() -> PathBuf {
    PathBuf::from(DEFAULT_REPLAY_CACHE_PATH)
}

const fn default_replay_cache_capacity() -> usize {
    DEFAULT_REPLAY_CACHE_CAPACITY
}

const fn default_max_concurrent_per_source() -> u32 {
    // Shared v4/v6 starting point on purpose: 256 is generous enough not to
    // throttle real shared/CGNAT sources while still bounding single-source
    // monopolization (the global limit is the real backstop). Operators behind
    // heavy carrier-NAT or running /64-per-VM fleets can raise the v6 cap.
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
    60_000
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    /// A 32-byte, high-entropy (32 distinct bytes) PSK for configs that must
    /// validate: server mode now hard-rejects a low-entropy PSK in every build
    /// profile, so the all-zero `KEY` cannot be reused for the `psk` field there.
    const STRONG_PSK: &str = "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY=";

    #[test]
    fn validates_client_config() {
        let server_identity_public_key = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{server_identity_public_key}"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn validates_client_and_server_configs() {
        let identity_public_key = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let client_raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

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
psk = "{STRONG_PSK}"

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
    fn secret_sources_views_stay_in_sync() {
        // `secret_sources` and `secret_sources_mut` are two hand-maintained lists
        // (Rust can't yield shared + `&mut` views from one fn). Guard against one
        // drifting from the other when a future secret field is added.
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
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
        let mut cfg = toml::from_str::<Config>(&server_raw).unwrap();
        let shared = cfg.secret_sources().len();
        let mutable = cfg.secret_sources_mut().len();
        assert_eq!(shared, mutable);
        assert_eq!(shared, 3, "server config exposes psk + 2 server keys");
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
    fn udp_defaults_are_disabled_and_safe() {
        let udp = UdpConfig::default();
        assert!(!udp.enabled);
        assert_eq!(udp.cc, UdpCongestionControl::Bbr);
        assert_eq!(udp.fec_profile, UdpFecProfile::Adaptive);
        assert_eq!(udp.probe_timeout_ms, 1000);
        assert_eq!(udp.brutal_up_mbps, 0);
        assert_eq!(udp.brutal_down_mbps, 0);
        assert!(!udp.ignore_client_bandwidth);
        assert!(udp.send_buffer_bytes.is_none());
        assert!(udp.recv_buffer_bytes.is_none());
        assert!(!udp.port_hop);
        assert!(udp.masque_front.is_none());
        assert!(!udp.ech);
        udp.validate().unwrap();
    }

    #[test]
    fn config_without_udp_section_defaults_to_disabled() {
        let identity = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{identity}"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
        assert!(!cfg.udp.enabled);
        assert_eq!(cfg.udp, UdpConfig::default());
    }

    #[test]
    fn udp_section_parses_overrides() {
        let identity = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{identity}"

[udp]
enabled = true
cc = "brutal"
brutal_up_mbps = 50
brutal_down_mbps = 200
fec_profile = "rs"
probe_timeout_ms = 250
max_udp_payload_bytes = 4096
port_hop = true
masque_front = "cdn.example.com"
ech = true
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.udp.enabled);
        assert_eq!(cfg.udp.cc, UdpCongestionControl::Brutal);
        assert_eq!(cfg.udp.brutal_up_mbps, 50);
        assert_eq!(cfg.udp.brutal_down_mbps, 200);
        assert_eq!(cfg.udp.fec_profile, UdpFecProfile::Rs);
        assert_eq!(cfg.udp.probe_timeout_ms, 250);
        assert_eq!(cfg.udp.max_udp_payload_bytes, Some(4096));
        assert_eq!(cfg.udp.effective_max_udp_payload(), 4096);
        assert!(cfg.udp.port_hop);
        assert_eq!(cfg.udp.masque_front.as_deref(), Some("cdn.example.com"));
        assert!(cfg.udp.ech);
    }

    #[test]
    fn udp_max_payload_defaults_and_validates() {
        // Unset => the conservative built-in default.
        let d = UdpConfig::default();
        assert_eq!(d.max_udp_payload_bytes, None);
        assert_eq!(
            d.effective_max_udp_payload(),
            DEFAULT_MAX_UDP_PAYLOAD_BYTES as usize
        );

        // At / above the §14.1 floor is accepted.
        let ok = UdpConfig {
            enabled: true,
            max_udp_payload_bytes: Some(MIN_UDP_PAYLOAD_BYTES),
            ..UdpConfig::default()
        };
        ok.validate().unwrap();
        assert_eq!(
            ok.effective_max_udp_payload(),
            MIN_UDP_PAYLOAD_BYTES as usize
        );

        // Below the floor (a cap that could not receive a legal Initial) is rejected.
        let too_small = UdpConfig {
            enabled: true,
            max_udp_payload_bytes: Some(MIN_UDP_PAYLOAD_BYTES - 1),
            ..UdpConfig::default()
        };
        assert!(matches!(
            too_small.validate().unwrap_err(),
            ConfigError::UdpMaxPayloadTooSmall
        ));

        // At the ceiling is accepted; above it (an operator typo that would size a
        // multi-GB recv buffer) is rejected.
        let at_max = UdpConfig {
            enabled: true,
            max_udp_payload_bytes: Some(MAX_UDP_PAYLOAD_BYTES),
            ..UdpConfig::default()
        };
        at_max.validate().unwrap();
        let too_large = UdpConfig {
            enabled: true,
            max_udp_payload_bytes: Some(MAX_UDP_PAYLOAD_BYTES + 1),
            ..UdpConfig::default()
        };
        assert!(matches!(
            too_large.validate().unwrap_err(),
            ConfigError::UdpMaxPayloadTooLarge
        ));
    }

    #[test]
    fn rejects_zero_udp_probe_timeout() {
        let udp = UdpConfig {
            enabled: true,
            probe_timeout_ms: 0,
            ..UdpConfig::default()
        };
        assert!(matches!(
            udp.validate().unwrap_err(),
            ConfigError::InvalidUdpProbeTimeout
        ));
    }

    #[test]
    fn rejects_brutal_without_declared_bandwidth() {
        let udp = UdpConfig {
            enabled: true,
            cc: UdpCongestionControl::Brutal,
            ..UdpConfig::default()
        };
        assert!(matches!(
            udp.validate().unwrap_err(),
            ConfigError::UdpBrutalMissingBandwidth
        ));
    }

    #[test]
    fn accepts_brutal_with_declared_bandwidth() {
        let udp = UdpConfig {
            enabled: true,
            cc: UdpCongestionControl::Brutal,
            brutal_up_mbps: 50,
            brutal_down_mbps: 200,
            ..UdpConfig::default()
        };
        udp.validate().unwrap();
    }

    #[test]
    fn accepts_brutal_when_ignoring_client_bandwidth() {
        let udp = UdpConfig {
            enabled: true,
            cc: UdpCongestionControl::Brutal,
            ignore_client_bandwidth: true,
            ..UdpConfig::default()
        };
        udp.validate().unwrap();
    }

    #[test]
    fn rejects_brutal_with_partial_bandwidth() {
        let up_only = UdpConfig {
            enabled: true,
            cc: UdpCongestionControl::Brutal,
            brutal_up_mbps: 50,
            brutal_down_mbps: 0,
            ..UdpConfig::default()
        };
        assert!(matches!(
            up_only.validate().unwrap_err(),
            ConfigError::UdpBrutalMissingBandwidth
        ));
        let down_only = UdpConfig {
            enabled: true,
            cc: UdpCongestionControl::Brutal,
            brutal_up_mbps: 0,
            brutal_down_mbps: 200,
            ..UdpConfig::default()
        };
        assert!(matches!(
            down_only.validate().unwrap_err(),
            ConfigError::UdpBrutalMissingBandwidth
        ));
    }

    #[test]
    fn rejects_empty_masque_front() {
        let udp = UdpConfig {
            enabled: true,
            masque_front: Some("  ".to_owned()),
            ..UdpConfig::default()
        };
        assert!(matches!(
            udp.validate().unwrap_err(),
            ConfigError::InvalidSocket { .. }
        ));
    }

    #[test]
    fn reserved_knobs_in_use_flags_only_non_default_reserved_fields() {
        // Default + the two LIVE knobs flipped => nothing reserved is in use.
        let live = UdpConfig {
            enabled: true,
            probe_timeout_ms: 250,
            ..UdpConfig::default()
        };
        assert!(live.reserved_knobs_in_use().is_empty());

        // A reserved knob set away from default IS flagged.
        let reserved = UdpConfig {
            enabled: true,
            port_hop: true,
            fec_profile: UdpFecProfile::Rs,
            masque_front: Some("cdn.example.com".to_owned()),
            ..UdpConfig::default()
        };
        let flagged = reserved.reserved_knobs_in_use();
        assert!(flagged.contains(&"port_hop"));
        assert!(flagged.contains(&"fec_profile"));
        assert!(flagged.contains(&"masque_front"));
        // LIVE knobs never appear.
        assert!(!flagged
            .iter()
            .any(|k| k.contains("probe") || k.contains("enabled")));
    }

    #[test]
    fn udp_partial_section_uses_field_defaults() {
        let identity = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{identity}"

[udp]
enabled = true
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.udp,
            UdpConfig {
                enabled: true,
                ..UdpConfig::default()
            }
        );
    }

    #[test]
    fn udp_enum_wire_spellings_round_trip() {
        let identity = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{identity}"

[udp]
cc = "bbr"
fec_profile = "off"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.udp.cc, UdpCongestionControl::Bbr);
        assert_eq!(cfg.udp.fec_profile, UdpFecProfile::Off);
    }

    #[test]
    fn server_mode_accepts_udp_section() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]

[udp]
enabled = true
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.udp.enabled);
    }

    #[test]
    fn rejects_non_loopback_client_listener() {
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

[client]
listen = "0.0.0.0:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
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
    fn low_entropy_psk_hard_fails_in_strict_mode() {
        // A 32-byte all-same-byte PSK passes the length floor but is low entropy.
        let weak = [0x41_u8; 32];
        assert!(psk_looks_low_entropy(&weak));
        assert!(matches!(
            check_psk_strength(&weak, true),
            Err(ConfigError::LowEntropyPsk)
        ));
    }

    #[test]
    fn low_entropy_psk_only_warns_in_non_strict_mode() {
        let weak = [0x41_u8; 32];
        assert!(check_psk_strength(&weak, false).is_ok());
    }

    #[test]
    fn strong_psk_passes_strict_mode() {
        // >= 16 distinct bytes => not flagged, so strict mode accepts it.
        let strong = b"0123456789abcdef0123456789abcdef";
        assert!(!psk_looks_low_entropy(strong));
        assert!(check_psk_strength(strong, true).is_ok());
    }

    #[test]
    fn server_validate_hard_fails_low_entropy_psk() {
        // The strict weak-PSK reject path is reached through the public validate()
        // entry point (not just the helper) and is uniform across build profiles,
        // so it runs and passes under the default `cargo test`. `KEY` is a 32-byte
        // but all-zero (low-entropy) PSK that clears the length floor.
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
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
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::LowEntropyPsk
        ));
    }

    #[test]
    fn client_validate_accepts_low_entropy_psk_with_warning() {
        // Client mode only warns on a low-entropy PSK, so validate() still
        // succeeds with the same all-zero `KEY`.
        let server_identity_public_key = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
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
server_identity_public_key = "{server_identity_public_key}"
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        cfg.validate().unwrap();
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
    fn rejects_padding_below_min_usable_plaintext_floor() {
        use crate::protocol::data::{max_plaintext_len, MIN_USABLE_PLAINTEXT_LEN};
        // The first max_padding that pushes usable plaintext under the floor: a
        // config there would let a single relay read explode into tens of
        // thousands of records and reserve ~1 GiB, so it must be rejected even
        // though it leaves a few non-zero plaintext bytes.
        let below = (0..=u16::MAX)
            .find(|&p| max_plaintext_len(p) < MIN_USABLE_PLAINTEXT_LEN)
            .expect("some padding drops plaintext below the floor");
        assert!(below > 0);
        let bad = TrafficConfig {
            max_padding: below,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            bad.validate().unwrap_err(),
            ConfigError::ExcessivePadding
        ));
        // One less padding stays at/above the floor and validates.
        assert!(max_plaintext_len(below - 1) >= MIN_USABLE_PLAINTEXT_LEN);
        let ok = TrafficConfig {
            max_padding: below - 1,
            ..TrafficConfig::default()
        };
        assert!(ok.validate().is_ok());
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

    #[test]
    fn rejects_cover_traffic_with_degenerate_padding() {
        // Cover traffic enabled but padding is degenerate (max == min == 0):
        // every cover record would be an identical-length beacon. Validation must
        // reject this combination.
        let traffic = TrafficConfig {
            cover_min_interval_ms: 50,
            cover_max_interval_ms: 200,
            min_padding: 0,
            max_padding: 0,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            traffic.validate().unwrap_err(),
            ConfigError::CoverRequiresVariablePadding
        ));

        // The same cover config with a non-degenerate padding range is accepted.
        let ok = TrafficConfig {
            cover_min_interval_ms: 50,
            cover_max_interval_ms: 200,
            min_padding: 0,
            max_padding: 256,
            ..TrafficConfig::default()
        };
        ok.validate().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn server_config_load_enforces_secret_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
        let server_identity_public_key = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
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
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
    fn rejects_wrong_identity_key_length_during_validation() {
        let err = decode_base64_bytes_exact(
            "client.server_identity_public_key",
            KEY,
            mldsa::public_key_bytes(),
        )
        .unwrap_err();
        match err {
            ConfigError::InvalidBytesLen {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "client.server_identity_public_key");
                assert_eq!(expected, mldsa::public_key_bytes());
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
    fn outbound_literal_internal_ip_flags_internal_literals_only() {
        // Internal / special literals are flagged (incl. the cloud metadata endpoint).
        for v in [
            "127.0.0.1:443",
            "10.0.0.5:443",
            "192.168.1.1:8443",
            "169.254.169.254:80", // cloud metadata
            "0.0.0.0:443",
            "[::1]:443",
            "[fe80::1]:443",
            "[fc00::1]:443",
        ] {
            assert!(
                outbound_literal_internal_ip(v).is_some(),
                "{v} must be flagged as internal",
            );
        }
        // Public literals and hostnames are not flagged (hostnames -> runtime).
        for v in [
            "1.1.1.1:443",
            "93.184.216.34:443",
            "[2606:4700:4700::1111]:443",
            "cloudflare.com:443",
            "example.com:8443",
        ] {
            assert!(
                outbound_literal_internal_ip(v).is_none(),
                "{v} must NOT be flagged",
            );
        }
    }

    fn server_config_with_targets(fallback_addr: &str, data_target: Option<&str>) -> Config {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let data_target_line = data_target
            .map(|t| format!("data_target = \"{t}\"\n"))
            .unwrap_or_default();
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "{fallback_addr}"
{data_target_line}private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
"#
        );
        toml::from_str::<Config>(&raw).unwrap()
    }

    #[test]
    fn internal_outbound_targets_flags_internal_fallback_and_data_target() {
        let cfg = server_config_with_targets("127.0.0.1:443", Some("10.1.2.3:9000"));
        let findings = cfg.internal_outbound_targets();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].0, "server.fallback_addr");
        assert_eq!(findings[1].0, "server.data_target");
    }

    #[test]
    fn internal_outbound_targets_empty_for_public_targets() {
        let cfg = server_config_with_targets("cloudflare.com:443", Some("1.1.1.1:443"));
        assert!(cfg.internal_outbound_targets().is_empty());
    }

    #[test]
    fn internal_outbound_targets_flags_only_the_internal_one() {
        // A public fallback but an internal data_target: only the latter is flagged.
        let cfg = server_config_with_targets("example.com:443", Some("192.168.0.10:8080"));
        let findings = cfg.internal_outbound_targets();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].0, "server.data_target");
    }

    #[test]
    fn internal_outbound_targets_empty_for_client_config() {
        let server_identity_public_key = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        let cfg = toml::from_str::<Config>(&format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{server_identity_public_key}"
"#
        ))
        .unwrap();
        assert!(cfg.internal_outbound_targets().is_empty());
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
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
        assert_eq!(server.fallback_idle_jitter_ms, 60_000);
        assert!(server.tcp_congestion.is_none());
    }

    #[test]
    fn server_validate_rejects_sub_minimum_timeout_floor() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
    fn server_validate_rejects_excessive_first_record_floor() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let make = |floor: u64| {
            format!(
                r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
first_record_wait_floor_ms = {floor}
"#
            )
        };
        // Above the 300_000ms ceiling: rejected.
        let cfg = toml::from_str::<Config>(&make(400_000)).unwrap();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::InvalidTimeoutCeiling
        ));
        // Exactly at the ceiling: accepted (guards > vs >=).
        let cfg = toml::from_str::<Config>(&make(300_000)).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn unknown_config_key_is_rejected() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        // A misspelled safety key under [server] must now hard-fail at parse
        // (deny_unknown_fields) instead of being silently dropped to the default.
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
max_pading = 1500
"#
        );
        let err = toml::from_str::<Config>(&raw).unwrap_err();
        assert!(
            err.to_string().contains("max_pading"),
            "error should name the unknown key, got: {err}"
        );

        // Same for the highest-stakes struct: a typo'd padding key under [traffic].
        let raw = format!(
            r#"
mode = "client"

[crypto]
psk = "{STRONG_PSK}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{KEY}"

[traffic]
max_padd = 1500
"#
        );
        let err = toml::from_str::<Config>(&raw).unwrap_err();
        assert!(
            err.to_string().contains("max_padd"),
            "error should name the unknown traffic key, got: {err}"
        );
    }

    #[test]
    fn udp_validate_skips_reserved_checks_when_disabled() {
        // Every individual rule deliberately violated, but the plane is OFF: the
        // disabled guard short-circuits all checks, matching the documented
        // "byte-identical to TCP-only" contract.
        let disabled = UdpConfig {
            enabled: false,
            cc: UdpCongestionControl::Brutal,
            brutal_up_mbps: 0,
            brutal_down_mbps: 0,
            probe_timeout_ms: 0,
            masque_front: Some("  ".to_owned()),
            ..UdpConfig::default()
        };
        disabled.validate().unwrap();

        // The same struct with the plane ON is rejected by the first check, proving
        // the guard does not mask validation when UDP is live.
        let enabled = UdpConfig {
            enabled: true,
            ..disabled
        };
        assert!(matches!(
            enabled.validate().unwrap_err(),
            ConfigError::InvalidUdpProbeTimeout
        ));
    }

    #[test]
    fn rejects_near_zero_cover_interval() {
        // The exact footgun: cover enabled with a near-zero floor hot-spins the
        // cover loop. Variable padding so it passes the CoverRequiresVariablePadding
        // gate and reaches the interval-floor check.
        let footgun = TrafficConfig {
            cover_min_interval_ms: 0,
            cover_max_interval_ms: 1,
            min_padding: 0,
            max_padding: 64,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            footgun.validate().unwrap_err(),
            ConfigError::CoverIntervalTooSmall { .. }
        ));
        // Just below the 50ms floor is still rejected (pins the boundary).
        let just_under = TrafficConfig {
            cover_min_interval_ms: 49,
            cover_max_interval_ms: 100,
            min_padding: 0,
            max_padding: 64,
            ..TrafficConfig::default()
        };
        assert!(matches!(
            just_under.validate().unwrap_err(),
            ConfigError::CoverIntervalTooSmall { .. }
        ));
        // Smallest accepted enabled config validates.
        let ok = TrafficConfig {
            cover_min_interval_ms: 50,
            cover_max_interval_ms: 200,
            min_padding: 0,
            max_padding: 256,
            ..TrafficConfig::default()
        };
        ok.validate().unwrap();
        // Disabled cover (both 0) is unaffected by the floor.
        let disabled = TrafficConfig {
            cover_min_interval_ms: 0,
            cover_max_interval_ms: 0,
            ..TrafficConfig::default()
        };
        disabled.validate().unwrap();
    }

    #[test]
    fn server_validate_rejects_tiny_idle_backstop() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
    fn server_validate_rejects_excessive_timeout_jitter() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

[server]
listen = "127.0.0.1:8443"
fallback_addr = "example.com:443"
private_key = "{KEY}"
identity_secret_key = "{identity_secret_key}"
authorized_sni = ["example.com"]
fallback_idle_jitter_ms = 999999999
"#
        );
        let cfg = toml::from_str::<Config>(&raw).unwrap();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            ConfigError::InvalidTimeoutJitter
        ));
    }

    #[test]
    fn server_validate_rejects_bogus_tcp_congestion() {
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        for bogus in ["\"\"", "\"bbr xtls\"", "\"a;b\""] {
            let raw = format!(
                r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
        let identity_secret_key = STANDARD.encode(vec![0_u8; mldsa::secret_key_bytes()]);
        let raw = format!(
            r#"
mode = "server"

[crypto]
psk = "{STRONG_PSK}"

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
psk = "{STRONG_PSK}"
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
psk = "{STRONG_PSK}"
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
        assert!(matches!(Config::load(&path), Err(ConfigError::Toml { .. })));
    }

    /// M-12: a TOML syntax error on or near a secret line must NOT leak the
    /// offending source line (which carries `crypto.psk` / `server.private_key`
    /// etc.) through the error's Display or Debug — only line/column/kind.
    #[test]
    fn toml_parse_error_never_leaks_secret_value() {
        let secret = "S3CR3T-DO-NOT-LEAK-0123456789abcdef";
        // Two operator-typo classes that historically leaked the secret:
        //  (1) an unterminated string on the psk line (toml_edit's Display renders
        //      the whole source line, secret included);
        //  (2) a secret string transposed onto a NUMERIC field, whose toml
        //      type-mismatch message() echoes the value verbatim
        //      (invalid type: string "<secret>", expected usize).
        // Neither may surface in Display or Debug of the resulting error.
        for body in [
            format!("mode = \"server\"\n[crypto]\npsk = \"{secret}\n"),
            format!("mode = \"server\"\n[server]\nreplay_cache_capacity = \"{secret}\"\n"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("leaky.toml");
            fs::write(&path, &body).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let err = Config::load(&path).unwrap_err();
            let rendered = format!("{err}");
            let debugged = format!("{err:?}");
            assert!(
                !rendered.contains(secret) && !debugged.contains(secret),
                "TOML parse error must not contain the secret (Display={rendered:?}, Debug={debugged:?})",
            );
            assert!(matches!(err, ConfigError::Toml { .. }));
        }
    }

    #[test]
    fn config_load_propagates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.toml");
        assert!(matches!(Config::load(&missing), Err(ConfigError::Read(_))));
    }

    #[cfg(unix)]
    fn write_0600(path: &Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inline_secret_is_parsed_and_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.toml");
        let identity = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        write_0600(
            &path,
            &format!(
                r#"
mode = "client"

[crypto]
psk = "{KEY}"

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{identity}"
"#
            ),
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.crypto.psk.as_b64(), KEY);
        assert!(cfg.crypto.psk.is_inline_secret());
        assert_eq!(cfg.inline_secret_fields(), vec!["crypto.psk"]);
    }

    #[cfg(unix)]
    #[test]
    fn psk_resolves_from_file_reference_and_is_not_flagged_inline() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("parallax.client.secrets.toml");
        write_0600(&secrets, &format!("psk = \"{KEY}\"\n"));
        let path = dir.path().join("client.toml");
        let identity = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        write_0600(
            &path,
            &format!(
                r#"
mode = "client"

[crypto]
psk = {{ file = "parallax.client.secrets.toml#psk" }}

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{identity}"
"#
            ),
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.crypto.psk.as_b64(), KEY);
        assert!(!cfg.crypto.psk.is_inline_secret());
        assert!(cfg.inline_secret_fields().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn psk_resolves_from_env_reference() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.toml");
        let identity = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        let var = "PARALLAX_TEST_PSK_ENV_REF";
        std::env::set_var(var, KEY);
        write_0600(
            &path,
            &format!(
                r#"
mode = "client"

[crypto]
psk = {{ env = "{var}" }}

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{identity}"
"#
            ),
        );
        let cfg = Config::load(&path).unwrap();
        std::env::remove_var(var);
        assert_eq!(cfg.crypto.psk.as_b64(), KEY);
        assert!(!cfg.crypto.psk.is_inline_secret());
    }

    #[cfg(unix)]
    #[test]
    fn secret_reference_with_two_sources_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.toml");
        let identity = STANDARD.encode(vec![0_u8; mldsa::public_key_bytes()]);
        write_0600(
            &path,
            &format!(
                r#"
mode = "client"

[crypto]
psk = {{ file = "a", env = "B" }}

[client]
listen = "127.0.0.1:1080"
server_addr = "example.com:443"
sni = "example.com"
server_public_key = "{KEY}"
server_identity_public_key = "{identity}"
"#
            ),
        );
        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::SecretReference {
                field: "crypto.psk"
            })
        ));
    }
}
