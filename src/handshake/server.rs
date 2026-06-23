use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        lookup_host,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{mpsc, Semaphore, TryAcquireError},
    time::{sleep, sleep_until, timeout, timeout_at, Instant},
};
use zeroize::Zeroize;

use super::source_limit::SourceLimiter;
use super::transcript::transcript_hash;

use crate::{
    config::{
        decode_base64_secret, decode_key32_secret, decode_psk, Config, ConfigError, Mode,
        ServerConfig, TrafficConfig, UdpConfig,
    },
    crypto::{
        auth::{
            derive_server_auth_key_from_shared, recover_stateful_auth_material_from_parsed,
            verify_masked_stateful_client_hello_auth_with_parsed_material, AuthError, ClientAuth,
        },
        identity::{self, IdentityError},
        parallel,
        pq::{self, PqError},
        replay::{
            current_unix_timestamp, ReplayCache, ReplayCacheError, ReplayEntry,
            ReplayInsertOutcome, DEFAULT_REPLAY_WINDOW_SECS,
        },
        session::{
            derive_server_keys_from_shared, expand_epoch_keys, x25519_public_from_private,
            x25519_shared_secret, AeadCodec, CipherSuite, SessionError, SessionKeys, X25519KeyPair,
        },
    },
    protocol::{
        command::{
            ConnectRequest, ConnectRequestError, FramedChunk, FramedChunkError, FramedReassembler,
            MuxFrame, MuxFrameError, MuxFrameKind, MuxFrameRef, MuxPayloadPool, PqRekeyError,
            PqRekeyRequest, ServerIdentityChunk, ServerIdentityChunkError, ServerIdentityProof,
            ServerIdentityProofError, ServerKeyExchange, ServerKeyExchangeError, SpeedTestAck,
            SpeedTestRequest, SpeedTestRequestError, MAX_PQ_HANDSHAKE_FRAME,
            PQ_HANDSHAKE_CHUNK_MAX_PLAINTEXT, PQ_HANDSHAKE_CHUNK_MIN_PLAINTEXT,
        },
        data::{
            max_plaintext_len, relay_read_buffer_len, should_parallelize_aead, DataRecordCodec,
            DataRecordError, SealedRecord, CLIENT_TO_SERVER_AAD, QUIC_RELAY_DONE_MARKER,
            RELAY_IDLE_CLOSE_CODE, SERVER_TO_CLIENT_AAD,
        },
    },
    tls::{
        client_hello::parse_client_hello,
        record::{
            log_record_read, parse_header, read_record, BufferedTlsRecordReader, TlsRecordReader,
            TLS_HEADER_LEN,
        },
        server_hello::{parse_server_hello, ServerHello, ServerHelloError},
    },
    traffic::{CoverTrafficProfile, PaddingProfile, TimingProfile, TrafficError},
    transport::{
        leg::{
            H3DataFrameLegReader, H3DataFrameLegWriter, LegReader, LegWriter, TcpLegReader,
            TcpLegWriter,
        },
        tcp::{
            connect_tuned_tcp_any, connect_tuned_tcp_host, drain_ready_tcp_read,
            is_fd_exhaustion_error, relay_connection_limit, tune_tcp_stream,
        },
    },
};

/// Fixed timeout for origin-facing handshake operations (dialing the camouflage
/// origin and reading its ServerHello). These gate genuine origin work, so they
/// stay constant -- jittering them would only add latency to legitimate clients.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
/// Floor for the client-facing wait on the first record. A real client sends its
/// ClientHello immediately, so only a slow/absent client (a probe or a broken
/// connection) ever reaches this; the floor matches the previous fixed value so
/// no legitimate client is given less time than before.
const FIRST_RECORD_WAIT_FLOOR: Duration = Duration::from_secs(8);
/// Upward jitter added to [`FIRST_RECORD_WAIT_FLOOR`] per connection. This does
/// not hide the give-up entirely -- the 8s floor is still the minimum a patient
/// prober converges to over many silent probes -- but it raises measuring the
/// wait from a single shot to a multi-sample minimum. Only ever extends the wait.
const FIRST_RECORD_WAIT_JITTER: Duration = Duration::from_secs(7);
/// Pure resource backstop for the camouflage relay idle cap -- NOT an
/// anti-probing measure. A legitimate relay resets it on every byte and a real
/// origin/client drives the close first, so this fires only on a deliberately
/// silent connection (a probe). Jittering it was theater: the floor, not the
/// ceiling, is the value a silent prober converges to, and a uniform band is
/// itself a synthetic signature no real origin produces. It is set high so
/// ParallaX rarely originates the close at all; genuinely matching an origin's
/// idle policy is an operational/Phase-3 concern. The *number* of concurrent
/// holds at this length is bounded by `relay_connection_limit`; the 600s length
/// itself is a deliberate fixed backstop -- a 5x raise from the prior 120s that
/// trades a longer fd hold on silent probes for fewer ParallaX-originated closes.
const FALLBACK_IDLE_TIMEOUT_FLOOR: Duration = Duration::from_secs(600);
/// Upward jitter on the idle backstop (M-3). In the all-silent corner case (the
/// origin never closes first, so ParallaX is the side that originates the close),
/// a fixed, round ~600.000s close is a synthetic signature no real origin
/// produces and is observable by a single long-lived silent probe. Jittering the
/// backstop into [600s, 660s] per connection removes that fixed tell;
/// `jittered_timeout` adds a uniform [0, jitter] grace over the floor.
const FALLBACK_IDLE_TIMEOUT_JITTER: Duration = Duration::from_secs(60);

/// Bounds concurrent cap-shed fallback relays (H-1). When the per-source or global
/// connection cap rejects a connection we must still look like the origin (relay
/// its ServerHello) rather than emit a bare ServerHello-less FIN, which a prober
/// could use to count our cap. But a cap-rejected connection that opened a full
/// 600s relay would turn the cap into an origin-DoS amplifier, so cap-shed relays
/// draw from this small SEPARATE budget (the main slots are already exhausted) and
/// use a tight idle bound. 64 userspace relays ~= 128 fds: a fixed reservation
/// that cannot itself exhaust fds. Past the budget we degrade to a graceful FIN —
/// a casual prober always lands inside it; only a genuine flood sees FINs, which a
/// real origin under flood also produces.
const MAX_CONCURRENT_CAP_SHED_FALLBACKS: usize = 64;
/// Idle bound for cap-shed fallback relays (H-1). These exist only to return the
/// origin ServerHello to a prober, not to serve a session, so they use a tight
/// bound instead of FALLBACK_IDLE_TIMEOUT_FLOOR (600s); this recycles the small
/// budget in seconds even under slow/idle attackers.
const CAP_SHED_FALLBACK_IDLE: Duration = Duration::from_secs(10);
/// Small upward jitter on the cap-shed idle so a saturated-cap prober does not see
/// a fixed, round 10.000s close on the cap-shed relay (the same fixed-constant tell
/// M-3 removed from the main idle backstop). Kept tiny to preserve the tight
/// anti-DoS-amplification bound.
const CAP_SHED_FALLBACK_IDLE_JITTER: Duration = Duration::from_secs(2);

static ACTIVE_CAP_SHED_FALLBACKS: AtomicUsize = AtomicUsize::new(0);

/// RAII slot for a cap-shed fallback relay; releases the budget on drop.
struct CapShedFallbackSlot(());
impl Drop for CapShedFallbackSlot {
    fn drop(&mut self) {
        ACTIVE_CAP_SHED_FALLBACKS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Takes a cap-shed fallback slot if the budget allows, else `None`.
fn try_enter_cap_shed_fallback() -> Option<CapShedFallbackSlot> {
    let prev = ACTIVE_CAP_SHED_FALLBACKS.fetch_add(1, Ordering::AcqRel);
    if prev >= MAX_CONCURRENT_CAP_SHED_FALLBACKS {
        ACTIVE_CAP_SHED_FALLBACKS.fetch_sub(1, Ordering::AcqRel);
        None
    } else {
        Some(CapShedFallbackSlot(()))
    }
}
const SERVER_IDENTITY_CHUNK_MIN_PLAINTEXT: usize = 960;
const SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT: usize = 1320;
const SERVER_IDENTITY_CHUNK_MIN_DELAY: Duration = Duration::from_millis(45);
// The client's residual-skip budget, mirrored here only for the operator-facing
// warning logged when the forward cap is reached. Bound to the shared constant so
// it can never drift from the client's actual budget again (the 16-vs-64 high-RTT
// handshake-failure bug).
const CLIENT_RESIDUAL_CAMOUFLAGE_RECORD_BUDGET: usize =
    super::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS;
/// Cap on fallback-origin records forwarded to the client before the ParallaX PQ
/// rekey arrives. This must comfortably cover a *full* fragmented TLS 1.3 server
/// handshake flight (ServerHello + EncryptedExtensions + a possibly large,
/// heavily fragmented Certificate chain + CertificateVerify + Finished): the
/// client only sends its PQ record once that flight completes its Safari TLS
/// camouflage, so a limit smaller than the origin's record count deadlocks the
/// session (the server stops forwarding, the client keeps waiting). 64 records
/// (~1 MiB) is far above any real handshake flight while still bounding forwarding.
/// Bound to the shared [`super::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS`] so the
/// client's residual-skip budget always covers exactly what this may forward.
const PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT: usize = super::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS;
const SERVER_MUX_FRAME_CHANNEL: usize = 1024;
/// Server-side ceilings on an authenticated speed-test request. The on-wire
/// format permits arbitrary u64 byte counts and a u16 sample count; without a
/// server-enforced bound a malicious authenticated client can request terabytes
/// of generated download or a never-ending upload, pinning bandwidth/CPU and a
/// connection slot. The CLI's own requests are orders of magnitude below these.
const MAX_SPEED_TEST_BYTES_PER_PHASE: u64 = 1024 * 1024 * 1024; // 1 GiB
const MAX_SPEED_TEST_SAMPLES: u16 = 32;
/// Aggregate ceiling across all phases (2x warmup + sample_count x (download +
/// upload)). The per-phase caps alone still permit tens of GiB of generated +
/// decrypt work per request; this bounds the whole request. The legitimate CLI
/// totals well under 30 MiB, far below this.
const MAX_SPEED_TEST_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB
const SERVER_MUX_FRAME_BATCH_LIMIT: usize = 64;
/// Hard cap on concurrent mux substreams per authenticated connection. Excess
/// `Open` frames are answered with `Reset` and never establish an outbound
/// connection, so an authenticated client cannot use substreams to bypass the
/// fd-based connection limit (which budgets ~2 fds per connection). Enforced by
/// the server on its own terms rather than trusting the client's advertised
/// `max_concurrent_streams`.
const SERVER_MUX_MAX_STREAMS: usize = 256;
/// Cap on the ciphertext bytes batched per mux read before opening, bounding
/// scratch memory while leaving enough records for the crypto pool to fan out.
const MUX_OPEN_BATCH_BYTES: usize = 1024 * 1024;
/// Max consecutive zero-length (padding-only) upload records tolerated before
/// the speed-test upload phase tears the connection down, so a client streaming
/// only empty records cannot loop forever (the per-read idle timeout resets on
/// every record and so never fires under that input).
const MAX_CONSECUTIVE_EMPTY_UPLOAD_RECORDS: u32 = 1024;

static NEXT_SERVER_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Test-only publication of the server's retained QUIC fast-plane endpoint so a
/// mid-relay reset test can kill the fast plane in flight and assert a clean
/// teardown. Set to the accepted connection's `Endpoint` on the Verified+enabled
/// retain path (the hand-rolled `Connection` is not cloneable; closing the
/// endpoint closes its single relay connection, which is what the test needs).
/// Not compiled in release.
#[cfg(test)]
static RETAINED_QUIC_CONN_FOR_TEST: Mutex<Option<crate::transport::udp::quic::endpoint::Endpoint>> =
    Mutex::new(None);

/// Test-only counter of X25519 DH ops performed on the inbound-decision path, used
/// to assert the rejection path's DH count is input-independent (M-2). Not
/// compiled in release.
#[cfg(test)]
static REJECT_DH_OPS: AtomicUsize = AtomicUsize::new(0);

/// Test accessor for [`RETAINED_QUIC_CONN_FOR_TEST`] so the mid-relay reset e2e
/// (in the client runtime test module) can grab and kill the server's retained
/// QUIC fast plane in flight.
#[cfg(test)]
pub(crate) fn retained_quic_conn_for_test(
) -> &'static Mutex<Option<crate::transport::udp::quic::endpoint::Endpoint>> {
    &RETAINED_QUIC_CONN_FOR_TEST
}

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
    #[error("outbound TCP connect timed out")]
    OutboundConnectTimeout,
    #[error("fallback ServerHello did not negotiate TLS 1.3")]
    Tls13Required,
    #[error("session key derivation failed: {0}")]
    Session(#[from] SessionError),
    #[error("data record error: {0}")]
    DataRecord(#[from] DataRecordError),
    #[error("traffic shaping error: {0}")]
    Traffic(#[from] TrafficError),
    #[error("connect request error: {0}")]
    ConnectRequest(#[from] ConnectRequestError),
    #[error("speed test request error: {0}")]
    SpeedTestRequest(#[from] SpeedTestRequestError),
    #[error("mux frame error: {0}")]
    MuxFrame(#[from] MuxFrameError),
    #[error("PQ rekey command error: {0}")]
    PqRekey(#[from] PqRekeyError),
    #[error("framed chunk command error: {0}")]
    FramedChunk(#[from] FramedChunkError),
    #[error("server key exchange command error: {0}")]
    ServerKeyExchange(#[from] ServerKeyExchangeError),
    #[error("PQ crypto error: {0}")]
    Pq(#[from] PqError),
    #[error("server identity proof command error: {0}")]
    ServerIdentityProof(#[from] ServerIdentityProofError),
    #[error("server identity chunk command error: {0}")]
    ServerIdentityChunk(#[from] ServerIdentityChunkError),
    #[error("server identity signing failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("replay cache error: {0}")]
    ReplayCache(#[from] ReplayCacheError),
    #[error("missing encrypted connect request and no fixed server.data_target configured")]
    MissingConnectTarget,
    // Unit variant on purpose: the denied target is the client's decrypted
    // destination (host + resolved IP) and must never reach logs via either
    // Display or the derived Debug (the connection-close path renders errors with
    // `error = %err`). Carrying no payload keeps the secret off every error sink.
    #[error("client-selected outbound target is denied by server egress policy")]
    OutboundTargetDenied,
    #[error("blocking crypto task failed: {0}")]
    BlockingTask(#[from] tokio::task::JoinError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundDecision {
    Authenticated(AuthenticatedHello),
    Fallback(FallbackReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedHello {
    pub sni: String,
    /// ParallaX ephemeral X25519 public key carried in ClientHello.random.
    pub x25519_key_share: [u8; 32],
    pub timestamp: u64,
    pub nonce: [u8; 8],
    pub transcript_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackReason {
    AuthFailed,
    Replay,
    MissingSni,
    UnauthorizedSni(String),
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
    pub session_keys: SessionKeys,
    pub server_public_key: [u8; 32],
}

struct AuthenticatedInbound {
    hello: AuthenticatedHello,
    x25519_shared_secret: zeroize::Zeroizing<[u8; 32]>,
}

struct PendingReplayEntry {
    cache: Arc<Mutex<ReplayCache>>,
    entry: ReplayEntry,
}

enum ConnectionDecision {
    Authenticated(AuthenticatedInbound),
    Fallback(FallbackReason),
}

#[derive(Debug, PartialEq, Eq)]
enum FirstClientRead {
    Record(Vec<u8>),
    FallbackPrefix(Vec<u8>),
}

/// Process-global 0-RTT enablement for the UDP fast plane, built once in [`run`]
/// when `udp.enabled` (otherwise the plane stays cold-start / 1-RTT only). `run`
/// is one-per-process, so a `OnceLock` is the right home — the same shape as
/// [`TIMEOUT_TUNING`].
///
/// `stek` is derived from the server's stable static private key: server-only (a
/// client cannot forge a ticket) and stable, so a ticket issued by one per-session
/// ephemeral QUIC endpoint still opens at the next one. `guard` is the shared,
/// persistent single-use anti-replay cache, so a replayed ticket's early data is
/// rejected — including across a server restart — and that connection falls back
/// to a full 1-RTT handshake.
struct ServerZeroRtt {
    stek: zeroize::Zeroizing<[u8; 32]>,
    guard: Arc<crate::transport::udp::zero_rtt::ReplayCacheGuard>,
}

static SERVER_ZERO_RTT: OnceLock<ServerZeroRtt> = OnceLock::new();

/// Process-global stable origin-splice carrier (the shared QUIC `:server.listen`
/// endpoint), built once in [`run`] when `udp.enabled`. `None` (never set) leaves
/// the UDP fast plane on the per-session ephemeral path. A `Mutex` (not a `OnceLock`)
/// so tests that drive [`handle_connection`] directly — bypassing `run`'s startup —
/// can inject a carrier; production sets it exactly once at startup. See
/// [`crate::transport::udp::stable::QuicCarrier`].
static SERVER_QUIC_CARRIER: Mutex<Option<Arc<crate::transport::udp::stable::QuicCarrier>>> =
    Mutex::new(None);

/// Test-only injector for [`SERVER_QUIC_CARRIER`]: lets a test that calls
/// [`handle_connection`] directly supply a stable carrier (production sets it in
/// [`run`]).
#[cfg(test)]
pub(crate) fn set_quic_carrier_for_test(
    carrier: Option<Arc<crate::transport::udp::stable::QuicCarrier>>,
) {
    *SERVER_QUIC_CARRIER
        .lock()
        .expect("quic carrier mutex poisoned") = carrier;
}

/// Bind the stable origin-splice carrier: marker key = the shared PSK + the server's
/// static X25519 private key (the same REALITY static key the TCP plane authenticates
/// with), splice origin = the camouflage origin's UDP `:443` (resolved from
/// `fallback_addr`), reusing the [`SERVER_ZERO_RTT`] STEK + guard if 0-RTT is enabled.
/// The carrier binds UDP on `server.listen` so the QUIC port is the same stable port
/// as the TCP face (an HTTP/3 origin shape), not a per-session ephemeral port.
async fn build_quic_carrier(
    server: &crate::config::ServerConfig,
    psk: &[u8],
    private_key: &[u8; 32],
) -> Result<Arc<crate::transport::udp::stable::QuicCarrier>, crate::transport::udp::UdpTransportError>
{
    use crate::transport::udp::UdpTransportError;
    // The camouflage origin's HTTP/3 endpoint: the fallback host on UDP :443.
    let origin_ip = lookup_host(&server.fallback_addr)
        .await?
        .next()
        .ok_or_else(|| {
            UdpTransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "fallback_addr did not resolve",
            ))
        })?
        .ip();
    let origin = std::net::SocketAddr::new(origin_ip, 443);
    // The fronted domain (host part of fallback_addr) backs the carrier's self-signed
    // cert; our clients accept any cert (trust is the marker + exporter token) and GFW
    // does not inspect QUIC certs, so only the SNI label matters cosmetically.
    let front = server
        .fallback_addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(server.fallback_addr.as_str());
    let (cert, key) = crate::transport::udp::endpoint::ephemeral_self_signed(front)?;
    let marker_key = (
        zeroize::Zeroizing::new(psk.to_vec()),
        zeroize::Zeroizing::new(*private_key),
    );
    let (stek, guard) = match SERVER_ZERO_RTT.get() {
        Some(zr) => (
            Some(zr.stek.clone()),
            Some(zr.guard.clone() as Arc<dyn crate::tls::quic::ZeroRttGuard>),
        ),
        None => (None, None),
    };
    let config =
        crate::transport::udp::server_config_stable(cert, key, stek, guard, marker_key, origin)?;
    Ok(crate::transport::udp::stable::QuicCarrier::bind(server.listen, config).await?)
}

/// Test-only carrier builder for suites that drive [`handle_connection`] directly
/// (bypassing `run`): decodes the static X25519 private key from `server` and binds
/// a carrier under `psk`, so the UDP fast plane is offered exactly as in production.
#[cfg(test)]
pub(crate) async fn build_quic_carrier_for_test(
    server: &crate::config::ServerConfig,
    psk: &[u8],
) -> Result<Arc<crate::transport::udp::stable::QuicCarrier>, crate::transport::udp::UdpTransportError>
{
    let private_key = decode_key32_secret("server.private_key", server.private_key.as_b64())
        .map_err(|e| crate::transport::udp::UdpTransportError::TlsConfig(e.to_string()))?;
    build_quic_carrier(server, psk, &private_key).await
}

/// 0-RTT resumption-ticket lifetime (RFC 8446 §4.6.1): 7 days, matching the
/// Safari-26 NewSessionTicket baseline. The anti-replay window is sized to this so
/// a ticket stays replay-protected for exactly as long as it is valid.
const ZERO_RTT_TICKET_LIFETIME_SECS: u64 = 604_800;

/// The 0-RTT anti-replay cache path: a sibling of the auth-handshake replay cache
/// (so an operator protects one directory), kept distinct because the two caches
/// key different things (auth: handshake transcript fingerprint; 0-RTT: the
/// resumption-ticket digest).
fn zero_rtt_replay_cache_path(auth_cache_path: &std::path::Path) -> std::path::PathBuf {
    let mut name = auth_cache_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("parallax-replay.cache"));
    name.push(".0rtt");
    auth_cache_path.with_file_name(name)
}

pub async fn run(config: Config) -> Result<(), HandshakeServerError> {
    if config.mode != Mode::Server {
        return Err(HandshakeServerError::WrongMode);
    }
    // Server UDP-offer parameters, read in run_authenticated_data_mode to decide
    // whether to offer the UDP fast plane (vs decline) and how long to wait on the
    // probe. Threaded as a cheap-to-clone Arc, mirroring how `traffic` flows down
    // the connection chain.
    let udp = Arc::new(config.udp.clone());
    if udp.enabled {
        tracing::info!(
            probe_timeout_ms = udp.probe_timeout_ms,
            "UDP fast plane ENABLED (experimental): offers a QUIC reliable-stream carrier \
             for the single-Connect relay; requires matched binaries on both ends"
        );
        let reserved = udp.reserved_knobs_in_use();
        if !reserved.is_empty() {
            tracing::warn!(
                reserved = ?reserved,
                "udp config sets RESERVED knobs that this version does not yet honor (no-op)"
            );
        }
    }

    let server = config
        .server
        .clone()
        .ok_or(HandshakeServerError::MissingServer)?;
    let server = Arc::new(server);
    // Install deployment-wide tuning before accepting any connection. First call
    // wins (run() is one-per-process); log if a second run somehow re-sets it.
    if TIMEOUT_TUNING
        .set(TimeoutTuning::from_server_config(&server))
        .is_err()
    {
        tracing::debug!("timeout tuning already set; keeping the first configuration");
    }
    crate::transport::tcp::configure_congestion_control(server.tcp_congestion.as_deref());
    let traffic = config.traffic;
    let psk = decode_psk(config.crypto.psk.as_b64())?;
    crate::process_hardening::protect_secret_bytes("runtime.crypto.psk", psk.as_slice());
    let psk = Arc::new(psk);
    let replay_cache = Arc::new(Mutex::new(
        ReplayCache::load_or_create_authenticated_with_window(
            &server.replay_cache_path,
            server.replay_cache_capacity,
            &psk,
            replay_freshness_window_secs(),
        )?,
    ));
    let secrets = ServerRuntimeSecrets::decode(&server)?;
    // Enable 0-RTT on the experimental UDP fast plane: a STEK derived from the
    // server's stable static private key (server-only, and stable across the
    // per-session ephemeral QUIC endpoints) lets the server issue + accept
    // resumption tickets, and a persistent single-use guard rejects a replayed
    // ticket's early data (that connection then falls back to 1-RTT). Proxied
    // outbound stays gated on the exporter-bound auth token (commit-late), so a
    // replayed 0-RTT flight — which cannot complete 1-RTT and therefore cannot
    // produce a valid token — never opens an outbound connection. Built only when
    // udp is enabled; the plane stays behind the experimental-UDP gate (active
    // probing is handled by the stable carrier's origin splice). A cache-load
    // failure degrades to cold-start (1-RTT only) rather than failing the server.
    if udp.enabled {
        let zr_path = zero_rtt_replay_cache_path(&server.replay_cache_path);
        match ReplayCache::load_or_create_authenticated_with_window(
            &zr_path,
            server.replay_cache_capacity,
            &psk,
            ZERO_RTT_TICKET_LIFETIME_SECS,
        ) {
            Ok(cache) => {
                let guard = Arc::new(crate::transport::udp::zero_rtt::ReplayCacheGuard::new(
                    cache,
                ));
                let stek = crate::tls::quic::derive_stek(secrets.private_key());
                if SERVER_ZERO_RTT.set(ServerZeroRtt { stek, guard }).is_err() {
                    tracing::debug!(
                        "0-RTT enablement already set; keeping the first configuration"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "0-RTT replay cache unavailable; UDP fast plane stays cold-start (1-RTT only)"
                );
            }
        }
        // Bind the process-wide stable origin-splice carrier on the server's listen
        // address (UDP), now that any 0-RTT STEK/guard above is set. It marker-
        // terminates authenticated clients and splices every other Initial verbatim
        // to the camouflage origin's UDP :443, so the stable QUIC port mirrors the
        // real origin to an active prober. A resolve/bind failure degrades to no
        // carrier (the plane stays on the per-session path) rather than failing the
        // server.
        match build_quic_carrier(&server, psk.as_slice(), secrets.private_key()).await {
            Ok(carrier) => {
                *SERVER_QUIC_CARRIER
                    .lock()
                    .expect("quic carrier mutex poisoned") = Some(carrier);
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "stable QUIC carrier unavailable; UDP fast plane stays on the per-session path"
                );
            }
        }
    }
    let listener = TcpListener::bind(server.listen).await?;
    let connection_limit = relay_connection_limit(udp.enabled)?;
    let connection_slots = Arc::new(Semaphore::new(connection_limit));
    let source_limiter = SourceLimiter::new(
        server.max_concurrent_per_source_v4,
        server.max_concurrent_per_source_v6,
        server.source_ipv6_prefix_len,
        connection_limit,
    );
    tracing::info!(
        connection_limit,
        "ParallaX server listening on {}",
        server.listen
    );

    loop {
        let (client, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) if is_fd_exhaustion_error(&err) => {
                tracing::error!(
                    error = %err,
                    "accept() ran out of file descriptors; backing off 100ms"
                );
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        // Per-source admission first, so a single source flooding the box is shed
        // before it can burn a global permit. Rejects FIN (detached) like every
        // other close path.
        let source_permit = match Arc::clone(&source_limiter).try_admit(peer.ip()) {
            Some(permit) => permit,
            None => {
                tracing::warn!(
                    %peer,
                    "per-source connection limit reached; cap-shedding to origin"
                );
                // Relay to the camouflage origin (H-1) so a prober still sees the
                // origin ServerHello and cannot count our cap by the missing one;
                // bounded budget + tight idle, degrading to a graceful FIN past the
                // budget. Detached so a flood at the cap cannot stall the loop.
                tokio::spawn(cap_shed_fallback_or_fin(
                    client,
                    server.fallback_addr.clone(),
                ));
                continue;
            }
        };
        let connection_permit = match Arc::clone(&connection_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                tracing::warn!(
                    %peer,
                    connection_limit,
                    "server connection limit reached; cap-shedding to origin"
                );
                // Relay to the camouflage origin (H-1) so a prober still sees the
                // origin ServerHello and cannot count our cap by the missing one.
                // Bounded budget + tight idle (cap_shed_fallback_or_fin), degrading
                // to a graceful FIN past the budget. Detached so a connection flood
                // at the limit cannot stall the accept loop.
                tokio::spawn(cap_shed_fallback_or_fin(
                    client,
                    server.fallback_addr.clone(),
                ));
                continue;
            }
            Err(TryAcquireError::Closed) => {
                return Err(io::Error::other("server connection limiter was closed").into());
            }
        };
        let cid = NEXT_SERVER_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let server = Arc::clone(&server);
        let connection_traffic = traffic;
        let connection_udp = Arc::clone(&udp);
        let psk = Arc::clone(&psk);
        let replay_cache = Arc::clone(&replay_cache);
        let secrets = secrets.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let _source_permit = source_permit;
            if let Err(err) = handle_connection_with_replay(
                client,
                &server,
                connection_traffic,
                &connection_udp,
                &psk,
                replay_cache,
                &secrets,
                cid,
            )
            .await
            {
                tracing::debug!(cid, %peer, error = %err, "connection closed");
            }
        });
    }
}

pub async fn handle_connection(
    client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    udp: &UdpConfig,
    psk: &[u8],
) -> Result<(), HandshakeServerError> {
    let cid = NEXT_SERVER_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let secrets = ServerRuntimeSecrets::decode(config)?;
    handle_connection_inner(client, config, traffic, udp, psk, None, &secrets, cid).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_with_replay(
    client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    udp: &UdpConfig,
    psk: &[u8],
    replay_cache: Arc<Mutex<ReplayCache>>,
    secrets: &ServerRuntimeSecrets,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    handle_connection_inner(
        client,
        config,
        traffic,
        udp,
        psk,
        Some(replay_cache),
        secrets,
        cid,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_inner(
    mut client: TcpStream,
    config: &ServerConfig,
    traffic: TrafficConfig,
    udp: &UdpConfig,
    psk: &[u8],
    replay_cache: Option<Arc<Mutex<ReplayCache>>>,
    secrets: &ServerRuntimeSecrets,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    tune_tcp_stream(&client)?;
    tracing::info!(
        cid,
        task_name = "server-connection",
        "accepted outer connection"
    );
    let server_private = secrets.private_key();
    let server_public_key = secrets.server_public_key();
    let first_record = match read_first_client_record(&mut client).await? {
        FirstClientRead::Record(record) => record,
        FirstClientRead::FallbackPrefix(prefix) => {
            tracing::info!(
                cid,
                prefix_len = prefix.len(),
                "falling back to camouflage origin before a complete ClientHello"
            );
            relay_fallback(client, &config.fallback_addr, prefix).await?;
            return Ok(());
        }
    };
    match decide_connection_inbound(&first_record, psk, &config.authorized_sni, server_private)? {
        ConnectionDecision::Fallback(reason) => {
            tracing::info!(cid, ?reason, "falling back to camouflage origin");
            relay_fallback(client, &config.fallback_addr, first_record).await?;
        }
        ConnectionDecision::Authenticated(authenticated) => {
            let AuthenticatedInbound {
                hello: client_hello,
                x25519_shared_secret,
            } = authenticated;
            let pending_replay = replay_cache.map(|cache| PendingReplayEntry {
                cache,
                entry: ReplayEntry {
                    timestamp: client_hello.timestamp,
                    nonce: client_hello.nonce,
                    transcript_fingerprint: client_hello.transcript_fingerprint,
                },
            });
            let handshake = accept_authenticated(
                client,
                config,
                psk,
                server_public_key,
                x25519_shared_secret,
                first_record,
                client_hello,
            )
            .await?;
            tracing::info!(
                cid,
                sni = %handshake.client_hello.sni,
                tls13 = handshake.server_hello.tls13_selected,
                "authenticated ParallaX handshake accepted"
            );
            run_authenticated_data_mode(
                handshake,
                config.data_target.as_deref(),
                secrets.identity_secret_key(),
                psk,
                traffic,
                udp,
                pending_replay,
                cid,
            )
            .await?;
        }
    }

    Ok(())
}

#[derive(Clone)]
struct ServerRuntimeSecrets {
    private_key: Arc<zeroize::Zeroizing<[u8; 32]>>,
    server_public_key: [u8; 32],
    identity_secret_key: Arc<zeroize::Zeroizing<Vec<u8>>>,
}

impl ServerRuntimeSecrets {
    fn decode(config: &ServerConfig) -> Result<Self, ConfigError> {
        let private_key = decode_key32_secret("server.private_key", config.private_key.as_b64())?;
        let server_public_key = x25519_public_from_private(&private_key);
        let identity_secret_key = decode_base64_secret(
            "server.identity_secret_key",
            config.identity_secret_key.as_b64(),
        )?;

        // Pin the secrets at their FINAL, stable addresses. private_key is an
        // inline [u8;32]: protecting it before the Arc::new below would mlock the
        // stack local, which is then copied into the Arc's heap allocation by the
        // move — leaving the live key at a new, unpinned, dumpable address. Wrap
        // first, then protect through the Arc so the lock lands on the bytes that
        // actually persist. (identity_secret_key is a Vec whose heap buffer is
        // stable across the move, but we protect it after the wrap too for
        // consistency.)
        let private_key = Arc::new(private_key);
        crate::process_hardening::protect_secret_bytes(
            "runtime.server.private_key",
            &**private_key,
        );
        let identity_secret_key = Arc::new(identity_secret_key);
        crate::process_hardening::protect_secret_bytes(
            "runtime.server.identity_secret_key",
            identity_secret_key.as_slice(),
        );
        Ok(Self {
            private_key,
            server_public_key,
            identity_secret_key,
        })
    }

    fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    fn server_public_key(&self) -> [u8; 32] {
        self.server_public_key
    }

    fn identity_secret_key(&self) -> Arc<zeroize::Zeroizing<Vec<u8>>> {
        Arc::clone(&self.identity_secret_key)
    }
}

fn client_hello_fingerprint(first_record: &[u8]) -> [u8; 32] {
    Sha256::digest(first_record).into()
}

pub fn decide_inbound(
    first_client_record: &[u8],
    psk: &[u8],
    authorized_sni: &[String],
    server_private: &[u8; 32],
) -> Result<InboundDecision, HandshakeServerError> {
    match decide_connection_inbound(first_client_record, psk, authorized_sni, server_private)? {
        ConnectionDecision::Authenticated(authenticated) => {
            Ok(InboundDecision::Authenticated(authenticated.hello))
        }
        ConnectionDecision::Fallback(reason) => Ok(InboundDecision::Fallback(reason)),
    }
}

fn decide_connection_inbound(
    first_client_record: &[u8],
    psk: &[u8],
    authorized_sni: &[String],
    server_private: &[u8; 32],
) -> Result<ConnectionDecision, HandshakeServerError> {
    let parsed = match parse_client_hello(first_client_record) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed)),
    };
    if !parsed.tls13_supported {
        return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed));
    }
    // Constant-time-by-op-count DH (M-2): the auth-failing path must perform a
    // FIXED number of X25519 ops regardless of ClientHello shape, else an off-path
    // observer reads the per-DH latency step (no key_share / recover-None /
    // auth-fail) as a distinguisher. Route every DH through this closure and pad
    // with discarded ballast so EVERY path runs exactly 2 ops (mask slot + auth
    // slot); ballast results are Zeroizing to match the real-DH zeroize discipline.
    // Auth semantics unchanged.
    let dh = |peer: &[u8; 32]| -> zeroize::Zeroizing<[u8; 32]> {
        #[cfg(test)]
        REJECT_DH_OPS.fetch_add(1, Ordering::Relaxed);
        zeroize::Zeroizing::new(x25519_shared_secret(server_private, peer))
    };

    // v4 masked-stateful path. mask_ecdh = X25519(server_static, tls_ephemeral)
    // (the unmasked standalone key_share); distinct from the auth DH below (the
    // recovered ParallaX ephemeral). The mask-slot DH ALWAYS runs once — a real
    // point when a key_share is present, else discarded ballast — so a hello with
    // no key_share is not one DH cheaper than one with it.
    let mask_ecdh = match parsed.x25519_key_share {
        Some(tls_key_share) => Some(dh(&tls_key_share)),
        None => {
            let _ = dh(&parsed.client_random);
            None
        }
    };
    if let Some(mask_ecdh) = mask_ecdh.as_deref() {
        // `recover` runs after the mask-slot DH but before the auth-slot DH. Its
        // only error sources are EmptyPsk (config-enforced non-empty) and HKDF
        // (infallible over fixed-length input), so on attacker-controlled parsed
        // input it always resolves to Ok(None)/Ok(Some) -- never Err. Handle Err
        // explicitly anyway, spending the auth-slot ballast first, so the M-2
        // fixed 2-DH-op reject budget cannot regress to 1 op if recover's error
        // surface is ever widened (mirrors the verify EmptyPsk/Hkdf arm below).
        let recovered = match recover_stateful_auth_material_from_parsed(
            first_client_record,
            psk,
            mask_ecdh,
            &parsed,
        ) {
            Ok(recovered) => recovered,
            Err(err) => {
                let _ = dh(&parsed.client_random); // ballast: auth-slot, recover error
                return Err(err.into());
            }
        };
        if let Some(material) = recovered {
            let x25519_key_share = material.x25519_public;
            let x25519_shared_secret = dh(&x25519_key_share);
            let auth_key = derive_server_auth_key_from_shared(psk, &x25519_shared_secret)?;
            let auth = match verify_masked_stateful_client_hello_auth_with_parsed_material(
                first_client_record,
                auth_key.as_slice(),
                &material,
                &parsed,
            ) {
                Ok(auth) => auth,
                Err(err @ (AuthError::EmptyPsk | AuthError::Hkdf)) => return Err(err.into()),
                Err(_) => return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed)),
            };
            if auth.authenticated {
                return authenticated_decision(
                    first_client_record,
                    auth,
                    authorized_sni,
                    x25519_key_share,
                    x25519_shared_secret,
                );
            }
            // Masked auth failed. The two real DH ops (mask slot + auth slot) are
            // already done, matching the recover==None and no-key_share reject
            // shapes below at a fixed 2 ops, so fall straight to the splice.
        } else {
            let _ = dh(&parsed.client_random); // ballast: auth-slot, recover==None
        }
    } else {
        let _ = dh(&parsed.client_random); // ballast: auth-slot, no key_share
    }

    Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed))
}

fn authenticated_decision(
    first_client_record: &[u8],
    auth: ClientAuth,
    authorized_sni: &[String],
    x25519_key_share: [u8; 32],
    x25519_shared_secret: zeroize::Zeroizing<[u8; 32]>,
) -> Result<ConnectionDecision, HandshakeServerError> {
    let timestamp = match auth.timestamp {
        Some(timestamp) => timestamp,
        None => return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed)),
    };
    let nonce = match auth.nonce {
        Some(nonce) => nonce,
        None => return Ok(ConnectionDecision::Fallback(FallbackReason::AuthFailed)),
    };

    let sni = match auth.sni {
        Some(sni) => sni,
        None => return Ok(ConnectionDecision::Fallback(FallbackReason::MissingSni)),
    };

    if !is_authorized_sni(&sni, authorized_sni) {
        return Ok(ConnectionDecision::Fallback(
            FallbackReason::UnauthorizedSni(sni),
        ));
    }

    Ok(ConnectionDecision::Authenticated(AuthenticatedInbound {
        hello: AuthenticatedHello {
            sni,
            x25519_key_share,
            timestamp,
            nonce,
            transcript_fingerprint: client_hello_fingerprint(first_client_record),
        },
        x25519_shared_secret,
    }))
}

pub async fn accept_authenticated(
    mut client: TcpStream,
    config: &ServerConfig,
    psk: &[u8],
    server_public_key: [u8; 32],
    x25519_shared_secret: zeroize::Zeroizing<[u8; 32]>,
    first_client_record: Vec<u8>,
    client_hello: AuthenticatedHello,
) -> Result<AuthenticatedHandshake, HandshakeServerError> {
    let mut fallback = connect_tcp_with_timeout(&config.fallback_addr).await?;
    tune_tcp_stream(&fallback)?;
    write_all_with_handshake_timeout(&mut fallback, &first_client_record).await?;

    let forwarded = read_forwarded_server_hello(&mut fallback).await?;
    if config.strict_tls13 && !forwarded.parsed.tls13_selected {
        // Mirror the origin's ServerHello to the client, then close it the same
        // drain->FIN way every other exit does so a strict-TLS1.3 reject is a FIN,
        // never a RST. Swallow a write error here: we tear the connection down
        // regardless and must still FIN.
        let _ = write_all_with_handshake_timeout(&mut client, &forwarded.raw_record).await;
        graceful_close_tcp_stream(client).await;
        return Err(HandshakeServerError::Tls13Required);
    }
    write_all_with_handshake_timeout(&mut client, &forwarded.raw_record).await?;

    let context = transcript_hash(&first_client_record, &forwarded.raw_record);
    let session_keys = derive_server_keys_from_shared(psk, &x25519_shared_secret, &context)?;
    session_keys.protect_secret_memory();

    Ok(AuthenticatedHandshake {
        client,
        fallback,
        client_hello,
        server_hello: forwarded.parsed,
        session_keys,
        server_public_key,
    })
}

pub async fn relay_fallback(
    client: TcpStream,
    fallback_addr: &str,
    first_client_record: Vec<u8>,
) -> Result<(), HandshakeServerError> {
    // Acquire the camouflage origin and replay the bytes we already read. If any
    // of this fails we must not just drop `client`: a bare drop with bytes still
    // queued in its receive buffer makes the kernel emit a RST, which is an
    // observable difference from an ordinary origin. Drain and FIN it instead,
    // exactly like the relay teardown, so both fallback exits behave the same.
    let fallback = match connect_and_forward_to_fallback(fallback_addr, &first_client_record).await
    {
        Ok(fallback) => fallback,
        Err(err) => {
            graceful_close_tcp_stream(client).await;
            return Err(err);
        }
    };
    relay_fallback_with_idle_timeout(client, fallback, fallback_idle_timeout()).await
}

async fn connect_and_forward_to_fallback(
    fallback_addr: &str,
    first_client_record: &[u8],
) -> Result<TcpStream, HandshakeServerError> {
    let mut fallback = connect_tcp_with_timeout(fallback_addr).await?;
    tune_tcp_stream(&fallback)?;
    fallback.write_all(first_client_record).await?;
    Ok(fallback)
}

/// Drains a read half to `WouldBlock` (bounded) so the eventual close is a FIN,
/// not a RST, even when more than one bufferful is queued. A single small pass
/// could leave a backlog that RSTs on drop; this mirrors the splice path's
/// multi-pass drain (capped at 16 x 16 KiB = 256 KiB).
fn drain_read_half_to_block(reader: &OwnedReadHalf) {
    let mut scratch = [0_u8; 16 * 1024];
    for _ in 0..16 {
        match drain_ready_tcp_read(reader, &mut scratch, 0) {
            Ok(n) if n == scratch.len() => continue,
            _ => break,
        }
    }
}

/// Drains any ready receive bytes and then half-closes the write side so the
/// peer sees a graceful FIN. Dropping a socket with unread bytes still queued
/// makes the kernel emit a RST, an observable tell a real origin would not
/// produce; this keeps the close indistinguishable from an ordinary teardown.
async fn graceful_close_tcp_stream(stream: TcpStream) {
    let (read_half, mut write_half) = stream.into_split();
    drain_read_half_to_block(&read_half);
    let _ = write_half.shutdown().await;
}

/// Cap-rejection close that stays indistinguishable from the origin (H-1): relay
/// to the camouflage origin so the client still gets a real ServerHello, under a
/// small bounded budget + tight idle bound; if the budget is full or the origin
/// dial fails, fall back to a graceful FIN (the prior behavior). We never read the
/// ClientHello at admission time, so the prefix is empty — the client's own
/// ClientHello then splices straight through to the origin.
async fn cap_shed_fallback_or_fin(client: TcpStream, fallback_addr: String) {
    let Some(_slot) = try_enter_cap_shed_fallback() else {
        graceful_close_tcp_stream(client).await;
        return;
    };
    match connect_and_forward_to_fallback(&fallback_addr, &[]).await {
        Ok(fallback) => {
            let _ = relay_fallback_with_idle_timeout(
                client,
                fallback,
                jittered_timeout(CAP_SHED_FALLBACK_IDLE, CAP_SHED_FALLBACK_IDLE_JITTER),
            )
            .await;
        }
        Err(_) => graceful_close_tcp_stream(client).await,
    }
    // `_slot` drops here, releasing the cap-shed budget.
}

async fn relay_fallback_with_idle_timeout(
    client: TcpStream,
    fallback: TcpStream,
    idle_timeout: Duration,
) -> Result<(), HandshakeServerError> {
    #[cfg(target_os = "linux")]
    {
        if crate::transport::tcp::kernel_splice_available() {
            // Bound concurrent kernel-splice relays: each holds ~8 fds + 2 native
            // threads, far above the 2 fds the admission semaphore budgets, so
            // unauthenticated fallback floods could exhaust fds/threads first.
            // Beyond the cap, fall through to the userspace relay (2 fds, no
            // native threads), which scales without per-relay threads.
            if let Some(_splice_slot) = crate::transport::tcp::try_enter_kernel_splice_relay() {
                tracing::debug!("using Linux splice(2) kernel relay for fallback TCP tunnel");
                crate::transport::tcp::record_kernel_splice_relay();
                return crate::transport::tcp::relay_kernel_splice_bidirectional_with_idle_timeout(
                    client,
                    fallback,
                    idle_timeout,
                )
                .await
                .map_err(HandshakeServerError::Io);
            }
            tracing::debug!(
                "kernel splice relay cap reached; using userspace fallback relay instead"
            );
            crate::transport::tcp::record_userspace_cap_hit_relay();
        }
    }

    #[cfg(not(target_os = "linux"))]
    crate::transport::tcp::record_userspace_non_linux_relay();

    let (mut client_read, mut client_write) = client.into_split();
    let (mut fallback_read, mut fallback_write) = fallback.into_split();

    let outcome = relay_fallback_userspace_loop(
        &mut client_read,
        &mut client_write,
        &mut fallback_read,
        &mut fallback_write,
        idle_timeout,
    )
    .await;

    // Whatever ended the relay -- the idle timeout, a clean half-close, or an
    // I/O error mid-stream -- tear both directions down with a graceful FIN
    // rather than letting the split halves drop. Dropping a socket that still
    // holds unread bytes makes the kernel send a RST, an observable tell a real
    // origin would not produce. Drain any ready bytes first so the close stays a
    // FIN even if a stray record arrived right before teardown.
    graceful_close_fallback_halves(
        &client_read,
        &mut client_write,
        &fallback_read,
        &mut fallback_write,
    )
    .await;

    outcome
}

async fn relay_fallback_userspace_loop(
    client_read: &mut OwnedReadHalf,
    client_write: &mut OwnedWriteHalf,
    fallback_read: &mut OwnedReadHalf,
    fallback_write: &mut OwnedWriteHalf,
    idle_timeout: Duration,
) -> Result<(), HandshakeServerError> {
    let fallback_buffer_len = relay_read_buffer_len(max_plaintext_len(0));
    let mut client_buf = vec![0_u8; fallback_buffer_len];
    let mut fallback_buf = vec![0_u8; fallback_buffer_len];
    let idle_sleep = sleep(idle_timeout);
    tokio::pin!(idle_sleep);
    let mut client_closed = false;
    let mut fallback_closed = false;

    loop {
        if client_closed && fallback_closed {
            break;
        }

        tokio::select! {
            _ = &mut idle_sleep => {
                break;
            }
            read = client_read.read(&mut client_buf), if !client_closed => {
                let n = read?;
                if n == 0 {
                    client_closed = true;
                    // Propagate the half-close promptly; best-effort so a
                    // shutdown error never skips the final graceful teardown.
                    let _ = fallback_write.shutdown().await;
                } else {
                    fallback_write.write_all(&client_buf[..n]).await?;
                    idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
            read = fallback_read.read(&mut fallback_buf), if !fallback_closed => {
                let n = read?;
                if n == 0 {
                    fallback_closed = true;
                    let _ = client_write.shutdown().await;
                } else {
                    client_write.write_all(&fallback_buf[..n]).await?;
                    idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
        }
    }

    Ok(())
}

async fn graceful_close_fallback_halves(
    client_read: &OwnedReadHalf,
    client_write: &mut OwnedWriteHalf,
    fallback_read: &OwnedReadHalf,
    fallback_write: &mut OwnedWriteHalf,
) {
    drain_read_half_to_block(client_read);
    drain_read_half_to_block(fallback_read);
    let _ = client_write.shutdown().await;
    let _ = fallback_write.shutdown().await;
}

/// Pre-PQ teardown: consume the buffered readers to recover the raw read halves,
/// then drain->FIN both directions (never a bare drop, which would RST). Used by
/// the pre-PQ deadline arm and by both forward-write deadline/peer-close arms so a
/// blocked forward write can no longer escape the phase deadline without a FIN.
async fn graceful_close_pre_pq(
    client_records: BufferedTlsRecordReader<OwnedReadHalf>,
    mut client_write: OwnedWriteHalf,
    fallback_records: BufferedTlsRecordReader<OwnedReadHalf>,
    mut fallback_write: OwnedWriteHalf,
) {
    let client_read = client_records.into_inner().into_inner();
    let fallback_read = fallback_records.into_inner().into_inner();
    graceful_close_fallback_halves(
        &client_read,
        &mut client_write,
        &fallback_read,
        &mut fallback_write,
    )
    .await;
}

async fn read_forwarded_server_hello(
    fallback: &mut TcpStream,
) -> Result<ForwardedServerHello, HandshakeServerError> {
    let raw_record = read_first_record(fallback).await?;
    let parsed = parse_server_hello(&raw_record)?;
    Ok(ForwardedServerHello { raw_record, parsed })
}

/// Adds a uniform `[0, jitter]` upward grace to `floor`. The floor is never
/// reduced, so this only ever extends a timeout: it removes the fixed constant a
/// prober could measure without ever giving a legitimate peer less time than the
/// previous behavior. Per-connection randomness (real thread RNG, not a seeded
/// stream) so the value is independent across connections.
fn jittered_timeout(floor: Duration, jitter: Duration) -> Duration {
    // Guard on the millisecond value actually used below, not on Duration::is_zero:
    // a sub-millisecond jitter is non-zero yet as_millis() == 0, which would make
    // gen_range(0..=0) silently return the bare floor while claiming to jitter.
    let jitter_ms = jitter.as_millis() as u64;
    if jitter_ms == 0 {
        return floor;
    }
    let extra = rand::thread_rng().gen_range(0..=jitter_ms);
    floor + Duration::from_millis(extra)
}

/// Client-facing first-record wait: floor + jitter. See [`FIRST_RECORD_WAIT_FLOOR`].
fn first_record_wait_timeout() -> Duration {
    let t = timeout_tuning();
    jittered_timeout(t.first_record_floor, t.first_record_jitter)
}

/// Camouflage relay idle backstop: floor + jitter. See [`FALLBACK_IDLE_TIMEOUT_FLOOR`].
fn fallback_idle_timeout() -> Duration {
    let t = timeout_tuning();
    jittered_timeout(t.fallback_idle_floor, t.fallback_idle_jitter)
}

/// Replay freshness window sized to outlast the pre-PQ phase. The ClientHello
/// timestamp is committed only AFTER the client's PQ rekey, up to the pre-PQ
/// deadline (`fallback_idle_floor`) later, so the window must exceed that
/// deadline or a slow-but-legitimate client is rejected as Stale after the
/// server already did the full PQ exchange. `DEFAULT_REPLAY_WINDOW_SECS` is added
/// on top as clock-skew slack, and the window tracks the floor automatically so
/// the two budgets can never diverge.
///
/// NOTE: this window also sets replay-cache retention, so the cache fills at
/// `replay_cache_capacity / window` sustained handshakes/sec before fail-closing
/// with `CacheFull`. `DEFAULT_REPLAY_CACHE_CAPACITY` is sized against this window;
/// an operator who raises `fallback_idle_floor_ms` (widening the window) should
/// raise `replay_cache_capacity` to keep the same throughput headroom.
fn replay_freshness_window_secs() -> u64 {
    timeout_tuning()
        .fallback_idle_floor
        .as_secs()
        .saturating_add(DEFAULT_REPLAY_WINDOW_SECS)
}

/// Deployment-wide timeout tuning, set once at server startup from config.
/// Tests and any non-`run` caller fall back to the built-in constants.
#[derive(Clone, Copy)]
struct TimeoutTuning {
    first_record_floor: Duration,
    first_record_jitter: Duration,
    fallback_idle_floor: Duration,
    fallback_idle_jitter: Duration,
}

impl TimeoutTuning {
    fn defaults() -> Self {
        Self {
            first_record_floor: FIRST_RECORD_WAIT_FLOOR,
            first_record_jitter: FIRST_RECORD_WAIT_JITTER,
            fallback_idle_floor: FALLBACK_IDLE_TIMEOUT_FLOOR,
            fallback_idle_jitter: FALLBACK_IDLE_TIMEOUT_JITTER,
        }
    }

    fn from_server_config(config: &ServerConfig) -> Self {
        Self {
            first_record_floor: Duration::from_millis(config.first_record_wait_floor_ms),
            first_record_jitter: Duration::from_millis(config.first_record_wait_jitter_ms),
            fallback_idle_floor: Duration::from_millis(config.fallback_idle_floor_ms),
            fallback_idle_jitter: Duration::from_millis(config.fallback_idle_jitter_ms),
        }
    }
}

static TIMEOUT_TUNING: OnceLock<TimeoutTuning> = OnceLock::new();

fn timeout_tuning() -> TimeoutTuning {
    TIMEOUT_TUNING
        .get()
        .copied()
        .unwrap_or_else(TimeoutTuning::defaults)
}

async fn read_first_record(stream: &mut TcpStream) -> Result<Vec<u8>, HandshakeServerError> {
    timeout(HANDSHAKE_TIMEOUT, read_record(stream))
        .await
        .map_err(|_| HandshakeServerError::Timeout)?
        .map_err(HandshakeServerError::Io)
}

/// Bounds a handshake-phase write so an authenticated peer that stops reading
/// cannot stall it indefinitely (pinning the slot/permits/fds between auth and
/// data mode). Reuses HANDSHAKE_TIMEOUT, the established handshake-phase bound.
async fn write_all_with_handshake_timeout<W>(
    stream: &mut W,
    buf: &[u8],
) -> Result<(), HandshakeServerError>
where
    W: AsyncWrite + Unpin,
{
    timeout(HANDSHAKE_TIMEOUT, stream.write_all(buf))
        .await
        .map_err(|_| HandshakeServerError::Timeout)?
        .map_err(HandshakeServerError::Io)
}

async fn read_first_client_record(
    stream: &mut TcpStream,
) -> Result<FirstClientRead, HandshakeServerError> {
    read_first_client_record_with_timeout(stream, first_record_wait_timeout()).await
}

async fn read_first_client_record_with_timeout<R>(
    stream: &mut R,
    read_timeout: Duration,
) -> Result<FirstClientRead, HandshakeServerError>
where
    R: AsyncRead + Unpin,
{
    let deadline = Instant::now() + read_timeout;
    let mut header = [0_u8; TLS_HEADER_LEN];
    let mut header_pos = 0;
    while header_pos < TLS_HEADER_LEN {
        let read = read_before_deadline(stream, &mut header[header_pos..], deadline).await;
        match read {
            Ok(Some(0)) if header_pos == 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS record header ended early",
                )
                .into());
            }
            Ok(Some(0)) => {
                return Ok(FirstClientRead::FallbackPrefix(
                    header[..header_pos].to_vec(),
                ));
            }
            Ok(Some(n)) => header_pos += n,
            Ok(None) => {
                return Ok(FirstClientRead::FallbackPrefix(
                    header[..header_pos].to_vec(),
                ));
            }
            Err(err) => return Err(err.into()),
        }
    }

    let parsed = match parse_header(&header) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(FirstClientRead::FallbackPrefix(header.to_vec())),
    };

    let mut record = vec![0_u8; parsed.total_len];
    record[..TLS_HEADER_LEN].copy_from_slice(&header);
    let mut record_pos = TLS_HEADER_LEN;
    while record_pos < parsed.total_len {
        let read = read_before_deadline(stream, &mut record[record_pos..], deadline).await;
        match read {
            Ok(Some(0)) => {
                return Ok(FirstClientRead::FallbackPrefix(
                    record[..record_pos].to_vec(),
                ))
            }
            Ok(Some(n)) => record_pos += n,
            Ok(None) => {
                return Ok(FirstClientRead::FallbackPrefix(
                    record[..record_pos].to_vec(),
                ))
            }
            Err(err) => return Err(err.into()),
        }
    }

    Ok(FirstClientRead::Record(record))
}

async fn read_before_deadline<R>(
    stream: &mut R,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<Option<usize>, io::Error>
where
    R: AsyncRead + Unpin,
{
    match timeout_at(deadline, stream.read(buf)).await {
        Ok(read) => read.map(Some),
        Err(_) => Ok(None),
    }
}

async fn connect_tcp_with_timeout(addr: &str) -> Result<TcpStream, HandshakeServerError> {
    connect_future_with_timeout(connect_tuned_tcp_host(addr), HANDSHAKE_TIMEOUT).await
}

async fn connect_future_with_timeout<F>(
    connect: F,
    connect_timeout: Duration,
) -> Result<TcpStream, HandshakeServerError>
where
    F: Future<Output = io::Result<TcpStream>>,
{
    timeout(connect_timeout, connect)
        .await
        .map_err(|_| HandshakeServerError::OutboundConnectTimeout)?
        .map_err(HandshakeServerError::Io)
}

#[allow(clippy::too_many_arguments)]
async fn run_authenticated_data_mode(
    handshake: AuthenticatedHandshake,
    fixed_data_target: Option<&str>,
    identity_secret_key: Arc<zeroize::Zeroizing<Vec<u8>>>,
    sandwich_secret: &[u8],
    traffic: TrafficConfig,
    udp: &UdpConfig,
    mut pending_replay: Option<PendingReplayEntry>,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    handshake.session_keys.protect_secret_memory();
    let padding = PaddingProfile::from_config(traffic)?;
    let timing = TimingProfile::from_config(traffic);
    let cover = CoverTrafficProfile::from_config(traffic);
    let mut client_open = DataRecordCodec::new(
        AeadCodec::new(
            handshake.session_keys.client_key,
            handshake.session_keys.client_nonce,
        ),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let mut server_seal = DataRecordCodec::new(
        AeadCodec::new(
            handshake.session_keys.server_key,
            handshake.session_keys.server_nonce,
        ),
        padding,
        SERVER_TO_CLIENT_AAD,
    );
    client_open.protect_secret_memory();
    server_seal.protect_secret_memory();

    let (client_read, mut client_write) = handshake.client.into_split();
    let (fallback_read, mut fallback_write) = handshake.fallback.into_split();
    let mut client_records = TlsRecordReader::buffered(client_read);
    let mut fallback_records = TlsRecordReader::buffered(fallback_read);
    let mut client_record = Vec::new();
    let mut fallback_record = Vec::new();
    let mut client_camouflage_records_before_pq = 0usize;
    let mut client_camouflage_bytes_before_pq = 0usize;
    let mut fallback_records_before_pq = 0usize;
    let mut fallback_bytes_before_pq = 0usize;
    // Reassembles the client's PQ rekey (PX1Q), now split across several
    // variable-length FramedChunk records (PAR-21). On this direction no
    // camouflage interleaves after the handshake — the client writes all chunks
    // contiguously in one flight — so successive opened records accumulate here
    // until the full rekey frame is recovered.
    let mut pq_rekey_reassembler = FramedReassembler::default();

    tracing::info!(
        cid,
        sni = %handshake.client_hello.sni,
        "authenticated pre-data mode started; waiting for client PQ rekey"
    );

    // Hard deadline for the whole pre-PQ phase. A client that completes the
    // camouflage handshake (passing PSK/X25519 auth) must send its PQ rekey
    // record promptly (legitimately within milliseconds). This deadline is NOT
    // reset by incoming records: otherwise a malicious authenticated client could
    // trickle one camouflage record just under the timeout forever — never
    // sending the PQ rekey — pinning the global connection slot, the per-source
    // permit, and both fds, and forwarding each record to the fallback origin
    // unbounded. A fixed, generous deadline bounds the entire phase regardless.
    // Anchored as an absolute Instant so it also bounds a BLOCKED forward write
    // (via timeout_at below), not only an idle wait inside the select.
    let pre_pq_deadline = Instant::now() + fallback_idle_timeout();

    loop {
        tokio::select! {
            _ = sleep_until(pre_pq_deadline) => {
                tracing::debug!(
                    cid,
                    "pre-PQ deadline reached before client PQ rekey; tearing down"
                );
                // Close both halves with a graceful drain->FIN, not a bare drop.
                // The pre-PQ phase is still forwarding camouflage records to the
                // fallback origin, so a stalled-but-trickling client may have
                // unread RX buffered; dropping the sockets would make close() emit
                // a RST — exactly the FIN/RST tell the relay-teardown gate forbids.
                graceful_close_pre_pq(
                    client_records,
                    client_write,
                    fallback_records,
                    fallback_write,
                )
                .await;
                return Ok(());
            }
            read = client_records.read_record_into(&mut client_record) => {
                match read {
                    Ok(()) => {}
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };
                log_record_read(
                    cid,
                    "client->server",
                    "server-predata-client-reader",
                    &client_record,
                );

                match client_open.open(&client_record) {
                    Ok(chunk_payload) => {
                        // Accumulate PX1Q chunks; proceed only once the whole
                        // rekey frame is reassembled. Incomplete => wait for the
                        // next chunk (still bounded by pre_pq_deadline, which is
                        // not reset by incoming records). Malformed framing/payload
                        // from the (already authenticated) client tears down
                        // gracefully (drain->FIN), never a bare-drop RST -- the
                        // no-RST contract every other arm in this loop honors.
                        let first_payload = match pq_rekey_reassembler
                            .push(&chunk_payload, MAX_PQ_HANDSHAKE_FRAME)
                        {
                            Ok(Some(payload)) => payload,
                            Ok(None) => continue,
                            Err(err) => {
                                tracing::debug!(cid, error = %err, "malformed PX1Q chunk framing; graceful teardown");
                                graceful_close_pre_pq(
                                    client_records,
                                    client_write,
                                    fallback_records,
                                    fallback_write,
                                )
                                .await;
                                return Ok(());
                            }
                        };
                        let pq_rekey = match PqRekeyRequest::decode_ref(first_payload.as_slice()) {
                            Ok(pq_rekey) => pq_rekey,
                            Err(err) => {
                                tracing::debug!(cid, error = %err, "malformed PX1Q payload; graceful teardown");
                                graceful_close_pre_pq(
                                    client_records,
                                    client_write,
                                    fallback_records,
                                    fallback_write,
                                )
                                .await;
                                return Ok(());
                            }
                        };
                        let client_x25519_public = pq_rekey.client_x25519_public;
                        let client_mlkem_public_key = pq_rekey.client_mlkem_public_key.to_vec();
                        if !commit_pending_replay_entry(&mut pending_replay).await? {
                            tracing::warn!(cid, "closing on replayed ClientHello after data proof");
                            // Graceful drain->FIN instead of a bare drop (M-1). At
                            // this point the fallback origin's read half (and any
                            // client RX buffered in the record reader) may hold
                            // unread bytes, so dropping the sockets would make
                            // close() emit a RST -- the FIN/RST tell every other
                            // teardown here avoids. Mirrors the pre-PQ-deadline
                            // teardown above; covers Replayed/Stale/CacheFull.
                            let client_read = client_records.into_inner().into_inner();
                            let fallback_read = fallback_records.into_inner().into_inner();
                            graceful_close_fallback_halves(
                                &client_read,
                                &mut client_write,
                                &fallback_read,
                                &mut fallback_write,
                            )
                            .await;
                            return Ok(());
                        }
                        let server_ephemeral = X25519KeyPair::generate();
                        crate::process_hardening::protect_secret_bytes(
                            "pq_rekey.server_x25519_private",
                            &server_ephemeral.private,
                        );
                        let x25519_ephemeral_shared = zeroize::Zeroizing::new(x25519_shared_secret(
                            &server_ephemeral.private,
                            &client_x25519_public,
                        ));
                        let mut pq_encapsulation =
                            encapsulate_mlkem_blocking(client_mlkem_public_key).await?;
                        // Move the ML-KEM shared secret into a wipe-on-drop local and
                        // clear the struct's own [u8;32] copy immediately. A struct-level
                        // ZeroizeOnDrop can't help (`.ciphertext` is moved into the
                        // key-exchange payload below, partially moving the struct so its
                        // Drop glue can never run), and every `?` between here and the
                        // rekey (encode / seal / write / rekey) would otherwise drop the
                        // secret un-wiped — a path the new degenerate-X25519 rekey
                        // rejection makes reachable. The Zeroizing local clears on ANY
                        // return.
                        let pq_shared_secret =
                            zeroize::Zeroizing::new(pq_encapsulation.shared_secret);
                        pq_encapsulation.shared_secret.zeroize();
                        let cipher_suite = server_data_cipher_suite();
                        let key_exchange_payload = ServerKeyExchange {
                            server_x25519_public: server_ephemeral.public,
                            mlkem_ciphertext: pq_encapsulation.ciphertext,
                        }
                        .encode_with_suite(cipher_suite)?;
                        let pq_identity_binding =
                            identity::pq_rekey_binding(first_payload.as_slice(), &key_exchange_payload);
                        crate::process_hardening::protect_secret_bytes(
                            "pq_rekey.mlkem_shared_secret",
                            &*pq_shared_secret,
                        );
                        let mut rng = StdRng::from_entropy();
                        // Split the key-exchange (PX1K) record across several
                        // variable-length chunks for the same reason as the client
                        // PX1Q split (PAR-21): no fixed ~1632-byte single record,
                        // no equal-length run, no fixed per-session regime. Sealed
                        // into one buffer => one write => single flight.
                        let mut key_exchange_record = Vec::new();
                        for chunk in FramedChunk::encode_all_shaped(
                            &key_exchange_payload,
                            &mut rng,
                            PQ_HANDSHAKE_CHUNK_MIN_PLAINTEXT,
                            PQ_HANDSHAKE_CHUNK_MAX_PLAINTEXT,
                        )? {
                            server_seal.seal_into(&chunk, &mut rng, &mut key_exchange_record)?;
                        }
                        log_outer_write(
                            cid,
                            "server->client",
                            "server-key-exchange-writer",
                            key_exchange_payload.len(),
                            &key_exchange_record,
                        );
                        write_all_with_handshake_timeout(&mut client_write, &key_exchange_record)
                            .await?;
                        tracing::info!(
                            cid,
                            client_camouflage_records_before_pq,
                            client_camouflage_bytes_before_pq,
                            fallback_records_before_pq,
                            fallback_bytes_before_pq,
                            key_exchange_record_len = key_exchange_record.len(),
                            "server key exchange record written"
                        );
                        let rekeyed_keys = apply_server_pq_rekey(
                            cipher_suite,
                            &mut client_open,
                            &mut server_seal,
                            &handshake.session_keys,
                            &x25519_ephemeral_shared,
                            &pq_shared_secret,
                            sandwich_secret,
                        )?;
                        rekeyed_keys.protect_secret_memory();
                        let identity_signature = sign_server_identity_blocking(
                            identity_secret_key,
                            rekeyed_keys.transcript_hash,
                            handshake.server_public_key,
                            pq_identity_binding,
                            rekeyed_keys.epoch,
                        )
                        .await?;
                        let identity_payload = ServerIdentityProof {
                            signature: identity_signature,
                        }
                        .encode()?;
                        let identity_chunk_plaintext =
                            server_identity_chunk_plaintext_len(&mut rng);
                        let identity_chunks =
                            ServerIdentityChunk::encode_all(&identity_payload, identity_chunk_plaintext)?;
                        write_server_identity_chunks(
                            &mut client_write,
                            &mut server_seal,
                            identity_chunks,
                            &mut rng,
                            timing,
                            cid,
                        )
                        .await?;

                        drop(fallback_write);
                        // Release the fallback read half too: it owns the
                        // fallback origin's read-side fd, which is no longer
                        // needed once the client has switched to ParallaX data
                        // mode. Without this, the fd lingers for the entire
                        // proxied session (one extra fd per authenticated relay,
                        // beyond the 2 the connection limit budgets).
                        drop(fallback_records);
                        // Bound the wait for the first data-mode record. Without a
                        // deadline, an authenticated client that completes the PQ
                        // rekey but never sends a CONNECT/data record pins this
                        // connection's slot, per-source permit, and both fds
                        // indefinitely (the post-CONNECT relay watchdog is only
                        // reached after this read returns).
                        match timeout(
                            fallback_idle_timeout(),
                            client_records.read_record_into(&mut client_record),
                        )
                        .await
                        {
                            Ok(result) => match result {
                                Ok(()) => {}
                                Err(err) if is_clean_close(&err) => return Ok(()),
                                Err(err) => return Err(HandshakeServerError::Io(err)),
                            },
                            Err(_) => {
                                tracing::debug!(
                                    cid,
                                    "no data-mode record before idle backstop; tearing down"
                                );
                                // Graceful drain->FIN on the client (the fallback
                                // halves were already dropped above): avoid a RST
                                // if the client left unread bytes buffered.
                                let client_read = client_records.into_inner().into_inner();
                                drain_read_half_to_block(&client_read);
                                let _ = client_write.shutdown().await;
                                return Ok(());
                            }
                        }
                        log_record_read(
                            cid,
                            "client->server",
                            "server-connect-reader",
                            &client_record,
                        );
                        let mut first_payload_range =
                            client_open.open_in_place_payload_range(&mut client_record)?;
                        tracing::info!(
                            cid,
                            client_camouflage_records_before_pq,
                            fallback_records_before_pq,
                            "ParallaX data mode switch confirmed"
                        );

                        // Set on the Verified+enabled path only: the retained
                        // ephemeral QUIC endpoint and the accepted connection,
                        // kept alive so the single-Connect relay can carry data
                        // over a reliable bidi stream. `None` on every other path
                        // (declined, probe not Verified, or udp.enabled=false), in
                        // which case the relay stays byte-identical on TCP.
                        let mut retained_quic: Option<ServerProbedQuic> = None;

                        // Client-initiated, fail-soft UDP negotiation (PX1G). The
                        // server NEVER offers UDP unsolicited. When udp.enabled it
                        // offers, probes, and -- only if the client reports the
                        // probe Verified (PX1P) -- RETAINS the QUIC connection for
                        // the single-Connect data relay. This keeps every
                        // config/version combination desync-free.
                        if crate::protocol::command::UdpRequest::has_magic(
                            &client_record[first_payload_range.clone()],
                        ) {
                            use crate::protocol::command::{
                                UdpDecline, UdpOffer, UdpProbeAck, UDP_CC_BBR,
                                UDP_DECLINE_DISABLED, UDP_FEC_ADAPTIVE,
                            };

                            let offered = if udp.enabled {
                                // Route through the process-wide stable carrier (bound
                                // on the server's listen address in `run`): register
                                // this session's offer_id and hand the client the
                                // stable QUIC port. The carrier marker-terminates the
                                // client and delivers the connection here by offer_id
                                // (the client sets it as its first-Initial DCID),
                                // splicing every unauthenticated Initial to the origin.
                                // No per-session endpoint is bound.
                                let carrier = SERVER_QUIC_CARRIER
                                    .lock()
                                    .expect("quic carrier mutex poisoned")
                                    .clone();
                                match carrier {
                                    Some(carrier) => match carrier.local_addr() {
                                        Ok(addr) if addr.port() != 0 => {
                                            let offer_id: [u8; 16] = rand::random();
                                            let rx = carrier.register(offer_id);
                                            // The client connects QUIC to the same
                                            // stable host:port it reached us on over
                                            // TCP (the carrier's bound port).
                                            Some((carrier, offer_id, addr.port(), rx))
                                        }
                                        _ => None,
                                    },
                                    None => None,
                                }
                            } else {
                                None
                            };

                            if let Some((carrier, offer_id, port, rx)) = offered {
                                let offer = UdpOffer {
                                    offer_id,
                                    udp_port: port,
                                    port_hop_seed: 0,
                                    cc: UDP_CC_BBR,
                                    fec_profile: UDP_FEC_ADAPTIVE,
                                    ignore_client_bandwidth: false,
                                }
                                .encode()
                                .expect("valid udp offer");
                                let offer_record = server_seal.seal(&offer, &mut rng)?;
                                write_all_with_handshake_timeout(&mut client_write, &offer_record)
                                    .await?;

                                // Best-effort, fully time-bounded: accept the client's
                                // QUIC connection and answer one probe. The QUIC
                                // handshake (`incoming.await`) and the datagram read
                                // inside `serve_probe` MUST be bounded too — a peer that
                                // completes the handshake then goes silent on datagrams
                                // (a black-holed/throttled UDP path, exactly what this
                                // probe exists to detect) would otherwise pin this task
                                // on quinn's ~30s idle timeout and stall the TCP control
                                // stream (PX1P + the real command stay unread). A timeout
                                // here does NOT desync: the client always sends PX1P next
                                // and we always read it below.
                                // The server's probe budget must comfortably exceed
                                // the client's TOTAL patience (connect window + probe
                                // window = 2x probe_timeout), because the server's
                                // clock starts when it writes the offer — one offer
                                // propagation ahead of the client's connect clock. Use
                                // 2x the configured timeout: large enough that a real-
                                // RTT QUIC handshake + probe round-trip finishes before
                                // the endpoint is closed, yet still far below quinn's
                                // ~30s idle pin (the H1 anti-stall goal). A single 1x
                                // window let a real handshake consume the whole budget
                                // and misreport a healthy path as Unreachable.
                                let probe_budget = std::time::Duration::from_millis(
                                    u64::from(udp.probe_timeout_ms.max(1)),
                                )
                                .saturating_mul(2);
                                // Lift the accepted connection OUT of the timeout
                                // scope so it can outlive the probe. quinn
                                // application-closes a connection when its last
                                // `Connection` handle drops, so we must hold it
                                // (and the endpoint) for the relay's whole life.
                                // `serve_probe` only QUEUES its reply, so the
                                // connection must stay alive past the probe
                                // regardless; here we additionally keep it for the
                                // data path when the client confirms Verified.
                                // Accept the probe QUIC connection ONLY from the
                                // authenticated TCP peer's source IP (L-6): the carrier
                                // is reachable by anyone, and although the marker fork
                                // already gates termination, the source-IP check keeps
                                // a racing/off-path connector that somehow learned the
                                // offer_id from stealing the slot. peer_addr() reads it
                                // off the live socket; None fails closed (decline QUIC,
                                // stay on TCP).
                                let expect_ip = client_write.peer_addr().ok().map(|a| a.ip());
                                // Await the carrier's handoff for this offer_id (bounded
                                // by the probe budget), then serve the probe on the
                                // routed connection. A timeout / dropped sender means no
                                // client connected in time — unregister so the offer_id
                                // does not leak, and stay on TCP.
                                let probed_conn: Option<ServerProbedQuic> =
                                    match tokio::time::timeout(probe_budget, rx).await {
                                        Ok(Ok(conn))
                                            if expect_ip
                                                .is_some_and(|ip| conn.remote_address().ip() == ip) =>
                                        {
                                            serve_probed_quic_on_conn(
                                                conn,
                                                sandwich_secret,
                                                &offer_id,
                                                cid,
                                            )
                                            .await
                                        }
                                        Ok(Ok(conn)) => {
                                            tracing::debug!(
                                                cid,
                                                peer = %conn.remote_address(),
                                                "declining fast-plane QUIC (source IP / fail-closed)"
                                            );
                                            drop(conn);
                                            None
                                        }
                                        _ => {
                                            carrier.unregister(&offer_id);
                                            None
                                        }
                                    };

                                client_record.clear();
                                // BOUNDED read: we are holding the ephemeral QUIC
                                // endpoint (a live UDP-socket fd) and the accepted
                                // connection (`probed_conn`) while waiting for the
                                // client's PX1P ack. A misbehaving client that
                                // withholds PX1P here would otherwise pin both
                                // indefinitely (the keep-alive masks quinn's idle
                                // timeout). On timeout, eagerly close both so the
                                // UDP fd is released promptly, then fail the
                                // connection. A real client always sends PX1P next.
                                match tokio::time::timeout(
                                    PX1_CONTROL_READ_TIMEOUT,
                                    client_records.read_record_into(&mut client_record),
                                )
                                .await
                                {
                                    Ok(res) => match res {
                                        Ok(()) => {}
                                        Err(err) if is_clean_close(&err) => {
                                            if let Some(probed) = probed_conn {
                                                probed.conn.close(0u32.into(), b"px1p-eof");
                                            }
                                            return Ok(());
                                        }
                                        Err(err) => return Err(HandshakeServerError::Io(err)),
                                    },
                                    Err(_) => {
                                        tracing::warn!(
                                            cid,
                                            "udp PX1P ack read timed out; releasing QUIC connection"
                                        );
                                        if let Some(probed) = probed_conn {
                                            probed.conn.close(0u32.into(), b"px1p-timeout");
                                        }
                                        return Err(HandshakeServerError::Io(io::Error::new(
                                            io::ErrorKind::TimedOut,
                                            "udp PX1P ack read timed out",
                                        )));
                                    }
                                }
                                let ack_range =
                                    client_open.open_in_place_payload_range(&mut client_record)?;
                                let ack_status = match UdpProbeAck::decode(&client_record[ack_range])
                                {
                                    Ok(ack) if ack.offer_id == offer_id => {
                                        tracing::info!(cid, status = ?ack.status, "udp probe ack");
                                        Some(ack.status)
                                    }
                                    Ok(ack) => {
                                        // The ack echoed a DIFFERENT offer_id than the
                                        // one we generated for this session. It is
                                        // AEAD-authenticated, so this is defense-in-
                                        // depth, but a mismatched offer_id is never a
                                        // valid response to THIS offer: treat it as a
                                        // declined probe (do NOT retain QUIC) and fall
                                        // through to the TCP path.
                                        tracing::debug!(
                                            cid,
                                            status = ?ack.status,
                                            "udp probe ack offer_id mismatch; declining"
                                        );
                                        None
                                    }
                                    Err(err) => {
                                        tracing::debug!(cid, error = %err, "udp probe ack decode failed");
                                        None
                                    }
                                };

                                // Retain the QUIC connection for the data relay
                                // ONLY when the client reported the probe Verified.
                                // The PX1P status is the single authoritative
                                // cross-side fact (the server cannot otherwise
                                // observe whether its queued echo reached the
                                // client), so both ends gate on the SAME signal:
                                // the client commits its relay to QUIC iff its probe
                                // was Verified, and the server retains iff the ack
                                // says Verified. Any other outcome -> drop the conn
                                // and close the endpoint, staying on TCP.
                                match udp_retention_decision(ack_status, probed_conn.is_some()) {
                                    UdpRetentionDecision::Retain => {
                                        let probed = probed_conn
                                            .expect("Retain implies a retained connection");
                                        tracing::info!(
                                            cid,
                                            "retaining QUIC fast-plane connection for data relay"
                                        );
                                        #[cfg(test)]
                                        {
                                            *RETAINED_QUIC_CONN_FOR_TEST
                                                .lock()
                                                .expect("retained quic test hook poisoned") =
                                                Some(carrier.endpoint_handle());
                                        }
                                        retained_quic = Some(probed);
                                    }
                                    UdpRetentionDecision::HardFail => {
                                        // Verified ack but we no longer hold the
                                        // probed connection (the probe budget elapsed
                                        // after serve_probe queued its echo). The
                                        // client has committed its relay to QUIC and
                                        // will reset, so fail identically instead of
                                        // silently diverging onto TCP. The shared
                                        // carrier persists for other sessions. (L-7)
                                        tracing::warn!(
                                            cid,
                                            "Verified PX1P ack but server lost the probed QUIC \
                                             connection; resetting to stay aligned with the client"
                                        );
                                        return Err(HandshakeServerError::Io(io::Error::new(
                                            io::ErrorKind::ConnectionAborted,
                                            "Verified PX1P ack with no retained QUIC connection",
                                        )));
                                    }
                                    UdpRetentionDecision::StayOnTcp => {
                                        // Not Verified: the client also stays on TCP.
                                        // Close any accepted connection (the shared
                                        // carrier itself persists for other sessions).
                                        if let Some(probed) = probed_conn {
                                            probed.conn.close(0u32.into(), b"done");
                                        }
                                    }
                                }
                            } else {
                                let decline = UdpDecline {
                                    reason: UDP_DECLINE_DISABLED,
                                }
                                .encode();
                                let decline_record = server_seal.seal(&decline, &mut rng)?;
                                write_all_with_handshake_timeout(
                                    &mut client_write,
                                    &decline_record,
                                )
                                .await?;
                            }

                            // Read the client's real first command.
                            client_record.clear();
                            // BOUNDED read: on the Verified path we are now holding
                            // the retained QUIC endpoint + connection in
                            // `retained_quic` (and on the non-Verified path the
                            // endpoint was already closed above). A misbehaving
                            // client that sent a Verified PX1P but then withholds the
                            // real command would pin the retained UDP fd + connection
                            // indefinitely; bound the read and, on timeout, eagerly
                            // release whatever is held before failing.
                            match tokio::time::timeout(
                                PX1_CONTROL_READ_TIMEOUT,
                                client_records.read_record_into(&mut client_record),
                            )
                            .await
                            {
                                Ok(res) => match res {
                                    Ok(()) => {}
                                    Err(err) if is_clean_close(&err) => {
                                        drop_retained_quic(retained_quic.take());
                                        return Ok(());
                                    }
                                    Err(err) => return Err(HandshakeServerError::Io(err)),
                                },
                                Err(_) => {
                                    tracing::warn!(
                                        cid,
                                        "udp real first-command read timed out; releasing QUIC"
                                    );
                                    drop_retained_quic(retained_quic.take());
                                    return Err(HandshakeServerError::Io(io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        "udp real first-command read timed out",
                                    )));
                                }
                            }
                            first_payload_range =
                                client_open.open_in_place_payload_range(&mut client_record)?;
                        }

                        let first_payload = &mut client_record[first_payload_range];
                        if SpeedTestRequest::has_magic(first_payload) {
                            // Speed test stays on TCP in this slice; release any
                            // retained QUIC connection so no idle fast-plane
                            // connection lingers.
                            drop_retained_quic(retained_quic);
                            let request = SpeedTestRequest::decode(first_payload)?;
                            return run_authenticated_speed_test_mode(
                                client_records,
                                client_write,
                                client_open,
                                server_seal,
                                request,
                                max_plaintext_len(traffic.max_padding),
                                cid,
                            )
                            .await;
                        }

                        if MuxFrame::has_magic(first_payload) {
                            // Mux stays on TCP in this slice; release any retained
                            // QUIC connection.
                            drop_retained_quic(retained_quic);
                            let first_frames = MuxFrame::decode_all(first_payload)?;
                            return run_authenticated_mux_data_mode(
                                client_records,
                                client_write,
                                client_open,
                                server_seal,
                                first_frames,
                                ServerMuxContext {
                                    fixed_data_target,
                                    timing,
                                    cover,
                                    chunk_size: max_plaintext_len(traffic.max_padding),
                                    // Use the server's own stream ceiling, clamped
                                    // to an absolute hard cap so a large configured
                                    // value can't inflate per-connection fd usage.
                                    max_streams: (traffic.max_concurrent_streams as usize)
                                        .min(SERVER_MUX_MAX_STREAMS),
                                    cid,
                                    target_write_timeout: MUX_TARGET_WRITE_TIMEOUT,
                                },
                            )
                            .await;
                        }

                        let (target_addr, initial_payload) =
                            resolve_connect_target(first_payload, fixed_data_target)?;
                        let mut target =
                            connect_outbound_target(&target_addr, fixed_data_target.is_some())
                                .await?;
                        tune_tcp_stream(&target)?;
                        if !initial_payload.is_empty() {
                            target.write_all(initial_payload).await?;
                            initial_payload.zeroize();
                        }
                        let (target_read, target_write) = target.into_split();
                        return DataRelay {
                            client_records,
                            client_write,
                            target_read,
                            target_write,
                            client_open,
                            server_seal,
                            timing,
                            cover,
                            chunk_size: max_plaintext_len(traffic.max_padding),
                            retained_quic,
                            cid,
                        }
                        .run()
                        .await;
                    }
                    Err(DataRecordError::Aead(_)) | Err(DataRecordError::NotApplicationData) => {
                        client_camouflage_records_before_pq += 1;
                        client_camouflage_bytes_before_pq += client_record.len();
                        if client_camouflage_records_before_pq > PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT
                        {
                            // Same 64-record ceiling as the fallback->client cap
                            // below (that direction pauses; this one tears down). A
                            // legitimate client emits only a handful of camouflage
                            // records before its PQ rekey, so an unbounded
                            // client->fallback stream is abuse. Drain->FIN both
                            // halves (never a bare drop, which would RST) and stop.
                            tracing::debug!(
                                cid,
                                client_camouflage_records_before_pq,
                                client_camouflage_bytes_before_pq,
                                pre_pq_forward_limit = PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT,
                                "client camouflage record cap reached before PQ rekey; tearing down"
                            );
                            graceful_close_pre_pq(
                                client_records,
                                client_write,
                                fallback_records,
                                fallback_write,
                            )
                            .await;
                            return Ok(());
                        }
                        if client_camouflage_records_before_pq == 1
                            || client_camouflage_records_before_pq == 8
                        {
                            tracing::info!(
                                cid,
                                client_camouflage_records_before_pq,
                                client_camouflage_bytes_before_pq,
                                record_len = client_record.len(),
                                "forwarding client camouflage record before ParallaX PQ rekey"
                            );
                        }
                        match timeout_at(
                            pre_pq_deadline,
                            fallback_write.write_all(&client_record),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) if is_write_peer_close(&err) => {
                                // The cover origin (fallback) closed; the client is
                                // still live mid-camouflage and may have unread RX,
                                // so drain->FIN both halves instead of a bare drop
                                // (which would RST the client — the teardown tell we
                                // avoid), matching the deadline arm below.
                                let _ = err;
                                graceful_close_pre_pq(
                                    client_records,
                                    client_write,
                                    fallback_records,
                                    fallback_write,
                                )
                                .await;
                                return Ok(());
                            }
                            Ok(Err(err)) => return Err(HandshakeServerError::Io(err)),
                            Err(_) => {
                                tracing::debug!(
                                    cid,
                                    "pre-PQ deadline reached during client camouflage forward; tearing down"
                                );
                                graceful_close_pre_pq(
                                    client_records,
                                    client_write,
                                    fallback_records,
                                    fallback_write,
                                )
                                .await;
                                return Ok(());
                            }
                        }
                    }
                    Err(err) => return Err(HandshakeServerError::DataRecord(err)),
                }
            }
            read = fallback_records.read_record_into(&mut fallback_record),
                if fallback_records_before_pq < PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT => {
                match read {
                    Ok(()) => {}
                    Err(err) if is_clean_close(&err) => return Ok(()),
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };
                log_record_read(
                    cid,
                    "fallback->server",
                    "server-predata-fallback-reader",
                    &fallback_record,
                );
                fallback_records_before_pq += 1;
                fallback_bytes_before_pq += fallback_record.len();
                if let Ok(header) = crate::tls::record::parse_header(&fallback_record) {
                    if fallback_records_before_pq == 1 {
                        tracing::info!(
                            cid,
                            direction = "fallback->client",
                            task_name = "server-camouflage-writer",
                            fallback_records_before_pq,
                            fallback_bytes_before_pq,
                            outer_tls_payload_len = header.payload_len,
                            tls_content_type = header.content_type,
                            "forwarding fallback camouflage record before ParallaX PQ rekey"
                        );
                    } else if fallback_records_before_pq == PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT {
                        tracing::warn!(
                            cid,
                            direction = "fallback->client",
                            task_name = "server-camouflage-writer",
                            fallback_records_before_pq,
                            fallback_bytes_before_pq,
                            outer_tls_payload_len = header.payload_len,
                            tls_content_type = header.content_type,
                            client_residual_budget = CLIENT_RESIDUAL_CAMOUFLAGE_RECORD_BUDGET,
                            pre_pq_forward_limit = PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT,
                            "pre-PQ fallback camouflage forward limit reached; pausing fallback \
                             reads until ParallaX PQ rekey"
                        );
                    }
                } else if fallback_records_before_pq == PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT {
                    tracing::warn!(
                        cid,
                        fallback_records_before_pq,
                        fallback_bytes_before_pq,
                        record_len = fallback_record.len(),
                        client_residual_budget = CLIENT_RESIDUAL_CAMOUFLAGE_RECORD_BUDGET,
                        pre_pq_forward_limit = PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT,
                        "pre-PQ fallback camouflage forward limit reached with unparsed TLS \
                         record; pausing fallback reads until ParallaX PQ rekey"
                    );
                }
                match timeout_at(pre_pq_deadline, client_write.write_all(&fallback_record)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) if is_write_peer_close(&err) => {
                        // The client closed; the fallback origin is still live, so
                        // drain->FIN both halves instead of a bare drop (RST tell),
                        // matching the deadline arm below.
                        let _ = err;
                        graceful_close_pre_pq(
                            client_records,
                            client_write,
                            fallback_records,
                            fallback_write,
                        )
                        .await;
                        return Ok(());
                    }
                    Ok(Err(err)) => return Err(HandshakeServerError::Io(err)),
                    Err(_) => {
                        tracing::debug!(
                            cid,
                            "pre-PQ deadline reached during fallback camouflage forward; tearing down"
                        );
                        graceful_close_pre_pq(
                            client_records,
                            client_write,
                            fallback_records,
                            fallback_write,
                        )
                        .await;
                        return Ok(());
                    }
                }
            }
        }
    }
}

fn resolve_connect_target<'a>(
    first_payload: &'a mut [u8],
    fixed_data_target: Option<&str>,
) -> Result<(String, &'a mut [u8]), HandshakeServerError> {
    crate::process_hardening::exclude_from_core_dump(
        "connect_request.first_payload",
        first_payload,
    );
    match ConnectRequest::decode_ref(first_payload) {
        Ok(request) => {
            request.protect_plaintext_memory();
            let payload_len = request.initial_payload.len();
            let target = fixed_data_target
                .map(str::to_owned)
                .unwrap_or_else(|| request.target());
            let start = first_payload.len().saturating_sub(payload_len);
            let initial_payload = &mut first_payload[start..];
            crate::process_hardening::exclude_from_core_dump(
                "connect_request.initial_payload",
                initial_payload,
            );
            Ok((target, initial_payload))
        }
        Err(ConnectRequestError::BadMagic | ConnectRequestError::Truncated) => {
            let target = fixed_data_target.ok_or(HandshakeServerError::MissingConnectTarget)?;
            crate::process_hardening::exclude_from_core_dump(
                "connect_request.fixed_target_payload",
                first_payload,
            );
            Ok((target.to_owned(), first_payload))
        }
        Err(err) => Err(HandshakeServerError::ConnectRequest(err)),
    }
}

async fn connect_outbound_target(
    target_addr: &str,
    allow_private: bool,
) -> Result<TcpStream, HandshakeServerError> {
    if allow_private {
        return connect_tcp_with_timeout(target_addr).await;
    }

    let addrs = resolve_public_target_addrs(target_addr).await?;
    connect_future_with_timeout(connect_tuned_tcp_any(addrs.as_slice()), HANDSHAKE_TIMEOUT).await
}

async fn resolve_public_target_addrs(
    target_addr: &str,
) -> Result<Vec<SocketAddr>, HandshakeServerError> {
    // Map the resolver error to a host-free message too: std's getaddrinfo
    // wrapper does not normally echo the queried host, but the raw error would
    // otherwise be the one decrypted-target path left unscrubbed (this is logged
    // via `error = %err` on the connection-close line).
    let addrs: Vec<SocketAddr> = lookup_host(target_addr)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "client-selected target lookup failed",
            )
        })?
        .collect();
    if addrs.is_empty() {
        // No host detail in the message: it is the client's decrypted destination
        // and the connection-close path logs errors via Display.
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "client-selected target did not resolve",
        )
        .into());
    }
    validate_public_target_addrs(&addrs)?;
    Ok(addrs)
}

fn validate_public_target_addrs(addrs: &[SocketAddr]) -> Result<(), HandshakeServerError> {
    for addr in addrs {
        if is_denied_outbound_ip(addr.ip()) {
            return Err(HandshakeServerError::OutboundTargetDenied);
        }
    }
    Ok(())
}

fn is_denied_outbound_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_denied_outbound_ipv4(ip),
        IpAddr::V6(ip) => {
            // `to_ipv4` covers both v4-mapped (::ffff:a.b.c.d) and the deprecated
            // v4-compatible (::a.b.c.d) embeddings, so an embedded private/special
            // IPv4 is screened by the IPv4 policy. (::1 maps to 0.0.0.1, which the
            // IPv4 policy denies via the octets[0]==0 rule.)
            if let Some(mapped) = ip.to_ipv4() {
                return is_denied_outbound_ipv4(mapped);
            }
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || is_ipv6_unique_local(ip)
                || is_ipv6_unicast_link_local(ip)
                || is_ipv6_documentation(ip)
                || is_ipv6_teredo(ip)
                || is_ipv6_6to4(ip)
                || is_ipv6_nat64(ip)
        }
    }
}

fn is_denied_outbound_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn is_ipv6_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn is_ipv6_teredo(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0
}

fn is_ipv6_6to4(ip: Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2002
}

/// NAT64 well-known prefix `64:ff9b::/96` (RFC 6052), which embeds an IPv4
/// address in its low 32 bits and would otherwise tunnel to an arbitrary IPv4
/// destination without passing through the IPv4 egress policy.
fn is_ipv6_nat64(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x0064 && segments[1] == 0xff9b
}

async fn encapsulate_mlkem_blocking(
    client_mlkem_public_key: Vec<u8>,
) -> Result<pq::MlKemEncapsulation, HandshakeServerError> {
    Ok(tokio::task::spawn_blocking(move || pq::encapsulate(&client_mlkem_public_key)).await??)
}

async fn sign_server_identity_blocking(
    identity_secret_key: Arc<zeroize::Zeroizing<Vec<u8>>>,
    transcript_hash: [u8; 32],
    server_public_key: [u8; 32],
    pq_rekey_binding: [u8; 32],
    epoch: u64,
) -> Result<Vec<u8>, HandshakeServerError> {
    Ok(tokio::task::spawn_blocking(move || {
        identity::sign_server_identity(
            identity_secret_key.as_slice(),
            &transcript_hash,
            &server_public_key,
            &pq_rekey_binding,
            epoch,
        )
    })
    .await??)
}

async fn insert_replay_entry_blocking(
    replay_cache: Arc<Mutex<ReplayCache>>,
    entry: ReplayEntry,
) -> Result<bool, HandshakeServerError> {
    let outcome = tokio::task::spawn_blocking(move || {
        let now = current_unix_timestamp()?;
        // Recover from a poisoned lock rather than panicking the task: a prior
        // panic while holding the cache lock must not take down every subsequent
        // authenticated handshake. The cache invariants are restored on each
        // insert, so proceeding on the recovered guard is safe.
        replay_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert_new_outcome(entry, now)
    })
    .await??;
    Ok(match outcome {
        ReplayInsertOutcome::Inserted => true,
        ReplayInsertOutcome::Replayed | ReplayInsertOutcome::Stale => false,
        ReplayInsertOutcome::CacheFull => {
            // Capacity exhaustion is an operational load-shed, NOT a replay. We
            // still close this connection (we cannot prove it is not a replay
            // without evicting a fresh entry), but we surface it distinctly so it
            // is not misdiagnosed as an attack and so operators can raise
            // replay_cache capacity if it recurs.
            tracing::warn!(
                "replay cache at capacity with fresh entries; shedding handshake \
                 (raise replay cache capacity if persistent)"
            );
            false
        }
    })
}

async fn commit_pending_replay_entry(
    pending_replay: &mut Option<PendingReplayEntry>,
) -> Result<bool, HandshakeServerError> {
    let Some(pending) = pending_replay.take() else {
        return Ok(true);
    };
    insert_replay_entry_blocking(pending.cache, pending.entry).await
}

fn apply_server_pq_rekey(
    suite: CipherSuite,
    client_open: &mut DataRecordCodec,
    server_seal: &mut DataRecordCodec,
    keys: &SessionKeys,
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
    sandwich_secret: &[u8],
) -> Result<SessionKeys, HandshakeServerError> {
    let chain_secret = zeroize::Zeroizing::new(pq::hybrid_sandwich_rekey(
        &keys.chain_secret,
        x25519_shared_secret,
        pq_shared_secret,
        sandwich_secret,
    )?);
    let next_keys = expand_epoch_keys(
        *chain_secret,
        keys.epoch.saturating_add(1),
        keys.transcript_hash,
        *x25519_shared_secret,
    )?;
    client_open.rekey_with_suite(suite, next_keys.client_key, next_keys.client_nonce);
    server_seal.rekey_with_suite(suite, next_keys.server_key, next_keys.server_nonce);
    Ok(next_keys)
}

/// Picks the data-plane AEAD for a new session: AES-256-GCM where the CPU has
/// AES hardware (then it is ~2x ChaCha20-Poly1305), otherwise ChaCha. Both are
/// equally strong 256-bit AEADs, so this is a pure throughput choice, signaled
/// to the client in the AEAD-sealed ServerKeyExchange (no downgrade surface). A
/// busy server's per-byte AEAD cost is the scaling bottleneck, so the server's
/// hardware decides the session suite.
fn server_data_cipher_suite() -> CipherSuite {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if std::arch::is_x86_feature_detected!("aes") {
            return CipherSuite::Aes256Gcm;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            return CipherSuite::Aes256Gcm;
        }
    }
    CipherSuite::ChaCha20Poly1305
}

fn server_identity_chunk_delay<R>(timing: TimingProfile, rng: &mut R) -> Duration
where
    R: Rng + ?Sized,
{
    if timing.is_enabled() {
        SERVER_IDENTITY_CHUNK_MIN_DELAY + timing.sample_delay(rng)
    } else {
        Duration::ZERO
    }
}

fn server_identity_chunk_plaintext_len<R>(rng: &mut R) -> usize
where
    R: Rng + ?Sized,
{
    rng.gen_range(SERVER_IDENTITY_CHUNK_MIN_PLAINTEXT..=SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT)
}

async fn write_server_identity_chunks<W, R>(
    client_write: &mut W,
    server_seal: &mut DataRecordCodec,
    identity_chunks: Vec<Vec<u8>>,
    rng: &mut R,
    timing: TimingProfile,
    cid: u64,
) -> Result<(), HandshakeServerError>
where
    W: AsyncWrite + Unpin,
    R: Rng + rand::RngCore + ?Sized,
{
    if timing.is_enabled() {
        let identity_chunk_count = identity_chunks.len();
        for (idx, chunk) in identity_chunks.into_iter().enumerate() {
            let identity_record = server_seal.seal(&chunk, rng)?;
            log_outer_write(
                cid,
                "server->client",
                "server-identity-writer",
                chunk.len(),
                &identity_record,
            );
            write_all_with_handshake_timeout(client_write, &identity_record).await?;
            if idx + 1 < identity_chunk_count {
                let delay = server_identity_chunk_delay(timing, rng);
                if !delay.is_zero() {
                    sleep(delay).await;
                }
            }
        }
        return Ok(());
    }

    let capacity = identity_chunks
        .iter()
        .map(|chunk| server_seal.max_sealed_len(chunk.len()))
        .sum();
    let mut identity_records = Vec::with_capacity(capacity);
    for chunk in identity_chunks {
        let range = server_seal.seal_into(&chunk, rng, &mut identity_records)?;
        log_outer_write(
            cid,
            "server->client",
            "server-identity-writer",
            chunk.len(),
            &identity_records[range],
        );
    }
    write_all_with_handshake_timeout(client_write, &identity_records).await?;
    Ok(())
}

struct DataRelay {
    client_records: BufferedTlsRecordReader<OwnedReadHalf>,
    client_write: OwnedWriteHalf,
    target_read: OwnedReadHalf,
    target_write: OwnedWriteHalf,
    client_open: DataRecordCodec,
    server_seal: DataRecordCodec,
    timing: TimingProfile,
    cover: CoverTrafficProfile,
    chunk_size: usize,
    /// Retained QUIC fast-plane endpoint + probed connection (with its HTTP/3
    /// stream set) when the client's probe was Verified. `Some` => carry the relay
    /// over the SAME request bidi (DATA-framed); `None` => the relay stays on the
    /// TCP record legs exactly as before this slice.
    retained_quic: Option<ServerProbedQuic>,
    cid: u64,
}

/// Cross-side carrier decision at the PX1P retention gate (L-7). Both ends gate
/// the relay carrier on the SAME signal (the client's reported probe status), so
/// the server's local view must agree. The one state that can DESYNC is a Verified
/// ack with no retained connection: the client has already committed its relay to
/// QUIC (and will hard-error if the stream never materializes), so the server must
/// reset too rather than silently fall back to TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpRetentionDecision {
    /// Verified + we still hold the connection: carry the relay over QUIC.
    Retain,
    /// Verified but the probed connection was lost (probe budget elapsed after
    /// serve_probe queued its echo): reset so both ends fail identically.
    HardFail,
    /// Not Verified: the client also stays on TCP. Drop the conn, close, continue.
    StayOnTcp,
}

fn udp_retention_decision(
    ack_status: Option<crate::protocol::command::UdpProbeStatus>,
    have_probed_conn: bool,
) -> UdpRetentionDecision {
    use crate::protocol::command::UdpProbeStatus;
    match (ack_status, have_probed_conn) {
        (Some(UdpProbeStatus::Verified), true) => UdpRetentionDecision::Retain,
        (Some(UdpProbeStatus::Verified), false) => UdpRetentionDecision::HardFail,
        _ => UdpRetentionDecision::StayOnTcp,
    }
}

/// Accept the QUIC connection for the fast-plane probe, but ONLY from the
/// authenticated TCP peer's source IP (L-6). The ephemeral endpoint is reachable
/// by anyone who learns the port, so a racing/off-path connector could otherwise
/// steal the single accept slot and force a TCP downgrade. Connectors from a
/// different source IP are `ignore()`d — dropped WITHOUT a response packet, so the
/// "nothing here" probe-resistance posture is preserved (a `refuse()` would emit
/// an observable CONNECTION_CLOSE). `serve_probe` still gates authenticity on the
/// exporter-bound token, so a peer that spoofs the IP cannot pass; this only closes
/// the free downgrade. `expect_ip == None` fails closed (declines the QUIC offer;
/// the session stays on TCP). The caller wraps this in the probe-budget timeout,
/// which bounds the loop.
/// The QUIC fast-plane connection the server accepted and probed, together with
/// the HTTP/3 stream set established during the probe. On the Verified retain path
/// these are kept alive (with the endpoint) for the single-Connect relay, which
/// continues on the SAME request bidi (`relay_send`/`relay_recv`). The control +
/// encoder uni streams (`h3_control`) must stay open per RFC 9114 §6.2.1.
struct ServerProbedQuic {
    conn: crate::transport::udp::quic::endpoint::Connection,
    h3_control: crate::transport::udp::h3::H3ControlStreams,
    relay_send: crate::transport::udp::quic::endpoint::SendStream,
    relay_recv: crate::transport::udp::quic::endpoint::RecvStream,
}

/// Per-session ephemeral accept path: loop `accept()` with the L-6 source-IP filter
/// to pick the authenticated peer's connection, then serve the probe on it. Retained
/// as a focused test of the accept-loop + [`serve_probed_quic_on_conn`]; the live
/// runtime now routes through the stable carrier (which does its own IP check before
/// calling `serve_probed_quic_on_conn`), so this is exercised only by tests.
#[cfg(test)]
async fn accept_probed_quic_from_peer(
    udp_ep: &crate::transport::udp::quic::endpoint::Endpoint,
    expect_ip: Option<std::net::IpAddr>,
    sandwich_secret: &[u8],
    offer_id: &[u8; 16],
    cid: u64,
) -> Option<ServerProbedQuic> {
    // Fail closed: if the authenticated TCP peer IP could not be determined, do
    // not accept a fast-plane QUIC connection from any source (which would let a
    // racing off-path connector occupy the single accept slot and force a TCP
    // downgrade). Staying on TCP is the safe fallback.
    let Some(expect_ip) = expect_ip else {
        tracing::warn!(
            cid,
            "peer IP unknown; declining fast-plane QUIC (fail closed)"
        );
        return None;
    };
    // L-6 source-IP filter: the ephemeral endpoint is reachable by anyone who
    // learns the port, so accept ONLY a connection whose source IP matches the
    // authenticated TCP peer. A connection from any other IP is an off-path racer
    // trying to steal the single accept slot and force a TCP downgrade — drop it
    // SILENTLY (no CONNECTION_CLOSE, so the port stays unobservable; the dropped
    // connection idle-times-out in the endpoint) and keep waiting. The whole call
    // is bounded by `probe_budget` at the call site, so a flood of mismatched
    // connectors just times out to a safe TCP fallback.
    let conn = loop {
        let c = udp_ep.accept().await?;
        if c.remote_address().ip() == expect_ip {
            break c;
        }
        tracing::debug!(
            cid,
            peer = %c.remote_address(),
            "declining fast-plane QUIC from an unexpected source IP (L-6)"
        );
        drop(c); // silent: no CONNECTION_CLOSE on the wire (no response oracle)
    };

    serve_probed_quic_on_conn(conn, sandwich_secret, offer_id, cid).await
}

/// Serve the H3 reachability probe on an already-accepted (and source-IP-validated)
/// fast-plane connection: open the control stream, accept + serve the request bidi,
/// open the encoder stream, verify the client's Safari-26 H3 SETTINGS, and return the
/// retained streams. Shared by the per-session ephemeral accept path
/// ([`accept_probed_quic_from_peer`]) and the stable carrier handoff (which performs
/// its own source-IP check on the routed connection before calling this).
async fn serve_probed_quic_on_conn(
    conn: crate::transport::udp::quic::endpoint::Connection,
    sandwich_secret: &[u8],
    offer_id: &[u8; 16],
    cid: u64,
) -> Option<ServerProbedQuic> {
    // H3 stream order mirrors the client: open this endpoint's control stream
    // (SETTINGS) first, accept the client's request bidi and serve the bidi
    // probe (HEADERS + DATA), then open the QPACK encoder stream. The
    // exporter-bound auth inside `serve_probe_over_bidi` is unchanged; only the
    // carrier is H3 framing. A failure to open a control stream means the QUIC
    // connection is unusable for H3 — decline (stay on TCP).
    //
    // ACTIVE-PROBING (resolved by the stable carrier): this is reached ONLY for a
    // connection the carrier already marker-terminated — i.e. a genuine ParallaX
    // client that proved knowledge of the PSK + the server's static X25519 key in its
    // first Initial. Every unauthenticated v1 Initial (no / forged / replayed marker)
    // is spliced verbatim to the real origin at datagram zero, BEFORE any ParallaX
    // QUIC byte is emitted, so an active prober reads the TRUE origin's SETTINGS +
    // auth-failure behaviour, never this code path. The Safari-26 *client* SETTINGS
    // sent here are therefore seen only by our own client (which expects them — the
    // LOCKSTEP below); they are not an origin-facing tell, and "drop on H3-probe
    // failure" only ever drops our own misbehaving client (a prober was already
    // spliced), so it matches no origin a prober can compare against.
    let control_send = crate::transport::udp::h3::open_h3_control_stream(&conn)
        .await
        .ok()?;
    let (mut relay_send, mut relay_recv) = conn.accept_bi().await?;
    if let Err(err) = crate::transport::udp::probe::serve_probe_over_bidi(
        &conn,
        &mut relay_send,
        &mut relay_recv,
        sandwich_secret,
        offer_id,
    )
    .await
    {
        // A malformed probe means the client's probe will be Failed and it will
        // report PX1P=Failed -> the retention gate keeps the session on TCP, so
        // returning the (now-suspect) streams is harmless. Log and continue:
        // parity with the uni `serve_probe`.
        tracing::debug!(cid, error = %err, "udp serve_probe_over_bidi failed");
    }
    let encoder_send = crate::transport::udp::h3::open_h3_encoder_stream(&conn)
        .await
        .ok()?;
    // Read + verify the client's H3 SETTINGS off its control stream (opened
    // before the bidi probe, so already in flight; no deadlock). A client that
    // does not advertise Safari-26's SETTINGS is a protocol divergence; decline
    // (return None) so the session stays on TCP — the client, having seen a
    // Verified probe response, reports PX1P=Verified and the retention gate's
    // HardFail arm resets both ends cleanly.
    //
    // LOCKSTEP: this requires the client's SETTINGS to be Safari-26-SHAPED — the
    // two QPACK params exact, the GREASE setting per-connection random so only its
    // reserved form is checked (see `is_safari26_settings`). The client sends those
    // (client runtime SETTINGS check). Both ends keep the Safari-26 client shape:
    // since the carrier already spliced every unauthenticated Initial to the origin,
    // this SETTINGS exchange happens only between our own client and server (a prober
    // sees the TRUE origin's SETTINGS via the splice, never these), so the two sides
    // simply have to agree — they do.
    match crate::transport::udp::h3::read_peer_h3_settings(&conn).await {
        Ok(settings) if crate::fingerprint::http3::is_safari26_settings(&settings) => {}
        _ => {
            tracing::debug!(
                cid,
                "client H3 SETTINGS missing/mismatched; declining fast plane"
            );
            return None;
        }
    }
    Some(ServerProbedQuic {
        conn,
        h3_control: crate::transport::udp::h3::H3ControlStreams::new(control_send, encoder_send),
        relay_send,
        relay_recv,
    })
}

/// Drops a retained QUIC endpoint + connection (and its held H3 streams),
/// application-closing the connection promptly so no idle fast-plane connection
/// lingers when a dispatch path (Mux/SpeedTest) stays on TCP. A bare drop would
/// also close it, but the explicit close gives the peer an immediate
/// CONNECTION_CLOSE rather than waiting for an idle timeout. The shared carrier
/// endpoint is process-wide and is never closed here.
fn drop_retained_quic(retained: Option<ServerProbedQuic>) {
    if let Some(probed) = retained {
        probed.conn.close(0u32.into(), b"tcp-path");
    }
}

/// Bound on the two PX1G control-plane reads (the PX1P probe-ack and the real
/// first-command re-read) that run WHILE the server is holding the ephemeral QUIC
/// endpoint (a live UDP-socket fd) and the accepted `quinn::Connection`. These
/// reads are reached ONLY on the UDP-negotiated path; without a bound a
/// misbehaving authenticated client that sends PX1G, lets the server bind+offer+
/// accept, then withholds PX1P (or the real command) would pin the UDP fd +
/// connection indefinitely (quinn's keep-alive masks the idle timeout, so the
/// connection would not self-collect). On timeout the server eagerly closes
/// whatever QUIC resources it holds (releasing the UDP fd promptly) and fails the
/// connection. A real client always sends both records immediately, so this never
/// trips a legitimate peer. The non-PX1G first-command read elsewhere is NOT
/// affected, so the udp-off baseline is byte-identical.
const PX1_CONTROL_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on a single client->target mux write (H-3). The mux reader loop
/// processes every substream's frames serially, so a wedged target — its kernel
/// send buffer full because the peer advertises a zero receive window and never
/// drains — blocking `write_all` would park the loop and pin the WHOLE
/// connection: every other substream, all permits, every fd. A live target
/// accepts one <=chunk_size (~16 KiB) frame far inside 30s, so this never trips a
/// slow-but-draining peer; only a genuinely wedged stream is shed (with a Reset).
/// Distinct from the 600s idle backstop, which bounds whole-relay SILENCE, not
/// single-stream backpressure — using 600s here would still pin for ten minutes.
const MUX_TARGET_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Brief grace, applied AFTER the teardown DONE `select!` returns its
/// `conn.closed()` sentinel, for the reliable TCP DONE to arrive. The peer sends
/// its DONE over the TCP control stream and THEN closes the QUIC connection; the
/// CONNECTION_CLOSE can reorder ahead of the already-sent TCP DONE bytes, so the
/// biased select can take the `conn.closed()` arm even though a fully-successful
/// relay's DONE is in flight. No data is lost (the app already has everything),
/// but it would spuriously error without this grace. Small: the DONE was sent
/// before the peer closed, so it is at most one TCP delivery away.
const QUIC_RELAY_DONE_GRACE: Duration = Duration::from_secs(2);

/// Generous backstop on the teardown DONE read (see the client-side twin). The
/// read is primarily bounded on connection liveness, but the 15s keep-alive masks
/// the idle timeout for an alive-but-stuck peer, so without a backstop a completed
/// side could park in the DONE handshake indefinitely, pinning the connection.
const QUIC_RELAY_DONE_BACKSTOP: Duration = Duration::from_secs(120);

#[derive(Clone, Copy)]
struct ServerMuxContext<'a> {
    fixed_data_target: Option<&'a str>,
    timing: TimingProfile,
    cover: CoverTrafficProfile,
    chunk_size: usize,
    /// Server-enforced ceiling on concurrent substreams for this connection.
    max_streams: usize,
    cid: u64,
    /// Per-write deadline on a client->target mux write (H-3): a wedged target
    /// must not park the serial reader loop. Injectable so tests can use a short
    /// value; production passes `MUX_TARGET_WRITE_TIMEOUT`.
    target_write_timeout: Duration,
}

/// Tracks the live substreams of one authenticated mux connection.
///
/// `writes` holds the client->target write halves; `readers` holds the abort
/// handles of the spawned target->client reader tasks. The two are tracked
/// separately so that:
///   - admission is gated on the count of *live readers* (a stream is alive as
///     long as its target->client direction is), not on the write-half count —
///     otherwise a client could `Fin` each stream (dropping the write half while
///     the reader/fd lives) to open unboundedly many target sockets past
///     `max_streams`;
///   - a `Fin` (client done sending) closes only the write half, preserving the
///     target's ability to keep streaming back (half-close), while a `Reset` or
///     a connection teardown aborts the reader task too so no target fd/task is
///     orphaned.
struct ServerMuxStreams {
    writes: HashMap<u32, OwnedWriteHalf>,
    readers: HashMap<u32, tokio::task::JoinHandle<()>>,
}

impl ServerMuxStreams {
    fn new() -> Self {
        Self {
            writes: HashMap::new(),
            readers: HashMap::new(),
        }
    }

    /// Drop the handles of readers that have already finished so `live_count`
    /// reflects only streams still doing work.
    fn prune_finished(&mut self) {
        self.readers.retain(|_, h| !h.is_finished());
    }

    /// Number of substreams still holding a file descriptor (used for the
    /// `max_streams` admission gate). A stream occupies a slot while EITHER half
    /// is open: its client->target write half, or its (unfinished) target->client
    /// reader. Counting the UNION bounds the per-connection fd footprint to
    /// `max_streams` across half-closes — a client `Fin` drops the write half but
    /// the reader lives (the target may still stream back), and a target EOF
    /// finishes the reader but the write half lives until the client `Fin`s.
    /// Gating on either side alone lets the other accumulate unbounded.
    fn live_count(&mut self) -> usize {
        self.prune_finished();
        let readers_without_write = self
            .readers
            .keys()
            .filter(|id| !self.writes.contains_key(id))
            .count();
        self.writes.len() + readers_without_write
    }

    /// Tear down every substream: abort all reader tasks (closing the target
    /// read fds) and shut down every client->target write half.
    async fn teardown(&mut self) {
        for (_, handle) in self.readers.drain() {
            handle.abort();
        }
        let writes = std::mem::take(&mut self.writes);
        for (_, mut write) in writes {
            let _ = write.shutdown().await;
        }
    }
}

impl Drop for ServerMuxStreams {
    /// Backstop against orphaned target readers: a `JoinHandle` dropped without
    /// `abort()` leaves its task (and the target fd it holds) running. Aborting
    /// on drop guarantees that any return path out of the reader loop — including
    /// `?` error propagation — reclaims every spawned reader.
    fn drop(&mut self) {
        for (_, handle) in self.readers.drain() {
            handle.abort();
        }
    }
}

/// Monotonic milliseconds since a process-local epoch, backing the lock-free
/// relay activity clock. Coarse (ms) granularity is ample for the idle backstop
/// (timeouts are whole seconds) and lets the clock live in a single atomic.
fn relay_now_millis() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Shared last-activity clock for an authenticated relay, reset on every byte
/// moved in either direction. Lock-free: both relay directions and the watchdog
/// touch it with a single relaxed atomic, so the hot path never contends on a
/// mutex (the previous `Arc<Mutex<Instant>>` bounced a cache line between the two
/// relay tasks on every relayed chunk).
type RelayActivity = Arc<AtomicU64>;

fn bump_relay_activity(activity: &RelayActivity) {
    activity.store(relay_now_millis(), Ordering::Relaxed);
}

/// Resolves once the relay has been idle (no bytes either direction) for
/// `idle_timeout`. Without this, a `try_join!` relay where the client has gone
/// but the target stays open and silent (e.g. a malicious PSK holder dialing an
/// attacker target that holds the socket after EOF) would block on the target
/// read forever, pinning a connection slot, both fds, and the per-source/global
/// permits indefinitely. Reusing the configurable fallback idle backstop keeps a
/// generous, operator-tunable grace. Only real payload bytes (either direction)
/// reset the clock; server-generated cover records deliberately do NOT, so the
/// backstop still fires on a genuinely-idle relay even when cover traffic is on.
async fn relay_idle_watchdog(activity: RelayActivity, idle_timeout: Duration) {
    let timeout_ms = idle_timeout.as_millis() as u64;
    loop {
        let elapsed_ms = relay_now_millis().saturating_sub(activity.load(Ordering::Relaxed));
        if elapsed_ms >= timeout_ms {
            return;
        }
        sleep(idle_timeout.saturating_sub(Duration::from_millis(elapsed_ms))).await;
    }
}

impl DataRelay {
    async fn run(self) -> Result<(), HandshakeServerError> {
        let DataRelay {
            client_records,
            client_write,
            target_read,
            target_write,
            client_open,
            server_seal,
            timing,
            cover,
            chunk_size,
            retained_quic,
            cid,
        } = self;
        let target_buf = vec![0_u8; relay_read_buffer_len(chunk_size)];

        // QUIC fast-plane path: the client (the bidi opener) ran the probe over an
        // HTTP/3 request bidi during establishment and committed its relay to that
        // SAME stream, so the server already holds the bidi (`relay_send`/
        // `relay_recv`) and its H3 control set. The relay continues on the request
        // bidi, DATA-framed. The endpoint + connection + control streams are held
        // alive for the whole relay. Direction mapping: the bidi's (send =
        // server->client, recv = client->server), so server_download (server->
        // client) writes the SendStream and server_upload (client->server) reads
        // the RecvStream.
        if let Some(probed) = retained_quic {
            let ServerProbedQuic {
                conn,
                h3_control,
                relay_send,
                relay_recv,
            } = probed;
            // Hold the connection + H3 control streams alive across the relay.
            // `_h3_control` must not drop early (the control/encoder uni streams must
            // stay open per RFC 9114 §6.2.1). The carrier endpoint is process-wide.
            let _h3_control = h3_control;
            // Keep the TCP control halves alive for the relay's duration so the
            // outer TCP connection stays open (the client likewise holds its TCP
            // halves). They carry no relay DATA, but they DO carry the teardown
            // DONE handshake: the TCP control stream is reliable and independent
            // of the QUIC connection close, so it coordinates a safe,
            // truncation-free teardown after the QUIC relay finishes.
            // `client_records` is read for the client's DONE; `client_write`
            // needs `mut` to write our DONE marker.
            let mut client_records = client_records;
            let mut client_write = client_write;
            // Idle backstop shared by both QUIC relay directions (main's DoS
            // hardening, carried onto the fast plane): a silent-but-open target
            // must not pin the connection slot, the fds, and the per-source/global
            // permits forever. Only real payload bytes (either direction) reset the
            // clock. The QUIC connection's own idle-timeout is a separate, coarser
            // bound; this is the operator-tunable backstop that matches the TCP
            // path's behavior.
            let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
            let idle_timeout = fallback_idle_timeout();

            tracing::info!(
                cid,
                "QUIC fast-plane relay continuing on the H3 request bidi (DATA-framed)"
            );
            // The relay legs wrap each record batch in an H3 DATA frame and strip
            // DATA headers on read. No accept_bi / trigger / SETTINGS read is needed
            // here — the probe established and rendezvoused the bidi already.
            let upload = server_upload_loop(
                H3DataFrameLegReader::buffered(relay_recv),
                target_write,
                client_open,
                activity.clone(),
                cid,
                idle_timeout,
            );
            let download = server_download_loop(
                target_read,
                H3DataFrameLegWriter(relay_send),
                server_seal,
                target_buf,
                timing,
                cover,
                activity.clone(),
                cid,
            );
            // Application-level DONE handshake over the reliable TCP
            // control stream. quinn 0.11.9's `Connection::close` ABANDONS
            // undelivered stream data, and `finish`/`stopped` only signal
            // FIN / ack -- none prove the PEER's application consumed every
            // byte. The earlier fixed 5s `conn.closed()` grace was also
            // wrong: it dropped a HEALTHY large/slow server->client
            // download whose client took >5s to drain to a slow local app.
            // Instead:
            //   1. Our `try_join` Ok means BOTH directions finished here --
            //      we sent our FIN (download) AND fully drained the
            //      client->server stream to the target (upload). The loops
            //      hand back their owned codecs.
            //   2. We seal a DONE marker on the SAME server->client (send)
            //      codec -- its next sequence number -- and write it over the
            //      TCP control stream, then flush.
            //   3. We BLOCK reading exactly one record over the TCP
            //      control stream and open it on the SAME client->server
            //      (recv) codec; that is the client's DONE. The read is
            //      bounded on CONNECTION LIVENESS, not a wall clock: we
            //      `select!` it against `conn.closed()`. Because we have NOT
            //      closed the QUIC connection yet, it stays alive while we
            //      block, so the client keeps draining our download tail
            //      (kept up by the 15s keep-alive PINGs) for as long as it
            //      legitimately needs -- a multi-minute drain is fine, with
            //      no fixed cap to truncate a slow-but-alive client. Only if
            //      the client genuinely vanishes does the QUIC connection
            //      idle-time-out (~60s, configured), resolving
            //      `conn.closed()` into a clean Err.
            //   4. Receiving the client's DONE proves the client fully
            //      drained every byte we sent, so nothing is in flight --
            //      only THEN do we close.
            // On any relay error, or any DONE seal/write/read/liveness/open/
            // marker mismatch, we close and return Err: a clean, VISIBLE
            // reset (the accepted v1 failure mode), never a silent success.
            //
            // The whole relay is additionally bounded by the idle backstop
            // (main's DoS hardening): if neither direction moves a real
            // payload byte for `idle_timeout`, the watchdog fires, we close
            // the QUIC connection, and return Ok WITHOUT the DONE handshake
            // (a forced teardown -- a genuinely-idle relay has nothing left
            // to drain). A live-but-slow drain keeps bumping `activity`, so
            // the backstop never truncates it.
            let relay = async { tokio::try_join!(upload, download) };
            let relay_outcome = tokio::select! {
                joined = relay => Some(joined),
                _ = relay_idle_watchdog(activity, idle_timeout) => {
                    tracing::debug!(
                        cid,
                        "QUIC fast-plane relay idle backstop reached; tearing down"
                    );
                    None
                }
            };
            let join_result = match relay_outcome {
                Some(joined) => joined,
                None => {
                    conn.close(RELAY_IDLE_CLOSE_CODE.into(), b"relay-idle");
                    return Ok(());
                }
            };
            match join_result {
                Ok((mut client_open, mut server_seal)) => {
                    let result = server_exchange_quic_done(
                        &conn,
                        &mut client_write,
                        &mut client_records,
                        &mut server_seal,
                        &mut client_open,
                        cid,
                    )
                    .await;
                    match result {
                        Ok(()) => {
                            conn.close(0u32.into(), b"relay-done");
                            return Ok(());
                        }
                        Err(err) => {
                            conn.close(0u32.into(), b"relay-done-failed");
                            return Err(err);
                        }
                    }
                }
                Err(err) => {
                    // If the peer's own idle watchdog fired first it
                    // surfaces as a connection error here; recognize that
                    // benign mutual idle teardown and return Ok rather than
                    // a relay failure (symmetric outcome regardless of which
                    // side's watchdog fires first).
                    if is_peer_idle_close(&conn) {
                        return Ok(());
                    }
                    conn.close(0u32.into(), b"relay-error");
                    return Err(err);
                }
            }
        }

        // No retained QUIC connection: TCP record legs, byte-identical to before
        // this slice. The idle backstop (main's DoS hardening) bounds the relay so
        // a silent target cannot pin resources forever; only real payload bytes
        // (either direction) reset the clock.
        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let idle_timeout = fallback_idle_timeout();
        let upload = server_upload_loop(
            TcpLegReader(client_records),
            target_write,
            client_open,
            activity.clone(),
            cid,
            idle_timeout,
        );
        let download = server_download_loop(
            target_read,
            TcpLegWriter(client_write),
            server_seal,
            target_buf,
            timing,
            cover,
            activity.clone(),
            cid,
        );

        // TCP teardown is unchanged: TCP is reliable and FIN/EOF is a clean,
        // fully-delivered close, so the returned per-direction codecs (the loops
        // hand them back for the QUIC DONE handshake) are simply discarded here --
        // no DONE handshake is needed on the TCP path. The relay is still bounded
        // by main's idle backstop: if neither direction moves a real payload byte
        // for `idle_timeout`, the watchdog fires and we tear the relay down so a
        // silent-but-open target cannot pin the connection slot, both fds, and the
        // per-source/global permits forever.
        tokio::select! {
            result = async {
                tokio::try_join!(upload, download).map(|(_client_open, _server_seal)| ())
            } => result,
            _ = relay_idle_watchdog(activity, idle_timeout) => {
                tracing::debug!(cid, "authenticated relay idle backstop reached; tearing down");
                Ok(())
            }
        }
    }
}

/// Performs the server side of the QUIC fast-plane teardown DONE handshake over
/// the held TCP control stream halves, using the SAME per-direction session
/// codecs the relay used so the sequence numbers continue uninterrupted. It
/// seals and writes our DONE, then reads, opens, and verifies the client's DONE.
/// The DONE read is bounded on CONNECTION LIVENESS (`conn.closed()`), not a wall
/// clock, so a slow-but-alive client draining a large download tail is never
/// truncated. Returns Ok only when both DONEs are exchanged; the caller closes
/// the QUIC connection afterward (on Ok) or eagerly (on Err).
async fn server_exchange_quic_done(
    conn: &crate::transport::udp::quic::endpoint::Connection,
    client_write: &mut OwnedWriteHalf,
    client_records: &mut BufferedTlsRecordReader<OwnedReadHalf>,
    server_seal: &mut DataRecordCodec,
    client_open: &mut DataRecordCodec,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    // Seal our DONE on the server->client (send) codec -- its next sequence
    // number -- and write it over the reliable TCP control stream.
    let mut rng = StdRng::from_entropy();
    let done = server_seal.seal(QUIC_RELAY_DONE_MARKER, &mut rng)?;
    // Bound the DONE write+flush with the same backstop as the DONE read below: a
    // peer that completes its data directions but then stops reading the TCP
    // control stream must not pin the slot/fds/permits forever.
    match tokio::time::timeout(QUIC_RELAY_DONE_BACKSTOP, async {
        client_write.write_all(&done).await?;
        client_write.flush().await?;
        Ok::<(), HandshakeServerError>(())
    })
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            tracing::warn!(cid, "QUIC fast-plane teardown DONE write backstop elapsed");
            return Err(HandshakeServerError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "QUIC fast-plane teardown DONE write backstop elapsed",
            )));
        }
    }

    // Read exactly ONE record (the client's DONE) over the TCP control stream.
    // The read is bounded on CONNECTION LIVENESS, not a wall clock: we `select!`
    // it against `conn.closed()`. While the client is alive (actively draining our
    // download tail + the 15s keep-alive PINGs keeping the QUIC connection up),
    // `conn.closed()` pends and this read blocks for as long as the client
    // legitimately needs -- a multi-minute drain is fine, with no fixed cap to
    // truncate a slow-but-alive peer. If the client genuinely vanishes, the QUIC
    // connection idle-times-out (~60s, configured) and `conn.closed()` resolves,
    // yielding a clean Err. EOF on the TCP read is likewise NOT a clean close: we
    // require the client's explicit DONE record.
    let mut record = Vec::new();
    // PRIMARY bound: connection liveness; BACKSTOP: generous wall-clock timeout
    // (the keep-alive masks the idle timeout for an alive-but-stuck peer).
    //
    // The inner select yields a SENTINEL rather than concluding: `Ok(true)` means
    // the DONE record was read into `record`; `Ok(false)` means `conn.closed()`
    // fired first. The grace read runs AFTER the select returns (so the
    // `client_records`/`record` borrows the select held are released -- no double-
    // mutable borrow) to absorb a teardown reorder: the client sends its DONE over
    // the reliable TCP control stream and THEN closes the QUIC connection, so the
    // CONNECTION_CLOSE can reorder ahead of the already-sent TCP DONE bytes and
    // trip the `conn.closed()` arm even on a fully-successful relay. No data is
    // lost; the grace just lets the in-flight DONE land before concluding failure.
    let read_done = async {
        tokio::select! {
            // `biased`: poll the DONE read FIRST so an already-arrived peer DONE wins
            // over a concurrently-ready `conn.closed()` (the client sends its DONE
            // over TCP then closes the QUIC connection).
            biased;
            res = client_records.read_record_into(&mut record) => res.map(|()| true).map_err(HandshakeServerError::Io),
            _ = crate::transport::udp::endpoint::conn_closed(conn) => Ok(false),
        }
    };
    let done_read = match tokio::time::timeout(QUIC_RELAY_DONE_BACKSTOP, read_done).await {
        Ok(res) => res?,
        Err(_) => {
            tracing::warn!(cid, "QUIC fast-plane teardown DONE backstop elapsed");
            return Err(HandshakeServerError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "QUIC fast-plane teardown DONE backstop elapsed",
            )));
        }
    };
    if !done_read {
        // `conn.closed()` won the select. The peer's TCP DONE was sent BEFORE it
        // closed the QUIC connection, so give it a brief grace to arrive over the
        // reliable control stream before concluding failure. This read runs after
        // the select returned, so the `client_records`/`record` borrows are free.
        match tokio::time::timeout(
            QUIC_RELAY_DONE_GRACE,
            client_records.read_record_into(&mut record),
        )
        .await
        {
            Ok(Ok(())) => {}
            _ => {
                return Err(HandshakeServerError::Io(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "QUIC connection closed before peer DONE",
                )));
            }
        }
    }
    let plaintext = client_open.open_in_place_payload_range(&mut record)?;
    if &record[plaintext] != QUIC_RELAY_DONE_MARKER {
        tracing::warn!(cid, "QUIC fast-plane teardown DONE marker mismatch");
        return Err(HandshakeServerError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "QUIC fast-plane teardown DONE marker mismatch",
        )));
    }
    Ok(())
}

async fn run_authenticated_mux_data_mode(
    client_records: BufferedTlsRecordReader<OwnedReadHalf>,
    client_write: OwnedWriteHalf,
    client_open: DataRecordCodec,
    server_seal: DataRecordCodec,
    first_frames: Vec<MuxFrame>,
    context: ServerMuxContext<'_>,
) -> Result<(), HandshakeServerError> {
    tracing::info!(cid = context.cid, "ParallaX mux data mode started");
    let (frame_tx, frame_rx) = mpsc::channel(SERVER_MUX_FRAME_CHANNEL);
    let payload_pool = MuxPayloadPool::with_capacity(MuxFrame::max_payload_len(context.chunk_size));
    let reader = server_mux_client_reader_loop(
        TcpLegReader(client_records),
        client_open,
        frame_tx,
        first_frames,
        context,
        payload_pool.clone(),
    );
    let writer = server_mux_writer_loop(
        TcpLegWriter(client_write),
        server_seal,
        frame_rx,
        context.cover,
        context.cid,
        payload_pool,
    );
    let ((), ()) = tokio::try_join!(reader, writer)?;
    Ok(())
}

async fn server_mux_client_reader_loop<R>(
    mut client_records: R,
    mut client_open: DataRecordCodec,
    frame_tx: mpsc::Sender<MuxFrame>,
    first_frames: Vec<MuxFrame>,
    context: ServerMuxContext<'_>,
    payload_pool: MuxPayloadPool,
) -> Result<(), HandshakeServerError>
where
    R: LegReader,
{
    let mut streams = ServerMuxStreams::new();
    for frame in first_frames {
        process_server_mux_frame(
            MuxFrameRef {
                stream_id: frame.stream_id,
                kind: frame.kind,
                payload: &frame.payload,
            },
            &mut streams,
            &frame_tx,
            context,
            &payload_pool,
        )
        .await?;
    }

    let mut client_record = Vec::new();
    let mut extra_record = Vec::new();
    let mut batch_records = Vec::new();
    let mut batch_plaintext = Vec::new();
    let mut deferred_read_error: Option<io::Error> = None;
    // Idle backstop for the whole mux session. Without it, a client that goes
    // silent (while its target readers also idle out) would leave this loop
    // blocked on read forever, holding the connection slot, permits, and every
    // target fd. A real record resets the clock implicitly (the read returns).
    let mux_idle_timeout = fallback_idle_timeout();
    loop {
        let read_result = match deferred_read_error.take() {
            Some(err) => Err(err),
            None => match timeout(
                mux_idle_timeout,
                client_records.read_record_into(&mut client_record),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    tracing::debug!(
                        cid = context.cid,
                        "mux client idle backstop reached; tearing down session"
                    );
                    streams.teardown().await;
                    return Ok(());
                }
            },
        };
        match read_result {
            Ok(()) => {}
            Err(err) if is_clean_close(&err) => {
                streams.teardown().await;
                return Ok(());
            }
            Err(err) => {
                streams.teardown().await;
                return Err(HandshakeServerError::Io(err));
            }
        };
        log_record_read(
            context.cid,
            "client->server",
            "server-mux-client-reader",
            &client_record,
        );

        // Opportunistically grab any records that are already buffered so a
        // bulk burst can be opened across the crypto pool instead of pinning
        // every open on this task. A would-block leaves partial reader state
        // intact; a read error is surfaced on the next iteration, after the
        // records that did arrive have been relayed.
        let mut record_count = 1_usize;
        batch_records.clear();
        // Explicit byte accumulator seeded with the first record's length so the
        // batch budget counts each record exactly once (the first record is
        // appended into `batch_records` lazily on the first extra read).
        let mut batch_bytes = client_record.len();
        while batch_bytes < MUX_OPEN_BATCH_BYTES {
            match client_records.try_read_record_into(&mut extra_record).await {
                None => break,
                Some(Ok(())) => {
                    log_record_read(
                        context.cid,
                        "client->server",
                        "server-mux-client-reader",
                        &extra_record,
                    );
                    if record_count == 1 {
                        batch_records.extend_from_slice(&client_record);
                    }
                    batch_records.extend_from_slice(&extra_record);
                    batch_bytes += extra_record.len();
                    record_count += 1;
                }
                Some(Err(err)) => {
                    deferred_read_error = Some(err);
                    break;
                }
            }
        }

        let frames_payload: &[u8] = if record_count == 1 {
            let payload = client_open.open_in_place_payload_range(&mut client_record)?;
            &client_record[payload]
        } else {
            // Frames never span records (the sender keeps records
            // frame-aligned), so decoding the concatenated plaintext is
            // equivalent to decoding each record's plaintext in order.
            batch_plaintext.clear();
            let payload_bytes =
                batch_records.len() - record_count * crate::tls::record::TLS_HEADER_LEN;
            if should_parallelize_aead(record_count, payload_bytes) {
                client_open.open_concat_records_parallel(
                    parallel::global(),
                    &batch_records,
                    &mut batch_plaintext,
                )?;
            } else {
                client_open.open_concat_records(&mut batch_records, &mut batch_plaintext)?;
            }
            batch_plaintext.as_slice()
        };
        let mut frames = frames_payload;
        while !frames.is_empty() {
            let (frame, used) = MuxFrame::decode_ref_prefix(frames)?;
            process_server_mux_frame(frame, &mut streams, &frame_tx, context, &payload_pool)
                .await?;
            frames = &frames[used..];
        }
    }
}

async fn process_server_mux_frame(
    frame: MuxFrameRef<'_>,
    streams: &mut ServerMuxStreams,
    frame_tx: &mpsc::Sender<MuxFrame>,
    context: ServerMuxContext<'_>,
    payload_pool: &MuxPayloadPool,
) -> Result<(), HandshakeServerError> {
    match frame.kind {
        MuxFrameKind::Open => {
            // Drop handles of readers that have already finished so a stream_id
            // whose reader just exited (target EOF / idle) is not treated as a
            // live duplicate below.
            streams.prune_finished();
            if streams.writes.contains_key(&frame.stream_id)
                || streams.readers.contains_key(&frame.stream_id)
            {
                send_server_mux_frame(frame_tx, frame.stream_id, MuxFrameKind::Reset, Vec::new())
                    .await?;
                return Ok(());
            }
            if streams.live_count() >= context.max_streams {
                // Per-connection substream ceiling reached: refuse the new stream
                // and do not open an outbound connection. The client maps Reset
                // to a ConnectionReset on that stream. Gating on live readers (not
                // write halves) prevents a Fin-then-Open loop from opening more
                // than `max_streams` concurrent target sockets.
                tracing::debug!(
                    cid = context.cid,
                    stream_id = frame.stream_id,
                    max_streams = context.max_streams,
                    "mux stream cap reached; resetting"
                );
                send_server_mux_frame(frame_tx, frame.stream_id, MuxFrameKind::Reset, Vec::new())
                    .await?;
                return Ok(());
            }
            let mut payload = frame.payload.to_vec();
            // Per-stream target setup (resolve / connect / tune) fails on routine
            // client-chosen destinations: a bad ConnectRequest, DNS failure, a denied
            // IP, or a refused/timed-out connect. Shed ONLY this substream on any of
            // these — never `?`-propagate, which would poison the serial reader loop
            // and tear down the whole mux session (one bad target killing every
            // healthy concurrent stream). Nothing is registered yet, so a Reset for
            // this stream id plus returning (dropping any half-built `target`, closing
            // its fds) is the complete teardown — exactly like the cap-reached,
            // duplicate-stream, and initial-payload-write arms.
            let (target_addr, initial_payload) =
                match resolve_connect_target(payload.as_mut_slice(), context.fixed_data_target) {
                    Ok((target_addr, initial_payload)) => (target_addr, initial_payload.to_vec()),
                    Err(_) => {
                        tracing::debug!(
                            cid = context.cid,
                            stream_id = frame.stream_id,
                            "mux connect target resolve failed; resetting stream"
                        );
                        send_server_mux_frame(
                            frame_tx,
                            frame.stream_id,
                            MuxFrameKind::Reset,
                            Vec::new(),
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let mut target =
                match connect_outbound_target(&target_addr, context.fixed_data_target.is_some())
                    .await
                {
                    Ok(target) => target,
                    Err(_) => {
                        tracing::debug!(
                            cid = context.cid,
                            stream_id = frame.stream_id,
                            "mux outbound connect failed; resetting stream"
                        );
                        send_server_mux_frame(
                            frame_tx,
                            frame.stream_id,
                            MuxFrameKind::Reset,
                            Vec::new(),
                        )
                        .await?;
                        return Ok(());
                    }
                };
            if tune_tcp_stream(&target).is_err() {
                tracing::debug!(
                    cid = context.cid,
                    stream_id = frame.stream_id,
                    "mux target tune failed; resetting stream"
                );
                send_server_mux_frame(frame_tx, frame.stream_id, MuxFrameKind::Reset, Vec::new())
                    .await?;
                return Ok(());
            }
            if !initial_payload.is_empty() {
                // Bound the initial-payload write (H-3): a wedged target must not
                // park the serial mux reader loop. Nothing is registered yet, so on
                // stall just Reset the stream and drop `target` (both fds close).
                match timeout(
                    context.target_write_timeout,
                    target.write_all(&initial_payload),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        // Initial-payload write failed before anything was
                        // registered: Reset this stream and drop `target` (both
                        // fds close). Never poison the serial mux reader loop.
                        tracing::debug!(
                            cid = context.cid,
                            stream_id = frame.stream_id,
                            "mux target initial-payload write failed; resetting stream"
                        );
                        send_server_mux_frame(
                            frame_tx,
                            frame.stream_id,
                            MuxFrameKind::Reset,
                            Vec::new(),
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(_) => {
                        tracing::debug!(
                            cid = context.cid,
                            stream_id = frame.stream_id,
                            "mux target initial-payload write stalled; resetting stream"
                        );
                        send_server_mux_frame(
                            frame_tx,
                            frame.stream_id,
                            MuxFrameKind::Reset,
                            Vec::new(),
                        )
                        .await?;
                        return Ok(());
                    }
                }
                let mut initial_payload = initial_payload;
                initial_payload.zeroize();
            }
            let (target_read, target_write) = target.into_split();
            streams.writes.insert(frame.stream_id, target_write);
            let stream_id = frame.stream_id;
            let target_frame_tx = frame_tx.clone();
            let target_pool = payload_pool.clone();
            let handle = tokio::spawn(async move {
                if let Err(err) = server_mux_target_reader_loop(
                    target_read,
                    target_frame_tx,
                    stream_id,
                    context.timing,
                    context.chunk_size,
                    context.cid,
                    target_pool,
                )
                .await
                {
                    tracing::debug!(
                        cid = context.cid,
                        stream_id,
                        error = %err,
                        "server mux target reader stopped"
                    );
                }
            });
            streams.readers.insert(frame.stream_id, handle);
        }
        MuxFrameKind::Data => {
            if !frame.payload.is_empty() {
                // Bound the target write (H-3) and shed ONLY this stream on stall,
                // keeping the serial reader loop and every healthy substream alive.
                // The get_mut borrow ends before we remove, so the outcome is owned.
                let outcome = match streams.writes.get_mut(&frame.stream_id) {
                    Some(target_write) => Some(
                        timeout(
                            context.target_write_timeout,
                            target_write.write_all(frame.payload),
                        )
                        .await,
                    ),
                    None => None,
                };
                match outcome {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(_))) => {
                        // Routine per-destination write failure (e.g. the target
                        // closed its end). Shed ONLY this substream and keep the
                        // serial reader loop + every healthy substream alive,
                        // exactly as the stall path below does.
                        tracing::debug!(
                            cid = context.cid,
                            stream_id = frame.stream_id,
                            "mux target write failed; resetting stream"
                        );
                        shed_server_mux_substream(streams, frame_tx, frame.stream_id).await?;
                        return Ok(());
                    }
                    Some(Err(_)) => {
                        tracing::debug!(
                            cid = context.cid,
                            stream_id = frame.stream_id,
                            "mux target write stalled; resetting stream"
                        );
                        shed_server_mux_substream(streams, frame_tx, frame.stream_id).await?;
                    }
                    None => {}
                }
            }
        }
        MuxFrameKind::Fin => {
            // Client is done sending on this stream: close only the write half so
            // the target can keep streaming back (half-close). The reader task is
            // left running and will exit on target EOF or its own idle backstop.
            if let Some(mut target_write) = streams.writes.remove(&frame.stream_id) {
                let _ = target_write.shutdown().await;
            }
        }
        MuxFrameKind::Reset => {
            // Full stream teardown: close the write half AND abort the reader so
            // the target read fd/task is reclaimed immediately.
            if let Some(mut target_write) = streams.writes.remove(&frame.stream_id) {
                let _ = target_write.shutdown().await;
            }
            if let Some(handle) = streams.readers.remove(&frame.stream_id) {
                handle.abort();
            }
        }
        MuxFrameKind::Cover => {}
    }
    Ok(())
}

/// Shed a single mux substream without disturbing the rest of the connection:
/// close + drop its write half, abort + drop its reader task, and tell the
/// client to tear down that stream id with a Reset. Used on per-destination
/// write stalls/errors so one bad target never poisons the whole mux session.
async fn shed_server_mux_substream(
    streams: &mut ServerMuxStreams,
    frame_tx: &mpsc::Sender<MuxFrame>,
    stream_id: u32,
) -> Result<(), HandshakeServerError> {
    if let Some(mut w) = streams.writes.remove(&stream_id) {
        let _ = w.shutdown().await;
    }
    if let Some(h) = streams.readers.remove(&stream_id) {
        h.abort();
    }
    send_server_mux_frame(frame_tx, stream_id, MuxFrameKind::Reset, Vec::new()).await
}

async fn server_mux_target_reader_loop(
    mut target_read: OwnedReadHalf,
    frame_tx: mpsc::Sender<MuxFrame>,
    stream_id: u32,
    timing: TimingProfile,
    chunk_size: usize,
    cid: u64,
    payload_pool: MuxPayloadPool,
) -> Result<(), HandshakeServerError> {
    let max_payload_len = MuxFrame::max_payload_len(chunk_size);
    if max_payload_len == 0 {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0).into(),
        ));
    }
    let mut target_buf = vec![0_u8; relay_read_buffer_len(max_payload_len)];
    let mut rng = StdRng::from_entropy();
    // Per-read idle backstop: a target that connects then stays silent (after the
    // client Fin'd its write half, or an attacker-controlled target deliberately
    // holding the socket) must not pin this reader — and therefore its frame_tx
    // clone and target fd — forever. On idle, send Fin and exit so the slot is
    // reclaimed and the writer can drain.
    let read_idle_timeout = fallback_idle_timeout();

    loop {
        let n = match timeout(read_idle_timeout, target_read.read(&mut target_buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(err)) => {
                // Target read failed: tell the client to tear down this substream
                // promptly (best-effort) instead of letting it dangle until the
                // whole-session idle backstop, mirroring the Fin-on-EOF handling.
                let _ =
                    send_server_mux_frame(&frame_tx, stream_id, MuxFrameKind::Reset, Vec::new())
                        .await;
                return Err(HandshakeServerError::Io(err));
            }
            Err(_) => {
                tracing::debug!(cid, stream_id, "mux target reader idle backstop reached");
                send_server_mux_frame(&frame_tx, stream_id, MuxFrameKind::Fin, Vec::new()).await?;
                return Ok(());
            }
        };
        if n == 0 {
            send_server_mux_frame(&frame_tx, stream_id, MuxFrameKind::Fin, Vec::new()).await?;
            return Ok(());
        }
        let n = match drain_ready_tcp_read(&target_read, &mut target_buf, n) {
            Ok(n) => n,
            Err(err) => {
                // Drain of additional ready bytes failed: same prompt teardown as
                // the primary read-error path above.
                let _ =
                    send_server_mux_frame(&frame_tx, stream_id, MuxFrameKind::Reset, Vec::new())
                        .await;
                return Err(HandshakeServerError::Io(err));
            }
        };
        let delay = timing.sample_delay(&mut rng);
        if !delay.is_zero() {
            sleep(delay).await;
        }
        for chunk in target_buf[..n].chunks(max_payload_len) {
            send_server_mux_frame(
                &frame_tx,
                stream_id,
                MuxFrameKind::Data,
                payload_pool.take_filled(chunk),
            )
            .await?;
        }
        tracing::trace!(
            cid,
            stream_id,
            bytes = n,
            "queued server mux download payload"
        );
    }
}

async fn server_mux_writer_loop<W>(
    mut client_write: W,
    mut server_seal: DataRecordCodec,
    mut frame_rx: mpsc::Receiver<MuxFrame>,
    cover: CoverTrafficProfile,
    cid: u64,
    payload_pool: MuxPayloadPool,
) -> Result<(), HandshakeServerError>
where
    W: LegWriter,
{
    let mut seal_scratch = RelaySealScratch::with_payload_capacity(server_seal.max_plaintext_len());
    let mut rng = StdRng::from_entropy();
    if !cover.is_enabled() {
        loop {
            let Some(frame) = frame_rx.recv().await else {
                let _ = client_write.shutdown().await;
                return Ok(());
            };
            write_server_mux_frames_batched(
                &mut client_write,
                &mut server_seal,
                frame,
                ServerMuxBatchState {
                    frame_rx: &mut frame_rx,
                },
                &mut rng,
                &mut seal_scratch,
                RelayWriteLog::new(cid, "server->client", "server-mux-writer"),
                &payload_pool,
            )
            .await?;
        }
    }

    let mut cover_sleep = Box::pin(sleep(cover.sample_interval(&mut rng)));

    loop {
        tokio::select! {
            _ = &mut cover_sleep, if cover.is_enabled() => {
                write_server_mux_frame(
                    &mut client_write,
                    &mut server_seal,
                    MuxFrame { stream_id: 0, kind: MuxFrameKind::Cover, payload: Vec::new() },
                    &mut rng,
                    &mut seal_scratch,
                    cid,
                    "server-mux-cover-writer",
                )
                .await?;
                cover_sleep.as_mut().reset(Instant::now() + cover.sample_interval(&mut rng));
            }
            frame = frame_rx.recv() => {
                let Some(frame) = frame else {
                    let _ = client_write.shutdown().await;
                    return Ok(());
                };
                write_server_mux_frames_batched(
                    &mut client_write,
                    &mut server_seal,
                    frame,
                    ServerMuxBatchState {
                        frame_rx: &mut frame_rx,
                    },
                    &mut rng,
                    &mut seal_scratch,
                    RelayWriteLog::new(cid, "server->client", "server-mux-writer"),
                    &payload_pool,
                )
                .await?;
            }
        }
    }
}

async fn write_server_mux_frame<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    frame: MuxFrame,
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    cid: u64,
    task_name: &'static str,
) -> Result<(), HandshakeServerError>
where
    W: LegWriter,
    R: Rng + rand::RngCore + ?Sized,
{
    let frame_payload = frame.encode()?;
    write_server_data_records_chunked(
        writer,
        codec,
        &frame_payload,
        rng,
        scratch,
        RelayWriteLog::new(cid, "server->client", task_name),
    )
    .await
}

pub(crate) struct ServerMuxBatchState<'a> {
    pub(crate) frame_rx: &'a mut mpsc::Receiver<MuxFrame>,
}

/// Encodes the first frame plus any immediately available frames into
/// frame-aligned plaintext records (one record per `max_plaintext_len`
/// window), then seals the whole batch — inline for small batches, fanned out
/// across the shared crypto pool for bulk — and writes the records in order
/// with a single socket write.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_server_mux_frames_batched<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    first_frame: MuxFrame,
    batch: ServerMuxBatchState<'_>,
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    log: RelayWriteLog,
    payload_pool: &MuxPayloadPool,
) -> Result<(), HandshakeServerError>
where
    W: LegWriter,
    R: Rng + rand::RngCore + ?Sized,
{
    let max_plaintext_len = codec.max_plaintext_len();
    if max_plaintext_len == 0 {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0).into(),
        ));
    }

    // Phase A: drain frames into frame-aligned plaintext records, tracking
    // each record's length so the record boundaries are fixed before sealing.
    scratch.plaintext_buf.clear();
    scratch.record_lens.clear();
    let mut record_plaintext_len = encode_server_mux_frame(
        &mut scratch.plaintext_buf,
        first_frame,
        max_plaintext_len,
        payload_pool,
    )?;

    let mut drained = 0;
    while drained < SERVER_MUX_FRAME_BATCH_LIMIT {
        let frame = match batch.frame_rx.try_recv() {
            Ok(frame) => frame,
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        };
        let frame_len = MuxFrame::encoded_len(frame.payload.len())?;
        if record_plaintext_len + frame_len > max_plaintext_len {
            scratch.record_lens.push(record_plaintext_len);
            record_plaintext_len = 0;
        }
        record_plaintext_len += encode_server_mux_frame(
            &mut scratch.plaintext_buf,
            frame,
            max_plaintext_len,
            payload_pool,
        )?;
        drained += 1;
    }
    scratch.record_lens.push(record_plaintext_len);

    // Phase B: seal every record with unchanged boundaries and sequence
    // order; only the bulk path pays the crypto-pool dispatch cost.
    scratch.records_buf.clear();
    if should_parallelize_aead(scratch.record_lens.len(), scratch.plaintext_buf.len()) {
        codec.seal_records_into_parallel(
            parallel::global(),
            &scratch.plaintext_buf,
            &scratch.record_lens,
            rng,
            &mut scratch.records_buf,
        )?;
    } else {
        codec.seal_records_into(
            &scratch.plaintext_buf,
            &scratch.record_lens,
            rng,
            &mut scratch.records_buf,
        )?;
    }
    log_outer_write_batch(log, &scratch.record_lens, &scratch.records_buf);
    writer.write_records(scratch.records_buf.as_slice()).await?;
    scratch.records_buf.clear();
    Ok(())
}

/// Debug-logs each sealed record of a batch, mirroring the per-record
/// [`log_outer_write`] calls the serial writer used to make.
fn log_outer_write_batch(log: RelayWriteLog, record_lens: &[usize], records_buf: &[u8]) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let mut offset = 0;
    for &plaintext_len in record_lens {
        let Ok(header) = crate::tls::record::parse_header(&records_buf[offset..]) else {
            return;
        };
        log_outer_write(
            log.cid,
            log.direction,
            log.task_name,
            plaintext_len,
            &records_buf[offset..offset + header.total_len],
        );
        offset += header.total_len;
    }
}

fn encode_server_mux_frame(
    out: &mut Vec<u8>,
    frame: MuxFrame,
    max_plaintext_len: usize,
    payload_pool: &MuxPayloadPool,
) -> Result<usize, HandshakeServerError> {
    let frame_len = MuxFrame::encoded_len(frame.payload.len())?;
    if frame_len > max_plaintext_len {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(frame_len).into(),
        ));
    }
    frame.encode_into(out)?;
    payload_pool.put(frame.payload);
    Ok(frame_len)
}

async fn send_server_mux_frame(
    frame_tx: &mpsc::Sender<MuxFrame>,
    stream_id: u32,
    kind: MuxFrameKind,
    payload: Vec<u8>,
) -> Result<(), HandshakeServerError> {
    frame_tx
        .send(MuxFrame {
            stream_id,
            kind,
            payload,
        })
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()).into())
}

async fn run_authenticated_speed_test_mode(
    mut client_records: BufferedTlsRecordReader<OwnedReadHalf>,
    client_write: OwnedWriteHalf,
    mut client_open: DataRecordCodec,
    mut server_seal: DataRecordCodec,
    request: SpeedTestRequest,
    chunk_size: usize,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    tracing::info!(
        cid,
        warmup_bytes = request.warmup_bytes,
        download_bytes = request.download_bytes,
        upload_bytes = request.upload_bytes,
        sample_count = request.sample_count,
        "ParallaX speed test mode started"
    );
    if chunk_size == 0 {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0).into(),
        ));
    }
    // Reject requests beyond the server's ceilings. The wire format allows any
    // non-zero u64/u16 values; a malicious authenticated client could otherwise
    // request unbounded generated download or a never-ending upload to pin a
    // connection slot and bandwidth/CPU.
    if request.warmup_bytes > MAX_SPEED_TEST_BYTES_PER_PHASE
        || request.download_bytes > MAX_SPEED_TEST_BYTES_PER_PHASE
        || request.upload_bytes > MAX_SPEED_TEST_BYTES_PER_PHASE
        || request.sample_count > MAX_SPEED_TEST_SAMPLES
    {
        tracing::warn!(
            cid,
            warmup_bytes = request.warmup_bytes,
            download_bytes = request.download_bytes,
            upload_bytes = request.upload_bytes,
            sample_count = request.sample_count,
            "rejecting speed test request that exceeds server limits"
        );
        return Err(HandshakeServerError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "speed test request exceeds server limits",
        )));
    }
    // Aggregate ceiling: bound total generated + decrypted work per request, which
    // the individual per-phase caps do not (2x warmup + sample_count x (down+up)).
    let total_bytes = request.warmup_bytes.saturating_mul(2).saturating_add(
        (request.sample_count as u64)
            .saturating_mul(request.download_bytes.saturating_add(request.upload_bytes)),
    );
    if total_bytes > MAX_SPEED_TEST_TOTAL_BYTES {
        tracing::warn!(
            cid,
            total_bytes,
            "rejecting speed test request whose aggregate work exceeds the server limit"
        );
        return Err(HandshakeServerError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "speed test request exceeds server aggregate limit",
        )));
    }

    let mut rng = StdRng::from_entropy();
    let mut scratch = RelaySealScratch::with_payload_capacity(chunk_size);
    let batch_len = relay_read_buffer_len(chunk_size);
    let payload = vec![0xA5; batch_len];
    let mut client_write = TcpLegWriter(client_write);
    let mut io = SpeedServerIo {
        client_records: &mut client_records,
        client_write: &mut client_write,
        client_open: &mut client_open,
        server_seal: &mut server_seal,
        rng: &mut rng,
        scratch: &mut scratch,
        cid,
    };

    write_speed_download_phase(
        &mut io,
        &payload,
        request.warmup_bytes,
        SpeedTestAck::warmup_download_done(request.warmup_bytes),
        fallback_idle_timeout(),
    )
    .await?;
    read_speed_upload_phase(
        &mut io,
        request.warmup_bytes,
        SpeedTestAck::warmup_upload_done(request.warmup_bytes),
    )
    .await?;

    for _ in 0..request.sample_count {
        write_speed_download_phase(
            &mut io,
            &payload,
            request.download_bytes,
            SpeedTestAck::download_done(request.download_bytes),
            fallback_idle_timeout(),
        )
        .await?;
    }
    for _ in 0..request.sample_count {
        read_speed_upload_phase(
            &mut io,
            request.upload_bytes,
            SpeedTestAck::upload_done(request.upload_bytes),
        )
        .await?;
    }

    tracing::info!(cid, "ParallaX speed test mode finished");
    Ok(())
}

struct SpeedServerIo<'a, R: ?Sized> {
    client_records: &'a mut BufferedTlsRecordReader<OwnedReadHalf>,
    client_write: &'a mut TcpLegWriter,
    client_open: &'a mut DataRecordCodec,
    server_seal: &'a mut DataRecordCodec,
    rng: &'a mut R,
    scratch: &'a mut RelaySealScratch,
    cid: u64,
}

async fn write_speed_download_phase<R>(
    io: &mut SpeedServerIo<'_, R>,
    payload: &[u8],
    bytes: u64,
    ack: SpeedTestAck,
    idle: Duration,
) -> Result<(), HandshakeServerError>
where
    R: Rng + rand::RngCore + ?Sized,
{
    let mut remaining = bytes;
    while remaining > 0 {
        let len = remaining.min(payload.len() as u64) as usize;
        // Stall backstop (M-8): a client that advertises a zero receive window and
        // stops draining would otherwise block this write forever, pinning the
        // slot, both fds, and the per-source/global permits. Mirrors the upload
        // phase's per-read idle timeout; reclaims the connection after `idle`.
        timeout(
            idle,
            write_server_data_records_chunked(
                io.client_write,
                io.server_seal,
                &payload[..len],
                io.rng,
                io.scratch,
                RelayWriteLog::new(io.cid, "server->client", "server-speed-download-writer"),
            ),
        )
        .await
        .map_err(|_| HandshakeServerError::Timeout)??;
        remaining -= len as u64;
    }
    let ack = ack.encode();
    timeout(
        idle,
        write_server_data_records_chunked(
            io.client_write,
            io.server_seal,
            &ack,
            io.rng,
            io.scratch,
            RelayWriteLog::new(io.cid, "server->client", "server-speed-download-done"),
        ),
    )
    .await
    .map_err(|_| HandshakeServerError::Timeout)?
}

async fn read_speed_upload_phase<R>(
    io: &mut SpeedServerIo<'_, R>,
    bytes: u64,
    ack: SpeedTestAck,
) -> Result<(), HandshakeServerError>
where
    R: Rng + rand::RngCore + ?Sized,
{
    let mut uploaded = 0_u64;
    let mut consecutive_empty: u32 = 0;
    let mut client_record = Vec::new();
    let idle = fallback_idle_timeout();
    while uploaded < bytes {
        let read = timeout(idle, io.client_records.read_record_into(&mut client_record))
            .await
            .map_err(|_| HandshakeServerError::Timeout)?;
        match read {
            Ok(()) => {}
            Err(err) if is_clean_close(&err) => return Ok(()),
            Err(err) => return Err(HandshakeServerError::Io(err)),
        };
        log_record_read(
            io.cid,
            "client->server",
            "server-speed-upload-reader",
            &client_record,
        );
        let plaintext = io
            .client_open
            .open_in_place_payload_range(&mut client_record)?;
        let len = plaintext.len() as u64;
        if len == 0 {
            // Padding-only record carries no progress. Bound how many may arrive
            // back-to-back so a client streaming only empty records cannot pin the
            // phase forever (the idle timeout resets on every record received).
            consecutive_empty += 1;
            if consecutive_empty > MAX_CONSECUTIVE_EMPTY_UPLOAD_RECORDS {
                return Err(HandshakeServerError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "speed upload sent too many consecutive empty records",
                )));
            }
            continue;
        }
        consecutive_empty = 0;
        if uploaded + len > bytes {
            return Err(HandshakeServerError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "speed upload sent more bytes than requested",
            )));
        }
        uploaded += len;
    }

    let ack = ack.encode();
    write_server_data_records_chunked(
        io.client_write,
        io.server_seal,
        &ack,
        io.rng,
        io.scratch,
        RelayWriteLog::new(io.cid, "server->client", "server-speed-upload-done"),
    )
    .await
}

/// Drains the client->server direction to the target. Returns the owned
/// `client_open` codec on a clean finish so the QUIC fast-plane teardown can
/// open the peer's DONE marker on the SAME receive-direction codec (sequence
/// continues uninterrupted). TCP-path callers discard the returned codec.
async fn server_upload_loop<R>(
    mut client_records: R,
    mut target_write: OwnedWriteHalf,
    mut client_open: DataRecordCodec,
    activity: RelayActivity,
    cid: u64,
    idle_timeout: Duration,
) -> Result<DataRecordCodec, HandshakeServerError>
where
    R: LegReader,
{
    let mut client_record = Vec::new();

    loop {
        match client_records.read_record_into(&mut client_record).await {
            Ok(()) => {}
            Err(err) if client_records.is_clean_close(&err) => {
                let _ = target_write.shutdown().await;
                return Ok(client_open);
            }
            Err(err) => return Err(HandshakeServerError::Io(err)),
        };
        log_record_read(
            cid,
            "client->server",
            "server-data-client-reader",
            &client_record,
        );
        match client_open.open_in_place_payload_range(&mut client_record) {
            Ok(plaintext) => {
                if !plaintext.is_empty() {
                    // Bound the target write so a stuck upstream cannot pin this
                    // relay indefinitely. NOTE: this per-write timeout reliably
                    // fires only when the relay is otherwise progressing (the
                    // download direction keeps bumping `activity`); in the pure
                    // "client keeps sending, target accepts-then-stalls, no
                    // download traffic" case the shared idle-watchdog (anchored to
                    // the last activity bump, hence an equal-or-earlier deadline)
                    // wins the race and tears the relay down at the idle backstop.
                    // Either way the connection is reclaimed within ~idle_timeout
                    // (the resource-pinning DoS is closed); the residual is that in
                    // that narrow case the partial body is FIN'd to the target
                    // rather than surfaced as a Timeout error — a pre-existing
                    // behavior a fully deterministic fix would need to address by
                    // distinguishing "stuck write" from "idle" in the watchdog.
                    timeout(
                        idle_timeout,
                        target_write.write_all(&client_record[plaintext]),
                    )
                    .await
                    .map_err(|_| HandshakeServerError::Timeout)??;
                    bump_relay_activity(&activity);
                }
            }
            Err(err) => {
                return Err(HandshakeServerError::DataRecord(err));
            }
        }
    }
}

/// Drains the server->client direction (target response) into the client leg.
/// Returns the owned `server_seal` codec on a clean finish so the QUIC
/// fast-plane teardown can seal the local DONE marker on the SAME send-direction
/// codec (sequence continues uninterrupted). TCP-path callers discard it.
#[allow(clippy::too_many_arguments)]
async fn server_download_loop<W>(
    mut target_read: OwnedReadHalf,
    mut client_write: W,
    mut server_seal: DataRecordCodec,
    mut target_buf: Vec<u8>,
    timing: TimingProfile,
    cover: CoverTrafficProfile,
    activity: RelayActivity,
    cid: u64,
) -> Result<DataRecordCodec, HandshakeServerError>
where
    W: LegWriter,
{
    let mut seal_scratch = RelaySealScratch::with_payload_capacity(target_buf.len());
    let mut rng = StdRng::from_entropy();
    if !cover.is_enabled() {
        loop {
            let n = target_read.read(&mut target_buf).await?;
            if n == 0 {
                let _ = client_write.shutdown().await;
                return Ok(server_seal);
            }
            bump_relay_activity(&activity);
            let n = drain_ready_tcp_read(&target_read, &mut target_buf, n)?;

            let delay = timing.sample_delay(&mut rng);
            if !delay.is_zero() {
                sleep(delay).await;
            }

            write_server_data_records_chunked(
                &mut client_write,
                &mut server_seal,
                &target_buf[..n],
                &mut rng,
                &mut seal_scratch,
                RelayWriteLog::new(cid, "server->client", "server-download-writer"),
            )
            .await?;
        }
    }

    let mut cover_sleep = Box::pin(sleep(cover.sample_interval(&mut rng)));

    loop {
        tokio::select! {
            _ = &mut cover_sleep, if cover.is_enabled() => {
                write_server_data_records_chunked(
                    &mut client_write,
                    &mut server_seal,
                    &[],
                    &mut rng,
                    &mut seal_scratch,
                    RelayWriteLog::new(cid, "server->client", "server-cover-writer"),
                )
                .await?;
                cover_sleep.as_mut().reset(
                    Instant::now() + cover.sample_interval(&mut rng),
                );
            }
            read = target_read.read(&mut target_buf) => {
                let n = read?;
                if n == 0 {
                    let _ = client_write.shutdown().await;
                    return Ok(server_seal);
                }
                bump_relay_activity(&activity);
                let n = drain_ready_tcp_read(&target_read, &mut target_buf, n)?;

                let delay = timing.sample_delay(&mut rng);
                if !delay.is_zero() {
                    sleep(delay).await;
                }

                write_server_data_records_chunked(
                    &mut client_write,
                    &mut server_seal,
                    &target_buf[..n],
                    &mut rng,
                    &mut seal_scratch,
                    RelayWriteLog::new(cid, "server->client", "server-download-writer"),
                )
                .await?;
            }
        }
    }
}

async fn write_server_data_records_chunked<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    payload: &[u8],
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    log: RelayWriteLog,
) -> Result<(), HandshakeServerError>
where
    W: LegWriter,
    R: rand::Rng + rand::RngCore + ?Sized,
{
    let max_chunk_len = codec.max_plaintext_len();
    if max_chunk_len == 0 {
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(payload.len()).into(),
        ));
    }
    scratch.records_buf.clear();
    let debug_records = tracing::enabled!(tracing::Level::DEBUG);
    if debug_records {
        codec.seal_chunks_into_reusing(
            payload,
            rng,
            &mut scratch.records_buf,
            &mut scratch.records,
        )?;
        for record in scratch.records.iter() {
            log_outer_write(
                log.cid,
                log.direction,
                log.task_name,
                record.plaintext_len,
                &scratch.records_buf[record.range.clone()],
            );
        }
    } else {
        codec.seal_chunks_into_untracked(payload, rng, &mut scratch.records_buf)?;
    }
    writer.write_records(scratch.records_buf.as_slice()).await?;
    Ok(())
}

pub(crate) struct RelaySealScratch {
    records_buf: Vec<u8>,
    records: Vec<SealedRecord>,
    /// Frame-aligned record plaintext accumulated before sealing, so the seal
    /// can be fanned out across the crypto pool without changing record
    /// boundaries.
    plaintext_buf: Vec<u8>,
    record_lens: Vec<usize>,
}

impl RelaySealScratch {
    pub(crate) fn with_payload_capacity(capacity: usize) -> Self {
        Self {
            records_buf: Vec::with_capacity(capacity + crate::tls::record::TLS_HEADER_LEN),
            records: Vec::new(),
            plaintext_buf: Vec::with_capacity(capacity),
            record_lens: Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RelayWriteLog {
    cid: u64,
    direction: &'static str,
    task_name: &'static str,
}

impl RelayWriteLog {
    pub(crate) fn new(cid: u64, direction: &'static str, task_name: &'static str) -> Self {
        Self {
            cid,
            direction,
            task_name,
        }
    }
}

fn log_outer_write(
    cid: u64,
    direction: &'static str,
    task_name: &'static str,
    plaintext_len: usize,
    record: &[u8],
) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    if let Ok(header) = crate::tls::record::parse_header(record) {
        tracing::debug!(
            cid,
            direction,
            task_name,
            plaintext_len,
            sealed_len = header.payload_len,
            outer_tls_payload_len = header.payload_len,
            tls_content_type = header.content_type,
            "outer TLS record write"
        );
    }
}

// TCP-leg clean-close predicate: a peer FIN (`UnexpectedEof`), the proxy's
// graceful-close RST convention (`ConnectionReset`), or `BrokenPipe`. Used by
// the TCP-only fallback/relay/mux reader loops. The QUIC fast-plane legs do NOT
// use this — they go through `LegReader::is_clean_close`, which (unlike TCP)
// treats a `RESET_STREAM`-derived `ConnectionReset` as a truncation, not a clean
// close. See `transport::leg`.
fn is_clean_close(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    )
}

/// True when a WRITE failed because the receiving peer has closed its end
/// (BrokenPipe / ConnectionReset). Deliberately separate from `is_clean_close`
/// (a read-side predicate): a normal peer close observed on a forward write
/// should end the phase gracefully, not be reported as a hard I/O error.
fn is_write_peer_close(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
    )
}

/// True iff the QUIC connection was closed by the peer with the agreed
/// [`RELAY_IDLE_CLOSE_CODE`], i.e. the peer's idle watchdog fired first. Lets this
/// side treat that as a benign mutual idle teardown (Ok) instead of a relay error.
fn is_peer_idle_close(conn: &crate::transport::udp::quic::endpoint::Connection) -> bool {
    crate::protocol::data::is_relay_idle_close_reason(conn.close_reason().as_ref())
}

fn is_authorized_sni(sni: &str, authorized_sni: &[String]) -> bool {
    authorized_sni
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(sni))
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use rand::{rngs::StdRng, SeedableRng};
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use super::*;

    // --- Track A1: lock-free relay activity clock — watchdog semantics ---
    // Below the `mod tests` boundary, so the no-timeout static ratchet (which
    // scans the production region) is unaffected. Lock the preserved idle
    // semantics so a future coarsening that broke the DoS backstop turns red.

    #[tokio::test]
    async fn relay_idle_watchdog_fires_after_idle_timeout() {
        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let fired = tokio::time::timeout(
            Duration::from_secs(2),
            relay_idle_watchdog(activity, Duration::from_millis(20)),
        )
        .await;
        assert!(fired.is_ok(), "watchdog must fire once the relay is idle");
    }

    #[tokio::test]
    async fn relay_idle_watchdog_pending_before_idle_timeout() {
        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let fired = tokio::time::timeout(
            Duration::from_millis(50),
            relay_idle_watchdog(activity, Duration::from_secs(30)),
        )
        .await;
        assert!(
            fired.is_err(),
            "watchdog must not fire before the idle timeout"
        );
    }

    #[tokio::test]
    async fn bump_relay_activity_defers_watchdog() {
        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let bumped = activity.clone();
        let bumper = tokio::spawn(async move {
            for _ in 0..10 {
                sleep(Duration::from_millis(15)).await;
                bump_relay_activity(&bumped);
            }
        });
        let fired = tokio::time::timeout(
            Duration::from_millis(100),
            relay_idle_watchdog(activity, Duration::from_millis(60)),
        )
        .await;
        assert!(
            fired.is_err(),
            "ongoing activity must defer the idle watchdog"
        );
        bumper.await.unwrap();
    }

    use crate::{
        crypto::{
            auth::{
                build_auth_tail_at, build_masked_stateful_auth_session_id,
                build_masked_stateful_client_random, derive_client_auth_key,
            },
            session::X25519KeyPair,
        },
        handshake::client::ClientDataSession,
        protocol::command::{ConnectRequest, ConnectRequestError},
        tls::{
            client_hello::tests::{
                client_hello_fixture_no_key_share, client_hello_fixture_with_key_share,
                client_hello_fixture_with_key_share_no_sni,
                client_hello_fixture_with_random_and_key_share,
            },
            server_hello::{parse_server_hello, tests::server_hello_fixture},
        },
    };

    const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn outbound_connect_timeout_maps_to_server_timeout_error() {
        let err = connect_future_with_timeout(
            std::future::pending::<io::Result<TcpStream>>(),
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, HandshakeServerError::OutboundConnectTimeout));
    }

    #[tokio::test]
    async fn first_client_record_timeout_enters_fallback_without_close() {
        let (_client, mut server_side) = tokio::io::duplex(8);

        let read =
            read_first_client_record_with_timeout(&mut server_side, Duration::from_millis(1))
                .await
                .unwrap();

        assert_eq!(read, FirstClientRead::FallbackPrefix(Vec::new()));
    }

    #[tokio::test]
    async fn first_client_record_invalid_header_preserves_probe_prefix() {
        let (mut client, mut server_side) = tokio::io::duplex(8);
        client
            .write_all(&[0x16, 0x03, 0x03, 0xff, 0xff])
            .await
            .unwrap();

        let read =
            read_first_client_record_with_timeout(&mut server_side, Duration::from_millis(50))
                .await
                .unwrap();

        assert_eq!(
            read,
            FirstClientRead::FallbackPrefix(vec![0x16, 0x03, 0x03, 0xff, 0xff])
        );
    }

    #[tokio::test]
    async fn first_client_record_timeout_is_total_not_per_read() {
        let (mut client, mut server_side) = tokio::io::duplex(8);
        client.write_all(&[0x16]).await.unwrap();
        tokio::spawn(async move {
            sleep(Duration::from_millis(30)).await;
            let _ = client.write_all(&[0x03]).await;
            sleep(Duration::from_millis(30)).await;
            let _ = client.write_all(&[0x03]).await;
        });

        let started = Instant::now();
        let read =
            read_first_client_record_with_timeout(&mut server_side, Duration::from_millis(50))
                .await
                .unwrap();

        let FirstClientRead::FallbackPrefix(prefix) = read else {
            panic!("slow first record should fall back");
        };
        assert!(!prefix.is_empty());
        assert!(prefix.len() < TLS_HEADER_LEN);
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn pending_replay_entry_commits_once_after_data_proof() {
        let cache = Arc::new(Mutex::new(ReplayCache::new(8)));
        let entry = ReplayEntry {
            timestamp: current_unix_timestamp().unwrap(),
            nonce: [7; 8],
            transcript_fingerprint: [8; 32],
        };
        let mut first = Some(PendingReplayEntry {
            cache: Arc::clone(&cache),
            entry: entry.clone(),
        });
        let mut replayed = Some(PendingReplayEntry {
            cache: Arc::clone(&cache),
            entry,
        });

        assert!(commit_pending_replay_entry(&mut first).await.unwrap());
        assert!(first.is_none());
        assert!(!commit_pending_replay_entry(&mut replayed).await.unwrap());
        assert!(replayed.is_none());
    }

    #[test]
    fn identity_chunk_delay_is_zero_for_speed_first_traffic() {
        let timing = TimingProfile::from_config(TrafficConfig::default());
        let mut rng = StdRng::seed_from_u64(101);

        assert_eq!(
            server_identity_chunk_delay(timing, &mut rng),
            Duration::ZERO
        );
    }

    #[test]
    fn identity_chunk_delay_keeps_camouflage_floor_when_timing_enabled() {
        let timing = TimingProfile::from_config(TrafficConfig {
            min_delay_ms: 1,
            max_delay_ms: 1,
            ..TrafficConfig::default()
        });
        let mut rng = StdRng::seed_from_u64(102);

        assert_eq!(
            server_identity_chunk_delay(timing, &mut rng),
            SERVER_IDENTITY_CHUNK_MIN_DELAY + Duration::from_millis(1)
        );
    }

    #[test]
    fn identity_chunk_plaintext_len_jitters_without_timing_delay() {
        let mut rng = StdRng::seed_from_u64(104);
        let mut saw_different = false;
        let first = server_identity_chunk_plaintext_len(&mut rng);

        for _ in 0..64 {
            let len = server_identity_chunk_plaintext_len(&mut rng);
            assert!(
                (SERVER_IDENTITY_CHUNK_MIN_PLAINTEXT..=SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT)
                    .contains(&len)
            );
            saw_different |= len != first;
        }

        assert!(saw_different);
    }

    #[tokio::test]
    async fn speed_first_identity_writer_batches_chunks_into_one_write() {
        let traffic = TrafficConfig::default();
        let padding = PaddingProfile::from_config(traffic).unwrap();
        let timing = TimingProfile::from_config(traffic);
        let mut server_seal = DataRecordCodec::new(
            AeadCodec::new([3_u8; 32], [4_u8; crate::crypto::session::NONCE_LEN]),
            padding,
            SERVER_TO_CLIENT_AAD,
        );
        let mut client_open = DataRecordCodec::new(
            AeadCodec::new([3_u8; 32], [4_u8; crate::crypto::session::NONCE_LEN]),
            padding,
            SERVER_TO_CLIENT_AAD,
        );
        let payload = vec![0x42_u8; SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT * 2 + 1];
        let chunks =
            ServerIdentityChunk::encode_all(&payload, SERVER_IDENTITY_CHUNK_MAX_PLAINTEXT).unwrap();
        let expected_chunks = chunks.clone();
        let mut rng = StdRng::seed_from_u64(103);
        let mut writer = CountingWriter::default();

        write_server_identity_chunks(&mut writer, &mut server_seal, chunks, &mut rng, timing, 7)
            .await
            .unwrap();

        assert_eq!(writer.writes, 1);
        let mut opened_chunks = Vec::new();
        let mut offset = 0;
        while offset < writer.bytes.len() {
            let header = crate::tls::record::parse_header(&writer.bytes[offset..]).unwrap();
            let end = offset + header.total_len;
            opened_chunks.push(client_open.open(&writer.bytes[offset..end]).unwrap());
            offset = end;
        }
        assert_eq!(opened_chunks, expected_chunks);
    }

    #[derive(Default)]
    struct CountingWriter {
        writes: usize,
        bytes: Vec<u8>,
    }

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Builds a v4 masked-stateful authenticated ClientHello: `parallax_public`
    /// (the ParallaX ephemeral the server recovers) rides behind the carrier
    /// mask, `tls_key_share` is the standalone TLS key_share the server uses to
    /// derive mask_ecdh, and the masked auth tag is keyed by `auth_key`. Pass a
    /// wrong `auth_key` for a record that recovers (recover==Some) but fails
    /// masked auth -- the M-2 "shape D" reject case.
    fn masked_authed_client_hello(
        server_private: &[u8; 32],
        parallax_public: &[u8; 32],
        tls_key_share: &[u8; 32],
        sni: &str,
        auth_key: &[u8],
        timestamp: u64,
    ) -> Vec<u8> {
        let mut record =
            client_hello_fixture_with_random_and_key_share(sni, parallax_public, tls_key_share);
        let parsed = parse_client_hello(&record).unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        let tail = build_auth_tail_at(timestamp, &mut rng);
        let mask_ecdh = x25519_shared_secret(server_private, tls_key_share);
        let encoded_random =
            build_masked_stateful_client_random(PSK, &mask_ecdh, sni, parallax_public, &tail)
                .unwrap();
        let session_id = build_masked_stateful_auth_session_id(
            PSK,
            &mask_ecdh,
            auth_key,
            sni,
            parallax_public,
            &encoded_random,
            &tail,
        )
        .unwrap();
        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        record[random_offset..random_offset + 32].copy_from_slice(&encoded_random);
        record[parsed.session_id_range].copy_from_slice(&session_id);
        record
    }

    #[test]
    fn decides_authenticated_inbound() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = *derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let record = masked_authed_client_hello(
            &server.private,
            &client.public,
            &[0x44_u8; 32],
            "example.com",
            &auth_key,
            1_700_000_001,
        );

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        match decision {
            InboundDecision::Authenticated(hello) => {
                assert_eq!(hello.sni, "example.com");
                assert_eq!(hello.x25519_key_share, client.public);
            }
            other => panic!("unexpected decision: {other:?}"),
        }

        let decision = decide_connection_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();
        match decision {
            ConnectionDecision::Authenticated(authenticated) => {
                assert_eq!(
                    *authenticated.x25519_shared_secret,
                    x25519_shared_secret(&server.private, &client.public)
                );
            }
            ConnectionDecision::Fallback(reason) => panic!("unexpected fallback: {reason:?}"),
        }
    }

    #[test]
    fn decides_masked_stateful_inbound() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = *derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let mut record = client_hello_fixture_with_random_and_key_share(
            "example.com",
            &client.public,
            &[0x44_u8; 32],
        );
        let parsed = parse_client_hello(&record).unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        let tail = build_auth_tail_at(1_700_000_001, &mut rng);
        // The fixture's standalone X25519 key_share is [0x44; 32]; the server
        // derives mask_ecdh = X25519(server.private, [0x44;32]), so build the
        // masks with the same value.
        let mask_ecdh = x25519_shared_secret(&server.private, &[0x44_u8; 32]);
        let encoded_random = build_masked_stateful_client_random(
            PSK,
            &mask_ecdh,
            "example.com",
            &client.public,
            &tail,
        )
        .unwrap();
        let session_id = build_masked_stateful_auth_session_id(
            PSK,
            &mask_ecdh,
            &auth_key,
            "example.com",
            &client.public,
            &encoded_random,
            &tail,
        )
        .unwrap();
        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        record[random_offset..random_offset + 32].copy_from_slice(&encoded_random);
        record[parsed.session_id_range].copy_from_slice(&session_id);

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        match decision {
            InboundDecision::Authenticated(hello) => {
                assert_eq!(hello.sni, "example.com");
                assert_eq!(hello.x25519_key_share, client.public);
                assert_eq!(hello.timestamp, 1_700_000_001);
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn masked_stateful_without_tls13_support_falls_back() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = *derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let mut record = client_hello_fixture_with_random_and_key_share(
            "example.com",
            &client.public,
            &[0x44_u8; 32],
        );
        let parsed = parse_client_hello(&record).unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        let tail = build_auth_tail_at(1_700_000_001, &mut rng);
        let mask_ecdh = x25519_shared_secret(&server.private, &[0x44_u8; 32]);
        let encoded_random = build_masked_stateful_client_random(
            PSK,
            &mask_ecdh,
            "example.com",
            &client.public,
            &tail,
        )
        .unwrap();
        let session_id = build_masked_stateful_auth_session_id(
            PSK,
            &mask_ecdh,
            &auth_key,
            "example.com",
            &client.public,
            &encoded_random,
            &tail,
        )
        .unwrap();
        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        record[random_offset..random_offset + 32].copy_from_slice(&encoded_random);
        record[parsed.session_id_range].copy_from_slice(&session_id);
        replace_tls13_supported_version_with_tls12(&mut record);

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::AuthFailed)
        );
    }

    #[test]
    fn v4_real_start_authenticates_against_decide_inbound() {
        // End-to-end agreement across the REAL client start() and the REAL server
        // decide path: proves the client mask_key = X25519(tls.private, server.pub)
        // equals the server mask_key = X25519(server.private, tls.pub), so the v4
        // carrier masks round-trip.
        let server = X25519KeyPair::generate();
        let session = crate::tls::safari26::Safari26TlsCamouflage
            .start("example.com".to_owned(), PSK, &server.public)
            .unwrap();
        let record = session.client_hello_bytes().to_vec();
        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();
        assert!(
            matches!(decision, InboundDecision::Authenticated(_)),
            "a real v4 client must authenticate, got {decision:?}"
        );
    }

    #[test]
    fn v4_mask_ecdh_mismatch_falls_back_not_authenticated() {
        // Simulates a version/peer mismatch (e.g. v3 client ↔ v4 server): masks
        // built with a mask_ecdh the server will not derive yield garbage material
        // → tag mismatch → Fallback, never Authenticated (fail-closed).
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = *derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let mut record = client_hello_fixture_with_random_and_key_share(
            "example.com",
            &client.public,
            &[0x44_u8; 32],
        );
        let parsed = parse_client_hello(&record).unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        let tail = build_auth_tail_at(1_700_000_001, &mut rng);
        // != X25519(server.private, [0x44;32]) that decide_inbound will derive.
        let wrong_mask_ecdh = [0x99_u8; 32];
        let encoded_random = build_masked_stateful_client_random(
            PSK,
            &wrong_mask_ecdh,
            "example.com",
            &client.public,
            &tail,
        )
        .unwrap();
        let session_id = build_masked_stateful_auth_session_id(
            PSK,
            &wrong_mask_ecdh,
            &auth_key,
            "example.com",
            &client.public,
            &encoded_random,
            &tail,
        )
        .unwrap();
        let random_offset = crate::tls::record::TLS_HEADER_LEN + 4 + 2;
        record[random_offset..random_offset + 32].copy_from_slice(&encoded_random);
        record[parsed.session_id_range].copy_from_slice(&session_id);

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();
        assert!(
            matches!(decision, InboundDecision::Fallback(_)),
            "mask_ecdh mismatch must fall back, got {decision:?}"
        );
    }

    #[test]
    fn falls_back_on_bad_auth() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        // Unsigned fixture: 32-byte session_id placeholder + SNI -> recover==Some,
        // but the placeholder is not a valid masked auth tag, so auth fails.
        let record = client_hello_fixture_with_key_share("example.com", &client.public);

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::AuthFailed)
        );
    }

    /// Run `decide_connection_inbound` once and return how many X25519 DH ops it
    /// performed (via the #[cfg(test)] REJECT_DH_OPS counter). Shared by the
    /// constant-work / timing tests below, all #[ignore]d + serial because the
    /// counter is process-global.
    fn dh_ops_for(record: &[u8], server_priv: &[u8; 32]) -> usize {
        REJECT_DH_OPS.store(0, Ordering::Relaxed);
        let _ = decide_connection_inbound(record, PSK, &[String::from("example.com")], server_priv);
        REJECT_DH_OPS.load(Ordering::Relaxed)
    }

    /// M-2: the inbound-decision rejection path must perform an input-INDEPENDENT
    /// number of X25519 DH ops, else the per-DH latency step (no key_share vs
    /// auth-fail) is a timing distinguisher. Ignored + serial: it reads
    /// the process-global REJECT_DH_OPS counter that parallel decide_* tests perturb.
    #[test]
    #[ignore = "reads the process-global REJECT_DH_OPS counter; run serially"]
    fn rejection_path_x25519_count_is_input_independent() {
        let server = X25519KeyPair::generate();

        // Shape B: no x25519 key_share -> mask-slot ballast + auth-slot ballast (2).
        let no_ks = client_hello_fixture_no_key_share("example.com");
        // Shape D: key_share present, recover==Some, masked auth fails. The unsigned
        // fixture's 32-byte session_id placeholder recovers Some but is not a valid
        // masked auth tag, so the mask-slot and auth-slot DH both run (2).
        let auth_fail = client_hello_fixture_with_key_share("example.com", &[0x66; 32]);

        let b = dh_ops_for(&no_ks, &server.private);
        let d = dh_ops_for(&auth_fail, &server.private);
        assert_eq!(
            b, d,
            "no-key_share vs auth-fail DH count differs (timing distinguisher)"
        );
        assert_eq!(
            b, 2,
            "rejection path must perform a constant 2 X25519 DH ops"
        );
    }

    /// M-2 (coverage extension): the THIRD attacker-reachable parseable reject
    /// shape — a key_share IS present but `recover_stateful_auth_material` returns
    /// None — must also perform the constant 2 DH ops, so ALL parseable-but-
    /// rejected ClientHello shapes (no-key_share, recover==None, masked-auth-fail)
    /// are mutually timing-indistinguishable, not just two of the three.
    ///
    /// To actually reach recover==None WITH a key_share present, the fixture must
    /// trip one of recover's early-None gates while still carrying a key_share. A
    /// fixture with an SNI and a 32-byte session_id (e.g.
    /// `client_hello_fixture_with_key_share`) recovers `Some` — it would silently
    /// re-test the masked-auth-fail (recover==Some) shape, not this one. So we use
    /// a key_share-present fixture with NO SNI, which makes recover return None via
    /// its missing-SNI gate. We assert that None as independent ground truth so the
    /// test cannot silently mis-cover.
    #[test]
    #[ignore = "reads the process-global REJECT_DH_OPS counter; run serially"]
    fn rejection_path_x25519_count_covers_recover_none_shape() {
        let server = X25519KeyPair::generate();
        // key_share present, but NO SNI -> recover hits its missing-SNI early-None
        // gate and the code takes the `ballast: v4 auth-slot, recover==None` path.
        const KEY_SHARE: [u8; 32] = [0x66; 32];
        let key_share_no_recover = client_hello_fixture_with_key_share_no_sni(&KEY_SHARE);

        // Independent ground truth: prove the intended branch is actually taken —
        // recover returns None for this fixture. mask_ecdh is computed exactly as
        // the server does for a present key_share: X25519(server_static, key_share).
        let parsed = parse_client_hello(&key_share_no_recover).expect("fixture parses");
        assert!(
            parsed.x25519_key_share.is_some(),
            "fixture must carry a key_share so the recover==None path is the \
             key_share-present shape, not the no-key_share shape"
        );
        let mask_ecdh = x25519_shared_secret(&server.private, &KEY_SHARE);
        let recovered = recover_stateful_auth_material_from_parsed(
            &key_share_no_recover,
            PSK,
            &mask_ecdh,
            &parsed,
        )
        .expect("recover must not error on a parseable record");
        assert!(
            recovered.is_none(),
            "ground truth: recover must return None for this fixture, else the test \
             re-covers the recover==Some shape instead of the intended recover==None"
        );

        assert_eq!(
            dh_ops_for(&key_share_no_recover, &server.private),
            2,
            "key_share + recover==None reject path must perform the constant 2 X25519 DH ops"
        );
    }

    /// META-TEST (deterministic teeth for the constant-work guard): prove the
    /// REJECT_DH_OPS counter is NOT vacuously pinned to 3. A genuinely different
    /// path — an unparseable record short-circuits at `parse_client_hello` before
    /// any DH — must read a DIFFERENT count (0). Without this, the constant-work
    /// assertions above could pass against a broken/stuck counter; with it, we
    /// know the counter discriminates and the `assert_eq!(.., 2)` guards bite.
    #[test]
    #[ignore = "reads the process-global REJECT_DH_OPS counter; run serially"]
    fn constant_work_counter_is_non_vacuous() {
        let server = X25519KeyPair::generate();
        let unparseable = dh_ops_for(b"this is not a TLS ClientHello", &server.private);
        let valid_unauth = dh_ops_for(
            &client_hello_fixture_no_key_share("example.com"),
            &server.private,
        );
        assert_eq!(unparseable, 0, "an unparseable record performs zero DH ops");
        assert_eq!(
            valid_unauth, 2,
            "a parseable-but-unauthenticated record performs 2 DH ops"
        );
        assert_ne!(
            unparseable, valid_unauth,
            "the counter must discriminate, else the constant-work guards are vacuous"
        );
    }

    /// Median of a sample (sorts in place). Robust to scheduler/GC outliers.
    #[cfg(test)]
    fn timing_median_ns(mut samples: Vec<u64>) -> u64 {
        assert!(!samples.is_empty());
        samples.sort_unstable();
        samples[samples.len() / 2]
    }

    /// META-TEST (deterministic teeth for the timing gate's STATISTICS): the
    /// self-normalized separability used by the dynamic test below must correctly
    /// FLAG a shifted distribution and PASS an unshifted one — otherwise a green
    /// dynamic-timing result would be meaningless. We test the pure median logic
    /// on synthetic data so this is fast and never flaky.
    #[test]
    fn timing_separability_statistic_is_non_vacuous() {
        // Same distribution split in two -> medians ~equal -> tiny gap.
        let a: Vec<u64> = (0..1000).map(|i| 1000 + (i % 7)).collect();
        let a2: Vec<u64> = (0..1000).map(|i| 1000 + ((i + 3) % 7)).collect();
        let same_gap = (timing_median_ns(a.clone()) as i64 - timing_median_ns(a2) as i64).abs();
        // A clearly shifted distribution (+200) -> large gap the gate must catch.
        let shifted: Vec<u64> = (0..1000).map(|i| 1200 + (i % 7)).collect();
        let shift_gap = (timing_median_ns(a) as i64 - timing_median_ns(shifted) as i64).abs();
        assert!(
            same_gap <= 3,
            "same-distribution median gap must be ~0, got {same_gap}"
        );
        assert!(
            shift_gap >= 150,
            "a 200ns shift must produce a large median gap, got {shift_gap}"
        );
    }

    /// WORLD-FIRST-FOR-THIS-REPO dynamic side-channel MEASUREMENT. The
    /// counter tests above prove the DH OP COUNT is input-independent; this
    /// proves the actual WALL-CLOCK latency of the rejection decision is not
    /// grossly input-dependent either (catching a data-dependent branch or
    /// memory pattern a pure op-count cannot see). It is SELF-NORMALIZED — the
    /// cross-shape median gap is compared against a same-shape control gap
    /// measured in the same run — and gated GENEROUSLY so it documents the
    /// signal and catches only a gross asymmetry without flaking on shared CI
    /// runners; the precise 1-DH-asymmetry guard is the deterministic counter
    /// test, not this one. #[ignore]: wall-clock + global counter, serial lane.
    #[test]
    #[ignore = "dynamic wall-clock timing; run serially in the --ignored lane"]
    fn rejection_path_timing_is_not_grossly_input_dependent() {
        use std::time::Instant;
        let server = X25519KeyPair::generate();
        let shape_b = client_hello_fixture_no_key_share("example.com");
        let shape_d = client_hello_fixture_with_key_share("example.com", &[0x66; 32]);

        let reject = |record: &[u8]| {
            let _ = decide_connection_inbound(
                record,
                PSK,
                &[String::from("example.com")],
                &server.private,
            );
        };
        // Warm up code/data caches and the branch predictor for both shapes.
        for _ in 0..2000 {
            reject(&shape_b);
            reject(&shape_d);
        }

        // Interleaved paired sampling cancels environmental drift: in each round
        // we time shape_b, shape_d, then shape_b again (the second b is the
        // same-shape control). Drift over a round hits all three equally.
        let n = 3000usize;
        let (mut tb, mut td, mut tb2) = (
            Vec::with_capacity(n),
            Vec::with_capacity(n),
            Vec::with_capacity(n),
        );
        for _ in 0..n {
            let s = Instant::now();
            reject(&shape_b);
            tb.push(s.elapsed().as_nanos() as u64);
            let s = Instant::now();
            reject(&shape_d);
            td.push(s.elapsed().as_nanos() as u64);
            let s = Instant::now();
            reject(&shape_b);
            tb2.push(s.elapsed().as_nanos() as u64);
        }
        let med_b = timing_median_ns(tb);
        let med_d = timing_median_ns(td);
        let med_b2 = timing_median_ns(tb2);

        let cross_gap = (med_b as i64 - med_d as i64).unsigned_abs();
        let control_gap = (med_b as i64 - med_b2 as i64).unsigned_abs();
        eprintln!(
            "decide_inbound reject timing: med_b={med_b}ns med_d={med_d}ns med_b2={med_b2}ns \
             cross_gap={cross_gap}ns control_gap={control_gap}ns"
        );

        // Generous, self-normalized bound: the cross-shape gap must not exceed a
        // large multiple of the same-shape noise floor, with an absolute slack
        // floor so a near-zero control_gap cannot make this spuriously strict.
        let slack = (med_b.min(med_d) / 4)
            .max(control_gap.saturating_mul(6))
            .max(2_000);
        assert!(
            cross_gap <= slack,
            "rejection latency is grossly input-dependent: cross_gap={cross_gap}ns exceeds \
             slack={slack}ns (control_gap={control_gap}ns). A timing distinguisher between \
             reject shapes may have been introduced."
        );
    }

    /// L-7: a Verified PX1P ack with no retained connection must map to HardFail
    /// (reset), not silently stay on TCP, so the carrier choice cannot desync from
    /// the client (which has already committed its relay to QUIC).
    #[test]
    fn udp_retention_decision_verified_without_conn_is_hard_fail() {
        use crate::protocol::command::UdpProbeStatus;
        assert_eq!(
            udp_retention_decision(Some(UdpProbeStatus::Verified), true),
            UdpRetentionDecision::Retain
        );
        assert_eq!(
            udp_retention_decision(Some(UdpProbeStatus::Verified), false),
            UdpRetentionDecision::HardFail,
        );
        assert_eq!(
            udp_retention_decision(Some(UdpProbeStatus::Unreachable), false),
            UdpRetentionDecision::StayOnTcp
        );
        assert_eq!(
            udp_retention_decision(Some(UdpProbeStatus::Unreachable), true),
            UdpRetentionDecision::StayOnTcp
        );
        assert_eq!(
            udp_retention_decision(Some(UdpProbeStatus::Failed), true),
            UdpRetentionDecision::StayOnTcp
        );
        assert_eq!(
            udp_retention_decision(None, true),
            UdpRetentionDecision::StayOnTcp
        );
        assert_eq!(
            udp_retention_decision(None, false),
            UdpRetentionDecision::StayOnTcp
        );
    }

    #[tokio::test]
    async fn accept_probed_quic_pins_to_authenticated_peer_ip() {
        let server_ep = crate::transport::udp::endpoint::bind_server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            "localhost",
        )
        .await
        .expect("bind server endpoint");
        let server_addr = server_ep.local_addr().unwrap();

        // A loopback client connects (source IP 127.0.0.1). Establish it FIRST and
        // assert the QUIC handshake actually completes, so the rejection below is
        // proven to be the L-6 source-IP filter and not a failed/incomplete connect.
        let client_ep = crate::transport::udp::endpoint::bind_client_endpoint_accept_any(
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .expect("bind client endpoint");
        let _client_conn = client_ep
            .connect(server_addr, "localhost")
            .await
            .expect("loopback client completes the QUIC handshake (reaches the server)");

        // Expect a DIFFERENT source IP (TEST-NET-3) than the loopback connector, so
        // the now-established connection is declined (L-6 source-IP filter) and NO
        // connection is accepted within the budget.
        let offer_id = [7_u8; 16];
        let accepted = tokio::time::timeout(
            Duration::from_millis(300),
            accept_probed_quic_from_peer(
                &server_ep,
                Some("203.0.113.1".parse().unwrap()),
                PSK,
                &offer_id,
                0,
            ),
        )
        .await;
        assert!(
            matches!(accepted, Err(_) | Ok(None)),
            "a connector from a non-authenticated source IP must not be accepted",
        );
    }

    #[test]
    fn falls_back_on_unauthorized_sni() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = *derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let record = masked_authed_client_hello(
            &server.private,
            &client.public,
            &[0x44_u8; 32],
            "example.com",
            &auth_key,
            1_700_000_001,
        );

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("allowed.com")],
            &server.private,
        )
        .unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::UnauthorizedSni(String::from("example.com")))
        );
    }

    #[test]
    fn authorized_sni_matching_is_case_insensitive() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let auth_key = *derive_client_auth_key(PSK, &client.private, &server.public).unwrap();
        let record = masked_authed_client_hello(
            &server.private,
            &client.public,
            &[0x44_u8; 32],
            "Example.COM",
            &auth_key,
            1_700_000_001,
        );

        let decision = decide_inbound(
            &record,
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        match decision {
            InboundDecision::Authenticated(hello) => {
                assert_eq!(hello.sni, "Example.COM");
                assert_eq!(hello.x25519_key_share, client.public);
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn malformed_probe_falls_back_instead_of_closing() {
        let server = X25519KeyPair::generate();
        let decision = decide_inbound(
            b"not a TLS ClientHello",
            PSK,
            &[String::from("example.com")],
            &server.private,
        )
        .unwrap();

        assert_eq!(
            decision,
            InboundDecision::Fallback(FallbackReason::AuthFailed)
        );
    }

    #[test]
    fn resolve_connect_target_decodes_explicit_request() {
        let request = ConnectRequest {
            host: "2001:db8::1".to_owned(),
            port: 443,
            initial_payload: b"hello".to_vec(),
        };

        let mut encoded = request.encode().unwrap();
        let (target, initial_payload) = resolve_connect_target(&mut encoded, None).unwrap();

        assert_eq!(target, "[2001:db8::1]:443");
        assert_eq!(initial_payload, b"hello");
    }

    #[test]
    fn resolve_connect_target_honors_fixed_target_for_connect_request() {
        let request = ConnectRequest {
            host: "2001:db8::1".to_owned(),
            port: 443,
            initial_payload: b"hello".to_vec(),
        };

        let mut encoded = request.encode().unwrap();
        let (target, initial_payload) =
            resolve_connect_target(&mut encoded, Some("target.example:443")).unwrap();

        assert_eq!(target, "target.example:443");
        assert_eq!(initial_payload, b"hello");
    }

    #[test]
    fn resolve_connect_target_uses_fixed_target_for_raw_payload() {
        let mut raw = *b"GET / HTTP/1.1\r\n\r\n";
        let (target, initial_payload) =
            resolve_connect_target(&mut raw, Some("target.example:443")).unwrap();

        assert_eq!(target, "target.example:443");
        assert_eq!(initial_payload, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn resolve_connect_target_requires_fixed_target_for_raw_payload() {
        let mut raw = *b"raw";
        assert!(matches!(
            resolve_connect_target(&mut raw, None).unwrap_err(),
            HandshakeServerError::MissingConnectTarget
        ));
    }

    #[test]
    fn resolve_connect_target_rejects_malformed_connect_request() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"PX1C");
        encoded.extend_from_slice(&0_u16.to_be_bytes());

        assert!(matches!(
            resolve_connect_target(&mut encoded, Some("target.example:443")).unwrap_err(),
            HandshakeServerError::ConnectRequest(ConnectRequestError::EmptyHost)
        ));
    }

    #[test]
    fn client_selected_egress_policy_denies_private_addresses() {
        let denied = [
            "127.0.0.1:80",
            "0.1.2.3:80",
            "10.0.0.1:80",
            "172.16.0.1:80",
            "192.168.0.1:80",
            "192.0.2.1:80",
            "198.18.0.1:80",
            "198.51.100.1:80",
            "203.0.113.1:80",
            "240.0.0.1:80",
            "169.254.169.254:80",
            "100.64.0.1:80",
            "[::1]:80",
            "[fc00::1]:80",
            "[fd00::1]:80",
            "[fe80::1]:80",
            "[febf::1]:80",
            "[2001:db8::1]:80",
            "[2001::1]:80",
            "[2002:c000:0201::1]:80",
        ];

        for target in denied {
            let addr: SocketAddr = target.parse().unwrap();
            assert!(
                validate_public_target_addrs(&[addr]).is_err(),
                "{target} should be denied"
            );
        }
    }

    #[test]
    fn client_selected_egress_policy_allows_public_addresses() {
        let allowed = [
            "93.184.216.34:443",
            "[2606:2800:220:1:248:1893:25c8:1946]:443",
        ];

        for target in allowed {
            let addr: SocketAddr = target.parse().unwrap();
            validate_public_target_addrs(&[addr]).unwrap();
        }
    }

    #[test]
    fn client_selected_egress_policy_rejects_any_denied_dns_result() {
        let addrs = [
            "93.184.216.34:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];

        assert!(matches!(
            validate_public_target_addrs(&addrs).unwrap_err(),
            HandshakeServerError::OutboundTargetDenied
        ));
    }

    #[test]
    fn egress_policy_denies_embedded_and_nat64_ipv6() {
        // v4-mapped private (::ffff:10.0.0.1)
        let v4_mapped_private = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001));
        // v4-compatible private (::10.0.0.1) — only caught by to_ipv4(), not to_ipv4_mapped()
        let v4_compatible_private = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0a00, 0x0001));
        // NAT64 well-known prefix wrapping 8.8.8.8 (64:ff9b::808:808)
        let nat64 = IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808));
        for denied in [
            v4_mapped_private,
            v4_compatible_private,
            nat64,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert!(
                is_denied_outbound_ip(denied),
                "expected {denied} to be denied"
            );
        }

        // A global unicast IPv6 address must still be allowed.
        let public_v6 = IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946,
        ));
        assert!(!is_denied_outbound_ip(public_v6));
    }

    #[tokio::test]
    async fn mux_open_beyond_stream_cap_is_reset_without_outbound() {
        let traffic = TrafficConfig::default();
        // max_streams = 0 exercises the cap branch on the very first Open, so no
        // live outbound target is needed to prove the refusal path.
        let context = ServerMuxContext {
            fixed_data_target: None,
            timing: TimingProfile::from_config(traffic),
            cover: CoverTrafficProfile::from_config(traffic),
            chunk_size: max_plaintext_len(traffic.max_padding),
            max_streams: 0,
            cid: 1,
            target_write_timeout: MUX_TARGET_WRITE_TIMEOUT,
        };
        let (frame_tx, mut frame_rx) = mpsc::channel(SERVER_MUX_FRAME_CHANNEL);
        let payload_pool =
            MuxPayloadPool::with_capacity(MuxFrame::max_payload_len(context.chunk_size));
        let mut streams = ServerMuxStreams::new();

        process_server_mux_frame(
            MuxFrameRef {
                stream_id: 7,
                kind: MuxFrameKind::Open,
                payload: &[],
            },
            &mut streams,
            &frame_tx,
            context,
            &payload_pool,
        )
        .await
        .unwrap();

        // No outbound connection was established for the over-cap stream.
        assert!(streams.writes.is_empty());
        assert!(streams.readers.is_empty());
        // The client receives a Reset for that stream id.
        let reset = frame_rx.try_recv().unwrap();
        assert_eq!(reset.stream_id, 7);
        assert_eq!(reset.kind, MuxFrameKind::Reset);
    }

    /// H-3: a wedged target (peer never reads) must not park the serial mux reader
    /// loop on a single stream's write — only that stream is shed (Reset + close),
    /// keeping the connection and every healthy substream alive. Uses an injected
    /// short write deadline + an oversized payload that reliably blocks once the
    /// socket buffers fill, so the test runs in real time.
    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn mux_wedged_target_data_write_sheds_only_that_stream() {
        let traffic = TrafficConfig::default();
        let context = ServerMuxContext {
            fixed_data_target: None,
            timing: TimingProfile::from_config(traffic),
            cover: CoverTrafficProfile::from_config(traffic),
            chunk_size: max_plaintext_len(traffic.max_padding),
            max_streams: 8,
            cid: 1,
            target_write_timeout: Duration::from_millis(100),
        };
        let (frame_tx, mut frame_rx) = mpsc::channel(SERVER_MUX_FRAME_CHANNEL);
        let payload_pool =
            MuxPayloadPool::with_capacity(MuxFrame::max_payload_len(context.chunk_size));

        // A target that accepts but never reads: writes to it wedge once buffers fill.
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let acceptor = tokio::spawn(async move {
            let (s, _) = target_listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        });
        let target = TcpStream::connect(target_addr).await.unwrap();
        let (_target_read, target_write) = target.into_split();

        let mut streams = ServerMuxStreams::new();
        streams.writes.insert(9, target_write);
        // A live reader handle so the shed path's abort+remove is exercised.
        streams
            .readers
            .insert(9, tokio::spawn(std::future::pending::<()>()));

        // Oversized payload guarantees write_all blocks (exceeds any socket buffer).
        let big = vec![0_u8; 4 * 1024 * 1024];
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            process_server_mux_frame(
                MuxFrameRef {
                    stream_id: 9,
                    kind: MuxFrameKind::Data,
                    payload: &big,
                },
                &mut streams,
                &frame_tx,
                context,
                &payload_pool,
            ),
        )
        .await
        .expect("process_server_mux_frame must return within the wall budget");
        result.expect("shedding a wedged stream must not error the connection");

        // Only stream 9 is shed; the connection (and any other stream) survives.
        assert!(
            !streams.writes.contains_key(&9),
            "wedged stream's write half removed"
        );
        assert!(
            !streams.readers.contains_key(&9),
            "wedged stream's reader aborted"
        );
        let reset = frame_rx.try_recv().unwrap();
        assert_eq!(reset.stream_id, 9);
        assert_eq!(reset.kind, MuxFrameKind::Reset);

        acceptor.abort();
    }

    /// M-8: the speed-test DOWNLOAD phase must reclaim a zero-window stall as a
    /// Timeout (the upload phase already did). A client that connects and never
    /// reads drives the server's receive window to zero; once the send buffer
    /// fills, the write would block forever without the per-write idle backstop.
    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn speed_download_phase_idle_timeout_reclaims_zero_window_stall() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Client connects and NEVER reads.
        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(stream);
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let (read_half, write_half) = server_stream.into_split();
        let mut client_records = TlsRecordReader::buffered(read_half);
        let mut client_write = TcpLegWriter(write_half);
        let chunk = max_plaintext_len(0);
        let mut server_seal = DataRecordCodec::new(
            AeadCodec::new([0x11; 32], [0x22; 12]),
            PaddingProfile::new(0, 0).unwrap(),
            SERVER_TO_CLIENT_AAD,
        );
        let mut client_open = DataRecordCodec::new(
            AeadCodec::new([0x33; 32], [0x44; 12]),
            PaddingProfile::new(0, 0).unwrap(),
            CLIENT_TO_SERVER_AAD,
        );
        let mut rng = StdRng::seed_from_u64(7);
        let mut scratch = RelaySealScratch::with_payload_capacity(chunk);
        let mut io = SpeedServerIo {
            client_records: &mut client_records,
            client_write: &mut client_write,
            client_open: &mut client_open,
            server_seal: &mut server_seal,
            rng: &mut rng,
            scratch: &mut scratch,
            cid: 1,
        };
        let payload = vec![0_u8; chunk];

        // Inject a short idle; a zero-window stall must surface as Timeout, not hang.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            write_speed_download_phase(
                &mut io,
                &payload,
                64 * 1024 * 1024, // far exceeds the socket buffers
                SpeedTestAck::download_done(64 * 1024 * 1024),
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("download phase must return within the wall budget (idle backstop fired)");
        assert!(
            matches!(result, Err(HandshakeServerError::Timeout)),
            "a zero-window stall must surface as Timeout, got {result:?}",
        );

        client.abort();
    }

    #[tokio::test]
    async fn fallback_relay_forwards_client_records_after_origin_flight() {
        let first_client_record = client_hello_fixture_with_key_share("example.com", &[0x22; 32]);
        let second_client_record = crate::tls::record::wrap_application_data(b"client-finished")
            .expect("test client record fits");
        let first_origin_record = crate::tls::record::wrap_application_data(b"server-flight")
            .expect("test origin record fits");
        let second_origin_record = crate::tls::record::wrap_application_data(b"origin-reply")
            .expect("test origin reply fits");

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let expected_first = first_client_record.clone();
        let expected_second = second_client_record.clone();
        let origin_first = first_origin_record.clone();
        let origin_second = second_origin_record.clone();
        let origin_task = tokio::spawn(async move {
            let (mut origin, _) = origin_listener.accept().await.unwrap();
            let relayed_first = read_record(&mut origin).await.unwrap();
            assert_eq!(relayed_first, expected_first);
            origin.write_all(&origin_first).await.unwrap();

            let relayed_second = read_record(&mut origin).await.unwrap();
            assert_eq!(relayed_second, expected_second);
            origin.write_all(&origin_second).await.unwrap();
        });

        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (server_side, _) = parallax_listener.accept().await.unwrap();
            relay_fallback(server_side, &origin_addr.to_string(), first_client_record)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let relayed_origin_first = read_record(&mut client).await.unwrap();
        assert_eq!(relayed_origin_first, first_origin_record);
        client.write_all(&second_client_record).await.unwrap();
        let relayed_origin_second = read_record(&mut client).await.unwrap();
        assert_eq!(relayed_origin_second, second_origin_record);
        drop(client);

        origin_task.await.unwrap();
        relay_task.await.unwrap();
    }

    /// H-1: a cap-rejected connection must still receive the origin ServerHello
    /// (relayed), NOT a bare ServerHello-less FIN, so an active prober cannot count
    /// the server's connection cap. Ignored + serial: it uses real sockets and
    /// mutates the process-global cap-shed budget.
    #[tokio::test]
    #[ignore = "requires loopback TCP sockets + mutates the process-global cap-shed budget"]
    async fn cap_shed_fallback_relays_serverhello_not_bare_fin() {
        let client_hello = client_hello_fixture_with_key_share("example.com", &[0x22; 32]);
        let server_hello = crate::tls::record::wrap_application_data(b"origin-server-hello")
            .expect("test ServerHello fits");

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let expected_client_hello = client_hello.clone();
        let origin_hello = server_hello.clone();
        let origin_task = tokio::spawn(async move {
            let (mut origin, _) = origin_listener.accept().await.unwrap();
            let relayed = read_record(&mut origin).await.unwrap();
            assert_eq!(relayed, expected_client_hello);
            origin.write_all(&origin_hello).await.unwrap();
        });

        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let origin_addr_str = origin_addr.to_string();
        let relay_task = tokio::spawn(async move {
            let (server_side, _) = parallax_listener.accept().await.unwrap();
            cap_shed_fallback_or_fin(server_side, origin_addr_str).await;
        });

        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        client.write_all(&client_hello).await.unwrap();
        let received = read_record(&mut client).await.unwrap();
        assert_eq!(
            received, server_hello,
            "cap-shed must relay the origin ServerHello, not emit a bare FIN",
        );
        drop(client);
        origin_task.await.unwrap();
        relay_task.await.unwrap();
    }

    /// H-1: when the cap-shed budget is full, a cap-rejected connection degrades to
    /// a graceful FIN (EOF), never a hang or RST. Ignored + serial: it saturates
    /// the process-global budget.
    #[tokio::test]
    #[ignore = "requires loopback TCP sockets + mutates the process-global cap-shed budget"]
    async fn cap_shed_fallback_budget_exhausted_falls_back_to_fin() {
        // Saturate the cap-shed budget and hold the guards for the whole test.
        let held: Vec<CapShedFallbackSlot> = (0..MAX_CONCURRENT_CAP_SHED_FALLBACKS)
            .map(|_| try_enter_cap_shed_fallback().expect("within budget"))
            .collect();
        assert!(
            try_enter_cap_shed_fallback().is_none(),
            "budget exhausted must yield no further slot",
        );

        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (server_side, _) = parallax_listener.accept().await.unwrap();
            // The address is never dialed: the budget is full, so it FINs directly.
            cap_shed_fallback_or_fin(server_side, "127.0.0.1:9".to_string()).await;
        });

        // Client connects and reads without writing: it must see a prompt graceful
        // FIN (EOF), proving the budget-full path closes instead of relaying. (We
        // deliberately do not write here — a client write that races the close is a
        // harness artifact, not the production cap path where the ClientHello is
        // already queued and drained before the FIN.)
        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let mut one = [0_u8; 1];
        let n = timeout(Duration::from_secs(2), client.read(&mut one))
            .await
            .expect("budget-full cap-shed must close promptly, not hang")
            .unwrap();
        assert_eq!(
            n, 0,
            "budget-full cap-shed must be a graceful FIN (EOF), not a relay",
        );
        relay_task.await.unwrap();

        // Restore the process-global budget for any other ignored/serial tests.
        drop(held);
    }

    /// H-1: pins the tight cap-shed idle bound so a future edit cannot silently
    /// raise it to the 600s legit backstop and re-open the cap-as-DoS-amplifier.
    #[test]
    fn cap_shed_fallback_idle_is_tight() {
        assert_eq!(CAP_SHED_FALLBACK_IDLE, Duration::from_secs(10));
        assert!(
            CAP_SHED_FALLBACK_IDLE < FALLBACK_IDLE_TIMEOUT_FLOOR,
            "cap-shed relays must use a tight idle bound, not the 600s legit backstop",
        );
    }

    #[tokio::test]
    async fn fallback_relay_idle_timeout_closes_empty_probe() {
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut origin, _) = origin_listener.accept().await.unwrap();
            let mut one = [0_u8; 1];
            origin.read(&mut one).await.unwrap()
        });

        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (server_side, _) = parallax_listener.accept().await.unwrap();
            let fallback = TcpStream::connect(origin_addr).await.unwrap();
            relay_fallback_with_idle_timeout(server_side, fallback, Duration::from_millis(30))
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let mut one = [0_u8; 1];
        let client_read = timeout(Duration::from_millis(500), client.read(&mut one))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(client_read, 0);
        assert_eq!(origin_task.await.unwrap(), 0);
        relay_task.await.unwrap();
    }

    #[test]
    fn first_record_wait_and_idle_backstop_both_jitter_within_band() {
        // Helper-level test (does not assert the production call-site wiring; the
        // wiring is exercised by the relay/handshake integration tests).
        let mut first_record_values = std::collections::HashSet::new();
        let mut idle_values = std::collections::HashSet::new();
        for _ in 0..128 {
            let wait = first_record_wait_timeout();
            assert!(
                wait >= FIRST_RECORD_WAIT_FLOOR,
                "first-record wait must never drop below the floor"
            );
            assert!(
                wait <= FIRST_RECORD_WAIT_FLOOR + FIRST_RECORD_WAIT_JITTER,
                "first-record wait must stay within floor + jitter"
            );
            first_record_values.insert(wait.as_millis());

            // The idle backstop is now jittered (M-3) so the all-silent close is not
            // a fixed, round ~600s ParallaX signature: it stays within the band.
            let idle = fallback_idle_timeout();
            assert!(
                idle >= FALLBACK_IDLE_TIMEOUT_FLOOR,
                "idle backstop must never drop below the floor"
            );
            assert!(
                idle <= FALLBACK_IDLE_TIMEOUT_FLOOR + FALLBACK_IDLE_TIMEOUT_JITTER,
                "idle backstop must stay within floor + jitter"
            );
            idle_values.insert(idle.as_millis());
        }
        // Both give-ups must be randomized so a prober cannot read a fixed constant.
        assert!(
            first_record_values.len() > 1,
            "first-record wait must be randomized, not a fixed constant"
        );
        assert!(
            idle_values.len() > 1,
            "idle backstop must be randomized, not a fixed 600s tell"
        );
    }

    #[test]
    fn origin_facing_timeout_stays_fixed_and_first_record_floor_matches_legacy() {
        // Origin-facing operations must keep the fixed timeout (jittering them
        // would only add latency to legit clients), and the client-facing floor
        // must equal the pre-jitter fixed value so no client gets less time.
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(8));
        // Anchor the client-facing floor to the pre-jitter legacy value (8s)
        // directly, NOT to HANDSHAKE_TIMEOUT: the two are now deliberately
        // independent (origin-facing vs client-facing), so coupling them would
        // make an origin-side change spuriously break this client-side test.
        assert_eq!(FIRST_RECORD_WAIT_FLOOR, Duration::from_secs(8));
        assert!(FIRST_RECORD_WAIT_JITTER > Duration::from_secs(0));
        assert_eq!(FALLBACK_IDLE_TIMEOUT_JITTER, Duration::from_secs(60));
        // The constants are the defaults when no config override is installed,
        // and must match the config default_*_ms values (config.rs): 8000 / 7000
        // / 600000 / 60000. Pin the idle floor here so the two cannot drift apart.
        assert_eq!(FALLBACK_IDLE_TIMEOUT_FLOOR, Duration::from_secs(600));
        let defaults = TimeoutTuning::defaults();
        assert_eq!(defaults.first_record_floor, FIRST_RECORD_WAIT_FLOOR);
        assert_eq!(defaults.first_record_jitter, FIRST_RECORD_WAIT_JITTER);
        assert_eq!(defaults.fallback_idle_floor, FALLBACK_IDLE_TIMEOUT_FLOOR);
        assert_eq!(defaults.fallback_idle_jitter, FALLBACK_IDLE_TIMEOUT_JITTER);
    }

    #[tokio::test]
    async fn fallback_relay_connect_failure_closes_client_with_fin() {
        // Reserve a port and immediately release it so the camouflage-origin
        // dial is refused deterministically.
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (server_side, _) = parallax_listener.accept().await.unwrap();
            relay_fallback(
                server_side,
                &dead_addr.to_string(),
                b"probe-prefix".to_vec(),
            )
            .await
        });

        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let mut buf = [0_u8; 16];
        // The client must observe a prompt, graceful close (EOF / FIN). A reset
        // would surface here as an Err, failing the inner expect.
        let n = timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("client should observe a prompt close, not hang")
            .expect("fallback connect failure must close the client with a FIN, not a RST");
        assert_eq!(
            n, 0,
            "client must see EOF (FIN) after an origin dial failure"
        );

        let relay_result = relay_task.await.unwrap();
        assert!(
            relay_result.is_err(),
            "relay_fallback must surface the origin dial failure"
        );
    }

    #[tokio::test]
    async fn strict_tls13_rejection_relays_origin_server_hello_first() {
        let tls12_server_hello = server_hello_fixture_with_tls12_selected();
        let fallback_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback_listener.local_addr().unwrap();
        let expected_first_client_record =
            client_hello_fixture_with_key_share("example.com", &[0x22; 32]);
        let origin_record = tls12_server_hello.clone();
        let fallback_task = tokio::spawn(async move {
            let (mut origin, _) = fallback_listener.accept().await.unwrap();
            let relayed_first = read_record(&mut origin).await.unwrap();
            assert_eq!(relayed_first, expected_first_client_record);
            origin.write_all(&origin_record).await.unwrap();
        });

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = identity::keypair();
        let replay_cache_dir = tempfile::tempdir().unwrap();
        let config = authenticated_server_config(
            fallback_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_dir.path().join("parallax-replay.cache"),
        );
        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let first_client_record = client_hello_fixture_with_key_share("example.com", &[0x22; 32]);
        let accepted = tokio::spawn(async move {
            let (server_side, _) = parallax_listener.accept().await.unwrap();
            accept_authenticated(
                server_side,
                &config,
                &[0x5a_u8; 32],
                server_keys.public,
                zeroize::Zeroizing::new([0_u8; 32]),
                first_client_record,
                AuthenticatedHello {
                    sni: String::from("example.com"),
                    x25519_key_share: [0x22; 32],
                    timestamp: 1_700_000_001,
                    nonce: [7; 8],
                    transcript_fingerprint: [8; 32],
                },
            )
            .await
        });

        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let relayed = read_record(&mut client).await.unwrap();
        assert_eq!(relayed, tls12_server_hello);

        let err = accepted.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeServerError::Tls13Required));
        fallback_task.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn authenticated_connection_switches_to_data_mode() {
        let (fallback_addr, fallback_task) = spawn_server_hello_fallback().await;
        let (target_addr, target_task) = spawn_ping_pong_target().await;

        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = identity::keypair();
        let client_keys = X25519KeyPair::generate();
        let _replay_cache_dir = tempfile::tempdir().unwrap();
        let replay_cache_path = _replay_cache_dir.path().join("parallax-replay.cache");
        let traffic = TrafficConfig::default();
        let mut config = authenticated_server_config(
            fallback_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_path,
        );
        config.data_target = Some(target_addr.to_string());
        let (parallax_addr, server_task) = spawn_authenticated_server(config, traffic).await;
        let (mut client, mut data_session, mut rng) = open_authenticated_data_session(
            parallax_addr,
            &server_keys,
            &server_identity_keys.public,
            &client_keys,
            traffic,
        )
        .await;

        send_ping_connect(&mut client, &mut data_session, &mut rng, target_addr).await;

        drop(client);
        server_task.await.unwrap();
        target_task.await.unwrap();
        fallback_task.await.unwrap();
    }

    async fn spawn_server_hello_fallback() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _client_hello = read_record(&mut stream).await.unwrap();
            stream.write_all(&server_hello_fixture()).await.unwrap();

            let mut one = [0_u8; 1];
            let _ = timeout(Duration::from_millis(500), stream.read(&mut one)).await;
        });
        (addr, task)
    }

    async fn spawn_ping_pong_target() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut initial = [0_u8; 4];
            stream.read_exact(&mut initial).await.unwrap();
            assert_eq!(&initial, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        (addr, task)
    }

    fn authenticated_server_config(
        fallback_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_identity_keys: &identity::MlDsaKeyPair,
        replay_cache_path: std::path::PathBuf,
    ) -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            fallback_addr: fallback_addr.to_string(),
            data_target: None,
            private_key: STANDARD.encode(server_keys.private).into(),
            identity_secret_key: STANDARD.encode(&server_identity_keys.secret).into(),
            replay_cache_path,
            replay_cache_capacity: crate::config::DEFAULT_REPLAY_CACHE_CAPACITY,
            authorized_sni: vec![String::from("example.com")],
            strict_tls13: true,
            max_concurrent_per_source_v4: 256,
            max_concurrent_per_source_v6: 256,
            source_ipv6_prefix_len: 64,
            first_record_wait_floor_ms: 8_000,
            first_record_wait_jitter_ms: 7_000,
            fallback_idle_floor_ms: 600_000,
            fallback_idle_jitter_ms: 0,
            tcp_congestion: None,
        }
    }

    async fn spawn_authenticated_server(
        config: ServerConfig,
        traffic: TrafficConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, &config, traffic, &UdpConfig::default(), PSK)
                .await
                .unwrap();
        });
        (addr, task)
    }

    async fn open_authenticated_data_session(
        parallax_addr: SocketAddr,
        server_keys: &X25519KeyPair,
        server_identity_public_key: &[u8],
        client_keys: &X25519KeyPair,
        traffic: TrafficConfig,
    ) -> (TcpStream, ClientDataSession, StdRng) {
        let mut client = TcpStream::connect(parallax_addr).await.unwrap();
        let auth_key =
            *derive_client_auth_key(PSK, &client_keys.private, &server_keys.public).unwrap();
        let client_hello = masked_authed_client_hello(
            &server_keys.private,
            &client_keys.public,
            &[0x44_u8; 32],
            "example.com",
            &auth_key,
            1_700_000_001,
        );
        let mut rng = StdRng::seed_from_u64(20);
        client.write_all(&client_hello).await.unwrap();

        let server_hello_record = read_record(&mut client).await.unwrap();
        let _server_hello = parse_server_hello(&server_hello_record).unwrap();
        let session_keys = crate::handshake::client::derive_session_keys(
            PSK,
            &client_keys.private,
            &server_keys.public,
            &client_hello,
            &server_hello_record,
        )
        .unwrap();
        let mut data_session = ClientDataSession::new(session_keys, traffic).unwrap();
        let (pq_record, pending_rekey) = data_session.build_pq_rekey_record(&mut rng).unwrap();
        client.write_all(&pq_record).await.unwrap();
        // Drive the real client receive path: skips residual camouflage and
        // reassembles the server's chunked PX1K (PAR-21), against the real server.
        crate::client::runtime::apply_server_key_exchange_after_residuals(
            &mut client,
            &mut data_session,
            &pending_rekey,
            PSK,
        )
        .await
        .unwrap();
        let mut identity_payload = Vec::new();
        loop {
            let identity_record = read_record(&mut client).await.unwrap();
            let chunk = data_session
                .open_server_identity_chunk(&identity_record)
                .unwrap();
            assert_eq!(chunk.offset as usize, identity_payload.len());
            identity_payload.extend_from_slice(&chunk.bytes);
            if identity_payload.len() == chunk.total_len as usize {
                break;
            }
        }
        data_session
            .verify_server_identity_payload(
                &identity_payload,
                server_identity_public_key,
                &server_keys.public,
            )
            .unwrap();

        (client, data_session, rng)
    }

    fn replace_tls13_supported_version_with_tls12(record: &mut [u8]) {
        let needle = [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        let offset = record
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("ClientHello fixture carries supported_versions TLS 1.3");
        record[offset + needle.len() - 1] = 0x03;
        assert!(!parse_client_hello(record).unwrap().tls13_supported);
    }

    fn server_hello_fixture_with_tls12_selected() -> Vec<u8> {
        let mut record = server_hello_fixture();
        let needle = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        let offset = record
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("ServerHello fixture carries supported_versions TLS 1.3");
        record[offset + needle.len() - 1] = 0x03;
        assert!(!parse_server_hello(&record).unwrap().tls13_selected);
        record
    }

    async fn send_ping_connect(
        client: &mut TcpStream,
        data_session: &mut ClientDataSession,
        rng: &mut StdRng,
        target_addr: SocketAddr,
    ) {
        let connect = ConnectRequest {
            host: target_addr.ip().to_string(),
            port: target_addr.port(),
            initial_payload: b"ping".to_vec(),
        };
        let connect_record = data_session.build_connect_record(connect, rng).unwrap();
        client.write_all(&connect_record).await.unwrap();

        let response_record = read_record(client).await.unwrap();
        let response = data_session.open_server_record(&response_record).unwrap();
        assert_eq!(response, b"pong");
    }
}
