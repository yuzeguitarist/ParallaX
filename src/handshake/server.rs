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
use zeroize::{Zeroize, Zeroizing};

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
        },
        data::{
            max_plaintext_len, relay_read_buffer_len, should_parallelize_aead, DataRecordCodec,
            DataRecordError, SealedRecord, CLIENT_TO_SERVER_AAD, QUIC_RELAY_DONE_MARKER,
            RELAY_IDLE_CLOSE_CODE, SERVER_TO_CLIENT_AAD, SPEED_QUIC_DONE_MARKER,
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
            write_batch_with_read_ahead, H3DataFrameLegReader, H3DataFrameLegWriter, LegReader,
            LegWriter, TcpLegReader, TcpLegWriter,
        },
        tcp::{
            connect_tuned_tcp_any, connect_tuned_tcp_host, drain_ready_tcp_read,
            is_fd_exhaustion_error, is_transient_accept_error, relay_connection_limit,
            tune_tcp_stream,
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
/// could use to count our cap. Cap-shed relays draw from this small SEPARATE budget
/// (the main slots are already exhausted). This hard concurrency ceiling — NOT a
/// tightened idle bound — is the real anti-amplification backstop: it bounds the
/// number of concurrent cap-shed origin connections at 64 regardless of flood
/// volume, so even though each relay now uses the SAME idle distribution as a
/// healthy splice ([`fallback_idle_timeout`], [600s, 660s]) the worst case is 64
/// idle origin connections — negligible for any real origin, bounded, no growth.
/// Unifying the idle band (vs. the prior tight [10s, 90s] band, which was disjoint
/// from the healthy [600s, 660s] band and thus a probe-separable "box at cap" state
/// tell) is what keeps a cap-shed close's IDLE TIME indistinguishable from a healthy
/// one (a pre-existing handshake-start dial-RTT difference is separate and unchanged).
/// 64 userspace relays ~= 128 fds: a fixed reservation that cannot itself exhaust fds.
/// Past the budget we degrade to a graceful FIN — a casual prober always lands
/// inside it; only a genuine flood sees FINs, which a real origin under flood also
/// produces.
const MAX_CONCURRENT_CAP_SHED_FALLBACKS: usize = 64;

/// Replayed-ClientHello close is detected only AFTER the full PQ exchange, so a
/// replay's teardown lands at a near-fixed moment in the handshake (no server PQ
/// response, then FIN) that a holder of the deployment PSK who recorded a genuine
/// client could time to confirm it was flagged as a replay (M-5). This residual is
/// invisible to a keyless censor (a non-PSK peer never reaches this arm; it splices
/// at the first record), so the bar is already very high — but to blur the one
/// measurable signal that remains, hold the connection for a WIDE jittered delay
/// before the graceful FIN, drawn from `[0, jitter]` so there is no fixed lower edge
/// that itself becomes a new constant. The connection is otherwise inert during the
/// wait (nothing is forwarded to the origin, unlike a relay), so there is no
/// origin-side DoS-amplification cost — it is a local socket held a little longer,
/// and replays are rare by construction.
const REPLAY_CLOSE_DELAY_FLOOR: Duration = Duration::from_secs(0);
const REPLAY_CLOSE_DELAY_JITTER: Duration = Duration::from_secs(60);

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
const SERVER_IDENTITY_CHUNK_MIN_DELAY: Duration = Duration::from_millis(45);
// The client's residual-skip byte budget, mirrored here only for the
// operator-facing warning logged when the forward cap is reached. Bound to the
// shared constant so it can never drift from the client's actual budget again
// (the 16-vs-64 record and 64-records-vs-~1MiB unit high-RTT handshake-failure
// bugs).
const CLIENT_RESIDUAL_CAMOUFLAGE_BYTE_BUDGET: usize = super::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_BYTES;
/// Cap on the CLIENT's camouflage records read before its ParallaX PQ rekey
/// arrives (the client->fallback direction; the fallback->client direction is
/// byte-capped, see [`PRE_PQ_FALLBACK_FORWARD_BYTE_LIMIT`]). A legitimate client
/// emits only a handful of camouflage records before its PQ record, so 64 is far
/// above any real client flight while still bounding an abusive unbounded
/// client->fallback stream. Bound to the shared
/// [`super::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS`].
const PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT: usize = super::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS;
/// Byte ceiling on the origin->client camouflage forward in the authenticated
/// pre-PQ phase (D5). That direction now forwards the origin's bytes VERBATIM —
/// preserving its native TCP segmentation — instead of re-framing each TLS record
/// into its own write (a "one record, one segment" shape that no direct-to-origin
/// connection and no `relay_fallback` byte pump produces, making the authenticated
/// splice separable from both). Because the forward is byte-oriented now, the
/// cap is byte-oriented too: ~1 MiB (64 full-size records) comfortably covers a
/// *full* fragmented TLS 1.3 server handshake flight (ServerHello,
/// EncryptedExtensions, a possibly large, heavily fragmented Certificate chain,
/// CertificateVerify, Finished); the client only sends its PQ record once
/// that flight completes its Safari TLS camouflage, so a ceiling smaller than
/// the origin's flight deadlocks the session (the server stops forwarding, the
/// client keeps waiting). The CLIENT enforces the SAME byte budget on the
/// reassembled record stream (both are bound to
/// [`super::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_BYTES`] — see its doc for why the
/// two ends must share a unit), and the forward's final read is capped at the
/// remaining budget so this end can never overshoot what the client tolerates.
const PRE_PQ_FALLBACK_FORWARD_BYTE_LIMIT: usize = super::MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_BYTES;
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
/// Phase-level cap on the TOTAL zero-length records the upload phase tolerates,
/// counted cumulatively and never reset. The consecutive cap above is reset by
/// any progress-bearing record, so a client alternating a burst of empty records
/// with a single 1-byte data record keeps both that cap AND the per-read idle
/// timeout from ever firing, pinning the connection slot for ~`bytes` 1-byte
/// iterations. This cumulative cap bounds that input regardless of interleaving.
/// A legitimate upload carries its bytes in full ~16 KiB records and emits
/// essentially no empty records, so this is orders of magnitude above any honest
/// value while keeping the abusive case strictly bounded.
const MAX_TOTAL_EMPTY_UPLOAD_RECORDS: u64 = 256 * 1024;
/// Minimum sustained upload throughput (bytes/sec) the speed-test upload phase
/// requires once past the startup grace below. This is the backstop that actually
/// bounds the connection-slot hold: the empty-record caps above only bound
/// padding-only amplification, and the per-read idle timeout resets on EVERY
/// record, so a client dribbling a single small data record every ~599 s keeps
/// every other backstop from firing while pinning a slot/permit/fds for
/// `bytes / (tiny rate)` ~= unbounded wall-clock time. Enforcing a floor on the
/// average rate collapses that to a bounded `bytes / MIN_RATE` worst case.
///
/// Sized far below any honest client: a real speed test saturates the link (even
/// a badly congested mobile uplink moves tens of KiB/s+, and the CLI's own phases
/// are 1-4 MiB finishing in seconds at multi-MiB/s). 4 KiB/s (~32 kbit/s) is
/// slower than any useful measurement, so the floor only ever trips deliberate
/// trickle abuse — zero false-reject for legitimate uploads.
const MIN_UPLOAD_BYTES_PER_SEC: u64 = 4 * 1024;
/// Startup grace before the throughput floor is enforced: absorbs connection
/// ramp-up (TCP slow-start, RTT warmup, the first small records) so a slow START
/// is never mistaken for a trickle. The floor is checked only after this elapses.
const UPLOAD_RATE_GRACE: Duration = Duration::from_secs(15);

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

/// Fixed synthetic PSK used only to build the reject-path ballast context below.
/// It never touches a real connection: it masks/authenticates a throwaway
/// ClientHello whose verification work the reject arms replay. Using a constant
/// (not the live PSK) keeps the context a pure `OnceLock` and keeps the real PSK
/// out of the ballast code path entirely.
const REJECT_BALLAST_PSK: &[u8] = b"parallax reject-path ballast psk (not a real secret)";

/// Pre-built, read-only inputs that let the reject path replay the EXACT recover +
/// derive + verify crypto the `recover==Some` auth-fail arm runs — by calling the
/// SAME real functions on a fixed, legitimately-masked synthetic ClientHello,
/// rather than hand-mirroring each step. Built once per process.
struct RejectBallastCtx {
    record: Vec<u8>,
    parsed: crate::tls::client_hello::ClientHello,
    /// X25519(ballast_server_static, record_tls_key_share) — the mask-slot shared
    /// secret `recover` needs, precomputed so the ballast performs NO X25519 (the
    /// reject arms' DH op-count parity is owned by the `dh()` ballast calls).
    mask_ecdh: [u8; 32],
    /// X25519(ballast_server_static, recovered_parallax_public) — the auth-slot
    /// shared secret the HKDF auth-key derivation consumes, likewise precomputed.
    auth_shared: [u8; 32],
}

/// Build the ballast context, or `None` if the synthetic ClientHello could not be
/// produced/parsed (treated as "ballast unavailable" — the reject path then simply
/// performs no replay; it never changes the decision, only the timing).
fn build_reject_ballast_ctx() -> Option<RejectBallastCtx> {
    let server = X25519KeyPair::generate();
    let session = crate::tls::safari26::Safari26TlsCamouflage
        .start(
            "ballast.example".to_owned(),
            REJECT_BALLAST_PSK,
            &server.public,
        )
        .ok()?;
    let record = session.client_hello_bytes().to_vec();
    let parsed = parse_client_hello(&record).ok()?;
    let tls_key_share = parsed.x25519_key_share?;
    let mask_ecdh = x25519_shared_secret(&server.private, &tls_key_share);
    // Recover the embedded ParallaX ephemeral so we can precompute the auth-slot
    // shared secret the real verify path's HKDF would consume.
    let material = recover_stateful_auth_material_from_parsed(
        &record,
        REJECT_BALLAST_PSK,
        &mask_ecdh,
        &parsed,
    )
    .ok()??;
    let auth_shared = x25519_shared_secret(&server.private, &material.x25519_public);
    Some(RejectBallastCtx {
        record,
        parsed,
        mask_ecdh,
        auth_shared,
    })
}

/// Replay the `recover==Some` auth-fail crypto budget (recover + auth-key HKDF +
/// verify HMAC/compare/ClientAuth-build) so the no-key_share and recover==None
/// reject shapes are wall-clock indistinguishable from the auth-fail shape.
///
/// It calls the SAME real functions the auth-fail arm calls, on a fixed
/// synthetic ClientHello, so there is nothing to keep in sync and no
/// data-dependent branch — and it performs NO X25519 (DH op-count parity is
/// already owned by the reject arms' `dh()` ballast). Verifying the dudect gate
/// in `mod tests` proves the residual cross-shape timing is at the noise floor.
///
/// If the context failed to build (see `build_reject_ballast_ctx`), this is a
/// no-op: the security decision is unchanged, only the timing-equalisation is
/// skipped on that (degenerate, never-in-practice) platform.
fn reject_path_constant_work() {
    static CTX: OnceLock<Option<RejectBallastCtx>> = OnceLock::new();
    let Some(ctx) = CTX.get_or_init(build_reject_ballast_ctx) else {
        return;
    };
    let Ok(Some(material)) = recover_stateful_auth_material_from_parsed(
        &ctx.record,
        REJECT_BALLAST_PSK,
        &ctx.mask_ecdh,
        &ctx.parsed,
    ) else {
        return;
    };
    let Ok(auth_key) = derive_server_auth_key_from_shared(REJECT_BALLAST_PSK, &ctx.auth_shared)
    else {
        return;
    };
    let auth = verify_masked_stateful_client_hello_auth_with_parsed_material(
        &ctx.record,
        auth_key.as_slice(),
        &material,
        &ctx.parsed,
    );
    std::hint::black_box(&auth);
}

/// Test-only counter of how many times `server_download_loop` took the saturated
/// read-ahead (pipeline) branch, so a regression test can prove a short/non-bulk
/// flow stays on the serial branch (counter unchanged) while a saturating bulk
/// flow engages the pipeline (counter advances). Not compiled in release.
#[cfg(test)]
static DOWNLOAD_READ_AHEAD_ENGAGED: AtomicU64 = AtomicU64::new(0);

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

/// Drop guard that unregisters a pending UDP `offer_id` from the stable carrier on
/// EVERY scope exit after [`crate::transport::udp::stable::QuicCarrier::register`]
/// (item #3a). Before this, only the probe-timeout arm unregistered, so an early
/// `?` on the offer seal / offer-record write returned first and leaked the
/// oneshot sender in the carrier registry (an unbounded per-failed-negotiation
/// leak). The guard unregisters unconditionally; after a successful handoff the
/// carrier's accept loop has already `remove`d the entry, so this is then a
/// harmless no-op. `unregister` is a synchronous lock+remove, so a `Drop` guard is
/// sufficient (no async-drop needed).
struct OfferRegistrationGuard {
    carrier: Arc<crate::transport::udp::stable::QuicCarrier>,
    offer_id: [u8; 16],
}

impl Drop for OfferRegistrationGuard {
    fn drop(&mut self) {
        self.carrier.unregister(&self.offer_id);
    }
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
    max_udp_payload: usize,
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
    // STEK and anti-replay guard travel as one inseparable pair, so the carrier can
    // never accept 0-RTT without anti-replay.
    let zero_rtt =
        SERVER_ZERO_RTT
            .get()
            .map(|zr| crate::transport::udp::quic::endpoint::ZeroRttKeys {
                stek: zr.stek.clone(),
                guard: zr.guard.clone() as Arc<dyn crate::tls::quic::ZeroRttGuard>,
            });
    // Persistent single-use anti-replay for accepted origin-splice markers (issue
    // #74): a sibling `.marker` of the auth-handshake replay cache, keyed by the same
    // PSK, with a window >= the marker freshness window so a captured marker stays
    // replay-protected for as long as it is valid. A cache-load failure degrades to
    // the in-memory first-sighting cache (lost on restart) rather than failing the
    // carrier, mirroring the 0-RTT cache's failure handling.
    let marker_replay_guard = {
        let mpath = marker_replay_cache_path(&server.replay_cache_path);
        match ReplayCache::load_or_create_authenticated_with_window(
            &mpath,
            server.replay_cache_capacity,
            psk,
            MARKER_REPLAY_WINDOW_SECS,
        ) {
            Ok(cache) => Some(Arc::new(
                crate::transport::udp::marker_replay::MarkerReplayGuard::new(cache),
            )),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "marker replay cache load failed; falling back to in-memory \
                     first-sighting (not persistent across restart)"
                );
                None
            }
        }
    };
    let config = crate::transport::udp::server_config_stable(
        cert,
        key,
        zero_rtt,
        marker_key,
        marker_replay_guard,
        origin,
        // The same allowlist the TCP plane authenticates against: a marked QUIC client
        // may only front operator-approved domains; any other SNI splices to the origin.
        server.authorized_sni.clone(),
        max_udp_payload,
    )?;
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
    // Tests exercise the default recv cap (0 => built-in default).
    build_quic_carrier(server, psk, &private_key, 0).await
}

/// 0-RTT resumption-ticket lifetime (RFC 8446 §4.6.1): 7 days, matching the
/// Safari-26 NewSessionTicket baseline. The anti-replay window is sized to this so
/// a ticket stays replay-protected for exactly as long as it is valid.
const ZERO_RTT_TICKET_LIFETIME_SECS: u64 = 604_800;
/// Bind the cross-file invariant at compile time: the replay window here must be
/// `>=` the ticket lifetime advertised by the QUIC server (`TICKET_LIFETIME_SECS`
/// in `crate::tls::quic::server`). Ticket expiry is enforced separately by the
/// lifetime check, so a window LONGER than the lifetime is strictly safer (more
/// replay coverage, no downside); only a window SHORTER than the lifetime is a
/// hole — a still-valid ticket would lose replay protection. Mirrors the marker
/// `>=` invariant above.
const _: () = assert!(
    ZERO_RTT_TICKET_LIFETIME_SECS >= crate::tls::quic::TICKET_LIFETIME_SECS as u64,
    "0-RTT replay window must outlast the advertised ticket lifetime"
);

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

/// Retention window for the persistent origin-splice marker replay cache (issue #74).
/// MUST be `>=` the marker freshness window (`MARKER_WINDOW_SECS` in
/// `crate::tls::quic::server`) so a captured marker stays replay-protected for at
/// least as long as the server would still accept it.
const MARKER_REPLAY_WINDOW_SECS: u64 = 3600;
/// Bind the cross-file invariant at compile time: if a future change raises the
/// marker freshness window past the replay window, a captured marker would be
/// accepted after it left the replay cache (a validity-tail replay hole). A bare
/// comment cannot catch that drift; this assertion does.
const _: () = assert!(
    MARKER_REPLAY_WINDOW_SECS >= crate::tls::quic::MARKER_WINDOW_SECS,
    "marker replay window must outlast the marker freshness window"
);

/// The marker replay cache path: a sibling `.marker` of the auth-handshake replay
/// cache, kept distinct because it keys the marker `(nonce, timestamp)` rather than a
/// handshake transcript fingerprint or a resumption ticket.
fn marker_replay_cache_path(auth_cache_path: &std::path::Path) -> std::path::PathBuf {
    let mut name = auth_cache_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("parallax-replay.cache"));
    name.push(".marker");
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
    crate::transport::tcp::configure_socket_buffers(
        config.transport.tcp_send_buffer_bytes,
        config.transport.tcp_recv_buffer_bytes,
    );
    // Same idea for the UDP carrier socket (wire-invisible: UDP has no advertised
    // window). Installed only when the fast plane is on; a no-op unless an operator
    // set the buffers, and the override is read at endpoint bind time.
    if udp.enabled {
        crate::transport::udp::quic::endpoint::configure_udp_socket_buffers(
            udp.send_buffer_bytes,
            udp.recv_buffer_bytes,
        );
    }
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
        match build_quic_carrier(
            &server,
            psk.as_slice(),
            secrets.private_key(),
            udp.effective_max_udp_payload(),
        )
        .await
        {
            Ok(carrier) => {
                *SERVER_QUIC_CARRIER
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(carrier);
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

    // Eagerly build the reject-path ballast context now (one X25519 keygen +
    // synthetic-ClientHello build), before the first connection. Otherwise the
    // process's FIRST rejected connection would pay that one-time `OnceLock`
    // initialisation and be measurably slower than later rejects — a "first-packet"
    // timing tell. Warming it here folds that cost into startup.
    reject_path_constant_work();

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
            Err(err) if is_transient_accept_error(&err) => {
                // A remote peer can induce ECONNABORTED (RST between SYN and
                // accept) at will; treating it as fatal would let any peer shut
                // the listener down. Drop the would-be connection and keep serving.
                tracing::debug!(
                    error = %err,
                    "transient accept() error; dropping connection and continuing"
                );
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
                // bounded by the 64-relay concurrency ceiling, with idle drawn from
                // the SAME band as a healthy splice (so the close time is not a probe-
                // separable "box at cap" tell), degrading to a graceful FIN past the
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
                // Bounded by the 64-relay concurrency ceiling, with idle unified with
                // the healthy splice band (cap_shed_fallback_or_fin), degrading to a
                // graceful FIN past the budget. Detached so a connection flood at the
                // limit cannot stall the accept loop.
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
    // #3 (obfuscated residency): the ML-DSA identity signing key is used at most
    // once per connection, so it is kept XOR-masked while idle and unmasked only
    // for the brief sign window. The X25519 static private key stays a plain mlocked
    // `Zeroizing` because it is on every connection's key-derivation hot path, where
    // a per-use unmask would be the wrong trade.
    identity_secret_key: Arc<crate::process_hardening::MaskedSecret>,
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
        // #3: mask the identity key for idle residency. `decode_base64_secret`
        // returned it in a `Zeroizing`, which wipes the plaintext copy on drop at
        // the end of this scope once `MaskedSecret::new` has masked it. `MaskedSecret`
        // registers its own masked/mask regions with the dump/lock hardening, so no
        // separate `protect_secret_bytes` call is needed here.
        let identity_secret_key = Arc::new(crate::process_hardening::MaskedSecret::new(
            &identity_secret_key,
        ));
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

    fn identity_secret_key(&self) -> Arc<crate::process_hardening::MaskedSecret> {
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
            // already done; the recover + derive + verify crypto budget this arm
            // just spent is what the two reject arms below replay via
            // reject_path_constant_work, so all three are wall-clock equal.
        } else {
            // recover==None: spend the auth-slot DH (op-count parity), then replay
            // the SAME recover+derive+verify crypto the auth-fail arm runs, so this
            // reject shape is wall-clock indistinguishable from it (op-count alone
            // cannot equalise the HKDF/HMAC the auth-fail arm runs and this skips).
            let _ = dh(&parsed.client_random); // ballast: auth-slot, recover==None
            reject_path_constant_work();
        }
    } else {
        // no key_share: same auth-slot DH (op-count parity) + recover+verify crypto
        // replay as the arms above.
        let _ = dh(&parsed.client_random); // ballast: auth-slot, no key_share
        reject_path_constant_work();
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

    if !crate::handshake::is_authorized_sni(&sni, authorized_sni) {
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
    // Dialing the fallback origin fails before we own it, so only `client` needs a
    // graceful FIN here (a bare `?`-drop with client RX queued would RST).
    let mut fallback = match connect_tcp_with_timeout(&config.fallback_addr).await {
        Ok(fallback) => fallback,
        Err(err) => {
            graceful_close_tcp_stream(client).await;
            return Err(err);
        }
    };
    // From here both `client` and `fallback` are owned; every error must FIN BOTH
    // (never a bare drop → RST), even though the peer is already PSK-authenticated.
    // Run the fallible forward-and-derive body in a closure and close both on Err.
    let forward = async {
        tune_tcp_stream(&fallback)?;
        write_all_with_handshake_timeout(&mut fallback, &first_client_record).await?;
        let forwarded = read_forwarded_server_hello(&mut fallback).await?;
        Ok::<_, HandshakeServerError>(forwarded)
    }
    .await;
    let forwarded = match forward {
        Ok(forwarded) => forwarded,
        Err(err) => {
            tokio::join!(
                graceful_close_tcp_stream(client),
                graceful_close_tcp_stream(fallback),
            );
            return Err(err);
        }
    };
    if config.strict_tls13 && !forwarded.parsed.tls13_selected {
        // Mirror the origin's ServerHello to the client, then close BOTH sockets the
        // same drain->FIN way every other exit does so a strict-TLS1.3 reject is a
        // FIN, never a RST. The origin (`fallback`) side matters too: dropping it bare
        // with bytes still queued (e.g. the rest of its handshake flight) makes the
        // kernel RST the origin, an asymmetry no other teardown produces — drain->FIN
        // it like the client. Swallow a write error here: we tear the connection down
        // regardless and must still FIN.
        let _ = write_all_with_handshake_timeout(&mut client, &forwarded.raw_record).await;
        tokio::join!(
            graceful_close_tcp_stream(client),
            graceful_close_tcp_stream(fallback),
        );
        return Err(HandshakeServerError::Tls13Required);
    }
    // Mirror the origin ServerHello + derive the epoch-0 keys; on any error FIN
    // both sockets rather than bare-dropping (post-auth, but still no RST tell).
    let finish = async {
        write_all_with_handshake_timeout(&mut client, &forwarded.raw_record).await?;
        let context = transcript_hash(&first_client_record, &forwarded.raw_record);
        let session_keys = derive_server_keys_from_shared(psk, &x25519_shared_secret, &context)?;
        Ok::<_, HandshakeServerError>(session_keys)
    }
    .await;
    let session_keys = match finish {
        Ok(session_keys) => session_keys,
        Err(err) => {
            tokio::join!(
                graceful_close_tcp_stream(client),
                graceful_close_tcp_stream(fallback),
            );
            return Err(err);
        }
    };
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

/// Wall-clock budget for the FIN-first lingering drain. Bounded so a peer that
/// keeps sending and never closes after our FIN cannot pin the teardown; for
/// that adversarial case a residual RST at the bounded cutoff is unavoidable and
/// is indistinguishable from a real origin under memory pressure. Cooperating
/// peers (the overwhelming common case) close well within this window.
const GRACEFUL_FIN_DRAIN_BUDGET: Duration = Duration::from_secs(2);

/// FIN-first graceful half-close of one direction. Sends our FIN (`shutdown`) on
/// the write half FIRST, then reads-and-discards the peer's remaining bytes until
/// it closes (`read` == 0) or the bounded budget elapses. Order matters: only by
/// draining to the peer's EOF *after* we FIN does the receive queue reach empty at
/// the final drop, making the close a clean FIN. A bare drop — or the old
/// drain-then-close under a fast sender — leaves queued bytes at close and the
/// kernel emits a RST, the exact censor-observable tell a real origin never
/// produces. (`shutdown(Read)` would NOT help: it neither flushes the receive
/// queue nor suppresses the RST.)
async fn graceful_fin_then_drain(read_half: &mut OwnedReadHalf, write_half: &mut OwnedWriteHalf) {
    let _ = write_half.shutdown().await;
    let mut scratch = [0_u8; 16 * 1024];
    let deadline = tokio::time::Instant::now() + GRACEFUL_FIN_DRAIN_BUDGET;
    loop {
        match tokio::time::timeout_at(deadline, read_half.read(&mut scratch)).await {
            Ok(Ok(0)) => break,    // peer FIN: recv queue drained, clean close
            Ok(Ok(_)) => continue, // discard and keep draining
            _ => break,            // read error or budget elapsed
        }
    }
}

/// FIN-first graceful close of a whole `TcpStream` (by mutable ref, so callers can
/// close on an error path without giving up ownership on the success path).
/// `AsyncWriteExt::shutdown` on a `TcpStream` half-closes the write side (FIN);
/// we then drain the peer to EOF (bounded) so the final drop carries no queued
/// bytes and cannot RST. See [`graceful_fin_then_drain`].
async fn graceful_fin_then_drain_stream(stream: &mut TcpStream) {
    let _ = stream.shutdown().await;
    let mut scratch = [0_u8; 16 * 1024];
    let deadline = tokio::time::Instant::now() + GRACEFUL_FIN_DRAIN_BUDGET;
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut scratch)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
}

/// Drains any ready receive bytes and then half-closes the write side so the
/// peer sees a graceful FIN. Dropping a socket with unread bytes still queued
/// makes the kernel emit a RST, an observable tell a real origin would not
/// produce; this keeps the close indistinguishable from an ordinary teardown.
async fn graceful_close_tcp_stream(mut stream: TcpStream) {
    graceful_fin_then_drain_stream(&mut stream).await;
}

/// Cap-rejection close that stays indistinguishable from the origin (H-1): relay
/// to the camouflage origin so the client still gets a real ServerHello, bounded by
/// the 64-relay concurrency ceiling with the idle drawn from the SAME band as a
/// healthy splice; if the budget is full or the origin dial fails, fall back to a
/// graceful FIN (the prior behavior).
///
/// L8: read the client's first record BEFORE dialing the origin, then forward it —
/// mirroring the healthy splice's dial-AFTER-read ordering. Dialing upfront with an
/// empty prefix (the old behavior) made a cap-shed connection's handshake-start
/// timing observably different from a healthy splice to a keyless prober that could
/// drive the box to its cap; reading first removes that establishment-ordering tell.
/// The read is bounded by `first_record_wait_timeout` and the whole path by the 64
/// cap-shed slots, so it cannot be amplified into a resource exhaustion.
async fn cap_shed_fallback_or_fin(mut client: TcpStream, fallback_addr: String) {
    let Some(_slot) = try_enter_cap_shed_fallback() else {
        graceful_close_tcp_stream(client).await;
        return;
    };
    // Read the ClientHello (or the partial give-up prefix) first, exactly as the
    // healthy path does, so the origin dial happens AFTER the read on both paths.
    let prefix = match read_first_client_record(&mut client).await {
        Ok(FirstClientRead::Record(record)) => record,
        Ok(FirstClientRead::FallbackPrefix(prefix)) => prefix,
        Err(_) => {
            graceful_close_tcp_stream(client).await;
            return;
        }
    };
    match connect_and_forward_to_fallback(&fallback_addr, &prefix).await {
        Ok(fallback) => {
            // Draw the idle backstop from the SAME distribution as a healthy splice
            // ([`fallback_idle_timeout`], [600s, 660s]) rather than a separate tight
            // band. A separate band ([10s, 90s]) was disjoint from the healthy band,
            // so a prober that timed our server-originated FIN on a silent relay could
            // separate the two populations in a handful of samples and read "this box
            // is at its cap" — a threshold-triggered, externally observable state tell
            // (a real origin's idle policy does not switch on THIS front box's permit
            // accounting). Unifying the band removes that idle-close-time tell. The
            // former handshake-start difference (cap-shed dialed BEFORE reading a
            // ClientHello, healthy splice dials after) is now also gone: cap-shed
            // reads the first record first (L8), so both paths dial-after-read.
            //
            // The cap-as-DoS-amplifier concern is still defused by construction: the
            // hard [`MAX_CONCURRENT_CAP_SHED_FALLBACKS`] (64) ceiling bounds the
            // CONCURRENCY of cap-shed relays regardless of flood volume (the idle
            // resets on every byte, so a trickling prober can hold a slot past 660s —
            // exactly as a healthy splice can — but never more than 64 at once). 64
            // idle origin connections is negligible for any real origin: bounded, no
            // growth. That fixed concurrency bound, not a tightened idle, is the
            // actual resource backstop.
            let _ =
                relay_fallback_with_idle_timeout(client, fallback, cap_shed_fallback_idle()).await;
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
        &mut client_read,
        &mut client_write,
        &mut fallback_read,
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
                    // Bound the forward write with the SAME idle timeout (#262):
                    // this write is awaited INSIDE the selected arm, where the
                    // pinned `idle_sleep` is not polled, so a zero-window peer
                    // that never drains its receive buffer would otherwise stall
                    // `write_all` forever and pin the connection permit. The
                    // kernel splice path already polls the write fd against this
                    // idle bound; on elapse, break so the relay tears down.
                    match timeout(idle_timeout, fallback_write.write_all(&client_buf[..n])).await {
                        Ok(result) => result?,
                        Err(_) => break,
                    }
                    idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
            read = fallback_read.read(&mut fallback_buf), if !fallback_closed => {
                let n = read?;
                if n == 0 {
                    fallback_closed = true;
                    let _ = client_write.shutdown().await;
                } else {
                    // Same write-side idle bound as the client->fallback arm.
                    match timeout(idle_timeout, client_write.write_all(&fallback_buf[..n])).await {
                        Ok(result) => result?,
                        Err(_) => break,
                    }
                    idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
        }
    }

    Ok(())
}

async fn graceful_close_fallback_halves(
    client_read: &mut OwnedReadHalf,
    client_write: &mut OwnedWriteHalf,
    fallback_read: &mut OwnedReadHalf,
    fallback_write: &mut OwnedWriteHalf,
) {
    // FIN both directions first, then drain each to the peer's EOF (bounded), so
    // neither socket drops with queued bytes (which would RST). Concurrent so the
    // total teardown is bounded by one budget, not two.
    tokio::join!(
        graceful_fin_then_drain(client_read, client_write),
        graceful_fin_then_drain(fallback_read, fallback_write),
    );
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
    let mut client_read = client_records.into_inner().into_inner();
    let mut fallback_read = fallback_records.into_inner().into_inner();
    graceful_close_fallback_halves(
        &mut client_read,
        &mut client_write,
        &mut fallback_read,
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

/// Idle backstop for a cap-shed fallback relay. Deliberately the SAME distribution
/// as a healthy splice ([`fallback_idle_timeout`]) so a cap-shed close time is not a
/// probe-separable "box at cap" tell (the anti-amplification bound is carried by the
/// [`MAX_CONCURRENT_CAP_SHED_FALLBACKS`] concurrency ceiling, not a tighter idle).
/// A named indirection so the test pins THIS — a future revert to a separate tight
/// band fails the guard instead of silently re-opening the disjoint-band tell.
fn cap_shed_fallback_idle() -> Duration {
    fallback_idle_timeout()
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
    mut handshake: AuthenticatedHandshake,
    fixed_data_target: Option<&str>,
    identity_secret_key: Arc<crate::process_hardening::MaskedSecret>,
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
    // #1 (shrink the residency window): client->target plaintext is decrypted in
    // place into this buffer, so wrap it in `Zeroizing` to scrub on drop at every
    // exit of this relay. Best-effort: `Zeroizing` wipes the live `[0..len)` of the
    // final buffer only — a record larger than capacity reallocs and frees the old
    // (plaintext) buffer un-scrubbed, and a truncate leaves a stale capacity tail.
    // It removes the dominant exposure (the last record sitting in a long-lived
    // named buffer), not every fragment. See the realloc-scrub follow-up.
    let mut client_record = Zeroizing::new(Vec::new());
    // Raw byte scratch for the origin->client camouflage forward (D5). The origin
    // direction is now a verbatim byte pump (preserving the origin's native TCP
    // segmentation) rather than a per-record re-frame, so it reads into a fixed
    // buffer exactly like `relay_fallback_userspace_loop`, not into a record Vec.
    let mut fallback_relay_buf = vec![0_u8; relay_read_buffer_len(max_plaintext_len(0))];
    let mut client_camouflage_records_before_pq = 0usize;
    let mut client_camouflage_bytes_before_pq = 0usize;
    let mut fallback_bytes_before_pq = 0usize;
    // The camouflage origin can finish its side (TLS `close_notify` + FIN) before
    // the authenticated client's PX1Q reaches us — a real origin closes a
    // completed HTTP/2 GET whenever it likes, and on a high-RTT link the client's
    // PX1Q is still in flight when that close arrives. The origin closing is NOT a
    // session-fatal event: the server is about to drop the origin the instant
    // PX1Q arrives anyway (the splice exists only to cover the camouflage
    // handshake). So when the origin half closes, stop pumping it and keep waiting
    // for PX1Q on the client arm, rather than tearing the whole handshake down and
    // leaving the client to read a FIN where it expects PX1K. `false` disables the
    // fallback->client select arm (mirroring the byte-limit pause already there),
    // so the loop proceeds on the client and deadline arms with no busy-spin.
    let mut fallback_open = true;
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
                            // Blur the replay close-time tell (M-5): hold the inert
                            // connection for a WIDE jittered delay before tearing it
                            // down, so the FIN no longer lands at a near-fixed moment
                            // a PSK-holding observer could time to confirm a replay
                            // was flagged. Drawn from [0, jitter] so there is no fixed
                            // lower edge. Nothing is forwarded during the wait (no
                            // origin-side cost); replays are rare, so this never
                            // affects throughput.
                            sleep(jittered_timeout(
                                REPLAY_CLOSE_DELAY_FLOOR,
                                REPLAY_CLOSE_DELAY_JITTER,
                            ))
                            .await;
                            // Graceful drain->FIN instead of a bare drop (M-1). At
                            // this point the fallback origin's read half (and any
                            // client RX buffered in the record reader) may hold
                            // unread bytes, so dropping the sockets would make
                            // close() emit a RST -- the FIN/RST tell every other
                            // teardown here avoids. Mirrors the pre-PQ-deadline
                            // teardown above; covers Replayed/Stale/CacheFull.
                            let mut client_read = client_records.into_inner().into_inner();
                            let mut fallback_read = fallback_records.into_inner().into_inner();
                            graceful_close_fallback_halves(
                                &mut client_read,
                                &mut client_write,
                                &mut fallback_read,
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
                        let pq_encapsulation =
                            encapsulate_mlkem_blocking(client_mlkem_public_key).await?;
                        // The ML-KEM shared secret is a `Zeroizing<[u8; 32]>` field, so
                        // moving it out here into a wipe-on-drop local scrubs it on ANY
                        // return (every `?` between here and the rekey — encode / seal /
                        // write / rekey). `.ciphertext` is moved into the key-exchange
                        // payload below (partially moving the struct), which is why the
                        // secret is a self-wiping FIELD rather than relying on struct
                        // Drop glue that a partial move would forbid.
                        let pq_shared_secret = pq_encapsulation.shared_secret;
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
                        // Shape the key-exchange (PX1K) record into the SAME
                        // browser-modeled distribution + aggregate decorrelation pad as
                        // the client PX1Q and the identity proof below (PAR-35), so the
                        // whole post-handshake burst shares one coherent H2-page-like
                        // regime instead of reading as a second, heavier PQ exchange.
                        // Sealed into one buffer => one write => single flight.
                        let mut key_exchange_record = Vec::new();
                        // Cap the shaped chunk size to what `server_seal` can seal under
                        // its padding profile so a heavy `max_padding` config cannot push
                        // a shaped record past the TLS record limit (the aggregate pad on
                        // the last record is reserved too). The padding profile is
                        // unchanged by the PQ rekey below, so this cap also governs the
                        // identity flight.
                        let max_pq_chunk = crate::protocol::command::pq_flight_max_chunk_size(
                            server_seal.max_plaintext_len(),
                        );
                        let key_exchange_chunks = FramedChunk::encode_all_browser_shaped(
                            &key_exchange_payload,
                            max_pq_chunk,
                            &mut rng,
                        )?;
                        server_seal.seal_pq_flight(
                            &key_exchange_chunks,
                            &mut rng,
                            &mut key_exchange_record,
                        )?;
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
                        // Advance the session's live keys to the post-rekey epoch so
                        // any later derivation root (mux-over-QUIC per-substream keys)
                        // matches the client's post-rekey `data_session` keys. Without
                        // this, substream codecs would derive from the stale epoch-0
                        // chain secret and every substream AEAD-open would fail.
                        handshake.session_keys = rekeyed_keys.clone();
                        // The stored clone is a distinct heap copy of the live
                        // derivation root (mux-over-QUIC substreams key off it), so
                        // pin its secret pages too — not just the local `rekeyed_keys`.
                        handshake.session_keys.protect_secret_memory();
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
                        // Shape the identity proof into the SAME browser-modeled
                        // record-size distribution as PX1Q/PX1K (PAR-35), so the whole
                        // server burst is one coherent regime with no observable
                        // [256,1024]->[960,1320] switch to segment on.
                        let identity_chunks = ServerIdentityChunk::encode_all_browser_shaped(
                            &identity_payload,
                            max_pq_chunk,
                            &mut rng,
                        )?;
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
                                let mut client_read = client_records.into_inner().into_inner();
                                graceful_fin_then_drain(&mut client_read, &mut client_write).await;
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
                            fallback_bytes_before_pq,
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
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
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
                                // Item #3a: from the moment `carrier.register` ran
                                // (producing `rx`), guarantee the offer_id is
                                // unregistered on EVERY exit — including the offer
                                // seal / offer-record write `?` below, which return
                                // before the probe-timeout arm that used to be the
                                // sole unregister and would otherwise leak the
                                // registry entry.
                                let _offer_registration = OfferRegistrationGuard {
                                    carrier: carrier.clone(),
                                    offer_id,
                                };
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
                                // C4: snap this PX1O onto a CONNECT size band (reuses
                                // C3 shaping) instead of a tiny fixed control record.
                                let offer_record = seal_control_frame_band_shaped(
                                    &mut server_seal,
                                    &offer,
                                    &mut rng,
                                )?;
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
                                // C6: snap this PX1N onto a CONNECT size band (reuses
                                // C3 shaping) instead of a tiny fixed control record.
                                let decline_record = seal_control_frame_band_shaped(
                                    &mut server_seal,
                                    &decline,
                                    &mut rng,
                                )?;
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
                            // Speed test: always measure TCP, then QUIC when the probe
                            // Verified (the retained bidi the relay would use). The
                            // request just decoded is the TCP run's opener; the QUIC
                            // run sends its own request on the bidi.
                            let request = SpeedTestRequest::decode(first_payload)?;
                            return run_authenticated_speed_test_mode(
                                client_records,
                                client_write,
                                client_open,
                                server_seal,
                                request,
                                max_plaintext_len(traffic.max_padding),
                                retained_quic,
                                &handshake.session_keys,
                                traffic,
                                cid,
                            )
                            .await;
                        }

                        if MuxFrame::has_magic(first_payload) {
                            let first_frames = MuxFrame::decode_all(first_payload)?;
                            // Mux-over-QUIC fast plane: enter ONLY when we hold the
                            // retained QUIC connection AND the TCP first record is
                            // exactly the mux-mode signal — a single zero-stream Cover
                            // frame carrying no substream. A real client on the QUIC
                            // fast plane sends precisely that and then opens substreams
                            // as QUIC bidis. If instead the frames carry actual Open
                            // requests (a version mismatch or a hostile peer mixing TCP
                            // Opens with a Verified probe), do NOT switch to QUIC — that
                            // would silently drop those Opens. Release the retained QUIC
                            // and fall through to the TCP mux path, which relays them.
                            if is_mux_quic_signal(&first_frames) {
                                if let Some(probed) = retained_quic {
                                    return run_authenticated_mux_quic_data_mode(
                                        client_records,
                                        client_write,
                                        probed,
                                        ServerMuxQuicContext {
                                            session_keys: &handshake.session_keys,
                                            traffic,
                                            fixed_data_target,
                                            cid,
                                        },
                                        fallback_idle_timeout(),
                                    )
                                    .await;
                                }
                                // The signal arrived but we hold no retained QUIC
                                // (config asymmetry / probe not Verified): fall
                                // through to the TCP mux path below, which treats the
                                // lone Cover frame as a no-op.
                            }
                            // Not the QUIC fast plane (no retained QUIC, or the first
                            // record is real TCP mux frames): release any retained QUIC
                            // and relay over TCP mux, byte-identical to before.
                            drop_retained_quic(retained_quic);
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

                        let (target_addr, target_source, initial_payload) =
                            resolve_connect_target(first_payload, fixed_data_target)?;
                        let mut target =
                            connect_outbound_target(&target_addr, target_source).await?;
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
                            // Same camouflage window as the fallback->client byte
                            // cap below (that direction pauses; this one tears down). A
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
                        // Only forward to the origin while its half is still open.
                        // If it already closed before PX1Q (handled on the
                        // fallback->client arm), drop the client's remaining
                        // camouflage tail: those bytes were destined for an origin
                        // that has left, and the client sends its camouflage flight
                        // fire-and-forget before PX1Q, so discarding them is inert.
                        // The record cap above still bounds this direction.
                        if !fallback_open {
                            continue;
                        }
                        match timeout_at(
                            pre_pq_deadline,
                            fallback_write.write_all(&client_record),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) if is_write_peer_close(&err) => {
                                // The cover origin closed mid-camouflage, observed on
                                // the write side. Same benign case as an origin FIN on
                                // the read arm: stop forwarding to it and keep waiting
                                // for the client's PX1Q rather than tearing the
                                // authenticated handshake down. The client is still
                                // live; we simply stop pumping the (now-absent) origin.
                                let _ = err;
                                tracing::debug!(
                                    cid,
                                    "fallback origin closed on forward write before client PQ rekey; \
                                     pausing fallback, still awaiting PX1Q"
                                );
                                fallback_open = false;
                                continue;
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
            // D5: forward the origin's camouflage handshake to the client as a
            // VERBATIM byte stream, preserving its native TCP segmentation — the
            // same byte-pump shape `relay_fallback_userspace_loop` produces on the
            // unauthenticated splice. The prior per-record `read_record_into` +
            // per-record `write_all` re-framed the origin flight into "one TLS
            // record, one segment", a shape neither a direct-to-origin connection
            // nor the fallback splice emits, which made the authenticated splice
            // separable from both. Reading raw bytes off the buffered reader drains
            // any already-buffered bytes first, so nothing the record path left
            // behind is lost (we never read records off this half again in pre-PQ).
            // The cap is byte-oriented to match (see PRE_PQ_FALLBACK_FORWARD_BYTE_LIMIT),
            // and each read is capped at the remaining budget so the forward can never
            // overshoot the client's equal residual byte budget mid-read.
            read = fallback_records.get_mut().read({
                let remaining = PRE_PQ_FALLBACK_FORWARD_BYTE_LIMIT
                    .saturating_sub(fallback_bytes_before_pq)
                    .min(fallback_relay_buf.len());
                &mut fallback_relay_buf[..remaining]
            }),
                if fallback_open && fallback_bytes_before_pq < PRE_PQ_FALLBACK_FORWARD_BYTE_LIMIT => {
                let n = match read {
                    // Origin half-closed (FIN) or reset before PX1Q arrived. This is
                    // expected camouflage debris, not a failure: a real origin closes
                    // a finished session on its own schedule. Disable this arm and keep
                    // waiting for the client's PX1Q on the client arm; the splice was
                    // only ever covering the camouflage handshake, and the server drops
                    // the origin on PX1Q regardless. Bounded by `pre_pq_deadline` if
                    // PX1Q never comes (an authenticated client that never rekeys hits
                    // the existing graceful teardown).
                    Ok(0) => {
                        tracing::debug!(
                            cid,
                            fallback_bytes_before_pq,
                            "fallback origin closed before client PQ rekey; pausing fallback reads, \
                             still awaiting PX1Q"
                        );
                        fallback_open = false;
                        continue;
                    }
                    Ok(n) => n,
                    Err(ref err) if is_clean_close(err) => {
                        tracing::debug!(
                            cid,
                            fallback_bytes_before_pq,
                            "fallback origin closed before client PQ rekey; pausing fallback reads, \
                             still awaiting PX1Q"
                        );
                        fallback_open = false;
                        continue;
                    }
                    Err(err) => return Err(HandshakeServerError::Io(err)),
                };
                let before = fallback_bytes_before_pq;
                fallback_bytes_before_pq += n;
                if before == 0 {
                    tracing::info!(
                        cid,
                        direction = "fallback->client",
                        task_name = "server-camouflage-writer",
                        forwarded_bytes = n,
                        "forwarding fallback camouflage bytes before ParallaX PQ rekey"
                    );
                } else if before < PRE_PQ_FALLBACK_FORWARD_BYTE_LIMIT
                    && fallback_bytes_before_pq >= PRE_PQ_FALLBACK_FORWARD_BYTE_LIMIT
                {
                    tracing::warn!(
                        cid,
                        direction = "fallback->client",
                        task_name = "server-camouflage-writer",
                        fallback_bytes_before_pq,
                        client_residual_byte_budget = CLIENT_RESIDUAL_CAMOUFLAGE_BYTE_BUDGET,
                        pre_pq_forward_byte_limit = PRE_PQ_FALLBACK_FORWARD_BYTE_LIMIT,
                        "pre-PQ fallback camouflage forward byte limit reached; pausing fallback \
                         reads until ParallaX PQ rekey"
                    );
                }
                match timeout_at(pre_pq_deadline, client_write.write_all(&fallback_relay_buf[..n]))
                    .await
                {
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

/// Who chose the egress target, so the outbound path's private-address policy is
/// keyed on an explicit fact rather than the implicit `fixed_data_target.is_some()`
/// coupling. The two were equivalent today only because `resolve_connect_target`
/// reads the same `Option` twice (once to pick the target, once to derive
/// `allow_private`); separating them keeps the SSRF screen correct if a future
/// feature ever lets the client influence the target while a fixed one is also set
/// — only an operator-fixed target may reach a private address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetSource {
    /// The operator's `data_target` config decided the destination; the client's
    /// requested target was ignored. Trusted, so private/loopback egress is allowed
    /// (e.g. a sidecar on localhost).
    OperatorFixed,
    /// The client's `ConnectRequest` decided the destination. Untrusted: it must
    /// pass the public-address SSRF screen ([`validate_public_target_addrs`]).
    ClientChosen,
}

fn resolve_connect_target<'a>(
    first_payload: &'a mut [u8],
    fixed_data_target: Option<&str>,
) -> Result<(String, TargetSource, &'a mut [u8]), HandshakeServerError> {
    crate::process_hardening::exclude_from_core_dump(
        "connect_request.first_payload",
        first_payload,
    );
    match ConnectRequest::decode_ref(first_payload) {
        Ok(request) => {
            request.protect_plaintext_memory();
            let payload_len = request.initial_payload.len();
            // A fixed target overrides the client's request (and is operator-chosen,
            // so trusted); otherwise the destination is the client's own request.
            let (target, source) = match fixed_data_target {
                Some(fixed) => (fixed.to_owned(), TargetSource::OperatorFixed),
                None => (request.target(), TargetSource::ClientChosen),
            };
            let start = first_payload.len().saturating_sub(payload_len);
            let initial_payload = &mut first_payload[start..];
            crate::process_hardening::exclude_from_core_dump(
                "connect_request.initial_payload",
                initial_payload,
            );
            Ok((target, source, initial_payload))
        }
        Err(ConnectRequestError::BadMagic | ConnectRequestError::Truncated) => {
            // Raw payload with no decodable request: only an operator-fixed target
            // can name the destination (the client named none).
            let target = fixed_data_target.ok_or(HandshakeServerError::MissingConnectTarget)?;
            crate::process_hardening::exclude_from_core_dump(
                "connect_request.fixed_target_payload",
                first_payload,
            );
            Ok((
                target.to_owned(),
                TargetSource::OperatorFixed,
                first_payload,
            ))
        }
        Err(err) => Err(HandshakeServerError::ConnectRequest(err)),
    }
}

async fn connect_outbound_target(
    target_addr: &str,
    source: TargetSource,
) -> Result<TcpStream, HandshakeServerError> {
    // Only an operator-fixed destination may reach a private/loopback address; a
    // client-chosen target is always screened against the public-address policy.
    if matches!(source, TargetSource::OperatorFixed) {
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
        // 6to4 relay anycast 192.88.99.0/24 (RFC 7526): the deprecated 6to4 relay
        // anycast prefix, which can be used to bounce traffic through relays; deny
        // it outbound alongside the other special-use v4 ranges.
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
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

/// NAT64 embedding prefixes that carry an IPv4 destination and would otherwise
/// tunnel to an arbitrary IPv4 host without passing through the IPv4 egress
/// policy:
///
///   * RFC 6052 well-known prefix `64:ff9b::/96`, and
///   * RFC 8215 local-use prefix `64:ff9b:1::/48`.
///
/// For an address in EITHER prefix, the embedded IPv4 is extracted with the
/// per-prefix-length layout of RFC 6052 §2.2 and re-screened through
/// [`is_denied_outbound_ipv4`], so a NAT64-embedded private/metadata address
/// (e.g. `64:ff9b::10.0.0.1`) is denied while a legitimate public NAT64 target
/// (e.g. `64:ff9b::8.8.8.8`) is ALLOWED rather than the whole prefix being
/// wholesale-denied. This screens the ultimate IPv4 destination the NAT64
/// tunnel would reach — closing the SSRF gap for the RFC 8215 prefix, which
/// was not embedding-screened before.
///
/// Extraction layouts (RFC 6052 §2.2):
///
///   * `/96`: the IPv4 sits in bits 96..127 (the low 32 bits).
///   * `/48`: the IPv4 sits in bits 48..63 (high two octets) and 72..87 (low
///     two octets), skipping the reserved `u` octet at bits 64..71.
///
/// The per-prefix layout matters both ways: reading the low 32 bits for a /48
/// address would screen suffix bits instead of the real destination (an
/// attacker parks a public-looking decoy in the suffix while the translator
/// connects to a private embedded target), and it would deny a legitimate /48
/// public target whose zero suffix extracts as `0.0.0.0`.
fn is_ipv6_nat64(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    let in_well_known_96 = segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0;
    let in_rfc8215_48 = segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001;
    let embedded = if in_well_known_96 {
        Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        )
    } else if in_rfc8215_48 {
        Ipv4Addr::new(
            (segments[3] >> 8) as u8,
            (segments[3] & 0xff) as u8,
            (segments[4] & 0xff) as u8,
            (segments[5] >> 8) as u8,
        )
    } else {
        return false;
    };
    is_denied_outbound_ipv4(embedded)
}

async fn encapsulate_mlkem_blocking(
    client_mlkem_public_key: Vec<u8>,
) -> Result<pq::MlKemEncapsulation, HandshakeServerError> {
    Ok(tokio::task::spawn_blocking(move || pq::encapsulate(&client_mlkem_public_key)).await??)
}

async fn sign_server_identity_blocking(
    identity_secret_key: Arc<crate::process_hardening::MaskedSecret>,
    transcript_hash: [u8; 32],
    server_public_key: [u8; 32],
    pq_rekey_binding: [u8; 32],
    epoch: u64,
) -> Result<Vec<u8>, HandshakeServerError> {
    // #3: the identity key is masked while idle; unmask it only inside this brief
    // sign window (the `with_plaintext` scratch is wiped the moment signing returns).
    Ok(tokio::task::spawn_blocking(move || {
        identity_secret_key.with_plaintext(|sk| {
            identity::sign_server_identity(
                sk,
                &transcript_hash,
                &server_public_key,
                &pq_rekey_binding,
                epoch,
            )
        })
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
    // Per-session aggregate decorrelation pad (PAR-35), applied to the LAST identity
    // record so the identity flight's total on-wire size varies across sessions.
    // Stripped transparently by the client's per-record padding trailer; never touches
    // the relay codec.
    let aggregate_pad = FramedChunk::aggregate_pad_len(rng);
    let last = identity_chunks.len().saturating_sub(1);

    if timing.is_enabled() {
        let identity_chunk_count = identity_chunks.len();
        for (idx, chunk) in identity_chunks.into_iter().enumerate() {
            let identity_record = if idx == last {
                let mut buf = Vec::new();
                server_seal.seal_into_extra_padded(&chunk, aggregate_pad, rng, &mut buf)?;
                buf
            } else {
                server_seal.seal(&chunk, rng)?
            };
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

    // Reservation hint only (a loose over-estimate is harmless): the sealed records
    // plus the aggregate pad and its 2-byte length trailer on the last record.
    let capacity = identity_chunks
        .iter()
        .map(|chunk| server_seal.max_sealed_len(chunk.len()))
        .sum::<usize>()
        + aggregate_pad
        + 2;
    let mut identity_records = Vec::with_capacity(capacity);
    for (idx, chunk) in identity_chunks.iter().enumerate() {
        let range = if idx == last {
            server_seal.seal_into_extra_padded(chunk, aggregate_pad, rng, &mut identity_records)?
        } else {
            server_seal.seal_into(chunk, rng, &mut identity_records)?
        };
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

/// Depth of a single substream's client->target upload channel: how many decrypted
/// upload frames the shared mux reader may queue ahead of that substream's own
/// task before it must wait for the task to drain to the target socket. Bounds
/// per-stream memory while giving the task enough slack that a live-but-slow target
/// never forces the reader to block. Mirrors the client's `CLIENT_MUX_STREAM_CHANNEL`.
const SERVER_MUX_UPLOAD_CHANNEL: usize = 32;

/// Grace the shared mux reader waits on a FULL upload channel before shedding the
/// substream. A full channel alone does NOT mean the target is wedged: a live app
/// draining slower than a bulk upload burst fills it transiently too. So on a full
/// channel the reader waits UP TO this long for a slot instead of shedding at once
/// (deliver, no reset, if the target drains within the window; shed only a genuine
/// stall). Bounds how long ONE stalled upload can hold the shared reader — the only
/// residual head-of-line term once connect/target-write moved off the reader onto
/// per-stream tasks. Mirrors the client's `CLIENT_MUX_STALL_RESET_GRACE`.
const SERVER_MUX_STALL_RESET_GRACE: Duration = Duration::from_secs(2);

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
/// Each live substream is ONE spawned supervisor task ([`server_mux_upstream_task`])
/// that owns the target socket, connects it OFF the shared reader, and runs BOTH
/// relay directions. The maps split routing from lifetime:
///   - `uploads` holds the sender of each substream's client->target upload channel.
///     The shared reader `try_send`s decrypted upload frames here and NEVER blocks
///     on target I/O. A client `Fin` drops the sender (removed from the map); the
///     channel then closes and the task half-closes the target write while the
///     target keeps streaming back.
///   - `tasks` holds each substream's supervisor `JoinHandle`. A stream occupies a
///     `max_streams` slot for as long as its task is unfinished — and the task runs
///     until BOTH directions finish — so `live_count` (the admission gate) counts
///     exactly the streams with either direction still open. This is the same
///     union-across-half-close bound the previous write/reader split enforced,
///     collapsed onto one task per stream.
///
/// A `Reset` (or connection teardown) aborts the task so no target fd is orphaned.
struct ServerMuxStreams {
    uploads: HashMap<u32, mpsc::Sender<Vec<u8>>>,
    tasks: HashMap<u32, tokio::task::JoinHandle<()>>,
}

impl ServerMuxStreams {
    fn new() -> Self {
        Self {
            uploads: HashMap::new(),
            tasks: HashMap::new(),
        }
    }

    /// Drop finished supervisor tasks (both directions done) and their now-defunct
    /// upload senders so `live_count` reflects only streams still doing work.
    fn prune_finished(&mut self) {
        self.tasks.retain(|_, h| !h.is_finished());
        self.uploads.retain(|id, _| self.tasks.contains_key(id));
    }

    /// Number of substreams still holding a target fd (the `max_streams` admission
    /// gate). Each live substream is exactly one supervisor task, which runs until
    /// BOTH relay directions finish, so the unfinished-task count is precisely the
    /// set of streams with either direction open — bounding the per-connection fd
    /// footprint to `max_streams` across half-closes.
    fn live_count(&mut self) -> usize {
        self.prune_finished();
        self.tasks.len()
    }

    /// Tear down every substream: drop all upload senders (closing each upload
    /// channel) and abort every supervisor task (closing its target fds).
    async fn teardown(&mut self) {
        self.uploads.clear();
        for (_, handle) in self.tasks.drain() {
            handle.abort();
        }
    }
}

impl Drop for ServerMuxStreams {
    /// Backstop against orphaned per-stream tasks: a `JoinHandle` dropped without
    /// `abort()` leaves its task (and the target fds it holds) running. Aborting on
    /// drop guarantees that any return path out of the reader loop — including `?`
    /// error propagation — reclaims every spawned task.
    fn drop(&mut self) {
        for (_, handle) in self.tasks.drain() {
            handle.abort();
        }
    }
}

/// Owned, `'static` slice of [`ServerMuxContext`] handed to a spawned per-substream
/// task, which outlives the borrowed reader-loop context.
struct ServerMuxStreamContext {
    fixed_data_target: Option<String>,
    timing: TimingProfile,
    chunk_size: usize,
    cid: u64,
    target_write_timeout: Duration,
}

/// Per-substream supervisor, spawned by the shared mux reader on every `Open`. It
/// performs the per-destination blocking work — DNS resolve, outbound connect
/// (`HANDSHAKE_TIMEOUT`), and the initial-payload write (`target_write_timeout`) —
/// OFF the shared reader, so a slow/blackholed/unreachable target stalls ONLY this
/// substream and never head-of-line-blocks the carrier's other concurrent streams
/// (the China-path failure this fixes). On any setup failure it sheds just this
/// stream (Reset to the client). On success it runs both relay directions to
/// completion; either direction's error tears down the other (its half of the
/// target socket drops).
async fn server_mux_upstream_task(
    stream_id: u32,
    connect_payload: Vec<u8>,
    upload_rx: mpsc::Receiver<Vec<u8>>,
    frame_tx: mpsc::Sender<MuxFrame>,
    ctx: ServerMuxStreamContext,
    payload_pool: MuxPayloadPool,
) {
    // Own the decrypted request in a scrub-on-drop buffer; copy out the target +
    // initial payload (also scrub-on-drop) so the request buffer is dropped
    // (scrubbed) before the connect await.
    let mut connect_payload = Zeroizing::new(connect_payload);
    let (target_addr, target_source, initial) = match resolve_connect_target(
        connect_payload.as_mut_slice(),
        ctx.fixed_data_target.as_deref(),
    ) {
        Ok((addr, source, initial)) => (addr, source, Zeroizing::new(initial.to_vec())),
        Err(_) => {
            tracing::debug!(
                cid = ctx.cid,
                stream_id,
                "mux connect target resolve failed; resetting stream"
            );
            let _ = reset_unregistered_stream(&frame_tx, stream_id).await;
            return;
        }
    };
    drop(connect_payload);
    crate::process_hardening::exclude_from_core_dump("mux.upstream.initial_payload", &initial);

    let mut target = match connect_outbound_target(&target_addr, target_source).await {
        Ok(target) => target,
        Err(_) => {
            tracing::debug!(
                cid = ctx.cid,
                stream_id,
                "mux outbound connect failed; resetting stream"
            );
            let _ = reset_unregistered_stream(&frame_tx, stream_id).await;
            return;
        }
    };
    if tune_tcp_stream(&target).is_err() {
        tracing::debug!(
            cid = ctx.cid,
            stream_id,
            "mux target tune failed; resetting stream"
        );
        let _ = reset_unregistered_stream(&frame_tx, stream_id).await;
        return;
    }
    if !initial.is_empty() {
        match timeout(ctx.target_write_timeout, target.write_all(&initial)).await {
            Ok(Ok(())) => {}
            _ => {
                tracing::debug!(
                    cid = ctx.cid,
                    stream_id,
                    "mux target initial-payload write failed/stalled; resetting stream"
                );
                let _ = reset_unregistered_stream(&frame_tx, stream_id).await;
                return;
            }
        }
    }
    drop(initial);

    let (target_read, target_write) = target.into_split();
    let reader = server_mux_target_reader_loop(
        target_read,
        frame_tx.clone(),
        stream_id,
        ctx.timing,
        ctx.chunk_size,
        ctx.cid,
        payload_pool,
    );
    let writer = server_mux_upload_drain(
        upload_rx,
        target_write,
        stream_id,
        ctx.cid,
        ctx.target_write_timeout,
        &frame_tx,
    );
    // Run both directions; an error in either drops the other's half of the target
    // socket. Half-close (client Fin) resolves `writer` Ok while `reader` keeps
    // streaming the target back until its EOF.
    let _ = tokio::try_join!(reader, writer);
}

/// Drains a substream's client->target upload channel to its target socket, OFF the
/// shared mux reader. Each write is bounded by `write_timeout`; a stall sheds ONLY
/// this substream (Reset to the client + `Err`, which drops the paired target
/// reader). The channel closing (client `Fin` — the reader dropped the upload
/// sender) half-closes the target write and returns Ok, so the target can keep
/// streaming back (the paired reader stays live).
async fn server_mux_upload_drain(
    mut upload_rx: mpsc::Receiver<Vec<u8>>,
    mut target_write: OwnedWriteHalf,
    stream_id: u32,
    cid: u64,
    write_timeout: Duration,
    frame_tx: &mpsc::Sender<MuxFrame>,
) -> Result<(), HandshakeServerError> {
    while let Some(payload) = upload_rx.recv().await {
        if payload.is_empty() {
            continue;
        }
        match timeout(write_timeout, target_write.write_all(&payload)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::debug!(cid, stream_id, "mux target write failed; resetting stream");
                let _ = send_server_mux_frame(frame_tx, stream_id, MuxFrameKind::Reset, Vec::new())
                    .await;
                return Err(HandshakeServerError::Io(err));
            }
            Err(_) => {
                tracing::debug!(cid, stream_id, "mux target write stalled; resetting stream");
                let _ = send_server_mux_frame(frame_tx, stream_id, MuxFrameKind::Reset, Vec::new())
                    .await;
                return Err(HandshakeServerError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mux target write stalled",
                )));
            }
        }
    }
    // Client Fin (upload sender dropped): half-close the target write half so the
    // target can keep streaming back; the paired reader remains live.
    let _ = target_write.shutdown().await;
    Ok(())
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
        fallback_idle_timeout(),
    );
    let ((), ()) = tokio::try_join!(reader, writer)?;
    Ok(())
}

/// Whether the TCP first record is the mux-over-QUIC mode signal: exactly one
/// zero-stream `Cover` frame and nothing else. The client emits precisely this to
/// say "I am multiplexing over QUIC bidis; expect no further TCP mux frames". Any
/// other shape (real `Open`/`Data` frames, extra frames) is NOT the signal, so the
/// server must stay on the TCP mux path and relay those frames rather than silently
/// dropping them by switching to QUIC.
fn is_mux_quic_signal(frames: &[MuxFrame]) -> bool {
    matches!(
        frames,
        [MuxFrame {
            stream_id: 0,
            kind: MuxFrameKind::Cover,
            ..
        }]
    )
}

/// Context for the mux-over-QUIC data mode: the per-substream key-derivation root
/// plus the target-resolution config. Mirrors the fields [`ServerMuxContext`] needs
/// that still apply when each substream is its own QUIC bidi (no shared frame
/// channel / cover / chunk plumbing — those are per-substream concerns here).
struct ServerMuxQuicContext<'a> {
    session_keys: &'a crate::crypto::session::SessionKeys,
    traffic: TrafficConfig,
    fixed_data_target: Option<&'a str>,
    cid: u64,
}

/// Mux-over-QUIC data mode: accept business substreams as QUIC bidis on the probed
/// connection and relay each independently (native multiplexing — no head-of-line
/// blocking). The TCP connection (`_client_records`/`_client_write`) is parked alive
/// for the session so the authenticated channel stays up; all relay traffic is on
/// QUIC. Each accepted bidi derives its own per-substream codec from the bidi's wire
/// stream id (matching the client), reads the `ConnectRequest` as its first record,
/// connects the target, and relays over the H3 DATA-frame legs.
///
/// A per-connection ceiling (`max_streams`) bounds concurrent substreams; excess
/// bidis are reset. The accept loop ends when the client closes the connection,
/// or when the whole-session idle backstop fires: `idle_timeout` (drawn from
/// [`fallback_idle_timeout`] by the production call site; injected so tests can
/// run the backstop on a short clock) bounds how long the session may sit with
/// zero admitted and zero live substreams before it is reclaimed.
async fn run_authenticated_mux_quic_data_mode(
    client_records: BufferedTlsRecordReader<OwnedReadHalf>,
    client_write: OwnedWriteHalf,
    probed: ServerProbedQuic,
    context: ServerMuxQuicContext<'_>,
    idle_timeout: Duration,
) -> Result<(), HandshakeServerError> {
    let ServerProbedQuic {
        conn,
        h3_control,
        mut relay_send,
        relay_recv,
    } = probed;
    // The probe bidi carried raw H3 probe DATA; the client does not reuse it, so
    // quiesce it (finish our send half, drop the recv half). Business substreams
    // arrive as fresh bidis below.
    relay_send.finish();
    drop(relay_recv);
    // Hold the H3 control set alive for the session's duration.
    let _h3_control = h3_control;

    // Bind the session lifetime to the parked TCP control connection: when the
    // client drops the mux session, its TCP read half hits EOF, and this watcher
    // closes the QUIC connection so the `accept_bi` loop below returns `None` and
    // the session ends. Per-substream teardown is independent (QUIC stream
    // FIN/RESET); this only governs the whole-session end. The write half is held
    // by the watcher too so the outer TCP connection stays open until then.
    let mut client_read = client_records.into_inner().into_inner();
    let watch_conn = conn.clone();
    let tcp_watch = tokio::spawn(async move {
        let _client_write = client_write;
        let mut buf = [0_u8; 1];
        // A real client sends no further TCP bytes after the mux-mode signal, so
        // any read result (EOF, a stray byte, or an error) ends the session.
        let _ = client_read.read(&mut buf).await;
        watch_conn.close(0u32.into(), b"mux-session-end");
    });

    let max_streams = (context.traffic.max_concurrent_streams as usize).min(SERVER_MUX_MAX_STREAMS);
    let live = Arc::new(Semaphore::new(max_streams));
    tracing::info!(
        cid = context.cid,
        "ParallaX mux-over-QUIC data mode started"
    );

    // Application-level idle backstop for the whole session, mirroring the
    // sibling relay modes (which all bound whole-relay silence with
    // `fallback_idle_timeout`). The QUIC connection's own idle timeout is NOT a
    // bound here: it is refreshed by ANY received packet, and keep-alive PINGs
    // keep both ends exchanging packets, so a client that ACKs keep-alives while
    // opening zero substreams (and sending zero TCP bytes to trip the watcher
    // above) would otherwise pin the connection, both fds, and the admission
    // permit forever. The clock resets ONLY when a substream is admitted; live
    // substreams defer expiry (each is bounded by its own idle watchdog, which
    // releases its permit on teardown, so a later expiry still reclaims the
    // session).
    let idle_sleep = sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    loop {
        let accepted = tokio::select! {
            accepted = conn.accept_bi() => accepted,
            _ = &mut idle_sleep => {
                if live.available_permits() < max_streams {
                    // Substreams are still relaying: the session is not idle.
                    idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                    continue;
                }
                tracing::debug!(
                    cid = context.cid,
                    "mux-over-QUIC session idle backstop reached; tearing down"
                );
                conn.close(RELAY_IDLE_CLOSE_CODE.into(), b"mux-idle");
                tcp_watch.abort();
                return Ok(());
            }
        };
        let Some((send, recv)) = accepted else {
            // The QUIC connection closed (client dropped the session, surfaced via
            // the TCP watcher, or a transport close): no further substreams.
            tcp_watch.abort();
            return Ok(());
        };
        let stream_id = recv.id();
        // Admission: cap concurrent substreams per connection. If full, reset the
        // excess bidi (release the client's slot) rather than queue it.
        let Ok(permit) = Arc::clone(&live).try_acquire_owned() else {
            let mut send = send;
            send.reset(crate::transport::udp::quic::endpoint::VarInt::from_u32(0));
            tracing::debug!(
                cid = context.cid,
                stream_id,
                "mux-over-QUIC substream cap reached; resetting bidi"
            );
            continue;
        };
        // An admitted substream is real client activity: reset the session idle
        // clock. (Rejected bidis deliberately do not.)
        idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
        let (client_open, server_seal) =
            match crate::transport::udp::quic::mux::server_substream_codecs(
                context.session_keys,
                context.traffic,
                stream_id,
            ) {
                Ok(codecs) => codecs,
                Err(err) => {
                    tracing::warn!(cid = context.cid, stream_id, error = %err, "substream codec derivation failed");
                    let mut send = send;
                    send.reset(crate::transport::udp::quic::endpoint::VarInt::from_u32(0));
                    continue;
                }
            };
        let traffic = context.traffic;
        let fixed_data_target = context.fixed_data_target.map(str::to_owned);
        let cid = context.cid;
        let substream_conn = conn.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = serve_mux_quic_substream(
                substream_conn,
                send,
                recv,
                client_open,
                server_seal,
                traffic,
                fixed_data_target.as_deref(),
                cid,
                stream_id,
            )
            .await
            {
                tracing::debug!(cid, stream_id, error = %err, "mux-over-QUIC substream ended");
            }
        });
    }
}

/// Relay one mux-over-QUIC substream: read the `ConnectRequest` first record off
/// the bidi (under the per-substream codec), connect the target, then run the
/// upload/download loops over the H3 DATA-frame legs. Teardown is per-stream: a
/// clean finish on the server's send half, a `RESET_STREAM` on error.
#[allow(clippy::too_many_arguments)]
async fn serve_mux_quic_substream(
    conn: crate::transport::udp::quic::endpoint::Connection,
    send: crate::transport::udp::quic::endpoint::SendStream,
    recv: crate::transport::udp::quic::endpoint::RecvStream,
    client_open: DataRecordCodec,
    server_seal: DataRecordCodec,
    traffic: TrafficConfig,
    fixed_data_target: Option<&str>,
    cid: u64,
    stream_id: u64,
) -> Result<(), HandshakeServerError> {
    // Any failure (a withheld/garbled ConnectRequest, a target-connect error, a
    // mid-relay fault, or an idle teardown) must RESET_STREAM so the peer sees a
    // prompt reset instead of waiting on the connection idle-timeout. The send half
    // is moved into the relay writer below, so reset by id via the connection. A
    // clean relay finish already FINs the stream inside the download loop, so the
    // reset on the Ok path is a no-op.
    let result = serve_mux_quic_substream_inner(
        send,
        recv,
        client_open,
        server_seal,
        traffic,
        fixed_data_target,
        cid,
        stream_id,
    )
    .await;
    // Reset unless the relay finished cleanly (`Ok(true)`): an error or an idle
    // teardown (`Ok(false)`) RESET_STREAMs so the peer recovers promptly.
    let clean_finish = matches!(result, Ok(true));
    if !clean_finish {
        conn.reset_stream(
            stream_id,
            crate::transport::udp::quic::endpoint::VarInt::from_u32(0),
        );
    }
    result.map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn serve_mux_quic_substream_inner(
    mut send: crate::transport::udp::quic::endpoint::SendStream,
    mut recv: crate::transport::udp::quic::endpoint::RecvStream,
    mut client_open: DataRecordCodec,
    server_seal: DataRecordCodec,
    traffic: TrafficConfig,
    fixed_data_target: Option<&str>,
    cid: u64,
    stream_id: u64,
) -> Result<bool, HandshakeServerError> {
    use crate::transport::udp::h3::{
        read_business_request_headers, write_business_response_headers,
    };

    let chunk_size = max_plaintext_len(traffic.max_padding);

    // A business bidi opens with a Safari-26 request HEADERS frame (browser-plausible
    // HTTP/3 request lifecycle) before its relay DATA frames. Read+validate it off
    // the raw recv BEFORE wrapping the rest of the stream in the DATA-frame de-framer.
    // BOUNDED by the same control-read timeout as the ConnectRequest below: a client
    // that opens a bidi but never sends HEADERS must not pin this task + its permit.
    match tokio::time::timeout(
        PX1_CONTROL_READ_TIMEOUT,
        read_business_request_headers(&mut recv),
    )
    .await
    {
        Ok(res) => res.map_err(HandshakeServerError::Io)?,
        Err(_) => {
            return Err(HandshakeServerError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "mux-over-QUIC substream request HEADERS read timed out",
            )));
        }
    }

    let mut client_reader = H3DataFrameLegReader::buffered(recv);

    // First record on the substream: the ConnectRequest (mirrors MuxFrame::Open).
    // BOUNDED: a client that opens a bidi but withholds its ConnectRequest would
    // otherwise pin this task + its admission permit indefinitely. Same bound the
    // TCP path's real-first-command read uses (`PX1_CONTROL_READ_TIMEOUT`).
    let mut first_record = Vec::new();
    match tokio::time::timeout(
        PX1_CONTROL_READ_TIMEOUT,
        client_reader.read_record_into(&mut first_record),
    )
    .await
    {
        Ok(res) => res.map_err(HandshakeServerError::Io)?,
        Err(_) => {
            return Err(HandshakeServerError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "mux-over-QUIC substream ConnectRequest read timed out",
            )));
        }
    }
    let first_range = client_open.open_in_place_payload_range(&mut first_record)?;
    let (target_addr, target_source, initial_payload) =
        resolve_connect_target(&mut first_record[first_range], fixed_data_target)?;
    let mut target = connect_outbound_target(&target_addr, target_source).await?;
    tune_tcp_stream(&target)?;
    if !initial_payload.is_empty() {
        target.write_all(initial_payload).await?;
        initial_payload.zeroize();
    }
    let (target_read, target_write) = target.into_split();

    // Answer with the `:status 200` response HEADERS frame before the download DATA
    // frames, completing the browser-plausible request/response lifecycle (the
    // client opened the bidi with request HEADERS). Sent only after the target
    // connect succeeds, mirroring a real origin emitting response headers once it
    // has something to serve.
    write_business_response_headers(&mut send)
        .await
        .map_err(HandshakeServerError::Io)?;

    let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
    let idle_timeout = fallback_idle_timeout();
    let timing = TimingProfile::from_config(traffic);
    let cover = CoverTrafficProfile::from_config(traffic);
    let target_buf = vec![0_u8; relay_read_buffer_len(chunk_size)];

    // Direction mapping mirrors the single-Connect QUIC relay: the bidi's recv is
    // client->server (upload to target), its send is server->client (download).
    let upload = server_upload_loop(
        client_reader,
        target_write,
        client_open,
        activity.clone(),
        cid,
        idle_timeout,
    );
    let download = server_download_loop(
        target_read,
        H3DataFrameLegWriter(send),
        server_seal,
        target_buf,
        timing,
        cover,
        activity.clone(),
        cid,
    );
    let relay = async { tokio::try_join!(upload, download) };
    let outcome = tokio::select! {
        joined = relay => Some(joined),
        _ = relay_idle_watchdog(activity, idle_timeout) => {
            tracing::debug!(cid, stream_id, "mux-over-QUIC substream idle backstop reached");
            None
        }
    };
    match outcome {
        // Both directions finished cleanly: the download loop already FINned the
        // send half. `true` => no reset needed.
        Some(Ok(_)) => Ok(true),
        // Idle teardown: the relay was forced down, so the caller resets the stream
        // (`false`) — a genuinely-idle substream has nothing left to drain.
        None => Ok(false),
        Some(Err(err)) => Err(err),
    }
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

    // #1 (shrink the residency window): the relay plaintext buffers are wrapped in
    // `Zeroizing` so every exit from this multi-`return` loop scrubs the relayed
    // plaintext on drop, rather than leaving it in a freed page. `client_record`/
    // `batch_plaintext` hold decrypted client->target plaintext; `batch_records`/
    // `extra_record` stage the ciphertext records opened in place, so they too
    // transit plaintext and are wiped. Drop-scrub keeps the hot loop body untouched
    // (no per-record zeroize). Best-effort: only the final buffer's live `[0..len)`
    // is wiped — reallocated-and-freed buffers and post-truncate capacity tails are
    // not scrubbed (tracked follow-up).
    let mut client_record = Zeroizing::new(Vec::new());
    let mut extra_record = Zeroizing::new(Vec::new());
    let mut batch_records = Zeroizing::new(Vec::new());
    let mut batch_plaintext = Zeroizing::new(Vec::new());
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
            // Drop finished tasks so a stream_id whose task just exited (target EOF /
            // idle) is not treated as a live duplicate below.
            streams.prune_finished();
            if streams.uploads.contains_key(&frame.stream_id)
                || streams.tasks.contains_key(&frame.stream_id)
            {
                reset_unregistered_stream(frame_tx, frame.stream_id).await?;
                return Ok(());
            }
            if streams.live_count() >= context.max_streams {
                // Per-connection substream ceiling reached: refuse the new stream
                // and do not spawn a supervisor (no outbound connection). The client
                // maps Reset to a ConnectionReset on that stream. Gating on live
                // tasks (each runs while EITHER direction is open) prevents a
                // Fin-then-Open loop from opening more than `max_streams` targets.
                tracing::debug!(
                    cid = context.cid,
                    stream_id = frame.stream_id,
                    max_streams = context.max_streams,
                    "mux stream cap reached; resetting"
                );
                reset_unregistered_stream(frame_tx, frame.stream_id).await?;
                return Ok(());
            }
            // Route this substream's client->target uploads over a BOUNDED channel to
            // its own supervisor task, which performs ALL per-destination blocking
            // work (resolve / connect / initial-payload write / relay) OFF this shared
            // reader. This is the fix: a slow/blackholed/unreachable target can no
            // longer head-of-line-block the carrier's other concurrent substreams —
            // the reader only ever `try_send`s upload frames and spawns the task.
            let (upload_tx, upload_rx) = mpsc::channel(SERVER_MUX_UPLOAD_CHANNEL);
            let stream_ctx = ServerMuxStreamContext {
                fixed_data_target: context.fixed_data_target.map(str::to_owned),
                timing: context.timing,
                chunk_size: context.chunk_size,
                cid: context.cid,
                target_write_timeout: context.target_write_timeout,
            };
            let stream_id = frame.stream_id;
            let handle = tokio::spawn(server_mux_upstream_task(
                stream_id,
                frame.payload.to_vec(),
                upload_rx,
                frame_tx.clone(),
                stream_ctx,
                payload_pool.clone(),
            ));
            streams.uploads.insert(stream_id, upload_tx);
            streams.tasks.insert(stream_id, handle);
        }
        MuxFrameKind::Data => {
            if !frame.payload.is_empty() {
                use tokio::sync::mpsc::error::TrySendError;
                // Route to the substream's upload channel with a NON-BLOCKING
                // `try_send` on the common path, so one slow local target never
                // head-of-line-blocks this shared reader. Decide the outcome while
                // borrowing the map (cloning the sender only for the rare full-channel
                // grace); apply any shed AFTER the borrow ends.
                enum UploadOutcome {
                    Delivered,
                    Shed,
                    Grace(mpsc::Sender<Vec<u8>>, Vec<u8>),
                }
                let outcome = match streams.uploads.get(&frame.stream_id) {
                    Some(sender) => match sender.try_send(frame.payload.to_vec()) {
                        Ok(()) => UploadOutcome::Delivered,
                        // Task gone (setup failed / relay ended): shed this stream.
                        Err(TrySendError::Closed(_)) => UploadOutcome::Shed,
                        // Full: the target is draining slower than this burst. Wait UP
                        // TO the grace for a slot instead of shedding at once.
                        Err(TrySendError::Full(payload)) => {
                            UploadOutcome::Grace(sender.clone(), payload)
                        }
                    },
                    // Unknown / already-Fin'd stream: ignore (matches half-close).
                    None => UploadOutcome::Delivered,
                };
                match outcome {
                    UploadOutcome::Delivered => {}
                    UploadOutcome::Shed => {
                        shed_server_mux_substream(streams, frame_tx, frame.stream_id).await?;
                    }
                    UploadOutcome::Grace(sender, payload) => {
                        match timeout(SERVER_MUX_STALL_RESET_GRACE, sender.send(payload)).await {
                            // Drained within the window: live-but-slow target.
                            Ok(Ok(())) => {}
                            // Task vanished while we waited.
                            Ok(Err(_)) => {
                                shed_server_mux_substream(streams, frame_tx, frame.stream_id)
                                    .await?;
                            }
                            // No slot freed for the whole window: a genuine stall.
                            Err(_) => {
                                tracing::debug!(
                                    cid = context.cid,
                                    stream_id = frame.stream_id,
                                    "mux upload stalled; resetting the stream"
                                );
                                shed_server_mux_substream(streams, frame_tx, frame.stream_id)
                                    .await?;
                            }
                        }
                    }
                }
            }
        }
        MuxFrameKind::Fin => {
            // Client is done sending on this stream: drop the upload sender so the
            // channel closes and the substream's task half-closes the target write
            // (the target can keep streaming back). The task (and its slot) stays live
            // until the target->client direction also finishes.
            streams.uploads.remove(&frame.stream_id);
        }
        MuxFrameKind::Reset => {
            // Full stream teardown: drop the upload sender AND abort the task so both
            // target fds are reclaimed immediately.
            streams.uploads.remove(&frame.stream_id);
            if let Some(handle) = streams.tasks.remove(&frame.stream_id) {
                handle.abort();
            }
        }
        MuxFrameKind::Cover => {}
    }
    Ok(())
}

/// Shed a single mux substream without disturbing the rest of the connection: drop
/// its upload sender, abort + drop its supervisor task (closing both target fds),
/// and tell the client to tear down that stream id with a Reset. Used when a
/// substream's upload channel stalls or its task has gone, so one bad target never
/// poisons the whole mux session.
async fn shed_server_mux_substream(
    streams: &mut ServerMuxStreams,
    frame_tx: &mpsc::Sender<MuxFrame>,
    stream_id: u32,
) -> Result<(), HandshakeServerError> {
    streams.uploads.remove(&stream_id);
    if let Some(handle) = streams.tasks.remove(&stream_id) {
        handle.abort();
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

/// Item #3b: bound every client-facing write. The batched writer does one
/// `write_records` await per drained batch; with no bound, an authenticated
/// client that stops reading wedges that write once its kernel receive buffer
/// fills, pinning this session, the 1024-deep frame channel, and every relayed
/// target fd for the life of the process (dropping the frame senders only wakes
/// `recv()`, never a task already parked in `write_records`). Mirror the client's
/// `client_mux_download_loop`: bound each write by the `idle` backstop (the
/// production caller passes [`fallback_idle_timeout`]) and SHED (tear the session
/// down) on expiry. A live-but-slow client keeps making progress well inside the
/// (600s-scale) window and is never falsely shed; `idle` is a parameter so the
/// wedge-shed path is testable without a 600s wait.
async fn server_mux_writer_loop<W>(
    mut client_write: W,
    mut server_seal: DataRecordCodec,
    mut frame_rx: mpsc::Receiver<MuxFrame>,
    cover: CoverTrafficProfile,
    cid: u64,
    payload_pool: MuxPayloadPool,
    idle: Duration,
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
            match timeout(
                idle,
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
                ),
            )
            .await
            {
                Ok(res) => res?,
                Err(_) => return Err(shed_mux_writer_on_stalled_client(cid)),
            }
        }
    }

    let mut cover_sleep = Box::pin(sleep(cover.sample_interval(&mut rng)));

    loop {
        tokio::select! {
            _ = &mut cover_sleep, if cover.is_enabled() => {
                match timeout(
                    idle,
                    write_server_mux_frame(
                        &mut client_write,
                        &mut server_seal,
                        MuxFrame { stream_id: 0, kind: MuxFrameKind::Cover, payload: Vec::new() },
                        &mut rng,
                        &mut seal_scratch,
                        cid,
                        "server-mux-cover-writer",
                    ),
                )
                .await
                {
                    Ok(res) => res?,
                    Err(_) => return Err(shed_mux_writer_on_stalled_client(cid)),
                }
                cover_sleep.as_mut().reset(Instant::now() + cover.sample_interval(&mut rng));
            }
            frame = frame_rx.recv() => {
                let Some(frame) = frame else {
                    let _ = client_write.shutdown().await;
                    return Ok(());
                };
                match timeout(
                    idle,
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
                    ),
                )
                .await
                {
                    Ok(res) => res?,
                    Err(_) => return Err(shed_mux_writer_on_stalled_client(cid)),
                }
            }
        }
    }
}

/// Item #3b: the shed outcome when the mux writer's client-facing write exceeds
/// the idle backstop (a non-reading authenticated client). Logs once and maps to
/// a `Timeout` error so the writer loop returns and `try_join!` tears the whole
/// session down, releasing the frame channel and every relayed target fd.
fn shed_mux_writer_on_stalled_client(cid: u64) -> HandshakeServerError {
    tracing::warn!(
        cid,
        "server mux client-write idle backstop elapsed; shedding session"
    );
    HandshakeServerError::Timeout
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

/// Shed a substream that failed setup before anything was registered for it
/// (duplicate id, stream cap, resolve/connect/tune failure, initial-payload
/// write failure). Enqueues an empty RESET for `stream_id`; the caller then
/// `return`s, dropping any half-built target. Centralizes the
/// `Reset + empty payload` shape every such arm repeats so they cannot drift.
async fn reset_unregistered_stream(
    frame_tx: &mpsc::Sender<MuxFrame>,
    stream_id: u32,
) -> Result<(), HandshakeServerError> {
    send_server_mux_frame(frame_tx, stream_id, MuxFrameKind::Reset, Vec::new()).await
}

/// Validate a speed request against the server's per-phase and aggregate ceilings.
/// Applied to EACH transport run (TCP and QUIC each send their own request).
fn validate_speed_request(
    request: &SpeedTestRequest,
    cid: u64,
) -> Result<(), HandshakeServerError> {
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
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_authenticated_speed_test_mode(
    mut client_records: BufferedTlsRecordReader<OwnedReadHalf>,
    mut client_write: OwnedWriteHalf,
    mut client_open: DataRecordCodec,
    mut server_seal: DataRecordCodec,
    request: SpeedTestRequest,
    chunk_size: usize,
    retained_quic: Option<ServerProbedQuic>,
    session_keys: &crate::crypto::session::SessionKeys,
    traffic: TrafficConfig,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    tracing::info!(
        cid,
        warmup_bytes = request.warmup_bytes,
        download_bytes = request.download_bytes,
        upload_bytes = request.upload_bytes,
        sample_count = request.sample_count,
        quic = retained_quic.is_some(),
        "ParallaX speed test mode started"
    );
    if chunk_size == 0 {
        drop_retained_quic(retained_quic);
        return Err(HandshakeServerError::DataRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0).into(),
        ));
    }
    // The TCP request was already decoded; reject (releasing QUIC) before measuring.
    if let Err(err) = validate_speed_request(&request, cid) {
        drop_retained_quic(retained_quic);
        return Err(err);
    }

    let mut rng = StdRng::from_entropy();
    let mut scratch = RelaySealScratch::with_payload_capacity(chunk_size);
    let batch_len = relay_read_buffer_len(chunk_size);
    let payload = vec![0xA5; batch_len];

    // TCP run: the request just decoded opens it.
    {
        let mut tcp_reader = TcpLegReader(client_records);
        let mut tcp_writer = TcpLegWriter(client_write);
        run_speed_phases_over_legs(
            &mut tcp_reader,
            &mut tcp_writer,
            &mut client_open,
            &mut server_seal,
            &mut rng,
            &mut scratch,
            &payload,
            &request,
            cid,
        )
        .await?;
        client_records = tcp_reader.0;
        client_write = tcp_writer.0;
    }

    // QUIC run: when the probe Verified, continue on the retained single-Connect
    // bidi. The client sends a fresh request on the bidi as the first record; we
    // read it, validate, and run the same phases — a fair same-stream comparison.
    if let Some(probed) = retained_quic {
        let ServerProbedQuic {
            conn,
            h3_control,
            relay_send,
            relay_recv,
        } = probed;
        let _h3_control = h3_control;
        // The QUIC run uses an INDEPENDENT codec derived from the bidi's stream id
        // (mux-over-QUIC mechanism), NOT the shared TCP-run codec: the two
        // transports' record/ack streams are not byte-symmetric, so a shared AEAD
        // sequence would desync. Both ends derive the same codec by stream id.
        let stream_id = relay_recv.id();
        let result = match crate::transport::udp::quic::mux::server_substream_codecs(
            session_keys,
            traffic,
            stream_id,
        ) {
            Ok((mut quic_open, mut quic_seal)) => {
                run_quic_speed_run(
                    &mut quic_open,
                    &mut quic_seal,
                    &mut rng,
                    &mut scratch,
                    &payload,
                    relay_send,
                    relay_recv,
                    chunk_size,
                    cid,
                )
                .await
            }
            Err(err) => Err(HandshakeServerError::Io(io::Error::other(err.to_string()))),
        };
        result?;
        // Race-free teardown over the RELIABLE TCP control connection (held alive on
        // both ends): read the client's DONE marker, which the client sends only
        // AFTER it has received the QUIC final ack. This proves nothing is in flight,
        // so closing the QUIC connection now cannot truncate a buffered ack. The DONE
        // continues the TCP-run's AEAD sequence on the shared codecs.
        let mut tcp_reader = TcpLegReader(client_records);
        let done = read_speed_tcp_done(&mut tcp_reader, &mut client_open, cid).await;
        client_records = tcp_reader.0;
        conn.close(0u32.into(), b"speed-done");
        done?;
    }

    // Keep the TCP control halves alive until here so the connection is not torn
    // down before the QUIC run + teardown complete.
    let _client_records = client_records;
    let _client_write = client_write;

    tracing::info!(cid, "ParallaX speed test mode finished");
    Ok(())
}

/// Read the client's speed QUIC-run DONE marker off the TCP control connection,
/// bounded by an absolute deadline so neither a vanished client nor an
/// empty-record trickle can pin the server.
async fn read_speed_tcp_done<R>(
    reader: &mut R,
    client_open: &mut DataRecordCodec,
    cid: u64,
) -> Result<(), HandshakeServerError>
where
    R: LegReader,
{
    let mut record = Vec::new();
    let mut consecutive_empty: u32 = 0;
    let mut total_empty: u64 = 0;
    // Absolute phase deadline: a per-read timeout is reset by every record
    // received, so a client trickling empty records just inside the backstop
    // could hold the teardown for MAX_CONSECUTIVE_EMPTY_UPLOAD_RECORDS *
    // backstop (~34 h). Anchoring one deadline before the loop bounds the WHOLE
    // wait regardless of how many records arrive (the upload phase's throughput
    // floor plays this role there; the DONE read carries no data to rate-check,
    // so a wall-clock bound is the equivalent backstop).
    let deadline = Instant::now() + QUIC_RELAY_DONE_BACKSTOP;
    loop {
        match timeout_at(deadline, reader.read_record_into(&mut record)).await {
            Ok(res) => res.map_err(HandshakeServerError::Io)?,
            Err(_) => {
                return Err(HandshakeServerError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "speed QUIC-run TCP DONE read timed out",
                )))
            }
        }
        let range = client_open.open_in_place_payload_range(&mut record)?;
        if range.is_empty() {
            // Padding-only record carries no progress. Bound how many may arrive
            // back-to-back so a client streaming only empty records cannot pin the
            // teardown (the same cap the upload phase applies).
            consecutive_empty += 1;
            if consecutive_empty > MAX_CONSECUTIVE_EMPTY_UPLOAD_RECORDS {
                return Err(HandshakeServerError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "speed QUIC-run TCP DONE sent too many consecutive empty records",
                )));
            }
            // Cumulative cap, mirroring the upload phase: counted across the whole
            // read and never reset, so no record interleaving can extend it.
            total_empty += 1;
            if total_empty > MAX_TOTAL_EMPTY_UPLOAD_RECORDS {
                return Err(HandshakeServerError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "speed QUIC-run TCP DONE sent too many empty records",
                )));
            }
            continue;
        }
        if &record[range] != SPEED_QUIC_DONE_MARKER {
            tracing::warn!(cid, "speed QUIC-run TCP DONE marker mismatch");
            return Err(HandshakeServerError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "speed QUIC-run TCP DONE marker mismatch",
            )));
        }
        return Ok(());
    }
}

/// Read + validate the QUIC run's opening request off the bidi, then run the speed
/// phases over the H3 DATA-frame legs (same protocol as TCP).
#[allow(clippy::too_many_arguments)]
async fn run_quic_speed_run(
    client_open: &mut DataRecordCodec,
    server_seal: &mut DataRecordCodec,
    rng: &mut StdRng,
    scratch: &mut RelaySealScratch,
    payload: &[u8],
    relay_send: crate::transport::udp::quic::endpoint::SendStream,
    relay_recv: crate::transport::udp::quic::endpoint::RecvStream,
    chunk_size: usize,
    cid: u64,
) -> Result<(), HandshakeServerError> {
    let mut quic_reader = H3DataFrameLegReader::buffered(relay_recv);
    let mut quic_writer = H3DataFrameLegWriter(relay_send);

    // The QUIC run's opening SpeedTestRequest, bounded so a client that opens the
    // bidi but withholds the request cannot pin this task.
    let mut request_record = Vec::new();
    match tokio::time::timeout(
        PX1_CONTROL_READ_TIMEOUT,
        quic_reader.read_record_into(&mut request_record),
    )
    .await
    {
        Ok(res) => res.map_err(HandshakeServerError::Io)?,
        Err(_) => {
            return Err(HandshakeServerError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "speed QUIC-run request read timed out",
            )))
        }
    }
    let range = client_open.open_in_place_payload_range(&mut request_record)?;
    if !SpeedTestRequest::has_magic(&request_record[range.clone()]) {
        return Err(HandshakeServerError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "speed QUIC-run first record is not a SpeedTestRequest",
        )));
    }
    let request = SpeedTestRequest::decode(&request_record[range])?;
    validate_speed_request(&request, cid)?;
    let _ = chunk_size; // chunk_size is the same as the TCP run's; payload reused.

    run_speed_phases_over_legs(
        &mut quic_reader,
        &mut quic_writer,
        client_open,
        server_seal,
        rng,
        scratch,
        payload,
        &request,
        cid,
    )
    .await?;
    // FIN our send half so the final ack is DELIVERED (quinn `finish` flushes
    // buffered data, unlike `close`). The deterministic teardown handshake then
    // happens over the reliable TCP control connection (see the caller), not on the
    // QUIC streams, so it is race-free.
    quic_writer.0.finish();
    Ok(())
}

/// The transport-agnostic speed measurement: warmup + sample sets in both
/// directions over a `LegReader`/`LegWriter` pair. Shared by the TCP and QUIC runs.
#[allow(clippy::too_many_arguments)]
async fn run_speed_phases_over_legs<Reader, Writer>(
    reader: &mut Reader,
    writer: &mut Writer,
    client_open: &mut DataRecordCodec,
    server_seal: &mut DataRecordCodec,
    rng: &mut StdRng,
    scratch: &mut RelaySealScratch,
    payload: &[u8],
    request: &SpeedTestRequest,
    cid: u64,
) -> Result<(), HandshakeServerError>
where
    Reader: LegReader,
    Writer: LegWriter,
{
    let mut io = SpeedServerIo {
        client_records: reader,
        client_write: writer,
        client_open,
        server_seal,
        rng,
        scratch,
        cid,
    };

    write_speed_download_phase(
        &mut io,
        payload,
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
            payload,
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
    Ok(())
}

struct SpeedServerIo<'a, Reader, Writer, R: ?Sized> {
    client_records: &'a mut Reader,
    client_write: &'a mut Writer,
    client_open: &'a mut DataRecordCodec,
    server_seal: &'a mut DataRecordCodec,
    rng: &'a mut R,
    scratch: &'a mut RelaySealScratch,
    cid: u64,
}

async fn write_speed_download_phase<Reader, Writer, R>(
    io: &mut SpeedServerIo<'_, Reader, Writer, R>,
    payload: &[u8],
    bytes: u64,
    ack: SpeedTestAck,
    idle: Duration,
) -> Result<(), HandshakeServerError>
where
    Reader: LegReader,
    Writer: LegWriter,
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
    // C6: band-shape the PX1*-done ack onto a CONNECT size band (reuses C3
    // shaping) instead of a tiny fixed control record. Keep the same idle stall
    // backstop the bulk download writes use.
    timeout(
        idle,
        write_server_control_frame_band_shaped(io.client_write, io.server_seal, &ack, io.rng),
    )
    .await
    .map_err(|_| HandshakeServerError::Timeout)?
}

async fn read_speed_upload_phase<Reader, Writer, R>(
    io: &mut SpeedServerIo<'_, Reader, Writer, R>,
    bytes: u64,
    ack: SpeedTestAck,
) -> Result<(), HandshakeServerError>
where
    Reader: LegReader,
    Writer: LegWriter,
    R: Rng + rand::RngCore + ?Sized,
{
    let mut uploaded = 0_u64;
    let mut consecutive_empty: u32 = 0;
    let mut total_empty: u64 = 0;
    // #1: speed-test upload carries throwaway measurement bytes, but wrap the
    // buffer in `Zeroizing` anyway so every relay-reader call site is uniformly
    // scrub-on-drop (the reader's internal buffer is already `Zeroizing`).
    let mut client_record = Zeroizing::new(Vec::new());
    let idle = fallback_idle_timeout();
    let phase_start = Instant::now();
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
            // Cumulative cap: the consecutive cap below is reset by any data
            // record, so an empty/1-byte alternation never trips it. Counting all
            // empty records across the phase bounds that interleaving too.
            total_empty += 1;
            if total_empty > MAX_TOTAL_EMPTY_UPLOAD_RECORDS {
                return Err(HandshakeServerError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "speed upload sent too many empty records",
                )));
            }
        } else {
            consecutive_empty = 0;
            if uploaded + len > bytes {
                return Err(HandshakeServerError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "speed upload sent more bytes than requested",
                )));
            }
            uploaded += len;
        }
        // Minimum-throughput floor: the empty-record caps above and the per-read
        // idle timeout can all be reset indefinitely by a slow data-record dribble,
        // so they do not bound the wall-clock slot hold. Past a startup grace,
        // require the average upload rate to stay above a floor far below any honest
        // speed test; a deliberate trickle trips this and is torn down. Evaluated
        // AFTER crediting this record's bytes (so a valid record that arrives just
        // past the grace boundary is not rejected on the stale prior total), and on
        // every record so a pure empty-record stall is caught too. Reuses the
        // existing InvalidData teardown shape (no new close behavior). This path is
        // reached only by an AUTHENTICATED peer, so it adds no externally probeable
        // signal.
        let elapsed = phase_start.elapsed();
        if elapsed > UPLOAD_RATE_GRACE {
            let active = elapsed - UPLOAD_RATE_GRACE;
            let floor = MIN_UPLOAD_BYTES_PER_SEC.saturating_mul(active.as_secs());
            if uploaded < floor {
                return Err(HandshakeServerError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "speed upload fell below the minimum throughput floor",
                )));
            }
        }
    }

    let ack = ack.encode();
    // C6: band-shape the PX1*-done ack onto a CONNECT size band (reuses C3 shaping).
    write_server_control_frame_band_shaped(io.client_write, io.server_seal, &ack, io.rng).await
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
    // #1 (shrink the residency window): this is the production client->target TCP
    // upload relay, so its plaintext buffers are `Zeroizing` to scrub on drop at
    // every exit, matching the mux relay loop and the reader's internal buffer.
    // `client_record`/`batch_plaintext` carry decrypted client->target plaintext;
    // `batch_records`/`extra_record` stage the ciphertext records opened in place.
    // Best-effort (same caveat as the mux loop): only the final buffer's live bytes
    // are wiped; reallocated/truncated remnants are not (tracked follow-up).
    let mut client_record = Zeroizing::new(Vec::new());
    // Scratch reused across iterations for the opportunistic batch-open path
    // (mirrors the mux reader): extra-record staging, concatenated records, and
    // concatenated plaintext.
    let mut extra_record = Zeroizing::new(Vec::new());
    let mut batch_records = Zeroizing::new(Vec::new());
    let mut batch_plaintext = Zeroizing::new(Vec::new());
    let mut deferred_read_error: Option<io::Error> = None;

    loop {
        match deferred_read_error.take() {
            Some(err) if client_records.is_clean_close(&err) => {
                let _ = target_write.shutdown().await;
                return Ok(client_open);
            }
            Some(err) => return Err(HandshakeServerError::Io(err)),
            None => match client_records.read_record_into(&mut client_record).await {
                Ok(()) => {}
                Err(err) if client_records.is_clean_close(&err) => {
                    let _ = target_write.shutdown().await;
                    return Ok(client_open);
                }
                Err(err) => return Err(HandshakeServerError::Io(err)),
            },
        }
        log_record_read(
            cid,
            "client->server",
            "server-data-client-reader",
            &client_record,
        );

        // Opportunistically drain any already-buffered records so a bulk burst is
        // opened across the crypto pool instead of pinning every open on this
        // task. A would-block (`None`) ends the drain with partial reader state
        // intact; a read error is deferred and surfaced on the next iteration,
        // after the records that did arrive have been relayed. The bytes written
        // to the target are identical to opening each record in order — only the
        // CPU placement of the AEAD changes.
        let mut record_count = 1_usize;
        batch_records.clear();
        let mut batch_bytes = client_record.len();
        while batch_bytes < MUX_OPEN_BATCH_BYTES {
            match client_records.try_read_record_into(&mut extra_record).await {
                None => break,
                Some(Ok(())) => {
                    log_record_read(
                        cid,
                        "client->server",
                        "server-data-client-reader",
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

        // Open the batch (or single record). The batch-open fans the AEAD across
        // the crypto pool, but the *write* below is deliberately re-split into
        // <= max_plaintext_len slices so each bounded write stays the same size as
        // the pre-batch per-record write (see the write loop's NOTE).
        let payload: &[u8] = if record_count == 1 {
            let range = client_open
                .open_in_place_payload_range(&mut client_record)
                .map_err(HandshakeServerError::DataRecord)?;
            &client_record[range]
        } else {
            batch_plaintext.clear();
            let payload_bytes =
                batch_records.len() - record_count * crate::tls::record::TLS_HEADER_LEN;
            if should_parallelize_aead(record_count, payload_bytes) {
                client_open
                    .open_concat_records_parallel(
                        parallel::global(),
                        &batch_records,
                        &mut batch_plaintext,
                    )
                    .map_err(HandshakeServerError::DataRecord)?;
            } else {
                client_open
                    .open_concat_records(&mut batch_records, &mut batch_plaintext)
                    .map_err(HandshakeServerError::DataRecord)?;
            }
            batch_plaintext.as_slice()
        };
        // Write in <= max_plaintext_len slices, each under its OWN idle_timeout
        // and bumping `activity` per slice. Records are sealed at most
        // max_plaintext_len of plaintext each, so a slice never splits a record;
        // it may coalesce several small adjacent records into one write, but every
        // write stays bounded by the same max_plaintext_len the pre-batch
        // per-record write was bounded by — so the per-write timeout budget is
        // unchanged. Wrapping the whole batch (up to MUX_OPEN_BATCH_BYTES) in a
        // single timeout would instead force a slow-but-alive target to absorb
        // ~1 MiB within one idle_timeout instead of ~16 KiB, tearing down
        // legitimately-progressing relays at aggressive (low but valid) idle
        // floors. NOTE: this per-write timeout reliably fires
        // only when the relay is otherwise progressing (the download direction
        // keeps bumping `activity`); in the pure "client keeps sending, target
        // accepts-then-stalls, no download traffic" case the shared idle-watchdog
        // (anchored to the last activity bump, hence an equal-or-earlier deadline)
        // wins the race and tears the relay down at the idle backstop. Either way
        // the connection is reclaimed within ~idle_timeout (the resource-pinning
        // DoS is closed); the residual is that in that narrow case the partial body
        // is FIN'd to the target rather than surfaced as a Timeout error — a
        // pre-existing behavior a fully deterministic fix would need to address by
        // distinguishing "stuck write" from "idle" in the watchdog.
        if !payload.is_empty() {
            let write_slice = client_open.max_plaintext_len().max(1);
            for slice in payload.chunks(write_slice) {
                timeout(idle_timeout, target_write.write_all(slice))
                    .await
                    .map_err(|_| HandshakeServerError::Timeout)??;
                bump_relay_activity(&activity);
            }
        }
    }
}

/// Drains the server->client direction (target response) into the client leg.
/// Returns the owned `server_seal` codec on a clean finish so the QUIC
/// fast-plane teardown can seal the local DONE marker on the SAME send-direction
/// codec (sequence continues uninterrupted). TCP-path callers discard it.
///
/// No-RST teardown (item #1): this thin wrapper owns the client-facing (censor-
/// facing) write half and FINs it on ANY mid-relay error. The inner relay's
/// clean-EOF paths already `shutdown()` their write half; before this, a mid-relay
/// `?` bare-dropped `client_write`, which for the QUIC fast-plane leg
/// (`H3DataFrameLegWriter` over a quinn `SendStream`) emits a `RESET_STREAM`
/// (the QUIC analog of an RST / a visible truncation) instead of a clean stream
/// finish. FIN-ing on error (mirroring `client_mux_download_loop` and
/// `graceful_fin_then_drain`) turns that abrupt reset into a clean half-close on
/// the error path too. (On the concrete TCP leg tokio's `OwnedWriteHalf` already
/// FINs on drop, so there the explicit FIN just makes the send prompt/explicit.)
#[allow(clippy::too_many_arguments)]
async fn server_download_loop<W>(
    target_read: OwnedReadHalf,
    mut client_write: W,
    server_seal: DataRecordCodec,
    target_buf: Vec<u8>,
    timing: TimingProfile,
    cover: CoverTrafficProfile,
    activity: RelayActivity,
    cid: u64,
) -> Result<DataRecordCodec, HandshakeServerError>
where
    W: LegWriter,
{
    let result = server_download_relay(
        target_read,
        &mut client_write,
        server_seal,
        target_buf,
        timing,
        cover,
        activity,
        cid,
    )
    .await;
    if result.is_err() {
        // FIN the censor-facing write half before propagating so teardown is a
        // clean half-close, not an abrupt reset (see the fn doc). Best-effort:
        // the relay is already failing, so a shutdown error is not actionable.
        let _ = client_write.shutdown().await;
    }
    result
}

/// The actual server->client relay body. Borrows the client-facing write half so
/// [`server_download_loop`] retains ownership to FIN it on error; every clean-EOF
/// path here still `shutdown()`s it directly (so the wrapper never double-FINs).
#[allow(clippy::too_many_arguments)]
async fn server_download_relay<W>(
    mut target_read: OwnedReadHalf,
    client_write: &mut W,
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
    // Default hot path: no cover traffic and no timing jitter. Read-ahead pipeline
    // the next source read against the in-flight client write so a high-BDP link
    // keeps draining the origin socket while `write_records` is throttled by
    // TCP_NOTSENT_LOWAT/cwnd.
    //
    // Covertness gate: read-ahead is engaged ONLY while the source is saturating
    // the whole read buffer (`drain_ready_tcp_read` filled it to capacity). When
    // the source is saturated the serial path ALSO reads full buffer -> full
    // buffer, so concurrently prefetching the next burst does not change the burst
    // segmentation (hence not the record-size/count histogram): both paths chunk a
    // full buffer into the same `ceil(cap/max_chunk)` records. A non-full burst
    // (short flow, interactive traffic, the tail of a transfer) takes the serial
    // write below and is NOT prefetched, so its segmentation is byte-for-byte the
    // serial path's. This confines the pipeline to exactly the saturated-bulk case
    // it targets, where it is segmentation-equivalent, and avoids the "prefetch
    // drains the source earlier -> smaller, more numerous bursts" distribution
    // drift a buffer-unconditional prefetch would introduce. The seal always runs
    // to completion before the concurrent read, so the codec stays strictly
    // sequential. Timing jitter (opt-in) keeps the original serial loop so its
    // per-burst delay cadence is untouched.
    if !cover.is_enabled() && !timing.is_enabled() {
        let cap = target_buf.len();
        // Spare buffers for the pipeline, allocated lazily on the first full-buffer
        // burst: a short flow that never saturates the buffer never pays the extra
        // ~256 KiB read buffer + seal scratch.
        let mut spare_buf: Option<Vec<u8>> = None;
        let mut spare_scratch: Option<RelaySealScratch> = None;

        // Prime: read the first burst.
        let mut n = target_read.read(&mut target_buf).await?;
        if n == 0 {
            let _ = client_write.shutdown().await;
            return Ok(server_seal);
        }
        bump_relay_activity(&activity);
        n = drain_ready_tcp_read(&target_read, &mut target_buf, n)?;

        loop {
            // Seal the current burst into `seal_scratch` (sequential; codec state
            // advances here, never inside the concurrent read below).
            seal_server_data_records_chunked(
                &mut server_seal,
                &target_buf[..n],
                &mut rng,
                &mut seal_scratch,
                RelayWriteLog::new(cid, "server->client", "server-download-writer"),
            )?;

            if n == cap {
                #[cfg(test)]
                DOWNLOAD_READ_AHEAD_ENGAGED.fetch_add(1, Ordering::Relaxed);
                // Saturated bulk: overlap the flush of this batch with reading the
                // next burst into the spare buffer (lazily allocated). The borrows
                // are disjoint (write: `client_write` + `seal_scratch.records_buf`;
                // read: `target_read` + `spare`), so neither aliases the codec. The
                // helper finishes the write before surfacing any read result; only a
                // write that completes FIRST with an error cancels the still-pending
                // read, matching the serial path's "write error before next read"
                // order (a read error never cancels the in-flight write).
                let spare = spare_buf.get_or_insert_with(|| vec![0_u8; cap]);
                let next_n = write_batch_with_read_ahead(
                    &mut *client_write,
                    seal_scratch.records_buf.as_slice(),
                    target_read.read(spare),
                )
                .await?;
                if next_n == 0 {
                    let _ = client_write.shutdown().await;
                    return Ok(server_seal);
                }
                bump_relay_activity(&activity);
                let next_n = drain_ready_tcp_read(&target_read, spare, next_n)?;

                // Swap: the just-read spare becomes the current burst; the
                // just-written scratch becomes the spare seal buffer.
                let scratch_slot = spare_scratch
                    .get_or_insert_with(|| RelaySealScratch::with_payload_capacity(cap));
                std::mem::swap(&mut target_buf, spare_buf.as_mut().unwrap());
                std::mem::swap(&mut seal_scratch, scratch_slot);
                n = next_n;
            } else {
                // Non-saturated burst: write serially (no prefetch), so this burst's
                // segmentation is identical to the pure serial loop. Then read the
                // next burst serially too.
                client_write
                    .write_records(seal_scratch.records_buf.as_slice())
                    .await?;
                let next_n = target_read.read(&mut target_buf).await?;
                if next_n == 0 {
                    let _ = client_write.shutdown().await;
                    return Ok(server_seal);
                }
                bump_relay_activity(&activity);
                n = drain_ready_tcp_read(&target_read, &mut target_buf, next_n)?;
            }
        }
    }

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
                &mut *client_write,
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
                    &mut *client_write,
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
                    &mut *client_write,
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

/// Seal a fixed-length server->client in-band control frame (C4 PX1O offer /
/// PX1N decline; C6 the PX1W/PX1V/PX1D/PX1U speed acks) onto a randomly chosen
/// CONNECT size band, instead of its tiny fixed wire size. Reuses the CONNECT
/// (C3) shaping primitives: `control_frame_shaping_pad` picks the band, and
/// `seal_into_exact_padded` writes EXACTLY that pad while bypassing the codec's
/// profile sampling so the record lands on its band even under a non-default
/// padding profile. The pad rides the self-describing 2-byte trailer, so the
/// client decodes the exact `payload` unchanged.
fn seal_control_frame_band_shaped<R>(
    codec: &mut DataRecordCodec,
    payload: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, HandshakeServerError>
where
    R: rand::Rng + rand::RngCore + ?Sized,
{
    let max_extra_pad = codec.max_plaintext_len().saturating_sub(payload.len());
    let shaping_pad =
        crate::protocol::command::control_frame_shaping_pad(payload.len(), max_extra_pad, rng);
    let mut out = Vec::new();
    codec.seal_into_exact_padded(payload, shaping_pad, rng, &mut out)?;
    Ok(out)
}

/// Band-shape a single server->client control frame (the C6 PX1W/PX1V/PX1D/PX1U
/// speed acks) and write it out as one record. Used in place of
/// [`write_server_data_records_chunked`] for the speed-test acks specifically, so
/// the tiny fixed-length ack lands on a CONNECT size band instead of a constant
/// tiny record; the bulk speed payload keeps using the chunked writer unchanged.
async fn write_server_control_frame_band_shaped<W, R>(
    writer: &mut W,
    codec: &mut DataRecordCodec,
    payload: &[u8],
    rng: &mut R,
) -> Result<(), HandshakeServerError>
where
    W: LegWriter,
    R: rand::Rng + rand::RngCore + ?Sized,
{
    let record = seal_control_frame_band_shaped(codec, payload, rng)?;
    writer.write_records(record.as_slice()).await?;
    Ok(())
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
    seal_server_data_records_chunked(codec, payload, rng, scratch, log)?;
    writer.write_records(scratch.records_buf.as_slice()).await?;
    Ok(())
}

/// Seal `payload` into `scratch.records_buf` (clearing it first) using the same
/// chunking, parallel-AEAD, and debug-logging policy as
/// [`write_server_data_records_chunked`], but WITHOUT writing. Splitting the seal
/// from the write lets the bulk download loop overlap the next source read with
/// the in-flight client write (read-ahead pipelining): the codec stays strictly
/// sequential (this runs to completion before any concurrent read), so record
/// boundaries, sequence order, padding distribution, and the on-wire byte stream
/// are unchanged.
fn seal_server_data_records_chunked<R>(
    codec: &mut DataRecordCodec,
    payload: &[u8],
    rng: &mut R,
    scratch: &mut RelaySealScratch,
    log: RelayWriteLog,
) -> Result<(), HandshakeServerError>
where
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
        // Fan the bulk seal across the crypto pool when the batch clears the
        // parallel threshold. The parallel path produces the SAME record
        // boundaries and advances the sequence counter identically to the serial
        // path, and each record's padding length is drawn from the identical
        // per-record distribution (`sample_padding_len` is a pure per-record draw),
        // so on-wire record sizes and the size/count histogram are unchanged.
        // NOTE: the two paths consume the RNG differently (the parallel path
        // re-seeds a per-group StdRng), so the concrete padding BYTES are not
        // bit-identical to the serial path for the same starting RNG — they are
        // only distributionally equivalent. That is fine because seal output is
        // written exactly once (no re-seal/resume relies on byte-identity). Small
        // batches stay on the low-latency serial path.
        let record_count = payload.len().div_ceil(max_chunk_len).max(1);
        if should_parallelize_aead(record_count, payload.len()) {
            codec.seal_chunks_into_parallel(
                parallel::global(),
                payload,
                rng,
                &mut scratch.records_buf,
            )?;
        } else {
            codec.seal_chunks_into_untracked(payload, rng, &mut scratch.records_buf)?;
        }
    }
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

impl Drop for RelaySealScratch {
    /// Wipe the relay plaintext on teardown (#1, shrink the residency window).
    /// `plaintext_buf` accumulates frame-aligned relay plaintext before sealing
    /// and `records_buf` holds the staged (plaintext-then-sealed) record bytes; a
    /// bare `Vec` drop only frees, it does not scrub, leaving relay plaintext in a
    /// freed page until the allocator reuses it. Zeroizing at scratch teardown (one
    /// call per relay, NOT per record) keeps the hot seal path untouched while
    /// denying a post-relay scrape the final buffers' plaintext. Best-effort: wipes
    /// the live `[0..len)` only — buffers reallocated as the session grew were freed
    /// un-scrubbed, so this is residency reduction, not a guarantee every byte is
    /// gone. `records`/`record_lens` are offset/length bookkeeping, not secret.
    fn drop(&mut self) {
        self.plaintext_buf.zeroize();
        self.records_buf.zeroize();
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

    #[test]
    fn mux_quic_signal_accepts_only_lone_zero_stream_cover() {
        let cover = |sid: u32| MuxFrame {
            stream_id: sid,
            kind: MuxFrameKind::Cover,
            payload: Vec::new(),
        };
        let open = MuxFrame {
            stream_id: 1,
            kind: MuxFrameKind::Open,
            payload: b"connect".to_vec(),
        };

        // The canonical signal: exactly one zero-stream Cover frame.
        let lone_cover = vec![cover(0)];
        assert!(is_mux_quic_signal(&lone_cover));

        // Anything else must NOT be treated as the QUIC mux signal (so the server
        // stays on TCP mux and never silently drops real frames):
        let empty: Vec<MuxFrame> = Vec::new();
        let lone_open = vec![open.clone()];
        let cover_plus_open = vec![cover(0), open];
        let two_covers = vec![cover(0), cover(0)];
        assert!(!is_mux_quic_signal(&empty), "empty is not the signal");
        assert!(
            !is_mux_quic_signal(&lone_open),
            "a real Open is not the signal"
        );
        assert!(
            !is_mux_quic_signal(&cover_plus_open),
            "Cover plus a real frame is not the signal"
        );
        assert!(
            !is_mux_quic_signal(&two_covers),
            "two frames are not the signal"
        );
    }

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
        let payload = vec![0x42_u8; 4096];
        let mut rng = StdRng::seed_from_u64(103);
        let max_chunk =
            crate::protocol::command::pq_flight_max_chunk_size(server_seal.max_plaintext_len());
        let chunks =
            ServerIdentityChunk::encode_all_browser_shaped(&payload, max_chunk, &mut rng).unwrap();
        let expected_chunks = chunks.clone();
        let mut writer = CountingWriter::default();

        write_server_identity_chunks(&mut writer, &mut server_seal, chunks, &mut rng, timing, 7)
            .await
            .unwrap();

        // Speed-first (timing disabled) path batches the whole identity flight into a
        // single write; the per-record padding (incl. the aggregate decorrelation pad
        // on the last record) is stripped transparently by client_open, so the opened
        // chunks equal the FramedChunk records that went in.
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

    // ====================================================================
    // dudect-style constant-time WALL-CLOCK proof of the inbound-reject path.
    //
    // The REJECT_DH_OPS counter tests above prove the X25519 OP COUNT is
    // input-independent (exactly 2 per reject shape). That is necessary but NOT
    // sufficient: it cannot see a data-dependent branch, cache pattern, or
    // memcmp/HKDF/HMAC timing step that runs *within* a fixed op count. This
    // section is the load-bearing measurement that closes that gap.
    //
    // Method (after Reparaz/Balasch/Verbauwhede, "Dude, is my code constant
    // time?", DATE 2017): for each ordered pair of reject shapes we collect
    // ~1e5–1e6 paired latency samples, accumulate them ONLINE (Welford — O(1)
    // memory, no million-element vectors), and compute a Welch two-sample
    // t-statistic. Per dudect we also evaluate a percentile-CROPPED variant that
    // discards the slow tail (scheduler/IRQ outliers that swamp the real signal)
    // and take the most significant |t| across crops.
    //
    // The gate is SELF-CALIBRATED: alongside every cross-shape pair we measure a
    // same-shape control (shape vs itself, two independent interleaved streams).
    // The control's |t| is the statistical noise floor of THIS run on THIS
    // runner. A cross-shape |t| is a real distinguisher only if it materially
    // exceeds the control. An absolute dudect floor (T_ABS) backstops the case
    // where the control itself is pathologically large. This is what makes the
    // test a hard gate that survives shared CI runners instead of an advisory.
    // ====================================================================

    /// Online (Welford) accumulator: streaming mean + variance over an unbounded
    /// number of samples in O(1) memory. Used so the t-test never materialises a
    /// million-element vector per shape.
    #[cfg(test)]
    #[derive(Clone, Default)]
    struct WelfordAcc {
        n: u64,
        mean: f64,
        m2: f64,
    }

    #[cfg(test)]
    impl WelfordAcc {
        fn push(&mut self, x: f64) {
            self.n += 1;
            let delta = x - self.mean;
            self.mean += delta / self.n as f64;
            let delta2 = x - self.mean;
            self.m2 += delta * delta2;
        }
        /// Sample variance (n-1 denominator). 0.0 if fewer than 2 samples.
        fn variance(&self) -> f64 {
            if self.n < 2 {
                0.0
            } else {
                self.m2 / (self.n - 1) as f64
            }
        }
    }

    /// Welch's two-sample t-statistic for unequal variances/sizes:
    ///   t = (mean_a - mean_b) / sqrt(var_a/n_a + var_b/n_b)
    /// Returns 0.0 when the pooled standard error is zero (degenerate/identical
    /// constant streams) so the caller's |t| comparison stays well-defined.
    #[cfg(test)]
    fn welch_t(a: &WelfordAcc, b: &WelfordAcc) -> f64 {
        if a.n < 2 || b.n < 2 {
            return 0.0;
        }
        let se2 = a.variance() / a.n as f64 + b.variance() / b.n as f64;
        if se2 <= 0.0 {
            return 0.0;
        }
        (a.mean - b.mean) / se2.sqrt()
    }

    /// META-TEST (deterministic teeth for the t-statistic itself): Welch's t must
    /// be ~0 for two draws of the same distribution and large for a clearly
    /// shifted one. Pure arithmetic on synthetic data — fast, never flaky — so a
    /// green dudect result below is not resting on a broken statistic.
    #[test]
    fn welch_t_statistic_is_non_vacuous() {
        // Two interleaved halves of one ramp: same mean -> |t| small.
        let (mut a, mut a2) = (WelfordAcc::default(), WelfordAcc::default());
        for i in 0..2000u64 {
            let x = 1000.0 + (i % 11) as f64;
            if i % 2 == 0 {
                a.push(x);
            } else {
                a2.push(x);
            }
        }
        let same = welch_t(&a, &a2).abs();
        assert!(
            same < 4.5,
            "same-distribution |t| must be small, got {same}"
        );

        // A shifted distribution (+50, same spread, same n) -> |t| huge.
        let (mut lo, mut hi) = (WelfordAcc::default(), WelfordAcc::default());
        for i in 0..2000u64 {
            lo.push(1000.0 + (i % 11) as f64);
            hi.push(1050.0 + (i % 11) as f64);
        }
        let shifted = welch_t(&lo, &hi).abs();
        assert!(
            shifted > 50.0,
            "a clear mean shift must produce a large |t|, got {shifted}"
        );
    }

    /// Self-calibrated Welch |t| ceiling for the dudect gate (item #4): the largest
    /// cross-shape |t| tolerated, given the SAME-run same-shape control |t| that is
    /// the per-runner statistical noise floor. Structured exactly like the physical
    /// mean-gap gate (`max(FLOOR, MULT × control)`):
    ///
    ///   allow = max(t_abs, t_mult × t_ctrl)
    ///
    /// This is what makes gating |t| robust despite |t| ∝ √n: cross and control are
    /// measured together at the SAME sample count in the SAME interleaved loop, so
    /// the √n inflation hits both equally and cancels in the ratio. A real
    /// data-dependent distinguisher (the µs-scale asymmetry this test exists to
    /// catch) blows the cross |t| into the thousands+ — orders of magnitude past the
    /// control — while the already-bounded sub-µs SNI-length residue keeps the cross
    /// |t| in the control's neighbourhood. The `t_abs` floor keeps the gate from
    /// tripping on pure ratio noise when the control |t| happens to be tiny.
    #[cfg(test)]
    fn dudect_t_allow(t_ctrl: f64, t_abs: f64, t_mult: f64) -> f64 {
        t_abs.max(t_mult * t_ctrl)
    }

    /// META-TEST (deterministic teeth for the |t| GATE itself, item #4): proves the
    /// self-calibrated |t| ceiling is non-vacuous — it REJECTS a gross statistical
    /// distinguisher (the kind a µs-scale timing regression produces) yet ACCEPTS a
    /// residue whose |t| tracks the control, and widens with a noisy control so it
    /// cannot false-positive on per-runner jitter. Pure arithmetic, never flaky, and
    /// compiled in every test build (not behind `--features dudect`), so the gate
    /// logic is guarded even when the slow measurement job does not run.
    #[test]
    fn dudect_t_gate_is_non_vacuous() {
        // The production defaults used by the dudect test below.
        let (t_abs, t_mult) = (1_000.0_f64, 10.0_f64);

        // A real distinguisher: cross |t| in the thousands against a quiet control
        // MUST be rejected (this is the µs-scale regression signature).
        let regression_t_cross = 6_000.0;
        let quiet_ctrl = 8.0;
        assert!(
            regression_t_cross > dudect_t_allow(quiet_ctrl, t_abs, t_mult),
            "a µs-scale distinguisher (|t| in the thousands) must exceed the gate"
        );

        // A constant-time-but-not-perfect residue: cross |t| a few tens, tracking a
        // similar control, MUST be accepted (no false positive on the SNI residue).
        assert!(
            45.0 <= dudect_t_allow(20.0, t_abs, t_mult),
            "a sub-µs residue whose |t| tracks the control must be within the gate"
        );

        // Self-calibration: a pathologically noisy control widens the allowance so a
        // proportionally-noisy cross does not trip purely on per-runner jitter.
        assert!(
            1_500.0 <= dudect_t_allow(200.0, t_abs, t_mult),
            "the gate must scale with the control noise floor (t_mult × t_ctrl)"
        );

        // Non-vacuous floor: when the control |t| is ~0, the absolute floor (not an
        // ill-defined ratio) is what bounds the cross |t| — and it is finite, so a
        // huge cross |t| is still caught.
        assert_eq!(
            dudect_t_allow(0.0, t_abs, t_mult),
            t_abs,
            "with a ~0 control the absolute floor governs the gate"
        );
        assert!(
            10_000.0 > dudect_t_allow(0.0, t_abs, t_mult),
            "the absolute floor must still reject a gross |t| when the control is ~0"
        );
    }

    /// Time a single `decide_connection_inbound` reject in nanoseconds. The result
    /// is discarded; only the latency matters. Marked #[inline(never)] so the
    /// optimiser cannot hoist or fold the call out of the timing loop.
    #[cfg(all(test, feature = "dudect"))]
    #[inline(never)]
    fn time_one_reject(record: &[u8], server_priv: &[u8; 32]) -> u64 {
        use std::time::Instant;
        let start = Instant::now();
        let decision =
            decide_connection_inbound(record, PSK, &[String::from("example.com")], server_priv);
        // Consume the result through a black box so it is observably used.
        std::hint::black_box(&decision);
        start.elapsed().as_nanos() as u64
    }

    /// dudect crop levels: keep the fastest P% of samples, discarding the slow
    /// tail where scheduler/IRQ noise dwarfs the (sub-ns) real signal. 100% = no
    /// crop. We report the most significant |t| across all crops, as dudect does.
    #[cfg(all(test, feature = "dudect"))]
    const DUDECT_CROPS: &[u64] = &[100, 90, 70, 50, 30];

    /// Run the dudect measurement for ONE ordered pair of byte records. Returns
    /// `(t_cross, t_control)`:
    ///   * `t_cross`   = max over crops of |Welch t(stream of `a`, stream of `b`)|
    ///   * `t_control` = max over crops of |Welch t(two interleaved streams of `a`)|
    ///
    /// Both are measured in the SAME interleaved loop so environmental drift hits
    /// them equally; the control is the per-run noise floor the gate calibrates
    /// against. Sampling order within each round is permuted by a deterministic,
    /// seeded RNG (dudect randomises class order to defeat systematic per-slot
    /// bias) — deterministic so the test is reproducible without wall-clock RNG.
    #[cfg(all(test, feature = "dudect"))]
    fn dudect_pair(a: &[u8], b: &[u8], server_priv: &[u8; 32], samples: usize) -> DudectPair {
        // Per-crop accumulators. Index 0 of each tuple is the "a"/"control-a"
        // stream, index 1 is the "b"/"control-a2" stream.
        let crops = DUDECT_CROPS.len();
        let mut cross: Vec<(WelfordAcc, WelfordAcc)> = vec![Default::default(); crops];
        let mut ctrl: Vec<(WelfordAcc, WelfordAcc)> = vec![Default::default(); crops];

        // Pass 1: warm caches/branch predictor for BOTH shapes and estimate the
        // per-crop latency cutoff from the combined a+b distribution, so cropping
        // is data-driven rather than a magic constant. A small reservoir keeps
        // this O(1)-ish without storing every warm-up sample.
        let warm = (samples / 20).clamp(2_000, 50_000);
        let mut reservoir: Vec<u64> = Vec::with_capacity(warm * 2);
        for _ in 0..warm {
            reservoir.push(time_one_reject(a, server_priv));
            reservoir.push(time_one_reject(b, server_priv));
        }
        reservoir.sort_unstable();
        // cutoff[c] = the P-th percentile latency for crop DUDECT_CROPS[c].
        let cutoffs: Vec<u64> = DUDECT_CROPS
            .iter()
            .map(|&p| {
                if p >= 100 {
                    u64::MAX
                } else {
                    let idx = ((reservoir.len() as u64 * p) / 100) as usize;
                    reservoir[idx.min(reservoir.len() - 1)]
                }
            })
            .collect();

        // Deterministic xorshift64* — seeded constant, no wall-clock entropy, so
        // the permutation of measurement order is reproducible across runs.
        let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next_bit = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng & 1 == 1
        };

        // Pass 2: interleaved paired sampling. Each round measures, in a
        // randomised order, one sample of `a` and one of `b` for the cross test,
        // plus two further independent `a` samples for the control. Feeding each
        // latency into every crop whose cutoff it satisfies.
        let feed = |accs: &mut [(WelfordAcc, WelfordAcc)], cutoffs: &[u64], slot: usize, x: u64| {
            for (acc, &cut) in accs.iter_mut().zip(cutoffs.iter()) {
                if x <= cut {
                    if slot == 0 {
                        acc.0.push(x as f64);
                    } else {
                        acc.1.push(x as f64);
                    }
                }
            }
        };

        for _ in 0..samples {
            // Cross pair: randomise whether `a` or `b` is timed first this round.
            if next_bit() {
                let xa = time_one_reject(a, server_priv);
                let xb = time_one_reject(b, server_priv);
                feed(&mut cross, &cutoffs, 0, xa);
                feed(&mut cross, &cutoffs, 1, xb);
            } else {
                let xb = time_one_reject(b, server_priv);
                let xa = time_one_reject(a, server_priv);
                feed(&mut cross, &cutoffs, 1, xb);
                feed(&mut cross, &cutoffs, 0, xa);
            }
            // Control pair: two independent `a` streams, same randomisation.
            if next_bit() {
                let c0 = time_one_reject(a, server_priv);
                let c1 = time_one_reject(a, server_priv);
                feed(&mut ctrl, &cutoffs, 0, c0);
                feed(&mut ctrl, &cutoffs, 1, c1);
            } else {
                let c1 = time_one_reject(a, server_priv);
                let c0 = time_one_reject(a, server_priv);
                feed(&mut ctrl, &cutoffs, 1, c1);
                feed(&mut ctrl, &cutoffs, 0, c0);
            }
        }

        let max_abs_t = |accs: &[(WelfordAcc, WelfordAcc)]| -> f64 {
            accs.iter()
                .map(|(x, y)| welch_t(x, y).abs())
                .fold(0.0_f64, f64::max)
        };
        // Absolute mean-latency gap (ns) on the UNCROPPED (crop 100%, index 0)
        // accumulators — the physical effect size, used as the second gate. Unlike
        // |t| (which ∝ √n and flags sub-ns structure at scale), this is invariant
        // to sample count, so it cleanly separates a µs-scale regression from the
        // sub-µs SNI-length residue.
        let mean_gap_ns = |accs: &[(WelfordAcc, WelfordAcc)]| -> f64 {
            let (a, b) = &accs[0];
            (a.mean - b.mean).abs()
        };
        DudectPair {
            t_cross: max_abs_t(&cross),
            t_ctrl: max_abs_t(&ctrl),
            mean_gap_cross_ns: mean_gap_ns(&cross),
            mean_gap_ctrl_ns: mean_gap_ns(&ctrl),
        }
    }

    /// Result of one `dudect_pair` measurement: the self-calibrated Welch |t|
    /// (statistical, √n-sensitive) and the absolute mean-latency gap in ns
    /// (physical effect size, sample-count-invariant), each with its same-shape
    /// control counterpart for self-normalisation.
    #[cfg(all(test, feature = "dudect"))]
    struct DudectPair {
        t_cross: f64,
        t_ctrl: f64,
        mean_gap_cross_ns: f64,
        mean_gap_ctrl_ns: f64,
    }

    /// LOAD-BEARING constant-time gate. For all three ordered pairs of the three
    /// attacker-reachable parseable reject shapes (no-key_share `B`,
    /// key_share+recover==None `R`, key_share+auth-fail `D`), the cross-shape
    /// latency must be indistinguishable from a same-shape control on BOTH a
    /// physical effect-size measure (absolute mean-latency gap, ns) AND a
    /// statistical measure (self-calibrated Welch |t|). A real data-dependent
    /// timing distinguisher between reject shapes turns this RED.
    ///
    /// Gated behind `--features dudect` (NOT #[ignore]): it is too slow for the
    /// default `cargo test`, but when built it is a hard, non-ignored gate so a
    /// regression cannot pass CI silently. The dedicated `dudect.yml` job runs it.
    /// Sample count: env `DUDECT_SAMPLES` (default 1e5; nightly sets 1e6).
    #[cfg(feature = "dudect")]
    #[test]
    fn rejection_path_timing_is_constant_dudect() {
        let server = X25519KeyPair::generate();

        // Minimum sample count for the gate to have statistical power. A tiny (or
        // zero) sample count would make the loop below run too few iterations for
        // the mean/variance to be meaningful — and `DUDECT_SAMPLES=0` would skip
        // sampling entirely, leaving the accumulators empty and the assertions
        // vacuously green. Reject anything below the floor LOUDLY rather than
        // silently clamping, so the load-bearing gate cannot be neutered via env.
        const MIN_DUDECT_SAMPLES: usize = 1_000;
        let samples: usize = match std::env::var("DUDECT_SAMPLES") {
            Ok(v) => {
                let n: usize = v
                    .parse()
                    .unwrap_or_else(|_| panic!("DUDECT_SAMPLES={v:?} is not a valid usize"));
                assert!(
                    n >= MIN_DUDECT_SAMPLES,
                    "DUDECT_SAMPLES={n} is below the {MIN_DUDECT_SAMPLES} floor; too few \
                     samples would make this load-bearing constant-time gate vacuous"
                );
                n
            }
            Err(_) => 100_000,
        };

        // The three parseable reject shapes, matching the REJECT_DH_OPS counter
        // tests' coverage exactly (B / recover==None / D).
        let shape_b = client_hello_fixture_no_key_share("example.com");
        let shape_r = client_hello_fixture_with_key_share_no_sni(&[0x66; 32]);
        let shape_d = client_hello_fixture_with_key_share("example.com", &[0x66; 32]);
        let shapes: [(&str, &[u8]); 3] = [
            ("B(no-key_share)", &shape_b),
            ("R(recover-None)", &shape_r),
            ("D(auth-fail)", &shape_d),
        ];

        // DECISION CRITERIA — physical effect size AND a self-calibrated |t|, both
        // self-calibrated against the same-run same-shape control (item #4). A pair
        // must pass BOTH gates.
        //
        // GATE 1 (physical, sample-count-invariant): the absolute mean-latency gap
        // (ns) between reject shapes, bounded against the same-run control gap. The
        // mean gap is the EFFECT SIZE and does NOT inflate at 1e6 samples. The
        // distinguisher this test exists to catch — the original ~93µs auth-fail
        // asymmetry — is µs-scale and blows this gate out by orders of magnitude;
        // the sub-µs residue that survives the constant-work replay (an
        // SNI-length-dependent HMAC cost of a few ns) sits far below it.
        //   phys_allow = max(PHYS_FLOOR_NS, PHYS_MULT × control_gap_ns)
        //
        // GATE 2 (statistical, self-calibrated): the Welch |t| is now GATED too, but
        // NOT against a fixed absolute threshold — that would be flaky, because at
        // 1e5–1e6 samples |t| ∝ √n flags even a constant-time path's few-ns residue
        // as "significant" and swings with per-run jitter (the dudect literature's
        // |t|>4.5 rule assumes a fixed, modest sample budget). Instead the cross |t|
        // is bounded against the SAME-RUN control |t|, which is measured at the SAME
        // sample count in the SAME interleaved loop — so the √n inflation and the
        // per-runner jitter hit both and cancel in the ratio:
        //   t_allow = max(T_ABS, T_MULT × control_t)
        // A real µs-scale distinguisher pushes the cross |t| into the thousands+
        // (orders of magnitude past control), so this gate has teeth; the bounded
        // sub-µs residue keeps the cross |t| in the control's neighbourhood, so it is
        // robust. The `T_ABS` floor keeps a tiny control |t| from turning pure ratio
        // noise into a false positive. `dudect_t_gate_is_non_vacuous` unit-tests this
        // decision directly. Tunable via env for the nightly job; defaults chosen so
        // the residue (few-ns → |t| ≲ 100 even at 1e6) is far under T_ABS while the
        // µs regression (|t| in the thousands) is far over it.
        let phys_floor_ns: f64 = env_f64("DUDECT_PHYS_FLOOR_NS", 3_000.0);
        let phys_mult: f64 = env_f64("DUDECT_PHYS_MULT", 8.0);
        let t_abs: f64 = env_f64("DUDECT_T_ABS", 1_000.0);
        let t_mult: f64 = env_f64("DUDECT_T_MULT", 10.0);

        for i in 0..shapes.len() {
            for j in 0..shapes.len() {
                if i == j {
                    continue;
                }
                let (na, a) = shapes[i];
                let (nb, b) = shapes[j];
                let r = dudect_pair(a, b, &server.private, samples);
                let phys_allow = phys_floor_ns.max(phys_mult * r.mean_gap_ctrl_ns);
                let t_allow = dudect_t_allow(r.t_ctrl, t_abs, t_mult);
                eprintln!(
                    "dudect {na} vs {nb}: mean_gap={:.0}ns (ctrl {:.0}ns, allow {:.0}ns) \
                     |t|={:.2} (ctrl {:.2}, allow {:.2}) samples={samples}",
                    r.mean_gap_cross_ns,
                    r.mean_gap_ctrl_ns,
                    phys_allow,
                    r.t_cross,
                    r.t_ctrl,
                    t_allow,
                );
                assert!(
                    r.mean_gap_cross_ns <= phys_allow,
                    "TIMING DISTINGUISHER ({na} vs {nb}): mean latency gap {:.0}ns \
                     exceeds allow {:.0}ns (control {:.0}ns, samples={samples}, \
                     diag |t|={:.2}). The inbound-reject path has a µs-scale data-\
                     dependent latency the X25519 op-count guard cannot see — the \
                     anti-active-probing argument is breached.",
                    r.mean_gap_cross_ns,
                    phys_allow,
                    r.mean_gap_ctrl_ns,
                    r.t_cross,
                );
                assert!(
                    r.t_cross <= t_allow,
                    "TIMING DISTINGUISHER ({na} vs {nb}): Welch |t|={:.2} exceeds the \
                     self-calibrated allow {:.2} (control |t|={:.2}, T_ABS={t_abs}, \
                     T_MULT={t_mult}, mean_gap={:.0}ns, samples={samples}). The cross-\
                     shape latency is statistically distinguishable from the same-shape \
                     control by orders of magnitude past per-run noise.",
                    r.t_cross,
                    t_allow,
                    r.t_ctrl,
                    r.mean_gap_cross_ns,
                );
            }
        }
    }

    /// Parse an `f64` from an env var, falling back to `default` when unset/invalid.
    #[cfg(all(test, feature = "dudect"))]
    fn env_f64(key: &str, default: f64) -> f64 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
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
        let (target, source, initial_payload) = resolve_connect_target(&mut encoded, None).unwrap();

        assert_eq!(target, "[2001:db8::1]:443");
        assert_eq!(source, TargetSource::ClientChosen);
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
        let (target, source, initial_payload) =
            resolve_connect_target(&mut encoded, Some("target.example:443")).unwrap();

        assert_eq!(target, "target.example:443");
        // A fixed target overrides the client request and is operator-chosen.
        assert_eq!(source, TargetSource::OperatorFixed);
        assert_eq!(initial_payload, b"hello");
    }

    #[test]
    fn resolve_connect_target_uses_fixed_target_for_raw_payload() {
        let mut raw = *b"GET / HTTP/1.1\r\n\r\n";
        let (target, source, initial_payload) =
            resolve_connect_target(&mut raw, Some("target.example:443")).unwrap();

        assert_eq!(target, "target.example:443");
        assert_eq!(source, TargetSource::OperatorFixed);
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
        // NAT64 well-known prefix wrapping a PRIVATE v4 (64:ff9b::10.0.0.1): the
        // embedded low-32-bit IPv4 is re-screened, so a NAT64-tunnelled private
        // destination is denied (a public-v4 NAT64 target is allowed — covered by
        // the dedicated NAT64 embedding test).
        let nat64_private = IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001));
        for denied in [
            v4_mapped_private,
            v4_compatible_private,
            nat64_private,
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

        // No supervisor task was spawned for the over-cap stream.
        assert!(streams.uploads.is_empty());
        assert!(streams.tasks.is_empty());
        // The client receives a Reset for that stream id.
        let reset = frame_rx.try_recv().unwrap();
        assert_eq!(reset.stream_id, 7);
        assert_eq!(reset.kind, MuxFrameKind::Reset);
    }

    /// The shared mux reader must NEVER block on a single substream's target I/O.
    /// A wedged target (accepts but never reads) parks THAT substream's own task on
    /// the target write; routing an upload frame to it must still return from the
    /// reader PROMPTLY (a non-blocking `try_send`), and once the per-stream channel
    /// fills the stalled stream is shed with a Reset — the connection and every
    /// healthy substream stay alive. Before the fix the reader wrote client->target
    /// INLINE and parked for `target_write_timeout` per stalled stream: the China
    /// head-of-line-blocking bug this regression guards.
    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn mux_wedged_target_upload_does_not_block_reader() {
        let traffic = TrafficConfig::default();
        let context = ServerMuxContext {
            fixed_data_target: None,
            timing: TimingProfile::from_config(traffic),
            cover: CoverTrafficProfile::from_config(traffic),
            chunk_size: max_plaintext_len(traffic.max_padding),
            max_streams: 8,
            cid: 1,
            // Large enough that the task's OWN write deadline never fires during the
            // test; the shed here is driven by the full-channel grace instead.
            target_write_timeout: Duration::from_secs(30),
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

        let mut streams = ServerMuxStreams::new();

        // Open the substream toward the wedged target (empty initial payload). The
        // supervisor task connects OFF the reader and begins draining uploads.
        let open_payload = ConnectRequest {
            host: target_addr.ip().to_string(),
            port: target_addr.port(),
            initial_payload: Vec::new(),
        }
        .encode()
        .unwrap();
        process_server_mux_frame(
            MuxFrameRef {
                stream_id: 9,
                kind: MuxFrameKind::Open,
                payload: &open_payload,
            },
            &mut streams,
            &frame_tx,
            context,
            &payload_pool,
        )
        .await
        .unwrap();
        assert!(
            streams.tasks.contains_key(&9),
            "Open spawns the substream task"
        );
        // Let the task connect and park on its first (wedging) target write.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Oversized payload so the target's socket buffers fill and the task's write
        // stays parked. Routing it to the reader must NOT block ~target_write_timeout;
        // it `try_send`s into the per-stream channel and returns at once.
        let big = vec![0_u8; 4 * 1024 * 1024];
        tokio::time::timeout(
            Duration::from_millis(500),
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
        .expect("reader must not block on a wedged target's write")
        .expect("routing an upload to a wedged stream must not error the connection");

        // Keep routing until the bounded channel fills; the reader then waits at most
        // the grace and sheds the stalled stream with a Reset, freeing its slot.
        for _ in 0..(SERVER_MUX_UPLOAD_CHANNEL as u32 + 8) {
            let _ = process_server_mux_frame(
                MuxFrameRef {
                    stream_id: 9,
                    kind: MuxFrameKind::Data,
                    payload: &big,
                },
                &mut streams,
                &frame_tx,
                context,
                &payload_pool,
            )
            .await;
        }

        // The client is told to tear down the wedged stream, and its slot is freed.
        let mut saw_reset = false;
        while let Ok(frame) = frame_rx.try_recv() {
            if frame.stream_id == 9 && frame.kind == MuxFrameKind::Reset {
                saw_reset = true;
            }
        }
        assert!(saw_reset, "wedged stream is eventually shed with a Reset");
        streams.prune_finished();
        assert!(
            !streams.tasks.contains_key(&9),
            "shed stream's task is removed"
        );

        acceptor.abort();
    }

    /// #56: a client that keeps the mux-over-QUIC session transport-alive (the
    /// QUIC connection's idle timeout is refreshed by ANY packet, keep-alives
    /// included) while opening ZERO substreams and sending ZERO TCP bytes must
    /// not pin the session — connection, both TCP fds, and admission permit —
    /// forever. The accept loop's application-level idle backstop must return
    /// within the injected idle timeout and close the connection with the agreed
    /// idle code so the client reads the teardown as benign.
    #[tokio::test]
    #[ignore = "requires loopback UDP + TCP sockets"]
    async fn mux_quic_idle_backstop_reclaims_silent_session() {
        use crate::crypto::session::derive_server_keys;
        use crate::protocol::data::is_relay_idle_close_reason;
        use crate::tls::quic::{AcceptAnyServerCert, ClientConfig as QuicClientConfig};
        use crate::transport::udp::h3::H3ControlStreams;
        use crate::transport::udp::quic::endpoint::{Endpoint, ServerConfig as QuicServerConfig};
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        // In-process QUIC pair over loopback UDP (mirrors the endpoint unit tests).
        let signing_key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap()
                .as_ref()
                .to_vec();
        let quic_server = Endpoint::server(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(QuicServerConfig {
                cert_chain: vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
                signing_key_pkcs8: signing_key,
                alpn_protocols: vec![b"h3".to_vec()],
                zero_rtt: None,
                origin_udp_addr: None,
                marker_key: None,
                marker_replay_guard: None,
                authorized_sni: vec!["example.com".to_owned()],
                max_udp_payload: 0,
            }),
        )
        .await
        .unwrap();
        let quic_addr = quic_server.local_addr().unwrap();
        let quic_client = Endpoint::client("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        quic_client.set_default_client_config(Arc::new(QuicClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        )));
        let (client_conn, server_conn) = tokio::join!(
            quic_client.connect(quic_addr, "example.com"),
            quic_server.accept(),
        );
        let client_conn = client_conn.unwrap();
        let server_conn = server_conn.unwrap();

        // The probe bidi the production path quiesces on entry: the client opens
        // it and writes a byte so it materializes on the server.
        let (mut probe_send, probe_recv) = client_conn.open_bi();
        probe_send.write_all(b"p").await.unwrap();
        let (relay_send, relay_recv) = server_conn.accept_bi().await.unwrap();
        // The server-opened H3 control/QPACK-encoder unis the session parks.
        let h3_control = H3ControlStreams::new(server_conn.open_uni(), server_conn.open_uni());

        // The parked TCP control connection: the client half stays open and
        // SILENT for the whole test (no EOF, no stray byte), so `tcp_watch`
        // never fires — exactly the DoS shape.
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let (client_tcp, accepted) =
            tokio::join!(TcpStream::connect(tcp_addr), tcp_listener.accept());
        let client_tcp = client_tcp.unwrap();
        let (server_tcp, _) = accepted.unwrap();
        let (server_tcp_read, server_tcp_write) = server_tcp.into_split();

        let client_x = X25519KeyPair::generate();
        let server_x = X25519KeyPair::generate();
        let session_keys =
            derive_server_keys(PSK, &server_x.private, &client_x.public, &[7_u8; 32]).unwrap();

        // The client opens ZERO substreams: the session must be reclaimed by the
        // idle backstop (the call RETURNS within the wall budget) rather than
        // pinned on `accept_bi` indefinitely.
        let session = run_authenticated_mux_quic_data_mode(
            BufferedTlsRecordReader::buffered(server_tcp_read),
            server_tcp_write,
            ServerProbedQuic {
                conn: server_conn,
                h3_control,
                relay_send,
                relay_recv,
            },
            ServerMuxQuicContext {
                session_keys: &session_keys,
                traffic: TrafficConfig::default(),
                fixed_data_target: None,
                cid: 1,
            },
            Duration::from_millis(100),
        );
        tokio::time::timeout(Duration::from_secs(5), session)
            .await
            .expect("a zero-substream silent session must be reclaimed by the idle backstop")
            .expect("idle teardown is a clean session end, not an error");

        // The client observes the agreed idle close code (benign teardown), not a
        // generic error close.
        tokio::time::timeout(
            Duration::from_secs(5),
            crate::transport::udp::endpoint::conn_closed(&client_conn),
        )
        .await
        .expect("the idle close must reach the client");
        assert!(
            is_relay_idle_close_reason(client_conn.close_reason().as_ref()),
            "the backstop must close with RELAY_IDLE_CLOSE_CODE, got {:?}",
            client_conn.close_reason()
        );

        drop(client_tcp);
        drop((probe_send, probe_recv));
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
        let mut client_records = TcpLegReader::buffered(read_half);
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

    /// A `LegReader` double for the upload-throughput-floor tests: on each read it
    /// advances the (paused) tokio clock by `advance_per_read`, then returns one
    /// freshly sealed record carrying `payload`, until `max_reads` is reached
    /// (after which it reports a clean EOF). Sealing with the client->server codec
    /// keeps the phase's `client_open` decoder in lockstep.
    struct TrickleLegReader {
        sealer: DataRecordCodec,
        rng: StdRng,
        payload: Vec<u8>,
        advance_per_read: Duration,
        remaining: u64,
    }

    impl LegReader for TrickleLegReader {
        async fn read_record_into(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
            if self.remaining == 0 {
                // Clean end-of-leg (treated as a graceful close by the phase).
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.remaining -= 1;
            tokio::time::advance(self.advance_per_read).await;
            let record = self
                .sealer
                .seal(&self.payload, &mut self.rng)
                .expect("seal a trickle record");
            buf.clear();
            buf.extend_from_slice(&record);
            Ok(())
        }

        async fn try_read_record_into(&mut self, _buf: &mut Vec<u8>) -> Option<io::Result<()>> {
            None
        }
    }

    /// A no-op `LegWriter`: the floor-trip path errors mid-loop before any write,
    /// so the sink is never exercised.
    struct NullLegWriter;

    impl LegWriter for NullLegWriter {
        async fn write_records(&mut self, _bytes: &[u8]) -> io::Result<()> {
            Ok(())
        }
        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn upload_floor_io_codecs() -> (DataRecordCodec, DataRecordCodec) {
        // Sealer (client->server) and the phase's matching opener share key/nonce/aad.
        let sealer = DataRecordCodec::new(
            AeadCodec::new([0x33; 32], [0x44; 12]),
            PaddingProfile::new(0, 0).unwrap(),
            CLIENT_TO_SERVER_AAD,
        );
        let opener = DataRecordCodec::new(
            AeadCodec::new([0x33; 32], [0x44; 12]),
            PaddingProfile::new(0, 0).unwrap(),
            CLIENT_TO_SERVER_AAD,
        );
        (sealer, opener)
    }

    #[tokio::test(start_paused = true)]
    async fn upload_phase_rejects_a_sub_floor_trickle() {
        // A 1-byte-per-record dribble that advances the clock 60 s per record drives
        // the average rate far below MIN_UPLOAD_BYTES_PER_SEC; once past the grace,
        // the floor must tear the phase down rather than let it pin the slot.
        let (sealer, opener) = upload_floor_io_codecs();
        let mut client_records = TrickleLegReader {
            sealer,
            rng: StdRng::seed_from_u64(1),
            payload: vec![0x5a; 1],
            advance_per_read: Duration::from_secs(60),
            remaining: 10_000,
        };
        let mut client_write = NullLegWriter;
        let mut client_open = opener;
        let mut server_seal = DataRecordCodec::new(
            AeadCodec::new([0x11; 32], [0x22; 12]),
            PaddingProfile::new(0, 0).unwrap(),
            SERVER_TO_CLIENT_AAD,
        );
        let mut rng = StdRng::seed_from_u64(2);
        let mut scratch = RelaySealScratch::with_payload_capacity(max_plaintext_len(0));
        let mut io = SpeedServerIo {
            client_records: &mut client_records,
            client_write: &mut client_write,
            client_open: &mut client_open,
            server_seal: &mut server_seal,
            rng: &mut rng,
            scratch: &mut scratch,
            cid: 1,
        };

        let result =
            read_speed_upload_phase(&mut io, 1024 * 1024 * 1024, SpeedTestAck::upload_done(0))
                .await;
        let err = result.expect_err("a sub-floor trickle must be rejected");
        match err {
            HandshakeServerError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("expected InvalidData, got {other:?}"),
        }
        // It must reject promptly (a couple of grace-crossing records), NOT after
        // ~1e9 iterations — the whole point of the floor.
        assert!(
            io.client_records.remaining > 9_990,
            "floor must fire within a few records (remaining {})",
            io.client_records.remaining
        );
    }

    #[tokio::test(start_paused = true)]
    async fn upload_phase_accepts_a_healthy_fast_upload() {
        // A full-rate upload (large records, no clock advance) completes the
        // requested byte count and returns Ok — the floor never false-rejects.
        let (sealer, opener) = upload_floor_io_codecs();
        let chunk = max_plaintext_len(0);
        let total = (chunk as u64) * 4; // four full records
        let mut client_records = TrickleLegReader {
            sealer,
            rng: StdRng::seed_from_u64(3),
            payload: vec![0x42; chunk],
            advance_per_read: Duration::from_secs(0),
            remaining: 8,
        };
        let mut client_write = NullLegWriter;
        let mut client_open = opener;
        let mut server_seal = DataRecordCodec::new(
            AeadCodec::new([0x11; 32], [0x22; 12]),
            PaddingProfile::new(0, 0).unwrap(),
            SERVER_TO_CLIENT_AAD,
        );
        let mut rng = StdRng::seed_from_u64(4);
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

        read_speed_upload_phase(&mut io, total, SpeedTestAck::upload_done(total))
            .await
            .expect("a healthy fast upload must complete without tripping the floor");
    }

    #[tokio::test(start_paused = true)]
    async fn upload_phase_credits_the_current_record_before_the_floor() {
        // Boundary case: a client sends almost nothing during the grace window,
        // then a full record arrives just AFTER the grace boundary. Counting that
        // record's own bytes, it clears the (tiny, ~1 s of active time) floor — so
        // it must NOT be rejected on the stale pre-record total. Reaching the
        // requested byte count and returning Ok proves the credit-then-check order.
        let (sealer, opener) = upload_floor_io_codecs();
        let chunk = max_plaintext_len(0); // ~16 KiB, far above the ~4 KiB floor at 1 s active
        let total = chunk as u64; // exactly one record satisfies the request
        let mut client_records = TrickleLegReader {
            sealer,
            rng: StdRng::seed_from_u64(5),
            // The single read jumps just past the 15 s grace (active ~= 1 s, floor
            // ~= 4 KiB); the record's own ~16 KiB clears it once credited. With the
            // pre-fix stale-total order, uploaded would still be 0 here and reject.
            payload: vec![0x37; chunk],
            advance_per_read: Duration::from_secs(16),
            remaining: 4,
        };
        let mut client_write = NullLegWriter;
        let mut client_open = opener;
        let mut server_seal = DataRecordCodec::new(
            AeadCodec::new([0x11; 32], [0x22; 12]),
            PaddingProfile::new(0, 0).unwrap(),
            SERVER_TO_CLIENT_AAD,
        );
        let mut rng = StdRng::seed_from_u64(6);
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

        read_speed_upload_phase(&mut io, total, SpeedTestAck::upload_done(total))
            .await
            .expect("a full record crossing the grace boundary must be credited, not rejected");
    }

    #[tokio::test(start_paused = true)]
    async fn speed_tcp_done_bounds_an_empty_record_trickle_with_an_absolute_deadline() {
        // #54: padding-only records arriving well inside the per-read backstop
        // must not extend the DONE wait past the anchored phase deadline. Pre-fix,
        // every record reset the 120 s per-read clock, so the trickle ran until
        // the ~1024-record consecutive cap (~34 h of slot pin).
        let (sealer, opener) = upload_floor_io_codecs();
        let mut reader = TrickleLegReader {
            sealer,
            rng: StdRng::seed_from_u64(8),
            payload: Vec::new(), // padding-only: opens to an empty payload range
            advance_per_read: Duration::from_secs(30),
            remaining: 10_000,
        };
        let mut client_open = opener;

        let err = read_speed_tcp_done(&mut reader, &mut client_open, 1)
            .await
            .expect_err("an empty-record trickle must not satisfy the DONE read");
        match err {
            HandshakeServerError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected TimedOut, got {other:?}"),
        }
        // The deadline must fire after ~QUIC_RELAY_DONE_BACKSTOP of trickle (a
        // handful of 30 s records), NOT after the ~1024-record consecutive cap.
        assert!(
            reader.remaining > 9_900,
            "deadline must fire within a few records (remaining {})",
            reader.remaining
        );
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

    /// H-1 / M-4: a cap-shed close's IDLE-CLOSE TIME must not be separable from a
    /// healthy splice's. The prior design gave cap-shed relays a SEPARATE tight idle
    /// band ([10s, 90s]) that was disjoint from the healthy band ([600s, 660s]); a
    /// prober timing our server-originated FIN on a silent relay could separate the
    /// two populations in a few samples and read "this box is at its cap". This pins
    /// the fix: the cap-shed call site draws its idle from [`cap_shed_fallback_idle`],
    /// which must stay inside the healthy splice band. Sampling the actual call-site
    /// helper (not `fallback_idle_timeout` directly) means a future revert that points
    /// cap-shed at a separate tight band fails HERE. The anti-amplification bound is
    /// carried solely by the 64-concurrency ceiling. (A pre-existing handshake-START
    /// timing difference — cap-shed dials before reading the ClientHello — is out of
    /// scope here and unchanged by the fix.)
    #[test]
    fn cap_shed_fallback_idle_matches_healthy_band() {
        // Sample the cap-shed call site's own idle helper: every value it can produce
        // must be a value the healthy splice band ([floor, floor + jitter]) contains.
        for _ in 0..256 {
            let idle = cap_shed_fallback_idle();
            assert!(
                idle >= FALLBACK_IDLE_TIMEOUT_FLOOR
                    && idle <= FALLBACK_IDLE_TIMEOUT_FLOOR + FALLBACK_IDLE_TIMEOUT_JITTER,
                "cap-shed idle must sit inside the healthy splice band so the close \
                 time is not a separable 'box at cap' tell",
            );
        }
        // The anti-DoS-amplification backstop is the hard concurrency ceiling, not a
        // tightened idle; pin it so a future edit cannot quietly remove it.
        assert_eq!(MAX_CONCURRENT_CAP_SHED_FALLBACKS, 64);
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

    /// #262: the userspace fallback relay's forward writes must be bounded by the
    /// SAME idle timeout as its reads. `write_all` is awaited inside the selected
    /// `select!` arm, where the pinned idle sleep is not polled, so a zero-window
    /// peer (accepts but never reads) would stall the write forever, pinning the
    /// connection permit — an unauthenticated DoS. The kernel splice path already
    /// polls the write fd against the idle bound; this pins the userspace loop's
    /// parity. Drives `relay_fallback_userspace_loop` directly because the
    /// production entry may route to the kernel splice path on Linux.
    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn fallback_userspace_relay_write_stall_hits_idle_timeout() {
        // client -> parallax pair: the probe writes an oversized payload.
        let parallax_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parallax_addr = parallax_listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(parallax_addr).await.unwrap();
            // Far exceeds the socket buffers; the task blocks mid-write and keeps
            // the socket open for the duration of the test.
            let big = vec![0_u8; 64 * 1024 * 1024];
            let _ = stream.write_all(&big).await;
            sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        let (client_side, _) = parallax_listener.accept().await.unwrap();

        // parallax -> origin pair: the origin accepts and NEVER reads, so its
        // receive window goes to zero once the buffers fill.
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (s, _) = origin_listener.accept().await.unwrap();
            sleep(Duration::from_secs(30)).await;
            drop(s);
        });
        let fallback = TcpStream::connect(origin_addr).await.unwrap();

        let (mut client_read, mut client_write) = client_side.into_split();
        let (mut fallback_read, mut fallback_write) = fallback.into_split();

        let result = timeout(
            Duration::from_secs(5),
            relay_fallback_userspace_loop(
                &mut client_read,
                &mut client_write,
                &mut fallback_read,
                &mut fallback_write,
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("a zero-window stall on the forward write must hit the idle timeout, not hang");
        result.expect("write-side idle timeout is a clean relay exit");

        client.abort();
        origin.abort();
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

    #[test]
    fn zero_rtt_replay_cache_path_is_a_sibling_with_0rtt_suffix() {
        // The 0-RTT cache path must be the auth cache path with ".0rtt" appended to
        // its file name (same directory). A `-> Default::default()` body replacement
        // would yield an empty path; pin the exact derivation.
        let auth = std::path::Path::new("/var/lib/parallax/replay.cache");
        let zero = zero_rtt_replay_cache_path(auth);
        assert_eq!(
            zero,
            std::path::PathBuf::from("/var/lib/parallax/replay.cache.0rtt")
        );
        // Same parent directory, distinct file name.
        assert_eq!(zero.parent(), auth.parent());
        assert_ne!(zero, auth.to_path_buf());

        // A path with no file name falls back to the default base name + suffix.
        let fallback = zero_rtt_replay_cache_path(std::path::Path::new("/"));
        assert!(fallback
            .to_string_lossy()
            .ends_with("parallax-replay.cache.0rtt"));
    }

    #[test]
    fn marker_replay_cache_path_is_a_sibling_with_marker_suffix() {
        // Mirror of the 0-RTT path test for the origin-splice marker cache: the path
        // must be the auth cache path with ".marker" appended (same directory). Kills
        // the `-> Default::default()` body replacement.
        let auth = std::path::Path::new("/var/lib/parallax/replay.cache");
        let marker = marker_replay_cache_path(auth);
        assert_eq!(
            marker,
            std::path::PathBuf::from("/var/lib/parallax/replay.cache.marker")
        );
        assert_eq!(marker.parent(), auth.parent());
        assert_ne!(marker, auth.to_path_buf());

        let fallback = marker_replay_cache_path(std::path::Path::new("/"));
        assert!(fallback
            .to_string_lossy()
            .ends_with("parallax-replay.cache.marker"));
    }

    #[test]
    fn client_hello_fingerprint_is_sha256_of_the_record() {
        // The fingerprint feeds the replay cache key, so it must be the real SHA-256
        // of the first record, not a constant. A `-> [0;32]` / `-> [1;32]` body
        // replacement would collapse every distinct ClientHello to the same key
        // (breaking replay detection); pin it to the actual digest and require it to
        // vary across inputs.
        let record = b"\x16\x03\x01\x00\x05hello";
        let fp = client_hello_fingerprint(record);
        assert_eq!(fp, <[u8; 32]>::from(Sha256::digest(record)));
        assert_ne!(fp, [0_u8; 32]);
        assert_ne!(fp, [1_u8; 32]);
        // Distinct records must yield distinct fingerprints.
        assert_ne!(fp, client_hello_fingerprint(b"a different record"));
    }

    #[test]
    fn server_runtime_secrets_getters_return_the_decoded_keys() {
        // The private/public getters must return the decoded key material, not a
        // fixed [0;32]/[1;32]. Decode a config built from a known X25519 keypair and
        // assert the getters match (and that the public key is the X25519 image of
        // the private key, which is how decode() derives it).
        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = identity::keypair();
        let replay_cache_dir = tempfile::tempdir().unwrap();
        let fallback_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let config = authenticated_server_config(
            fallback_addr,
            &server_keys,
            &server_identity_keys,
            replay_cache_dir.path().join("parallax-replay.cache"),
        );

        let secrets = ServerRuntimeSecrets::decode(&config).unwrap();
        assert_eq!(secrets.private_key(), &server_keys.private);
        assert_eq!(secrets.server_public_key(), server_keys.public);
        // Cross-check the derivation: public == X25519(private).
        assert_eq!(
            secrets.server_public_key(),
            x25519_public_from_private(secrets.private_key())
        );
        // Sanity: the real keys are not the mutant's degenerate constants.
        assert_ne!(secrets.private_key(), &[0_u8; 32]);
        assert_ne!(secrets.private_key(), &[1_u8; 32]);
    }

    #[test]
    fn replay_freshness_window_outlasts_the_prepq_deadline() {
        // The replay freshness window must be the pre-PQ idle floor PLUS the default
        // replay window (clock-skew slack), so a slow-but-legitimate client whose
        // ClientHello timestamp is committed up to the floor later is not rejected as
        // Stale. A `-> 0` / `-> 1` body replacement would collapse the window and
        // re-introduce that rejection; pin it to the real sum (which far exceeds 1).
        let expected = timeout_tuning().fallback_idle_floor.as_secs() + DEFAULT_REPLAY_WINDOW_SECS;
        assert_eq!(replay_freshness_window_secs(), expected);
        assert!(
            replay_freshness_window_secs() >= DEFAULT_REPLAY_WINDOW_SECS,
            "the window must never be smaller than the skew slack"
        );
        assert!(replay_freshness_window_secs() > 1);
    }

    #[test]
    fn outbound_egress_filter_denies_every_special_range() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        // SSRF / egress policy: each address below is denied by EXACTLY one rule in
        // is_denied_outbound_ipv4 / is_denied_outbound_ip, so a mutation that breaks
        // that rule (|| -> &&, == -> !=, && -> ||) re-opens the corresponding range
        // and this assertion catches it. Security-critical: a hole here lets an
        // authenticated client reach loopback/RFC1918/cloud-metadata-adjacent space.
        let denied_v4: &[(Ipv4Addr, &str)] = &[
            (Ipv4Addr::new(127, 0, 0, 1), "loopback"),
            (Ipv4Addr::new(10, 0, 0, 1), "private 10/8"),
            (Ipv4Addr::new(172, 16, 0, 1), "private 172.16/12"),
            (Ipv4Addr::new(192, 168, 1, 1), "private 192.168/16"),
            (
                Ipv4Addr::new(169, 254, 0, 1),
                "link-local (incl. cloud metadata)",
            ),
            (Ipv4Addr::new(0, 0, 0, 0), "unspecified / octets[0]==0"),
            (Ipv4Addr::new(0, 1, 2, 3), "octets[0]==0 'this network'"),
            (Ipv4Addr::new(224, 0, 0, 1), "multicast"),
            (Ipv4Addr::new(255, 255, 255, 255), "broadcast"),
            (
                Ipv4Addr::new(240, 0, 0, 1),
                "octets[0]>=240 (reserved class E)",
            ),
            (Ipv4Addr::new(100, 64, 0, 1), "CGNAT 100.64/10 low"),
            (Ipv4Addr::new(100, 127, 255, 1), "CGNAT 100.64/10 high"),
            (
                Ipv4Addr::new(192, 0, 0, 1),
                "192.0.0/24 IETF protocol assignments",
            ),
            (Ipv4Addr::new(192, 0, 2, 1), "192.0.2/24 TEST-NET-1"),
            (Ipv4Addr::new(198, 18, 0, 1), "198.18/15 benchmark low"),
            (Ipv4Addr::new(198, 19, 0, 1), "198.18/15 benchmark high"),
            (Ipv4Addr::new(198, 51, 100, 1), "198.51.100/24 TEST-NET-2"),
            (Ipv4Addr::new(203, 0, 113, 1), "203.0.113/24 TEST-NET-3"),
        ];
        for (ip, why) in denied_v4 {
            assert!(is_denied_outbound_ipv4(*ip), "{ip} must be denied ({why})");
            assert!(
                is_denied_outbound_ip(IpAddr::V4(*ip)),
                "{ip} must be denied via is_denied_outbound_ip ({why})"
            );
        }

        // Normal, routable public IPv4 must be ALLOWED: this is what proves the
        // filter is not a blanket deny (a `|| -> &&` somewhere that made the whole
        // chain collapse to false would be missed without an allow case; conversely
        // a `&& -> ||` that broadened a special range would wrongly deny these).
        let allowed_v4 = [
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(93, 184, 216, 34),  // example.com
            Ipv4Addr::new(100, 63, 255, 255), // just below CGNAT
            Ipv4Addr::new(100, 128, 0, 1),    // just above CGNAT
            Ipv4Addr::new(192, 0, 1, 1),      // adjacent to 192.0.0/24 and .2/24
            Ipv4Addr::new(198, 20, 0, 1),     // just above the benchmark range
            Ipv4Addr::new(203, 0, 114, 1),    // adjacent to TEST-NET-3
        ];
        for ip in allowed_v4 {
            assert!(
                !is_denied_outbound_ipv4(ip),
                "{ip} is a normal public address and must be allowed"
            );
            assert!(
                !is_denied_outbound_ip(IpAddr::V4(ip)),
                "{ip} must be allowed"
            );
        }

        // IPv6 special ranges, each denied by one rule.
        let denied_v6: &[(Ipv6Addr, &str)] = &[
            (Ipv6Addr::LOCALHOST, "::1 loopback"),
            (Ipv6Addr::UNSPECIFIED, ":: unspecified"),
            (Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), "multicast"),
            (
                Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1),
                "unique local fc00::/7",
            ),
            (
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                "link-local fe80::/10",
            ),
            (
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                "documentation 2001:db8::/32",
            ),
            (
                Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
                "teredo 2001:0::/32",
            ),
            (
                Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 1),
                "NAT64 64:ff9b::/96",
            ),
            // v4-mapped private address must be screened by the IPv4 policy.
            (
                Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001),
                "::ffff:10.0.0.1 v4-mapped private",
            ),
        ];
        for (ip, why) in denied_v6 {
            assert!(
                is_denied_outbound_ip(IpAddr::V6(*ip)),
                "{ip} must be denied ({why})"
            );
        }

        // The targeted IPv6 classifiers, pinned positive/negative so the `&&` and
        // `==` inside them cannot be flipped without detection.
        assert!(is_ipv6_documentation(Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_documentation(Ipv6Addr::new(
            0x2001, 0x0db9, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_teredo(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_ipv6_teredo(Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1)));
        assert!(is_ipv6_nat64(Ipv6Addr::new(
            0x0064, 0xff9b, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_nat64(Ipv6Addr::new(
            0x0064, 0xff9c, 0, 0, 0, 0, 0, 1
        )));

        // A normal public IPv6 must be allowed.
        assert!(!is_denied_outbound_ip(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111
        ))));
    }

    #[test]
    fn ipv6_6to4_range_is_classified_and_denied_outbound() {
        // 2002::/16 (6to4) embeds an IPv4 address in its payload and would
        // otherwise tunnel to an arbitrary v4 destination without passing the v4
        // egress policy. It is in the deny chain but — unlike its sibling
        // classifiers (documentation/teredo/nat64), pinned just above — had no test.
        assert!(is_ipv6_6to4(Ipv6Addr::new(
            0x2002, 0xc058, 0x6301, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_6to4(Ipv6Addr::new(
            0x2001, 0xc058, 0x6301, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_6to4(Ipv6Addr::new(0x2003, 0, 0, 0, 0, 0, 0, 1)));
        // The range must actually be denied at the egress gate, not just classified.
        assert!(is_denied_outbound_ip(IpAddr::V6(Ipv6Addr::new(
            0x2002, 0xc058, 0x6301, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn nat64_embedded_ipv4_is_rescreened_for_both_prefixes() {
        // NAT64 (RFC 6052 `64:ff9b::/96` and RFC 8215 `64:ff9b:1::/48`) embeds an
        // IPv4 destination at a prefix-length-dependent position (RFC 6052 §2.2).
        // The egress screen must extract that embedded v4 with the correct layout
        // and re-apply the IPv4 policy, so a NAT64 tunnel cannot be used to reach
        // a private/metadata host (SSRF) while a NAT64 tunnel to a genuine public
        // v4 stays usable (not wholesale-denied).
        //
        // helpers: build a NAT64 address embedding v4 octets `o` per RFC 6052 §2.2.
        // /96: v4 in bits 96..127 (the low 32 bits).
        let nat64_96 = |o: [u8; 4]| {
            IpAddr::V6(Ipv6Addr::new(
                0x0064,
                0xff9b,
                0,
                0,
                0,
                0,
                u16::from(o[0]) << 8 | u16::from(o[1]),
                u16::from(o[2]) << 8 | u16::from(o[3]),
            ))
        };
        // /48: v4 in bits 48..63 and 72..87, u octet (zero) at bits 64..71,
        // arbitrary suffix from bit 88.
        let nat64_48 = |o: [u8; 4], suffix: [u16; 3]| {
            IpAddr::V6(Ipv6Addr::new(
                0x0064,
                0xff9b,
                0x0001,
                u16::from(o[0]) << 8 | u16::from(o[1]),
                u16::from(o[2]),
                u16::from(o[3]) << 8 | (suffix[0] & 0xff),
                suffix[1],
                suffix[2],
            ))
        };

        let private_v4 = [
            ([10, 0, 0, 1], "RFC1918 10/8"),
            ([192, 168, 1, 1], "RFC1918 192.168/16"),
            ([127, 0, 0, 1], "loopback"),
            ([169, 254, 169, 254], "link-local cloud metadata"),
            ([0, 0, 0, 0], "unspecified / octets[0]==0"),
        ];
        let public_v4 = [[8, 8, 8, 8], [1, 1, 1, 1], [93, 184, 216, 34]];

        // Embedded PRIVATE / special v4 must be DENIED under BOTH prefixes. For
        // /48 the suffix carries a public-looking decoy (`8.8.8.8` in the low 32
        // bits): a low-32-bit extraction would read the decoy and let the
        // translator reach the private embedded target.
        for (o, why) in private_v4 {
            for addr in [nat64_96(o), nat64_48(o, [0, 0x0808, 0x0808])] {
                assert!(
                    is_denied_outbound_ip(addr),
                    "NAT64 {addr} embedding {o:?} ({why}) must be denied"
                );
                if let IpAddr::V6(v6) = addr {
                    assert!(
                        is_ipv6_nat64(v6),
                        "{addr} must classify as a denied NAT64 address"
                    );
                }
            }
        }

        // Embedded PUBLIC v4 must be ALLOWED under BOTH prefixes (not wholesale-
        // denied): this is the behaviour change from "deny the whole 64:ff9b:*
        // space" to "screen the embedded destination". The /48 case uses a ZERO
        // suffix: a low-32-bit extraction would read `0.0.0.0` and wrongly deny a
        // legitimate public NAT64 target (the RFC 8215 overblocking bug).
        for o in public_v4 {
            for addr in [nat64_96(o), nat64_48(o, [0, 0, 0])] {
                assert!(
                    !is_denied_outbound_ip(addr),
                    "NAT64 {addr} embedding public {o:?} must be allowed"
                );
                if let IpAddr::V6(v6) = addr {
                    assert!(
                        !is_ipv6_nat64(v6),
                        "{addr} embeds a public v4 and must not classify as denied NAT64"
                    );
                }
            }
        }

        // Segment-boundary pin for the /48 layout: 192.168.1.1 embeds as
        // 64:ff9b:1:c0a8:1:100:: (segments[3]=0xc0a8, u|o2=0x0001, o3|suffix=0x0100),
        // straddling three hextets. Any off-by-one-octet extraction misreads it.
        assert!(is_ipv6_nat64(Ipv6Addr::new(
            0x0064, 0xff9b, 0x0001, 0xc0a8, 0x0001, 0x0100, 0, 0
        )));

        // An address that merely shares the first hextet but is neither prefix
        // (e.g. `64:ff9c::` / `64:ff9b:2::`) must NOT be treated as NAT64.
        assert!(!is_ipv6_nat64(Ipv6Addr::new(
            0x0064, 0xff9c, 0, 0, 0, 0, 0x0a00, 0x0001
        )));
        assert!(!is_ipv6_nat64(Ipv6Addr::new(
            0x0064, 0xff9b, 0x0002, 0, 0, 0, 0x0a00, 0x0001
        )));
    }

    #[test]
    fn ipv4_6to4_relay_anycast_is_denied_outbound() {
        // 6to4 relay anycast 192.88.99.0/24 (RFC 7526, deprecated): must be denied
        // outbound both directly on the v4 policy and via the IpAddr entrypoint.
        for last in [0u8, 1, 128, 255] {
            let ip = Ipv4Addr::new(192, 88, 99, last);
            assert!(
                is_denied_outbound_ipv4(ip),
                "{ip} (6to4 relay anycast) must be denied"
            );
            assert!(
                is_denied_outbound_ip(IpAddr::V4(ip)),
                "{ip} must be denied via is_denied_outbound_ip"
            );
        }
        // Adjacent addresses outside the /24 remain allowed (guards `octets[2]==99`).
        assert!(!is_denied_outbound_ipv4(Ipv4Addr::new(192, 88, 98, 1)));
        assert!(!is_denied_outbound_ipv4(Ipv4Addr::new(192, 88, 100, 1)));
    }

    #[test]
    fn speed_test_dos_ceilings_match_their_documented_values() {
        // These are SECURITY ceilings that bound an authenticated client's speed-test
        // request (a malicious client could otherwise request terabytes of generated
        // download or a never-ending upload to pin bandwidth/CPU/a connection slot).
        // The wire format allows arbitrary u64/u16 values, so the only thing standing
        // between the server and that abuse is these constants. Freeze their exact
        // documented magnitudes so an arithmetic typo (e.g. `1024 * 1024 * 1024`
        // becoming `1024 + 1024 * 1024`) cannot silently shrink or balloon a ceiling.
        // Expected values written as plain decimal literals (no `*`) so the check is
        // independent of the constants' own arithmetic.
        assert_eq!(
            MAX_SPEED_TEST_BYTES_PER_PHASE,
            1_073_741_824, // 1 GiB
            "per-phase ceiling must be exactly 1 GiB"
        );
        assert_eq!(
            MAX_SPEED_TEST_TOTAL_BYTES,
            4_294_967_296, // 4 GiB
            "aggregate ceiling must be exactly 4 GiB"
        );
        assert_eq!(
            MAX_SPEED_TEST_SAMPLES, 32,
            "sample-count ceiling must be 32"
        );
        assert_eq!(
            MUX_OPEN_BATCH_BYTES,
            1_048_576, // 1 MiB
            "mux open batch must be exactly 1 MiB"
        );
    }

    #[test]
    fn validate_speed_request_accepts_the_maximal_single_phase_request() {
        // Each phase exactly at the per-phase cap with no samples: aggregate work
        // is 2*1 GiB = 2 GiB, under the 4 GiB ceiling. The caps use `>`, so a
        // request sitting exactly on the per-phase cap is still accepted — this
        // guards against a `>` silently becoming `>=`.
        let req = SpeedTestRequest {
            warmup_bytes: MAX_SPEED_TEST_BYTES_PER_PHASE,
            download_bytes: MAX_SPEED_TEST_BYTES_PER_PHASE,
            upload_bytes: MAX_SPEED_TEST_BYTES_PER_PHASE,
            sample_count: 0,
        };
        assert!(validate_speed_request(&req, 0).is_ok());
    }

    #[test]
    fn validate_speed_request_rejects_each_per_phase_overage() {
        // One field over its cap at a time (others zero) must fail closed, so no
        // single per-phase guard can be dropped without a test noticing.
        let over = MAX_SPEED_TEST_BYTES_PER_PHASE + 1;
        let cases = [
            SpeedTestRequest {
                warmup_bytes: over,
                download_bytes: 0,
                upload_bytes: 0,
                sample_count: 0,
            },
            SpeedTestRequest {
                warmup_bytes: 0,
                download_bytes: over,
                upload_bytes: 0,
                sample_count: 0,
            },
            SpeedTestRequest {
                warmup_bytes: 0,
                download_bytes: 0,
                upload_bytes: over,
                sample_count: 0,
            },
            SpeedTestRequest {
                warmup_bytes: 0,
                download_bytes: 0,
                upload_bytes: 0,
                sample_count: MAX_SPEED_TEST_SAMPLES + 1,
            },
        ];
        for req in &cases {
            assert!(
                validate_speed_request(req, 0).is_err(),
                "a per-phase overage must be rejected: {req:?}"
            );
        }
    }

    #[test]
    fn validate_speed_request_rejects_aggregate_over_ceiling_within_per_phase_caps() {
        // Every field is within its own per-phase cap, but the aggregate
        // 2*warmup + sample_count*(download+upload) = 2*1 GiB + 2*(1 GiB + 1 GiB)
        // = 6 GiB exceeds the 4 GiB total ceiling. This is the branch the
        // individual per-phase caps cannot catch.
        let req = SpeedTestRequest {
            warmup_bytes: MAX_SPEED_TEST_BYTES_PER_PHASE,
            download_bytes: MAX_SPEED_TEST_BYTES_PER_PHASE,
            upload_bytes: MAX_SPEED_TEST_BYTES_PER_PHASE,
            sample_count: 2,
        };
        assert!(validate_speed_request(&req, 0).is_err());
    }

    #[test]
    fn cap_shed_fallback_admission_enforces_budget_and_releases_on_drop() {
        // RAII admission control for cap-shed fallback relays. This is the ONLY unit
        // test that touches the process-global ACTIVE_CAP_SHED_FALLBACKS counter, so
        // there is no intra-binary race; we still measure relative to the baseline
        // and restore it. Pins three things:
        //   - a slot is granted while under budget (kills `-> None` and `>=` -> `<`),
        //   - the counter rises by exactly one per granted slot,
        //   - Drop releases the slot (kills the no-op Drop replacement).
        let baseline = ACTIVE_CAP_SHED_FALLBACKS.load(Ordering::Acquire);
        assert_eq!(baseline, 0, "test fixture expects a quiescent counter");

        // Under budget: the first entry must succeed and bump the counter to 1.
        let slot = try_enter_cap_shed_fallback().expect("under budget -> Some");
        assert_eq!(ACTIVE_CAP_SHED_FALLBACKS.load(Ordering::Acquire), 1);

        // Dropping the slot must release the budget back to the baseline. A no-op
        // Drop would leave the counter at 1.
        drop(slot);
        assert_eq!(
            ACTIVE_CAP_SHED_FALLBACKS.load(Ordering::Acquire),
            baseline,
            "dropping a slot must release the budget"
        );

        // Saturate the budget: MAX_CONCURRENT_CAP_SHED_FALLBACKS slots are grantable,
        // the next is refused (None), and the counter never exceeds the cap.
        let mut slots = Vec::new();
        for _ in 0..MAX_CONCURRENT_CAP_SHED_FALLBACKS {
            slots.push(try_enter_cap_shed_fallback().expect("within budget -> Some"));
        }
        assert_eq!(
            ACTIVE_CAP_SHED_FALLBACKS.load(Ordering::Acquire),
            MAX_CONCURRENT_CAP_SHED_FALLBACKS
        );
        assert!(
            try_enter_cap_shed_fallback().is_none(),
            "at the cap a further entry must be refused"
        );
        // The refused attempt must not have leaked budget (its fetch_add was undone).
        assert_eq!(
            ACTIVE_CAP_SHED_FALLBACKS.load(Ordering::Acquire),
            MAX_CONCURRENT_CAP_SHED_FALLBACKS
        );

        // Release everything; the counter returns to baseline.
        drop(slots);
        assert_eq!(ACTIVE_CAP_SHED_FALLBACKS.load(Ordering::Acquire), baseline);
    }

    /// Read-ahead pipelining regression: the bulk `server_download_loop` overlaps
    /// the next origin read with the in-flight client write, ping-ponging two read
    /// buffers and two seal scratches. This proves the pipeline relays every byte
    /// exactly once, in order, with NO loss, reordering, or duplication across the
    /// buffer swaps — including bursts large enough to trigger the parallel-AEAD
    /// path — and that a clean origin EOF is propagated as a FIN to the client side.
    #[tokio::test]
    async fn download_pipeline_relays_bytes_byte_exact_across_buffer_swaps() {
        use rand::{rngs::StdRng, RngCore, SeedableRng};
        use tokio::time::{timeout, Duration};

        use crate::crypto::session::{AeadCodec, KEY_LEN, NONCE_LEN};
        use crate::protocol::data::{max_plaintext_len, relay_read_buffer_len, DataRecordCodec};

        // Matched seal (loop) / open (verifier) codec pair: same key + nonce base,
        // server->client direction, zero padding so the opened plaintext is exactly
        // the origin bytes.
        fn codec() -> DataRecordCodec {
            let key = [0x55_u8; KEY_LEN];
            let nonce = [0x66_u8; NONCE_LEN];
            let padding = PaddingProfile::new(0, 0).unwrap();
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD)
        }

        // Several MiB of deterministic data so multiple 256 KiB relay reads (and
        // hence multiple buffer swaps + parallel seals) occur.
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        let mut payload = vec![0_u8; 6 * 1024 * 1024 + 4321];
        rng.fill_bytes(&mut payload);

        // origin/target -> server download loop: a real TCP pair.
        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let payload_for_origin = payload.clone();
        let origin = tokio::spawn(async move {
            let mut target = tokio::net::TcpStream::connect(origin_addr).await.unwrap();
            target.write_all(&payload_for_origin).await.unwrap();
            // Drop closes the write half -> the download loop reads EOF and FINs.
        });
        let (origin_for_loop, _) = origin_listener.accept().await.unwrap();
        let (target_read, _target_write_unused) = origin_for_loop.into_split();

        // server download loop -> client side: a second TCP pair carrying sealed
        // records, opened in order by the client end.
        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let collector = tokio::spawn(async move {
            let (client_side, _) = client_listener.accept().await.unwrap();
            let (client_read, _client_write_unused) = client_side.into_split();
            let mut reader = crate::transport::leg::TcpLegReader::buffered(client_read);
            let mut open = codec();
            let mut record = Vec::new();
            let mut plaintext = Vec::new();
            loop {
                match reader.read_record_into(&mut record).await {
                    Ok(()) => {
                        let range = open.open_in_place_payload_range(&mut record).unwrap();
                        plaintext.extend_from_slice(&record[range]);
                    }
                    Err(err) if reader.is_clean_close(&err) => break,
                    Err(err) => panic!("unexpected reader error: {err}"),
                }
            }
            plaintext
        });
        let client_for_loop = tokio::net::TcpStream::connect(client_addr).await.unwrap();
        let (_client_read_unused, client_write) = client_for_loop.into_split();

        let target_buf = vec![0_u8; relay_read_buffer_len(max_plaintext_len(0))];
        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let traffic = TrafficConfig::default();
        let download = server_download_loop(
            target_read,
            crate::transport::leg::TcpLegWriter(client_write),
            codec(),
            target_buf,
            TimingProfile::from_config(traffic),
            CoverTrafficProfile::from_config(traffic),
            activity,
            9,
        );

        let (loop_res, origin_res, collected) = timeout(Duration::from_secs(30), async {
            tokio::join!(download, origin, collector)
        })
        .await
        .expect("pipeline relay must complete promptly");
        loop_res.expect("download loop returns Ok on clean EOF");
        origin_res.expect("origin task");
        let collected = collected.expect("collector task");

        assert_eq!(
            collected.len(),
            payload.len(),
            "pipeline must relay exactly the origin byte count (no loss/duplication)"
        );
        assert!(
            collected == payload,
            "pipeline must relay every byte in order, byte-exact across buffer swaps"
        );
    }

    /// Covertness/serial-branch regression for the saturated-buffer gate: a payload
    /// SMALLER than the relay read buffer never saturates it, so it must take the
    /// pure-serial (no read-ahead, no spare allocation) branch and relay byte-exact.
    /// This pins the non-bulk path the gate routes short/interactive flows through,
    /// whose burst segmentation is identical to the pre-pipeline serial loop.
    ///
    /// Reads the process-global `DOWNLOAD_READ_AHEAD_ENGAGED` counter that other
    /// parallel relay tests can perturb, so it is `#[ignore]`d and run serially
    /// (CI runs `cargo test -- --ignored --test-threads=1`), matching the
    /// `REJECT_DH_OPS` counter-test convention. The counter-unchanged assertion is
    /// the part that distinguishes a correctly-gated serial relay from an
    /// unconditional read-ahead (which would also relay byte-exact).
    #[tokio::test]
    #[ignore = "reads the process-global DOWNLOAD_READ_AHEAD_ENGAGED counter; run serially"]
    async fn download_short_flow_takes_serial_branch_byte_exact() {
        use rand::{rngs::StdRng, RngCore, SeedableRng};
        use tokio::time::{timeout, Duration};

        use crate::crypto::session::{AeadCodec, KEY_LEN, NONCE_LEN};
        use crate::protocol::data::{max_plaintext_len, relay_read_buffer_len, DataRecordCodec};

        fn codec() -> DataRecordCodec {
            let key = [0x77_u8; KEY_LEN];
            let nonce = [0x88_u8; NONCE_LEN];
            let padding = PaddingProfile::new(0, 0).unwrap();
            DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD)
        }

        // A few KiB: far below the 256 KiB relay buffer, so the read never fills it
        // and the loop stays on the serial branch.
        let mut rng = StdRng::seed_from_u64(0x1234);
        let mut payload = vec![0_u8; 7777];
        rng.fill_bytes(&mut payload);

        // Snapshot the saturated-read-ahead engagement counter; for a sub-buffer
        // flow it must NOT advance (the whole point of the saturated gate). This is
        // what distinguishes a correctly-gated serial relay from an unconditional
        // read-ahead, which would also relay byte-exact and pass the byte check.
        let read_ahead_before = DOWNLOAD_READ_AHEAD_ENGAGED.load(Ordering::Relaxed);

        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let payload_for_origin = payload.clone();
        let origin = tokio::spawn(async move {
            let mut target = tokio::net::TcpStream::connect(origin_addr).await.unwrap();
            target.write_all(&payload_for_origin).await.unwrap();
        });
        let (origin_for_loop, _) = origin_listener.accept().await.unwrap();
        let (target_read, _target_write_unused) = origin_for_loop.into_split();

        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let collector = tokio::spawn(async move {
            let (client_side, _) = client_listener.accept().await.unwrap();
            let (client_read, _client_write_unused) = client_side.into_split();
            let mut reader = crate::transport::leg::TcpLegReader::buffered(client_read);
            let mut open = codec();
            let mut record = Vec::new();
            let mut plaintext = Vec::new();
            loop {
                match reader.read_record_into(&mut record).await {
                    Ok(()) => {
                        let range = open.open_in_place_payload_range(&mut record).unwrap();
                        plaintext.extend_from_slice(&record[range]);
                    }
                    Err(err) if reader.is_clean_close(&err) => break,
                    Err(err) => panic!("unexpected reader error: {err}"),
                }
            }
            plaintext
        });
        let client_for_loop = tokio::net::TcpStream::connect(client_addr).await.unwrap();
        let (_client_read_unused, client_write) = client_for_loop.into_split();

        let target_buf = vec![0_u8; relay_read_buffer_len(max_plaintext_len(0))];
        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let traffic = TrafficConfig::default();
        let download = server_download_loop(
            target_read,
            crate::transport::leg::TcpLegWriter(client_write),
            codec(),
            target_buf,
            TimingProfile::from_config(traffic),
            CoverTrafficProfile::from_config(traffic),
            activity,
            11,
        );

        let (loop_res, origin_res, collected) = timeout(Duration::from_secs(30), async {
            tokio::join!(download, origin, collector)
        })
        .await
        .expect("serial-branch relay must complete promptly");
        loop_res.expect("download loop returns Ok on clean EOF");
        origin_res.expect("origin task");
        let collected = collected.expect("collector task");

        assert_eq!(
            collected, payload,
            "short flow must relay byte-exact via the serial branch"
        );
        assert_eq!(
            DOWNLOAD_READ_AHEAD_ENGAGED.load(Ordering::Relaxed),
            read_ahead_before,
            "a sub-buffer flow must NOT engage the saturated read-ahead branch \
             (the saturated gate must keep short/interactive flows on the serial path)",
        );

        // Conversely, a multi-MiB saturating transfer MUST engage the read-ahead
        // branch — proving the gate is not vacuously always-serial. Run in the same
        // serial test so the counter delta is race-free.
        let bulk_before = DOWNLOAD_READ_AHEAD_ENGAGED.load(Ordering::Relaxed);
        let mut bulk = vec![0_u8; 4 * 1024 * 1024 + 99];
        rng.fill_bytes(&mut bulk);

        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let bulk_for_origin = bulk.clone();
        let origin = tokio::spawn(async move {
            let mut target = tokio::net::TcpStream::connect(origin_addr).await.unwrap();
            target.write_all(&bulk_for_origin).await.unwrap();
        });
        let (origin_for_loop, _) = origin_listener.accept().await.unwrap();
        let (target_read, _t) = origin_for_loop.into_split();

        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let collector = tokio::spawn(async move {
            let (client_side, _) = client_listener.accept().await.unwrap();
            let (client_read, _c) = client_side.into_split();
            let mut reader = crate::transport::leg::TcpLegReader::buffered(client_read);
            let mut open = codec();
            let mut record = Vec::new();
            let mut plaintext = Vec::new();
            loop {
                match reader.read_record_into(&mut record).await {
                    Ok(()) => {
                        let range = open.open_in_place_payload_range(&mut record).unwrap();
                        plaintext.extend_from_slice(&record[range]);
                    }
                    Err(err) if reader.is_clean_close(&err) => break,
                    Err(err) => panic!("unexpected reader error: {err}"),
                }
            }
            plaintext
        });
        let client_for_loop = tokio::net::TcpStream::connect(client_addr).await.unwrap();
        let (_c, client_write) = client_for_loop.into_split();

        let target_buf = vec![0_u8; relay_read_buffer_len(max_plaintext_len(0))];
        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let traffic = TrafficConfig::default();
        let download = server_download_loop(
            target_read,
            crate::transport::leg::TcpLegWriter(client_write),
            codec(),
            target_buf,
            TimingProfile::from_config(traffic),
            CoverTrafficProfile::from_config(traffic),
            activity,
            13,
        );
        let (loop_res, origin_res, collected) = timeout(Duration::from_secs(30), async {
            tokio::join!(download, origin, collector)
        })
        .await
        .expect("bulk relay must complete promptly");
        loop_res.expect("download loop returns Ok on clean EOF");
        origin_res.expect("origin task");
        let collected = collected.expect("collector task");
        assert_eq!(collected, bulk, "bulk flow must relay byte-exact");
        assert!(
            DOWNLOAD_READ_AHEAD_ENGAGED.load(Ordering::Relaxed) > bulk_before,
            "a multi-MiB saturating transfer must engage the read-ahead pipeline branch \
             (the saturated gate must not be vacuously always-serial)",
        );
    }

    /// Item #1 (deterministic teeth): on a mid-relay ERROR the download loop must
    /// FIN (call `shutdown` on) its client-facing write half — not bare-drop it.
    /// A mock `LegWriter` whose write always fails drives the loop into its error
    /// path and records whether `shutdown` was invoked. Transport-agnostic, so it
    /// distinguishes the fix from the pre-fix bare-drop (which never called
    /// `shutdown`), independent of tokio's TCP shutdown-on-drop.
    #[tokio::test]
    async fn download_loop_fins_client_write_on_relay_error() {
        use std::sync::atomic::AtomicBool;
        use tokio::time::{timeout, Duration};

        use crate::crypto::session::{AeadCodec, KEY_LEN, NONCE_LEN};
        use crate::protocol::data::{max_plaintext_len, relay_read_buffer_len, DataRecordCodec};

        struct FinRecordingWriter {
            shutdown_called: Arc<AtomicBool>,
        }
        impl LegWriter for FinRecordingWriter {
            async fn write_records(&mut self, _bytes: &[u8]) -> io::Result<()> {
                // Force the relay's error path on the very first client write.
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "client stopped reading",
                ))
            }
            async fn shutdown(&mut self) -> io::Result<()> {
                self.shutdown_called.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let key = [0x33_u8; KEY_LEN];
        let nonce = [0x44_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let codec = DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD);

        // Target -> loop: a real TCP pair; the peer sends a few bytes (a sub-buffer
        // burst, so the loop takes the serial branch and reaches the client write)
        // and stays open, so the loop's error is the failing WRITE, not an EOF.
        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let mut target = tokio::net::TcpStream::connect(origin_addr).await.unwrap();
            target.write_all(b"some-origin-bytes").await.unwrap();
            tokio::time::sleep(Duration::from_secs(3)).await;
        });
        let (origin_for_loop, _) = origin_listener.accept().await.unwrap();
        let (target_read, _target_write) = origin_for_loop.into_split();

        let shutdown_called = Arc::new(AtomicBool::new(false));
        let writer = FinRecordingWriter {
            shutdown_called: shutdown_called.clone(),
        };

        let target_buf = vec![0_u8; relay_read_buffer_len(max_plaintext_len(0))];
        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let traffic = TrafficConfig::default();
        let result = timeout(
            Duration::from_secs(10),
            server_download_loop(
                target_read,
                writer,
                codec,
                target_buf,
                TimingProfile::from_config(traffic),
                CoverTrafficProfile::from_config(traffic),
                activity,
                21,
            ),
        )
        .await
        .expect("download loop must return promptly on a client write error");

        assert!(
            result.is_err(),
            "a failing client write must surface as a relay error"
        );
        assert!(
            shutdown_called.load(Ordering::SeqCst),
            "on a mid-relay error the download loop must FIN (shutdown) the client-facing \
             write half, not bare-drop it",
        );
        origin.abort();
    }

    /// Item #1 (observable, over real TCP): a mid-relay error (here: the TARGET
    /// resets) must leave the client-facing socket a clean FIN — the client peer's
    /// drain ends in `read == 0`, never `ECONNRESET`. This is the no-RST-on-teardown
    /// invariant the loop must uphold on the error path, not just the clean-EOF path.
    #[tokio::test]
    async fn download_loop_relay_error_fins_client_not_rst() {
        use tokio::io::AsyncReadExt;
        use tokio::time::{timeout, Duration};

        use crate::crypto::session::{AeadCodec, KEY_LEN, NONCE_LEN};
        use crate::protocol::data::{max_plaintext_len, relay_read_buffer_len, DataRecordCodec};

        let key = [0x35_u8; KEY_LEN];
        let nonce = [0x46_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let codec = DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD);

        // Target side: the peer sets SO_LINGER(0) and drops after a short delay, so
        // the server's target read errors with a RST (ECONNRESET), driving the loop
        // into its error path (NOT a clean EOF).
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_peer = tokio::spawn(async move {
            let peer = tokio::net::TcpStream::connect(target_addr).await.unwrap();
            // Force an RST (not a FIN) on drop by setting SO_LINGER(0). Use socket2's
            // SockRef (as the rest of the tree does) since tokio's `set_linger` is
            // deprecated (it can block the thread on drop; here the socket is dropped
            // explicitly with no queued send data, so the linger-close is immediate).
            socket2::SockRef::from(&peer)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(peer); // linger 0 -> RST to the server's target read half
        });
        let (target_for_loop, _) = target_listener.accept().await.unwrap();
        let (target_read, _target_write) = target_for_loop.into_split();

        // Client side: the download loop's client-facing write half; the peer drains
        // and must observe a FIN, never a reset.
        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client_peer = tokio::spawn(async move {
            let (mut client_side, _) = client_listener.accept().await.unwrap();
            let mut scratch = [0_u8; 4096];
            loop {
                match client_side.read(&mut scratch).await {
                    Ok(0) => return Ok(()), // clean FIN
                    Ok(_) => continue,      // relayed record bytes, keep draining
                    Err(err) => return Err(err),
                }
            }
        });
        let client_for_loop = tokio::net::TcpStream::connect(client_addr).await.unwrap();
        let (_client_read, client_write) = client_for_loop.into_split();

        let target_buf = vec![0_u8; relay_read_buffer_len(max_plaintext_len(0))];
        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let traffic = TrafficConfig::default();
        let download = server_download_loop(
            target_read,
            crate::transport::leg::TcpLegWriter(client_write),
            codec,
            target_buf,
            TimingProfile::from_config(traffic),
            CoverTrafficProfile::from_config(traffic),
            activity,
            23,
        );

        let (loop_res, peer_res, _target_res) = timeout(Duration::from_secs(10), async {
            tokio::join!(download, client_peer, target_peer)
        })
        .await
        .expect("relay-error teardown must complete promptly");

        assert!(
            loop_res.is_err(),
            "the target RST must surface as a relay error"
        );
        let peer_drain = peer_res.expect("client peer task");
        assert!(
            peer_drain.is_ok(),
            "client must see a clean FIN on relay error, got {:?} (an RST/ECONNRESET is the \
             censor-observable teardown tell the loop must never produce)",
            peer_drain.err().map(|e| e.kind()),
        );
    }

    /// Item #3a: the `OfferRegistrationGuard` must unregister its `offer_id` on
    /// EVERY scope exit. Before this guard the only unregister lived on the
    /// probe-timeout arm, so an early `?` on the offer seal / offer-record write
    /// returned first and leaked the carrier's oneshot sender (an unbounded
    /// per-failed-negotiation registry leak). Here: register an offer, confirm the
    /// receiver is live (pending, not closed), drop the guard, then confirm the
    /// sender was removed — the receiver observes a CLOSED channel. A leak would
    /// keep the sender parked in the registry and the receiver open, so the
    /// closed-channel observation is exactly the tell the fix restores.
    #[tokio::test]
    async fn offer_registration_guard_unregisters_on_drop() {
        use tokio::sync::oneshot::error::TryRecvError;

        // A production carrier bound on loopback: no external network is needed —
        // the numeric fallback_addr resolves without DNS, the camouflage cert is
        // self-signed in-process, the replay cache is a temp file, and the endpoint
        // binds 127.0.0.1:0. This is the same build path production uses.
        let server_keys = X25519KeyPair::generate();
        let server_identity_keys = identity::keypair();
        let replay_cache_dir = tempfile::tempdir().unwrap();
        let config = authenticated_server_config(
            "127.0.0.1:443".parse().unwrap(),
            &server_keys,
            &server_identity_keys,
            replay_cache_dir.path().join("parallax-replay.cache"),
        );
        let carrier = build_quic_carrier_for_test(&config, PSK)
            .await
            .expect("bind loopback stable carrier");

        let offer_id = [0x5c_u8; 16];
        let mut rx = carrier.register(offer_id);
        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Empty)),
            "a freshly registered offer_id must have a live (pending) sender"
        );

        {
            // The guard is the ONLY thing that unregisters here; dropping it at the
            // end of this scope must remove the registry entry unconditionally.
            let _guard = OfferRegistrationGuard {
                carrier: carrier.clone(),
                offer_id,
            };
        }

        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Closed)),
            "dropping the guard must unregister the offer_id (drop its sender) so the \
             receiver observes a closed channel — not a leaked, still-open entry",
        );
    }

    /// Item #3b: a non-reading authenticated client must not wedge the mux writer
    /// forever. Once a client-facing write exceeds the idle backstop, the writer
    /// SHEDS (returns `Timeout`) so `try_join!` tears the session down and releases
    /// the frame channel + relayed target fds. A `LegWriter` whose `write_records`
    /// never completes models the wedged client; with a short injected idle the
    /// loop must return `Err(Timeout)` promptly instead of parking indefinitely.
    #[tokio::test]
    async fn mux_writer_sheds_when_client_write_stalls() {
        use crate::crypto::session::{AeadCodec, KEY_LEN, NONCE_LEN};
        use crate::protocol::data::{max_plaintext_len, DataRecordCodec};

        struct StalledWriter;
        impl LegWriter for StalledWriter {
            async fn write_records(&mut self, _bytes: &[u8]) -> io::Result<()> {
                // A wedged client: the client-facing write never drains.
                std::future::pending().await
            }
            async fn shutdown(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let key = [0x51_u8; KEY_LEN];
        let nonce = [0x62_u8; NONCE_LEN];
        let padding = PaddingProfile::new(0, 0).unwrap();
        let codec = DataRecordCodec::new(AeadCodec::new(key, nonce), padding, SERVER_TO_CLIENT_AAD);

        let chunk_size = max_plaintext_len(0);
        let payload_pool = MuxPayloadPool::with_capacity(MuxFrame::max_payload_len(chunk_size));
        let (frame_tx, frame_rx) = mpsc::channel(SERVER_MUX_FRAME_CHANNEL);

        // One real frame so the loop takes the write path (where the mock parks).
        // Keep the sender alive so `recv()` never returns None — otherwise the loop
        // would exit cleanly instead of exercising the wedge-shed.
        frame_tx
            .send(MuxFrame {
                stream_id: 1,
                kind: MuxFrameKind::Data,
                payload: b"payload".to_vec(),
            })
            .await
            .unwrap();

        // Cover is disabled by default (cover_max_interval_ms == 0), so the simpler
        // non-cover write branch runs. Inject a short idle so the shed is observable
        // without the production 600s wait.
        let cover = CoverTrafficProfile::from_config(TrafficConfig::default());
        assert!(
            !cover.is_enabled(),
            "test relies on the non-cover write branch"
        );
        let idle = Duration::from_millis(50);

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            server_mux_writer_loop(StalledWriter, codec, frame_rx, cover, 7, payload_pool, idle),
        )
        .await
        .expect("the mux writer must shed (return) well before the outer 5s budget");

        assert!(
            matches!(result, Err(HandshakeServerError::Timeout)),
            "a wedged client-facing write past the idle backstop must shed as Timeout, \
             got {result:?}",
        );
        drop(frame_tx);
    }
}
