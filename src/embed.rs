//! Embedding API: the ParallaX client inside another process.
//!
//! The CLI owns a SOCKS5 listener, process hardening, a Tokio runtime and config
//! files. An embedder (an iOS packet tunnel, a desktop TUN engine) already owns
//! all of that and must not have it replaced. This module is the client without
//! any of it: no listener, no files, no environment variables, no tracing
//! subscriber, no resource limits, no process-wide hooks. The embedder hands over
//! byte streams and datagram flows it has already accepted from its own
//! applications, and the client relays them over pooled, authenticated mux
//! sessions with exactly the CLI's frames and records.
//!
//! The contract — runtime and threading rules, memory profiles, what this module
//! must never do, and the versioning policy — is `EMBEDDING.md` at the repository
//! root. Any change to this module's public items bumps [`API_VERSION`].

use std::{
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::{
    client::runtime::{
        embedded_mux_pool, next_client_connection_id, relay_mux_stream, ClientMuxPool,
        ClientRelayLimits, ClientRuntimeError, ClientUdpAssociation, UdpOpenError, UdpSendError,
    },
    config::{
        decode_base64_bytes, decode_key32, decode_psk, ClientConfig, Config, ConfigError,
        TrafficConfig, UdpConfig,
    },
};

pub use crate::client::local::{LocalReader, LocalWriter};
pub use crate::tls::safari26::ServerCertVerifier;

/// Version of this module's public contract. An embedder pins the value it was
/// written against and fails its build on a mismatch; see `EMBEDDING.md` for the
/// bump policy and changelog.
pub const API_VERSION: u32 = 1;

/// Datagrams an association buffers toward the embedder before dropping.
const UDP_ASSOCIATION_QUEUE: usize = 64;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EmbedError {
    /// The profile failed to parse or validate. Messages never contain secrets.
    #[error("invalid client profile: {0}")]
    Profile(#[from] ConfigError),
    /// [`Client::start`] ran outside a Tokio runtime.
    #[error("Client::start must be called inside a Tokio runtime")]
    NoRuntime,
    /// [`Client::shutdown`] has run; the client accepts no more work.
    #[error("the ParallaX client is shut down")]
    Shutdown,
    /// The server does not relay UDP (it predates `PX1A`, relays only to an
    /// operator-fixed target, or the session runs on the QUIC plane).
    #[error("the ParallaX server does not relay UDP")]
    UdpUnsupported,
    /// The server refused this UDP target (resolution or egress policy).
    #[error("the ParallaX server refused the UDP target")]
    UdpRefused,
    /// A datagram exceeds what one mux frame carries on this session.
    #[error("datagram exceeds the {max}-byte association limit")]
    DatagramTooLarge { max: usize },
    /// The UDP association has ended.
    #[error("the UDP association is closed")]
    UdpClosed,
    /// Session establishment or the relay itself failed.
    #[error(transparent)]
    Relay(ClientRuntimeError),
}

/// A validated client profile: the CLI's client TOML, held in memory.
///
/// Secrets must be inline (`psk = "base64…"`); file, environment, and sealed
/// references are rejected because resolving them would touch the host's
/// filesystem or environment. `client.listen` may be omitted. Validation is the
/// CLI's own, minus the file-permission checks that only apply to files.
pub struct ClientProfile {
    config: ClientConfig,
    traffic: TrafficConfig,
    udp: UdpConfig,
    psk: Zeroizing<Vec<u8>>,
    server_public: [u8; 32],
    server_identity_public: Arc<[u8]>,
}

impl ClientProfile {
    /// Parses and validates a client-mode TOML profile. The caller owns `toml`
    /// and should wipe it once this returns; every copy this crate keeps of a
    /// secret is zeroized on drop.
    pub fn from_toml_str(toml: &str) -> Result<Self, EmbedError> {
        let config = Config::from_embedded_client_toml(toml)?;
        let client = config.client.clone().ok_or(ConfigError::MissingClient)?;
        let psk = decode_psk(config.crypto.psk.as_b64())?;
        let server_public = decode_key32("client.server_public_key", &client.server_public_key)?;
        let server_identity_public = Arc::<[u8]>::from(
            decode_base64_bytes(
                "client.server_identity_public_key",
                &client.server_identity_public_key,
            )?
            .into_boxed_slice(),
        );
        Ok(Self {
            config: client,
            traffic: config.traffic,
            udp: config.udp,
            psk,
            server_public,
            server_identity_public,
        })
    }

    /// The configured server address (`host:port`).
    pub fn server_addr(&self) -> &str {
        &self.config.server_addr
    }

    /// The camouflage server name.
    pub fn sni(&self) -> &str {
        &self.config.sni
    }

    /// Streams one mux session carries before the pool opens another.
    pub fn max_concurrent_streams(&self) -> u8 {
        self.traffic.max_concurrent_streams
    }
}

impl fmt::Debug for ClientProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientProfile")
            .field("server_addr", &self.config.server_addr)
            .field("sni", &self.config.sni)
            .finish_non_exhaustive()
    }
}

/// How much memory the client data path may use. Neither profile changes a
/// byte on the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryProfile {
    /// The CLI's tuning: large reads and batches, and bulk AEAD fanned out to a
    /// process-wide crypto thread pool.
    #[default]
    Standard,
    /// For hosts with a hard memory ceiling, such as an iOS packet tunnel
    /// extension: small per-stream buffers, shallow queues, one idle session,
    /// and all AEAD work on the relay's own task (no crypto pool threads).
    Constrained,
}

/// Upper bounds of the buffers the client keeps, per [`MemoryProfile`]. Bytes
/// held by the operating system (socket buffers), by the embedder's own halves,
/// and transient handshake state are not included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryBudget {
    /// One open, idle stream: its read buffer and its pending upload tail.
    pub stream_steady_bytes: usize,
    /// One stream at full throughput in both directions.
    pub stream_peak_bytes: usize,
    /// One mux session, shared by its streams: record reader, open and seal
    /// batches, and the recycled payload buffers.
    pub session_bytes: usize,
    /// Fully idle sessions the pool keeps open for reuse.
    pub idle_sessions: usize,
    /// Whether bulk AEAD may run on the process-wide crypto thread pool.
    pub crypto_pool_threads: bool,
}

/// Largest plaintext one record or frame payload carries (default padding).
const MAX_FRAME_PAYLOAD: usize = 16 * 1024;

impl MemoryProfile {
    fn limits(self) -> ClientRelayLimits {
        match self {
            Self::Standard => ClientRelayLimits::STANDARD,
            Self::Constrained => ClientRelayLimits::CONSTRAINED,
        }
    }

    /// The buffer bounds this profile guarantees (see [`MemoryBudget`]).
    pub fn budget(self) -> MemoryBudget {
        let limits = self.limits();
        let read_buffer = limits.read_buffer_len(MAX_FRAME_PAYLOAD);
        // Upload: read buffer + one held tail frame + this stream's share of the
        // session's upload queue. Download: its channel + the frame being written.
        let stream_peak_bytes = read_buffer
            + MAX_FRAME_PAYLOAD
            + limits.frame_channel_per_stream * MAX_FRAME_PAYLOAD
            + (limits.stream_channel + 1) * MAX_FRAME_PAYLOAD;
        let open_batch = limits.open_batch_bytes + MAX_FRAME_PAYLOAD;
        let seal_batch = (limits.frame_batch_limit + 1) * MAX_FRAME_PAYLOAD;
        let session_bytes = limits.record_read_buffer
            + 2 * MAX_FRAME_PAYLOAD
            + 2 * open_batch
            + 2 * seal_batch
            + limits.payload_pool_buffers * MAX_FRAME_PAYLOAD;
        MemoryBudget {
            stream_steady_bytes: read_buffer + MAX_FRAME_PAYLOAD,
            stream_peak_bytes,
            session_bytes,
            idle_sessions: limits.max_idle_sessions,
            crypto_pool_threads: limits.parallel_aead,
        }
    }
}

/// Options for [`Client::start`].
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ClientOptions {
    pub memory: MemoryProfile,
    /// Validates the camouflage origin's certificate chain in place of webpki
    /// with the native root store. Required where that store cannot be loaded
    /// (iOS); `None` keeps the CLI's path.
    pub cert_verifier: Option<Arc<dyn ServerCertVerifier>>,
}

impl ClientOptions {
    pub fn with_memory(mut self, memory: MemoryProfile) -> Self {
        self.memory = memory;
        self
    }

    pub fn with_cert_verifier(mut self, verifier: Arc<dyn ServerCertVerifier>) -> Self {
        self.cert_verifier = Some(verifier);
        self
    }
}

impl fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientOptions")
            .field("memory", &self.memory)
            .field("cert_verifier", &self.cert_verifier.is_some())
            .finish()
    }
}

/// Where a proxied stream or datagram flow goes. The server resolves names, so
/// an embedder that answered DNS itself can pass the name it handed out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Domain(String, u16),
    Ip(SocketAddr),
}

impl Target {
    fn into_host_port(self) -> (String, u16) {
        match self {
            Self::Domain(host, port) => (host, port),
            // Bracketless, like the SOCKS5 front-end's IPv6 mapping (SPEC §15.1).
            Self::Ip(addr) => (addr.ip().to_string(), addr.port()),
        }
    }
}

/// Application bytes one finished relay moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayReport {
    /// Read from the embedder's reader and sent toward the target.
    pub bytes_up: u64,
    /// Received from the target and written to the embedder's writer.
    pub bytes_down: u64,
}

/// A running embedded client. Cheap to clone; every clone shares one session
/// pool. Dropping the last clone shuts it down.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    pool: ClientMuxPool,
    runtime: tokio::runtime::Handle,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        let teardown = self.pool.shutdown();
        self.runtime.spawn(teardown);
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("shut_down", &self.inner.pool.is_shut_down())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Starts a client on the current Tokio runtime (any flavor). No I/O happens
    /// until the first stream: the server address resolves then, and sessions
    /// open on demand.
    pub fn start(profile: ClientProfile, options: ClientOptions) -> Result<Self, EmbedError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| EmbedError::NoRuntime)?;
        // The per-record core-dump toggle would otherwise be read from the
        // environment on the first mux frame; an embedder's process has no core
        // dumps to protect and must not have its environment read.
        crate::process_hardening::set_transient_plaintext_hardening(false);
        let ClientProfile {
            config,
            traffic,
            udp,
            psk,
            server_public,
            server_identity_public,
        } = profile;
        let pool = embedded_mux_pool(
            config,
            traffic,
            udp,
            psk,
            server_public,
            server_identity_public,
            options.memory.limits(),
            options.cert_verifier,
        );
        pool.start_keeper();
        Ok(Self {
            inner: Arc::new(ClientInner { pool, runtime }),
        })
    }

    /// Relays one application stream to `target` until both directions end.
    ///
    /// `read` yields the application's upload; `write` receives its download. A
    /// clean server close shuts `write` down gracefully; a reset or failure calls
    /// [`LocalWriter::abort`]. Safe to cancel: dropping the future resets the
    /// stream on the server and releases its slot.
    pub async fn relay_tcp<R, W>(
        &self,
        target: Target,
        read: R,
        write: W,
    ) -> Result<RelayReport, EmbedError>
    where
        R: LocalReader,
        W: LocalWriter,
    {
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let (host, port) = target.into_host_port();
        relay_mux_stream(
            host,
            port,
            Counted::new(read, Arc::clone(&up)),
            Counted::new(write, Arc::clone(&down)),
            &self.inner.pool,
            next_client_connection_id(),
        )
        .await
        .map_err(|err| self.relay_error(err))?;
        Ok(RelayReport {
            bytes_up: up.load(Ordering::Relaxed),
            bytes_down: down.load(Ordering::Relaxed),
        })
    }

    /// Opens a UDP association toward `target` (SPEC §6.7).
    pub async fn open_udp(&self, target: Target) -> Result<UdpAssociation, EmbedError> {
        let (host, port) = target.into_host_port();
        match self
            .inner
            .pool
            .open_udp(host, port, UDP_ASSOCIATION_QUEUE)
            .await
        {
            Ok(inner) => Ok(UdpAssociation { inner }),
            Err(UdpOpenError::Unsupported) => Err(EmbedError::UdpUnsupported),
            Err(UdpOpenError::Refused) => Err(EmbedError::UdpRefused),
            Err(UdpOpenError::Runtime(err)) => Err(self.relay_error(err)),
        }
    }

    /// Tells the client the host's network path changed (for example Wi-Fi to
    /// cellular). Sessions built on the old path end at once — their streams
    /// fail so applications reconnect — and the next session re-resolves the
    /// server and re-probes UDP. Callable from any thread.
    pub fn network_changed(&self) {
        let reap = self.inner.pool.network_changed();
        self.inner.runtime.spawn(reap);
    }

    /// Stops the client: every session, build and background task ends, and
    /// later calls fail with [`EmbedError::Shutdown`]. Callable from any thread;
    /// idempotent.
    pub fn shutdown(&self) {
        let teardown = self.inner.pool.shutdown();
        self.inner.runtime.spawn(teardown);
    }

    pub fn is_shut_down(&self) -> bool {
        self.inner.pool.is_shut_down()
    }

    fn relay_error(&self, err: ClientRuntimeError) -> EmbedError {
        if self.inner.pool.is_shut_down() {
            EmbedError::Shutdown
        } else {
            EmbedError::Relay(err)
        }
    }
}

/// One UDP flow relayed over a mux session (SPEC §6.7). Dropping it without
/// [`UdpAssociation::close`] resets the association on the server.
pub struct UdpAssociation {
    inner: ClientUdpAssociation,
}

/// Datagrams an association dropped rather than block (UDP semantics).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpDrops {
    /// From the server, because the embedder was not receiving fast enough.
    pub inbound: u64,
    /// Toward the server: queue full, oversize, or empty.
    pub outbound: u64,
}

impl UdpAssociation {
    /// Largest datagram [`UdpAssociation::send`] accepts.
    pub fn max_datagram_len(&self) -> usize {
        self.inner.max_datagram_len()
    }

    /// Queues one datagram without waiting. `Ok(false)` means it was dropped
    /// (the session's send queue is full, or the datagram is empty), as a full
    /// socket buffer would drop it.
    pub fn send(&self, datagram: &[u8]) -> Result<bool, EmbedError> {
        self.inner.send(datagram).map_err(|err| match err {
            UdpSendError::TooLarge(max) => EmbedError::DatagramTooLarge { max },
            UdpSendError::Closed => EmbedError::UdpClosed,
        })
    }

    /// Waits for the next datagram, copies it into `buf`, and returns its full
    /// length (a longer datagram is truncated to `buf`, as `recv(2)` does).
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, EmbedError> {
        self.inner.recv(buf).await.ok_or(EmbedError::UdpClosed)
    }

    pub fn dropped(&self) -> UdpDrops {
        let (inbound, outbound) = self.inner.dropped();
        UdpDrops { inbound, outbound }
    }

    /// Ends the association cleanly.
    pub async fn close(self) {
        self.inner.close().await;
    }
}

impl fmt::Debug for UdpAssociation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpAssociation")
            .field("max_datagram_len", &self.inner.max_datagram_len())
            .finish_non_exhaustive()
    }
}

/// Counts application bytes through an embedder's half without changing it.
struct Counted<T> {
    inner: T,
    bytes: Arc<AtomicU64>,
}

impl<T> Counted<T> {
    fn new(inner: T, bytes: Arc<AtomicU64>) -> Self {
        Self { inner, bytes }
    }

    fn add(&self, n: usize) {
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            let read = buf.filled().len() - before;
            self.add(read);
        }
        polled
    }
}

impl<T: LocalReader> LocalReader for Counted<T> {
    fn drain_ready(&mut self, buf: &mut [u8], filled: usize) -> io::Result<usize> {
        let drained = self.inner.drain_ready(buf, filled)?;
        self.add(drained.saturating_sub(filled));
        Ok(drained)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            self.add(written);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: LocalWriter> LocalWriter for Counted<T> {
    fn abort(self: Box<Self>) {
        Box::new(self.inner).abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constrained_budget_meets_the_embedding_targets() {
        let constrained = MemoryProfile::Constrained.budget();
        assert!(
            constrained.stream_steady_bytes <= 64 * 1024,
            "{constrained:?}"
        );
        assert!(
            constrained.stream_peak_bytes <= 160 * 1024,
            "{constrained:?}"
        );
        assert!(constrained.session_bytes <= 512 * 1024, "{constrained:?}");
        assert_eq!(constrained.idle_sessions, 1);
        assert!(!constrained.crypto_pool_threads);
    }

    #[test]
    fn standard_profile_is_the_cli_tuning() {
        assert_eq!(MemoryProfile::default(), MemoryProfile::Standard);
        assert_eq!(
            MemoryProfile::Standard.limits(),
            ClientRelayLimits::STANDARD
        );
        let standard = MemoryProfile::Standard.budget();
        assert!(standard.crypto_pool_threads);
        assert_eq!(standard.idle_sessions, 2);
        assert!(standard.stream_peak_bytes > MemoryProfile::Constrained.budget().stream_peak_bytes);
    }

    #[test]
    fn ip_targets_use_the_bracketless_host_form() {
        let v6 = Target::Ip("[2001:db8::1]:443".parse().unwrap()).into_host_port();
        assert_eq!(v6, ("2001:db8::1".to_owned(), 443));
        let v4 = Target::Ip("192.0.2.7:53".parse().unwrap()).into_host_port();
        assert_eq!(v4, ("192.0.2.7".to_owned(), 53));
    }
}
