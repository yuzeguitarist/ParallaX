//! Async endpoint / connection façade over the synchronous [`Connection`] state
//! machine (RFC 9000 §5), clean-room.
//!
//! A single per-endpoint driver task owns the [`tokio::net::UdpSocket`] and every
//! live connection's [`Connection`] core behind a mutex. It pumps the cores on
//! three events — an inbound datagram, an armed loss/PTO/keep-alive timer, or a
//! handle nudging it after queuing outbound work — then flushes each core's
//! [`Connection::poll_transmit`] to the socket and wakes any blocked handles. The
//! client uses a zero-length source connection id, so the server routes datagrams
//! to connections by the UDP 4-tuple (peer address), matching the scope note in
//! [`super`].
//!
//! This module presents the quinn-shaped surface the carrier expects — `Endpoint`
//! (`client` / `server` / `connect` / `accept` / `local_addr` / `close`),
//! `Connection` (`open_bi` / `accept_bi` / `open_uni` / `accept_uni` /
//! `export_keying_material` / `close`), and `SendStream` / `RecvStream`
//! (`AsyncWrite` / `AsyncRead`) — so the cutover is a re-export swap.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

use super::conn::{CloseReason, Connection as Core};
use super::packet::{first_packet_space, ConnectionId, PacketSpace};
use super::splice::SpliceFlow;
use crate::tls::quic::{ClientConfig, ClientTicket, QuicTlsError, ZeroRttGuard, QUIC_VERSION_V1};
use zeroize::Zeroizing;

/// Maximum UDP payload we will read in one datagram (a generous ceiling above the
/// path MTU; oversized datagrams are truncated, which fails AEAD and is dropped).
const MAX_UDP_PAYLOAD: usize = 2048;

/// Minimum size of a datagram carrying a client's first Initial (RFC 9000 §14.1):
/// a server MUST discard smaller Initials. Used to gate server connection creation.
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// Hard cap on concurrently-tracked connections. A DoS backstop: UDP source
/// addresses are spoofable and there is no Retry address validation yet, so without
/// a cap an off-path attacker spraying spoofed Initials could allocate connection
/// state without bound. (Finer-grained per-address Retry validation is future work.)
const MAX_SERVER_CONNS: usize = 1 << 16;

/// Hard cap on concurrently-spliced flows (the QUIC origin-fallback relay). A DoS
/// backstop: spoofed sources could otherwise drive unbounded upstream sockets at the
/// origin. Past the cap, new probe flows are dropped — degrading like a real origin
/// shedding under a UDP flood, never amplifying (the relay is 1:1).
const MAX_SPLICE_FLOWS: usize = 1 << 12;

/// Idle lifetime of a spliced flow. A flow with no client→origin datagram for this
/// long is reaped (its pump task aborted), bounding state to active relays.
const SPLICE_IDLE: Duration = Duration::from_secs(30);

/// Retention of an auth-marker `(nonce, timestamp)` in the replay cache. Must be at
/// least the marker freshness window so a captured marker cannot be replayed into a
/// local termination while it is still valid; entries older than this are evicted.
const MARKER_REPLAY_TTL: Duration = Duration::from_secs(3600);

/// Max Initials buffered for one pending marker decision before defaulting to a
/// splice. The Safari-26 ClientHello spans two Initials (PQ-inflated), so the
/// terminate-vs-splice fork can only decide once the full first flight is
/// reassembled; the slack absorbs reordering without letting an Initial-shaped
/// probe pin a held core indefinitely (past it, the flow is spliced to the origin).
const MAX_PENDING_INITIALS: usize = 4;

/// Idle lifetime of a held (pending-decision) Initial flight. A peer that sends a
/// partial first flight then vanishes is reaped after this, freeing the held core.
const PENDING_IDLE: Duration = Duration::from_secs(2);

/// How long a held first flight may stay undecided before it is spliced to the
/// origin instead of held silently. A real QUIC origin ACKs an ack-eliciting
/// Initial within max_ack_delay (~25ms; see MAX_ACK_DELAY in conn.rs); holding
/// silently past that (the prior behaviour held indefinitely until unrelated traffic
/// swept it) is an active-probing distinguisher — a prober sending one incomplete
/// Initial sees a real origin answer while ParallaX stays silent. Kept comfortably
/// above a genuine Safari two-Initial burst's inter-arrival (sub-millisecond when not
/// reordered) so real clients are decided locally before it fires.
///
/// RESIDUAL (documented, NOT closed): this turns an *infinite* silence into a *fixed*
/// ~50ms one — the held core sits in `pending`, which `flush` never transmits, so its
/// Initial ACK is withheld for the window, and 50ms is above max_ack_delay, so a
/// prober crafting one decryptable, non-CH-completing v1 Initial still measures a
/// bounded ~50ms+RTT offset versus the bare origin. This is irreducible in the
/// buffer-decide design (splicing datagram-0 before the marker is visible could never
/// terminate a marked client); an accepted, bounded tradeoff like the first-sighting
/// `marker_fresh` race below. The 50ms value is a reliability choice — a smaller one
/// (toward max_ack_delay) tightens the timing match but risks force-splicing a genuine
/// client whose second Initial is merely reordered under load (such a client then
/// fails closed on the origin cert and self-heals by redialing).
const PENDING_DECIDE_DELAY: Duration = Duration::from_millis(50);

/// Process-wide explicit SO_SNDBUF/SO_RCVBUF for the UDP carrier socket, installed
/// once at startup (see [`configure_udp_socket_buffers`]). Either field `None` keeps
/// kernel autotuning for that direction — the safe default, byte-identical to a build
/// that never calls the configurator. Unlike TCP, a UDP socket has no advertised
/// receive window or window scale, so both directions are entirely wire-invisible;
/// the only effect is how many bytes the kernel will queue before user space reads
/// (recv) or how much it will hold while the path drains (send). A larger recv buffer
/// lets the single-threaded driver absorb inbound bursts without socket-layer drops;
/// a larger send buffer lifts the upload window on high-BDP links where autotuning
/// under-provisions it. An explicit value DISABLES autotuning for that direction and
/// is clamped by the OS maximum.
static UDP_SOCKET_BUFFER_OVERRIDE: std::sync::OnceLock<UdpSocketBuffers> =
    std::sync::OnceLock::new();

#[derive(Clone, Copy, Default)]
struct UdpSocketBuffers {
    send: Option<u32>,
    recv: Option<u32>,
}

/// Set the explicit SO_SNDBUF/SO_RCVBUF requested on the UDP carrier socket, process
/// wide. Call once at startup before any endpoint is bound. A `Some(0)` is treated as
/// `None` (keep autotuning). First call wins; later calls are ignored. With both
/// fields `None`/`0` the socket keeps kernel defaults (no behavioural change).
pub fn configure_udp_socket_buffers(send_bytes: Option<u32>, recv_bytes: Option<u32>) {
    let bufs = UdpSocketBuffers {
        send: send_bytes.filter(|&b| b > 0),
        recv: recv_bytes.filter(|&b| b > 0),
    };
    if UDP_SOCKET_BUFFER_OVERRIDE.set(bufs).is_err() {
        tracing::debug!("udp socket buffer override already set; keeping the first value");
    }
}

/// Apply the configured SO_SNDBUF/SO_RCVBUF to a freshly-bound UDP socket. Best-effort
/// with a getsockopt read-back: the kernel silently clamps to the OS max, and a clamp
/// BELOW the request means autotuning would likely have done better, so surface it
/// (the same diagnostic shape as the TCP path). A no-op when no override is set.
#[cfg(unix)]
fn set_udp_socket_buffers(socket: &UdpSocket) {
    let Some(bufs) = UDP_SOCKET_BUFFER_OVERRIDE.get() else {
        return;
    };
    let _ = apply_udp_socket_buffers(socket, *bufs);
}

/// The buffer sizes the kernel actually applied, read back after the set. `None` for a
/// direction means it was not requested, or the set / read-back failed — so a test can
/// assert the plumbing took effect rather than tautologically passing on a silent
/// failure.
#[cfg(unix)]
#[derive(Debug, Default, PartialEq, Eq)]
struct AppliedUdpBuffers {
    send: Option<usize>,
    recv: Option<usize>,
}

/// Apply explicit buffer sizes to a UDP socket (the pure core of
/// [`set_udp_socket_buffers`], without the global lookup, so it is unit-testable).
/// Returns the read-back applied sizes per direction. A no-op (all-`None`) when both
/// directions are `None`.
#[cfg(unix)]
fn apply_udp_socket_buffers(socket: &UdpSocket, bufs: UdpSocketBuffers) -> AppliedUdpBuffers {
    use socket2::SockRef;

    let mut applied = AppliedUdpBuffers::default();
    if bufs.send.is_none() && bufs.recv.is_none() {
        return applied;
    }
    let sock = SockRef::from(socket);
    if let Some(send) = bufs.send {
        match sock.set_send_buffer_size(send as usize) {
            Ok(()) => {
                if let Ok(got) = sock.send_buffer_size() {
                    applied.send = Some(got);
                    if got < send as usize {
                        tracing::warn!(
                            requested = send,
                            applied = got,
                            "kernel clamped udp SO_SNDBUF (raise net.core.wmem_max / kern.ipc.maxsockbuf)"
                        );
                    }
                }
            }
            Err(_) => tracing::trace!("udp SO_SNDBUF request failed; keeping kernel default"),
        }
    }
    if let Some(recv) = bufs.recv {
        match sock.set_recv_buffer_size(recv as usize) {
            Ok(()) => {
                if let Ok(got) = sock.recv_buffer_size() {
                    applied.recv = Some(got);
                    if got < recv as usize {
                        tracing::warn!(
                            requested = recv,
                            applied = got,
                            "kernel clamped udp SO_RCVBUF (raise net.core.rmem_max / kern.ipc.maxsockbuf)"
                        );
                    }
                }
            }
            Err(_) => tracing::trace!("udp SO_RCVBUF request failed; keeping kernel default"),
        }
    }
    applied
}

#[cfg(not(unix))]
fn set_udp_socket_buffers(_socket: &UdpSocket) {}

/// Whether `data` is plausibly a client's first Initial: a v1 long-header Initial
/// packet in a datagram padded to the §14.1 minimum. A cheap pre-check so garbage,
/// truncated, or non-Initial datagrams from unknown peers never allocate the
/// (multi-KB) per-connection state.
fn looks_like_initial(data: &[u8]) -> bool {
    data.len() >= MIN_INITIAL_DATAGRAM
        && first_packet_space(data) == Some(PacketSpace::Initial)
        && u32::from_be_bytes([data[1], data[2], data[3], data[4]]) == QUIC_VERSION_V1
}

/// 0-RTT resumption material: the STEK that seals/opens NewSessionTickets and the
/// cross-connection single-use anti-replay guard. Pairing them in one struct makes
/// it impossible to enable 0-RTT acceptance (a STEK) without also wiring the
/// anti-replay guard (RFC 8446 §8), closing the misconfiguration where a replayed
/// ticket's early data would be accepted for the ticket lifetime.
pub struct ZeroRttKeys {
    /// STEK for issuing + accepting 0-RTT resumption tickets.
    pub stek: Zeroizing<[u8; 32]>,
    /// Cross-connection single-use 0-RTT anti-replay guard, installed on every
    /// accepted connection.
    pub guard: Arc<dyn ZeroRttGuard>,
}

/// Server identity for accepting connections. Transport parameters are NOT stored
/// here: they are encoded per-connection from the chosen source connection id (so
/// `initial_source_connection_id` matches the Initial header SCID, RFC 9000 §7.3),
/// see [`Driver::on_datagram`].
pub struct ServerConfig {
    /// DER-encoded certificate chain presented in the TLS Certificate message.
    pub cert_chain: Vec<Vec<u8>>,
    /// PKCS#8 ECDSA P-256 signing key for the CertificateVerify.
    pub signing_key_pkcs8: Vec<u8>,
    /// Offered ALPN protocols (the relay offers exactly `h3`).
    pub alpn_protocols: Vec<Vec<u8>>,
    /// 0-RTT resumption keys (STEK + anti-replay guard), or `None` to keep the
    /// server cold-start-only (no NewSessionTicket, no 0-RTT acceptance). Bundling
    /// the two makes "accept 0-RTT without anti-replay" unrepresentable.
    pub zero_rtt: Option<ZeroRttKeys>,
    /// Camouflage origin's UDP/443 address for the REALITY-style fallback splice.
    /// When `Some`, a datagram from an unknown peer that is NOT a well-formed v1
    /// Initial (a probe, garbage, non-v1, version-negotiation-eliciting) is relayed
    /// verbatim to the origin so the prober reaches the TRUE origin (see
    /// [`Driver::on_datagram`]). `None` keeps the current behaviour (drop), so the
    /// splice stays dormant until the server runtime supplies the resolved origin.
    pub origin_udp_addr: Option<SocketAddr>,
    /// Origin-splice auth-marker key `(psk, server static X25519 private)`. When
    /// `Some`, a well-formed v1 Initial whose ClientHello.random carries a valid,
    /// fresh, non-replayed marker is TERMINATED locally (a real ParallaX client);
    /// any other v1 Initial (no/forged/replayed marker) is spliced to the origin.
    /// `None` keeps the current behaviour (every v1 Initial terminates locally), so
    /// the marker fork stays dormant until the server runtime supplies the key.
    pub marker_key: Option<crate::crypto::quic_marker::MarkerKey>,
    /// Persistent single-use anti-replay for accepted markers (issue #74). When
    /// `Some`, a marker's first sighting is recorded in the crash-safe replay cache
    /// so a captured marker replayed after a process / carrier restart is still
    /// spliced to the origin, not re-terminated. `None` falls back to the in-memory
    /// first-sighting cache (cold-start / tests), which is lost on restart.
    pub marker_replay_guard: Option<Arc<crate::transport::udp::marker_replay::MarkerReplayGuard>>,
    /// Operator's authorized-SNI allowlist, paired with `marker_key`. A v1 Initial
    /// carrying a valid + fresh marker terminates locally only if its SNI is on this
    /// list; any other SNI is fronted to the origin, matching the TCP plane's
    /// authorized-SNI gate. Empty when `marker_key` is `None` (cold-start: the gate
    /// never runs because no marker is ever recovered).
    pub authorized_sni: Vec<String>,
    /// Maximum UDP payload read per datagram on this endpoint — the inbound recv
    /// buffer size and the origin-splice relay buffer size (issue #75). Oversized
    /// datagrams are truncated, which fails AEAD and is dropped. `0` means use the
    /// built-in default ([`MAX_UDP_PAYLOAD`]); the server runtime resolves it from
    /// `udp.max_udp_payload_bytes`.
    pub max_udp_payload: usize,
}

/// Failure to establish a connection.
#[derive(Debug)]
pub enum ConnectError {
    /// The TLS / transport layer rejected the handshake.
    Tls(QuicTlsError),
    /// The endpoint driver shut down before the handshake completed.
    EndpointClosed,
    /// The connection closed (peer rejection or idle timeout) before the
    /// handshake completed.
    ConnectionClosed,
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Tls(e) => write!(f, "handshake failed: {e:?}"),
            ConnectError::EndpointClosed => write!(f, "endpoint closed"),
            ConnectError::ConnectionClosed => write!(f, "connection closed during handshake"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// A QUIC variable-length integer (RFC 9000 §16), the type error codes + limits
/// travel as. Mirrors `quinn::VarInt` closely enough for the carrier's call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

impl VarInt {
    /// The largest value a QUIC varint can hold (2^62 - 1).
    pub const MAX: VarInt = VarInt((1 << 62) - 1);

    /// Construct from a `u32` (always in range).
    pub fn from_u32(v: u32) -> Self {
        VarInt(v as u64)
    }

    /// The inner value.
    pub fn into_inner(self) -> u64 {
        self.0
    }
}

impl From<u32> for VarInt {
    fn from(v: u32) -> Self {
        VarInt(v as u64)
    }
}

impl From<VarInt> for u64 {
    fn from(v: VarInt) -> u64 {
        v.0
    }
}

/// An application CONNECTION_CLOSE (RFC 9000 §19.19) the peer sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationClose {
    pub error_code: VarInt,
    pub reason: Vec<u8>,
}

/// Why a connection ended (a subset of quinn's `ConnectionError`, matching the
/// carrier's pattern matches).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// The peer sent an application CONNECTION_CLOSE.
    ApplicationClosed(ApplicationClose),
    /// The peer sent a transport CONNECTION_CLOSE.
    ConnectionClosed(VarInt),
    /// This endpoint closed the connection locally.
    LocallyClosed,
    /// The idle timeout fired.
    TimedOut,
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::ApplicationClosed(c) => {
                write!(f, "application closed (code {})", c.error_code.into_inner())
            }
            ConnectionError::ConnectionClosed(code) => {
                write!(f, "connection closed (code {})", code.into_inner())
            }
            ConnectionError::LocallyClosed => write!(f, "locally closed"),
            ConnectionError::TimedOut => write!(f, "idle timed out"),
        }
    }
}

impl std::error::Error for ConnectionError {}

/// Shared per-connection state: the synchronous core behind a mutex, plus the
/// notifications the driver uses to wake blocked handles.
struct ConnShared {
    core: Mutex<Core>,
    peer: SocketAddr,
    /// The client-chosen Destination Connection ID from the first Initial: the value
    /// the client put in its first packet's DCID field (on the server side, peeked off
    /// the wire; on the client side, the CID it chose). A stable-:443 listener routes
    /// an accepted connection back to its originating session by this id (the client
    /// sets it to the session's `offer_id`), since the client's UDP 4-tuple is not
    /// predictable in advance. See [`Connection::peer_initial_dcid`].
    initial_dcid: ConnectionId,
    /// Fired whenever the connection state advances (handshake progress, new
    /// readable data, a newly-accepted stream, or teardown).
    event: Notify,
    /// Nudge the driver after a handle queues outbound work (a write / open / FIN).
    wake: Arc<Notify>,
    /// Wakers of `RecvStream::poll_read` calls blocked for data, woken by the
    /// driver after each event. (Async handles use `event` instead.)
    read_wakers: Mutex<Vec<Waker>>,
    /// Set once the connection has been pushed to the accept queue (server only).
    accept_taken: std::sync::atomic::AtomicBool,
}

impl ConnShared {
    fn is_handshaking(&self) -> bool {
        self.core.lock().unwrap().is_handshaking()
    }

    fn is_closed(&self) -> bool {
        self.core.lock().unwrap().is_closed()
    }

    /// Nudge the driver to flush this connection's outbound datagrams.
    fn nudge(&self) {
        self.wake.notify_one();
    }

    /// Register a `poll_read` waker (deduplicated). Called while holding the core
    /// lock so the driver cannot deliver + wake between the read-check and here.
    fn register_read_waker(&self, w: &Waker) {
        let mut wakers = self.read_wakers.lock().unwrap();
        if !wakers.iter().any(|e| e.will_wake(w)) {
            wakers.push(w.clone());
        }
    }

    /// Wake every blocked reader + async waiter (called by the driver after events).
    fn wake_handles(&self) {
        self.event.notify_waiters();
        for w in std::mem::take(&mut *self.read_wakers.lock().unwrap()) {
            w.wake();
        }
    }
}

/// A request from [`Endpoint::connect`] for the driver to open a client connection.
struct ConnectRequest {
    addr: SocketAddr,
    server_name: String,
    config: Arc<ClientConfig>,
    /// `Some` for a 0-RTT resumption connect: the client offers this ticket and
    /// installs 0-RTT keys so early data can be sent before the handshake completes.
    ticket: Option<ClientTicket>,
    /// Current Unix time in milliseconds (for `obfuscated_ticket_age`); 0 when not
    /// resuming.
    now_ms: u64,
    /// The client-chosen Destination Connection ID for the first Initial. `None` uses
    /// a fresh random CID (the default). A stable-:443 carrier sets it to the session
    /// `offer_id` so the server can route the accepted connection back to its session.
    dcid: Option<ConnectionId>,
    reply: tokio::sync::oneshot::Sender<Result<Arc<ConnShared>, ConnectError>>,
}

/// An async QUIC endpoint: a cheap, cloneable handle onto the driver task that
/// owns the socket (like `quinn::Endpoint`).
#[derive(Clone)]
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    /// Nudge the driver after a handle queues outbound work.
    wake: Arc<Notify>,
    /// Submit a client connect request to the driver.
    connect_tx: mpsc::UnboundedSender<ConnectRequest>,
    /// Ask the driver to close every connection `(error_code, reason)`.
    close_tx: mpsc::UnboundedSender<(u64, Vec<u8>)>,
    /// Receive server-accepted, fully-established connections.
    accept_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Arc<ConnShared>>>>,
    /// The client config used by [`Endpoint::connect`] (set at bind or via
    /// [`Endpoint::set_default_client_config`]).
    default_config: Arc<Mutex<Option<Arc<ClientConfig>>>>,
}

impl Endpoint {
    /// Bind a client endpoint (no server config: it never accepts).
    pub async fn client(bind: SocketAddr) -> io::Result<Endpoint> {
        Self::bind(bind, None).await
    }

    /// Bind a server endpoint that accepts connections with `config`.
    pub async fn server(bind: SocketAddr, config: Arc<ServerConfig>) -> io::Result<Endpoint> {
        Self::bind(bind, Some(config)).await
    }

    async fn bind(bind: SocketAddr, server: Option<Arc<ServerConfig>>) -> io::Result<Endpoint> {
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        // Apply any process-wide explicit SO_SNDBUF/SO_RCVBUF (wire-invisible kernel
        // tuning for high-BDP links). A no-op unless an operator opted in; see
        // [`configure_udp_socket_buffers`].
        set_udp_socket_buffers(&socket);
        let wake = Arc::new(Notify::new());
        let (connect_tx, connect_rx) = mpsc::unbounded_channel();
        let (close_tx, close_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let driver = Driver {
            socket: socket.clone(),
            wake: wake.clone(),
            conns: HashMap::new(),
            splices: HashMap::new(),
            marker_replay: HashMap::new(),
            pending: HashMap::new(),
            server,
            accept_tx,
            connect_rx,
            close_rx,
        };
        tokio::spawn(driver.run());
        Ok(Endpoint {
            socket,
            wake,
            connect_tx,
            close_tx,
            accept_rx: Arc::new(tokio::sync::Mutex::new(accept_rx)),
            default_config: Arc::new(Mutex::new(None)),
        })
    }

    /// Set the client config [`Endpoint::connect`] uses (like quinn's
    /// `set_default_client_config`).
    pub fn set_default_client_config(&self, config: Arc<ClientConfig>) {
        *self.default_config.lock().unwrap() = Some(config);
    }

    /// The bound local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Close every connection on this endpoint with an application error code +
    /// reason (RFC 9000 §10.2). Best-effort: the driver sends each CONNECTION_CLOSE.
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let _ = self
            .close_tx
            .send((error_code.into_inner(), reason.to_vec()));
        self.wake.notify_one();
    }

    /// Open a client connection to `addr`, awaiting handshake completion, using the
    /// configured default client config (see [`Endpoint::set_default_client_config`]).
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connection, ConnectError> {
        self.connect_inner(addr, server_name, None, 0).await
    }

    /// Like [`Self::connect`] but offers `ticket` for a 0-RTT resumption: any data
    /// written to a stream before the handshake completes is sent under the 0-RTT
    /// keys (early data). `now_ms` is the current Unix time in milliseconds (for
    /// `obfuscated_ticket_age`). Falls back transparently to a full 1-RTT handshake
    /// if the server rejects the ticket.
    pub async fn connect_resumption(
        &self,
        addr: SocketAddr,
        server_name: &str,
        ticket: ClientTicket,
        now_ms: u64,
    ) -> Result<Connection, ConnectError> {
        self.connect_inner(addr, server_name, Some(ticket), now_ms)
            .await
    }

    /// Like [`Self::connect_resumption`] but returns as soon as the connection is
    /// constructed — BEFORE the handshake completes — so the caller can open streams
    /// and write 0-RTT early data (sent under the 0-RTT keys until the handshake
    /// installs 1-RTT keys; RFC 9001 §4.6). Await [`Connection::wait_established`]
    /// before relying on 1-RTT-only facilities (the exporter, or reads of the peer's
    /// 1-RTT response). If the server rejects the ticket, the early data is
    /// retransmitted under 1-RTT by normal loss recovery — no data is lost.
    pub async fn connect_resumption_0rtt(
        &self,
        addr: SocketAddr,
        server_name: &str,
        ticket: ClientTicket,
        now_ms: u64,
    ) -> Result<Connection, ConnectError> {
        let shared = self
            .submit_connect(addr, server_name, Some(ticket), now_ms, None)
            .await?;
        // 0-RTT keys are installed at construction (new_client_resumption), so the
        // returned handle can send early data immediately; the handshake continues
        // in the background.
        Ok(Connection { shared })
    }

    /// Like [`Self::connect_resumption_0rtt`] but the first Initial carries `dcid` as
    /// its Destination Connection ID (= the session offer_id), so a stable-:443
    /// carrier can route the resumed connection back to its session.
    pub async fn connect_resumption_0rtt_with_dcid(
        &self,
        addr: SocketAddr,
        server_name: &str,
        ticket: ClientTicket,
        now_ms: u64,
        dcid: ConnectionId,
    ) -> Result<Connection, ConnectError> {
        let shared = self
            .submit_connect(addr, server_name, Some(ticket), now_ms, Some(dcid))
            .await?;
        Ok(Connection { shared })
    }

    async fn connect_inner(
        &self,
        addr: SocketAddr,
        server_name: &str,
        ticket: Option<ClientTicket>,
        now_ms: u64,
    ) -> Result<Connection, ConnectError> {
        let shared = self
            .submit_connect(addr, server_name, ticket, now_ms, None)
            .await?;
        let conn = Connection { shared };
        conn.wait_established().await?;
        Ok(conn)
    }

    /// Open a client connection whose first Initial carries `dcid` as its Destination
    /// Connection ID (instead of a random CID), awaiting handshake completion. A
    /// stable-:443 carrier sets `dcid` to the session `offer_id` so the server can
    /// route the accepted connection back to its originating session.
    pub async fn connect_with_dcid(
        &self,
        addr: SocketAddr,
        server_name: &str,
        dcid: ConnectionId,
    ) -> Result<Connection, ConnectError> {
        let shared = self
            .submit_connect(addr, server_name, None, 0, Some(dcid))
            .await?;
        let conn = Connection { shared };
        conn.wait_established().await?;
        Ok(conn)
    }

    /// Submit a connect request to the driver and await the constructed connection
    /// handle (0-RTT keys, if a ticket was offered, are installed at construction).
    /// Shared by the handshake-awaiting connects and the 0-RTT early-data connect.
    async fn submit_connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
        ticket: Option<ClientTicket>,
        now_ms: u64,
        dcid: Option<ConnectionId>,
    ) -> Result<Arc<ConnShared>, ConnectError> {
        let config = self
            .default_config
            .lock()
            .unwrap()
            .clone()
            .ok_or(ConnectError::EndpointClosed)?;
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        self.connect_tx
            .send(ConnectRequest {
                addr,
                server_name: server_name.to_string(),
                config,
                ticket,
                now_ms,
                dcid,
                reply,
            })
            .map_err(|_| ConnectError::EndpointClosed)?;
        // Outer `?`: the driver dropped the sender (endpoint gone). The remaining
        // Result is the driver's own client-init/TLS outcome.
        reply_rx.await.map_err(|_| ConnectError::EndpointClosed)?
    }

    /// Accept the next fully-established incoming connection (server endpoints).
    /// Returns `None` once the endpoint is closed.
    pub async fn accept(&self) -> Option<Connection> {
        let shared = {
            let mut rx = self.accept_rx.lock().await;
            rx.recv().await
        }?;
        Some(Connection { shared })
    }
}

/// A held first-flight Initial awaiting the buffer-decide-then-route marker fork
/// (see [`Driver::pending`]). The core has been fed every datagram but never
/// flushed (it is not in `conns`, so the run loop neither transmits nor times it
/// out), so on a terminate decision it is promoted intact, and on a splice decision
/// the raw `datagrams` are replayed to the origin verbatim.
struct PendingInitial {
    shared: Arc<ConnShared>,
    datagrams: Vec<Vec<u8>>,
    /// First-arrival time of this flight, fixed at creation. Drives the
    /// [`PENDING_DECIDE_DELAY`] decision deadline so an undecided flight is spliced
    /// to the origin rather than held silently (an active-probing tell).
    created: Instant,
    last: Instant,
}

/// The endpoint driver: owns the socket + all live connections, pumping them on
/// every IO / timer / wake event.
struct Driver {
    socket: Arc<UdpSocket>,
    wake: Arc<Notify>,
    conns: HashMap<SocketAddr, Arc<ConnShared>>,
    /// Active origin-fallback relays, keyed by client 4-tuple, with last-activity
    /// time for idle reaping. A flow here is NOT a ParallaX connection — its
    /// datagrams are forwarded verbatim to the origin (see [`Self::on_datagram`]).
    splices: HashMap<SocketAddr, (SpliceFlow, Instant)>,
    /// Initial-time auth-marker replay cache, keyed on `(nonce, timestamp)` with the
    /// insert time for window eviction: a marker is TERMINATED only on its first
    /// sighting, so a captured-and-replayed marker (a later sighting) is spliced to
    /// the origin instead of re-exposing the local termination path.
    marker_replay: HashMap<([u8; 12], u64), Instant>,
    /// Unknown-peer Initials held for the buffer-decide-then-route marker fork. The
    /// Safari ClientHello spans two Initials, so terminate-vs-splice can only be
    /// decided once the full first flight is reassembled. Each entry holds the
    /// fed-but-never-flushed server core and the raw datagrams verbatim, so a splice
    /// decision can replay them to the origin byte-for-byte. Only populated when
    /// `marker_key` is set (otherwise the cold-start path terminates immediately).
    pending: HashMap<SocketAddr, PendingInitial>,
    server: Option<Arc<ServerConfig>>,
    accept_tx: mpsc::UnboundedSender<Arc<ConnShared>>,
    connect_rx: mpsc::UnboundedReceiver<ConnectRequest>,
    close_rx: mpsc::UnboundedReceiver<(u64, Vec<u8>)>,
}

impl Driver {
    /// The effective inbound recv-buffer ceiling: the server config's resolved cap
    /// when present and non-zero, else the built-in default. A client endpoint (no
    /// server config) always uses the default. See issue #75.
    fn recv_cap(&self) -> usize {
        match self.server.as_ref().map(|c| c.max_udp_payload) {
            Some(n) if n != 0 => n,
            _ => MAX_UDP_PAYLOAD,
        }
    }

    async fn run(mut self) {
        let mut buf = vec![0u8; self.recv_cap()];
        loop {
            let socket = self.socket.clone();
            let wake = self.wake.clone();
            let deadline = self.next_deadline();

            tokio::select! {
                r = socket.recv_from(&mut buf) => {
                    match r {
                        Ok((len, peer)) => self.on_datagram(&buf[..len], peer),
                        Err(_) => continue,
                    }
                }
                req = self.connect_rx.recv() => {
                    match req {
                        Some(req) => self.on_connect(req),
                        None => return, // endpoint dropped
                    }
                }
                close = self.close_rx.recv() => {
                    if let Some((code, reason)) = close {
                        for c in self.conns.values() {
                            c.core.lock().unwrap().close(code, &reason);
                            c.wake_handles();
                        }
                    }
                }
                _ = wake.notified() => {}
                _ = sleep_until(deadline) => self.on_timeout(),
            }

            self.flush().await;
            self.promote_accepts();
            // Reap fully-drained connections (RFC 9000 §10.2) so the routing table
            // and timers do not grow without bound. App handles keep their own Arc.
            self.conns
                .retain(|_, c| !c.core.lock().unwrap().is_drained());
        }
    }

    /// The earliest armed timer across all connections, plus the idle-reap deadline of
    /// origin-splice flows and the decision deadline of held pending Initials, so the
    /// driver wakes for all three even when no new datagrams arrive. A conns-only
    /// deadline would never fire for an idle splice (pinning its socket + pump task to
    /// the hard cap) nor for an undecided pending flight (held silently past a real
    /// origin's ACK — an active-probing tell).
    fn next_deadline(&self) -> Option<Instant> {
        let conn_timeouts = self
            .conns
            .values()
            .filter_map(|c| c.core.lock().unwrap().next_timeout());
        // Origin-splice flows: idle-reap deadline so a peer that opens flows then goes
        // silent cannot pin upstream sockets + pump tasks until the hard cap.
        let splice_idle = self.splices.values().map(|(_, last)| *last + SPLICE_IDLE);
        // Held first flights: wake at the decision deadline so an undecided flight is
        // spliced to the origin instead of held silently.
        let pending_decide = self
            .pending
            .values()
            .map(|p| p.created + PENDING_DECIDE_DELAY);
        conn_timeouts.chain(splice_idle).chain(pending_decide).min()
    }

    fn on_timeout(&mut self) {
        let now = Instant::now();
        for c in self.conns.values() {
            let mut core = c.core.lock().unwrap();
            if core.next_timeout().is_some_and(|t| t <= now) {
                core.handle_timeout(now);
            }
        }
        // Reap origin-splice flows idle past SPLICE_IDLE (their deadline is armed in
        // next_deadline) so a peer that opens flows then goes silent cannot pin upstream
        // sockets + pump tasks to the hard cap. Wire-silent: a UDP relay just stops
        // forwarding (SpliceFlow::drop aborts the pump), no teardown packet.
        self.sweep_idle_splices(now);
        // Resolve any held first flight whose decision deadline elapsed: decide_pending
        // now falls through to a splice (the CH never completed), so an incomplete
        // Initial reaches the origin instead of being held silently. Collect first to
        // avoid borrowing `self.pending` across the `decide_pending` calls.
        let overdue: Vec<SocketAddr> = self
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.created) >= PENDING_DECIDE_DELAY)
            .map(|(addr, _)| *addr)
            .collect();
        for peer in overdue {
            self.decide_pending(peer, now);
        }
    }

    fn on_datagram(&mut self, data: &[u8], peer: SocketAddr) {
        let now = Instant::now();
        if let Some(c) = self.conns.get(&peer) {
            let _ = c.core.lock().unwrap().handle_datagram(data, now);
            c.wake_handles();
            return;
        }
        // An established origin-fallback relay for this peer: forward verbatim.
        if let Some((flow, last)) = self.splices.get_mut(&peer) {
            let _ = flow.forward(data);
            *last = now;
            return;
        }
        // A datagram for an in-progress marker decision: feed it into the held core
        // and re-evaluate the terminate-vs-splice fork (the Safari ClientHello spans
        // two Initials, so the decision matures only once the whole CH is parsed).
        if self.pending.contains_key(&peer) {
            self.feed_pending(peer, data, now);
            return;
        }
        // A datagram from an unknown peer: open a server connection if configured.
        let Some(cfg) = self.server.clone() else {
            return;
        };
        // Not a well-formed v1 Initial from an unknown peer ⇒ not a ParallaX client
        // (a probe, garbage, non-v1, or version-negotiation-eliciting packet). The
        // QUIC analogue of the TCP REALITY fallback: relay it verbatim to the real
        // origin so an active prober reaches the TRUE origin and ParallaX emits
        // nothing of its own. Dormant (drop, the prior behaviour) until the server
        // runtime supplies `origin_udp_addr`.
        if !looks_like_initial(data) {
            if let Some(origin) = cfg.origin_udp_addr {
                self.open_splice(peer, origin, data, now);
            }
            return;
        }
        // Reap held flights whose owner vanished mid-first-flight, before the cap
        // check and any allocation (bounds held cores to active arrivals).
        self.pending
            .retain(|_, p| now.duration_since(p.last) < PENDING_IDLE);
        // Bound state creation (review finding #1): held + active cores never exceed
        // the hard cap. Past the cap we must NOT allocate a Box<ServerHandshake> +
        // Bbr + spaces (unauthenticated DoS). But a silent drop here is a present-tense
        // distinguisher: the TCP plane sheds an overflow to the origin fallback
        // (cap_shed_fallback_or_fin), so a QUIC plane that instead goes silent at its
        // cap diverges observably from a real origin under load. Shed this v1 Initial
        // to the origin splice too — a verbatim 1:1 relay, so the prober reaches the
        // TRUE origin (which answers like the real server it is) and the two transports
        // behave identically when saturated. The splice has its own independent
        // MAX_SPLICE_FLOWS budget, so this adds no unbounded resource surface; once
        // that budget is also exhausted the splice itself sheds, degrading exactly like
        // an origin under a UDP flood. Dormant (drop, the prior behaviour) until the
        // runtime supplies `origin_udp_addr`.
        if self.conns.len() + self.pending.len() >= MAX_SERVER_CONNS {
            if let Some(origin) = cfg.origin_udp_addr {
                self.open_splice(peer, origin, data, now);
            }
            return;
        }
        // Random source connection id (RFC 9000 §5.1). A monotonic counter would make
        // every connection accepted by one bind serially linkable (a present-tense
        // fingerprint a real origin never exhibits — real servers use unpredictable
        // CIDs). The header SCID and the `initial_source_connection_id` transport
        // parameter both derive from this same value, so they stay consistent
        // (RFC 9000 §7.3).
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let mut scid = [0u8; 8];
        SystemRandom::new()
            .fill(&mut scid)
            .expect("system RNG available");
        // The client's chosen DCID, peeked off the first Initial without decryption: a
        // stable-:443 carrier routes the accepted connection back to its session by this
        // id, and it is bound into the auth-marker MAC (issue #74) so a captured marker
        // cannot be lifted onto a different DCID. Falls back to empty if the header
        // cannot be parsed; the marker fork has already validated `looks_like_initial`.
        let initial_dcid = super::packet::peek_long_cids(data)
            .map(|(dcid, _scid)| dcid)
            .unwrap_or_else(|_| ConnectionId::new(&[]));
        let core = match Core::new_server_with_stek(
            cfg.cert_chain.clone(),
            &cfg.signing_key_pkcs8,
            cfg.alpn_protocols.clone(),
            // Encode the server transport parameters with THIS connection's source
            // CID, so initial_source_connection_id matches the Initial header SCID
            // (RFC 9000 §7.3) instead of a stale config-time placeholder.
            super::transport_params::TransportParameters::server(&scid).encode_server(),
            ConnectionId::new(&scid),
            cfg.zero_rtt.as_ref().map(|z| z.stek.clone()),
        ) {
            Ok(mut core) => {
                // Install the shared single-use 0-RTT anti-replay guard so a replayed
                // ticket on any connection is rejected (falls back to 1-RTT). Paired
                // with the STEK in `zero_rtt`, so enabling 0-RTT always wires the guard.
                if let Some(z) = cfg.zero_rtt.as_ref() {
                    core.set_zero_rtt_replay_guard(z.guard.clone());
                }
                // Install the auth-marker key BEFORE the ClientHello is processed: the
                // marker is verified during handle_datagram and read back below. The
                // first-Initial DCID is bound into the marker MAC (issue #74).
                if let Some((psk, static_priv)) = &cfg.marker_key {
                    core.set_marker_key(
                        psk.clone(),
                        static_priv.clone(),
                        initial_dcid.as_slice().to_vec(),
                        cfg.authorized_sni.clone(),
                    );
                }
                core
            }
            Err(_) => return,
        };
        let shared = Arc::new(ConnShared {
            core: Mutex::new(core),
            peer,
            initial_dcid,
            event: Notify::new(),
            wake: self.wake.clone(),
            read_wakers: Mutex::new(Vec::new()),
            accept_taken: std::sync::atomic::AtomicBool::new(false),
        });
        let _ = shared.core.lock().unwrap().handle_datagram(data, now);

        // Cold-start (no marker key): terminate locally immediately, exactly as the
        // pre-marker behaviour — no buffering, no added per-connection latency.
        if cfg.marker_key.is_none() {
            self.conns.insert(peer, shared);
            return;
        }

        // Origin-splice marker fork — buffer-decide-then-route. The Safari-26
        // ClientHello spans TWO Initials, and the marker's ECDH needs the client's
        // X25519 share (carried in the SECOND Initial), so terminate-vs-splice cannot
        // be decided on this first datagram. Hold the fed-but-never-flushed core plus
        // the raw datagram: a held core is NOT in `conns`, so the run loop never
        // transmits or times it out — zero ParallaX bytes escape while we wait. Once
        // the full CH is reassembled, [`Self::decide_pending`] promotes a valid +
        // fresh + non-replayed marker to a local termination, and splices everything
        // else to the origin (replaying the buffered datagrams verbatim).
        self.pending.insert(
            peer,
            PendingInitial {
                shared,
                datagrams: vec![data.to_vec()],
                created: now,
                last: now,
            },
        );
        self.decide_pending(peer, now);
    }

    /// Feed a follow-up datagram into a peer's held first flight, then re-run the
    /// marker decision.
    fn feed_pending(&mut self, peer: SocketAddr, data: &[u8], now: Instant) {
        if let Some(p) = self.pending.get_mut(&peer) {
            let _ = p.shared.core.lock().unwrap().handle_datagram(data, now);
            p.datagrams.push(data.to_vec());
            p.last = now;
        }
        self.decide_pending(peer, now);
    }

    /// Resolve a held first flight once enough of it has arrived. Promote it to a
    /// local connection on a valid + fresh marker, or splice it to the origin
    /// otherwise. While the ClientHello is still incomplete AND the buffer budget
    /// remains, this is a no-op: nothing is emitted and the flight keeps buffering.
    fn decide_pending(&mut self, peer: SocketAddr, now: Instant) {
        let (processed, marker, count, held_for) = match self.pending.get(&peer) {
            Some(p) => {
                let core = p.shared.core.lock().unwrap();
                (
                    core.client_hello_processed(),
                    core.marker_result(),
                    p.datagrams.len(),
                    now.duration_since(p.created),
                )
            }
            None => return,
        };
        // CH not yet parsed and budget remains: keep buffering, emit nothing — but
        // only until the decision deadline. Past it, fall through to a splice so an
        // incomplete first flight reaches the origin (which ACKs like a real origin)
        // instead of being held silently, which is an active-probing distinguisher.
        if !processed && count < MAX_PENDING_INITIALS && held_for < PENDING_DECIDE_DELAY {
            return;
        }
        let p = self.pending.remove(&peer).expect("pending entry present");
        // Terminate ONLY on a parsed CH carrying a valid marker on its FIRST sighting;
        // a replay (same nonce/ts) returns false and is spliced. `marker_fresh` runs
        // at most once per flight (only here, when the CH is decided), so a buffered
        // or replayed flight never pollutes the replay cache.
        let terminate = processed && matches!(marker, Some(m) if self.marker_fresh(m, now));
        if terminate {
            // Promote intact: the buffered server flight flushes on the run loop's
            // next `flush()`, right after this datagram is handled.
            self.conns.insert(peer, p.shared);
            return;
        }
        // Splice: drop the held core (no ParallaX bytes ever left it) and replay the
        // buffered datagrams to the origin verbatim, so the prober reaches the TRUE
        // origin. Dormant unless the runtime supplied `origin_udp_addr`.
        drop(p.shared);
        if let Some(origin) = self.server.as_ref().and_then(|c| c.origin_udp_addr) {
            self.splice_pending(peer, origin, p.datagrams, now);
        }
    }

    /// Open an origin-fallback relay for `peer` and replay the buffered first-flight
    /// datagrams to `origin` verbatim, in arrival order.
    fn splice_pending(
        &mut self,
        peer: SocketAddr,
        origin: SocketAddr,
        datagrams: Vec<Vec<u8>>,
        now: Instant,
    ) {
        let mut it = datagrams.into_iter();
        let Some(first) = it.next() else {
            return;
        };
        self.open_splice(peer, origin, &first, now);
        if let Some((flow, last)) = self.splices.get_mut(&peer) {
            for d in it {
                let _ = flow.forward(&d);
            }
            *last = now;
        }
    }

    /// Record an auth marker's `(nonce, timestamp)` and report whether this is its
    /// FIRST sighting (so the connection terminates locally). A repeat — a captured
    /// marker replayed within its window — returns `false`, so that flow is spliced
    /// to the origin instead of re-exposing the local termination path. (The first
    /// sighting could itself be an attacker who raced the genuine client; that
    /// residual is bounded by the short freshness window and is the documented QUIC
    /// limit — the authenticated path cannot reach full TCP-REALITY parity.)
    ///
    /// When the server config supplies a persistent [`MarkerReplayGuard`] (issue #74)
    /// the first-sighting record lives in the crash-safe replay cache, so a marker
    /// captured before a process / carrier restart is still spliced after it. Without
    /// one (cold-start / tests) it falls back to the in-memory cache, which is lost on
    /// restart.
    fn marker_fresh(&mut self, m: crate::crypto::quic_marker::Marker, now: Instant) -> bool {
        if let Some(guard) = self
            .server
            .as_ref()
            .and_then(|c| c.marker_replay_guard.clone())
        {
            // Persistent path: the cache keys on `(nonce, timestamp)` via SHA-256 and
            // retains by the marker's own timestamp, so the in-memory map is unused.
            // A clock-read failure FAILS CLOSED (splice, not terminate): feeding a 0
            // "now" would let `prune_expired` later evict a recorded entry once the
            // clock recovers, reopening a replay window. A genuine client merely
            // fails to terminate this once and self-heals by redialing.
            let Ok(now_unix) = crate::crypto::replay::current_unix_timestamp() else {
                return false;
            };
            return guard.first_sighting(&m, now_unix);
        }
        self.marker_replay
            .retain(|_, t| now.duration_since(*t) < MARKER_REPLAY_TTL);
        use std::collections::hash_map::Entry;
        match self.marker_replay.entry((m.nonce, m.timestamp)) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(now);
                true
            }
        }
    }

    /// Open a verbatim origin-fallback relay for `peer` toward `origin`, forwarding
    /// `first` now. Idle relays are reaped first (bounding state to active flows),
    /// and the global splice budget is enforced — past it, the datagram is dropped,
    /// degrading like a real origin shedding under a UDP flood (the relay is 1:1, so
    /// there is no amplification, only state to bound).
    fn open_splice(&mut self, peer: SocketAddr, origin: SocketAddr, first: &[u8], now: Instant) {
        self.sweep_idle_splices(now);
        if self.splices.len() >= MAX_SPLICE_FLOWS {
            return;
        }
        let cap = self.recv_cap();
        if let Ok(flow) = SpliceFlow::open(self.socket.clone(), peer, origin, first, cap) {
            self.splices.insert(peer, (flow, now));
        }
    }

    /// Drop relays with no client→origin datagram for [`SPLICE_IDLE`]. Removing the
    /// entry drops its [`SpliceFlow`], which aborts the origin→client pump task.
    fn sweep_idle_splices(&mut self, now: Instant) {
        self.splices
            .retain(|_, (_, last)| now.duration_since(*last) < SPLICE_IDLE);
    }

    fn on_connect(&mut self, req: ConnectRequest) {
        let dcid = req.dcid.unwrap_or_else(random_cid);
        let core_result = match &req.ticket {
            Some(ticket) => Core::new_client_resumption(
                req.config,
                &req.server_name,
                dcid,
                ConnectionId::new(&[]),
                ticket,
                req.now_ms,
            ),
            None => Core::new_client(req.config, &req.server_name, dcid, ConnectionId::new(&[])),
        };
        let core = match core_result {
            Ok(core) => core,
            Err(err) => {
                // Surface the real TLS/init failure to connect() instead of
                // letting the dropped sender masquerade as EndpointClosed.
                let _ = req.reply.send(Err(ConnectError::Tls(err)));
                return;
            }
        };
        let shared = Arc::new(ConnShared {
            core: Mutex::new(core),
            peer: req.addr,
            initial_dcid: dcid,
            event: Notify::new(),
            wake: self.wake.clone(),
            read_wakers: Mutex::new(Vec::new()),
            accept_taken: std::sync::atomic::AtomicBool::new(false),
        });
        self.conns.insert(req.addr, shared.clone());
        let _ = req.reply.send(Ok(shared));
    }

    /// Drain every connection's outbound datagrams and wake blocked handles.
    async fn flush(&mut self) {
        let now = Instant::now();
        let mut out: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
        for c in self.conns.values() {
            {
                let mut core = c.core.lock().unwrap();
                while let Some(dg) = core.poll_transmit(now) {
                    out.push((dg, c.peer));
                }
            }
            c.wake_handles();
        }
        for (dg, peer) in out {
            let _ = self.socket.send_to(&dg, peer).await;
        }
    }

    /// Push newly-established server connections to the accept queue.
    fn promote_accepts(&mut self) {
        if self.server.is_none() {
            return;
        }
        for c in self.conns.values() {
            let established = {
                let core = c.core.lock().unwrap();
                !core.is_handshaking()
            };
            // A connection is promoted once; `accept_taken` is tracked via the
            // event channel's idempotent send guard below.
            if established
                && !c
                    .accept_taken
                    .swap(true, std::sync::atomic::Ordering::AcqRel)
            {
                let _ = self.accept_tx.send(c.clone());
            }
        }
    }
}

/// Await an optional deadline; never resolves when there is no timer armed.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d.into()).await,
        None => std::future::pending::<()>().await,
    }
}

/// A random 8-byte connection id for a client's first Initial.
fn random_cid() -> ConnectionId {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system RNG available");
    ConnectionId::new(&bytes)
}

/// An established connection handle. A cheap `Arc` wrapper: cloning yields another
/// handle to the SAME connection (close is explicit via [`Connection::close`], not
/// on drop), so the mux-over-QUIC path can share one connection across many
/// concurrent substream tasks that each `open_bi`.
#[derive(Clone)]
pub struct Connection {
    shared: Arc<ConnShared>,
}

impl Connection {
    /// The peer's UDP socket address (its source 4-tuple endpoint). Used by the
    /// server to filter an accepted connection against the authenticated peer's IP.
    pub fn remote_address(&self) -> SocketAddr {
        self.shared.peer
    }

    /// The client-chosen Destination Connection ID from the first Initial. On a
    /// server endpoint this is the value the client put on the wire; a stable-:443
    /// carrier routes an accepted connection back to its originating session by this
    /// id (the client sets it to the session `offer_id` via
    /// [`Endpoint::connect_with_dcid`]).
    pub fn peer_initial_dcid(&self) -> &[u8] {
        self.shared.initial_dcid.as_slice()
    }

    /// Take a resumption ticket received on this connection (client only; the server
    /// returns `None`). `now_ms` stamps the ticket-age epoch. Call after the relay
    /// completes to cache a ticket for a future 0-RTT reconnect.
    pub fn take_session_ticket(&self, now_ms: u64) -> Option<ClientTicket> {
        self.shared.core.lock().unwrap().take_session_ticket(now_ms)
    }

    /// Whether 0-RTT keys are installed on this connection. On the SERVER side this
    /// reports whether the resumed ticket's 0-RTT was ACCEPTED (a replayed/rejected
    /// ticket leaves it `false`, the connection having fallen back to 1-RTT); on a
    /// resuming client it is always `true`. Used by the resumption/replay tests to
    /// assert acceptance vs single-use rejection.
    #[allow(dead_code)] // 0-RTT acceptance inspection; exercised by the resumption/replay tests
    pub(crate) fn zero_rtt_keys_installed(&self) -> bool {
        self.shared.core.lock().unwrap().zero_rtt_keys_installed()
    }

    /// Await handshake completion (or a connection close). A 0-RTT connect
    /// ([`Endpoint::connect_resumption_0rtt`]) returns before the handshake so the
    /// caller can send early data; it then awaits this before relying on 1-RTT-only
    /// facilities (the RFC 5705 exporter, or reads of the peer's 1-RTT response).
    pub async fn wait_established(&self) -> Result<(), ConnectError> {
        loop {
            // Arm the waiter BEFORE checking the handshake state. tokio's `notified()`
            // does NOT register the waiter until first poll / `enable()`, and the
            // driver wakes via `notify_waiters()`, which wakes only already-registered
            // waiters and stores NO permit for a future one. Merely creating the future
            // before the check (the old code) does not register it, so a driver that
            // flips `is_handshaking → false` and calls `notify_waiters()` between our
            // check and our `.await` would have its wake-up lost — leaving `connect()`
            // parked on an already-fired notification until some unrelated later wake.
            // `pin! + enable()` registers the waiter up front, exactly as `await_accept`
            // does, so a wake racing the state check still wakes us.
            let notified = self.shared.event.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.shared.is_closed() {
                return Err(ConnectError::ConnectionClosed);
            }
            if !self.shared.is_handshaking() {
                return Ok(());
            }
            notified.await;
        }
    }

    /// RFC 5705 exporter (backs the auth token).
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), QuicTlsError> {
        self.shared
            .core
            .lock()
            .unwrap()
            .export_keying_material(out, label, context)
    }

    /// The peer's transport-parameters blob.
    pub fn peer_transport_parameters(&self) -> Option<Vec<u8>> {
        self.shared
            .core
            .lock()
            .unwrap()
            .peer_transport_parameters()
            .map(|tp| tp.to_vec())
    }

    /// Close the connection with an application error code + reason (RFC 9000 §10.2).
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.shared
            .core
            .lock()
            .unwrap()
            .close(error_code.into_inner(), reason);
        self.shared.nudge();
    }

    /// Why the connection ended, if it has (peer close, local close, or idle).
    pub fn close_reason(&self) -> Option<ConnectionError> {
        let core = self.shared.core.lock().unwrap();
        core.close_reason().map(|r| match r {
            CloseReason::PeerApp(code, reason) => {
                ConnectionError::ApplicationClosed(ApplicationClose {
                    error_code: VarInt(*code),
                    reason: reason.clone(),
                })
            }
            CloseReason::PeerTransport(code, _) => ConnectionError::ConnectionClosed(VarInt(*code)),
            CloseReason::LocalApp(_, _) => ConnectionError::LocallyClosed,
            CloseReason::IdleTimeout => ConnectionError::TimedOut,
        })
    }

    /// Whether the connection has closed.
    pub fn is_closed(&self) -> bool {
        self.shared.core.lock().unwrap().is_closed()
    }

    /// Abruptly reset a stream's send half by id (RFC 9000 §19.4), without needing
    /// the owning [`SendStream`] handle. The mux-over-QUIC substream relay uses this
    /// to RESET_STREAM on an error/idle teardown after the send half was moved into
    /// the relay writer, so the peer sees a prompt reset rather than waiting on the
    /// connection idle-timeout. A no-op if the stream is already closed/finished.
    pub fn reset_stream(&self, id: u64, error_code: VarInt) {
        self.shared
            .core
            .lock()
            .unwrap()
            .reset_stream(id, error_code.into_inner());
        self.shared.nudge();
    }

    /// Open an outgoing bidirectional stream (RFC 9000 §2.1).
    pub fn open_bi(&self) -> (SendStream, RecvStream) {
        let id = self.shared.core.lock().unwrap().open_bi();
        self.shared.nudge();
        (
            SendStream::new(self.shared.clone(), id),
            RecvStream::new(self.shared.clone(), id),
        )
    }

    /// Open an outgoing unidirectional stream (HTTP/3 control / QPACK).
    pub fn open_uni(&self) -> SendStream {
        let id = self.shared.core.lock().unwrap().open_uni();
        self.shared.nudge();
        SendStream::new(self.shared.clone(), id)
    }

    /// Accept the next peer-initiated bidirectional stream.
    pub async fn accept_bi(&self) -> Option<(SendStream, RecvStream)> {
        let id = self.await_accept(false).await?;
        Some((
            SendStream::new(self.shared.clone(), id),
            RecvStream::new(self.shared.clone(), id),
        ))
    }

    /// Accept the next peer-initiated unidirectional stream.
    pub async fn accept_uni(&self) -> Option<RecvStream> {
        let id = self.await_accept(true).await?;
        Some(RecvStream::new(self.shared.clone(), id))
    }

    /// Await the next peer-initiated stream id of the given directionality.
    async fn await_accept(&self, uni: bool) -> Option<u64> {
        loop {
            let notified = self.shared.event.notified();
            tokio::pin!(notified);
            // Arm the waiter BEFORE checking so a stream that races the check still
            // wakes us (RFC-agnostic tokio Notify lost-wakeup avoidance).
            notified.as_mut().enable();
            {
                let mut core = self.shared.core.lock().unwrap();
                let id = if uni {
                    core.accept_uni()
                } else {
                    core.accept_bi()
                };
                if let Some(id) = id {
                    return Some(id);
                }
                // A closed connection yields no further streams (Option contract).
                if core.is_closed() {
                    return None;
                }
            }
            notified.await;
        }
    }
}

/// The send half of a QUIC stream — an [`AsyncWrite`] into the connection's stream
/// buffer (the driver packetizes it under flow + congestion control).
pub struct SendStream {
    shared: Arc<ConnShared>,
    id: u64,
}

impl SendStream {
    fn new(shared: Arc<ConnShared>, id: u64) -> Self {
        Self { shared, id }
    }

    /// The stream id (RFC 9000 §2.1).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Mark the stream finished: a FIN follows the buffered bytes (RFC 9000 §3.3).
    pub fn finish(&mut self) {
        self.shared.core.lock().unwrap().finish_stream(self.id);
        self.shared.nudge();
    }

    /// Abruptly reset the send half with `error_code` (RFC 9000 §19.4).
    pub fn reset(&mut self, error_code: VarInt) {
        self.shared
            .core
            .lock()
            .unwrap()
            .reset_stream(self.id, error_code.into_inner());
        self.shared.nudge();
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut core = self.shared.core.lock().unwrap();
        if core.is_closed() {
            // Writing to a torn-down connection can never reach the peer; fail so the
            // relay's write side terminates instead of buffering into a dead conn.
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            )));
        }
        core.send_stream(self.id, data);
        drop(core);
        self.shared.nudge();
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Bytes are buffered in the core and sent by the driver; nothing to force.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.core.lock().unwrap().finish_stream(self.id);
        self.shared.nudge();
        Poll::Ready(Ok(()))
    }
}

/// The receive half of a QUIC stream — an [`AsyncRead`] over the in-order bytes the
/// driver reassembles. A clean FIN reads as EOF (`Ok(0)`); a peer RESET_STREAM is a
/// truncation surfaced as [`io::ErrorKind::ConnectionReset`] (the leg.rs contract).
pub struct RecvStream {
    shared: Arc<ConnShared>,
    id: u64,
    /// Leftover bytes from a read that did not fit the caller's buffer.
    pending: Vec<u8>,
    pos: usize,
}

impl RecvStream {
    fn new(shared: Arc<ConnShared>, id: u64) -> Self {
        Self {
            shared,
            id,
            pending: Vec::new(),
            pos: 0,
        }
    }

    /// The stream id (RFC 9000 §2.1).
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // Serve any leftover from a prior oversized read first.
        if me.pos < me.pending.len() {
            let n = (me.pending.len() - me.pos).min(buf.remaining());
            buf.put_slice(&me.pending[me.pos..me.pos + n]);
            me.pos += n;
            return Poll::Ready(Ok(()));
        }
        // Pull fresh in-order bytes from the core. Register the waker while holding
        // the core lock so the driver cannot deliver + wake between check and
        // registration (lost-wakeup avoidance).
        let mut core = me.shared.core.lock().unwrap();
        let data = core.read_stream(me.id);
        if !data.is_empty() {
            drop(core);
            // Consuming bytes grows the receive windows, so `read_stream` may have
            // re-armed a MAX_DATA / MAX_STREAM_DATA grant. Nudge the driver to flush
            // it promptly: under sustained backpressure the blocked sender transmits
            // nothing, so without this nudge the receiver's driver would never wake
            // to emit the grant and the transfer would stall until the idle timeout.
            me.shared.nudge();
            me.pending = data;
            me.pos = 0;
            let n = me.pending.len().min(buf.remaining());
            buf.put_slice(&me.pending[..n]);
            me.pos = n;
            return Poll::Ready(Ok(()));
        }
        if let Some(code) = core.stream_reset(me.id) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("stream reset by peer (code {code})"),
            )));
        }
        if core.stream_recv_finished(me.id) {
            return Poll::Ready(Ok(())); // clean FIN → EOF (buf left unfilled)
        }
        if core.is_closed() {
            // The connection was torn down (peer CONNECTION_CLOSE / idle / local)
            // before this stream finished: surface a reset so a blocked reader (the
            // relay) terminates instead of hanging for bytes that will never arrive.
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection closed before stream completed",
            )));
        }
        me.shared.register_read_waker(cx.waker());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::quic::AcceptAnyServerCert;

    fn client_config() -> Arc<ClientConfig> {
        Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ))
    }

    /// Build a test `ServerConfig` with a fresh ECDSA key and the standard test
    /// cert/ALPN, varying only the two fields the individual builders care about.
    /// The authorized-SNI allowlist is `["example.com"]` — the SNI every marker test
    /// client connects with — so a valid marker on that SNI terminates locally.
    fn base_server_config(
        origin_udp_addr: Option<SocketAddr>,
        marker_key: Option<crate::crypto::quic_marker::MarkerKey>,
    ) -> Arc<ServerConfig> {
        base_server_config_sni(origin_udp_addr, marker_key, vec!["example.com".to_owned()])
    }

    /// Like [`base_server_config`] but with an explicit authorized-SNI allowlist, so a
    /// test can exercise the marker SNI gate (a marked client whose SNI is not on the
    /// list must be fronted to the origin, not terminated).
    fn base_server_config_sni(
        origin_udp_addr: Option<SocketAddr>,
        marker_key: Option<crate::crypto::quic_marker::MarkerKey>,
        authorized_sni: Vec<String>,
    ) -> Arc<ServerConfig> {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap()
                .as_ref()
                .to_vec();
        Arc::new(ServerConfig {
            cert_chain: vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            signing_key_pkcs8: key,
            alpn_protocols: vec![b"h3".to_vec()],
            zero_rtt: None,
            origin_udp_addr,
            marker_key,
            marker_replay_guard: None,
            authorized_sni,
            max_udp_payload: 0,
        })
    }

    fn server_config() -> Arc<ServerConfig> {
        base_server_config(None, None)
    }

    fn server_config_splicing(origin: SocketAddr) -> Arc<ServerConfig> {
        base_server_config(Some(origin), None)
    }

    /// A datagram from an unknown peer that is NOT a well-formed v1 Initial (a probe
    /// or garbage) is spliced verbatim to the configured origin, and the origin's
    /// reply is relayed back to the client — the QUIC analogue of the TCP REALITY
    /// origin fallback. (With no origin configured the same datagram is dropped, the
    /// cold-start default exercised by every other test here.)
    #[tokio::test]
    async fn unknown_non_initial_datagram_splices_to_origin() {
        // Mock origin: echo one datagram back with a suffix (proves both directions).
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; 2048];
            let (n, from) = origin.recv_from(&mut b).await.unwrap();
            let mut reply = b[..n].to_vec();
            reply.extend_from_slice(b"-origin");
            origin.send_to(&reply, from).await.unwrap();
        });

        let server = Endpoint::server(
            "127.0.0.1:0".parse().unwrap(),
            server_config_splicing(origin_addr),
        )
        .await
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        // A raw client sends a non-Initial datagram (25 bytes: fails looks_like_initial,
        // which requires a >=1200B v1 Initial). The driver must splice it to the origin.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"not-a-quic-initial-packet", server_addr)
            .await
            .unwrap();

        // The origin's echo returns to the client FROM the server's listen address.
        let mut rb = vec![0u8; 2048];
        let (rn, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut rb))
            .await
            .expect("origin reply relayed back in time")
            .unwrap();
        assert_eq!(
            from, server_addr,
            "reply comes from the QUIC listener address"
        );
        assert_eq!(
            &rb[..rn],
            b"not-a-quic-initial-packet-origin",
            "datagram spliced verbatim to the origin and the reply relayed back"
        );
    }

    #[test]
    fn looks_like_initial_gates_connection_creation() {
        // Garbage / truncated / non-Initial datagrams from unknown peers must not
        // create connection state (review finding #1).
        assert!(!looks_like_initial(&[]), "empty");
        assert!(
            !looks_like_initial(&[0xff; MIN_INITIAL_DATAGRAM]),
            "a Retry-type long header is not an Initial"
        );
        assert!(
            !looks_like_initial(&[0xc0, 0, 0, 0, 1]),
            "below the 1200-byte minimum"
        );
        // A long-header Initial whose version is not v1 (here QUIC v2) is rejected.
        let mut v2 = vec![0xc0u8, 0x6b, 0x33, 0x43, 0xcf];
        v2.resize(MIN_INITIAL_DATAGRAM, 0);
        assert!(!looks_like_initial(&v2), "non-v1 version rejected");
        // A well-formed v1 long-header Initial, padded to the minimum, is accepted.
        let mut good = vec![0xc0u8, 0x00, 0x00, 0x00, 0x01];
        good.resize(MIN_INITIAL_DATAGRAM, 0);
        assert!(
            looks_like_initial(&good),
            "a well-formed v1 Initial is accepted"
        );
    }

    #[tokio::test]
    async fn async_client_and_server_handshake_over_udp_loopback() {
        let loop_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Endpoint::server(loop_addr, server_config()).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = Endpoint::client(loop_addr).await.unwrap();
        client.set_default_client_config(client_config());

        let accept = tokio::spawn(async move { server.accept().await });
        let conn = client
            .connect(server_addr, "example.com")
            .await
            .expect("client handshake completes over real UDP");
        let server_conn = accept
            .await
            .unwrap()
            .expect("server accepts the connection");

        // The RFC 5705 exporter agrees on both ends — the handshake really ran.
        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        conn.export_keying_material(&mut ce, b"parallax tudp", b"binding")
            .unwrap();
        server_conn
            .export_keying_material(&mut se, b"parallax tudp", b"binding")
            .unwrap();
        assert_eq!(ce, se, "exporter material matches across the UDP loopback");
        assert_ne!(ce, [0u8; 32]);
        assert!(
            conn.peer_transport_parameters().is_some(),
            "client learned the server's transport parameters"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_returns_promptly_without_follow_up_traffic() {
        // PAR-25 regression: wait_established must register its waiter (pin! + enable())
        // BEFORE re-checking is_handshaking, or a driver flipping handshake→done +
        // notify_waiters() between the check and the .await loses the wake-up, parking
        // connect() until some unrelated later wake. The failure is "no immediate
        // follow-up datagram after the handshake" — so we drive ONLY the handshake and
        // assert connect() resolves within a tight bound (it would otherwise hang for
        // seconds-to-minutes until the keep-alive/idle timer). Multi-thread runtime so
        // the driver and connect() race on separate threads, as in production.
        let loop_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Endpoint::server(loop_addr, server_config()).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = Endpoint::client(loop_addr).await.unwrap();
        client.set_default_client_config(client_config());

        let accept = tokio::spawn(async move { server.accept().await });
        let connected = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.connect(server_addr, "example.com"),
        )
        .await;
        let conn = connected
            .expect("connect() must resolve promptly after the handshake, not park on a lost wake")
            .expect("client handshake completes");
        let _server_conn = accept.await.unwrap().expect("server accepts");

        let mut ce = [0u8; 32];
        conn.export_keying_material(&mut ce, b"parallax tudp", b"binding")
            .unwrap();
        assert_ne!(ce, [0u8; 32], "the handshake really completed");
    }

    #[tokio::test]
    async fn connect_with_dcid_is_visible_to_the_server_for_session_routing() {
        // A stable-:443 carrier routes an accepted connection back to its session by
        // the client-chosen DCID (= the session offer_id). Prove the server observes
        // the exact DCID the client connected with.
        let loop_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Endpoint::server(loop_addr, server_config()).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = Endpoint::client(loop_addr).await.unwrap();
        client.set_default_client_config(client_config());

        let offer_id: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ];
        let accept = tokio::spawn(async move { server.accept().await });
        let conn = client
            .connect_with_dcid(server_addr, "example.com", ConnectionId::new(&offer_id))
            .await
            .expect("client handshake completes with an explicit DCID");
        let server_conn = accept
            .await
            .unwrap()
            .expect("server accepts the connection");

        assert_eq!(
            server_conn.peer_initial_dcid(),
            &offer_id,
            "server sees the client-chosen DCID verbatim (session-routing key)"
        );
        // The handshake still completes normally with a non-random DCID.
        let mut ce = [0u8; 32];
        conn.export_keying_material(&mut ce, b"parallax tudp", b"binding")
            .unwrap();
        assert_ne!(ce, [0u8; 32]);
    }

    #[tokio::test]
    async fn async_bidi_stream_round_trips_with_fin() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let loop_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Endpoint::server(loop_addr, server_config()).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = Endpoint::client(loop_addr).await.unwrap();
        client.set_default_client_config(client_config());

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut req = Vec::new();
            recv.read_to_end(&mut req).await.unwrap();
            // Echo the request back with a suffix, then FIN.
            send.write_all(&req).await.unwrap();
            send.write_all(b"-pong").await.unwrap();
            send.finish();
            // Keep the endpoint alive until the client has read the response.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let conn = client.connect(server_addr, "example.com").await.unwrap();
        let (mut send, mut recv) = conn.open_bi();
        send.write_all(b"ping").await.unwrap();
        send.finish();
        let mut resp = Vec::new();
        recv.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"ping-pong", "bidi stream echoes with FIN → EOF");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn async_uni_stream_delivers_to_accept_uni() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let loop_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Endpoint::server(loop_addr, server_config()).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = Endpoint::client(loop_addr).await.unwrap();
        client.set_default_client_config(client_config());

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap();
            let mut recv = conn.accept_uni().await.unwrap();
            let mut got = Vec::new();
            recv.read_to_end(&mut got).await.unwrap();
            got
        });

        let conn = client.connect(server_addr, "example.com").await.unwrap();
        let mut ctrl = conn.open_uni();
        ctrl.write_all(b"H3-SETTINGS").await.unwrap();
        ctrl.finish();
        let got = srv.await.unwrap();
        assert_eq!(got, b"H3-SETTINGS", "uni stream delivered to accept_uni");
    }

    #[tokio::test]
    async fn application_close_reason_reaches_the_peer() {
        let loop_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Endpoint::server(loop_addr, server_config()).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = Endpoint::client(loop_addr).await.unwrap();
        client.set_default_client_config(client_config());

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap();
            // Wait until the client's CONNECTION_CLOSE arrives.
            for _ in 0..50 {
                if let Some(reason) = conn.close_reason() {
                    return Some(reason);
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            None
        });

        let conn = client.connect(server_addr, "example.com").await.unwrap();
        conn.close(VarInt::from_u32(7), b"bye");

        let reason = srv.await.unwrap();
        assert_eq!(
            reason,
            Some(ConnectionError::ApplicationClosed(ApplicationClose {
                error_code: VarInt::from_u32(7),
                reason: b"bye".to_vec(),
            })),
            "the server observes the client's application close code + reason"
        );
    }

    fn server_config_marker(
        origin: SocketAddr,
        psk: zeroize::Zeroizing<Vec<u8>>,
        static_priv: [u8; 32],
    ) -> Arc<ServerConfig> {
        base_server_config(
            Some(origin),
            Some((psk, zeroize::Zeroizing::new(static_priv))),
        )
    }

    /// Like [`server_config_marker`] but with an explicit authorized-SNI allowlist, so
    /// the DN-1 marker SNI gate can be exercised.
    fn server_config_marker_sni(
        origin: SocketAddr,
        psk: zeroize::Zeroizing<Vec<u8>>,
        static_priv: [u8; 32],
        authorized_sni: Vec<String>,
    ) -> Arc<ServerConfig> {
        base_server_config_sni(
            Some(origin),
            Some((psk, zeroize::Zeroizing::new(static_priv))),
            authorized_sni,
        )
    }

    /// The marker fork: a client whose ClientHello.random carries a valid auth marker
    /// is TERMINATED locally (the handshake completes), while an unmarked client's
    /// Initial is spliced verbatim to the origin (which receives the >=1200B Initial).
    ///
    /// Buffer-decide-then-route marker fork, end to end: a MARKED client (whose
    /// PQ-inflated ClientHello spans two Initials) is held until the full first flight
    /// is reassembled, then terminated locally (handshake completes); an UNMARKED
    /// client's first flight is spliced to the origin verbatim. Exercises the
    /// multi-datagram path that the single-datagram fork used to mis-splice.
    #[tokio::test]
    async fn marked_client_terminates_while_unmarked_initial_splices() {
        use crate::crypto::session::X25519KeyPair;
        use crate::tls::quic::QuicMarkerConfig;
        use crate::transport::udp::endpoint::bind_client_endpoint_accept_any;

        let server_kp = X25519KeyPair::generate();
        let psk = zeroize::Zeroizing::new(b"parallax-quic-marker-fork-e2e-ps".to_vec());

        // Mock origin: report the size of any datagram it receives (the spliced Initial).
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let (otx, mut orx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut b = vec![0u8; 2048];
            while let Ok((n, _)) = origin.recv_from(&mut b).await {
                if otx.send(n).is_err() {
                    break;
                }
            }
        });

        let server = Endpoint::server(
            "127.0.0.1:0".parse().unwrap(),
            server_config_marker(origin_addr, psk.clone(), server_kp.private),
        )
        .await
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        // 1. A MARKED client terminates locally (the handshake completes).
        let marked = Endpoint::client("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        marked.set_default_client_config(Arc::new(
            ClientConfig::new(Arc::new(AcceptAnyServerCert), vec![b"h3".to_vec()]).with_marker(
                QuicMarkerConfig {
                    psk: psk.clone(),
                    server_static_public: server_kp.public,
                },
            ),
        ));
        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let conn = tokio::time::timeout(
            Duration::from_secs(5),
            marked.connect(server_addr, "example.com"),
        )
        .await
        .expect("marked client handshake must not hang (marker accepted -> terminate)")
        .expect("marked client must terminate locally (handshake completes)");
        let _server_conn = acceptor
            .await
            .unwrap()
            .expect("server accepts the marked client");
        drop(conn);

        // 2. An UNMARKED client's Initial is spliced to the origin (which receives a
        // full >=1200B v1 Initial). Its connect never completes (the echo origin is
        // not a QUIC server), so it is timeout-bounded.
        let unmarked = bind_client_endpoint_accept_any("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            unmarked.connect(server_addr, "example.com"),
        )
        .await;
        let got = tokio::time::timeout(Duration::from_secs(5), orx.recv())
            .await
            .expect("origin receives the spliced Initial in time")
            .expect("origin channel open");
        assert!(
            got >= MIN_INITIAL_DATAGRAM,
            "origin received a full v1 Initial ({got} bytes): the unmarked client was spliced"
        );
    }

    /// DN-1: a client carrying a VALID marker but an UNAUTHORIZED SNI is fronted to the
    /// origin, NOT terminated locally — parity with the TCP plane's authorized-SNI gate.
    /// The marker MAC commits to the SNI, so the client cannot lie about it; the server
    /// authorizes only `allowed.example` while the client connects with `example.com`,
    /// so the otherwise-valid marker is dropped and the flight splices to the origin
    /// (which receives the full >=1200B Initial). Sibling to
    /// `marked_client_terminates_while_unmarked_initial_splices`, which authorizes the
    /// client's SNI and so terminates it.
    #[tokio::test]
    async fn marked_client_with_unauthorized_sni_is_spliced() {
        use crate::crypto::session::X25519KeyPair;
        use crate::tls::quic::QuicMarkerConfig;
        use crate::transport::udp::endpoint::bind_client_endpoint_accept_any;

        let server_kp = X25519KeyPair::generate();
        let psk = zeroize::Zeroizing::new(b"parallax-quic-unauth-sni-fork-psk".to_vec());

        // Mock origin: report the size of any datagram it receives (the spliced flight).
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let (otx, mut orx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut b = vec![0u8; 2048];
            while let Ok((n, _)) = origin.recv_from(&mut b).await {
                if otx.send(n).is_err() {
                    break;
                }
            }
        });

        // The server authorizes ONLY `allowed.example`; the marked client below connects
        // with `example.com`, so its valid marker must not rescue it from the splice.
        let server = Endpoint::server(
            "127.0.0.1:0".parse().unwrap(),
            server_config_marker_sni(
                origin_addr,
                psk.clone(),
                server_kp.private,
                vec!["allowed.example".to_owned()],
            ),
        )
        .await
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        let marked = bind_client_endpoint_accept_any("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        marked.set_default_client_config(Arc::new(
            ClientConfig::new(Arc::new(AcceptAnyServerCert), vec![b"h3".to_vec()]).with_marker(
                QuicMarkerConfig {
                    psk,
                    server_static_public: server_kp.public,
                },
            ),
        ));
        // The connect never completes (the flight is spliced to the echo origin, not a
        // real QUIC server), so bound it.
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            marked.connect(server_addr, "example.com"),
        )
        .await;

        let got = tokio::time::timeout(Duration::from_secs(5), orx.recv())
            .await
            .expect("origin receives the spliced Initial (unauthorized SNI, not terminated)")
            .expect("origin channel open");
        assert!(
            got >= MIN_INITIAL_DATAGRAM,
            "origin received a full v1 Initial ({got} bytes): the unauthorized-SNI marked client was spliced"
        );
    }

    /// A LONE, incomplete first flight — a single well-formed v1 Initial whose
    /// ClientHello never completes, so the marker can never be verified — must NOT be
    /// held silently forever. The decision deadline ([`PENDING_DECIDE_DELAY`]) splices
    /// it to the origin, so a single-Initial active prober sees the real origin answer
    /// instead of the silence that would distinguish ParallaX from a bare origin.
    /// Pre-fix the held core armed no timer, so this datagram never reached the origin.
    #[tokio::test]
    async fn lone_incomplete_initial_is_spliced_after_the_decision_deadline() {
        use crate::crypto::session::X25519KeyPair;

        let server_kp = X25519KeyPair::generate();
        let psk = zeroize::Zeroizing::new(b"parallax-quic-lone-initial-splic".to_vec());

        // Mock origin: report the size of any datagram it receives (the spliced Initial).
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let (otx, mut orx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut b = vec![0u8; 2048];
            while let Ok((n, _)) = origin.recv_from(&mut b).await {
                if otx.send(n).is_err() {
                    break;
                }
            }
        });

        let server = Endpoint::server(
            "127.0.0.1:0".parse().unwrap(),
            server_config_marker(origin_addr, psk, server_kp.private),
        )
        .await
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        // One well-formed v1 long-header Initial padded to the §14.1 minimum: it passes
        // looks_like_initial (so it is held for the marker decision) but its CRYPTO never
        // assembles a ClientHello, so the flight stays undecided — the path that
        // previously hung silently forever.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut initial = vec![0xc0u8, 0x00, 0x00, 0x00, 0x01];
        initial.resize(MIN_INITIAL_DATAGRAM, 0);
        client.send_to(&initial, server_addr).await.unwrap();

        // The decision deadline must splice it to the origin (which receives the full
        // >=1200B Initial), bounded well under the generous timeout.
        let got = tokio::time::timeout(Duration::from_secs(5), orx.recv())
            .await
            .expect("origin receives the timed-out lone Initial (spliced, not held silently)")
            .expect("origin channel open");
        assert!(
            got >= MIN_INITIAL_DATAGRAM,
            "origin received the full v1 Initial ({got} bytes): the lone undecided flight was spliced"
        );
    }

    /// A genuine MARKED client whose SECOND Initial arrives after the decision deadline
    /// is still spliced, NOT rescued into local termination: the deadline force-splices
    /// the held first flight even though the marker would have validated had the full
    /// ClientHello arrived in time. Pins the accepted fail-safe tradeoff (such a client
    /// fails closed on the origin cert and self-heals by redialing — availability, not a
    /// security regression). Sibling to `marked_client_terminates_while_unmarked_initial_splices`,
    /// which sends both Initials back-to-back (decided locally before the deadline).
    #[tokio::test]
    async fn marked_client_with_late_second_initial_is_spliced() {
        use crate::crypto::session::X25519KeyPair;
        use crate::tls::quic::QuicMarkerConfig;

        let server_kp = X25519KeyPair::generate();
        let psk = zeroize::Zeroizing::new(b"parallax-quic-late-2nd-initial-p".to_vec());

        // Mock origin: report the size of each datagram it receives (the spliced flight).
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let (otx, mut orx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut b = vec![0u8; 2048];
            while let Ok((n, _)) = origin.recv_from(&mut b).await {
                if otx.send(n).is_err() {
                    break;
                }
            }
        });

        let server = Endpoint::server(
            "127.0.0.1:0".parse().unwrap(),
            server_config_marker(origin_addr, psk.clone(), server_kp.private),
        )
        .await
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        // A delay relay between client and server: forwards every client->server datagram,
        // but holds the SECOND (the rest of the PQ ClientHello) well past
        // PENDING_DECIDE_DELAY, so the server's decision deadline fires on the first
        // Initial alone — before the marker (which needs the key_share in the 2nd) can be
        // verified. One upstream socket, so the server sees a single peer/flow.
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay.local_addr().unwrap();
        tokio::spawn(async move {
            let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            upstream.connect(server_addr).await.unwrap();
            let mut count = 0u32;
            let mut cbuf = vec![0u8; 2048];
            loop {
                let Ok((n, _from)) = relay.recv_from(&mut cbuf).await else {
                    return;
                };
                count += 1;
                let data = cbuf[..n].to_vec();
                let up = upstream.clone();
                if count == 2 {
                    tokio::spawn(async move {
                        tokio::time::sleep(PENDING_DECIDE_DELAY * 3).await;
                        let _ = up.send(&data).await;
                    });
                } else {
                    let _ = up.send(&data).await;
                }
            }
        });

        let marked = Endpoint::client("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        marked.set_default_client_config(Arc::new(
            ClientConfig::new(Arc::new(AcceptAnyServerCert), vec![b"h3".to_vec()]).with_marker(
                QuicMarkerConfig {
                    psk,
                    server_static_public: server_kp.public,
                },
            ),
        ));
        // The connect never completes (the flight is spliced to the echo origin, not a
        // real QUIC server), so bound it.
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            marked.connect(relay_addr, "example.com"),
        )
        .await;

        // The held first Initial is spliced to the origin at the deadline (a full
        // >=1200B Initial); the late second Initial — arriving after the splice — is
        // forwarded verbatim too. So the origin sees the marked client's whole flight: a
        // valid marker did not rescue a flight that missed the deadline.
        let first = tokio::time::timeout(Duration::from_secs(5), orx.recv())
            .await
            .expect("origin receives the deadline-spliced first Initial")
            .expect("origin channel open");
        assert!(
            first >= MIN_INITIAL_DATAGRAM,
            "origin received the full first v1 Initial ({first} bytes): spliced at the deadline"
        );
        tokio::time::timeout(Duration::from_secs(5), orx.recv())
            .await
            .expect("the late second Initial is also forwarded to the origin (not rescued)")
            .expect("origin channel open");
    }

    /// `Some(0)` is normalized to `None` (keep autotuning); a positive value is kept.
    #[test]
    fn configure_normalizes_zero_to_autotuning() {
        let bufs = UdpSocketBuffers {
            send: Some(0u32).filter(|&b| b > 0),
            recv: Some(1_048_576u32).filter(|&b| b > 0),
        };
        assert!(bufs.send.is_none(), "0 means keep autotuning");
        assert_eq!(bufs.recv, Some(1_048_576), "positive value is kept");
    }

    /// With no buffers requested, applying is a pure no-op (the default, zero-regression
    /// path): it reports nothing applied and leaves the socket's kernel-chosen sizes.
    #[cfg(unix)]
    #[tokio::test]
    async fn apply_none_leaves_socket_untouched() {
        use socket2::SockRef;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let before = SockRef::from(&socket).recv_buffer_size().unwrap();
        let applied = apply_udp_socket_buffers(&socket, UdpSocketBuffers::default());
        assert_eq!(
            applied,
            AppliedUdpBuffers::default(),
            "no-op reports nothing"
        );
        let after = SockRef::from(&socket).recv_buffer_size().unwrap();
        assert_eq!(before, after, "no override must not touch the socket");
    }

    /// Applying an explicit recv buffer is accepted by the kernel and visible on the
    /// returned read-back (the socket2 plumbing works on this platform). The kernel may
    /// clamp to net.core.rmem_max / kern.ipc.maxsockbuf, so assert the set both reported
    /// a value AND that value actually grew above the autotuned baseline — a silently
    /// ignored or failed setsockopt would leave `applied.recv == None`, failing here.
    #[cfg(unix)]
    #[tokio::test]
    async fn apply_explicit_recv_buffer_takes_effect() {
        use socket2::SockRef;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let baseline = SockRef::from(&socket).recv_buffer_size().unwrap();
        let applied = apply_udp_socket_buffers(
            &socket,
            UdpSocketBuffers {
                send: None,
                recv: Some(4_000_000),
            },
        );
        // The meaningful plumbing assertion: the set + read-back both returned Ok, so
        // `applied.recv` is Some (a silently-ignored or failed setsockopt would leave it
        // None and fail here). The value must be at least the baseline — the kernel may
        // clamp to net.core.rmem_max / kern.ipc.maxsockbuf, so it can equal but never
        // shrink below where autotuning started.
        let got = applied
            .recv
            .expect("the recv setsockopt + read-back must succeed");
        assert!(
            got >= baseline,
            "explicit recv buffer ({got}) must be >= baseline ({baseline})"
        );
        assert!(applied.send.is_none(), "send was not requested");
    }
}
