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

/// Whether `data` is plausibly a client's first Initial: a v1 long-header Initial
/// packet in a datagram padded to the §14.1 minimum. A cheap pre-check so garbage,
/// truncated, or non-Initial datagrams from unknown peers never allocate the
/// (multi-KB) per-connection state.
fn looks_like_initial(data: &[u8]) -> bool {
    data.len() >= MIN_INITIAL_DATAGRAM
        && first_packet_space(data) == Some(PacketSpace::Initial)
        && u32::from_be_bytes([data[1], data[2], data[3], data[4]]) == QUIC_VERSION_V1
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
    /// STEK for issuing + accepting 0-RTT resumption tickets. `None` keeps the
    /// server cold-start-only (no NewSessionTicket, no 0-RTT acceptance).
    pub stek: Option<Zeroizing<[u8; 32]>>,
    /// Cross-connection single-use 0-RTT anti-replay guard, installed on every
    /// accepted connection. Should be `Some` whenever `stek` is `Some`.
    pub replay_guard: Option<Arc<dyn ZeroRttGuard>>,
    /// Camouflage origin's UDP/443 address for the REALITY-style fallback splice.
    /// When `Some`, a datagram from an unknown peer that is NOT a well-formed v1
    /// Initial (a probe, garbage, non-v1, version-negotiation-eliciting) is relayed
    /// verbatim to the origin so the prober reaches the TRUE origin (see
    /// [`Driver::on_datagram`]). `None` keeps the current behaviour (drop), so the
    /// splice stays dormant until the server runtime supplies the resolved origin.
    pub origin_udp_addr: Option<SocketAddr>,
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
        let wake = Arc::new(Notify::new());
        let (connect_tx, connect_rx) = mpsc::unbounded_channel();
        let (close_tx, close_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let driver = Driver {
            socket: socket.clone(),
            wake: wake.clone(),
            conns: HashMap::new(),
            splices: HashMap::new(),
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
            .submit_connect(addr, server_name, Some(ticket), now_ms)
            .await?;
        // 0-RTT keys are installed at construction (new_client_resumption), so the
        // returned handle can send early data immediately; the handshake continues
        // in the background.
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
            .submit_connect(addr, server_name, ticket, now_ms)
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

    /// Nudge the driver (used by connection handles after queuing outbound work).
    fn wake(&self) {
        self.wake.notify_one();
    }
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
    server: Option<Arc<ServerConfig>>,
    accept_tx: mpsc::UnboundedSender<Arc<ConnShared>>,
    connect_rx: mpsc::UnboundedReceiver<ConnectRequest>,
    close_rx: mpsc::UnboundedReceiver<(u64, Vec<u8>)>,
}

impl Driver {
    async fn run(mut self) {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
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

    /// The earliest armed timer across all connections.
    fn next_deadline(&self) -> Option<Instant> {
        self.conns
            .values()
            .filter_map(|c| c.core.lock().unwrap().next_timeout())
            .min()
    }

    fn on_timeout(&mut self) {
        let now = Instant::now();
        for c in self.conns.values() {
            let mut core = c.core.lock().unwrap();
            if core.next_timeout().is_some_and(|t| t <= now) {
                core.handle_timeout(now);
            }
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
        // Bound state creation (review finding #1): never beyond the hard cap. Floods
        // past the cap are dropped before they can allocate a Box<ServerHandshake> +
        // Bbr + spaces (unauthenticated DoS).
        if self.conns.len() >= MAX_SERVER_CONNS {
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
        let core = match Core::new_server_with_stek(
            cfg.cert_chain.clone(),
            &cfg.signing_key_pkcs8,
            cfg.alpn_protocols.clone(),
            // Encode the server transport parameters with THIS connection's source
            // CID, so initial_source_connection_id matches the Initial header SCID
            // (RFC 9000 §7.3) instead of a stale config-time placeholder.
            super::transport_params::TransportParameters::server(&scid).encode_server(),
            ConnectionId::new(&scid),
            cfg.stek.clone(),
        ) {
            Ok(mut core) => {
                // Install the shared single-use 0-RTT anti-replay guard so a replayed
                // ticket on any connection is rejected (falls back to 1-RTT).
                if let Some(guard) = cfg.replay_guard.clone() {
                    core.set_zero_rtt_replay_guard(guard);
                }
                core
            }
            Err(_) => return,
        };
        let shared = Arc::new(ConnShared {
            core: Mutex::new(core),
            peer,
            event: Notify::new(),
            wake: self.wake.clone(),
            read_wakers: Mutex::new(Vec::new()),
            accept_taken: std::sync::atomic::AtomicBool::new(false),
        });
        let _ = shared.core.lock().unwrap().handle_datagram(data, now);
        self.conns.insert(peer, shared);
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
        if let Ok(flow) = SpliceFlow::open(self.socket.clone(), peer, origin, first) {
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
        let dcid = random_cid();
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

/// An established connection handle.
pub struct Connection {
    shared: Arc<ConnShared>,
}

impl Connection {
    /// The peer's UDP socket address (its source 4-tuple endpoint). Used by the
    /// server to filter an accepted connection against the authenticated peer's IP.
    pub fn remote_address(&self) -> SocketAddr {
        self.shared.peer
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
    pub(crate) fn zero_rtt_keys_installed(&self) -> bool {
        self.shared.core.lock().unwrap().zero_rtt_keys_installed()
    }

    /// Await handshake completion (or a connection close). A 0-RTT connect
    /// ([`Endpoint::connect_resumption_0rtt`]) returns before the handshake so the
    /// caller can send early data; it then awaits this before relying on 1-RTT-only
    /// facilities (the RFC 5705 exporter, or reads of the peer's 1-RTT response).
    pub async fn wait_established(&self) -> Result<(), ConnectError> {
        // Create the notification BEFORE the re-check so a wake-up between check and
        // await is not lost.
        loop {
            if self.shared.is_closed() {
                return Err(ConnectError::ConnectionClosed);
            }
            if !self.shared.is_handshaking() {
                return Ok(());
            }
            let notified = self.shared.event.notified();
            if self.shared.is_handshaking() && !self.shared.is_closed() {
                notified.await;
            }
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

    fn server_config() -> Arc<ServerConfig> {
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
            stek: None,
            replay_guard: None,
            origin_udp_addr: None,
        })
    }

    fn server_config_splicing(origin: SocketAddr) -> Arc<ServerConfig> {
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
            stek: None,
            replay_guard: None,
            origin_udp_addr: Some(origin),
        })
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
}
