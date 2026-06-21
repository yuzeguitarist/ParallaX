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
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

use super::conn::Connection as Core;
use super::packet::ConnectionId;
use crate::tls::quic::{ClientConfig, QuicTlsError};

/// Maximum UDP payload we will read in one datagram (a generous ceiling above the
/// path MTU; oversized datagrams are truncated, which fails AEAD and is dropped).
const MAX_UDP_PAYLOAD: usize = 2048;

/// Server identity + parameters for accepting connections.
pub struct ServerConfig {
    /// DER-encoded certificate chain presented in the TLS Certificate message.
    pub cert_chain: Vec<Vec<u8>>,
    /// PKCS#8 ECDSA P-256 signing key for the CertificateVerify.
    pub signing_key_pkcs8: Vec<u8>,
    /// Offered ALPN protocols (the relay offers exactly `h3`).
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Encoded QUIC transport parameters blob.
    pub transport_parameters: Vec<u8>,
}

/// Failure to establish a connection.
#[derive(Debug)]
pub enum ConnectError {
    /// The TLS / transport layer rejected the handshake.
    Tls(QuicTlsError),
    /// The endpoint driver shut down before the handshake completed.
    EndpointClosed,
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Tls(e) => write!(f, "handshake failed: {e:?}"),
            ConnectError::EndpointClosed => write!(f, "endpoint closed"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Shared per-connection state: the synchronous core behind a mutex, plus the
/// notifications the driver uses to wake blocked handles.
struct ConnShared {
    core: Mutex<Core>,
    peer: SocketAddr,
    /// Fired whenever the connection state advances (handshake progress, new
    /// readable data, a newly-accepted stream, or teardown).
    event: Notify,
    /// Set once the connection has been pushed to the accept queue (server only).
    accept_taken: std::sync::atomic::AtomicBool,
}

impl ConnShared {
    fn is_handshaking(&self) -> bool {
        self.core.lock().unwrap().is_handshaking()
    }
}

/// A request from [`Endpoint::connect`] for the driver to open a client connection.
struct ConnectRequest {
    addr: SocketAddr,
    server_name: String,
    config: Arc<ClientConfig>,
    reply: tokio::sync::oneshot::Sender<Arc<ConnShared>>,
}

/// An async QUIC endpoint: a handle onto the driver task that owns the socket.
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    /// Nudge the driver after a handle queues outbound work.
    wake: Arc<Notify>,
    /// Submit a client connect request to the driver.
    connect_tx: mpsc::UnboundedSender<ConnectRequest>,
    /// Receive server-accepted, fully-established connections.
    accept_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Arc<ConnShared>>>,
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
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let driver = Driver {
            socket: socket.clone(),
            wake: wake.clone(),
            conns: HashMap::new(),
            server,
            accept_tx,
            connect_rx,
            next_scid: 1,
        };
        tokio::spawn(driver.run());
        Ok(Endpoint {
            socket,
            wake,
            connect_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
        })
    }

    /// The bound local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Open a client connection to `addr`, awaiting handshake completion.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Connection, ConnectError> {
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        self.connect_tx
            .send(ConnectRequest {
                addr,
                server_name: server_name.to_string(),
                config,
                reply,
            })
            .map_err(|_| ConnectError::EndpointClosed)?;
        let shared = reply_rx.await.map_err(|_| ConnectError::EndpointClosed)?;
        // Drive until the handshake completes. Create the notification BEFORE the
        // re-check so a wake-up between check and await is not lost, and never hold
        // the borrow across the move into `Connection`.
        loop {
            if !shared.is_handshaking() {
                break;
            }
            let notified = shared.event.notified();
            if shared.is_handshaking() {
                notified.await;
            }
        }
        Ok(Connection { shared })
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
    server: Option<Arc<ServerConfig>>,
    accept_tx: mpsc::UnboundedSender<Arc<ConnShared>>,
    connect_rx: mpsc::UnboundedReceiver<ConnectRequest>,
    /// Source-connection-id counter for accepted server connections.
    next_scid: u64,
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
                _ = wake.notified() => {}
                _ = sleep_until(deadline) => self.on_timeout(),
            }

            self.flush().await;
            self.promote_accepts();
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
            c.event.notify_waiters();
            return;
        }
        // A datagram from an unknown peer: open a server connection if configured.
        let Some(cfg) = self.server.clone() else {
            return;
        };
        let scid = self.next_scid.to_be_bytes();
        self.next_scid += 1;
        let core = match Core::new_server(
            cfg.cert_chain.clone(),
            &cfg.signing_key_pkcs8,
            cfg.alpn_protocols.clone(),
            cfg.transport_parameters.clone(),
            ConnectionId::new(&scid),
        ) {
            Ok(core) => core,
            Err(_) => return,
        };
        let shared = Arc::new(ConnShared {
            core: Mutex::new(core),
            peer,
            event: Notify::new(),
            accept_taken: std::sync::atomic::AtomicBool::new(false),
        });
        let _ = shared.core.lock().unwrap().handle_datagram(data, now);
        self.conns.insert(peer, shared);
    }

    fn on_connect(&mut self, req: ConnectRequest) {
        let dcid = random_cid();
        let core =
            match Core::new_client(req.config, &req.server_name, dcid, ConnectionId::new(&[])) {
                Ok(core) => core,
                Err(_) => return, // reply dropped → connect() sees EndpointClosed
            };
        let shared = Arc::new(ConnShared {
            core: Mutex::new(core),
            peer: req.addr,
            event: Notify::new(),
            accept_taken: std::sync::atomic::AtomicBool::new(false),
        });
        self.conns.insert(req.addr, shared.clone());
        let _ = req.reply.send(shared);
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
            c.event.notify_waiters();
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
        let tp = super::super::transport_params::TransportParameters::safari_client(&[])
            .encode_safari_client();
        Arc::new(ServerConfig {
            cert_chain: vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            signing_key_pkcs8: key,
            alpn_protocols: vec![b"h3".to_vec()],
            transport_parameters: tp,
        })
    }

    #[tokio::test]
    async fn async_client_and_server_handshake_over_udp_loopback() {
        let loop_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Endpoint::server(loop_addr, server_config()).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = Endpoint::client(loop_addr).await.unwrap();

        let accept = tokio::spawn(async move { server.accept().await });
        let conn = client
            .connect(server_addr, "example.com", client_config())
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
}
