//! Stable-:443 origin-splice QUIC carrier.
//!
//! One process-wide endpoint, bound on the real `:443/UDP` like an HTTP/3 origin,
//! that:
//!   * marker-terminates an authenticated ParallaX client (a valid + fresh +
//!     non-replayed covert marker in its ClientHello.random) — these are the only
//!     connections [`Endpoint::accept`] yields;
//!   * splices every other v1 Initial (no / forged / replayed marker, junk, or a
//!     non-v1 datagram) VERBATIM to the real origin inside the endpoint, so an
//!     active prober reaches the TRUE origin and ParallaX emits nothing of its own;
//!   * routes each accepted (terminated) connection back to the TCP session that
//!     offered the fast plane, keyed by the client-chosen Destination Connection ID
//!     (the client sets it to the session `offer_id`; the server cannot predict the
//!     client's UDP source port in advance, so the DCID is the correlation handle).
//!
//! This is the QUIC analogue of the TCP REALITY fallback: authentication lives in
//! the first Initial (the marker), and everything unauthenticated is handed to the
//! fronted origin rather than answered by ParallaX.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use super::quic::endpoint::{Connection, Endpoint, ServerConfig};

/// Maps a pending session's `offer_id` to the channel that delivers its connection.
type OfferRegistry = Arc<Mutex<HashMap<[u8; 16], oneshot::Sender<Connection>>>>;

/// The process-wide stable-:443 carrier (see the module docs).
pub(crate) struct QuicCarrier {
    registry: OfferRegistry,
    /// The endpoint handle whose driver task owns the bound `:443/UDP` socket. Held
    /// for the carrier's lifetime; on drop the accept task is aborted (see
    /// [`Self::accept_task`]) and this handle is released, which lets the driver exit
    /// and frees the socket.
    endpoint: Endpoint,
    /// Handle to the spawned accept loop, ABORTED by [`Drop`] to break a reference
    /// cycle: the accept task owns an [`Endpoint`] clone (a live `connect_tx`), so
    /// while it runs the driver's `connect_rx` never closes, the driver never
    /// returns, [`Endpoint::accept`] never yields `None`, and neither the driver
    /// task nor the bound `:443/UDP` socket are ever freed — dropping the carrier's
    /// `endpoint` alone cannot break it. Aborting this task drops that clone so,
    /// once the `endpoint` field drops right after, the driver exits and the socket
    /// is released.
    accept_task: tokio::task::JoinHandle<()>,
}

impl QuicCarrier {
    /// Bind the carrier on `listen` (the real `:443/UDP`) with `config` (marker key +
    /// origin set, e.g. via [`super::server_config_stable`]) and spawn the accept loop
    /// that demuxes terminated connections to waiting sessions by their DCID.
    pub(crate) async fn bind(
        listen: SocketAddr,
        config: Arc<ServerConfig>,
    ) -> std::io::Result<Arc<Self>> {
        let endpoint = Endpoint::server(listen, config).await?;
        let registry: OfferRegistry = Arc::new(Mutex::new(HashMap::new()));

        let accept_ep = endpoint.clone();
        let accept_reg = registry.clone();
        let accept_task = tokio::spawn(async move {
            // `accept()` only yields marker-terminated connections — probers are
            // spliced to the origin inside the endpoint and never surface here.
            while let Some(conn) = accept_ep.accept().await {
                // Route by the client-chosen DCID (= the session `offer_id`). A
                // connection whose DCID is not a registered 16-byte offer_id (a stray,
                // a late arrival after the session gave up, or a marked client with no
                // pending session) is dropped — closing it cleanly via the handle drop.
                let Ok(offer_id) = <[u8; 16]>::try_from(conn.peer_initial_dcid()) else {
                    continue;
                };
                // Recover from a poisoned registry rather than unwrap-panicking: this
                // is the process-wide accept task, so a panic here would silently kill
                // demuxing for ALL future connections (a much larger blast radius than
                // one connection). The map only ever holds plain oneshot senders, so a
                // recovered guard is consistent. Matches the poison-tolerant locking in
                // `handshake::source_limit` and keeps register/unregister consistent.
                let waiter = accept_reg
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&offer_id);
                if let Some(tx) = waiter {
                    // Receiver gone (session timed out) → the connection drops here.
                    let _ = tx.send(conn);
                }
            }
        });

        Ok(Arc::new(Self {
            registry,
            endpoint,
            accept_task,
        }))
    }

    /// The carrier's bound local address (the real `:443/UDP`).
    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// A cloned handle on the carrier's endpoint. Used by the server runtime's
    /// mid-relay-reset test hook to forcibly close the carrier (and thus the relay
    /// connection) in flight; production code never closes the shared carrier.
    #[cfg(test)]
    pub(crate) fn endpoint_handle(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// Register a session's `offer_id` and return a receiver for its connection. The
    /// session sends the client an offer carrying this id; the client connects to the
    /// carrier with the id as its first-Initial DCID, and the accept loop delivers the
    /// connection. The session MUST await (bounded) and, on timeout, call
    /// [`Self::unregister`] so a no-show registration does not leak.
    pub(crate) fn register(&self, offer_id: [u8; 16]) -> oneshot::Receiver<Connection> {
        let (tx, rx) = oneshot::channel();
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(offer_id, tx);
        rx
    }

    /// Drop a pending registration (the session gave up before the client connected).
    pub(crate) fn unregister(&self, offer_id: &[u8; 16]) {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(offer_id);
    }
}

impl Drop for QuicCarrier {
    fn drop(&mut self) {
        // Break the reference cycle documented on `accept_task`: the accept loop
        // owns an `Endpoint` clone (a live `connect_tx`). Aborting it drops that
        // clone, so once the `endpoint` field drops immediately after this returns,
        // the driver's `connect_rx` closes, the driver task returns, and the bound
        // `:443/UDP` socket is released. Without this the driver — and the socket —
        // would live forever.
        self.accept_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::crypto::session::X25519KeyPair;
    use crate::tls::quic::{AcceptAnyServerCert, ClientConfig, QuicMarkerConfig};
    use crate::transport::udp::quic::endpoint::Endpoint;
    use crate::transport::udp::quic::packet::ConnectionId;
    use crate::transport::udp::server_config_stable;
    use crate::transport::udp::test_support::self_signed_cert;

    /// A marked client connecting to the carrier with its DCID set to the session
    /// `offer_id` is terminated locally AND routed to the exact session that
    /// registered that id — the stable-:443 demux working end to end on loopback.
    #[tokio::test]
    async fn marked_client_is_routed_to_its_registered_session() {
        let server_kp = X25519KeyPair::generate();
        let psk = zeroize::Zeroizing::new(b"parallax-quic-stable-carrier-psk".to_vec());
        // Origin is never exercised here (the marked client terminates locally); any
        // address works as the dormant splice target.
        let origin: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (cert, key) = self_signed_cert();
        let config = server_config_stable(
            cert,
            key,
            None,
            (psk.clone(), zeroize::Zeroizing::new(server_kp.private)),
            None,
            origin,
            // The client below connects with "example.com", so authorize it.
            vec!["example.com".to_owned()],
            0,
        )
        .unwrap();
        let carrier = QuicCarrier::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();
        let carrier_addr = carrier.local_addr().unwrap();

        let client = Endpoint::client("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        client.set_default_client_config(Arc::new(
            ClientConfig::new(Arc::new(AcceptAnyServerCert), vec![b"h3".to_vec()]).with_marker(
                QuicMarkerConfig {
                    psk: psk.clone(),
                    server_static_public: server_kp.public,
                },
            ),
        ));

        let offer_id: [u8; 16] = [
            0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d,
            0x8e, 0x9f,
        ];
        let rx = carrier.register(offer_id);

        // Drive the client connect and the server-side handoff concurrently.
        let connect =
            client.connect_with_dcid(carrier_addr, "example.com", ConnectionId::new(&offer_id));
        let (client_res, server_res) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), connect),
            tokio::time::timeout(Duration::from_secs(5), rx),
        );

        let _client_conn = client_res
            .expect("client connect did not time out")
            .expect("marked client terminates locally (handshake completes)");
        let server_conn = server_res
            .expect("session handoff did not time out")
            .expect("the carrier delivered the connection to the registered session");
        assert_eq!(
            server_conn.peer_initial_dcid(),
            &offer_id,
            "the routed connection carries the session offer_id as its DCID"
        );
    }

    /// Dropping the carrier must stop its accept loop and free the bound
    /// `:443/UDP` socket. Regression: the accept task owns an `Endpoint` clone, so
    /// without a `Drop` that aborts it the driver never exits and the port stays
    /// bound forever — the "dropping it stops the endpoint + accept loop" contract
    /// was false. Proven by rebinding the exact port after the drop.
    #[tokio::test]
    async fn dropping_the_carrier_frees_the_socket() {
        let server_kp = X25519KeyPair::generate();
        let psk = zeroize::Zeroizing::new(b"parallax-quic-stable-carrier-psk".to_vec());
        let origin: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (cert, key) = self_signed_cert();
        let config = server_config_stable(
            cert,
            key,
            None,
            (psk.clone(), zeroize::Zeroizing::new(server_kp.private)),
            None,
            origin,
            vec!["example.com".to_owned()],
            0,
        )
        .unwrap();

        let carrier = QuicCarrier::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();
        let carrier_addr = carrier.local_addr().unwrap();

        // While the carrier is alive its socket owns the port: a fresh UDP bind to
        // the same address must fail (the endpoint binds without SO_REUSEADDR).
        assert!(
            tokio::net::UdpSocket::bind(carrier_addr).await.is_err(),
            "the carrier's port {carrier_addr} must be in use while it is alive"
        );

        drop(carrier);

        // The abort + driver exit are asynchronous, so poll-rebind under a bounded
        // timeout: a successful bind proves the driver task released the socket
        // (i.e. the accept loop stopped and the cycle was broken). Pre-fix this
        // never succeeds and the test times out.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if tokio::net::UdpSocket::bind(carrier_addr).await.is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "dropping the carrier did not free {carrier_addr}: the driver task \
                 (and its accept loop) is still running"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
