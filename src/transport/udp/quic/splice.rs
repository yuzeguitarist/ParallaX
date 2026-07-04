//! Verbatim UDP relay to the camouflage origin — the QUIC analogue of the TCP
//! REALITY fallback splice (`crate::handshake::server::relay_fallback`).
//!
//! When a UDP flow reaching the QUIC listener is NOT a provably-authenticated
//! ParallaX client (a probe, garbage, a non-v1 / non-Initial packet, or — once the
//! Initial marker lands — an unauthenticated ClientHello), its datagrams are
//! forwarded **byte-for-byte** to the real origin's UDP/443 and the origin's
//! replies are sent back to the client through the listening socket. The active
//! prober therefore completes its handshake against the TRUE origin (real cert,
//! real H3 SETTINGS, real behaviour) and ParallaX emits no QUIC bytes of its own —
//! exactly the property the TCP plane already has, with zero per-origin config.
//!
//! This module is the relay ENGINE only; the decide-to-splice fork lives in the
//! endpoint driver ([`super::endpoint`]). The relay is origin-agnostic and never
//! parses, decrypts, or reframes QUIC — it preserves datagram boundaries verbatim,
//! so it cannot itself become a fingerprint distinct from a transparent forwarder.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

/// Receive-buffer size for the origin→client pump: the largest possible UDP
/// datagram payload (65535 minus the 8-byte UDP header), mirroring
/// [`crate::config::MAX_UDP_PAYLOAD_BYTES`]. The client→origin direction forwards
/// each datagram verbatim with no relay-imposed cap (on Linux a single inbound
/// datagram of up to 64 KiB reaches [`SpliceFlow::forward`] through the endpoint's
/// GRO gather buffer), so the pump must be equally generous: sizing it to the
/// endpoint's recv cap silently truncated larger origin datagrams, corrupting the
/// relayed flow and making the relay a non-transparent forwarder (finding #35).
const MAX_RELAY_PAYLOAD: usize = crate::config::MAX_UDP_PAYLOAD_BYTES as usize;

/// One spliced flow: a connected UDP socket toward the origin plus the background
/// task pumping origin→client replies back through the listening socket. Dropping
/// it aborts the pump and closes the upstream socket (the relay ends).
pub(crate) struct SpliceFlow {
    /// Connected, non-blocking std socket toward the origin, for synchronous
    /// client→origin sends from the driver's `on_datagram`. A direct non-blocking
    /// syscall avoids tokio's cached-readiness `try_send`, which can spuriously
    /// report `WouldBlock` on a freshly registered socket and silently drop the
    /// first forwarded datagram.
    send_sock: std::net::UdpSocket,
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for SpliceFlow {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

impl SpliceFlow {
    /// Open a relay for `client` toward `origin`, forwarding the client's first
    /// datagram (`first`) now and pumping origin replies back to `client` via
    /// `listen` (the QUIC listener socket, so replies carry the address the client
    /// sent to). The upstream socket is `connect()`ed to `origin`, so only the
    /// origin's datagrams are received and a stray off-path sender cannot inject.
    ///
    /// Synchronous (no `.await`) so the endpoint driver's synchronous `on_datagram`
    /// fork can open a relay inline: a `connect()`ed UDP socket needs no network
    /// round-trip, and the first `send` only queues into the socket buffer. Must be
    /// called from within a Tokio runtime (the driver task) — `from_std` registers
    /// the recv half with the reactor and the pump is spawned there.
    pub(crate) fn open(
        listen: Arc<UdpSocket>,
        client: SocketAddr,
        origin: SocketAddr,
        first: &[u8],
    ) -> std::io::Result<SpliceFlow> {
        let recv_std = std::net::UdpSocket::bind(unspecified_for(origin))?;
        recv_std.connect(origin)?;
        // Non-blocking is required by `UdpSocket::from_std` and is shared with the
        // cloned send half (O_NONBLOCK is a per-open-file-description flag).
        recv_std.set_nonblocking(true)?;
        let send_sock = recv_std.try_clone()?;
        // Verbatim: exact bytes, single datagram, no coalesce/split/reframe.
        send_sock.send(first)?;
        let to_origin = Arc::new(UdpSocket::from_std(recv_std)?);
        let pump = tokio::spawn(pump_origin_to_client(to_origin, listen, client));
        Ok(SpliceFlow { send_sock, pump })
    }

    /// Forward a subsequent client→origin datagram verbatim (non-blocking). A
    /// `WouldBlock` (origin socket buffer full) drops this datagram, which is benign
    /// for a relay — the client's QUIC stack treats it as ordinary packet loss.
    pub(crate) fn forward(&self, data: &[u8]) -> std::io::Result<()> {
        match self.send_sock.send(data) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Pump origin→client: every datagram the origin sends is relayed back to the
/// client through the listening socket verbatim, until the upstream socket errors
/// or the flow is dropped. The buffer holds the largest possible UDP datagram
/// ([`MAX_RELAY_PAYLOAD`]) so an origin datagram is never silently truncated —
/// symmetric with the uncapped client→origin forward.
async fn pump_origin_to_client(
    to_origin: Arc<UdpSocket>,
    listen: Arc<UdpSocket>,
    client: SocketAddr,
) {
    let mut buf = vec![0u8; MAX_RELAY_PAYLOAD];
    loop {
        match to_origin.recv(&mut buf).await {
            Ok(n) => {
                // A send failure to the client (gone / unreachable) ends the relay.
                if listen.send_to(&buf[..n], client).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// The wildcard bind address in the origin's address family, so the upstream
/// socket can reach an IPv4 or IPv6 origin.
fn unspecified_for(origin: SocketAddr) -> SocketAddr {
    if origin.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The relay forwards client→origin and origin→client datagrams byte-for-byte,
    /// with origin replies arriving at the client FROM the listener address (so the
    /// client's QUIC stack sees a consistent peer). This is the core "reach the true
    /// origin" property the splice provides.
    #[tokio::test]
    async fn splice_relays_verbatim_both_directions() {
        // Mock origin: echo one datagram back with a suffix (proves both directions).
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; MAX_RELAY_PAYLOAD];
            let (n, from) = origin.recv_from(&mut b).await.unwrap();
            let mut reply = b[..n].to_vec();
            reply.extend_from_slice(b"-origin");
            origin.send_to(&reply, from).await.unwrap();
        });

        // The ParallaX QUIC listener socket and a client socket.
        let listen = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let listen_addr = listen.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // Client sends its first datagram to the listener; the driver would read it,
        // classify it as splice-bound, and open a relay with it as `first`.
        client.send_to(b"hello", listen_addr).await.unwrap();
        let mut b = vec![0u8; MAX_RELAY_PAYLOAD];
        let (n, peer) = listen.recv_from(&mut b).await.unwrap();
        assert_eq!(peer, client_addr);
        let flow = SpliceFlow::open(listen.clone(), peer, origin_addr, &b[..n]).unwrap();

        // The origin's echo must arrive at the client, verbatim, from the listener.
        let mut rb = vec![0u8; MAX_RELAY_PAYLOAD];
        let (rn, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut rb))
            .await
            .expect("client receives origin reply in time")
            .unwrap();
        assert_eq!(
            from, listen_addr,
            "reply must come from the listener address"
        );
        assert_eq!(
            &rb[..rn],
            b"hello-origin",
            "both directions relayed verbatim"
        );

        // A subsequent client→origin datagram also forwards verbatim.
        let origin2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin2_addr = origin2.local_addr().unwrap();
        let flow2 = SpliceFlow::open(listen.clone(), client_addr, origin2_addr, b"d0").unwrap();
        flow2.forward(b"d1").unwrap();
        let mut ob = vec![0u8; MAX_RELAY_PAYLOAD];
        let (on, _) = origin2.recv_from(&mut ob).await.unwrap();
        assert_eq!(&ob[..on], b"d0", "first datagram forwarded verbatim");
        let (on2, _) = tokio::time::timeout(Duration::from_secs(5), origin2.recv_from(&mut ob))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ob[..on2], b"d1", "subsequent datagram forwarded verbatim");

        drop(flow);
        drop(flow2);
    }

    /// An origin→client datagram larger than the endpoint's per-datagram recv cap
    /// (which used to size the pump buffer) must be relayed intact, not silently
    /// truncated: the client→origin forward imposes no relay-specific ceiling, so
    /// the pump must not either (finding #35).
    #[tokio::test]
    async fn pump_relays_origin_datagram_larger_than_recv_cap_intact() {
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let listen = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let flow = SpliceFlow::open(listen.clone(), client_addr, origin_addr, b"first").unwrap();

        // Learn the relay's upstream address from the first forwarded datagram,
        // then reply with a patterned datagram well above the endpoint's default
        // recv cap (the old pump buffer size).
        let mut b = vec![0u8; MAX_RELAY_PAYLOAD];
        let (_, relay_addr) = origin.recv_from(&mut b).await.unwrap();
        let big: Vec<u8> = (0..2 * crate::config::DEFAULT_MAX_UDP_PAYLOAD_BYTES as usize)
            .map(|i| (i % 251) as u8)
            .collect();
        origin.send_to(&big, relay_addr).await.unwrap();

        let mut rb = vec![0u8; MAX_RELAY_PAYLOAD];
        let (rn, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut rb))
            .await
            .expect("client receives large origin datagram in time")
            .unwrap();
        assert_eq!(rn, big.len(), "origin datagram must not be truncated");
        assert_eq!(&rb[..rn], &big[..], "origin datagram relayed intact");
        drop(flow);
    }

    /// Dropping a flow aborts its pump (no leaked task / socket).
    #[tokio::test]
    async fn dropping_flow_ends_the_relay() {
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let listen = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let flow = SpliceFlow::open(listen, client, origin_addr, b"x").unwrap();
        let handle = flow.pump.abort_handle();
        drop(flow);
        // Give the runtime a tick to process the abort.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(handle.is_finished(), "pump task aborted on drop");
    }
}
