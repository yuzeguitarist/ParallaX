//! Deterministic loss/reorder network simulator + invariant checks for the
//! hand-rolled QUIC stack (issue #76). **Test-only**: this whole module is behind
//! `#[cfg(test)]`, adds no production dependency, and changes no wire behaviour.
//!
//! After the de-quinn cutover ParallaX owns the QUIC transport state machine, so it
//! needs adversarial regression coverage beyond happy-path loopback. The core
//! `Connection` is sans-IO with an injected `now: Instant` (the only wall-clock read
//! lives in the async `endpoint` driver), so this harness drives two `Connection`s
//! directly over a virtual link — no sockets, no tokio, no `Instant::now()` inside
//! the pump — and scripts packet loss, reordering, duplication, and delay against a
//! seeded RNG. The network model (which datagrams drop/reorder/duplicate and when)
//! is fully determined by `(seed, policy)`, so a failure reproduces from those alone.
//! (The cover-certificate signing key is the one fresh-per-process input; it is
//! behaviourally inert — see `server_key` — so it never affects a reproduction.)
//!
//! ## Oracle (internal, by design)
//!
//! The repo is deliberately quinn-free (no external QUIC impl to differential-test
//! against), so the oracle is internal:
//!
//! 1. **Convergence (differential)** — under any impairment the simulator can
//!    recover from, BOTH endpoints must deliver the exact same application bytes
//!    that were sent (`read_stream`), i.e. a lossy run is behaviourally equivalent
//!    to the lossless run for delivered data. This is the headline correctness oracle.
//! 2. **Transport invariants** — the pure packet-number/recovery modules are the
//!    reference: send-side packet numbers are monotonic and never reused
//!    (`PacketNumberSpace::allocate` asserts this on every send the pump drives), the
//!    receive set rejects duplicates/replays (`ReceivedPackets::insert`), and an ACK
//!    of an un-sent packet is refused (`recv_ack`). Since the AEAD nonce is a pure
//!    function of `(iv, packet_number)` per space+direction (RFC 9001 §5.3), "no
//!    nonce reuse within a key phase" reduces to "no packet-number reuse", which the
//!    allocator guarantees.

use std::collections::BinaryHeap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::conn::Connection;
use super::packet::ConnectionId;
use super::spaces::{PacketNumberSpace, ReceivedPackets};
use crate::tls::quic::{AcceptAnyServerCert, ClientConfig};

const RELAY_STREAM_ID: u64 = 0;

/// Which endpoint a datagram is travelling toward.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum To {
    Client,
    Server,
}

/// A datagram in flight on the virtual link, ordered by delivery time. Ties break on
/// a monotonic sequence number so the heap is a total order (determinism: no two
/// in-flight datagrams ever compare equal).
struct InFlight {
    deliver_at: Instant,
    seq: u64,
    to: To,
    bytes: Vec<u8>,
}

impl PartialEq for InFlight {
    fn eq(&self, other: &Self) -> bool {
        self.deliver_at == other.deliver_at && self.seq == other.seq
    }
}
impl Eq for InFlight {}
impl Ord for InFlight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse so the BinaryHeap (a max-heap) pops the EARLIEST delivery first.
        other
            .deliver_at
            .cmp(&self.deliver_at)
            .then(other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for InFlight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Seeded impairment policy. All probabilities are in `[0.0, 1.0]`.
#[derive(Clone, Copy)]
struct Policy {
    /// Per-datagram drop probability.
    loss: f64,
    /// Per-datagram duplication probability (the duplicate is also subject to delay).
    dup: f64,
    /// Extra per-datagram delay drawn uniformly from `[0, jitter]` on top of the base
    /// one-way delay; combined with the base delay this also reorders datagrams.
    jitter: Duration,
}

impl Policy {
    fn lossless() -> Self {
        Self {
            loss: 0.0,
            dup: 0.0,
            jitter: Duration::ZERO,
        }
    }
}

/// A deterministic in-memory link between a client and server `Connection`. Owns a
/// virtual clock and a seeded RNG; advancing it pumps `poll_transmit` →
/// (seeded loss/dup/jitter) → `handle_datagram`, firing `handle_timeout` at each
/// connection's next deadline so loss recovery / PTO progress without real time.
struct Link {
    client: Connection,
    server: Connection,
    clock: Instant,
    rng: StdRng,
    policy: Policy,
    /// Base one-way delay applied to every (non-dropped) datagram.
    base_delay: Duration,
    queue: BinaryHeap<InFlight>,
    seq: u64,
    /// Total datagrams dropped (for `log`-style assertions: a scenario that intends
    /// loss should actually have dropped something).
    dropped: u64,
}

impl Link {
    fn with_dcid(seed: u64, policy: Policy, dcid: ConnectionId) -> Self {
        let client = Connection::new_client(client_config(), "example.com", dcid, scid())
            .expect("client ctor");
        let server = Connection::new_server(
            cover_cert(),
            &server_key(),
            vec![b"h3".to_vec()],
            server_tp(),
            ConnectionId::new(&[0x5e, 0x52, 0x00, (seed & 0xff) as u8]),
        )
        .expect("server ctor");
        Self {
            client,
            server,
            clock: Instant::now(),
            rng: StdRng::seed_from_u64(seed),
            policy,
            base_delay: Duration::from_millis(5),
            queue: BinaryHeap::new(),
            seq: 0,
            dropped: 0,
        }
    }

    /// Drain a side's pending datagrams onto the link, applying the seeded policy.
    fn pump_out(&mut self, to: To) {
        loop {
            let dg = match to {
                To::Server => self.client.poll_transmit(self.clock),
                To::Client => self.server.poll_transmit(self.clock),
            };
            let Some(bytes) = dg else { break };
            self.enqueue(to, bytes, true);
        }
    }

    /// Schedule one datagram toward `to`, applying loss/dup/jitter when `impair`.
    fn enqueue(&mut self, to: To, bytes: Vec<u8>, impair: bool) {
        if impair && self.rng.gen_bool(self.policy.loss.clamp(0.0, 1.0)) {
            self.dropped += 1;
            return;
        }
        let extra = if impair && !self.policy.jitter.is_zero() {
            self.policy.jitter.mul_f64(self.rng.gen_range(0.0..1.0))
        } else {
            Duration::ZERO
        };
        let deliver_at = self.clock + self.base_delay + extra;
        self.seq += 1;
        let seq = self.seq;
        let dup = impair && self.rng.gen_bool(self.policy.dup.clamp(0.0, 1.0));
        self.queue.push(InFlight {
            deliver_at,
            seq,
            to,
            bytes: bytes.clone(),
        });
        if dup {
            self.seq += 1;
            let seq = self.seq;
            self.queue.push(InFlight {
                deliver_at,
                seq,
                to,
                bytes,
            });
        }
    }

    /// Deliver every datagram whose time has come, then let both sides react. Returns
    /// whether anything was delivered.
    fn deliver_due(&mut self) -> bool {
        let mut delivered = false;
        while let Some(top) = self.queue.peek() {
            if top.deliver_at > self.clock {
                break;
            }
            let item = self.queue.pop().expect("peeked");
            match item.to {
                To::Server => {
                    let _ = self.server.handle_datagram(&item.bytes, self.clock);
                }
                To::Client => {
                    let _ = self.client.handle_datagram(&item.bytes, self.clock);
                }
            }
            delivered = true;
        }
        delivered
    }

    /// The next event time: the earliest of a queued delivery and either endpoint's
    /// next timer deadline.
    fn next_event(&self) -> Option<Instant> {
        let mut t: Option<Instant> = self.queue.peek().map(|i| i.deliver_at);
        for c in [self.client.next_timeout(), self.server.next_timeout()]
            .into_iter()
            .flatten()
        {
            t = Some(t.map_or(c, |cur| cur.min(c)));
        }
        t
    }

    /// Fire any timers due at `clock` on both endpoints.
    fn fire_timers(&mut self) {
        if self.client.next_timeout().is_some_and(|d| d <= self.clock) {
            self.client.handle_timeout(self.clock);
        }
        if self.server.next_timeout().is_some_and(|d| d <= self.clock) {
            self.server.handle_timeout(self.clock);
        }
    }

    /// Run the event loop until both endpoints are quiescent (handshake done, nothing
    /// queued, no imminent timer) or `max_steps` is hit. Each step: pump both sides'
    /// output, deliver due datagrams, then advance the clock to the next event.
    fn run(&mut self, max_steps: usize) {
        for _ in 0..max_steps {
            self.pump_out(To::Server);
            self.pump_out(To::Client);
            self.deliver_due();
            self.fire_timers();
            // Re-pump: a delivered datagram or fired timer may have produced output.
            self.pump_out(To::Server);
            self.pump_out(To::Client);

            match self.next_event() {
                Some(t) if t > self.clock => self.clock = t,
                Some(_) => {
                    // An event is due now; loop again to drain it.
                    self.deliver_due();
                    self.fire_timers();
                }
                None => break, // nothing in flight and no armed timer: quiescent.
            }
        }
    }
}

// ---- deterministic fixtures (mirror the conn.rs test helpers) -------------------

fn seed_dcid(seed: u64) -> ConnectionId {
    ConnectionId::new(&seed.to_be_bytes())
}

fn scid() -> ConnectionId {
    ConnectionId::new(&[])
}

fn client_config() -> Arc<ClientConfig> {
    Arc::new(ClientConfig::new(
        Arc::new(AcceptAnyServerCert),
        vec![b"h3".to_vec()],
    ))
}

fn cover_cert() -> Vec<Vec<u8>> {
    vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]
}

/// The cover-certificate signing key, generated ONCE per process and shared by
/// every `Link`. The key only signs the server's CertificateVerify, which the
/// client accepts unconditionally (`AcceptAnyServerCert`); no assertion in this
/// module inspects the certificate or signature bytes, so the key is behaviourally
/// inert. Caching it (rather than minting one per `Link`) keeps a run's handshake
/// path identical across seeds, so the only varying input is the seeded
/// loss/reorder/dup/delay policy — which is what reproducibility from `(seed,
/// policy)` actually depends on. (aws-lc-rs `SecureRandom` is a sealed trait, so a
/// seeded key source is not available; this cache is the deterministic substitute.)
fn server_key() -> Vec<u8> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec()
    })
    .clone()
}

fn server_tp() -> Vec<u8> {
    super::transport_params::TransportParameters::safari_client(&[]).encode_safari_client()
}

// ---- scenarios ------------------------------------------------------------------

#[test]
fn handshake_completes_under_initial_and_handshake_loss() {
    // 20% per-datagram loss with reordering hits the Initial and Handshake flights;
    // PTO + retransmission must still drive both sides to a completed handshake.
    let mut link = Link::with_dcid(
        0x1457,
        Policy {
            loss: 0.20,
            dup: 0.05,
            jitter: Duration::from_millis(7),
        },
        seed_dcid(0x1457),
    );
    link.run(4000);
    assert!(
        !link.client.is_handshaking() && !link.server.is_handshaking(),
        "handshake completes despite Initial/Handshake-flight loss (dropped {} datagrams)",
        link.dropped
    );
    assert!(link.dropped > 0, "the scenario actually exercised loss");
}

#[test]
fn one_rtt_stream_survives_loss_reorder_and_duplication() {
    // Establish 1-RTT under loss, then transfer a multi-packet payload through the
    // same lossy/reordering/duplicating link. The differential oracle: the server
    // delivers exactly the bytes the client sent.
    let mut link = Link::with_dcid(
        0xD47A,
        Policy {
            loss: 0.15,
            dup: 0.10,
            jitter: Duration::from_millis(9),
        },
        seed_dcid(0xD47A),
    );
    link.run(4000);
    assert!(!link.client.is_handshaking() && !link.server.is_handshaking());

    let payload: Vec<u8> = (0..16_384u32).map(|i| (i % 251) as u8).collect();
    link.client.send_stream(RELAY_STREAM_ID, &payload);
    link.client.finish_stream(RELAY_STREAM_ID);
    link.run(8000);

    assert_eq!(
        link.server.read_stream(RELAY_STREAM_ID),
        payload,
        "the full stream is reassembled in order despite loss/reorder/dup (dropped {})",
        link.dropped
    );
}

#[test]
fn lossy_delivery_matches_lossless_delivery() {
    // Differential oracle: the SAME payload delivered over a lossless link and over a
    // lossy/reordering link must produce byte-identical received data on the server.
    fn transfer(seed: u64, policy: Policy) -> Vec<u8> {
        let mut link = Link::with_dcid(seed, policy, seed_dcid(seed));
        link.run(4000);
        assert!(!link.client.is_handshaking() && !link.server.is_handshaking());
        let payload: Vec<u8> = (0..12_000u32).map(|i| (i % 241) as u8).collect();
        link.client.send_stream(RELAY_STREAM_ID, &payload);
        link.client.finish_stream(RELAY_STREAM_ID);
        link.run(8000);
        link.server.read_stream(RELAY_STREAM_ID)
    }

    let clean = transfer(0xBEEF, Policy::lossless());
    let lossy = transfer(
        0xBEEF,
        Policy {
            loss: 0.18,
            dup: 0.07,
            jitter: Duration::from_millis(11),
        },
    );
    assert_eq!(
        clean, lossy,
        "loss/reorder is behaviourally transparent for delivered application bytes"
    );
    assert_eq!(
        clean.len(),
        12_000,
        "the lossless baseline delivered it all"
    );
}

#[test]
fn pto_recovers_a_tail_loss() {
    // A pure tail loss (the last data packet) is not ACK-detectable; only a PTO
    // probe recovers it. Drive a transfer where loss is concentrated, then confirm
    // the PTO-driven retransmission completes the stream.
    let mut link = Link::with_dcid(0x9701, Policy::lossless(), seed_dcid(0x9701));
    link.run(4000);
    assert!(!link.client.is_handshaking() && !link.server.is_handshaking());

    let payload: Vec<u8> = (0..6000u32).map(|i| (i % 239) as u8).collect();
    link.client.send_stream(RELAY_STREAM_ID, &payload);
    link.client.finish_stream(RELAY_STREAM_ID);

    // Pump the client's data out, dropping the LAST datagram (tail loss).
    let mut pkts = Vec::new();
    while let Some(dg) = link.client.poll_transmit(link.clock) {
        pkts.push(dg);
    }
    assert!(pkts.len() >= 3, "payload spans several packets");
    for dg in &pkts[..pkts.len() - 1] {
        let _ = link.server.handle_datagram(dg, link.clock);
    }
    // Let ACKs flow; the client cannot yet see the tail loss.
    link.run(50);
    // Advance well past the PTO and run to completion.
    link.clock += Duration::from_secs(2);
    link.fire_timers();
    link.run(4000);

    assert_eq!(
        link.server.read_stream(RELAY_STREAM_ID),
        payload,
        "the PTO probe retransmitted the tail and the stream completed"
    );
}

#[test]
fn reset_stream_survives_loss() {
    // RESET_STREAM under loss: the peer must eventually observe the reset (it is
    // retransmitted on loss like any ack-eliciting frame).
    let mut link = Link::with_dcid(
        0x5E7,
        Policy {
            loss: 0.20,
            dup: 0.0,
            jitter: Duration::from_millis(6),
        },
        seed_dcid(0x5E7),
    );
    link.run(4000);
    assert!(!link.client.is_handshaking() && !link.server.is_handshaking());

    // Open the relay stream with a little data, then reset it.
    link.client
        .send_stream(RELAY_STREAM_ID, b"partial body before reset");
    link.client.reset_stream(RELAY_STREAM_ID, 7);
    link.run(8000);

    assert_eq!(
        link.server.stream_reset(RELAY_STREAM_ID),
        Some(7),
        "the RESET_STREAM (code 7) reached the server despite loss (dropped {})",
        link.dropped
    );
}

#[test]
fn zero_rtt_early_data_survives_loss_and_reorder() {
    use zeroize::Zeroizing;

    // 1. Cold-start handshake (lossless) to obtain a resumption ticket. Both ends
    // share a STEK so the server can issue and later accept the ticket.
    let stek = Zeroizing::new([0x44u8; 32]);
    let mut link = Link::with_dcid(0x0317, Policy::lossless(), seed_dcid(0x0317));
    link.server = Connection::new_server_with_stek(
        cover_cert(),
        &server_key(),
        vec![b"h3".to_vec()],
        server_tp(),
        ConnectionId::new(&[0xab, 0xcd, 0xef, 0x01]),
        Some(stek.clone()),
    )
    .unwrap();
    link.run(4000);
    assert!(!link.client.is_handshaking() && !link.server.is_handshaking());
    let ticket = link
        .client
        .take_session_ticket(1_000_000)
        .expect("client received a resumption ticket");

    // 2. A resumption connection that sends early data, over a lossy/reordering link.
    let mut rlink = Link::with_dcid(
        0x0318,
        Policy {
            loss: 0.15,
            dup: 0.05,
            jitter: Duration::from_millis(8),
        },
        seed_dcid(0x0318),
    );
    rlink.client = Connection::new_client_resumption(
        client_config(),
        "example.com",
        seed_dcid(0x0318),
        scid(),
        &ticket,
        1_001_000,
    )
    .unwrap();
    rlink.server = Connection::new_server_with_stek(
        cover_cert(),
        &server_key(),
        vec![b"h3".to_vec()],
        server_tp(),
        ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]),
        Some(stek),
    )
    .unwrap();
    let early = b"GET /?0rtt resumed early data carried over a lossy link";
    rlink.client.send_stream(RELAY_STREAM_ID, early);
    rlink.client.finish_stream(RELAY_STREAM_ID);
    rlink.run(8000);

    assert!(!rlink.client.is_handshaking() && !rlink.server.is_handshaking());
    assert_eq!(
        rlink.server.read_stream(RELAY_STREAM_ID),
        early,
        "0-RTT early data is delivered intact despite loss/reorder (dropped {})",
        rlink.dropped
    );
}

// ---- transport invariants -------------------------------------------------------

#[test]
fn packet_number_space_never_reuses_a_number() {
    // The send-side allocator is strictly monotonic; `allocate` also asserts it
    // internally. Reusing a packet number would reuse the AEAD nonce within a key
    // phase (nonce = iv XOR pn), so this is the nonce-uniqueness invariant.
    let mut space = PacketNumberSpace::new();
    let mut last = None;
    for _ in 0..10_000 {
        let pn = space.allocate();
        if let Some(prev) = last {
            assert!(pn > prev, "packet numbers are strictly increasing");
        }
        last = Some(pn);
    }
    assert_eq!(space.peek(), 10_000, "peek reflects the next unused number");
}

#[test]
fn received_set_rejects_duplicates_and_replays() {
    // The receive set treats a re-presented packet number as a duplicate, so a
    // replayed/duplicated datagram is dropped without reprocessing.
    let mut recv = ReceivedPackets::new();
    assert!(recv.insert(0), "first sighting of pn 0 is new");
    assert!(!recv.insert(0), "a duplicate pn 0 is rejected");
    assert!(recv.insert(1));
    assert!(recv.insert(3), "a gap (reorder) is accepted");
    assert!(!recv.insert(1), "a duplicate of an earlier pn is rejected");
    assert!(recv.insert(2), "filling the gap is accepted once");
    assert!(!recv.insert(2), "and is then a duplicate");
    assert_eq!(recv.largest(), Some(3));
}

// Note: "ACK of an un-sent packet is rejected" is covered by `conn.rs`'s
// `ack_of_unsent_packet_is_rejected` (recv_ack has private visibility), so it is not
// duplicated here.
