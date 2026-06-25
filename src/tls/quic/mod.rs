//! Hand-written, transport-agnostic TLS 1.3 client engine for QUIC (RFC 9001).
//!
//! This is ParallaX's own TLS 1.3 client state machine. It owns the visible QUIC
//! handshake wire image (a byte-faithful Safari-26 H3 ClientHello) and the full
//! QUIC key schedule, with **no dependency on rustls and no dependency on quinn**.
//! The crate's hand-written QUIC transport ([`crate::transport::udp::quic`])
//! drives it directly through the transport-neutral API exported here.
//!
//! ## Why transport-agnostic
//!
//! The de-vendoring north star was two-phase, both now landed: Phase 1 (this
//! engine) removed the vendored rustls fork from the production QUIC client path;
//! Phase 2 removed quinn itself in favour of the hand-written QUIC transport. The
//! engine exposes a transport-neutral API ([`ClientHandshake`], [`Keys`],
//! [`PacketKey`], [`HeaderProtectionKey`], the RFC 5705 exporter, retry
//! validation) and never names a quinn or rustls type, so the transport binds to
//! it with no adapter shim.
//!
//! ## What it does / does not verify
//!
//! The production QUIC leg is REALITY-style: trust derives from the
//! exporter-bound auth token, not the certificate (see
//! [`crate::transport::udp::auth`]). The engine therefore takes a pluggable
//! [`ServerCertVerifier`]; production injects [`AcceptAnyServerCert`]. Regardless
//! of the verifier, the engine ALWAYS parses Certificate/CertificateVerify into
//! the transcript and ALWAYS verifies the server Finished MAC — those are
//! intrinsic to TLS 1.3 correctness, not policy.

mod client_hello;
mod keys;
mod schedule;
mod server;
mod suite;
mod ticket;
mod verify;

pub use keys::{DirectionalKeys, HeaderProtectionKey, KeyPair, Keys, PacketKey};
pub use suite::CipherSuite;
pub use verify::{AcceptAnyServerCert, CertVerifyError, ServerCertVerifier};

use std::sync::Arc;

use thiserror::Error;

/// QUIC v1 (RFC 9000). The only version this engine speaks; drafts and v2 are
/// rejected at [`ClientHandshake::new`].
pub const QUIC_VERSION_V1: u32 = 0x0000_0001;

/// Endpoint role, used to pick the Initial-secret label and the local/remote
/// direction. The client engine always runs as [`Side::Client`]; [`Side::Server`]
/// exists so [`ClientHandshake::initial_keys`] can derive both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

// --- TLS alert codes (RFC 8446 §6) used to tag fatal handshake failures --------
//
// The adapter maps `QuicTlsError::Alert(code, _)` onto a QUIC CRYPTO_ERROR
// (0x0100 | code); anything else becomes PROTOCOL_VIOLATION.
pub(crate) const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
pub(crate) const ALERT_BAD_RECORD_MAC: u8 = 20;
pub(crate) const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub(crate) const ALERT_BAD_CERTIFICATE: u8 = 42;
pub(crate) const ALERT_ILLEGAL_PARAMETER: u8 = 47;
pub(crate) const ALERT_DECODE_ERROR: u8 = 50;
pub(crate) const ALERT_DECRYPT_ERROR: u8 = 51;
pub(crate) const ALERT_MISSING_EXTENSION: u8 = 109;
pub(crate) const ALERT_UNSUPPORTED_EXTENSION: u8 = 110;
pub(crate) const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

/// Errors surfaced by the hand-written TLS engine.
///
/// [`QuicTlsError::Alert`] carries the TLS alert description the peer should see;
/// the quinn adapter turns it into a QUIC `CRYPTO_ERROR`. The remaining variants
/// map to `PROTOCOL_VIOLATION` (or the `ConnectError` cases at `start_session`).
#[derive(Debug, Error)]
pub enum QuicTlsError {
    /// A fatal TLS alert (`description`) with a human-readable reason.
    #[error("TLS alert {description}: {reason}")]
    Alert { description: u8, reason: String },
    /// Local crypto operation (HKDF/AEAD/KEM) failed.
    #[error("TLS crypto failure: {0}")]
    Crypto(String),
    /// A QUIC-layer protocol violation (RFC 9000 §11): maps to PROTOCOL_VIOLATION.
    #[error("QUIC protocol violation: {0}")]
    Protocol(String),
    /// Certificate or CertificateVerify rejected by the verifier.
    #[error("certificate verification failed: {0}")]
    Certificate(String),
    /// Unsupported QUIC version (engine speaks v1 only).
    #[error("unsupported QUIC version")]
    UnsupportedVersion,
    /// Malformed SNI handed to [`ClientHandshake::new`].
    #[error("invalid server name: {0}")]
    InvalidServerName(String),
}

impl QuicTlsError {
    pub(crate) fn alert(description: u8, reason: impl Into<String>) -> Self {
        Self::Alert {
            description,
            reason: reason.into(),
        }
    }

    /// The TLS alert description to surface to the peer, if this failure has one.
    pub fn alert_description(&self) -> Option<u8> {
        match self {
            Self::Alert { description, .. } => Some(*description),
            _ => None,
        }
    }
}

/// Immutable configuration shared across handshakes from one client endpoint.
///
/// Rustls-free analogue of the old `rustls::ClientConfig` the QUIC carrier used.
/// The Safari-26 ClientHello shape, the pinned post-quantum-hybrid key exchange,
/// and TLS-1.3-only are all hard-coded by the engine (they are camouflage
/// invariants, not knobs); only the cert verifier and ALPN are configurable.
#[derive(Clone)]
pub struct ClientConfig {
    /// Offered ALPN protocols, in preference order. The QUIC carrier uses `[b"h3"]`.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Server-certificate trust policy. Production uses [`AcceptAnyServerCert`].
    pub verifier: Arc<dyn ServerCertVerifier>,
    /// When `Some`, the client hides a covert authentication marker in its
    /// `ClientHello.random` (see [`crate::crypto::quic_marker`]) so the server's
    /// datagram-zero fork can recognise a real ParallaX client on the first Initial
    /// and terminate locally, while everything else is spliced to the origin. `None`
    /// (the default) emits a pure-random `ClientHello.random`, the cold-start shape.
    pub marker: Option<QuicMarkerConfig>,
}

/// Client-side material for the QUIC `ClientHello.random` authentication marker:
/// the deployment PSK and the server's static X25519 public key (the same
/// REALITY-style relationship the TCP plane uses). With these plus the client's
/// per-connection ephemeral X25519 share, the client derives the marker the server
/// verifies with its static private key + the same PSK.
#[derive(Clone)]
pub struct QuicMarkerConfig {
    pub psk: zeroize::Zeroizing<Vec<u8>>,
    pub server_static_public: [u8; 32],
}

impl ClientConfig {
    /// Build a config with the given verifier and ALPN list (no marker).
    pub fn new(verifier: Arc<dyn ServerCertVerifier>, alpn_protocols: Vec<Vec<u8>>) -> Self {
        Self {
            alpn_protocols,
            verifier,
            marker: None,
        }
    }

    /// Enable the covert ClientHello.random authentication marker.
    pub fn with_marker(mut self, marker: QuicMarkerConfig) -> Self {
        self.marker = Some(marker);
        self
    }
}

pub use handshake::{ClientHandshake, KeyChange};

mod handshake;

pub(crate) use schedule::initial_keys;
pub(crate) use server::ServerHandshake;
pub(crate) use ticket::derive_stek;
pub use ticket::ClientTicket;

/// Cross-connection 0-RTT anti-replay (single-use ticket; RFC 8446 §8). The server
/// consults it before accepting a resumed ticket's early data: `accept_ticket`
/// returns `true` to accept (the ticket is fresh and is now recorded as used) or
/// `false` to reject (a replay — the connection falls back to a full 1-RTT
/// handshake). The runtime backs it with the persistent replay cache; it MUST be
/// safe to call concurrently from many connections.
pub trait ZeroRttGuard: Send + Sync {
    /// `ticket_identity` is the opaque `pre_shared_key` identity (the sealed
    /// ticket); `now_unix` is the current time in seconds.
    fn accept_ticket(&self, ticket_identity: &[u8], now_unix: u64) -> bool;
}

/// The TLS-session surface the hand-rolled QUIC connection drives. Both
/// [`ClientHandshake`] and [`ServerHandshake`] implement it, so the connection
/// state machine is role-generic over a `Box<dyn TlsSession>`. `Send` is required
/// so a connection can live in the async endpoint's driver task.
pub(crate) trait TlsSession: Send {
    /// Feed reassembled CRYPTO-stream bytes (a handshake-message stream).
    fn read_handshake(&mut self, data: &[u8]) -> Result<bool, QuicTlsError>;
    /// Emit outgoing CRYPTO bytes; return a [`KeyChange`] on a space transition.
    fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange>;
    /// The next 1-RTT packet-key generation (RFC 9001 §6 key update). Implemented +
    /// tested; the relay closes at the AEAD limit rather than rotating, so no
    /// production caller invokes it yet.
    #[allow(dead_code)]
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<PacketKey>>;
    fn is_handshaking(&self) -> bool;
    /// The peer's raw `quic_transport_parameters` blob, once available.
    fn peer_transport_parameters(&self) -> Option<&[u8]>;
    /// RFC 5705 exporter (byte-identical on both ends; backs the auth token).
    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), QuicTlsError>;
    /// Take a resumption ticket received via NewSessionTicket (client only; the
    /// server returns `None`). `now_ms` stamps the ticket-age epoch.
    fn take_session_ticket(&mut self, _now_ms: u64) -> Option<ClientTicket> {
        None
    }
    /// Install the cross-connection 0-RTT anti-replay guard (server only; the client
    /// default is a no-op).
    fn set_zero_rtt_guard(&mut self, _guard: Arc<dyn ZeroRttGuard>) {}
    /// Install the origin-splice auth-marker key (server only; client default no-op).
    /// `bound_dcid` is this connection's first-Initial Destination Connection ID; the
    /// marker MAC commits to it so a captured marker cannot be lifted onto another DCID.
    fn set_marker_key(
        &mut self,
        _psk: zeroize::Zeroizing<Vec<u8>>,
        _static_priv: zeroize::Zeroizing<[u8; 32]>,
        _bound_dcid: Vec<u8>,
    ) {
    }
    /// The auth marker recovered from this connection's ClientHello.random, if valid
    /// + fresh (server only; client default `None`).
    fn marker_result(&self) -> Option<crate::crypto::quic_marker::Marker> {
        None
    }
    /// Whether the ClientHello has been processed, so [`Self::marker_result`] is final
    /// (server only; client default `false`). Gates the endpoint's
    /// buffer-decide-then-route marker fork (the Safari CH spans two Initials).
    fn client_hello_processed(&self) -> bool {
        false
    }
}

impl TlsSession for ClientHandshake {
    fn read_handshake(&mut self, data: &[u8]) -> Result<bool, QuicTlsError> {
        ClientHandshake::read_handshake(self, data)
    }
    fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        ClientHandshake::write_handshake(self, out)
    }
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<PacketKey>> {
        ClientHandshake::next_1rtt_keys(self)
    }
    fn is_handshaking(&self) -> bool {
        ClientHandshake::is_handshaking(self)
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        ClientHandshake::peer_transport_parameters(self)
    }
    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), QuicTlsError> {
        ClientHandshake::export_keying_material(self, out, label, context)
    }
    fn take_session_ticket(&mut self, now_ms: u64) -> Option<ClientTicket> {
        ClientHandshake::take_session_ticket(self, now_ms)
    }
}

impl TlsSession for ServerHandshake {
    fn read_handshake(&mut self, data: &[u8]) -> Result<bool, QuicTlsError> {
        ServerHandshake::read_handshake(self, data)
    }
    fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        ServerHandshake::write_handshake(self, out)
    }
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<PacketKey>> {
        ServerHandshake::next_1rtt_keys(self)
    }
    fn is_handshaking(&self) -> bool {
        ServerHandshake::is_handshaking(self)
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        ServerHandshake::peer_transport_parameters(self)
    }
    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), QuicTlsError> {
        ServerHandshake::export_keying_material(self, out, label, context)
    }
    fn set_zero_rtt_guard(&mut self, guard: Arc<dyn ZeroRttGuard>) {
        ServerHandshake::set_zero_rtt_guard(self, guard)
    }
    fn set_marker_key(
        &mut self,
        psk: zeroize::Zeroizing<Vec<u8>>,
        static_priv: zeroize::Zeroizing<[u8; 32]>,
        bound_dcid: Vec<u8>,
    ) {
        ServerHandshake::set_marker_key(self, psk, static_priv, bound_dcid)
    }
    fn marker_result(&self) -> Option<crate::crypto::quic_marker::Marker> {
        ServerHandshake::marker_result(self)
    }
    fn client_hello_processed(&self) -> bool {
        ServerHandshake::client_hello_processed(self)
    }
}
