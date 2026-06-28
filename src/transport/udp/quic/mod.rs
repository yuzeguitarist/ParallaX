//! Hand-written, quinn-free QUIC transport stack (Phase 2 of de-vendoring).
//!
//! Built clean-room from RFC 9000 (transport), RFC 9001 (TLS), and RFC 9002
//! (loss/recovery). It is the live production carrier for the UDP fast plane; the
//! `quinn` + `quinn-proto` (and the vendored `quinn-proto` fork) it replaced are
//! gone from the dependency tree. The TLS 1.3 engine that drives the handshake
//! lives, transport-agnostic, in [`crate::tls::quic`]; this stack owns everything
//! below it: the packet/frame wire format, packet-number spaces, header
//! protection, the connection state machine, loss recovery + BBR, and the async
//! endpoint/stream façade.
//!
//! ## Scope (ParallaX's actual needs, not all of RFC 9000)
//!
//! QUIC v1 only. 0-RTT resumption (early data) is supported; no DATAGRAM frames,
//! no connection migration / path validation (the client uses a zero-length
//! source connection id, so it is routed by UDP 4-tuple only), no Retry issuance,
//! no active CID rotation. The relay rides one reliable bidi stream (HTTP/3 DATA
//! frames) plus the H3 control/encoder uni streams.

pub(crate) mod congestion;
pub(crate) mod conn;
pub(crate) mod endpoint;
pub(crate) mod frame;
/// Per-substream codec derivation for mux-over-QUIC (native QUIC multiplexing of
/// the multi-stream relay path).
pub(crate) mod mux;
/// Deterministic loss/reorder network simulator + transport invariants (test-only,
/// issue #76). Drives two sans-IO `Connection`s over a virtual link.
#[cfg(test)]
mod netsim;
pub(crate) mod pacer;
pub(crate) mod packet;
pub(crate) mod recovery;
pub(crate) mod spaces;
/// Verbatim UDP relay to the camouflage origin (the QUIC analogue of the TCP
/// REALITY fallback splice). Probe / non-authenticated flows reach the true origin.
pub(crate) mod splice;
pub(crate) mod transport_params;
pub(crate) mod varint;
