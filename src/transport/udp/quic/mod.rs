//! Hand-written, quinn-free QUIC transport stack (Phase 2 of de-vendoring).
//!
//! Built clean-room from RFC 9000 (transport), RFC 9001 (TLS), and RFC 9002
//! (loss/recovery) to replace `quinn` + `quinn-proto` (and the vendored
//! `quinn-proto` fork) on the production UDP fast plane. The TLS 1.3 engine that
//! drives the handshake already exists, transport-agnostic, in
//! [`crate::tls::quic`]; this stack owns everything below it: the packet/frame
//! wire format, packet-number spaces, header protection, the connection state
//! machine, loss recovery + BBR, and the async endpoint/stream façade.
//!
//! ## Scope (ParallaX's actual needs, not all of RFC 9000)
//!
//! QUIC v1 only. No 0-RTT/early-data, no DATAGRAM frames, no connection
//! migration / path validation (the client uses a zero-length source connection
//! id, so it is routed by UDP 4-tuple only), no Retry issuance, no active CID
//! rotation. The relay rides one reliable bidi stream (HTTP/3 DATA frames) plus
//! the H3 control/encoder uni streams.
//!
//! ## Staged, inert landing
//!
//! Each module lands with its own RFC KAT / round-trip tests and is NOT yet wired
//! into the live carrier (which keeps running on `quinn` until the cutover PR).
//! The crate-level `#![allow(dead_code)]` below records that not-yet-referenced
//! status; it is removed module-by-module as the wiring lands.

#![allow(dead_code)]

pub(crate) mod transport_params;
pub(crate) mod varint;
