//! Source-level GFW (Great Firewall of China) simulator.
//!
//! Reproduces the GFW's detection / injection pipeline as closely as the public
//! research record allows. This is a *passive* simulator: it does not open
//! sockets, send forged packets, or interact with real networks; it only
//! consumes byte streams provided by red-team scenarios and produces per-layer
//! verdicts.
//!
//! The module layout follows the architecture of the leaked Geedge / MESA
//! analysis (InterSecLab, 2025) and the academic body of work surveying the
//! GFW: see `/home/ubuntu/parallax-gfw-analysis.md` and the per-module
//! docstrings for citations.
//!
//! Layout:
//! - [`data`] - reference tables (SNI blocklist, JA3/JA4 fingerprint DB,
//!   USENIX'23 ASCII tables, protocol-fingerprint registry)
//! - [`detection`] - per-layer detectors (SNI, DNS, USENIX'23, JA3/JA4,
//!   QUIC Initial, burst statistics, active prober, dual MB)
//! - [`injection`] - blocking actions (TCP RST, UDP drop, residual table)
//! - [`runtime`] - the full pipeline + scenario report
//!
//! The simulator is a *library* shared across red-team scenarios; many public
//! items are dead-code from the perspective of any single scenario but stay
//! `pub` so future scenarios can opt in. We silence the resulting dead-code /
//! unused-import noise at the module root rather than annotating each item.

#![allow(
    dead_code,
    unused_imports,
    clippy::module_inception,
    clippy::too_many_arguments
)]

pub mod data;
pub mod detection;
pub mod fixtures;
pub mod injection;
pub mod runtime;
