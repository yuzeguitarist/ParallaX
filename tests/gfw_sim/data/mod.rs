//! Reference data for the GFW simulator.
//!
//! These tables aggregate publicly-documented censor knobs: ASCII printability lookups
//! used by the USENIX'23 first-packet heuristic, the SNI / domain keyword blocklists that
//! the Tiangou Secure Gateway (TSG) is known to ship, the protocol fingerprint signatures
//! used to exempt benign traffic, and the JA3 / JA4 hashes that map to real browser builds.
//!
//! The values are *publicly* derived (from the USENIX 2023 paper, the GFW Report dataset,
//! the FoxIO JA4 reference implementation, and the 2025 InterSecLab analysis of the
//! Geedge / MESA leak). Nothing here comes from the leak itself; consumers of this module
//! are expected to treat the data as approximations to what the real GFW would see.

pub mod ascii_tables;
pub mod observed_protocols;
pub mod sni_blocklist;
pub mod tls_fingerprints;
