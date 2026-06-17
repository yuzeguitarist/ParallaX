//! Detection layers of the GFW simulator.
//!
//! Each module models a single censor layer described in the public GFW research
//! corpus and reproduced in the 2025 Geedge / MESA leak analyses:
//!
//! - [`sni_filter`]: TLS 1.3 SNI keyword filter + dual middlebox;
//!   gfw.report TLS 1.3 SNI study, 2019.
//! - [`dns_inject`]: DNS injection subsystem;
//!   Anonymous 2014, "Towards a Comprehensive Picture of GFW DNS".
//! - [`http_host`]: HTTP Host / CONNECT keyword filter;
//!   Weaver 2009 and ongoing GFW HTTP keyword measurements.
//! - [`fully_encrypted`]: USENIX'23 first-packet heuristic;
//!   Wu et al. USENIX Security 2023.
//! - [`tls_fingerprint`]: JA3 / JA4 rule matching;
//!   InterSecLab Geedge analysis 2025 and FoxIO JA4 spec.
//! - [`quic_initial`]: QUIC Initial decryption + SNI extraction;
//!   gfw.report 2024 QUIC SNI study and RFC 9001.
//! - [`burst_statistics`]: chi-squared 3-gram + Mahalanobis bursts;
//!   Xue et al. NDSS 2022, "Towards Fingerprinting Proxies".
//! - [`cross_flow`]: cross-flow connection-topology correlation (one source ->
//!   many destinations near-simultaneously); guards multipath/fleet designs
//!   against fan-out tells the per-flow layers above are blind to.
//! - [`active_prober`]: active-probing infrastructure;
//!   Fifield 2015, Alice 2020, and Frolov 2020.
//! - [`tcp_dual_mb`]: dual middlebox MB-RA + MB-R state machine;
//!   Bock et al. CCS 2021, "Even Censors Have a Backup".

pub mod active_prober;
pub mod burst_statistics;
pub mod cross_flow;
pub mod dns_inject;
pub mod fully_encrypted;
pub mod http_host;
pub mod quic_initial;
pub mod sni_filter;
pub mod tcp_dual_mb;
pub mod tls_fingerprint;
