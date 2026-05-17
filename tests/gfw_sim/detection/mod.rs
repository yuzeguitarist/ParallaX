//! Detection layers of the GFW simulator.
//!
//! Each module models a single censor layer described in the public GFW research
//! corpus and reproduced in the 2025 Geedge / MESA leak analyses:
//!
//! | module | maps to                                              | source |
//! |---|---|---|
//! | [`sni_filter`]      | TLS 1.3 SNI keyword filter + dual middlebox  | gfw.report TLS 1.3 SNI study, 2019 |
//! | [`dns_inject`]      | DNS injection subsystem                       | Anonymous 2014, "Towards a Comprehensive Picture of GFW DNS" |
//! | [`fully_encrypted`] | USENIX'23 first-packet heuristic              | Wu et al. USENIX Security 2023 |
//! | [`tls_fingerprint`] | JA3 / JA4 rule matching (Maat regex / hashes) | InterSecLab Geedge analysis 2025; FoxIO JA4 spec |
//! | [`quic_initial`]    | QUIC Initial decryption + SNI extraction      | gfw.report 2024 QUIC SNI study; RFC 9001 |
//! | [`burst_statistics`]| chi-squared 3-gram + Mahalanobis bursts       | Xue et al. NDSS 2022, "Towards Fingerprinting Proxies" |
//! | [`active_prober`]   | Active-probing infrastructure                 | Fifield 2015; Alice 2020; Frolov 2020 |
//! | [`tcp_dual_mb`]     | Dual middlebox MB-RA + MB-R state machine     | Bock et al. CCS 2021, "Even Censors Have a Backup" |

pub mod active_prober;
pub mod burst_statistics;
pub mod dns_inject;
pub mod fully_encrypted;
pub mod quic_initial;
pub mod sni_filter;
pub mod tcp_dual_mb;
pub mod tls_fingerprint;
