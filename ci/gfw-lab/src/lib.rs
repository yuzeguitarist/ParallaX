//! Shared types and analysis primitives for the ParallaX end-to-end GFW lab.
//!
//! This crate is a **clean-room** test harness. Its censorship-detection
//! heuristics are implemented from public research on DPI / traffic analysis
//! (e.g. Frolov & Wustrow's "fully encrypted traffic" first-packet entropy
//! heuristic, USENIX Security 2023; JA3/JA4 TLS fingerprinting; packet
//! size/timing statistics), NOT from any third-party source code.
//!
//! The purpose is defensive: measure whether ParallaX's on-wire behaviour is
//! distinguishable from a genuine TLS-to-CDN session by a middle-box observer,
//! so the protocol can be hardened.

pub mod analyze;
pub mod link;
pub mod report;
pub mod scenario;
pub mod stats;
pub mod tls;

pub use link::LinkProfile;
pub use report::{
    ActiveProbeReport, ActiveProbeResult, FlowFeatures, FlowVerdict, LabReport, ScenarioOutcome,
};
pub use scenario::{Scenario, ScenarioKind};
