//! Statistical distinguisher battery — test-support library.
//!
//! Turns "I believe ParallaX looks like Safari" into "I have numbers that prove
//! it does (or does not)". The battery compares two corpora — the real Safari-26
//! capture (ground truth) and ParallaX's own output, in the same units — with
//! three independent two-sample distinguishers:
//!
//! * Kolmogorov–Smirnov on marginal distributions (record length, IAT),
//! * Pearson chi-squared on categorical features (direction runs, buckets),
//! * Ljung–Box on serial autocorrelation,
//!
//! plus a cross-validated logistic-regression classifier whose held-out ROC AUC
//! is the headline indistinguishability metric.
//!
//! Acceptance (indistinguishable): two-sample `KS p > 0.05` AND classifier
//! `AUC ∈ [0.45, 0.55]`. Discriminability self-proof: injecting a known
//! perturbation (e.g. the 1:1-ACK pathology) must drive `KS p → 0` and
//! `AUC → 1`, demonstrating the battery actually fires.
//!
//! Layout mirrors `tests/gfw_sim/`: a `mod`-included support tree driven by the
//! `tests/distinguisher_battery.rs` integration test. Items are `pub` and may be
//! dead from any single scenario's view; we silence that at the root.

#![allow(dead_code)]

pub mod classifier;
pub mod features;
pub mod parallax_source;
pub mod perturb;
pub mod safari_h3_source;
pub mod safari_quic_source;
pub mod safari_source;
pub mod stats;
pub mod trace;
pub mod udp_capture;
pub mod udp_tsv;
