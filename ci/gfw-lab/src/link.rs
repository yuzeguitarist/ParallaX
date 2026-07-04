//! Link-quality profiles applied by the GFW box's software impairment engine.
//!
//! Impairment is applied in userspace inside the relay (no `tc`/`netem`/root
//! required, so it runs identically on any CI runner). On the reliable TCP
//! transport only latency, jitter and bandwidth are modelled (dropping or
//! reordering bytes on a byte stream would corrupt it); on the UDP/QUIC
//! datagram transport loss, duplication and reorder are additionally applied,
//! because that is exactly the impairment QUIC is designed to survive.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkProfile {
    pub name: String,
    /// One-way added latency in milliseconds (applied per direction).
    pub latency_ms: u32,
    /// Uniform +/- jitter in milliseconds added on top of `latency_ms`.
    pub jitter_ms: u32,
    /// Bandwidth cap per direction in kilobits/sec (0 = unlimited).
    pub bandwidth_kbps: u32,
    /// Datagram loss percentage (UDP/QUIC path only).
    pub loss_pct: f64,
    /// Datagram duplication percentage (UDP/QUIC path only).
    pub dup_pct: f64,
    /// Datagram reorder percentage (UDP/QUIC path only): held back briefly.
    pub reorder_pct: f64,
}

impl LinkProfile {
    pub fn preset(name: &str) -> Option<LinkProfile> {
        let p = match name {
            // Effectively no impairment: a fast datacentre loopback.
            "perfect" => LinkProfile {
                name: "perfect".into(),
                latency_ms: 0,
                jitter_ms: 0,
                bandwidth_kbps: 0,
                loss_pct: 0.0,
                dup_pct: 0.0,
                reorder_pct: 0.0,
            },
            // Home broadband: ~40ms RTT, 100 Mbit.
            "broadband" => LinkProfile {
                name: "broadband".into(),
                latency_ms: 20,
                jitter_ms: 2,
                bandwidth_kbps: 100_000,
                loss_pct: 0.0,
                dup_pct: 0.0,
                reorder_pct: 0.0,
            },
            // Good 4G/LTE: ~60ms RTT, 30 Mbit, some jitter + slight loss.
            "mobile_4g" => LinkProfile {
                name: "mobile_4g".into(),
                latency_ms: 30,
                jitter_ms: 8,
                bandwidth_kbps: 30_000,
                loss_pct: 0.2,
                dup_pct: 0.0,
                reorder_pct: 0.5,
            },
            // Congested 3G: ~300ms RTT, 3 Mbit, high jitter + loss.
            "mobile_3g" => LinkProfile {
                name: "mobile_3g".into(),
                latency_ms: 150,
                jitter_ms: 40,
                bandwidth_kbps: 3_000,
                loss_pct: 1.0,
                dup_pct: 0.1,
                reorder_pct: 1.0,
            },
            // Trans-pacific fibre (the China->overseas scenario): ~360ms RTT.
            "transpacific" => LinkProfile {
                name: "transpacific".into(),
                latency_ms: 180,
                jitter_ms: 20,
                bandwidth_kbps: 50_000,
                loss_pct: 0.3,
                dup_pct: 0.0,
                reorder_pct: 0.8,
            },
            // Deliberately hostile lossy link to stress QUIC recovery.
            "lossy" => LinkProfile {
                name: "lossy".into(),
                latency_ms: 100,
                jitter_ms: 30,
                bandwidth_kbps: 10_000,
                loss_pct: 5.0,
                dup_pct: 1.0,
                reorder_pct: 3.0,
            },
            // Geostationary satellite: very high latency, modest bandwidth.
            "satellite" => LinkProfile {
                name: "satellite".into(),
                latency_ms: 600,
                jitter_ms: 30,
                bandwidth_kbps: 10_000,
                loss_pct: 0.5,
                dup_pct: 0.0,
                reorder_pct: 0.5,
            },
            _ => return None,
        };
        Some(p)
    }

    pub fn preset_names() -> &'static [&'static str] {
        &[
            "perfect",
            "broadband",
            "mobile_4g",
            "mobile_3g",
            "transpacific",
            "lossy",
            "satellite",
        ]
    }

    /// One-way delay in milliseconds for the next chunk/datagram, including a
    /// uniformly sampled jitter component.
    pub fn sample_delay_ms(&self, rng: &mut impl rand::Rng) -> u32 {
        if self.jitter_ms == 0 {
            return self.latency_ms;
        }
        let j = self.jitter_ms as i64;
        let delta = rng.gen_range(-j..=j);
        (self.latency_ms as i64 + delta).max(0) as u32
    }
}
