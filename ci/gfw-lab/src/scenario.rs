//! Traffic scenario definitions shared by the generator and orchestrator.
//!
//! Each scenario is driven by `trafficgen` through the ParallaX client's SOCKS5
//! port, so the bytes traverse the full path:
//!   trafficgen -> (SOCKS5) -> plx client -> GFW box -> plx server -> origin

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioKind {
    /// Bulk single-stream download (server -> client).
    Download,
    /// Bulk single-stream upload (client -> server).
    Upload,
    /// Simultaneous bulk up + down on one stream.
    Bidirectional,
    /// Many short sequential request/response exchanges on reused connections.
    Serial,
    /// Many concurrent streams each doing a medium transfer.
    Parallel,
    /// A single long-lived stream (interactivity/large object).
    SingleStream,
    /// Streaming-video shape: sustained downlink bitrate with periodic bursts.
    Video,
    /// VoIP/call shape: small bidirectional frames at a fixed cadence.
    Call,
    /// Web-page shape: one burst of parallel small/medium objects.
    Web,
}

impl ScenarioKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScenarioKind::Download => "download",
            ScenarioKind::Upload => "upload",
            ScenarioKind::Bidirectional => "bidirectional",
            ScenarioKind::Serial => "serial",
            ScenarioKind::Parallel => "parallel",
            ScenarioKind::SingleStream => "single-stream",
            ScenarioKind::Video => "video",
            ScenarioKind::Call => "call",
            ScenarioKind::Web => "web",
        }
    }

    pub fn parse(s: &str) -> Option<ScenarioKind> {
        Some(match s {
            "download" => ScenarioKind::Download,
            "upload" => ScenarioKind::Upload,
            "bidirectional" | "bidir" => ScenarioKind::Bidirectional,
            "serial" => ScenarioKind::Serial,
            "parallel" => ScenarioKind::Parallel,
            "single-stream" | "single" => ScenarioKind::SingleStream,
            "video" => ScenarioKind::Video,
            "call" => ScenarioKind::Call,
            "web" => ScenarioKind::Web,
            _ => return None,
        })
    }

    pub fn all() -> &'static [ScenarioKind] {
        &[
            ScenarioKind::Download,
            ScenarioKind::Upload,
            ScenarioKind::Bidirectional,
            ScenarioKind::Serial,
            ScenarioKind::Parallel,
            ScenarioKind::SingleStream,
            ScenarioKind::Video,
            ScenarioKind::Call,
            ScenarioKind::Web,
        ]
    }
}

/// Fully parameterised scenario. `trafficgen` interprets these fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub kind: ScenarioKind,
    /// Total bytes for bulk transfers (download/upload/bidir/single-stream).
    pub bytes: u64,
    /// Concurrency for parallel/web scenarios; per-object size via `bytes`.
    pub concurrency: usize,
    /// Number of iterations for serial/call scenarios.
    pub iterations: usize,
    /// Per-frame payload size for call/video (bytes).
    pub frame_bytes: usize,
    /// Cadence between frames/iterations in milliseconds (call/video).
    pub interval_ms: u64,
    /// Target downlink bitrate in kbit/s for video pacing (origin-side).
    pub video_kbps: u32,
}

impl Scenario {
    /// Reasonable defaults per scenario for a fast-but-representative CI run.
    pub fn default_for(kind: ScenarioKind) -> Scenario {
        match kind {
            ScenarioKind::Download => Scenario {
                kind,
                bytes: 8 * 1024 * 1024,
                concurrency: 1,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
            ScenarioKind::Upload => Scenario {
                kind,
                bytes: 4 * 1024 * 1024,
                concurrency: 1,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
            ScenarioKind::Bidirectional => Scenario {
                kind,
                bytes: 4 * 1024 * 1024,
                concurrency: 1,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
            ScenarioKind::Serial => Scenario {
                kind,
                bytes: 16 * 1024,
                concurrency: 1,
                iterations: 50,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
            ScenarioKind::Parallel => Scenario {
                kind,
                bytes: 1024 * 1024,
                concurrency: 8,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
            ScenarioKind::SingleStream => Scenario {
                kind,
                bytes: 16 * 1024 * 1024,
                concurrency: 1,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
            ScenarioKind::Video => Scenario {
                kind,
                bytes: 0,
                concurrency: 1,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 250,
                // ~5 Mbit/s stream for ~6 seconds of play-out.
                video_kbps: 5000,
            },
            ScenarioKind::Call => Scenario {
                kind,
                bytes: 0,
                concurrency: 1,
                iterations: 150,
                // ~160-byte frames every 20ms ≈ a 64 kbit/s codec, 3 seconds.
                frame_bytes: 160,
                interval_ms: 20,
                video_kbps: 0,
            },
            ScenarioKind::Web => Scenario {
                kind,
                bytes: 64 * 1024,
                concurrency: 12,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
        }
    }
}
