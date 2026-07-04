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
    /// Bulk single-stream upload of a large object (client -> server).
    LargeUpload,
    /// HD streaming-video shape: like `Video` but at a higher bitrate.
    VideoHd,
    /// Heavy web-page shape: a larger burst of parallel small objects.
    WebHeavy,
    /// Messaging shape: sporadic small echoes with randomized idle gaps.
    Chat,
    /// On/off browsing shape: medium downloads separated by idle gaps.
    Burst,
    /// API-polling shape: tiny requests at a fixed cadence.
    ApiPoll,
    /// Multitask shape: concurrent video downlink + VoIP call on two tunnels.
    Mixed,
    /// Ramp shape: sequential downloads of increasing size on one tunnel.
    DownloadRamp,
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
            ScenarioKind::LargeUpload => "large-upload",
            ScenarioKind::VideoHd => "video-hd",
            ScenarioKind::WebHeavy => "web-heavy",
            ScenarioKind::Chat => "chat",
            ScenarioKind::Burst => "burst",
            ScenarioKind::ApiPoll => "api-poll",
            ScenarioKind::Mixed => "mixed",
            ScenarioKind::DownloadRamp => "download-ramp",
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
            "large-upload" => ScenarioKind::LargeUpload,
            "video-hd" => ScenarioKind::VideoHd,
            "web-heavy" => ScenarioKind::WebHeavy,
            "chat" => ScenarioKind::Chat,
            "burst" => ScenarioKind::Burst,
            "api-poll" => ScenarioKind::ApiPoll,
            "mixed" => ScenarioKind::Mixed,
            "download-ramp" => ScenarioKind::DownloadRamp,
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
            ScenarioKind::LargeUpload,
            ScenarioKind::VideoHd,
            ScenarioKind::WebHeavy,
            ScenarioKind::Chat,
            ScenarioKind::Burst,
            ScenarioKind::ApiPoll,
            ScenarioKind::Mixed,
            ScenarioKind::DownloadRamp,
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
            ScenarioKind::LargeUpload => Scenario {
                kind,
                bytes: 32 * 1024 * 1024,
                concurrency: 1,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
            ScenarioKind::VideoHd => Scenario {
                kind,
                bytes: 0,
                concurrency: 1,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 250,
                // ~15 Mbit/s HD stream for ~6 seconds of play-out.
                video_kbps: 15000,
            },
            ScenarioKind::WebHeavy => Scenario {
                kind,
                bytes: 48 * 1024,
                concurrency: 24,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
            ScenarioKind::Chat => Scenario {
                kind,
                bytes: 0,
                // 40 messages of 96 B with randomized idle gaps drawn from
                // [interval_ms/4 .. interval_ms*3] (sporadic, human-chat-like).
                concurrency: 1,
                iterations: 40,
                frame_bytes: 96,
                interval_ms: 800,
                video_kbps: 0,
            },
            ScenarioKind::Burst => Scenario {
                kind,
                // 8 on/off cycles: 512 KiB download then 500ms idle.
                bytes: 512 * 1024,
                concurrency: 1,
                iterations: 8,
                frame_bytes: 0,
                interval_ms: 500,
                video_kbps: 0,
            },
            ScenarioKind::ApiPoll => Scenario {
                kind,
                bytes: 0,
                concurrency: 1,
                // 60 pings at a fixed 500ms period (~30s of polling).
                iterations: 60,
                frame_bytes: 0,
                interval_ms: 500,
                video_kbps: 0,
            },
            ScenarioKind::Mixed => Scenario {
                kind,
                bytes: 0,
                concurrency: 1,
                // Call leg: 150 frames x 160 B @ 20ms; video leg: ~4 Mbit/s
                // for ~6 seconds of play-out, on separate tunnels.
                iterations: 150,
                frame_bytes: 160,
                interval_ms: 20,
                video_kbps: 4000,
            },
            ScenarioKind::DownloadRamp => Scenario {
                kind,
                // Sizes are fixed in trafficgen: 64 KiB, 256 KiB, 1 MiB, 4 MiB.
                bytes: 0,
                concurrency: 1,
                iterations: 1,
                frame_bytes: 0,
                interval_ms: 0,
                video_kbps: 0,
            },
        }
    }
}
