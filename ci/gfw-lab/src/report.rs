//! Report schema emitted by the GFW box and the orchestrator.

use serde::{Deserialize, Serialize};

use crate::stats::Summary;
use crate::tls::ClientHelloInfo;

/// Per-flow passive-analysis features + verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFeatures {
    pub flow_id: u64,
    pub client_addr: String,
    pub duration_ms: f64,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    /// Ratio bytes_s2c / bytes_c2s (download-heavy > 1).
    pub down_up_ratio: f64,
    pub segments_c2s: usize,
    pub segments_s2c: usize,
    /// Segment (relayed chunk) size stats, both directions.
    pub segment_size: Summary,
    /// Inter-arrival gaps (ms) between client->server segments.
    pub c2s_interarrival_ms: Summary,
    /// First-flight entropy / structure statistics.
    pub first_flight_len: usize,
    pub first_flight_bits_per_byte: f64,
    pub first_flight_popcount_per_byte: f64,
    pub first_flight_printable_fraction: f64,
    pub first_flight_longest_printable_run: usize,
    /// TLS ClientHello inspection of the first flight.
    pub client_hello: ClientHelloInfo,
    pub verdict: FlowVerdict,
}

/// The censor's decision for a flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowVerdict {
    /// Heuristic flags that fired (each is a potential distinguisher).
    pub flags: Vec<String>,
    /// True if a middle-box would classify this flow as a (non-TLS) proxy /
    /// fully-encrypted tunnel and therefore block/throttle it.
    pub flagged_as_proxy: bool,
    /// Human-readable rationale.
    pub rationale: String,
}

/// Result of one active-probe family against the ParallaX server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProbeResult {
    pub probe: String,
    pub description: String,
    /// Bytes the server sent back in response to the probe.
    pub server_response_len: usize,
    /// Whether the server held the connection open (no immediate reset).
    pub connection_held: bool,
    /// Whether the server's first response byte looks like a TLS record (0x16).
    pub response_looks_like_tls: bool,
    /// Whether this probe revealed a distinguisher from a real TLS origin.
    /// Gated on response *class* mismatch (the cheap signal a censor uses),
    /// not on timing.
    pub distinguisher_found: bool,
    /// Time to first response byte from the ParallaX server (ms).
    pub server_latency_ms: f64,
    /// Time to first response byte from the reference origin (ms).
    pub reference_latency_ms: f64,
    pub detail: String,
}

/// The full active-probing campaign result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProbeReport {
    pub server_addr: String,
    pub reference_origin: String,
    pub results: Vec<ActiveProbeResult>,
    pub any_distinguisher: bool,
}

/// Outcome of a single traffic scenario, produced by the orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioOutcome {
    pub scenario: String,
    pub link_profile: String,
    pub ok: bool,
    pub detail: String,
    /// Optional throughput / latency measurements gathered by trafficgen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<Summary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_transferred: Option<u64>,
}

/// Report emitted by the `gfw-box` binary for one measurement window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GfwBoxReport {
    pub schema: String,
    pub link_profile: crate::link::LinkProfile,
    pub flows: Vec<FlowFeatures>,
    pub total_flows: usize,
    pub flagged_flows: usize,
    /// Aggregate impairment counters (UDP path).
    pub udp_datagrams_forwarded: u64,
    pub udp_datagrams_dropped: u64,
    pub udp_datagrams_reordered: u64,
    pub udp_datagrams_duplicated: u64,
}

impl GfwBoxReport {
    pub const SCHEMA: &'static str = "parallax.gfwlab.box.v1";
}

/// Top-level orchestrated lab report (assembled by the orchestrator script).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabReport {
    pub schema: String,
    pub generated_unix_ms: u128,
    pub transport: String,
    pub scenarios: Vec<ScenarioOutcome>,
    pub active_probe: Option<ActiveProbeReport>,
    pub passive: Option<GfwBoxReport>,
    /// Negative-control run: the same analyzer over deliberately-detectable
    /// flows. `detector_has_teeth` is true only when the control was flagged,
    /// proving the passive verdict is meaningful (not rigged to always pass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<GfwBoxReport>,
    #[serde(default)]
    pub detector_has_teeth: bool,
    pub pass: bool,
    pub summary: String,
}

impl LabReport {
    pub const SCHEMA: &'static str = "parallax.gfwlab.report.v1";
}
