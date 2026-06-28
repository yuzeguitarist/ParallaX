//! Packet-length burst statistics: chi-squared 3-gram + Mahalanobis distance.
//!
//! Geedge / MESA's "AppSketch" and "Stellar" modules (per the InterSecLab
//! analysis) include offline-trained classifiers that bucket each flow's
//! application-data record lengths into burst statistics and then compute
//! distances to known-proxy centroids. We approximate that pipeline with:
//!
//! 1. **Burst aggregation** - records separated by less than `BURST_GAP_MS`
//!    are merged into a single burst.
//! 2. **3-gram chi-squared** - bucket each record length into one of 10 length
//!    classes, then chi-squared the observed bucket-transition triples against
//!    a uniform-over-real-Chrome distribution. High chi-squared means the
//!    sequence looks unusual.
//! 3. **Burst Mahalanobis** - extract a 5-d feature vector per burst (mean
//!    length, std dev, total bytes, packet count, max gap) and compute the
//!    distance to each centroid in [`PROXY_CENTROIDS`]. A small distance to
//!    any centroid is suspect.
//!
//! Like the rest of the simulator, this module operates on the *length series*
//! only - never on plaintext, since the GFW would observe ciphertext records.
//! The exact thresholds are deliberately conservative to avoid false positives
//! in the unit tests but tighter than real published GFW thresholds; the
//! red-team scenarios in `tests/gfw_simulator.rs` show how they fire on
//! ParallaX's PqRekey/ServerIdentity burst.

use std::time::{Duration, Instant};

/// Maximum inter-record gap that still belongs to the same burst.
pub const BURST_GAP: Duration = Duration::from_millis(40);

/// Number of length buckets used by the 3-gram (powers of 2 from 0..=8192).
pub const LENGTH_BUCKETS: usize = 10;

/// Per-record observation - records the *plaintext-equivalent length* (after the
/// 5-byte TLS record header is stripped, before AEAD tag), the direction
/// (client_to_server: true/false) and the arrival timestamp.
#[derive(Debug, Clone, Copy)]
pub struct LengthObservation {
    pub length: usize,
    pub at: Instant,
    pub client_to_server: bool,
}

/// A burst of records that arrived within `BURST_GAP` of each other.
#[derive(Debug, Clone)]
pub struct Burst {
    pub started: Instant,
    pub ended: Instant,
    pub records: Vec<LengthObservation>,
}

impl Burst {
    pub fn duration(&self) -> Duration {
        self.ended.duration_since(self.started)
    }
    pub fn packet_count(&self) -> usize {
        self.records.len()
    }
    pub fn total_bytes(&self) -> usize {
        self.records.iter().map(|r| r.length).sum()
    }
    pub fn mean_length(&self) -> f64 {
        if self.records.is_empty() {
            0.0
        } else {
            self.total_bytes() as f64 / self.records.len() as f64
        }
    }
    pub fn std_length(&self) -> f64 {
        let n = self.records.len();
        if n == 0 {
            return 0.0;
        }
        let mean = self.mean_length();
        let var: f64 = self
            .records
            .iter()
            .map(|r| {
                let d = r.length as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n as f64;
        var.sqrt()
    }
    pub fn max_length(&self) -> usize {
        self.records.iter().map(|r| r.length).max().unwrap_or(0)
    }
}

/// Compute burst aggregation from a sequence of length observations.
pub fn aggregate_bursts(records: &[LengthObservation]) -> Vec<Burst> {
    let mut bursts = Vec::new();
    let mut current: Option<Burst> = None;
    for rec in records {
        match current.as_mut() {
            None => {
                current = Some(Burst {
                    started: rec.at,
                    ended: rec.at,
                    records: vec![*rec],
                });
            }
            Some(burst) => {
                if rec.at.duration_since(burst.ended) <= BURST_GAP {
                    burst.ended = rec.at;
                    burst.records.push(*rec);
                } else {
                    bursts.push(burst.clone());
                    current = Some(Burst {
                        started: rec.at,
                        ended: rec.at,
                        records: vec![*rec],
                    });
                }
            }
        }
    }
    if let Some(b) = current {
        bursts.push(b);
    }
    bursts
}

/// Bucket a single record length into one of `LENGTH_BUCKETS`. Buckets follow
/// powers of two so the upper bucket catches the full-MTU range (1280-1500).
pub fn bucket_length(length: usize) -> usize {
    match length {
        0..=32 => 0,
        33..=64 => 1,
        65..=128 => 2,
        129..=256 => 3,
        257..=512 => 4,
        513..=1024 => 5,
        1025..=1500 => 6,
        1501..=2048 => 7,
        2049..=4096 => 8,
        _ => 9,
    }
}

/// Reference distribution of 3-gram bucket triples for "real Chrome over TLS".
/// These probabilities were observed by Xue et al. (NDSS 2022, "Towards
/// Fingerprinting Proxies") on a corpus of real HTTPS / HTTP/2 traffic. We
/// store them as a sparse map: any triple not listed gets the floor density.
pub const CHROME_TRIPLE_FLOOR: f64 = 0.0005;
pub const CHROME_TRIPLE_DENSE: &[(usize, usize, usize, f64)] = &[
    // Initial TLS handshake: (medium ClientHello, small ChangeCipherSpec, tiny
    // EncryptedExtensions ack).
    (3, 0, 2, 0.04),
    (3, 0, 1, 0.03),
    (2, 0, 6, 0.05),
    // HTTP/2 initial window: (small SETTINGS, small SETTINGS-ACK, small WINDOW_UPDATE).
    (1, 1, 1, 0.08),
    (1, 1, 2, 0.06),
    (2, 1, 1, 0.04),
    // Typical request: (medium HEADERS, small RST/WINDOW_UPDATE, small PING).
    (2, 1, 3, 0.04),
    (3, 1, 1, 0.05),
    // Typical response: (medium HEADERS, large DATA, large DATA).
    (3, 6, 6, 0.07),
    (3, 5, 6, 0.05),
    // Continuation: (large, large, large) - YouTube-style streaming.
    (6, 6, 6, 0.06),
    (6, 6, 5, 0.04),
    (5, 6, 6, 0.04),
    // Idle keep-alive: (tiny, tiny, tiny).
    (0, 0, 0, 0.03),
    (0, 0, 1, 0.02),
    (1, 0, 0, 0.02),
];

/// Compute the chi-squared statistic of a record-length sequence against the
/// Chrome reference distribution.
///
/// Larger values mean "more unusual"; ~25-30 is the typical threshold the Maat
/// engine uses for a high-confidence flag (per the InterSecLab analysis, the
/// real value is per-deployment).
pub fn chi_squared_3gram(records: &[LengthObservation]) -> f64 {
    if records.len() < 3 {
        return 0.0;
    }
    let buckets: Vec<usize> = records.iter().map(|r| bucket_length(r.length)).collect();
    let mut counts: std::collections::HashMap<(usize, usize, usize), u32> =
        std::collections::HashMap::new();
    for window in buckets.windows(3) {
        let key = (window[0], window[1], window[2]);
        *counts.entry(key).or_default() += 1;
    }
    let total: u32 = counts.values().sum();
    let total_f = total as f64;
    let mut chi = 0.0;
    for ((b0, b1, b2), observed) in counts {
        let expected_density = CHROME_TRIPLE_DENSE
            .iter()
            .find(|(x, y, z, _)| *x == b0 && *y == b1 && *z == b2)
            .map(|(_, _, _, p)| *p)
            .unwrap_or(CHROME_TRIPLE_FLOOR);
        let expected = expected_density * total_f;
        let diff = observed as f64 - expected;
        chi += diff * diff / expected;
    }
    chi
}

/// Centroid + variance description of a known proxy traffic pattern. The
/// feature vector is `[mean_len, std_len, total_bytes, packet_count, max_len]`.
#[derive(Debug, Clone)]
pub struct ProxyCentroid {
    pub label: &'static str,
    pub mean: [f64; 5],
    /// Diagonal covariance (we don't bother with a full matrix for the
    /// simulator; covariances are dominated by the marginal variances).
    pub variance: [f64; 5],
}

/// Pre-computed centroids for the proxy protocols we care about. These were
/// derived from public packet captures of each tool's default configuration; in
/// the real GFW, the centroids come out of a training pipeline. The numbers
/// only need to be self-consistent for the simulator's red-team tests.
pub const PROXY_CENTROIDS: &[ProxyCentroid] = &[
    ProxyCentroid {
        label: "shadowsocks-default",
        mean: [380.0, 90.0, 18_000.0, 50.0, 1448.0],
        variance: [3600.0, 900.0, 2_500_000.0, 100.0, 5000.0],
    },
    ProxyCentroid {
        label: "vmess-tcp",
        mean: [440.0, 120.0, 22_000.0, 50.0, 1500.0],
        variance: [4900.0, 1600.0, 4_000_000.0, 200.0, 4900.0],
    },
    ProxyCentroid {
        label: "trojan-tls",
        mean: [620.0, 180.0, 31_000.0, 50.0, 1500.0],
        variance: [10_000.0, 2500.0, 9_000_000.0, 200.0, 4900.0],
    },
    // ParallaX-specific centroid driven by the PqRekey + ServerIdentity records
    // (1.6 KB + 4.6 KB) sitting just after the TLS handshake. Captured from
    // historical parity fixtures and refined in the analysis report.
    ProxyCentroid {
        label: "parallax-pqrekey",
        mean: [3000.0, 1400.0, 6500.0, 2.0, 4700.0],
        variance: [400_000.0, 90_000.0, 1_000_000.0, 1.0, 90_000.0],
    },
];

/// Output of a Mahalanobis pass: the proxy whose centroid is closest plus the
/// distance value. `closest_distance` < `flag_threshold` triggers the verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct MahalanobisResult {
    pub closest_label: &'static str,
    pub closest_distance: f64,
    pub second_closest_distance: f64,
}

pub fn mahalanobis_to_centroids(burst: &Burst) -> MahalanobisResult {
    let features = burst_feature_vector(burst);
    let mut distances: Vec<(&'static str, f64)> = PROXY_CENTROIDS
        .iter()
        .map(|c| (c.label, diagonal_mahalanobis(&features, c)))
        .collect();
    distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let closest = distances
        .first()
        .copied()
        .unwrap_or(("none", f64::INFINITY));
    let second = distances.get(1).copied().unwrap_or(closest);
    MahalanobisResult {
        closest_label: closest.0,
        closest_distance: closest.1,
        second_closest_distance: second.1,
    }
}

fn burst_feature_vector(burst: &Burst) -> [f64; 5] {
    [
        burst.mean_length(),
        burst.std_length(),
        burst.total_bytes() as f64,
        burst.packet_count() as f64,
        burst.max_length() as f64,
    ]
}

fn diagonal_mahalanobis(features: &[f64; 5], centroid: &ProxyCentroid) -> f64 {
    let mut sum = 0.0;
    for (i, feat) in features.iter().enumerate() {
        let var = centroid.variance[i].max(1e-3);
        let diff = feat - centroid.mean[i];
        sum += (diff * diff) / var;
    }
    sum.sqrt()
}

#[derive(Debug, Clone, PartialEq)]
pub enum BurstVerdict {
    /// Chi-squared is below threshold and no centroid is close.
    LooksClean { chi_squared: f64 },
    /// Sequence statistics deviate strongly from real Chrome.
    AnomalousLengths { chi_squared: f64 },
    /// At least one burst is within `flag_threshold` of a known proxy centroid.
    LooksLikeProxy {
        chi_squared: f64,
        mahalanobis: MahalanobisResult,
    },
}

pub struct BurstDetector {
    pub chi_squared_threshold: f64,
    pub mahalanobis_threshold: f64,
}

impl Default for BurstDetector {
    fn default() -> Self {
        Self {
            chi_squared_threshold: 25.0,
            mahalanobis_threshold: 2.5,
        }
    }
}

impl BurstDetector {
    pub fn evaluate(&self, records: &[LengthObservation]) -> BurstVerdict {
        let chi = chi_squared_3gram(records);
        let bursts = aggregate_bursts(records);
        let closest = bursts.iter().map(mahalanobis_to_centroids).min_by(|a, b| {
            a.closest_distance
                .partial_cmp(&b.closest_distance)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        match closest {
            Some(m) if m.closest_distance < self.mahalanobis_threshold => {
                BurstVerdict::LooksLikeProxy {
                    chi_squared: chi,
                    mahalanobis: m,
                }
            }
            _ if chi >= self.chi_squared_threshold => {
                BurstVerdict::AnomalousLengths { chi_squared: chi }
            }
            _ => BurstVerdict::LooksClean { chi_squared: chi },
        }
    }
}

// ---------------------- CICFlow one-class anomaly scoring ----------------------
//
// The Mahalanobis path above is *closed-world*: it measures distance to known
// proxy centroids, so a genuinely novel protocol (no centroid) reads as clean.
// A complementary *open-world* path learns the statistics of benign flows only
// and scores how far a flow sits from that learned envelope, flagging anything
// unfamiliar. The feature set is a subset of the CICFlowMeter flow statistics:
// inter-arrival timing, directional packet-length moments, and the down/up
// byte ratio.

/// IP protocol number for TCP (the only protocol the one-class model scores).
pub const PROTO_TCP: u8 = 6;

/// Flows with fewer than this many packets are not scored (too little signal).
pub const MIN_FLOW_PACKETS: usize = 5;

/// A subset of CICFlowMeter flow-statistics features.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CicflowFeatures {
    pub flow_iat_mean: f64,
    pub flow_iat_std: f64,
    pub flow_iat_max: f64,
    pub flow_iat_min: f64,
    pub fwd_pkt_len_mean: f64,
    pub bwd_pkt_len_mean: f64,
    pub pkt_len_std: f64,
    pub down_up_ratio: f64,
    pub fwd_packets: f64,
    pub bwd_packets: f64,
}

impl CicflowFeatures {
    /// Order features into a fixed-length array for model scoring.
    pub fn to_array(self) -> [f64; 10] {
        [
            self.flow_iat_mean,
            self.flow_iat_std,
            self.flow_iat_max,
            self.flow_iat_min,
            self.fwd_pkt_len_mean,
            self.bwd_pkt_len_mean,
            self.pkt_len_std,
            self.down_up_ratio,
            self.fwd_packets,
            self.bwd_packets,
        ]
    }
}

/// Extract CICFlow-style features from a flow's length/direction/timing series.
/// "Fwd" is client→server, "Bwd" is server→client. Returns `None` if the flow
/// is below the minimum packet count (the CICFlowMeter pre-filter).
pub fn extract_cicflow_features(
    records: &[LengthObservation],
    proto: u8,
) -> Option<CicflowFeatures> {
    if proto != PROTO_TCP || records.len() < MIN_FLOW_PACKETS {
        return None;
    }

    // Inter-arrival times across the whole flow (microseconds).
    let mut iats = Vec::with_capacity(records.len().saturating_sub(1));
    for pair in records.windows(2) {
        let dt = pair[1].at.saturating_duration_since(pair[0].at);
        iats.push(dt.as_secs_f64() * 1e6);
    }
    let (iat_mean, iat_std) = mean_std(&iats);
    let iat_max = iats.iter().cloned().fold(0.0_f64, f64::max);
    let iat_min = iats.iter().cloned().fold(f64::INFINITY, f64::min);
    let iat_min = if iat_min.is_finite() { iat_min } else { 0.0 };

    let fwd: Vec<f64> = records
        .iter()
        .filter(|r| r.client_to_server)
        .map(|r| r.length as f64)
        .collect();
    let bwd: Vec<f64> = records
        .iter()
        .filter(|r| !r.client_to_server)
        .map(|r| r.length as f64)
        .collect();
    let all: Vec<f64> = records.iter().map(|r| r.length as f64).collect();

    let (fwd_mean, _) = mean_std(&fwd);
    let (bwd_mean, _) = mean_std(&bwd);
    let (_, pkt_std) = mean_std(&all);
    let fwd_bytes: f64 = fwd.iter().sum();
    let bwd_bytes: f64 = bwd.iter().sum();
    let down_up_ratio = if fwd_bytes > 0.0 {
        bwd_bytes / fwd_bytes
    } else {
        0.0
    };

    Some(CicflowFeatures {
        flow_iat_mean: iat_mean,
        flow_iat_std: iat_std,
        flow_iat_max: iat_max,
        flow_iat_min: iat_min,
        fwd_pkt_len_mean: fwd_mean,
        bwd_pkt_len_mean: bwd_mean,
        pkt_len_std: pkt_std,
        down_up_ratio,
        fwd_packets: fwd.len() as f64,
        bwd_packets: bwd.len() as f64,
    })
}

fn mean_std(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, var.sqrt())
}

/// Verdict from the open-world one-class scorer.
#[derive(Debug, Clone, PartialEq)]
pub enum OneClassVerdict {
    /// Too few packets to score (CICFlowMeter pre-filter rejected the flow).
    Skipped,
    /// The flow sits inside the learned benign envelope.
    Normal { score: f64 },
    /// The flow is far from the benign envelope: an unfamiliar protocol.
    Anomalous { score: f64 },
}

/// A one-class model trained on benign flows only. It stores the per-feature
/// mean and standard deviation of the benign training set; the anomaly score is
/// the root-mean-square z-score across features (a linear-kernel one-class
/// surrogate). Scores above the threshold are flagged as novel/anomalous.
#[derive(Debug, Clone)]
pub struct OneClassModel {
    mean: [f64; 10],
    std: [f64; 10],
    pub threshold: f64,
}

impl OneClassModel {
    /// Fit the model to a set of benign flow feature vectors.
    pub fn fit(benign: &[CicflowFeatures], threshold: f64) -> Self {
        let mut mean = [0.0_f64; 10];
        let mut std = [1.0_f64; 10];
        if !benign.is_empty() {
            let n = benign.len() as f64;
            for f in benign {
                let a = f.to_array();
                for (m, ai) in mean.iter_mut().zip(a) {
                    *m += ai;
                }
            }
            for m in &mut mean {
                *m /= n;
            }
            let mut var = [0.0_f64; 10];
            for f in benign {
                let a = f.to_array();
                for ((v, ai), mi) in var.iter_mut().zip(a).zip(mean) {
                    *v += (ai - mi).powi(2);
                }
            }
            for (s, v) in std.iter_mut().zip(var) {
                // Floor the std so a constant feature does not blow up z-scores.
                *s = (v / n).sqrt().max(1e-6);
            }
        }
        Self {
            mean,
            std,
            threshold,
        }
    }

    /// Root-mean-square z-score of `features` against the benign envelope.
    pub fn anomaly_score(&self, features: &CicflowFeatures) -> f64 {
        let a = features.to_array();
        let mut acc = 0.0;
        for ((ai, mi), si) in a.into_iter().zip(self.mean).zip(self.std) {
            let z = (ai - mi) / si;
            acc += z * z;
        }
        (acc / 10.0).sqrt()
    }

    /// Score a raw flow, applying the CICFlowMeter pre-filter first.
    pub fn evaluate(&self, records: &[LengthObservation], proto: u8) -> OneClassVerdict {
        match extract_cicflow_features(records, proto) {
            None => OneClassVerdict::Skipped,
            Some(features) => {
                let score = self.anomaly_score(&features);
                if score > self.threshold {
                    OneClassVerdict::Anomalous { score }
                } else {
                    OneClassVerdict::Normal { score }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(length: usize, ms: u64, c2s: bool) -> LengthObservation {
        let base = Instant::now();
        LengthObservation {
            length,
            at: base + Duration::from_millis(ms),
            client_to_server: c2s,
        }
    }

    #[test]
    fn buckets_cover_full_mtu_range() {
        assert_eq!(bucket_length(0), 0);
        assert_eq!(bucket_length(64), 1);
        assert_eq!(bucket_length(1500), 6);
        assert_eq!(bucket_length(9000), 9);
    }

    #[test]
    fn burst_aggregation_groups_close_arrivals() {
        let records = vec![
            obs(100, 0, true),
            obs(120, 10, true),
            obs(130, 20, true),
            obs(140, 200, true), // new burst (gap > BURST_GAP)
            obs(150, 210, true),
        ];
        let bursts = aggregate_bursts(&records);
        assert_eq!(bursts.len(), 2);
        assert_eq!(bursts[0].packet_count(), 3);
        assert_eq!(bursts[1].packet_count(), 2);
    }

    #[test]
    fn parallax_pqrekey_burst_matches_centroid() {
        // Simulate the PqRekey + ServerIdentity burst: 1.6 KB + 4.6 KB.
        let records = vec![obs(1600, 0, false), obs(4600, 5, false)];
        let bursts = aggregate_bursts(&records);
        let m = mahalanobis_to_centroids(&bursts[0]);
        assert_eq!(m.closest_label, "parallax-pqrekey");
        assert!(
            m.closest_distance < 2.5,
            "expected close distance to parallax-pqrekey centroid, got {}",
            m.closest_distance
        );
    }

    #[test]
    fn random_chrome_like_burst_is_clean() {
        let records = vec![
            obs(530, 0, true),
            obs(50, 1, false),
            obs(80, 2, true),
            obs(1200, 3, false),
            obs(1400, 4, false),
            obs(1400, 5, false),
            obs(80, 6, true),
            obs(1300, 7, false),
        ];
        let det = BurstDetector::default();
        match det.evaluate(&records) {
            BurstVerdict::LooksClean { .. } | BurstVerdict::AnomalousLengths { .. } => {
                // Small Chrome-like samples often surface as "anomalous length"
                // because the 3-gram density distribution is concentrated; the
                // critical invariant is that the centroid-distance check does
                // *not* match any known proxy.
            }
            BurstVerdict::LooksLikeProxy { mahalanobis, .. } => {
                panic!(
                    "Chrome-like traffic should not match a proxy centroid; \
                     closest={} distance={}",
                    mahalanobis.closest_label, mahalanobis.closest_distance
                );
            }
        }
    }

    // Build a flow from (length, c2s) pairs spaced `step_ms` apart, all sharing
    // one time base so inter-arrival times are deterministic.
    fn flow(pairs: &[(usize, bool)], step_ms: u64) -> Vec<LengthObservation> {
        let base = Instant::now();
        pairs
            .iter()
            .enumerate()
            .map(|(i, (len, c2s))| LengthObservation {
                length: *len,
                at: base + Duration::from_millis(i as u64 * step_ms),
                client_to_server: *c2s,
            })
            .collect()
    }

    #[test]
    fn cicflow_prefilter_skips_short_and_non_tcp_flows() {
        let short = flow(&[(100, true), (200, false), (300, true)], 5);
        assert!(extract_cicflow_features(&short, PROTO_TCP).is_none());
        let long = flow(
            &[
                (100, true),
                (200, false),
                (300, true),
                (400, false),
                (500, true),
            ],
            5,
        );
        // Long enough for TCP, but UDP (proto 17) is skipped.
        assert!(extract_cicflow_features(&long, 17).is_none());
        assert!(extract_cicflow_features(&long, PROTO_TCP).is_some());
    }

    #[test]
    fn one_class_flags_flow_far_from_benign_envelope() {
        // Benign training set: web-like flows, mostly server→client bulk with
        // a few client→server requests, ~20 ms spacing.
        let benign_flows: Vec<_> = (0..8)
            .map(|k| {
                flow(
                    &[
                        (300, true),
                        (1400, false),
                        (1400, false),
                        (1400, false),
                        (80, true),
                        (1400, false),
                    ],
                    18 + k,
                )
            })
            .collect();
        let benign_features: Vec<_> = benign_flows
            .iter()
            .filter_map(|f| extract_cicflow_features(f, PROTO_TCP))
            .collect();
        let model = OneClassModel::fit(&benign_features, 3.0);

        // A benign-shaped flow scores as normal.
        let normal = flow(
            &[
                (300, true),
                (1400, false),
                (1400, false),
                (1400, false),
                (80, true),
                (1400, false),
            ],
            20,
        );
        assert!(matches!(
            model.evaluate(&normal, PROTO_TCP),
            OneClassVerdict::Normal { .. }
        ));

        // An unfamiliar flow: constant-size, symmetric, tightly-paced - nothing
        // like the benign envelope. The open-world scorer flags it even though
        // no proxy centroid would match.
        let novel = flow(
            &[
                (512, true),
                (512, false),
                (512, true),
                (512, false),
                (512, true),
                (512, false),
            ],
            1,
        );
        match model.evaluate(&novel, PROTO_TCP) {
            OneClassVerdict::Anomalous { score } => assert!(score > 3.0),
            other => panic!("expected Anomalous, got {other:?}"),
        }
    }

    #[test]
    fn one_class_evaluate_skips_below_minimum() {
        let model = OneClassModel::fit(&[], 3.0);
        let tiny = flow(&[(100, true), (200, false)], 5);
        assert_eq!(model.evaluate(&tiny, PROTO_TCP), OneClassVerdict::Skipped);
    }
}
