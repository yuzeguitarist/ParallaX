//! Feature extraction: turn a [`Trace`] into the marginal samples the stats
//! tests consume, and into per-window feature vectors the classifier consumes.
//!
//! The dimensions are exactly "the places a naive imitation gets caught":
//!
//! * **length distribution** — the C2S record-length sample (KS vs Safari).
//! * **IAT** — inter-arrival times (KS / autocorrelation).
//! * **direction-run lengths** — how long the stream stays one-directional
//!   before flipping. A proxy that ACKs 1:1 has run-length ≈ 1 everywhere,
//!   which a real browser does not — this is the "1:1 ACK" tell made numeric.
//! * **ACK ratio** — S2C records per C2S record. Browsers batch; a lockstep
//!   relay sits near 1.0.
//! * **burst 5-d** — mean/std/total/count/max over records grouped within
//!   `BURST_GAP`, mirroring the GFW simulator's `burst_statistics` features.

use super::trace::{Dir, Record, Trace};

/// Same 40 ms burst gap the GFW simulator's `burst_statistics` uses, so the
/// burst features are directly comparable to that detector.
pub const BURST_GAP_MICROS: u64 = 40_000;

/// Direction-run lengths: the lengths of maximal same-direction runs over the
/// whole (time-ordered) record sequence. A 1:1-ACK relay produces runs of ~1.
pub fn direction_runs(trace: &Trace) -> Vec<f64> {
    let mut runs = Vec::new();
    let mut cur_dir: Option<Dir> = None;
    let mut run_len = 0u32;
    for r in &trace.records {
        match cur_dir {
            Some(d) if d == r.dir => run_len += 1,
            _ => {
                if run_len > 0 {
                    runs.push(run_len as f64);
                }
                cur_dir = Some(r.dir);
                run_len = 1;
            }
        }
    }
    if run_len > 0 {
        runs.push(run_len as f64);
    }
    runs
}

/// ACK ratio: total S2C records / total C2S records. Near 1.0 for a lockstep
/// relay; browsers batch downstream so the real ratio departs from 1.
pub fn ack_ratio(trace: &Trace) -> f64 {
    let c2s = trace.records.iter().filter(|r| r.dir == Dir::C2S).count();
    let s2c = trace.records.iter().filter(|r| r.dir == Dir::S2C).count();
    if c2s == 0 {
        0.0
    } else {
        s2c as f64 / c2s as f64
    }
}

/// One burst: records grouped within `BURST_GAP_MICROS` of each other.
struct Burst {
    lens: Vec<f64>,
}

fn aggregate_bursts(records: &[Record]) -> Vec<Burst> {
    let mut bursts: Vec<Burst> = Vec::new();
    let mut last_t: Option<u64> = None;
    for r in records {
        let new_burst = match last_t {
            Some(t) => r.t_micros.saturating_sub(t) > BURST_GAP_MICROS,
            None => true,
        };
        if new_burst {
            bursts.push(Burst { lens: Vec::new() });
        }
        bursts.last_mut().unwrap().lens.push(r.len as f64);
        last_t = Some(r.t_micros);
    }
    bursts
}

/// The 5-d burst feature vector `[mean_len, std_len, total_bytes, count, max_len]`
/// — the same layout as `burst_statistics::burst_feature_vector`.
fn burst_vector(b: &Burst) -> [f64; 5] {
    let n = b.lens.len().max(1) as f64;
    let total: f64 = b.lens.iter().sum();
    let mean = total / n;
    let var = b.lens.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let max = b.lens.iter().cloned().fold(0.0, f64::max);
    [mean, var.sqrt(), total, b.lens.len() as f64, max]
}

/// Per-window classifier features for one trace, split into fixed-size windows
/// so a single capture yields many labelled rows (the classifier needs N rows,
/// not one). Each window contributes one feature vector summarising its records.
///
/// Feature layout (10-d):
///   [0] mean C2S length
///   [1] std  C2S length
///   [2] mean IAT (C2S, micros)
///   [3] std  IAT (C2S, micros)
///   [4] mean direction-run length
///   [5] ACK ratio in the window
///   [6..=9] first four burst features (mean/std/total/count), averaged over
///           the window's C2S bursts; `max_len` is dropped because under a
///           uniform 16401-byte record regime it is collinear with `mean_len`.
pub fn window_features(trace: &Trace, window: usize) -> Vec<Vec<f64>> {
    if trace.records.len() < window || window == 0 {
        // One window over the whole trace if it is too short to split.
        return vec![feature_vector(trace)];
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + window <= trace.records.len() {
        let slice = Trace {
            records: trace.records[i..i + window].to_vec(),
        };
        out.push(feature_vector(&slice));
        i += window;
    }
    out
}

/// The 10-d summary feature vector for a (sub-)trace.
pub fn feature_vector(trace: &Trace) -> Vec<f64> {
    let c2s_lens = trace.lengths(Dir::C2S);
    let c2s_iats = trace.iats(Dir::C2S);
    let runs = direction_runs(trace);

    let mean = |v: &[f64]| {
        if v.is_empty() {
            0.0
        } else {
            v.iter().sum::<f64>() / v.len() as f64
        }
    };
    let std = |v: &[f64]| {
        if v.is_empty() {
            return 0.0;
        }
        let m = mean(v);
        (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64).sqrt()
    };

    let c2s_records: Vec<Record> = trace.dir(Dir::C2S);
    let bursts = aggregate_bursts(&c2s_records);
    let mut burst_acc = [0.0f64; 5];
    if !bursts.is_empty() {
        for b in &bursts {
            let v = burst_vector(b);
            for d in 0..5 {
                burst_acc[d] += v[d];
            }
        }
        for acc in &mut burst_acc {
            *acc /= bursts.len() as f64;
        }
    }

    vec![
        mean(&c2s_lens),
        std(&c2s_lens),
        mean(&c2s_iats),
        std(&c2s_iats),
        mean(&runs),
        ack_ratio(trace),
        burst_acc[0],
        burst_acc[1],
        burst_acc[2],
        burst_acc[3],
    ]
}
