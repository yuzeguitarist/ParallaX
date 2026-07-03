//! Small dependency-free statistics helpers.

/// Summary statistics for a slice of samples.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub median: f64,
    pub stddev: f64,
}

impl Summary {
    pub fn of(samples: &[f64]) -> Summary {
        if samples.is_empty() {
            return Summary::default();
        }
        let count = samples.len();
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let min = sorted[0];
        let max = sorted[count - 1];
        let sum: f64 = sorted.iter().sum();
        let mean = sum / count as f64;
        let median = if count % 2 == 1 {
            sorted[count / 2]
        } else {
            (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0
        };
        let var = sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / count as f64;
        Summary {
            count,
            min,
            max,
            mean,
            median,
            stddev: var.sqrt(),
        }
    }
}

/// Shannon entropy in bits/byte over the byte-value histogram of `data`.
///
/// A uniformly random stream approaches 8.0; English/ASCII text sits well
/// below. Used as one input to the "fully encrypted" first-packet heuristic.
pub fn shannon_bits_per_byte(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in freq.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Mean number of set bits per byte (popcount / len).
///
/// This is the Ex1 statistic from Frolov & Wustrow (USENIX'23): a fully random
/// payload centres near 4.0 bits set per byte; structured/ASCII payloads fall
/// outside a tolerance band around 4.0.
pub fn mean_popcount_per_byte(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let total: u32 = data.iter().map(|b| b.count_ones()).sum();
    total as f64 / data.len() as f64
}

/// Fraction of bytes that are printable ASCII (0x20..=0x7e), tab/newline count.
pub fn printable_ascii_fraction(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || b == 0x09 || b == 0x0a || b == 0x0d)
        .count();
    printable as f64 / data.len() as f64
}

/// Longest run of consecutive printable-ASCII bytes.
pub fn longest_printable_run(data: &[u8]) -> usize {
    let mut best = 0usize;
    let mut cur = 0usize;
    for &b in data {
        if (0x20..=0x7e).contains(&b) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}
