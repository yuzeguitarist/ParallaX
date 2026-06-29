//! Hand-rolled logistic-regression distinguisher with k-fold cross-validated
//! AUC — zero external dependencies.
//!
//! This is the battery's headline metric. Given per-flow feature vectors for
//! two corpora (label 0 = Safari ground truth, label 1 = ParallaX), we train a
//! logistic regression to tell them apart and measure held-out ROC AUC:
//!
//! * **AUC ≈ 0.5** — the classifier cannot separate the corpora better than a
//!   coin flip ⇒ the two are *statistically indistinguishable*. This is the
//!   success target (`AUC ∈ [0.45, 0.55]`).
//! * **AUC → 1.0** — a trivial linear boundary separates them ⇒ ParallaX is
//!   *trivially fingerprintable* on these features.
//!
//! Everything is deterministic (a fixed-seed LCG drives the fold shuffle and
//! weight init) so the AUC is reproducible across runs — a flaky gate would be
//! worse than no gate.

/// A labelled feature row: a fixed-width feature vector and a binary class.
#[derive(Debug, Clone)]
pub struct Sample {
    pub features: Vec<f64>,
    pub label: u8, // 0 or 1
}

/// Deterministic 64-bit LCG (Numerical Recipes constants) — reproducible
/// shuffling and weight init without pulling in `rand`.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    /// Uniform in [0, 1).
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = (self.next_f64() * (i + 1) as f64) as usize;
            v.swap(i, j);
        }
    }
}

/// Standardise each feature column to zero mean / unit variance using stats
/// computed on `train` only, then apply to both `train` and `test` (no leakage).
fn standardise(train: &mut [Sample], test: &mut [Sample], dim: usize) {
    for d in 0..dim {
        let col: Vec<f64> = train.iter().map(|s| s.features[d]).collect();
        let mean = col.iter().sum::<f64>() / col.len().max(1) as f64;
        let var = col.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / col.len().max(1) as f64;
        let sd = if var > 1e-12 { var.sqrt() } else { 1.0 };
        for s in train.iter_mut() {
            s.features[d] = (s.features[d] - mean) / sd;
        }
        for s in test.iter_mut() {
            s.features[d] = (s.features[d] - mean) / sd;
        }
    }
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

/// Train logistic regression by full-batch gradient descent with L2
/// regularisation. Returns `(weights, bias)`.
fn train_logreg(data: &[Sample], dim: usize, epochs: usize, lr: f64, l2: f64) -> (Vec<f64>, f64) {
    let mut w = vec![0.0; dim];
    let mut b = 0.0;
    let n = data.len().max(1) as f64;
    for _ in 0..epochs {
        let mut grad_w = vec![0.0; dim];
        let mut grad_b = 0.0;
        for s in data {
            let z = b + w
                .iter()
                .zip(&s.features)
                .map(|(wi, xi)| wi * xi)
                .sum::<f64>();
            let err = sigmoid(z) - s.label as f64;
            for (g, &x) in grad_w.iter_mut().zip(&s.features) {
                *g += err * x;
            }
            grad_b += err;
        }
        for (wi, gi) in w.iter_mut().zip(&grad_w) {
            *wi -= lr * (gi / n + l2 * *wi);
        }
        b -= lr * (grad_b / n);
    }
    (w, b)
}

fn predict(w: &[f64], b: f64, x: &[f64]) -> f64 {
    sigmoid(b + w.iter().zip(x).map(|(wi, xi)| wi * xi).sum::<f64>())
}

/// ROC AUC via the Mann–Whitney U statistic (rank-sum), with tie handling.
///
/// `scored` is `(predicted_score, true_label)`. AUC = P(score of a random
/// positive > score of a random negative). Returns 0.5 if either class is empty.
pub fn roc_auc(scored: &[(f64, u8)]) -> f64 {
    let n_pos = scored.iter().filter(|(_, y)| *y == 1).count();
    let n_neg = scored.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return 0.5;
    }
    // Rank scores ascending (average ranks for ties).
    let mut idx: Vec<usize> = (0..scored.len()).collect();
    idx.sort_by(|&i, &j| {
        scored[i]
            .0
            .partial_cmp(&scored[j].0)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut ranks = vec![0.0; scored.len()];
    let mut i = 0;
    while i < idx.len() {
        let mut j = i;
        while j + 1 < idx.len() && scored[idx[j + 1]].0 == scored[idx[i]].0 {
            j += 1;
        }
        // Ranks are 1-based; average rank over the tie block [i, j].
        let avg = ((i + 1) + (j + 1)) as f64 / 2.0;
        for k in i..=j {
            ranks[idx[k]] = avg;
        }
        i = j + 1;
    }
    let sum_pos_ranks: f64 = scored
        .iter()
        .zip(&ranks)
        .filter(|((_, y), _)| *y == 1)
        .map(|(_, r)| *r)
        .sum();
    let u = sum_pos_ranks - (n_pos * (n_pos + 1)) as f64 / 2.0;
    u / (n_pos * n_neg) as f64
}

/// k-fold cross-validated AUC of a logistic-regression distinguisher.
///
/// Pools all held-out fold predictions and computes a single AUC over them (a
/// standard, low-variance CV-AUC estimator for small corpora). Deterministic.
pub fn cross_validated_auc(samples: &[Sample], folds: usize) -> f64 {
    if samples.is_empty() {
        return 0.5;
    }
    let dim = samples[0].features.len();
    let mut order: Vec<usize> = (0..samples.len()).collect();
    Lcg::new(0x5151_2026).shuffle(&mut order);

    let k = folds.clamp(2, samples.len().max(2));
    let mut pooled: Vec<(f64, u8)> = Vec::with_capacity(samples.len());

    for f in 0..k {
        let mut train: Vec<Sample> = Vec::new();
        let mut test: Vec<Sample> = Vec::new();
        for (pos, &si) in order.iter().enumerate() {
            if pos % k == f {
                test.push(samples[si].clone());
            } else {
                train.push(samples[si].clone());
            }
        }
        if train.is_empty() || test.is_empty() {
            continue;
        }
        standardise(&mut train, &mut test, dim);
        let (w, b) = train_logreg(&train, dim, 300, 0.3, 1e-3);
        for s in &test {
            pooled.push((predict(&w, b, &s.features), s.label));
        }
    }
    // Raw two-sided AUC. The caller decides the gate semantics: the
    // indistinguishability gate checks `auc ∈ [0.45, 0.55]` (i.e. |auc-0.5| is
    // small in *either* direction), while the discriminability self-proof checks
    // separability via `(auc-0.5).abs()` being large. Folding to one side here
    // would hide a backwards-but-separating classifier from the first gate.
    roc_auc(&pooled)
}

/// Two-sided separability: how far the CV-AUC is from chance, in [0, 0.5].
/// `0` = indistinguishable, `0.5` = perfectly separable in either direction.
pub fn separability(samples: &[Sample], folds: usize) -> f64 {
    (cross_validated_auc(samples, folds) - 0.5).abs()
}
