//! Hand-rolled two-sample statistics — zero external dependencies.
//!
//! Three independent distinguishers, each answering "could these two samples
//! have come from the same process?":
//!
//! * [`two_sample_ks`] — Kolmogorov–Smirnov: the largest gap between the two
//!   empirical CDFs, plus an asymptotic p-value. Sensitive to *any* difference
//!   in a marginal distribution (length, IAT).
//! * [`chi_square_gof`] — Pearson chi-squared goodness-of-fit of an observed
//!   histogram against expected counts, with an asymptotic p-value. Used for
//!   categorical features (direction-run lengths, length buckets).
//! * [`ljung_box`] — a portmanteau test for serial autocorrelation up to lag
//!   `h`. A real browser's record stream has structured autocorrelation; a naive
//!   imitation often does not (or has the wrong kind).
//!
//! P-values use standard asymptotic approximations (Kolmogorov series; regular
//! incomplete-gamma for chi-squared). They are accurate enough to drive the
//! battery's accept/reject gates (`p > 0.05` = indistinguishable) and are
//! cross-checked against synthetic distributions in the unit tests.

/// Result of a two-sample Kolmogorov–Smirnov test.
#[derive(Debug, Clone, Copy)]
pub struct KsResult {
    /// The KS statistic D: sup |F1(x) - F2(x)|, in [0, 1].
    pub statistic: f64,
    /// Asymptotic two-sided p-value. Small p ⇒ distributions differ.
    pub p_value: f64,
}

/// Two-sample Kolmogorov–Smirnov test.
///
/// Returns D = 0, p = 1 for degenerate inputs (either sample empty) so the
/// caller treats "no data" as "indistinguishable" rather than panicking.
pub fn two_sample_ks(a: &[f64], b: &[f64]) -> KsResult {
    let (n, m) = (a.len(), b.len());
    if n == 0 || m == 0 {
        return KsResult {
            statistic: 0.0,
            p_value: 1.0,
        };
    }
    let mut xa = a.to_vec();
    let mut xb = b.to_vec();
    xa.sort_by(|p, q| p.partial_cmp(q).unwrap_or(std::cmp::Ordering::Equal));
    xb.sort_by(|p, q| p.partial_cmp(q).unwrap_or(std::cmp::Ordering::Equal));

    // Merge-walk both sorted samples, tracking the running ECDF gap.
    let (mut i, mut j) = (0usize, 0usize);
    let mut d: f64 = 0.0;
    while i < n && j < m {
        let (va, vb) = (xa[i], xb[j]);
        if va <= vb {
            // Advance through all ties in xa at this value.
            let v = va;
            while i < n && xa[i] == v {
                i += 1;
            }
        }
        if vb <= va {
            let v = vb;
            while j < m && xb[j] == v {
                j += 1;
            }
        }
        let gap = (i as f64 / n as f64) - (j as f64 / m as f64);
        d = d.max(gap.abs());
    }

    let en = ((n * m) as f64 / (n + m) as f64).sqrt();
    let p = kolmogorov_sf((en + 0.12 + 0.11 / en) * d);
    KsResult {
        statistic: d,
        p_value: p.clamp(0.0, 1.0),
    }
}

/// Survival function of the Kolmogorov distribution, Q(λ) = 2·Σ (-1)^{k-1}
/// e^{-2 k² λ²}. This is the standard asymptotic tail used by SciPy's
/// `ks_2samp`. Converges fast; 100 terms is far more than needed.
fn kolmogorov_sf(lambda: f64) -> f64 {
    if lambda <= 0.0 {
        return 1.0;
    }
    let mut sum = 0.0;
    let mut sign = 1.0;
    for k in 1..=100 {
        let term = sign * (-2.0 * (k * k) as f64 * lambda * lambda).exp();
        sum += term;
        sign = -sign;
        if term.abs() < 1e-12 {
            break;
        }
    }
    (2.0 * sum).clamp(0.0, 1.0)
}

/// Result of a Pearson chi-squared goodness-of-fit test.
#[derive(Debug, Clone, Copy)]
pub struct ChiSquareResult {
    pub statistic: f64,
    pub dof: usize,
    pub p_value: f64,
}

/// Pearson chi-squared goodness-of-fit: observed vs expected bin counts.
///
/// `dof = bins - 1`. Bins with `expected <= 0` are skipped (they would divide
/// by zero); this matches the convention of pooling empty expected bins away.
pub fn chi_square_gof(observed: &[f64], expected: &[f64]) -> ChiSquareResult {
    assert_eq!(observed.len(), expected.len(), "bin count mismatch");
    let mut chi = 0.0;
    let mut used = 0usize;
    for (&o, &e) in observed.iter().zip(expected.iter()) {
        if e > 0.0 {
            let diff = o - e;
            chi += diff * diff / e;
            used += 1;
        }
    }
    let dof = used.saturating_sub(1);
    let p = if dof == 0 {
        1.0
    } else {
        chi_square_sf(chi, dof)
    };
    ChiSquareResult {
        statistic: chi,
        dof,
        p_value: p,
    }
}

/// Survival function of the chi-squared distribution with `dof` degrees of
/// freedom: P(X > x) = 1 - regularised_lower_gamma(dof/2, x/2).
pub fn chi_square_sf(x: f64, dof: usize) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }
    (1.0 - reg_lower_gamma(dof as f64 / 2.0, x / 2.0)).clamp(0.0, 1.0)
}

/// Regularised lower incomplete gamma P(a, x) via series expansion (good for
/// x < a+1) or continued fraction (good for x >= a+1) — Numerical Recipes §6.2.
fn reg_lower_gamma(a: f64, x: f64) -> f64 {
    if x < 0.0 || a <= 0.0 {
        return 0.0;
    }
    if x == 0.0 {
        return 0.0;
    }
    if x < a + 1.0 {
        // Series representation.
        let mut ap = a;
        let mut sum = 1.0 / a;
        let mut del = sum;
        for _ in 0..1000 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * 1e-15 {
                break;
            }
        }
        (sum * (-x + a * x.ln() - ln_gamma(a)).exp()).clamp(0.0, 1.0)
    } else {
        // Continued fraction for the upper incomplete gamma Q(a,x); P = 1 - Q.
        let tiny = 1e-300;
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / tiny;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..1000 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < tiny {
                d = tiny;
            }
            c = b + an / c;
            if c.abs() < tiny {
                c = tiny;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < 1e-15 {
                break;
            }
        }
        let q = (-x + a * x.ln() - ln_gamma(a)).exp() * h;
        (1.0 - q).clamp(0.0, 1.0)
    }
}

/// Lanczos approximation of ln Γ(z) for z > 0.
fn ln_gamma(z: f64) -> f64 {
    const G: f64 = 7.0;
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    let z = z - 1.0;
    let mut a = C[0];
    let t = z + G + 0.5;
    for (i, &c) in C.iter().enumerate().skip(1) {
        a += c / (z + i as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (z + 0.5) * t.ln() - t + a.ln()
}

/// Result of a Ljung–Box portmanteau autocorrelation test.
#[derive(Debug, Clone, Copy)]
pub struct LjungBoxResult {
    pub statistic: f64,
    pub dof: usize,
    pub p_value: f64,
}

/// Ljung–Box test for serial autocorrelation in a time series up to lag `h`.
///
/// Q = n(n+2) Σ_{k=1}^{h} r_k² / (n-k), asymptotically χ²(h) under the null of
/// no autocorrelation. Small p ⇒ the series is autocorrelated.
pub fn ljung_box(x: &[f64], h: usize) -> LjungBoxResult {
    let n = x.len();
    if n < 4 || h == 0 {
        return LjungBoxResult {
            statistic: 0.0,
            dof: 0,
            p_value: 1.0,
        };
    }
    let h = h.min(n - 1);
    let mean = x.iter().sum::<f64>() / n as f64;
    let denom: f64 = x.iter().map(|v| (v - mean).powi(2)).sum();
    if denom == 0.0 {
        return LjungBoxResult {
            statistic: 0.0,
            dof: h,
            p_value: 1.0,
        };
    }
    let mut q = 0.0;
    for k in 1..=h {
        let mut num = 0.0;
        for t in k..n {
            num += (x[t] - mean) * (x[t - k] - mean);
        }
        let r_k = num / denom;
        q += r_k * r_k / (n - k) as f64;
    }
    q *= (n * (n + 2)) as f64;
    let p = chi_square_sf(q, h);
    LjungBoxResult {
        statistic: q,
        dof: h,
        p_value: p,
    }
}
