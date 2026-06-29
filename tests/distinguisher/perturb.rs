//! Known-perturbation injectors for the discriminability self-proof.
//!
//! A distinguisher battery is only trustworthy if it *fires* on a difference we
//! deliberately introduce. These functions take a real Safari [`Trace`] and bend
//! one feature dimension into a known proxy pathology; the battery must then
//! reject the perturbed trace (KS p→0, separability→0.5). If it does not, the
//! battery is blind on that dimension and any "indistinguishable" verdict it
//! produces elsewhere is worthless.
//!
//! Every injector is deterministic.

use super::trace::{Dir, Record, Trace};

/// Deterministic 64-bit LCG, local to this module (no `rand` dependency).
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed)
    }
    fn next_f64(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The "1:1 ACK" pathology: rewrite the stream so every C2S record is
/// immediately followed by exactly one S2C record (strict lockstep), the way a
/// transparent relay that ACKs each uplink record looks. This collapses
/// direction-run lengths to 1 and pins the ACK ratio to 1.0 — the exact tell
/// the user called out.
pub fn force_1to1_ack(trace: &Trace) -> Trace {
    let c2s: Vec<Record> = trace.dir(Dir::C2S);
    // A representative S2C length to clone for the synthetic ACKs.
    let s2c_len = trace
        .records
        .iter()
        .find(|r| r.dir == Dir::S2C)
        .map(|r| r.len)
        .unwrap_or(60);
    let mut out = Vec::with_capacity(c2s.len() * 2);
    let mut t = 0u64;
    for r in c2s {
        out.push(Record {
            len: r.len,
            dir: Dir::C2S,
            t_micros: t,
        });
        t += 200; // 0.2 ms later: the lockstep ACK
        out.push(Record {
            len: s2c_len,
            dir: Dir::S2C,
            t_micros: t,
        });
        t += 1_000;
    }
    Trace::new(out)
}

/// Scale every record length by `factor` (e.g. 0.5 ⇒ half-size records). Shifts
/// the length distribution wholesale so the length-KS test must reject.
pub fn resize_records(trace: &Trace, factor: f64) -> Trace {
    let records = trace
        .records
        .iter()
        .map(|r| Record {
            len: ((r.len as f64 * factor).round() as u32).max(1),
            ..*r
        })
        .collect();
    Trace::new(records)
}

/// Add multiplicative jitter to inter-arrival times: each record's timestamp is
/// the previous one plus the original gap scaled by a per-record random factor
/// in `[1-amount, 1+amount]`. Perturbs IAT distribution and autocorrelation
/// without touching lengths or directions.
pub fn jitter_iat(trace: &Trace, amount: f64, seed: u64) -> Trace {
    let mut rng = Lcg::new(seed);
    let mut out = Vec::with_capacity(trace.records.len());
    let mut prev_orig: Option<u64> = None;
    let mut t = 0u64;
    for r in &trace.records {
        let gap = match prev_orig {
            Some(p) => r.t_micros.saturating_sub(p),
            None => 0,
        };
        let f = 1.0 - amount + 2.0 * amount * rng.next_f64();
        t += (gap as f64 * f).round() as u64;
        out.push(Record {
            len: r.len,
            dir: r.dir,
            t_micros: t,
        });
        prev_orig = Some(r.t_micros);
    }
    Trace::new(out)
}
