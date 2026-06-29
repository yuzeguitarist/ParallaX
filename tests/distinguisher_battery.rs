//! Statistical distinguisher battery — integration driver.
//!
//! Four tiers (see `tests/distinguisher/mod.rs` for the methodology):
//!
//! 1. **Unit self-checks (fast)** — feed synthetic known distributions to KS /
//!    chi-squared / Ljung-Box / AUC and assert they behave (same ⇒ p>0.05,
//!    different ⇒ p<0.01; separable ⇒ AUC≈1, identical ⇒ AUC≈0.5). Proves the
//!    machinery is correct before trusting any verdict it gives.
//! 2. **Self-test (fast)** — split the real Safari corpus in two and confirm the
//!    battery finds it indistinguishable from itself (KS p>0.05, AUC∈[0.45,0.55]).
//!    If the battery is biased against its own ground truth, every downstream
//!    verdict is void.
//! 3. **Discriminability self-proof (fast)** — inject a known perturbation
//!    (1:1-ACK, record resize) into half the corpus and assert the battery FIRES
//!    (KS p→0, AUC→1). Proves it has discriminating power, not just low variance.
//! 4. **ParallaX vs Safari (length, fast)** — drive ParallaX's production record
//!    encoder, compare its uplink record-length distribution to Safari's, and
//!    report the KS verdict. The richer socket-level timing/direction comparison
//!    is an `#[ignore]` placeholder pending an end-to-end authenticated harness.

mod distinguisher;

use distinguisher::classifier::{cross_validated_auc, roc_auc, separability, Sample};
use distinguisher::features::{self, window_features};
use distinguisher::parallax_source;
use distinguisher::perturb;
use distinguisher::safari_h3_source;
use distinguisher::safari_quic_source;
use distinguisher::safari_source;
use distinguisher::stats::{chi_square_gof, ljung_box, two_sample_ks};
use distinguisher::trace::{Dir, Trace};
use distinguisher::udp_capture;

/// Records-per-window for classifier feature rows. ~1528 Safari records / 30 ≈
/// 50 rows, enough for a stable 5-fold CV-AUC.
const WINDOW: usize = 30;
const FOLDS: usize = 5;

/// Deterministic LCG for synthetic-distribution generation in the unit tier.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed)
    }
    fn unit(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Approx-normal via central limit (sum of 12 uniforms − 6).
    fn normal(&mut self, mean: f64, sd: f64) -> f64 {
        let s: f64 = (0..12).map(|_| self.unit()).sum::<f64>() - 6.0;
        mean + sd * s
    }
}

// ---------------------------------------------------------------------------
// Tier 1: unit self-checks on synthetic data.
// ---------------------------------------------------------------------------

#[test]
fn ks_separates_known_distributions() {
    let mut rng = Lcg::new(1);
    let a: Vec<f64> = (0..400).map(|_| rng.normal(100.0, 10.0)).collect();
    let b: Vec<f64> = (0..400).map(|_| rng.normal(100.0, 10.0)).collect();
    let c: Vec<f64> = (0..400).map(|_| rng.normal(160.0, 10.0)).collect();

    let same = two_sample_ks(&a, &b);
    let diff = two_sample_ks(&a, &c);

    assert!(same.p_value > 0.05, "same-dist KS p too low: {:?}", same);
    assert!(diff.p_value < 0.01, "diff-dist KS p too high: {:?}", diff);
    assert!(diff.statistic > same.statistic);
}

#[test]
fn chi_square_flags_skewed_histogram() {
    // Uniform expected over 5 bins, n=500.
    let expected = vec![100.0; 5];
    let uniform_obs = vec![98.0, 102.0, 100.0, 101.0, 99.0];
    let skewed_obs = vec![200.0, 50.0, 50.0, 100.0, 100.0];

    let flat = chi_square_gof(&uniform_obs, &expected);
    let skew = chi_square_gof(&skewed_obs, &expected);

    assert!(flat.p_value > 0.05, "flat hist flagged: {:?}", flat);
    assert!(skew.p_value < 0.01, "skewed hist not flagged: {:?}", skew);
}

#[test]
fn ljung_box_detects_autocorrelation() {
    let mut rng = Lcg::new(7);
    // White noise: no autocorrelation.
    let white: Vec<f64> = (0..300).map(|_| rng.normal(0.0, 1.0)).collect();
    // AR(1) with phi=0.8: strong autocorrelation.
    let mut ar = vec![0.0; 300];
    let mut prev = 0.0;
    for v in ar.iter_mut() {
        let e = rng.normal(0.0, 1.0);
        *v = 0.8 * prev + e;
        prev = *v;
    }

    let w = ljung_box(&white, 10);
    let a = ljung_box(&ar, 10);
    assert!(
        w.p_value > 0.05,
        "white noise flagged autocorrelated: {:?}",
        w
    );
    assert!(a.p_value < 0.01, "AR(1) not flagged: {:?}", a);
}

#[test]
fn auc_is_one_for_separable_and_half_for_identical() {
    let mut rng = Lcg::new(11);
    // Separable: class 0 ~ N(0,1), class 1 ~ N(5,1) on one feature.
    let mut separable = Vec::new();
    for _ in 0..80 {
        separable.push(Sample {
            features: vec![rng.normal(0.0, 1.0)],
            label: 0,
        });
        separable.push(Sample {
            features: vec![rng.normal(5.0, 1.0)],
            label: 1,
        });
    }
    // Identical: both classes ~ N(0,1) — no signal.
    let mut identical = Vec::new();
    for _ in 0..80 {
        identical.push(Sample {
            features: vec![rng.normal(0.0, 1.0)],
            label: 0,
        });
        identical.push(Sample {
            features: vec![rng.normal(0.0, 1.0)],
            label: 1,
        });
    }

    let sep_auc = cross_validated_auc(&separable, FOLDS);
    let id_auc = cross_validated_auc(&identical, FOLDS);

    assert!(sep_auc > 0.9, "separable AUC too low: {sep_auc}");
    assert!(
        (id_auc - 0.5).abs() < 0.12,
        "identical AUC not near 0.5: {id_auc}"
    );
}

#[test]
fn roc_auc_handles_ties_and_perfect_ranking() {
    // Perfect ranking.
    let perfect = vec![(0.1, 0), (0.2, 0), (0.8, 1), (0.9, 1)];
    assert!((roc_auc(&perfect) - 1.0).abs() < 1e-9);
    // All tied scores ⇒ AUC 0.5.
    let tied = vec![(0.5, 0), (0.5, 1), (0.5, 0), (0.5, 1)];
    assert!((roc_auc(&tied) - 0.5).abs() < 1e-9);
}

// ---------------------------------------------------------------------------
// Helpers for tiers 2–4: build classifier samples from two traces.
// ---------------------------------------------------------------------------

/// Build labelled per-window samples: label 0 from `a`, label 1 from `b`.
fn samples_from(a: &Trace, b: &Trace) -> Vec<Sample> {
    let mut s: Vec<Sample> = window_features(a, WINDOW)
        .into_iter()
        .map(|features| Sample { features, label: 0 })
        .collect();
    s.extend(
        window_features(b, WINDOW)
            .into_iter()
            .map(|features| Sample { features, label: 1 }),
    );
    s
}

/// Randomly partition a trace's records into two sub-traces sharing the same
/// generating process — the self-test null. A deterministic LCG drives a coin
/// flip per record. (An even/odd split is wrong here: the Safari uplink
/// alternates 44 B/30 B control records in lockstep, so index parity would
/// systematically sort the two lengths into opposite halves and manufacture a
/// difference where there is none — a lesson the battery taught us directly.)
fn split_halves(trace: &Trace) -> (Trace, Trace) {
    let mut rng = Lcg::new(0xd157_2026);
    let mut a = Vec::new();
    let mut b = Vec::new();
    for r in &trace.records {
        if rng.unit() < 0.5 {
            a.push(*r);
        } else {
            b.push(*r);
        }
    }
    (Trace::new(a), Trace::new(b))
}

fn load_safari() -> Trace {
    safari_source::load_fixture().expect("load Safari TCP fixture")
}

// ---------------------------------------------------------------------------
// Tier 2: self-test — Safari is indistinguishable from itself.
// ---------------------------------------------------------------------------

#[test]
fn self_test_safari_is_indistinguishable_from_itself() {
    let safari = load_safari();
    let (a, b) = split_halves(&safari);

    // KS on C2S lengths: same source ⇒ high p.
    let ks = two_sample_ks(&a.lengths(Dir::C2S), &b.lengths(Dir::C2S));
    assert!(
        ks.p_value > 0.05,
        "self-test length KS rejected same source: D={:.4} p={:.4}",
        ks.statistic,
        ks.p_value
    );

    // Classifier AUC must sit in the documented indistinguishability gate. This
    // is the contract from the module header and PR — no fallback escape hatch.
    // Deterministic (fixed LCG seed + fixed corpus), so the measured AUC is
    // stable rather than flaky; `separability` is reported for diagnostics only.
    let samples = samples_from(&a, &b);
    let auc = cross_validated_auc(&samples, FOLDS);
    assert!(
        (0.45..=0.55).contains(&auc),
        "self-test AUC not near chance: {auc} (separability={:.4}, n={})",
        separability(&samples, FOLDS),
        samples.len()
    );
}

// ---------------------------------------------------------------------------
// Tier 3: discriminability self-proof — known perturbations must fire.
// ---------------------------------------------------------------------------

#[test]
fn detects_1to1_ack_pathology() {
    let safari = load_safari();
    let perturbed = perturb::force_1to1_ack(&safari);

    // The "1:1 ACK" tell is NOT the count ratio — the battery measured the real
    // Safari S2C/C2S ratio at 1.045, i.e. genuinely ~1:1, so "ratio ≈ 1.0" would
    // falsely flag the real browser. The tell is the *structure* of the
    // direction-run lengths: a strict-lockstep relay has every same-direction
    // run pinned to length 1, whereas a real browser bursts (runs > 1). We prove
    // the battery fires on that structural difference.
    let real_runs = features::direction_runs(&safari);
    let bad_runs = features::direction_runs(&perturbed);

    // Sanity: the pathology really does collapse runs to 1, and the real stream
    // does not (otherwise the test below would be vacuous).
    let real_max_run = real_runs.iter().cloned().fold(0.0, f64::max);
    let bad_max_run = bad_runs.iter().cloned().fold(0.0, f64::max);
    assert!(
        bad_max_run <= 1.0,
        "lockstep should pin runs to 1, got max {bad_max_run}"
    );
    assert!(
        real_max_run > 1.0,
        "real Safari runs unexpectedly all length 1"
    );

    let ks = two_sample_ks(&real_runs, &bad_runs);
    assert!(
        ks.p_value < 0.01,
        "1:1-ACK direction-run KS failed to fire: D={:.4} p={:.4}",
        ks.statistic,
        ks.p_value
    );

    // Classifier must separate real vs perturbed on the full feature vector.
    let samples = samples_from(&safari, &perturbed);
    let auc = cross_validated_auc(&samples, FOLDS);
    assert!(
        separability(&samples, FOLDS) > 0.25,
        "1:1-ACK AUC failed to fire: {auc}"
    );
}

#[test]
fn detects_record_resize() {
    let safari = load_safari();
    let halved = perturb::resize_records(&safari, 0.5);

    let ks = two_sample_ks(&safari.lengths(Dir::C2S), &halved.lengths(Dir::C2S));
    assert!(
        ks.p_value < 0.01,
        "record-resize length KS failed to fire: D={:.4} p={:.4}",
        ks.statistic,
        ks.p_value
    );
}

// ---------------------------------------------------------------------------
// Tier 4: ParallaX vs Safari — length dimension via the production encoder.
// ---------------------------------------------------------------------------

#[test]
fn parallax_vs_safari_uplink_length_distribution() {
    // Use the BIG-POST corpus: it has the real ~900 full 16401-byte uplink
    // records that the data plane is tuned to match. The control-frame fixture
    // has no large POST and is not length-comparable to ParallaX's pure-data
    // uplink (the battery surfaced this directly).
    let safari = safari_source::load_bigpost().expect("load Safari big-POST fixture");
    let safari_c2s = safari.lengths(Dir::C2S);
    let total_bytes: u64 = safari_c2s.iter().map(|&l| l as u64).sum();

    // Drive ParallaX's production record encoder over a payload of the same
    // total uplink volume Safari sent, so the record-count regimes are
    // comparable. The payload content is irrelevant to record sizing.
    let payload = vec![0x5a_u8; total_bytes as usize];
    let parallax = parallax_source::uplink_trace(&payload);
    let parallax_c2s = parallax.lengths(Dir::C2S);

    let ks = two_sample_ks(&safari_c2s, &parallax_c2s);

    // Report — this tier observes and prints; the gate is informational because
    // the two corpora have legitimately different *small-record* tails (Safari's
    // H2 control frames vs ParallaX's pure-data uplink). The headline check is
    // that the FULL-record regime matches exactly.
    let safari_full = safari_c2s.iter().filter(|&&l| l >= 16000.0).count();
    let parallax_full = parallax_c2s.iter().filter(|&&l| l >= 16000.0).count();
    eprintln!(
        "[tier4-length] Safari C2S n={} (full≥16000:{}), ParallaX C2S n={} (full≥16000:{}); \
         KS D={:.4} p={:.4}",
        safari_c2s.len(),
        safari_full,
        parallax_c2s.len(),
        parallax_full,
        ks.statistic,
        ks.p_value
    );

    // Hard assertions on the deliberately-matched 16401 full-record regime.
    //
    // We pin the literal 16401 as the *modal* (most-common) record length in
    // both corpora, rather than requiring every >=16000 record to equal it.
    // Both corpora legitimately carry non-16401 near-full records: Safari's H2
    // DATA framing leaves a tail of 16340..16400, and ParallaX's `seal_chunks`
    // emits one short remainder record at the end of the payload. The matched
    // regime claim is that the *full* record — the dominant bucket — is exactly
    // 16401 on both sides, byte-for-byte.
    const FULL_RECORD_LEN: u32 = 16401;
    let modal_len = |lens: &[f64]| -> (u32, usize) {
        let mut counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
        for &l in lens {
            *counts.entry(l as u32).or_default() += 1;
        }
        counts.into_iter().max_by_key(|&(_, c)| c).unwrap_or((0, 0))
    };
    let (safari_modal, safari_modal_n) = modal_len(&safari_c2s);
    let (parallax_modal, parallax_modal_n) = modal_len(&parallax_c2s);

    assert_eq!(
        parallax_modal, FULL_RECORD_LEN,
        "ParallaX modal record length {parallax_modal} (×{parallax_modal_n}) != {FULL_RECORD_LEN}"
    );
    assert_eq!(
        safari_modal, FULL_RECORD_LEN,
        "Safari modal record length {safari_modal} (×{safari_modal_n}) != {FULL_RECORD_LEN}"
    );
}

// ---------------------------------------------------------------------------
// Tier 5: direction-interleave structure (UDP/H3 layer).
//
// Scope is deliberate (see udp_capture / safari_h3_source docs): we gate on
// datagram DIRECTION structure and SIZE — both wire-faithful on loopback — and
// never on inter-arrival time, whose absolute value is host-scheduling noise.
// ---------------------------------------------------------------------------

/// Fast tier: the direction-interleave distinguisher must fire on the 1:1-ACK
/// pathology against the real Safari H3 datagram trace. This proves the
/// direction-run dimension has discriminating power before we trust any
/// "indistinguishable" verdict from the live capture.
#[test]
fn h3_direction_runs_detect_lockstep() {
    let safari = safari_h3_source::load_fixture().expect("load Safari H3 fixture");
    let lockstep = perturb::force_1to1_ack(&safari);

    let real_runs = features::direction_runs(&safari);
    let bad_runs = features::direction_runs(&lockstep);

    // The pathology pins every run to length 1; the real browser bursts.
    let real_max = real_runs.iter().cloned().fold(0.0, f64::max);
    let bad_max = bad_runs.iter().cloned().fold(0.0, f64::max);
    assert!(
        bad_max <= 1.0,
        "lockstep should pin runs to 1, got {bad_max}"
    );
    assert!(
        real_max > 1.0,
        "real Safari H3 runs unexpectedly all length 1"
    );

    let ks = two_sample_ks(&real_runs, &bad_runs);
    assert!(
        ks.p_value < 0.05,
        "H3 direction-run KS failed to fire on lockstep: D={:.4} p={:.4}",
        ks.statistic,
        ks.p_value
    );
}

/// Tier 5b (live): capture a real ParallaX QUIC session at the UDP-datagram
/// layer through the recording forwarder, and compare its uplink direction-run
/// and datagram-size distributions to Safari H3. Reports KS for both. IAT is
/// printed for context only and never asserted on.
#[tokio::test]
#[ignore = "live QUIC loopback capture; run with --ignored --test-threads=1"]
async fn parallax_vs_safari_h3_direction_and_size() {
    let safari = safari_h3_source::load_fixture().expect("load Safari H3 fixture");

    // Transfer volumes loosely matched to the Safari H3 capture so the datagram
    // counts are comparable; content is irrelevant to size/direction.
    let parallax = udp_capture::capture_parallax_quic_trace(64 * 1024, 64 * 1024)
        .await
        .expect("capture ParallaX QUIC trace");

    // Direction-interleave structure (wire-faithful).
    let safari_runs = features::direction_runs(&safari);
    let parallax_runs = features::direction_runs(&parallax);
    let runs_ks = two_sample_ks(&safari_runs, &parallax_runs);

    // Datagram-size distribution, C2S (uplink) — the imitated direction.
    let safari_up = safari.lengths(Dir::C2S);
    let parallax_up = parallax.lengths(Dir::C2S);
    let size_ks = two_sample_ks(&safari_up, &parallax_up);

    eprintln!(
        "[tier5-h3] Safari datagrams n={} (C2S {}), ParallaX n={} (C2S {})",
        safari.len(),
        safari_up.len(),
        parallax.len(),
        parallax_up.len()
    );
    eprintln!(
        "[tier5-h3] direction-run KS D={:.4} p={:.4} | C2S size KS D={:.4} p={:.4}",
        runs_ks.statistic, runs_ks.p_value, size_ks.statistic, size_ks.p_value
    );
    // IAT printed for context ONLY — not a gate (loopback wall-clock is noise).
    let safari_iat = safari.iats(Dir::C2S);
    let parallax_iat = parallax.iats(Dir::C2S);
    if !safari_iat.is_empty() && !parallax_iat.is_empty() {
        let iat_ks = two_sample_ks(&safari_iat, &parallax_iat);
        eprintln!(
            "[tier5-h3] (context only, NOT gated) C2S IAT KS D={:.4} p={:.4}",
            iat_ks.statistic, iat_ks.p_value
        );
    }

    // Sanity gate only: the capture must have produced a usable *bidirectional*
    // trace — datagrams in BOTH directions, not just C2S (direction_runs() is
    // non-empty for any non-empty trace, so it alone would accept a one-way
    // capture). We do not gate on the KS verdicts themselves yet — loopback
    // datagram distributions need calibration before a hard threshold, exactly
    // as the length tier was left informational first.
    let c2s = parallax.dir(Dir::C2S).len();
    let s2c = parallax.dir(Dir::S2C).len();
    assert!(
        c2s >= 1 && s2c >= 1,
        "ParallaX capture not bidirectional: C2S={c2s} S2C={s2c}"
    );
}

// ---------------------------------------------------------------------------
// Tier 6: QUIC direction/size CALIBRATION against the large real-traffic
// corpus (~6k datagrams), using an interactive request/response capture.
//
// Tier 5's bulk capture streams one big payload each way, producing a single
// uplink burst then a single downlink burst — which inflates the direction-run
// KS against a browser that interleaves many small turns. This tier (a) compares
// against the high-volume QUIC corpus instead of the ~55-datagram H3 sample, and
// (b) drives an interactive ping-pong so ParallaX's own direction interleave is
// browser-shaped. It quantifies how much of the earlier divergence was a capture
// artifact versus a genuine gap. Size + direction only; IAT is context-only.
// ---------------------------------------------------------------------------

/// A browser-like exchange schedule: many small request turns, each answered by
/// a small-to-medium response. Deterministic (index-driven) so the capture is
/// reproducible. ~20 turns is enough to build a direction-run distribution
/// comparable to the real corpus without a multi-second test.
fn browser_like_schedule() -> Vec<udp_capture::Exchange> {
    // Response sizes cycle through a realistic spread (1–8 KB); requests stay
    // small (~500 B), as a typical HTTP/3 GET would.
    const RESPONSES: [usize; 5] = [1200, 3500, 8000, 600, 5000];
    (0..20)
        .map(|i| udp_capture::Exchange {
            request_bytes: 500,
            response_bytes: RESPONSES[i % RESPONSES.len()],
        })
        .collect()
}

#[tokio::test]
#[ignore = "live QUIC loopback capture; run with --ignored --test-threads=1"]
async fn quic_direction_size_calibration_vs_real_corpus() {
    let safari = safari_quic_source::load_fixture().expect("load Safari QUIC corpus");

    // Interactive (browser-shaped) capture — the calibrated comparison.
    let interactive = udp_capture::capture_parallax_quic_interactive(&browser_like_schedule())
        .await
        .expect("interactive QUIC capture");

    // Bulk single-shot capture — the old, uncalibrated shape, for contrast.
    let bulk = udp_capture::capture_parallax_quic_trace(64 * 1024, 64 * 1024)
        .await
        .expect("bulk QUIC capture");

    let ks_runs = |p: &Trace| {
        two_sample_ks(
            &features::direction_runs(&safari),
            &features::direction_runs(p),
        )
    };
    let ks_size = |p: &Trace| two_sample_ks(&safari.lengths(Dir::C2S), &p.lengths(Dir::C2S));

    let bulk_runs = ks_runs(&bulk);
    let int_runs = ks_runs(&interactive);
    let bulk_size = ks_size(&bulk);
    let int_size = ks_size(&interactive);

    eprintln!(
        "[tier6-cal] Safari QUIC corpus n={} (C2S {} / S2C {})",
        safari.len(),
        safari.dir(Dir::C2S).len(),
        safari.dir(Dir::S2C).len()
    );
    eprintln!(
        "[tier6-cal] direction-run KS:  bulk D={:.4} p={:.4}  ->  interactive D={:.4} p={:.4}",
        bulk_runs.statistic, bulk_runs.p_value, int_runs.statistic, int_runs.p_value
    );
    eprintln!(
        "[tier6-cal] C2S size KS:       bulk D={:.4} p={:.4}  ->  interactive D={:.4} p={:.4}",
        bulk_size.statistic, bulk_size.p_value, int_size.statistic, int_size.p_value
    );

    // Sanity gate only (same posture as Tier 5): the interactive capture must be
    // genuinely bidirectional. KS values stay informational — this tier exists
    // to MEASURE the gap, not to gate on a threshold that loopback distributions
    // have not yet been calibrated to support.
    let c2s = interactive.dir(Dir::C2S).len();
    let s2c = interactive.dir(Dir::S2C).len();
    assert!(
        c2s >= 1 && s2c >= 1,
        "interactive capture not bidirectional: C2S={c2s} S2C={s2c}"
    );
}
