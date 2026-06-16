//! Provenance + adversary-coverage guards for the source-level GFW simulator.
//!
//! Background
//! ----------
//! The simulator under `tests/gfw_sim/` classifies TLS ClientHellos. For a long
//! time its detectors were exercised against a *synthetic* strawman ClientHello
//! (`gfw_sim::fixtures::synthetic_tls13_client_hello` — 7 ciphers, 6 extensions,
//! no GREASE) rather than the bytes the product actually emits. Judging a
//! hand-rolled stand-in instead of the real emitter is a tautology: the test can
//! pass while the real product is trivially fingerprintable.
//!
//! This file closes that gap with three layers of guard:
//!
//! 1. **Real-bytes-into-detectors bridge** — feed the *actual* Safari 26 ParallaX
//!    camouflage ClientHello through each top-level detector entry point and
//!    assert the safety-critical invariants (never `KnownProxy`, always parses,
//!    benign SNI passes / blocklisted SNI blocks).
//! 2. **Provenance diff-guard** — route the bytes a detector consumes through a
//!    single capture point and hash EXACTLY what it received, so the asserted
//!    hash is load-bearing: re-pointing the detector at the synthetic strawman
//!    changes the captured hash and fails. Backed by independent ground truth —
//!    the JA4 derived from the captured bytes must equal the EXTERNAL real-Safari
//!    26 value and must NOT equal the strawman's JA4 (the external constant is
//!    not the same buffer, so this cannot self-confirm).
//! 3. **Adversary-coverage manifest** — an in-test registry asserting every
//!    required detector processed at least one real-product observation. Adding a
//!    detector to `REQUIRED_DETECTORS` without feeding it real bytes fails here.
//!
//! All of this is test-only: nothing in `src/` is touched, and no existing test
//! is weakened. Hashing reuses the `sha2` crate (already a dependency).

mod gfw_sim;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use parallax::crypto::session::X25519KeyPair;
use parallax::tls::safari26::Safari26TlsCamouflage;

use crate::gfw_sim::detection::burst_statistics::{BurstDetector, BurstVerdict, LengthObservation};
use crate::gfw_sim::detection::fully_encrypted::{self, Exemption};
use crate::gfw_sim::detection::sni_filter::{self, SniFilter, SniVerdict};
use crate::gfw_sim::detection::tls_fingerprint::{self, fingerprint, TlsFingerprintVerdict};

// --------------------------------------------------------------------------
// Real product bytes
// --------------------------------------------------------------------------

/// Drive the REAL Safari 26 ParallaX camouflage emitter to produce the actual
/// product ClientHello bytes that go on the wire — the exact pattern used by
/// `safari_parity_baseline.rs` and `gfw_simulator.rs`. This is what every
/// detector in this file is fed, so the simulator judges the real
/// 20-cipher / 13-extension / GREASE product rather than a synthetic stand-in.
///
/// Note: the real path draws GREASE bytes, the client random, and the X25519
/// key share from `OsRng`, so two calls produce *different* byte strings. Tests
/// that need a stable buffer capture the result once and reuse the binding.
fn real_parallax_client_hello(sni: &str) -> Vec<u8> {
    let server = X25519KeyPair::generate();
    let psk = b"0123456789abcdef0123456789abcdef";
    Safari26TlsCamouflage
        .start(sni.to_owned(), psk, &server.public)
        .expect("start Safari 26 ParallaX TLS camouflage")
        .client_hello_bytes()
        .to_vec()
}

/// A benign, never-blocklisted SNI (Apple first-party origin).
const BENIGN_SNI: &str = "apple.com";

/// An SNI the simulator already treats as circumvention: `*.shadowsocks.io` is a
/// default-blocklist rule (see `gfw_sim::data::sni_blocklist` and
/// `gfw_simulator.rs::scenario_3`). Used to prove SNI extraction works on real
/// product bytes (not just on the synthetic fixture).
const BLOCKLISTED_SNI: &str = "relay7.shadowsocks.io";

/// The EXTERNAL ground-truth JA4 for real Safari 26 (FoxIO algorithm over the
/// in-tree first-party tcpdump captures). This is independent of the product:
/// the provenance guard asserts the JA4 derived from the bytes a detector
/// consumed equals THIS constant, so the check cannot be satisfied by the
/// product validating against its own buffer. Sourced from the single canonical
/// `gfw_sim::data::tls_fingerprints::SAFARI26_MACOS_JA4` so it can never desync
/// from the census `ja4_full` band (cross-checked by the census oracle's
/// `census_ja4_full_agrees_with_canonical_constant` test).
const REAL_SAFARI26_JA4: &str = gfw_sim::data::tls_fingerprints::SAFARI26_MACOS_JA4;

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Single capture point for the provenance guard: hash EXACTLY the bytes the
/// detector consumes, then run the detector on those same bytes. Because the hash
/// is taken from the slice handed to `evaluate` (not re-derived from some other
/// binding), the captured hash is load-bearing — re-pointing this call at the
/// synthetic strawman (or any other buffer) changes `captured_hash` and the
/// downstream equality fails. That is the regression this guard exists to catch.
fn evaluate_capturing(bytes: &[u8], captured_hash: &mut Option<String>) -> TlsFingerprintVerdict {
    *captured_hash = Some(sha256_hex(bytes));
    tls_fingerprint::evaluate(bytes)
}

// --------------------------------------------------------------------------
// Adversary-coverage manifest
// --------------------------------------------------------------------------

/// Every detector that MUST be shown to process at least one real-product
/// observation. Adding a detector here without wiring real bytes into it (via
/// `Coverage::record`) makes `coverage_manifest_*` fail — that is the point: a
/// new detector cannot silently ship without being fed the real emitter output.
const REQUIRED_DETECTORS: &[&str] = &[
    "tls_fingerprint",
    "sni_filter",
    "fully_encrypted",
    "burst_statistics",
];

/// Tiny in-test registry counting how many real-product observations each named
/// detector saw. Keyed by detector name; the count is the number of distinct
/// real ClientHellos (or real-derived series) fed through that detector.
#[derive(Default)]
struct Coverage {
    counts: BTreeMap<&'static str, usize>,
}

impl Coverage {
    fn record(&mut self, detector: &'static str) {
        *self.counts.entry(detector).or_insert(0) += 1;
    }

    fn count(&self, detector: &str) -> usize {
        self.counts.get(detector).copied().unwrap_or(0)
    }

    /// Assert every required detector has at least one real-product observation.
    fn assert_all_required_covered(&self) {
        for detector in REQUIRED_DETECTORS {
            assert!(
                self.count(detector) >= 1,
                "adversary-coverage gap: detector `{detector}` was never fed a \
                 real-product observation (required by REQUIRED_DETECTORS). Wire \
                 the real emitter output into it or remove it from the list.",
                detector = detector,
            );
        }
    }
}

// --------------------------------------------------------------------------
// 1. Real-bytes-into-detectors bridge
// --------------------------------------------------------------------------

/// The single most important safety invariant: the real product ClientHello must
/// (a) parse as TLS and (b) NEVER be classified `KnownProxy` by the JA3/JA4
/// fingerprint detector. If the real emitter's fingerprint ever lands in the
/// proxy table this panics — the product would be flagged on sight by the GFW.
#[test]
fn real_clienthello_is_never_known_proxy_and_always_parses() {
    let bytes = real_parallax_client_hello(BENIGN_SNI);

    // (a) must parse — never `NotTls`.
    let parsed = sni_filter::parse_client_hello(&bytes)
        .expect("real ParallaX ClientHello must parse as a TLS ClientHello");
    assert_eq!(
        parsed.sni.as_deref(),
        Some(BENIGN_SNI),
        "SNI extraction must recover the real product SNI"
    );

    // (b) top-level fingerprint verdict must never be KnownProxy, and must not be
    // NotTls. (KnownBrowser is the goal; Unknown is acceptable for the
    // simulator's logic — the hard failure is KnownProxy.)
    match tls_fingerprint::evaluate(&bytes) {
        TlsFingerprintVerdict::KnownProxy { fingerprints } => panic!(
            "SAFETY VIOLATION: real ParallaX ClientHello classified as KnownProxy \
             (ja3={}, ja4={}) — the product would be blocked on sight",
            fingerprints.ja3, fingerprints.ja4
        ),
        TlsFingerprintVerdict::NotTls => {
            panic!("real ParallaX ClientHello must not be classified NotTls")
        }
        TlsFingerprintVerdict::KnownBrowser { .. } | TlsFingerprintVerdict::Unknown { .. } => {}
    }
}

/// Prove the SNI filter's extraction + blocklist logic works on REAL product
/// bytes: a benign SNI passes, and a blocklisted SNI is blocked. If SNI
/// extraction silently failed on real bytes, the blocklisted case would fall
/// through to `Allow`/`NoSni` and this would catch it.
#[test]
fn sni_filter_passes_benign_and_blocks_blocklisted_on_real_bytes() {
    let filter = SniFilter::default();

    let benign = real_parallax_client_hello(BENIGN_SNI);
    match filter.evaluate(&benign) {
        SniVerdict::Allow { sni } => assert_eq!(sni, BENIGN_SNI),
        other => panic!("benign real ClientHello must be Allowed, got {other:?}"),
    }

    let blocked = real_parallax_client_hello(BLOCKLISTED_SNI);
    match filter.evaluate(&blocked) {
        SniVerdict::Block { sni, matched_rule } => {
            assert_eq!(sni, BLOCKLISTED_SNI);
            assert_eq!(
                matched_rule, "*.shadowsocks.io",
                "the blocklist rule that fires on real bytes must be the shadowsocks wildcard"
            );
        }
        other => panic!(
            "blocklisted real ClientHello must be Blocked (proves SNI extraction \
             works on real product bytes), got {other:?}"
        ),
    }
}

/// The USENIX'23 "fully-encrypted traffic" first-packet heuristic must EXEMPT the
/// real ClientHello via the TLS protocol fingerprint (Ex5): a real TLS record
/// starts with the handshake content type and is recognised as TLS, so the GFW's
/// random-block gate does not fire on it. This also feeds real bytes through the
/// fully_encrypted detector for coverage.
#[test]
fn fully_encrypted_exempts_real_clienthello_via_tls_fingerprint() {
    let bytes = real_parallax_client_hello(BENIGN_SNI);
    let signals = fully_encrypted::analyze(&bytes);
    assert!(
        signals.is_exempt(),
        "real ClientHello must be exempt from the fully-encrypted block gate"
    );
    assert!(
        signals
            .triggered_exemptions
            .contains(&Exemption::Ex5ProtocolFingerprint),
        "real ClientHello must trigger Ex5 (recognised as TLS), got {:?}",
        signals.triggered_exemptions
    );
    assert_eq!(
        signals.protocol_match,
        Some("TLS"),
        "the first-packet classifier must recognise the real ClientHello as TLS"
    );
}

// --------------------------------------------------------------------------
// 2. Provenance diff-guard (the novel core)
// --------------------------------------------------------------------------

/// Provenance guard (load-bearing). Route the bytes a detector consumes through a
/// single capture point ([`evaluate_capturing`]) and assert, by SHA-256, that the
/// detector received exactly the captured real-emitter buffer — re-pointing that
/// call at the synthetic strawman changes the captured hash and fails here.
///
/// The hash equality alone is necessary but not the strongest guarantee (a hash
/// of a buffer against itself is weak ground truth), so the load-bearing core is
/// independent: the JA4 derived from the bytes the detector consumed must equal
/// the EXTERNAL real-Safari-26 constant [`REAL_SAFARI26_JA4`] AND must differ
/// from the strawman's JA4. The external constant is not the same buffer, so this
/// cannot be satisfied by the product validating against its own bytes — pointing
/// the detector at the strawman makes the derived JA4 the strawman's, which is
/// `!= REAL_SAFARI26_JA4`, and the test goes red.
#[test]
fn detector_input_provenance_matches_real_emitter_via_external_ja4() {
    // The buffer the detector will consume — the real product bytes, captured once.
    let detector_input = real_parallax_client_hello(BENIGN_SNI);
    let real_hash = sha256_hex(&detector_input);

    // Feed the captured buffer through the SINGLE capture point and read back the
    // hash of exactly what the detector consumed. This binding is load-bearing:
    // it is derived inside `evaluate_capturing` from the slice handed to the
    // detector, not re-hashed from `detector_input` here.
    let mut captured = None;
    let _ = evaluate_capturing(&detector_input, &mut captured);
    let observed_input_hash = captured.expect("captured");

    // Provenance: the detector saw exactly the real-emitter buffer.
    assert_eq!(
        observed_input_hash, real_hash,
        "detector input diverged from the captured real-emitter ClientHello — \
         a detector is being fed something other than the real product bytes"
    );

    // LOAD-BEARING, non-self-referential core: parse the bytes the detector
    // consumed and derive their JA4 with the in-tree FoxIO reimplementation. It
    // must equal the EXTERNAL real-Safari-26 ground truth and must NOT equal the
    // strawman's JA4. (Independent of the captured buffer, so it cannot self-pass.)
    let real_parsed = sni_filter::parse_client_hello(&detector_input).expect("real parses");
    let real_ja4 = fingerprint(&real_parsed).ja4;
    assert_eq!(
        real_ja4, REAL_SAFARI26_JA4,
        "JA4 derived from the bytes the detector consumed must equal the external \
         real-Safari-26 ground truth — if a detector is fed the strawman (or the \
         product fingerprint drifts) this fails"
    );

    let strawman = gfw_sim::fixtures::synthetic_tls13_client_hello(BENIGN_SNI, 7);
    let strawman_parsed = sni_filter::parse_client_hello(&strawman).expect("strawman parses");
    let strawman_ja4 = fingerprint(&strawman_parsed).ja4;
    assert_ne!(
        real_ja4, strawman_ja4,
        "the real-emitter JA4 must differ from the synthetic strawman's JA4 — \
         equal JA4s would mean the detector is judging the stand-in, not the product"
    );

    // SECONDARY structural sanity (NOT the load-bearing guard): the real-emitter
    // buffer hash differs from the strawman hash across several strawman seeds.
    // This compares two local generators, so on its own it does not guard detector
    // wiring (that is what the external-JA4 check above is for) — it only confirms
    // the real bytes and the stand-in are genuinely distinct byte strings.
    for seed in [0u64, 7, 0xC0FFEE, 1001, 3003] {
        let strawman_seeded = gfw_sim::fixtures::synthetic_tls13_client_hello(BENIGN_SNI, seed);
        assert_ne!(
            real_hash,
            sha256_hex(&strawman_seeded),
            "structural sanity: real-emitter ClientHello hash equals the synthetic \
             strawman (seed={seed})",
        );
    }

    // Structural sanity: the real product carries strictly more ciphers (20) than
    // the strawman (7), so the inequalities reflect a genuine product/stand-in gap.
    assert!(
        real_parsed.cipher_suites.len() > strawman_parsed.cipher_suites.len(),
        "real product ({} ciphers) must be richer than the synthetic strawman ({} ciphers)",
        real_parsed.cipher_suites.len(),
        strawman_parsed.cipher_suites.len(),
    );
}

// --------------------------------------------------------------------------
// 3. Adversary-coverage manifest
// --------------------------------------------------------------------------

/// Derive a real-product length series for the burst detector directly from the
/// real ClientHello bytes: chunk the actual emitter output into browser-sized
/// TLS records. These are *real-product-derived* lengths (not invented numbers),
/// so the burst detector is exercised on genuine product data.
fn real_product_length_series(bytes: &[u8]) -> Vec<LengthObservation> {
    let start = Instant::now();
    bytes
        .chunks(1200)
        .enumerate()
        .map(|(i, chunk)| LengthObservation {
            length: chunk.len(),
            at: start + Duration::from_millis(i as u64 * 4),
            // The ClientHello is a client-to-server record.
            client_to_server: true,
        })
        .collect()
}

/// The coverage manifest. Run every required detector against the real product,
/// record each observation, and assert full coverage. This is the guard that
/// fails when a detector is added to `REQUIRED_DETECTORS` but never fed real
/// bytes — preventing a detector from shipping un-exercised against the product.
#[test]
fn coverage_manifest_every_required_detector_sees_real_product() {
    let mut coverage = Coverage::default();

    // tls_fingerprint: real bytes -> verdict, asserted non-proxy / non-NotTls.
    {
        let bytes = real_parallax_client_hello(BENIGN_SNI);
        let verdict = tls_fingerprint::evaluate(&bytes);
        assert!(
            !matches!(verdict, TlsFingerprintVerdict::KnownProxy { .. }),
            "real product must not be KnownProxy in the coverage pass"
        );
        assert!(
            !matches!(verdict, TlsFingerprintVerdict::NotTls),
            "real product must parse in the coverage pass"
        );
        coverage.record("tls_fingerprint");
    }

    // sni_filter: real bytes through the default filter, benign SNI allowed.
    {
        let bytes = real_parallax_client_hello(BENIGN_SNI);
        let verdict = SniFilter::default().evaluate(&bytes);
        assert!(
            matches!(verdict, SniVerdict::Allow { .. }),
            "real product with benign SNI must be Allowed in the coverage pass, got {verdict:?}"
        );
        coverage.record("sni_filter");
    }

    // fully_encrypted: real bytes are exempt (Ex5 TLS fingerprint).
    {
        let bytes = real_parallax_client_hello(BENIGN_SNI);
        let signals = fully_encrypted::analyze(&bytes);
        assert!(
            signals.is_exempt(),
            "real product must be exempt from the fully-encrypted gate in the coverage pass"
        );
        coverage.record("fully_encrypted");
    }

    // burst_statistics: real-product-derived length series must not match a known
    // proxy centroid (a single ClientHello burst is not proxy-shaped).
    {
        let bytes = real_parallax_client_hello(BENIGN_SNI);
        let series = real_product_length_series(&bytes);
        assert!(
            !series.is_empty(),
            "real-product length series must contain at least one observation"
        );
        let verdict = BurstDetector::default().evaluate(&series);
        assert!(
            !matches!(verdict, BurstVerdict::LooksLikeProxy { .. }),
            "real ClientHello length series must not match a proxy centroid, got {verdict:?}"
        );
        coverage.record("burst_statistics");
    }

    // The manifest gate: every required detector saw >= 1 real-product observation.
    coverage.assert_all_required_covered();

    // Defensive: the recorded coverage set must cover exactly the required set
    // (no required detector silently missing). Extra detectors are allowed.
    for detector in REQUIRED_DETECTORS {
        assert!(
            coverage.count(detector) >= 1,
            "required detector `{detector}` missing from coverage after the manifest run"
        );
    }
}
