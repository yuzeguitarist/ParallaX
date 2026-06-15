//! JA4 / JA4H "census-membership" oracle keyed to REAL product bytes.
//!
//! This is Phase 1 item #7. Where `safari_parity_baseline.rs` asserts the
//! product is byte-equal to one fixture (a strong but self-referential check),
//! this file asserts something with independent provenance: that the live
//! product's fingerprint fields equal the captured real-Safari values, computed
//! via an INDEPENDENT FoxIO JA4 reimplementation (the in-tree `gfw_sim` parser),
//! and that the oracle has discriminating power (a known proxy fingerprint falls
//! outside the captured value on at least one axis).
//!
//! Honest scope
//! ------------
//! As of the census date every band holds exactly ONE captured value (the two
//! first-party captures agree on every JA4_a axis), so `FieldBand::contains` is
//! point-equality and the live checks are *fixture-anchored equality*: ground
//! truth is the in-tree tcpdump captures + the independent parser, NOT the
//! product validating against itself. We deliberately do NOT claim "is a member
//! of a distribution band" or "is not a statistical outlier" here — those need a
//! SECOND independent real Safari capture per axis and are future work. The
//! corroboration we DO assert is provenance multiplicity: each first-party band
//! names >= 2 independent provenance entries for its captured value.
//!
//! The census lives in `tests/support/census.rs` as a dated, provenanced data
//! structure (zero deps — no toml/serde needed). Each band carries >= 2
//! provenance entries naming concrete Safari builds; a loader test rejects any
//! band that violates that discipline.
//!
//! Layout of the assertions:
//!
//! - `census_loader_*`: provenance discipline is enforced.
//! - `live_*_is_member_*`: live product fields equal the captured value, across
//!   SNIs + GREASE draws.
//! - `live_membership_is_corroborated_*`: the matched value rests on >= 2
//!   independent provenance sources (not statistical non-outlier-ness).
//! - `anti_inversion_*`: disagreement with an INFERRED band WARNs and passes;
//!   disagreement with a first-party band fails. Never satisfiable by mutating
//!   the product toward an unverified value.
//! - `negative_control_*`: a known-proxy JA4 falls OUTSIDE at least one band,
//!   and an over-broadened band would let it back in (the guardrail is itself
//!   tested).
//! - `live_h2_*`: H2 SETTINGS id-set/order + WINDOW_UPDATE equal the captured
//!   values.
//!
//! Nothing in `src/` is touched and no existing test is weakened.

#[path = "support/census.rs"]
mod census;
#[path = "gfw_sim/mod.rs"]
mod gfw_sim;

use parallax::crypto::session::X25519KeyPair;
use parallax::fingerprint::http2::Http2Fingerprint;
use parallax::tls::safari26::Safari26TlsCamouflage;

use crate::census::{
    anti_inversion_decision, safari_census, FieldBand, MembershipOutcome, Provenance, Trust,
};
use crate::gfw_sim::detection::sni_filter::{parse_client_hello, ParsedClientHello, EXT_ALPN};
use crate::gfw_sim::detection::tls_fingerprint::{fingerprint, is_grease};

const EXT_SERVER_NAME: u16 = 0x0000;

// --------------------------------------------------------------------------
// Live product bytes (the exact pattern from safari_parity_baseline.rs).
// --------------------------------------------------------------------------

/// Drive the REAL Safari 26 ParallaX camouflage emitter and return its actual
/// ClientHello bytes. GREASE / client-random / key-share are drawn from `OsRng`,
/// so successive calls differ in those positions but agree on every JA4_a axis.
fn live_client_hello(sni: &str) -> Vec<u8> {
    let server = X25519KeyPair::generate();
    let psk = b"0123456789abcdef0123456789abcdef";
    Safari26TlsCamouflage
        .start(sni.to_owned(), psk, &server.public)
        .expect("start Safari 26 ParallaX TLS camouflage")
        .client_hello_bytes()
        .to_vec()
}

/// Several real origins to vary SNI across samples.
const SAMPLE_SNIS: &[&str] = &["apple.com", "cloudflare.com", "www.icloud.com"];

// --------------------------------------------------------------------------
// JA4_a field extraction over a parsed (real) ClientHello.
// --------------------------------------------------------------------------

/// The JA4_a-relevant scalar/structural fields, recomputed the same way the
/// FoxIO algorithm + the in-tree `tls_fingerprint` module do (GREASE stripped,
/// section-2 extensions exclude SNI/ALPN, sig-algs keep wire order).
struct Ja4Fields {
    version: &'static str,
    n_ciphers: usize,
    n_exts: usize,
    alpn_pair: &'static str,
    cipher_set_sorted: Vec<u16>,
    ext_set_sorted_no_sni_alpn: Vec<u16>,
    sig_alg_order: Vec<u16>,
}

fn ja4_fields(parsed: &ParsedClientHello) -> Ja4Fields {
    let ciphers: Vec<u16> = parsed
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let exts: Vec<u16> = parsed
        .extensions_order
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();
    let sig_alg_order: Vec<u16> = parsed
        .signature_algorithms
        .iter()
        .copied()
        .filter(|s| !is_grease(*s))
        .collect();

    let mut cipher_set_sorted = ciphers.clone();
    cipher_set_sorted.sort_unstable();

    let mut ext_set_sorted_no_sni_alpn: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|e| *e != EXT_SERVER_NAME && *e != EXT_ALPN)
        .collect();
    ext_set_sorted_no_sni_alpn.sort_unstable();

    // Highest non-GREASE supported_version maps to the JA4 two-char version.
    let version = match parsed
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(parsed.legacy_version)
    {
        0x0304 => "13",
        0x0303 => "12",
        _ => "00",
    };

    // ALPN first/last pair, e.g. "h2" -> "h2".
    let alpn_pair = match parsed.alpn.iter().find(|p| !p.is_empty()) {
        Some(first) if first == "h2" => "h2",
        Some(first) if first == "http/1.1" => "h1",
        Some(_) => "xx",
        None => "00",
    };

    Ja4Fields {
        version,
        n_ciphers: ciphers.len(),
        n_exts: exts.len(),
        alpn_pair,
        cipher_set_sorted,
        ext_set_sorted_no_sni_alpn,
        sig_alg_order,
    }
}

/// Run a membership check for one axis and apply the anti-inversion policy.
/// Panics (RED) only when a first-party band disagrees; prints a neutral WARN
/// and passes when an inferred band disagrees.
fn assert_member_or_warn<T, Q>(band: &FieldBand<T>, value: Q)
where
    T: std::fmt::Debug + PartialEq<Q>,
    Q: std::fmt::Debug + Copy,
{
    let outcome = MembershipOutcome {
        axis: band.axis,
        is_member: band.contains(value),
        trust: band.trust,
        member_count: band.distinct_member_count(),
    };
    match anti_inversion_decision(&outcome) {
        Ok(None) => {} // clean member
        Ok(Some(warn)) => println!("{warn} (live value = {value:?})"),
        Err(red) => panic!(
            "{red}\n  live value = {value:?}\n  band = {:?}",
            band.members
        ),
    }
}

// ==========================================================================
// 1. Census loader / provenance discipline.
// ==========================================================================

#[test]
fn census_loader_accepts_well_formed_census() {
    let census = safari_census();
    census
        .validate()
        .expect("the shipped census must satisfy its own provenance discipline");
}

#[test]
fn census_loader_rejects_band_with_too_few_provenance_entries() {
    // A single-source band is a tautology; validate() must reject it.
    let solo: &[Provenance] = &[Provenance {
        build: "Safari 26.4 / macOS Tahoe (apple.com capture)",
        artifact: Some("tests/fixtures/safari26_apple_com_clienthello.bin"),
    }];
    let mut census = safari_census();
    census.n_ciphers = FieldBand {
        axis: "n_ciphers",
        members: &[20],
        provenance: solo,
        trust: Trust::FirstPartyCapture,
    };
    let err = census
        .validate()
        .expect_err("a band with one provenance entry must be rejected");
    assert!(
        err.contains("n_ciphers") && err.contains("provenance"),
        "rejection must name the offending axis + reason, got: {err}"
    );
}

#[test]
fn census_loader_rejects_band_with_empty_build_string() {
    let blank: &[Provenance] = &[
        Provenance {
            build: "   ",
            artifact: None,
        },
        Provenance {
            build: "Safari 26.4 / macOS Tahoe (cloudflare.com capture)",
            artifact: Some("tests/fixtures/safari26_cloudflare_com_clienthello.bin"),
        },
    ];
    let mut census = safari_census();
    census.n_exts = FieldBand {
        axis: "n_exts",
        members: &[13],
        provenance: blank,
        trust: Trust::FirstPartyCapture,
    };
    let err = census
        .validate()
        .expect_err("a band with an empty build string must be rejected");
    assert!(
        err.contains("n_exts") && err.contains("build string"),
        "rejection must name the axis + the empty-build reason, got: {err}"
    );
}

#[test]
fn census_bands_carry_in_tree_artifacts() {
    // Every band's provenance artifact (when present) must (a) actually exist in
    // the tree — provenance you can follow, not just assert — and (b) NOT point
    // into `src/`: a capture artifact is real captured data under tests/fixtures,
    // never a product source file (that would be self-referential — the product
    // "corroborating" itself). The capture-calibrated H2 emitter entry expresses
    // this by carrying `artifact: None` rather than a `src/` path.
    let census = safari_census();
    let referenced = [
        census.ja4_version.provenance,
        census.n_ciphers.provenance,
        census.n_exts.provenance,
        census.alpn_pair.provenance,
        census.cipher_set_sorted.provenance,
        census.ext_set_sorted_no_sni_alpn.provenance,
        census.sig_alg_order.provenance,
        census.ja4_full.provenance,
        census.h2_settings_id_order.provenance,
        census.h2_window_update.provenance,
    ];
    for provenance in referenced {
        for p in provenance {
            if let Some(artifact) = p.artifact {
                assert!(
                    !artifact.starts_with("src/"),
                    "provenance artifact `{artifact}` for build `{}` points into \
                     src/ — capture provenance must be real captured data under \
                     tests/fixtures, not a product source file",
                    p.build,
                );
                assert!(
                    std::path::Path::new(artifact).exists(),
                    "provenance artifact `{artifact}` for build `{}` does not exist in-tree",
                    p.build,
                );
            }
        }
    }
}

// ==========================================================================
// 2. Live membership oracle over real product bytes.
// ==========================================================================

#[test]
fn live_scalar_fields_are_census_members_across_snis() {
    let census = safari_census();
    census.validate().expect("census valid");

    for sni in SAMPLE_SNIS {
        let bytes = live_client_hello(sni);
        let parsed = parse_client_hello(&bytes).expect("real ClientHello parses");
        let f = ja4_fields(&parsed);

        assert_member_or_warn(&census.ja4_version, f.version);
        assert_member_or_warn(&census.n_ciphers, f.n_ciphers);
        assert_member_or_warn(&census.n_exts, f.n_exts);
        assert_member_or_warn(&census.alpn_pair, f.alpn_pair);
        assert_member_or_warn(&census.cipher_set_sorted, f.cipher_set_sorted.as_slice());
        assert_member_or_warn(
            &census.ext_set_sorted_no_sni_alpn,
            f.ext_set_sorted_no_sni_alpn.as_slice(),
        );
        assert_member_or_warn(&census.sig_alg_order, f.sig_alg_order.as_slice());
    }
}

#[test]
fn live_full_ja4_is_census_member_across_grease_samples() {
    let census = safari_census();
    // Loop start() several times so multiple independent GREASE / random draws
    // are exercised; the JA4 (GREASE-stripped) must be invariant and a member.
    for round in 0..8 {
        let sni = SAMPLE_SNIS[round % SAMPLE_SNIS.len()];
        let bytes = live_client_hello(sni);
        let parsed = parse_client_hello(&bytes).expect("real ClientHello parses");
        let fp = fingerprint(&parsed);
        assert_member_or_warn(&census.ja4_full, fp.ja4.as_str());
    }
}

#[test]
fn live_membership_is_corroborated_by_multiple_provenance_sources() {
    // What we can soundly assert today is provenance multiplicity, NOT statistical
    // non-outlier-ness (every band is a single captured value as of the census
    // date — see the module docs). The corroboration is: the live value equals the
    // captured member, AND that member is backed by >= 2 INDEPENDENT provenance
    // entries (two first-party captures), so the match rests on more than one
    // source rather than self-validating against a single fixture.
    let census = safari_census();
    let bytes = live_client_hello("apple.com");
    let parsed = parse_client_hello(&bytes).expect("parses");
    let f = ja4_fields(&parsed);

    assert!(
        census.n_ciphers.contains(f.n_ciphers),
        "live n_ciphers must equal the captured member"
    );
    assert!(
        census.n_ciphers.provenance.len() >= 2,
        "n_ciphers band must rest on >= 2 independent provenance sources so the \
         match is corroborated, not single-source"
    );
}

// ==========================================================================
// 3. Anti-inversion guard (synthetic; not actually triggered by the product).
// ==========================================================================

#[test]
fn anti_inversion_warns_and_passes_on_inferred_band_disagreement() {
    // Build a synthetic INFERRED band whose value the product does NOT emit.
    // The product really emits 20 ciphers; this inferred band says 99. The
    // anti-inversion policy must NOT fail (no RED) and must surface a WARN —
    // proving the product can never be pressured toward the unverified 99.
    let inferred_band: FieldBand<usize> = FieldBand {
        axis: "synthetic_inferred_n_ciphers",
        members: &[99],
        provenance: &[
            Provenance {
                build: "external ja4db row (unverified, no in-tree capture)",
                artifact: None,
            },
            Provenance {
                build: "second external row (also unverified)",
                artifact: None,
            },
        ],
        trust: Trust::Inferred,
    };
    let live_value = 20usize; // the real product value
    let outcome = MembershipOutcome {
        axis: inferred_band.axis,
        is_member: inferred_band.contains(live_value),
        trust: inferred_band.trust,
        member_count: inferred_band.distinct_member_count(),
    };
    assert!(
        !outcome.is_member,
        "precondition: product disagrees with band"
    );
    match anti_inversion_decision(&outcome) {
        Ok(Some(warn)) => assert!(
            warn.contains("WARN") && warn.contains("anti-inversion"),
            "inferred disagreement must produce a neutral anti-inversion WARN, got: {warn}"
        ),
        Ok(None) => panic!("inferred disagreement must not be silently treated as a member"),
        Err(red) => panic!(
            "inferred-band disagreement must NEVER be a hard RED (that would \
             pressure the product toward an unverified value); got: {red}"
        ),
    }
}

#[test]
fn anti_inversion_fails_hard_on_first_party_band_disagreement() {
    // The mirror image: a FIRST-PARTY band the product disagrees with MUST be a
    // hard failure. This is what makes the oracle non-vacuous — a real drift
    // away from the captured Safari fingerprint cannot pass.
    let first_party_band: FieldBand<usize> = FieldBand {
        axis: "synthetic_first_party_n_ciphers",
        members: &[20],
        provenance: &[
            Provenance {
                build: "Safari 26.4 / macOS Tahoe (apple.com capture)",
                artifact: Some("tests/fixtures/safari26_apple_com_clienthello.bin"),
            },
            Provenance {
                build: "Safari 26.4 / macOS Tahoe (cloudflare.com capture)",
                artifact: Some("tests/fixtures/safari26_cloudflare_com_clienthello.bin"),
            },
        ],
        trust: Trust::FirstPartyCapture,
    };
    let drifted_value = 14usize; // pretend the product regressed to 14 ciphers
    let outcome = MembershipOutcome {
        axis: first_party_band.axis,
        is_member: first_party_band.contains(drifted_value),
        trust: first_party_band.trust,
        member_count: first_party_band.distinct_member_count(),
    };
    assert!(
        anti_inversion_decision(&outcome).is_err(),
        "disagreement with a first-party band MUST be a hard RED"
    );
}

// ==========================================================================
// 4. Negative control: discriminating power + guardrail self-test.
// ==========================================================================

/// The known-proxy JA4 used as the negative control. Sourced from the in-tree
/// proxy table `tests/gfw_sim/data/tls_fingerprints.rs`
/// (entry `xray-utls-default`). A real non-browser stack: it MUST fall outside
/// the Safari census, otherwise the oracle has no discriminating power.
const PROXY_JA4_NEGATIVE_CONTROL: &str = "t13d301400_8daaf6152771_43c4ff36b8c1";

/// Parse a JA4 string's prefix scalars (`n_ciphers`, `n_exts`, version, alpn)
/// from the `t<ver><sni><nc><ne><alpn>_..._...` header. Enough to test census
/// membership of the scalar axes for an externally-supplied JA4.
fn ja4_prefix_scalars(ja4: &str) -> (&str, usize, usize, String) {
    // Layout: t | 2-char version | 1-char sni | 2-digit nc | 2-digit ne | 2-char alpn
    let prefix = ja4.split('_').next().expect("ja4 has a prefix section");
    let version = &prefix[1..3];
    let n_ciphers: usize = prefix[4..6].parse().expect("nc digits");
    let n_exts: usize = prefix[6..8].parse().expect("ne digits");
    let alpn = prefix[8..].to_string();
    (version, n_ciphers, n_exts, alpn)
}

#[test]
fn negative_control_proxy_ja4_falls_outside_at_least_one_band() {
    let census = safari_census();

    // (a) Full-JA4 axis: the proxy string is not the Safari JA4.
    assert!(
        !census.ja4_full.contains(PROXY_JA4_NEGATIVE_CONTROL),
        "proxy JA4 must not be a member of the full-JA4 band"
    );

    // (b) Scalar axes: prove discrimination on >= 1 structural axis, not just
    // the opaque hash. xray advertises 30 ciphers / 14 exts — both outside the
    // Safari band (20 / 13).
    let (_v, nc, ne, _alpn) = ja4_prefix_scalars(PROXY_JA4_NEGATIVE_CONTROL);
    let outside_count = [!census.n_ciphers.contains(nc), !census.n_exts.contains(ne)]
        .iter()
        .filter(|outside| **outside)
        .count();
    assert!(
        outside_count >= 1,
        "negative control must fall outside >= 1 scalar census band \
         (n_ciphers={nc}, n_exts={ne}); the oracle would otherwise lack \
         discriminating power"
    );
}

#[test]
fn negative_control_guardrail_itself_is_tested_over_broadened_band_lets_proxy_in() {
    // Build a deliberately OVER-BROADENED local copy of the n_ciphers band that
    // also admits the proxy's cipher count. If the oracle were this loose, the
    // negative control would PASS membership — i.e. the guardrail would be
    // defeated. Asserting that the broadened band *does* admit the proxy proves
    // our real (narrow) band is what provides the discriminating power, and that
    // the test is sensitive to band width rather than vacuously true.
    let (_v, nc, _ne, _alpn) = ja4_prefix_scalars(PROXY_JA4_NEGATIVE_CONTROL);

    let narrow = safari_census().n_ciphers; // real band: {20}
    assert!(
        !narrow.contains(nc),
        "sanity: the real narrow band must EXCLUDE the proxy cipher count"
    );

    let broadened: FieldBand<usize> = FieldBand {
        axis: "over_broadened_n_ciphers",
        members: &[13, 14, 20, 30], // includes the proxy's 30 -> too loose
        provenance: narrow.provenance,
        trust: narrow.trust,
    };
    assert!(
        broadened.contains(nc),
        "an over-broadened band MUST admit the negative control — this confirms \
         the discriminating power comes from the band's narrowness, so widening \
         it would break the negative control (guardrail is itself tested)"
    );
}

// ==========================================================================
// 5. H2 (JA4H-ish) membership over the real Http2Fingerprint.
// ==========================================================================

#[test]
fn live_h2_settings_and_window_update_are_census_members() {
    let census = safari_census();
    census.validate().expect("census valid");

    let fp = Http2Fingerprint::safari26();
    let settings_ids: Vec<u16> = fp.settings.iter().map(|s| s.id).collect();

    assert_member_or_warn(&census.h2_settings_id_order, settings_ids.as_slice());

    let increment = fp
        .initial_window_update
        .expect("Safari H2 preface carries a connection-level WINDOW_UPDATE");
    assert_member_or_warn(&census.h2_window_update, increment);
}

#[test]
fn h2_settings_order_is_load_bearing_not_just_the_set() {
    // JA4H-style fingerprints are order-sensitive: a reordered SETTINGS list is
    // a different fingerprint even with the same id-set. Assert the census band
    // rejects a permuted order, so the membership check above is not satisfiable
    // by the same ids in a different sequence.
    let census = safari_census();
    let fp = Http2Fingerprint::safari26();
    let mut permuted: Vec<u16> = fp.settings.iter().map(|s| s.id).collect();
    permuted.reverse();
    assert!(
        !census.h2_settings_id_order.contains(permuted.as_slice()),
        "census H2 band must be order-sensitive: a reversed SETTINGS id list \
         must NOT be a member"
    );
}
