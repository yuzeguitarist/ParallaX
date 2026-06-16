//! Safari JA4 / JA4H "census" — a dated, provenanced record of the
//! fingerprint-relevant fields of a real Safari 26.4 ClientHello and HTTP/2
//! preface.
//!
//! Why a census instead of a fixture
//! ---------------------------------
//! Asserting "the product's JA4 is byte-equal to fixture X" is a tautology: the
//! fixture and the product can be wrong in exactly the same way and the test
//! still passes. This census instead encodes, per fingerprint axis, the
//! captured Safari value(s), each tagged with the exact build it came from. The
//! membership oracle (in the test file) then asserts the live product value is a
//! MEMBER of that captured set.
//!
//! Honest scope (as of the census date)
//! ------------------------------------
//! Every band below currently holds exactly ONE captured value (both first-party
//! captures agree on every JA4_a axis; they differ only in SNI and per-connection
//! GREASE/random, which JA4_a excludes). So [`FieldBand::contains`] is, today,
//! point-equality, and the live membership checks are *fixture-anchored equality*:
//! ground truth is the in-tree tcpdump captures + the gfw_sim parser (an
//! INDEPENDENT FoxIO JA4 reimplementation), NOT the product asserting against
//! itself. Multi-member distribution bands and a true "not a statistical outlier"
//! claim are future work pending a SECOND, independent real Safari capture per
//! axis. We therefore do not claim distribution membership or non-outlier-ness
//! here — only captured-value equality with independent provenance.
//!
//! Provenance is load-bearing and tiered (see [`Trust`]). [`Census::validate`]
//! enforces it: a `FirstPartyCapture` band must carry >= 2 INDEPENDENT real
//! captures (artifacts under `tests/fixtures/`, never the emitter); a
//! `SingleFirstPartyCapture` band (the H2 axes today) must carry >= 1 real
//! capture; every entry must name a concrete build string; and NO entry may cite
//! a `src/` product source as capture provenance. So a `FirstPartyCapture` band
//! can never silently degrade into a single-source (tautological) claim, and a
//! single-capture axis must be tiered honestly rather than masquerade as
//! dual-sourced.
//!
//! Anti-inversion
//! --------------
//! The dangerous failure mode for a self-referential oracle is "inversion":
//! someone mutates the *product* toward an unverified target value and the test
//! goes green, laundering an unsourced number into ground truth. The census
//! marks each band with a [`Trust`] level. When the live product DISAGREES with
//! a band whose trust is only [`Trust::Inferred`], the oracle must emit a
//! neutral WARN and PASS — never a hard RED (which would pressure someone to
//! "fix" the product toward the unverified value) and never a green that a
//! product mutation could satisfy. Membership is only *enforced* (RED on
//! disagreement) against [`Trust::FirstPartyCapture`] bands, which are anchored
//! to in-tree tcpdump captures.
//!
//! This module is test-only data + pure helpers; it has zero external deps.

#![allow(dead_code)] // Shared across test fns; not every helper is used by every test.

/// Provenance for one observed value: which real build it was captured from.
#[derive(Debug, Clone, Copy)]
pub struct Provenance {
    /// Exact build / capture string, e.g.
    /// "Safari 26.4 / macOS Tahoe (apple.com capture)". Must be non-empty.
    pub build: &'static str,
    /// In-tree artifact the value was derived from, when one exists. `None`
    /// marks a value whose provenance is only inferred (see [`Trust`]).
    pub artifact: Option<&'static str>,
}

/// How much we trust a band's provenance. Drives the anti-inversion guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Anchored to >= 2 INDEPENDENT first-party captures in `tests/fixtures/`.
    /// Disagreement is a hard RED. `validate()` enforces the >= 2 real-capture
    /// floor (counting only `tests/fixtures/` artifacts, never the emitter), so
    /// this tier can never silently degrade into a single source.
    FirstPartyCapture,
    /// Anchored to exactly ONE first-party capture in `tests/fixtures/` (plus,
    /// optionally, a non-capture calibration entry such as the emitter). Still a
    /// hard RED on disagreement — it IS backed by a real capture — but it does
    /// NOT claim the >= 2 independent-capture corroboration of
    /// [`Trust::FirstPartyCapture`]. Used for axes with only one capture today
    /// (the H2 bands), pending a second independent capture.
    SingleFirstPartyCapture,
    /// Derived only from external/inferred sources (no in-tree capture).
    /// Disagreement is a neutral WARN + PASS, never RED.
    Inferred,
}

/// A per-field census band: the captured value(s) of this axis from real Safari,
/// plus the provenance backing them. As of the census date every band holds a
/// single captured value, so membership is point-equality (see the module docs).
#[derive(Debug, Clone, Copy)]
pub struct FieldBand<T: 'static> {
    /// Human label for the axis (used in diagnostics).
    pub axis: &'static str,
    /// The captured value(s) for this axis.
    pub members: &'static [T],
    /// Provenance entries; [`Census::validate`] enforces the per-[`Trust`]-tier
    /// real-capture floor (>= 2 for `FirstPartyCapture`, >= 1 for
    /// `SingleFirstPartyCapture`) with non-empty `build` strings and no `src/`
    /// artifacts.
    pub provenance: &'static [Provenance],
    /// Trust level controlling enforce-vs-warn (see [`Trust`]).
    pub trust: Trust,
}

impl<T: std::fmt::Debug> FieldBand<T> {
    /// True if `value` equals a captured member of this band.
    ///
    /// `value` is queried as a possibly-different type `Q` (typically a
    /// non-`'static` borrow such as `&[u16]` / `&str`, or an owned scalar), so
    /// callers can compare live values against `&'static`-typed members without
    /// fighting lifetimes. Comparison is by value via `T: PartialEq<Q>`.
    pub fn contains<Q>(&self, value: Q) -> bool
    where
        T: PartialEq<Q>,
        Q: Copy,
    {
        self.members.iter().any(|m| *m == value)
    }

    /// Number of distinct captured members on this axis. Today every band has a
    /// single member; a future second independent capture could widen this into a
    /// genuine distribution band.
    pub fn distinct_member_count(&self) -> usize {
        self.members.len()
    }
}

/// Result of a single-axis membership check, carrying enough context for the
/// caller to decide between enforce (RED) and warn (PASS).
#[derive(Debug)]
pub struct MembershipOutcome {
    pub axis: &'static str,
    pub is_member: bool,
    pub trust: Trust,
    pub member_count: usize,
}

/// Decide what to do with a membership result, honoring the anti-inversion rule.
///
/// Returns `Ok(())` on a clean membership against any trust level, or a neutral
/// WARN string (still `Ok`) when an [`Trust::Inferred`] band disagrees. Returns
/// `Err` only when a [`Trust::FirstPartyCapture`] band disagrees — the single
/// case where a hard failure is sound, because the band is anchored to a real
/// in-tree capture and the product is the thing that drifted.
///
/// Crucially this never returns `Ok` for a *disagreeing* enforced band, so the
/// oracle cannot be satisfied by mutating the product toward an unverified
/// value: a first-party band that the product disagrees with always fails, and
/// an inferred band can never turn the build green by agreement-pressure because
/// its disagreement is a no-op WARN.
pub fn anti_inversion_decision(outcome: &MembershipOutcome) -> Result<Option<String>, String> {
    if outcome.is_member {
        return Ok(None);
    }
    match outcome.trust {
        Trust::FirstPartyCapture | Trust::SingleFirstPartyCapture => Err(format!(
            "axis `{}`: live product value is NOT a member of the first-party \
             capture band — the product fingerprint drifted from real Safari",
            outcome.axis
        )),
        Trust::Inferred => Ok(Some(format!(
            "WARN (anti-inversion): axis `{}` disagrees with an INFERRED census \
             band (no in-tree capture backs it). Passing without RED so the \
             product is never pressured toward an unverified value. Capture a \
             first-party artifact to promote this band to enforced.",
            outcome.axis
        ))),
    }
}

/// The full Safari fingerprint census. Each field is an independent band so a
/// single drifting axis is pinpointed rather than hidden inside one opaque
/// hash.
///
/// All numeric values below were cross-checked on 2026-06 against the two
/// first-party tcpdump captures in `tests/fixtures/` AND against the live
/// product emitter (`Safari26TlsCamouflage`), which the captures match 1:1.
pub struct Census {
    /// JA4 "version" two-char token, e.g. "13" for TLS 1.3.
    pub ja4_version: FieldBand<&'static str>,
    /// Count of non-GREASE cipher suites (JA4_a `n_ciphers`).
    pub n_ciphers: FieldBand<usize>,
    /// Count of non-GREASE extensions (JA4_a `n_exts`).
    pub n_exts: FieldBand<usize>,
    /// ALPN first/last pair token, e.g. "h2".
    pub alpn_pair: FieldBand<&'static str>,
    /// Sorted-ascending non-GREASE cipher set (JA4 section 1 input).
    pub cipher_set_sorted: FieldBand<&'static [u16]>,
    /// Sorted-ascending non-GREASE extension set with SNI+ALPN removed
    /// (JA4 section 2 input).
    pub ext_set_sorted_no_sni_alpn: FieldBand<&'static [u16]>,
    /// signature_algorithms in WIRE order (JA4 section 2 preserves order).
    pub sig_alg_order: FieldBand<&'static [u16]>,
    /// The whole JA4 string, anchored to the first-party captures.
    pub ja4_full: FieldBand<&'static str>,

    // --- HTTP/2 (JA4H-ish) bands -----------------------------------------
    /// SETTINGS id-set in WIRE order.
    pub h2_settings_id_order: FieldBand<&'static [u16]>,
    /// Connection-level WINDOW_UPDATE increment.
    pub h2_window_update: FieldBand<u32>,
}

impl Census {
    /// Validate every band's provenance discipline. Returns `Err` listing the
    /// first offending axis if any band has < 2 provenance entries or an empty
    /// build string. This is the guard that keeps the census honest.
    pub fn validate(&self) -> Result<(), String> {
        // Collect (axis, provenance, trust) tuples without caring about member type.
        let bands: [(&'static str, &'static [Provenance], Trust); 10] = [
            (
                self.ja4_version.axis,
                self.ja4_version.provenance,
                self.ja4_version.trust,
            ),
            (
                self.n_ciphers.axis,
                self.n_ciphers.provenance,
                self.n_ciphers.trust,
            ),
            (self.n_exts.axis, self.n_exts.provenance, self.n_exts.trust),
            (
                self.alpn_pair.axis,
                self.alpn_pair.provenance,
                self.alpn_pair.trust,
            ),
            (
                self.cipher_set_sorted.axis,
                self.cipher_set_sorted.provenance,
                self.cipher_set_sorted.trust,
            ),
            (
                self.ext_set_sorted_no_sni_alpn.axis,
                self.ext_set_sorted_no_sni_alpn.provenance,
                self.ext_set_sorted_no_sni_alpn.trust,
            ),
            (
                self.sig_alg_order.axis,
                self.sig_alg_order.provenance,
                self.sig_alg_order.trust,
            ),
            (
                self.ja4_full.axis,
                self.ja4_full.provenance,
                self.ja4_full.trust,
            ),
            (
                self.h2_settings_id_order.axis,
                self.h2_settings_id_order.provenance,
                self.h2_settings_id_order.trust,
            ),
            (
                self.h2_window_update.axis,
                self.h2_window_update.provenance,
                self.h2_window_update.trust,
            ),
        ];

        for (axis, provenance, trust) in bands {
            // Every entry must name a concrete build, and no entry may cite a
            // product source file as capture provenance (citing the code under
            // test would be the self-referential trap this census exists to avoid).
            for (i, p) in provenance.iter().enumerate() {
                if p.build.trim().is_empty() {
                    return Err(format!(
                        "census band `{axis}` provenance[{i}] has an empty build \
                         string; every observed value must name a concrete build"
                    ));
                }
                if let Some(artifact) = p.artifact {
                    if artifact.starts_with("src/") {
                        return Err(format!(
                            "census band `{axis}` provenance[{i}] cites product source \
                             `{artifact}` as capture provenance; only real captures under \
                             tests/fixtures/ count as a first-party source"
                        ));
                    }
                }
            }

            // Count ONLY real first-party captures (artifacts under tests/fixtures/),
            // never the emitter-calibration entry (artifact: None) — so a band's
            // trust tier cannot be inflated by listing the product under test.
            let real_captures = provenance
                .iter()
                .filter(|p| p.artifact.is_some_and(|a| a.starts_with("tests/fixtures/")))
                .count();

            match trust {
                Trust::FirstPartyCapture => {
                    if real_captures < 2 {
                        return Err(format!(
                            "census band `{axis}` is Trust::FirstPartyCapture but has only \
                             {real_captures} first-party-capture provenance entries; >= 2 \
                             INDEPENDENT captures are required (use \
                             Trust::SingleFirstPartyCapture for a single-capture band)"
                        ));
                    }
                }
                Trust::SingleFirstPartyCapture => {
                    if real_captures < 1 {
                        return Err(format!(
                            "census band `{axis}` is Trust::SingleFirstPartyCapture but has no \
                             first-party-capture (tests/fixtures/) provenance entry"
                        ));
                    }
                }
                Trust::Inferred => {
                    if provenance.len() < 2 {
                        return Err(format!(
                            "census band `{axis}` has {} provenance entries; >= 2 distinct \
                             sources are required so the band is not a single-source tautology",
                            provenance.len()
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------
// The dated census instance.
// --------------------------------------------------------------------------
//
// CENSUS DATE: 2026-06-15.
//
// First-party captures backing the bands:
//   A = "Safari 26.4 / macOS Tahoe (apple.com capture)"
//       -> tests/fixtures/safari26_apple_com_clienthello.bin
//   B = "Safari 26.4 / macOS Tahoe (cloudflare.com capture)"
//       -> tests/fixtures/safari26_cloudflare_com_clienthello.bin
//   H = "Safari 26.4 / macOS Tahoe (localhost h2 capture)"
//       -> tests/fixtures/safari26_h2_preface_localhost.bin
//
// The ClientHello bands are corroborated by TWO independent captures (A and B):
// both agree on every scalar/structural axis below (they differ only in SNI and
// per-connection GREASE/random, which are excluded from JA4_a), so each band
// lists the agreed value once but is dual-sourced -> Trust::FirstPartyCapture.
// The H2 bands have only ONE independent capture (H) today, so they are tiered
// honestly as Trust::SingleFirstPartyCapture (still hard-RED). That dual-source agreement is exactly what
// makes a match non-outlier.

/// Provenance shared by ClientHello-derived bands: both first-party captures.
const PROV_CLIENTHELLO: &[Provenance] = &[
    Provenance {
        build: "Safari 26.4 / macOS Tahoe (apple.com capture)",
        artifact: Some("tests/fixtures/safari26_apple_com_clienthello.bin"),
    },
    Provenance {
        build: "Safari 26.4 / macOS Tahoe (cloudflare.com capture)",
        artifact: Some("tests/fixtures/safari26_cloudflare_com_clienthello.bin"),
    },
];

/// Provenance for the H2 bands: the localhost preface capture, plus the
/// source-of-record encoder calibrated against it. The encoder entry is NOT an
/// independent capture — it carries `artifact: None` so it is never blessed as
/// capture provenance, and its build string says so explicitly. Only the first
/// entry is a real capture; promoting H2 to a genuine multi-capture band is
/// future work pending a second independent Safari H2 preface capture.
const PROV_H2: &[Provenance] = &[
    Provenance {
        build: "Safari 26.4 / macOS Tahoe (localhost h2 capture)",
        artifact: Some("tests/fixtures/safari26_h2_preface_localhost.bin"),
    },
    Provenance {
        build:
            "Http2Fingerprint::safari26 emitter (capture-calibrated, NOT an independent capture)",
        artifact: None,
    },
];

/// Real Safari 26.4 non-GREASE cipher suite list, sorted ascending (JA4 section
/// 1 input). 20 entries — verified against both ClientHello captures. Note the
/// TLS 1.3 suites 0x1301..0x1303 sort numerically *before* the 0xc0xx/0xccxx
/// suites, which is the ordering the JA4 algorithm's `sort_unstable` produces.
const SAFARI_CIPHER_SET_SORTED: &[u16] = &[
    0x000a, 0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc008, 0xc009, 0xc00a, 0xc012,
    0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9,
];

/// Real Safari 26.4 non-GREASE extension set, sorted ascending, with SNI
/// (0x0000) and ALPN (0x0010) removed (JA4 section 2 input). 11 entries (13
/// non-GREASE extensions minus SNI and ALPN).
const SAFARI_EXT_SET_SORTED_NO_SNI_ALPN: &[u16] = &[
    0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0017, 0x001b, 0x002b, 0x002d, 0x0033, 0xff01,
];

/// Real Safari 26.4 signature_algorithms in wire order, including Apple's
/// duplicated 0x0805 (JA4 section 2 preserves wire order).
const SAFARI_SIG_ALG_ORDER: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

/// Real Safari 26.4 HTTP/2 SETTINGS id-set in wire order.
const SAFARI_H2_SETTINGS_ID_ORDER: &[u16] = &[0x2, 0x4, 0x3, 0x9];

/// Build the dated census. Free function (not `const`) so the band `members`
/// can reference the `&'static` slices above without `const` promotion gymnastics.
pub fn safari_census() -> Census {
    Census {
        ja4_version: FieldBand {
            axis: "ja4_version",
            members: &["13"],
            provenance: PROV_CLIENTHELLO,
            trust: Trust::FirstPartyCapture,
        },
        n_ciphers: FieldBand {
            axis: "n_ciphers",
            members: &[20],
            provenance: PROV_CLIENTHELLO,
            trust: Trust::FirstPartyCapture,
        },
        n_exts: FieldBand {
            axis: "n_exts",
            members: &[13],
            provenance: PROV_CLIENTHELLO,
            trust: Trust::FirstPartyCapture,
        },
        alpn_pair: FieldBand {
            axis: "alpn_pair",
            members: &["h2"],
            provenance: PROV_CLIENTHELLO,
            trust: Trust::FirstPartyCapture,
        },
        cipher_set_sorted: FieldBand {
            axis: "cipher_set_sorted",
            members: &[SAFARI_CIPHER_SET_SORTED],
            provenance: PROV_CLIENTHELLO,
            trust: Trust::FirstPartyCapture,
        },
        ext_set_sorted_no_sni_alpn: FieldBand {
            axis: "ext_set_sorted_no_sni_alpn",
            members: &[SAFARI_EXT_SET_SORTED_NO_SNI_ALPN],
            provenance: PROV_CLIENTHELLO,
            trust: Trust::FirstPartyCapture,
        },
        sig_alg_order: FieldBand {
            axis: "sig_alg_order",
            members: &[SAFARI_SIG_ALG_ORDER],
            provenance: PROV_CLIENTHELLO,
            trust: Trust::FirstPartyCapture,
        },
        ja4_full: FieldBand {
            axis: "ja4_full",
            // The full JA4 the FoxIO algorithm yields over real Safari 26.4.
            // SYNC: must equal the canonical `gfw_sim::data::tls_fingerprints::
            // SAFARI26_MACOS_JA4`; the `census_ja4_full_agrees_with_canonical_constant`
            // test in ja4_census_oracle.rs fails the build if these ever desync.
            members: &["t13d2013h2_a09f3c656075_7f0f34a4126d"],
            provenance: PROV_CLIENTHELLO,
            trust: Trust::FirstPartyCapture,
        },
        h2_settings_id_order: FieldBand {
            axis: "h2_settings_id_order",
            members: &[SAFARI_H2_SETTINGS_ID_ORDER],
            provenance: PROV_H2,
            // Only ONE independent H2 capture exists today (see PROV_H2; the 2nd
            // entry is the emitter, not a capture). Hard-RED, but honestly tiered
            // as single-capture rather than falsely claiming >= 2 corroboration.
            trust: Trust::SingleFirstPartyCapture,
        },
        h2_window_update: FieldBand {
            axis: "h2_window_update",
            members: &[10_485_760],
            provenance: PROV_H2,
            trust: Trust::SingleFirstPartyCapture,
        },
    }
}
