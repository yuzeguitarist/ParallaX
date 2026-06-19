//! NIST ACVP known-answer-test (KAT) gate for the hand-rolled `crypto::mldsa`
//! ML-DSA-87 (FIPS 204) implementation. This is the decisive correctness gate
//! (plan §4): byte-for-byte agreement with the official ACVP vectors proves the
//! port reproduces the reference exactly, which the differential-vs-pqcrypto
//! tests (`tests/mldsa_differential.rs`) cannot — the C oracle is hedged-only and
//! offers no seed-injection / deterministic API, so byte-equality must come from
//! these vectors.
//!
//! Vectors are read at runtime from the on-disk ACVP `internalProjection.json`
//! files (which hold inputs AND answers in one file, so no `tcId` join is needed);
//! the sigGen file is ~9 MB, so it is `read_to_string`d, never `include_str!`d.
//! We filter to exactly ParallaX's path: `parameterSet == "ML-DSA-87"`,
//! `signatureInterface == "external"`, `preHash == "pure"` (the `internal` /
//! `externalMu` / `preHash` groups exercise APIs this module does not implement).
//!
//! All four ACVP gates are driven through the same `pub` entry points the rest of
//! the module is built on:
//!
//! * keyGen — `sign::keygen_internal(seed)` -> (pk, sk), byte-exact.
//! * sigGen — `sign::signature_ctx(sk, msg, ctx, rnd)` -> signature, byte-exact.
//!   Deterministic groups carry no `rnd`, so `rnd = 0^32`; hedged groups inject
//!   the vector's `rnd`.
//! * sigVer — top-level `mldsa::verify(pk, sig, msg, ctx).is_ok()` must equal the
//!   vector's `testPassed` for every case (accept the valid ones, reject all four
//!   mutation classes).
//!
//! These run by default (no sockets, no network): they are the permanent
//! regression gate and must never be `#[ignore]`d.

use parallax::crypto::mldsa;
use parallax::crypto::mldsa::params::{
    PUBLICKEYBYTES, RNDBYTES, SECRETKEYBYTES, SEEDBYTES, SIGNBYTES,
};
use parallax::crypto::mldsa::sign;
use serde_json::Value;

/// Curated NIST ACVP FIPS-204 vectors (ML-DSA-87, external/pure groups only),
/// vendored under `tests/fixtures/mldsa_acvp/` so this gate is self-contained and
/// reproducible — no dependency on any gitignored local download. Resolved via
/// `CARGO_MANIFEST_DIR` so the test is independent of the launch directory.
fn acvp_path(op: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mldsa_acvp")
        .join(op)
        .join("internalProjection.json")
}

/// Load and parse an ACVP `internalProjection.json` for one operation.
fn load(op: &str) -> Value {
    let path = acvp_path(op);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read ACVP vectors {}: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parse ACVP vectors {}: {e}", path.display()))
}

/// Decode a required uppercase-hex string field of a test object.
fn hex_field(t: &Value, key: &str) -> Vec<u8> {
    let s = t
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing hex field {key:?}"));
    hex::decode(s).unwrap_or_else(|e| panic!("decode hex field {key:?}: {e}"))
}

/// Decode an *optional* hex field that may be absent or the empty string
/// (ACVP encodes an empty `context` as `""`, and deterministic sigGen omits
/// `rnd` entirely). Returns an empty vec in both cases.
fn hex_field_opt(t: &Value, key: &str) -> Vec<u8> {
    match t.get(key).and_then(Value::as_str) {
        None | Some("") => Vec::new(),
        Some(s) => hex::decode(s).unwrap_or_else(|e| panic!("decode hex field {key:?}: {e}")),
    }
}

/// Is this test group exactly ParallaX's ML-DSA-87 external/pure path? keyGen has
/// no `signatureInterface`/`preHash` keys, so this predicate (used for sigGen /
/// sigVer) is gated by `parameterSet` plus those two fields, and explicitly
/// excludes the `externalMu` groups (which feed a pre-hashed mu, an interface
/// this module does not implement). The current vectors only set `externalMu` on
/// `internal` groups, so the `signatureInterface`/`preHash` gate already drops
/// them, but checking `externalMu` directly keeps the filter correct if a future
/// vector set pairs `externalMu: true` with `external`/`pure` (absent == false).
fn is_ml_dsa_87_external_pure(group: &Value) -> bool {
    group.get("parameterSet").and_then(Value::as_str) == Some("ML-DSA-87")
        && group.get("signatureInterface").and_then(Value::as_str) == Some("external")
        && group.get("preHash").and_then(Value::as_str) == Some("pure")
        && group.get("externalMu").and_then(Value::as_bool) != Some(true)
}

fn groups(doc: &Value) -> &Vec<Value> {
    doc.get("testGroups")
        .and_then(Value::as_array)
        .expect("ACVP doc has testGroups array")
}

fn tests(group: &Value) -> &Vec<Value> {
    group
        .get("tests")
        .and_then(Value::as_array)
        .expect("ACVP group has tests array")
}

fn tc_id(t: &Value) -> i64 {
    t.get("tcId").and_then(Value::as_i64).expect("tcId int")
}

/// Gate 1 — keyGen KAT: `keygen_internal(seed)` reproduces `(pk, sk)` byte-for-byte.
///
/// This transitively validates ExpandA, ExpandS, the NTT, power2round, pk/sk
/// packing, and `tr = H(pk)` — any single-bit slip in those would diverge here.
#[test]
fn acvp_keygen_byte_exact() {
    let doc = load("ML-DSA-keyGen-FIPS204");
    let mut checked = 0usize;
    for group in groups(&doc) {
        // keyGen groups only carry `parameterSet` (no interface/preHash fields).
        if group.get("parameterSet").and_then(Value::as_str) != Some("ML-DSA-87") {
            continue;
        }
        for t in tests(group) {
            let seed = hex_field(t, "seed");
            assert_eq!(seed.len(), SEEDBYTES, "tcId {}: seed length", tc_id(t));
            let expected_pk = hex_field(t, "pk");
            let expected_sk = hex_field(t, "sk");
            assert_eq!(
                expected_pk.len(),
                PUBLICKEYBYTES,
                "tcId {}: pk len",
                tc_id(t)
            );
            assert_eq!(
                expected_sk.len(),
                SECRETKEYBYTES,
                "tcId {}: sk len",
                tc_id(t)
            );

            let seed_arr: [u8; SEEDBYTES] = seed.try_into().unwrap();
            let (pk, sk) = sign::keygen_internal(&seed_arr);

            assert_eq!(
                pk.as_slice(),
                expected_pk.as_slice(),
                "tcId {}: public key mismatch",
                tc_id(t)
            );
            assert_eq!(
                sk.as_slice(),
                expected_sk.as_slice(),
                "tcId {}: secret key mismatch",
                tc_id(t)
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no ML-DSA-87 keyGen vectors were exercised");
    eprintln!("ACVP keyGen ML-DSA-87: {checked} vectors byte-exact");
}

/// Gates 2 & 3 — sigGen KAT: deterministic (`rnd = 0^32`, the groups that omit
/// `rnd`) and hedged (inject the vector's `rnd`) both reproduce the `signature`
/// field byte-for-byte. This is the determinism seam the C oracle cannot provide.
///
/// Exercises ExpandMask, SampleInBall, the full rejection loop, decompose /
/// make_hint, and signature packing, all pinned to exact bytes.
#[test]
fn acvp_siggen_byte_exact() {
    let doc = load("ML-DSA-sigGen-FIPS204");
    let mut det_checked = 0usize;
    let mut hedged_checked = 0usize;
    for group in groups(&doc) {
        if !is_ml_dsa_87_external_pure(group) {
            continue;
        }
        let deterministic = group
            .get("deterministic")
            .and_then(Value::as_bool)
            .expect("sigGen group has `deterministic` flag");
        for t in tests(group) {
            let sk = hex_field(t, "sk");
            assert_eq!(sk.len(), SECRETKEYBYTES, "tcId {}: sk len", tc_id(t));
            let msg = hex_field(t, "message");
            let ctx = hex_field_opt(t, "context");
            let expected_sig = hex_field(t, "signature");
            assert_eq!(
                expected_sig.len(),
                SIGNBYTES,
                "tcId {}: signature len",
                tc_id(t)
            );

            // Deterministic groups omit `rnd` (FIPS 204 deterministic variant uses
            // the all-zero nonce); hedged groups carry the exact 32-byte `rnd` used.
            let rnd_bytes = hex_field_opt(t, "rnd");
            let rnd: [u8; RNDBYTES] = if deterministic {
                assert!(
                    rnd_bytes.is_empty(),
                    "tcId {}: deterministic group unexpectedly carries rnd",
                    tc_id(t)
                );
                [0u8; RNDBYTES]
            } else {
                assert_eq!(rnd_bytes.len(), RNDBYTES, "tcId {}: rnd len", tc_id(t));
                rnd_bytes.try_into().unwrap()
            };

            let sk_arr: [u8; SECRETKEYBYTES] = sk.try_into().unwrap();
            let sig = sign::signature_ctx(&sk_arr, &msg, &ctx, &rnd)
                .unwrap_or_else(|e| panic!("tcId {}: signature_ctx rejected ctx: {e:?}", tc_id(t)));

            assert_eq!(
                sig.as_slice(),
                expected_sig.as_slice(),
                "tcId {}: signature mismatch (deterministic={deterministic})",
                tc_id(t)
            );
            if deterministic {
                det_checked += 1;
            } else {
                hedged_checked += 1;
            }
        }
    }
    assert!(
        det_checked > 0,
        "no deterministic ML-DSA-87 sigGen vectors were exercised"
    );
    assert!(
        hedged_checked > 0,
        "no hedged ML-DSA-87 sigGen vectors were exercised"
    );
    eprintln!(
        "ACVP sigGen ML-DSA-87: {det_checked} deterministic + {hedged_checked} hedged byte-exact"
    );
}

/// Gate 4 — sigVer KAT: `verify(...).is_ok()` equals `testPassed` for every case.
///
/// The valid cases (`testPassed == true`) must accept; the four mutation classes
/// (`modified message`, `... - z`, `... - hint`, `... - commitment`) must each
/// reject. The hint mutation in particular only fails if `unpack_sig` enforces
/// the hint-decode rejections, which valid-only round-trips would miss.
#[test]
fn acvp_sigver_matches_testpassed() {
    let doc = load("ML-DSA-sigVer-FIPS204");
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for group in groups(&doc) {
        if !is_ml_dsa_87_external_pure(group) {
            continue;
        }
        for t in tests(group) {
            let pk = hex_field(t, "pk");
            assert_eq!(pk.len(), PUBLICKEYBYTES, "tcId {}: pk len", tc_id(t));
            let sig = hex_field(t, "signature");
            assert_eq!(sig.len(), SIGNBYTES, "tcId {}: signature len", tc_id(t));
            let msg = hex_field(t, "message");
            let ctx = hex_field_opt(t, "context");
            let expected = t
                .get("testPassed")
                .and_then(Value::as_bool)
                .expect("sigVer test has `testPassed` bool");

            let got = mldsa::verify(&pk, &sig, &msg, &ctx).is_ok();
            assert_eq!(
                got,
                expected,
                "tcId {}: verify()={got} but testPassed={expected} (reason: {})",
                tc_id(t),
                t.get("reason").and_then(Value::as_str).unwrap_or("<none>")
            );
            if expected {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
    }
    assert!(
        accepted > 0,
        "no valid ML-DSA-87 sigVer vectors were exercised"
    );
    assert!(
        rejected > 0,
        "no invalid ML-DSA-87 sigVer vectors were exercised (mutation classes)"
    );
    eprintln!("ACVP sigVer ML-DSA-87: {accepted} accepted + {rejected} rejected match testPassed");
}
