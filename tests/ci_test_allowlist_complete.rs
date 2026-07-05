//! CI integration-test allowlist guard.
//!
//! `.github/workflows/ci-pr.yml` runs integration tests via a hand-maintained
//! `--test <name>` allowlist; the workflow comment itself warns that any new
//! `tests/*.rs` MUST be added there or its non-`#[ignore]`d tests will never
//! run in CI. Unlike the fuzz side (`fuzz/ci/select_targets.py --check`),
//! nothing enforced that — until this test. It fails whenever a `tests/*.rs`
//! file exists that the workflow never invokes.
//!
//! Std-only, no external dependencies: the workflow YAML is read as plain
//! text and every `--test <name>` token is extracted regardless of which job
//! or step it appears in.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const WORKFLOW_PATH: &str = ".github/workflows/ci-pr.yml";

/// Integration test files intentionally NOT invoked by ci-pr.yml.
///
/// Every entry must carry a comment justifying the exclusion. Currently
/// empty: every `tests/*.rs` file is expected to run in CI (gfw_simulator
/// runs in its own dedicated job, which still counts as invoked).
const INTENTIONALLY_EXCLUDED: &[&str] = &[];

/// Names (file stems) of every integration test target: files directly in
/// `tests/` with an `.rs` extension. Subdirectories (`tests/support/`,
/// `tests/fixtures/`, ...) are shared helpers, not targets, and are skipped.
fn integration_test_names(repo_root: &Path) -> BTreeSet<String> {
    let tests_dir = repo_root.join("tests");
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(&tests_dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", tests_dir.display()))
    {
        let path = entry.expect("failed to read tests/ directory entry").path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            names.insert(
                path.file_stem()
                    .expect("tests/*.rs file must have a stem")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    names
}

/// Every `--test <name>` token in the workflow text, from any job or step.
/// Robust to the YAML shape: the file is treated as whitespace-separated
/// tokens, so shell line continuations (`\`) and flag ordering don't matter.
/// `--test-threads=1` and similar are not `--test` and are ignored.
fn workflow_invoked_tests(workflow_text: &str) -> BTreeSet<String> {
    let words: Vec<&str> = workflow_text.split_whitespace().collect();
    let mut invoked = BTreeSet::new();
    for pair in words.windows(2) {
        if pair[0] == "--test" {
            invoked.insert(pair[1].trim_end_matches('\\').to_string());
        }
    }
    invoked
}

/// Test files present on disk but neither invoked by the workflow nor
/// explicitly excluded. Kept as a standalone function so the non-vacuity
/// test below can exercise the diff logic directly.
fn missing_from_allowlist(
    test_files: &BTreeSet<String>,
    invoked: &BTreeSet<String>,
    excluded: &[&str],
) -> Vec<String> {
    test_files
        .iter()
        .filter(|name| !excluded.contains(&name.as_str()))
        .filter(|name| !invoked.contains(*name))
        .cloned()
        .collect()
}

#[test]
fn ci_allowlist_covers_every_integration_test() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workflow_file = repo_root.join(WORKFLOW_PATH);
    let workflow_text = fs::read_to_string(&workflow_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", workflow_file.display()));

    let test_files = integration_test_names(repo_root);
    let invoked = workflow_invoked_tests(&workflow_text);

    // Non-vacuity: if the workflow were restructured so this parser finds
    // (almost) nothing, fail loudly instead of silently passing an empty diff.
    assert!(
        invoked.len() > 5,
        "only {} `--test <name>` tokens parsed from {WORKFLOW_PATH} ({invoked:?}); \
         the workflow layout probably changed — update this test's parser",
        invoked.len(),
    );
    assert!(
        !test_files.is_empty(),
        "no tests/*.rs files found; repo-root detection is broken"
    );

    // Hygiene: exclusions must reference real files, so the list can't rot.
    for excluded in INTENTIONALLY_EXCLUDED {
        assert!(
            test_files.contains(*excluded),
            "INTENTIONALLY_EXCLUDED entry `{excluded}` does not match any tests/*.rs file; \
             remove the stale exclusion"
        );
    }

    let missing = missing_from_allowlist(&test_files, &invoked, INTENTIONALLY_EXCLUDED);
    assert!(
        missing.is_empty(),
        "integration test file(s) never run by CI: {missing:?}. \
         For each `tests/<name>.rs` above, add `--test <name>` to the cargo test \
         allowlist in {WORKFLOW_PATH} (or, if the exclusion is deliberate, add it to \
         INTENTIONALLY_EXCLUDED in tests/ci_test_allowlist_complete.rs with a \
         justification comment)."
    );
}

/// Unit-level check that the guard has teeth: a deliberately-fake test file
/// missing from the invoked set is detected, and the token parser extracts
/// exactly the `--test` names from a realistic workflow snippet.
#[test]
fn guard_detects_a_missing_entry() {
    let snippet = "run: |\n  cargo test --locked --no-fail-fast \\\n    --lib \\\n    \
                   --test alpha \\\n    --test beta\n  cargo test --test gamma -- \
                   --ignored --test-threads=1\n";
    let invoked = workflow_invoked_tests(snippet);
    let expected: BTreeSet<String> = ["alpha", "beta", "gamma"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(invoked, expected, "parser extracted wrong `--test` tokens");

    let mut test_files = expected.clone();
    test_files.insert("deliberately_fake_missing_test".to_string());
    let missing = missing_from_allowlist(&test_files, &invoked, &[]);
    assert_eq!(
        missing,
        vec!["deliberately_fake_missing_test".to_string()],
        "diff logic failed to flag a file absent from the invoked set"
    );

    // And an exclusion suppresses the failure, as documented.
    let missing_with_exclusion =
        missing_from_allowlist(&test_files, &invoked, &["deliberately_fake_missing_test"]);
    assert!(missing_with_exclusion.is_empty());
}
