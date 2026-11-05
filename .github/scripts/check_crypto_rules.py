#!/usr/bin/env python3
"""Blocking AST regression rules, including mutations of the production source.

The rules enforce reviewed syntactic boundaries; Kani and runtime tests cover
the arithmetic/state properties. This is not a general control-flow proof.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/crypto.yml"
FIXTURES = RULES.with_suffix(".rs")


def run(semgrep, *args):
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    result = subprocess.run(
        [semgrep, "scan", *args], cwd=ROOT, env=env, capture_output=True, text=True, timeout=180
    )
    return result


def scan(semgrep, target, require_clean=False):
    args = ["--strict", "--no-git-ignore", "--config", str(RULES), "--json", "--quiet"]
    if require_clean:
        args.append("--error")
    result = run(semgrep, *args, str(target))
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete security scan: {data}")
    findings = data["results"]
    if require_clean and (result.returncode != 0 or findings):
        raise RuntimeError(f"Security rule violations: {findings}")
    return findings


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError(f"Mutation anchor changed or is ambiguous: {old!r}")
    return source.replace(old, new, 1)


def check_mutations(semgrep):
    data = (ROOT / "src/protocol/data.rs").read_text()
    signing = (ROOT / "src/crypto/mldsa/mod.rs").read_text()
    batch_start = data.index("pub fn seal_records_into_parallel")
    batch_end = data.index("    /// Serial counterpart", batch_start)
    batch = data[batch_start:batch_end]
    reserve = "let base_sequence = self.aead.reserve_sequence(record_count as u64)?;"
    dispatch = "let segments = parallel::dispatch_blocking(|| pool.run_ordered(jobs));"
    late_batch = replace_once(batch, reserve, "let base_sequence = self.aead.sequence();")
    late_batch = replace_once(
        late_batch, dispatch, dispatch + "\nself.aead.advance_sequence(record_count as u64);"
    )
    late_reserve = data[:batch_start] + late_batch + data[batch_end:]
    worker_start = data.index("fn seal_worker_payload(")
    unbounded_worker = data[:worker_start] + replace_once(
        data[worker_start:], "    check_padded_len(plaintext.len())?;\n", ""
    )
    unpoisoned = data[:batch_start] + replace_once(
        batch, "                    self.aead.poison();\n", ""
    ) + data[batch_end:]
    exact_start = data.index("    pub(crate) fn seal_records_into_exact_padded")
    exact_end = data.index("    /// Like [`Self::seal_records_into`]", exact_start)
    exact = data[exact_start:exact_end]
    preflight = "let reserve = validate_exact_padded_record_lens(record_lens, pad_lens, plaintext.len())?;"

    def exact_variant(old, new):
        return data[:exact_start] + replace_once(exact, old, new) + data[exact_end:]

    policy = data[data.index("fn checked_seal_end("):data.index("\nfn check_padded_len(")]
    usability = data[data.index("    fn ensure_seal_budget("):data.index("    fn seal_padded_payload(")]

    def scoped_variant(scope, old, new):
        return replace_once(data, scope, replace_once(scope, old, new))

    variants = {
        "poison_policy_missing_check.rs": (
            scoped_variant(policy, "    usable?;\n", ""),
            "parallax-record-seal-poison-policy",
        ),
        "poison_policy_late_check.rs": (
            scoped_variant(policy,
                "    usable?;\n    if record_count == 0 {\n        return Ok(sequence);\n    }",
                "    if record_count == 0 {\n        return Ok(sequence);\n    }\n    usable?;"),
            "parallax-record-seal-poison-policy",
        ),
        "poison_policy_conditional_check.rs": (
            scoped_variant(policy, "    usable?;", "    if record_count != 0 { usable?; }"),
            "parallax-record-seal-poison-policy",
        ),
        "poison_caller_assumes_usable.rs": (
            scoped_variant(usability, "self.aead.ensure_usable(),", "Ok(()),"),
            "parallax-record-seal-usability",
        ),
        "poison_caller_empty_fast_path.rs": (
            scoped_variant(usability, "        checked_seal_end(",
                "        if record_count == 0 { return Ok(()); }\n        checked_seal_end("),
            "parallax-record-seal-usability",
        ),
        "poison_caller_ignores_check.rs": (
            scoped_variant(usability, "        checked_seal_end(\n            self.aead.ensure_usable(),",
                "        let _ = self.aead.ensure_usable();\n        checked_seal_end(\n            Ok(()),"),
            "parallax-record-seal-usability",
        ),
        "exact_missing_last_pad_check.rs": (
            replace_once(data, "exact_padded_record_capacity(len, pad)?", "exact_padded_record_capacity(len, 0)?"),
            "parallax-exact-padding-whole-window",
        ),
        "exact_missing_pad_count.rs": (
            replace_once(data, "record_lens.len() != pad_lens.len()", "false"),
            "parallax-exact-padding-whole-window",
        ),
        "exact_missing_plaintext_length_sum.rs": (
            replace_once(data, "    validate_record_lens(record_lens, plaintext_len)?;", ""),
            "parallax-exact-padding-whole-window",
        ),
        "exact_missing_u16_bound.rs": (
            replace_once(data, "total_pad > u16::MAX as usize", "false"),
            "parallax-exact-padding-capacity",
        ),
        "exact_missing_tls_bound.rs": (
            replace_once(data, "tls_len > OUTER_TLS_RECORD_LIMIT", "false"),
            "parallax-exact-padding-capacity",
        ),
        "exact_unchecked_aggregate.rs": (
            replace_once(data, ".checked_add(exact_padded_record_capacity(len, pad)?)", ".wrapping_add(exact_padded_record_capacity(len, pad)?)"),
            "parallax-exact-padding-whole-window",
        ),
        "exact_no_preflight.rs": (
            exact_variant(preflight, "let reserve = 0;"),
            "parallax-exact-padding-batch-preflight",
        ),
        "exact_ignored_batch_budget.rs": (
            exact_variant("self.ensure_seal_budget(record_lens.len())?;", "let _ = self.ensure_seal_budget(record_lens.len());"),
            "parallax-exact-padding-batch-preflight",
        ),
        "exact_budget_only_first_record.rs": (
            exact_variant("self.ensure_seal_budget(record_lens.len())?;", "self.ensure_seal_budget(1)?;"),
            "parallax-exact-padding-batch-preflight",
        ),
        "exact_unchecked_output_length.rs": (
            exact_variant(".checked_add(reserve)", ".wrapping_add(reserve)"),
            "parallax-exact-padding-batch-preflight",
        ),
        "exact_late_batch_budget.rs": (
            replace_once(exact_variant("self.ensure_seal_budget(record_lens.len())?;", ""),
                "for (&len, &pad) in record_lens.iter().zip(pad_lens) {",
                "for (&len, &pad) in record_lens.iter().zip(pad_lens) { self.ensure_seal_budget(1)?;"),
            "parallax-exact-padding-batch-preflight",
        ),
        "exact_early_seal_canonical_retained.rs": (
            exact_variant(preflight, "self.seal_into_exact_padded(&plaintext[..1], 0, rng, out)?;\n" + preflight),
            "parallax-exact-padding-batch-preflight",
        ),
        "exact_nested_early_seal_canonical_retained.rs": (
            exact_variant(preflight, "if !plaintext.is_empty() { self.seal_into_exact_padded(&plaintext[..1], 0, rng, out)?; }\n" + preflight),
            "parallax-exact-padding-batch-preflight",
        ),
        "exact_early_output_canonical_retained.rs": (
            exact_variant(preflight, "out.push(0);\n" + preflight),
            "parallax-exact-padding-batch-preflight",
        ),
        "exact_unpoisoned_failure.rs": (
            exact_variant("self.aead.poison();", ""),
            "parallax-exact-padding-batch-preflight",
        ),
        "owned_key.rs": (
            replace_once(
                signing,
                "fn to_sk_array(sk: &[u8]) -> Result<&[u8; SECRETKEYBYTES], MlDsaError>",
                "fn to_sk_array(sk: &[u8]) -> Result<[u8; SECRETKEYBYTES], MlDsaError>",
            ),
            "parallax-owned-signing-key-copy",
        ),
        "ignored_budget.rs": (
            replace_once(
                data,
                "        self.ensure_seal_budget(1)?;\n        check_padded_len(plaintext.len())?;",
                "        let _ = self.ensure_seal_budget(1);\n        check_padded_len(plaintext.len())?;",
            ),
            "parallax-record-seal-guard",
        ),
        "late_reservation.rs": (late_reserve, "parallax-reserve-before-seal-dispatch"),
        "unbounded_worker.rs": (unbounded_worker, "parallax-worker-seal-length-guard"),
        "unpoisoned_worker.rs": (unpoisoned, "parallax-poison-failed-seal-worker"),
        "unreserved_raw_caller.rs": (
            data + """
fn unreserved_raw_caller(
    cipher: &LessSafeKey, nonce: &[u8; NONCE_LEN], sequence: u64,
    plaintext: &mut [u8], aad: &[u8],
) -> Result<[u8; AEAD_TAG_LEN], DataRecordError> {
    check_padded_len(plaintext.len())?;
    session::seal_in_place_detached_with(cipher, nonce, sequence, plaintext, aad)
        .map_err(Into::into)
}
""",
            "parallax-raw-worker-seal-boundary",
        ),
        "allocating_primitive.rs": (
            data + """
impl DataRecordCodec {
    pub fn unbudgeted_allocating_seal(&mut self, plaintext: &[u8])
        -> Result<Vec<u8>, DataRecordError> {
        self.aead.seal(plaintext, self.aad).map_err(Into::into)
    }
}
""",
            "parallax-record-allocating-seal-bypass",
        ),
    }
    with tempfile.TemporaryDirectory(prefix="parallax-security-rules-") as directory:
        for name, (source, _) in variants.items():
            (Path(directory) / name).write_text(source)
        findings = scan(semgrep, directory)
        found = {}
        for finding in findings:
            found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
        for name, (_, expected) in variants.items():
            if expected not in found.get(name, set()):
                raise RuntimeError(f"Security regression mutation escaped: {name} ({expected})")
    print(f"Production-source mutation checks: {len(variants)} detected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep", help="Semgrep executable (CI uses the pinned venv)")
    args = parser.parse_args()
    fixtures = run(args.semgrep, "--test", "--config", str(RULES), str(FIXTURES))
    if fixtures.returncode:
        raise RuntimeError(fixtures.stdout + fixtures.stderr)
    print(fixtures.stdout.strip())
    scan(args.semgrep, ROOT / "src", require_clean=True)
    check_mutations(args.semgrep)
    print("Project cryptographic AST rules: passed (source, fixtures, mutations)")


if __name__ == "__main__":
    main()
