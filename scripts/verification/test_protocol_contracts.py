"""Reference and retained-evidence rejection controls; these do not run Rust."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "protocol_contracts", ROOT / "scripts/verification/protocol_contracts.py")
contracts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contracts)
COMMIT = "a" * 40


class ProtocolContractControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(contracts.LEDGER.read_text())
        cls.entries = contracts.validate_ledger(cls.document)

    def fixture(self, directory):
        root = Path(directory)
        root.joinpath("source.log").write_text(COMMIT + "\n")
        root.joinpath("source-status.log").write_text("")
        root.joinpath("toolchain.log").write_text("rustc fixture\n")
        selections = {}
        for contract in self.entries:
            for test in contract["tests"]:
                selections.setdefault(test["suite"], set()).add(test["name"])
        report = {"schema_version": 1, "kind": "protocol", "status": "passed",
                  "source_commit": COMMIT, "working_tree_dirty": False,
                  "toolchain": "rustc fixture", "tests": {}, "commands": [],
                  "bounds": {"PARALLAX_PROP_SEED": "0x123", "PARALLAX_PROP_CASES": "256"}}
        for suite, names in sorted(selections.items()):
            selected = sorted(names)
            report["tests"][suite] = {"selected": selected, "passed": len(selected),
                                       "failed": 0, "ignored": 0}
            target = ["--lib"] if suite == "protocol_library" else ["--test", suite]
            argv = ["cargo", "test", "--locked", *target, "--", "--test-threads=1", "--nocapture"]
            if suite == "protocol_library":
                argv.append("--include-ignored")
            elif suite in ("protocol_e2e", "security_listener"):
                argv.append("--ignored")
            report["commands"].append({"argv": argv, "log": f"{suite}.log"})
            root.joinpath(f"{suite}-list.log").write_text("".join(f"{name}: test\n" for name in selected))
            root.joinpath(f"{suite}.log").write_text(
                f"test result: ok. {len(selected)} passed; 0 failed; 0 ignored; 0 measured;\n")
        path = root / "report.json"
        path.write_text(json.dumps(report))
        return path, report

    def test_real_references_are_valid_without_claiming_execution(self):
        self.assertEqual(len(self.entries), 40)
        self.assertEqual({entry["id"] for entry in self.entries}, contracts.REQUIRED_IDS)

    def test_empty_missing_duplicate_and_stale_references_are_rejected(self):
        def missing(document):
            document["contracts"].pop()

        def duplicate(document):
            document["contracts"].append(copy.deepcopy(document["contracts"][0]))

        def stale_heading(document):
            document["contracts"][0]["spec"] = "## A heading that does not exist"

        def stale_symbol(document):
            document["contracts"][0]["sources"][0]["symbol"] = "removed_parser"

        def stale_selector(document):
            document["contracts"][0]["tests"][0]["name"] = "wrong_module::generated_socks_formats_preserve_payload_under_short_reads_and_every_eof"

        def no_tests(document):
            document["contracts"][0]["tests"] = []

        for mutation in (missing, duplicate, stale_heading, stale_symbol, stale_selector, no_tests):
            with self.subTest(mutation=mutation.__name__):
                document = copy.deepcopy(self.document)
                mutation(document)
                with self.assertRaises(ValueError):
                    contracts.validate_ledger(document)
        with self.assertRaisesRegex(ValueError, "empty protocol"):
            contracts.validate_ledger({"schema_version": 1, "scope": "fixture", "contracts": []})

    def test_rust_scope_index_ignores_strings_comments_and_non_tests(self):
        source = '''
const LIMIT: usize = 3;
fn production() {}
const TEXT: &str = r###"mod bogus { #[test] fn fake() {} }"###;
/* outer /* nested } */ #[test] fn also_fake() {} */
#[cfg(test)]
mod tests {
    #[test]
    fn real() { let brace = '}'; let text = "mod bogus {"; }
    mod nested {
        #[tokio::test(start_paused = true)]
        async fn asynchronous() {}
    }
    fn helper() {}
}
'''
        functions, constants, tests = contracts.rust_index(source, "unit")
        self.assertEqual(tests, {"unit::tests::real", "unit::tests::nested::asynchronous"})
        self.assertTrue({"production", "real", "asynchronous", "helper"} <= functions)
        self.assertFalse({"fake", "also_fake"} & functions)
        self.assertIn("LIMIT", constants)

    def test_complete_matching_evidence_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.fixture(directory)
            contracts.validate_evidence(self.entries, path, COMMIT)

    def test_cli_rejects_changes_after_a_clean_execution(self):
        with mock.patch.object(contracts.sys, "argv", ["contracts", "--evidence", "unused.json"]), \
                mock.patch.object(contracts.subprocess, "check_output",
                                  side_effect=[COMMIT, " M src/client/socks.rs\n"]), \
                contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(contracts.main(), 1)
        self.assertIn("current working tree changed", output.getvalue())

    def test_stale_dirty_incomplete_and_unbounded_reports_are_rejected(self):
        changes = [
            lambda report: report.update(status="running"),
            lambda report: report.update(status="failed"),
            lambda report: report.update(kind="listener"),
            lambda report: report.update(source_commit="b" * 40),
            lambda report: report.update(working_tree_dirty=True),
            lambda report: report.update(commands=[]),
            lambda report: report.update(tests={}),
            lambda report: report.update(bounds={}),
            lambda report: report["bounds"].update(PARALLAX_PROP_CASES="0"),
            lambda report: report["bounds"].update(PARALLAX_PROP_CASES="10001"),
            lambda report: report["bounds"].update(PARALLAX_PROP_SEED=str(1 << 64)),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for index, change in enumerate(changes):
                with self.subTest(case=index):
                    path, report = self.fixture(directory)
                    change(report)
                    path.write_text(json.dumps(report))
                    with self.assertRaises(ValueError):
                        contracts.validate_evidence(self.entries, path, COMMIT)

    def test_empty_failed_ignored_duplicate_or_omitted_test_selections_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("empty", "failed", "ignored", "duplicate", "omitted", "false_count"):
                with self.subTest(mode=mode):
                    path, report = self.fixture(directory)
                    entry = report["tests"]["protocol_carrier"]
                    if mode == "empty":
                        entry.update(selected=[], passed=0)
                    elif mode == "failed":
                        entry["failed"] = 1
                    elif mode == "ignored":
                        entry["ignored"] = 1
                    elif mode == "duplicate":
                        entry["selected"].append(entry["selected"][0])
                        entry["passed"] += 1
                    elif mode == "omitted":
                        entry["selected"].pop()
                        entry["passed"] -= 1
                    else:
                        entry["passed"] = True
                    path.write_text(json.dumps(report))
                    with self.assertRaises(ValueError):
                        contracts.validate_evidence(self.entries, path, COMMIT)

    def test_retained_logs_and_locked_target_commands_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("no_summary", "wrong_count", "wrong_selection", "dirty_log", "toolchain", "unlocked", "wrong_target"):
                with self.subTest(mode=mode):
                    path, report = self.fixture(directory)
                    if mode == "no_summary":
                        path.with_name("protocol_carrier.log").write_text("Compilation completed successfully\n")
                    elif mode == "wrong_count":
                        path.with_name("protocol_carrier.log").write_text("test result: ok. 0 passed; 0 failed; 0 ignored;\n")
                    elif mode == "wrong_selection":
                        path.with_name("protocol_carrier-list.log").write_text("different_test: test\n")
                    elif mode == "dirty_log":
                        path.with_name("source-status.log").write_text(" M src/lib.rs\n")
                    elif mode == "toolchain":
                        path.with_name("toolchain.log").write_text("a different compiler\n")
                    else:
                        command = next(value for value in report["commands"] if value["log"] == "protocol_carrier.log")
                        if mode == "unlocked":
                            command["argv"].remove("--locked")
                        else:
                            command["argv"][command["argv"].index("protocol_carrier")] = "protocol_properties"
                        path.write_text(json.dumps(report))
                    with self.assertRaises(ValueError):
                        contracts.validate_evidence(self.entries, path, COMMIT)
            path, _ = self.fixture(directory)
            path.with_name("protocol_carrier.log").unlink()
            with self.assertRaises(OSError):
                contracts.validate_evidence(self.entries, path, COMMIT)


if __name__ == "__main__":
    unittest.main()
