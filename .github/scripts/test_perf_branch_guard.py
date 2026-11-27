#!/usr/bin/env python3
"""Exercise the perf/latency-peak no-regression guard."""

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import check_perf_branch_guard as guard  # noqa: E402

WORKFLOWS = Path(__file__).parents[1] / "workflows"


class PerfBranchGuardTests(unittest.TestCase):
    def test_every_main_gate_also_gates_the_perf_branch(self):
        self.assertEqual(guard.ungated_workflows(WORKFLOWS), [])

    def test_the_guard_workflow_runs_on_perf_branch_pull_requests(self):
        text = (WORKFLOWS / "perf-branch-guard.yml").read_text()
        self.assertEqual(guard.pr_branches(text), [guard.BRANCH])
        self.assertIn("check_perf_branch_guard.py", text)

    def test_branch_filters_are_parsed_inline_and_listed(self):
        inline = "on:\n  pull_request:\n    branches: [main, 'perf/latency-peak']\n  push:\n    branches: [main]\n"
        listed = "on:\n  pull_request:\n    branches:\n      - main\n      - master\n    paths:\n      - 'src/**'\n"
        self.assertEqual(guard.pr_branches(inline), ["main", "perf/latency-peak"])
        self.assertEqual(guard.pr_branches(listed), ["main", "master"])
        self.assertIsNone(guard.pr_branches("on:\n  pull_request:\n    paths: ['src/**']\n"))
        self.assertIsNone(guard.pr_branches("on:\n  push:\n    branches: [main]\n"))

    def test_ungated_workflow_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.yml").write_text("on:\n  pull_request:\n    branches: [main, master]\n")
            (root / "b.yml").write_text("on:\n  pull_request:\n    branches: [main, 'perf/latency-peak']\n")
            (root / "c.yml").write_text("on:\n  pull_request:\n")
            (root / "d.yaml").write_text("on:\n  pull_request:\n    branches: [main]\n")
            self.assertEqual(guard.ungated_workflows(root), ["a.yml", "d.yaml"])

    def test_rust_tests_are_counted_with_ignore_state(self):
        total, active = guard.rust_tests(
            "#[test]\nfn plain() {}\n"
            "#[tokio::test(flavor = \"current_thread\")]\n#[ignore = \"loopback\"]\nasync fn looped() {}\n"
            "#[ignore]\n#[test]\npub(crate) fn skipped() {}\n"
            "#[cfg(test)]\nfn helper() {}\n"
            "#[test]\n// comment\nfn commented() {}\n"
        )
        self.assertEqual(dict(total), {"plain": 1, "looped": 1, "skipped": 1, "commented": 1})
        self.assertEqual(dict(active), {"plain": 1, "commented": 1})

    def test_cfg_gated_tests_are_not_counted_as_active(self):
        total, active = guard.rust_tests(
            "#[test]\n#[cfg(any())]\nfn compiled_out() {}\n"
            "#[cfg_attr(not(feature = \"x\"), ignore)]\n#[test]\nfn maybe_ignored() {}\n"
            "#[test]\nfn plain() {}\n"
        )
        self.assertEqual(dict(total), {"compiled_out": 1, "maybe_ignored": 1, "plain": 1})
        self.assertEqual(dict(active), {"plain": 1})


if __name__ == "__main__":
    unittest.main()
