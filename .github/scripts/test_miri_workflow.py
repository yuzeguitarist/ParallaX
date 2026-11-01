#!/usr/bin/env python3
"""Exercise the Miri workflow's per-module coverage gate with mocked cargo."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).parents[1] / "workflows" / "miri.yml"
FILTERS = (
    "transport::udp::quic::varint::",
    "transport::udp::quic::frame::",
    "traffic::",
    "protocol::command::",
)


def script():
    for block in re.split(r"(?=^      - )", WORKFLOW.read_text(), flags=re.M):
        if block.startswith("      - name: cargo miri test ("):
            return textwrap.dedent(block.split("        run: |\n", 1)[1])
    raise AssertionError("Missing Miri test step")


class MiriWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "cargo.jsonl"
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "TOOL_LOG": str(self.log),
        }
        cargo = self.bin / "cargo"
        cargo.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
            import json
            import os
            import sys

            args = sys.argv[1:]
            with open(os.environ["TOOL_LOG"], "a") as log:
                log.write(json.dumps(args) + "\\n")
            assert args[:6] == ["+nightly", "miri", "test", "--locked", "--lib", "--"]
            test_filter = args[6]
            if args[7:] == ["--list"]:
                if test_filter == os.environ.get("LIST_FAIL_FILTER"):
                    sys.exit(42)
                if test_filter == os.environ.get("EMPTY_FILTER"):
                    print("0 tests, 0 benchmarks")
                else:
                    print(f"{test_filter}tests::example: test\\n\\n1 test, 0 benchmarks")
            else:
                assert args[7:] == []
                if test_filter == os.environ.get("RUN_FAIL_FILTER"):
                    sys.exit(43)
            '''))
        cargo.chmod(0o755)

    def run_workflow(self, **env):
        self.log.write_text("")
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", script()],
            cwd=self.root, env={**self.env, **env},
            text=True, capture_output=True,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, calls

    def test_each_module_is_listed_and_run_separately(self):
        result, calls = self.run_workflow()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = []
        for test_filter in FILTERS:
            command = ["+nightly", "miri", "test", "--locked", "--lib", "--", test_filter]
            expected.extend([command + ["--list"], command])
        self.assertEqual(calls, expected)

    def test_any_empty_filter_fails_before_running_that_module(self):
        for index, test_filter in enumerate(FILTERS):
            with self.subTest(test_filter=test_filter):
                result, calls = self.run_workflow(EMPTY_FILTER=test_filter)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"::error::Miri filter matched no tests: {test_filter}",
                              result.stdout)
                self.assertEqual(len(calls), 2 * index + 1)
                self.assertEqual(calls[-1][-2:], [test_filter, "--list"])

    def test_list_failures_propagate(self):
        for index, test_filter in enumerate(FILTERS):
            with self.subTest(test_filter=test_filter):
                result, calls = self.run_workflow(LIST_FAIL_FILTER=test_filter)
                self.assertEqual(result.returncode, 42)
                self.assertEqual(len(calls), 2 * index + 1)

    def test_miri_failures_propagate(self):
        result, calls = self.run_workflow(RUN_FAIL_FILTER=FILTERS[0])
        self.assertEqual(result.returncode, 43)
        self.assertEqual(len(calls), 2)

    def test_path_triggers_cover_current_modules(self):
        workflow = WORKFLOW.read_text()
        self.assertNotIn("reorder", workflow)
        for path in (
            "src/transport/udp/quic/varint.rs",
            "src/transport/udp/quic/frame.rs",
            "src/traffic.rs",
            "src/protocol/command.rs",
        ):
            self.assertTrue((WORKFLOW.parents[2] / path).is_file(), path)
            self.assertEqual(workflow.count(f"      - '{path}'"), 2, path)


if __name__ == "__main__":
    unittest.main()
