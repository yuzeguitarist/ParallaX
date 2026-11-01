#!/usr/bin/env python3
"""Exercise the PR fuzz workflow shell with local artifacts and mocked tools."""

import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).parents[1] / "workflows" / "fuzz-pr.yml"


def step(name):
    for block in re.split(r"(?=^      - )", WORKFLOW.read_text(), flags=re.M):
        if block.startswith(f"      - name: {name}\n"):
            return block
    raise AssertionError(f"Missing workflow step: {name}")


def script(name):
    return textwrap.dedent(step(name).split("        run: |\n", 1)[1])


class FuzzPrWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.artifacts = self.root / "fuzz" / "artifacts" / "decode_record"
        self.summary = self.root / "summary"
        self.summary.touch()
        self.output = self.root / "environment"
        self.output.touch()
        self.log = self.root / "tools.jsonl"
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "TARGET": "decode_record",
            "FUZZ_SANITIZER": "address",
            "FUZZ_RSS": "2048",
            "FUZZ_TIMEOUT": "10",
            "FUZZ_MAXLEN": "4096",
            "GITHUB_ENV": str(self.output),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "GITHUB_REPOSITORY": "test/parallax",
            "TOOL_LOG": str(self.log),
        }
        cargo = self.bin / "cargo"
        cargo.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
            import base64
            import json
            import os
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            with open(os.environ["TOOL_LOG"], "a") as log:
                log.write(json.dumps(["cargo", *args]) + "\\n")
            if args[2] == "tmin":
                if not Path(args[-1]).is_file():
                    sys.exit(91)
                if os.environ.get("TMIN_FAIL"):
                    sys.exit(1)
                if os.environ.get("MIN_NAME"):
                    output = Path(args[-1]).parent / os.environ["MIN_NAME"]
                    output.write_bytes(base64.b64decode(os.environ["MIN_BYTES"]))
            else:
                if os.environ.get("CRASH_NAME"):
                    output = Path("fuzz/artifacts") / os.environ["TARGET"] / os.environ["CRASH_NAME"]
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(base64.b64decode(os.environ["CRASH_BYTES"]))
                sys.exit(int(os.environ.get("RUN_RC", "0")))
            '''))
        cargo.chmod(0o755)
        gh = self.bin / "gh"
        gh.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
            import json
            import os
            import sys

            with open(os.environ["TOOL_LOG"], "a") as log:
                log.write(json.dumps(["gh", *sys.argv[1:]]) + "\\n")
            sys.exit(1)
            '''))
        gh.chmod(0o755)

    def run_step(self, name, **env):
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", script(name)],
            cwd=self.root, env={**self.env, **env},
            text=True, capture_output=True,
        )

    def crash(self, name="crash-test", payload=b"\x00raw\xff\n", **env):
        result = self.run_step(
            "Smoke fuzz (non-blocking)", RUN_RC="77", CRASH_NAME=name,
            CRASH_BYTES=base64.b64encode(payload).decode(), **env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), "FUZZ_RC=77\n")
        return self.artifacts / name

    def annotate(self, payload, **env):
        result = self.run_step("Annotate crash (warn only, never blocks)", **env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("::warning title=fuzz smoke crash::decode_record crashed",
                      result.stdout)
        match = re.search(r"```\n(.*?)\n```", self.summary.read_text(), re.S)
        self.assertIsNotNone(match, self.summary.read_text())
        self.assertEqual(base64.b64decode(match[1]), payload)
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_failed_minimization_embeds_original_and_keeps_raw_artifact(self):
        raw = self.crash()
        (self.artifacts / "minimized-from-stale").write_bytes(b"unrelated")
        calls = self.annotate(raw.read_bytes(), TMIN_FAIL="1")
        self.assertEqual(calls[-1][-1], "fuzz/artifacts/decode_record/crash-test")
        self.assertEqual(raw.read_bytes(), b"\x00raw\xff\n")
        self.assertTrue(all(call[0] == "cargo" for call in calls))

    def test_successful_minimization_embeds_minimized_bytes(self):
        raw = self.crash()
        self.annotate(b"\x00min\xff", MIN_NAME="minimized-from-test",
                      MIN_BYTES=base64.b64encode(b"\x00min\xff").decode())
        self.assertTrue(raw.is_file())

    def test_success_without_minimized_file_uses_original(self):
        raw = self.crash()
        self.annotate(raw.read_bytes())

    def test_odd_artifact_filenames_remain_exact_arguments(self):
        name = 'crash-spaces \t"$(touch INJECTED)"\nlast line\n'
        raw = self.crash(name)
        calls = self.annotate(
            b"small", MIN_NAME="minimized-from-spaces \t\nlast line\n",
            MIN_BYTES=base64.b64encode(b"small").decode(),
        )
        self.assertEqual(calls[-1][-1], f"fuzz/artifacts/decode_record/{name}")
        self.assertTrue(raw.is_file())
        self.assertFalse((self.root / "INJECTED").exists())

    def test_newest_raw_artifact_is_selected_and_handled_files_are_skipped(self):
        raw = self.crash()
        os.utime(raw, (1, 1))
        for name in ("oom-new", "timeout-new"):
            with self.subTest(name=name):
                chosen = self.artifacts / name
                chosen.write_bytes(name.encode())
                os.utime(chosen, (2, 2))
                handled = self.artifacts / f"{name}.handled"
                handled.write_bytes(b"handled")
                os.utime(handled, (3, 3))
                self.summary.write_text("")
                calls = self.annotate(name.encode(), TMIN_FAIL="1")
                self.assertEqual(calls[-1][-1], f"fuzz/artifacts/decode_record/{name}")
                chosen.unlink()

    def test_failed_run_without_artifacts_still_warns(self):
        result = self.run_step("Annotate crash (warn only, never blocks)")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("::warning", result.stdout)
        self.assertIn("CRASHED (non-blocking)", self.summary.read_text())
        self.assertNotIn("base64", self.summary.read_text())
        self.assertFalse(self.log.exists())

    def test_successful_smoke_has_zero_status_and_no_artifacts(self):
        result = self.run_step("Smoke fuzz (non-blocking)")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), "FUZZ_RC=0\n")
        self.assertFalse(self.artifacts.exists())
        self.assertIn("if: env.FUZZ_RC != '0'", step("Annotate crash (warn only, never blocks)"))

    def test_seed_download_is_read_only_and_offline_failure_is_nonblocking(self):
        bootstrap = self.root / "ops/fuzz-cluster/bootstrap.sh"
        bootstrap.parent.mkdir(parents=True)
        bootstrap.write_text('CAMPAIGN_TAG="fuzz-corpus-test"\n')
        result = self.run_step("Seed corpus from VPS Release (read-only)")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(calls, [["gh", "release", "download", "fuzz-corpus-test",
                                 "--repo", "test/parallax", "-p",
                                 "corpus-decode_record.tar.zst", "-D", "/tmp/seed"]])

    def test_raw_upload_is_pinned_bounded_and_precedes_minimization(self):
        workflow = WORKFLOW.read_text()
        upload = step("Preserve raw crash artifacts")
        self.assertIn("if: always() && env.FUZZ_RC != '0'", upload)
        self.assertRegex(upload, r"uses: actions/upload-artifact@[0-9a-f]{40}\b")
        self.assertIn("path: fuzz/artifacts/${{ matrix.target }}/", upload)
        self.assertIn("if-no-files-found: ignore", upload)
        self.assertIn("retention-days: 7", upload)
        self.assertIn("name: fuzz-pr-${{ matrix.target }}-${{ github.run_attempt }}", upload)
        self.assertLess(workflow.index("name: Preserve raw crash artifacts"),
                        workflow.index("name: Annotate crash"))
        self.assertIn("  pull_request:\n", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s+[\w-]+: write\s*$")
        self.assertNotIn("secrets.", workflow)


if __name__ == "__main__":
    unittest.main()
