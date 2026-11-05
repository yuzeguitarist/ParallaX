"""Controls against vacuous sanitizer success and environment contamination."""
import importlib.util
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "parallax_sanitizers", ROOT / "scripts/security/sanitizers.py")
sanitizers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sanitizers)


class SanitizerControls(unittest.TestCase):
    def test_runtime_builder_can_clean_up_before_timeout_failure(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
                sanitizers, "ROOT", Path(temporary)):
            marker = Path(temporary) / "cleanup-complete"
            code = (
                "import pathlib, signal, sys, time\n"
                "def stop(signum, frame):\n"
                "    pathlib.Path(sys.argv[1]).write_text('cleaned')\n"
                "    raise SystemExit(0)\n"
                "signal.signal(signal.SIGTERM, stop)\n"
                "time.sleep(60)\n"
            )
            runner = sanitizers.Runner("thread", sanitizers.NIGHTLY, False)
            with self.assertRaisesRegex(RuntimeError, "exceeded 2s"):
                runner.run("tsan-runtime-build", [sys.executable, "-c", code, str(marker)],
                           timeout=2)
            self.assertEqual(marker.read_text(), "cleaned")

    def test_epoll_control_requires_clean_completed_execution(self):
        marker = "sanitizer-epoll-publication-control-complete: duplicate-fd"
        for code, output in ((66, marker), (0, ""), (0, marker + " ThreadSanitizer: data race")):
            self.assertFalse(sanitizers.epoll_control_completed(
                subprocess.CompletedProcess([], code, output), "duplicate-fd"))
        self.assertTrue(sanitizers.epoll_control_completed(
            subprocess.CompletedProcess([], 0, marker), "duplicate-fd"))

    def test_runtime_inputs_and_artifact_hashes_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive = directory / "runtime with spaces.a"
            symbols = directory / "runtime with spaces.a.syms"
            archive.write_bytes(b"archive fixture")
            symbols.write_bytes(b"symbols fixture")
            report = {"schema": 1, "status": "passed", "source_commit": sanitizers.TSAN_SOURCE,
                      "patch_commit": sanitizers.TSAN_PATCH}
            for key, path in (("archive", archive), ("dynamic_list", symbols)):
                report[key] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            args = sanitizers.runtime_link_arguments(report, directory)
            self.assertIn(str(archive.resolve()), args)
            self.assertIn(f"-Wl,--dynamic-list={symbols.resolve()}", args)
            for key, value in (("status", "running"), ("source_commit", "main"),
                               ("patch_commit", "main"), ("schema", 2), ("archive", [])):
                with self.assertRaises(RuntimeError):
                    sanitizers.runtime_link_arguments({**report, key: value}, directory)
            with self.assertRaises(RuntimeError):
                sanitizers.runtime_link_arguments(report, directory / "different-root")
            archive.write_bytes(b"changed archive")
            with self.assertRaises(RuntimeError):
                sanitizers.runtime_link_arguments(report, directory)

    def test_compile_or_loader_failure_does_not_count_as_detection(self):
        for kind, diagnostic in sanitizers.DIAGNOSTICS.items():
            self.assertFalse(sanitizers.expected_detection(kind, 1, "compile error"))
            self.assertFalse(sanitizers.expected_detection(kind, 0, diagnostic))
            self.assertTrue(sanitizers.expected_detection(kind, 23, diagnostic))

    def test_empty_or_filtered_list_cannot_pass(self):
        self.assertEqual(sanitizers.listed_tests("0 tests, 0 benchmarks\n"), [])
        self.assertEqual(sanitizers.listed_tests("compile note: test\n"), [])
        self.assertEqual(sanitizers.listed_tests("a::b: test\nc: benchmark\n"), ["a::b"])

    def test_dedicated_suites_cannot_silently_ignore_cases(self):
        output = "test result: ok. 1 passed; 0 failed; 1 ignored;"
        with self.assertRaises(RuntimeError):
            sanitizers.completed_counts(output, 2)
        self.assertEqual(sanitizers.completed_counts(output, 2, allow_ignored=True),
                         {"passed": 1, "failed": 0, "ignored": 1})
        with self.assertRaises(RuntimeError):
            sanitizers.completed_counts("test result: ok. 0 passed; 0 failed; 0 ignored;", 0)

    def test_runtime_failure_remains_failure_after_collecting_other_suites(self):
        listing = subprocess.CompletedProcess([], 0, "case: test\n", None)
        success = subprocess.CompletedProcess(
            [], 0, "test result: ok. 1 passed; 0 failed; 0 ignored;", None)
        with tempfile.TemporaryDirectory() as directory, patch.object(
                sanitizers, "ROOT", Path(directory)), patch.object(
                sanitizers, "SUITES", (("first", [], []), ("second", [], []))):
            runner = sanitizers.Runner("thread", sanitizers.NIGHTLY, False)
            with patch.object(runner, "run", side_effect=[listing, RuntimeError("race"),
                                                          listing, success]), patch.object(
                    runner, "native_inventory"):
                with self.assertRaisesRegex(RuntimeError, "failed: first"):
                    runner.application()
            self.assertEqual(runner.report["tests"]["first"]["status"], "failed")
            self.assertEqual(runner.report["tests"]["second"]["status"], "passed")

    def test_flags_and_suppressions_are_not_inherited(self):
        contaminated = {
            "RUSTFLAGS": "-Copt-level=3", "CARGO_ENCODED_RUSTFLAGS": "bad",
            "CFLAGS_x86_64-unknown-linux-gnu": "-fno-sanitize=all",
            "TSAN_OPTIONS": "suppressions=/tmp/ignore-everything",
            "LSAN_OPTIONS": "detect_leaks=0", "PATH": os.environ.get("PATH", ""),
        }
        with patch.dict(os.environ, contaminated, clear=True):
            env = sanitizers.configured_environment("thread", Path("/tmp/sanitized"))
        self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", env)
        self.assertNotIn("CFLAGS_x86_64-unknown-linux-gnu", env)
        self.assertIn("-Zsanitizer=thread", env["RUSTFLAGS"])
        self.assertIn("-fsanitize=thread", env["CFLAGS_x86_64_unknown_linux_gnu"])
        self.assertNotIn("suppressions", env["TSAN_OPTIONS"])
        self.assertNotIn("detect_leaks=0", env["LSAN_OPTIONS"])

    def test_native_and_production_paths_are_selected(self):
        names = {name for name, _, _ in sanitizers.SUITES}
        self.assertTrue({"library", "linux-fd-lifetimes", "production-cert-tunnel",
                         "mldsa-oracle", "fault-injection"} <= names)
        workflow = (ROOT / ".github/workflows/security-sanitizers.yml").read_text()
        self.assertIn("kind: [address, thread, leak]", workflow)
        self.assertNotIn("continue-on-error", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("id-token: write", workflow)


if __name__ == "__main__":
    unittest.main()
