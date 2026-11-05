"""Controls against vacuous sanitizer success and environment contamination."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "parallax_sanitizers", ROOT / "scripts/security/sanitizers.py")
sanitizers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sanitizers)


class SanitizerControls(unittest.TestCase):
    def test_compile_or_loader_failure_does_not_count_as_detection(self):
        for kind, diagnostic in sanitizers.DIAGNOSTICS.items():
            self.assertFalse(sanitizers.expected_detection(kind, 1, "compile error"))
            self.assertFalse(sanitizers.expected_detection(kind, 0, diagnostic))
            self.assertTrue(sanitizers.expected_detection(kind, 23, diagnostic))

    def test_empty_or_filtered_list_cannot_pass(self):
        self.assertEqual(sanitizers.listed_tests("0 tests, 0 benchmarks\n"), [])
        self.assertEqual(sanitizers.listed_tests("compile note: test\n"), [])
        self.assertEqual(sanitizers.listed_tests("a::b: test\nc: benchmark\n"), ["a::b"])

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
