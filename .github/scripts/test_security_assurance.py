"""Fail-closed selection and completion checks for the security runner."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "parallax_assurance", ROOT / "scripts/security/assurance.py")
assurance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assurance)


class AssuranceControls(unittest.TestCase):
    def test_empty_filtered_or_ignored_runs_are_rejected(self):
        for output, selected in [
            ("test result: ok. 0 passed; 0 failed; 0 ignored;", 0),
            ("test result: ok. 0 passed; 0 failed; 1 ignored;", 1),
            ("test result: ok. 1 passed; 0 failed; 0 ignored;", 2),
            ("Compilation completed successfully", 3),
        ]:
            with self.assertRaises(RuntimeError):
                assurance.checked_summary(output, selected)

    def test_nonempty_complete_result_is_accepted(self):
        result = assurance.checked_summary(
            "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured;", 2)
        self.assertEqual(result, {"passed": 2, "failed": 0, "ignored": 0})
        self.assertEqual(assurance.selected_tests(
            "compiler note: test\nalpha::beta: test\ngamma: benchmark\n"),
            ["alpha::beta"])

    def test_real_listener_and_isolated_models_are_selected(self):
        listener = assurance.selections("listener")
        self.assertIn("security_listener", listener[0][1])
        self.assertEqual(listener[0][2], ["--ignored"])
        for kind in ("loom", "shuttle"):
            command = assurance.selections(kind)[0][1]
            self.assertIn("verification/concurrency/Cargo.toml", command)
            self.assertIn("--locked", command)
            self.assertIn("--release", command)
            self.assertEqual(command[-4:], ["--features", kind, "--test", kind])


if __name__ == "__main__":
    unittest.main()
