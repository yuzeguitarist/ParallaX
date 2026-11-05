"""Fail-closed selection and completion checks for the security runner."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest import mock

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

    def test_native_backend_is_selected_without_model_features(self):
        command = assurance.selections("std")[0][1]
        self.assertIn("verification/concurrency/Cargo.toml", command)
        self.assertIn("--locked", command)
        self.assertNotIn("--features", command)
        self.assertEqual(command[-2:], ["--test", "std"])
        workflow = (ROOT / ".github/workflows/security-assurance.yml").read_text()
        self.assertIn("- suite: std\n            toolchain: stable", workflow)

    def test_encoded_replay_requires_exact_shuttle_case(self):
        for arguments, environment in [
            (["shuttle", "--plan"], {"PARALLAX_SHUTTLE_REPLAY": "schedule"}),
            (["std", "--plan", "--replay-test", "fd_unwind_releases"],
             {"PARALLAX_SHUTTLE_REPLAY": "schedule"}),
            (["shuttle", "--plan", "--replay-test", "fd_unwind_releases"], {}),
        ]:
            with self.subTest(arguments=arguments), \
                    mock.patch.dict(assurance.os.environ, environment, clear=True), \
                    mock.patch.object(assurance.sys, "argv", ["assurance.py", *arguments]), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                assurance.main()
            self.assertEqual(error.exception.code, 2)

        with mock.patch.dict(assurance.os.environ,
                             {"PARALLAX_SHUTTLE_REPLAY": "schedule"}, clear=True), \
                mock.patch.object(assurance.sys, "argv", [
                    "assurance.py", "shuttle", "--plan", "--replay-test", "fd_unwind_releases"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(assurance.main(), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan[0][2], ["fd_unwind_releases", "--exact"])
        self.assertEqual(assurance.selections("shuttle")[0][2], [])


if __name__ == "__main__":
    unittest.main()
