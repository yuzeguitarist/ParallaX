#!/usr/bin/env python3
"""Negative tests for the zero-exemption policy and fail-closed audit reporting."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dependencies", ROOT / "scripts/security/dependencies.py")
DEP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEP)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        # Prevent inherited Git configuration from launching fsmonitor (or
        # redirecting the repository) while temporary policy fixtures exist.
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
        isolation = patch.dict(os.environ, env, clear=True)
        isolation.start()
        self.addCleanup(isolation.stop)
        self.temp = tempfile.TemporaryDirectory()
        # Clean up the repository before restoring inherited Git configuration.
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        for manifest, store, _, _ in DEP.WORKSPACES.values():
            for filename in (manifest, str(Path(manifest).with_name("Cargo.lock")),
                             f"{store}/config.toml", f"{store}/audits.toml", f"{store}/imports.lock"):
                destination = self.root / filename
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / filename, destination)
        self.std = self.root / DEP.STD_ONLY
        self.std.parent.mkdir(parents=True)
        self.std.write_text('[package]\nname="parallax-sanitizer-canaries"\nversion="0.0.0"\npublish=false\n[workspace]\n')
        self.std.with_name("Cargo.lock").write_text('version=3\n[[package]]\nname="parallax-sanitizer-canaries"\nversion="0.0.0"\n')

    def test_valid_policy_has_no_exemptions(self):
        protected = DEP.policy(self.root)
        self.assertEqual(len(protected), 22)

    def test_new_or_missing_workspace_is_rejected(self):
        extra = self.root / "extra/Cargo.toml"
        extra.parent.mkdir()
        extra.write_text("[workspace]\n")
        with self.assertRaisesRegex(ValueError, "Uncovered/missing"):
            DEP.policy(self.root)
        extra.unlink()
        self.std.unlink()
        with self.assertRaisesRegex(ValueError, "Uncovered/missing"):
            DEP.policy(self.root)

    def test_exact_exemption_is_still_prohibited(self):
        config = DEP.read_toml(self.root / "supply-chain/config.toml")
        config["exemptions"] = {"innocent-name": [{"version": "1.0.0", "criteria": "safe-to-deploy"}]}
        with self.assertRaisesRegex(ValueError, "exemptions are prohibited"):
            DEP.validate_config(config, "main")

    def test_no_criteria_lowering_or_remapping(self):
        original = DEP.read_toml(self.root / "supply-chain/config.toml")
        config = copy.deepcopy(original)
        config["policy"]["parallax"]["criteria"] = "safe-to-run"
        with self.assertRaisesRegex(ValueError, "changed audit criteria"):
            DEP.validate_config(config, "main")
        config = copy.deepcopy(original)
        config["imports"]["google"]["criteria-map"] = {"safe-to-run": "safe-to-deploy"}
        with self.assertRaisesRegex(ValueError, "remapping"):
            DEP.validate_config(config, "main")

    def test_import_url_and_snapshot_bytes_are_pinned(self):
        config = DEP.read_toml(self.root / "supply-chain/config.toml")
        config["imports"]["google"]["url"] = "https://example.invalid/audits.toml"
        with self.assertRaisesRegex(ValueError, "immutable snapshot"):
            DEP.validate_config(config, "main")
        imported = self.root / "supply-chain/imports.lock"
        imported.write_text(imported.read_text() + "\n# replacement snapshot\n")
        with self.assertRaisesRegex(ValueError, "snapshot bytes changed"):
            DEP.policy(self.root)

    def test_wildcard_and_publisher_trust_are_rejected_recursively(self):
        for key in ("trusted", "publisher", "wildcard-audits"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "trust is prohibited"):
                DEP.no_blanket_trust({"audits": {"nested": {key: {"crate": [{"user-id": 1}]}}}})

    def test_local_custom_criterion_cannot_override_builtin(self):
        path = self.root / "supply-chain/audits.toml"
        path.write_text(path.read_text() + '\n[criteria.safe-to-deploy]\ndescription="anything"\n')
        with self.assertRaisesRegex(ValueError, "criteria overrides"):
            DEP.policy(self.root)

    def test_std_only_exclusion_closes_on_new_dependency(self):
        self.std.write_text(self.std.read_text() + '\n[target."cfg(unix)".dependencies]\nlibc="0.2"\n')
        with self.assertRaisesRegex(ValueError, "acquired dependencies"):
            DEP.policy(self.root)

    def test_std_only_rejects_legacy_dependency_aliases_in_every_table(self):
        original = self.std.read_text()
        for table in ("dev_dependencies", "build_dependencies",
                      'target."cfg(unix)".dev_dependencies', 'target."cfg(unix)".build_dependencies',
                      "workspace.dev_dependencies", "workspace.build_dependencies"):
            with self.subTest(table=table):
                # Keep the one-package lock unchanged: manifest validation
                # must reject Cargo 2021 aliases before stale-lock detection.
                self.std.write_text(original + f'\n[{table}]\nlibc="0.2"\n')
                with self.assertRaisesRegex(ValueError, "acquired dependencies"):
                    DEP.policy(self.root)

    def test_std_only_lock_cannot_hide_third_party_package(self):
        path = self.std.with_name("Cargo.lock")
        path.write_text(path.read_text() + '\n[[package]]\nname="libc"\nversion="0.2.0"\n')
        with self.assertRaisesRegex(ValueError, "lock acquired packages"):
            DEP.policy(self.root)

    def test_git_dependencies_require_explicit_review(self):
        path = self.root / "Cargo.lock"
        path.write_text(path.read_text().replace(
            "registry+https://github.com/rust-lang/crates.io-index",
            "git+https://example.invalid/dep#123", 1))
        with self.assertRaisesRegex(ValueError, "unreviewed registry/git"):
            DEP.policy(self.root)

    def test_report_survives_missing_audits_and_exit_stays_nonzero(self):
        report_path = self.root / "report.json"
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if "--version" in args:
                return subprocess.CompletedProcess(args, 0, "cargo-vet 0.10.3\n", "")
            if args[:2] == ["cargo", "fetch"]:
                self.assertIn("--locked", args)
                return subprocess.CompletedProcess(args, 0, "", "")
            self.assertIn("--locked", args)
            self.assertIn("--frozen", args)
            self.assertIn("--no-minimize-exemptions", args)
            self.assertNotIn("init", args)
            return subprocess.CompletedProcess(args, 255, json.dumps({
                "conclusion": "fail (vetting)",
                "failures": [{"name": "missing", "version": "1.2.3", "missing_criteria": ["safe-to-run"]}],
            }), "")
        protected = DEP.policy(self.root)
        with patch.object(DEP.subprocess, "run", side_effect=run), patch.object(
                DEP.subprocess, "check_output", return_value="a" * 40 + "\n"):
            result = DEP.check(self.root, protected, None, report_path)
        self.assertEqual(result, 1)
        report = json.loads(report_path.read_text())
        self.assertFalse(report["passed"])
        self.assertEqual(len(report["workspaces"]), 4)
        self.assertTrue(all(value["missing_audit_count"] == 1 for value in report["workspaces"].values()))
        self.assertTrue(all(value["exit_code"] == 255 for value in report["workspaces"].values()))


if __name__ == "__main__":
    unittest.main()
