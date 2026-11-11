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
import textwrap
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

    def commit_base(self):
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "-c", "user.name=Policy Test", "-c", "user.email=test@example.invalid",
                        "commit", "--allow-empty", "-qm", "base", "--no-gpg-sign"], cwd=self.root, check=True)
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()

    def test_base_snapshot_cannot_change_with_its_current_digest(self):
        base = self.commit_base()
        DEP.policy(self.root, base)
        for workspace, (_, store, _, _) in DEP.WORKSPACES.items():
            with self.subTest(workspace=workspace):
                path = self.root / store / "imports.lock"
                original = path.read_bytes()
                path.write_bytes(original + b"\n# substituted snapshot\n")
                # Model a PR updating the script's expected digest together
                # with the snapshot: only comparison with base can catch it.
                with patch.dict(DEP.IMPORT_LOCK_SHA256, {workspace: DEP.sha(path)}):
                    with self.assertRaisesRegex(ValueError, "base audit snapshot bytes changed"):
                        DEP.policy(self.root, base)
                path.write_bytes(original)

    def test_base_missing_snapshot_requires_explicit_migration(self):
        path = self.root / "supply-chain/imports.lock"
        snapshot = path.read_bytes()
        path.unlink()
        base = self.commit_base()
        path.write_bytes(snapshot)
        with self.assertRaisesRegex(ValueError, "base audit snapshot missing"):
            DEP.policy(self.root, base)

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

    def run_delta(self, previous, missing, conclusion="fail (vetting)", returncode=255,
                  output=None, base_error=False):
        base = self.commit_base()
        real_run = subprocess.run
        scanned = []
        def run(args, **kwargs):
            if args[0] == "git":
                return real_run(args, **kwargs)
            if "--version" in args:
                return subprocess.CompletedProcess(args, 0, "cargo-vet 0.10.3\n", "")
            if args[:2] == ["cargo", "fetch"]:
                self.assertIn("--locked", args)
                return subprocess.CompletedProcess(args, 0, "", "")
            self.assertIn("--locked", args)
            self.assertIn("--frozen", args)
            self.assertIn("--no-minimize-exemptions", args)
            is_base = kwargs["cwd"] != self.root
            scanned.append((is_base, args[args.index("--manifest-path") + 1]))
            if is_base:
                if base_error:
                    return subprocess.CompletedProcess(args, 1, "invalid base result", "")
                return subprocess.CompletedProcess(args, 255 if previous else 0, json.dumps({
                    "conclusion": "fail (vetting)" if previous else "success", "failures": previous,
                }), "")
            result = {"conclusion": conclusion, "failures": missing}
            return subprocess.CompletedProcess(args, returncode,
                                               json.dumps(result) if output is None else output, "")
        with patch.object(DEP.subprocess, "run", side_effect=run):
            result = DEP.check_delta(self.root, None, base)
        self.assertEqual(scanned, [(is_base, entry[0]) for is_base in (True, False)
                                   for entry in DEP.WORKSPACES.values()])
        worktrees = subprocess.check_output(["git", "worktree", "list", "--porcelain"],
                                           cwd=self.root, text=True)
        self.assertEqual(worktrees.count("worktree "), 1)
        return result

    def test_delta_allows_existing_or_resolved_debt(self):
        previous = [{"name": "existing", "version": "1.0.0", "missing_criteria": ["safe-to-run"]}]
        self.assertEqual(self.run_delta(previous, previous), 0)
        self.assertEqual(self.run_delta(previous, [], "success", 0), 0)

    def test_delta_allows_reduced_criteria(self):
        previous = [{"name": "existing", "version": "1.0.0", "missing_criteria": ["safe-to-deploy"]}]
        missing = [{"name": "existing", "version": "1.0.0", "missing_criteria": ["safe-to-run"]}]
        self.assertEqual(self.run_delta(previous, missing), 0)

    def test_delta_rejects_new_missing_audit(self):
        previous = [{"name": "existing", "version": "1.0.0", "missing_criteria": ["safe-to-run"]}]
        for name, version, criterion in (("new-dependency", "1.0.0", "safe-to-run"),
                                         ("existing", "2.0.0", "safe-to-run"),
                                         ("existing", "1.0.0", "safe-to-deploy")):
            missing = [{"name": name, "version": version, "missing_criteria": [criterion]}]
            with self.subTest(name=name, version=version, criterion=criterion):
                with self.assertRaisesRegex(ValueError, "new unaudited dependencies"):
                    self.run_delta(previous, missing)

    def test_delta_rejects_ledger_poisoned_in_previous_commit(self):
        missing = [{"name": "new-dependency", "version": "1.0.0", "missing_criteria": ["safe-to-run"]}]
        # run_delta commits this poisoned ledger BEFORE scanning the base.
        path = self.root / "supply-chain/audit-debt.json"
        path.write_text(json.dumps({"schema": 1, "not_an_exemption": True, "workspaces": {
            name: {"missing": missing} for name in DEP.WORKSPACES
        }}))
        with self.assertRaisesRegex(ValueError, "new unaudited dependencies"):
            self.run_delta([], missing)

    def test_delta_rejects_removed_audit_or_reintroduced_dependency(self):
        missing = [{"name": "existing", "version": "1.0.0", "missing_criteria": ["safe-to-run"]}]
        # An old inventory can outlive a completed audit or a removed package.
        # Neither can grandfather a later audit removal or package reintroduction.
        path = self.root / "supply-chain/audit-debt.json"
        path.write_text(json.dumps({"schema": 1, "not_an_exemption": True, "workspaces": {
            name: {"missing": missing} for name in DEP.WORKSPACES
        }}))
        self.assertEqual(self.run_delta(missing, [], "success", 0), 0)
        with self.assertRaisesRegex(ValueError, "new unaudited dependencies"):
            self.run_delta([], missing)

    def test_delta_fails_closed_on_base_error_and_removes_worktree(self):
        with self.assertRaisesRegex(ValueError, "invalid cargo-vet JSON"):
            self.run_delta([], [], base_error=True)
        worktrees = subprocess.check_output(["git", "worktree", "list", "--porcelain"],
                                           cwd=self.root, text=True)
        self.assertEqual(worktrees.count("worktree "), 1)

    def test_delta_rejects_cargo_vet_errors_even_with_existing_failures(self):
        previous = [{"name": "existing", "version": "1.0.0", "missing_criteria": ["safe-to-run"]}]
        for conclusion, returncode in (("fail (violation)", 255), ("success", 1),
                                       ("fail (vetting)", 0), ("fail (vetting)", -9)):
            with self.subTest(conclusion=conclusion, returncode=returncode):
                with self.assertRaisesRegex(ValueError, "cargo-vet failed"):
                    self.run_delta(previous, previous, conclusion, returncode)

    def test_delta_rejects_malformed_cargo_vet_results(self):
        for output in ("invalid JSON", "[]", "{}", '{"conclusion":"success","failures":{}}',
                       '{"conclusion":"fail (vetting)","failures":[{}]}'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.run_delta([], [], output=output)

    def test_delta_workflow_resolves_only_new_branch_push_base(self):
        workflow = (ROOT / ".github/workflows/dependency-assurance.yml").read_text()
        step = workflow.split("      - name: Reject audit debt introduced by this change\n", 1)[1]
        lines = step.split("        run: |\n", 1)[1].splitlines(keepends=True)
        end = next((index for index, line in enumerate(lines)
                    if line.strip() and not line.startswith("          ")), len(lines))
        script = textwrap.dedent("".join(lines[:end]))
        base = self.commit_base()
        subprocess.run(["git", "update-ref", "refs/remotes/origin/main", base],
                       cwd=self.root, check=True)
        subprocess.run(["git", "-c", "user.name=Policy Test", "-c", "user.email=test@example.invalid",
                        "commit", "--allow-empty", "-qm", "head", "--no-gpg-sign"],
                       cwd=self.root, check=True)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()
        for event, supplied, expected in (("new branch push", "0" * 40, base),
                                          ("normal push", base, base), ("pull request", head, head)):
            with self.subTest(event=event):
                result = subprocess.run(["bash", "-euo", "pipefail", "-c",
                    "python3() { printf '%s\\n' \"$@\"; }\n" + script], cwd=self.root,
                    env={**os.environ, "BASE_SHA": supplied, "DEFAULT_BRANCH": "main"},
                    capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout.splitlines(),
                                 ["scripts/security/dependencies.py", "check-delta", "--base", expected])


if __name__ == "__main__":
    unittest.main()
