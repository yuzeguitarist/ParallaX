#!/usr/bin/env python3
"""Offline credential regressions. Run: python3 ops/fuzz-cluster/tests/test_credentials.py.

Uses real Git/gh with a temporary HOME and a local bare remote. Only privileged
bootstrap operations and unrelated metrics/build/release tools are stubbed.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PACKAGE = Path(__file__).resolve().parents[1]
TOKEN = "fake-plxfuzz-regression-token"
URL = "https://github.com/yuzeguitarist/ParallaX.git"
GIT = shutil.which("git")
GH = shutil.which("gh")

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["TEST_ARGV_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\n")
if any(os.environ["TEST_TOKEN"] in arg for arg in args):
    sys.exit("credential leaked into argv")
if name == "sudo":
    preserve = "--preserve-env=GH_TOKEN" in args
    while args and args[0].startswith("-"):
        option = args.pop(0)
        if option == "-u": args.pop(0)
    os.environ["HOME"] = os.environ["TEST_HOME"]
    if not preserve: os.environ.pop("GH_TOKEN", None)
    os.execvp(args[0], args)
elif name == "install":
    clean = []
    while args:
        arg = args.pop(0)
        if arg in ("-o", "-g"): args.pop(0)
        else: clean.append(arg)
    os.execv(os.environ["TEST_INSTALL"], ["install", *clean])
elif name == "git":
    if "archive" in args and os.environ.get("TEST_ARCHIVE_MODE"):
        archive = subprocess.run([os.environ["TEST_GIT"], *args], capture_output=True, check=True)
        sys.stdout.buffer.write(archive.stdout)
        sys.stdout.buffer.flush()
        if os.environ["TEST_ARCHIVE_MODE"] == "fail": sys.exit(23)
        # Extra valid tar padding forces a pipe producer to outlive a consumer
        # that stops at the end-of-archive marker, making SIGPIPE deterministic.
        sys.stdout.buffer.write(b"\0" * (1024 * 1024))
        sys.stdout.buffer.flush()
        sys.exit(0)
    os.execv(os.environ["TEST_GIT"], ["git", *args])
elif name == "tar":
    if os.environ.get("TEST_TAR_FAIL"): sys.exit(24)
    os.execv(os.environ["TEST_TAR"], ["tar", *args])
elif name == "gh" and args and args[0] == "auth":
    os.execv(os.environ["TEST_GH"], ["gh", *args])
elif name == "id": print("0")
'''


@unittest.skipUnless(GIT and GH, "git and gh are required")
class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.etc = self.root / "etc/plxfuzz"
        self.mockbin = self.home / ".cargo/bin"
        self.mockbin.mkdir(parents=True)
        self.env = os.environ.copy()
        for name in list(self.env):
            if name.startswith(("GIT_", "GH_", "PLXFUZZ_")):
                self.env.pop(name)
        self.env.update(
            HOME=str(self.home), GH_CONFIG_DIR=str(self.home / ".config/gh"),
            PATH=f"{self.mockbin}:{os.environ['PATH']}",
            GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0",
            TEST_ARGV_LOG=str(self.root / "argv.jsonl"), TEST_HOME=str(self.home),
            TEST_TOKEN=TOKEN, TEST_GIT=GIT, TEST_GH=GH,
            TEST_INSTALL=shutil.which("install"),
            TEST_TAR=shutil.which("tar"),
        )
        mock = self.mockbin / "mock"
        mock.write_text(MOCK)
        mock.chmod(0o755)
        for name in ("sudo", "install", "git", "gh", "id", "useradd", "usermod",
                     "chown", "apt-get", "systemctl", "journalctl", "rustup", "cargo", "tar"):
            (self.mockbin / name).symlink_to(mock.name)
        self.seed = self.root / "seed"
        self.git("init", "-q", "-b", "main", str(self.seed))
        self.git("-C", str(self.seed), "config", "user.name", "test")
        self.git("-C", str(self.seed), "config", "user.email", "test@localhost")
        package = self.seed / "ops/fuzz-cluster"
        shutil.copytree(PACKAGE, package, ignore=shutil.ignore_patterns("tests"))
        (package / "bin/status.sh").write_text("#!/bin/bash\necho old-pinned-operator\n")
        self.commit("old campaign")
        self.pin = self.git("-C", str(self.seed), "rev-parse", "HEAD").stdout.strip()
        shutil.copyfile(PACKAGE / "bin/status.sh", package / "bin/status.sh")
        self.commit("operator credential fix")
        self.ops = self.git("-C", str(self.seed), "rev-parse", "HEAD").stdout.strip()
        self.remote = self.root / "remote.git"
        self.git("clone", "-q", "--bare", str(self.seed), str(self.remote))
        self.git("--git-dir", str(self.remote), "branch", "fuzz-crashes", self.ops)
        self.git("--git-dir", str(self.remote), "tag", "fuzz-status", self.ops)
        self.git("config", "--global", f"url.{self.remote.as_uri()}.insteadOf", URL)
        for directory in ("systemd/system", "systemd/journald.conf.d", "logrotate.d"):
            (self.root / "etc" / directory).mkdir(parents=True, exist_ok=True)

    def run_command(self, args, **kwargs):
        kwargs.setdefault("timeout", 60)
        result = subprocess.run(args, env=self.env, text=True, capture_output=True, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return result

    def git(self, *args):
        return self.run_command([GIT, *args])

    def commit(self, message):
        self.git("-C", str(self.seed), "add", ".")
        self.git("-C", str(self.seed), "commit", "-qm", message)

    def script(self, relative):
        return ((PACKAGE / relative).read_text()
                .replace("/var/lib/plxfuzz", str(self.home))
                .replace("/etc/", str(self.root / "etc") + "/")
                .replace('PINNED_COMMIT="d240e663"', f'PINNED_COMMIT="{self.pin}"'))

    def bootstrap(self):
        self.env["PLXFUZZ_PAT"] = TOKEN
        self.env["PLXFUZZ_OPS_COMMIT"] = self.ops
        result = self.run_command(["bash", "-s", "--", "box-a"],
                                  input=self.script("bootstrap.sh"), cwd=self.root)
        self.env.pop("PLXFUZZ_PAT")
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertEqual((self.home.stat().st_mode & 0o777), 0o700)
        self.assertEqual(((self.etc / "pat").stat().st_mode & 0o777), 0o600)
        self.assertEqual((self.etc / "pat").read_text().strip(), TOKEN)
        self.assertNotIn(TOKEN, (self.home / ".gitconfig").read_text())
        return result

    def assert_clean_remote(self, clone):
        urls = self.git("-C", str(clone), "config", "--get-all", "remote.origin.url").stdout.splitlines()
        self.assertEqual(urls, [URL])
        push = subprocess.run([GIT, "-C", str(clone), "config", "--get-all", "remote.origin.pushurl"],
                              env=self.env, text=True, capture_output=True)
        self.assertEqual(push.returncode, 1)
        self.assertNotIn(TOKEN, (clone / ".git/config").read_text())

    def legacy_remote(self, clone):
        self.git("clone", "-q", str(self.remote), str(clone))
        unsafe = f"https://x-access-token:{TOKEN}@github.com/yuzeguitarist/ParallaX.git"
        self.git("-C", str(clone), "config", "--replace-all", "remote.origin.url", unsafe)
        self.git("-C", str(clone), "config", "--add", "remote.origin.url", unsafe)
        self.git("-C", str(clone), "config", "--add", "remote.origin.pushurl", unsafe)
        (clone / ".git/config").chmod(0o644)

    def assert_no_secret_argv(self):
        commands = [json.loads(line) for line in (self.root / "argv.jsonl").read_text().splitlines()]
        self.assertTrue(any(c[0] == "git" for c in commands))
        self.assertFalse(any(TOKEN in arg for command in commands for arg in command))

    def test_bootstrap_and_service_git_with_env_helper(self):
        result = self.bootstrap()
        self.assertIn(self.ops, result.stdout)
        source = self.home / "src"
        self.assert_clean_remote(source)
        self.assertEqual(self.git("-C", str(source), "rev-parse", "HEAD").stdout.strip(), self.pin)
        self.assertEqual((self.home / "bin/status.sh").read_bytes(), (PACKAGE / "bin/status.sh").read_bytes())
        self.assertIn("old-pinned-operator", (source / "ops/fuzz-cluster/bin/status.sh").read_text())
        # A fresh service process has only its token environment and HOME, with
        # no bootstrap shell/PAT variables or persisted gh login.
        self.env["GH_TOKEN"] = (self.etc / "pat").read_text().strip()
        filled = self.run_command([str(self.mockbin / "git"), "credential", "fill"],
                                  input="protocol=https\nhost=github.com\n\n")
        self.assertIn(f"password={TOKEN}\n", filled.stdout)
        self.run_command([str(self.mockbin / "git"), "-C", str(source), "fetch", "origin", "main"])
        self.run_command([str(self.mockbin / "git"), "-C", str(source), "push", "origin", "HEAD:refs/heads/service-test"])
        self.assert_no_secret_argv()

    def test_bootstrap_migrates_every_legacy_clone(self):
        clones = [self.home / "src", self.home / "state/branch-fuzz-status",
                  self.home / "state/branch-fuzz-crashes"]
        self.home.chmod(0o755)
        for clone in clones:
            self.legacy_remote(clone)
        # Reproduce the original exposure with a fake token and public modes.
        self.assertTrue(self.home.stat().st_mode & 0o005)
        self.assertTrue((clones[0] / ".git/config").stat().st_mode & 0o004)
        self.bootstrap()
        for clone in clones:
            self.assert_clean_remote(clone)
        self.assert_no_secret_argv()

    def test_operator_archive_handles_consumer_early_close(self):
        self.env["TEST_ARCHIVE_MODE"] = "padding"
        self.bootstrap()
        self.assertEqual((self.home / "bin/status.sh").read_bytes(), (PACKAGE / "bin/status.sh").read_bytes())
        self.assert_no_secret_argv()

    def test_operator_archive_failure_stops_before_install(self):
        # Emit a complete, valid tar before failing: extraction alone would
        # succeed, so bootstrap must check the producer's exit independently.
        self.env["TEST_ARCHIVE_MODE"] = "fail"
        self.assert_operator_package_failure("could not archive operator scripts")
        commands = [json.loads(line) for line in (self.root / "argv.jsonl").read_text().splitlines()]
        self.assertFalse(any(command[0] == "tar" for command in commands))

    def test_operator_extract_failure_stops_before_install(self):
        self.env["TEST_TAR_FAIL"] = "1"
        self.assert_operator_package_failure("could not extract operator scripts")

    def assert_operator_package_failure(self, diagnostic):
        self.env["PLXFUZZ_PAT"] = TOKEN
        self.env["PLXFUZZ_OPS_COMMIT"] = self.ops
        result = subprocess.run(["bash", "-s", "--", "box-a"], env=self.env,
                                input=self.script("bootstrap.sh"), cwd=self.root,
                                text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn(diagnostic, result.stderr)
        self.assertNotIn(TOKEN, result.stderr + result.stdout)
        self.assertNotIn("[9/11]", result.stdout)
        self.assertFalse((self.home / "bin/status.sh").exists())
        self.assert_no_secret_argv()

    def test_status_and_cmin_migrate_and_clone_without_secret_arguments(self):
        self.bootstrap()
        status = self.home / "state/branch-fuzz-status"
        crashes = self.home / "state/branch-fuzz-crashes"
        # Execute status itself, including the first-clone/tag-push path.
        self.run_command(["bash", "-s"], input=self.script("bin/status.sh"), cwd=self.root)
        self.assert_clean_remote(status)
        self.assertTrue((self.home / "state/last-status-ts").is_file())
        self.git("-C", str(status), "config", "--add", "remote.origin.pushurl", f"https://x-access-token:{TOKEN}@github.com/x")
        self.run_command(["bash", "-s"], input=self.script("bin/status.sh"), cwd=self.root)
        self.assert_clean_remote(status)
        # The legacy cmin repro downloader is not used by main today; execute
        # that real function too so it cannot reintroduce token URL arguments.
        cmin = self.root / "cmin.sh"
        cmin.write_text(self.script("bin/cmin.sh"))
        invocation = 'exit() { :; }; script="$1"; set -- test-target; source "$script"; fetch_crash_repros test-target "$STATE/repros"'
        self.run_command(["bash", "-c", invocation, "test", str(cmin)])
        self.assert_clean_remote(crashes)
        self.git("-C", str(crashes), "config", "--add", "remote.origin.pushurl", f"https://x-access-token:{TOKEN}@github.com/x")
        self.run_command(["bash", "-c", invocation, "test", str(cmin)])
        self.assert_clean_remote(crashes)
        # The crash uploader uses a linked worktree sharing the source clone's
        # config; clean legacy fetch/push URLs before preparing that worktree.
        source = self.home / "src"
        unsafe = f"https://x-access-token:{TOKEN}@github.com/yuzeguitarist/ParallaX.git"
        self.git("-C", str(source), "config", "--replace-all", "remote.origin.url", unsafe)
        self.git("-C", str(source), "config", "--add", "remote.origin.pushurl", unsafe)
        (source / "fuzz/artifacts/test-target").mkdir(parents=True)
        crash_push = self.root / "crash-push.sh"
        crash_push.write_text(self.script("bin/crash-push.sh"))
        invocation = 'exit() { :; }; script="$1"; set -- test-target; source "$script"; prepare_worktree'
        self.run_command(["bash", "-c", invocation, "test", str(crash_push)])
        self.assert_clean_remote(source)
        worktree = self.home / "crashes-wt"
        self.assertTrue((worktree / ".git").is_file())
        self.assertEqual(self.git("-C", str(worktree), "remote", "get-url", "origin").stdout.strip(), self.remote.as_uri())
        self.assert_no_secret_argv()


if __name__ == "__main__":
    unittest.main(verbosity=2)
