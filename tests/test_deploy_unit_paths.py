"""Reject paths that systemd would interpret differently from installation."""

import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/deploy-vps.sh"
SHELLS = list(dict.fromkeys(str(Path(shell).resolve()) for shell in
                          ("/bin/bash", shutil.which("bash"), "/opt/homebrew/bin/bash",
                           "/usr/local/bin/bash") if shell and Path(shell).is_file()))


def run_bash(shell, args, *, script=None, env=None):
    with tempfile.TemporaryFile() as script_input:
        if script is not None:
            script_input.write(script.encode())
            script_input.seek(0)
        process = subprocess.Popen([shell, *args], stdin=script_input,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, start_new_session=True, text=True)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=5)
            raise
    return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)


class DeployUnitPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SHELLS:
            raise unittest.SkipTest("Bash is not installed; deployment unit-path tests were not run")

    def test_nonliteral_unit_paths_fail_before_build_or_ssh(self):
        # systemd unquotes/unescapes ExecStart, substitutes ${ENV}, and expands
        # %n to the unit name. Installing these literal paths cannot match that.
        paths = ("/tmp/plx'quoted", '/tmp/plx"quoted', r"/tmp/plx\name",
                 "/tmp/${UNSET}/plx", "/tmp/%n/plx", "/tmp/plx%21")
        with tempfile.TemporaryDirectory(prefix="parallax-deploy-paths-") as folder:
            root = Path(folder)
            (root / "scripts").mkdir()
            copied_script = root / "scripts/deploy-vps.sh"
            shutil.copyfile(SCRIPT, copied_script)
            (root / "Cargo.toml").write_text("[workspace]\n")
            commands = root / "commands"
            commands.mkdir()
            for command in ("ssh", "scp", "cargo", "docker", "git", "zig", "rustup"):
                stub = commands / command
                stub.write_text('#!/bin/sh\nprintf called >> "$CALL_LOG"\nexit 97\n')
                stub.chmod(0o755)
            calls = root / "called"
            env = {**os.environ, "PATH": str(commands) + os.pathsep + os.environ["PATH"],
                   "CALL_LOG": str(calls)}
            for shell in SHELLS:
                for flag in ("--remote-bin", "--remote-config"):
                    for path in paths:
                        with self.subTest(shell=shell, flag=flag, path=path):
                            result = run_bash(shell, [str(copied_script), "--host",
                                                     "root@sandbox.invalid", "--dest",
                                                     "example.invalid", "--non-interactive",
                                                     "--dry-run", flag, path], env=env)
                            self.assertNotEqual(result.returncode, 0)
                            self.assertIn(flag + " must not contain systemd", result.stderr)
                            self.assertFalse(calls.exists(), result.stdout + result.stderr)
                            self.assertFalse((root / "target").exists())

    def test_supported_paths_keep_the_installed_unit_arguments(self):
        functions = SCRIPT.read_text().split('\nSSH_TARGET=""\n', 1)[0]
        program = functions + '''
require_safe_remote_path --remote-bin "$REMOTE_BIN"
require_safe_remote_path --remote-config "$REMOTE_CONFIG"
write_unit_file "$UNIT_FILE"
'''
        binary = "/opt/parallax-v1.2_@host:+/plx"
        config = "/etc/parallax/节点-[v1]+@server:1.toml"
        for shell in SHELLS:
            with self.subTest(shell=shell):
                with tempfile.TemporaryDirectory(prefix="parallax-unit-paths-") as folder:
                    unit = Path(folder) / "parallax.service"
                    env = {**os.environ, "REMOTE_BIN": binary, "REMOTE_CONFIG": config,
                           "UNIT_FILE": str(unit)}
                    result = run_bash(shell, ["-s"], script=program, env=env)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(f"\nExecStart={binary} serve -c {config}\n", unit.read_text())


if __name__ == "__main__":
    unittest.main()
