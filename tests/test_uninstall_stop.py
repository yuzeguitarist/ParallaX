"""Exercise stop failures in the generated remote uninstaller, without SSH."""

import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/uninstall-vps.sh"

STUB = r'''
import json
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ["VPS_ROOT"])
command = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "commands.jsonl").open("a") as log:
    log.write(json.dumps([command, *args]) + "\n")

if command == "systemctl":
    states = json.loads((root / "states.json").read_text())
    if args[0] in ("list-unit-files", "list-units"):
        if os.environ.get("FAIL_INVENTORY") == args[0]:
            raise SystemExit(1)
        if args[0] == "list-unit-files":
            if (root / "etc/systemd/system" / args[-1]).exists():
                print(args[-1], "enabled")
        elif "--type=service" in args:
            for unit, state in states.items():
                print(unit, "loaded", state)
        elif args[-1] in states:
            print(args[-1], "loaded", states[args[-1]])
    elif args[0] == "stop" and args[-1] == os.environ.get("FAIL_STOP"):
        print("Failed to stop " + args[-1], file=sys.stderr)
        raise SystemExit(1)
    elif args[0] == "show":
        print("User=parallax\nDescription=ParallaX")
elif command in ("rm", "rmdir"):
    for arg in args:
        if arg.startswith("-"):
            continue
        path = Path(arg)
        if not path.is_relative_to(root):
            raise SystemExit("refusing mutation outside sandbox: " + arg)
        if command == "rmdir":
            path.rmdir()
        elif path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
elif command == "id":
    print("1001")
elif command == "ufw":
    print("Status: inactive")
'''


class UninstallStopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = shutil.which("bash")
        command = [cls.bash, str(SCRIPT), "--host", "root@sandbox.invalid", "--keep-local", "--dry-run"]
        process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=5)
            raise
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command, stdout, stderr)
        start = stdout.index('set -Eeuo pipefail\nexport PATH=')
        cls.remote_script = stdout[start:].split("\nDry run finished.", 1)[0]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="parallax-uninstall-stop-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands_dir = self.root / "commands"
        self.commands_dir.mkdir()
        for command in ("cat", "grep", "dirname", "readlink", "awk", "sort", "tr"):
            (self.commands_dir / command).symlink_to(shutil.which(command))
        stub = self.put("stub", f"#!{sys.executable}\n{STUB}")
        stub.chmod(0o755)
        for command in ("systemctl", "ufw", "sysctl", "snap", "id", "userdel", "rm", "rmdir"):
            (self.commands_dir / command).symlink_to(stub)
        self.put("states.json", json.dumps({"parallax.service": "active running"}))
        self.artifacts = [
            "etc/systemd/system/parallax.service",
            "usr/local/bin/plx", "etc/parallax/parallax.toml",
            "etc/parallax/parallax.toml.secrets.enc", "etc/parallax/parallax.secrets.enc",
            "etc/parallax/parallax-replay.cache", "var/lib/parallax/host.key",
            "var/lib/parallax/replay-parallax.cache", "var/lib/parallax/replay-parallax.cache.0rtt",
            "var/lib/parallax/replay-parallax.cache.marker",
            "etc/parallax/polarsignals.env", "etc/parallax/polarsignals.token",
            "etc/modules-load.d/parallax-bbr.conf", "etc/sysctl.d/99-parallax-bbr.conf",
            "etc/sysctl.d/99-parallax-netbuf.conf",
        ]
        for path in self.artifacts:
            self.put(path, "fixture\n")

    def put(self, path, text):
        path = self.root / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def run_payload(self, **options):
        # Keep utility lookup hermetic, including the payload's usual sbin paths.
        script = self.remote_script.replace('export PATH="$PATH:/usr/sbin:/sbin"', 'export PATH="$PATH"')
        script = re.sub(r"/(?:etc/|var/lib/|usr/local/lib/|run/systemd/|usr/lib/systemd/|lib/systemd/)",
                        lambda match: f"{self.root}{match[0]}", script)
        env = {
            **os.environ, "PATH": str(self.commands_dir), "VPS_ROOT": str(self.root),
            "SUDO": "", "REMOTE_BIN": f"{self.root}/usr/local/bin/plx",
            "REMOTE_CONFIG": f"{self.root}/etc/parallax/parallax.toml",
            "SERVICE_NAME": "parallax", "REMOVE_USER": "1", "REMOVE_PARCA_AGENT": "1",
            "FAIL_STOP": "", "FAIL_INVENTORY": "", **options,
        }
        self.result = subprocess.run([self.bash, "-s"], input=script, env=env,
                                     text=True, capture_output=True)
        log = self.root / "commands.jsonl"
        self.commands = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def assert_aborted_intact(self):
        self.assertNotEqual(self.result.returncode, 0, self.result.stdout + self.result.stderr)
        self.assertIn("aborting uninstall", self.result.stderr)
        for path in self.artifacts:
            self.assertEqual((self.root / path).read_text(), "fixture\n", path)
        for command in self.commands:
            self.assertIn(command[0], ("systemctl",))
            self.assertIn(command[1], ("list-unit-files", "list-units", "stop"))
        self.assertNotIn("uninstall finished", self.result.stdout)

    def test_failed_stop_preserves_unit_and_every_artifact(self):
        self.run_payload(FAIL_STOP="parallax.service")
        self.assert_aborted_intact()
        self.assertEqual(self.commands[-1], ["systemctl", "stop", "parallax.service"])

    def test_loaded_unit_without_file_still_requires_successful_stop(self):
        (self.root / self.artifacts.pop(0)).unlink()
        self.run_payload(FAIL_STOP="parallax.service")
        self.assert_aborted_intact()
        self.assertEqual(self.commands[-1], ["systemctl", "stop", "parallax.service"])

    def test_inactive_unit_is_stopped_before_cleanup(self):
        self.put("states.json", json.dumps({"parallax.service": "inactive dead"}))
        self.run_payload()
        self.assertEqual(self.result.returncode, 0, self.result.stdout + self.result.stderr)
        stop = self.commands.index(["systemctl", "stop", "parallax.service"])
        first_rm = next(i for i, command in enumerate(self.commands) if command[0] == "rm")
        self.assertLess(stop, first_rm)
        for path in self.artifacts:
            self.assertFalse((self.root / path).exists(), path)

    def test_missing_unit_does_not_attempt_stop(self):
        (self.root / self.artifacts.pop(0)).unlink()
        self.put("states.json", "{}")
        self.run_payload()
        self.assertEqual(self.result.returncode, 0, self.result.stdout + self.result.stderr)
        self.assertNotIn(["systemctl", "stop", "parallax.service"], self.commands)
        for path in self.artifacts:
            self.assertFalse((self.root / path).exists(), path)

    def test_missing_systemctl_with_unit_preserves_artifacts(self):
        (self.commands_dir / "systemctl").unlink()
        self.run_payload()
        self.assert_aborted_intact()
        self.assertIn("systemctl not found", self.result.stderr)

    def test_missing_systemctl_and_missing_unit_allow_cleanup(self):
        (self.commands_dir / "systemctl").unlink()
        (self.root / self.artifacts.pop(0)).unlink()
        self.run_payload()
        self.assertEqual(self.result.returncode, 0, self.result.stdout + self.result.stderr)
        for path in self.artifacts:
            self.assertFalse((self.root / path).exists(), path)

    def test_failed_inventory_is_not_treated_as_missing(self):
        for command in ("list-unit-files", "list-units"):
            with self.subTest(command=command):
                self.run_payload(FAIL_INVENTORY=command)
                self.assert_aborted_intact()


if __name__ == "__main__":
    unittest.main()
