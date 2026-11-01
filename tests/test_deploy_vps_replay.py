"""Exercise the generated deploy payload's replay-cache rotation in a sandbox.

Run with: python3 -m unittest discover -s tests -p test_deploy_vps_replay.py
"""

import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/deploy-vps.sh"
CACHE = "var/lib/parallax/replay-parallax.cache"
SUFFIXES = ("", ".0rtt", ".marker")
# Captured from the previous heredoc builders, evaluated in the same Bash with
# reference-only padding to select its tempfile backend, then removing padding.
# Seal-enabled snapshots include the legacy-bundle resolution copy; removing
# only its five emitted lines reproduces the historical snapshots byte-for-byte.
PAYLOAD_SHA256 = {
    ("0", "0", "none"): "bc973151a7195f6f95e5d615ebc9df4a21a970150ceb09647e14cf27066f4719",
    ("0", "0", "polar-cloud"): "8fe2688f438307b0e35c45a5d09b3d6826bc9c5a5a4831afb696f1b549aa5efb",
    ("0", "1", "none"): "1c030a794f8255481d64eb507070238725c47e0dec771901a8d4be146f9abe24",
    ("0", "1", "polar-cloud"): "cc0781046ddba2aece9fa75002e8bfdef09bc204f6933f453ebab6484e3e2535",
    ("1", "0", "none"): "3569bf8c486f5f4a080c4d80280618be04947e276e63446ba9b2127091bdf091",
    ("1", "0", "polar-cloud"): "6b705ac4760c691926263864197d925941e5b49b2d90e31260b83a13de937c86",
    ("1", "1", "none"): "7cf7144f87a6359aad0494fdfb192908ee38e8979a8b03d2a05b0f2d2e744d70",
    ("1", "1", "polar-cloud"): "1d4743b4531d6627215bac40d1c32f95f75d8e68f42117cfdc1e1815ce0726dc",
}


def run_bash(script, *, env, check=False):
    # A regular input file avoids a second, tiny Darwin pipe while the child is
    # also writing output; communicate can then enforce the timeout while reading.
    with tempfile.TemporaryFile(mode="w+") as script_input:
        script_input.write(script)
        script_input.seek(0)
        process = subprocess.Popen(["bash", "-s"], stdin=script_input,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=env, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=5)
            raise
    result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


STUB = r'''
import json
import os
from pathlib import Path
import re
import shutil
import sys

root = Path(os.environ["VPS_ROOT"])
command = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "commands.jsonl").open("a") as log:
    log.write(json.dumps([command, *args]) + "\n")
if command == "rm":
    for arg in args:
        if arg.startswith("-"):
            continue
        path = Path(arg)
        if not path.is_relative_to(root):
            raise SystemExit("refusing removal outside sandbox: " + arg)
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
elif command == "systemctl" and args[0] == "stop":
    # Assert the actual files still exist when the old server is being stopped.
    for cache in json.loads(os.environ["STOP_CACHES"]):
        assert Path(cache).is_file()
    raise SystemExit(int(os.environ.get("STOP_EXIT", "0")))
elif command == "systemctl" and args[0] == "show":
    print(os.environ.get("LOAD_STATE", "loaded"))
elif command == "systemctl" and args[0] == "restart" and os.environ.get("SIMULATE_SERVER"):
    service = args[1].removesuffix(".service")
    config = (root / f"etc/parallax/{service}.toml").read_text()
    cache = root / re.search(r'replay_cache_path = "([^"]+)"', config)[1].lstrip("/")
    for suffix in ("", ".0rtt", ".marker"):
        Path(str(cache) + suffix).write_text(f"MAC state for {service}\n")
elif command == "install":
    if "-d" in args:
        Path(args[-1]).mkdir(parents=True, exist_ok=True)
    else:
        shutil.copyfile(args[-2], args[-1])
elif command == "id":
    print("1001")
elif command == "uname":
    print("Darwin")
elif command == "ufw":
    print("Status: inactive")
'''


class DeployReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SCRIPT.read_text()
        functions, rest = source.split('\nSSH_TARGET=""\n', 1)
        defaults = 'SSH_TARGET=""\n' + rest.split("\nORIGINAL_ARGS=", 1)[0]
        generator = functions + "\n" + defaults + r'''
DRY_RUN=1
ENABLE_BBR="${TEST_ENABLE_BBR:-0}"
SEAL_SECRETS="${TEST_SEAL_SECRETS:-0}"
PROFILE_MODE="${TEST_PROFILE_MODE:-none}"
PARCA_UNIT_FILE=/unused/parca-agent.service
POLAR_ENV_FILE=/unused/polarsignals.env
POLAR_TOKEN_UPLOAD_FILE=/unused/polarsignals.token
REMOTE_SUDO=""
SSH_TARGET=root@sandbox.invalid
SERVICE_NAME="$TEST_SERVICE_NAME"
REMOTE_CONFIG="/etc/parallax/$SERVICE_NAME.toml"
REUSE_CONFIG="$TEST_REUSE_CONFIG"
trap 'rm -rf "$SSH_CONTROL_DIR"' EXIT
run() {
  if [[ "${!#}" == $'set -Eeuo pipefail\n'* ]]; then
    printf 'REMOTE_SCRIPT\n%s\nEND_REMOTE_SCRIPT\n' "${!#}"
  fi
}
DRY_RUN=0
normalize_server_replay_cache_path "$TEST_SERVER_CONFIG"
DRY_RUN=1
install_remote /unused /unused/server.toml /unused/parallax.service
'''
        cls.generator = generator
        cls.payloads = {}
        cls.configs = {}
        cls.original_config = ('[server]\npsk = { sealed = "legacy.secrets.enc#psk" }\n'
                               'replay_cache_path = "/var/lib/parallax/parallax-replay.cache"\n')
        with tempfile.TemporaryDirectory(prefix="parallax-deploy-configs-") as directory:
            config = Path(directory) / "server.toml"
            for service in ("parallax", "edge-b"):
                for reuse in ("0", "1"):
                    config.write_text(cls.original_config)
                    result = run_bash(generator,
                                      env={**os.environ, "TEST_REUSE_CONFIG": reuse,
                                           "TEST_SERVICE_NAME": service,
                                           "TEST_SERVER_CONFIG": str(config)}, check=True)
                    cls.payloads[service, reuse] = result.stdout.split("REMOTE_SCRIPT\n", 1)[1].split(
                        "\nEND_REMOTE_SCRIPT", 1)[0]
                    cls.configs[service, reuse] = config.read_text()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="parallax-deploy-replay-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc/systemd/system").mkdir(parents=True)
        stub = self.root / "stub"
        stub.write_text(f"#!{sys.executable}\n{STUB}")
        stub.chmod(0o755)
        commands = self.root / "commands"
        commands.mkdir()
        for command in ("systemctl", "rm", "id", "uname", "ufw", "install", "chown"):
            (commands / command).symlink_to(stub)
        self.related = [CACHE + suffix for suffix in SUFFIXES]
        self.unrelated = ["var/lib/parallax/host.key", "var/lib/parallax/other.cache",
                          "var/lib/parallax/parallax-replay.cache.other"]
        self.unrelated += ["var/lib/parallax/other.cache" + s for s in SUFFIXES[1:]]
        self.legacy = ["var/lib/parallax/parallax-replay.cache" + s for s in SUFFIXES]
        self.second = ["var/lib/parallax/replay-edge-b.cache" + s for s in SUFFIXES]
        self.unrelated += self.legacy
        for relative in self.related + self.unrelated + self.second:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("old state\n")

    def run_payload(self, reuse="0", stop_exit="0", load_state="loaded", systemctl=True,
                    service="parallax", simulate_server=False):
        upload = self.root / "tmp/parallax-deploy.XXXXXX"
        upload.mkdir(parents=True, exist_ok=True)
        for name, content in (("plx", "binary fixture"), ("parallax.service", "unit fixture"),
                              ("parallax.server.toml", self.configs[service, reuse])):
            (upload / name).write_text(content)
        payload = re.sub(r"/(?:etc/|var/lib/|usr/local/|tmp/parallax-deploy\.)",
                         lambda match: f"{self.root}{match[0]}", self.payloads[service, reuse])
        if not systemctl:
            payload = '''command() {
  if [[ "$*" == "-v systemctl" ]]; then return 1; fi
  builtin command "$@"
}
''' + payload
        result = run_bash(payload, env={**os.environ,
                                "PATH": f"{self.root}/commands:{os.environ['PATH']}",
                                "VPS_ROOT": str(self.root), "STOP_EXIT": stop_exit,
                                "LOAD_STATE": load_state,
                                "STOP_CACHES": json.dumps([str(p) for s in SUFFIXES
                                    if (p := self.root / f"var/lib/parallax/replay-{service}.cache{s}").exists()]),
                                "SIMULATE_SERVER": "1" if simulate_server else ""})
        self.commands = [json.loads(line) for line in
                         (self.root / "commands.jsonl").read_text().splitlines()]
        for relative in self.unrelated:
            self.assertEqual((self.root / relative).read_text(), "old state\n", relative)
        return result

    def test_fresh_config_rotates_all_three_after_service_stop(self):
        result = self.run_payload()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for relative in self.related:
            self.assertFalse((self.root / relative).exists(), relative)
        removal = ["rm", "-f", *[str(self.root / p) for p in self.related]]
        self.assertIn(removal, self.commands)
        self.assertLess(self.commands.index(["systemctl", "stop", "parallax.service"]),
                        self.commands.index(removal))
        for relative in self.second:
            self.assertEqual((self.root / relative).read_text(), "old state\n", relative)
        self.assertIn('replay_cache_path = "/' + CACHE + '"', self.configs["parallax", "0"])

    def test_reused_config_preserves_all_three(self):
        result = self.run_payload(reuse="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for relative in self.related:
            self.assertEqual((self.root / relative).read_text(), "old state\n", relative)
        self.assertNotIn(["systemctl", "stop", "parallax.service"], self.commands)
        self.assertEqual(self.configs["parallax", "1"], self.original_config)
        self.assertEqual((self.root / "etc/parallax/parallax.toml").read_text(), self.original_config)

    def test_two_units_use_separate_generated_cache_paths(self):
        # Start B with the actual generated payload/config, then rotate A while B
        # remains running. The restart stub writes each configured cache's state.
        result = self.run_payload(service="edge-b", simulate_server=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        before = {p: (self.root / p).read_bytes() for p in self.second}
        command_count = len(self.commands)
        result = self.run_payload(simulate_server=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(["systemctl", "stop", "edge-b.service"], self.commands[command_count:])
        for relative, contents in before.items():
            self.assertEqual((self.root / relative).read_bytes(), contents, relative)
        for relative in self.related:
            self.assertEqual((self.root / relative).read_text(), "MAC state for parallax\n")
        self.assertIn('replay_cache_path = "/var/lib/parallax/replay-edge-b.cache"',
                      (self.root / "etc/parallax/edge-b.toml").read_text())

    def test_fresh_migration_preserves_other_legacy_reused_instance(self):
        result = self.run_payload(service="edge-b", reuse="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for relative in self.related:
            (self.root / relative).unlink()
        before = {p: (self.root / p).read_bytes() for p in self.legacy}
        command_count = len(self.commands)
        result = self.run_payload(simulate_server=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(["systemctl", "stop", "edge-b.service"], self.commands[command_count:])
        self.assertEqual((self.root / "etc/parallax/edge-b.toml").read_text(), self.original_config)
        for relative, contents in before.items():
            self.assertEqual((self.root / relative).read_bytes(), contents, relative)

    def test_reusing_current_instance_config_does_not_rewrite_sealed_secrets(self):
        config = self.root / "reused.toml"
        original = self.configs["parallax", "0"]
        config.write_text(original)
        result = run_bash(self.generator,
                          env={**os.environ, "TEST_REUSE_CONFIG": "1",
                               "TEST_SERVICE_NAME": "parallax",
                               "TEST_SERVER_CONFIG": str(config)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(config.read_text(), original)

    def test_all_optional_payloads_start_within_timeout(self):
        config = self.root / "startup.toml"
        # Repeated startup catches the intermittent pipe-capacity failure. Every
        # option combination also exercises the large expanded final payload.
        for repeat, bbr, seal, profile in itertools.product(range(5), ("0", "1"),
                                                          ("0", "1"), ("none", "polar-cloud")):
            with self.subTest(repeat=repeat, bbr=bbr, seal=seal, profile=profile):
                config.write_text(self.original_config)
                result = run_bash(self.generator, env={**os.environ,
                    "TEST_REUSE_CONFIG": "0", "TEST_SERVICE_NAME": "parallax",
                    "TEST_SERVER_CONFIG": str(config), "TEST_ENABLE_BBR": bbr,
                    "TEST_SEAL_SECRETS": seal, "TEST_PROFILE_MODE": profile})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                payload = result.stdout.split("REMOTE_SCRIPT\n", 1)[1].split(
                    "\nEND_REMOTE_SCRIPT", 1)[0]
                self.assertEqual("Checking VPS TCP BBR/fq tuning..." in payload, bbr == "1")
                self.assertEqual("Sealing server secrets at rest" in payload, seal == "1")
                self.assertEqual("systemctl restart parca-agent.service" in payload,
                                 profile == "polar-cloud")
                self.assertEqual(hashlib.sha256(payload.encode()).hexdigest(),
                                 PAYLOAD_SHA256[bbr, seal, profile])

    def test_failed_stop_preserves_all_three_and_aborts(self):
        result = self.run_payload(stop_exit="1")
        self.assertNotEqual(result.returncode, 0)
        for relative in self.related:
            self.assertEqual((self.root / relative).read_text(), "old state\n", relative)
        self.assertNotIn(["systemctl", "restart", "parallax.service"], self.commands)

    def test_first_install_allows_missing_unit_and_cache(self):
        for relative in self.related:
            (self.root / relative).unlink()
        result = self.run_payload(stop_exit="5", load_state="not-found")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(["systemctl", "restart", "parallax.service"], self.commands)

    def test_no_systemctl_refuses_to_remove_existing_caches(self):
        result = self.run_payload(systemctl=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot rotate existing replay caches", result.stderr)
        for relative in self.related:
            self.assertEqual((self.root / relative).read_text(), "old state\n", relative)

    def test_first_install_without_systemctl_has_no_cache_to_rotate(self):
        for relative in self.related:
            (self.root / relative).unlink()
        result = self.run_payload(systemctl=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
