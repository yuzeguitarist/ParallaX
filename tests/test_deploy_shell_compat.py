"""Exercise local deploy helpers without SSH, builds, or a heredoc pipe."""

import hashlib
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
# Captured from the old local heredoc templates, with reference-only padding
# selecting Bash's tempfile backend, then removing that padding from the bytes.
FILE_SHA256 = {
    "server.service": "cee8717c5fe4ac51b7fdee1a5cdd602758577bc4178da9fa746413642f66fc46",
    "parca.service": "ef8dbae74b2cd0dfc8488df343d338296f536f2b7f8f6a12df403218b41e1938",
    "polar.env": "55a779eab8b8cc8c1b41578d387fb7bfc76c20c0c899df7fe761a6a8db96c94d",
}
GUIDANCE_SHA256 = {
    "none": "64e0f3b9dbd5f38f488fb4cc0ee22accd7a57b9888aa70980ea22ce3149362b3",
    "polar-cloud": "447e81743c9a3e10bd6f4a3e4c31fa5bd49da31a36a42695aa2bb512d05fac7e",
}
VALUES = {
    "REMOTE_BIN": "/usr/local/bin/plx-$literal-quote'-slash\\",
    "REMOTE_CONFIG": "/etc/parallax/config-$literal-quote'-slash\\.toml",
    "POLAR_STORE_ADDRESS": "grpc.example.invalid:443",
    "POLAR_NODE": "node-$literal-quote'-slash\\",
    "PARCA_HTTP_ADDRESS": "127.0.0.1:7071",
    "POLAR_LABELS": "service=parallax;quote=';dollar=$literal;slash=\\",
    "POLAR_PROJECT_ID": "12345678-1234-1234-1234-123456789abc",
    "CLIENT_CFG": "/tmp/client-$literal-quote'-slash\\.toml",
    "SSH_PORT": "2222",
    "SSH_TARGET": "root@example.invalid",
    "REMOTE_SUDO": "sudo",
    "SERVICE_NAME": "parallax-test",
}


def run_bash(shell, args, *, script=None, env=None):
    # Keep script input out of a second pipe: Darwin can shrink pipe capacity
    # while communicate is feeding input and the child is writing its output.
    with tempfile.TemporaryFile() as script_input:
        if script is not None:
            script_input.write(script)
            script_input.seek(0)
        process = subprocess.Popen([shell, *args], stdin=script_input,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, start_new_session=True)
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
        raise AssertionError(stderr.decode(errors="replace"))
    return stdout


class DeployShellCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SHELLS:
            raise unittest.SkipTest("Bash is not installed; deployment shell compatibility tests were not run")
        source = SCRIPT.read_text()
        cls.functions = source.split('\nSSH_TARGET=""\n', 1)[0]
        cls.guidance = source.split(
            '\ninstall_remote "$DEPLOY_DIR" "$SERVER_CFG" "$UNIT_FILE"\n', 1)[1]

    def test_complete_file_syntax_and_help_launches(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                run_bash(shell, ["-n", str(SCRIPT)])
                for _ in range(5):
                    output = run_bash(shell, [str(SCRIPT), "--help"])
                    self.assertTrue(output.startswith(b"ParallaX private VPS deployer.\n"))
                    self.assertTrue(output.endswith(b"https://ifconfig.me\n"))

    def test_generated_files_and_guidance_keep_legacy_bytes(self):
        program = self.functions + '''
usage
interactive_banner
write_unit_file "$OUTPUT_DIR/server.service"
write_parca_agent_unit_file "$OUTPUT_DIR/parca.service"
write_polar_env_file "$OUTPUT_DIR/polar.env"
''' + self.guidance
        for shell in SHELLS:
            for mode in ("none", "polar-cloud"):
                for attempt in range(3):
                    with self.subTest(shell=shell, mode=mode, attempt=attempt):
                        with tempfile.TemporaryDirectory(prefix="parallax-deploy-shell-") as folder:
                            env = {**os.environ, **VALUES, "PROFILE_MODE": mode, "OUTPUT_DIR": folder}
                            output = run_bash(shell, ["-s"], script=program.encode(), env=env)
                            self.assertEqual(hashlib.sha256(output).hexdigest(), GUIDANCE_SHA256[mode])
                            for name, expected in FILE_SHA256.items():
                                self.assertEqual(hashlib.sha256((Path(folder) / name).read_bytes()).hexdigest(),
                                                 expected, name)

    def test_trim_large_input_without_preloading_a_pipe(self):
        expected = "literal-'\"-$-`-\\" * 2000
        program = (self.functions + '\ntrim_space "$TRIM_INPUT"\n').encode()
        for shell in SHELLS:
            with self.subTest(shell=shell):
                env = {**os.environ, "TRIM_INPUT": " \t" + expected + "\r \t"}
                self.assertEqual(run_bash(shell, ["-s"], script=program, env=env), expected.encode())


if __name__ == "__main__":
    unittest.main()
