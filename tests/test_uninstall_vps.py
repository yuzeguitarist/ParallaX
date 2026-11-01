"""Run the uninstaller's remote payload in a temporary, stubbed VPS filesystem.

Run with: python3 -m unittest discover -s tests -p test_uninstall_vps.py
"""

import contextlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/uninstall-vps.sh"
HOMEBREW_BASH = next((path for path in (Path("/opt/homebrew/bin/bash"), Path("/usr/local/bin/bash"))
                      if path.is_file()), None)


def run_bounded_command(command, env=None, input_text=None):
    with contextlib.ExitStack() as cleanup:
        stdin = None
        if input_text is not None:
            # A regular file also avoids Python's blocking writes to macOS
            # pipes whose dynamic capacity is below its assumed write size.
            stdin = cleanup.enter_context(tempfile.TemporaryFile(mode="w+t", encoding="utf-8"))
            stdin.write(input_text)
            stdin.seek(0)
        process = subprocess.Popen(command, text=True, stdin=stdin, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, env=env)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=5)
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def run_script(shell, *args, env=None):
    return run_bounded_command([str(shell), str(SCRIPT), *args], env=env)


def run_script_dry_run(shell):
    return run_script(shell, "--host", "root@sandbox.invalid", "--keep-local", "--dry-run")


def expected_remote_payload():
    literal = SCRIPT.read_text().split("  printf -v remote_script '%s' ", 1)[1]
    literal = literal.split('\n\n  if [[ "$DRY_RUN"', 1)[0]
    words = shlex.split(literal)
    if len(words) != 1:
        raise AssertionError("remote payload must be one literal printf argument")
    return words[0] + "\n"


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

if command in ("rm", "rmdir"):
    for arg in args:
        if arg.startswith("-"):
            continue
        path = Path(arg)
        if not path.is_relative_to(root):
            raise SystemExit("refusing filesystem mutation outside sandbox: " + arg)
        if command == "rmdir":
            path.rmdir()
        elif path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
elif command == "systemctl":
    units = json.loads((root / "loaded.json").read_text())
    if args[0] == "list-unit-files":
        if (root / "etc/systemd/system" / args[-1]).exists():
            print(args[-1], "enabled")
    elif args[0] == "list-units":
        if "--type=service" in args:
            if (root / "inventory-fails").exists():
                raise SystemExit(1)
            for unit in units:
                print(unit, "loaded active running")
        elif (root / "etc/systemd/system" / args[-1]).exists():
            print(args[-1], "loaded active running")
    elif args[0] == "show":
        print(units[args[-1]])
elif command == "ufw" and args[0] == "status":
    print("Status: active\n[ 1] 22/tcp ALLOW IN Anywhere # SSH\n"
          "[ 2] 443/tcp ALLOW IN Anywhere # ParallaX\n"
          "[ 3] 443/tcp (v6) ALLOW IN Anywhere (v6) # ParallaX")
elif command == "id":
    print("1001")
'''


class UninstallShellCompatibilityTests(unittest.TestCase):
    def assert_shell_syntax(self, shell):
        result = subprocess.run([str(shell), "-n", str(SCRIPT)], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_shell_dry_run(self, shell):
        result = run_script_dry_run(shell)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("decode_service_executable() {", result.stdout)
        self.assertIn("Dry run finished. Nothing was changed.", result.stdout)
        return result.stdout

    def test_literal_remote_payload_matches_emitted_bytes_in_both_shells(self):
        self.assertNotIn("<<", SCRIPT.read_text(), "avoid synchronous heredoc/here-string prefill")
        expected = expected_remote_payload()
        for shell in ("/bin/bash", HOMEBREW_BASH):
            if shell is None:
                continue
            with self.subTest(shell=str(shell)):
                stdout = self.assert_shell_dry_run(shell)
                actual = stdout[stdout.index('set -Eeuo pipefail\nexport PATH='):].split("\nDry run finished.", 1)[0]
                self.assertEqual(actual, expected)

    def test_fake_ssh_receives_exact_payload_bytes_in_both_shells(self):
        with tempfile.TemporaryDirectory(prefix="parallax-fake-ssh-") as directory:
            root = Path(directory)
            ssh = root / "ssh"
            ssh.write_text("#!/usr/bin/env python3\nimport os, pathlib, sys\n"
                           "pathlib.Path(os.environ['CAPTURE']).write_bytes(sys.stdin.buffer.read())\n")
            ssh.chmod(0o755)
            capture = root / "payload"
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "CAPTURE": str(capture)}
            for shell in ("/bin/bash", HOMEBREW_BASH):
                if shell is None:
                    continue
                with self.subTest(shell=str(shell)):
                    result = run_script(shell, "--host", "root@sandbox.invalid", "--yes",
                                        "--keep-local", "--no-sudo", env=env)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(capture.read_bytes(), expected_remote_payload().encode())

    def test_help_and_banner_literal_output_in_both_shells(self):
        source = SCRIPT.read_text()
        definitions = source.split('\nSSH_TARGET=""\n', 1)[0]
        for shell in ("/bin/bash", HOMEBREW_BASH):
            if shell is None:
                continue
            with self.subTest(shell=str(shell)):
                help_result = run_script(shell, "--help")
                self.assertEqual(help_result.returncode, 0, help_result.stderr)
                help_words = shlex.split(source.split("usage() {\n", 1)[1].split("\n}\n", 1)[0])
                self.assertEqual(help_result.stdout, help_words[2])
                banner_result = run_bounded_command([str(shell), "-c", definitions + "\ninteractive_banner\n"])
                self.assertEqual(banner_result.returncode, 0, banner_result.stderr)
                banner_words = shlex.split(source.split("interactive_banner() {\n", 1)[1].split("\n}\n", 1)[0])
                self.assertEqual(banner_result.stdout, banner_words[2])

    def test_large_plan_prints_without_document_prefill(self):
        remote_bin = "/opt/" + "binary-" * 200 + "/plx"
        remote_config = "/etc/" + "config-" * 200 + "/server.toml"
        for shell in ("/bin/bash", HOMEBREW_BASH):
            if shell is None:
                continue
            with self.subTest(shell=str(shell)):
                result = run_script(shell, "--host", "root@sandbox.invalid", "--keep-local", "--dry-run",
                                    "--remote-bin", remote_bin, "--remote-config", remote_config)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(remote_bin, result.stdout)
                self.assertIn(remote_config, result.stdout)

    def test_system_bash_complete_script_syntax(self):
        self.assert_shell_syntax("/bin/bash")

    def test_system_bash_complete_script_dry_run(self):
        self.assert_shell_dry_run("/bin/bash")

    @unittest.skipUnless(HOMEBREW_BASH, "Homebrew Bash is not installed")
    def test_homebrew_bash_complete_script_syntax(self):
        self.assert_shell_syntax(HOMEBREW_BASH)

    @unittest.skipUnless(HOMEBREW_BASH, "Homebrew Bash is not installed")
    def test_homebrew_bash_complete_script_dry_run(self):
        self.assert_shell_dry_run(HOMEBREW_BASH)


class UninstallVpsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = run_script_dry_run("bash")
        result.check_returncode()
        start = result.stdout.index('set -Eeuo pipefail\nexport PATH=')
        cls.remote_script = result.stdout[start:].split("\nDry run finished.", 1)[0]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="parallax-uninstall-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.put("loaded.json", "{}")
        stub = self.put("stub", f"#!/usr/bin/env python3\n{STUB}")
        stub.chmod(0o755)
        for command in ("systemctl", "ufw", "sysctl", "snap", "id", "userdel", "rm", "rmdir"):
            path = self.root / "commands" / command
            path.parent.mkdir(exist_ok=True)
            path.symlink_to(stub)

        self.put("etc/systemd/system/parallax.service", "[Service]\nUser=parallax\n")
        self.put("etc/systemd/system/parca-agent.service",
                 "[Service]\nEnvironmentFile=/etc/parallax/polarsignals.env\n")
        self.shared = [
            "usr/local/bin/plx", "etc/parallax/parallax.toml",
            "etc/parallax/parallax.toml.secrets.enc",
            "etc/parallax/parallax.secrets.enc", "etc/parallax/parallax-replay.cache",
            "var/lib/parallax/host.key", "var/lib/parallax/parallax-replay.cache",
            "etc/parallax/polarsignals.env", "etc/parallax/polarsignals.token",
            "etc/modules-load.d/parallax-bbr.conf", "etc/sysctl.d/99-parallax-bbr.conf",
            "etc/sysctl.d/99-parallax-netbuf.conf",
            "var/lib/parallax/replay-parallax.cache",
            "var/lib/parallax/replay-parallax.cache.0rtt",
            "var/lib/parallax/replay-parallax.cache.marker",
        ]
        for path in self.shared:
            self.put(path, "fixture\n")
        self.instance_files = [
            "usr/local/bin/plx", "etc/parallax/parallax.toml",
            "etc/parallax/parallax.toml.secrets.enc",
            "var/lib/parallax/replay-parallax.cache",
            "var/lib/parallax/replay-parallax.cache.0rtt",
            "var/lib/parallax/replay-parallax.cache.marker",
        ]

    def put(self, path, content):
        path = self.root / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.sandbox_paths(content))
        return path

    def sandbox_paths(self, text):
        return re.sub(r"/(?:etc/|var/lib/|usr/local/lib/|usr/local/bin/|run/systemd/|usr/lib/systemd/|lib/systemd/|opt/)",
                      lambda match: f"{self.root}{match[0]}", text)

    def run_uninstall(self, **options):
        script = self.sandbox_paths(self.remote_script)
        env = {
            **os.environ,
            "VPS_ROOT": str(self.root),
            "PATH": f"{self.root}/commands:{os.environ['PATH']}",
            "SUDO": "",
            "REMOTE_BIN": f"{self.root}/usr/local/bin/plx",
            "REMOTE_CONFIG": f"{self.root}/etc/parallax/parallax.toml",
            "SERVICE_NAME": "parallax",
            "REMOVE_USER": "1", "REMOVE_PARCA_AGENT": "1",
            **options,
        }
        self.result = run_bounded_command(["bash", "-s"], input_text=script, env=env)
        self.assertEqual(self.result.returncode, 0, self.result.stdout + self.result.stderr)
        self.commands = [json.loads(line) for line in
                         (self.root / "commands.jsonl").read_text().splitlines()]
        self.assertFalse((self.root / "etc/systemd/system/parallax.service").exists())
        self.assertIn(["systemctl", "stop", "parallax.service"], self.commands)
        self.assertIn(["systemctl", "daemon-reload"], self.commands)

    def assert_shared_kept(self):
        for path in self.shared:
            if path in self.instance_files:
                continue
            self.assertTrue((self.root / path).is_file(), path)
            self.assertEqual((self.root / path).read_text(), "fixture\n", path)
        self.assertTrue((self.root / "etc/systemd/system/parca-agent.service").exists())
        for command in self.commands:
            self.assertNotIn(command[0], ("ufw", "sysctl", "snap", "userdel"))
            self.assertNotEqual(command, ["systemctl", "stop", "parca-agent.service"])
        self.assertIn("kept shared resources", self.result.stdout + self.result.stderr)

    def assert_instance_removed(self):
        for path in self.instance_files:
            self.assertFalse((self.root / path).exists(), path)

    def test_second_service_sharing_legacy_bundle_and_binary(self):
        path = "etc/systemd/system/edge-two.service"
        self.put(path, "[Service]\nUser=parallax\nExecStart=/usr/local/bin/plx serve -c /etc/parallax/two.toml\n")
        self.put("etc/parallax/two.toml", 'psk = { sealed = "parallax.secrets.enc#psk" }\n')
        self.run_uninstall()
        self.assert_shared_kept()
        self.assertTrue((self.root / path).exists())
        self.assertTrue((self.root / "etc/parallax/two.toml").exists())
        self.assertTrue((self.root / "usr/local/bin/plx").exists())
        for path in self.instance_files[1:]:
            self.assertFalse((self.root / path).exists(), path)

    def test_large_unit_settings_preserve_shared_files_with_early_grep_match(self):
        self.put_other_shared_references("-c /etc/parallax/other.toml")
        self.put("etc/systemd/system/other.service",
                 "[Service]\nUser=parallax\n" + "# long unit settings\n" * 1000 +
                 "ExecStart=/opt/other/plx serve -c /etc/parallax/other.toml\n")
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_second_service_sharing_same_config_and_binary(self):
        self.put("etc/systemd/system/shared.service",
                 "[Service]\nUser=parallax\nExecStart=/usr/local/bin/plx serve -c /etc/parallax/parallax.toml\n")
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)

    def test_second_service_with_separate_config_and_binary(self):
        self.put("etc/systemd/system/custom-name.service",
                 "[Unit]\nDescription=ParallaX server\n[Service]\nExecStart=/opt/other/plx serve -c /opt/other/server.toml\n")
        self.put("opt/other/server.toml",
                 '[crypto]\npsk = { sealed = "server.toml.secrets.enc#psk" }\n'
                 '[traffic]\nmax_concurrent_streams = 4\n'
                 '[server]\nlisten = "0.0.0.0:443"\n'
                 'authorized_sni = ["example.org"] # ordinary generated array\n'
                 'replay_cache_path = "/var/lib/parallax/replay-other.cache"\n')
        self.put("opt/other/server.toml.secrets.enc", "other sealed bundle")
        self.put("var/lib/parallax/replay-other.cache", "other replay cache")
        self.put("opt/other/plx", "other binary")
        self.run_uninstall()
        self.assert_shared_kept()
        self.assert_instance_removed()
        self.assertTrue((self.root / "opt/other/server.toml").exists())
        self.assertTrue((self.root / "opt/other/server.toml.secrets.enc").exists())
        self.assertTrue((self.root / "var/lib/parallax/replay-other.cache").exists())
        self.assertTrue((self.root / "opt/other/plx").exists())

    def test_no_seal_removes_selected_plaintext_credentials(self):
        self.put("etc/parallax/parallax.toml", 'psk = "selected plaintext credential"\n')
        (self.root / "etc/parallax/parallax.toml.secrets.enc").unlink()
        self.put("etc/systemd/system/other.service",
                 "[Service]\nUser=parallax\nExecStart=/opt/other/plx serve --config=/opt/other/server.toml\n")
        self.put("opt/other/server.toml", 'psk = "other plaintext credential"\n')
        self.run_uninstall()
        self.assert_shared_kept()
        self.assertFalse((self.root / "etc/parallax/parallax.toml").exists(),
                         "uninstall must remove the selected plaintext credentials")
        self.assert_instance_removed()
        self.assertTrue((self.root / "opt/other/server.toml").exists())

    def test_exact_paths_do_not_treat_prefixes_as_shared(self):
        self.put("etc/systemd/system/other.service",
                 "[Service]\nUser=parallax\nExecStart=/usr/local/bin/plx-two serve -c /etc/parallax/parallax.toml.bak\n")
        self.put("etc/parallax/parallax.toml.bak", 'psk = "other credential"\n')
        self.put("usr/local/bin/plx-two", "other binary")
        self.run_uninstall()
        self.assert_shared_kept()
        self.assert_instance_removed()
        self.assertTrue((self.root / "etc/parallax/parallax.toml.bak").exists())
        self.assertTrue((self.root / "usr/local/bin/plx-two").exists())

    def test_other_config_can_reference_selected_bundle_and_replay_cache(self):
        self.put_other_shared_references("-c /etc/parallax/other.toml")
        self.run_uninstall()
        self.assert_other_references_preserved()

    def put_custom_other_executable(self, executable):
        self.put_other_shared_references("-c /etc/parallax/other.toml")
        self.put("etc/systemd/system/other.service",
                 "[Unit]\nDescription=custom proxy\n[Service]\nUser=root\n"
                 f"ExecStart={executable} serve -c /etc/parallax/other.toml\n")

    def test_quoted_plx_executable_preserves_shared_dependencies_and_host_key(self):
        self.put_custom_other_executable('"/opt/other/plx"')
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_quoted_parallax_executable_preserves_shared_dependencies_and_host_key(self):
        self.put_custom_other_executable("'/opt/other/parallax'")
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_bare_plx_executable_preserves_shared_dependencies_and_host_key(self):
        self.put_custom_other_executable("plx")
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_bare_parallax_executable_preserves_shared_dependencies_and_host_key(self):
        self.put_custom_other_executable("parallax")
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_prefixed_quoted_plx_executable_preserves_shared_dependencies(self):
        self.put_custom_other_executable('-@:"/opt/other/plx" custom-argv-zero')
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_prefixed_bare_executable_preserves_shared_dependencies(self):
        self.put_custom_other_executable("+plx")
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_shell_credential_prefixed_executable_preserves_shared_dependencies(self):
        self.put_custom_other_executable("!|plx")
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_escaped_executable_preserves_all_instance_files(self):
        self.put_custom_other_executable(r'"/opt/other/p\x6cx"')
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)
        self.assertIn("could not inspect service executable", self.result.stderr)

    def test_variable_executable_preserves_all_instance_files(self):
        self.put_custom_other_executable('"/opt/other/${PROXY_BINARY}"')
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)
        self.assertIn("could not inspect service executable", self.result.stderr)

    def test_unrelated_quoted_prefixed_executable_allows_final_cleanup(self):
        self.put("etc/systemd/system/other.service",
                 "[Unit]\nDescription=custom proxy\n[Service]\nUser=root\n"
                 "ExecStart=-\"/usr/bin/httpd\" -c /etc/httpd/httpd.conf\n")
        self.run_uninstall()
        for path in self.shared:
            self.assertFalse((self.root / path).exists(), path)
        self.assertTrue((self.root / "etc/systemd/system/other.service").exists())

    def test_basic_quoted_toml_keys_preserve_dependencies(self):
        self.put_other_shared_references("-c /etc/parallax/other.toml")
        self.put("etc/parallax/other.toml",
                 'psk = { "sealed" = "parallax.toml.secrets.enc#psk" }\n'
                 '"replay_cache_path" = "/var/lib/parallax/replay-parallax.cache"\n')
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_literal_quoted_toml_keys_preserve_dependencies(self):
        self.put_other_shared_references("-c /etc/parallax/other.toml")
        self.put("etc/parallax/other.toml",
                 "psk = { 'sealed' = 'parallax.toml.secrets.enc#psk' }\n"
                 "'replay_cache_path' = '/var/lib/parallax/replay-parallax.cache'\n")
        self.run_uninstall()
        self.assert_other_references_preserved()

    def assert_unknown_toml_preserves_all_instance_files(self, text):
        self.put_other_shared_references("-c /etc/parallax/other.toml")
        self.put("etc/parallax/other.toml", text)
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)
        self.assertIn("could not inspect config references", self.result.stderr)

    def test_escaped_quoted_toml_key_preserves_all_instance_files(self):
        self.assert_unknown_toml_preserves_all_instance_files(
            r'psk = { "se\u0061led" = "parallax.toml.secrets.enc#psk" }' + '\n')

    def test_multiline_basic_toml_string_preserves_all_instance_files(self):
        self.assert_unknown_toml_preserves_all_instance_files(
            'psk = { sealed = """parallax.toml.secrets.enc#psk""" }\n')

    def test_multiline_literal_toml_string_preserves_all_instance_files(self):
        self.assert_unknown_toml_preserves_all_instance_files(
            "psk = { sealed = '''parallax.toml.secrets.enc#psk''' }\n")

    def test_dotted_toml_table_preserves_all_instance_files(self):
        self.assert_unknown_toml_preserves_all_instance_files(
            '[crypto.psk]\nsealed = "parallax.toml.secrets.enc#psk"\n')

    def test_dotted_toml_key_preserves_all_instance_files(self):
        self.assert_unknown_toml_preserves_all_instance_files(
            'server."replay_cache_path" = "/var/lib/parallax/replay-parallax.cache"\n')

    def put_other_shared_references(self, config_args):
        self.put("etc/systemd/system/other.service",
                 f"[Service]\nUser=parallax\nExecStart=/opt/other/plx serve {config_args}\n")
        self.put("etc/parallax/other.toml",
                 'psk = { sealed = "parallax.toml.secrets.enc#psk" }\n'
                 'replay_cache_path = "/var/lib/parallax/replay-parallax.cache"\n')

    def assert_other_references_preserved(self):
        self.assert_shared_kept()
        self.assertFalse((self.root / "etc/parallax/parallax.toml").exists())
        self.assertFalse((self.root / "usr/local/bin/plx").exists())
        for path in self.instance_files[2:]:
            self.assertTrue((self.root / path).exists(), path)

    def test_file_only_unit_whole_quoted_config_flag_preserves_dependencies(self):
        self.put_other_shared_references('"--config=/etc/parallax/other.toml"')
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_file_only_unit_quoted_short_flag_preserves_dependencies(self):
        self.put_other_shared_references('"-c" "/etc/parallax/other.toml"')
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_quoted_independent_config_still_removes_selected_credentials(self):
        self.put("etc/systemd/system/other.service",
                 "[Service]\nUser=parallax\nExecStart=/opt/other/plx serve '--config=/opt/other/server.toml'\n")
        self.put("opt/other/server.toml", 'psk = "other credential"\n')
        self.run_uninstall()
        self.assert_shared_kept()
        self.assert_instance_removed()

    def test_unresolved_config_arguments_preserve_all_instance_files(self):
        self.put_other_shared_references('"$OTHER_FLAGS"')
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)
        self.assertIn("could not decode config arguments", self.result.stderr)

    def test_missing_config_value_preserves_all_instance_files(self):
        self.put_other_shared_references('"--config"')
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)
        self.assertIn("could not decode config arguments", self.result.stderr)

    def test_description_config_flag_does_not_hide_ambiguous_execstart(self):
        self.put_other_shared_references('"$OTHER_FLAGS"')
        self.put("etc/systemd/system/other.service",
                 "[Unit]\nDescription=ParallaX -c /etc/parallax/other.toml\n"
                 "[Service]\nUser=parallax\nExecStart=/opt/other/plx serve \"$OTHER_FLAGS\"\n")
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)
        self.assertIn("could not decode config arguments", self.result.stderr)

    def test_dynamic_arguments_with_visible_config_preserve_all_instance_files(self):
        self.put_other_shared_references('--config=/etc/parallax/other.toml "$OTHER_FLAGS"')
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)
        self.assertIn("could not decode config arguments", self.result.stderr)

    def test_unclosed_quote_preserves_all_instance_files(self):
        self.put_other_shared_references('"--config=/etc/parallax/other.toml')
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)
        self.assertIn("could not decode config arguments", self.result.stderr)

    def test_loaded_unit_quoted_config_preserves_dependencies(self):
        self.put_other_shared_references('"--config=/etc/parallax/other.toml"')
        (self.root / "etc/systemd/system/other.service").unlink()
        self.put("loaded.json", json.dumps({
            "other.service": "User=parallax\nExecStart={ path=/opt/other/plx ; "
                             "argv[]=/opt/other/plx serve \"--config=/etc/parallax/other.toml\" ; }\n",
        }))
        self.run_uninstall()
        self.assert_other_references_preserved()

    def test_vendor_unit_and_old_root_service(self):
        self.put("usr/lib/systemd/system/legacy.service",
                 "[Service]\nUser=root\nExecStart=/usr/local/bin/plx serve -c /opt/legacy.toml\n")
        self.put("opt/legacy.toml", 'psk = "legacy credential"\n')
        self.run_uninstall()
        self.assert_shared_kept()

    def test_symlinked_disabled_unit(self):
        other = self.put("opt/other.service", "[Service]\nUser=parallax\n")
        (self.root / "etc/systemd/system/custom.service").symlink_to(other)
        self.run_uninstall()
        self.assert_shared_kept()

    def test_service_dropin(self):
        self.put("run/systemd/system/custom.service.d/override.conf", "[Service]\nUser=parallax\n")
        self.run_uninstall()
        self.assert_shared_kept()

    def test_loaded_unit_without_file(self):
        self.put("loaded.json", json.dumps({
            "transient-name.service": "User=root\nDescription=custom proxy\n"
                                      "ExecStart={ path=/usr/local/bin/plx ; argv[]=plx serve ; }\n",
        }))
        self.run_uninstall()
        self.assert_shared_kept()

    def test_failed_inventory_preserves_shared_resources(self):
        self.put("inventory-fails", "")
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.shared:
            self.assertTrue((self.root / path).exists(), path)

    def test_failed_config_inspection_preserves_instance_files(self):
        self.put("etc/systemd/system/other.service",
                 "[Service]\nUser=parallax\nExecStart=/opt/other/plx serve -c /opt/missing.toml\n")
        self.run_uninstall()
        self.assert_shared_kept()
        for path in self.instance_files:
            self.assertTrue((self.root / path).exists(), path)

    def test_last_instance_removes_all_requested_artifacts(self):
        self.put("etc/systemd/system/unrelated.service", "[Service]\nUser=www-data\nExecStart=/usr/bin/httpd\n")
        self.put("loaded.json", json.dumps({
            "unrelated.service": "User=www-data\nExecStart={ path=/usr/bin/httpd ; }\n",
            "parallax.service": "User=parallax\n",
        }))
        self.run_uninstall()
        for path in self.shared:
            self.assertFalse((self.root / path).exists(), path)
        self.assertFalse((self.root / "var/lib/parallax").exists())
        self.assertFalse((self.root / "etc/systemd/system/parca-agent.service").exists())
        self.assertIn(["snap", "remove", "parca-agent"], self.commands)
        self.assertIn(["userdel", "parallax"], self.commands)
        self.assertIn(["sysctl", "--system"], self.commands)
        self.assertEqual([c for c in self.commands if c[:3] == ["ufw", "--force", "delete"]],
                         [["ufw", "--force", "delete", "3"], ["ufw", "--force", "delete", "2"]])
        self.assertTrue((self.root / "etc/systemd/system/unrelated.service").exists())

    def test_last_instance_honors_keep_options(self):
        self.run_uninstall(REMOVE_BBR="0", REMOVE_UFW_RULE="0", REMOVE_USER="0", REMOVE_PARCA_AGENT="0")
        for path in ("etc/modules-load.d/parallax-bbr.conf", "etc/sysctl.d/99-parallax-bbr.conf",
                     "etc/sysctl.d/99-parallax-netbuf.conf"):
            self.assertTrue((self.root / path).exists(), path)
        self.assertFalse((self.root / "var/lib/parallax").exists())
        for command in self.commands:
            self.assertNotIn(command[0], ("ufw", "sysctl", "snap", "userdel"))


if __name__ == "__main__":
    unittest.main()
