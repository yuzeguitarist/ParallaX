#!/usr/bin/env python3
"""Offline guards for the source-pinned TSan builder.

Set PARALLAX_TSAN_VERIFY_INPUTS=1 to additionally acquire the pinned upstream
inputs and validate extraction/backport on a host without a Linux compiler.
That integration check does not build or validate the runtime.
"""

import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "tsan_runtime", Path(__file__).with_name("tsan_runtime.py"))
rt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rt)


class RuntimeBuilderGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_environment_does_not_instrument_the_runtime(self):
        contaminated = {
            "PATH": "/usr/bin", "HOME": "/tmp/example",
            "CFLAGS": "-fsanitize=thread",
            "CFLAGS_x86_64_unknown_linux_gnu": "-fsanitize=thread",
            "CXXFLAGS_x86_64-unknown-linux-gnu": "-fsanitize=thread",
            "CPPFLAGS": "-include malicious.h", "LDFLAGS": "-fsanitize=thread",
            "CMAKE_PREFIX_PATH": "/unexpected", "CMAKE_TOOLCHAIN_FILE": "/unexpected",
            "CC": "wrapper", "CXX": "wrapper", "CCACHE_PREFIX": "wrapper",
            "RUSTFLAGS": "-Zsanitizer=thread", "CARGO_ENCODED_RUSTFLAGS": "injected",
            "CPATH": "/injected", "LIBRARY_PATH": "/injected",
            "LD_PRELOAD": "/injected.so", "CCC_OVERRIDE_OPTIONS": "+-fsanitize=thread",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": "/injected", "LLVM_CMAKE_DIR": "/wrong",
        }
        clean = rt.clean_environment(contaminated)
        self.assertEqual(clean["PATH"], "/usr/bin")
        self.assertEqual(clean["HOME"], "/tmp/example")
        for name in set(contaminated) - {"PATH", "HOME"}:
            self.assertNotIn(name, clean)
        self.assertEqual(clean["GIT_CONFIG_GLOBAL"], os.devnull)

    def test_hash_mismatch_and_symlink_cache_are_rejected(self):
        source = self.root / "cache"
        source.write_bytes(b"correct source")
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(rt.verify_hash(source, expected)["sha256"], expected)
        with self.assertRaisesRegex(rt.BuildError, "SHA-256 mismatch"):
            rt.acquire(rt.PATCH_URL, self.root / "copy", "0" * 64, 1024, source)
        self.assertFalse((self.root / "copy").exists())
        link = self.root / "link"
        link.symlink_to(source)
        with self.assertRaisesRegex(rt.BuildError, "regular file"):
            rt.verify_hash(link, expected)

    def test_download_redirects_remain_https_on_pinned_hosts(self):
        rt.check_download_url(rt.SOURCE_URL)
        for url in ("http://github.com/a", "https://example.com/a",
                    "https://github.com.evil.invalid/a",
                    "https://name:password@github.com/a", "https://github.com:444/a"):
            with self.subTest(url=url), self.assertRaises(rt.BuildError):
                rt.check_download_url(url)

    def archive(self, extra=None):
        destination = self.root / "source.tar.gz"
        prefix = f"llvm-project-{rt.SOURCE_COMMIT}/"
        with tarfile.open(destination, "w:gz") as output:
            for name in ("compiler-rt/CMakeLists.txt", "llvm/CMakeLists.txt",
                         "compiler-rt/lib/tsan/rtl/tsan_interceptors_posix.cpp"):
                info = tarfile.TarInfo(prefix + name)
                info.size = 4
                info.mode = 0o644
                output.addfile(info, io.BytesIO(b"base"))
            if extra is not None:
                output.addfile(extra, io.BytesIO(b"evil") if extra.isfile() else None)
        return destination

    def test_archive_extracts_only_build_inputs(self):
        ignored = tarfile.TarInfo(f"llvm-project-{rt.SOURCE_COMMIT}/clang/unneeded.cpp")
        ignored.size = 4
        rt.extract_sources(self.archive(ignored), self.root / "source")
        self.assertFalse((self.root / "source/clang").exists())
        self.assertTrue((self.root / "source/compiler-rt/CMakeLists.txt").is_file())

    def test_archive_traversal_links_and_duplicates_are_rejected(self):
        prefix = f"llvm-project-{rt.SOURCE_COMMIT}/"
        for number, kind in enumerate(("traversal", "symlink", "duplicate")):
            name = {
                "traversal": prefix + "compiler-rt/../../escape",
                "symlink": prefix + "compiler-rt/redirect",
                "duplicate": prefix + "compiler-rt/CMakeLists.txt",
            }[kind]
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "../../escape"
            else:
                info.size = 4
            with self.subTest(kind=kind), self.assertRaises(rt.BuildError):
                rt.extract_sources(self.archive(info), self.root / f"source-{number}")
        self.assertFalse((self.root / "escape").exists())

    def test_unneeded_llvm_utilities_are_not_extracted(self):
        # The pinned archive has symlinks in LLVM's unrelated MLGO utilities.
        # Standalone compiler-rt uses its own symbol-generation scripts.
        ignored = tarfile.TarInfo(
            f"llvm-project-{rt.SOURCE_COMMIT}/llvm/utils/mlgo-utils/combine_training_corpus.py")
        ignored.type = tarfile.SYMTYPE
        ignored.linkname = "mlgo/corpus/combine.py"
        rt.extract_sources(self.archive(ignored), self.root / "source")
        self.assertFalse((self.root / "source/llvm/utils").exists())

    def test_patch_identity_and_exact_changed_paths(self):
        patch = self.root / "fix.patch"
        text = f"From {rt.PATCH_COMMIT} Mon Sep 17 00:00:00 2001\n"
        text += "".join(f"diff --git a/{name} b/{name}\n" for name in rt.PATCH_PATHS)
        patch.write_text(text, encoding="utf-8")
        rt.verify_patch(patch)
        patch.write_text(text + "diff --git a/unrelated b/unrelated\n", encoding="utf-8")
        with self.assertRaisesRegex(rt.BuildError, "exact upstream fix"):
            rt.verify_patch(patch)
        before = {rt.PATCH_PATHS[0]: "old", "unrelated": "unchanged"}
        after = {rt.PATCH_PATHS[0]: "new", rt.PATCH_PATHS[1]: "new", "unrelated": "unchanged"}
        rt.check_patch_changes(before, after)
        after["unrelated"] = "changed"
        with self.assertRaisesRegex(rt.BuildError, "unexpected sources"):
            rt.check_patch_changes(before, after)

    def test_runtime_requires_static_archive_and_fcntl_definitions(self):
        archive = self.root / "runtime.a"
        exports = self.root / "runtime.a.syms"
        archive.write_bytes(b"!<arch>\nfixture")
        exports.write_text("{\n" + "".join(f"  {name};\n" for name in rt.REQUIRED_SYMBOLS) + "};\n")
        nm = "\n".join(f"00000000 T {name}" for name in rt.REQUIRED_SYMBOLS)
        rt.validate_runtime(archive, exports, nm)
        with self.assertRaisesRegex(rt.BuildError, "missing definitions"):
            rt.validate_runtime(archive, exports, "00000000 T __tsan_init")
        archive.write_bytes(b"!<thin>\nfixture")
        with self.assertRaisesRegex(rt.BuildError, "self-contained static archive"):
            rt.validate_runtime(archive, exports, nm)
        archive.write_bytes(b"!<arch>\nfixture")
        exports.write_text("{};\n")
        with self.assertRaisesRegex(rt.BuildError, "sanitizer exports"):
            rt.validate_runtime(archive, exports, nm)

    def test_cmake_has_explicit_target_and_rejects_wrong_effective_config(self):
        tools = {name: Path("/usr/bin") / name for name in
                 ("cmake", "ninja", "clang", "clangxx")}
        command = rt.cmake_arguments(self.root / "src", self.root / "build",
                                     tools, self.root / "llvm-cmake")
        self.assertIn("-DCMAKE_C_COMPILER_TARGET=x86_64-unknown-linux-gnu", command)
        self.assertIn("-DCOMPILER_RT_SANITIZERS_TO_BUILD=tsan", command)
        self.assertIn("-DCMAKE_C_FLAGS=", command)
        self.assertIn("-DCMAKE_CXX_FLAGS=", command)
        cache = self.root / "CMakeCache.txt"
        entries = [item[2:].replace("=", ":STRING=", 1) for item in command if item.startswith("-D")]
        cache.write_text("\n".join(entries), encoding="utf-8")
        rt.validate_cache(cache)
        cache.write_text(cache.read_text().replace(
            "CMAKE_C_COMPILER_TARGET:STRING=x86_64-unknown-linux-gnu",
            "CMAKE_C_COMPILER_TARGET:STRING=aarch64-linux-gnu"), encoding="utf-8")
        with self.assertRaisesRegex(rt.BuildError, "configuration mismatch"):
            rt.validate_cache(cache)

    def test_output_ownership_and_failure_invalidate_previous_pass(self):
        occupied = self.root / "unowned"
        occupied.mkdir()
        (occupied / "important.txt").write_text("keep")
        with self.assertRaises(rt.BuildError):
            rt.prepare_output(occupied)
        self.assertEqual((occupied / "important.txt").read_text(), "keep")
        owned = self.root / "owned"
        owned.mkdir()
        rt.write_report(owned, {"schema": 1, "tool": rt.TOOL, "status": "passed",
                                "archive": {"path": "stale", "sha256": "stale"}})
        args = rt.arguments(["--output", str(owned)])
        with mock.patch.object(rt.sys, "platform", "linux"), \
                mock.patch.object(rt.platform, "machine", return_value="x86_64"), \
                mock.patch.object(rt, "executable", side_effect=rt.BuildError("missing compiler")):
            with self.assertRaisesRegex(rt.BuildError, "missing compiler"):
                rt.build_runtime(args)
        report = json.loads((owned / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertNotIn("archive", report)

    def test_incompatible_platform_has_no_build_side_effect(self):
        output = self.root / "unsupported"
        args = rt.arguments(["--output", str(output)])
        with mock.patch.object(rt.sys, "platform", "darwin"):
            with self.assertRaisesRegex(rt.BuildError, "native Linux x86_64"):
                rt.build_runtime(args)
        self.assertFalse(output.exists())


@unittest.skipUnless(os.name == "posix", "POSIX command-group cleanup")
class RuntimeProcessGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.groups = set()
        self.caller_group = os.getpgrp()
        self.helper = self.root / "process_fixture.py"
        self.helper.write_text(textwrap.dedent("""\
            import os
            import signal
            import subprocess
            import sys
            import time
            from pathlib import Path

            mode, directory = sys.argv[1:]
            root = Path(directory)
            if mode == "grandchild":
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                (root / "grandchild.pid").write_text(str(os.getpid()))
                while True:
                    time.sleep(0.1)
            (root / "parent.pid").write_text(str(os.getpid()))
            child = subprocess.Popen([sys.executable, __file__, "grandchild", directory])
            deadline = time.monotonic() + 10
            while not (root / "grandchild.pid").exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("grandchild did not start")
                time.sleep(0.01)
            if mode == "fail":
                raise SystemExit(7)
            while True:
                time.sleep(0.1)
            """), encoding="utf-8")

    def tearDown(self):
        # A broken cleanup implementation must not leave test descendants.
        parent = self.root / "parent.pid"
        if parent.exists():
            self.groups.add(int(parent.read_text()))
        for group in self.groups:
            if group != self.caller_group and group > 1:
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.temporary.cleanup()

    def wait_for(self, path):
        deadline = time.monotonic() + 10
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail(f"fixture did not create {path.name}")
            time.sleep(0.02)

    def assert_descendants_exited(self):
        for filename in ("parent.pid", "grandchild.pid"):
            path = self.root / filename
            self.assertTrue(path.is_file(), f"missing real-process fixture: {filename}")
            pid = int(path.read_text())
            with self.assertRaises(ProcessLookupError, msg=f"process {pid} survived cleanup"):
                os.kill(pid, 0)
        self.assertEqual(os.getpgrp(), self.caller_group)

    def test_timeout_cleans_real_descendants_without_signalling_caller(self):
        report = {"commands": []}
        commands = rt.Commands(self.root, rt.clean_environment(dict(os.environ)), report)
        with mock.patch.object(rt.os, "killpg", wraps=os.killpg) as signal_group:
            with rt.work_directory(self.root, commands) as work:
                with self.assertRaises(subprocess.TimeoutExpired):
                    commands.run([sys.executable, str(self.helper), "hang", str(self.root)],
                                 "timeout-fixture", work, timeout=3)
                self.assertTrue(work.is_dir())
            self.assertFalse(work.exists())
            self.assertTrue(signal_group.called)
            for call in signal_group.call_args_list:
                self.assertGreater(call.args[0], 1)
                self.assertNotEqual(call.args[0], self.caller_group)
        self.assertTrue(report["commands"][0]["cleanup_complete"])
        self.assert_descendants_exited()

    def test_nonzero_exit_cleans_abandoned_descendants(self):
        report = {"commands": []}
        commands = rt.Commands(self.root, rt.clean_environment(dict(os.environ)), report)
        with self.assertRaisesRegex(rt.BuildError, r"failed \(7\)"):
            commands.run([sys.executable, str(self.helper), "fail", str(self.root)],
                         "nonzero-fixture", self.root, timeout=10)
        self.assertTrue(report["commands"][0]["cleanup_complete"])
        self.assert_descendants_exited()

    def test_sigterm_unwinds_main_and_cleans_nested_command_group(self):
        driver = self.root / "driver_fixture.py"
        driver.write_text(textwrap.dedent("""\
            import importlib.util
            import json
            import os
            import sys
            from pathlib import Path

            spec = importlib.util.spec_from_file_location("runtime_builder", sys.argv[1])
            rt = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(rt)
            root = Path(sys.argv[2])
            report = {"commands": []}
            def build_fixture(_args):
                commands = rt.Commands(root, rt.clean_environment(dict(os.environ)), report)
                with rt.work_directory(root, commands) as work:
                    (root / "work.path").write_text(str(work))
                    try:
                        commands.run([sys.executable, str(root / "process_fixture.py"),
                                      "hang", str(root)], "term-fixture", work, timeout=30)
                    finally:
                        (root / "commands.json").write_text(json.dumps(report))
            rt.build_runtime = build_fixture
            raise SystemExit(rt.main([]))
            """), encoding="utf-8")
        with (self.root / "driver.log").open("w") as stream:
            driver_process = subprocess.Popen(
                [sys.executable, str(driver), str(Path(rt.__file__).resolve()), str(self.root)],
                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            self.groups.add(driver_process.pid)
            try:
                self.wait_for(self.root / "grandchild.pid")
                command_group = int((self.root / "parent.pid").read_text())
                self.assertNotEqual(command_group, driver_process.pid)
                self.assertNotEqual(command_group, self.caller_group)
                driver_process.send_signal(signal.SIGTERM)
                self.assertEqual(driver_process.wait(timeout=10), 1)
            finally:
                if driver_process.poll() is None:
                    os.killpg(driver_process.pid, signal.SIGKILL)
                    driver_process.wait(timeout=5)
        report = json.loads((self.root / "commands.json").read_text())
        self.assertTrue(report["commands"][0]["cleanup_complete"])
        self.assertIn("terminated by signal", (self.root / "driver.log").read_text())
        self.assertFalse(Path((self.root / "work.path").read_text()).exists())
        self.assert_descendants_exited()

    def test_unconfirmed_cleanup_retains_work_for_failed_report(self):
        report = {"commands": []}
        commands = rt.Commands(self.root, {}, report)
        with self.assertRaisesRegex(rt.BuildError, "fixture cleanup failed"):
            with rt.work_directory(self.root, commands) as work:
                commands.safe_to_clean = False
                raise rt.BuildError("fixture cleanup failed")
        self.assertTrue(work.is_dir())
        self.assertEqual(report["retained_work_directory"], str(work))


@unittest.skipUnless(os.environ.get("PARALLAX_TSAN_VERIFY_INPUTS") == "1",
                     "opt-in network source/backport verification; no runtime build")
class PinnedInputIntegration(unittest.TestCase):
    def test_pinned_archive_and_exact_backport(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            archive, patch = work / "source.tar.gz", work / "fix.patch"
            rt.acquire(rt.SOURCE_URL, archive, rt.SOURCE_SHA256, rt.MAX_SOURCE_BYTES)
            rt.acquire(rt.PATCH_URL, patch, rt.PATCH_SHA256, 2 * 1024 * 1024)
            rt.verify_patch(patch)
            source = work / "source"
            rt.extract_sources(archive, source)
            before = rt.source_state(source)
            commands = rt.Commands(work, rt.clean_environment(dict(os.environ)), {"commands": []})
            git = str(rt.executable("git"))
            template = work / "empty-template"
            template.mkdir()
            commands.run([git, "init", "--quiet", f"--template={template}"], "git-init", source)
            commands.run([git, "apply", "--check", "--whitespace=error-all", str(patch)],
                         "patch-check", source)
            commands.run([git, "apply", "--whitespace=error-all", str(patch)],
                         "patch-apply", source)
            after = rt.source_state(source)
            rt.check_patch_changes(before, after)
            print("Pinned source/backport verified; runtime NOT built. "
                  f"selected source SHA-256={rt.state_digest(after)}", flush=True)


if __name__ == "__main__":
    unittest.main()
