#!/usr/bin/env python3
"""Run release ref and shell regressions locally: python3 <this file>."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).parents[1] / "workflows" / "release.yml"
TAG_EXPRESSION = "${{ github.event.inputs.tag || github.ref_name }}"


def step(name):
    for block in re.split(r"(?=^      - )", WORKFLOW.read_text(), flags=re.M):
        if block.startswith(f"      - name: {name}\n"):
            return block
    raise AssertionError(f"Missing workflow step: {name}")


def script(name):
    return textwrap.dedent(step(name).split("        run: |\n", 1)[1])


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.checkout = self.root / "checkout"
        self.source.mkdir()
        self.checkout.mkdir()
        self.git(self.source, "init", "-b", "main")
        self.commit("old")
        self.old = self.git(self.source, "rev-parse", "HEAD").stdout.strip()
        self.git(self.source, "tag", "v0.1.0")
        self.git(self.source, "-c", "user.name=Release Test", "-c",
                 "user.email=release@example.invalid", "tag", "-a",
                 "v0.1.0-annotated", "-m", "release")
        self.commit("new")
        self.new = self.git(self.source, "rev-parse", "HEAD").stdout.strip()
        self.git(self.source, "branch", "v0.1.0")
        self.git(self.source, "branch", "vbranch-only")
        self.git(self.checkout, "init")
        self.git(self.checkout, "remote", "add", "origin", str(self.source))

    @staticmethod
    def git(cwd, *args, check=True):
        return subprocess.run(
            ["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args],
            cwd=cwd, text=True, capture_output=True, check=check,
        )

    def commit(self, message):
        self.git(self.source, "-c", "user.name=Release Test", "-c",
                 "user.email=release@example.invalid", "commit",
                 "--allow-empty", "-m", message)

    def fetch_release(self, tag="", ref_name="main", check=True):
        match = re.search(r"^          ref: (.+)$", WORKFLOW.read_text(), re.M)
        # Without an explicit ref, checkout uses the event's selected branch/tag.
        ref = (match[1].replace(TAG_EXPRESSION, tag or ref_name) if match else
               f"refs/{'heads' if tag else 'tags'}/{ref_name}")
        self.assertNotIn("${{", ref)
        # Mirror the pinned action's qualified tag/branch refspecs.
        local_ref = (f"refs/remotes/origin/{ref[len('refs/heads/'):]}"
                     if ref.startswith("refs/heads/") else ref)
        result = self.git(self.checkout, "fetch", "--no-tags", "--depth=1",
                          "origin", f"+{ref}:{local_ref}", check=check)
        if result.returncode == 0:
            self.git(self.checkout, "checkout", "--detach", local_ref)
        return result

    def run_step(self, name, **env):
        self.assertNotIn("${{", script(name),
                         "release values must enter the shell through env")
        output = self.root / "output"
        output.write_text("")
        result = subprocess.run(
            ["bash", "-c", script(name)], cwd=self.checkout, text=True,
            capture_output=True,
            env={**os.environ, "GITHUB_OUTPUT": str(output), **env},
        )
        return result, output.read_text()

    def resolve(self, tag, push_commit=""):
        return self.run_step("Resolve version", RELEASE_TAG=tag,
                             PUSH_COMMIT=push_commit)

    def test_dispatch_from_main_builds_old_tag_despite_same_named_branch(self):
        self.fetch_release("v0.1.0", "main")
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD").stdout.strip(),
                         self.old)
        result, output = self.resolve("v0.1.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "tag=v0.1.0\nversion=0.1.0\n")

    def test_push_lightweight_and_annotated_tags(self):
        for tag in ("v0.1.0", "v0.1.0-annotated"):
            with self.subTest(tag=tag):
                self.fetch_release(ref_name=tag)
                result, _ = self.resolve(tag, self.old)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_branch_and_commit_inputs_are_not_tags(self):
        for tag in ("main", "vbranch-only", "refs/heads/main", self.old):
            with self.subTest(tag=tag):
                self.assertNotEqual(self.fetch_release(tag, check=False).returncode, 0)

    def test_wrong_checkout_is_rejected_before_build(self):
        self.fetch_release("v0.1.0")
        self.git(self.checkout, "fetch", "origin", "main")
        self.git(self.checkout, "checkout", "--detach", "FETCH_HEAD")
        result, output = self.resolve("v0.1.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, "")

    def test_moved_push_tag_is_rejected(self):
        self.fetch_release("v0.1.0")
        result, output = self.resolve("v0.1.0", self.new)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, "")

    def test_malformed_and_nonrelease_tags_are_rejected(self):
        self.fetch_release("v0.1.0")
        for tag in ("main", "v0.1.0\ntag=injected", "v0.1.0^{commit}", "v../main"):
            with self.subTest(tag=tag):
                result, output = self.resolve(tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")

    def test_shell_metacharacters_remain_data_through_packaging(self):
        tag = 'v$(touch${IFS}INJECTED);"quoted"'
        self.git(self.source, "tag", tag, self.old)
        self.fetch_release(tag)
        result, output = self.resolve(tag)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, f"tag={tag}\nversion={tag[1:]}\n")
        target = "x86_64-unknown-linux-gnu"
        bindir = self.checkout / "target" / target / "release"
        bindir.mkdir(parents=True)
        for binary in ("parallax", "plx"):
            (bindir / binary).write_bytes(b"test binary")
        result, output = self.run_step("Package", VERSION=tag[1:], TARGET=target)
        self.assertEqual(result.returncode, 0, result.stderr)
        tarball = f"parallax-{tag[1:]}-{target}.tar.gz"
        self.assertTrue((self.checkout / tarball).is_file())
        self.assertEqual(output, f"tarball={tarball}\n")
        stubdir = self.root / "bin"
        stubdir.mkdir()
        gh = stubdir / "gh"
        gh.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$GH_LOG"\n')
        gh.chmod(0o755)
        log = self.root / "gh.log"
        result, _ = self.run_step(
            "Publish to GitHub Release", TAG=tag, TARBALL=tarball,
            GH_LOG=str(log), PATH=f"{stubdir}{os.pathsep}{os.environ['PATH']}",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_text().splitlines(), [
            "release", "create", tag, "--title", tag, "--generate-notes",
            "--verify-tag", "release", "upload", tag, tarball,
            f"{tarball}.sha256", "--clobber",
        ])
        self.assertFalse((self.checkout / "INJECTED").exists())

    def test_release_values_are_wired_through_env(self):
        for name, bindings in {
            "Resolve version": {
                "RELEASE_TAG": TAG_EXPRESSION,
                "PUSH_COMMIT": "${{ github.event_name == 'push' && github.sha || '' }}",
            },
            "Package": {"VERSION": "${{ steps.ver.outputs.version }}",
                        "TARGET": "${{ matrix.target }}"},
            "Publish to GitHub Release": {
                "TAG": "${{ steps.ver.outputs.tag }}",
                "TARBALL": "${{ steps.pkg.outputs.tarball }}",
            },
        }.items():
            for key, value in bindings.items():
                self.assertIn(f"          {key}: {value}\n", step(name))


if __name__ == "__main__":
    unittest.main()
