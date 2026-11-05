#!/usr/bin/env python3
"""Exercise real release workflow guards and package bytes without publishing."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release.yml"
SPEC = importlib.util.spec_from_file_location("release_artifacts", ROOT / "scripts/security/release_artifacts.py")
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)
COMMIT, TAG, TARGET = "a" * 40, "v0.1.0", "x86_64-unknown-linux-gnu"


def step(name):
    lines = WORKFLOW.read_text().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line == f"      - name: {name}\n")
    end = start + 1
    while end < len(lines):
        line = lines[end]
        if line.strip() and (not line.startswith("      ") or line.startswith("      - ")):
            break
        end += 1
    return "".join(lines[start:end])


def script(name):
    return textwrap.dedent(step(name).split("        run: |\n", 1)[1])


def inline_python(name):
    source = script(name)
    assert source.startswith("python3 - <<'PY'\n")
    return source.split("\n", 1)[1].rsplit("\nPY", 1)[0]


def fixture(root, out, target=TARGET):
    root.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True)
    for filename in ("README.md", "LICENSE", "NOTICE", "Cargo.lock"):
        (root / filename).write_text(f"fixture {filename}\n")
    sboms = {}
    for binary in PACKAGE.BINARIES:
        (out / binary).write_bytes(f"fixture final {binary}".encode())
        raw = {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"name": "parallax", "bom-ref": "path+file:///private/source"}},
            "components": [{"name": "fixture-dependency", "version": "1.2.3"}],
            "dependencies": [{"ref": "path+file:///private/source", "dependsOn": []}],
        }
        sboms[binary] = PACKAGE.bind_sbom(raw, binary, PACKAGE.digest(out / binary),
                                          TAG, target, COMMIT, "0.1.0")
    native = {"schema": 1, "target": target, "coverage": PACKAGE.COVERAGE}
    PACKAGE.assemble(root, out, TAG, target, COMMIT, "fixture rustc", sboms, native, 123456789)
    return out


class RefTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-b", "main")
        self.git("-c", "user.name=Release Test", "-c", "user.email=test@example.invalid",
                 "commit", "--allow-empty", "-m", "old")
        self.old = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("tag", TAG)
        self.git("-c", "user.name=Release Test", "-c", "user.email=test@example.invalid",
                 "tag", "-a", TAG + "-annotated", "-m", "test")
        self.git("-c", "user.name=Release Test", "-c", "user.email=test@example.invalid",
                 "commit", "--allow-empty", "-m", "new")
        self.new = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("branch", TAG)

    def git(self, *args):
        return subprocess.run(["git", "-c", "gc.auto=0", *args], cwd=self.root,
                              capture_output=True, text=True, check=True)

    def run_step(self, name, **env):
        output = self.root / "outputs"
        output.write_text("")
        source = script(name)
        self.assertNotIn("${{", source)
        result = subprocess.run(["bash", "-c", source], cwd=self.root, capture_output=True,
                                text=True, env={**os.environ, "GITHUB_OUTPUT": str(output), **env})
        return result, output.read_text()

    def test_dispatch_requires_same_tag_ref(self):
        for ref, input_tag, ok in [
            ("refs/heads/main", TAG, False),
            (f"refs/tags/{TAG}", TAG, True),
            (f"refs/tags/{TAG}", "v0.2.0", False),
        ]:
            result, _ = self.run_step("Validate event ref", EVENT_NAME="workflow_dispatch",
                                      EVENT_REF=ref, EVENT_TAG=TAG, INPUT_TAG=input_tag)
            self.assertEqual(result.returncode == 0, ok, result.stderr)

    def test_invalid_tags_never_reach_build(self):
        for tag in ("main", "v01.0.0", "v0.1.0\ninjected", "v0.1.0^{commit}",
                    "v$(touch INJECTED)", "v0.1.0/extra", "v" + "1" * 101):
            result, _ = self.run_step("Validate event ref", EVENT_NAME="push",
                                      EVENT_REF=f"refs/tags/{tag}", EVENT_TAG=tag, INPUT_TAG="")
            self.assertNotEqual(result.returncode, 0, tag)
        self.assertFalse((self.root / "INJECTED").exists())

    def test_exact_lightweight_and_annotated_commit(self):
        for tag in (TAG, TAG + "-annotated"):
            self.git("checkout", "--detach", self.old)
            result, output = self.run_step("Resolve version", RELEASE_TAG=tag, EVENT_COMMIT=self.old)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"commit={self.old}\n", output)

    def test_wrong_head_and_moved_tag_rejected(self):
        result, output = self.run_step("Resolve version", RELEASE_TAG=TAG, EVENT_COMMIT=self.old)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, "")
        self.git("checkout", "--detach", self.old)
        result, output = self.run_step("Resolve version", RELEASE_TAG=TAG, EVENT_COMMIT=self.new)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, "")


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = fixture(self.root / "source", self.root / "artifacts")
        self.name = PACKAGE.prefix(TAG, TARGET)

    def validate(self, **env):
        with patch.dict(os.environ, {
            "RELEASE_TAG": TAG, "TARGET": TARGET, "SOURCE_SHA": COMMIT,
            "ARTIFACT_DIR": str(self.out), "GITHUB_OUTPUT": str(self.root / "outputs"), **env,
        }):
            exec(compile(inline_python("Validate release artifacts"), str(WORKFLOW), "exec"), {})

    def rewrite_manifest_hash(self, filename):
        path = self.out / f"{self.name}.manifest.json"
        manifest = PACKAGE.read_json(path)
        manifest["files"][filename] = {
            "sha256": PACKAGE.digest(self.out / filename), "size": (self.out / filename).stat().st_size,
        }
        PACKAGE.write_json(path, manifest)

    def test_complete_package_is_accepted_and_archive_has_licenses(self):
        self.validate()
        with tarfile.open(self.out / f"{self.name}.tar.gz") as archive:
            names = set(archive.getnames())
            for filename in ("parallax", "plx", "README.md", "LICENSE", "NOTICE"):
                self.assertIn(f"{self.name}/{filename}", names)
            self.assertTrue(all(not item.issym() and not item.islnk() for item in archive.getmembers()))
            self.assertEqual(archive.extractfile(f"{self.name}/parallax").read(),
                             (self.out / "parallax").read_bytes())

    def test_tampered_binary_rejected(self):
        (self.out / "parallax").write_bytes(b"tampered")
        with self.assertRaisesRegex(SystemExit, "mismatch"):
            self.validate()

    def test_valid_checksums_cannot_hide_wrong_archive_bytes_or_paths(self):
        tar_path = self.out / f"{self.name}.tar.gz"
        original = tar_path.read_bytes()
        for mutation in ("binary", "path", "mode"):
            with self.subTest(mutation=mutation):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as source:
                    with tarfile.open(fileobj=buffer, mode="w:gz") as forged:
                        for member in source:
                            data = source.extractfile(member).read() if member.isfile() else None
                            if member.name == f"{self.name}/parallax":
                                if mutation == "binary":
                                    data = b"changed executable"
                                    member.size = len(data)
                                elif mutation == "path":
                                    member.name = "../escaped"
                                else:
                                    member.mode = 0o4755
                            forged.addfile(member, io.BytesIO(data) if data is not None else None)
                tar_path.write_bytes(buffer.getvalue())
                checksum = self.out / f"{self.name}.tar.gz.sha256"
                checksum.write_text(f"{PACKAGE.digest(tar_path)}  {tar_path.name}\n")
                self.rewrite_manifest_hash(tar_path.name)
                self.rewrite_manifest_hash(checksum.name)
                with self.assertRaisesRegex(SystemExit, "archive"):
                    self.validate()

    def test_self_consistent_manifest_cannot_hide_wrong_sbom(self):
        filename = f"{self.name}.parallax.cdx.json"
        bom = PACKAGE.read_json(self.out / filename)
        bom["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
        PACKAGE.write_json(self.out / filename, bom)
        self.rewrite_manifest_hash(filename)
        with self.assertRaisesRegex(SystemExit, "SBOM binary mismatch"):
            self.validate()

    def test_missing_extra_and_symlink_rejected(self):
        extra = self.out / "unexpected"
        extra.write_text("extra")
        with self.assertRaisesRegex(SystemExit, "unexpected/missing"):
            self.validate()
        extra.unlink()
        (self.out / "parallax").unlink()
        with self.assertRaisesRegex(SystemExit, "unexpected/missing"):
            self.validate()
        (self.out / "parallax").symlink_to(self.out / "plx")
        with self.assertRaisesRegex(SystemExit, "non-regular"):
            self.validate()

    def test_duplicate_json_and_wrong_target_rejected(self):
        path = self.out / f"{self.name}.manifest.json"
        valid = path.read_text()
        path.write_text(valid.replace('"schema": 1', '"schema": 1, "schema": 1'))
        with self.assertRaisesRegex(SystemExit, "duplicate JSON"):
            self.validate()
        path.write_text(valid)
        with self.assertRaisesRegex(SystemExit, "unexpected/missing"):
            self.validate(TARGET="aarch64-apple-darwin")

    def test_manifest_cannot_escape_artifact_directory(self):
        path = self.out / f"{self.name}.manifest.json"
        manifest = PACKAGE.read_json(path)
        manifest["files"]["../secret"] = manifest["files"].pop("parallax")
        PACKAGE.write_json(path, manifest)
        with self.assertRaisesRegex(SystemExit, "wrong manifest file set"):
            self.validate()

    def test_bound_sbom_preserves_graph_and_hides_build_path(self):
        bom = PACKAGE.read_json(self.out / f"{self.name}.parallax.cdx.json")
        self.assertEqual(bom["dependencies"][0]["ref"], bom["metadata"]["component"]["bom-ref"])
        self.assertNotIn("/private/source", json.dumps(bom))
        self.assertEqual(bom["metadata"]["component"]["hashes"][0]["content"],
                         PACKAGE.digest(self.out / "parallax"))


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "downloads"
        for target in PACKAGE.TARGETS:
            out = fixture(self.root / "source", self.artifacts / f"signed-{target}", target)
            prefix = PACKAGE.prefix(TAG, target)
            for suffix in (".provenance.sigstore.jsonl", ".parallax.sbom.sigstore.jsonl", ".plx.sbom.sigstore.jsonl"):
                (out / f"{prefix}{suffix}").write_text("fixture bundle\n")
        self.calls = []

    def publish(self, fail_verify=False, tag_commit=COMMIT, annotated=False):
        def run(args, check):
            self.assertTrue(check)
            self.calls.append(args)
            if fail_verify and args[1:3] == ["attestation", "verify"]:
                raise subprocess.CalledProcessError(1, args)
        def response(args, text):
            self.assertTrue(text)
            self.calls.append(args)
            if annotated and "/git/ref/tags/" in args[-1]:
                return json.dumps({"object": {"type": "tag", "sha": "b" * 40}})
            return json.dumps({"object": {"type": "commit", "sha": tag_commit}})
        with patch.dict(os.environ, {
            "RELEASE_TAG": TAG, "SOURCE_SHA": COMMIT, "GITHUB_REPOSITORY": "yuzeguitarist/ParallaX",
            "GITHUB_REF": f"refs/tags/{TAG}", "ARTIFACT_DIR": str(self.artifacts),
        }), patch("subprocess.run", side_effect=run), patch("subprocess.check_output", side_effect=response):
            exec(compile(inline_python("Verify attestations and publish"), str(WORKFLOW), "exec"), {})

    def test_all_targets_verified_before_first_write(self):
        self.publish(annotated=True)
        first_write = next(i for i, call in enumerate(self.calls) if call[1:3] == ["release", "create"])
        verifies = [call for call in self.calls[:first_write] if call[1:3] == ["attestation", "verify"]]
        self.assertEqual(len(verifies), 30)
        for call in verifies:
            for flag in ("--source-ref", "--source-digest", "--signer-workflow", "--deny-self-hosted-runners"):
                self.assertIn(flag, call)
        self.assertTrue(any("/git/tags/" in call[-1] for call in self.calls if call[1] == "api"))
        self.assertIn("--draft", self.calls[first_write])
        self.assertNotIn("--clobber", str(self.calls))
        self.assertEqual(self.calls[-1][1:3], ["release", "edit"])

    def test_verification_or_moved_remote_tag_blocks_writes(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish(fail_verify=True)
        self.assertFalse(any(call[1] == "release" for call in self.calls))
        self.calls.clear()
        with self.assertRaisesRegex(SystemExit, "tag moved"):
            self.publish(tag_commit="c" * 40)
        self.assertFalse(any(call[1] == "release" for call in self.calls))

    def test_unexpected_target_blocks_writes(self):
        (self.artifacts / "signed-extra").mkdir()
        with self.assertRaisesRegex(SystemExit, "missing/extra targets"):
            self.publish()
        self.assertEqual(self.calls, [])


class TrustBoundaryTests(unittest.TestCase):
    def test_privileged_jobs_never_checkout_or_build(self):
        workflow = WORKFLOW.read_text()
        attest = workflow.split("\n  attest:\n", 1)[1].split("\n  publish:\n", 1)[0]
        publish = workflow.split("\n  publish:\n", 1)[1]
        for job in (attest, publish):
            self.assertNotIn("actions/checkout@", job)
            self.assertNotIn("cargo ", job)
            self.assertNotIn("scripts/security/", job)
            self.assertNotIn("tar -", job)
        self.assertIn("needs: [resolve, build]", attest)
        self.assertIn("needs: [resolve, build, attest]", publish)
        self.assertIn("id-token: write", attest)
        self.assertNotIn("contents: write", attest)
        self.assertNotIn("id-token: write", publish)
        self.assertIn("contents: write", publish)
        for action in re.findall(r"uses: ([^\s#]+)", workflow):
            self.assertRegex(action, r"@[0-9a-f]{40}$")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "validate-artifacts":
        parser = argparse.ArgumentParser(description="Run the actual privileged-job validator locally.")
        parser.add_argument("--directory", required=True)
        parser.add_argument("--tag", required=True)
        parser.add_argument("--target", required=True)
        parser.add_argument("--commit", required=True)
        args = parser.parse_args(sys.argv[2:])
        with patch.dict(os.environ, {
            "ARTIFACT_DIR": args.directory, "RELEASE_TAG": args.tag,
            "TARGET": args.target, "SOURCE_SHA": args.commit, "GITHUB_OUTPUT": os.devnull,
        }):
            exec(compile(inline_python("Validate release artifacts"), str(WORKFLOW), "exec"), {})
        print("Actual release artifacts passed the signing-job validator.")
    else:
        unittest.main()
