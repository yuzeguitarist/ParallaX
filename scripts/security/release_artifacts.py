#!/usr/bin/env python3
"""Build-side release packaging. Run only in the read-only build job.

Requires Python 3.11 and cargo-cyclonedx 0.5.9. The signing/publishing jobs do
not check out this file, run Cargo, or execute anything from the build artifacts.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import uuid

TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-apple-darwin")
BINARIES = ("parallax", "plx")
TAG_PATTERN = r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
NATIVE_CRATES = {"aws-lc-sys", "ring"}
COVERAGE = (
    "Cargo dependencies for this target and default release features, including "
    "build dependencies and excluding dev-only dependencies. Bundled native code "
    "is identified by the enclosing crate source checksum; its internal upstream "
    "components are not individually inventoried. OS/SDK libraries are external "
    "runtime dependencies; their installed versions are not asserted."
)

def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def read_json(path):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, f"Duplicate JSON key: {key}")
            out[key] = value
        return out
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)

def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def command(args, root, env=None):
    return subprocess.run(
        args, cwd=root, env=env, check=True, text=True, capture_output=True,
    ).stdout.strip()

def prefix(tag, target):
    require(re.fullmatch(TAG_PATTERN, tag) is not None, "Expected a version tag such as v0.1.0")
    require(len(tag) <= 100, "Release tag is too long")
    require(target in TARGETS, "Unsupported release target")
    return f"parallax-{tag[1:]}-{target}"

def bind_sbom(bom, binary, sha256, tag, target, commit, package_version):
    require(bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") == "1.5",
            "Expected a CycloneDX 1.5 SBOM")
    component = bom["metadata"]["component"]
    old_ref = component["bom-ref"]
    new_ref = f"urn:parallax:{commit}:{target}:{binary}"
    # cargo-cyclonedx emits the local absolute workspace path in the root ID.
    # Replace that ID throughout the graph, preserving all dependency edges.
    def replace(value):
        if isinstance(value, str):
            return new_ref if value == old_ref else value
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value
    bom = replace(bom)
    component = bom["metadata"]["component"]
    component.update({
        "name": binary,
        "version": tag[1:],
        "purl": f"pkg:github/yuzeguitarist/ParallaX@{commit}#{binary}",
        "hashes": [{"alg": "SHA-256", "content": sha256}],
    })
    # cargo-cyclonedx 0.5.9 omits this optional CycloneDX field, but the
    # attestation action requires it. Bind a canonical UUID URN to final bytes.
    identity = f"https://github.com/yuzeguitarist/ParallaX/{commit}/{target}/{binary}/sha256/{sha256}"
    bom["serialNumber"] = uuid.uuid5(uuid.NAMESPACE_URL, identity).urn
    props = bom["metadata"].setdefault("properties", [])
    props.extend({"name": key, "value": value} for key, value in {
        "parallax:source:commit": commit,
        "parallax:source:ref": f"refs/tags/{tag}",
        "parallax:release:target": target,
        "parallax:cargo:package-version": package_version,
        "parallax:sbom:coverage": COVERAGE,
    }.items())
    require(bom.get("components"), "Empty dependency SBOM")
    for item in bom["components"]:
        if item.get("name") in NATIVE_CRATES:
            item.setdefault("properties", []).append({
                "name": "parallax:native:source-scope",
                "value": "Bundled native source and assembly identified by this crate checksum",
            })
    require("path+file://" not in json.dumps(bom), "Local source path remains in the SBOM")
    return bom

def native_inventory(root, paths, target, sboms):
    linked = {}
    for binary, path in paths.items():
        if target.endswith("apple-darwin"):
            lines = command(["otool", "-L", str(path)], root).splitlines()[1:]
            libraries = sorted({line.strip().split(" ", 1)[0] for line in lines if line.strip()})
        else:
            dynamic = command(["readelf", "--dynamic", str(path)], root)
            libraries = sorted(set(re.findall(r"Shared library: \[([^\]]+)\]", dynamic)))
        require(libraries, f"No external-library inventory for {binary}")
        linked[binary] = libraries
    bundles = {}
    for bom in sboms.values():
        for item in bom["components"]:
            if item.get("name") in NATIVE_CRATES:
                hashes = {h["alg"]: h["content"] for h in item.get("hashes", [])}
                require(re.fullmatch(r"[0-9a-f]{64}", hashes.get("SHA-256", "")) is not None,
                        "Native source bundle lacks a crate checksum")
                entry = {
                    "crate": item["name"], "version": item["version"],
                    "crate_sha256": hashes["SHA-256"],
                    "scope": "Bundled source including native C/assembly; not a separate upstream audit",
                }
                require(item["name"] not in bundles or bundles[item["name"]] == entry,
                        "Native source versions/checksums disagree between binary SBOMs")
                bundles[item["name"]] = entry
    require(set(bundles) == NATIVE_CRATES, "Expected native source bundles are missing")
    return {
        "schema": 1, "target": target, "external_libraries": linked,
        "bundled_sources": sorted(bundles.values(), key=lambda item: item["crate"]),
        "coverage": COVERAGE,
    }

def assemble(root, out, tag, target, commit, compiler, sboms, native, epoch):
    """Package final, already stripped binaries and bound SBOMs."""
    name = prefix(tag, target)
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "Invalid source commit")
    for binary in BINARIES:
        require((out / binary).is_file() and not (out / binary).is_symlink(),
                f"Missing regular binary: {binary}")
        bom = sboms[binary]
        hashes = bom["metadata"]["component"]["hashes"]
        require(hashes == [{"alg": "SHA-256", "content": digest(out / binary)}],
                "SBOM does not match final binary")
        write_json(out / f"{name}.{binary}.cdx.json", bom)
    write_json(out / f"{name}.native.json", native)
    tar_path = out / f"{name}.tar.gz"
    packaged = list(BINARIES) + [f"{name}.{b}.cdx.json" for b in BINARIES] + [f"{name}.native.json"]
    with tempfile.TemporaryDirectory(prefix="parallax-package-") as temporary:
        stage = Path(temporary) / name
        stage.mkdir()
        for item in packaged:
            shutil.copyfile(out / item, stage / item)
        for document in ("README.md", "LICENSE", "NOTICE"):
            source = root / document
            require(source.is_file() and not source.is_symlink(), f"Missing {document}")
            shutil.copyfile(source, stage / document)
        def normalize(info):
            require(info.isfile() or info.isdir(), "Non-regular archive entry")
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            info.mode = 0o755 if info.isdir() or Path(info.name).name in BINARIES else 0o644
            return info
        with tar_path.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as zipped:
                with tarfile.open(mode="w", fileobj=zipped, format=tarfile.PAX_FORMAT) as archive:
                    archive.add(stage, arcname=name, filter=normalize)
    checksum = out / f"{name}.tar.gz.sha256"
    checksum.write_text(f"{digest(tar_path)}  {tar_path.name}\n")
    files = BINARIES + (tar_path.name, checksum.name, f"{name}.native.json") + tuple(
        f"{name}.{binary}.cdx.json" for binary in BINARIES
    )
    manifest = {
        "schema": 1, "tag": tag, "target": target, "source_commit": commit,
        "source_ref": f"refs/tags/{tag}", "compiler": compiler,
        "cargo_lock_sha256": digest(root / "Cargo.lock"),
        "sbom_tool": "cargo-cyclonedx 0.5.9",
        "coverage": COVERAGE,
        "files": {item: {"sha256": digest(out / item), "size": (out / item).stat().st_size}
                  for item in sorted(files)},
    }
    write_json(out / f"{name}.manifest.json", manifest)
    return manifest

def package(root, out, tag, target, commit, cyclonedx):
    prefix(tag, target)
    require(command(["git", "rev-parse", "HEAD"], root) == commit,
            "Checkout does not match the selected source commit")
    compiler = command(["rustc", "-vV"], root)
    require(f"host: {target}" in compiler.splitlines(), "Release target must use a native builder")
    require(command(cyclonedx + ["--version"], root) == "cargo-cyclonedx-cyclonedx 0.5.9",
            "Expected cargo-cyclonedx 0.5.9")
    lock_before = digest(root / "Cargo.lock")
    # A release-only build does not populate Cargo's cache with dev-only and
    # other-target packages that cargo metadata still resolves. Fetch the whole
    # locked graph before disabling network access for the SBOM generator.
    command(["cargo", "fetch", "--locked"], root)
    require(digest(root / "Cargo.lock") == lock_before, "Locked prefetch changed Cargo.lock")
    epoch = int(command(["git", "show", "-s", "--format=%ct", commit], root))
    env = {**os.environ, "CARGO_NET_OFFLINE": "true", "SOURCE_DATE_EPOCH": str(epoch)}
    # 0.5.9 has no --locked flag. Offline operation plus the before/after
    # assertion makes a changed resolution fatal instead of silently shipping it.
    command(cyclonedx + ["--format", "json", "--spec-version", "1.5", "--describe",
                         "binaries", "--target", target, "--target-in-filename"], root, env)
    require(digest(root / "Cargo.lock") == lock_before, "SBOM generation changed Cargo.lock")
    out.mkdir(parents=True, exist_ok=False)
    paths, sboms = {}, {}
    package_version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
    for binary in BINARIES:
        source = root / "target" / target / "release" / binary
        require(source.is_file() and not source.is_symlink(), f"Missing native build: {source}")
        paths[binary] = out / binary
        shutil.copyfile(source, paths[binary])
        command(["strip", str(paths[binary])], root)
        paths[binary].chmod(0o755)
        bom = read_json(root / f"{binary}_bin_{target}.cdx.json")
        sboms[binary] = bind_sbom(bom, binary, digest(paths[binary]), tag, target,
                                 commit, package_version)
    native = native_inventory(root, paths, target, sboms)
    return assemble(root, out, tag, target, commit, compiler, sboms, native, epoch)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cyclonedx-bin", type=Path,
                        help="Optional explicitly installed cargo-cyclonedx executable")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    tool = ([str(args.cyclonedx_bin.resolve()), "cyclonedx"] if args.cyclonedx_bin
            else ["cargo", "cyclonedx"])
    try:
        package(root, args.output.resolve(), args.tag, args.target, args.commit, tool)
    except subprocess.CalledProcessError as error:
        # capture_output preserves diagnostics, but the exception's default
        # traceback omits them. Keep the actual metadata/linker failure visible.
        print(f"Packaging subprocess failed: {error}", file=sys.stderr)
        for output in (error.stdout, error.stderr):
            if output:
                print(output[-32768:], file=sys.stderr)
        raise SystemExit(error.returncode if error.returncode > 0 else 1) from error
    print(f"Packaged {args.tag} for {args.target}: {args.output}")

if __name__ == "__main__":
    main()
