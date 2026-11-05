#!/usr/bin/env python3
"""Fail-closed dependency assurance for every ParallaX Cargo workspace (Python 3.11+).

No exemption, publisher trust, wildcard audit, or missing-audit baseline can make
the strict check pass. Audit debt is reported before returning a nonzero status.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
WORKSPACES = {
    "main": ("Cargo.toml", "supply-chain", "parallax", "safe-to-deploy"),
    "fuzz": ("fuzz/Cargo.toml", "fuzz/supply-chain", "parallax-fuzz", "safe-to-run"),
    "gfw-lab": ("ci/gfw-lab/Cargo.toml", "ci/gfw-lab/supply-chain", "gfw-lab", "safe-to-run"),
    "concurrency": ("verification/concurrency/Cargo.toml", "verification/concurrency/supply-chain",
                    "parallax-concurrency", "safe-to-run"),
}
STD_ONLY = "verification/sanitizers/Cargo.toml"
IMPORTS = {
    "google": "https://raw.githubusercontent.com/google/supply-chain/8cec794c38751495cf7a6c083220c207af1303d6/audits.toml",
    "mozilla": "https://raw.githubusercontent.com/mozilla/supply-chain/4716047f88d72d0685224af330bf21d0c2435b69/audits.toml",
}
CRITERIA = {"safe-to-run", "safe-to-deploy"}
IMPORT_LOCK_SHA256 = {
    "main": "63c3e4a4d49177ff92a6ae07c36cb53b02212019a7d3372cefc3064ba6306c9e",
    "fuzz": "bc64165d98ecc6af0662d41b2cf09e08d7e29b163cdf43a634ffd1c00a48a905",
    "gfw-lab": "3276d14fe647b44bfaeb31716a4891cd574f00bd7ec649c6c90b1e90ccb8765b",
    "concurrency": "5485dd125f401af30f0e4c9961c27262f3f1da02662a037874bfab120a03f18a",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_toml(path):
    require(path.is_file() and not path.is_symlink(), f"Missing regular file: {path}")
    return tomllib.loads(path.read_text())


def no_blanket_trust(value, path=""):
    if isinstance(value, dict):
        for key, child in value.items():
            require(key not in {"trusted", "wildcard-audits", "publisher"} or not child,
                    f"Publisher/wildcard trust is prohibited: {path}/{key}")
            no_blanket_trust(child, f"{path}/{key}")
    elif isinstance(value, list):
        for child in value:
            no_blanket_trust(child, path)


def validate_config(config, workspace):
    _, _, package, criterion = WORKSPACES[workspace]
    require(set(config) <= {"cargo-vet", "imports", "policy", "exemptions"},
            f"{workspace}: unexpected policy fields")
    require(config.get("cargo-vet") == {"version": "0.10"}, "Unexpected cargo-vet store version")
    require(not config.get("exemptions"), f"{workspace}: exemptions are prohibited; audit missing source")
    expected = {package: {"audit-as-crates-io": False, "criteria": criterion, "dev-criteria": "safe-to-run"}}
    if workspace == "fuzz":
        expected["parallax"] = {"audit-as-crates-io": False}
    require(config.get("policy") == expected, f"{workspace}: changed audit criteria or first-party policy")
    imports = config.get("imports", {})
    expected_names = {"google"} if workspace == "main" else {"google", "mozilla"}
    require(set(imports) == expected_names, f"{workspace}: changed import trust set")
    for name, settings in imports.items():
        require(settings.get("url") == IMPORTS[name], f"{workspace}: import is not the reviewed immutable snapshot")
        require(set(settings) <= {"url", "exclude"}, f"{workspace}: criteria remapping is prohibited")
        require(settings.get("exclude", []) in ([], ["unicode-xid"]), "Unexpected import exclusion")


def validate_std_only(manifest, lock):
    require(manifest.get("package", {}).get("name") == "parallax-sanitizer-canaries",
            "Unexpected std-only package")
    require(manifest["package"].get("publish") is False, "Sanitizer canaries must be unpublished")
    def no_dependencies(value):
        if isinstance(value, dict):
            for key, child in value.items():
                require(key not in {"dependencies", "dev-dependencies", "build-dependencies"} or not child,
                        "Std-only sanitizer workspace acquired dependencies")
                no_dependencies(child)
    no_dependencies(manifest)
    packages = lock.get("package", [])
    require(len(packages) == 1, "Std-only lock acquired packages")
    require(packages[0] == {"name": "parallax-sanitizer-canaries", "version": manifest["package"]["version"]},
            "Std-only lock has third-party or path dependencies")


def policy(root=ROOT, base=None):
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--",
         "Cargo.toml", "**/Cargo.toml"], cwd=root, text=True, capture_output=True, check=True,
    )
    manifests = set(filter(None, result.stdout.split("\0")))
    expected = {entry[0] for entry in WORKSPACES.values()} | {STD_ONLY}
    require(manifests == expected, f"Uncovered/missing Cargo manifests: {sorted(manifests ^ expected)}")
    protected = []
    for workspace, (manifest, store, package, _) in WORKSPACES.items():
        manifest_path = root / manifest
        data = read_toml(manifest_path)
        require(data["package"]["name"] == package, f"{workspace}: package identity changed")
        lock_path = manifest_path.with_name("Cargo.lock")
        lock = read_toml(lock_path)
        for dependency in lock["package"]:
            source = dependency.get("source")
            if source:
                require(source == "registry+https://github.com/rust-lang/crates.io-index",
                        f"{workspace}: unreviewed registry/git dependency")
                require(re.fullmatch(r"[0-9a-f]{64}", dependency.get("checksum", "")),
                        f"{workspace}: missing source checksum")
            else:
                require(dependency["name"] in {package, "parallax"}, f"{workspace}: unreviewed first-party dependency")
        config_path = root / store / "config.toml"
        validate_config(read_toml(config_path), workspace)
        for filename in ("audits.toml", "imports.lock"):
            path = root / store / filename
            document = read_toml(path)
            no_blanket_trust(document)
            if filename == "imports.lock":
                require(sha(path) == IMPORT_LOCK_SHA256[workspace],
                        f"{workspace}: imported audit snapshot bytes changed")
            if filename == "audits.toml":
                require(not document.get("criteria"), "Local criteria overrides are prohibited")
                for name, audits in document.get("audits", {}).items():
                    for audit in audits:
                        criteria = audit.get("criteria", [])
                        criteria = [criteria] if isinstance(criteria, str) else criteria
                        require(criteria and set(criteria) <= CRITERIA, f"Unknown audit criteria: {name}")
                        require(audit.get("who") and audit.get("notes"), f"Audit lacks attribution/evidence: {name}")
            protected.append(path)
        protected.extend([manifest_path, lock_path, config_path])
    manifest_path = root / STD_ONLY
    validate_std_only(read_toml(manifest_path), read_toml(manifest_path.with_name("Cargo.lock")))
    protected.extend([manifest_path, manifest_path.with_name("Cargo.lock")])
    if base:
        require(re.fullmatch(r"[0-9a-f]{40}", base), "Base must be an exact commit SHA")
        subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"], cwd=root, check=True)
        # A same-PR exemption/trust addition cannot be hidden by replacing a debt
        # ledger. The current zero-exemption policy above is unconditional.
        for workspace, (_, store, _, _) in WORKSPACES.items():
            result = subprocess.run(["git", "show", f"{base}:{store}/config.toml"],
                                    cwd=root, capture_output=True, text=True)
            if result.returncode == 0:
                previous = tomllib.loads(result.stdout)
                require(not previous.get("exemptions"), "Base contains exemptions; explicit policy migration required")
                require(previous.get("imports") == read_toml(root / store / "config.toml").get("imports"),
                        "Import trust changes require separate security policy review")
    return protected


def check(root, protected, executable, report_path):
    tool = [str(executable.resolve()), "vet"] if executable else ["cargo", "vet"]
    environment = {**os.environ, "CARGO": "cargo"}
    version = subprocess.run(tool + ["--version"], cwd=root, env=environment,
                             text=True, capture_output=True, check=True).stdout.strip()
    require(version == "cargo-vet 0.10.3", "Install cargo-vet 0.10.3 with --locked")
    before = {str(path.relative_to(root)): sha(path) for path in protected}
    report = {
        "schema": 1, "tool": version, "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "policy": "Zero exemptions. Missing audits fail the check; inventory never grants criteria.",
        "std_only": STD_ONLY, "workspaces": {},
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    failed = False
    for workspace, (manifest, store, _, criterion) in WORKSPACES.items():
        entry = {"manifest": manifest, "required": criterion, "cargo_lock_sha256": sha((root / manifest).with_name("Cargo.lock"))}
        report["workspaces"][workspace] = entry
        # Fetch crates with Cargo's lock enforced, then forbid ALL network while
        # vet resolves the committed audit snapshot. Neither command builds code.
        fetch = subprocess.run(["cargo", "fetch", "--locked", "--manifest-path", manifest],
                               cwd=root, env=environment, text=True, capture_output=True)
        if fetch.returncode:
            entry.update({"status": "fetch-error", "stderr": fetch.stderr})
            failed = True
        else:
            vet = subprocess.run(tool + [
                "--manifest-path", manifest, "--store-path", store, "--locked", "--frozen",
                "--no-minimize-exemptions", "--no-registry-suggestions", "--output-format", "json",
            ], cwd=root, env=environment, text=True, capture_output=True)
            try:
                result = json.loads(vet.stdout)
            except json.JSONDecodeError:
                result = {"error": "Invalid or empty cargo-vet JSON", "stdout": vet.stdout}
            entry.update({"exit_code": vet.returncode, "result": result, "stderr": vet.stderr})
            missing = result.get("failures", [])
            entry["missing_audit_count"] = len(missing)
            entry["status"] = "pass" if vet.returncode == 0 and result.get("conclusion") == "success" else "fail"
            failed |= entry["status"] != "pass"
            print(f"{workspace}: {entry['status']}; {len(missing)} crate versions lack required audits", flush=True)
        # Preserve partial evidence even if a later workspace/tool fails.
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    after = {str(path.relative_to(root)): sha(path) for path in protected}
    require(after == before, "Dependency check mutated a manifest, lockfile, or audit store")
    report["passed"] = not failed
    report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("policy", "check"))
    parser.add_argument("--base")
    parser.add_argument("--vet-bin", type=Path)
    parser.add_argument("--report", type=Path, default=Path("target/security/dependency-report.json"))
    args = parser.parse_args()
    try:
        protected = policy(ROOT, args.base)
        if args.command == "policy":
            print("Dependency policy valid: four workspaces under audit policy, one verified std-only workspace, zero exemptions.")
            return 0
        return check(ROOT, protected, args.vet_bin, args.report.resolve())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Dependency assurance failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
