#!/usr/bin/env python3
"""Check all requested categories without turning boundaries into security PASS."""
from __future__ import annotations

import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "verification/security_catalog.json"


def module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


protocol = module("protocol_contracts", Path(__file__).with_name("protocol_contracts.py"))
require = protocol.require
GROUP_NAMES = {
    "cryptography": """Known Answer Testing (KAT)
Cryptographic Algorithm Validation
Cryptographic Module Validation
Encryption Correctness Testing
Authenticated Encryption Verification
Message Authentication Code Verification
Digital Signature Verification Testing
Cryptographic Key Generation Testing
Key Derivation Function Testing (KDF)
Key Management Testing
Random Number Generator Testing
Initialization Vector / Nonce Reuse Testing
Cryptographic Parameter Validation
Cryptographic Error Handling Testing
Side-channel Analysis
Timing Attack Testing
Constant-time Implementation Verification""".splitlines(),
    "protocol": """Replay Attack Testing
Man-in-the-Middle Attack Testing (MITM)
Downgrade Attack Testing
Forward Secrecy Verification
Mutual Authentication Verification
Key Confirmation Testing
Authentication and Key Exchange (AKE) Security Analysis
Key Compromise Impersonation (KCI) Analysis
Session Key Independence Verification
Protocol State Machine Testing
Protocol Version Negotiation Testing
Message Integrity Verification
Certificate Chain Validation Testing
Certificate Revocation Checking
Early Data / 0-RTT Replay Analysis
Packet Reordering Testing
Duplicate Packet Handling Testing
Connection Migration Security Testing
Anti-Amplification Verification
Denial-of-Service Resistance Testing""".splitlines(),
    "privacy": """Traffic Analysis
Traffic Fingerprinting
Website Fingerprinting
Correlation Attack Analysis
Metadata Leakage Analysis
DNS Leak Testing
IP Leak Testing
Protocol Identification Testing
Active Probing Resistance Testing
Traffic Classification Evaluation""".splitlines(),
}
MEASUREMENT = "handshake::server::tests::rejection_path_timing_is_constant_dudect"
MODES = {"automated", "symbolic", "statistical", "policy_boundary", "external_validation"}


def validate(document: dict, root: Path = ROOT) -> list[dict]:
    require(document.get("schema_version") == 1 and bool(document.get("scope")), "invalid catalog schema/scope")
    items = document.get("items", [])
    expected = {name: group for group, names in GROUP_NAMES.items() for name in names}
    require(len(items) == 47 and {item.get("name") for item in items} == set(expected),
            "catalog must contain exactly all 47 requested categories")
    ids = [item.get("id") for item in items]
    require(all(isinstance(key, str) and re.fullmatch(r"[a-z][a-z0-9-]*", key) for key in ids)
            and len(set(ids)) == len(ids), "invalid/duplicate category IDs")
    contracts = {entry["id"]: entry for entry in protocol.validate_ledger(
        json.loads((root / "verification/protocol_contracts.json").read_text()), root)}
    cache = {}
    resolved = []
    for item in items:
        label = item["id"]
        require(item.get("group") == expected[item["name"]] and item.get("mode") in MODES,
                f"{label}: incorrect category group/mode")
        require(isinstance(item.get("claim"), str) and bool(item["claim"]), f"{label}: missing scoped claim")
        for field in ("protocol_contracts", "analyses", "limitations", "external_requirements"):
            values = item.get(field)
            require(isinstance(values, list) and all(isinstance(value, str) and value for value in values),
                    f"{label}: invalid {field}")
        require(bool(item["limitations"]), f"{label}: missing limitations")
        if item["mode"] in ("external_validation", "policy_boundary"):
            require(bool(item["external_requirements"]), f"{label}: missing external/policy boundary")
        tests = list(item.get("tests", []))
        for key in item["protocol_contracts"]:
            require(key in contracts, f"{label}: unknown protocol contract {key}")
            tests.extend(contracts[key]["tests"])
        unique = {}
        for test in tests:
            suite, file, name = test.get("suite"), test.get("file", ""), test.get("name")
            require(isinstance(suite, str) and re.fullmatch(r"[a-z][a-z0-9_]*", suite), f"{label}: bad suite")
            require((suite == "protocol_library" and file.startswith("src/")) or file == f"tests/{suite}.rs",
                    f"{label}: suite/file mismatch")
            if file not in cache:
                path = protocol.relative_file(root, file)
                parts = Path(file).with_suffix("").parts
                prefix = "::".join(parts[1:-1] if parts[-1] in ("mod", "lib") else parts[1:]) if parts[0] == "src" else ""
                cache[file] = protocol.rust_index(path.read_text(), prefix)[2]
            require(name in cache[file], f"{label}: missing exact test {name} in {file}")
            require(name != MEASUREMENT or item["mode"] == "statistical", f"{label}: feature timing is statistical")
            unique[(suite, name)] = test
        for file in item["analyses"]:
            protocol.relative_file(root, file)
        require(bool(unique) or bool(item["analyses"]), f"{label}: no test/analysis reference")
        require(item["mode"] != "automated" or bool(unique), f"{label}: automated category has no tests")
        resolved.append({**item, "tests": list(unique.values())})
    for name in ("Cryptographic Algorithm Validation", "Cryptographic Module Validation"):
        require(next(item for item in items if item["name"] == name)["mode"] == "external_validation",
                "formal algorithm/module certification cannot be supplied by a test run")
    return resolved


def provenance(report: dict, commit: str) -> None:
    require(report.get("source_commit") == commit and report.get("working_tree_dirty") is False,
            "supplemental evidence is stale or from dirty source")


def compromise_evidence(path: Path, commit: str) -> None:
    verifier = module("compromise", ROOT / "verification/proverif/compromise.py")
    report = json.loads(path.read_text())
    provenance(report, commit)
    require(report.get("status") == "passed" and report.get("source_regions") == verifier.identity.check_source_contracts(),
            "incomplete or mismatched compromise source mapping")
    base = verifier.identity.MODEL.read_text()
    require(report.get("base_model_sha256") == verifier.identity.sha256(base.encode()), "stale base model")
    cases = report.get("cases", [])
    require([case.get("case") for case in cases] == list(verifier.CASE_NAMES), "missing/duplicate compromise cases")
    for row, (name, derived) in zip(cases, verifier.variants(base)):
        saved = path.parent / f"{name}.pv"
        require(saved.read_text() == derived and row.get("model_sha256") == verifier.identity.sha256(derived.encode()),
                f"{name}: saved model disagrees")
        properties = verifier.parse_results((path.parent / f"{name}.log").read_text())
        verifier.require_results(name, properties)
        require(row.get("properties") == properties, f"{name}: query log disagrees")


def timing_evidence(path: Path, commit: str) -> None:
    timing = module("timing", ROOT / "scripts/security/timing.py")
    report = json.loads(path.read_text())
    provenance(report, commit)
    require(report.get("kind") == "reject_path_timing" and report.get("status") == "no_detected_regression",
            "timing experiment is incomplete/failed")
    require((path.parent / "source.log").read_text().strip() == commit and
            not (path.parent / "source-status.log").read_text().strip() and bool(report.get("toolchain")) and
            (path.parent / "toolchain.log").read_text().strip() == report["toolchain"],
            "timing provenance logs disagree")
    require(report.get("runner_sha256") == timing.hashlib.sha256(Path(timing.__file__).read_bytes()).hexdigest(),
            "stale timing runner")
    selected = timing.bounds(report.get("bounds", {}))
    require(report.get("bounds") == selected, "incomplete timing bounds")
    commands = report.get("commands", [])
    expected = [*timing.CONTROLS, timing.MEASUREMENT]
    require([command.get("selected") for command in commands] == expected, "missing timing controls/measurement")
    for index, command in enumerate(commands):
        require(command.get("log") == f"{index}.log" and command.get("argv") ==
                ["cargo", "test", "--locked", "--features", "dudect", "--lib", expected[index],
                 "--", "--exact", "--nocapture", "--test-threads=1"], "wrong timing command")
        output = (path.parent / f"{index}.log").read_text()
        timing.assurance.checked_summary(output, 1)
        require(timing.assurance.selected_tests((path.parent / f"{index}-list.log").read_text()) == [expected[index]],
                "wrong timing selection")
    rows = timing.measurements(output, int(selected["DUDECT_SAMPLES"]))
    require(report.get("measurements") == rows, "timing measurement log disagrees")


def doctest_evidence(path: Path) -> None:
    report = json.loads(path.read_text())
    entry = report.get("tests", {}).get("production_api", {})
    names = entry.get("selected", [])
    require(isinstance(names, list) and len(names) >= 4 and all(isinstance(name, str) for name in names)
            and len(set(names)) == len(names) and type(entry.get("passed")) is int and entry["passed"] == len(names)
            and type(entry.get("failed")) is int and entry["failed"] == 0
            and type(entry.get("ignored")) is int and entry["ignored"] == 0,
            "production positive/negative API doctests did not fully execute")
    for symbol in ("crypto::session::SessionKeys", "crypto::pq::MlKemEncapsulation"):
        require(sum(f" - {symbol} (line " in name for name in names) == 2, f"missing API controls for {symbol}")
    timing = module("timing", ROOT / "scripts/security/timing.py")
    require(timing.assurance.selected_tests((path.parent / "production_api-list.log").read_text()) == names,
            "production API listing disagrees")
    timing.assurance.checked_summary((path.parent / "production_api.log").read_text(), len(names))
    commands = [command for command in report.get("commands", []) if command.get("log") == "production_api.log"]
    require(len(commands) == 1 and commands[0].get("argv") ==
            ["cargo", "test", "--locked", "--doc", "--", "--test-threads=1", "--nocapture"], "wrong API doctest command")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--compromise-report", type=Path)
    parser.add_argument("--timing-report", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.check and args.evidence is None:
        parser.error("select --check or --evidence")
    if args.evidence is None and (args.compromise_report or args.timing_report):
        parser.error("supplemental reports require matching --evidence")
    try:
        items = validate(json.loads(CATALOG.read_text()))
        report = {"schema_version": 1, "kind": "security_category_inventory", "categories": [],
                  "scope": "Scoped checks, analyses and explicit unfulfilled boundaries; no aggregate security PASS."}
        if args.evidence:
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            require(not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip(),
                    "working tree changed after recorded execution")
            ordinary = [{"tests": [test for test in item["tests"] if test["name"] != MEASUREMENT]} for item in items]
            protocol.validate_evidence(ordinary, args.evidence, commit)
            doctest_evidence(args.evidence)
            if args.compromise_report:
                compromise_evidence(args.compromise_report, commit)
            if args.timing_report:
                timing_evidence(args.timing_report, commit)
            report["source_commit"] = commit
        for item in items:
            state = "references_only"
            if args.evidence:
                state = {"automated": "bounded_tests_executed", "policy_boundary": "policy_boundary_remains",
                         "external_validation": "external_validation_required", "symbolic": "symbolic_report_not_supplied",
                         "statistical": "experiment_or_field_data_required"}[item["mode"]]
                if item["mode"] == "symbolic" and args.compromise_report and any(
                        path.startswith("verification/proverif/") for path in item["analyses"]):
                    state = "identity_rekey_symbolic_slice_checked"
                if any(test["name"] == MEASUREMENT for test in item["tests"]) and args.timing_report:
                    state = "bounded_timing_report_checked"
            report["categories"].append({"id": item["id"], "name": item["name"], "mode": item["mode"],
                                         "evidence_state": state, "limitations": item["limitations"],
                                         "external_requirements": item["external_requirements"]})
        report["counts"] = dict(Counter(row["evidence_state"] for row in report["categories"]))
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"47 security categories checked: {json.dumps(report['counts'], sort_keys=True)}")
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"security catalog verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
