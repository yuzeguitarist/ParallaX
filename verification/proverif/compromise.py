#!/usr/bin/env python3
"""Check completed-session secrecy under explicitly ordered credential disclosure.

This derives three models from the existing identity/rekey slice. Global phases
discard unfinished phase-zero roles; these are not concurrent-corruption or
computational forward-secrecy proofs. Original model checks remain independent.
"""

import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("identity_rekey_check", DIRECTORY / "run.py")
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)
CASE_NAMES = ("late_signing_disclosure", "late_session_disclosure", "early_signing_disclosure")
ROLES = "((!client(public_identity(identity_secret))) | (!server(identity_secret)))"
SEND = "out(network, seal_client_data(application_secret, key, selected, client_direction_aad))"


def variants(model):
    phased = identity.replace_exact(
        model, "query attacker(application_secret).",
        "query attacker(application_secret) phase 0.\n"
        "query attacker(application_secret) phase 1.",
    )
    phased = identity.replace_exact(
        phased, "event acceptance_reached.",
        "event acceptance_reached.\nevent disclosure_reached.",
    )
    phased = identity.replace_exact(
        phased, "query event(acceptance_reached).",
        "query event(acceptance_reached).\nquery event(disclosure_reached).",
    )
    late = identity.replace_exact(
        phased, ROLES,
        "((!client(public_identity(identity_secret))) | (!server(identity_secret)) |\n"
        "   (phase 1; out(network, identity_secret); event disclosure_reached))",
    )
    yield CASE_NAMES[0], late
    yield CASE_NAMES[1], identity.replace_exact(
        late, SEND + ".", SEND + ";\n  phase 1; out(network, key).",
    )
    yield CASE_NAMES[2], identity.replace_exact(
        late, "out(network, public_identity(identity_secret));",
        "out(network, public_identity(identity_secret));\n  out(network, identity_secret);",
    )


def parse_results(output):
    # Keep the original exact tuple/injectivity checker. Only the two exact
    # phase-qualified secrecy lines and disclosure reachability are handled here.
    if output.count("Verification summary:") != 1:
        raise ValueError("Missing or ambiguous verification summary")
    summary = output.split("Verification summary:", 1)[1]
    lines = [line for line in summary.splitlines() if line.startswith("Query ")]
    phase = {}
    retained = []
    disclosure = None
    for line in lines:
        # ProVerif 2.05 prints phase zero as attacker and phase one as
        # attacker_p1, rather than repeating the source's `phase n` suffix.
        match = re.fullmatch(
            r"Query not attacker(_p1)?\(application_secret\[\]\) is (true|false)\.", line)
        if match:
            number = int(match[1] is not None)
            if number in phase:
                raise ValueError("Duplicate phase-specific secrecy result")
            phase[number] = match[2] == "true"
            if number == 1:
                retained.append(line.replace("attacker_p1(", "attacker("))
        elif match := re.fullmatch(r"Query not event\(disclosure_reached\) is (true|false)\.", line):
            if disclosure is not None:
                raise ValueError("Duplicate disclosure reachability result")
            disclosure = match[1] == "true"
        else:
            retained.append(line)
    if set(phase) != {0, 1} or disclosure is None or len(lines) != 6:
        raise ValueError("Missing or unexpected compromise queries")
    checked = identity.parse_results("Verification summary:\n" + "\n".join(retained))
    checked["phase1_secrecy"] = checked.pop("application_secrecy")
    checked["phase0_secrecy"] = phase[0]
    checked["disclosure_unreachable"] = disclosure
    return checked


def require_results(case, results):
    if case not in CASE_NAMES:
        raise ValueError(f"Unknown compromise case: {case}")
    if results["acceptance_unreachable"] or results["disclosure_unreachable"]:
        raise ValueError(f"{case}: acceptance and disclosure must both be reachable")
    expected_auth = case != "early_signing_disclosure"
    expected_phase0 = case != "early_signing_disclosure"
    expected_phase1 = case == "late_signing_disclosure"
    expected = {
        "pinned_server_full_tuple": expected_auth,
        "derived_key_agreement": expected_auth,
        "phase0_secrecy": expected_phase0,
        "phase1_secrecy": expected_phase1,
    }
    for name, value in expected.items():
        if results[name] != value:
            raise ValueError(f"{case}: unexpected {name}; required {value}")


def verify_case(executable, name, model, directory):
    path = directory / f"{name}.pv"
    path.write_text(model)
    result = subprocess.run([executable, str(path)], capture_output=True, text=True, timeout=180)
    (directory / f"{name}.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise ValueError(f"{name}: verifier exited {result.returncode}; see saved log")
    properties = parse_results(result.stdout)
    require_results(name, properties)
    return {"case": name, "model_sha256": identity.sha256(model.encode()), "properties": properties}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proverif", default="proverif", help="ProVerif 2.05 executable")
    parser.add_argument("--output-dir", type=Path, default=identity.ROOT / "target/proverif/compromise")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=args.output_dir))
    report = {"status": "running", "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "completed phase-zero identity/rekey sessions; ideal cryptography",
              "runner_sha256": identity.sha256(Path(__file__).read_bytes())}
    print(f"Compromise-model artifacts: {directory}", flush=True)
    try:
        report["source_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=identity.ROOT, text=True).strip()
        report["working_tree_dirty"] = bool(subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=identity.ROOT, text=True).strip())
        report["source_regions"] = identity.check_source_contracts()
        report["expected_verifier_source"] = json.loads(identity.CONTRACTS.read_text())["verifier_source"]
        resolved = shutil.which(args.proverif)
        if resolved is None:
            raise ValueError("Verifier executable cannot be located")
        executable = Path(resolved)
        version_result = subprocess.run(
            [str(executable), "-help"], capture_output=True, text=True, check=True, timeout=30
        )
        (directory / "verifier-version.log").write_text(version_result.stdout + version_result.stderr)
        version = version_result.stdout.splitlines()[0] if version_result.stdout else ""
        if not version.startswith(f"Proverif {identity.TOOL_VERSION}."):
            raise ValueError(f"Unexpected verifier version: {version}")
        report["verifier"] = {"version": version,
                              "binary_sha256": identity.sha256(executable.read_bytes())}
        model = identity.MODEL.read_text()
        report["base_model_sha256"] = identity.sha256(model.encode())
        cases = list(variants(model))
        queries = identity.query_section(cases[0][1])
        report["cases"] = []
        for name, derived in cases:
            if identity.query_section(derived) != queries:
                raise ValueError(f"{name}: control modified the property declarations")
            checked = verify_case(str(executable), name, derived, directory)
            report["cases"].append(checked)
            print(json.dumps(checked, sort_keys=True), flush=True)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        (directory / "verification.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
