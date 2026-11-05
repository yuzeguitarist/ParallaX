#!/usr/bin/env python3
"""Verify the mapped identity/rekey slice and require detected negative controls."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = Path(__file__).resolve().parent
MODEL = DIRECTORY / "rekey_identity.pv"
CONTRACTS = DIRECTORY / "source_contracts.json"
TOOL_VERSION = "2.05"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_span(text, contract):
    """Fingerprint reviewed source regions; not a parser or refinement proof."""
    if "function" in contract:
        pattern = re.compile(
            r"^([ \t]*)(?:pub(?:\([^\n)]*\))?\s+)?(?:async\s+)?fn\s+"
            + re.escape(contract["function"])
            + r"\s*(?:\(|<)", re.MULTILINE,
        )
        matches = list(pattern.finditer(text))
        if len(matches) != 1:
            raise ValueError(f"Expected one function for {contract['id']}")
        start = matches[0]
        closing = re.compile(r"^" + re.escape(start.group(1)) + r"\}[ \t]*$", re.MULTILINE)
        end = closing.search(text, start.end())
        if end is None:
            raise ValueError(f"Missing function end for {contract['id']}")
        return text[start.start():end.end()]
    if text.count(contract["start"]) != 1:
        raise ValueError(f"Ambiguous source start for {contract['id']}")
    start = text.index(contract["start"])
    end = text.find(contract["end"], start + len(contract["start"]))
    if end < 0:
        raise ValueError(f"Missing source end for {contract['id']}")
    return text[start:end]


def check_source_contracts():
    checked = []
    for contract in json.loads(CONTRACTS.read_text())["regions"]:
        source = (ROOT / contract["path"]).resolve()
        source.relative_to(ROOT.resolve())
        if source.suffix != ".rs":
            raise ValueError("Source contracts must name Rust sources within the repository")
        text = source.read_text()
        digest = sha256(source_span(text, contract).encode())
        if digest != contract["sha256"]:
            raise ValueError(f"Source/model review required: {contract['id']} changed ({digest})")
        checked.append({"id": contract["id"], "path": contract["path"], "sha256": digest})
    if not checked:
        raise ValueError("Source contract set must not be empty")
    return checked


def replace_exact(text, old, new, count=1):
    if text.count(old) != count:
        raise ValueError(f"Negative-control anchor changed: {old!r}")
    return text.replace(old, new)


def variants(model):
    yield "baseline", model
    yield "binding_erased", replace_exact(
        model, "binding(client_request, server_response)", "identity_label", 2
    )
    identity_start = "identity_message(identity_label, e, transcript, server_static_pin,"
    yield "transcript_erased", replace_exact(
        model, identity_start,
        "identity_message(identity_label, e, identity_label, server_static_pin,", 2,
    )
    yield "epoch_erased", replace_exact(
        model, identity_start,
        "identity_message(identity_label, next_epoch(initial_epoch), transcript, server_static_pin,", 2,
    )
    suite_variant = replace_exact(
        model, "fun identity_message(",
        "fun response_core(group, kem_ciphertext): bitstring [data].\n"
        "reduc forall dh: group, ct: kem_ciphertext, s: suite;\n"
        "  response_without_suite(response(dh, ct, s)) = response_core(dh, ct).\n"
        "fun identity_message(",
    )
    yield "suite_unbound", replace_exact(
        suite_variant, "binding(client_request, server_response)",
        "binding(client_request, response_without_suite(server_response))", 2,
    )
    yield "identity_message_check_removed", replace_exact(
        model, "if verified_message = expected_message then", "if true then"
    )


def query_section(text):
    return text[text.index("event server_signed("):text.index("let client(")]


def query_property(query):
    exact = {
        "not attacker(application_secret[])": "application_secrecy",
        "not event(acceptance_reached)": "acceptance_unreachable",
    }
    if query in exact:
        return exact[query]
    context = ("identity", "pin", "transcript", "req", "resp", "e")
    for client, server, fields, key in (
        ("client_accepted", "server_signed", context, "pinned_server_full_tuple"),
        ("client_derived", "server_derived", context + ("key",), "derived_key_agreement"),
    ):
        # ProVerif preserves query-variable stems and may append numeric suffixes.
        # Match every field and require its exact renamed variable on both sides.
        left = r"\s*,\s*".join(rf"(?P<{field}>{field}(?:_[0-9]+)?)" for field in fields)
        right = r"\s*,\s*".join(rf"(?P={field})" for field in fields)
        pattern = rf"inj-event\({client}\({left}\)\)\s*==>\s*inj-event\({server}\({right}\)\)"
        if re.fullmatch(pattern, query):
            return key
    raise ValueError(f"Unexpected query shape: {query}")


def parse_results(output):
    expected = {
        "pinned_server_full_tuple", "derived_key_agreement",
        "application_secrecy", "acceptance_unreachable",
    }
    results = {}
    if output.count("Verification summary:") != 1:
        raise ValueError("Missing or ambiguous verification summary")
    summary = output.split("Verification summary:", 1)[1]
    lines = [line for line in summary.splitlines() if line.startswith("Query ")]
    if len(lines) != len(expected):
        raise ValueError(f"Expected exactly {len(expected)} results, found {len(lines)}")
    for line in lines:
        match = re.fullmatch(r"Query (.+) is (true|false)\.", line)
        if match is None:
            raise ValueError(f"Unknown or unproved result: {line}")
        key = query_property(match.group(1))
        if key in results:
            raise ValueError(f"Unexpected/duplicate result: {line}")
        results[key] = match.group(2) == "true"
    if set(results) != expected:
        raise ValueError("Missing required query result")
    return results


def require_results(case, results):
    # Reachable acceptance means FALSE for 'not event(acceptance_reached)'.
    if results["acceptance_unreachable"]:
        raise ValueError(f"{case}: unreachable acceptance makes security proofs vacuous")
    if case == "baseline":
        for key in ("pinned_server_full_tuple", "derived_key_agreement", "application_secrecy"):
            if not results[key]:
                raise ValueError(f"Baseline property failed: {key}")
    elif results["pinned_server_full_tuple"]:
        raise ValueError(f"{case}: removed binding/check escaped the authentication detector")
    if case in ("binding_erased", "identity_message_check_removed") and results["application_secrecy"]:
        raise ValueError(f"{case}: expected a concrete secrecy attack")


def verify_case(executable, name, model, output_directory):
    model_path = output_directory / f"{name}.pv"
    model_path.write_text(model)
    result = subprocess.run([executable, str(model_path)], capture_output=True, text=True, timeout=180)
    (output_directory / f"{name}.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise ValueError(f"{name}: verifier exited {result.returncode}; see saved log")
    properties = parse_results(result.stdout)
    require_results(name, properties)
    return {"case": name, "model_sha256": sha256(model.encode()), "properties": properties}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proverif", default="proverif", help="ProVerif 2.05 executable")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "target/proverif")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_directory = Path(tempfile.mkdtemp(prefix="run-", dir=args.output_dir))
    report = {"status": "running", "started_at_utc": datetime.now(timezone.utc).isoformat()}
    print(f"ProVerif artifacts: {output_directory}", flush=True)
    try:
        report["expected_verifier_source"] = json.loads(CONTRACTS.read_text())["verifier_source"]
        report["source_regions"] = check_source_contracts()
        resolved = shutil.which(args.proverif)
        if resolved is None:
            raise ValueError("Verifier executable cannot be located")
        executable = Path(resolved)
        version = subprocess.run(
            [str(executable), "-help"], capture_output=True, text=True, check=True, timeout=30
        ).stdout.splitlines()[0]
        if not version.startswith(f"Proverif {TOOL_VERSION}."):
            raise ValueError(f"Unexpected verifier version: {version}")
        report["verifier"] = {"version": version, "binary_sha256": sha256(executable.read_bytes())}
        model = MODEL.read_text()
        report["model_sha256"] = sha256(model.encode())
        report["cases"] = []
        for name, case_model in variants(model):
            if query_section(case_model) != query_section(model):
                raise ValueError(f"{name}: negative control modified the property declarations")
            checked = verify_case(str(executable), name, case_model, output_directory)
            report["cases"].append(checked)
            print(json.dumps(checked, sort_keys=True), flush=True)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        (output_directory / "verification.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
