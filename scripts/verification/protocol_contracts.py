#!/usr/bin/env python3
"""Check protocol references, optionally require matching executed-test evidence.

Reference checks do not execute Rust or prove a claim. Evidence is the existing
assurance runner's report and retained logs, tied to the current clean commit.
These are runner records, not cryptographically attested third-party results.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "verification/protocol_contracts.json"
REQUIRED_IDS = frozenset("""
socks-addresses initial-payload tls-trust tls-server-hello
tls-retry carrier-auth degenerate-x25519 replay-gates tls-drain tls-finished
pq-rekey identity-binding identity-reassembly command-connect command-key-exchange
command-chunks command-mux command-udp records-aead records-nonce-budget
records-batch-failure records-padding mux-lifecycle mux-isolation egress-policy
quic-packet quic-packet-crypto quic-frame quic-replay quic-recovery
quic-flow-control quic-key-update-close http2-carrier http3-framing http3-settings
qpack-fields udp-exporter udp-probe zero-rtt camouflage-splice
""".split())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def relative_file(root: Path, name: str) -> Path:
    require(isinstance(name, str) and bool(name), "empty file reference")
    path = (root / name).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file(),
            f"invalid/missing file reference: {name}")
    return path


def rust_code(text: str) -> str:
    """Mask comments and strings before tracking Rust module brace scopes."""
    out = list(text)
    pos = 0
    raw_string = re.compile(r'r(#{0,255})"')
    character = re.compile(r"'(?:\\u\{[0-9a-fA-F_]+\}|\\x[0-9a-fA-F]{2}|\\.|[^'\\])'")
    while pos < len(text):
        start = pos
        if text.startswith("//", pos):
            end = text.find("\n", pos)
            pos = len(text) if end < 0 else end
        elif text.startswith("/*", pos):
            depth = 1
            pos += 2
            while pos < len(text) and depth:
                if text.startswith("/*", pos):
                    depth += 1
                    pos += 2
                elif text.startswith("*/", pos):
                    depth -= 1
                    pos += 2
                else:
                    pos += 1
        elif match := raw_string.match(text, pos):
            terminator = '"' + match[1]
            end = text.find(terminator, pos + len(match[0]))
            pos = len(text) if end < 0 else end + len(terminator)
        elif text[pos] == '"':
            pos += 1
            while pos < len(text):
                if text[pos] == "\\":
                    pos += 2
                elif text[pos] == '"':
                    pos += 1
                    break
                else:
                    pos += 1
        elif match := character.match(text, pos):
            pos += len(match[0])
        else:
            pos += 1
            continue
        out[start:pos] = ["\n" if char == "\n" else " " for char in text[start:pos]]
    return "".join(out)


def rust_index(text: str, prefix: str) -> tuple[set[str], set[str], set[str]]:
    code = rust_code(text)
    attributed = re.compile(
        r"(?P<attrs>(?:#\[[^\]]*\]\s*)+)(?:pub(?:\([^)]*\))?\s+)?"
        r"(?:async\s+)?fn\s+(?P<name>[A-Za-z_]\w*)\s*(?:<|\()")
    tests_at = {match.start("name") for match in attributed.finditer(code)
                if re.search(r"#\[\s*(?:tokio::)?test\s*(?:\(|\])", match["attrs"])}
    tokens = re.compile(r"\bmod\s+(?P<module>[A-Za-z_]\w*)\s*\{|"
                        r"\bfn\s+(?P<function>[A-Za-z_]\w*)\s*(?=[<(])|"
                        r"(?P<open>\{)|(?P<close>\})")
    depth = 0
    modules: list[tuple[str, int]] = []
    functions, tests = set(), set()
    for match in tokens.finditer(code):
        if name := match["module"]:
            depth += 1
            modules.append((name, depth))
        elif name := match["function"]:
            functions.add(name)
            if match.start("function") in tests_at:
                tests.add("::".join(filter(None, [prefix, *(name for name, _ in modules), name])))
        elif match["open"]:
            depth += 1
        else:
            if modules and modules[-1][1] == depth:
                modules.pop()
            depth -= 1
    constants = set(re.findall(r"\bconst\s+([A-Za-z_]\w*)\s*:", code))
    return functions, constants, tests


def validate_ledger(document: dict, root: Path = ROOT) -> list[dict]:
    require(document.get("schema_version") == 1 and bool(document.get("scope")),
            "invalid protocol ledger schema/scope")
    contracts = document.get("contracts")
    require(isinstance(contracts, list) and contracts, "empty protocol contracts")
    ids = [entry.get("id") for entry in contracts]
    require(all(isinstance(name, str) and name for name in ids) and len(set(ids)) == len(ids),
            "empty/duplicate contract IDs")
    require(REQUIRED_IDS <= set(ids), f"missing required contracts: {sorted(REQUIRED_IDS - set(ids))}")
    headings = (root / "SPEC.md").read_text().splitlines()
    cache: dict[str, tuple[set[str], set[str], set[str]]] = {}

    def index(name: str) -> tuple[set[str], set[str], set[str]]:
        if name not in cache:
            path = relative_file(root, name)
            parts = Path(name).with_suffix("").parts
            prefix = "::".join(parts[1:-1] if parts[-1] in ("mod", "lib") else parts[1:]) if parts[0] == "src" else ""
            cache[name] = rust_index(path.read_text(), prefix)
        return cache[name]

    for contract in contracts:
        label = contract["id"]
        require(bool(contract.get("claim")) and bool(contract.get("bounds")), f"{label}: missing claim/bounds")
        conditions = contract.get("external_conditions")
        require(isinstance(conditions, list) and all(isinstance(value, str) and value for value in conditions),
                f"{label}: invalid external conditions")
        anchor = contract.get("spec")
        require(isinstance(anchor, str) and anchor.startswith("#") and headings.count(anchor) == 1,
                f"{label}: specification heading is missing or ambiguous")
        sources, tests = contract.get("sources"), contract.get("tests")
        require(isinstance(sources, list) and sources and isinstance(tests, list) and tests,
                f"{label}: empty source/test references")
        for source in sources:
            name = source.get("file", "")
            require(name.startswith("src/"), f"{label}: source reference is not production Rust")
            functions, constants, _ = index(name)
            symbols = functions if source.get("kind") == "fn" else constants if source.get("kind") == "const" else set()
            require(source.get("symbol") in symbols, f"{label}: missing production symbol {source}")
        for test in tests:
            suite, name, file = test.get("suite"), test.get("name"), test.get("file", "")
            require(isinstance(suite, str) and re.fullmatch(r"[a-z][a-z0-9_]*", suite), f"{label}: invalid suite")
            require((suite == "protocol_library" and file.startswith("src/")) or
                    (file == f"tests/{suite}.rs"), f"{label}: test suite/file mismatch")
            require(name in index(file)[2], f"{label}: missing exact Rust test selector {name} in {file}")
    return contracts


def validate_evidence(contracts: list[dict], path: Path, commit: str) -> None:
    report = json.loads(path.read_text())
    require(report.get("schema_version") == 1 and report.get("kind") == "protocol" and
            report.get("status") == "passed", "report is not a completed passing protocol run")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None and report.get("source_commit") == commit,
            "execution evidence does not match the current commit")
    require(report.get("working_tree_dirty") is False, "dirty source cannot establish exact-commit evidence")
    require((path.parent / "source.log").read_text().strip() == commit and
            not (path.parent / "source-status.log").read_text().strip(), "source provenance logs disagree")
    require(bool(report.get("toolchain")) and
            (path.parent / "toolchain.log").read_text().strip() == report["toolchain"], "toolchain provenance missing/mismatched")
    bounds = report.get("bounds", {})
    try:
        raw_seed = bounds["PARALLAX_PROP_SEED"]
        seed = int(raw_seed[2:], 16) if raw_seed.startswith("0x") else int(raw_seed, 10)
        cases = int(bounds["PARALLAX_PROP_CASES"], 10)
    except (KeyError, ValueError, TypeError, AttributeError) as error:
        raise ValueError("missing/invalid property seed or case budget") from error
    require(0 <= seed < 1 << 64 and 1 <= cases <= 10_000, "property bounds outside supported range")
    commands = report.get("commands", [])
    require(isinstance(commands, list), "missing executed commands")
    required: dict[str, set[str]] = {}
    for contract in contracts:
        for test in contract["tests"]:
            required.setdefault(test["suite"], set()).add(test["name"])
    for suite, needed in required.items():
        entry = report.get("tests", {}).get(suite, {})
        selected = entry.get("selected", [])
        require(isinstance(selected, list) and selected and all(isinstance(name, str) for name in selected) and
                len(set(selected)) == len(selected), f"{suite}: empty/duplicate selected tests")
        require(needed <= set(selected), f"{suite}: unexecuted contract tests {sorted(needed - set(selected))}")
        require(type(entry.get("passed")) is int and entry["passed"] == len(selected) and
                type(entry.get("failed")) is int and entry["failed"] == 0 and
                type(entry.get("ignored")) is int and entry["ignored"] == 0, f"{suite}: incomplete/failed/ignored execution")
        chosen = [command for command in commands if command.get("log") == f"{suite}.log"]
        require(len(chosen) == 1, f"{suite}: missing/duplicate execution command")
        argv = chosen[0].get("argv", [])
        require(isinstance(argv, list) and all(isinstance(arg, str) for arg in argv) and
                argv[:2] == ["cargo", "test"] and "--locked" in argv, f"{suite}: execution was not a locked cargo test")
        require("--lib" in argv if suite == "protocol_library" else
                any(argv[index:index + 2] == ["--test", suite] for index in range(len(argv) - 1)),
                f"{suite}: command does not select the claimed test target")
        listing = (path.parent / f"{suite}-list.log").read_text()
        listed = re.findall(r"^([A-Za-z_][A-Za-z0-9_:]*): test$", listing, re.MULTILINE)
        require(listed == selected, f"{suite}: selection log disagrees with report")
        output = (path.parent / f"{suite}.log").read_text()
        summaries = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", output, re.MULTILINE)
        require(summaries == [(str(len(selected)), "0", "0")], f"{suite}: missing/mismatched runtime completion log")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate references without claiming execution")
    parser.add_argument("--evidence", type=Path, help="require the assurance report and its retained sibling logs")
    args = parser.parse_args()
    if not args.check and args.evidence is None:
        parser.error("select --check and/or --evidence")
    try:
        contracts = validate_ledger(json.loads(LEDGER.read_text()))
        if args.evidence is None:
            print(f"protocol contracts: {len(contracts)} references valid; execution evidence not supplied")
        else:
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
            require(not status.strip(), "current working tree changed after the recorded execution")
            validate_evidence(contracts, args.evidence, commit)
            print(f"protocol contracts: {len(contracts)} have passing execution evidence at {commit}")
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"protocol contract verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
