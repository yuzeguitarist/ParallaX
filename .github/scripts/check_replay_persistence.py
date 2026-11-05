#!/usr/bin/env python3
"""Finite replay-persistence syntax guards, not alias/CFG or filesystem proofs.

Compare complete reviewed AST definitions, attributes and real production owners,
plus their full source spans. Ignore positions, identifier serial numbers,
whitespace and line comments. Actual fault-injection tests cover I/O rollback/retry; Kani
separately checks the shipping digest copy/wipe helper.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from check_crypto_rules import replace_once, run
from check_mux_receipts import findings, rust_parser
from check_quic_key_phase import method

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/crypto/replay.rs"
RULES = ROOT / ".github/semgrep/replay_persistence.yml"
OBSERVE = ROOT / ".github/semgrep/replay_persistence_observe.yml"
CANONICAL = ROOT / ".github/semgrep/replay_persistence_canonical.rs"
SCOPES = {"key": ("CacheMacKey", 1), "compaction": ("compact_authenticated_journal", 1),
          "sync": ("fsync_parent_dir", 2), "derive": ("cache_mac_key", 1),
          "wipe": ("cache_mac_key_from_digest", 1)}


def walk(value):
    pending = [value]
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, dict):
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)


def name(statement):
    return statement.get("DefStmt", [{}])[0].get("name", {}).get("EN", {}).get("Id", [[None]])[0][0]


def tokens(node):
    return [part["OriginTok"] for part in walk(node) if isinstance(part, dict) and "OriginTok" in part]


def source_shape(text):
    # Reviewed scopes contain ordinary quoted strings. Preserve their exact
    # contents; remove only whitespace and // comments outside those strings.
    # Block/raw-string syntax is not normalized into the reviewed source.
    out, quoted, index = [], False, 0
    while index < len(text):
        char = text[index]
        if not quoted and text.startswith("//", index):
            index = text.find("\n", index)
            if index < 0:
                break
            continue
        if char == '"':
            quoted = not quoted
        if quoted and char == "\\" and index + 1 < len(text):
            out.append(text[index:index + 2])
            index += 2
            continue
        if quoted or not char.isspace():
            out.append(char)
        index += 1
    return "".join(out)


def fingerprint(node, content):
    origin = tokens(node)
    low = min(token["bytepos"] for token in origin)
    high = max(token["bytepos"] + len(token["str"].encode()) for token in origin)
    return json.dumps([normalized(node), source_shape(content[low:high].decode())], sort_keys=True)


def normalized(node, depth=0):
    if depth > 256:
        raise RuntimeError("Replay AST exceeds nesting bound")
    if isinstance(node, dict):
        if "OriginTok" in node:
            return {"OriginTok": node["OriginTok"]["str"]}
        return {key: normalized(value, depth + 1) for key, value in node.items() if key != "id_info_id"}
    if isinstance(node, list):
        return [normalized(value, depth + 1) for value in node]
    return node


def parse(path):
    path = Path(path).resolve()
    content = path.read_bytes()
    if not 0 < len(content) <= 2 * 1024 * 1024:
        raise RuntimeError(f"Empty/oversize replay AST input: {path}")
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            [rust_parser(), "-lang", "rust", "-json", "-full_token_info", "-dump_ast", str(path)],
            cwd=ROOT, stdout=output, stderr=subprocess.PIPE, timeout=5,
            env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
        )
        if result.returncode or result.stderr or not 0 < output.tell() <= 32 * 1024 * 1024:
            raise RuntimeError(f"Incomplete/oversize replay AST: {path} {result.returncode} {result.stderr}")
        output.seek(0)
        tree = json.load(output)
    if not isinstance(tree, dict) or not isinstance(tree.get("Pr"), list):
        raise RuntimeError(f"Invalid replay AST program: {path}")
    for token in tokens(tree):
        low, text = token.get("bytepos"), token.get("str")
        if type(low) is not int or not isinstance(text, str) or not text:
            raise RuntimeError("Invalid replay AST origin token")
        encoded = text.encode()
        if not 0 <= low < low + len(encoded) <= len(content) or content[low:low + len(encoded)] != encoded:
            raise RuntimeError("Replay AST token does not match complete source")
        if Path(token["file"]).resolve() != path:
            raise RuntimeError("Replay AST token belongs to another source")
    return tree, content


def scope_violations(semgrep, path, canonical):
    tree, content = parse(path)
    definitions = [node for node in walk(tree) if isinstance(node, dict) and "DefStmt" in node]
    owners = []
    for node in tree["Pr"]:
        definition = node.get("DefStmt", [{}, {}])[1]
        other = definition.get("OtherDef", [])
        if len(other) == 2 and other[0][0] == "Impl":
            target = other[1][0].get("T", {}).get("t", {}).get("TyN", {}).get("Id", [[None]])[0][0]
            if target == "ReplayCache":
                owners.append(node)
    violations = set()
    children = []
    if len(owners) != 1:
        violations.add("replay-cache-owner")
    else:
        owner = owners[0]
        children = owner["DefStmt"][1]["OtherDef"][1][1].get("Ss", [])
        if not children or owner["DefStmt"][0].get("attrs"):
            violations.add("replay-cache-owner")
        else:
            low = min(token["bytepos"] for token in tokens(owner["DefStmt"][0]))
            high = min(token["bytepos"] for token in tokens(children[0]))
            # The generic AST omits trait-impl headers. Check the real source
            # header too, so `impl SomeTrait for ReplayCache` is not an owner.
            if content[low:high].split() not in ([b"impl", b"ReplayCache", b"{"], [b"impl", b"ReplayCache", b"{", b"pub"]):
                violations.add("replay-cache-owner")
    selected = {}
    for kind, (identifier, expected) in SCOPES.items():
        nodes = [node for node in definitions if name(node) == identifier]
        selected[kind] = nodes
        if len(nodes) != expected:
            violations.add(f"replay-{kind}-count")
        actual = Counter(fingerprint(node, content) for node in nodes)
        if actual != canonical[kind]:
            violations.add(f"replay-{kind}-scope")
        allowed = children if kind == "compaction" else tree["Pr"]
        if any(not any(node is child for child in allowed) for node in nodes):
            violations.add(f"replay-{kind}-owner")
    observations = {kind: set() for kind in SCOPES if kind != "key"}
    for finding in findings(semgrep, OBSERVE, path):
        kind = finding["check_id"].split(".")[-1].removeprefix("observe-replay-")
        low, high = finding["start"]["offset"], finding["end"]["offset"]
        if kind not in observations or type(low) is not int or type(high) is not int or not 0 <= low < high <= len(content):
            raise RuntimeError("Invalid replay AST observation")
        observations[kind].add((low, high))
        spans = [(min(t["bytepos"] for t in tokens(node)), max(t["bytepos"] + len(t["str"].encode()) for t in tokens(node)))
                 for node in selected[kind]]
        if not any(start <= low and high == end for start, end in spans):
            violations.add(f"replay-{kind}-boundary")
    for kind, spans in observations.items():
        if len(spans) != SCOPES[kind][1]:
            violations.add(f"replay-{kind}-count")
    return violations


def canonical_scopes():
    tree, content = parse(CANONICAL)
    definitions = [node for node in walk(tree) if isinstance(node, dict) and "DefStmt" in node]
    result = {}
    for kind, (identifier, expected) in SCOPES.items():
        selected = [node for node in definitions if name(node) == identifier]
        if len(selected) != expected:
            raise RuntimeError(f"Incomplete canonical replay AST: {kind}")
        result[kind] = Counter(fingerprint(node, content) for node in selected)
    return result


def variants(source):
    scopes = {key: method(source, value[0]) for key, value in SCOPES.items() if key != "key"}
    cases = {}

    def edit(label, kind, old, new):
        cases[label] = (replace_once(source, scopes[kind], replace_once(scopes[kind], old, new)), f"replay-{kind}-scope")

    edit("missing_invalidation", "compaction", "        self.auth_journal = None;\n", "")
    edit("invalidation_after_rename", "compaction", "        self.auth_journal = None;\n", "")
    changed = replace_once(scopes["compaction"], "        self.auth_journal = None;\n", "")
    changed = replace_once(changed, "        fs::rename(tmp, path)?;", "        fs::rename(tmp, path)?;\n        self.auth_journal = None;")
    cases["invalidation_after_rename"] = (replace_once(source, scopes["compaction"], changed), "replay-compaction-scope")
    for label, old, new in (
        ("ignored_file_sync", "write_cache_file(&tmp, raw.as_bytes())?;", "let _ = write_cache_file(&tmp, raw.as_bytes());"),
        ("ignored_rename", "fs::rename(tmp, path)?;", "let _ = fs::rename(tmp, path);"),
        ("ignored_directory_result", "        )?;\n        self.auth_journal", "        );\n        self.auth_journal"),
        ("publish_before_sync", "        fsync_parent_dir(", "        self.auth_journal = Some(journal);\n        fsync_parent_dir("),
        ("early_return_before_io", "        let tmp =", "        return Ok(());\n        let tmp ="),
    ):
        edit(label, "compaction", old, new)
    for scope in ("if", "loop", "closure"):
        extra = {"if": "if path.exists() { self.auth_journal = Some(journal); }",
                 "loop": "for _ in 0..1 { self.auth_journal = Some(journal); }",
                 "closure": "let _early = || { self.auth_journal = Some(journal); };"}[scope]
        edit("nested_publish_" + scope, "compaction", "        let tmp =", "        " + extra + "\n        let tmp =")
    for label, old, new in (
        ("open_error_unwrap", "let dir_file = open()?;", "let dir_file = open().unwrap();"),
        ("sync_error_ignored", "    dir_file.sync_all()", "    let _ = dir_file.sync_all();\n    Ok(())"),
        ("directory_never_opened", "    let dir_file = open()?;", "    return Ok(());\n    let dir_file = open()?;"),
    ):
        edit(label, "sync", old, new)
    old = scopes["sync"]
    prefix = old[:old.index("    let dir_file = open()?;")]
    cases["original_best_effort"] = (replace_once(source, old, prefix + "    if let Ok(dir_file) = open() { let _ = dir_file.sync_all(); }\n    Ok(())\n}"), "replay-sync-scope")
    for label, old, new in (
        ("digest_not_mutable", "let mut digest =", "let digest ="),
        ("helper_bypassed", "cache_mac_key_from_digest(&mut digest)", "CacheMacKey(digest.into())"),
        ("caller_retains_raw_copy", "    cache_mac_key_from_digest(&mut digest)", "    let retained = digest.to_vec();\n    cache_mac_key_from_digest(&mut digest)"),
    ):
        edit(label, "derive", old, new)
    for label, old, new in (
        ("missing_wipe", "    digest.zeroize();\n", ""),
        ("partial_wipe", "digest.zeroize()", "digest[..1].zeroize()"),
        ("wrong_buffer_wipe", "digest.zeroize()", "key.0.zeroize()"),
        ("nonvolatile_fill", "digest.zeroize()", "digest.fill(0)"),
        ("return_before_wipe", "    digest.zeroize();", "    return key;\n    digest.zeroize();"),
        ("raw_out_owner", "let mut key = CacheMacKey([0_u8; 32]);", "let mut out = [0_u8; 32];\n    out.copy_from_slice(digest);\n    let mut key = CacheMacKey(out);"),
    ):
        edit(label, "wipe", old, new)
    for scope in ("plain", "if", "loop", "closure"):
        extra = "let retained = key.0;"
        if scope == "if": extra = "if !digest.is_empty() { " + extra + " }"
        if scope == "loop": extra = "for _ in 0..1 { " + extra + " }"
        if scope == "closure": extra = "let _copy = || { " + extra + " };"
        edit("nested_raw_copy_" + scope, "wipe", "    digest.zeroize();", "    " + extra + "\n    digest.zeroize();")
    for label, old, new, policy in (
        ("missing_key_drop", "#[derive(Clone, Zeroize, ZeroizeOnDrop)]", "#[derive(Clone, Zeroize)]", "replay-key-scope"),
        ("missing_key_zeroize", "#[derive(Clone, Zeroize, ZeroizeOnDrop)]", "#[derive(Clone, ZeroizeOnDrop)]", "replay-key-scope"),
        ("key_test_cfg", "struct CacheMacKey([u8; 32]);", "#[cfg(test)]\nstruct CacheMacKey([u8; 32]);", "replay-key-scope"),
        ("unix_cfg_changed", "#[cfg(unix)]\nfn fsync_parent_dir", "#[cfg(any(unix, test))]\nfn fsync_parent_dir", "replay-sync-scope"),
        ("helper_test_cfg", "fn cache_mac_key_from_digest(digest:", "#[cfg(test)]\nfn cache_mac_key_from_digest(digest:", "replay-wipe-scope"),
        ("impl_test_cfg", "impl ReplayCache {", "#[cfg(test)]\nimpl ReplayCache {", "replay-cache-owner"),
        ("trait_owner", "impl ReplayCache {", "impl ReadonlyPersistence for ReplayCache {", "replay-cache-owner"),
    ):
        cases[label] = (replace_once(source, old, new), policy)
    without = replace_once(source, scopes["wipe"], "")
    cases["canonical_helper_only_in_tests"] = (replace_once(without, "#[cfg(test)]\nmod tests {", "#[cfg(test)]\nmod tests {\n" + scopes["wipe"]), "replay-wipe-owner")
    without = replace_once(source, scopes["compaction"], "")
    cases["canonical_compaction_wrong_owner"] = (without + "\nimpl ReadonlyCache {\n" + scopes["compaction"] + "\n}\n", "replay-compaction-owner")
    cases["duplicate_helper"] = (source + "\n#[cfg(test)]\n" + scopes["wipe"] + "\n", "replay-wipe-count")
    cases["duplicate_impl"] = (source + "\nimpl ReplayCache {}\n", "replay-cache-owner")
    cases["positive_whitespace"] = (replace_once(source, scopes["wipe"], scopes["wipe"].replace("    ", "        ")), None)
    cases["positive_comments"] = (replace_once(source, "    digest.zeroize();", "    // The complete input is erased.\n    digest.zeroize();"), None)
    cases["positive_same_owner"] = (replace_once(source, scopes["compaction"], scopes["compaction"] + "\n    #[cfg(test)]\n    fn replay_guard_safe_helper(&self) {}"), None)
    return cases


def verify(semgrep):
    started = time.monotonic()
    fixture = run(semgrep, "--jobs", "1", "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if fixture.returncode:
        raise RuntimeError(fixture.stdout + fixture.stderr)
    print(fixture.stdout.strip(), flush=True)
    canonical = canonical_scopes()
    for path in (CANONICAL, SOURCE):
        actual = findings(semgrep, RULES, path)
        violations = scope_violations(semgrep, path, canonical)
        if actual or violations:
            raise RuntimeError(f"Replay production/canonical violations: {path} {actual} {violations}")
    cases = variants(SOURCE.read_text())
    manifest = []
    with tempfile.TemporaryDirectory(prefix="parallax-replay-persistence-") as directory:
        for label, (content, _) in cases.items():
            (Path(directory) / (label + ".rs")).write_text(content)
        # A parse error/timeout is a failed scan, never counted as a detection.
        found = {}
        for finding in findings(semgrep, RULES, directory):
            found.setdefault(Path(finding["path"]).stem, set()).add(finding["check_id"].split(".")[-1])
        for label, (content, expected) in cases.items():
            violations = scope_violations(semgrep, Path(directory) / (label + ".rs"), canonical)
            detected = violations | found.get(label, set())
            if expected is None and detected or expected is not None and expected not in detected:
                raise RuntimeError(f"Replay complete-source mutation failed: {label} {expected} {detected}")
            manifest.append({"name": label, "sha256": hashlib.sha256(content.encode()).hexdigest(),
                             "expected": expected, "violations": sorted(detected)})
    negatives = sum(expected is not None for _, expected in cases.values())
    positives = len(cases) - negatives
    print(f"Replay guards: 5 fixtures, {negatives} full-source negatives, {positives} positives passed", flush=True)
    return {"status": "passed", "scope": __doc__, "semgrep_version": "1.182.1", "fixtures": 5,
            "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "negative_mutants": negatives, "positive_mutants": positives, "mutants": manifest,
            "seconds": time.monotonic() - started}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    result = verify(args.semgrep)
    if args.manifest:
        with args.manifest.open("x") as output:
            json.dump(result, output, indent=2)
