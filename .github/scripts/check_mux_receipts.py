#!/usr/bin/env python3
"""Bounded receipt syntax/complete AST scopes and complete-source mutations.

This is not a general Rust alias/CFG, Tokio scheduling or weak-memory proof.
Real channels/sockets cover publication/cancellation; Kani checks sequential
shipping atomic state, with the CAS model limitation preserved separately.
"""
import argparse
from functools import lru_cache
import json
import os
from pathlib import Path
import subprocess
import tempfile

from check_crypto_rules import replace_once, run
from check_quic_key_phase import method

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/mux_receipt.yml"
OBSERVE = ROOT / ".github/semgrep/mux_receipt_observe.yml"
CANONICAL = ROOT / ".github/semgrep/mux_receipt_canonical.rs"
SOURCES = {"server": ROOT / "src/handshake/server.rs", "client": ROOT / "src/client/runtime.rs",
           "command": ROOT / "src/protocol/command.rs"}
COUNTS = {
    "server": {"claim": 1, "register": 1, "send": 1, "fallback": 1, "drive": 1,
               "upstream": 1, "stream": 1, "stream-impl": 2, "import": 1,
               "constructor": 2, "test-owner": 1},
    "client": {"dead": 1, "watchdog": 1, "client-loop": 1, "import": 1},
    "command": {"budget": 1},
}
KINDS = set().union(*(counts for counts in COUNTS.values()))


def findings(semgrep, config, *targets):
    result = run(semgrep, "--jobs", "1", "--strict", "--no-git-ignore", "--config", str(config),
                 "--json", "--quiet", *(str(p) for p in targets))
    data = json.loads(result.stdout)
    if result.returncode not in (0, 1) or data.get("version") != "1.182.1" or data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete/unpinned receipt scan: status={result.returncode} errors={data.get('errors')} stderr={result.stderr}")
    return data["results"]


def shape(source):
    # Preserve every token and complete macro/argument contents. Only line-edge
    # indentation is ignored; no substring or canonical-tail acceptance.
    return "\n".join(line.strip() for line in source.strip().splitlines())


def observed(semgrep, *targets):
    nodes = {}
    prefix = "observe-mux-receipt-"
    for node in findings(semgrep, OBSERVE, *targets):
        identifier = node["check_id"].split(".")[-1]
        kind = identifier.removeprefix(prefix)
        low, high = node["start"]["offset"], node["end"]["offset"]
        if not identifier.startswith(prefix) or kind not in KINDS or not isinstance(low, int) or not isinstance(high, int) or low >= high:
            raise RuntimeError(f"Invalid receipt AST range: {node}")
        path = str(Path(node["path"]).resolve())
        nodes.setdefault((path, kind), set()).add((low, high))
    return nodes


@lru_cache(maxsize=1)
def rust_parser():
    from semgrep.semgrep_core import SemgrepCore
    parser = SemgrepCore.executable_path()
    version = subprocess.run([parser, "-version"], capture_output=True, text=True, timeout=5)
    if version.returncode or version.stderr or version.stdout.split()[:3] != ["semgrep-core", "version:", "1.182.1"]:
        raise RuntimeError(f"Incomplete/unpinned receipt AST parser: {version.stdout} {version.stderr}")
    return parser


def test_module_violations(path, role):
    # Matching `mod tests { ... }` repeatedly walks the huge test body and can
    # exhaust Semgrep's unchanged 5s rule budget. Read the same pinned parser's
    # complete AST instead: no body wildcard, source slicing or name exemption.
    contents = Path(path).read_bytes()
    if len(contents) > 2 * 1024 * 1024:
        raise RuntimeError(f"Oversize receipt AST source: {path}")
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            [rust_parser(), "-lang", "rust", "-json", "-full_token_info", "-dump_ast", str(path)], cwd=ROOT,
            env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
            stdout=output, stderr=subprocess.PIPE, timeout=5,
        )
        if result.returncode or result.stderr:
            raise RuntimeError(f"Incomplete receipt module AST: {path} {result.returncode} {result.stderr}")
        if not 0 < output.tell() <= 32 * 1024 * 1024:
            raise RuntimeError(f"Oversize/empty receipt AST JSON: {path}")
        output.seek(0)
        tree = json.load(output)
    if not isinstance(tree, dict) or not isinstance(tree.get("Pr"), list):
        raise RuntimeError(f"Unexpected receipt module AST schema: {path}")

    def name(identifier):
        return identifier.get("Id", [[None]])[0][0]

    def entity_name(statement):
        return name(statement["DefStmt"][0].get("name", {}).get("EN", {}))

    definitions = []
    pending = [tree]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if "DefStmt" in node:
                definitions.append(node)
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    modules = [node for node in definitions if entity_name(node) == "tests"
               and "ModuleDef" in node["DefStmt"][1]]
    violations = set()
    if len(modules) != 1:
        violations.add("receipt-test-module-count")
    if role == "server":
        # The unique tests module must itself be the last top-level AST item.
        # A same-name module nested in a production module/function cannot pass.
        valid = len(modules) == 1 and tree["Pr"] and modules[0] is tree["Pr"][-1]
        if valid:
            entity, definition = modules[0]["DefStmt"]
            attrs = entity.get("attrs", [])
            attribute = attrs[0].get("NamedAttr", []) if len(attrs) == 1 else []
            bracket = attribute[2] if len(attribute) == 3 else []
            args = bracket[1] if len(bracket) == 3 else []
            argument = args[0].get("Arg", {}).get("N", {}) if len(args) == 1 else {}
            valid = len(attribute) == 3 and name(attribute[1]) == "cfg" and name(argument) == "test"
            body = definition["ModuleDef"]["mbody"]["ModuleStruct"][1]
            owners = [node for node in definitions if entity_name(node) == "mux_tail_test_reader"
                      and "FuncDef" in node["DefStmt"][1]]
            # Match identity in the parsed tree, not merely a copied function
            # name/source. Whole-function AST pins and constructor spans below
            # still verify this exact owner's contents and its one literal.
            valid = valid and len(owners) == 1 and any(owners[0] is child for child in body)
            # Use actual parser token byte offsets, not a textual search for a
            # module header or brace. As with the previous observer, the module
            # AST retains its final child's closing brace, then exactly the
            # module's own closing brace and whitespace must reach EOF.
            ends = []
            pending = [modules[0]]
            token_files = set()
            while pending:
                node = pending.pop()
                if isinstance(node, dict):
                    if "OriginTok" in node:
                        token = node["OriginTok"]
                        low, text = token["bytepos"], token["str"].encode()
                        high = low + len(text)
                        if type(low) is not int or not 0 <= low < high <= len(contents) or contents[low:high] != text:
                            raise RuntimeError(f"Invalid receipt AST token span: {path} {token}")
                        token_files.add(token["file"])
                        ends.append(high)
                    pending.extend(node.values())
                elif isinstance(node, list):
                    pending.extend(node)
            if not ends or any(Path(file).resolve() != Path(path).resolve() for file in token_files):
                raise RuntimeError(f"Invalid receipt AST token owner: {path}")
            valid = valid and contents[max(ends):].strip() == b"}"
        if not valid:
            violations.add("receipt-test-constructor-owner")
    return violations


def scope_violations(semgrep, roles, canonical):
    nodes = observed(semgrep, *roles)
    violations = {}
    for path, role in roles.items():
        contents = Path(path).read_bytes()
        for kind in KINDS:
            spans = nodes.get((str(Path(path).resolve()), kind), set())
            if len(spans) != COUNTS[role].get(kind, 0):
                violations.setdefault(Path(path).name, set()).add("receipt-" + kind + "-count")
            for low, high in spans:
                if shape(contents[low:high].decode()) not in canonical[kind]:
                    violations.setdefault(Path(path).name, set()).add("receipt-" + kind + "-scope")
                if kind == "import" and not contents[low:high].rstrip().endswith(b";"):
                    # Some Rust import queries end at a path. Require the actual
                    # declaration boundary, rejecting a trailing `as` alias.
                    if not contents[high:].lstrip().startswith(b";"):
                        violations.setdefault(Path(path).name, set()).add("receipt-import-boundary")
        module_violations = test_module_violations(path, role)
        if module_violations:
            violations.setdefault(Path(path).name, set()).update(module_violations)
        if role == "server":
            key = str(Path(path).resolve())
            owners = nodes.get((key, "test-owner"), set())
            registers = nodes.get((key, "register"), set())
            constructors = nodes.get((key, "constructor"), set())

            def contains(outer, inner):
                return outer[0] <= inner[0] and inner[1] <= outer[1]

            for owner_kind, owner_spans in (("register", registers), ("test", owners)):
                owned = [ctor for ctor in constructors if any(contains(owner, ctor) for owner in owner_spans)]
                if len(owned) != 1:
                    violations.setdefault(Path(path).name, set()).add("receipt-" + owner_kind + "-constructor-count")
            if any(not any(contains(owner, ctor) for owner in registers | owners) for ctor in constructors):
                violations.setdefault(Path(path).name, set()).add("receipt-constructor-owner")
    return violations


def mutations(semgrep, canonical):
    texts = {role: path.read_text() for role, path in SOURCES.items()}
    server, client, command = (texts[role] for role in ("server", "client", "command"))
    methods = {name: method(server, name) for name in (
        "claim_mux_publication", "register", "send", "send_receipt_if_unanswered",
        "with_mux_open_receipt", "server_mux_upstream_task", "server_mux_target_reader_loop",
        "server_mux_upload_drain", "mux_tail_test_reader")}
    variants = {}

    def add(name, role, old, new, policy):
        variants[name + ".rs"] = (role, replace_once(texts[role], old, new), policy)

    def edit(name, scope, old, new, policy):
        original = methods[scope]
        add(name, "server", original, replace_once(original, old, new), policy)

    for name, old, new in (
        ("claim_always_wins", "!first_publication.swap(true, Ordering::AcqRel)", "true"),
        ("claim_resets", "swap(true,", "swap(false,"),
        ("claim_wrong_winner", "!first_publication.swap", "first_publication.swap"),
        ("claim_weak_order", "Ordering::AcqRel", "Ordering::Relaxed"),
    ):
        edit(name, "claim_mux_publication", old, new, "receipt-claim-scope")
    for name, old, new in (
        ("relative_registration_budget", "MUX_CARRIER_SUSPECT_AFTER / 2", "Duration::from_millis(500)"),
        ("reset_deadline_after_registration_wait", "        Ok(ServerMuxStreamTx {", "        let receipt_deadline = Instant::now() + MUX_CARRIER_SUSPECT_AFTER / 2;\n        Ok(ServerMuxStreamTx {"),
        ("initial_claim_true", "AtomicBool::new(false)", "AtomicBool::new(true)"),
    ):
        edit(name, "register", old, new, "receipt-register-scope")
    for name, old, new in (
        ("ordinary_early_claim", "        let permit =", "        claim_mux_publication(&self.first_publication);\n        let permit ="),
        ("ordinary_dropped_after_receipt", "        permit.send(MuxFrame {", "        if self.first_publication.load(Ordering::Acquire) { return Ok(()); }\n        permit.send(MuxFrame {"),
        ("ordinary_yields_after_claim", "        // Ordinary frames", "        tokio::task::yield_now().await;\n        // Ordinary frames"),
        ("ordinary_fin_not_confirmation", "MuxFrameKind::Data | MuxFrameKind::Fin | MuxFrameKind::Reset", "MuxFrameKind::Data | MuxFrameKind::Reset"),
    ):
        edit(name, "send", old, new, "receipt-send-scope")
    for name, old, new in (
        ("fallback_early_claim", "        let permit =", "        claim_mux_publication(&self.first_publication);\n        let permit ="),
        ("fallback_always_sends", "if claim_mux_publication(&self.first_publication)", "if true"),
        ("fallback_yields_after_claim", "            permit.send", "            tokio::task::yield_now().await;\n            permit.send"),
        ("fallback_canonical_extra_frame", "        Ok(())", "        let _ = self.frames.try_send(MuxFrame { stream_id: self.stream_id, kind: MuxFrameKind::Data, payload: Vec::new() });\n        Ok(())"),
    ):
        edit(name, "send_receipt_if_unanswered", old, new, "receipt-fallback-scope")
    for name, old, new in (
        ("driver_restarts_deadline", "sleep_until(downlink.receipt_deadline)", "sleep(MUX_CARRIER_SUSPECT_AFTER / 2)"),
        ("driver_blocks_before_upstream", "    tokio::pin!(upstream, receipt);", "    receipt.await.ok();\n    upstream.await;\n    return;\n    tokio::pin!(upstream, receipt);"),
        ("driver_suppresses_upstream", "    let receipt = async {", "    let upstream = std::future::pending::<()>();\n    let receipt = async {"),
        ("driver_adds_detached_task", "    let receipt = async {", "    tokio::spawn(async { tokio::task::yield_now().await; });\n    let receipt = async {"),
        ("driver_drops_upstream_after_receipt", "                upstream.await;", "                return;"),
    ):
        edit(name, "with_mux_open_receipt", old, new, "receipt-drive-scope")
    edit("restore_immediate_ack", "server_mux_upstream_task", "        let mut target =", "        let _ = downlink.send(MuxFrameKind::Data, Vec::new()).await;\n        let mut target =", "receipt-upstream-scope")
    edit("skip_receipt_driver", "server_mux_upstream_task", "with_mux_open_receipt(&downlink, upstream).await", "upstream.await", "receipt-upstream-scope")
    add("reset_claim_from_another_producer", "server", "    let max_payload_len = MuxFrame::max_payload_len(chunk_size);", "    downlink.first_publication.store(false, Ordering::Release);\n    let max_payload_len = MuxFrame::max_payload_len(chunk_size);", "parallax-mux-receipt-no-state-bypass")
    add("replace_deadline_from_another_producer", "server", "    let max_payload_len = MuxFrame::max_payload_len(chunk_size);", "    let mut downlink = downlink;\n    downlink.receipt_deadline = Instant::now();\n    let max_payload_len = MuxFrame::max_payload_len(chunk_size);", "parallax-mux-receipt-no-state-bypass")
    forked_tx = """ServerMuxStreamTx {
        stream_id: downlink.stream_id,
        frames: downlink.frames.clone(),
        wake: downlink.wake.clone(),
        first_publication: Arc::new(AtomicBool::new(false)),
        receipt_deadline: downlink.receipt_deadline,
    }"""
    reader_anchor = "    let max_payload_len ="
    edit("reader_forks_publication_state", "server_mux_target_reader_loop", reader_anchor,
         "    let downlink = " + forked_tx + ";\n" + reader_anchor, "receipt-constructor-count")
    edit("reader_nested_block_forks_publication_state", "server_mux_target_reader_loop", reader_anchor,
         "    let downlink = { " + forked_tx + " };\n" + reader_anchor, "receipt-constructor-count")
    edit("upload_producer_forks_publication_state", "server_mux_upload_drain",
         "    while let Some(payload)", "    let downlink = " + forked_tx + ";\n    while let Some(payload)",
         "receipt-constructor-count")
    test_helper = methods["mux_tail_test_reader"]
    without_test_helper = replace_once(server, test_helper, "")
    variants["same_test_owner_moved_to_production.rs"] = (
        "server", replace_once(without_test_helper, "#[cfg(test)]\nmod tests {",
                               test_helper + "\n\n#[cfg(test)]\nmod tests {"),
        "receipt-test-constructor-owner")
    add("test_namespace_without_test_attribute", "server", "#[cfg(test)]\nmod tests {",
        "#[cfg(any(test, not(test)))]\nmod tests {", "receipt-test-constructor-owner")
    add("test_namespace_nested_in_another_module", "server", "#[cfg(test)]\nmod tests {",
        "mod receipt_scope {\n#[cfg(test)]\nmod tests {", "receipt-test-constructor-owner")
    role, nested, policy = variants["test_namespace_nested_in_another_module.rs"]
    variants["test_namespace_nested_in_another_module.rs"] = (role, nested + "}\n", policy)
    variants["test_module_non_whitespace_after_closing_token.rs"] = (
        "server", server + "// AST still ends in the tests module; preserve the exact EOF token boundary.\n",
        "receipt-test-constructor-owner")
    add("clone_replaces_shared_state", "server", "#[derive(Clone)]\nstruct ServerMuxStreamTx", "struct ServerMuxStreamTx", "receipt-stream-impl-count")
    role, clone_source, policy = variants["clone_replaces_shared_state.rs"]
    variants["clone_replaces_shared_state.rs"] = (role, clone_source + "\nimpl Clone for ServerMuxStreamTx { fn clone(&self) -> Self { Self { stream_id: self.stream_id, frames: self.frames.clone(), wake: self.wake.clone(), first_publication: Arc::new(AtomicBool::new(false)), receipt_deadline: self.receipt_deadline } } }\n", policy)
    for role, declaration in (("server", "static"), ("client", "const")):
        altered = replace_once(texts[role], "use crate::protocol::command::MUX_CARRIER_SUSPECT_AFTER;\n", "")
        variants[role + "_budget_rebind.rs"] = (role, altered + "\n" + declaration + " MUX_CARRIER_SUSPECT_AFTER: Duration = Duration::from_secs(5);\n", "receipt-budget-count")
    add("client_changes_dead_budget", "client", "const MUX_CARRIER_DEAD_AFTER: Duration = Duration::from_secs(25);", "const MUX_CARRIER_DEAD_AFTER: Duration = Duration::from_secs(250);", "receipt-dead-scope")
    add("client_ignores_implicit_confirmation", "client", "                unanswered_opens.remove(&frame.stream_id);", "                if frame.payload.is_empty() { unanswered_opens.remove(&frame.stream_id); }", "receipt-client-loop-scope")
    add("client_waits_before_upload", "client", "    let upload = client_mux_upload_loop(", "    sleep(MUX_CARRIER_SUSPECT_AFTER).await;\n    let upload = client_mux_upload_loop(", "parallax-mux-receipt-no-client-upload-gate")
    for call in ("time::sleep(MUX_CARRIER_SUSPECT_AFTER)", "time::sleep_until(Instant::now())"):
        add("client_waits_before_upload_" + call.split("(")[0].replace("::", "_"), "client",
            "    let upload = client_mux_upload_loop(",
            "    " + call + ".await;\n    let upload = client_mux_upload_loop(",
            "parallax-mux-receipt-no-client-upload-gate")
    add("shared_budget_changed", "command", "std::time::Duration::from_secs(5)", "std::time::Duration::from_secs(50)", "receipt-budget-scope")
    add("shared_budget_canonical_decoy", "command", "std::time::Duration::from_secs(5)", "{ let mut budget = std::time::Duration::from_secs(5); budget = std::time::Duration::from_secs(50); budget }", "receipt-budget-scope")
    # Positive complete files exercise every observed production node, not just
    # one tiny positive rule fixture; whitespace remains semantically irrelevant.
    positives = set()
    for role, text in texts.items():
        name = "positive_" + role + ".rs"
        variants[name] = (role, text, None)
        positives.add(name)
    name = "positive_reader_clones_shared_tx.rs"
    variants[name] = ("server", replace_once(server, methods["server_mux_target_reader_loop"],
        replace_once(methods["server_mux_target_reader_loop"], reader_anchor,
                     "    let downlink = downlink.clone();\n" + reader_anchor)), None)
    positives.add(name)
    with tempfile.TemporaryDirectory(prefix="parallax-mux-receipt-") as temporary:
        batches = []
        for index, (name, (role, content, _)) in enumerate(variants.items()):
            directory = Path(temporary) / f"batch-{index // 4:03d}"
            if directory not in batches:
                directory.mkdir()
                batches.append(directory)
            (directory / name).write_text(content)
        found = {}
        for directory in batches:
            for finding in findings(semgrep, RULES, directory):
                found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
            roles = {path: variants[path.name][0] for path in directory.iterdir()}
            for name, policies in scope_violations(semgrep, roles, canonical).items():
                found.setdefault(name, set()).update(policies)
        for name, (_, _, expected) in variants.items():
            if expected is None:
                if found.get(name):
                    raise RuntimeError(f"Valid complete receipt source rejected: {name} {found[name]}")
            elif expected not in found.get(name, set()):
                raise RuntimeError(f"Receipt production-source mutation escaped: {name} ({expected})")
    print(f"Mux receipt complete-source mutations: {len(variants)-len(positives)} detected; {len(positives)} positive files passed")


def verify(semgrep):
    result = run(semgrep, "--jobs", "1", "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip())
    golden_bytes = CANONICAL.read_bytes()
    canonical = {kind: set() for kind in KINDS}
    for (_, kind), spans in observed(semgrep, CANONICAL).items():
        if kind in canonical:
            canonical[kind].update(shape(golden_bytes[low:high].decode()) for low, high in spans)
    if any(not values for values in canonical.values()):
        raise RuntimeError("Incomplete canonical receipt AST observations")
    actual = findings(semgrep, RULES, *SOURCES.values())
    roles = {path: role for role, path in SOURCES.items()}
    scopes = scope_violations(semgrep, roles, canonical)
    if actual or scopes:
        raise RuntimeError(f"Receipt source violations: {actual} {scopes}")
    mutations(semgrep, canonical)
    print("Mux receipt AST scopes/rules: passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    verify(parser.parse_args().semgrep)
