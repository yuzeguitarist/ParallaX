#!/usr/bin/env python3
"""Block regressions in QUIC role, replay-commit, and exhausted-key boundaries.

AST ordering plus actual production-source mutations complement real encrypted
packet tests and narrowly scoped production-state Kani proofs.
"""

import argparse
import json
from pathlib import Path
import re
import tempfile

from check_crypto_rules import replace_once, run
from check_quic_key_phase import method


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/quic_packet_guards.yml"
SOURCE = ROOT / "src/transport/udp/quic/conn.rs"
OBSERVATIONS = ROOT / ".github/semgrep/quic_packet_guards_observe.yml"
CANONICAL = ROOT / ".github/semgrep/quic_packet_guards_canonical.rs"

ADMISSION_COUNTS = {
    "level-binding": 1, "type-binding": 1, "frame-binding": 1,
    "gate": 1, "call": 1, "iterate": 1, "iterator": 1,
    "crypto": 1, "stream": 1, "reset": 1, "stop": 1, "ack": 1,
    "close": 1, "closed-write": 1,
}
ADMISSION_NODES = {
    "level-binding": """let pspace = match packet::first_packet_space(pkt) {
            Some(s) => s,
            None => return Ok(()), // unsupported type / clear fixed bit: drop
        };""",
    "type-binding": "let frame_type = frames.last_frame_type();",
    "frame-binding": """let frame = frame.map_err(|e| {
                transport_error(0x07, frame_type, format!("frame decode failed: {e:?}"))
            })?;""",
    "gate": """if !frame_permitted(pspace, self.side, frame_type) {
                self.close_transport(0x0a, frame_type, b"frame not permitted");
                return Err(transport_error(0x0a, frame_type, "frame not permitted"));
            }""",
}


def node_shape(text):
    # Ignore line indentation only. In particular, do not erase tokens/comments
    # or normalize macro arguments into a shorter pure-expression substring.
    return "\n".join(line.strip() for line in text.strip().splitlines()).rstrip(";")


def admission_observations(semgrep, target, require_definitions=False):
    result = run(semgrep, "--jobs", "1", "--strict", "--no-git-ignore", "--config", str(OBSERVATIONS),
                 "--json", "--quiet", str(target))
    if result.returncode:
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("version") != "1.182.1" or data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete admission AST observations: {data}")
    prefix = "observe-quic-admission-"
    known = {"helper-definition", "receive-definition", "binding-pattern", *ADMISSION_COUNTS}
    ranges = {}
    for finding in data["results"]:
        identifier = finding["check_id"].split(".")[-1]
        kind = identifier.removeprefix(prefix)
        low, high = finding["start"]["offset"], finding["end"]["offset"]
        if not identifier.startswith(prefix) or kind not in known or not isinstance(low, int) or not isinstance(high, int) or low >= high:
            raise RuntimeError(f"Invalid admission AST observation: {finding}")
        path = str(Path(finding["path"]).resolve())
        ranges.setdefault((path, kind), set()).add((low, high))
    violations = {}
    for scope in ("helper", "receive"):
        definition = scope + "-definition"
        paths = {path for path, kind in ranges if kind == definition}
        if require_definitions and paths != {str(Path(target).resolve())}:
            raise RuntimeError(f"Missing complete admission scope: {scope}")
        for path in paths:
            definitions = ranges[(path, definition)]
            if len(definitions) != 1:
                violations.setdefault(Path(path).name, set()).add("quic-admission-definition-count")
                continue
            low, high = next(iter(definitions))
            contents = Path(path).read_bytes()
            if scope == "helper":
                expected = node_shape(method(CANONICAL.read_text(), "frame_permitted"))
                if node_shape(contents[low:high].decode()) != expected:
                    violations.setdefault(Path(path).name, set()).add("quic-admission-helper-scope")
                continue
            for kind, expected_count in ADMISSION_COUNTS.items():
                sites = ranges.get((path, kind), set())
                if any(not (low <= start and end <= high) for start, end in sites):
                    raise RuntimeError(f"Unscoped admission AST site: {path} {kind}")
                if len(sites) != expected_count:
                    violations.setdefault(Path(path).name, set()).add(f"quic-admission-{kind}-count")
                if kind in ADMISSION_NODES:
                    for start, end in sites:
                        # Rust binding observations begin at the identifier,
                        # excluding the `let` keyword in pinned Semgrep.
                        canonical = ADMISSION_NODES[kind]
                        if kind.endswith("-binding"):
                            canonical = canonical.removeprefix("let ")
                        if node_shape(contents[start:end].decode()) != node_shape(canonical):
                            violations.setdefault(Path(path).name, set()).add(f"quic-admission-{kind}-scope")
                if kind == "iterate":
                    canonical = method(CANONICAL.read_text(), "reviewed_frame_iteration")
                    canonical = canonical[canonical.index("{") + 1:canonical.rindex("}")].strip()
                    for start, end in sites:
                        if node_shape(contents[start:end].decode()) != node_shape(canonical):
                            violations.setdefault(Path(path).name, set()).add("quic-admission-iterate-scope")
            for start, end in ranges.get((path, "binding-pattern"), set()):
                if not low <= start < end <= high:
                    raise RuntimeError(f"Unscoped admission binding pattern: {path}")
                pattern = contents[start:end].decode()
                identifiers = set(re.findall(r"[A-Za-z_][A-Za-z_0-9]*", pattern))
                protected = identifiers & {"pspace", "frame_type", "frame", "frames", "frame_permitted"}
                # Ordinary identifier bindings are pinned/counted above. Reject
                # destructuring shadows and local predicate bindings too. This
                # reads a COMPLETE AST-focused binding, not arbitrary Rust text.
                shape = "".join(pattern.split())
                if protected and ("frame_permitted" in protected or shape not in {
                    "pspace", "frame_type", "frame", "frames", "mutframes", "Some(frame)",
                }):
                    violations.setdefault(Path(path).name, set()).add("quic-admission-binding-pattern")
    return violations


def scan(semgrep, target, require_clean=False):
    result = run(semgrep, "--jobs", "1", "--strict", "--no-git-ignore", "--config", str(RULES),
                 "--json", "--quiet", str(target))
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("version") != "1.182.1" or data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete QUIC guard scan: {data}")
    if require_clean and (result.returncode or data["results"]):
        raise RuntimeError(f"QUIC guard violations: {data['results']}")
    return data["results"]


def mutations(semgrep):
    source = SOURCE.read_text()
    start = source.index("    fn process_packet(")
    end = source.index("    fn recv_ack(", start)
    receive = source[start:end]
    role_guard = """        if self.side == Side::Client && pspace == PacketSpace::ZeroRtt {
            return Ok(());
        }
"""
    dedup = """        if !self.spaces[space].recv.insert(header.packet_number()) {
            return Ok(());
        }
"""
    late_role = replace_once(receive, role_guard, "")
    late_role = replace_once(late_role, "        let local_cid_len =", role_guard + "        let local_cid_len =")
    late_idle = replace_once(receive, "        self.last_recv_time = Some(now);\n", "")
    late_idle = replace_once(late_idle, dedup, "        self.last_recv_time = Some(now);\n" + dedup)
    cid_commit = """        if let Some((_, scid)) = long_cids {
            if !self.peer_cid_adopted {
                self.dcid = scid;
                self.peer_cid_adopted = true;
            }
        }
"""
    early_cid = replace_once(receive, cid_commit, "")
    early_cid = replace_once(early_cid, dedup, cid_commit + dedup)
    helper_start = source.index("fn close_on_exhausted_data_key(")
    helper_end = source.index("fn transport_error(", helper_start)
    helper = source[helper_start:helper_end]
    enforce_start = source.index("    fn enforce_aead_confidentiality_limit(")
    enforce_end = source.index("    /// Enforce the AEAD integrity limit", enforce_start)
    enforce = source[enforce_start:enforce_end]
    close = method(source, "build_close_packet")
    transmit_start = source.index("    fn poll_transmit_inner(")
    transmit_end = source.index("    fn drain_duration(", transmit_start)
    transmit = source[transmit_start:transmit_end]
    variants = {
        "missing_role.rs": (receive, replace_once(receive, role_guard, ""), "parallax-quic-reject-client-zero-rtt"),
        "wrong_role.rs": (receive, replace_once(receive, "self.side == Side::Client && pspace == PacketSpace::ZeroRtt",
            "self.side == Side::Server && pspace == PacketSpace::ZeroRtt"), "parallax-quic-reject-client-zero-rtt"),
        "late_role.rs": (receive, late_role, "parallax-quic-reject-client-zero-rtt"),
        "idle_before_dedup.rs": (receive, late_idle, "parallax-quic-authenticated-dedup-before-state"),
        "missing_dedup.rs": (receive, replace_once(receive, dedup, ""), "parallax-quic-authenticated-dedup-before-state"),
        "cid_before_dedup.rs": (receive, early_cid, "parallax-quic-authenticated-dedup-before-state"),
        "wrong_limit_boundary.rs": (helper, replace_once(helper, "if sealed < limit {", "if sealed <= limit {"),
            "parallax-quic-exhausted-key-is-silent"),
        "pending_close_survives.rs": (helper, replace_once(helper, "    *close_pending = None;\n", ""),
            "parallax-quic-exhausted-key-is-silent"),
        "closed_skips_retirement.rs": (helper, replace_once(helper, "    if sealed < limit {",
            "    if closed.is_some() { return; }\n    if sealed < limit {"), "parallax-quic-exhausted-key-is-silent"),
        "closed_skips_enforcement.rs": (enforce, replace_once(enforce,
            "        let limit =", "        if self.closed.is_some() { return; }\n        let limit ="),
            "parallax-quic-budget-gates-closed-connections"),
        "close_without_gate.rs": (close, replace_once(close, "        self.enforce_aead_confidentiality_limit();\n", ""),
            "parallax-quic-close-builder-budget"),
        "pn_before_close_gate.rs": (close, replace_once(close, "        self.enforce_aead_confidentiality_limit();",
            "        let _pn = self.spaces[SPACE_DATA].send.allocate();\n        self.enforce_aead_confidentiality_limit();"),
            "parallax-quic-close-builder-budget"),
        "transmit_without_gate.rs": (transmit, replace_once(transmit,
            "        self.enforce_aead_confidentiality_limit();\n        self.enforce_aead_integrity_limit();",
            "        self.enforce_aead_integrity_limit();"), "parallax-quic-transmit-budget"),
        "missing_seal_accounting.rs": (source, replace_once(source,
            "            self.data_packets_sealed = self.data_packets_sealed.saturating_add(1);",
            "            self.data_packets_sealed = self.data_packets_sealed;"), "parallax-quic-sealed-data-accounting"),
    }
    # Keep the entire original path and canonical commit statements. These
    # additive mutations must be caught by the negative write rule itself, even
    # when the positive canonical-block requirement still passes.
    protected_writes = {
        "idle": "self.last_recv_time = Some(now);",
        "cid": "self.dcid = long_cids.map_or(self.dcid, |(_, scid)| scid);",
        "key": "self.spaces[SPACE_INITIAL].keys = pending_initial.as_ref().map(|(dcid, _)| initial_keys(dcid.as_slice(), Side::Server));",
        "ecn": "self.spaces[space].recv_ecn.record(ecn);",
    }
    for kind, write in protected_writes.items():
        for position, anchor, prefix in (
            ("before_auth", "        let local_cid_len =", "        " + write + "\n"),
            ("before_dedup", dedup, "        " + write + "\n"),
            ("failed_auth", "                return Ok(()); // undecryptable: drop, do NOT fail the connection",
             "                " + write + "\n"),
            ("nested_before_auth", "        let local_cid_len =",
             "        if !pkt.is_empty() {\n            " + write + "\n        }\n"),
        ):
            name = f"duplicated_{kind}_{position}.rs"
            variants[name] = (receive, replace_once(receive, anchor, prefix + anchor),
                              "parallax-quic-no-early-receive-state-write")
    # Every new case keeps the complete shipping source, not an isolated
    # pseudocode function. Additive cases retain the canonical decision block.
    admission = method(source, "frame_permitted")
    early_types = "0x02 | 0x03 | 0x06 | 0x07 | 0x19 | 0x1b | 0x1e"
    for frame_type in ("0x02", "0x03", "0x06", "0x07", "0x19", "0x1b", "0x1e"):
        types = " | ".join(part for part in early_types.split(" | ") if part != frame_type)
        variants[f"admit_early_{frame_type}.rs"] = (admission,
            replace_once(admission, early_types, types), "parallax-quic-decoded-frame-matrix")
    for name, old, new in (
        ("reverse_receiver_role", "side == Side::Server", "side == Side::Client"),
        ("deny_legal_new_cid", early_types, early_types + " | 0x18"),
        ("deny_legal_path_challenge", early_types, early_types + " | 0x1a"),
        ("deny_legal_application_close", early_types, early_types + " | 0x1d"),
        ("allow_application_close_initial", "0x03 | 0x06 | 0x1c", "0x03 | 0x06 | 0x1c | 0x1d"),
    ):
        variants[name + ".rs"] = (admission, replace_once(admission, old, new), "parallax-quic-decoded-frame-matrix")
    for scope, extra in (
        ("plain", "if frame_type == 0x06 { return true; }"),
        ("nested", "if side == Side::Server { if frame_type == 0x06 { return true; } }"),
        ("closure", "let bypass = || frame_type == 0x06; if bypass() { return true; }"),
    ):
        variants[f"canonical_helper_extra_{scope}.rs"] = (admission,
            replace_once(admission, "    if side ==", "    " + extra + "\n    if side =="),
            "quic-admission-helper-scope")
    for name, old, new in (
        ("collapsed_space", "frame_permitted(pspace, self.side, frame_type)", "frame_permitted(PacketSpace::OneRtt, self.side, frame_type)"),
        ("wrong_receiver", "frame_permitted(pspace, self.side, frame_type)", "frame_permitted(pspace, Side::Client, frame_type)"),
        ("fake_codepoint", "frame_permitted(pspace, self.side, frame_type)", "frame_permitted(pspace, self.side, 0x01)"),
        ("inverted_admission", "if !frame_permitted(", "if frame_permitted("),
        ("missing_sticky_close", '                self.close_transport(0x0a, frame_type, b"frame not permitted");\n', ""),
        ("conditional_sticky_close", 'self.close_transport(0x0a, frame_type, b"frame not permitted");', 'if self.peer_addr_validated { self.close_transport(0x0a, frame_type, b"frame not permitted"); }'),
        ("continue_after_rejection", 'return Err(transport_error(0x0a, frame_type, "frame not permitted"));', "continue;"),
        ("effect_in_error_reason", 'transport_error(0x0a, frame_type, "frame not permitted")', 'transport_error(0x0a, frame_type, format!("frame not permitted: {:?}", self.closed.take()))'),
    ):
        variants[name + ".rs"] = (receive, replace_once(receive, old, new), "parallax-quic-frame-admission-before-dispatch")
    reject = '                self.close_transport(0x0a, frame_type, b"frame not permitted");\n                return Err(transport_error(0x0a, frame_type, "frame not permitted"));'
    variants["sticky_after_return.rs"] = (receive, replace_once(receive, reject,
        '                return Err(transport_error(0x0a, frame_type, "frame not permitted"));\n                self.close_transport(0x0a, frame_type, b"frame not permitted");'),
        "parallax-quic-frame-admission-before-dispatch")
    for name, anchor, extra, policy in (
        ("shadow_level", "        let mut frames =", "let pspace = PacketSpace::OneRtt;", "quic-admission-level-binding-count"),
        ("nested_shadow_level", "        let mut frames =", "{ let pspace = PacketSpace::OneRtt; let _ = pspace; }", "quic-admission-level-binding-count"),
        ("shadow_type", "            if !frame_permitted", "let frame_type = 0x01;", "quic-admission-type-binding-count"),
        ("shadow_frame", "            if !frame_permitted", "let frame = Frame::Ping;", "quic-admission-frame-binding-count"),
        ("change_role", "        let mut frames =", "self.side = Side::Client;", "parallax-quic-frame-admission-no-input-mutation"),
        ("alias_role", "        let mut frames =", "let role = &mut self.side; *role = Side::Client;", "parallax-quic-frame-admission-no-input-mutation"),
        ("undo_close", "            match frame {", "self.closed.take();", "parallax-quic-frame-admission-no-input-mutation"),
        ("nested_undo_close", "        let mut frames =", "if self.closed.is_some() { self.closed.take(); }", "parallax-quic-frame-admission-no-input-mutation"),
        ("extra_closed_assignment", "        let mut frames =", "self.closed = None;", "quic-admission-closed-write-count"),
        ("early_crypto_dispatch", "        let mut frames =", 'self.recv_crypto(space, 1, b"future")?;', "quic-admission-crypto-count"),
        ("nested_early_stream_dispatch", "        let mut frames =", 'if space == SPACE_DATA { self.recv_stream(0, 0, false, b"early")?; }', "quic-admission-stream-count"),
        ("early_reset_dispatch", "        let mut frames =", "self.recv_reset_stream(0, 0, 0)?;", "quic-admission-reset-count"),
    ):
        variants[name + ".rs"] = (receive, replace_once(receive, anchor, "        " + extra + "\n" + anchor), policy)
    loop_start = receive.index("        while let Some(frame) = frames.next() {")
    loop_end = receive.index("        // Stamp the receive time", loop_start)
    loop = receive[loop_start:loop_end]
    variants["duplicated_canonical_frame_loop.rs"] = (receive,
        replace_once(receive, "        // Stamp the receive time", loop + "        // Stamp the receive time"),
        "quic-admission-iterate-count")
    for name, extra in (
        ("tuple_shadow_level", "let (pspace,) = (PacketSpace::OneRtt,);"),
        ("array_shadow_level", "let [pspace] = [PacketSpace::OneRtt];"),
        ("predicate_closure_shadow", "let frame_permitted = |_: PacketSpace, _: Side, _: u64| true;"),
        ("predicate_pointer_shadow", "let frame_permitted: fn(PacketSpace, Side, u64) -> bool = |_, _, _| true;"),
    ):
        variants[name + ".rs"] = (receive, replace_once(receive, "        let mut frames =", "        " + extra + "\n        let mut frames ="),
            "quic-admission-binding-pattern")
    for kind in ("const", "static"):
        extra = f"{kind} frame_permitted: fn(PacketSpace, Side, u64) -> bool = |_, _, _| true;"
        variants[f"predicate_{kind}_shadow.rs"] = (receive,
            replace_once(receive, "        let mut frames =", "        " + extra + "\n        let mut frames ="),
            "parallax-quic-frame-admission-no-item-shadow")
    with tempfile.TemporaryDirectory(prefix="parallax-quic-guards-") as temporary:
        for name, (original, mutated, _) in variants.items():
            (Path(temporary) / name).write_text(replace_once(source, original, mutated))
        found = {}
        for finding in scan(semgrep, temporary):
            found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
        for name, policies in admission_observations(semgrep, temporary).items():
            found.setdefault(name, set()).update(policies)
        for name, (_, _, expected) in variants.items():
            if expected not in found.get(name, set()):
                raise RuntimeError(f"QUIC mutation escaped: {name} ({expected})")
    print(f"QUIC production-source mutation checks: {len(variants)} detected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    result = run(args.semgrep, "--jobs", "1", "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip())
    scan(args.semgrep, SOURCE, require_clean=True)
    observations = admission_observations(args.semgrep, SOURCE, require_definitions=True)
    if observations:
        raise RuntimeError(f"Admission AST source violations: {observations}")
    mutations(args.semgrep)
    print("QUIC packet guard AST rules: passed (source, fixtures, mutations)")


if __name__ == "__main__":
    main()
