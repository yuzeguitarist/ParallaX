#!/usr/bin/env python3
"""Reviewed delayed-ACK syntax and AST-cardinality regression boundaries.

This checks shipping source and canonical-preserving production-method mutants;
it is not a general control-flow, alias or complete QUIC proof.
"""
import argparse
import json
from pathlib import Path
import tempfile

from check_crypto_rules import replace_once, run
from check_quic_key_phase import method

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/quic_ack.yml"
OBSERVATIONS = ROOT / ".github/semgrep/quic_ack_observe.yml"
SOURCE = ROOT / "src/transport/udp/quic/conn.rs"


def findings(semgrep, rules, target):
    result = run(semgrep, "--jobs", "1", "--strict", "--no-git-ignore", "--config", str(rules),
                 "--json", "--quiet", str(target))
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("version") != "1.182.1" or data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete or unpinned ACK scan: {data}")
    return data["results"]


def cardinality(semgrep, target, require_definitions=False):
    scopes = {"receive": {"schedule": 1}, "builder": {"reserve": 1, "record": 1},
              "ready": {"due": 1, "return": 1}}
    known = {f"observe-ack-{scope}-{kind}" for scope, effects in scopes.items()
             for kind in ("definition", *effects)}
    ranges = {}
    for finding in findings(semgrep, OBSERVATIONS, target):
        identifier = finding["check_id"].split(".")[-1]
        start, end = finding["start"]["offset"], finding["end"]["offset"]
        if identifier not in known or not isinstance(start, int) or not isinstance(end, int) or start >= end:
            raise RuntimeError(f"Invalid ACK AST observation: {finding}")
        ranges.setdefault((str(Path(finding["path"]).resolve()), identifier), set()).add((start, end))
    violations = {}
    for scope, effects in scopes.items():
        definition = f"observe-ack-{scope}-definition"
        paths = {path for path, identifier in ranges if identifier == definition}
        if require_definitions and paths != {str(Path(target).resolve())}:
            raise RuntimeError(f"Missing ACK production definition: {scope}")
        for path in paths:
            definitions = ranges[(path, definition)]
            if len(definitions) != 1:
                raise RuntimeError(f"Ambiguous ACK AST scope: {path}")
            low, high = next(iter(definitions))
            for effect, expected in effects.items():
                calls = ranges.get((path, f"observe-ack-{scope}-{effect}"), set())
                if any(not (low <= start and end <= high) for start, end in calls):
                    raise RuntimeError(f"ACK effect escaped its observed function: {path}")
                if len(calls) != expected:
                    policy = "ack-one-readiness-result" if scope == "ready" and effect == "return" else f"ack-one-{effect}"
                    violations.setdefault(Path(path).name, set()).add(policy)
    return violations


def mutations(semgrep):
    source = SOURCE.read_text()
    receive = method(source, "process_packet")
    schedule = method(source, "schedule_ack")
    builder = method(source, "build_ack_packet")
    sendable = method(source, "pending_data_ack_deadline")
    timeout = method(source, "next_timeout")
    poll = method(source, "poll_transmit_inner")
    count = method(source, "ack_count_after_packet")
    due = method(source, "ack_count_due")
    delay = method(source, "encoded_ack_delay")
    ready = method(source, "ack_ready_for_space")
    variants = {}
    variants["inverted_space_full_source.rs"] = (
        replace_once(source, ready, replace_once(ready, "space != SPACE_DATA", "space == SPACE_DATA")),
        "parallax-quic-ack-readiness-predicate",
    )

    def add(name, original, old, new, policy, impl=True):
        changed = replace_once(original, old, new)
        variants[name + ".rs"] = (("impl Connection {\n" + changed + "\n}" if impl else changed), policy)

    for name, old, new in (
        ("inverted_ready_space", "space != SPACE_DATA", "space == SPACE_DATA"),
        ("inverted_ready_confirmation", "!self.handshake_confirmed", "self.handshake_confirmed"),
        ("missing_ready_confirmation", "                || !self.handshake_confirmed\n", ""),
        ("inverted_ready_expiry", "now >= deadline", "now < deadline"),
        ("strict_ready_expiry", "now >= deadline", "now > deadline"),
        ("missing_ready_debt", "sp.ack_pending\n            && ", ""),
    ):
        add(name, ready, old, new, "parallax-quic-ack-readiness-predicate")
    canonical_start = ready.index("        sp.ack_pending\n")
    canonical = ready[canonical_start:ready.rfind("\n    }")].strip()
    for scope in ("plain", "if", "loop", "closure"):
        extra = "return sp.ack_pending;"
        if scope == "if":
            extra = "if space == SPACE_DATA { " + extra + " }"
        elif scope == "loop":
            extra = "for _ in 0..1 { " + extra + " }"
        elif scope == "closure":
            extra = "let _extra = || { " + extra + " };"
        add(f"canonical_retained_early_return_{scope}", ready, "        sp.ack_pending\n",
            "        " + extra + "\n        sp.ack_pending\n", "parallax-quic-ack-readiness-no-early-return")
        # Keep the original final predicate, but copy it into a separate scope
        # with a return. Both explicit-return and due-call AST counts must see it.
        duplicate = "return " + canonical + ";"
        if scope == "if":
            duplicate = "if space == SPACE_DATA { " + duplicate + " }"
        elif scope == "loop":
            duplicate = "for _ in 0..1 { " + duplicate + " }"
        elif scope == "closure":
            duplicate = "let _extra = || { " + duplicate + " };"
        add(f"duplicate_whole_ready_predicate_{scope}", ready, "        sp.ack_pending\n",
            "        " + duplicate + "\n        sp.ack_pending\n", "ack-one-due")
    add("early_return_before_ready_binding", ready, "        let sp =",
        "        return true;\n        let sp =", "parallax-quic-ack-readiness-no-early-return")
    add("readiness_result_cardinality", ready, "        sp.ack_pending\n",
        "        if space == SPACE_DATA { return sp.ack_pending; }\n        sp.ack_pending\n",
        "ack-one-readiness-result")

    call = "self.schedule_ack(space, ack_eliciting, immediate_ack, now);"
    add("missing_early_tp_validation", receive, "        self.prevalidate_peer_transport_params()?;\n", "", "parallax-quic-ack-legacy-immediate-policy")
    add("schedule_before_auth", receive, "        let local_cid_len =",
        "        " + call + "\n        let local_cid_len =", "parallax-quic-ack-schedule-after-admission")
    for position, anchor in (("before", "        let local_cid_len ="),
                             ("after", "        self.last_recv_time = Some(now);")):
        for field, value in (("ack_pending", "true"), ("ack_eliciting_count", "2"), ("ack_deadline", "Some(now)")):
            write = f"self.spaces[space].{field} = {value};"
            for nested in (False, True):
                extra = ("if !pkt.is_empty() { " + write + " }" if nested else write)
                add(f"extra_{field}_{position}_{nested}", receive, anchor, "        " + extra + "\n" + anchor,
                    "parallax-quic-ack-no-direct-receive-write")
    for scope in ("plain", "if", "loop", "closure"):
        extra = call
        if scope == "if":
            extra = "if !pkt.is_empty() { " + call + " }"
        elif scope == "loop":
            extra = "for _ in 0..1 { " + call + " }"
        elif scope == "closure":
            extra = "let _extra = || { " + call + " };"
        add(f"duplicate_whole_schedule_{scope}", receive, "        self.pump_write();",
            "        " + extra + "\n        self.pump_write();", "ack-one-schedule")
    for name, old, new in (
        ("ack_of_ack", "        if !ack_eliciting {\n            return;\n        }\n", ""),
        ("deadline_postponed", "old.min(deadline)", "old.max(deadline)"),
        ("deadline_restarted", "Some(sp.ack_deadline.map_or(deadline, |old| old.min(deadline)))", "Some(deadline)"),
        ("pure_ack_counted", "ack_count_after_packet(sp.ack_eliciting_count, ack_eliciting, immediate)", "ack_count_after_packet(sp.ack_eliciting_count, true, immediate)"),
    ):
        add(name, schedule, old, new, "parallax-quic-ack-bounded-earliest-schedule")
    add("early_pn", schedule, "        let sp =", "        self.allocate_packet_number(space);\n        let sp =",
        "parallax-quic-ack-no-timer-seal-or-probe")
    add("ack_timer_pto", schedule, "        let sp =", "        self.queue_probe();\n        let sp =",
        "parallax-quic-ack-no-timer-seal-or-probe")
    add("wrapping_count", count, "saturating_add(1)", "wrapping_add(1)", "parallax-quic-ack-count-and-due", False)
    add("missing_tail_due", due, " || (count != 0 && expired)", "", "parallax-quic-ack-count-and-due", False)
    for name, old in (("no_key_spin", "            || sp.keys.is_none()\n"),
                      ("amp_spin", "            || (!self.peer_addr_validated\n                && self.anti_amp_sent.saturating_add(MAX_DATAGRAM as u64)\n                    > self.anti_amp_recv.saturating_mul(3))\n")):
        add(name, sendable, old, "", "parallax-quic-ack-sendable-timer")
    timer = """        if let Some(ack) = self.pending_data_ack_deadline() {
            earliest(ack);
        }
"""
    add("missing_timer_connection", timeout, timer, "", "parallax-quic-ack-timeout-connected")
    add("immediate_every_packet", poll, "self.ack_ready_for_space(space, now)", "self.spaces[space].ack_pending",
        "parallax-quic-ack-poll-before-congestion")
    add("discard_largest_stamp", builder, "        self.spaces[space].ack_pending = false;",
        "        self.spaces[space].largest_recv_time = None;\n        self.spaces[space].ack_pending = false;",
        "parallax-quic-ack-retain-largest-stamp")
    add("eliciting_ack", builder, "            false,\n            SentContent::default(),", "            true,\n            SentContent::default(),",
        "parallax-quic-ack-builder-fresh-current-key")
    add("stale_debt", builder, "        self.spaces[space].ack_deadline = None;\n", "",
        "parallax-quic-ack-builder-fresh-current-key")
    add("clipped_wire_delay", delay, "elapsed.as_micros()", "elapsed.min(MAX_ACK_DELAY).as_micros()",
        "parallax-quic-ack-wire-delay", False)
    add("new_generation_pure_ack_forced", receive, call,
        "self.schedule_ack(space, ack_eliciting || read_generation == Some(ReadGeneration::Next), immediate_ack, now);",
        "parallax-quic-ack-legacy-immediate-policy")

    with tempfile.TemporaryDirectory(prefix="parallax-quic-ack-") as temporary:
        for name, (content, _) in variants.items():
            (Path(temporary) / name).write_text(content)
        found = {}
        for finding in findings(semgrep, RULES, temporary):
            found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
        counted = cardinality(semgrep, temporary)
        count_only = sum(policy in counted.get(name, set()) and not found.get(name, set())
                         for name, (_, policy) in variants.items())
        for name, policies in counted.items():
            found.setdefault(name, set()).update(policies)
        for name, (_, policy) in variants.items():
            if policy not in found.get(name, set()):
                raise RuntimeError(f"ACK production-method mutation escaped: {name} ({policy})")
    print(f"QUIC ACK production-method mutations: {len(variants)} detected ({count_only} require AST cardinality)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    result = run(args.semgrep, "--jobs", "1", "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip())
    actual = findings(args.semgrep, RULES, SOURCE)
    counts = cardinality(args.semgrep, SOURCE, require_definitions=True)
    if actual or counts:
        raise RuntimeError(f"QUIC ACK source guard violations: {actual}, {counts}")
    mutations(args.semgrep)
    print("QUIC ACK guards passed (source, fixtures, AST cardinality, mutations)")


if __name__ == "__main__":
    main()
