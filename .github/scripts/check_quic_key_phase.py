#!/usr/bin/env python3
"""Check reviewed QUIC key-phase boundaries and production-method mutations.

These are syntactic regression guards, not a general Rust control-flow proof.
Kani covers the shipping metadata/allocation helpers; encrypted Connection tests
cover TLS, AEAD, loss and reordering. No PCS or full protocol theorem is claimed.
"""

import argparse
import json
from pathlib import Path
import tempfile

from check_crypto_rules import replace_once, run


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/quic_key_phase.yml"
OBSERVATIONS = ROOT / ".github/semgrep/quic_key_phase_observe.yml"
SOURCE = ROOT / "src/transport/udp/quic/conn.rs"
SPACES = ROOT / "src/transport/udp/quic/spaces.rs"
SUITE = ROOT / "src/tls/quic/suite.rs"
CANONICAL = ROOT / ".github/semgrep/quic_key_phase_canonical.rs"
REVIEWED_CLOSE_SCOPES = {
    "close": "build_close_packet",
    "close-size": "close_packet_size",
    "close-space": "build_close_packet_in_space",
}


def scan(semgrep, *targets, require_clean=False):
    result = run(semgrep, "--jobs", "1", "--strict", "--no-git-ignore", "--config", str(RULES),
                 "--json", "--quiet", *(str(target) for target in targets))
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("version") != "1.182.1":
        raise RuntimeError("QUIC key-phase guards require Semgrep 1.182.1")
    if data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete key-phase scan: {data}")
    if require_clean and data["results"]:
        raise RuntimeError(f"Key-phase violations: {data['results']}")
    return data["results"]


def effect_cardinality(semgrep, target, require_definitions=False):
    """Check complete reviewed scopes and count direct effect AST nodes.

    This is an assertion over direct call sites, including nested scopes. It
    does not prove runtime counts, alias resolution or arbitrary helper effects.
    """
    scopes = {
        "receive": {"commit": (1, "quic-one-generation-commit"), "derive": (0, "quic-no-receive-derivation")},
        "close": {"build": (1, "quic-one-close-batch-build"), "effect": (0, "quic-no-early-close-effect")},
        "close-space": {"allocate": (1, "quic-one-close-reservation"), "seal": (1, "quic-one-close-seal")},
        "close-size": {},
    }
    result = run(semgrep, "--jobs", "1", "--strict", "--no-git-ignore", "--config", str(OBSERVATIONS),
                 "--json", "--quiet", str(target))
    if result.returncode:
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("version") != "1.182.1" or data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete QUIC effect observations: {data}")
    known = {f"observe-quic-{scope}-{kind}" for scope, effects in scopes.items()
             for kind in ("definition", *effects)}
    ranges = {}
    for finding in data["results"]:
        identifier = finding["check_id"].split(".")[-1]
        if identifier not in known:
            raise RuntimeError(f"Unexpected QUIC observation: {identifier}")
        start, end = finding["start"]["offset"], finding["end"]["offset"]
        if not isinstance(start, int) or not isinstance(end, int) or start >= end:
            raise RuntimeError(f"Invalid QUIC AST range: {finding}")
        path = str(Path(finding["path"]).resolve())
        ranges.setdefault((path, identifier), set()).add((start, end))
    violations = {}
    for scope, effects in scopes.items():
        definition_id = f"observe-quic-{scope}-definition"
        paths = {path for path, identifier in ranges if identifier == definition_id}
        if require_definitions and paths != {str(Path(target).resolve())}:
            raise RuntimeError(f"Missing complete QUIC production definition: {scope}")
        for path in paths:
            definitions = ranges[(path, definition_id)]
            if len(definitions) != 1:
                raise RuntimeError(f"Ambiguous QUIC AST definition: {path} ({scope})")
            start, end = next(iter(definitions))
            if scope in REVIEWED_CLOSE_SCOPES:
                # Compare the COMPLETE function AST span to the reviewed source,
                # not a canonical subtree Semgrep may find inside a block with
                # extra effects. This deliberately pins these three small close
                # scopes, including the size/reason plan and all preflight order.
                # It is a syntactic regression policy, not general alias/CFG proof.
                canonical = method(CANONICAL.read_text(), REVIEWED_CLOSE_SCOPES[scope]).strip()
                actual = Path(path).read_bytes()[start:end].decode().strip()
                if actual != canonical:
                    violations.setdefault(Path(path).name, set()).add(f"quic-reviewed-{scope}-scope")
            for kind, (expected, policy) in effects.items():
                calls = ranges.get((path, f"observe-quic-{scope}-{kind}"), set())
                if any(not (start <= call_start and call_end <= end) for call_start, call_end in calls):
                    raise RuntimeError(f"Unscoped QUIC AST effect: {path} ({kind})")
                if len(calls) != expected:
                    violations.setdefault(Path(path).name, set()).add(policy)
    return violations


def method(source, name):
    """Retain the complete shipping method, including any nested blocks.

    Skip comments/string contents while balancing braces. Methods are never
    rewritten to simplified pseudocode before mutation.
    """
    signature = source.index(f"fn {name}(")
    start = source.rfind("\n", 0, signature) + 1
    pos = source.index("{", start)
    depth = 0
    comment_depth = 0
    quoted = False
    while pos < len(source):
        if comment_depth:
            if source.startswith("/*", pos):
                comment_depth += 1
                pos += 2
            elif source.startswith("*/", pos):
                comment_depth -= 1
                pos += 2
            else:
                pos += 1
            continue
        if quoted:
            if source[pos] == "\\":
                pos += 2
                continue
            if source[pos] == '"':
                quoted = False
        elif source.startswith("//", pos):
            pos = source.index("\n", pos)
            continue
        elif source.startswith("/*", pos):
            comment_depth = 1
            pos += 2
            continue
        elif source[pos] == '"':
            quoted = True
        elif source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
        pos += 1
    raise RuntimeError(f"Unbalanced production method: {name}")


def mutations(semgrep):
    source = SOURCE.read_text()
    receive = method(source, "process_packet")
    opener = method(source, "open_data_packet")
    install = method(source, "install_send_key")
    active = method(source, "active_successor")
    confirmation = method(source, "confirm")
    response = method(source, "valid_receive")
    dedup = """        if !self.spaces[space].recv.insert(header.packet_number()) {
            return Ok(());
        }
"""
    variants = {}

    def add(name, original, mutated, expected, owner="Connection"):
        if original == mutated:
            raise RuntimeError(f"No-op mutation: {name}")
        variants[name + ".rs"] = (f"impl {owner} {{\n{mutated}\n}}\n", expected)

    phase_check_start = receive.index("        if let Some(generation) = read_generation {")
    phase_check_end = receive.index("        // Only a new authenticated packet", phase_check_start)
    phase_check = receive[phase_check_start:phase_check_end]
    add("missing_frontier", receive, replace_once(receive, phase_check, ""),
        "parallax-quic-phase-receive-gates")
    add("missing_global_dedup", receive, replace_once(receive, dedup, ""),
        "parallax-quic-phase-receive-gates")
    handshake_gate = """        if pspace == PacketSpace::OneRtt && self.tls.is_handshaking() {
            return Ok(());
        }
"""
    add("missing_finished_gate", receive, replace_once(receive, handshake_gate, ""),
        "parallax-quic-phase-handshake-receive-boundary")
    add("role_limited_finished_gate", receive, replace_once(receive,
        "if pspace == PacketSpace::OneRtt && self.tls.is_handshaking()",
        "if self.side == Side::Server && pspace == PacketSpace::OneRtt && self.tls.is_handshaking()"),
        "parallax-quic-phase-handshake-receive-boundary")
    add("expected_reply_rejected", response, replace_once(response,
        "(!self.update_ack_pending || self.rx.checked_add(1) == Some(self.tx))", "!self.update_ack_pending"),
        "parallax-quic-phase-expected-response-gate", "KeyPhaseState")
    add("unsolicited_update_allowed", response, replace_once(response,
        "(!self.update_ack_pending || self.rx.checked_add(1) == Some(self.tx))", "true"),
        "parallax-quic-phase-expected-response-gate", "KeyPhaseState")

    close = method(source, "build_close_packet")
    close_space = method(source, "build_close_packet_in_space")
    close_frame = method(source, "close_frame")
    preflight_start = close.index("        if spaces\n            .iter()")
    preflight_end = close.index("        let mtu =", preflight_start)
    preflight = close[preflight_start:preflight_end]
    add("missing_whole_close_pn_preflight", close, replace_once(close, preflight, ""),
        "parallax-quic-phase-handshake-close-batch")
    add("confirmed_lower_close", close, replace_once(close, "let mut spaces = if !self.handshake_confirmed", "let mut spaces = if true"),
        "parallax-quic-phase-handshake-close-batch")
    for kind, extra in (("allocate", "self.allocate_packet_number(SPACE_HANDSHAKE);"),
                        ("seal", "seal_packet(keys, header, frames);")):
        add(f"close_effect_before_preflight_{kind}", close, replace_once(close,
            preflight, "        " + extra + "\n" + preflight), "quic-no-early-close-effect")
    loop_start = close.index("        for space in spaces {")
    loop_end = close.index("        self.close_sent = true;", loop_start)
    extra_loop = close[loop_start:loop_end].replace("for space in spaces", "for space in spaces.clone()")
    for scope in ("plain", "if", "loop", "closure"):
        extra = extra_loop
        if scope == "if":
            extra = "        if !spaces.is_empty() {\n" + extra + "        }\n"
        elif scope == "loop":
            extra = "        for _ in 0..1 {\n" + extra + "        }\n"
        elif scope == "closure":
            extra = "        let _extra = || -> Option<()> {\n" + extra + "Some(())\n};\n"
        add(f"duplicate_close_builder_{scope}", close, replace_once(close,
            "        let mut datagram = Vec::new();", "        let mut datagram = Vec::new();\n" + extra),
            "quic-one-close-batch-build")
    add("direct_close_missing_budget", close_space, replace_once(close_space,
        "        self.enforce_aead_confidentiality_limit();\n", ""),
        "parallax-quic-phase-explicit-close-space-budget")
    add("direct_close_after_confirmation", close_space, replace_once(close_space,
        "            || (self.handshake_confirmed && space != SPACE_DATA)\n", ""),
        "parallax-quic-phase-explicit-close-space-budget")
    add("lower_application_reason_leak", close_frame, replace_once(close_frame,
        "reason: &[]", "reason"), "parallax-quic-phase-close-frame-level")

    # New close-plan regressions use the COMPLETE Connection source. In
    # particular, additive cases preserve all canonical blocks and insert a
    # second state/plan mutation before or after them. Complete AST-scope pins
    # complement the older shape rules and effect counts without removing any
    # existing mutants.
    def add_full(name, original, mutated, expected):
        if original == mutated:
            raise RuntimeError(f"No-op complete-source mutation: {name}")
        variants[name + ".rs"] = (replace_once(source, original, mutated), expected)

    for name, old, new in (
        ("server_missing_initial_close", "self.side == Side::Server && available(SPACE_INITIAL)", "self.side == Side::Client && available(SPACE_INITIAL)"),
        ("missing_mandatory_handshake_close", "if available(SPACE_HANDSHAKE)", "if false && available(SPACE_HANDSHAKE)"),
        ("discarded_keys_become_candidates", "!self.spaces[space].discarded && self.spaces[space].keys.is_some()", "self.spaces[space].keys.is_some()"),
        ("mandatory_count_drops_handshake", "let mandatory = spaces.len().max(1);", "let mandatory = 1;"),
        ("truncate_mandatory_handshake", "spaces.truncate(mandatory);", "spaces.truncate(1);"),
        ("close_unchecked_size_sum", "total.checked_add(self.close_packet_size(space, code, frame_type, reason))", "Some(total + self.close_packet_size(space, code, frame_type, reason))"),
        ("preflight_wrong_wire_reason", "let mut size = batch_size(&spaces, &reason)?;", "let mut size = batch_size(&spaces, &[])?;"),
        ("missing_size_after_optional_drop", "            size = batch_size(&spaces, &reason)?;\n", ""),
        ("missing_empty_reason_size", "            size = batch_size(&spaces, &[])?;\n", ""),
        ("shortened_size_but_original_wire_reason", "            self.close_pending.as_mut()?.2.clear();\n", ""),
        ("reason_shortening_loses_handshake", "spaces.as_slice() == [SPACE_INITIAL, SPACE_HANDSHAKE]", "spaces.as_slice() == [SPACE_INITIAL]"),
        ("ignore_final_total_mtu", "        if size > mtu {", "        if false && size > mtu {"),
        ("ignore_final_anti_amplification", "        if !self.peer_addr_validated\n", "        if false && !self.peer_addr_validated\n"),
    ):
        add_full(name, close, replace_once(close, old, new), "quic-reviewed-close-scope")
    for name, anchor, extra in (
        ("canonical_extra_early_budget_reset", "        self.enforce_aead_confidentiality_limit();", "self.data_packets_sealed = 0;"),
        ("canonical_drop_data_before_pn_preflight", "        if spaces\n            .iter()", "spaces.retain(|&space| space != SPACE_DATA);"),
        ("canonical_drop_handshake_after_preflight", "        let mtu =", "spaces.retain(|&space| space != SPACE_HANDSHAKE);"),
        ("canonical_extra_truncate_after_preflight", "        let mut datagram =", "spaces.truncate(1);"),
        ("canonical_extra_space_after_preflight", "        let mut datagram =", "spaces.push(SPACE_DATA);"),
        ("canonical_shadow_size", "        if size > mtu {", "let size = 0usize;"),
        ("canonical_shadow_reason", "        let batch_size =", "let reason = Vec::new();"),
        ("canonical_change_wire_reason_after_preflight", "        let mut datagram =", "self.close_pending.as_mut()?.2.push(b'x');"),
        ("canonical_nested_change_wire_reason", "        let mut datagram =", 'if !spaces.is_empty() { self.close_pending.as_mut()?.2.extend_from_slice(b"extra"); }'),
        ("canonical_revoke_local_close", "        let mut datagram =", "self.closed.take();"),
        ("canonical_change_anti_amp_credit", "        if !self.peer_addr_validated\n", "self.anti_amp_recv = u64::MAX;"),
        ("canonical_nested_space_mutation", "        let mut datagram =", "if self.side == Side::Server { spaces.truncate(1); }"),
        ("canonical_closure_plan_mutation", "        let mut datagram =", "let mut change = || spaces.truncate(1); change();"),
    ):
        add_full(name, close, replace_once(close, anchor, "        " + extra + "\n" + anchor), "quic-reviewed-close-scope")
    add_full("canonical_pn_check_after_sealing", close,
        replace_once(replace_once(close, preflight, ""), "        self.close_sent = true;", preflight + "        self.close_sent = true;"),
        "quic-reviewed-close-scope")
    close_size = method(source, "close_packet_size")
    for name, old, new in (
        ("size_omits_padding", ".checked_add(3)", ".checked_add(0)"),
        ("size_overflow_accepts_zero", ".unwrap_or(usize::MAX)", ".unwrap_or(0)"),
        ("size_uses_different_close", "Self::close_frame(space, code, frame_type, reason)", "Self::close_frame(space, 0, frame_type, &[])"),
        ("canonical_size_extra_tail", "            .unwrap_or(usize::MAX)", "            .unwrap_or(usize::MAX)\n            .saturating_sub(20)"),
    ):
        add_full(name, close_size, replace_once(close_size, old, new), "quic-reviewed-close-size-scope")
    for name, anchor, extra in (
        ("canonical_sealer_different_reason", "        let pn =", "let reason = Vec::new();"),
        ("canonical_sealer_extra_pending_reason", "        let pn =", "self.close_pending.as_mut()?.2.push(b'x');"),
        ("canonical_sealer_reenable_discarded_keys", "        self.enforce_aead_confidentiality_limit();", "self.spaces[space].discarded = false;"),
    ):
        add_full(name, close_space, replace_once(close_space, anchor, "        " + extra + "\n" + anchor), "quic-reviewed-close-space-scope")

    canonical_start = receive.index("        let receive_generation = if let Some(generation) = read_generation {")
    canonical_end = receive.index("        // Refresh idle", canonical_start)
    canonical = receive[canonical_start:canonical_end].replace("let receive_generation =", "let _extra_generation =")
    for position, anchor in (("before", "        let local_cid_len ="),
                             ("after", "        self.last_recv_time = Some(now);")):
        for scope in ("plain", "if", "loop", "closure"):
            extra = canonical
            if scope == "if":
                extra = "        if !pkt.is_empty() {\n" + canonical + "        }\n"
            elif scope == "loop":
                extra = "        for _ in 0..1 {\n" + canonical + "        }\n"
            elif scope == "closure":
                extra = "        let _extra = || -> Result<(), QuicTlsError> {\n" + canonical + "Ok(())\n};\n"
            add(f"whole_canonical_commit_{position}_{scope}", receive,
                replace_once(receive, anchor, extra + anchor), "quic-one-generation-commit")
            derive = "self.tls.next_1rtt_keys();"
            if scope == "if":
                derive = "if !pkt.is_empty() { " + derive + " }"
            elif scope == "loop":
                derive = "for _ in 0..1 { " + derive + " }"
            elif scope == "closure":
                derive = "let _extra = || { " + derive + " };"
            add(f"receive_derivation_{position}_{scope}", receive,
                replace_once(receive, anchor, "        " + derive + "\n" + anchor), "quic-no-receive-derivation")

    # Preserve the entire canonical commit path while adding illegal writes at
    # both sides of it, including nested and failed-authentication branches.
    for position, anchor, indent, nested in (
        ("before_auth", "        let local_cid_len =", "        ", False),
        ("before_dedup", dedup, "        ", False),
        ("failed_auth", "                return Ok(()); // undecryptable: drop, do NOT fail the connection", "                ", False),
        ("nested_before_auth", "        let local_cid_len =", "        ", True),
        ("after_commit", "        self.last_recv_time = Some(now);", "        ", False),
        ("nested_after_commit", "        self.last_recv_time = Some(now);", "        ", True),
    ):
        for field, write in (
            ("generation", "self.key_phase.rx = 9;"),
            ("cache", "self.next_packet_keys = None;"),
        ):
            inserted = (indent + "if !pkt.is_empty() {\n" + indent + "    " + write + "\n" + indent + "}\n"
                        if nested else indent + write + "\n")
            add(f"extra_{field}_{position}", receive,
                replace_once(receive, anchor, inserted + anchor),
                "parallax-quic-phase-no-direct-receive-mutation")
    for position, anchor in (("before", "        let local_cid_len ="),
                             ("after", "        self.last_recv_time = Some(now);")):
        add(f"duplicate_commit_{position}", receive,
            replace_once(receive, anchor, "        self.commit_data_generation(ReadGeneration::Next, 42, now)?;\n" + anchor),
            "parallax-quic-phase-single-commit")

    for position, anchor in (("before", "        let next ="),
                             ("after", "        self.next_update_at = None;")):
        for nested in (False, True):
            reset = ("        if generation > 0 { self.data_packets_open_failed = 0; }\n" if nested
                     else "        self.data_packets_open_failed = 0;\n")
            add(f"reset_integrity_{position}_{nested}", install,
                replace_once(install, anchor, reset + anchor),
                "parallax-quic-phase-cumulative-integrity")
    add("reset_budget_before_install", install,
        replace_once(install, "        let next =", "        self.data_packets_sealed = 0;\n        let next ="),
        "parallax-quic-phase-confidentiality-reset-after-key")
    add("reset_budget_after_canonical", install,
        replace_once(install, "        self.next_update_at = None;",
                     "        self.data_packets_sealed = 0;\n        self.next_update_at = None;"),
        "parallax-quic-phase-confidentiality-reset-after-key")
    for field, write in (("pn", "self.spaces[SPACE_DATA].send = PacketNumberSpace::default();"),
                         ("replay", "self.spaces[SPACE_DATA].recv = ReceivedPackets::default();")):
        add(f"reset_{field}", install,
            replace_once(install, "        let next =", "        " + write + "\n        let next ="),
            "parallax-quic-phase-global-pn-and-replay")
    header = "        let opened = unprotect_packet_header(&keys.remote.header, pkt, local_cid_len, largest)?;"
    payload = "        let range = open_packet_payload(selected.unwrap_or(&keys.remote.packet), pkt, &opened)?;"
    add("double_header", opener, replace_once(opener, header,
        header + "\n        let again = unprotect_packet_header(&keys.remote.header, pkt, local_cid_len, largest)?;"),
        "parallax-quic-phase-single-header-and-aead")
    add("double_payload", opener, replace_once(opener, payload,
        payload + "\n        let again = open_packet_payload(selected.unwrap_or(&keys.remote.packet), pkt, &opened)?;"),
        "parallax-quic-phase-single-header-and-aead")
    add("nested_double_header", opener, replace_once(opener, header,
        header + "\n        if !pkt.is_empty() {\n            let again = unprotect_packet_header(&keys.remote.header, pkt, local_cid_len, largest)?;\n        }"),
        "parallax-quic-phase-single-header-and-aead")
    add("nested_double_payload", opener, replace_once(opener, payload,
        payload + "\n        if !pkt.is_empty() {\n            let again = open_packet_payload(selected.unwrap_or(&keys.remote.packet), pkt, &opened)?;\n        }"),
        "parallax-quic-phase-single-header-and-aead")
    for kind, extra in (("mutating_retry", "open_packet(&keys.remote, pkt, local_cid_len, largest);"),
                        ("derive_on_forged_phase", "self.tls.next_1rtt_keys();")):
        add(kind, opener, replace_once(opener, header, "        " + extra + "\n" + header),
            "parallax-quic-phase-single-header-and-aead")
    add("rotate_hp", install, replace_once(install,
        "        self.key_phase.tx = generation;",
        "        self.spaces[SPACE_DATA].keys.as_mut().unwrap().local.header = hp;\n        self.key_phase.tx = generation;"),
        "parallax-quic-phase-no-hp-rotation")
    for name, old, new in (
        ("without_confirmed", "confirmed && ", ""),
        ("without_ack", " && self.tx_acked", ""),
        ("wrapping_generation", "self.tx.checked_add(1)", "Some(self.tx.wrapping_add(1))"),
    ):
        add(name, active, replace_once(active, old, new), "parallax-quic-phase-active-successor", "KeyPhaseState")
    for name, old, new in (
        ("old_ack_confirms", "receive_generation < self.tx || ", ""),
        ("unrelated_pn_confirms", "!covered", "false"),
    ):
        add(name, confirmation, replace_once(confirmation, old, new), "parallax-quic-phase-ack-confirmation", "KeyPhaseState")
    retiring = method(source, "retire_previous_read_key")
    add("extend_retirement", retiring, replace_once(retiring,
        "        if self", "        previous.retire_at = now + self.drain_duration();\n        if self"),
        "parallax-quic-phase-fixed-retirement")
    allocation = method(source, "allocate_packet_number")
    add("raw_pn_reservation", allocation, replace_once(allocation,
        "        let (sealed, limit)", "        self.spaces[SPACE_DATA].send.allocate();\n        let (sealed, limit)"),
        "parallax-quic-phase-protected-allocation")
    extract = method(SUITE.read_text(), "hkdf_extract")
    for hash_name in ("Sha384", "Sha256"):
        copy = f"""                let (mut prk, _) = Hkdf::<{hash_name}>::extract(Some(salt), ikm);
                let result = prk.to_vec();
                prk.as_mut_slice().zeroize();
"""
        add(f"unwiped_extract_{hash_name}", extract,
            replace_once(extract, copy, copy.replace("                prk.as_mut_slice().zeroize();\n", "")),
            "parallax-quic-hkdf-extract-prk-wipe", "CipherSuite")
    with tempfile.TemporaryDirectory(prefix="parallax-quic-phase-") as temporary:
        batches = []
        for index, (name, (mutated, _)) in enumerate(variants.items()):
            directory = Path(temporary) / f"batch-{index // 8:03d}"
            if directory not in batches:
                directory.mkdir()
                batches.append(directory)
            (directory / name).write_text(mutated)
        found, cardinality = {}, {}
        # Bound scan work per subprocess, not its checks. Every complete source
        # mutant is scanned by both rule and observation configs and checked by
        # name below; errors/timeouts still fail rather than skip a batch.
        for directory in batches:
            for finding in scan(semgrep, directory):
                found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
            cardinality.update(effect_cardinality(semgrep, directory))
        cardinality_only = sum(expected in cardinality.get(name, set()) and expected not in found.get(name, set())
                               for name, (_, expected) in variants.items())
        for name, policies in cardinality.items():
            found.setdefault(name, set()).update(policies)
        for name, (_, expected) in variants.items():
            if expected not in found.get(name, set()):
                raise RuntimeError(f"Key-phase production-method mutation escaped: {name} ({expected})")
    print(f"QUIC key-phase production-method mutation checks: {len(variants)} detected in {len(batches)} fixed batches "
          f"({len(cardinality)} trigger AST scope/count checks; {cardinality_only} require companion assertions)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    result = run(args.semgrep, "--jobs", "1", "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip())
    scan(args.semgrep, SOURCE, SPACES, SUITE, require_clean=True)
    effects = effect_cardinality(args.semgrep, SOURCE, require_definitions=True)
    if effects:
        raise RuntimeError(f"QUIC production AST cardinality violations: {effects}")
    mutations(args.semgrep)
    print("QUIC key-phase AST guards: passed (source, fixtures, mutations)")


if __name__ == "__main__":
    main()
