#!/usr/bin/env python3
"""Peer ACK parameter syntax, direct-effect cardinality and source mutations.

The guards supplement encrypted Connection tests and scoped Kani proofs. They
do not establish arbitrary alias/control-flow or complete QUIC conformance.
Initializer checks focus complete field-expression AST nodes within one complete
Self expression and function, then compare the entire captured source span.
Explicit early-return spellings also use lexical checks inside AST scopes.
"""
import argparse
from pathlib import Path
import tempfile

from check_crypto_rules import replace_once, run
from check_quic_ack import findings
from check_quic_key_phase import method

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/peer_ack.yml"
OBSERVATIONS = ROOT / ".github/semgrep/peer_ack_observe.yml"
SOURCE = ROOT / "src/transport/udp/quic/conn.rs"
PARAMETERS = ROOT / "src/transport/udp/quic/transport_params.rs"

# Each count covers the entire function, including nested scopes and closures.
# Semgrep return nodes include Rust expression tails and closure result paths.
SCOPES = {
    # Semgrep normalizes three returns here; its let-else return is observed
    # separately as the complete missing-input branch, never silently omitted.
    "prevalidate": ("prevalidate_peer_transport_params", {"read": 1, "validated": 1, "getter": 1, "close": 1, "return": 3, "missing": 1, "reason": 1}),
    "apply": ("apply_authenticated_peer_ack_params", {"read": 1, "exponent": 1, "maximum": 1, "applied": 1, "return": 4, "authenticated": 1}),
    "decode": ("decoded_ack_delay", {"duration": 1, "return": 1}),
    "cap": ("cap_decoded_peer_ack_delay", {"clamp": 1, "return": 3}),
    "wrapper": ("ack_delay_for_recovery", {"decode": 1, "cap": 1}),
    "eligible": ("pto_space_eligible", {"return": 1}),
    "extra": ("peer_ack_delay_for_pto", {"return": 2}),
    "receive": ("process_packet", {"apply": 1, "prevalidate": 1}),
    "rtt": ("recv_ack", {"delay": 1, "update": 1}),
    "pto": ("pto_duration", {"extra": 1}),
    "drain": ("drain_duration", {"extra": 1}),
    "next": ("next_timeout", {"eligible": 1}),
    "timeout": ("handle_timeout", {"eligible": 1}),
    "probe": ("queue_probe", {"eligible": 1}),
    "parser": ("read", {"exponent": 1, "maximum": 1}),
}

INITIALIZERS = {
    "connection": ("new_inner", {
        "peer_ack_delay_exponent": "ACK_DELAY_EXPONENT",
        "peer_max_ack_delay": "MAX_ACK_DELAY",
        "peer_ack_params_applied": "false",
        "peer_transport_params_prevalidated": "false",
    }),
    "parser": ("read", {
        "ack_delay_exponent": "DEFAULT_ACK_DELAY_EXPONENT",
        "max_ack_delay_ms": "DEFAULT_MAX_ACK_DELAY_MS",
    }),
    "safari": ("safari_client", {
        "ack_delay_exponent": "DEFAULT_ACK_DELAY_EXPONENT",
        "max_ack_delay_ms": "DEFAULT_MAX_ACK_DELAY_MS",
    }),
    "server": ("server", {
        "ack_delay_exponent": "DEFAULT_ACK_DELAY_EXPONENT",
        "max_ack_delay_ms": "DEFAULT_MAX_ACK_DELAY_MS",
    }),
}


def initializer_expressions(observations, target, require_definitions=False):
    """Validate complete AST-focused expression spans, never token prefixes.

    The field schema is explicit in the pinned Semgrep patterns. Exactly one
    complete owner/struct/value is required; adding a canonical decoy cannot
    excuse another initializer. This does not resolve aliases or later writes.
    """
    prefix = "observe-peer-ack-initial-"
    known = {f"{prefix}{scope}-{kind}" for scope, (_, fields) in INITIALIZERS.items()
             for kind in ("definition", "expression", *fields)}
    ranges, contents = {}, {}
    for finding in observations:
        identifier = finding["check_id"].split(".")[-1]
        if not identifier.startswith(prefix):
            continue
        low, high = finding["start"]["offset"], finding["end"]["offset"]
        if identifier not in known or not isinstance(low, int) or not isinstance(high, int) or low >= high:
            raise RuntimeError(f"Invalid initializer AST observation: {finding}")
        path = str(Path(finding["path"]).resolve())
        ranges.setdefault((path, identifier), set()).add((low, high))
    required = set(INITIALIZERS) - {"connection"} if Path(target).resolve() == PARAMETERS else {"connection"}
    violations = {}
    for scope, (_, fields) in INITIALIZERS.items():
        definition = f"{prefix}{scope}-definition"
        paths = {path for path, identifier in ranges if identifier == definition}
        if require_definitions and scope in required and paths != {str(Path(target).resolve())}:
            raise RuntimeError(f"Missing initializer owner: {scope}")
        for path in paths:
            definitions = ranges[(path, definition)]
            structures = ranges.get((path, f"{prefix}{scope}-expression"), set())
            if len(definitions) != 1 or len(structures) != 1:
                violations.setdefault(Path(path).name, set()).add("peer-ack-initializer-expression")
                continue
            fn_low, fn_high = next(iter(definitions))
            struct_low, struct_high = next(iter(structures))
            if not (fn_low <= struct_low < struct_high <= fn_high):
                raise RuntimeError(f"Initializer escaped its owner: {path} {scope}")
            if path not in contents:
                contents[path] = Path(path).read_bytes()
            for field, expected in fields.items():
                expressions = ranges.get((path, f"{prefix}{scope}-{field}"), set())
                if len(expressions) != 1:
                    violations.setdefault(Path(path).name, set()).add("peer-ack-initializer-expression")
                    continue
                low, high = next(iter(expressions))
                if not (struct_low <= low < high <= struct_high <= len(contents[path])):
                    raise RuntimeError(f"Initializer field escaped its complete struct: {path} {field}")
                if contents[path][low:high].strip() != expected.encode("ascii"):
                    violations.setdefault(Path(path).name, set()).add("peer-ack-initializer-expression")
    return violations


def cardinality(semgrep, target, require_definitions=False):
    known = {f"observe-peer-ack-{scope}-{kind}" for scope, (_, effects) in SCOPES.items()
             for kind in ("definition", *effects)}
    ranges = {}
    observations = findings(semgrep, OBSERVATIONS, target)
    for finding in observations:
        identifier = finding["check_id"].split(".")[-1]
        if identifier.startswith("observe-peer-ack-initial-"):
            continue
        low, high = finding["start"]["offset"], finding["end"]["offset"]
        if identifier not in known or not isinstance(low, int) or not isinstance(high, int) or low >= high:
            raise RuntimeError(f"Invalid peer ACK observation: {finding}")
        ranges.setdefault((str(Path(finding["path"]).resolve()), identifier), set()).add((low, high))
    required = {"parser"} if Path(target).resolve() == PARAMETERS else set(SCOPES) - {"parser"}
    violations = {}
    for scope, (_, effects) in SCOPES.items():
        definition = f"observe-peer-ack-{scope}-definition"
        paths = {path for path, identifier in ranges if identifier == definition}
        if require_definitions and scope in required and paths != {str(Path(target).resolve())}:
            raise RuntimeError(f"Missing complete peer ACK function: {scope}")
        for path in paths:
            definitions = ranges[(path, definition)]
            if len(definitions) != 1:
                raise RuntimeError(f"Ambiguous peer ACK function: {path} {scope}")
            low, high = next(iter(definitions))
            for kind, expected in effects.items():
                effects_found = ranges.get((path, f"observe-peer-ack-{scope}-{kind}"), set())
                if any(not (low <= start and end <= high) for start, end in effects_found):
                    raise RuntimeError(f"Unscoped peer ACK effect: {path} {scope} {kind}")
                if len(effects_found) != expected:
                    violations.setdefault(Path(path).name, set()).add(f"peer-ack-{scope}-{kind}-count")
                if scope == "prevalidate" and kind == "missing":
                    # Pinned Semgrep does not traverse the let-else body for
                    # ordinary return/effect queries. Validate its COMPLETE AST
                    # source span, not a prefix that could hide a cache write.
                    canonical = b"Some(blob)=self.tls.peer_transport_parameters()else{returnOk(());};"
                    contents = Path(path).read_bytes()
                    for start, end in effects_found:
                        if b"".join(contents[start:end].split()) != canonical:
                            violations.setdefault(Path(path).name, set()).add("peer-ack-prevalidate-missing-body")
                if scope == "prevalidate" and kind == "reason":
                    # Compare the entire argument AST node. Structural matching
                    # can otherwise find a pure format! inside a side-effecting
                    # block whose tail is that same canonical expression.
                    canonical = b'format!("invalid peer transport parameters: {error:?}")'
                    contents = Path(path).read_bytes()
                    for start, end in effects_found:
                        if contents[start:end].strip() != canonical:
                            violations.setdefault(Path(path).name, set()).add("peer-ack-prevalidate-reason-expression")
    for path, policies in initializer_expressions(observations, target, require_definitions).items():
        violations.setdefault(path, set()).update(policies)
    return violations


def mutations(semgrep):
    source, parameters = SOURCE.read_text(), PARAMETERS.read_text()
    methods = {scope: method(parameters if scope == "parser" else source, name)
               for scope, (name, _) in SCOPES.items()}
    variants = {}

    def add(name, scope, old, new, policy):
        original = methods[scope] if scope in methods else scope
        variants[name + ".rs"] = (replace_once(original, old, new), policy)

    for name, old, new in (
        ("early_raw_adoption", "self.peer_ack_params_applied || self.tls.is_handshaking()", "self.peer_ack_params_applied"),
        ("inverted_authentication", "self.tls.is_handshaking()", "!self.tls.is_handshaking()"),
        ("swallowed_invalid_parameters", ")?;\n        self.peer_ack_delay_exponent", ").unwrap();\n        self.peer_ack_delay_exponent"),
        ("wrong_parameter_error", "0x08,", "0x0a,"),
        ("wrong_missing_extension", "crate::tls::quic::ALERT_MISSING_EXTENSION", "crate::tls::quic::ALERT_ILLEGAL_PARAMETER"),
        ("wrong_peer_exponent", "= tp.ack_delay_exponent;", "= ACK_DELAY_EXPONENT;"),
        ("wrong_peer_maximum", "Duration::from_millis(tp.max_ack_delay_ms)", "MAX_ACK_DELAY"),
    ):
        add(name, "apply", old, new, "parallax-peer-ack-authenticated-apply")
    for field, value in (("peer_ack_delay_exponent", "3"), ("peer_max_ack_delay", "MAX_ACK_DELAY"), ("peer_ack_params_applied", "true")):
        remembered = method(source, "apply_remembered_transport_params")
        add("cached_" + field, remembered, "        self.send_max_data =", f"        self.{field} = {value};\n        self.send_max_data =",
            "parallax-peer-ack-exclusive-state-commit")
    for name, old, new in (
        ("early_check_waits_for_finished", "if self.peer_transport_params_prevalidated {", "if self.peer_transport_params_prevalidated || self.tls.is_handshaking() {"),
        ("early_check_ignores_invalid", "if let Err(error) = TransportParameters::read(blob) {", "if let Err(error) = TransportParameters::read(blob).or_else(|_| TransportParameters::read(&[])) {"),
        ("early_check_parses_other_input", "TransportParameters::read(blob)", "TransportParameters::read(&[])"),
        ("early_check_wrong_error", "return Err(transport_error(\n                0x08,", "return Err(transport_error(\n                0x0a,"),
        ("early_check_wrong_frame", "                0x06,\n                format!", "                0x00,\n                format!"),
        ("early_check_commits_before_parse", "        let Some(blob)", "        self.peer_transport_params_prevalidated = true;\n        let Some(blob)"),
    ):
        add(name, "prevalidate", old, new, "parallax-peer-ack-early-prevalidation")
    add("early_check_caches_none", "prevalidate", "let Some(blob) = self.tls.peer_transport_parameters() else {", "let Some(blob) = self.tls.peer_transport_parameters() else { self.peer_transport_params_prevalidated = true;", "peer-ack-prevalidate-missing-body")
    close = 'self.close_transport(0x08, 0x06, b"invalid peer transport parameters");'
    add("sticky_failure_missing_close", "prevalidate", close, "", "parallax-peer-ack-early-prevalidation")
    # Semgrep deep matching can retain the canonical call inside an uninvoked
    # closure. Its extra normalized return must still fail the count assertion.
    add("sticky_failure_unused_close_closure", "prevalidate", close, 'let _ = || self.close_transport(0x08, 0x06, b"invalid peer transport parameters");', "peer-ack-prevalidate-return-count")
    add("sticky_failure_conditional_on_finished", "prevalidate", close, "if self.handshake_confirmed { " + close + " }", "parallax-peer-ack-early-prevalidation")
    add("sticky_failure_wrong_code", "prevalidate", close, 'self.close_transport(0x0a, 0x06, b"invalid peer transport parameters");', "parallax-peer-ack-early-prevalidation")
    add("sticky_failure_leaky_close_reason", "prevalidate", close, 'self.close_transport(0x08, 0x06, format!("{blob:?}").as_bytes());', "parallax-peer-ack-early-prevalidation")
    checked = methods["prevalidate"]
    returned_start = checked.index("            return Err(transport_error(")
    returned_end = checked.index("            ));", returned_start) + len("            ));")
    returned = checked[returned_start:returned_end]
    late_close = replace_once(checked, close, "")
    late_close = replace_once(late_close, returned, returned + "\n            " + close)
    variants["sticky_failure_close_after_return.rs"] = (late_close, "parallax-peer-ack-early-prevalidation")
    add("validation_after_key_installation", "receive", "        self.prevalidate_peer_transport_params()?;\n        self.pump_write();", "        self.pump_write();\n        self.prevalidate_peer_transport_params()?;", "parallax-peer-ack-handshake-apply-connected")
    for field, value in (("peer_ack_delay_exponent", "3"), ("peer_max_ack_delay", "MAX_ACK_DELAY"), ("peer_ack_params_applied", "true")):
        add("early_check_commits_" + field, "prevalidate", "        let Some(blob)",
            f"        self.{field} = {value};\n        let Some(blob)", "parallax-peer-ack-exclusive-state-commit")
    remembered = method(source, "apply_remembered_transport_params")
    add("ticket_fakes_early_validation", remembered, "        self.send_max_data =", "        self.peer_transport_params_prevalidated = true;\n        self.send_max_data =", "parallax-peer-ack-exclusive-prevalidation-commit")
    add("authenticated_parse_replaced_by_early_cache", "apply", "        let blob =", "        if self.peer_transport_params_prevalidated { return Ok(()); }\n        let blob =", "parallax-peer-ack-authenticated-apply")
    add("missing_early_validation", "receive", "        self.prevalidate_peer_transport_params()?;\n", "", "parallax-peer-ack-handshake-apply-connected")
    add("swallowed_early_error", "receive", "self.prevalidate_peer_transport_params()?;", "let _ = self.prevalidate_peer_transport_params();", "parallax-peer-ack-handshake-apply-connected")
    add("forced_early_cache_before_receive", "receive", "        let local_cid_len =", "        self.peer_transport_params_prevalidated = true;\n        let local_cid_len =", "parallax-peer-ack-exclusive-prevalidation-commit")
    for nested in (False, True):
        extra = "self.prevalidate_peer_transport_params()?;"
        if nested:
            extra = "if true { " + extra + " }"
        add("duplicate_early_validation_" + str(nested), "receive", "        let local_cid_len =",
            "        " + extra + "\n        let local_cid_len =", "peer-ack-receive-prevalidate-count")
    for name, old, new in (
        ("narrow_before_scale", "(raw as u128) << exponent", "(raw << exponent) as u128"),
        ("fixed_exponent", "<< exponent", "<< ACK_DELAY_EXPONENT"),
        ("clipped_peer_wire_delay", "let micros = (raw as u128) << exponent;", "let micros = ((raw as u128) << exponent).min(25_000);"),
    ):
        add(name, "decode", old, new, "parallax-peer-ack-exact-wire-decoding")
    for name, old, new in (
        ("wrong_rtt_space", "space != SPACE_DATA", "space == SPACE_DATA"),
        ("inverted_confirmation", "if confirmed {", "if !confirmed {"),
        ("never_cap_confirmed", "delay.min(peer_max)", "delay"),
    ):
        add(name, "cap", old, new, "parallax-peer-ack-recovery-delay-policy")
    add("cap_before_confirmation", "cap", "        delay\n", "        delay.min(peer_max)\n", "peer-ack-cap-clamp-count")
    add("data_pto_before_confirmation", "eligible", "space != SPACE_DATA || confirmed", "true", "parallax-peer-ack-pto-policy")
    add("handshake_pto_disabled", "eligible", "|| confirmed", "&& confirmed", "parallax-peer-ack-pto-policy")
    add("peer_max_before_confirmation", "extra", "space == SPACE_DATA && confirmed", "space == SPACE_DATA", "parallax-peer-ack-pto-policy")
    add("pto_uses_local_max", "extra", "        peer_max\n", "        MAX_ACK_DELAY\n", "parallax-peer-ack-pto-policy")
    add("rtt_uses_local_exponent", "rtt", "self.peer_ack_delay_exponent,", "ACK_DELAY_EXPONENT,", "parallax-peer-ack-recovery-connected")
    add("rtt_uses_local_maximum", "rtt", "self.peer_max_ack_delay,", "MAX_ACK_DELAY,", "parallax-peer-ack-recovery-connected")
    add("wrapper_uses_local_exponent", "wrapper", "decoded_ack_delay(raw, exponent)", "decoded_ack_delay(raw, ACK_DELAY_EXPONENT)", "parallax-peer-ack-recovery-delay-policy")
    add("wrapper_ignores_confirmation", "wrapper", "space, confirmed, peer_max", "space, true, peer_max", "parallax-peer-ack-recovery-delay-policy")
    add("wrapper_uses_local_maximum", "wrapper", "space, confirmed, peer_max", "space, confirmed, MAX_ACK_DELAY", "parallax-peer-ack-recovery-delay-policy")
    add("missing_handshake_apply", "receive", "        self.apply_authenticated_peer_ack_params()?;\n", "", "parallax-peer-ack-handshake-apply-connected")
    add("swallowed_handshake_error", "receive", "self.apply_authenticated_peer_ack_params()?;", "let _ = self.apply_authenticated_peer_ack_params();", "parallax-peer-ack-handshake-apply-connected")
    for scope in ("pto", "drain"):
        add(scope + "_local_maximum", scope, "self.peer_max_ack_delay", "MAX_ACK_DELAY", "parallax-peer-ack-pto-drain-connected")
    add("arming_data_pto", "next", "            if !pto_space_eligible(space, self.handshake_confirmed) {\n                continue;\n            }\n", "", "parallax-peer-ack-pto-qualification-connected")
    add("firing_data_pto", "timeout", "pto_space_eligible(space, self.handshake_confirmed)", "true", "parallax-peer-ack-pto-qualification-connected")
    add("selecting_data_probe", "probe", "!pto_space_eligible(space, self.handshake_confirmed)", "false", "parallax-peer-ack-pto-qualification-connected")
    add("exponent21_accepted", "parser", "if value > 20", "if value > 21", "parallax-peer-ack-parameter-parser")
    add("max16384_accepted", "parser", "if value >= 1 << 14", "if value > 1 << 14", "parallax-peer-ack-parameter-parser")
    add("empty_body_accepted", "parser", "let value = read_varint_body(body)?;\n                    if value > 20", "let value = 3;\n                    if value > 20", "parallax-peer-ack-parameter-parser")
    add("exponent_branch_missing", "parser", "                    tp.ack_delay_exponent = value as u32;", "", "peer-ack-parser-exponent-count")
    add("wrong_default_exponent", parameters, "const DEFAULT_ACK_DELAY_EXPONENT: u32 = 3;", "const DEFAULT_ACK_DELAY_EXPONENT: u32 = 4;", "parallax-peer-ack-defaults")
    add("wrong_default_maximum", parameters, "const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;", "const DEFAULT_MAX_ACK_DELAY_MS: u64 = 5;", "parallax-peer-ack-defaults")
    add("wrong_exponent_codepoint", parameters, "const TP_ACK_DELAY_EXPONENT: u64 = 0x0a;", "const TP_ACK_DELAY_EXPONENT: u64 = 0x0b;", "parallax-peer-ack-parameter-codepoints")
    swapped = replace_once(methods["parser"], "TP_ACK_DELAY_EXPONENT =>", "TEMP_ACK_PARAMETER =>")
    swapped = replace_once(swapped, "TP_MAX_ACK_DELAY =>", "TP_ACK_DELAY_EXPONENT =>")
    swapped = replace_once(swapped, "TEMP_ACK_PARAMETER =>", "TP_MAX_ACK_DELAY =>")
    variants["swapped_parser_branches.rs"] = (swapped, "parallax-peer-ack-parameter-codepoints")
    constructor = method(source, "new_inner")
    add("premature_applied_flag", constructor, "peer_ack_params_applied: false", "peer_ack_params_applied: true", "peer-ack-initializer-expression")
    positive_initializers = set()
    positive_reasons = {"early_reason_canonical_full_source.rs"}
    variants["early_reason_canonical_full_source.rs"] = (source, None)
    reason = 'format!("invalid peer transport parameters: {error:?}")'
    for name, expression in (
        ("reviewed_closed_take", 'format!("invalid peer transport parameters: {error:?}; {:?}", self.closed.take())'),
        ("pending_close_take", 'format!("invalid peer transport parameters: {error:?}; {:?}", self.close_pending.take())'),
        ("closed_take_block_with_canonical_tail", '{ let _ = self.closed.take(); ' + reason + ' }'),
        ("closed_take_tuple_with_canonical_tail", '(self.closed.take(), ' + reason + ').1'),
    ):
        changed = replace_once(methods["prevalidate"], reason, expression)
        variants["early_reason_" + name + "_full_source.rs"] = (
            replace_once(source, methods["prevalidate"], changed),
            "peer-ack-prevalidate-reason-expression",
        )
    # Every new initializer case mutates the COMPLETE owning source file, not a
    # reduced function fixture. Keep all nine prior default-field checks and add
    # the independent early-validation flag without changing their boundaries.
    for scope, (name, fields) in INITIALIZERS.items():
        complete = source if scope == "connection" else parameters
        original = method(complete, name)
        for field, expected in fields.items():
            suffix = " || true" if expected == "false" else (
                " + Duration::from_millis(1)" if expected == "MAX_ACK_DELAY" else " + 1")
            wrong = expected + suffix
            forms = {
                "composite": wrong,
                "block": "{ " + expected + "; " + wrong + " }",
                "canonical_tail_block": "{ " + wrong + "; " + expected + " }",
                "multiline": expected + "\n                " + suffix.strip(),
                "conditional": "if true { " + wrong + " } else { " + expected + " }",
                "commented": expected + " /* retained prefix */" + suffix,
                "parenthesized": "(" + expected + ")" + suffix,
                "method_call": expected + (
                    ".then_some(false).unwrap_or(true)" if expected == "false" else (
                        ".saturating_add(Duration::from_millis(1))" if expected == "MAX_ACK_DELAY"
                        else ".wrapping_add(1)")),
            }
            for form, value in forms.items():
                modified = replace_once(original, f"{field}: {expected},", f"{field}: {value},")
                variants[f"initializer_{scope}_{field}_{form}.rs"] = (
                    replace_once(complete, original, modified), "peer-ack-initializer-expression")
            for form, value in (
                ("multiline", "\n                " + expected + "\n            "),
                ("commented", "/* unchanged default */ " + expected),
            ):
                modified = replace_once(original, f"{field}: {expected},", f"{field}: {value},")
                filename = f"initializer_good_{scope}_{field}_{form}.rs"
                variants[filename] = (replace_once(complete, original, modified), None)
                positive_initializers.add(filename)
        # A complete canonical struct retained as a decoy must not permit a
        # second, changed initializer in the same owner function.
        start = original.index("Self {", original.index("{") + 1)
        end = original.index("\n        }", start) + len("\n        }")
        canonical = original[start:end]
        first, expected = next(iter(fields.items()))
        changed = replace_once(original, f"{first}: {expected},", f"{first}: {expected} + 1,")
        brace = changed.index("{") + 1
        returned = "Ok(" + canonical + ")" if scope == "parser" else canonical
        modified = changed[:brace] + "\n        if false { return " + returned + "; }\n" + changed[brace:]
        variants[f"initializer_{scope}_canonical_decoy.rs"] = (
            replace_once(complete, original, modified), "peer-ack-initializer-expression")
    for name in ("encode_server", "encode_safari_client_from"):
        encoder = method(parameters, name)
        add(name + "_advertises_peer_policy", encoder, "        out\n", "        put_param(&mut out, TP_ACK_DELAY_EXPONENT, self.ack_delay_exponent as u64);\n        out\n", "parallax-peer-ack-fixed-local-wire-contract")
    # Retain every reviewed canonical statement; direct-effect observations must
    # still reject extra state writes, calls and early returns in nested scopes.
    for nested in (False, True):
        for scope, anchor, extra, policy in (
            ("apply", "        let blob =", "self.peer_ack_params_applied = true;", "peer-ack-apply-applied-count"),
            ("receive", "        let local_cid_len =", "self.apply_authenticated_peer_ack_params()?;", "peer-ack-receive-apply-count"),
            ("cap", "    if space !=", "return Duration::ZERO;", "peer-ack-cap-return-count"),
            ("eligible", "    space !=", "return true;", "parallax-peer-ack-no-pure-helper-early-return"),
            ("decode", "    let micros =", "return Duration::ZERO;", "parallax-peer-ack-no-pure-helper-early-return"),
            ("wrapper", "    cap_decoded_peer_ack_delay(", "return Duration::ZERO;", "parallax-peer-ack-no-pure-helper-early-return"),
            ("rtt", "        // Feed the congestion controller:", "self.rtt.update(Duration::ZERO, Duration::ZERO);", "peer-ack-rtt-update-count"),
            ("parser", "        Ok(tp)", "tp.ack_delay_exponent = 21;", "peer-ack-parser-exponent-count"),
        ):
            statement = "if true { " + extra + " }" if nested else extra
            add(f"duplicate_{scope}_{nested}", scope, anchor, "        " + statement + "\n" + anchor, policy)

    with tempfile.TemporaryDirectory(prefix="parallax-peer-ack-") as temporary:
        batches = []
        for index, (name, (content, _)) in enumerate(variants.items()):
            if content.startswith("//!"):
                rendered = content
            else:
                owner = "TransportParameters" if "fn read(" in content else "Fixture"
                rendered = "impl " + owner + " {\n" + content + "\n}\n"
            directory = Path(temporary) / f"batch-{index // 8:03d}"
            if directory not in batches:
                directory.mkdir()
                batches.append(directory)
            (directory / name).write_text(rendered)
        found, counted = {}, {}
        # Keep all old negative and positive cases. Fixed batches bound work
        # under the unchanged strict scan timeouts; no partial scan is accepted.
        for directory in batches:
            for finding in findings(semgrep, RULES, directory):
                found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
            counted.update(cardinality(semgrep, directory))
        count_only = sum(policy in counted.get(name, set()) and policy not in found.get(name, set())
                         for name, (_, policy) in variants.items())
        for name, policies in counted.items():
            found.setdefault(name, set()).update(policies)
        falsely_flagged = {name: found[name] for name in positive_initializers | positive_reasons if found.get(name)}
        if falsely_flagged:
            raise RuntimeError(f"Valid complete-source initializer fixtures rejected: {falsely_flagged}")
        escaped = [(name, policy) for name, (_, policy) in variants.items()
                   if policy is not None and policy not in found.get(name, set())]
        if escaped:
            raise RuntimeError(f"Peer ACK production mutations escaped: {escaped}")
    print(f"Peer ACK complete-source initializer positive fixtures: {len(positive_initializers)} passed")
    print(f"Peer ACK complete-source pure-reason positive fixtures: {len(positive_reasons)} passed")
    print(f"Peer ACK production mutations: {len(variants)-len(positive_initializers)-len(positive_reasons)} detected ({count_only} require AST cardinality)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    fixtures = run(args.semgrep, "--jobs", "1", "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if fixtures.returncode:
        raise RuntimeError(fixtures.stdout + fixtures.stderr)
    print(fixtures.stdout.strip())
    for source in (SOURCE, PARAMETERS):
        actual = findings(args.semgrep, RULES, source)
        counts = cardinality(args.semgrep, source, require_definitions=True)
        if actual or counts:
            raise RuntimeError(f"Peer ACK source violations: {actual}, {counts}")
    mutations(args.semgrep)
    print("Peer ACK guards passed (source, fixtures, AST cardinality, mutations)")


if __name__ == "__main__":
    main()
