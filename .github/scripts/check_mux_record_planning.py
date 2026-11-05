#!/usr/bin/env python3
"""Reviewed mux-planner AST boundaries plus mutations of production functions.

This is a syntactic ratchet, not a scheduling, cryptographic or camouflage
theorem. Kani covers selected arithmetic/state helpers; real wire tests cover
framing, byte order, phases and write failures. Separate observation rules
enumerate AST call sites; checker assertions reject duplicate encoders across
statement scopes that ordinary Semgrep sequence patterns do not cross.
"""

import argparse
import json
from pathlib import Path
import tempfile

from check_crypto_rules import replace_once, run


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/mux_record_planning.yml"
OBSERVATIONS = ROOT / ".github/semgrep/mux_record_planning_observe.yml"
ENCODER_SCOPES = {
    "mux-data-piece": "parallax-mux-record-one-header-per-piece",
    "mux-record-planner": "parallax-mux-record-one-control-encode",
    "mux-record-padding": "parallax-mux-record-one-padding-per-record",
    "mux-record-positive-data": "parallax-mux-record-one-positive-data-site",
    "mux-record-exact-sealer": "parallax-mux-record-one-exact-sealer",
    "mux-record-writer-window": "parallax-mux-record-one-write-per-plan",
    "mux-record-writer-loop": "parallax-mux-record-one-batch-helper",
}


def scan(semgrep, target, require_clean=False):
    options = ["--strict", "--no-git-ignore", "--config", str(RULES), "--json", "--quiet"]
    if require_clean:
        options.append("--error")
    result = run(semgrep, *options, str(target))
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete mux planner scan: {data}")
    if require_clean and (result.returncode or data["results"]):
        raise RuntimeError(f"Mux planner violations: {data['results']}")
    return data["results"]


def encoder_cardinality(semgrep, target, require_definitions=False):
    """Count actual AST call ranges within complete observed function ranges.

    These are checker assertions, not synthetic Semgrep findings. Calls in
    branches, loops and closures count even when unreachable. This intentionally
    fixes the reviewed functions to one direct encoding site each; it is not a
    proof about aliases, helper calls or runtime execution counts.
    """
    result = run(semgrep, "--strict", "--no-git-ignore", "--config", str(OBSERVATIONS),
                 "--json", "--quiet", str(target))
    if result.returncode != 0:
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete mux encoder observation: {data}")
    known = {f"observe-{scope}-{kind}" for scope in ENCODER_SCOPES
             for kind in ("definition", "encoder")}
    ranges = {}
    for finding in data["results"]:
        identifier = finding["check_id"].split(".")[-1]
        if identifier not in known:
            raise RuntimeError(f"Unexpected mux observation rule: {identifier}")
        start, end = finding["start"]["offset"], finding["end"]["offset"]
        if not isinstance(start, int) or not isinstance(end, int) or start >= end:
            raise RuntimeError(f"Invalid mux observation range: {finding}")
        path = str(Path(finding["path"]).resolve())
        ranges.setdefault((path, identifier), set()).add((start, end))
    violations = {}
    for scope, policy in ENCODER_SCOPES.items():
        definition_id, encoder_id = f"observe-{scope}-definition", f"observe-{scope}-encoder"
        paths = {path for path, identifier in ranges if identifier in (definition_id, encoder_id)}
        if require_definitions and paths != {str(Path(target).resolve())}:
            raise RuntimeError(f"Missing complete production mux definition: {scope}")
        for path in paths:
            definitions = ranges.get((path, definition_id), set())
            encoders = ranges.get((path, encoder_id), set())
            if not definitions or any(
                sum(start <= call_start and call_end <= end for start, end in definitions) != 1
                for call_start, call_end in encoders
            ):
                raise RuntimeError(f"Incomplete mux AST scope observation: {path} ({scope})")
            if len(definitions) != 1 or any(
                sum(start <= call_start and call_end <= end for call_start, call_end in encoders) != 1
                for start, end in definitions
            ):
                violations.setdefault(Path(path).name, set()).add(policy)
    return violations


def fragment(source, start):
    """Extract the reviewed declaration; changed/unbalanced anchors fail closed."""
    start = source.index(start)
    opening = source.index("{", start)
    depth = 1
    for index in range(opening + 1, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[start:index + 1]
    raise RuntimeError("Unbalanced production mutation anchor")


def mutations(semgrep):
    server = (ROOT / "src/handshake/server.rs").read_text()
    config = (ROOT / "src/config.rs").read_text()
    bench = fragment((ROOT / "src/bench.rs").read_text(), "fn block_on_current_or_fresh<")
    budget = fragment(server, "impl MuxRecordBudget {")
    cursor = fragment(server, "impl MuxFrameCursor {")
    piece = fragment(server, "fn mux_record_data_piece_len(")
    data_run = fragment(server, "fn ready_mux_data_run(")
    planner = fragment(server, "fn plan_ready_mux_records(")
    encoder = fragment(server, "fn encode_mux_data_piece(")
    writer = fragment(server, "async fn write_server_mux_frames_planned<")
    writer_loop = fragment(server, "async fn server_mux_writer_loop<")
    padding = fragment(server, "fn mux_record_padding_plan(")
    record_limit_start = server.index("const SERVER_MUX_FRAME_BATCH_LIMIT:")
    record_limit = server[record_limit_start:server.index(";", record_limit_start) + 1]
    wire_limit_start = server.index("const SERVER_MUX_FAIR_BATCH_BYTES:")
    wire_limit = server[wire_limit_start:server.index(";", wire_limit_start) + 1]
    traffic = fragment(config, "impl TrafficConfig {")
    structure = "impl Config {\n" + fragment(config, "pub fn validate_structure(") + "\n}"
    mode_guard = fragment(structure, "if self.traffic.tcp_mux_record_profile")
    defaults = fragment(config, "impl Default for TrafficConfig {")
    enum_default = fragment(config, "impl Default for TcpMuxRecordProfile {")
    variants = {}

    def add(name, source, old, new, rule):
        variants[name + ".rs"] = (replace_once(source, old, new), "parallax-mux-" + rule)

    add("benchmark_without_time", bench, ".enable_time()", "", "benchmark-timer-driver")
    add("benchmark_wrong_driver", bench, ".enable_time()", ".enable_io()", "benchmark-timer-driver")
    add("benchmark_extra_unclocked_runtime", bench, "    match tokio::runtime::Handle::try_current() {",
        "    if false { let _other = tokio::runtime::Builder::new_current_thread().build()?; }\n"
        "    match tokio::runtime::Handle::try_current() {", "benchmark-timer-driver")
    add("enum_default_on", enum_default, "Self::Off", "Self::CloudflareDynamic", "profile-default-off")
    add("record_limit_expanded", record_limit, "= 64;", "= 128;", "record-window-constants")
    add("padded_write_limit_expanded", wire_limit, "= 64 * 1024;", "= 1024 * 1024;", "record-window-constants")
    add("struct_default_on", defaults, "tcp_mux_record_profile: TcpMuxRecordProfile::Off",
        "tcp_mux_record_profile: TcpMuxRecordProfile::CloudflareDynamic", "profile-default-off")
    add("client_profile", structure, "self.mode != Mode::Server", "self.mode == Mode::Server", "profile-server-mode")
    add("nested_mode_guard", structure, mode_guard, "if false {\n" + mode_guard + "\n}", "profile-server-mode")
    add("single_stream_profile", traffic, "self.max_concurrent_streams <= 1", "self.max_concurrent_streams == 0", "profile-traffic-compatibility")
    for field in ("min_padding", "max_padding", "min_delay_ms", "max_delay_ms", "cover_min_interval_ms", "cover_max_interval_ms"):
        add("unchecked_" + field, traffic, "self." + field + " != 0", "false", "profile-traffic-compatibility")
    add("wrong_codec_overhead", budget, "const CODEC_OVERHEAD: usize = 18;", "const CODEC_OVERHEAD: usize = 17;", "record-profile-budgets")
    add("early_medium_phase", budget, "self.records_sent > 40", "self.records_sent >= 40", "record-profile-budgets")
    add("early_large_phase", budget, "self.records_sent > 80", "self.records_sent >= 80", "record-profile-budgets")
    add("uncapped_small_budget", budget, "codec_max.min(1386 - CODEC_OVERHEAD)", "1386 - CODEC_OVERHEAD", "record-profile-budgets")
    add("idle_boundary_changed", budget, "now.duration_since(last) > Duration::from_millis(1000)", "now.duration_since(last) >= Duration::from_millis(1000)", "record-idle-reset")
    add("coalescing_is_not_idle", budget, "Duration::from_millis(1000)", "Duration::from_millis(5)", "record-idle-reset")
    add("unbounded_piece", piece, "remaining.div_ceil(2)", "remaining", "record-piece-capacity")
    add("cursor_skips_byte", cursor, "self.offset += take;", "self.offset += take + 1;", "record-cursor-progress")
    add("merge_across_streams", data_run, " || frame.stream_id != stream_id", "", "record-run-barriers")
    add("merge_across_control", data_run, "frame.kind != MuxFrameKind::Data || ", "", "record-run-barriers")
    add("unbounded_output_records", planner, "scratch.record_lens.len() < SERVER_MUX_FRAME_BATCH_LIMIT", "scratch.record_lens.len() < usize::MAX", "record-output-window")
    select = "let take = mux_record_data_piece_len(run_bytes, room - header_len);"
    encode = "encode_mux_data_piece(&mut scratch.plaintext_buf, frames, cursor, take)?;"
    raw_append = "scratch.plaintext_buf.extend_from_slice(&frames[cursor.frame].payload);"
    add("append_before_canonical", planner, select, raw_append + "\n" + select, "record-planner-effects")
    add("extra_encoder_before_canonical", planner, select, encode.replace("take", "run_bytes") + "\n" + select, "record-planner-effects")
    add("append_after_canonical", planner, "cursor.frame = run_end;", raw_append + "\ncursor.frame = run_end;", "record-planner-effects")
    add("failed_append_after_canonical", planner, "cursor.frame = run_end;", "if let Err(_) = Err::<(), ()>(()) { " + raw_append + " }\ncursor.frame = run_end;", "record-planner-effects")
    add("extra_control_encode", planner, "cursor.frame += 1;", "frame.encode_into(&mut scratch.plaintext_buf)?;\ncursor.frame += 1;", "record-planner-effects")
    add("extra_record_before_canonical", planner, "let len = scratch.plaintext_buf.len() - record_start;", "scratch.record_lens.push(1);\nlet len = scratch.plaintext_buf.len() - record_start;", "record-planner-effects")
    count = "budget.records_sent = budget.records_sent.saturating_add(1);"
    add("extra_count_after_canonical", planner, count, count + "\nif true { " + count + " }", "record-planner-effects")
    add("compound_count_after_canonical", planner, count, count + "\nbudget.records_sent += 1;", "record-planner-effects")
    add("extra_record_vector_append", planner, "let len = scratch.plaintext_buf.len() - record_start;", "scratch.record_lens.append(&mut Vec::from([1]));\nlet len = scratch.plaintext_buf.len() - record_start;", "record-planner-effects")
    copy = "out.extend_from_slice(&frame.payload[cursor.offset..cursor.offset + take]);"
    available = "let available = frame.payload.len() - cursor.offset;"
    advance = "cursor.advance(frame.payload.len(), take);"
    add("encoder_append_before", encoder, available, "out.extend_from_slice(&frame.payload);\n" + available, "record-encoder-prefix")
    add("encoder_append_after", encoder, advance, advance + "\nout.extend_from_slice(&frame.payload);", "record-encoder-prefix")
    add("encoder_failed_extra_copy", encoder, advance, advance + "\nif let Err(_) = Err::<(), ()>(()) { out.extend_from_slice(&frame.payload); }", "record-encoder-prefix")
    add("encoder_nested_duplicate", encoder, advance, advance + "\nif remaining > 0 { " + copy + " }", "record-encoder-prefix")
    add("encoder_double_advance", encoder, advance, advance + "\n" + advance, "record-encoder-prefix")
    add("encoder_vector_append", encoder, advance, advance + "\nout.append(&mut Vec::from(frame.payload.as_slice()));", "record-encoder-prefix")
    add("piece_allocation", encoder, "let stream_id =", "let _copy = frames[cursor.frame].payload.to_vec();\nlet stream_id =", "record-no-piece-allocation")
    header = "MuxFrame::encode_borrowed_into(stream_id, MuxFrameKind::Data, &[], out)?;"
    payload_header = "MuxFrame::encode_borrowed_into(stream_id, MuxFrameKind::Data, &frames[cursor.frame].payload, out)?;"
    header_block = ("let payload_len = u32::try_from(remaining).map_err(|_| MuxFrameError::PayloadTooLong)?;\n"
                    "    " + header + "\n    let header_end = out.len();")
    add("payload_header_before_canonical", encoder, header, payload_header + "\n" + header, "record-encoder-prefix")
    add("payload_header_after_canonical", encoder, "let header_end = out.len();", "let header_end = out.len();\n" + payload_header, "record-encoder-prefix")
    add("nested_payload_header_before", encoder, header_block, "if !frames.is_empty() { " + payload_header + " }\n" + header_block, "record-encoder-prefix")
    add("replace_empty_header_with_payload", encoder, header, payload_header, "record-encoder-prefix")
    add("ignored_header_error", encoder, header, "let _ = MuxFrame::encode_borrowed_into(stream_id, MuxFrameKind::Data, &[], out);", "record-encoder-prefix")
    add("missing_header_encoder", encoder, header, "", "record-one-header-per-piece")
    add("duplicate_complete_header_block", encoder, header_block, header_block + "\n" + header_block, "record-one-header-per-piece")
    add("nested_complete_header_before", encoder, header_block, "if !frames.is_empty() {\n" + header_block + "\n}\n" + header_block, "record-one-header-per-piece")
    add("failed_complete_header_after", encoder, header_block, header_block + "\nif let Err(_) = Err::<(), ()>(()) {\n" + header_block + "\n}", "record-one-header-per-piece")
    add("loop_complete_header_before", encoder, header_block, "for _ in 0..1 {\n" + header_block + "\n}\n" + header_block, "record-one-header-per-piece")
    add("closure_complete_header_after", encoder, header_block, header_block + "\nlet _extra = || -> Result<(), MuxFrameError> {\n" + header_block + "\nOk(())\n};", "record-one-header-per-piece")
    control_start = planner.index("            let frame_len = MuxFrame::encoded_len(frame.payload.len())?;")
    control_end = planner.index("            cursor.frame += 1;", control_start) + len("            cursor.frame += 1;")
    control = planner[control_start:control_end]
    add("missing_control_encoder", planner, "frame.encode_into(&mut scratch.plaintext_buf)?;", "", "record-one-control-encode")
    add("duplicate_complete_control_sequence", planner, control, control + "\n" + control, "record-one-control-encode")
    add("nested_complete_control_before", planner, control, "if !frames.is_empty() {\n" + control + "\n}\n" + control, "record-one-control-encode")
    add("failed_complete_control_after", planner, control, control + "\nif let Err(_) = Err::<(), ()>(()) {\n" + control + "\n}", "record-one-control-encode")
    add("loop_complete_control_before", planner, control, "for _ in 0..1 {\n" + control + "\n}\n" + control, "record-one-control-encode")
    add("closure_complete_control_after", planner, control, control + "\nlet _extra = || -> Result<(), MuxFrameError> {\nloop {\n" + control + "\nbreak;\n}\nOk(())\n};", "record-one-control-encode")
    add("extra_control_after_canonical", planner, control, control + "\nframe.encode_into(&mut scratch.plaintext_buf)?;", "record-planner-effects")
    associated_control = "MuxFrame::encode_borrowed_into(frame.stream_id, frame.kind, &frame.payload, &mut scratch.plaintext_buf)?;"
    add("associated_control_before_canonical", planner, control, associated_control + "\n" + control, "record-planner-effects")
    write_start = "let write_started = Instant::now();"
    write = fragment(writer, "match timeout(idle, writer.write_records")
    # fragment() stops at the match body; include its .await before the body.
    guarded_write = write
    activity = "if let Some(activity) = activity {\n            bump_relay_activity(activity);\n        }"
    raw_write = "writer.write_records(scratch.records_buf.as_slice()).await?;"
    add("early_commit_with_canonical_retained", writer, write_start, "*budget = planned_budget;\n" + write_start, "record-successful-write-commit")
    add("early_idle_commit", writer, write_start, "budget.last_write = Some(Instant::now());\n" + write_start, "record-successful-write-commit")
    add("early_compound_count", writer, write_start, "budget.records_sent += 1;\n" + write_start, "record-successful-write-commit")
    add("ignore_write_error", writer, "Ok(result) => result?,", "Ok(_result) => {},", "record-successful-write-commit")
    add("nested_late_count_commit", writer, "*budget = planned_budget;", "*budget = planned_budget;\nif let Err(_) = Err::<(), ()>(()) { budget.records_sent = budget.records_sent.saturating_add(1); }", "record-successful-write-commit")
    add("extra_write_before_canonical", writer, write_start, raw_write + "\n" + write_start, "record-successful-write-commit")
    block = (write_start + "\n        " + write + "\n        " + activity + "\n        waited = waited.saturating_add(write_started.elapsed());\n"
             "        planned_budget.last_write = Some(Instant::now());\n        *budget = planned_budget;\n"
             "        scratch.records_buf.clear();")
    add("duplicate_complete_write_block", writer, block, block + "\n" + block, "record-one-write-per-plan")
    add("unguarded_write_window", writer, guarded_write, raw_write, "record-successful-write-commit")
    add("window_activity_not_refreshed", writer, activity, "", "record-successful-write-commit")
    add("window_activity_refreshed_before_success", writer, write_start, "if let Some(activity) = activity { bump_relay_activity(activity); }\n" + write_start, "record-successful-write-commit")
    add("window_timeout_ignored", writer, "Err(_) => return Err(shed_mux_writer_on_stalled_client(log.cid)),", "Err(_) => {},", "record-successful-write-commit")
    add("window_timeout_raised", writer, "timeout(idle, writer.write_records", "timeout(FALLBACK_IDLE_TIMEOUT_FLOOR, writer.write_records", "record-successful-write-commit")
    add("window_activity_shadowed_with_canonical_retained", writer, write_start, "let activity = None;\n" + write_start, "record-write-policy-binding")
    add("window_timeout_shadowed_with_canonical_retained", writer, write_start, "let idle = Duration::MAX;\n" + write_start, "record-write-policy-binding")
    helper_start = writer_loop.index("        let waited = write_server_mux_frames_planned(")
    helper_end = writer_loop.index("        .await?;", helper_start) + len("        .await?;")
    helper = writer_loop[helper_start:helper_end]
    call = helper[helper.index("write_server_mux_frames_planned("):helper.rindex(".await?;")].strip()
    whole_timeout = "let waited = timeout(idle, " + call + ").await.map_err(|_| shed_mux_writer_on_stalled_client(cid))??;"
    add("whole_batch_fixed_timeout", writer_loop, helper, whole_timeout, "record-no-whole-batch-timeout")
    add("whole_batch_timeout_with_canonical_retained", writer_loop, helper, whole_timeout + "\n" + helper, "record-no-whole-batch-timeout")
    add("whole_batch_async_timeout_with_canonical_retained", writer_loop, helper,
        "let _ = timeout(idle, async { " + call + ".await }).await;\n" + helper, "record-no-whole-batch-timeout")
    add("whole_batch_outer_async_timeout_preserves_canonical_statement", writer_loop, helper,
        "let _ = timeout(idle, async {\n" + helper + "\nOk::<(), HandshakeServerError>(())\n}).await;", "record-writer-loop-timeout-boundary")
    add("whole_batch_activity_disabled", writer_loop, "(idle, Some(&activity))", "(idle, None)", "record-no-whole-batch-timeout")
    add("duplicate_complete_batch_helper", writer_loop, helper, helper + "\n" + helper, "record-one-batch-helper")

    add("padding_off_enabled", padding, "profile == TcpMuxRecordProfile::CloudflareDynamic && has_positive_data", "has_positive_data", "record-exact-padding-scope")
    add("padding_controls_enabled", padding, " && has_positive_data", "", "record-exact-padding-scope")
    add("padding_unchecked_subtraction", padding, "limit.checked_sub(plaintext_len)?", "limit - plaintext_len", "record-exact-padding-scope")
    add("padding_tls_bound_removed", padding, "tls_len > crate::protocol::data::OUTER_TLS_RECORD_LIMIT", "false", "record-exact-padding-scope")
    add("padding_nonzero_control_metadata", planner, "budget.profile, has_positive_data, len, limit", "budget.profile, true, len, limit", "record-planner-effects")
    add("padding_unbounded_wire_window", planner, "next_wire_bound > SERVER_MUX_FAIR_BATCH_BYTES", "false", "record-padded-wire-window")
    add("padding_unchecked_wire_window", planner, ".checked_add(maximum_wire_len)", ".wrapping_add(maximum_wire_len)", "record-padded-wire-window")
    add("padding_early_extra_push", planner, "let len = scratch.plaintext_buf.len() - record_start;", "scratch.exact_pad_lens.push(0);\nlet len = scratch.plaintext_buf.len() - record_start;", "record-planner-effects")
    add("padding_late_extra_push", planner, count, count + "\nscratch.exact_pad_lens.push(0);", "record-planner-effects")
    pad_start = planner.index("        let len = scratch.plaintext_buf.len() - record_start;")
    pad_end = planner.index(count, pad_start) + len(count)
    pad_block = planner[pad_start:pad_end]
    for name, duplicate in (
        ("padding_duplicate_complete", pad_block + "\n" + pad_block),
        ("padding_nested_complete", "if true {\n" + pad_block + "\n}\n" + pad_block),
        ("padding_closure_complete", pad_block + "\nlet _extra = || -> Result<(), HandshakeServerError> {\n" + pad_block + "\nOk(())\n};"),
    ):
        add(name, planner, pad_block, duplicate, "record-one-padding-per-record")
    add("padding_early_positive_flag", planner, "let len = scratch.plaintext_buf.len() - record_start;", "has_positive_data = true;\nlet len = scratch.plaintext_buf.len() - record_start;", "record-planner-effects")
    add("padding_extra_positive_flag_within_run", planner, "cursor.frame = run_end;", "has_positive_data = true;\ncursor.frame = run_end;", "record-planner-effects")
    add("padding_shadow_value", planner, "scratch.exact_pad_lens.push(pad);", "let pad = pad + 1;\nscratch.exact_pad_lens.push(pad);", "record-planner-effects")
    add("padding_swapped_pad_vector", writer, "&scratch.exact_pad_lens,", "&scratch.record_lens,", "record-exact-sealer-branch")
    add("padding_off_uses_exact", writer, "planned_budget.profile == TcpMuxRecordProfile::CloudflareDynamic", "planned_budget.profile == TcpMuxRecordProfile::Off", "record-exact-sealer-branch")
    seal_start = writer.index("        if planned_budget.profile == TcpMuxRecordProfile::CloudflareDynamic")
    seal_end = writer.index("        let write_started", seal_start)
    # Include only the branch, not intervening logging, in canonical duplicates.
    seal_block = fragment(writer[seal_start:seal_end], "if planned_budget.profile")
    exact_call_start = writer.index("            codec.seal_records_into_exact_padded(")
    exact_call_end = writer.index("            )?;", exact_call_start) + len("            )?;")
    exact_call = writer[exact_call_start:exact_call_end]
    seal_boundary = "scratch.records_buf.clear();\n        if planned_budget.profile == TcpMuxRecordProfile::CloudflareDynamic"
    add("padding_early_extra_seal", writer, seal_boundary, "scratch.records_buf.clear();\n" + exact_call + "\n        if planned_budget.profile == TcpMuxRecordProfile::CloudflareDynamic", "record-exact-sealer-branch")
    add("padding_duplicate_complete_seal_branch", writer, seal_block, seal_block + "\n" + seal_block, "record-one-exact-sealer")

    with tempfile.TemporaryDirectory(prefix="parallax-mux-planner-") as temporary:
        for name, (content, _) in variants.items():
            (Path(temporary) / name).write_text(content)
        found = {}
        for finding in scan(semgrep, temporary):
            found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
        cardinality = encoder_cardinality(semgrep, temporary)
        cardinality_only = sum(expected in cardinality.get(name, set()) and expected not in found.get(name, set())
                               for name, (_, expected) in variants.items())
        for name, policies in cardinality.items():
            found.setdefault(name, set()).update(policies)
        for name, (_, expected) in variants.items():
            if expected not in found.get(name, set()):
                raise RuntimeError(f"Mux planner mutation escaped: {name} ({expected})")
    print(f"Mux record planner production mutations: {len(variants)} detected "
          f"({len(cardinality)} trigger AST encoder cardinality; "
          f"{cardinality_only} require its cross-scope/count assertion)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    fixtures = run(args.semgrep, "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if fixtures.returncode:
        raise RuntimeError(fixtures.stdout + fixtures.stderr)
    print(fixtures.stdout.strip())
    for source in ("src/handshake/server.rs", "src/config.rs", "src/bench.rs"):
        scan(args.semgrep, ROOT / source, require_clean=True)
    cardinality = encoder_cardinality(args.semgrep, ROOT / "src/handshake/server.rs", require_definitions=True)
    if cardinality:
        raise RuntimeError(f"Production mux encoder cardinality violations: {cardinality}")
    print("Mux AST observations: 7 single-site policies across 4 complete functions")
    mutations(args.semgrep)
    print("Mux record planner guards: passed (source, fixtures, mutations)")


if __name__ == "__main__":
    main()
