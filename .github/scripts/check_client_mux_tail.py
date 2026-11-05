#!/usr/bin/env python3
"""Blocking AST pins and actual-source mutants for the private TCP mux tail.

The full producer body is a deliberately narrow syntactic ratchet. It does not
prove async scheduling, real delivery latency, cryptography or camouflage.
Separate AST observations enforce one production call inside the TCP dispatcher.
"""

import argparse
import json
from pathlib import Path
import tempfile

from check_crypto_rules import replace_once, run
from check_mux_record_planning import fragment


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/client_mux_tail.yml"
OBSERVATIONS = ROOT / ".github/semgrep/client_mux_tail_observe.yml"
POLICY = "parallax-client-mux-tail-single-tcp-callsite"


def findings(semgrep, target, rules=RULES):
    # Complete-runtime mutation files are deliberately large. Keep the scan
    # serial instead of multiplying parser memory and per-rule CPU contention.
    result = run(semgrep, "--strict", "--jobs", "1", "--no-git-ignore", "--config", str(rules),
                 "--json", "--quiet", str(target))
    data = json.loads(result.stdout)
    if result.returncode not in (0, 1) or data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete client mux tail AST scan: exit={result.returncode}, "
                           f"errors={data.get('errors')}, skipped={data.get('skipped_rules')}")
    return data["results"]


def cardinality(semgrep, target, require_complete=False):
    ranges = {}
    for item in findings(semgrep, target, OBSERVATIONS):
        kind = item["check_id"].split(".")[-1].removeprefix("observe-client-mux-tail-")
        if kind not in ("producer", "owner", "call"):
            raise RuntimeError(f"Unexpected client mux observation: {kind}")
        start, end = item["start"]["offset"], item["end"]["offset"]
        if not isinstance(start, int) or not isinstance(end, int) or start >= end:
            raise RuntimeError("Invalid AST observation range")
        ranges.setdefault(Path(item["path"]).name, {}).setdefault(kind, set()).add((start, end))
    if require_complete and set(ranges) != {Path(target).name}:
        raise RuntimeError("Missing complete production mux tail observations")
    violations = {}
    for path, scopes in ranges.items():
        owners, calls, producers = (scopes.get(kind, set()) for kind in ("owner", "call", "producer"))
        invalid = len(owners) > 1 or len(producers) > 1 or len(calls) > 1
        if owners or calls or require_complete:
            invalid |= len(owners) != 1 or len(calls) != 1
            invalid |= any(sum(a <= x and y <= b for a, b in owners) != 1 for x, y in calls)
        if require_complete:
            invalid |= len(producers) != 1
        if invalid:
            violations[path] = {POLICY}
    return violations


def mutations(semgrep):
    source = (ROOT / "src/client/runtime.rs").read_text()
    producer = fragment(source, "async fn client_mux_upload_loop(")
    owner = fragment(source, "async fn handle_local_mux_connection_with_cid(")
    flush = fragment(source, "async fn flush_client_mux_upload_tail(")
    cleanup = fragment(source, "impl Drop for ClientMuxUploadTail {")
    append = fragment(source, "fn client_mux_tail_append_len(")
    constant_start = source.index("const CLIENT_TCP_MUX_TAIL_HOLD:")
    constant = source[constant_start:source.index(";", constant_start) + 1]
    variants = {}

    def add(name, text, old, new, policy):
        variants[name + ".rs"] = (replace_once(text, old, new), "parallax-client-mux-tail-" + policy)

    add("long_hold", constant, "from_millis(1)", "from_millis(5)", "window")
    add("public_hold", constant, "const CLIENT", "pub const CLIENT", "private-window")
    add("crate_public_hold", constant, "const CLIENT", "pub(crate) const CLIENT", "private-window")
    add("multiline_public_hold", constant, "const CLIENT", "pub\nconst CLIENT", "private-window")
    add("restricted_public_hold", constant, "const CLIENT", "pub(in crate::client) const CLIENT", "private-window")
    add("unbounded_append_plan", append, "available.min(capacity - buffered)", "available", "capacity")
    add("incorrect_capacity_subtraction", append, "capacity - buffered", "capacity", "capacity")
    add("jitter_gate_inverted", owner, "mux_pool.traffic.max_delay_ms == 0", "mux_pool.traffic.max_delay_ms != 0", "callsite")
    add("configured_delay_used_as_hold", owner, "CLIENT_TCP_MUX_TAIL_HOLD", "Duration::from_millis(mux_pool.traffic.max_delay_ms)", "callsite")
    add("jitter_gets_added_hold", owner, "Duration::ZERO", "CLIENT_TCP_MUX_TAIL_HOLD", "callsite")
    add("quic_return_removed", owner, "return client_mux_quic_substream(", "let _ = client_mux_quic_substream(", "tcp-boundary")
    add("socks_validation_moved", owner, "let request = accept_local_socks_connect(&mut local).await?;", "let request = unreachable!();", "tcp-boundary")
    call_start = owner.index("    let upload = client_mux_upload_loop(")
    call_end = owner.index("    let download", call_start)
    call = owner[call_start:call_end]
    variants["explicit_jitter_zeroed_full_runtime.rs"] = (
        replace_once(source, call, "    let mut mux_pool = mux_pool;\n    mux_pool.traffic.max_delay_ms = 0;\n" + call),
        "parallax-client-mux-tail-gate-immutable",
    )
    # Whole-source, canonical-retaining variants. The real dispatcher owns its
    # ClientMuxPool argument and TrafficConfig is Copy with a u16 delay field.
    # Rebindings below can mutate that owned value. Direct-write variants also
    # make the parameter mutable; a bare write to the original immutable
    # parameter would be compiler-rejected and is not claimed as a bypass.
    # This runner checks AST rejection; the type assessment is by inspection,
    # not a separate compile of these mutation files.
    gate_variants = {
        "nested_pool_shadow": "let mux_pool = { let mut mux_pool = mux_pool; mux_pool.traffic.max_delay_ms = 0; mux_pool };",
        "tuple_pool_shadow": "let (mut mux_pool, _marker) = (mux_pool, ()); mux_pool.traffic.max_delay_ms = 0;",
        "pool_struct_shadow": "let mux_pool = ClientMuxPool { traffic: TrafficConfig { max_delay_ms: 0, ..mux_pool.traffic }, ..mux_pool };",
        "closure_pool_shadow": "let mux_pool = (|mut pool: ClientMuxPool| { pool.traffic.max_delay_ms = 0; pool })(mux_pool);",
    }
    for name, prefix in gate_variants.items():
        variants[name + "_full_runtime.rs"] = (
            replace_once(source, call, "    " + prefix + "\n" + call),
            "parallax-client-mux-tail-gate-immutable",
        )
    mutable_owner = replace_once(owner, "    mux_pool: ClientMuxPool,", "    mut mux_pool: ClientMuxPool,")
    for name, prefix in {
        "mutable_parameter_zero_gate": "mux_pool.traffic.max_delay_ms = 0;",
        "mutable_parameter_zero_traffic": "mux_pool.traffic = TrafficConfig { max_delay_ms: 0, ..mux_pool.traffic };",
        "compound_gate_and": "mux_pool.traffic.max_delay_ms &= 0;",
        "compound_gate_multiply": "mux_pool.traffic.max_delay_ms *= 0;",
        "compound_gate_xor": "mux_pool.traffic.max_delay_ms ^= mux_pool.traffic.max_delay_ms;",
        "compound_gate_subtract": "mux_pool.traffic.max_delay_ms -= mux_pool.traffic.max_delay_ms;",
        "mutable_gate_alias": "let gate = &mut mux_pool.traffic.max_delay_ms; *gate = 0;",
        "mutable_traffic_alias": "let traffic = &mut mux_pool.traffic; traffic.max_delay_ms = 0;",
        "replace_gate": "let _ = std::mem::replace(&mut mux_pool.traffic.max_delay_ms, 0);",
        "replace_whole_pool": "mux_pool = ClientMuxPool { traffic: TrafficConfig { max_delay_ms: 0, ..mux_pool.traffic }, ..mux_pool };",
    }.items():
        changed_owner = replace_once(mutable_owner, call, "    " + prefix + "\n" + call)
        variants[name + "_full_runtime.rs"] = (
            replace_once(source, owner, changed_owner),
            "parallax-client-mux-tail-gate-immutable",
        )
    add("producer_before_open", owner, call, "", "tcp-boundary")
    variants["producer_before_open.rs"] = (
        replace_once(variants["producer_before_open.rs"][0], "    // TCP path:", call + "    // TCP path:"),
        "parallax-client-mux-tail-tcp-boundary",
    )
    for name, extra in (
        ("duplicate_canonical_call", call + call),
        ("nested_canonical_call", "if false {\n" + call + "}\n" + call),
        ("closure_canonical_call", call + "let _extra = || {\n" + call + "};\n"),
    ):
        variants[name + ".rs"] = (replace_once(owner, call, extra), POLICY)

    reserve_start = flush.index("        let slot =")
    reserve_end = flush.index("        let payload", reserve_start)
    reserve = flush[reserve_start:reserve_end]
    payload = "let payload = std::mem::replace(&mut tail.bytes, tail.pool.take());"
    add("tail_moved_before_reserve", flush, reserve, payload + "\n" + reserve, "flush")
    add("empty_tail_sent", flush, "if !tail.bytes.is_empty()", "if true", "flush")
    add("flush_as_fin", flush, "MuxFrameKind::Data", "MuxFrameKind::Fin", "flush")
    add("flush_without_new_empty_tail", flush, payload, "let payload = std::mem::take(&mut tail.bytes);", "flush")
    add("ignored_reserve_failure", flush, ".map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?", ".unwrap()", "flush")
    add("drop_does_not_return_pool", cleanup, "self.pool.put(std::mem::take(&mut self.bytes));", "", "cancel-cleanup")
    add("drop_spawns_send", cleanup, "self.pool.put(std::mem::take(&mut self.bytes));", "self.pool.put(std::mem::take(&mut self.bytes));\ntokio::spawn(async move { send_mux_frame(&tx, 1, MuxFrameKind::Fin, Vec::new()).await; });", "cancel-cleanup")

    def mutate_producer(name, old, new):
        add(name, producer, old, new, "producer")

    mutate_producer("wrong_mux_payload_capacity", "let max_payload_len = MuxFrame::max_payload_len(chunk_size);", "let max_payload_len = chunk_size;")
    mutate_producer("second_tail_list", "let mut tail_deadline = None;", "let mut tails = Vec::<Vec<u8>>::new();\nlet mut tail_deadline = None;")
    mutate_producer("ready_read_starves_timer", "if Instant::now() >= deadline", "if false")
    mutate_producer("relative_read_timeout", "timeout_at(deadline, local_read.read(&mut local_buf))", "timeout(hold, local_read.read(&mut local_buf))")
    mutate_producer("deadline_restarted_on_read", "if !hold.is_zero() && tail.bytes.is_empty()", "if !hold.is_zero()")
    mutate_producer("deadline_restarted_after_append", "                if tail.bytes.is_empty() {", "                if true {")
    mutate_producer("suffix_gets_fresh_receipt_time", "                    tail_deadline = Some(received_at + hold);", "                    tail_deadline = Some(Instant::now() + hold);")
    mutate_producer("unbounded_tail_append", "tail.bytes.extend_from_slice(&input[..take]);", "tail.bytes.extend_from_slice(input);")
    mutate_producer("lost_input_suffix", "input = &input[take..];", "input = &[];")
    mutate_producer("full_tail_waits_for_timer", "if tail.bytes.len() == max_payload_len", "if false")
    mutate_producer("hold_zero_does_not_drain", "n = drain_ready_tcp_read(&local_read, &mut local_buf, n)?;", "")
    mutate_producer("held_reads_use_lossy_drain", "let received_at = Instant::now();", "let n = drain_ready_tcp_read(&local_read, &mut local_buf, n)?;\nlet received_at = Instant::now();")
    mutate_producer("extra_append_before_canonical", "                let take =", "                tail.bytes.extend_from_slice(input);\n                let take =")
    mutate_producer("nested_extra_append_after_canonical", "input = &input[take..];", "input = &input[take..];\nif true { tail.bytes.extend_from_slice(input); }")
    mutate_producer("extra_deadline_with_canonical_retained", "                let take =", "                tail_deadline = Some(Instant::now() + hold);\n                let take =")
    mutate_producer("shadow_receipt_with_canonical_retained", "                let take =", "                let received_at = Instant::now();\n                let take =")
    mutate_producer("shadow_hold_with_canonical_retained", "let mut tail_deadline = None;", "let hold = Duration::ZERO;\nlet mut tail_deadline = None;")
    bounded_start = producer.index("                let take =")
    full_start = producer.index("                if tail.bytes.len() == max_payload_len {", bounded_start)
    full_block = fragment(producer[full_start:], "if tail.bytes.len() == max_payload_len {")
    bounded = producer[bounded_start:full_start] + "                " + full_block
    mutate_producer("duplicate_complete_bounded_append", bounded, bounded + "\n" + bounded)
    mutate_producer("nested_complete_bounded_append", bounded, bounded + "\nif !input.is_empty() {\n" + bounded + "\n}")
    read_error = fragment(producer, "Err(err) => {")
    mutate_producer("read_error_discards_successful_tail", read_error, "Err(err) => { return Err(err.into()); }")
    mutate_producer("read_error_sends_its_own_reset", read_error, "Err(err) => { send_mux_frame(&frame_tx, stream_id, MuxFrameKind::Reset, Vec::new()).await?;\n" + read_error.removeprefix("Err(err) => {"))
    eof = fragment(producer, "if n == 0 {")
    mutate_producer("eof_fin_before_data", eof, "if n == 0 { send_mux_frame(&frame_tx, stream_id, MuxFrameKind::Fin, Vec::new()).await?;\n" + eof.removeprefix("if n == 0 {"))

    with tempfile.TemporaryDirectory(prefix="parallax-client-mux-tail-") as temporary:
        for name, (content, _) in variants.items():
            (Path(temporary) / name).write_text(content)
        found = {}
        for item in findings(semgrep, temporary):
            found.setdefault(Path(item["path"]).name, set()).add(item["check_id"].split(".")[-1])
        observed = cardinality(semgrep, temporary)
        for name, policies in observed.items():
            found.setdefault(name, set()).update(policies)
        for name, (_, expected) in variants.items():
            if expected not in found.get(name, set()):
                raise RuntimeError(f"Client mux tail mutation escaped: {name} ({expected}); detected={sorted(found.get(name, set()))}")
    gate_count = sum(expected == "parallax-client-mux-tail-gate-immutable" for _, expected in variants.values())
    print(f"Client mux tail actual-source mutants: {len(variants)} detected ({gate_count} complete-runtime gate rewrites)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    fixtures = run(args.semgrep, "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if fixtures.returncode:
        raise RuntimeError(fixtures.stdout + fixtures.stderr)
    print(fixtures.stdout.strip())
    source = ROOT / "src/client/runtime.rs"
    if violations := findings(args.semgrep, source):
        raise RuntimeError(f"Client mux tail production violations: {violations}")
    if violations := cardinality(args.semgrep, source, require_complete=True):
        raise RuntimeError(f"Client mux tail production callsite violations: {violations}")
    mutations(args.semgrep)
    print("Client mux tail AST guards: passed (source, fixtures, mutations, single TCP callsite)")


if __name__ == "__main__":
    main()
