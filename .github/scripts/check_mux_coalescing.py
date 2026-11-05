#!/usr/bin/env python3
"""Syntactic tail-buffer guards with actual production-source mutations.

These do not prove scheduling or camouflage. Actual socket regressions verify
byte order, oldest-byte timing, EOF/Reset and independent stream backpressure.
"""

import argparse
import json
from pathlib import Path
import tempfile

from check_crypto_rules import replace_once, run


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/mux_coalescing.yml"


def scan(semgrep, target, require_clean=False):
    options = ["--jobs", "1", "--strict", "--no-git-ignore", "--config", str(RULES), "--json", "--quiet"]
    if require_clean:
        options.append("--error")
    result = run(semgrep, *options, str(target))
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete mux coalescing scan: {data}")
    if require_clean and (result.returncode or data["results"]):
        raise RuntimeError(f"Mux coalescing violations: {data['results']}")
    return data["results"]


def mutations(semgrep):
    source = (ROOT / "src/handshake/server.rs").read_text()
    start = source.index("async fn server_mux_target_reader_loop(")
    end = source.index("\n/// Writes the mux connection's download path:", start)
    reader = source[start:end]
    flush = "flush_server_mux_tail(&downlink, &payload_pool, &mut tail, &mut tail_deadline)"
    append_start = "                let take = mux_tail_append_len(tail.len(), input.len(), max_payload_len);\n"
    append_end = ("                if tail.len() == max_payload_len {\n"
                  "                    " + flush + "\n                        .await?;\n                }\n")
    variants = {
        "unbounded_capacity.rs": (replace_once(source, "available.min(capacity - buffered)", "available"),
                                  "parallax-mux-tail-capacity"),
        "long_window.rs": (replace_once(source,
            "const SERVER_MUX_TAIL_HOLD: Duration = Duration::from_millis(5);",
            "const SERVER_MUX_TAIL_HOLD: Duration = Duration::from_millis(50);"),
            "parallax-mux-tail-window"),
        "restart_deadline.rs": (replace_once(reader,
            "                if tail.is_empty() {\n                    tail_deadline =",
            "                if true {\n                    tail_deadline ="),
            "parallax-mux-tail-oldest-deadline"),
        "ready_read_starves_timer.rs": (replace_once(reader,
            "if Instant::now() >= deadline {", "if false {"), "parallax-mux-tail-ready-deadline"),
        "relative_read_timeout.rs": (replace_once(reader,
            "timeout_at(deadline, target_read.read(&mut target_buf))",
            "timeout(SERVER_MUX_TAIL_HOLD, target_read.read(&mut target_buf))"),
            "parallax-mux-tail-ready-deadline"),
        "discard_timeout.rs": (replace_once(reader,
            "Err(_) => {\n                    " + flush + "\n                        .await?;",
            "Err(_) => {\n                    tail.clear();"),
            "parallax-mux-tail-ready-deadline"),
        "fin_before_tail.rs": (replace_once(reader,
            "            " + flush + ".await?;\n            downlink.send(MuxFrameKind::Fin, Vec::new()).await?;",
            "            downlink.send(MuxFrameKind::Fin, Vec::new()).await?;\n            " + flush + ".await?;"),
            "parallax-mux-tail-eof-order"),
        "missing_eof_flush.rs": (replace_once(reader,
            "            " + flush + ".await?;\n", ""), "parallax-mux-tail-eof-order"),
        "unbounded_append.rs": (replace_once(reader,
            "tail.extend_from_slice(&input[..take]);", "tail.extend_from_slice(input);"),
            "parallax-mux-tail-bounded-append"),
        "lost_input_suffix.rs": (replace_once(reader,
            "input = &input[take..];", "input = &[];"), "parallax-mux-tail-bounded-append"),
        "extra_append_before_canonical.rs": (replace_once(reader, append_start,
            "                tail.extend_from_slice(input);\n" + append_start),
            "parallax-mux-tail-bounded-append"),
        "extra_append_after_canonical.rs": (replace_once(reader, append_end,
            append_end + "                tail.extend_from_slice(input);\n"),
            "parallax-mux-tail-bounded-append"),
        "nested_append_before_canonical.rs": (replace_once(reader, append_start,
            "                if !input.is_empty() { tail.extend_from_slice(input); }\n" + append_start),
            "parallax-mux-tail-bounded-append"),
        "failed_branch_append_after_canonical.rs": (replace_once(reader, append_end,
            append_end + "                if let Err(_) = Err::<(), ()>(()) { tail.extend_from_slice(input); }\n"),
            "parallax-mux-tail-bounded-append"),
        "duplicate_bounded_append_after_canonical.rs": (replace_once(reader, append_end,
            append_end + "                if !input.is_empty() { tail.extend_from_slice(&input[..take]); }\n"),
            "parallax-mux-tail-bounded-append"),
        "interleaved_failed_append.rs": (replace_once(reader, append_start,
            append_start + "                if let Err(_) = Err::<(), ()>(()) { tail.extend_from_slice(input); }\n"),
            "parallax-mux-tail-bounded-append"),
        "hold_full_frame.rs": (replace_once(reader,
            "                if tail.is_empty() && input.len() >= max_payload_len {",
            "                if false {"), "parallax-mux-tail-full-fast-path"),
        "discard_tail.rs": (replace_once(source,
            "let payload = std::mem::replace(tail, payload_pool.take());",
            "let payload = Vec::new();"), "parallax-mux-tail-flush"),
        "ignore_queue_failure.rs": (replace_once(source,
            "downlink.send(MuxFrameKind::Data, payload).await?;",
            "let _ = downlink.send(MuxFrameKind::Data, payload).await;"),
            "parallax-mux-tail-flush"),
    }
    # Reader fragments include the real production function and its surrounding
    # comments; global mutations retain the real complete file.
    with tempfile.TemporaryDirectory(prefix="parallax-mux-tail-rules-") as temporary:
        for name, (content, _) in variants.items():
            (Path(temporary) / name).write_text(content)
        found = {}
        for finding in scan(semgrep, temporary):
            found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
        for name, (_, expected) in variants.items():
            if expected not in found.get(name, set()):
                raise RuntimeError(f"Mux coalescing mutation escaped: {name} ({expected})")
    print(f"Mux coalescing production mutations: {len(variants)} detected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    result = run(args.semgrep, "--jobs", "1", "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip())
    scan(args.semgrep, ROOT / "src/handshake/server.rs", require_clean=True)
    mutations(args.semgrep)
    print("Mux coalescing AST guards: passed (source, fixtures, mutations)")


if __name__ == "__main__":
    main()
