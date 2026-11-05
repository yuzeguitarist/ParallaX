#!/usr/bin/env python3
"""Enforce reviewed ready-only drain and post-handshake KeyUpdate Rust AST.

This is a blocking syntactic regression check, not a TLS protocol proof. A real
TLS origin regression withholds post-Finished records until the client opening.
"""

import argparse
import json
from pathlib import Path
import tempfile

from check_crypto_rules import replace_once, run


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/tls_drain.yml"


def scan(semgrep, target, require_clean=False):
    result = run(semgrep, "--strict", "--no-git-ignore", "--config", str(RULES),
                 "--json", "--quiet", str(target))
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete TLS drain scan: {data}")
    if require_clean and (result.returncode or data["results"]):
        raise RuntimeError(f"TLS drain violations: {data['results']}")
    return data["results"]


def mutations(semgrep):
    source = (ROOT / "src/tls/safari26.rs").read_text()
    start = source.index("    async fn drain_post_handshake(")
    end = source.index("    async fn open_http2_connection(", start)
    drain = source[start:end]
    boundary = "                None if reader.at_record_boundary() => return Ok(observed),\n"
    timeout_error = """                        return Err(Safari26TlsError::Handshake(
                            "post-handshake drain timed out mid-record".to_owned(),
                        ))"""
    variants = {
        "blocking_empty.rs": (replace_once(drain,
                                           "reader.try_read_record_into(&mut record).await",
                                           "Some(reader.read_record_into(&mut record).await)"),
                              "parallax-tls-ready-drain"),
        "removed_boundary.rs": (replace_once(drain, boundary, ""),
                                "parallax-tls-ready-drain"),
        "wait_empty.rs": (replace_once(drain, boundary, boundary.replace(
            "return Ok(observed)", "reader.read_record_into(&mut record).await")),
                          "parallax-tls-ready-drain"),
        "discard_prefix.rs": (replace_once(drain, "reader.read_record_into(&mut record)",
                                           "TlsRecordReader::new(&mut *stream).read_record_into(&mut record)"),
                              "parallax-tls-ready-drain"),
        "partial_timeout_ok.rs": (replace_once(drain, timeout_error, "return Ok(observed)"),
                                  "parallax-tls-ready-drain"),
        "partial_eof_ok.rs": (replace_once(drain,
                                           "is_clean_close(&err) && reader.at_record_boundary()",
                                           "is_clean_close(&err)"),
                              "parallax-tls-ready-drain"),
        "extra_blocking.rs": (replace_once(drain, "            observed += 1;",
                                            "            reader.read_record_into(&mut record).await?;\n            observed += 1;"),
                               "parallax-tls-no-extra-blocking-drain"),
        "throwaway_reader.rs": (replace_once(drain, "        let mut observed = 0usize;",
                                              "        let _discarded = read_record(stream).await?;\n        let mut observed = 0usize;"),
                                 "parallax-tls-no-extra-blocking-drain"),
    }
    variants = {name: (source[:start] + content + source[end:], expected)
                for name, (content, expected) in variants.items()}
    handler_start = source.index("    async fn process_post_handshake_record(")
    handler_end = source.index("    fn ensure_post_handshake_boundary(", handler_start)
    handler = source[handler_start:handler_end]
    parser_start = source.index("fn parse_post_handshake_message(")
    parser_end = source.index("#[cfg(kani)]", parser_start)
    parser = source[parser_start:parser_end]
    h2_start = source.index("    async fn await_http2_settings_ack(")
    h2_end = source.index("    async fn process_http2_frames(", h2_start)
    h2 = source[h2_start:h2_end]
    update_start = source.index("fn update_application_traffic_keys(")
    update_end = source.index("fn finished_verify_data(", update_start)
    update = source[update_start:update_end]
    rotate = "                        keys.update_client_application_keys()?;\n"
    early_rotation = replace_once(handler, rotate, "")
    early_rotation = replace_once(early_rotation, "                        let response =",
                                   rotate + "                        let response =")
    additions = {
        "ignored_drain_handshake.rs": (source[start:handler_start],
            replace_once(source[start:handler_start], "self.process_post_handshake_record(",
                         "self.ignore_post_handshake_record("), "parallax-tls-post-handshake-processing"),
        "ignored_h2_handshake.rs": (h2, replace_once(h2, "self.process_post_handshake_record(",
            "self.ignore_post_handshake_record("), "parallax-tls-post-handshake-processing"),
        "bad_ku_length.rs": (parser, replace_once(parser, "if len != 1 {", "if false {"),
            "parallax-tls-key-update-framing"),
        "bad_ku_value.rs": (parser, replace_once(parser, '_ => Err("invalid KeyUpdate request value")',
            '_ => Ok(Some(PostHandshakeMessage::KeyUpdate { request_update: false }))'),
            "parallax-tls-key-update-framing"),
        "ku_not_record_end.rs": (parser, replace_once(parser, "if bytes.len() != total {", "if false {"),
            "parallax-tls-key-update-framing"),
        "oversized_ticket.rs": (parser, replace_once(parser, "if len > MAX_POST_HANDSHAKE_MESSAGE {", "if false {"),
            "parallax-tls-key-update-framing"),
        "unframed_ticket.rs": (parser, replace_once(parser, "bytes.len() >= total", "true"),
            "parallax-tls-key-update-framing"),
        "early_send_rotation.rs": (handler, early_rotation, "parallax-tls-key-update-response-order"),
        "missing_receive_rotation.rs": (handler, replace_once(handler,
            "                    keys.update_server_application_keys()?;\n", ""),
            "parallax-tls-key-update-response-order"),
        "wrong_update_response.rs": (handler, replace_once(handler,
            "&[HANDSHAKE_KEY_UPDATE, 0, 0, 1, 0]", "&[HANDSHAKE_KEY_UPDATE, 0, 0, 1, 1]"),
            "parallax-tls-key-update-response-order"),
        "ignored_response_write_error.rs": (handler, replace_once(handler,
            "stream.write_all(&response).await?;", "let _ = stream.write_all(&response).await;"),
            "parallax-tls-key-update-response-order"),
        "wrong_update_label.rs": (update, replace_once(update, '"traffic upd"', '"key"'),
            "parallax-tls-key-update-derivation"),
        "nonzero_new_sequence.rs": (update, replace_once(update,
            "let next_cipher = RecordCipher::new(suite, &next)?;",
            "let mut next_cipher = RecordCipher::new(suite, &next)?;\n    next_cipher.seq = 1;"),
            "parallax-tls-key-update-derivation"),
        "forgot_next_secret.rs": (update, replace_once(update, "    *secret = next;\n", ""),
            "parallax-tls-key-update-derivation"),
        "unbounded_fragments.rs": (handler, replace_once(handler,
            "> POST_HANDSHAKE_BUFFER_LIMIT", "> usize::MAX"), "parallax-tls-post-handshake-buffer"),
        "discarded_fragments.rs": (handler, replace_once(handler,
            "self.pending_post_handshake.drain(..consumed);", "self.pending_post_handshake.clear();"),
            "parallax-tls-post-handshake-buffer"),
        "unchecked_handoff.rs": (source, replace_once(source,
            "        self.open_http2_connection(stream, &mut keys).await?;\n        self.ensure_post_handshake_boundary()?;",
            "        self.open_http2_connection(stream, &mut keys).await?;"),
            "parallax-tls-post-handshake-handoff"),
        "ordinary_secret_storage.rs": (source, replace_once(source,
            "    server_application_secret: Zeroizing<Vec<u8>>,", "    server_application_secret: Vec<u8>,"),
            "parallax-tls-application-secrets-zeroizing"),
    }
    for name, (original, mutated, expected) in additions.items():
        variants[name] = (replace_once(source, original, mutated), expected)
    with tempfile.TemporaryDirectory(prefix="parallax-tls-drain-rules-") as temporary:
        for name, (content, _) in variants.items():
            (Path(temporary) / name).write_text(content)
        found = {}
        for finding in scan(semgrep, temporary):
            found.setdefault(Path(finding["path"]).name, set()).add(
                finding["check_id"].split(".")[-1])
        for name, (_, expected) in variants.items():
            if expected not in found.get(name, set()):
                raise RuntimeError(f"TLS drain mutation escaped: {name} ({expected})")
    print(f"TLS production drain mutation checks: {len(variants)} detected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    result = run(args.semgrep, "--test", "--strict", "--config", str(RULES),
                 str(RULES.with_suffix(".rs")))
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip())
    scan(args.semgrep, ROOT / "src/tls/safari26.rs", require_clean=True)
    mutations(args.semgrep)
    print("TLS ready-only drain AST rules: passed (source, fixtures, mutations)")


if __name__ == "__main__":
    main()
