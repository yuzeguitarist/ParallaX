#!/usr/bin/env python3
"""Blocking Rust AST boundaries plus mutations of actual client runtime source.

These checks enforce reviewed syntactic ordering, not a whole-program network
noninterference theorem. Socket regressions and production-predicate Kani proofs
provide complementary evidence.
"""

import argparse
import json
from pathlib import Path
import tempfile

from check_crypto_rules import replace_once, run


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/client_activation.yml"
FIXTURES = RULES.with_suffix(".rs")


def scan(semgrep, target, require_clean=False):
    options = ["--strict", "--no-git-ignore", "--config", str(RULES), "--json", "--quiet"]
    if require_clean:
        options.append("--error")
    result = run(semgrep, *options, str(target))
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete activation scan: {data}")
    if require_clean and (result.returncode or data["results"]):
        raise RuntimeError(f"Client activation boundary violations: {data['results']}")
    return data["results"]


def mutations(semgrep):
    source = (ROOT / "src/client/runtime.rs").read_text()
    socks = (ROOT / "src/client/socks.rs").read_text()
    guard = "    let request = accept_local_socks_connect(&mut local).await?;\n"
    start = source.index("async fn handle_local_connection_with_cid(")
    end = source.index("pub(crate) async fn establish_authenticated_data_session(", start)
    single = source[start:end]
    task_start = single.index("    let server_session_task = {\n")
    task_end = single.index("    // A failed initial-payload read", task_start)
    demand_task = single[task_start:task_end]
    extra_dial = """    let _spare = establish_authenticated_data_session_with_resolver(
        &server_addr, config, traffic, udp, &reachability, psk,
        server_public, server_identity_public.clone(),
    ).await?;
"""
    late_single = replace_once(single, guard, "")
    late_single = replace_once(late_single, "    let chunk_size =", guard + "    let chunk_size =")
    start_mux = source.index("async fn handle_local_mux_connection_with_cid(")
    end_mux = source.index("    let initial_payload_cap =", start_mux)
    mux = source[start_mux:end_mux]
    late_mux = replace_once(mux, guard, "") + guard
    activity_guard = """            if !mux_activity_is_recent(
                self.last_activity.load(Ordering::Relaxed),
                relay_now_millis(),
            ) {
                return Ok(());
            }
"""
    variants = {
        "startup_fill.rs": (replace_once(source, "        mux_sessions.start_keeper();\n",
                                           "        mux_sessions.ensure_warm().await;\n        mux_sessions.start_keeper();\n"),
                            "parallax-no-startup-carrier"),
        "early_single.rs": (source[:start] + late_single + source[end:],
                            "parallax-validate-socks-before-carrier"),
        "early_mux.rs": (source[:start_mux] + late_mux + source[end_mux:],
                         "parallax-validate-socks-before-carrier"),
        "unguarded_warm.rs": (replace_once(source, activity_guard, ""),
                              "parallax-mux-warm-activation-guard"),
        "eager_keeper.rs": (replace_once(source, "            let mut failures: u32 = 0;\n",
                                          "            pool.ensure_warm().await;\n            let mut failures: u32 = 0;\n"),
                            "parallax-no-eager-keeper-build"),
        "zero_stamp.rs": (replace_once(source,
                                        ".store(relay_now_millis().saturating_add(1), Ordering::Relaxed);",
                                        ".store(relay_now_millis(), Ordering::Relaxed);"),
                          "parallax-mux-activity-stamp"),
        "active_constructor.rs": (replace_once(source,
                                                "last_activity: Arc::new(AtomicU64::new(0)),",
                                                "last_activity: Arc::new(AtomicU64::new(1)),"),
                                  "parallax-mux-starts-inactive"),
        "implicit_activation.rs": (replace_once(source, "    last_activity != 0\n", "    true\n"),
                                   "parallax-mux-activity-sentinel"),
        "fake_parser.rs": (replace_once(source,
                                         "match timeout(SOCKS_ACCEPT_TIMEOUT, socks::accept_connect(local)).await",
                                         "match timeout(SOCKS_ACCEPT_TIMEOUT, fake_parser(local)).await"),
                           "parallax-validated-socks-boundary"),
        "socks_rsv_removed.rs": (replace_once(socks,
                                               "    if reserved != 0 {\n        return Err(SocksError::InvalidReserved);\n    }\n", ""),
                                 "parallax-socks-reserved-byte"),
        "single_spare_before.rs": (replace_once(source, demand_task, extra_dial + demand_task),
                                   "parallax-single-demand-carrier"),
        "single_spare_after.rs": (replace_once(source, demand_task, demand_task + extra_dial),
                                  "parallax-single-demand-carrier"),
        "single_spare_nested.rs": (replace_once(source, demand_task,
                                                 "    if cid == 0 {\n" + extra_dial + "    }\n" + demand_task),
                                   "parallax-single-demand-carrier"),
        "single_pool_refill.rs": (replace_once(source, demand_task,
                                                demand_task + "    pool.fill_locked(&mut warm);\n"),
                                  "parallax-single-demand-carrier"),
        "single_duplicate_task.rs": (replace_once(source, demand_task, demand_task + demand_task),
                                     "parallax-single-demand-carrier-once"),
        "single_looped_task.rs": (replace_once(source, demand_task,
                                                "    for _ in 0..4 {\n" + demand_task + "    }\n" + demand_task),
                                  "parallax-single-demand-carrier-once"),
    }
    with tempfile.TemporaryDirectory(prefix="parallax-activation-rules-") as temporary:
        for name, (content, _) in variants.items():
            (Path(temporary)/name).write_text(content)
        found = {}
        for finding in scan(semgrep, temporary):
            found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
        for name, (_, expected) in variants.items():
            if expected not in found.get(name, set()):
                raise RuntimeError(f"Activation mutation escaped: {name} ({expected})")
    print(f"Client runtime mutation checks: {len(variants)} detected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    result = run(args.semgrep, "--test", "--strict", "--config", str(RULES), str(FIXTURES))
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip())
    scan(args.semgrep, ROOT/"src/client/runtime.rs", require_clean=True)
    scan(args.semgrep, ROOT/"src/client/socks.rs", require_clean=True)
    mutations(args.semgrep)
    print("Client activation AST rules: passed (source, fixtures, mutations)")


if __name__ == "__main__":
    main()
