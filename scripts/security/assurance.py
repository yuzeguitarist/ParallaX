#!/usr/bin/env python3
"""Run the project's bounded protocol, listener and concurrency assurance suites.

Each invocation records the source revision, command, selected tests, scheduler
bounds and complete logs. A successful command that ran no tests is a failure.
ASan/TSan/LSan use sanitizers.py; dependency and release controls have separate
tools documented in docs/security/README.md.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
NIGHTLY = "nightly-2026-06-17"
MODEL_MANIFEST = "verification/concurrency/Cargo.toml"
KINDS = ("protocol", "listener", "loom", "shuttle")


def selections(kind: str) -> list[tuple[str, list[str], list[str]]]:
    if kind == "protocol":
        return [(name, ["cargo", "test", "--locked", "--test", name], [])
                for name in ("security_protocol_differential", "security_fault_injection",
                             "mldsa_differential", "mldsa_acvp")]
    if kind == "listener":
        return [("security_listener", ["cargo", "test", "--locked", "--test",
                                      "security_listener"], ["--ignored"])]
    cargo = ["cargo", f"+{NIGHTLY}"] if kind == "loom" else ["cargo"]
    return [(kind, cargo + ["test", "--locked", "--release", "--manifest-path",
                           MODEL_MANIFEST, "--features", kind, "--test", kind], [])]


def selected_tests(output: str) -> list[str]:
    return re.findall(r"^([A-Za-z_][A-Za-z0-9_:]*): test$", output, re.MULTILINE)


def checked_summary(output: str, expected: int) -> dict[str, int]:
    summaries = re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", output)
    if not summaries or expected == 0:
        raise RuntimeError("no test execution evidence")
    passed, failed, ignored = (sum(int(row[i]) for row in summaries) for i in range(3))
    if failed or ignored or passed != expected:
        raise RuntimeError(
            f"test selection did not fully execute: selected={expected}, "
            f"passed={passed}, failed={failed}, ignored={ignored}")
    return {"passed": passed, "failed": failed, "ignored": ignored}


def execute(command: list[str], logfile: Path, env: dict[str, str],
            timeout: int = 2400) -> str:
    print("+ " + " ".join(command), flush=True)
    with logfile.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except BaseException:
            # Cargo owns compiler/test children; kill the entire isolated group
            # on timeout or cancellation, not only its parent process.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    output = logfile.read_text(encoding="utf-8", errors="replace")
    if status:
        print(output[-16000:], file=sys.stderr)
        raise RuntimeError(f"exit {status}: {logfile}")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=KINDS)
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    plan = selections(args.kind)
    if args.plan:
        print(json.dumps(plan, indent=2))
        return 0
    output = ROOT / "target/security/assurance" / args.kind
    output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({"CARGO_INCREMENTAL": "0", "CARGO_TERM_COLOR": "never",
                "CARGO_BUILD_JOBS": "4", "RUST_BACKTRACE": "1"})
    # Separate model target caches from production; their feature aliases must
    # never become release binary dependencies.
    if args.kind in ("loom", "shuttle"):
        env["CARGO_TARGET_DIR"] = str(ROOT / "target/security/models" / args.kind)
    defaults = {"PARALLAX_LOOM_PREEMPTIONS": "2",
                "PARALLAX_SHUTTLE_SEED": "20260828",
                "PARALLAX_SHUTTLE_ITERATIONS": "200",
                "PARALLAX_MODEL_WORKLOAD_SEED": "0" if args.kind == "loom" else "257"}
    for key, value in defaults.items():
        env.setdefault(key, value)
    report = {"schema_version": 1, "kind": args.kind, "status": "running",
              "commands": [], "tests": {},
              "bounds": {key: env[key] for key in defaults},
              "shuttle_replay": env.get("PARALLAX_SHUTTLE_REPLAY"),
              "scope": "bounded executed paths and schedules; not a proof of all interleavings"}
    try:
        report["source_commit"] = execute(
            ["git", "rev-parse", "HEAD"], output / "source.log", env).strip()
        report["working_tree_dirty"] = bool(execute(
            ["git", "status", "--porcelain"], output / "source-status.log", env).strip())
        rustc = ["rustc", f"+{NIGHTLY}", "-vV"] if args.kind == "loom" else ["rustc", "-vV"]
        report["toolchain"] = execute(rustc, output / "toolchain.log", env).strip()
        for label, command, runtime in plan:
            listing = command + ["--"] + runtime + ["--list"]
            names = selected_tests(execute(listing, output / f"{label}-list.log", env))
            if not names:
                raise RuntimeError(f"empty test selection: {label}")
            run = command + ["--"] + runtime + ["--test-threads=1", "--nocapture"]
            report["commands"].append({"argv": run, "log": f"{label}.log"})
            report["tests"][label] = {"selected": names}
            results = execute(run, output / f"{label}.log", env)
            report["tests"][label].update(checked_summary(results, len(names)))
        report["status"] = "passed"
        print(f"{args.kind}: passed; evidence: {output / 'report.json'}")
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n",
                                           encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
