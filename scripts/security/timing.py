#!/usr/bin/env python3
"""Retain bounded reject-path timing measurements; not a constant-time proof."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location("assurance", Path(__file__).with_name("assurance.py"))
assurance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assurance)
ROOT = assurance.ROOT
PREFIX = "handshake::server::tests::"
MEASUREMENT = PREFIX + "rejection_path_timing_is_constant_dudect"
CONTROLS = [PREFIX + "welch_t_statistic_is_non_vacuous", PREFIX + "dudect_t_gate_is_non_vacuous"]
SHAPES = ("B(no-key_share)", "R(recover-None)", "D(auth-fail)")
DEFAULTS = {"DUDECT_SAMPLES": "20000", "DUDECT_PHYS_FLOOR_NS": "3000",
            "DUDECT_PHYS_MULT": "8", "DUDECT_T_ABS": "1000", "DUDECT_T_MULT": "10"}


def bounds(environment: dict[str, str]) -> dict[str, str]:
    chosen = {key: environment.get(key, value) for key, value in DEFAULTS.items()}
    samples = int(chosen["DUDECT_SAMPLES"])
    if not 1000 <= samples <= 1_000_000:
        raise ValueError("DUDECT_SAMPLES must be in 1000..1000000")
    for key, upper in (("DUDECT_PHYS_FLOOR_NS", 15000), ("DUDECT_PHYS_MULT", 10),
                       ("DUDECT_T_ABS", 1000), ("DUDECT_T_MULT", 10)):
        number = float(chosen[key])
        if not math.isfinite(number) or not 0 < number <= upper:
            raise ValueError(f"{key} must be finite and in (0, {upper}]")
    return chosen


def measurements(output: str, samples: int) -> list[dict]:
    pattern = re.compile(
        r"^dudect (.+) vs (.+): mean_gap=([0-9.]+)ns "
        r"\(ctrl ([0-9.]+)ns, allow ([0-9.]+)ns\) "
        r"\|t\|=([0-9.]+) \(ctrl ([0-9.]+), allow ([0-9.]+)\) samples=(\d+)$")
    rows = []
    for line in output.splitlines():
        line = line.removeprefix(f"test {MEASUREMENT} ... ")
        if not line.startswith("dudect "):
            continue
        match = pattern.fullmatch(line)
        if match is None:
            raise ValueError("malformed timing measurement")
        a, b, *numbers, count = match.groups()
        values = [float(value) for value in numbers]
        if int(count) != samples or any(not math.isfinite(value) for value in values):
            raise ValueError("timing sample budget or finite measurements disagree")
        rows.append(dict(zip(("left", "right", "mean_gap_ns", "control_gap_ns", "allow_gap_ns",
                              "welch_abs_t", "control_abs_t", "allow_abs_t", "samples"),
                             [a, b, *values, int(count)])))
    expected = set(itertools.permutations(SHAPES, 2))
    if len(rows) != len(expected) or {(row["left"], row["right"]) for row in rows} != expected:
        raise ValueError("all six distinct ordered shape measurements are required")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    try:
        chosen = bounds(os.environ)
    except (ValueError, TypeError) as error:
        print(f"invalid timing bounds: {error}", file=sys.stderr)
        return 1
    base = ["cargo", "test", "--locked", "--features", "dudect", "--lib"]
    if args.plan:
        print(json.dumps({"commands": [base + [name, "--", "--exact", "--nocapture",
                                             "--test-threads=1"] for name in [*CONTROLS, MEASUREMENT]],
                          "bounds": chosen}, indent=2))
        return 0
    parent = ROOT / "target/security/timing"
    parent.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    env = os.environ.copy()
    env.update(chosen)
    env.update(CARGO_TERM_COLOR="never", CARGO_BUILD_JOBS="4")
    report = {"schema_version": 1, "kind": "reject_path_timing", "status": "running",
              "bounds": chosen, "commands": [],
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "scope": "Fixed server key, three reject shapes and recorded platform/compiler. "
                       "Statistical regression experiment; no proof about every primitive, "
                       "secret, cache, power/EM channel or platform."}
    try:
        report["source_commit"] = assurance.execute(["git", "rev-parse", "HEAD"], output / "source.log", env).strip()
        report["working_tree_dirty"] = bool(assurance.execute(
            ["git", "status", "--porcelain"], output / "source-status.log", env).strip())
        report["toolchain"] = assurance.execute(["rustc", "-vV"], output / "toolchain.log", env).strip()
        for index, name in enumerate([*CONTROLS, MEASUREMENT]):
            listed = assurance.execute(base + [name, "--", "--exact", "--list"], output / f"{index}-list.log", env)
            if assurance.selected_tests(listed) != [name]:
                raise ValueError("timing test selection is missing or ambiguous")
            command = base + [name, "--", "--exact", "--nocapture", "--test-threads=1"]
            text = assurance.execute(command, output / f"{index}.log", env)
            assurance.checked_summary(text, 1)
            report["commands"].append({"argv": command, "log": f"{index}.log", "selected": name})
            if name == MEASUREMENT:
                report["measurements"] = measurements(text, int(chosen["DUDECT_SAMPLES"]))
        report["status"] = "no_detected_regression"
        print(f"Timing experiment completed: {output / 'report.json'}")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
