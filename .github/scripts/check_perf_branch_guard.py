#!/usr/bin/env python3
"""No-regression guard for the long-lived perf/latency-peak branch.

Speed changes land in perf/latency-peak before main. This check keeps the
branch measured by main's security/camouflage yardstick:

1. every workflow that gates pull requests into main also gates pull requests
   into perf/latency-peak;
2. relative to the merge base with main, no captured-traffic fixture or
   censor-model data file is modified or removed;
3. relative to that merge base, no Rust test is removed or newly #[ignore]d.

Modified existing test files are reported as warnings for reviewers.
"""

import argparse
from collections import Counter
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BRANCH = "perf/latency-peak"
FROZEN = ("tests/fixtures/", "tests/gfw_sim/data/")
TEST_DIRS = ("src", "tests")
TEST_ATTR = re.compile(r"#\[(?:\w+::)*test\b")
FN = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)")


def pr_branches(text):
    """Return the pull_request branch filter of a workflow, or None."""
    block = re.search(r"^  pull_request:.*\n((?:    .*\n|\s*\n)*)", text, re.M)
    if not block:
        return None
    body = block.group(1)
    inline = re.search(r"^    branches:\s*\[(.*)\]", body, re.M)
    if inline:
        items = inline.group(1).split(",")
    else:
        listed = re.search(r"^    branches:\s*\n((?:      - .*\n)+)", body, re.M)
        if not listed:
            return None
        items = [line.split("- ", 1)[1] for line in listed.group(1).splitlines()]
    return [item.strip().strip("'\"") for item in items]


def ungated_workflows(workflows):
    missing = []
    for path in sorted(workflows.glob("*.yml")):
        branches = pr_branches(path.read_text())
        if branches and "main" in branches and BRANCH not in branches:
            missing.append(path.name)
    return missing


def rust_tests(text):
    """Count (all, non-ignored) test functions by name in Rust source."""
    total, active = Counter(), Counter()
    is_test = ignored = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#["):
            is_test = is_test or bool(TEST_ATTR.match(stripped))
            ignored = ignored or stripped.startswith("#[ignore")
            continue
        if not stripped or stripped.startswith("//"):
            continue
        match = FN.match(stripped)
        if is_test and match:
            total[match.group(1)] += 1
            if not ignored:
                active[match.group(1)] += 1
        is_test = ignored = False
    return total, active


def git(*args):
    return subprocess.run(
        ("git", *args), cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def tree_tests(rev):
    total, active = Counter(), Counter()
    for path in git("ls-tree", "-r", "--name-only", rev, "--", *TEST_DIRS).splitlines():
        if path.endswith(".rs"):
            file_total, file_active = rust_tests(git("show", f"{rev}:{path}"))
            total += file_total
            active += file_active
    return total, active


def regressions(base):
    errors, warnings = [], []
    for line in git("diff", "--name-status", "--no-renames", base, "HEAD").splitlines():
        status, path = line.split("\t", 1)
        if status == "A":
            continue
        if path.startswith(FROZEN):
            errors.append(f"frozen camouflage baseline changed ({status}): {path}")
        elif path.startswith("tests/"):
            warnings.append(f"existing test file changed ({status}): {path}")
    base_total, base_active = tree_tests(base)
    head_total, head_active = tree_tests("HEAD")
    for name in sorted(base_total):
        if head_total[name] < base_total[name]:
            errors.append(f"test removed: {name}")
        elif head_active[name] < base_active[name]:
            errors.append(f"test newly ignored: {name}")
    return errors, warnings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main")
    args = parser.parse_args()

    errors = [
        f"workflow gates main but not {BRANCH}: {name}"
        for name in ungated_workflows(ROOT / ".github" / "workflows")
    ]
    base = git("merge-base", args.base, "HEAD").strip()
    found, warnings = regressions(base)
    errors += found
    for warning in warnings:
        print(f"::warning::{warning}")
    for error in errors:
        print(f"::error::{error}")
    if errors:
        return 1
    print(f"perf branch guard: no regression against {base[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
