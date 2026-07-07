#!/usr/bin/env python3
"""Adaptive fuzz-target selector for the free-tier GitHub Actions fuzzing.

Reads fuzz/ci/target-map.toml and emits the set of fuzz targets to run, as a
GitHub Actions matrix. Stdlib only (needs Python >= 3.11 for tomllib, which the
ubuntu-latest runner has).

Modes
-----
  --mode pr --base <sha>            targets touched by the PR diff (cap 4)
  --mode nightly --pin <commit>     targets touched since the VPS pin, then a
                                    date-rotated round-robin fills up to the cap
                                    (cap 6) so even a no-change night fuzzes HEAD
  --params <target>                 print FUZZ_SANITIZER/RSS/MAXLEN/TIMEOUT lines
  --check                           validate the map against fuzz/fuzz_targets/

Matrix modes print two lines to STDOUT (for $GITHUB_OUTPUT):
    targets=["a","b",...]
    empty=true|false
Diagnostics go to STDERR so STDOUT stays clean.

The selection per changed file (shared by both modes):
  1. file matches a target's glob   -> select those targets (precise)
  2. else matches a core_trigger    -> flag the core subset (build/dep churn)
  3. else under a src_prefix         -> flag the core subset (unmapped src: fail-open)
  4. else                            -> ignore (docs, ops/, .github, ...)
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - runner is 3.12
    sys.exit("select_targets.py needs Python >= 3.11 (tomllib); runner has older")

DEFAULT_MAP = Path(__file__).resolve().parent / "target-map.toml"
DEFAULT_CAP = {"pr": 4, "nightly": 10}


def load_map(path: Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def match(path: str, glob: str) -> bool:
    """Match a changed file against a map glob. `dir/**` is a recursive prefix."""
    if glob.endswith("/**"):
        return path == glob[:-3] or path.startswith(glob[:-2])
    return fnmatch.fnmatch(path, glob)


def select_for_files(files: list[str], data: dict) -> tuple[set[str], bool]:
    targets = data["targets"]
    sel = data["selection"]
    core_triggers = sel["core_triggers"]
    src_prefixes = tuple(sel["src_prefixes"])
    chosen: set[str] = set()
    core_flag = False
    for f in files:
        matched = [
            name
            for name, t in targets.items()
            if any(match(f, g) for g in t.get("paths", []))
        ]
        if matched:
            chosen.update(matched)
        elif any(match(f, g) for g in core_triggers):
            core_flag = True
        elif f.startswith(src_prefixes):
            core_flag = True
        # else: not a fuzz-relevant path -> ignore
    return chosen, core_flag


def priority_order(data: dict) -> list[str]:
    core = data["selection"]["core"]
    canonical = list(data["targets"].keys())
    return core + [t for t in canonical if t not in core]


def order_and_cap(chosen: set[str], core_flag: bool, data: dict, cap: int) -> list[str]:
    picked = set(chosen)
    if core_flag:
        picked.update(data["selection"]["core"])
    ordered = [t for t in priority_order(data) if t in picked]
    return ordered[:cap]


def rotation_fill(ordered: list[str], data: dict, cap: int) -> list[str]:
    """Append a date-rotated round-robin so a no-change night still runs `cap`
    targets, and consecutive nights sweep the whole list every ceil(N/cap) days."""
    canonical = list(data["targets"].keys())
    n = len(canonical)
    start = (date.today().toordinal() * cap) % n
    rotated = [canonical[(start + i) % n] for i in range(n)]
    out = list(ordered)
    for t in rotated:
        if len(out) >= cap:
            break
        if t not in out:
            out.append(t)
    return out[:cap]


def nightly_select(
    chosen: set[str],
    core_flag: bool,
    data: dict,
    cap: int,
    today_ord: int | None = None,
) -> list[str]:
    """Pick the nightly HEAD-fuzz targets.

    Every core target runs each night (they are the highest-value pre-auth
    surfaces, so this never regresses below the old behaviour); the remaining
    slots date-rotate through the rest of the selected targets so *every* target
    is fuzzed within a bounded number of nights.

    Why this exists: the VPS pin is hundreds of commits behind HEAD, so the
    since-pin diff selects the whole map. The old path (`order_and_cap` then
    `rotation_fill`) then deterministically kept the same top-`cap` core set every
    night and `rotation_fill` never fired (it only fills when < cap were chosen),
    so the non-core targets — the newest, least-soaked parsers — were never fuzzed
    at HEAD. Anchoring core + rotating the rest restores the intended full sweep.
    """
    picked = set(chosen)
    if core_flag:
        picked.update(data["selection"]["core"])
    pool = [t for t in priority_order(data) if t in picked] or list(data["targets"].keys())
    if len(pool) <= cap:
        # Empty/small diff: run everything selected, fill the rest by rotation
        # (the classic "even a no-change night still fuzzes `cap` targets" path).
        return rotation_fill(pool, data, cap)
    core = data["selection"]["core"]
    anchors = [t for t in pool if t in core][:cap]  # all core, every night
    rest = [t for t in pool if t not in core]
    slots = cap - len(anchors)
    if slots <= 0 or not rest:
        return anchors[:cap]
    ord_ = date.today().toordinal() if today_ord is None else today_ord
    start = (ord_ * slots) % len(rest)
    window = [rest[(start + i) % len(rest)] for i in range(min(slots, len(rest)))]
    return anchors + window


def changed_files(mode: str, base: str | None, pin: str | None) -> list[str]:
    if mode == "pr":
        if not base:
            sys.exit("--mode pr needs --base <sha>")
        rng = [f"{base}...HEAD"]
    else:
        if not pin:
            sys.exit("--mode nightly needs --pin <commit>")
        rng = [pin, "HEAD"]
    res = subprocess.run(
        ["git", "diff", "--name-only", *rng],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        sys.exit(f"git diff failed: {res.stderr.strip()}")
    return [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]


def emit_matrix(ordered: list[str]) -> None:
    print(f"targets={json.dumps(ordered)}")
    print(f"empty={'true' if not ordered else 'false'}")
    print(f"selected {len(ordered)}: {' '.join(ordered) or '(none)'}", file=sys.stderr)


def do_check(data: dict, map_path: Path) -> int:
    targets_dir = map_path.resolve().parent.parent / "fuzz_targets"
    disk = {p.stem for p in targets_dir.glob("*.rs")}
    mapped = set(data["targets"].keys())
    core = set(data["selection"]["core"])
    errors: list[str] = []
    if not disk:
        errors.append(f"no fuzz targets found under {targets_dir}")
    missing = disk - mapped
    extra = mapped - disk
    if missing:
        errors.append(f"targets on disk but missing from map: {sorted(missing)}")
    if extra:
        errors.append(f"map entries with no fuzz_targets/*.rs: {sorted(extra)}")
    if not core <= mapped:
        errors.append(f"core subset references unknown targets: {sorted(core - mapped)}")
    for name, t in data["targets"].items():
        for key in ("sanitizer", "rss", "max_len", "timeout", "paths"):
            if key not in t:
                errors.append(f"target {name} missing '{key}'")
        if t.get("sanitizer") not in ("address", "none"):
            errors.append(f"target {name} sanitizer must be address|none")
    if errors:
        for e in errors:
            print(f"target-map check: {e}", file=sys.stderr)
        return 1
    print(f"target-map check: OK ({len(mapped)} targets)", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["pr", "nightly"])
    ap.add_argument("--base", help="PR base sha (pr mode)")
    ap.add_argument("--pin", help="VPS pin commit (nightly mode)")
    ap.add_argument("--cap", type=int, help="max targets (default pr=4 nightly=6)")
    ap.add_argument("--params", metavar="TARGET", help="print run params for one target")
    ap.add_argument("--check", action="store_true", help="validate the map")
    ap.add_argument("--files-from", help="read changed files from a file/'-' (testing)")
    ap.add_argument("--map", type=Path, default=DEFAULT_MAP)
    args = ap.parse_args()

    data = load_map(args.map)

    if args.check:
        return do_check(data, args.map)

    if args.params:
        t = data["targets"].get(args.params)
        if t is None:
            sys.exit(f"unknown target: {args.params}")
        print(f"FUZZ_SANITIZER={t['sanitizer']}")
        print(f"FUZZ_RSS={t['rss']}")
        print(f"FUZZ_MAXLEN={t['max_len']}")
        print(f"FUZZ_TIMEOUT={t['timeout']}")
        return 0

    if not args.mode:
        sys.exit("need one of --mode, --params, or --check")

    cap = args.cap if args.cap else DEFAULT_CAP[args.mode]

    if args.files_from:
        src = sys.stdin if args.files_from == "-" else open(args.files_from)
        with src:
            files = [ln.strip() for ln in src if ln.strip()]
    else:
        files = changed_files(args.mode, args.base, args.pin)

    chosen, core_flag = select_for_files(files, data)
    if args.mode == "nightly":
        ordered = nightly_select(chosen, core_flag, data, cap)
    else:
        ordered = order_and_cap(chosen, core_flag, data, cap)
    emit_matrix(ordered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
