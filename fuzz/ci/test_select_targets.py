#!/usr/bin/env python3
"""Unit tests for the nightly fuzz-target selector (select_targets.py).

Guards the property that motivated `nightly_select`: with a stale VPS pin the
since-pin diff selects the whole map, and the selector must still fuzz EVERY
target within a bounded window (no starvation) while running every core target
each night. Stdlib only.

Run: python3 fuzz/ci/test_select_targets.py
Wired into CI by fuzz-pr.yml's `select` job, next to `--check`.
"""
import importlib.util
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("select_targets", _HERE / "select_targets.py")
sel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sel)

DATA = sel.load_map(_HERE / "target-map.toml")
CORE = DATA["selection"]["core"]
ALL_TARGETS = list(DATA["targets"].keys())
CAP = 10  # matches fuzz-nightly.yml's default cap


class NightlySelectTest(unittest.TestCase):
    def test_saturated_diff_sweeps_every_target(self):
        """Stale pin == whole map selected. cap=10 must still reach every target
        within a bounded window (the old bug left 19/25 never fuzzed at HEAD)."""
        chosen = set(ALL_TARGETS)
        seen: set[str] = set()
        for day in range(0, 14):
            pick = sel.nightly_select(chosen, False, DATA, CAP, today_ord=day)
            self.assertEqual(len(pick), CAP, f"day {day}: expected {CAP} targets, got {pick}")
            self.assertEqual(len(set(pick)), CAP, f"day {day}: duplicate targets {pick}")
            for c in CORE:
                self.assertIn(c, pick, f"day {day}: core '{c}' must run every night")
            seen.update(pick)
        missing = set(ALL_TARGETS) - seen
        self.assertEqual(seen, set(ALL_TARGETS), f"targets never fuzzed in the window: {missing}")

    def test_deterministic_per_day(self):
        chosen = set(ALL_TARGETS)
        a = sel.nightly_select(chosen, False, DATA, CAP, today_ord=42)
        b = sel.nightly_select(chosen, False, DATA, CAP, today_ord=42)
        self.assertEqual(a, b)

    def test_precise_small_diff_is_kept_and_filled(self):
        """A precise single-target diff still runs that target, padded up to cap."""
        pick = sel.nightly_select({"quic_frame_decode"}, False, DATA, CAP, today_ord=7)
        self.assertIn("quic_frame_decode", pick)
        self.assertEqual(len(pick), CAP)
        self.assertEqual(len(set(pick)), CAP)

    def test_never_exceeds_available_targets(self):
        pick = sel.nightly_select(set(ALL_TARGETS), False, DATA, CAP, today_ord=0)
        self.assertLessEqual(len(pick), len(ALL_TARGETS))
        self.assertTrue(set(pick) <= set(ALL_TARGETS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
