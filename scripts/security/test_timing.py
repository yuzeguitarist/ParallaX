"""Reject empty, incomplete and unbounded timing experiment evidence."""
import importlib.util
import itertools
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("timing", Path(__file__).with_name("timing.py"))
timing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(timing)


class TimingControls(unittest.TestCase):
    def fixture(self):
        return "\n".join(f"dudect {a} vs {b}: mean_gap=2ns (ctrl 1ns, allow 3000ns) "
                         "|t|=1.50 (ctrl 0.50, allow 1000.00) samples=1000"
                         for a, b in itertools.permutations(timing.SHAPES, 2))

    def test_complete_ordered_pairs_and_bounds(self):
        rows = timing.measurements(self.fixture(), 1000)
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[0]["mean_gap_ns"], 2)
        self.assertEqual(len(timing.measurements(
            f"test {timing.MEASUREMENT} ... " + self.fixture(), 1000)), 6)
        self.assertEqual(timing.bounds({})["DUDECT_SAMPLES"], "20000")

    def test_missing_duplicate_bad_sample_and_malformed_rows_fail(self):
        text = self.fixture()
        first = text.splitlines()[0]
        for bad in ("", "\n".join(text.splitlines()[:-1]), text + "\n" + first,
                    text.replace("samples=1000", "samples=999"),
                    text.replace("mean_gap=2ns", "mean_gap=NaNns"),
                    text.replace("D(auth-fail)", "unknown")):
            with self.subTest(bad=bad[:80]), self.assertRaises(ValueError):
                timing.measurements(bad, 1000)

    def test_disabled_excessive_and_nonfinite_parameters_fail(self):
        for value in ("0", "999", "1000001", "bad"):
            with self.assertRaises(ValueError):
                timing.bounds({"DUDECT_SAMPLES": value})
        for key in timing.DEFAULTS.keys() - {"DUDECT_SAMPLES"}:
            for value in ("0", "-1", "NaN", "inf", "1000000"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    timing.bounds({key: value})


if __name__ == "__main__":
    unittest.main()
