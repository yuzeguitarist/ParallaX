"""The registry guard must detect the drift it was added to prevent."""
import re
import unittest

import check_spec


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.spec = (check_spec.ROOT / "SPEC.md").read_text()
        self.sources = {path: (check_spec.ROOT / path).read_text()
                        for path in (check_spec.COMMAND, check_spec.TICKET)}

    def test_current_registry_matches(self):
        self.assertGreater(check_spec.check(self.spec, self.sources), 16)

    def test_old_shaping_tables_are_rejected(self):
        for current, stale in [
            ("[286, 339, 469, 519, 569, 713, 735, 1353]",
             "[286, 469, 569, 735, 911, 1180, 1353, 1600]"),
            ("735, 1353, 1440, 1459]", "735, 911, 1180, 1353]"),
        ]:
            with self.subTest(stale=stale):
                self.assertIn(current, self.spec)
                broken = self.spec.replace(current, stale, 1)
                with self.assertRaisesRegex(ValueError, "SPEC disagrees"):
                    check_spec.check(broken, self.sources)

    def test_shaping_registry_rows_are_required_once_even_with_prose(self):
        for name in ("CONNECT_RECORD_SIZE_BANDS", "PQ_FLIGHT_RECORD_TARGETS",
                     "SHAPED_RECORD_SIZE_JITTER"):
            row = re.search(rf"^\| `{name}` \|[^\n]+$", self.spec, re.MULTILINE)
            self.assertIsNotNone(row)
            without_row = self.spec[:row.start()] + self.spec[row.end():]
            self.assertIn(f"{name} = ", without_row)
            for broken in (without_row, self.spec + "\n" + row[0]):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "one SPEC registry row"):
                    check_spec.check(broken, self.sources)

    def test_jitter_registry_drift_is_rejected_even_with_correct_prose(self):
        current = '| `SHAPED_RECORD_SIZE_JITTER` | `96` |'
        self.assertIn(current, self.spec)
        with self.assertRaisesRegex(ValueError, "SPEC disagrees"):
            check_spec.check(self.spec.replace(current, current.replace("96", "97")), self.sources)

    def test_ticket_and_jitter_bound_drift_is_rejected(self):
        for name, value in [("MIN_SEALED_TICKET_LEN", 157),
                            ("MAX_SEALED_TICKET_LEN", 160),
                            ("SHAPED_RECORD_SIZE_JITTER", 96)]:
            with self.subTest(name=name):
                current = f"{name} = {value}"
                self.assertIn(current, self.spec)
                with self.assertRaisesRegex(ValueError, "SPEC disagrees"):
                    check_spec.check(self.spec.replace(current, f"{name} = {value + 1}"),
                                     self.sources)

    def test_missing_duplicate_or_incorrect_magic_is_rejected(self):
        row = '| `PX1C` | `50 58 31 43` |'
        self.assertIn(row, self.spec)
        for broken in [self.spec.replace(row, "", 1),
                       self.spec + "\n" + row,
                       self.spec.replace("50 58 31 43", "50 58 31 44", 1)]:
            with self.subTest(), self.assertRaises(ValueError):
                check_spec.check(broken, self.sources)


if __name__ == "__main__":
    unittest.main()
