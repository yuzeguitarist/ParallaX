"""Catalog reference and supplemental evidence rejection controls, not Rust runs."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("security_catalog", Path(__file__).with_name("security_catalog.py"))
catalog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(catalog)


class CatalogControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(catalog.CATALOG.read_text())
        cls.items = catalog.validate(cls.document)

    def test_all_47_names_are_mapped_with_honest_modes(self):
        self.assertEqual(len(self.items), 47)
        for item in self.items:
            self.assertTrue(item["tests"] or item["analyses"])
            self.assertTrue(item["limitations"])
        certificate = next(item for item in self.items if item["name"] == "Certificate Revocation Checking")
        self.assertEqual(certificate["mode"], "policy_boundary")
        timing = [item for item in self.items if any(test["name"] == catalog.MEASUREMENT for test in item["tests"])]
        self.assertEqual(len(timing), 3)
        self.assertTrue(all(item["mode"] == "statistical" for item in timing))

    def test_missing_duplicate_stale_empty_and_false_certification_rejected(self):
        for mode in ("missing", "duplicate", "name", "group", "test", "contract", "analysis", "bounds", "certificate"):
            document = copy.deepcopy(self.document)
            entry = document["items"][0]
            if mode == "missing":
                document["items"].pop()
            elif mode == "duplicate":
                document["items"][-1] = copy.deepcopy(entry)
            elif mode == "name":
                entry["name"] = "Unrequested invented category"
            elif mode == "group":
                entry["group"] = "privacy"
            elif mode == "test":
                entry["tests"][0]["name"] = "missing_known_answer_test"
            elif mode == "contract":
                entry["protocol_contracts"] = ["missing-contract"]
            elif mode == "analysis":
                entry["analyses"] = ["../not-a-repository-artifact"]
            elif mode == "bounds":
                entry["limitations"] = []
            else:
                document["items"][1]["mode"] = "automated"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                catalog.validate(document)

    def test_supplemental_dirty_or_stale_provenance_rejected(self):
        for report in ({}, {"source_commit": "b" * 40, "working_tree_dirty": False},
                       {"source_commit": "a" * 40, "working_tree_dirty": True}):
            with self.assertRaises(ValueError):
                catalog.provenance(report, "a" * 40)
        catalog.provenance({"source_commit": "a" * 40, "working_tree_dirty": False}, "a" * 40)

    def fixture(self, root):
        names = [f"src/crypto/{file}.rs - {symbol} (line {line})"
                 for file, symbol in (("session", "crypto::session::SessionKeys"),
                                      ("pq", "crypto::pq::MlKemEncapsulation")) for line in (10, 20)]
        entry = {"selected": names, "passed": 4, "failed": 0, "ignored": 0}
        report = {"tests": {"production_api": entry}, "commands": [{"log": "production_api.log", "argv":
                  ["cargo", "test", "--locked", "--doc", "--", "--test-threads=1", "--nocapture"]}]}
        path = root / "report.json"
        path.write_text(json.dumps(report))
        (root / "production_api-list.log").write_text("".join(f"{name}: test\n" for name in names))
        (root / "production_api.log").write_text("test result: ok. 4 passed; 0 failed; 0 ignored;\n")
        return path, report

    def test_positive_and_negative_production_api_evidence_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _ = self.fixture(root)
            catalog.doctest_evidence(path)
            for mode in ("empty", "failed", "ignored", "missing_pair", "unlocked", "wrong_target", "no_log"):
                path, report = self.fixture(root)
                entry = report["tests"]["production_api"]
                if mode == "empty":
                    entry.update(selected=[], passed=0)
                elif mode == "failed":
                    entry["failed"] = 1
                elif mode == "ignored":
                    entry["ignored"] = 1
                elif mode == "missing_pair":
                    entry["selected"].pop()
                    entry["passed"] -= 1
                elif mode == "unlocked":
                    report["commands"][0]["argv"].remove("--locked")
                elif mode == "wrong_target":
                    report["commands"][0]["argv"].remove("--doc")
                else:
                    (root / "production_api.log").write_text("Compilation succeeded\n")
                path.write_text(json.dumps(report))
                with self.subTest(mode=mode), self.assertRaises((ValueError, RuntimeError)):
                    catalog.doctest_evidence(path)


if __name__ == "__main__":
    unittest.main()
