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

    def compromise_fixture(self, root):
        verifier = catalog.module("compromise_fixture", catalog.ROOT / "verification/proverif/compromise.py")
        base = verifier.identity.MODEL.read_text()
        banner = "Proverif 2.05. Cryptographic protocol verifier"
        report = {"source_commit": "a" * 40, "working_tree_dirty": False, "status": "passed",
                  "source_regions": verifier.identity.check_source_contracts(),
                  "base_model_sha256": verifier.identity.sha256(base.encode()),
                  "runner_sha256": verifier.identity.sha256(Path(verifier.__file__).read_bytes()),
                  "expected_verifier_source": json.loads(verifier.identity.CONTRACTS.read_text())["verifier_source"],
                  "verifier": {"version": banner, "binary_sha256": "b" * 64}, "cases": []}
        (root / "verifier-version.log").write_text(banner + "\n")
        for name, model in verifier.variants(base):
            auth = str(name != "early_signing_disclosure").lower()
            phase1 = str(name == "late_signing_disclosure").lower()
            summary = f"""Verification summary:
Query inj-event(client_accepted(identity,pin,transcript,req,resp,e)) ==> inj-event(server_signed(identity,pin,transcript,req,resp,e)) is {auth}.
Query inj-event(client_derived(identity,pin,transcript,req,resp,e,key)) ==> inj-event(server_derived(identity,pin,transcript,req,resp,e,key)) is {auth}.
Query not attacker(application_secret[]) is {auth}.
Query not attacker_p1(application_secret[]) is {phase1}.
Query not event(acceptance_reached) is false.
Query not event(disclosure_reached) is false.
"""
            (root / f"{name}.pv").write_text(model)
            (root / f"{name}.log").write_text(summary)
            report["cases"].append({"case": name, "model_sha256": verifier.identity.sha256(model.encode()),
                                    "properties": verifier.parse_results(summary)})
        path = root / "verification.json"
        path.write_text(json.dumps(report))
        return path, report

    def test_compromise_verifier_metadata_is_required(self):
        changes = [
            lambda report: report.pop("verifier"),
            lambda report: report.update(verifier=None),
            lambda report: report["verifier"].pop("version"),
            lambda report: report["verifier"].update(version="Proverif 2.06. Wrong verifier"),
            lambda report: report["verifier"].pop("binary_sha256"),
            lambda report: report["verifier"].update(binary_sha256="b" * 63),
            lambda report: report["verifier"].update(binary_sha256="z" * 64),
            lambda report: report.pop("expected_verifier_source"),
            lambda report: report["expected_verifier_source"].update(sha256="c" * 64),
            lambda report: report.pop("runner_sha256"),
            lambda report: report.update(runner_sha256="d" * 64),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path, report = self.compromise_fixture(Path(directory))
            catalog.compromise_evidence(path, "a" * 40)
            for index, change in enumerate(changes):
                altered = copy.deepcopy(report)
                change(altered)
                path.write_text(json.dumps(altered))
                with self.subTest(case=index), self.assertRaises(ValueError):
                    catalog.compromise_evidence(path, "a" * 40)

    def test_compromise_retained_models_logs_and_results_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mode in ("wrong_verifier_log", "missing_verifier_log", "empty_verifier_log",
                         "model", "query_log", "properties", "missing_case"):
                path, report = self.compromise_fixture(root)
                if mode == "wrong_verifier_log":
                    (root / "verifier-version.log").write_text("Proverif 2.06. Wrong verifier\n")
                elif mode == "missing_verifier_log":
                    (root / "verifier-version.log").unlink()
                elif mode == "empty_verifier_log":
                    (root / "verifier-version.log").write_text("")
                elif mode == "model":
                    (root / "late_signing_disclosure.pv").write_text("unrelated model")
                elif mode == "query_log":
                    (root / "late_signing_disclosure.log").write_text("Verification summary:\n")
                elif mode == "properties":
                    report["cases"][0]["properties"]["phase1_secrecy"] = False
                else:
                    report["cases"].pop()
                path.write_text(json.dumps(report))
                with self.subTest(mode=mode), self.assertRaises((ValueError, OSError)):
                    catalog.compromise_evidence(path, "a" * 40)

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
