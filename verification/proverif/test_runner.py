import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("proverif_check", Path(__file__).with_name("run.py"))
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

SUMMARY = """Verification summary:
Query inj-event(client_accepted(identity,pin,transcript,req,resp,e)) ==> inj-event(server_signed(identity,pin,transcript,req,resp,e)) is true.
Query inj-event(client_derived(identity,pin,transcript,req,resp,e,key)) ==> inj-event(server_derived(identity,pin,transcript,req,resp,e,key)) is true.
Query not attacker(application_secret[]) is true.
Query not event(acceptance_reached) is false.
"""


class ResultValidationTests(unittest.TestCase):
    def test_exact_baseline_results(self):
        properties = checker.parse_results(SUMMARY)
        checker.require_results("baseline", properties)

    def test_missing_query_is_rejected(self):
        with self.assertRaises(ValueError):
            checker.parse_results(SUMMARY.replace("Query not attacker(application_secret[]) is true.\n", ""))

    def test_unknown_result_is_rejected(self):
        with self.assertRaises(ValueError):
            checker.parse_results(SUMMARY.replace("is true.", "cannot be proved.", 1))

    def test_duplicate_result_is_rejected(self):
        with self.assertRaises(ValueError):
            checker.parse_results(SUMMARY.replace(
                "Query not attacker(application_secret[]) is true.",
                "Query not event(acceptance_reached) is false.",
            ))

    def test_unexpected_result_is_rejected(self):
        with self.assertRaises(ValueError):
            checker.parse_results(SUMMARY.replace("not attacker(application_secret[])", "not attacker(other_secret[])"))

    def test_secret_decoy_and_altered_reachability_are_rejected(self):
        for original, replacement in (
            ("application_secret[]", "application_secret_decoy[]"),
            ("application_secret[]", "application_secret[identity]"),
            ("acceptance_reached)", "acceptance_reached_decoy)"),
            ("acceptance_reached)", "acceptance_reached(identity))"),
        ):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                checker.parse_results(SUMMARY.replace(original, replacement))

    def test_consistent_proverif_numeric_variable_renaming_is_accepted(self):
        renamed = SUMMARY
        for field in ("identity", "pin", "transcript", "req", "resp", "e", "key"):
            renamed = checker.re.sub(rf"\b{field}\b", field + "_42", renamed)
        self.assertEqual(checker.parse_results(renamed), checker.parse_results(SUMMARY))

    def test_wrong_correspondence_events_or_injectivity_are_rejected(self):
        for original, replacement in (
            ("server_signed(", "server_signed_decoy("),
            ("server_derived(", "server_signed("),
            ("client_accepted(", "client_accepted_decoy("),
            ("==> inj-event(", "==> event("),
        ):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                checker.parse_results(SUMMARY.replace(original, replacement))

    def test_missing_extra_swapped_or_constant_correspondence_fields_are_rejected(self):
        for original, replacement in (
            ("identity,pin,transcript,req,resp,e", "identity,pin,transcript,req,resp"),
            ("identity,pin,transcript,req,resp,e", "identity,pin,transcript,req,resp,e,key"),
            ("req,resp", "resp,req"),
            ("pin,transcript", "identity_label,transcript"),
            ("pin,transcript", "identity,transcript"),
            ("e,key", "e"),
            ("e,key", "e,key,req"),
        ):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                checker.parse_results(SUMMARY.replace(original, replacement))

    def test_inconsistent_correspondence_variable_renaming_is_rejected(self):
        for original, replacement in (
            ("server_signed(identity,pin,transcript,req,resp,e)",
             "server_signed(identity,pin,transcript_2,req,resp,e)"),
            ("server_derived(identity,pin,transcript,req,resp,e,key)",
             "server_derived(identity,pin,transcript,req,resp,e,key_2)"),
            ("server_derived(identity,pin,transcript,req,resp,e,key)",
             "server_derived(identity,pin,transcript,resp,req,e,key)"),
        ):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                checker.parse_results(SUMMARY.replace(original, replacement))

    def test_missing_or_ambiguous_summary_is_rejected(self):
        for output in (SUMMARY.replace("Verification summary:", ""), SUMMARY + SUMMARY):
            with self.subTest(output=output), self.assertRaises(ValueError):
                checker.parse_results(output)

    def test_auxiliary_negative_injective_explanation_is_not_a_query(self):
        auxiliary = "RESULT (even event(x) ==> event(y) is false.)\n"
        self.assertEqual(checker.parse_results(auxiliary + SUMMARY), checker.parse_results(SUMMARY))

    def test_false_baseline_property_is_rejected(self):
        properties = checker.parse_results(SUMMARY)
        properties["application_secrecy"] = False
        with self.assertRaises(ValueError):
            checker.require_results("baseline", properties)

    def test_unreachable_acceptance_is_rejected(self):
        properties = checker.parse_results(SUMMARY)
        properties["acceptance_unreachable"] = True
        with self.assertRaises(ValueError):
            checker.require_results("baseline", properties)

    def test_undetected_negative_control_is_rejected(self):
        with self.assertRaises(ValueError):
            checker.require_results("binding_erased", checker.parse_results(SUMMARY))

    def test_missing_expected_secrecy_attack_is_rejected(self):
        properties = checker.parse_results(SUMMARY)
        properties["pinned_server_full_tuple"] = False
        with self.assertRaises(ValueError):
            checker.require_results("identity_message_check_removed", properties)

    def test_negative_controls_preserve_queries(self):
        model = checker.MODEL.read_text()
        cases = list(checker.variants(model))
        self.assertEqual(len(cases), 6)
        for name, variant in cases:
            with self.subTest(case=name):
                self.assertEqual(checker.query_section(variant), checker.query_section(model))
                self.assertEqual(variant == model, name == "baseline")


class SourceContractTests(unittest.TestCase):
    def test_current_reviewed_regions_match(self):
        self.assertEqual(len(checker.check_source_contracts()), 24)

    def require_actual_source_deletion_rejected(self, identifier, removed):
        contracts = json.loads(checker.CONTRACTS.read_text())["regions"]
        contract, = [contract for contract in contracts if contract["id"] == identifier]
        original = (checker.ROOT / contract["path"]).read_text()
        span = checker.source_span(original, contract)
        self.assertEqual(span.count(removed), 1)
        mutated = original.replace(span, span.replace(removed, "", 1), 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / contract["path"]
            source.parent.mkdir(parents=True)
            source.write_text(original)
            manifest = root / "source_contracts.json"
            manifest.write_text(json.dumps({"regions": [contract]}))
            with patch.object(checker, "ROOT", root), patch.object(checker, "CONTRACTS", manifest):
                self.assertEqual(len(checker.check_source_contracts()), 1)
                source.write_text(mutated)
                with self.assertRaisesRegex(ValueError, "Source/model review required: " + identifier):
                    checker.check_source_contracts()

    def test_heap_ikm_pq_secret_deletion_requires_review(self):
        self.require_actual_source_deletion_rejected(
            "write_hybrid_rekey_ikm_vec", "    out.extend_from_slice(pq_shared_secret);\n",
        )

    def test_heap_ikm_psk_deletion_requires_review(self):
        self.require_actual_source_deletion_rejected(
            "write_hybrid_rekey_ikm_vec", "    out.extend_from_slice(symmetric_secret);\n",
        )

    def test_heap_expand_epoch_deletion_requires_review(self):
        self.require_actual_source_deletion_rejected(
            "expand", "        info.extend_from_slice(&epoch);\n",
        )

    def test_stack_expand_info_construction_deletion_requires_review(self):
        self.require_actual_source_deletion_rejected(
            "expand", "        let used = write_epoch_hkdf_info(&mut info, label, epoch, transcript_hash);\n",
        )

    def test_stack_epoch_info_epoch_deletion_requires_review(self):
        self.require_actual_source_deletion_rejected(
            "write_epoch_hkdf_info", "    write_bytes(out, &mut offset, &epoch.to_be_bytes());\n",
        )

    def test_ambiguous_function_is_rejected(self):
        with self.assertRaises(ValueError):
            checker.source_span("fn f() {\n}\nfn f() {\n}\n", {"id": "f", "function": "f"})

    def test_nested_block_does_not_end_function(self):
        source = "fn f() {\n    if true {\n        nested();\n    }\n    last();\n}\nfn g() {\n}\n"
        span = checker.source_span(source, {"id": "f", "function": "f"})
        self.assertIn("last();", span)
        self.assertNotIn("fn g", span)

    def test_changed_region_requires_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.rs"
            original = "fn f() {\n    first();\n}\n"
            source.write_text(original)
            contract = {"id": "f", "path": "source.rs", "function": "f"}
            contract["sha256"] = checker.sha256(checker.source_span(original, contract).encode())
            manifest = root / "source_contracts.json"
            manifest.write_text(json.dumps({"regions": [contract]}))
            with patch.object(checker, "ROOT", root), patch.object(checker, "CONTRACTS", manifest):
                self.assertEqual(len(checker.check_source_contracts()), 1)
                source.write_text(original.replace("first();", "different();"))
                with self.assertRaises(ValueError):
                    checker.check_source_contracts()


if __name__ == "__main__":
    unittest.main()
