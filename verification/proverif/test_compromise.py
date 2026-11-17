import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("compromise_check", Path(__file__).with_name("compromise.py"))
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

SUMMARY = """Verification summary:
Query inj-event(client_accepted(identity,pin,transcript,req,resp,e)) ==> inj-event(server_signed(identity,pin,transcript,req,resp,e)) is true.
Query inj-event(client_derived(identity,pin,transcript,req,resp,e,key)) ==> inj-event(server_derived(identity,pin,transcript,req,resp,e,key)) is true.
Query not attacker(application_secret[]) is true.
Query not attacker_p1(application_secret[]) is true.
Query not event(acceptance_reached) is false.
Query not event(disclosure_reached) is false.
"""


class CompromiseControls(unittest.TestCase):
    def test_exact_late_signing_results(self):
        properties = checker.parse_results(SUMMARY)
        checker.require_results("late_signing_disclosure", properties)
        self.assertTrue(properties["phase0_secrecy"])
        self.assertTrue(properties["phase1_secrecy"])

    def test_missing_duplicate_wrong_phase_and_decoy_queries_are_rejected(self):
        for output in (
            SUMMARY.replace("Query not attacker_p1(application_secret[]) is true.\n", ""),
            SUMMARY.replace("attacker_p1(", "attacker("),
            SUMMARY.replace("attacker_p1(", "attacker_p2("),
            SUMMARY.replace("attacker_p1(application_secret[])", "attacker_p1(other_secret[])"),
            SUMMARY.replace("not event(disclosure_reached)", "not event(other_event)"),
            SUMMARY.replace("not event(disclosure_reached)", "not event(acceptance_reached)"),
            SUMMARY.replace("Verification summary:", ""),
            SUMMARY + SUMMARY,
            SUMMARY + "Query not attacker_p1(application_secret[]) is true.\n",
            SUMMARY.replace("is true.", "cannot be proved.", 1),
        ):
            with self.subTest(output=output), self.assertRaises(ValueError):
                checker.parse_results(output)

    def test_original_exact_correspondence_checks_are_preserved(self):
        for original, replacement in (
            ("==> inj-event(", "==> event("),
            ("server_signed(", "server_signed_decoy("),
            ("server_derived(identity,pin,transcript,req,resp,e,key)",
             "server_derived(identity,pin,transcript,resp,req,e,key)"),
        ):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                checker.parse_results(SUMMARY.replace(original, replacement))

    def test_unreachable_acceptance_or_disclosure_is_rejected(self):
        properties = checker.parse_results(SUMMARY)
        for field in ("acceptance_unreachable", "disclosure_unreachable"):
            changed = copy.deepcopy(properties)
            changed[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                checker.require_results("late_signing_disclosure", changed)

    def test_undetected_controls_and_wrong_disclosure_order_are_rejected(self):
        properties = checker.parse_results(SUMMARY)
        for case in ("late_session_disclosure", "early_signing_disclosure", "unknown"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                checker.require_results(case, properties)
        properties["phase1_secrecy"] = False
        checker.require_results("late_session_disclosure", properties)
        properties["phase0_secrecy"] = False
        with self.assertRaises(ValueError):
            checker.require_results("late_session_disclosure", properties)
        properties["pinned_server_full_tuple"] = False
        properties["derived_key_agreement"] = False
        checker.require_results("early_signing_disclosure", properties)

    def test_all_controls_preserve_queries_and_original_baseline(self):
        original = checker.identity.MODEL.read_text()
        variants = list(checker.variants(original))
        self.assertEqual(tuple(name for name, _ in variants), checker.CASE_NAMES)
        queries = checker.identity.query_section(variants[0][1])
        for name, model in variants:
            with self.subTest(case=name):
                self.assertEqual(checker.identity.query_section(model), queries)
                self.assertIn("query attacker(application_secret) phase 0.", model)
                self.assertIn("query attacker(application_secret) phase 1.", model)
                self.assertIn("phase 1; out(network, identity_secret); event disclosure_reached", model)
        self.assertEqual(len(list(checker.identity.variants(original))), 6)
        self.assertEqual(checker.identity.MODEL.read_text(), original)

    def test_session_control_reveals_actual_key_only_after_ciphertext(self):
        variants = dict(checker.variants(checker.identity.MODEL.read_text()))
        baseline = variants["late_signing_disclosure"]
        leaked = variants["late_session_disclosure"]
        self.assertNotIn("out(network, key)", baseline)
        self.assertIn(checker.SEND + ";\n  phase 1; out(network, key).", leaked)
        self.assertNotIn("out(network, application_secret)", leaked)
        early = variants["early_signing_disclosure"]
        self.assertIn("out(network, public_identity(identity_secret));\n  out(network, identity_secret);", early)
        self.assertNotIn("out(network, public_identity(identity_secret));\n  out(network, identity_secret);", baseline)

    def test_changed_source_anchor_blocks_model_derivation(self):
        model = checker.identity.MODEL.read_text()
        with self.assertRaises(ValueError):
            list(checker.variants(model.replace(checker.SEND, "out(network, identity_label)")))


if __name__ == "__main__":
    unittest.main()
