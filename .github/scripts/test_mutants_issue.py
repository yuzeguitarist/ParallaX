import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo", "ART_DIR": "unused"}):
    spec = importlib.util.spec_from_file_location("mutants_issue", Path(__file__).with_name("mutants_issue.py"))
    report = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(report)


class MutantsIssueTests(unittest.TestCase):
    def entry(self, **changes):
        return {"date": "old", "caught": 1, "unviable": 0, "timeout": 0,
                "missed": [], "missed_total": 0, "complete": True,
                "sha": "0123456789abcdef", "run_id": 0, "run_attempt": 1, **changes}

    def run_report(self, state, entry, issue_state="OPEN"):
        issue = {"number": 54, "title": report.TITLE, "state": issue_state,
                 "body": "<!-- mutants-state\n" + json.dumps(state) + "\n-->"}
        calls = []

        def gh(*args):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps([issue]) if args[:2] == ("issue", "list") else "", "")

        with tempfile.TemporaryDirectory() as directory, patch.object(report, "ART", directory + "/mutants-out-shard-0"), patch.object(report, "gh", gh), patch.object(report, "read_result", return_value=entry):
            previous = os.getcwd()
            try:
                os.chdir(directory)
                report.main()
                body = Path("body.md").read_text() if Path("body.md").exists() else None
            finally:
                os.chdir(previous)
        return body, calls

    def artifact(self, names=("first",), summaries=("CaughtMutant",)):
        counts = {"caught": "CaughtMutant", "missed": "MissedMutant",
                  "unviable": "Unviable", "timeout": "Timeout"}
        return {
            "outcomes": [{"scenario": "Baseline", "summary": "Success",
                          "phase_results": [{"phase": "Test", "process_status": "Success"}]}] + [
                {"scenario": {"Mutant": {"name": name}}, "summary": summary}
                for name, summary in zip(names, summaries)],
            "total_mutants": len(names), "end_time": "2026-11-08T00:00:00Z",
            **{key: summaries.count(summary) for key, summary in counts.items()},
        }

    def read_artifact(self, selected, outcomes):
        with tempfile.TemporaryDirectory() as directory, patch.object(report, "ART", directory):
            Path(directory, "mutants.json").write_text(json.dumps(selected))
            Path(directory, "outcomes.json").write_text(json.dumps(outcomes))
            return report.read_result()

    def test_manual_or_unknown_artifact_cannot_update_nightly_report(self):
        for name in ["mutants-out-shard-crypto-0of8", "mutants-out-shard-8", "mutants-out-shard-0-extra", "unknown"]:
            with self.subTest(name=name), patch.object(report, "ART", name), patch.object(report, "gh") as gh:
                report.main()
                gh.assert_not_called()

    def test_stale_unknown_shard_is_removed_and_real_survivors_remain(self):
        entry = self.entry(missed=["real survivor"], missed_total=1)
        state = {"?": entry, "0": entry, "1": entry}
        body, calls = self.run_report(state, self.entry())
        stored = json.loads(report.STATE_RE.search(body).group(1))
        self.assertEqual(set(stored), {"0", "1"})
        self.assertEqual(stored["1"], entry)
        self.assertIn("Total known survivors: 1", body)
        self.assertFalse(any(call[:2] == ("issue", "close") for call in calls))

    def test_finished_artifact_uses_named_json_outcomes_and_keeps_provenance(self):
        summaries = ("CaughtMutant", "MissedMutant", "Unviable", "Timeout")
        names = ("caught", "survivor", "cannot compile", "timed out")
        with patch.object(report, "SHA", "0123456789abcdef"), patch.object(report, "RUN_ID", 123), patch.object(report, "RUN_ATTEMPT", 2):
            entry = self.read_artifact([{"name": name} for name in names], self.artifact(names, summaries))
        self.assertEqual(entry["missed"], ["survivor"])
        self.assertEqual(entry["timed_out"], ["timed out"])
        self.assertEqual([entry[k] for k in ("caught", "missed_total", "unviable", "timeout")], [1, 1, 1, 1])
        self.assertTrue(entry["complete"])
        self.assertEqual(entry["sha"], "0123456789abcdef")
        self.assertEqual((entry["run_id"], entry["run_attempt"]), (123, 2))

    def test_full_result_is_available_to_autofix_while_issue_storage_is_capped(self):
        names = tuple(f"survivor {i}" for i in range(report.PER_SHARD_CAP + 1))
        entry = self.read_artifact([{"name": name} for name in names],
                                   self.artifact(names, ("MissedMutant",) * len(names)))
        self.assertEqual(entry["missed"], list(names))
        body, _ = self.run_report({}, entry)
        stored = json.loads(report.STATE_RE.search(body).group(1))["0"]
        self.assertEqual(stored["missed"], list(names[:report.PER_SHARD_CAP]))
        self.assertEqual(stored["missed_total"], len(names))
        self.assertIn("... and 1 more (see the run artifact)", body)
        self.assertEqual(entry["missed"], list(names))

    def test_partial_empty_failed_or_inconsistent_artifacts_cannot_replace_state(self):
        selected = [{"name": "first"}]
        for defect in ("empty", "no_end", "missing_outcome", "wrong_mutant", "duplicate",
                       "wrong_count", "unknown_summary", "failed_baseline", "no_baseline_tests"):
            with self.subTest(defect=defect):
                outcomes = self.artifact()
                expected = selected
                if defect == "empty":
                    expected = []
                    outcomes = self.artifact((), ())
                elif defect == "no_end":
                    outcomes["end_time"] = None
                elif defect == "missing_outcome":
                    outcomes["outcomes"].pop()
                elif defect == "wrong_mutant":
                    outcomes["outcomes"][1]["scenario"]["Mutant"]["name"] = "other"
                elif defect == "duplicate":
                    outcomes["outcomes"].append(outcomes["outcomes"][1])
                elif defect == "wrong_count":
                    outcomes["caught"] = 0
                elif defect == "unknown_summary":
                    outcomes["outcomes"][1]["summary"] = "Success"
                elif defect == "failed_baseline":
                    outcomes["outcomes"][0]["summary"] = "Failure"
                elif defect == "no_baseline_tests":
                    outcomes["outcomes"][0]["phase_results"] = []
                with self.assertRaises(ValueError):
                    self.read_artifact(expected, outcomes)
        with patch.object(report, "ART", "mutants-out-shard-0"), patch.object(report, "read_result", side_effect=FileNotFoundError), patch.object(report, "gh") as gh:
            with self.assertRaisesRegex(RuntimeError, "unverified shard artifact"):
                report.main()
            gh.assert_not_called()

    def test_closure_requires_all_eight_complete_shards_at_one_nonempty_commit(self):
        for defect in ("missing_shard", "legacy_shard", "timeout", "survivor",
                       "mixed_commits", "missing_commit", "empty_commits", None):
            with self.subTest(defect=defect):
                state = {str(i): self.entry() for i in range(8)}
                incoming = self.entry()
                if defect == "missing_shard":
                    del state["7"]
                elif defect == "legacy_shard":
                    del state["7"]["complete"]
                elif defect == "timeout":
                    state["7"]["timeout"] = 1
                elif defect == "survivor":
                    state["7"].update(missed=["survivor"], missed_total=1)
                elif defect == "mixed_commits":
                    state["7"]["sha"] = "another-commit"
                elif defect == "missing_commit":
                    del state["7"]["sha"]
                elif defect == "empty_commits":
                    state = {str(i): self.entry(sha="") for i in range(8)}
                    incoming["sha"] = ""
                body, calls = self.run_report(state, incoming)
                closes = [call for call in calls if call[:2] == ("issue", "close")]
                self.assertEqual(len(closes), int(defect is None))
                self.assertNotIn("All mutants caught", body)

    def test_completed_timeout_reopens_closed_issue_as_unresolved(self):
        body, calls = self.run_report({"0": self.entry()}, self.entry(timeout=1), issue_state="CLOSED")
        self.assertTrue(any(call[:2] == ("issue", "reopen") for call in calls))
        self.assertIn("unresolved timeouts: 1", body)
        self.assertFalse(any(call[:2] == ("issue", "close") for call in calls))

    def test_already_closed_clean_issue_does_not_receive_daily_closure_comment(self):
        _, calls = self.run_report({str(i): self.entry() for i in range(8)}, self.entry(), issue_state="CLOSED")
        self.assertFalse(any(call[:2] == ("issue", "close") for call in calls))

    def test_timeout_identity_change_reopens_but_same_timeout_does_not(self):
        previous = self.entry(timeout=1, timed_out=["first timeout"])
        for name in ("first timeout", "different timeout"):
            with self.subTest(name=name):
                incoming = self.entry(timeout=1, timed_out=[name])
                body, calls = self.run_report({"0": previous}, incoming, issue_state="CLOSED")
                self.assertEqual(any(call[:2] == ("issue", "reopen") for call in calls),
                                 name != "first timeout")
                self.assertIn("unresolved timeouts: 1", body)

    def test_unchanged_survivor_on_newer_run_does_not_reopen_closed_issue(self):
        previous = self.entry(run_id=123, missed=["survivor"], missed_total=1)
        incoming = {**previous, "run_id": 124}
        body, calls = self.run_report({"0": previous}, incoming, issue_state="CLOSED")
        self.assertIsNotNone(body)
        self.assertFalse(any(call[:2] in (("issue", "close"), ("issue", "reopen")) for call in calls))

    def test_older_run_attempt_and_duplicate_event_cannot_overwrite_newer_result(self):
        previous = self.entry(run_id=123, run_attempt=2)
        for run_id, attempt in ((122, 9), (123, 1), (123, 2)):
            with self.subTest(run_id=run_id, attempt=attempt):
                incoming = self.entry(run_id=run_id, run_attempt=attempt, missed=["stale survivor"], missed_total=1)
                body, calls = self.run_report({"0": previous}, incoming, issue_state="CLOSED")
                self.assertIsNone(body)
                self.assertEqual([call[:2] for call in calls], [("issue", "list")])

    def test_unchanged_survivors_beyond_storage_cap_do_not_reopen(self):
        missed = [f"survivor {i}" for i in range(report.PER_SHARD_CAP + 1)]
        previous = self.entry(run_id=123, missed=missed, missed_total=len(missed))
        body, _ = self.run_report({}, previous)
        stored = json.loads(report.STATE_RE.search(body).group(1))
        incoming = {**previous, "run_id": 124}
        body, calls = self.run_report(stored, incoming, issue_state="CLOSED")
        self.assertIsNotNone(body)
        self.assertFalse(any(call[:2] == ("issue", "reopen") for call in calls))

    def test_newer_run_or_attempt_and_legacy_replacement_can_update(self):
        for previous, incoming in ((self.entry(run_id=123, run_attempt=2), self.entry(run_id=123, run_attempt=3)),
                                   (self.entry(run_id=123, run_attempt=9), self.entry(run_id=124)),
                                   (self.entry(), self.entry(run_id=123))):
            with self.subTest(previous=previous, incoming=incoming):
                body, calls = self.run_report({"0": previous}, incoming)
                stored = json.loads(report.STATE_RE.search(body).group(1))
                self.assertEqual(stored["0"], incoming)
                self.assertTrue(any(call[:2] == ("issue", "edit") for call in calls))

    def test_github_failure_is_not_reported_as_success(self):
        with patch.object(report.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "denied")):
            with self.assertRaises(RuntimeError):
                report.gh("issue", "list")


if __name__ == "__main__":
    unittest.main()
