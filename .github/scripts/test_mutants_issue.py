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
                "missed": [], "missed_total": 0, "complete": True, **changes}

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
                body = Path("body.md").read_text()
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

    def test_finished_artifact_uses_named_json_outcomes_and_keeps_commit(self):
        summaries = ("CaughtMutant", "MissedMutant", "Unviable", "Timeout")
        names = ("caught", "survivor", "cannot compile", "timed out")
        with patch.object(report, "SHA", "0123456789abcdef"):
            entry = self.read_artifact([{"name": name} for name in names], self.artifact(names, summaries))
        self.assertEqual(entry["missed"], ["survivor"])
        self.assertEqual([entry[k] for k in ("caught", "missed_total", "unviable", "timeout")], [1, 1, 1, 1])
        self.assertTrue(entry["complete"])
        self.assertEqual(entry["sha"], "0123456789abcdef")

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
            report.main()
            gh.assert_not_called()

    def test_closure_requires_all_eight_complete_shards_without_timeouts(self):
        for defect in ("missing_shard", "legacy_shard", "timeout", "survivor", None):
            with self.subTest(defect=defect):
                state = {str(i): self.entry() for i in range(8)}
                if defect == "missing_shard":
                    del state["7"]
                elif defect == "legacy_shard":
                    del state["7"]["complete"]
                elif defect == "timeout":
                    state["7"]["timeout"] = 1
                elif defect == "survivor":
                    state["7"].update(missed=["survivor"], missed_total=1)
                body, calls = self.run_report(state, self.entry())
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

    def test_github_failure_is_not_reported_as_success(self):
        with patch.object(report.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "denied")):
            with self.assertRaises(RuntimeError):
                report.gh("issue", "list")


if __name__ == "__main__":
    unittest.main()
