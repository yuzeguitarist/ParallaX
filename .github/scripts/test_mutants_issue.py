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
    def test_manual_or_unknown_artifact_cannot_update_nightly_report(self):
        for name in ["mutants-out-shard-crypto-0of8", "mutants-out-shard-8", "mutants-out-shard-0-extra", "unknown"]:
            with self.subTest(name=name), patch.object(report, "ART", name), patch.object(report, "gh") as gh:
                report.main()
                gh.assert_not_called()

    def test_stale_unknown_shard_is_removed_and_real_survivors_remain(self):
        entry = {"date": "old", "caught": 0, "unviable": 0, "timeout": 0,
                 "missed": ["real survivor"], "missed_total": 1}
        state = {"?": entry, "0": entry, "1": entry}
        issue = {"number": 54, "title": report.TITLE, "state": "OPEN",
                 "body": "<!-- mutants-state\n" + json.dumps(state) + "\n-->"}
        calls = []

        def gh(*args):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps([issue]) if args[:2] == ("issue", "list") else "", "")

        with tempfile.TemporaryDirectory() as directory, patch.object(report, "ART", directory + "/mutants-out-shard-0"), patch.object(report, "gh", gh), patch.object(report, "read_lines", return_value=[]):
            previous = os.getcwd()
            try:
                os.chdir(directory)
                report.main()
                body = Path("body.md").read_text()
            finally:
                os.chdir(previous)
        stored = json.loads(report.STATE_RE.search(body).group(1))
        self.assertEqual(set(stored), {"0", "1"})
        self.assertEqual(stored["1"], entry)
        self.assertIn("Total known survivors: 1", body)
        self.assertFalse(any(call[:2] == ("issue", "close") for call in calls))


if __name__ == "__main__":
    unittest.main()
