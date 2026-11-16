"""Exercise the actual cloud hook against explicit and aggregate refspecs."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


GUARD = Path(__file__).resolve().parents[1] / ".github/claude-hooks/guard-no-main-push.sh"


class PushGuardTests(unittest.TestCase):
    def test_only_explicit_claude_destinations_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["git", "init", "-q", "-b", "claude/test", directory], check=True)
            allowed = (
                "git push -u origin claude/test",
                "git push origin HEAD:refs/heads/claude/test",
                "git push --force-with-lease origin +HEAD:claude/test",
            )
            denied = (
                "git push", "git push origin", "git push origin main",
                "git push origin --all", "git push origin --tags", "git push --mirror origin",
                "git push origin claude/test --all", "git push --follow-tags origin claude/test",
                "git -c remote.origin.push=refs/heads/main push origin claude/test",
                "git push origin claude/test:refs/heads/other",
                "git push origin refs/heads/claude/*:refs/heads/claude/*",
                "git push origin HEAD:refs/heads/claude/../main",
                "git push origin HEAD:ma''in", "git push origin $TARGET",
                "git push origin claude/test; git push --all",
                "git push origin claude/test # --mirror",
                "git push origin clau\\de/test",
            )
            for command in (*allowed, *denied):
                with self.subTest(command=command):
                    result = subprocess.run(
                        ["bash", str(GUARD)], cwd=directory, capture_output=True, text=True,
                        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}),
                    )
                    self.assertEqual(result.returncode, 0 if command in allowed else 2, result.stderr)
            for setting in ("push.followTags", "remote.origin.mirror"):
                subprocess.run(["git", "config", setting, "true"], cwd=directory, check=True)
                result = subprocess.run(
                    ["bash", str(GUARD)], cwd=directory, capture_output=True, text=True,
                    input=json.dumps({"tool_name": "Bash", "tool_input": {"command": allowed[0]}}),
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                subprocess.run(["git", "config", "--unset", setting], cwd=directory, check=True)


if __name__ == "__main__":
    unittest.main()
