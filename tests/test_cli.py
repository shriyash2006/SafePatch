from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from safepatch.cli import main


class CliTests(unittest.TestCase):
    def test_scan_writes_report_and_blocks_risky_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            (repo / "README.md").write_text("ordinary documentation", encoding="utf-8")
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "task": "Prepare the project.",
                        "commands": [
                            {
                                "id": "danger",
                                "argv": ["rm", "-rf", "./"],
                                "cwd": ".",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = root / "report.json"
            self.assertEqual(main(["scan", "--repo", str(repo), "--plan", str(plan), "--report", str(report)]), 2)
            self.assertTrue(report.exists())
            value = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(value["command_decisions"][0]["decision"], "block")


if __name__ == "__main__":
    unittest.main()
