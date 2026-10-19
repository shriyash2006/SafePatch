from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from safepatch.approval import create_approval, valid_approval
from safepatch.command_scanner import command_hash, parse_command
from safepatch.report import load, save, verify
from safepatch.repository_scanner import scan_repository
from safepatch.runner import execute, repository_hash


class WorkflowTests(unittest.TestCase):
    def test_approval_is_bound_to_plan_command_and_snapshot(self) -> None:
        event = create_approval("plan-a", "command-a", "repo-a", "tests")
        self.assertTrue(valid_approval(event, "plan-a", "command-a", "repo-a"))
        self.assertFalse(valid_approval(event, "plan-b", "command-a", "repo-a"))
        self.assertFalse(valid_approval(event, "plan-a", "command-b", "repo-a"))
        self.assertFalse(valid_approval(event, "plan-a", "command-a", "repo-b"))

    def test_runner_uses_argv_without_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = parse_command({"id": "hello", "argv": ["python3", "-c", "print('ok')"]}, 0)
            result = execute(command, root)
            self.assertEqual(result["status"], "confirmed")
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["stdout"].strip(), "ok")

    def test_report_hash_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "report.json"
            from safepatch.models import Report

            report = Report(
                report_version="1",
                generated_at="now",
                repository_path=str(root),
                task="test",
                task_hash="task",
                plan_hash="plan",
                plan={"task": "test", "commands": []},
                policy_version="test",
                scanned_files=[],
                findings=[],
                command_decisions=[],
            )
            save(report, report_path)
            self.assertTrue(verify(load(report_path)))
            value = json.loads(report_path.read_text(encoding="utf-8"))
            value["task"] = "tampered"
            report_path.write_text(json.dumps(value), encoding="utf-8")
            self.assertFalse(verify(load(report_path)))

    def test_repository_hash_changes_when_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file.txt").write_text("one", encoding="utf-8")
            first = repository_hash(scan_repository(root).files)
            (root / "file.txt").write_text("two", encoding="utf-8")
            second = repository_hash(scan_repository(root).files)
            self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
