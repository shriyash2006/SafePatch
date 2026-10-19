from __future__ import annotations

import unittest

from safepatch.demo_server import DemoApplication


class DemoApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.application = DemoApplication()

    def tearDown(self) -> None:
        self.application.close()

    def test_clean_demo_scans_and_runs_the_example_tests(self) -> None:
        report = self.application.scan("clean")

        self.assertEqual(report["decision"], "allow")
        self.assertEqual(report["blocked_commands"], 0)
        self.assertTrue(report["report_valid"])

        result = self.application.run(report["scan_id"], "tests")

        self.assertEqual(result["commands"][0]["execution"]["status"], "confirmed")
        self.assertTrue(self.application.verify(report["scan_id"])["valid"])

    def test_risky_demo_blocks_remote_installer(self) -> None:
        report = self.application.scan("risky")

        self.assertEqual(report["decision"], "block")
        self.assertEqual(report["blocked_commands"], 1)
        self.assertEqual(report["findings_count"], 2)
        blocked = next(item for item in report["commands"] if item["command_id"] == "remote-installer")
        self.assertEqual(blocked["decision"], "block")

        result = self.application.run(report["scan_id"], "remote-installer")

        self.assertEqual(result["cli_exit_code"], 2)
        self.assertIsNone(result["commands"][0]["execution"])


if __name__ == "__main__":
    unittest.main()
