from src.detection import detect_account_lockouts
from src.detection import detect_success_after_failures
import tempfile
import unittest
from pathlib import Path

from src.detection import analyze_logs


class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "auth_logs.csv"
        self.write_logs([
            ("2026-10-12T10:00:00", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:05", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:10", "192.0.2.10", "4625"),
        ])

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_logs(self, rows):
        content = "timestamp,source_ip,event_id,username\n"
        content += "".join(
            f"{timestamp},{ip},{event_id},testuser\n"
            for timestamp, ip, event_id in rows
        )
        self.log_file.write_text(content, encoding="utf-8")

    def test_three_failures_trigger_alert(self):
        result = analyze_logs(
            self.log_file, threshold=3, window_minutes=5
        )
        self.assertIn("192.0.2.10", result)
        self.assertEqual(
            result["192.0.2.10"]["failed_attempts"], 3
        )

    def test_two_failures_do_not_trigger_alert(self):
        self.write_logs([
            ("2026-10-12T10:00:00", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:05", "192.0.2.10", "4625"),
        ])
        result = analyze_logs(
            self.log_file, threshold=3, window_minutes=5
        )
        self.assertNotIn("192.0.2.10", result)

    def test_failures_outside_window_do_not_trigger_alert(self):
        self.write_logs([
            ("2026-10-12T10:00:00", "192.0.2.10", "4625"),
            ("2026-10-12T10:03:00", "192.0.2.10", "4625"),
            ("2026-10-12T10:06:00", "192.0.2.10", "4625"),
        ])
        result = analyze_logs(
            self.log_file, threshold=3, window_minutes=5
        )
        self.assertNotIn("192.0.2.10", result)

    def test_success_after_three_failures_triggers_investigation(self):
        self.write_logs([
            ("2026-10-12T10:00:00", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:05", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:10", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:20", "192.0.2.10", "4624"),
        ])

        result = detect_success_after_failures(
            self.log_file, threshold=3, window_minutes=5
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source_ip"], "192.0.2.10")
        self.assertEqual(result[0]["failed_attempts"], 3)
        self.assertEqual(result[0]["status"], "INVESTIGATE")

    def test_success_without_enough_failures_does_not_trigger(self):
        self.write_logs([
            ("2026-10-12T10:00:00", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:05", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:20", "192.0.2.10", "4624"),
        ])

        result = detect_success_after_failures(
            self.log_file, threshold=3, window_minutes=5
        )

        self.assertEqual(result, [])

    def test_failure_then_success_detection_workflow(self):
        self.write_logs([
            ("2026-10-12T10:00:00", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:05", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:10", "192.0.2.10", "4625"),
            ("2026-10-12T10:00:20", "192.0.2.10", "4624"),
        ])

        failures = analyze_logs(
            self.log_file, threshold=3, window_minutes=5
        )
        sequence = detect_success_after_failures(
            self.log_file, threshold=3, window_minutes=5
        )

        self.assertIn("192.0.2.10", failures)
        self.assertEqual(len(sequence), 1)
        self.assertEqual(sequence[0]["status"], "INVESTIGATE")


    def test_account_lockout_event_is_detected(self):
        self.write_logs([
            ("2026-10-12T10:00:00", "192.0.2.10", "4740"),
        ])

        result = detect_account_lockouts(self.log_file)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["username"], "testuser")
        self.assertEqual(result[0]["rule"], "ACCOUNT_LOCKOUT")
        self.assertEqual(result[0]["status"], "INVESTIGATE")

    def test_unrelated_event_is_not_a_lockout(self):
        self.write_logs([
            ("2026-10-12T10:00:00", "192.0.2.10", "4625"),
        ])

        result = detect_account_lockouts(self.log_file)

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()



