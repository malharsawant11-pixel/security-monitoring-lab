
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


if __name__ == "__main__":
    unittest.main()


