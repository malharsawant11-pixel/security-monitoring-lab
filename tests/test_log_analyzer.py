import csv
from collections import Counter
from pathlib import Path

def analyze_logs(log_file, threshold=3):
    failed_attempts = Counter()

    with Path(log_file).open(
        newline="", encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            if row.get("event_id") == "4625":
                ip = row.get("source_ip", "unknown")
                failed_attempts[ip] += 1

    return {
        ip: count
        for ip, count in failed_attempts.items()
        if count >= threshold
    }
import tempfile
import unittest
from pathlib import Path

from src.detection import analyze_logs


class TestLogAnalyzer(unittest.TestCase):

    def test_three_failures_trigger_alert(self):
        data = (
            "timestamp,source_ip,event_id,username\n"
            "t1,192.0.2.10,4625,testuser\n"
            "t2,192.0.2.10,4625,testuser\n"
            "t3,192.0.2.10,4625,testuser\n"
        )

        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "logs.csv"
            log.write_text(data, encoding="utf-8")

            result = analyze_logs(log)
            self.assertEqual(result["192.0.2.10"], 3)

    def test_two_failures_do_not_trigger_alert(self):
        data = (
            "timestamp,source_ip,event_id,username\n"
            "t1,192.0.2.10,4625,testuser\n"
            "t2,192.0.2.10,4625,testuser\n"
        )

        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "logs.csv"
            log.write_text(data, encoding="utf-8")

            result = analyze_logs(log)
            self.assertNotIn("192.0.2.10", result)


if __name__ == "__main__":
    unittest.main()
