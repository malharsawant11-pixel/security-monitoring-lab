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
