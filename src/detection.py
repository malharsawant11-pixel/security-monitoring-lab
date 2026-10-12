
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def analyze_logs(log_file, threshold=3, window_minutes=5):
    """Detect repeated failed logins within a rolling time window."""
    failed_by_ip = defaultdict(list)
    window = timedelta(minutes=window_minutes)

    with Path(log_file).open(
        newline="", encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            if row.get("event_id") != "4625":
                continue

            ip = row.get("source_ip") or "unknown"

            try:
                timestamp = datetime.fromisoformat(row["timestamp"])
            except (ValueError, KeyError, TypeError):
                continue

            failed_by_ip[ip].append(timestamp)

    alerts = {}

    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()

        for start in range(len(timestamps)):
            end = start

            while (
                end < len(timestamps)
                and timestamps[end] - timestamps[start] <= window
            ):
                end += 1

            count = end - start

            if count >= threshold:
                alerts[ip] = {
                    "failed_attempts": count,
                    "first_seen": timestamps[start].isoformat(),
                    "last_seen": timestamps[end - 1].isoformat(),
                    "status": "ALERT",
                }
                break

    return alerts
