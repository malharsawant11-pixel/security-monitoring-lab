
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

def detect_success_after_failures(
    log_file, threshold=3, window_minutes=5
):
    """Detect successful logons after repeated failures from the same IP."""
    events_by_ip = defaultdict(list)
    window = timedelta(minutes=window_minutes)

    with Path(log_file).open(
        newline="", encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            event_id = row.get("event_id")
            if event_id not in {"4624", "4625"}:
                continue

            ip = row.get("source_ip") or "unknown"

            try:
                timestamp = datetime.fromisoformat(row["timestamp"])
            except (ValueError, KeyError, TypeError):
                continue

            events_by_ip[ip].append((timestamp, event_id))

    alerts = []

    for ip, events in events_by_ip.items():
        events.sort(key=lambda event: event[0])

        for index, (success_time, event_id) in enumerate(events):
            if event_id != "4624":
                continue

            failures = [
                timestamp
                for timestamp, event in events[:index]
                if event == "4625"
                and timedelta(0) <= success_time - timestamp <= window
            ]

            if len(failures) >= threshold:
                alerts.append({
                    "source_ip": ip,
                    "failed_attempts": len(failures),
                    "success_time": success_time.isoformat(),
                    "status": "INVESTIGATE",
                    "rule": "SUCCESS_AFTER_REPEATED_FAILURES",
                })
                break

    return alerts


def detect_account_lockouts(log_file):
    """Detect Windows account lockout events (Event ID 4740)."""
    alerts = []

    with Path(log_file).open(
        newline="", encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            if row.get("event_id") != "4740":
                continue

            try:
                timestamp = datetime.fromisoformat(row["timestamp"])
            except (ValueError, KeyError, TypeError):
                continue

            alerts.append({
                "timestamp": timestamp.isoformat(),
                "username": row.get("username") or "unknown",
                "source_ip": row.get("source_ip") or "unknown",
                "status": "INVESTIGATE",
                "rule": "ACCOUNT_LOCKOUT",
            })

    return alerts
