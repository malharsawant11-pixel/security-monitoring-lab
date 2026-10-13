
import csv
from pathlib import Path

from detection import (
    analyze_logs,
    detect_success_after_failures,
)


log_file = Path("data/sample_auth_logs.csv")
report_file = Path("reports/alerts.csv")
threshold = 3
window_minutes = 5

if not log_file.exists():
    print(f"Log file not found: {log_file}")
    raise SystemExit(1)

# Rule 1: Repeated failed logins.
failure_alerts = analyze_logs(
    log_file,
    threshold=threshold,
    window_minutes=window_minutes,
)

# Rule 2: Successful login following repeated failures.
sequence_alerts = detect_success_after_failures(
    log_file,
    threshold=threshold,
    window_minutes=window_minutes,
)

report_file.parent.mkdir(parents=True, exist_ok=True)

fields = [
    "source_ip",
    "failed_attempts",
    "first_seen",
    "last_seen",
    "success_time",
    "status",
    "rule",
]

with report_file.open(
    "w", newline="", encoding="utf-8"
) as file:
    writer = csv.DictWriter(
    file,
    fieldnames=fields,
    lineterminator="\n",
)
    writer.writeheader()

    for ip, details in failure_alerts.items():
        writer.writerow({
            "source_ip": ip,
            **details,
            "success_time": "",
            "rule": "REPEATED_FAILED_LOGINS",
        })

    for alert in sequence_alerts:
        writer.writerow({
            "source_ip": alert["source_ip"],
            "failed_attempts": alert["failed_attempts"],
            "first_seen": "",
            "last_seen": "",
            "success_time": alert["success_time"],
            "status": alert["status"],
            "rule": alert["rule"],
        })

print("Authentication Log Analysis")
print("-" * 30)
print(f"Detection window: {window_minutes} minutes")
print(f"Failure threshold: {threshold} attempts")
print(f"Repeated-failure alerts: {len(failure_alerts)}")
print(f"Failure-then-success alerts: {len(sequence_alerts)}")

for ip, details in failure_alerts.items():
    print(
        f"ALERT: {ip} — {details['failed_attempts']} failed attempts "
        f"from {details['first_seen']} to {details['last_seen']}"
    )

for alert in sequence_alerts:
    print(
        f"INVESTIGATE: {alert['source_ip']} — "
        f"{alert['failed_attempts']} failures followed by a successful "
        f"login at {alert['success_time']}"
    )

if not failure_alerts and not sequence_alerts:
    print("No alerts detected.")

print(f"\nReport saved to: {report_file}")
