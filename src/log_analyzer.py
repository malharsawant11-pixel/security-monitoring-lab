
import csv
from pathlib import Path

from detection import analyze_logs


log_file = Path("data/sample_auth_logs.csv")
report_file = Path("reports/alerts.csv")
threshold = 3
window_minutes = 5

if not log_file.exists():
    print(f"Log file not found: {log_file}")
    raise SystemExit(1)

alerts = analyze_logs(
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
    "status",
]

with report_file.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()

    for ip, details in alerts.items():
        writer.writerow({
            "source_ip": ip,
            **details,
        })

print("Authentication Log Analysis")
print("-" * 30)
print(f"Detection window: {window_minutes} minutes")
print(f"Alert threshold: {threshold} failed attempts")

if alerts:
    for ip, details in alerts.items():
        print(
            f"ALERT: {ip} — "
            f"{details['failed_attempts']} failed attempts "
            f"from {details['first_seen']} "
            f"to {details['last_seen']}"
        )
else:
    print("No alerts detected.")

print(f"\nReport saved to: {report_file}")

