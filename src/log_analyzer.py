import csv
from collections import Counter
from pathlib import Path

log_file = Path("data/sample_auth_logs.csv")
report_file = Path("reports/alerts.csv")
threshold = 3

if not log_file.exists():
    print(f"Log file not found: {log_file}")
    raise SystemExit(1)

failed_attempts = Counter()

with log_file.open(newline="", encoding="utf-8") as file:
    reader = csv.DictReader(file)

    for row in reader:
        if row.get("event_id") == "4625":
            source_ip = row.get("source_ip", "unknown")
            failed_attempts[source_ip] += 1

report_file.parent.mkdir(parents=True, exist_ok=True)

with report_file.open("w", newline="", encoding="utf-8") as file:
    fields = ["source_ip", "failed_attempts", "status"]
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()

    for ip, count in failed_attempts.items():
        status = "ALERT" if count >= threshold else "Below threshold"
        writer.writerow({
            "source_ip": ip,
            "failed_attempts": count,
            "status": status
        })

print("Authentication Log Analysis")
print("-" * 30)

for ip, count in failed_attempts.items():
    print(f"{ip}: {count} failed login(s)")
    if count >= threshold:
        print("  ALERT: Threshold exceeded")

print(f"\nReport saved to: {report_file}")
