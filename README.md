# Security Monitoring and Incident Investigation Lab

## Overview
A Python-based cybersecurity project that analyzes authentication
logs and flags repeated failed login events.

## Objectives
- Parse authentication events from CSV files.
- Count failed login events by source IP.
- Apply a configurable alert threshold.
- Export alerts to a CSV report.

## Technologies
- Python 3
- Kali Linux
- Git
- CSV log analysis

## Project Structure
- src/log_analyzer.py: Main detection script
- data/sample_auth_logs.csv: Synthetic test data
- reports/alerts.csv: Generated alert report
- screenshots/: Project evidence
- docs/: Investigation documentation

## Detection Logic
The script counts events with ID 4625 and flags a source IP
when it reaches the configured threshold of three failed events.

## Testing
- Three failed events: expected to trigger an alert.
- Two failed events: expected not to trigger an alert.

## Limitations
This is a prototype tested with synthetic CSV data.
It does not establish malicious intent or confirm account compromise.

## Future Improvements
- Add time-window analysis.
- Include timestamps in alert reports.
- Implement automated tests.
- Integrate with Windows event logs or a SIEM.
