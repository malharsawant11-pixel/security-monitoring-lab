# Security Monitoring and Incident Investigation Lab

A Python-based cybersecurity project that detects repeated failed authentication attempts and uses a Large Language Model (LLM) to generate structured security investigation reports.

## Overview

This project simulates a defensive security monitoring workflow. It analyzes synthetic authentication logs, detects suspicious patterns of failed login attempts, exports alerts, and uses Google's Gemini API to explain detected alerts and recommend investigation steps.

The project was developed and tested in Kali Linux.

## Key Features

- **Authentication Log Analysis:** Parses CSV authentication events and identifies failed login attempts using Windows Event ID `4625`.
- **Threshold-Based Detection:** Flags source IP addresses after a configurable number of failed login attempts.
- **Time-Window Detection:** Detects repeated failures occurring within a configurable time window.
- **AI-Powered Alert Investigation:** Integrates Google's Gemini API to explain alerts and produce structured investigation reports.
- **Structured JSON Reports:** Generates explanations containing observed facts, possible explanations, recommended actions, and limitations.
- **CSV Alert Reporting:** Exports detected alerts for further investigation.
- **Automated Testing:** Includes unit tests for detection logic, report generation, and mocked LLM responses.

## Technologies Used

- Python 3
- Kali Linux
- Google Gemini API
- `google-genai` Python SDK
- CSV and JSON processing
- Git and GitHub
- Python `unittest`

## Project Structure

```text
security-monitoring-lab/
├── data/
│   └── sample_auth_logs.csv
├── reports/
│   ├── alerts.csv
│   ├── incident-report.md
│   ├── windows-log-investigation.md
│   └── ai_investigation.json
├── src/
│   ├── detection.py
│   ├── log_analyzer.py
│   └── ai_alert_explainer.py
├── tests/
│   ├── test_log_analyzer.py
│   └── test_ai_alert_explainer.py
├── .gitignore
└── README.md
```

## How Detection Works

1. Read authentication events from a CSV file.
2. Identify failed login events using Event ID `4625`.
3. Group failed attempts by source IP address.
4. Apply the configured threshold and time window.
5. Generate alerts when the detection conditions are met.
6. Export alert details to a CSV report.

The sample configuration uses a threshold of three failed attempts within five minutes.

## LLM-Powered Investigation

The `ai_alert_explainer.py` module sends an alert and its supporting evidence to Google's Gemini API.

The model is instructed to return a structured JSON investigation containing:

- **Summary:** A concise explanation of the alert.
- **Observed Facts:** Information directly supported by the supplied evidence.
- **Possible Explanations:** Potential reasons for the observed activity.
- **Recommended Actions:** Defensive investigation and remediation suggestions.
- **Limitations:** What cannot be concluded from the available evidence.

The LLM assists with investigation; it does not independently verify events or establish that an account has been compromised.

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/malharsawant11-pixel/security-monitoring-lab.git
cd security-monitoring-lab
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the Gemini SDK:

```bash
python -m pip install google-genai
```

## Configure the Gemini API Key

Create an API key through Google AI Studio. Configure it as an environment variable in your terminal:

```bash
read -rsp "Enter your Gemini API key: " GEMINI_API_KEY
echo
export GEMINI_API_KEY
```

The key is available to programs launched from that terminal session. Do not hardcode it in source files or commit it to GitHub.

## Run the Project

Run the authentication log analyzer:

```bash
python src/log_analyzer.py
```

Generate an AI investigation using the sample alert:

```bash
python src/ai_alert_explainer.py
```

The AI investigation module writes its structured result to:

```text
reports/ai_investigation.json
```

The AI command requires a valid Gemini API key and an available API connection. Use synthetic or sanitized data when testing external AI services.

## Run Automated Tests

Execute the test suite:

```bash
python -m unittest discover -s tests -v
```

**Current test coverage: 6 unit tests passing**, covering the existing detection logic, investigation request construction, JSON report saving, and mocked Gemini responses.

The LLM unit test mocks the API client and does not require a live API request.

## Security and Limitations

- This is a learning and portfolio project, not a production SIEM.
- Testing uses synthetic authentication data rather than a live enterprise log pipeline.
- A failed-login alert is an indicator for investigation, not proof of malicious activity.
- LLM-generated explanations may be inaccurate and should be reviewed by a human analyst.
- The current prototype does not automatically block IP addresses or remediate accounts.
- API credentials and sensitive logs must not be committed to the repository.

## Future Improvements

- Integrate Windows Event Logs or other authentication log sources.
- Add a dashboard for alert monitoring.
- Improve alert enrichment and investigation workflows.
- Add severity scoring and additional detection rules.
- Integrate with a SIEM or incident management platform.
- Expand automated testing and error handling.

## Author

**Malhar Sawant**

GitHub: https://github.com/malharsawant11-pixel/security-monitoring-lab
