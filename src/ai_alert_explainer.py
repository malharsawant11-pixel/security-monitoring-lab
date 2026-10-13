
import json
import os
from pathlib import Path

from google import genai


def build_investigation(alert):
    """Prepare an evidence-based investigation request."""
    return {
        "task": (
            "Act as a defensive cybersecurity analyst. "
            "Use only the supplied evidence. Separate facts from "
            "hypotheses. Do not claim compromise without evidence. "
            "Recommend safe investigation and remediation steps."
        ),
        "alert": alert,
        "required_sections": [
            "summary",
            "observed_facts",
            "possible_explanations",
            "recommended_actions",
            "limitations",
        ],
    }


def explain_alert(alert):
    """Ask Gemini to explain an alert using synthetic or sanitized data."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set in this terminal session."
        )

    client = genai.Client(api_key=api_key)
    request_data = build_investigation(alert)

    response = client.models.generate_content(
        model="gemini-3.8-flash",
        contents=(
            "Return only valid JSON with these keys: summary, "
            "observed_facts, possible_explanations, "
            "recommended_actions, limitations.\n\n"
            + json.dumps(request_data)
        ),
        config={
            "response_mime_type": "application/json",
        },
    )

    result = json.loads(response.text)
    return result


def save_investigation(investigation, output_file):
    """Save an investigation result as formatted JSON."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(investigation, file, indent=2)

    return output_path


if __name__ == "__main__":
    sample_alert = {
        "source_ip": "192.0.2.10",
        "failed_attempts": 3,
        "first_seen": "2026-10-12T10:00:00",
        "last_seen": "2026-10-12T10:00:10",
        "status": "ALERT",
    }

    result = explain_alert(sample_alert)
    output = save_investigation(
        result, "reports/ai_investigation.json"
    )
    print(json.dumps(result, indent=2))
    print(f"\nInvestigation saved to: {output}")

