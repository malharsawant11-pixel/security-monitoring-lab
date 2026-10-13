
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.ai_alert_explainer import (
    build_investigation,
    explain_alert,
    save_investigation,
)


class TestAIAlertExplainer(unittest.TestCase):

    def setUp(self):
        self.alert = {
            "source_ip": "192.0.2.10",
            "failed_attempts": 3,
            "status": "ALERT",
        }

    def test_build_investigation(self):
        result = build_investigation(self.alert)

        self.assertEqual(result["alert"], self.alert)
        self.assertIn("observed_facts", result["required_sections"])

    def test_save_investigation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "investigation.json"
            result = {"summary": "Synthetic test report"}

            saved_path = save_investigation(result, output)

            self.assertTrue(saved_path.exists())
            with saved_path.open(encoding="utf-8") as file:
                self.assertEqual(json.load(file), result)

    @patch("src.ai_alert_explainer.genai.Client")
    def test_explain_alert_uses_model_response(self, mock_client):
        mock_client.return_value.models.generate_content.return_value.text = (
            '{"summary":"Test summary","observed_facts":[],'
            '"possible_explanations":[],"recommended_actions":[],'
            '"limitations":[]}'
        )

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}):
            result = explain_alert(self.alert)

        self.assertEqual(result["summary"], "Test summary")
        mock_client.return_value.models.generate_content.assert_called_once()


if __name__ == "__main__":
    unittest.main()
