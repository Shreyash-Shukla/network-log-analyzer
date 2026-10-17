import base64
import unittest

from dashboard_app import update_output
from test_log_analyzer import log_line


class DashboardTests(unittest.TestCase):
    def test_upload_analysis(self):
        encoded = base64.b64encode(log_line().encode()).decode()
        status, content = update_output(f"data:text/plain;base64,{encoded}", "access.log")
        self.assertIn("Successfully analyzed", status.children)
        self.assertEqual(len(content), 3)

    def test_invalid_upload(self):
        status, _ = update_output("data:text/plain;base64,not-base64", "bad.log")
        self.assertIn("Error analyzing file", status.children)


if __name__ == "__main__":
    unittest.main()
