import tempfile
import unittest
from pathlib import Path

from log_analyzer import NetworkLogAnalyzer


STAMP = "10/Oct/2000:13:55:36 -0700"
AGENT = "Mozilla/5.0 (Example Browser)"


def log_line(ip="192.0.2.1", url="/", status=200, combined=True, size="123"):
    line = f'{ip} - - [{STAMP}] "GET {url} HTTP/1.1" {status} {size}'
    return line + (f' "-" "{AGENT}"' if combined else "")


class AnalyzerTests(unittest.TestCase):
    def test_common_combined_and_malformed_lines(self):
        analyzer = NetworkLogAnalyzer()
        analyzer.load_log_text("\n".join([
            log_line(combined=False, size="-"),
            log_line(ip="198.51.100.2", status=404),
            "invalid log line",
            '192.0.2.3 - - [invalid] "GET / HTTP/1.1" 200 1',
        ]))
        report = analyzer.generate_traffic_report()
        self.assertEqual(report["total_requests"], 2)
        self.assertEqual(report["malformed_lines"], 2)
        self.assertEqual(report["status_distribution"], {200: 1, 404: 1})
        self.assertEqual(report["error_rate"], 0.5)
        self.assertEqual(report["date_range"]["start"], "2000-10-10 20:55:36 UTC")
        self.assertEqual(analyzer.df.iloc[0]["size"], 0)

    def test_empty_and_reused_analyzer(self):
        analyzer = NetworkLogAnalyzer()
        analyzer.load_log_text("not a log")
        self.assertEqual(analyzer.generate_traffic_report()["malformed_lines"], 1)
        analyzer.load_log_text("")
        self.assertEqual(analyzer.generate_traffic_report()["total_requests"], 0)
        self.assertEqual(analyzer.generate_traffic_report()["malformed_lines"], 0)
        self.assertEqual(analyzer.detect_anomalies(), [])
        self.assertEqual(analyzer.create_visualizations(), {})

    def test_encoded_attacks_and_frequency(self):
        analyzer = NetworkLogAnalyzer(high_frequency_threshold=2)
        analyzer.load_log_text("\n".join([
            log_line(url="/file?path=%252e%252e%252fetc/passwd", status=403),
            log_line(url="/search?q=%3Cscript%3E", status=403),
            log_line(url="/search?q=UNION%20SELECT%20password", status=403),
        ]))
        types = {item["type"] for item in analyzer.detect_anomalies()}
        self.assertTrue({
            "High Frequency IP", "High Error Rate", "Directory traversal",
            "Cross-site scripting", "SQL injection",
        }.issubset(types))

    def test_report_escapes_log_values(self):
        analyzer = NetworkLogAnalyzer(high_frequency_threshold=1)
        analyzer.load_log_text(log_line(ip="<script>alert(1)</script>"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            analyzer.export_report(path)
            html = path.read_text(encoding="utf-8")
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            NetworkLogAnalyzer().load_log_file("missing-access.log")


if __name__ == "__main__":
    unittest.main()
