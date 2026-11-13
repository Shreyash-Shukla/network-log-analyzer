import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from log_analyzer import NetworkLogAnalyzer, format_bytes


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

    def test_suspicious_user_agent(self):
        analyzer = NetworkLogAnalyzer()
        analyzer.load_log_text("\n".join([
            log_line(combined=False),
            log_line(combined=True),
        ]))
        anomalies = analyzer.detect_anomalies()
        self.assertNotIn("Suspicious User Agent", {a["type"] for a in anomalies})

        short_agent_line = f'192.0.2.1 - - [{STAMP}] "GET / HTTP/1.1" 200 123 "-" "curl/7.68.0"'
        analyzer.load_log_text(short_agent_line)
        anomalies = analyzer.detect_anomalies()
        self.assertIn("Suspicious User Agent", {a["type"] for a in anomalies})

    def test_format_bytes(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(-10), "0 B")
        self.assertEqual(format_bytes(512), "512 B")
        self.assertEqual(format_bytes(1024), "1.00 KiB")
        self.assertEqual(format_bytes(1048576 * 5), "5.00 MiB")
        self.assertEqual(format_bytes(1073741824 * 2.5), "2.50 GiB")

    def test_bandwidth_metrics_and_report(self):
        analyzer = NetworkLogAnalyzer()
        analyzer.load_log_text("\n".join([
            log_line(ip="10.0.0.1", url="/api/data", size="1000"),
            log_line(ip="10.0.0.1", url="/index.html", size="2000"),
            log_line(ip="10.0.0.2", url="/api/data", size="500"),
        ]))
        report = analyzer.generate_traffic_report()
        self.assertEqual(report["total_bytes"], 3500)
        self.assertEqual(report["total_bytes_formatted"], "3.42 KiB")
        self.assertAlmostEqual(report["avg_bytes_per_request"], 3500 / 3)
        self.assertEqual(report["top_bandwidth_ips"]["10.0.0.1"], 3000)
        self.assertEqual(report["top_bandwidth_ips"]["10.0.0.2"], 500)
        self.assertEqual(report["top_bandwidth_urls"]["/api/data"], 1500)
        self.assertEqual(report["top_bandwidth_urls"]["/index.html"], 2000)

        figs = analyzer.create_visualizations()
        self.assertIn("bandwidth_timeline", figs)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            analyzer.export_report(path)
            content = path.read_text(encoding="utf-8")
        self.assertIn("Top Bandwidth Consumers", content)
        self.assertIn("3.42 KiB", content)

    def test_export_json_and_csv(self):
        analyzer = NetworkLogAnalyzer(high_frequency_threshold=2)
        # Test calling before load raises ValueError
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            csv_path = Path(directory) / "logs.csv"
            with self.assertRaises(ValueError):
                NetworkLogAnalyzer().export_json(json_path)
            with self.assertRaises(ValueError):
                NetworkLogAnalyzer().export_csv(csv_path)

            analyzer.load_log_text("\n".join([
                log_line(ip="10.0.0.1", url="/login", status=401, size="500"),
                log_line(ip="10.0.0.1", url="/api/data", status=200, size="1500"),
                log_line(ip="10.0.0.2", url="/index.html", status=200, size="2500"),
            ]))

            analyzer.export_json(json_path)
            data = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertIn("metadata", data)
            self.assertIn("summary", data)
            self.assertIn("anomalies", data)
            self.assertEqual(data["metadata"]["high_frequency_threshold"], 2)
            self.assertEqual(data["summary"]["total_requests"], 3)
            self.assertEqual(data["summary"]["total_bytes"], 4500)

            analyzer.export_csv(csv_path)
            csv_text = csv_path.read_text(encoding="utf-8")
            self.assertIn("line_number,ip,timestamp,datetime", csv_text)
            self.assertIn("10.0.0.1", csv_text)
            self.assertIn("10.0.0.2", csv_text)

            anom_csv = Path(directory) / "anom.csv"
            analyzer.export_csv(anom_csv, only_anomalies=True)
            self.assertTrue(anom_csv.exists())


if __name__ == "__main__":
    unittest.main()
