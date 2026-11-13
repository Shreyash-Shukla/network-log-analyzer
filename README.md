# Network Log Analyzer

A Python tool for reviewing Apache and Nginx access logs. It counts traffic, bandwidth consumption, status codes, and malformed lines; flags suspicious URLs, sensitive file probes, authentication brute-force attempts, unusually busy IPs, data exfiltration, and high error rates; provides log filtering; and exports structured HTML, JSON, and CSV reports or an interactive Dash dashboard.

## Install

Use Python 3.10 or newer:

```bash
python -m venv .venv
# Activate the environment, then:
python -m pip install -r requirements.txt
```

## Run

```bash
python main.py --generate-sample
python main.py sample_access.log
python main.py anomaly_access.log --json report.json --csv parsed.csv
python main.py access.log --filter-status 500 --json server_errors.json
python main.py --dashboard
```

The command line analysis writes `log_analysis_report.html` to the current directory by default. The dashboard is available at [http://127.0.0.1:8050](http://127.0.0.1:8050). Dashboard uploads are analyzed in memory and do not create a report file. The dashboard binds to localhost.

### Command Line Options

- `log_file`: Path to the log file to analyze.
- `--generate-sample`: Generate sample and anomaly test log files.
- `--dashboard`: Launch the interactive Dash web dashboard.
- `--output`, `-o`: Output path for the HTML report (default: `log_analysis_report.html`).
- `--json`: Export structured analysis results to JSON (e.g. `--json report.json`).
- `--csv`: Export parsed logs to CSV (e.g. `--csv parsed.csv`).
- `--threshold`: High frequency IP request threshold (default: 100).
- `--auth-threshold`: Failed authentication attempt threshold for brute-force detection.
- `--exfil-threshold`: Data exfiltration response size threshold in bytes (default: 10485760).
- `--filter-ip`: Filter logs by specific IP address.
- `--filter-status`: Filter logs by HTTP status code.
- `--filter-method`: Filter logs by HTTP method (`GET`, `POST`, etc.).
- `--filter-url`: Filter logs matching a URL regex pattern.

### Python API

```python
from log_analyzer import NetworkLogAnalyzer

analyzer = NetworkLogAnalyzer(high_frequency_threshold=100)
report = analyzer.run_full_analysis("access.log", report_path="report.html")
print(f"Total requests: {report['total_requests']}")
print(f"Total bandwidth: {report['total_bytes_formatted']}")

# Machine-readable exports
analyzer.export_json("report.json")
analyzer.export_csv("parsed_logs.csv")

# Fluent log filtering
server_errors = analyzer.filter_logs(status=(500, 599))
print(f"Server errors: {server_errors.generate_traffic_report()['total_requests']}")
```

## Input and Detection

The parser accepts Apache/Nginx Common and Combined Log Format lines, with a numeric response size or `-`. Timestamps must include a numeric UTC offset. Only valid requests appear in traffic counts; skipped nonempty lines appear in `malformed_lines`. Times in reports are converted to UTC. Empty files produce a zero count report.

Detection flags:

- **High Frequency IP**: IPs with at least `high_frequency_threshold` requests across the whole file (default: 100).
- **High Error Rate**: Files with more than 10% HTTP 4xx/5xx responses.
- **Suspicious URLs**: Directory traversal, cross-site scripting (XSS), SQL injection, and command execution patterns. Decodes percent escapes twice before evaluation.
- **Sensitive File Probing**: Scanning for configuration secrets, credentials, and backups (`.env`, `.git`, `.aws`, `wp-config.php`, `web.config`, `phpinfo.php`, `.sql`, `.tar.gz`).
- **Potential Auth Brute Force**: Repeated HTTP 401 Unauthorized or 403 Forbidden responses from an IP exceeding threshold.
- **Potential Data Exfiltration**: HTTP responses with unusually large payload sizes exceeding threshold (default: 10 MiB).
- **Suspicious User Agent**: Non-empty user agents shorter than 20 characters.

These are heuristics for triage, not proof of an attack. The high frequency rule counts the entire file, so choose a threshold that fits the log's time span.

## Tests

```bash
python -m unittest discover -s tests -v
```
