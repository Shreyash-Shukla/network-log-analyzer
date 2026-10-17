# Network Log Analyzer

A Python tool for reviewing Apache and Nginx access logs. It counts traffic, status codes, and malformed lines; flags suspicious URLs, unusually busy IPs, and high error rates; and provides an HTML report or an interactive Dash dashboard.

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
python main.py anomaly_access.log
python main.py --dashboard
```

The command line analysis writes `log_analysis_report.html` to the current directory. The dashboard is available at [http://127.0.0.1:8050](http://127.0.0.1:8050). Dashboard uploads are analyzed in memory and do not create a report file. The dashboard binds to localhost.

You can also use the analyzer directly:

```python
from log_analyzer import NetworkLogAnalyzer

analyzer = NetworkLogAnalyzer(high_frequency_threshold=100)
report = analyzer.run_full_analysis("access.log", report_path="report.html")
print(report)
print(analyzer.anomalies)
```

## Input and detection

The parser accepts Apache/Nginx Common and Combined Log Format lines, with a numeric response size or `-`. Timestamps must include a numeric UTC offset. Only valid requests appear in traffic counts; skipped nonempty lines appear in `malformed_lines`. Times in reports are converted to UTC. Empty files produce a zero count report.

Detection flags:

- IPs with at least `high_frequency_threshold` requests across the whole file (default: 100).
- Files with more than 10% HTTP 4xx/5xx responses.
- URLs containing traversal, script tags, common SQL injection, or command execution patterns. URL matching decodes percent escapes twice.
- User agents shorter than 20 characters.

These are heuristics for triage, not proof of an attack. The high frequency rule counts the entire file, so choose a threshold that fits the log's time span.

## Tests

```bash
python -m unittest discover -s tests -v
```
