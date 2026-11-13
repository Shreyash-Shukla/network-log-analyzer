"""Parse Apache/Nginx access logs and summarize suspicious traffic."""

from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
import re
from urllib.parse import unquote

import pandas as pd
import plotly.express as px


# Accept common and combined log formats, including "-" response sizes.
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?$'
)
SUSPICIOUS_PATTERNS = {
    "Directory traversal": re.compile(r'\.\.[/\\]'),
    "Cross-site scripting": re.compile(r'<script\b', re.I),
    "SQL injection": re.compile(r'\bunion\s+select\b|\bor\s+[^&]*=', re.I),
    "Command execution": re.compile(r'\bcmd\.exe\b|[?&]cmd=', re.I),
    "Sensitive file probing": re.compile(
        r'(?:^|/)(?:\.env|\.git|\.aws|\.ssh|wp-config\.php|web\.config|phpinfo\.php|phpmyadmin)(?:/|\?|$)|'
        r'\.(?:sql|bak|backup|old|swp|tar\.gz)$',
        re.I
    ),
}


def format_bytes(num_bytes):
    """Format byte counts into human-readable binary units (B, KiB, MiB, GiB, TiB)."""
    if num_bytes is None or num_bytes < 0:
        return "0 B"
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    unit_idx = 0
    val = float(num_bytes)
    while val >= 1024.0 and unit_idx < len(units) - 1:
        val /= 1024.0
        unit_idx += 1
    if unit_idx == 0:
        return f"{int(val)} {units[unit_idx]}"
    return f"{val:.2f} {units[unit_idx]}"


class NetworkLogAnalyzer:
    def __init__(self, log_file_path=None, high_frequency_threshold=100,
                 auth_failure_threshold=None, exfiltration_threshold=10 * 1024 * 1024):
        if high_frequency_threshold < 1:
            raise ValueError("high_frequency_threshold must be positive")
        self.log_file_path = log_file_path
        self.high_frequency_threshold = high_frequency_threshold
        self.auth_failure_threshold = (
            auth_failure_threshold if auth_failure_threshold is not None
            else max(2, min(10, high_frequency_threshold))
        )
        if self.auth_failure_threshold < 1:
            raise ValueError("auth_failure_threshold must be positive")
        self.exfiltration_threshold = exfiltration_threshold
        self.df = None
        self.malformed_lines = 0
        self.anomalies = []

    def load_log_file(self, file_path=None):
        """Load a UTF-8 access log. File errors propagate to the caller."""
        if file_path is not None:
            self.log_file_path = file_path
        if not self.log_file_path:
            raise ValueError("Please provide a log file path")
        with open(self.log_file_path, encoding="utf-8", errors="replace") as stream:
            return self._load_lines(stream)

    def load_log_text(self, text):
        """Load uploaded log text without creating a temporary file."""
        return self._load_lines(text.splitlines())

    def _load_lines(self, lines):
        records = []
        self.malformed_lines = 0
        self.anomalies = []
        for line_number, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            match = LOG_PATTERN.fullmatch(line)
            if not match:
                self.malformed_lines += 1
                continue
            record = match.groupdict()
            try:
                record["datetime"] = datetime.strptime(
                    record["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
                ).astimezone(timezone.utc)
            except ValueError:
                self.malformed_lines += 1
                continue
            record["line_number"] = line_number
            record["status"] = int(record["status"])
            record["size"] = 0 if record["size"] == "-" else int(record["size"])
            record["referer"] = record["referer"] or "-"
            record["user_agent"] = record["user_agent"] or "-"
            records.append(record)

        self.df = pd.DataFrame.from_records(records, columns=[
            "line_number", "ip", "timestamp", "datetime", "method", "url",
            "protocol", "status", "size", "referer", "user_agent",
        ])
        self.preprocess_data()
        return self.df

    def preprocess_data(self):
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
        self.df["datetime"] = pd.to_datetime(self.df["datetime"], utc=True)
        self.df["url_length"] = self.df["url"].str.len()
        self.df["has_query_params"] = self.df["url"].str.contains("?", regex=False)
        self.df["is_bot"] = self.df["user_agent"].str.contains(
            "bot|crawler|spider", case=False, regex=True, na=False
        )
        self.df["is_error"] = self.df["status"] >= 400
        self.df["is_success"] = self.df["status"] < 400

    def detect_anomalies(self):
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
        self.anomalies = []
        if self.df.empty:
            return self.anomalies
        for ip, count in self.df["ip"].value_counts().items():
            if count >= self.high_frequency_threshold:
                self.anomalies.append({
                    "type": "High Frequency IP", "ip": ip, "count": int(count),
                    "severity": "High" if count >= 2 * self.high_frequency_threshold else "Medium",
                })
        error_rate = float(self.df["is_error"].mean())
        if error_rate > 0.1:
            self.anomalies.append({
                "type": "High Error Rate", "error_rate": error_rate,
                "severity": "High" if error_rate > 0.2 else "Medium",
            })
        urls = self.df["url"].map(lambda url: unquote(unquote(url)))
        for name, pattern in SUSPICIOUS_PATTERNS.items():
            count = int(urls.str.contains(pattern).sum())
            if count:
                self.anomalies.append({"type": name, "count": count, "severity": "High"})
        short_agents = int((self.df["user_agent"].ne("-") & self.df["user_agent"].str.len().lt(20)).sum())
        if short_agents:
            self.anomalies.append({
                "type": "Suspicious User Agent", "count": short_agents, "severity": "Medium",
            })
        auth_failures = self.df[self.df["status"].isin([401, 403])]
        if not auth_failures.empty:
            for ip, count in auth_failures["ip"].value_counts().items():
                if count >= self.auth_failure_threshold:
                    self.anomalies.append({
                        "type": "Potential Auth Brute Force", "ip": ip, "count": int(count),
                        "severity": "High" if count >= 2 * self.auth_failure_threshold else "Medium",
                    })
        large_transfers = self.df[self.df["size"] >= self.exfiltration_threshold]
        if not large_transfers.empty:
            for _, row in large_transfers.head(10).iterrows():
                self.anomalies.append({
                    "type": "Potential Data Exfiltration", "ip": row["ip"], "url": row["url"],
                    "bytes": int(row["size"]), "formatted": format_bytes(row["size"]),
                    "severity": "High",
                })
        return self.anomalies

    def generate_traffic_report(self):
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
        dates = self.df["datetime"]
        total_bytes = int(self.df["size"].sum()) if not self.df.empty else 0
        avg_bytes = float(self.df["size"].mean()) if not self.df.empty else 0.0
        top_bandwidth_ips = (
            self.df.groupby("ip")["size"].sum().nlargest(10).to_dict()
            if not self.df.empty else {}
        )
        top_bandwidth_urls = (
            self.df.groupby("url")["size"].sum().nlargest(10).to_dict()
            if not self.df.empty else {}
        )
        return {
            "total_requests": len(self.df),
            "malformed_lines": self.malformed_lines,
            "unique_ips": self.df["ip"].nunique(),
            "total_bytes": total_bytes,
            "total_bytes_formatted": format_bytes(total_bytes),
            "avg_bytes_per_request": avg_bytes,
            "avg_bytes_formatted": format_bytes(avg_bytes),
            "date_range": {
                "start": dates.min().strftime("%Y-%m-%d %H:%M:%S UTC") if not dates.empty else "N/A",
                "end": dates.max().strftime("%Y-%m-%d %H:%M:%S UTC") if not dates.empty else "N/A",
            },
            "status_distribution": self.df["status"].value_counts().to_dict(),
            "error_rate": float(self.df["is_error"].mean()) if not self.df.empty else 0.0,
            "top_ips": self.df["ip"].value_counts().head(10).to_dict(),
            "top_urls": self.df["url"].value_counts().head(10).to_dict(),
            "top_bandwidth_ips": top_bandwidth_ips,
            "top_bandwidth_urls": top_bandwidth_urls,
            "method_distribution": self.df["method"].value_counts().to_dict(),
        }

    def create_visualizations(self):
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
        if self.df.empty:
            return {}
        hourly = self.df.set_index("datetime").resample("h").size()
        hourly_bandwidth = self.df.set_index("datetime")["size"].resample("h").sum()
        status = self.df["status"].value_counts()
        ips = self.df["ip"].value_counts().head(15)
        methods = self.df["method"].value_counts()
        return {
            "traffic_timeline": px.line(x=hourly.index, y=hourly.values,
                                        title="Traffic Over Time (Hourly)",
                                        labels={"x": "Time (UTC)", "y": "Requests"}),
            "bandwidth_timeline": px.line(x=hourly_bandwidth.index, y=hourly_bandwidth.values,
                                          title="Bandwidth Over Time (Hourly)",
                                          labels={"x": "Time (UTC)", "y": "Bytes Transferred"}),
            "status_distribution": px.pie(values=status.values, names=status.index,
                                           title="HTTP Status Codes"),
            "top_ips": px.bar(x=ips.values, y=ips.index, orientation="h",
                              title="Top IP Addresses", labels={"x": "Requests", "y": "IP"}),
            "method_distribution": px.bar(x=methods.index, y=methods.values,
                                          title="HTTP Methods"),
        }

    def export_report(self, filename="log_analysis_report.html"):
        report = self.generate_traffic_report()
        anomalies = self.detect_anomalies()
        items = "".join(
            "<li><strong>{}</strong> ({}) — {}</li>".format(
                escape(str(item["type"])), escape(str(item["severity"])),
                escape(", ".join(f"{key}: {value}" for key, value in item.items()
                                 if key not in {"type", "severity"})),
            ) for item in anomalies
        ) or "<li>None detected</li>"
        rows = "".join(
            f"<tr><td>{escape(str(ip))}</td><td>{count:,}</td></tr>"
            for ip, count in report["top_ips"].items()
        )
        bw_rows = "".join(
            f"<tr><td>{escape(str(ip))}</td><td>{format_bytes(bw)}</td></tr>"
            for ip, bw in report.get("top_bandwidth_ips", {}).items()
        )
        content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Network Log Analysis</title>
<style>body{{font:16px system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%;margin-bottom:1.5rem}}td,th{{border:1px solid #ccc;padding:.5rem;text-align:left}}
</style></head><body><h1>Network Log Analysis</h1>
<p>Valid requests: {report['total_requests']:,} · Malformed lines: {report['malformed_lines']:,}
· Unique IPs: {report['unique_ips']:,} · Bandwidth: {report['total_bytes_formatted']} (avg: {report['avg_bytes_formatted']}/req) · Error rate: {report['error_rate']:.2%}</p>
<p>Range: {report['date_range']['start']} to {report['date_range']['end']}</p>
<h2>Anomalies</h2><ul>{items}</ul>
<h2>Top IP addresses</h2><table><tr><th>IP address</th><th>Requests</th></tr>{rows}</table>
<h2>Top Bandwidth Consumers</h2><table><tr><th>IP address</th><th>Total Data</th></tr>{bw_rows}</table>
</body></html>"""
        Path(filename).write_text(content, encoding="utf-8")
        return filename

    def export_json(self, filename="log_analysis_report.json", indent=2):
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
        report = self.generate_traffic_report()
        anomalies = self.detect_anomalies()
        payload = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "log_file": str(self.log_file_path) if self.log_file_path else None,
                "high_frequency_threshold": self.high_frequency_threshold,
            },
            "summary": report,
            "anomalies": anomalies,
        }

        def _default_serializer(obj):
            if isinstance(obj, (pd.Timestamp, datetime)):
                return obj.isoformat()
            if hasattr(obj, "item"):
                return obj.item()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        Path(filename).write_text(json.dumps(payload, indent=indent, default=_default_serializer), encoding="utf-8")
        return filename

    def export_csv(self, filename="parsed_logs.csv", only_anomalies=False):
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
        if only_anomalies:
            anomalies = self.detect_anomalies()
            records = pd.DataFrame(anomalies)
            records.to_csv(filename, index=False, encoding="utf-8")
        else:
            self.df.to_csv(filename, index=False, encoding="utf-8")
        return filename

    def filter_logs(self, ip=None, status=None, method=None, url_pattern=None,
                    start_date=None, end_date=None, is_error=None):
        """Filter log records and return a new NetworkLogAnalyzer instance with matching records."""
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")

        filtered_df = self.df.copy()

        if ip is not None:
            filtered_df = filtered_df[filtered_df["ip"] == str(ip)]

        if status is not None:
            if isinstance(status, tuple) and len(status) == 2 and isinstance(status[0], int) and isinstance(status[1], int):
                filtered_df = filtered_df[(filtered_df["status"] >= status[0]) & (filtered_df["status"] <= status[1])]
            elif isinstance(status, (list, set)):
                filtered_df = filtered_df[filtered_df["status"].isin(status)]
            else:
                filtered_df = filtered_df[filtered_df["status"] == int(status)]

        if method is not None:
            if isinstance(method, (list, set, tuple)):
                methods = [str(m).upper() for m in method]
                filtered_df = filtered_df[filtered_df["method"].isin(methods)]
            else:
                filtered_df = filtered_df[filtered_df["method"] == str(method).upper()]

        if url_pattern is not None:
            filtered_df = filtered_df[filtered_df["url"].str.contains(url_pattern, regex=True, na=False)]

        if start_date is not None:
            ts_start = pd.to_datetime(start_date, utc=True)
            filtered_df = filtered_df[filtered_df["datetime"] >= ts_start]

        if end_date is not None:
            ts_end = pd.to_datetime(end_date, utc=True)
            filtered_df = filtered_df[filtered_df["datetime"] <= ts_end]

        if is_error is not None:
            filtered_df = filtered_df[filtered_df["is_error"] == bool(is_error)]

        new_analyzer = NetworkLogAnalyzer(
            log_file_path=self.log_file_path,
            high_frequency_threshold=self.high_frequency_threshold,
            auth_failure_threshold=self.auth_failure_threshold,
            exfiltration_threshold=self.exfiltration_threshold,
        )
        new_analyzer.df = filtered_df.reset_index(drop=True)
        new_analyzer.malformed_lines = 0
        new_analyzer.anomalies = []
        return new_analyzer

    def run_full_analysis(self, log_file_path=None, report_path="log_analysis_report.html"):
        self.load_log_file(log_file_path)
        self.detect_anomalies()
        report = self.generate_traffic_report()
        self.export_report(report_path)
        return report
