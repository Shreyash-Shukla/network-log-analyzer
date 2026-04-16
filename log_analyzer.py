import pandas as pd
import numpy as np
import re
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

class NetworkLogAnalyzer:
    def __init__(self, log_file_path=None):
        self.log_file_path = log_file_path
        self.df = None
        self.anomalies = []
        
    def load_log_file(self, file_path=None):
        """Load log file and parse into DataFrame"""
        if file_path:
            self.log_file_path = file_path
            
        if not self.log_file_path:
            raise ValueError("Please provide a log file path")
            
        try:
            # Common log patterns
            apache_pattern = r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+) "([^"]*)" "([^"]*)"'
            nginx_pattern = r'(\S+) - - \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+) "([^"]*)" "([^"]*)"'
            
            parsed_logs = []
            
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Try to parse with Apache pattern
                    match = re.match(apache_pattern, line)
                    if match:
                        ip, timestamp, method, url, protocol, status, size, referer, user_agent = match.groups()
                        parsed_logs.append({
                            'line_number': line_num,
                            'ip': ip,
                            'timestamp': timestamp,
                            'method': method,
                            'url': url,
                            'protocol': protocol,
                            'status': int(status),
                            'size': int(size) if size != '-' else 0,
                            'referer': referer,
                            'user_agent': user_agent,
                            'raw_log': line
                        })
                    else:
                        # For unparseable lines, store as-is
                        parsed_logs.append({
                            'line_number': line_num,
                            'raw_log': line,
                            'parsed': False
                        })
            
            self.df = pd.DataFrame(parsed_logs)
            print(f"Loaded {len(self.df)} log entries")
            return self.df
            
        except Exception as e:
            print(f"Error loading log file: {e}")
            return None
    
    def preprocess_data(self):
        """Preprocess and clean the data"""
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
            
        # Convert timestamp to datetime
        if 'timestamp' in self.df.columns:
            self.df['datetime'] = pd.to_datetime(self.df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
            
        # Extract additional features
        if 'url' in self.df.columns:
            self.df['url_length'] = self.df['url'].str.len()
            self.df['has_query_params'] = self.df['url'].str.contains('\?').astype(int)
            
        if 'user_agent' in self.df.columns:
            self.df['is_bot'] = self.df['user_agent'].str.contains('bot|crawler|spider', case=False, na=False).astype(int)
            
        if 'status' in self.df.columns:
            self.df['is_error'] = (self.df['status'] >= 400).astype(int)
            self.df['is_success'] = (self.df['status'] < 400).astype(int)
            
        print("Data preprocessing completed")
        
    def detect_anomalies(self):
        """Detect various types of anomalies in the logs"""
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
            
        self.anomalies = []
        
        # 1. High frequency requests from same IP
        if 'ip' in self.df.columns:
            ip_counts = self.df['ip'].value_counts()
            threshold = ip_counts.quantile(0.95)
            suspicious_ips = ip_counts[ip_counts > threshold]
            
            for ip, count in suspicious_ips.items():
                self.anomalies.append({
                    'type': 'High Frequency IP',
                    'ip': ip,
                    'count': count,
                    'severity': 'High' if count > threshold * 2 else 'Medium'
                })
        
        # 2. Error rate anomalies
        if 'status' in self.df.columns:
            error_rate = self.df['is_error'].mean()
            if error_rate > 0.1:  # More than 10% errors
                self.anomalies.append({
                    'type': 'High Error Rate',
                    'error_rate': error_rate,
                    'severity': 'High' if error_rate > 0.2 else 'Medium'
                })
        
        # 3. Suspicious URL patterns
        if 'url' in self.df.columns:
            suspicious_patterns = [
                r'\.\./',  # Directory traversal
                r'<script',  # XSS attempts
                r'union.*select',  # SQL injection
                r'cmd\.exe',  # Command injection
            ]
            
            for pattern in suspicious_patterns:
                matches = self.df[self.df['url'].str.contains(pattern, case=False, na=False)]
                if not matches.empty:
                    self.anomalies.append({
                        'type': 'Suspicious URL Pattern',
                        'pattern': pattern,
                        'count': len(matches),
                        'severity': 'High'
                    })
        
        # 4. Unusual user agents
        if 'user_agent' in self.df.columns:
            # Very short or missing user agents might be suspicious
            suspicious_ua = self.df[
                (self.df['user_agent'].str.len() < 20) | 
                (self.df['user_agent'].isna())
            ]
            if not suspicious_ua.empty:
                self.anomalies.append({
                    'type': 'Suspicious User Agent',
                    'count': len(suspicious_ua),
                    'severity': 'Medium'
                })
        
        print(f"Detected {len(self.anomalies)} anomalies")
        return self.anomalies
    
    def generate_traffic_report(self):
        """Generate comprehensive traffic analysis report"""
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
            
        report = {}
        
        # Basic statistics
        report['total_requests'] = len(self.df)
        report['unique_ips'] = self.df['ip'].nunique() if 'ip' in self.df.columns else 0
        report['date_range'] = {
            'start': self.df['datetime'].min().strftime('%Y-%m-%d %H:%M:%S') if 'datetime' in self.df.columns else 'N/A',
            'end': self.df['datetime'].max().strftime('%Y-%m-%d %H:%M:%S') if 'datetime' in self.df.columns else 'N/A'
        }
        
        # Status code distribution
        if 'status' in self.df.columns:
            report['status_distribution'] = self.df['status'].value_counts().to_dict()
            report['error_rate'] = (self.df['status'] >= 400).mean()
        
        # Top IPs
        if 'ip' in self.df.columns:
            report['top_ips'] = self.df['ip'].value_counts().head(10).to_dict()
        
        # Top URLs
        if 'url' in self.df.columns:
            report['top_urls'] = self.df['url'].value_counts().head(10).to_dict()
        
        # Method distribution
        if 'method' in self.df.columns:
            report['method_distribution'] = self.df['method'].value_counts().to_dict()
        
        return report
    
    def create_visualizations(self):
        """Create various visualizations for the log data"""
        if self.df is None:
            raise ValueError("No data loaded. Please load a log file first.")
            
        figs = {}
        
        # 1. Traffic over time
        if 'datetime' in self.df.columns:
            hourly_traffic = self.df.set_index('datetime').resample('H').size()
            fig1 = px.line(
                x=hourly_traffic.index, 
                y=hourly_traffic.values,
                title='Traffic Over Time (Hourly)',
                labels={'x': 'Time', 'y': 'Number of Requests'}
            )
            figs['traffic_timeline'] = fig1
        
        # 2. Status code distribution
        if 'status' in self.df.columns:
            status_counts = self.df['status'].value_counts()
            fig2 = px.pie(
                values=status_counts.values,
                names=status_counts.index,
                title='HTTP Status Code Distribution'
            )
            figs['status_distribution'] = fig2
        
        # 3. Top IPs bar chart
        if 'ip' in self.df.columns:
            top_ips = self.df['ip'].value_counts().head(15)
            fig3 = px.bar(
                x=top_ips.values,
                y=top_ips.index,
                orientation='h',
                title='Top 15 IP Addresses by Request Count',
                labels={'x': 'Request Count', 'y': 'IP Address'}
            )
            figs['top_ips'] = fig3
        
        # 4. Method distribution
        if 'method' in self.df.columns:
            method_counts = self.df['method'].value_counts()
            fig4 = px.bar(
                x=method_counts.index,
                y=method_counts.values,
                title='HTTP Methods Distribution',
                labels={'x': 'HTTP Method', 'y': 'Count'}
            )
            figs['method_distribution'] = fig4
        
        return figs
    
    def export_report(self, filename='log_analysis_report.html'):
        """Export analysis report to HTML file"""
        report = self.generate_traffic_report()
        anomalies = self.anomalies if self.anomalies else self.detect_anomalies()
        visualizations = self.create_visualizations()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Log Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                .anomaly {{ background-color: #ffebee; padding: 10px; margin: 5px 0; border-left: 4px solid #f44336; }}
                .stats {{ background-color: #e8f5e8; padding: 15px; border-radius: 5px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network Log Analysis Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Summary Statistics</h2>
                <div class="stats">
                    <p><strong>Total Requests:</strong> {report['total_requests']:,}</p>
                    <p><strong>Unique IPs:</strong> {report['unique_ips']:,}</p>
                    <p><strong>Date Range:</strong> {report['date_range']['start']} to {report['date_range']['end']}</p>
                    <p><strong>Error Rate:</strong> {report.get('error_rate', 0):.2%}</p>
                </div>
            </div>
            
            <div class="section">
                <h2>Detected Anomalies</h2>
        """
        
        for anomaly in anomalies:
            html_content += f"""
                <div class="anomaly">
                    <strong>{anomaly['type']}</strong> - Severity: {anomaly['severity']}<br>
                    {', '.join([f"{k}: {v}" for k, v in anomaly.items() if k not in ['type', 'severity']])}
                </div>
            """
        
        html_content += """
            </div>
            
            <div class="section">
                <h2>Top IP Addresses</h2>
                <table>
                    <tr><th>IP Address</th><th>Request Count</th></tr>
        """
        
        if 'top_ips' in report:
            for ip, count in list(report['top_ips'].items())[:10]:
                html_content += f"<tr><td>{ip}</td><td>{count:,}</td></tr>"
        
        html_content += """
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Report exported to {filename}")
        
    def run_full_analysis(self, log_file_path=None):
        """Run complete analysis pipeline"""
        print("Starting Network Log Analysis...")
        
        # Load data
        self.load_log_file(log_file_path)
        
        # Preprocess
        self.preprocess_data()
        
        # Detect anomalies
        self.detect_anomalies()
        
        # Generate report
        report = self.generate_traffic_report()
        
        # Export report
        self.export_report()
        
        print("Analysis completed successfully!")
        return report

# Example usage
if __name__ == "__main__":
    analyzer = NetworkLogAnalyzer()
    
    # Example with a sample log file (you would replace this with your actual log file)
    # analyzer.run_full_analysis("access.log")
    
    print("Network Log Analyzer initialized. Use analyzer.run_full_analysis('your_log_file.log') to start analysis.")
