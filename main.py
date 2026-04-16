#!/usr/bin/env python3
"""
Network Log Analyzer - Main Entry Point
Usage: python main.py [log_file_path]
"""

import sys
import argparse
from log_analyzer import NetworkLogAnalyzer

def main():
    parser = argparse.ArgumentParser(description='Analyze network logs for anomalies and patterns')
    parser.add_argument('log_file', nargs='?', help='Path to the log file to analyze')
    parser.add_argument('--generate-sample', action='store_true', help='Generate sample log files')
    parser.add_argument('--dashboard', action='store_true', help='Launch interactive dashboard')
    
    args = parser.parse_args()
    
    if args.generate_sample:
        from sample_data_generator import generate_sample_logs, generate_anomaly_logs
        print("Generating sample log files...")
        generate_sample_logs(10000, 'sample_access.log')
        generate_anomaly_logs(1000, 'anomaly_access.log')
        print("Sample files generated. Use 'python main.py sample_access.log' to analyze.")
        return
    
    if args.dashboard:
        from dashboard_app import app
        print("Starting dashboard at http://localhost:8050")
        app.run_server(debug=True, host='0.0.0.0', port=8050)
        return
    
    if not args.log_file:
        print("Usage: python main.py <log_file_path>")
        print("Or use --generate-sample to create sample data")
        print("Or use --dashboard to launch interactive dashboard")
        sys.exit(1)
    
    # Run analysis
    analyzer = NetworkLogAnalyzer()
    try:
        report = analyzer.run_full_analysis(args.log_file)
        print("\nAnalysis completed successfully!")
        print(f"Check 'log_analysis_report.html' for detailed results.")
        print(f"Total anomalies detected: {len(analyzer.anomalies)}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
