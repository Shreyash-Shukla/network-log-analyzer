# Network Log Analyzer

A comprehensive Python-based tool for analyzing large-scale network logs to detect anomalies and suspicious patterns. Built with Pandas for data processing and Regex for log filtering, with interactive visualization capabilities.

## Features

- **Log Parsing**: Supports Apache and Nginx log formats with regex-based parsing
- **Anomaly Detection**: Identifies various security threats and unusual patterns:
  - High-frequency requests from single IPs
  - SQL injection attempts
  - Directory traversal attacks
  - Suspicious user agents
  - Abnormal error rates
- **Traffic Analysis**: Comprehensive analysis of web server traffic patterns
- **Interactive Dashboard**: Real-time visualization using Dash and Plotly
- **Report Generation**: Automated HTML reports with detailed findings
- **Pattern Filtering**: Advanced regex-based log filtering capabilities

## Tech Stack

- **Data Processing**: Pandas, NumPy
- **Pattern Matching**: Regex (Python re module)
- **Visualization**: Plotly, Matplotlib, Seaborn
- **Interactive Dashboard**: Dash, Dash Bootstrap Components
- **Machine Learning**: Scikit-learn (for advanced anomaly detection)
- **Analysis**: Jupyter Notebooks for exploratory analysis

## Installation

1. Install Python 3.8 or higher
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

### Command Line Usage

```python
from log_analyzer import NetworkLogAnalyzer

# Initialize analyzer
analyzer = NetworkLogAnalyzer()

# Run complete analysis
report = analyzer.run_full_analysis('your_access.log')

# Generate sample data for testing
python sample_data_generator.py
```

### Interactive Dashboard

```bash
python dashboard_app.py
```

Then open http://localhost:8050 in your browser to access the interactive dashboard.

### Jupyter Notebook Analysis

```python
# Import the analyzer
from log_analyzer import NetworkLogAnalyzer

# Create analyzer instance
analyzer = NetworkLogAnalyzer()

# Load log file
analyzer.load_log_file('sample_access.log')

# Preprocess data
analyzer.preprocess_data()

# Detect anomalies
anomalies = analyzer.detect_anomalies()

# Generate visualizations
figs = analyzer.create_visualizations()

# Display in notebook
for name, fig in figs.items():
    fig.show()
```

## Key Features

### Anomaly Detection

The tool detects multiple types of security anomalies:

1. **High Frequency IP Detection**: Identifies IPs making unusually many requests
2. **SQL Injection Detection**: Pattern matching for common SQL injection payloads
3. **Directory Traversal**: Detects file system access attempts
4. **Error Rate Analysis**: Identifies unusual spikes in HTTP error codes
5. **Suspicious User Agents**: Flags bot-like or malformed user agents

### Traffic Analysis

- **Request Volume**: Time-series analysis of traffic patterns
- **Geographic Analysis**: IP-based geographic distribution
- **Status Code Analysis**: HTTP response code distribution
- **URL Analysis**: Most requested endpoints and suspicious URLs
- **User Agent Analysis**: Browser and bot traffic breakdown

### Visualization Capabilities

- **Interactive Time Series**: Traffic trends over time
- **Geographic Maps**: IP location visualization
- **Status Code Charts**: Distribution of HTTP responses
- **Top N Analysis**: Most active IPs, URLs, and user agents

## Sample Data Generation

Generate sample log files for testing:

```bash
python sample_data_generator.py
```

This creates:
- `sample_access.log`: Normal web server traffic (10,000 entries)
- `anomaly_access.log`: Logs with various security anomalies (1,000 entries)

## API Reference

### NetworkLogAnalyzer Class

#### Methods:

- `load_log_file(file_path)`: Load and parse log file
- `preprocess_data()`: Clean and prepare data for analysis
- `detect_anomalies()`: Identify security anomalies
- `generate_traffic_report()`: Create comprehensive traffic report
- `create_visualizations()`: Generate Plotly charts
- `export_report(filename)`: Export HTML report
- `run_full_analysis(file_path)`: Complete analysis pipeline

#### Attributes:

- `df`: Pandas DataFrame containing parsed log data
- `anomalies`: List of detected anomalies
- `log_file_path`: Path to current log file

## Supported Log Formats

### Apache Common Log Format
```
IP - - [timestamp] "method URL protocol" status size "referer" "user_agent"
```

### Nginx Log Format
```
IP - - [timestamp] "method URL protocol" status size "referer" "user_agent"
```

## Configuration

The analyzer can be customized through:

- **Log Patterns**: Modify regex patterns in `load_log_file()` method
- **Anomaly Thresholds**: Adjust detection sensitivity in `detect_anomalies()`
- **Visualization**: Customize chart styles in `create_visualizations()`

## Performance

- Handles log files with millions of entries efficiently
- Memory-optimized processing using Pandas
- Parallel processing capabilities for large datasets
- Configurable batch sizes for memory management

## Use Cases

1. **Security Monitoring**: Detect potential attacks and suspicious activities
2. **Traffic Analysis**: Understand usage patterns and peak times
3. **Performance Monitoring**: Identify error trends and bottlenecks
4. **Compliance**: Generate reports for security audits
5. **Capacity Planning**: Analyze traffic growth patterns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your enhancements
4. Submit a pull request

## License

MIT License - see LICENSE file for details
