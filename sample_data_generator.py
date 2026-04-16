import random
from datetime import datetime, timedelta
import pandas as pd

def generate_sample_logs(num_entries=10000, output_file='sample_access.log'):
    """Generate sample web server logs for testing"""
    
    # Sample data
    ips = [f"192.168.1.{random.randint(1, 254)}" for _ in range(100)] + \
          [f"10.0.0.{random.randint(1, 254)}" for _ in range(50)] + \
          ['203.0.113.1', '198.51.100.1', '172.16.0.1']  # Some suspicious IPs
    
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
    urls = [
        '/', '/index.html', '/about', '/contact', '/login', '/dashboard',
        '/api/users', '/api/posts', '/api/data', '/admin', '/config',
        '/images/logo.png', '/css/style.css', '/js/app.js',
        '/search?q=test', '/user/profile', '/api/auth/login'
    ]
    
    # Add some suspicious URLs
    suspicious_urls = [
        '/admin/config.php',
        '/wp-admin/',
        '../../../etc/passwd',
        '/script.php?cmd=ls',
        '/search?q=<script>alert("xss")</script>',
        '/api/users?id=1 UNION SELECT * FROM passwords'
    ]
    urls.extend(suspicious_urls)
    
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'curl/7.68.0',
        'Python-requests/2.28.1',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'facebookexternalhit/1.1'
    ]
    
    status_codes = [200, 200, 200, 200, 200, 200, 200, 200, 200, 200,  # 80% success
                   404, 404, 404, 404, 404,                           # 5% not found
                   301, 301, 301,                                      # 3% redirects
                   500, 500,                                           # 2% server errors
                   403, 403,                                           # 2% forbidden
                   401, 401]                                           # 2% unauthorized
    
    # Generate logs
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for i in range(num_entries):
        # Generate timestamp
        timestamp = base_time + timedelta(
            seconds=random.randint(0, 7*24*60*60),
            milliseconds=random.randint(0, 999)
        )
        
        # Select random values
        ip = random.choice(ips)
        method = random.choice(methods)
        url = random.choice(urls)
        status = random.choice(status_codes)
        size = random.randint(100, 50000)
        referer = '-' if random.random() > 0.3 else random.choice(urls)
        user_agent = random.choice(user_agents)
        
        # Apache log format
        log_entry = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {url} HTTP/1.1" {status} {size} "{referer}" "{user_agent}"'
        logs.append(log_entry)
    
    # Write to file
    with open(output_file, 'w') as f:
        for log in logs:
            f.write(log + '\n')
    
    print(f"Generated {num_entries} sample log entries in {output_file}")
    return output_file

def generate_anomaly_logs(num_entries=1000, output_file='anomaly_access.log'):
    """Generate logs with specific anomalies for testing"""
    
    logs = []
    base_time = datetime.now() - timedelta(days=1)
    
    # Anomaly 1: High frequency from single IP
    suspicious_ip = "203.0.113.100"
    for i in range(500):
        timestamp = base_time + timedelta(seconds=i*2)
        log_entry = f'{suspicious_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET /api/data HTTP/1.1" 200 1234 "-" "Python-requests/2.28.1"'
        logs.append(log_entry)
    
    # Anomaly 2: SQL injection attempts
    sql_injection_payloads = [
        "1' OR '1'='1",
        "1; DROP TABLE users; --",
        "1 UNION SELECT username, password FROM users"
    ]
    
    for i in range(200):
        timestamp = base_time + timedelta(minutes=i)
        payload = random.choice(sql_injection_payloads)
        log_entry = f'192.168.1.50 - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET /search?id={payload} HTTP/1.1" 404 567 "-" "curl/7.68.0"'
        logs.append(log_entry)
    
    # Anomaly 3: Directory traversal attempts
    traversal_attempts = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/shadow"
    ]
    
    for i in range(150):
        timestamp = base_time + timedelta(minutes=i*2)
        path = random.choice(traversal_attempts)
        log_entry = f'10.0.0.25 - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET /file?path={path} HTTP/1.1" 403 234 "-" "Python-requests/2.28.1"'
        logs.append(log_entry)
    
    # Anomaly 4: High error rate
    for i in range(150):
        timestamp = base_time + timedelta(minutes=i*3)
        status = random.choice([500, 502, 503, 404, 403])
        log_entry = f'172.16.0.10 - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET /api/service HTTP/1.1" {status} 89 "-" "Mozilla/5.0"'
        logs.append(log_entry)
    
    # Write to file
    with open(output_file, 'w') as f:
        for log in logs:
            f.write(log + '\n')
    
    print(f"Generated {len(logs)} anomaly log entries in {output_file}")
    return output_file

if __name__ == "__main__":
    # Generate sample data
    generate_sample_logs(10000, 'sample_access.log')
    generate_anomaly_logs(1000, 'anomaly_access.log')
    print("Sample log files generated successfully!")
    print("Use these files to test the Network Log Analyzer.")
