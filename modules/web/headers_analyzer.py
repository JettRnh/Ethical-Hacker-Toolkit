#!/usr/bin/env python3
"""
HTTP headers analyzer module for security assessment
Author: Jet
GitHub: https://github.com/JettRnh
"""

import requests
import ssl
import socket
from urllib.parse import urlparse
from core.logger import log
from config.settings import DEFAULT_USER_AGENT

class HeadersAnalyzer:
    """Analyze HTTP headers for security misconfigurations"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.headers = {}
        self.security_issues = []
        self.recommendations = []
        
        # Parse URL
        parsed = urlparse(target_url)
        self.scheme = parsed.scheme
        self.hostname = parsed.hostname
        self.port = parsed.port or (443 if self.scheme == 'https' else 80)
        
        log.status(f"HeadersAnalyzer initialized for {target_url}")
    
    def fetch_headers(self):
        """Fetch HTTP headers from target"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': DEFAULT_USER_AGENT})
            
            response = session.get(
                self.target_url,
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            self.headers = dict(response.headers)
            log.success(f"Fetched {len(self.headers)} headers")
            return self.headers
            
        except requests.exceptions.SSLError:
            log.error("SSL certificate error")
            return None
        except requests.exceptions.ConnectionError:
            log.error("Connection failed")
            return None
        except Exception as e:
            log.error(f"Error fetching headers: {e}")
            return None
    
    def analyze(self):
        """Analyze headers for security issues"""
        if not self.headers:
            self.fetch_headers()
        
        self._check_security_headers()
        self._check_server_info()
        self._check_cookie_security()
        self._check_cors_configuration()
        self._check_hsts()
        
        return {
            'headers': self.headers,
            'issues': self.security_issues,
            'recommendations': self.recommendations
        }
    
    def _check_security_headers(self):
        """Check for important security headers"""
        important_headers = {
            'Strict-Transport-Security': 'Missing HSTS header. Enforce HTTPS connections.',
            'Content-Security-Policy': 'Missing CSP header. Mitigate XSS and injection attacks.',
            'X-Frame-Options': 'Missing X-Frame-Options. Vulnerable to clickjacking.',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options. May allow MIME sniffing.',
            'X-XSS-Protection': 'Missing X-XSS-Protection. Older browsers may be vulnerable.',
            'Referrer-Policy': 'Missing Referrer-Policy. May leak sensitive info.',
            'Permissions-Policy': 'Missing Permissions-Policy. Browser features not restricted.'
        }
        
        for header, message in important_headers.items():
            if header not in self.headers:
                self.security_issues.append({
                    'type': 'missing',
                    'header': header,
                    'severity': 'medium',
                    'message': message
                })
                self.recommendations.append(f"Add {header} header: {message.split('.')[0]}")
            else:
                value = self.headers[header]
                log.info(f"{header}: {value}")
    
    def _check_server_info(self):
        """Check server information exposure"""
        if 'Server' in self.headers:
            server = self.headers['Server']
            log.info(f"Server: {server}")
            self.security_issues.append({
                'type': 'exposure',
                'header': 'Server',
                'severity': 'low',
                'message': f'Server version exposed: {server}'
            })
            self.recommendations.append("Hide Server header or remove version information")
        
        if 'X-Powered-By' in self.headers:
            powered = self.headers['X-Powered-By']
            self.security_issues.append({
                'type': 'exposure',
                'header': 'X-Powered-By',
                'severity': 'low',
                'message': f'Technology stack exposed: {powered}'
            })
            self.recommendations.append("Remove X-Powered-By header")
    
    def _check_cookie_security(self):
        """Check cookie security attributes"""
        if 'Set-Cookie' in self.headers:
            cookies = self.headers['Set-Cookie']
            issues = []
            
            if 'Secure' not in cookies:
                issues.append("Missing Secure flag")
            if 'HttpOnly' not in cookies:
                issues.append("Missing HttpOnly flag")
            if 'SameSite' not in cookies:
                issues.append("Missing SameSite flag")
            
            if issues:
                self.security_issues.append({
                    'type': 'cookie',
                    'severity': 'medium',
                    'message': f'Cookie security issues: {", ".join(issues)}'
                })
                self.recommendations.extend([
                    "Add Secure flag for HTTPS-only cookies",
                    "Add HttpOnly flag to prevent JavaScript access",
                    "Add SameSite=Strict or Lax for CSRF protection"
                ])
    
    def _check_cors_configuration(self):
        """Check CORS configuration"""
        if 'Access-Control-Allow-Origin' in self.headers:
            origin = self.headers['Access-Control-Allow-Origin']
            if origin == '*':
                self.security_issues.append({
                    'type': 'cors',
                    'severity': 'high',
                    'message': 'CORS allows all origins (*) - potential data leakage'
                })
                self.recommendations.append("Restrict Access-Control-Allow-Origin to specific domains")
    
    def _check_hsts(self):
        """Check HSTS configuration"""
        if 'Strict-Transport-Security' in self.headers:
            hsts = self.headers['Strict-Transport-Security']
            if 'max-age=0' in hsts:
                self.security_issues.append({
                    'type': 'hsts',
                    'severity': 'medium',
                    'message': 'HSTS max-age=0 - HSTS disabled'
                })
            elif 'max-age' in hsts:
                import re
                match = re.search(r'max-age=(\d+)', hsts)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 31536000:  # 1 year
                        self.security_issues.append({
                            'type': 'hsts',
                            'severity': 'low',
                            'message': f'HSTS max-age is {max_age} seconds (recommended: 31536000)'
                        })
    
    def get_report(self):
        """Generate analysis report"""
        lines = []
        lines.append("\n" + "=" * 70)
        lines.append("HTTP HEADERS SECURITY ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append(f"Target: {self.target_url}")
        lines.append("=" * 70)
        
        lines.append("\n[DETECTED HEADERS]")
        lines.append("-" * 40)
        for key, value in self.headers.items():
            lines.append(f"{key}: {value[:80]}")
        
        if self.security_issues:
            lines.append("\n[SECURITY ISSUES]")
            lines.append("-" * 40)
            for issue in self.security_issues:
                severity = issue['severity'].upper()
                lines.append(f"[{severity}] {issue['message']}")
        
        if self.recommendations:
            lines.append("\n[RECOMMENDATIONS]")
            lines.append("-" * 40)
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"{i}. {rec}")
        
        lines.append("\n" + "=" * 70)
        return "\n".join(lines)
