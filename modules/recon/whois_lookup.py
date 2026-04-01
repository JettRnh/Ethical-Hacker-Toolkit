#!/usr/bin/env python3
"""
WHOIS lookup module for domain information gathering
Author: Jet
GitHub: https://github.com/JettRnh
"""

import socket
import re
import whois
from datetime import datetime
from core.logger import log

class WhoisLookup:
    """WHOIS lookup for domain and IP information"""
    
    def __init__(self, target):
        self.target = target
        self.data = {}
        self.is_domain = self._detect_target_type(target)
        
        log.status(f"WhoisLookup initialized for {target}")
    
    def _detect_target_type(self, target):
        """Detect if target is domain or IP"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            return False
        return True
    
    def lookup_domain(self):
        """Perform WHOIS lookup for domain"""
        try:
            w = whois.whois(self.target)
            
            self.data = {
                'domain': w.domain_name,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'updated_date': w.updated_date,
                'name_servers': w.name_servers,
                'status': w.status,
                'registrant': w.registrant,
                'registrant_email': w.registrant_email,
                'admin_email': w.admin_email,
                'tech_email': w.tech_email,
                'org': w.org
            }
            
            # Clean up dates
            for key in ['creation_date', 'expiration_date', 'updated_date']:
                if self.data.get(key):
                    if isinstance(self.data[key], list):
                        self.data[key] = self.data[key][0]
                    if isinstance(self.data[key], datetime):
                        self.data[key] = self.data[key].strftime('%Y-%m-%d')
            
            log.success(f"WHOIS data retrieved for {self.target}")
            return self.data
            
        except whois.parser.PywhoisError as e:
            log.error(f"WHOIS lookup failed: {e}")
            return None
        except Exception as e:
            log.error(f"Error: {e}")
            return None
    
    def lookup_ip(self):
        """Perform WHOIS lookup for IP address"""
        try:
            # Use socket for IP WHOIS (simplified)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('whois.arin.net', 43))
            
            sock.send(f"{self.target}\r\n".encode())
            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()
            
            response_text = response.decode('utf-8', errors='ignore')
            
            # Parse basic info
            self.data = {
                'target': self.target,
                'raw_response': response_text[:5000]  # Limit size
            }
            
            # Extract netname
            netname_match = re.search(r'NetName:\s*(.+)', response_text, re.IGNORECASE)
            if netname_match:
                self.data['netname'] = netname_match.group(1).strip()
            
            # Extract organization
            org_match = re.search(r'Organization:\s*(.+)', response_text, re.IGNORECASE)
            if org_match:
                self.data['organization'] = org_match.group(1).strip()
            
            # Extract CIDR
            cidr_match = re.search(r'CIDR:\s*(.+)', response_text, re.IGNORECASE)
            if cidr_match:
                self.data['cidr'] = cidr_match.group(1).strip()
            
            log.success(f"IP WHOIS data retrieved for {self.target}")
            return self.data
            
        except socket.error as e:
            log.error(f"Socket error: {e}")
            return None
        except Exception as e:
            log.error(f"Error: {e}")
            return None
    
    def lookup(self):
        """Perform WHOIS lookup based on target type"""
        if self.is_domain:
            return self.lookup_domain()
        else:
            return self.lookup_ip()
    
    def get_report(self):
        """Generate WHOIS report"""
        if not self.data:
            self.lookup()
        
        lines = []
        lines.append("\n" + "=" * 70)
        lines.append("WHOIS LOOKUP REPORT")
        lines.append("=" * 70)
        lines.append(f"Target: {self.target}")
        lines.append("=" * 70)
        
        if self.is_domain:
            lines.append(f"\nDomain: {self.data.get('domain', 'N/A')}")
            lines.append(f"Registrar: {self.data.get('registrar', 'N/A')}")
            lines.append(f"Created: {self.data.get('creation_date', 'N/A')}")
            lines.append(f"Expires: {self.data.get('expiration_date', 'N/A')}")
            lines.append(f"Updated: {self.data.get('updated_date', 'N/A')}")
            lines.append(f"\nName Servers:")
            ns = self.data.get('name_servers', [])
            if ns:
                for ns_entry in ns:
                    lines.append(f"  - {ns_entry}")
            else:
                lines.append("  N/A")
            
            lines.append(f"\nRegistrant: {self.data.get('registrant', 'N/A')}")
            lines.append(f"Registrant Email: {self.data.get('registrant_email', 'N/A')}")
            lines.append(f"Admin Email: {self.data.get('admin_email', 'N/A')}")
            lines.append(f"Tech Email: {self.data.get('tech_email', 'N/A')}")
        else:
            lines.append(f"\nIP Address: {self.data.get('target', 'N/A')}")
            lines.append(f"Netname: {self.data.get('netname', 'N/A')}")
            lines.append(f"Organization: {self.data.get('organization', 'N/A')}")
            lines.append(f"CIDR: {self.data.get('cidr', 'N/A')}")
            lines.append("\nRaw Response (truncated):")
            lines.append(self.data.get('raw_response', 'N/A')[:1000])
        
        lines.append("\n" + "=" * 70)
        return "\n".join(lines)
